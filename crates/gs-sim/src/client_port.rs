use anyhow::{Context, Result};
use common::{
    crypto::{client_input_sign_bytes, now_ms, sha256},
    proto::{ClientCmd, ClientToGs, PlayTicket, ServerHello, WorldSnapshot},
};
use ed25519_dalek::{Signature, VerifyingKey};
use std::{convert::TryFrom, net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{sleep, Duration},
};

use crate::state::{PlayerState, Shared};

/// Send a length-prefixed bincode message over a TCP stream.
async fn send_bin_tcp<T: serde::Serialize>(sock: &mut TcpStream, msg: &T) -> Result<()> {
    let bytes = bincode::serialize(msg).context("serialize send_bin_tcp")?;
    let len_le = (bytes.len() as u32).to_le_bytes();

    sock.write_all(&len_le).await.context("write len")?;
    sock.write_all(&bytes).await.context("write body")?;

    Ok(())
}

/// Receive a length-prefixed bincode message from a TCP stream.
async fn recv_bin_tcp<T: serde::de::DeserializeOwned>(sock: &mut TcpStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await.context("read len")?;
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf).await.context("read body")?;

    let msg = bincode::deserialize(&buf).context("bincode::deserialize")?;
    Ok(msg)
}

/// Local TCP listener that talks to a client instance (client-sim for now).
///
/// Responsibilities per client connection:
///  - wait until we actually have a current PlayTicket from VS
///  - send `ServerHello { session_id, ticket, vs_pub }`
///  - then in a loop:
///      * check for revocation via `revoke_rx`
///      * recv `ClientToGs::Input`
///      * verify ticket freshness / counter match
///      * enforce ticket.client_binding matches the sender pubkey
///      * enforce per-client monotonic nonce
///      * verify client's signature
///      * clamp movement
///      * update receipt_tip (transcript hash)
///      * reply with multi-entity `WorldSnapshot`
///
/// Trust model:
///  - GS trusts VS (PlayTicket, vs_pub)
///  - GS trusts only inputs that are (a) signed by that client key, (b) bound to a fresh ticket,
///    (c) monotonic nonce, (d) not revoked.
pub async fn client_port_task(
    shared: Shared,
    revoke_rx: watch::Receiver<bool>,
    ticket_rx: watch::Receiver<Option<PlayTicket>>,
) -> Result<()> {
    // Bind a local port for clients to connect (client-sim, future real client).
    let listener = TcpListener::bind("127.0.0.1:50000")
        .await
        .context("bind 127.0.0.1:50000")?;

    // Outer accept loop: one spawned task per client connection.
    'accept_loop: loop {
        let (mut socket, peer_addr): (TcpStream, SocketAddr) =
            listener.accept().await.context("accept client")?;
        println!("[GS] client connected from {}", peer_addr);

        // If we've already been revoked, just refuse immediately.
        if *revoke_rx.borrow() {
            eprintln!(
                "[GS] refusing client {}: session already revoked",
                peer_addr
            );
            continue 'accept_loop;
        }

        // Snapshot session_id and vs_pub exactly once for this client.
        let (session_id, vs_pub) = {
            let guard = shared.lock().unwrap();
            (guard.session_id, guard.vs_pub)
        };

        // Clone a local watch receiver for tickets so this client follows updates.
        // We will *wait* until we have a Some(PlayTicket) before proceeding.
        let mut local_ticket_rx = ticket_rx.clone();
        let first_ticket: PlayTicket = loop {
            if let Some(t) = local_ticket_rx.borrow().clone() {
                break t;
            }
            // wait for VS to send the first PlayTicket via ticket_listener()
            if local_ticket_rx.changed().await.is_err() {
                eprintln!("[GS] ticket_rx closed; shutting client_port_task listener");
                return Ok(());
            }
        };

        // Send initial ServerHello with the first ticket.
        let hello = ServerHello {
            session_id,
            ticket: first_ticket.clone(),
            vs_pub,
        };

        if let Err(e) = send_bin_tcp(&mut socket, &hello).await {
            eprintln!("[GS] send ServerHello to {} failed: {e:?}", peer_addr);
            continue 'accept_loop;
        }

        // Each client gets its own async task so we can go back to accept().
        let shared_cloned = shared.clone();
        let revoke_rx_client = revoke_rx.clone();
        let client_ticket_rx = local_ticket_rx; // moved into task
        let session_id_for_client = session_id;

        tokio::spawn(async move {
            let mut tick: u64 = 0;
            let mut socket = socket;

            loop {
                // Hard revoke? Kill client immediately.
                if *revoke_rx_client.borrow() {
                    eprintln!("[GS] closing client {} (revoked)", peer_addr);
                    break;
                }

                // Receive exactly one client message.
                let msg_res = recv_bin_tcp::<ClientToGs>(&mut socket).await;
                let ci = match msg_res {
                    Ok(ClientToGs::Input(ci)) => ci,
                    Err(e) => {
                        eprintln!("[GS] recv ClientInput error from {peer_addr}: {e:?}");
                        break;
                    }
                };

                // Grab the freshest VS ticket we have from VS.
                // (ticket_listener keeps this updated via watch channel.)
                let cur_ticket = match client_ticket_rx.borrow().clone() {
                    Some(t) => t,
                    None => {
                        eprintln!("[GS] lost VS ticket mid-session for {peer_addr}");
                        break;
                    }
                };

                let now_ms_val = now_ms();

                // -----------------------------------------------------------------
                // Do all validation, sim update, transcript update, and snapshot
                // BUILD inside a no-await block that holds the mutex.
                //
                // Return:
                //   Ok(snapshot) -> we send it to the client this tick
                //   Err(())      -> we drop the client
                // -----------------------------------------------------------------
                let step_res: Result<WorldSnapshot, ()> = (|| {
                    // Lock global GS state
                    let mut guard = shared_cloned.lock().unwrap();

                    // --- Phase 0: read current per-player state immutably ---
                    // We don't mutate yet, we just copy out for checks.
                    let (prev_x, prev_y, prev_nonce) = match guard.players.get(&ci.client_pub) {
                        Some(ps) => (ps.x, ps.y, ps.last_nonce),
                        None => (0.0, 0.0, 0),
                    };
                    let prev_tip = guard.receipt_tip;

                    // --------------------------
                    // Validation / auth checks
                    // --------------------------

                    // 1) ticket counter must match input's claimed counter
                    if ci.ticket_counter != cur_ticket.counter {
                        eprintln!(
                            "[GS] bad ticket_counter from {peer_addr} (got {}, expected {})",
                            ci.ticket_counter, cur_ticket.counter
                        );
                        return Err(());
                    }

                    // 2) ticket_sig_vs from client must match the VS-signed ticket
                    if ci.ticket_sig_vs != cur_ticket.sig_vs {
                        eprintln!("[GS] ticket_sig_vs mismatch from {peer_addr}");
                        return Err(());
                    }

                    // 3) ticket must be fresh: within not_before_ms .. not_after_ms
                    if now_ms_val < cur_ticket.not_before_ms || now_ms_val > cur_ticket.not_after_ms
                    {
                        eprintln!("[GS] stale/expired ticket from {peer_addr}");
                        return Err(());
                    }

                    // 4) session_id binding check
                    if ci.session_id != session_id_for_client
                        || cur_ticket.session_id != session_id_for_client
                    {
                        eprintln!("[GS] session_id mismatch from {peer_addr}");
                        return Err(());
                    }

                    // 5) enforce ticket.client_binding
                    //    [0u8;32] means "unbound / any client is OK".
                    if cur_ticket.client_binding != [0u8; 32]
                        && cur_ticket.client_binding != ci.client_pub
                    {
                        eprintln!(
                            "[GS] client_binding mismatch from {peer_addr} \
                             (ticket was not issued for this client_pub)"
                        );
                        return Err(());
                    }

                    // 6) anti-replay / ordering via monotonically increasing client_nonce,
                    //    but now PER CLIENT, not global.
                    if ci.client_nonce <= prev_nonce {
                        eprintln!(
                            "[GS] client_nonce non-monotonic from {peer_addr} (got {}, last {})",
                            ci.client_nonce, prev_nonce
                        );
                        return Err(());
                    }

                    // 7) verify client's signature over canonical tuple
                    //    sign_bytes = bincode( (session_id, ticket_counter, ticket_sig_vs, client_nonce, cmd) )
                    let sign_bytes = client_input_sign_bytes(
                        &ci.session_id,
                        ci.ticket_counter,
                        &ci.ticket_sig_vs,
                        ci.client_nonce,
                        &ci.cmd,
                    );

                    // Parse claimed client_pub
                    let client_vk = match VerifyingKey::from_bytes(&ci.client_pub) {
                        Ok(vk) => vk,
                        Err(e) => {
                            eprintln!("[GS] bad client_pub from {peer_addr}: {e:?}");
                            return Err(());
                        }
                    };

                    // Convert raw [u8;64] sig bytes to dalek Signature
                    let sig = match Signature::try_from(&ci.client_sig[..]) {
                        Ok(s) => s,
                        Err(_) => {
                            eprintln!("[GS] malformed client_sig from {peer_addr}");
                            return Err(());
                        }
                    };

                    if client_vk.verify_strict(&sign_bytes, &sig).is_err() {
                        eprintln!("[GS] client_sig verification failed from {peer_addr}");
                        return Err(());
                    }

                    // --------------------------
                    // Simulation step
                    // --------------------------
                    let (new_x, new_y) = match ci.cmd {
                        ClientCmd::Move { mut dx, mut dy } => {
                            // Clamp per-tick displacement to kill speed/teleport hacks.
                            const MAX_STEP: f32 = 1.0;
                            let mag2 = dx * dx + dy * dy;
                            if mag2 > (MAX_STEP * MAX_STEP) {
                                let mag = (mag2 as f64).sqrt() as f32;
                                if mag > 0.0 {
                                    let scale = MAX_STEP / mag;
                                    dx *= scale;
                                    dy *= scale;
                                }
                            }

                            let nx = prev_x + dx;
                            let ny = prev_y + dy;

                            println!(
                                "[GS] accepted Move {{ dx: {:.3}, dy: {:.3} }} \
                                 (nonce={}, ticket_ctr={}) from {peer_addr}",
                                dx, dy, ci.client_nonce, ci.ticket_counter
                            );

                            (nx, ny)
                        }
                    };

                    // --- Phase 1: write back player state (scoped mutable borrow of entry) ---
                    {
                        let entry = guard.players.entry(ci.client_pub).or_insert(PlayerState {
                            x: 0.0,
                            y: 0.0,
                            last_nonce: 0,
                        });
                        entry.x = new_x;
                        entry.y = new_y;
                        entry.last_nonce = ci.client_nonce;
                    }
                    // mutable borrow of that entry ends here

                    // --- Phase 2: update rolling transcript tip in shared state ---
                    // transcript_tip := sha256(prev_tip || bincode(ci))
                    let mut ci_bytes =
                        bincode::serialize(&ci).expect("serialize ClientInput in GS");
                    let mut both = Vec::with_capacity(prev_tip.len() + ci_bytes.len());
                    both.extend_from_slice(&prev_tip);
                    both.append(&mut ci_bytes);
                    let new_tip = sha256(&both);

                    guard.receipt_tip = new_tip;

                    // --- Phase 3: build multi-entity snapshot (you + others) ---
                    tick += 1;

                    let mut others: Vec<([u8; 32], f32, f32)> =
                        Vec::with_capacity(guard.players.len().saturating_sub(1));

                    for (pubkey, st) in guard.players.iter() {
                        if *pubkey != ci.client_pub {
                            others.push((*pubkey, st.x, st.y));
                        }
                    }

                    let snapshot = WorldSnapshot {
                        tick,
                        you: (new_x, new_y),
                        others,
                    };

                    Ok(snapshot)
                })(); // <- end of inner no-await block; mutex guard dropped here

                // If validation failed inside block, drop client.
                let snapshot = match step_res {
                    Ok(s) => s,
                    Err(()) => {
                        break;
                    }
                };

                // Send the authoritative snapshot back to the client.
                if let Err(e) = send_bin_tcp(&mut socket, &snapshot).await {
                    eprintln!("[GS] send WorldSnapshot to {peer_addr} failed: {e:?}");
                    break;
                }

                // tiny breather so a spammy client doesn't 100% busy-loop us
                sleep(Duration::from_millis(5)).await;
            }

            println!("[GS] client {} disconnected / recv error", peer_addr);
        });
    }
}
