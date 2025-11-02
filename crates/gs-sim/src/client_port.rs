use anyhow::{Context, Result};
use common::{
    crypto::{client_input_sign_bytes, now_ms, receipt_tip_update},
    proto::{AuthoritativeEvent, ClientCmd, ClientToGs, PlayTicket, ServerHello, WorldSnapshot},
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
/// Security properties per client socket:
///  - client must staple a fresh VS-signed PlayTicket
///  - ticket must match our session / be within time window
///  - ticket.client_binding must match client_pub (if bound)
///  - client input must be signed with client_pub
///  - nonce must strictly increase per client_pub
///  - dx/dy is clamped server-side (anti-speedhack)
///  - we update per-player world state in shared memory
///  - we fold BOTH the ClientInput and an AuthoritativeEvent into receipt_tip
///  - we respond with a WorldSnapshot including you + others
///
/// When VS revokes us (or we miss tickets), we disconnect everyone.
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
        let (session_id, vs_pub_bytes) = {
            let guard = shared.lock().unwrap();
            (guard.session_id, guard.vs_pub.to_bytes())
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
            vs_pub: vs_pub_bytes,
        };

        if let Err(e) = send_bin_tcp(&mut socket, &hello).await {
            eprintln!("[GS] send ServerHello to {} failed: {e:?}", peer_addr);
            continue 'accept_loop;
        }

        // Each client gets its own async task so we can go back to accept()
        let shared_cloned = shared.clone();
        let revoke_rx_client = revoke_rx.clone();
        let session_id_for_client = session_id;

        tokio::spawn(async move {
            // per-connection tick counter for snapshots
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
                    Ok(ClientToGs::Input(ci)) => Some(ci),
                    Ok(ClientToGs::Bye) => {
                        println!("[GS] client {} said Bye; closing gracefully", peer_addr);
                        break;
                    }
                    Err(e) => {
                        eprintln!("[GS] recv ClientInput error from {peer_addr}: {e:?}");
                        break;
                    }
                };

                // If we didn’t get an Input (i.e., was Bye), end the loop.
                let ci = match ci {
                    Some(ci) => ci,
                    None => break,
                };

                let now_ms_val = now_ms();

                // === Everything that touches shared state lives in this block ===
                // We do NOT hold the mutex across an .await.
                let step_res: Result<WorldSnapshot, ()> = (|| {
                    // Snapshot GS-shared info we need BEFORE we await anything else.
                    let mut guard = shared_cloned.lock().unwrap();

                    // Phase 0: read current per-player state.
                    let (prev_x, prev_y, prev_nonce) = match guard.players.get(&ci.client_pub) {
                        Some(ps) => (ps.x, ps.y, ps.last_nonce),
                        None => (0.0, 0.0, 0),
                    };
                    let prev_tip = guard.receipt_tip;

                    // Grab current and previous tickets atomically.
                    let cur_ticket_opt = guard.latest_ticket.clone();
                    let prev_ticket_opt = guard.prev_ticket.clone();

                    // Helper to validate the stapled ticket against a candidate PlayTicket.
                    let ticket_matches = |pt: &PlayTicket| -> bool {
                        if now_ms_val < pt.not_before_ms || now_ms_val > pt.not_after_ms {
                            return false;
                        }
                        if pt.session_id != session_id_for_client {
                            return false;
                        }
                        if pt.client_binding != [0u8; 32] && pt.client_binding != ci.client_pub {
                            return false;
                        }
                        if ci.ticket_counter != pt.counter {
                            return false;
                        }
                        if ci.ticket_sig_vs != pt.sig_vs {
                            return false;
                        }
                        true
                    };

                    // ---- 1) ticket validation with rollover grace (current OR previous) ----
                    let using_prev_ticket = match cur_ticket_opt {
                        Some(ref cur) if ticket_matches(cur) => false,
                        Some(_) => {
                            if let Some(ref prev) = prev_ticket_opt {
                                if ticket_matches(prev) {
                                    true
                                } else {
                                    eprintln!(
                                        "[GS] ticket mismatch from {peer_addr} (neither current nor previous valid)"
                                    );
                                    return Err(());
                                }
                            } else {
                                eprintln!(
                                    "[GS] ticket mismatch from {peer_addr} (no previous ticket to grace)"
                                );
                                return Err(());
                            }
                        }
                        None => {
                            eprintln!("[GS] no current VS ticket available");
                            return Err(());
                        }
                    };

                    // ---- 2) anti-replay / ordering via monotonically increasing client_nonce ----
                    if ci.client_nonce <= prev_nonce {
                        eprintln!(
                            "[GS] client_nonce non-monotonic from {peer_addr} (got {}, last {})",
                            ci.client_nonce, prev_nonce
                        );
                        return Err(());
                    }

                    // ---- 3) verify client's signature over canonical tuple ----
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

                    // ---- 4) simulation step ----
                    // clamp movement, apply to per-player world state
                    let (new_x, new_y) = match ci.cmd {
                        ClientCmd::Move { mut dx, mut dy } => {
                            // per-tick displacement cap (anti-speedhack / anti-teleport)
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
                                 (nonce={}, ticket_ctr={}, used_prev_ticket={}) from {peer_addr}",
                                dx, dy, ci.client_nonce, ci.ticket_counter, using_prev_ticket
                            );

                            (nx, ny)
                        }
                    };

                    // advance world tick
                    let new_tick = tick + 1;

                    // write back player state
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

                    // Build an authoritative event for the transcript.
                    // This is "what the GS actually says happened."
                    let ev = AuthoritativeEvent::MoveResolved {
                        who: ci.client_pub,
                        x: new_x,
                        y: new_y,
                        tick: new_tick,
                    };

                    // ---- 5) update rolling transcript tip + save it in shared ----
                    let ci_bytes = bincode::serialize(&ci).expect("serialize ClientInput in GS");
                    let ev_bytes =
                        bincode::serialize(&ev).expect("serialize AuthoritativeEvent in GS");

                    let new_tip = receipt_tip_update(&prev_tip, &ci_bytes, &ev_bytes);
                    guard.receipt_tip = new_tip;

                    // update local tick counter
                    tick = new_tick;

                    // ---- 6) prepare WorldSnapshot ----
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
                })(); // drop mutex guard here

                // If validation or sim failed, kill client.
                let snapshot = match step_res {
                    Ok(s) => s,
                    Err(()) => {
                        break;
                    }
                };

                // Respond with an updated WorldSnapshot back to this client
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
