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

use crate::state::Shared;

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
///      * enforce nonce monotonicity
///      * verify client's signature
///      * update rolling receipt_tip (transcript hash)
///      * reply with `WorldSnapshot`
///
/// This task never trusts the transport. All trust comes from:
///  - VS-issued PlayTicket for liveness/blessing
///  - client-signed inputs (ed25519)
///  - monotonic nonces
///  - server-side sim & transcript hashing
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

        // Each client gets its own async task so we can go back to accept()
        let shared_cloned = shared.clone();
        let revoke_rx_client = revoke_rx.clone();
        let client_ticket_rx = local_ticket_rx; // move into task
        let session_id_for_client = session_id;
        tokio::spawn(async move {
            // tiny per-connection world state
            let mut player_x: f32 = 0.0;
            let mut player_y: f32 = 0.0;
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

                // Snapshot GS-shared info we need BEFORE we await anything else.
                // We DO NOT hold the lock across await.
                let (last_nonce_before, prev_tip) = {
                    let guard = shared_cloned.lock().unwrap();
                    (guard.last_client_nonce, guard.receipt_tip)
                };

                // Get freshest VS ticket (PlayTicket) to validate this input.
                let cur_ticket_opt = client_ticket_rx.borrow().clone();
                let cur_ticket = match cur_ticket_opt {
                    Some(t) => t,
                    None => {
                        eprintln!("[GS] lost VS ticket mid-session for {peer_addr}");
                        break;
                    }
                };

                let now_ms_val = now_ms();

                // 1) ticket counter must match input's claimed counter
                if ci.ticket_counter != cur_ticket.counter {
                    eprintln!(
                        "[GS] bad ticket_counter from {peer_addr} (got {}, expected {})",
                        ci.ticket_counter, cur_ticket.counter
                    );
                    break;
                }

                // 2) ticket_sig_vs from client must match the VS-signed ticket
                if ci.ticket_sig_vs != cur_ticket.sig_vs {
                    eprintln!("[GS] ticket_sig_vs mismatch from {peer_addr}");
                    break;
                }

                // 3) ticket must be fresh: within not_before_ms .. not_after_ms
                if now_ms_val < cur_ticket.not_before_ms || now_ms_val > cur_ticket.not_after_ms {
                    eprintln!("[GS] stale/expired ticket from {peer_addr}");
                    break;
                }

                // 4) session_id binding check
                if ci.session_id != session_id_for_client
                    || cur_ticket.session_id != session_id_for_client
                {
                    eprintln!("[GS] session_id mismatch from {peer_addr}");
                    break;
                }

                // 5) anti-replay / ordering via monotonically increasing client_nonce
                if ci.client_nonce <= last_nonce_before {
                    eprintln!(
                        "[GS] client_nonce non-monotonic from {peer_addr} (got {}, last {})",
                        ci.client_nonce, last_nonce_before
                    );
                    break;
                }

                // 6) verify client's signature over canonical tuple
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
                        break;
                    }
                };

                // Convert raw [u8;64] sig bytes to dalek Signature
                let sig = match Signature::try_from(&ci.client_sig[..]) {
                    Ok(s) => s,
                    Err(_) => {
                        eprintln!("[GS] malformed client_sig from {peer_addr}");
                        break;
                    }
                };

                if client_vk.verify_strict(&sign_bytes, &sig).is_err() {
                    eprintln!("[GS] client_sig verification failed from {peer_addr}");
                    break;
                }

                // If we got this far, input is considered valid & authorized.
                match ci.cmd {
                    ClientCmd::Move { dx, dy } => {
                        player_x += dx;
                        player_y += dy;
                        println!(
                            "[GS] accepted client input Move {{ dx: {dx}, dy: {dy} }} \
                             (nonce={}, ticket_ctr={}) from {peer_addr}",
                            ci.client_nonce, ci.ticket_counter
                        );
                    }
                }

                // 7) update rolling transcript tip + last_client_nonce in shared
                {
                    // transcript_tip := sha256(prev_tip || bincode(ci))
                    let mut ci_bytes = bincode::serialize(&ci).expect("serialize ClientInput");
                    let mut both = Vec::with_capacity(prev_tip.len() + ci_bytes.len());
                    both.extend_from_slice(&prev_tip);
                    both.append(&mut ci_bytes);
                    let new_tip = sha256(&both);

                    let mut guard = shared_cloned.lock().unwrap();
                    guard.receipt_tip = new_tip;
                    guard.last_client_nonce = ci.client_nonce;
                }

                // 8) respond with an updated WorldSnapshot back to this client
                tick += 1;
                let snapshot = WorldSnapshot {
                    session_id: session_id_for_client,
                    tick,
                    player_x,
                    player_y,
                };

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
