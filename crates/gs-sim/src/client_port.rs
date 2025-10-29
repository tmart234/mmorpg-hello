use anyhow::{Context, Result};
use common::{
    crypto::{now_ms, rolling_hash_update},
    proto::{ClientInput, ServerHello},
    tcp_framing::{tcp_recv_msg, tcp_send_msg},
};
use ed25519_dalek::{Signature, VerifyingKey};
use std::time::Duration;
use tokio::{
    net::TcpListener,
    sync::watch,
    time::{sleep, Instant},
};

use crate::state::Shared;

/// Handle a single local client (client-sim).
/// For now we accept exactly one connection for smoke.
pub async fn client_port_task(shared: Shared, revoke_rx: watch::Receiver<bool>) -> Result<()> {
    // listen on localhost:50000 for the local client-sim
    let listener = TcpListener::bind("127.0.0.1:50000")
        .await
        .context("bind client port 50000")?;

    // accept exactly one client for smoke test
    let (mut sock, peer_addr) = listener.accept().await.context("accept client-sim")?;
    println!("[GS] client connected from {}", peer_addr);

    // wait until we have at least one PlayTicket from VS
    let mut ticket;
    loop {
        {
            let guard = shared.lock().unwrap();
            if let Some(t) = guard.latest_ticket.clone() {
                ticket = t;
                break;
            }
        }
        sleep(Duration::from_millis(10)).await;
    }

    // Send initial ServerHello so the client knows:
    // - which session this GS thinks it's in
    // - the latest VS-blessed PlayTicket
    // - the VS long-term pubkey (so client can verify sig_vs)
    let sh = {
        let guard = shared.lock().unwrap();
        ServerHello {
            session_id: guard.session_id,
            ticket: ticket.clone(),
            vs_pub: guard.vs_pub,
        }
    };

    tcp_send_msg(&mut sock, &sh)
        .await
        .context("send ServerHello to client")?;

    // Track last-seen nonce so we can enforce strict monotonicity.
    // We'll also keep a local snapshot timestamp to occasionally refresh
    // our copy of the latest ticket from shared.
    let mut last_nonce: u64 = 0;
    let mut last_fresh_check = Instant::now();

    // Main per-client loop
    loop {
        // 0. Check global revocation. (ticket_listener watchdog flips this.)
        if *revoke_rx.borrow() {
            eprintln!("[GS] revoked; closing client socket");
            break;
        }

        // 1. Refresh latest ticket every ~100ms so we don't hold the lock constantly.
        if last_fresh_check.elapsed() >= Duration::from_millis(100) {
            if let Some(new_t) = {
                let guard = shared.lock().unwrap();
                guard.latest_ticket.clone()
            } {
                ticket = new_t;
            }
            last_fresh_check = Instant::now();
        }

        // 2. Refuse input if ticket is stale.
        //    If VS stops blessing us, ticket_listener will eventually mark revoked,
        //    but we also proactively stop honoring stale time windows here.
        let now = now_ms();
        let fresh = ticket.not_before_ms.saturating_sub(500) <= now
            && now <= ticket.not_after_ms.saturating_add(500);
        if !fresh {
            eprintln!("[GS] ticket stale; refusing further input");
            break;
        }

        // 3. Receive next ClientInput from this client.
        let ci_res: Result<ClientInput> = tcp_recv_msg(&mut sock).await.context("recv ClientInput");
        let ci = match ci_res {
            Ok(ci) => ci,
            Err(e) => {
                eprintln!("[GS] client disconnected / recv error: {e:?}");
                break;
            }
        };

        // 4. session must match what VS blessed in the ticket
        if ci.session_id != ticket.session_id {
            eprintln!("[GS] ClientInput wrong session_id");
            break;
        }

        // 5. stapled ticket info must match our latest ticket
        if ci.ticket_counter != ticket.counter {
            eprintln!(
                "[GS] ClientInput ticket_counter mismatch (got {}, want {})",
                ci.ticket_counter, ticket.counter
            );
            break;
        }
        if ci.ticket_sig_vs != ticket.sig_vs {
            eprintln!("[GS] ClientInput ticket_sig_vs mismatch");
            break;
        }

        // 6. client_nonce strictly increasing (anti-replay)
        if ci.client_nonce <= last_nonce {
            eprintln!(
                "[GS] ClientInput nonce not increasing (got {}, last {})",
                ci.client_nonce, last_nonce
            );
            break;
        }

        // 7. enforce binding if ticket declares a specific client
        if ticket.client_binding != [0u8; 32] && ci.client_pub != ticket.client_binding {
            eprintln!("[GS] client_binding mismatch: ticket was not issued for this client_pub");
            break;
        }

        // 8. Recompute the canonical body the client claims to have signed.
        //
        // IMPORTANT: we include &ci.ticket_sig_vs[..] as a slice.
        // Serde can't auto-Serialize [u8;64] in arbitrary tuples, but &[u8] is fine.
        //
        let sign_body = (
            ci.session_id,
            ci.ticket_counter,
            &ci.ticket_sig_vs[..],
            ci.client_nonce,
            &ci.cmd,
        );

        let sign_bytes = match bincode::serialize(&sign_body) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[GS] client sign_body serialize failed: {e:?}");
                break;
            }
        };

        // 9. Verify the client's ed25519 signature over that body.
        let client_vk = match VerifyingKey::from_bytes(&ci.client_pub) {
            Ok(vk) => vk,
            Err(e) => {
                eprintln!("[GS] bad client_pub: {e:?}");
                break;
            }
        };

        let client_sig = Signature::from_bytes(&ci.client_sig);
        if client_vk.verify_strict(&sign_bytes, &client_sig).is_err() {
            eprintln!("[GS] client_sig verification failed");
            break;
        }

        // 10. Promote this input:
        //     - record last_nonce (anti-replay)
        //     - roll forward receipt_tip, which is our transcript hash
        {
            let mut guard = shared.lock().unwrap();
            guard.last_client_nonce = ci.client_nonce;

            // rolling hash transcript tip:
            let new_tip = rolling_hash_update(guard.receipt_tip, &sign_bytes);
            guard.receipt_tip = new_tip;
        }
        last_nonce = ci.client_nonce;

        println!(
            "[GS] accepted client input {:?} (nonce={}, ticket_ctr={})",
            ci.cmd, ci.client_nonce, ci.ticket_counter
        );
    }

    Ok(())
}
