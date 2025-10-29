use anyhow::{Context, Result};
use common::{
    crypto::{now_ms, sha256, verify},
    framing::recv_msg,
    proto::PlayTicket,
};
use ed25519_dalek::VerifyingKey;
use quinn::Connection;
use tokio::{
    sync::watch,
    time::{sleep, Duration},
};

use crate::state::Shared;

/// VS → GS ticket stream, plus revocation watchdog.
///
/// - Listens for PlayTicket bi-streams from VS.
/// - Verifies counters, hash chain, VS signature.
/// - Updates shared.latest_ticket and notifies listeners.
/// - Runs a watchdog: if no fresh ticket in ~2.5s, mark revoked and broadcast.
pub async fn ticket_listener(
    conn: Connection,
    shared: Shared,
    vs_pub: VerifyingKey,
    revoke_tx: watch::Sender<bool>,
    ticket_tx: watch::Sender<Option<PlayTicket>>,
) -> Result<()> {
    let mut last_counter: u64 = 0;
    let mut last_hash: [u8; 32] = [0u8; 32];

    // Watchdog marks revoked if we stop getting fresh tickets.
    {
        let shared_for_watchdog = shared.clone();
        let revoke_tx = revoke_tx.clone();
        tokio::spawn(async move {
            // how long we're allowed to go without a new ticket
            const LIVENESS_BUDGET_MS: u64 = 2_500;

            loop {
                sleep(Duration::from_millis(250)).await;

                // check liveness without holding mutex across await
                let (should_revoke, idle_ms) = {
                    let guard = shared_for_watchdog.lock().unwrap();
                    let last = guard.last_ticket_ms;
                    let now = now_ms();
                    let idle = now.saturating_sub(last);
                    let dead = last != 0 && idle > LIVENESS_BUDGET_MS;
                    (dead || guard.revoked, idle)
                };

                if should_revoke {
                    let mut guard = shared_for_watchdog.lock().unwrap();
                    if !guard.revoked {
                        guard.revoked = true;
                        eprintln!(
                            "[GS] VS blessing lost (no fresh ticket in {} ms) → session revoked",
                            idle_ms
                        );
                        let _ = revoke_tx.send(true);
                    }
                }
            }
        });
    }

    loop {
        // VS opens a bi-stream and sends us exactly one PlayTicket.
        let pair = conn.accept_bi().await;
        let (_send, mut recv) = match pair {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[GS] accept_bi error: {e:?}");
                break;
            }
        };

        let pt: PlayTicket = match recv_msg(&mut recv).await {
            Ok(pt) => pt,
            Err(e) => {
                eprintln!("[GS] bad ticket: {e:?}");
                continue;
            }
        };

        // 1) monotonic counter
        if pt.counter != last_counter + 1 {
            eprintln!(
                "[GS] ticket counter non-monotonic (got {}, expected {})",
                pt.counter,
                last_counter + 1
            );
            break;
        }

        // 2) hash chain continuity
        if pt.prev_ticket_hash != last_hash {
            eprintln!("[GS] ticket prev_hash mismatch");
            break;
        }

        // 3) VS signature check over the canonical tuple
        let body_tuple = (
            pt.session_id,
            pt.client_binding,
            pt.counter,
            pt.not_before_ms,
            pt.not_after_ms,
            pt.prev_ticket_hash,
        );
        let body_bytes = bincode::serialize(&body_tuple).context("ticket serialize")?;
        if !verify(&vs_pub, &body_bytes, &pt.sig_vs) {
            eprintln!("[GS] ticket sig_vs BAD");
            break;
        }

        // publish freshest ticket into shared + watchers
        let now = now_ms();
        {
            let mut guard = shared.lock().unwrap();
            guard.latest_ticket = Some(pt.clone());
            guard.last_ticket_ms = now;
            // once revoked=true we don't flip it back here
        }
        let _ = ticket_tx.send(Some(pt.clone()));

        println!("[GS] ticket #{} (time_ok=true)", pt.counter);

        last_counter = pt.counter;
        last_hash = sha256(&body_bytes);
    }

    Ok(())
}
