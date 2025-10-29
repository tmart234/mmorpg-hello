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

pub async fn ticket_listener(
    conn: Connection,
    shared: Shared,
    vs_pub: VerifyingKey,
    revoke_tx: watch::Sender<bool>,
) -> Result<()> {
    let mut last_counter: u64 = 0;
    let mut last_hash: [u8; 32] = [0u8; 32];

    // watchdog for liveness / revocation
    {
        let shared_for_watchdog = shared.clone();
        let revoke_tx = revoke_tx.clone();
        tokio::spawn(async move {
            const LIVENESS_BUDGET_MS: u64 = 2_500;
            loop {
                sleep(Duration::from_millis(250)).await;

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

        // verify monotonic counter
        if pt.counter != last_counter + 1 {
            eprintln!(
                "[GS] ticket counter non-monotonic (got {}, expected {})",
                pt.counter,
                last_counter + 1
            );
            break;
        }

        // verify hash chain
        if pt.prev_ticket_hash != last_hash {
            eprintln!("[GS] ticket prev_hash mismatch");
            break;
        }

        // verify VS signature of ticket body
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

        let now = now_ms();

        // publish this as the latest valid ticket
        {
            let mut guard = shared.lock().unwrap();
            guard.latest_ticket = Some(pt.clone());
            guard.last_ticket_ms = now;
            // NOTE: once revoked, we do not auto-clear revoked here.
        }

        println!("[GS] ticket #{} (time_ok=true)", pt.counter);

        last_counter = pt.counter;
        last_hash = sha256(&body_bytes);
    }

    Ok(())
}
