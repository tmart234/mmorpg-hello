use anyhow::Result;
use common::{
    crypto::{heartbeat_sign_bytes, now_ms, sign},
    framing::{recv_msg, send_msg},
    proto::{Heartbeat, ProtectedReceipt, TranscriptDigest},
};
use ed25519_dalek::SigningKey;
use quinn::Connection;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::time::sleep;

use crate::state::Shared;

/// Periodic GS → VS liveness + transcript attestation.
pub async fn heartbeat_loop(
    conn: Connection,
    counter: Arc<AtomicU64>,
    eph_sk: SigningKey,
    session_id: [u8; 16],
    shared: Shared,
) -> Result<()> {
    loop {
        sleep(Duration::from_secs(2)).await;

        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();

        // snapshot current receipt_tip from shared
        let receipt_tip_now = {
            let guard = shared.lock().unwrap();
            guard.receipt_tip
        };

        // sign heartbeat payload with the ephemeral per-session key
        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip_now);
        let sig_gs = sign(&eph_sk, &to_sign);

        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip: receipt_tip_now,
            sig_gs,
        };

        // send Heartbeat on its own bi-stream
        let pair = conn.open_bi().await;
        let (mut send, _recv) = match pair {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[GS] heartbeat open_bi failed: {e:?}");
                break;
            }
        };

        if let Err(e) = send_msg(&mut send, &hb).await {
            eprintln!("[GS] heartbeat send failed: {e:?}");
        } else {
            println!("[GS] ♥ heartbeat {}", c);
        }

        // also send TranscriptDigest -> expect ProtectedReceipt
        let pair2 = conn.open_bi().await;
        match pair2 {
            Ok((mut send2, mut recv2)) => {
                let td = TranscriptDigest {
                    session_id,
                    gs_counter: c,
                    receipt_tip: receipt_tip_now,
                };

                if let Err(e) = send_msg(&mut send2, &td).await {
                    eprintln!("[GS] transcript digest send failed: {e:?}");
                } else {
                    match recv_msg::<ProtectedReceipt>(&mut recv2).await {
                        Ok(pr) => {
                            if pr.session_id == session_id
                                && pr.gs_counter == c
                                && pr.receipt_tip == receipt_tip_now
                            {
                                println!("[GS] VS ProtectedReceipt ok for counter {}", c);
                            } else {
                                eprintln!("[GS] VS ProtectedReceipt mismatch at counter {}", c);
                            }
                        }
                        Err(e) => {
                            eprintln!("[GS] transcript digest recv failed: {e:?}");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[GS] transcript digest open_bi failed: {e:?}");
            }
        }
    }

    Ok(())
}
