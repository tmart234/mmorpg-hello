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
/// - Sends a Heartbeat proving "I'm alive, here's my counter/time/tip"
/// - Sends a TranscriptDigest proving "this is the sim transcript tip I'm claiming"
///   and expects a ProtectedReceipt (VS-signed acknowledgment).
pub async fn heartbeat_loop(
    conn: Connection,
    counter: Arc<AtomicU64>,
    eph_sk: SigningKey,
    session_id: [u8; 16],
    shared: Shared,
) -> Result<()> {
    loop {
        // ~2s cadence
        sleep(Duration::from_secs(2)).await;

        // Monotonic counter for heartbeats
        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();

        // Snapshot the rolling "receipt_tip" hash that summarizes GS transcript so far
        let receipt_tip_now = {
            let guard = match shared.lock() {
                Ok(g) => g,
                Err(poison) => {
                    eprintln!(
                        "[GS] shared mutex poisoned in heartbeat_loop; continuing with inner state"
                    );
                    poison.into_inner()
                }
            };
            guard.receipt_tip
        };

        // Canonical bytes we sign for Heartbeat:
        // (session_id, gs_counter, gs_time_ms, receipt_tip)
        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip_now);

        // Per-session ephemeral key signs this heartbeat (NOT the long-term GS key!)
        let sig_gs_bytes = sign(&eph_sk, &to_sign); // [u8; 64]

        // Build the Heartbeat message we'll send to VS.
        // Heartbeat.sig_gs is Vec<u8>, so convert.
        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip: receipt_tip_now,
            sig_gs: sig_gs_bytes.to_vec(),
        };

        // ---- 1) Send Heartbeat on its own bi-stream ----
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

        // ---- 2) Send TranscriptDigest and expect ProtectedReceipt back ----
        let pair2 = conn.open_bi().await;
        match pair2 {
            Ok((mut send2, mut recv2)) => {
                // What GS claims its authoritative transcript tip is at counter c
                let td = TranscriptDigest {
                    session_id,
                    gs_counter: c,
                    receipt_tip: receipt_tip_now,
                };

                if let Err(e) = send_msg(&mut send2, &td).await {
                    eprintln!("[GS] transcript digest send failed: {e:?}");
                } else {
                    // VS should reply on that same stream with a ProtectedReceipt
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
