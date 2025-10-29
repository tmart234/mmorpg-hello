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

/// Periodic GS → VS liveness + transcript attestation + runtime attestation.
///
/// We send:
///   Heartbeat {
///       session_id,
///       gs_counter,
///       gs_time_ms,
///       receipt_tip,
///       sw_hash,    // prove we didn't hotpatch
///       sig_gs,
///   }
///
/// Then we also send:
///   TranscriptDigest {
///       session_id,
///       gs_counter,
///       receipt_tip,
///       positions: Vec<(client_pub, x, y)>,
///   }
///
/// VS can:
///  - kill us if sw_hash doesn't match approved code
///  - kill us if movement looks physically impossible
///  - sign back a ProtectedReceipt so we can't deny our transcript later
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

        // Snapshot GS shared state (no await while holding lock)
        let (receipt_tip_now, sw_hash_now, positions_vec) = {
            let guard = match shared.lock() {
                Ok(g) => g,
                Err(poison) => {
                    eprintln!(
                        "[GS] shared mutex poisoned in heartbeat_loop; continuing with inner state"
                    );
                    poison.into_inner()
                }
            };

            // Snapshot of all player positions for VS invariant checks
            let mut pos_out = Vec::with_capacity(guard.players.len());
            for (pubkey, ps) in guard.players.iter() {
                pos_out.push((*pubkey, ps.x, ps.y));
            }

            (guard.receipt_tip, guard.sw_hash, pos_out)
        };

        // Canonical bytes we sign for Heartbeat:
        // (session_id, gs_counter, gs_time_ms, receipt_tip, sw_hash)
        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip_now, &sw_hash_now);

        // Per-session ephemeral key signs this heartbeat
        let sig_gs_bytes = sign(&eph_sk, &to_sign); // [u8; 64]

        // Build the Heartbeat message we'll send to VS.
        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip: receipt_tip_now,
            sw_hash: sw_hash_now,
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
                // What GS claims its authoritative transcript tip and positions are
                let td = TranscriptDigest {
                    session_id,
                    gs_counter: c,
                    receipt_tip: receipt_tip_now,
                    positions: positions_vec,
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
