//! GS heartbeat & transcript attestation loop.
//!
//! - Heartbeats use a **unidirectional** stream (open_uni).
//! - TranscriptDigest/ProtectedReceipt round-trip still uses a bi-stream.
//! - We do **not** call `finish()`; we just drop the halves (best-effort).

pub async fn heartbeat_loop(
    conn: quinn::Connection,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    eph_sk: ed25519_dalek::SigningKey,
    session_id: [u8; 16],
    shared: crate::state::Shared,
) -> anyhow::Result<()> {
    use common::{
        crypto::{heartbeat_sign_bytes, now_ms, sign},
        framing::{recv_msg, send_msg},
        proto::{Heartbeat, ProtectedReceipt, TranscriptDigest},
    };
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::time::sleep;

    loop {
        // ~2s cadence
        sleep(Duration::from_secs(2)).await;

        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();

        // Snapshot state without holding mutex across awaits
        let (receipt_tip_now, sw_hash_now, positions_vec) = {
            let guard = match shared.lock() {
                Ok(g) => g,
                Err(p) => {
                    eprintln!("[GS] shared mutex poisoned in heartbeat_loop; using inner");
                    p.into_inner()
                }
            };
            let mut pos_out = Vec::with_capacity(guard.players.len());
            for (pubkey, ps) in guard.players.iter() {
                pos_out.push((*pubkey, ps.x, ps.y));
            }
            (guard.receipt_tip, guard.sw_hash, pos_out)
        };

        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip_now, &sw_hash_now);
        let sig_gs_bytes = sign(&eph_sk, &to_sign);

        // (1) HEARTBEAT — unidirectional stream
        match conn.open_uni().await {
            Ok(mut send) => {
                let hb = Heartbeat {
                    session_id,
                    gs_counter: c,
                    gs_time_ms: now,
                    receipt_tip: receipt_tip_now,
                    sw_hash: sw_hash_now,
                    sig_gs: sig_gs_bytes.to_vec(),
                };
                if let Err(e) = send_msg(&mut send, &hb).await {
                    eprintln!("[GS] heartbeat send failed: {e:?}");
                } else {
                    println!("[GS] \u{2665} heartbeat {c}");
                }
                // Drop send half (no finish)
            }
            Err(e) => {
                eprintln!("[GS] heartbeat open_uni failed: {e:?}");
                // keep looping; VS may be busy
            }
        }

        // (2) TRANSCRIPT DIGEST — bi-stream round trip
        match conn.open_bi().await {
            Ok((mut send2, mut recv2)) => {
                let td = TranscriptDigest {
                    session_id,
                    gs_counter: c,
                    receipt_tip: receipt_tip_now,
                    positions: positions_vec,
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
                                println!("[GS] VS ProtectedReceipt ok for counter {c}");
                            } else {
                                eprintln!("[GS] VS ProtectedReceipt mismatch at counter {c}");
                            }
                        }
                        Err(e) => {
                            eprintln!("[GS] transcript digest recv failed: {e:?}");
                        }
                    }
                }
                // Drop both halves
            }
            Err(e) => {
                eprintln!("[GS] transcript digest open_bi failed: {e:?}");
                // continue; heartbeats still flow
            }
        }
    }
}
