use anyhow::Result;
use common::{
    crypto::{heartbeat_sign_bytes, now_ms, sign},
    framing::send_msg,
    proto::Heartbeat,
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

        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip_now);
        let sig_gs = sign(&eph_sk, &to_sign);

        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip: receipt_tip_now,
            sig_gs,
        };

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
    }

    Ok(())
}
