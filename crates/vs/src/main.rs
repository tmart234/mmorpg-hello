use anyhow::*;
use common::{
    crypto::{now_ms, rand_u128, sha256, sign, verify},
    framing::{recv_msg, send_msg},
    Heartbeat, JoinAccept, JoinRequest, PlayTicket,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::stream::StreamExt;
use quinn::{Endpoint, Incoming, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<()> {
    let (endpoint, mut incoming) = make_quic_server("0.0.0.0:4444").await?;
    let vs_sk = load_vs_signing_key("keys/vs_ed25519.pk8")?;

    println!("[VS] listening on 0.0.0.0:4444");
    let sessions: Arc<Mutex<HashMap<[u8;16], VerifyingKey>>> = Arc::new(Mutex::new(HashMap::new()));

    while let Some(conn) = incoming.next().await {
        let vs_sk = vs_sk.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(conn, vs_sk, sessions).await {
                eprintln!("[VS] connection error: {e:?}");
            }
        });
    }
    drop(endpoint);
    Ok(())
}

async fn handle_conn(connecting: quinn::Connecting, vs_sk: SigningKey, sessions: Arc<Mutex<HashMap<[u8;16], VerifyingKey>>>) -> Result<()> {
    let quinn::NewConnection { connection, mut bi_streams, .. } = connecting.await?;
    println!("[VS] new conn from {}", connection.remote_address());

    // 1) First stream must carry JoinRequest
    let (mut join_send, mut join_recv) = bi_streams.next().await.ok_or_else(|| anyhow!("no join stream"))??;
    let jr: JoinRequest = recv_msg(&mut join_recv).await?;
    verify_join(&jr)?;

    let session_id = rand_u128().to_le_bytes();
    {
        let mut map = sessions.lock().unwrap();
        let gs_pk = VerifyingKey::from_bytes(&jr.gs_pub)?;
        map.insert(session_id, gs_pk);
    }

    let now = now_ms();
    let ja = JoinAccept {
        session_id,
        ticket_key_id: 1,
        not_before_ms: now,
        not_after_ms: now + 3_600_000,
        sig_vs: sign(&vs_sk, &bincode::serialize(&(session_id, 1u32, now, now + 3_600_000)).unwrap()),
    };
    send_msg(&mut join_send, &ja).await?;

    // 2) Spawn PlayTicket loop
    let conn2 = connection.clone();
    tokio::spawn(async move { playticket_task(conn2, vs_sk, session_id).await });

    // 3) Heartbeat monitor: read subsequent bi-streams expecting Heartbeat
    let sessions_hb = sessions.clone();
    tokio::spawn(async move {
        if let Err(e) = heartbeat_task(connection, bi_streams, sessions_hb, session_id).await {
            eprintln!("[VS] heartbeat task error: {e:?}");
        }
    });

    Ok(())
}

async fn playticket_task(conn: quinn::Connection, vs_sk: SigningKey, session_id: [u8;16]) -> Result<()> {
    let mut prev = [0u8; 32];
    let mut counter: u64 = 0;
    loop {
        sleep(Duration::from_secs(2)).await;
        counter += 1;
        let now = now_ms();
        let mut pt = PlayTicket {
            session_id,
            client_binding: [0u8; 32],
            counter,
            not_before_ms: now - 500,
            not_after_ms: now + 2_500,
            prev_ticket_hash: prev,
            sig_vs: [0u8; 64],
        };
        let sign_bytes = bincode::serialize(&(pt.session_id, pt.client_binding, pt.counter, pt.not_before_ms, pt.not_after_ms, pt.prev_ticket_hash)).unwrap();
        pt.sig_vs = sign(&vs_sk, &sign_bytes);
        prev = sha256(&bincode::serialize(&pt).unwrap());

        if let Ok((mut send, _recv)) = conn.open_bi().await {
            let _ = send_msg(&mut send, &pt).await;
        }
    }
}

async fn heartbeat_task(
    connection: quinn::Connection,
    mut bi_streams: quinn::IncomingBiStreams,
    sessions: Arc<Mutex<HashMap<[u8;16], VerifyingKey>>>,
    session_id: [u8;16],
) -> Result<()> {
    let mut last_counter = 0u64;
    loop {
        tokio::select! {
            stream = bi_streams.next() => {
                let Some(stream) = stream else { break; };
                let (mut send, mut recv) = stream?;
                drop(send);
                let hb: Heartbeat = match recv_msg(&mut recv).await {
                    Ok(h) => h,
                    Err(e) => { eprintln!("[VS] heartbeat decode error: {e:?}"); continue; }
                };
                if hb.session_id != session_id { eprintln!("[VS] heartbeat wrong session"); continue; }

                // Verify signature with GS pubkey for this session
                let pk = {
                    let map = sessions.lock().unwrap();
                    map.get(&session_id).cloned().ok_or_else(|| anyhow!("session pk missing"))?
                };
                let to_sign = bincode::serialize(&(hb.session_id, hb.gs_counter, hb.gs_time_ms, hb.receipt_tip)).unwrap();
                if !verify(&pk, &to_sign, &hb.sig_gs) {
                    eprintln!("[VS] heartbeat signature invalid");
                    continue;
                }
                if hb.gs_counter <= last_counter {
                    eprintln!("[VS] heartbeat counter not increasing (last={}, got={})", last_counter, hb.gs_counter);
                    // here you could terminate the connection/session
                } else {
                    last_counter = hb.gs_counter;
                    // OK
                    // println!("[VS] ♥ {} from {}", hb.gs_counter, connection.remote_address());
                }
            }
            _ = sleep(Duration::from_secs(10)) => {
                // Heartbeats stalled
                eprintln!("[VS] heartbeat timeout; closing session {}", hex::encode(&session_id[..4]));
                connection.close(0u32.into(), b"heartbeat timeout");
                break;
            }
        }
    }
    Ok(())
}

async fn make_quic_server(bind: &str) -> Result<(Endpoint, Incoming)> {
    // Self-signed cert (dev)
    let cert = generate_simple_self_signed(vec!["vs.dev".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();

    let server_config = ServerConfig::with_single_cert(vec![quinn::rustls::Certificate(cert_der.clone())], quinn::rustls::PrivateKey(key_der))?;
    let mut endpoint = Endpoint::server(server_config, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), bind.split(':').nth(1).unwrap().parse()?))?;
    let incoming = endpoint.incoming();
    Ok((endpoint, incoming))
}

fn load_vs_signing_key(path: &str) -> Result<SigningKey> {
    let bytes = std::fs::read(path).context("read vs_ed25519.pk8")?;
    let arr: [u8;32] = bytes.try_into().map_err(|_| anyhow!("vs key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

fn verify_join(jr: &JoinRequest) -> Result<()> {
    // time skew check (±5m)
    let now = now_ms();
    if jr.t_unix_ms + 300_000 < now || now + 300_000 < jr.t_unix_ms {
        bail!("join request time skew too large");
    }
    // signature check
    let pk = VerifyingKey::from_bytes(&jr.gs_pub)?;
    let sign_bytes = bincode::serialize(&(jr.gs_id.as_str(), &jr.sw_hash, jr.t_unix_ms, &jr.nonce)).unwrap();
    if !verify(&pk, &sign_bytes, &jr.sig_gs) {
        bail!("bad join signature");
    }
    // allowlist (dev: accept all; wire in a file later)
    Ok(())
}
