use anyhow::*;
use common::{
    crypto::{now_ms, rand_u128, sha256, sign, verify},
    proto::{Heartbeat, JoinAccept, JoinRequest, PlayTicket},
};
use futures::stream::StreamExt;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{Endpoint, Incoming, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;

/// ---- simple len-prefixed bincode framing (matches gs-sim) ----
async fn send_bincode<T: serde::Serialize>(s: &mut quinn::SendStream, v: &T) -> Result<()> {
    let body = bincode::serialize(v)?;
    s.write_all(&(body.len() as u32).to_be_bytes()).await?;
    s.write_all(&body).await?;
    s.finish().await?;
    Ok(())
}
async fn recv_bincode<T: serde::de::DeserializeOwned>(r: &mut quinn::RecvStream) -> Result<T> {
    use tokio::io::AsyncReadExt;
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(bincode::deserialize(&body)?)
}

/// ---- VS main ----
#[tokio::main]
async fn main() -> Result<()> {
    let (endpoint, mut incoming) = make_quic_server("0.0.0.0:4444").await?;
    let vs_sk = load_vs_signing_key("keys/vs_ed25519.pk8")
        .context("missing keys/vs_ed25519.pk8 (run tools/gen_keys first)")?;

    println!("[VS] listening on 0.0.0.0:4444");

    // session_id -> GS verifying key
    let sessions: Arc<Mutex<HashMap<[u8; 16], VerifyingKey>>> =
        Arc::new(Mutex::new(HashMap::new()));

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

async fn handle_conn(
    connecting: quinn::Connecting,
    vs_sk: SigningKey,
    sessions: Arc<Mutex<HashMap<[u8; 16], VerifyingKey>>>,
) -> Result<()> {
    let quinn::NewConnection {
        connection,
        mut bi_streams,
        ..
    } = connecting.await?;
    println!("[VS] new conn from {}", connection.remote_address());

    // 1) First stream: JoinRequest
    let (mut jsend, mut jrecv) = bi_streams
        .next()
        .await
        .ok_or_else(|| anyhow!("no join stream"))??;

    let jr: JoinRequest = recv_bincode(&mut jrecv).await?;
    verify_join(&jr)?;

    let session_id = rand_u128().to_le_bytes();
    {
        let mut m = sessions.lock().unwrap();
        let gs_pk = VerifyingKey::from_bytes(&jr.gs_pub)?;
        m.insert(session_id, gs_pk);
    }

    let now = now_ms();
    let ja = JoinAccept {
        session_id,
        ticket_key_id: 1,
        not_before_ms: now,
        not_after_ms: now + 3_600_000,
        sig_vs: sign(
            &vs_sk,
            &bincode::serialize(&(session_id, 1u32, now, now + 3_600_000)).unwrap(),
        ),
    };
    send_bincode(&mut jsend, &ja).await?;

    // 2) PlayTicket task
    let conn_tickets = connection.clone();
    tokio::spawn(async move { let _ = playticket_task(conn_tickets, vs_sk, session_id).await; });

    // 3) Heartbeat monitor
    tokio::spawn(heartbeat_task(
        connection,
        bi_streams,
        sessions.clone(),
        session_id,
    ));

    Ok(())
}

async fn playticket_task(
    conn: quinn::Connection,
    vs_sk: SigningKey,
    session_id: [u8; 16],
) -> Result<()> {
    let mut prev = [0u8; 32];
    let mut counter = 0u64;
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
        let sign_bytes = bincode::serialize(&(
            pt.session_id,
            pt.client_binding,
            pt.counter,
            pt.not_before_ms,
            pt.not_after_ms,
            pt.prev_ticket_hash,
        ))
        .unwrap();
        pt.sig_vs = sign(&vs_sk, &sign_bytes);
        prev = sha256(&bincode::serialize(&pt).unwrap());

        if let Ok((mut send, _)) = conn.open_bi().await {
            let _ = send_bincode(&mut send, &pt).await;
        }
    }
}

async fn heartbeat_task(
    connection: quinn::Connection,
    mut bi_streams: quinn::IncomingBiStreams,
    sessions: Arc<Mutex<HashMap<[u8; 16], VerifyingKey>>>,
    session_id: [u8; 16],
) {
    let mut last = 0u64;
    loop {
        tokio::select! {
            biased;

            stream = bi_streams.next() => {
                let Some(stream) = stream else { break; };
                let (mut send, mut recv) = match stream {
                    Ok(s) => s, Err(_) => break
                };
                drop(send);
                let hb: Result<Heartbeat> = recv_bincode(&mut recv).await;
                let Ok(hb) = hb else { continue; };

                if hb.session_id != session_id { continue; }
                let pk = {
                    let m = sessions.lock().unwrap();
                    match m.get(&session_id) { Some(pk)=>pk.clone(), None => continue }
                };

                let sign_bytes = bincode::serialize(&(hb.session_id, hb.gs_counter, hb.gs_time_ms, hb.receipt_tip)).unwrap();
                if !verify(&pk, &sign_bytes, &hb.sig_gs) {
                    eprintln!("[VS] heartbeat signature invalid");
                    continue;
                }
                if hb.gs_counter <= last {
                    eprintln!("[VS] heartbeat counter not increasing (last={}, got={})", last, hb.gs_counter);
                    connection.close(0u32.into(), b"counter violation");
                    break;
                }
                last = hb.gs_counter;
            }

            _ = sleep(Duration::from_secs(10)) => {
                eprintln!("[VS] heartbeat timeout; closing");
                connection.close(0u32.into(), b"heartbeat timeout");
                break;
            }
        }
    }
}

async fn make_quic_server(bind: &str) -> Result<(Endpoint, Incoming)> {
    // self-signed dev cert; GS uses "insecure" mode in dev
    let cert = generate_simple_self_signed(vec!["vs.dev".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();
    let server_config = quinn::ServerConfig::with_single_cert(
        vec![quinn::rustls::Certificate(cert_der)],
        quinn::rustls::PrivateKey(key_der),
    )?;
    let addr: SocketAddr = bind.parse().context("bind addr parse")?;
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok((endpoint, endpoint.incoming()))
}

fn load_vs_signing_key(path: &str) -> Result<SigningKey> {
    let bytes = std::fs::read(path)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("vs key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

fn verify_join(jr: &JoinRequest) -> Result<()> {
    // time window ±5min
    let now = now_ms();
    if jr.t_unix_ms + 300_000 < now || now + 300_000 < jr.t_unix_ms {
        bail!("join time skew too large");
    }
    // signature
    let pk = VerifyingKey::from_bytes(&jr.gs_pub)?;
    let sign_bytes =
        bincode::serialize(&(jr.gs_id.as_str(), &jr.sw_hash, jr.t_unix_ms, &jr.nonce)).unwrap();
    if !verify(&pk, &sign_bytes, &jr.sig_gs) {
        bail!("bad join signature");
    }
    // allowlist placeholder (accept all for now)
    Ok(())
}
