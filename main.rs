//! gs-sim: minimal untrusted Game Server simulator
//! - Attests its binary hash (dev-level)
//! - Joins VS
//! - Sends signed heartbeats
//! - Listens for PlayTickets

use anyhow::*;
use clap::Parser;
use common::{
    crypto::{
        file_sha256, heartbeat_sign_bytes, join_request_sign_bytes, now_ms, sha256, sign, verify,
    },
    framing::{recv_msg, send_msg},
    Heartbeat, JoinAccept, JoinRequest, PlayTicket, PubKey, Sig,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{ClientConfig, Endpoint};
use rand::{rngs::OsRng, RngCore};
use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::sleep;

#[derive(Parser, Debug)]
struct Opts {
    /// VS address (ip:port)
    #[arg(long, default_value = "127.0.0.1:4444")]
    vs: String,

    /// One-shot test: exit after first join + heartbeat + ticket
    #[arg(long)]
    test_once: bool,

    /// GS ID label
    #[arg(long, default_value = "gs-sim-local")]
    gs_id: String,

    /// Path to GS ed25519 private key (generated if missing)
    #[arg(long, default_value = "keys/gs_ed25519.pk8")]
    gs_sk: String,
    /// Path to GS ed25519 public key (generated if missing)
    #[arg(long, default_value = "keys/gs_ed25519.pub")]
    gs_pk: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // Load or generate GS keypair
    let (gs_sk, gs_pk) = load_or_make_keys(&opts.gs_sk, &opts.gs_pk)?;

    // Compute a dev-level "attestation" hash of this binary
    let exe = std::env::current_exe()?;
    let sw_hash = file_sha256(&exe)?;

    // QUIC client endpoint (dev: permissive cert verify)
    let (endpoint, server_addr) = make_endpoint_and_addr(&opts.vs).await?;

    // Connect to VS
    let conn = endpoint
        .connect_with(make_client_cfg_insecure()?, server_addr, "vs.dev")?
        .await?;
    println!("[GS] connected to VS at {server_addr}");

    // 1) Send JoinRequest on a fresh bi-stream
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let join_sig_bytes = join_request_sign_bytes(&opts.gs_id, &sw_hash, now_ms(), &nonce);
    let sig_gs: Sig = sign(&gs_sk, &join_sig_bytes);

    let jr = JoinRequest {
        gs_id: opts.gs_id.clone(),
        sw_hash,
        t_unix_ms: now_ms(),
        nonce,
        sig_gs,
        gs_pub: gs_pk.to_bytes(),
    };

    let (mut jsend, mut jrecv) = conn.open_bi().await?;
    send_msg(&mut jsend, &jr).await?;
    let ja: JoinAccept = recv_msg(&mut jrecv).await?;
    println!(
        "[GS] joined. session_id={}.., valid {}..{}",
        hex::encode(&ja.session_id[..4]),
        ja.not_before_ms,
        ja.not_after_ms
    );

    // 2) Spawn heartbeat loop
    let hb_counter = Arc::new(AtomicU64::new(0));
    let hb_task = tokio::spawn(heartbeat_loop(
        conn.clone(),
        hb_counter.clone(),
        &gs_sk,
        ja.session_id,
    ));

    // 3) Listen for PlayTickets (server-initiated streams)
    let ticket_task = tokio::spawn(ticket_listener(conn.clone()));

    if opts.test_once {
        // Allow a couple of heartbeats/tickets then exit
        sleep(Duration::from_secs(5)).await;
        println!("[GS] test_once complete.");
        return Ok(());
    }

    // Keep running
    tokio::try_join!(hb_task, ticket_task).map(|_| ())
}

async fn heartbeat_loop(
    conn: quinn::Connection,
    counter: Arc<AtomicU64>,
    gs_sk: &SigningKey,
    session_id: [u8; 16],
) -> Result<()> {
    let mut receipt_tip = [0u8; 32]; // none yet
    loop {
        sleep(Duration::from_secs(2)).await;
        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();
        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip);
        let sig_gs = sign(gs_sk, &to_sign);
        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip,
            sig_gs,
        };
        let (mut send, _recv) = conn.open_bi().await?;
        if let Err(e) = send_msg(&mut send, &hb).await {
            eprintln!("[GS] heartbeat send failed: {e:?}");
        } else {
            println!("[GS] ♥ heartbeat {}", c);
        }
    }
}

async fn ticket_listener(conn: quinn::Connection) -> Result<()> {
    let mut incoming = conn.accept_bi();
    loop {
        match incoming.await {
            Ok(Some((mut send, mut recv))) => {
                drop(send); // not replying on this stream
                match recv_msg::<PlayTicket>(&mut recv).await {
                    Ok(pt) => {
                        let ok_time =
                            pt.not_before_ms.saturating_sub(500) <= now_ms()
                                && now_ms() <= pt.not_after_ms.saturating_add(500);
                        println!(
                            "[GS] ticket #{} (time_ok={})",
                            pt.counter, ok_time
                        );
                    }
                    Err(e) => {
                        eprintln!("[GS] bad ticket: {e:?}");
                    }
                }
                incoming = conn.accept_bi(); // continue loop
            }
            Ok(None) => {
                eprintln!("[GS] VS closed connection.");
                break;
            }
            Err(e) => {
                eprintln!("[GS] accept_bi error: {e:?}");
                break;
            }
        }
    }
    Ok(())
}

/// Load ed25519 keypair from disk or create new.
fn load_or_make_keys(sk_path: &str, pk_path: &str) -> Result<(SigningKey, VerifyingKey)> {
    let skp = PathBuf::from(sk_path);
    let pkp = PathBuf::from(pk_path);
    if skp.exists() && pkp.exists() {
        let sk_bytes = std::fs::read(&skp)?;
        let pk_bytes = std::fs::read(&pkp)?;
        let sk = SigningKey::from_bytes(
            &sk_bytes
                .try_into()
                .map_err(|_| anyhow!("sk length != 32"))?,
        );
        let pk = VerifyingKey::from_bytes(
            &pk_bytes
                .try_into()
                .map_err(|_| anyhow!("pk length != 32"))?,
        )?;
        Ok((sk, pk))
    } else {
        std::fs::create_dir_all("keys")?;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        std::fs::write(&skp, sk.to_bytes())?;
        std::fs::write(&pkp, pk.to_bytes())?;
        println!(
            "[GS] generated dev keypair at {}, {}",
            skp.display(),
            pkp.display()
        );
        Ok((sk, pk))
    }
}

/// Dev-only: accept any server cert. Replace with proper pinning once VS serves a real cert.
fn make_client_cfg_insecure() -> Result<ClientConfig> {
    use rustls::{
        client::{ServerCertVerified, ServerCertVerifier},
        Certificate, ClientConfig as RustlsClientConfig, DigitallySignedStruct, ServerName,
    };
    use std::{sync::Arc, time::SystemTime};

    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: SystemTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &Certificate,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &Certificate,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
    }

    let mut cfg = RustlsClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.enable_early_data = true;
    Ok(ClientConfig::new(Arc::new(cfg)))
}

async fn make_endpoint_and_addr(vs: &str) -> Result<(Endpoint, SocketAddr)> {
    // Bind an ephemeral UDP port (IPv6 dual-stack OK)
    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
    let endpoint = Endpoint::client(bind_addr)?;
    let server_addr: SocketAddr = vs
        .parse()
        .with_context(|| format!("bad vs address: {vs}"))?;
    Ok((endpoint, server_addr))
}
