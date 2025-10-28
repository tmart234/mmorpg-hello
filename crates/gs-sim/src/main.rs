//! gs-sim: minimal untrusted Game Server simulator
//! - Attests its binary hash (dev-level)
//! - Joins VS
//! - Sends signed heartbeats
//! - Listens for PlayTickets

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use common::{
    crypto::{file_sha256, heartbeat_sign_bytes, join_request_sign_bytes, now_ms, sign},
    framing::{recv_msg, send_msg},
    proto::{Heartbeat, JoinAccept, JoinRequest, PlayTicket, Sig},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{ClientConfig, Connection, Endpoint};
use rand::{rngs::OsRng, RngCore};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::sleep; // for hex::encode

#[derive(Parser, Debug)]
struct Opts {
    /// VS address (ip:port)
    #[arg(long, default_value = "127.0.0.1:4444")]
    vs: String,

    /// Exit after first join/heartbeat/ticket
    #[arg(long)]
    test_once: bool,

    /// Logical GS ID label
    #[arg(long, default_value = "gs-sim-local")]
    gs_id: String,

    /// Paths to GS keypair
    #[arg(long, default_value = "keys/gs_ed25519.pk8")]
    gs_sk: String,
    #[arg(long, default_value = "keys/gs_ed25519.pub")]
    gs_pk: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // Load or generate GS signing keypair
    let (gs_sk, gs_pk) = load_or_make_keys(&opts.gs_sk, &opts.gs_pk)?;

    // Compute a dev "attestation" hash of this binary
    let exe = std::env::current_exe()?;
    let sw_hash = file_sha256(&exe)?;

    // Create a QUIC client Endpoint + connect to VS
    let (endpoint, server_addr) = make_endpoint_and_addr(&opts.vs)?;
    let conn: Connection = endpoint
        .connect_with(make_client_cfg_insecure()?, server_addr, "vs.dev")?
        .await?; // <-- unwrap Result<Connection, ConnectionError>
    println!("[GS] connected to VS at {server_addr}");

    // ---- Send JoinRequest on a fresh bi-stream ----
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let now = now_ms();
    let to_sign = join_request_sign_bytes(&opts.gs_id, &sw_hash, now, &nonce);
    let sig_gs: Sig = sign(&gs_sk, &to_sign);

    let jr = JoinRequest {
        gs_id: opts.gs_id.clone(),
        sw_hash,
        t_unix_ms: now,
        nonce,
        sig_gs,
        gs_pub: gs_pk.to_bytes(),
    };

    let (mut jsend, mut jrecv) = conn.open_bi().await?;
    send_msg(&mut jsend, &jr).await?;
    let ja: JoinAccept = recv_msg(&mut jrecv).await?;
    println!(
        "[GS] joined. session_id={}.. (vs sig ok = {} bytes)",
        hex::encode(&ja.session_id[..4]),
        ja.sig_vs.len()
    );

    // ---- Background tasks ----
    let hb_counter = Arc::new(AtomicU64::new(0));
    let hb_task = tokio::spawn(heartbeat_loop(
        conn.clone(),
        hb_counter.clone(),
        gs_sk.clone(),
        ja.session_id,
    ));

    let ticket_task = tokio::spawn(ticket_listener(conn.clone()));

    if opts.test_once {
        // let a couple heartbeats/tickets flow then exit
        sleep(Duration::from_secs(5)).await;
        println!("[GS] test_once complete.");
        return Ok(());
    }

    // main task just hangs out while background tasks run;
    // if either dies, bail.
    loop {
        sleep(Duration::from_secs(60)).await;
        if hb_task.is_finished() || ticket_task.is_finished() {
            eprintln!("[GS] background task ended, exiting main loop");
            break;
        }
    }

    Ok(())
}

async fn heartbeat_loop(
    conn: Connection,
    counter: Arc<AtomicU64>,
    gs_sk: SigningKey,
    session_id: [u8; 16],
) -> Result<()> {
    let receipt_tip = [0u8; 32]; // no receipts yet

    loop {
        sleep(Duration::from_secs(2)).await;

        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();

        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip);
        let sig_gs = sign(&gs_sk, &to_sign);

        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip,
            sig_gs,
        };

        // open a new bi-stream for each heartbeat
        let pair = conn.open_bi().await;
        if let Err(e) = pair {
            eprintln!("[GS] heartbeat open_bi failed: {e:?}");
            break;
        }
        let (mut send, _recv) = pair.unwrap();

        if let Err(e) = send_msg(&mut send, &hb).await {
            eprintln!("[GS] heartbeat send failed: {e:?}");
        } else {
            println!("[GS] ♥ heartbeat {}", c);
        }
    }

    Ok(())
}

async fn ticket_listener(conn: Connection) -> Result<()> {
    loop {
        let pair = conn.accept_bi().await;
        if let Err(e) = pair {
            eprintln!("[GS] accept_bi error: {e:?}");
            break;
        }

        let (send, mut recv) = pair.unwrap();
        drop(send);
        let pt_res = recv_msg::<PlayTicket>(&mut recv).await;
        match pt_res {
            Ok(pt) => {
                let now = now_ms();
                let ok_time = pt.not_before_ms.saturating_sub(500) <= now
                    && now <= pt.not_after_ms.saturating_add(500);
                println!("[GS] ticket #{} (time_ok={})", pt.counter, ok_time);
            }
            Err(e) => {
                eprintln!("[GS] bad ticket: {e:?}");
            }
        }
    }

    Ok(())
}

/// Load ed25519 keypair from disk or create new dev keys.
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

/// Dev-only: accept any server cert. Replace with real pinning for prod.
fn make_client_cfg_insecure() -> Result<ClientConfig> {
    use rustls::{
        client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        Certificate, ClientConfig as RustlsClientConfig, DigitallySignedStruct, ServerName,
    };
    use std::time::SystemTime;

    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &Certificate,
            _intermediates: &[Certificate],
            _server_name: &ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp_response: &[u8],
            _now: SystemTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &Certificate,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &Certificate,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
    }

    let tls_cfg = RustlsClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    Ok(ClientConfig::new(Arc::new(tls_cfg)))
}

/// Create a Quinn client Endpoint bound to an ephemeral UDP port,
/// choosing IPv4 vs IPv6 family to match the VS address.
fn make_endpoint_and_addr(vs: &str) -> Result<(Endpoint, SocketAddr)> {
    use quinn::{EndpointConfig, TokioRuntime};

    let server_addr: SocketAddr = vs.parse().context("bad vs address")?;

    // Bind locally on same IP family as the server
    let bind_ip = match server_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, 0);

    let udp = UdpSocket::bind(local_addr)?;
    udp.set_nonblocking(true)?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None, // client-only Endpoint, no server config
        udp,
        Arc::new(TokioRuntime),
    )?;

    Ok((endpoint, server_addr))
}
