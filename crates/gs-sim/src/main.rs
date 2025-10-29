use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{file_sha256, join_request_sign_bytes, now_ms, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{JoinAccept, JoinRequest, Sig},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{ClientConfig, Connection, Endpoint};
use rand::{rngs::OsRng, RngCore};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::sleep};

mod client_port;
mod heartbeat;
mod state;
mod tickets;

use crate::client_port::client_port_task;
use crate::heartbeat::heartbeat_loop;
use crate::state::{GsSharedState, Shared};
use crate::tickets::ticket_listener;

#[derive(Parser, Debug)]
struct Opts {
    /// VS address (ip:port)
    #[arg(long, default_value = "127.0.0.1:4444")]
    vs: String,

    /// Exit after first join/heartbeat/ticket/client-proof exchange.
    #[arg(long)]
    test_once: bool,

    /// Logical GS ID label
    #[arg(long, default_value = "gs-sim-local")]
    gs_id: String,

    /// Paths to GS *long-term* keypair
    #[arg(long, default_value = "keys/gs_ed25519.pk8")]
    gs_sk: String,
    #[arg(long, default_value = "keys/gs_ed25519.pub")]
    gs_pk: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    //
    // 1. Load/generate GS long-term keypair.
    //
    let (gs_sk_long, gs_pk_long) = load_or_make_keys(&opts.gs_sk, &opts.gs_pk)?;

    //
    // 2. Create per-session ephemeral signing key.
    //
    let eph_sk = SigningKey::generate(&mut OsRng);
    let eph_pub_bytes = eph_sk.verifying_key().to_bytes();

    //
    // 3. Compute sw_hash of our running binary (attestation placeholder).
    //
    let exe = std::env::current_exe()?;
    let sw_hash = file_sha256(&exe)?;

    //
    // 4. QUIC connect to Validation Server (VS).
    //
    let (endpoint, server_addr) = make_endpoint_and_addr(&opts.vs)?;
    let conn: Connection = endpoint
        .connect_with(make_client_cfg_insecure()?, server_addr, "vs.dev")?
        .await?;
    println!("[GS] connected to VS at {server_addr}");

    //
    // 5. Send JoinRequest over a bi-stream and receive JoinAccept.
    //
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let now = now_ms();
    let to_sign = join_request_sign_bytes(&opts.gs_id, &sw_hash, now, &nonce, &eph_pub_bytes);
    let sig_gs: Sig = sign(&gs_sk_long, &to_sign);

    let jr = JoinRequest {
        gs_id: opts.gs_id.clone(),
        sw_hash,
        t_unix_ms: now,
        nonce,
        ephemeral_pub: eph_pub_bytes,
        sig_gs,
        gs_pub: gs_pk_long.to_bytes(),
    };

    let (mut jsend, mut jrecv) = conn.open_bi().await?;
    send_msg(&mut jsend, &jr).await?;
    let ja: JoinAccept = recv_msg(&mut jrecv).await?;

    //
    // 6. Verify VS identity + session_id signature in JoinAccept.
    //
    let vs_vk = VerifyingKey::from_bytes(&ja.vs_pub).context("bad vs_pub from JoinAccept")?;

    let sig_ok = verify(&vs_vk, &ja.session_id, &ja.sig_vs);
    if !sig_ok {
        bail!("VS signature invalid on JoinAccept");
    }

    println!(
        "[GS] joined. session_id={}.. (vs sig OK, len={})",
        hex::encode(&ja.session_id[..4]),
        ja.sig_vs.len()
    );

    //
    // 7. Shared GS state (session, latest ticket, receipt_tip, revoked flag...)
    //
    let shared: Shared = Arc::new(Mutex::new(GsSharedState::new(ja.session_id, ja.vs_pub)));

    //
    // 8. Channel to broadcast "revoked" to all client handlers.
    //
    let (revoke_tx, revoke_rx) = watch::channel(false);

    //
    // 9. Spawn runtime tasks: heartbeat, ticket listener, client TCP port.
    //
    // a) heartbeat_loop: GS → VS liveness + receipt_tip every ~2s
    let hb_counter = Arc::new(AtomicU64::new(0));
    let heartbeat_task = tokio::spawn(heartbeat_loop(
        conn.clone(),
        hb_counter.clone(),
        eph_sk.clone(),
        ja.session_id,
        shared.clone(),
    ));

    // b) ticket_listener: VS → GS PlayTickets stream + revocation watchdog
    let tickets_task = tokio::spawn(ticket_listener(
        conn.clone(),
        shared.clone(),
        vs_vk,
        revoke_tx.clone(),
    ));

    // c) client_port_task: TCP listener accepting local client-sim connections
    let client_port_task_handle = tokio::spawn(client_port_task(shared.clone(), revoke_rx.clone()));

    //
    // 10. --test-once mode: let smoke test run a bit, then exit.
    //
    if opts.test_once {
        sleep(Duration::from_secs(5)).await;

        heartbeat_task.abort();
        tickets_task.abort();
        client_port_task_handle.abort();

        println!("[GS] test_once complete.");
        return Ok(());
    }

    //
    // 11. "Prod-ish": loop until any task dies.
    //
    loop {
        sleep(Duration::from_secs(60)).await;
        if heartbeat_task.is_finished()
            || tickets_task.is_finished()
            || client_port_task_handle.is_finished()
        {
            eprintln!("[GS] background task ended, exiting main loop");
            break;
        }
    }

    Ok(())
}

/// Load GS long-term Ed25519 keypair from disk or create dev keys.
fn load_or_make_keys(sk_path: &str, pk_path: &str) -> Result<(SigningKey, VerifyingKey)> {
    let skp = PathBuf::from(sk_path);
    let pkp = PathBuf::from(pk_path);

    if skp.exists() && pkp.exists() {
        let sk_bytes = std::fs::read(&skp).context("read gs_sk")?;
        let pk_bytes = std::fs::read(&pkp).context("read gs_pk")?;

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
        std::fs::create_dir_all("keys").context("mkdir keys")?;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        std::fs::write(&skp, sk.to_bytes()).context("write gs_sk")?;
        std::fs::write(&pkp, pk.to_bytes()).context("write gs_pk")?;
        println!(
            "[GS] generated dev keypair at {}, {}",
            skp.display(),
            pkp.display()
        );
        Ok((sk, pk))
    }
}

/// Dev-only QUIC client config: accept any server cert.
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

/// Create a Quinn client Endpoint bound to an ephemeral UDP port.
fn make_endpoint_and_addr(vs: &str) -> Result<(Endpoint, SocketAddr)> {
    use quinn::{EndpointConfig, TokioRuntime};

    let server_addr: SocketAddr = vs.parse().context("bad vs address")?;

    // bind to wildcard IP in same family as VS address
    let bind_ip = match server_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, 0);

    let udp = UdpSocket::bind(local_addr)?;
    udp.set_nonblocking(true)?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None, // client-only endpoint
        udp,
        Arc::new(TokioRuntime),
    )?;

    Ok((endpoint, server_addr))
}
