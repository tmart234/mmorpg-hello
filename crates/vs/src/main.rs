//! vs: minimal Validation Server for local smoke tests.
//!
//! Responsibilities right now:
//! - Bind QUIC on 127.0.0.1:4444 (UDP).
//! - Accept a gs-sim connection.
//! - Read the first bi-stream (JoinRequest).
//! - Reply with JoinAccept { session_id, sig_vs }.
//! - Stay alive so gs-sim can send heartbeats on new streams.
//!
//! This is what `tools::smoke` and `gs-sim --test-once` expect.

use anyhow::{anyhow, Context, Result};
use common::{
    crypto::sign,
    framing::{recv_msg, send_msg},
    proto::{JoinAccept, JoinRequest, Sig},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::Endpoint;
use rand::{rngs::OsRng, RngCore};
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::Arc,
};
use tokio::task;

const BIND_ADDR: &str = "127.0.0.1:4444";
const VS_SK_PATH: &str = "keys/vs_ed25519.pk8";
const VS_PK_PATH: &str = "keys/vs_ed25519.pub";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Make sure we have a VS signing keypair.
    //    This key signs the session_id in JoinAccept.
    let (vs_sk_raw, _vs_pk) = load_or_make_keys(VS_SK_PATH, VS_PK_PATH)?;
    let vs_sk = Arc::new(vs_sk_raw);

    // 2. Bring up QUIC endpoint on UDP/4444 with a throwaway TLS cert.
    let (endpoint, local_addr) = make_endpoint(BIND_ADDR)?;
    println!("[VS] listening on {local_addr}");

    // 3. Accept inbound QUIC connections forever.
    loop {
        // Endpoint::accept() -> Option<Connecting>.
        let connecting_opt = endpoint.accept().await;
        let Some(connecting) = connecting_opt else {
            // Endpoint shut down (shouldn't happen in dev). Exit loop.
            break;
        };

        let vs_sk_clone = vs_sk.clone();
        task::spawn(async move {
            if let Err(e) = handle_connection(connecting, vs_sk_clone).await {
                eprintln!("[VS] conn error: {e:?}");
            }
        });
    }

    Ok(())
}

// Per-connection task.
//
// Flow:
// - Complete QUIC handshake.
// - Accept the first bi-stream from the GS.
// - Read JoinRequest from that stream.
// - Send JoinAccept back on the same stream.
// - Park so the connection stays alive for heartbeats.
async fn handle_connection(connecting: quinn::Connecting, vs_sk: Arc<SigningKey>) -> Result<()> {
    // Finish handshake -> live Connection
    let conn = connecting.await.context("handshake accept")?;
    println!("[VS] new conn from {}", conn.remote_address());

    // First client-initiated bi-stream should carry JoinRequest
    let (mut vs_send, mut vs_recv) = conn.accept_bi().await.context("accept_bi")?;

    // Decode the JoinRequest
    let jr: JoinRequest = recv_msg(&mut vs_recv).await.context("recv JoinRequest")?;
    println!("[VS] got JoinRequest from gs_id={}", jr.gs_id);

    // Make a fresh session_id and sign it with VS's ed25519 key.
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);

    let sig_vs: Sig = sign(vs_sk.as_ref(), &session_id);

    let ja = JoinAccept { session_id, sig_vs };

    // Send JoinAccept back and finish the send half of the stream.
    send_msg(&mut vs_send, &ja)
        .await
        .context("send JoinAccept")?;

    // Keep the connection task alive so gs-sim can open new streams
    // for heartbeats. We don't parse heartbeats yet; we just park.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

/// Create a QUIC server Endpoint bound to `bind` ("127.0.0.1:4444").
/// We generate a throwaway self-signed TLS cert every run.
///
/// Behind the scenes:
/// - rcgen makes a self-signed cert for the hostname "vs.dev".
/// - quinn::ServerConfig::with_single_cert(...) builds a TLS config
///   that rustls + quinn will accept.
/// - We manually bind a UdpSocket and feed it to Endpoint::new because
///   we're using quinn 0.10's lower-level constructor.
fn make_endpoint(bind: &str) -> Result<(Endpoint, SocketAddr)> {
    use quinn::{EndpointConfig, ServerConfig, TokioRuntime};
    use rcgen::generate_simple_self_signed;
    use rustls::{Certificate, PrivateKey};

    // Generate ephemeral self-signed cert for "vs.dev"
    let cert = generate_simple_self_signed(vec!["vs.dev".into()]).context("self-signed cert")?;
    let cert_der = cert.serialize_der().context("cert der")?;
    let key_der = cert.serialize_private_key_der();

    let cert_chain = vec![Certificate(cert_der)];
    let priv_key = PrivateKey(key_der);

    // Quinn helper produces a full quinn::ServerConfig for us
    let server_cfg =
        ServerConfig::with_single_cert(cert_chain, priv_key).context("with_single_cert")?;

    // Bind UDP on the requested port.
    // We bind 0.0.0.0:<port> (or ::/<port>) so gs-sim can reach us via 127.0.0.1.
    let req_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("bad bind addr: {bind}"))?;
    let bind_ip = match req_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, req_addr.port());

    let udp = UdpSocket::bind(local_addr).context("bind UDP socket")?;
    udp.set_nonblocking(true).context("set_nonblocking")?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_cfg),
        udp,
        Arc::new(TokioRuntime),
    )
    .context("Endpoint::new")?;

    let actual = endpoint.local_addr().context("local_addr")?;
    Ok((endpoint, actual))
}

/// Load VS ed25519 keypair from disk, or create a dev pair if missing.
/// Mirrors gs-sim's key handling so both sides have signing keys on disk.
fn load_or_make_keys(sk_path: &str, pk_path: &str) -> Result<(SigningKey, VerifyingKey)> {
    let skp = PathBuf::from(sk_path);
    let pkp = PathBuf::from(pk_path);

    if skp.exists() && pkp.exists() {
        let sk_bytes = fs::read(&skp).context("read vs_sk")?;
        let pk_bytes = fs::read(&pkp).context("read vs_pk")?;

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
        fs::create_dir_all("keys").context("mkdir keys")?;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        fs::write(&skp, sk.to_bytes()).context("write vs_sk")?;
        fs::write(&pkp, pk.to_bytes()).context("write vs_pk")?;
        println!(
            "[VS] generated dev keypair at {}, {}",
            skp.display(),
            pkp.display()
        );
        Ok((sk, pk))
    }
}
