//! gs-sim: minimal untrusted Game Server simulator
//! - Attests its binary hash (dev-level)
//! - Joins VS with both long-term GS key and a fresh per-session ephemeral key
//! - Sends signed heartbeats using the ephemeral session key
//! - Listens for PlayTickets from VS, verifies them, caches latest
//! - (new) mock client-input gate: require fresh PlayTicket from VS

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{
        file_sha256, heartbeat_sign_bytes, join_request_sign_bytes, now_ms, sha256, sign, verify,
    },
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
use tokio::{sync::Mutex, time::sleep};

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

    /// Paths to GS long-term keypair
    #[arg(long, default_value = "keys/gs_ed25519.pk8")]
    gs_sk: String,
    #[arg(long, default_value = "keys/gs_ed25519.pub")]
    gs_pk: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // --- 1. Load or generate GS long-term identity keypair ---
    let (gs_sk, gs_pk) = load_or_make_keys(&opts.gs_sk, &opts.gs_pk)?;

    // --- 2. Generate fresh per-session ephemeral keypair ---
    // This one is NOT persisted. It lives only for this VS session.
    let eph_sk = SigningKey::generate(&mut OsRng);
    let eph_pk = eph_sk.verifying_key();
    let eph_pub_bytes = eph_pk.to_bytes(); // [u8;32]

    // --- 3. Compute dev "attestation" hash of this running binary ---
    let exe = std::env::current_exe()?;
    let sw_hash = file_sha256(&exe)?;

    // --- 4. QUIC client endpoint + connect to VS ---
    let (endpoint, server_addr) = make_endpoint_and_addr(&opts.vs)?;
    let conn: Connection = endpoint
        .connect_with(make_client_cfg_insecure()?, server_addr, "vs.dev")?
        .await?;
    println!("[GS] connected to VS at {server_addr}");

    // --- 5. Build and send JoinRequest on fresh bi-stream ---
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let now = now_ms();

    // The JoinRequest is authenticated by the *long-term* GS key.
    // The signed message includes the ephemeral_pub, so VS learns:
    // "This GS identity vouches that this ephemeral key is legit for this session."
    let to_sign = join_request_sign_bytes(
        &opts.gs_id,
        &sw_hash,
        now,
        &nonce,
        &eph_pub_bytes, // new extra param
    );
    let sig_gs: Sig = sign(&gs_sk, &to_sign);

    let jr = JoinRequest {
        gs_id: opts.gs_id.clone(),
        sw_hash,
        t_unix_ms: now,
        nonce,
        ephemeral_pub: eph_pub_bytes, // new field
        sig_gs,
        gs_pub: gs_pk.to_bytes(),
    };

    let (mut jsend, mut jrecv) = conn.open_bi().await?;
    send_msg(&mut jsend, &jr).await?;
    let ja: JoinAccept = recv_msg(&mut jrecv).await?;

    // --- 6. Verify VS proved identity over this session_id ---
    // GS will trust tickets from this VS key going forward.
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

    // --- 7. Shared state: the most recent blessed PlayTicket from VS ---
    // We'll demand clients echo this with every input.
    let latest_ticket: Arc<Mutex<Option<PlayTicket>>> = Arc::new(Mutex::new(None));

    // --- 8. Spawn background tasks ---

    // 8a. Heartbeat loop GS -> VS
    // IMPORTANT: heartbeats are signed with *ephemeral* key,
    // not the long-term GS key. VS will verify using ephemeral_pub
    // we handed over in JoinRequest.
    let hb_counter = Arc::new(AtomicU64::new(0));
    let hb_task = tokio::spawn(heartbeat_loop(
        conn.clone(),
        hb_counter.clone(),
        eph_sk.clone(), // <-- ephemeral signer for runtime liveness
        ja.session_id,
    ));

    // 8b. Ticket listener VS -> GS
    // Verifies PlayTickets, enforces continuity, caches newest ticket.
    let ticket_task = tokio::spawn(ticket_listener(
        conn.clone(),
        ja.session_id,
        vs_vk,
        latest_ticket.clone(),
    ));

    if opts.test_once {
        // let a couple heartbeats/tickets flow, then simulate client input enforcement
        sleep(Duration::from_secs(5)).await;
        mock_client_input_check(latest_ticket.clone()).await;
        println!("[GS] test_once complete.");
        return Ok(());
    }

    // 8c. Stay alive while background tasks run; bail if either dies.
    loop {
        sleep(Duration::from_secs(60)).await;
        if hb_task.is_finished() || ticket_task.is_finished() {
            eprintln!("[GS] background task ended, exiting main loop");
            break;
        }
    }

    Ok(())
}

// GS -> VS heartbeat loop.
// Opens a fresh bi-stream for each heartbeat,
// signs heartbeat with the *ephemeral* session key.
async fn heartbeat_loop(
    conn: Connection,
    counter: Arc<AtomicU64>,
    eph_sk: SigningKey, // now the ephemeral signer
    session_id: [u8; 16],
) -> Result<()> {
    let receipt_tip = [0u8; 32]; // placeholder, no receipts yet

    loop {
        sleep(Duration::from_secs(2)).await;

        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();

        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip);
        let sig_gs = sign(&eph_sk, &to_sign); // signed with eph_sk

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

// VS -> GS ticket listener.
// Accepts PlayTickets from VS, verifies signature, chain, timing,
// and records the latest good ticket for use when checking client inputs.
async fn ticket_listener(
    conn: Connection,
    session_id: [u8; 16],
    vs_pub: VerifyingKey,
    latest_ticket: Arc<Mutex<Option<PlayTicket>>>,
) -> Result<()> {
    let mut last_counter: u64 = 0;
    let mut last_hash: [u8; 32] = [0u8; 32];

    loop {
        // VS opens a fresh bi-stream for each PlayTicket.
        let pair = conn.accept_bi().await;
        let (send, mut recv) = match pair {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[GS] accept_bi error: {e:?}");
                break;
            }
        };
        drop(send); // we don't send data on ticket stream

        let pt_res = recv_msg::<PlayTicket>(&mut recv).await;
        let pt = match pt_res {
            Ok(pt) => pt,
            Err(e) => {
                eprintln!("[GS] bad ticket: {e:?}");
                continue;
            }
        };

        // 1. session binding
        if pt.session_id != session_id {
            eprintln!("[GS] ticket session mismatch");
            break;
        }

        // 2. counter monotonic
        if pt.counter != last_counter + 1 {
            eprintln!(
                "[GS] ticket counter non-monotonic (got {}, expected {})",
                pt.counter,
                last_counter + 1
            );
            break;
        }

        // 3. prev_ticket_hash continuity
        if pt.prev_ticket_hash != last_hash {
            eprintln!("[GS] ticket prev_hash mismatch");
            break;
        }

        // 4. verify VS signature on the ticket body (minus sig_vs)
        let body_tuple = (
            pt.session_id,
            pt.client_binding,
            pt.counter,
            pt.not_before_ms,
            pt.not_after_ms,
            pt.prev_ticket_hash,
        );
        let body_bytes = bincode::serialize(&body_tuple).context("ticket serialize")?;
        if !verify(&vs_pub, &body_bytes, &pt.sig_vs) {
            eprintln!("[GS] ticket sig_vs BAD");
            break;
        }

        // 5. freshness window
        let now = now_ms();
        let ok_time = pt.not_before_ms.saturating_sub(500) <= now
            && now <= pt.not_after_ms.saturating_add(500);

        println!("[GS] ticket #{} (time_ok={})", pt.counter, ok_time);

        // 6. update continuity chain for next ticket
        last_counter = pt.counter;
        last_hash = sha256(&body_bytes);

        // 7. publish newest valid ticket so client inputs must echo it
        {
            let mut guard = latest_ticket.lock().await;
            *guard = Some(pt.clone());
        }
    }

    Ok(())
}

// Pretend we got input from a client.
// Before trusting that input, GS would demand the client echo the latest
// VS-blessed PlayTicket (or its counter + sig_vs).
//
// We don't have a client crate yet, so here we just read whatever the
// latest ticket is and log what we would enforce.
async fn mock_client_input_check(latest_ticket: Arc<Mutex<Option<PlayTicket>>>) {
    let snapshot = {
        let guard = latest_ticket.lock().await;
        guard.clone()
    };

    match snapshot {
        Some(t) => {
            let now = now_ms();
            let fresh = t.not_before_ms.saturating_sub(500) <= now
                && now <= t.not_after_ms.saturating_add(500);

            println!(
                "[GS] mock client input validation: would accept ticket #{} (fresh={}) for session {}..",
                t.counter,
                fresh,
                hex::encode(&t.session_id[..4]),
            );

            // Future real check:
            // - client must include t.counter and t.sig_vs on every input
            // - reject if !fresh
        }
        None => {
            eprintln!(
                "[GS] mock client input validation: no ticket yet, would reject client input"
            );
        }
    }
}

/// Load ed25519 keypair from disk or create new dev keys for the GS long-term identity.
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
/// matching IPv4/IPv6 family to VS.
fn make_endpoint_and_addr(vs: &str) -> Result<(Endpoint, SocketAddr)> {
    use quinn::{EndpointConfig, TokioRuntime};

    let server_addr: SocketAddr = vs.parse().context("bad vs address")?;

    // Bind locally on same IP family as server.
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
