//! vs: Validation Server
//!
//! Preruntime
//!   - GS connects over QUIC.
//!   - GS sends JoinRequest { gs_pub, sw_hash, t_unix_ms, nonce, sig_gs }.
//!   - We verify sig_gs with gs_pub, check timestamp freshness,
//!     (TODO) check sw_hash allowlist.
//!   - We mint session_id, sign it with vs_sk, send JoinAccept { session_id, sig_vs }.
//!   - We remember {session_id -> gs_pub, last_counter}.
//!
//! Runtime
//!   - heartbeat_reader():
//!     GS -> VS bi-streams carrying Heartbeat {
//!     session_id, gs_counter, gs_time_ms, receipt_tip, sig_gs
//!     } every ~2s.
//!     We verify sig_gs against stored gs_pub and enforce monotonic counter.
//!     (TODO) liveness watchdog / teardown on stall.
//!
//!   - ticket_sender():
//!     VS -> GS bi-streams carrying PlayTicket every ~2s.
//!     For now we fill placeholder fields and a dummy sig.
//!     gs-sim just checks the time window and logs.
//!
//! Smoke test (`make ci`) proves:
//!   - vs comes up on 127.0.0.1:4444
//!   - gs-sim joins, gets a session, sends 2 heartbeats, reads tickets
//!   - gs-sim exits cleanly with --test-once
//!   - vs stays up.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use common::{
    crypto::{heartbeat_sign_bytes, join_request_sign_bytes, now_ms, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{Heartbeat, JoinAccept, JoinRequest, PlayTicket, Sig},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{Endpoint, ServerConfig};
use rand::{rngs::OsRng, RngCore};
use rcgen::generate_simple_self_signed;
use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::sleep};

/// Max allowed clock skew between GS and VS during join (ms).
/// This is our anti-replay window.
const JOIN_MAX_SKEW_MS: u64 = 10_000; // 10s dev window

/// Per-session state tracked on VS after join.
#[derive(Clone)]
struct SessionState {
    gs_pub: VerifyingKey, // GS's ed25519 public key
    last_counter: u64,    // last accepted heartbeat counter
}

/// Active sessions by session_id
type Sessions = Arc<Mutex<HashMap<[u8; 16], SessionState>>>;

#[derive(Parser, Debug)]
struct Opts {
    /// UDP bind address for the VS QUIC endpoint.
    /// gs-sim defaults to 127.0.0.1:4444
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: String,

    /// VS signing keypair (ed25519) used to sign JoinAccept.sig_vs
    #[arg(long, default_value = "keys/vs_ed25519.pk8")]
    vs_sk: String,
    #[arg(long, default_value = "keys/vs_ed25519.pub")]
    vs_pk: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    let (vs_sk_raw, vs_pk_raw) = load_or_make_keys(&opts.vs_sk, &opts.vs_pk)?;
    let vs_sk = Arc::new(vs_sk_raw);
    let vs_pk = Arc::new(vs_pk_raw);

    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    // Spin up QUIC listener with a self-signed cert
    let (endpoint, _local_addr) = make_endpoint(&opts.bind)?;
    println!("[VS] listening on {}", opts.bind);

    loop {
        // Quinn 0.10: accept() -> Option<Connecting>
        let connecting_opt = endpoint.accept().await;
        let Some(connecting) = connecting_opt else {
            // Endpoint closed; shouldn't normally happen in smoke.
            break;
        };

        let vs_sk_clone = vs_sk.clone();
        let vs_pk_clone = vs_pk.clone();
        let sessions_clone = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(connecting, vs_sk_clone, vs_pk_clone, sessions_clone).await
            {
                eprintln!("[VS] conn error: {e:?}");
            }
        });
    }

    Ok(())
}

/// Handle exactly one GS QUIC connection:
/// - Finish join handshake on first bi-stream.
/// - Register session in Sessions map.
/// - Spawn heartbeat_reader (VS <- GS) and ticket_sender (VS -> GS).
async fn handle_connection(
    connecting: quinn::Connecting,
    vs_sk: Arc<SigningKey>,
    vs_pk: Arc<VerifyingKey>,
    sessions: Sessions,
) -> Result<()> {
    // Finish QUIC handshake -> live Connection
    let conn = connecting.await.context("handshake accept")?;
    println!("[VS] new conn from {}", conn.remote_address());

    // First bi-stream: GS sends JoinRequest, expects JoinAccept back.
    let (mut vs_send, mut vs_recv) = conn
        .accept_bi()
        .await
        .context("accept_bi for JoinRequest")?;

    let jr: JoinRequest = recv_msg(&mut vs_recv).await.context("recv JoinRequest")?;
    println!("[VS] got JoinRequest from gs_id={}", jr.gs_id);

    // ---- Preruntime validation ----

    // 1. Verify JoinRequest signature.
    let jr_msg = join_request_sign_bytes(&jr.gs_id, &jr.sw_hash, jr.t_unix_ms, &jr.nonce);

    let gs_pub = VerifyingKey::from_bytes(&jr.gs_pub).context("bad gs_pub len")?;
    if !verify(&gs_pub, &jr_msg, &jr.sig_gs) {
        return Err(anyhow!("JoinRequest sig_gs invalid"));
    }

    // 2. Anti-replay freshness check.
    let now = now_ms();
    let skew = now.abs_diff(jr.t_unix_ms);
    if skew > JOIN_MAX_SKEW_MS {
        return Err(anyhow!(
            "JoinRequest timestamp skew too large ({} ms)",
            skew
        ));
    }

    // 3. Placeholder "attestation" policy:
    //    In prod we'd compare jr.sw_hash against an allowlist of known builds.
    let _allowed = true;
    if !_allowed {
        return Err(anyhow!("JoinRequest sw_hash not allowed"));
    }

    // 4. Mint session_id and sign it with VS key.
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);

    let sig_vs: Sig = sign(vs_sk.as_ref(), &session_id);

    let ja = JoinAccept {
        session_id,
        sig_vs,
        vs_pub: vs_pk.to_bytes(),
    };

    // Send JoinAccept back on same stream.
    send_msg(&mut vs_send, &ja)
        .await
        .context("send JoinAccept")?;

    println!(
        "[VS] accepted gs_id={} session={}..",
        jr.gs_id,
        hex::encode(&session_id[..4])
    );

    // Remember this GS for runtime checks.
    {
        let mut guard = sessions.lock().await;
        guard.insert(
            session_id,
            SessionState {
                gs_pub,
                last_counter: 0,
            },
        );
    }

    // Spawn runtime tasks and return. The tasks hold cloned Arcs
    // so the connection stays alive.
    let conn_for_hb = conn.clone();
    let sessions_for_hb = sessions.clone();
    let session_id_for_hb = session_id;
    tokio::spawn(async move {
        if let Err(e) = heartbeat_reader(conn_for_hb, session_id_for_hb, sessions_for_hb).await {
            eprintln!("[VS] heartbeat_reader error: {e:?}");
        }
    });

    let conn_for_ticket = conn.clone();
    let session_id_for_ticket = session_id;
    tokio::spawn(async move {
        if let Err(e) = ticket_sender(conn_for_ticket, session_id_for_ticket).await {
            eprintln!("[VS] ticket_sender error: {e:?}");
        }
    });

    Ok(())
}

/// Read heartbeats from GS.
/// Each heartbeat bi-stream should contain exactly one Heartbeat.
/// We verify sig_gs and counter monotonicity.
async fn heartbeat_reader(
    conn: quinn::Connection,
    session_id: [u8; 16],
    sessions: Sessions,
) -> Result<()> {
    loop {
        let pair = conn.accept_bi().await;
        let (mut _send, mut recv) = match pair {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "[VS] heartbeat accept_bi error (session {}..): {e:?}",
                    hex::encode(&session_id[..4])
                );
                break;
            }
        };

        // We don't send anything back on this heartbeat stream.
        drop(_send);

        let hb_res = recv_msg::<Heartbeat>(&mut recv).await;
        let hb = match hb_res {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "[VS] heartbeat decode error (session {}..): {e:?}",
                    hex::encode(&session_id[..4])
                );
                continue;
            }
        };

        // Session must match
        if hb.session_id != session_id {
            eprintln!(
                "[VS] heartbeat wrong session id {}.. (expected {}..)",
                hex::encode(&hb.session_id[..4]),
                hex::encode(&session_id[..4]),
            );
            continue;
        }

        // Look up session state to get gs_pub / last_counter.
        let mut guard = sessions.lock().await;
        let st = match guard.get_mut(&session_id) {
            Some(s) => s,
            None => {
                eprintln!(
                    "[VS] heartbeat for unknown/expired session {}..",
                    hex::encode(&session_id[..4])
                );
                continue;
            }
        };

        // Verify sig_gs on heartbeat.
        let hb_msg = heartbeat_sign_bytes(
            &hb.session_id,
            hb.gs_counter,
            hb.gs_time_ms,
            &hb.receipt_tip,
        );
        if !verify(&st.gs_pub, &hb_msg, &hb.sig_gs) {
            eprintln!(
                "[VS] BAD heartbeat sig (session {}..)",
                hex::encode(&session_id[..4])
            );
            continue;
        }

        // Enforce monotonic counter.
        if hb.gs_counter <= st.last_counter {
            eprintln!(
                "[VS] non-monotonic counter {} (last {}) for session {}..",
                hb.gs_counter,
                st.last_counter,
                hex::encode(&session_id[..4])
            );
            continue;
        }
        st.last_counter = hb.gs_counter;

        // TODO: watchdog if heartbeats stop.
        println!(
            "[VS] hb ok c={} from session {}..",
            hb.gs_counter,
            hex::encode(&session_id[..4])
        );
    }

    Ok(())
}

/// Send PlayTickets to GS every ~2s.
/// VS opens a fresh bi-stream for each ticket.
///
/// We currently fill placeholder fields so gs-sim can deserialize.
async fn ticket_sender(conn: quinn::Connection, session_id: [u8; 16]) -> Result<()> {
    let mut counter: u64 = 0;

    // Chaining / binding placeholders
    let client_binding = [0u8; 32];
    let mut prev_ticket_hash = [0u8; 32];

    loop {
        sleep(Duration::from_secs(2)).await;
        counter += 1;

        let now = now_ms();

        // Dummy sig_vs for now. We'll replace this with a real
        // vs_sk signature once we define ticket_sign_bytes().
        let sig_vs: Sig = [0u8; 64];

        // Fill the whole struct so it matches common::proto::PlayTicket.
        let pt = PlayTicket {
            session_id,
            client_binding,
            prev_ticket_hash,
            counter,
            not_before_ms: now,
            not_after_ms: now + 2_000,
            sig_vs,
        };

        // Open a bi-stream to send the ticket.
        let pair = conn.open_bi().await;
        let (mut send, _recv) = match pair {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "[VS] ticket open_bi failed (session {}..): {e:?}",
                    hex::encode(&session_id[..4])
                );
                break;
            }
        };

        if let Err(e) = send_msg(&mut send, &pt).await {
            eprintln!(
                "[VS] ticket send failed (session {}..): {e:?}",
                hex::encode(&session_id[..4])
            );
        } else {
            println!(
                "[VS] sent ticket #{} to session {}..",
                counter,
                hex::encode(&session_id[..4])
            );
        }

        // TODO: once we define how prev_ticket_hash is computed
        // (probably sha256 of the serialized ticket), update it here:
        // prev_ticket_hash = sha256(serialized_pt);
        let _ = &mut prev_ticket_hash;
    }

    Ok(())
}

/// Build a QUIC Endpoint bound to `bind` (e.g. "127.0.0.1:4444"),
/// with a fresh self-signed cert "vs.dev".
fn make_endpoint(bind: &str) -> Result<(Endpoint, SocketAddr)> {
    use rustls::{Certificate, PrivateKey};

    // Self-signed cert for vs.dev each run.
    let cert = generate_simple_self_signed(vec!["vs.dev".into()]).context("self-signed cert")?;
    let cert_der = cert.serialize_der().context("cert der")?;
    let key_der = cert.serialize_private_key_der();

    let cert_chain = vec![Certificate(cert_der)];
    let priv_key = PrivateKey(key_der);

    // Quinn helper builds quinn::ServerConfig for us.
    let server_cfg =
        ServerConfig::with_single_cert(cert_chain, priv_key).context("with_single_cert")?;

    // Parse requested bind addr.
    let req_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("bad bind addr: {bind}"))?;

    // Bind wildcard of that IP family so gs-sim can hit 127.0.0.1.
    let bind_ip = match req_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, req_addr.port());

    // Launch QUIC server endpoint
    let endpoint = Endpoint::server(server_cfg, local_addr).context("Endpoint::server")?;

    Ok((endpoint, local_addr))
}

/// Ensure we have an ed25519 keypair for VS. If not, generate and persist dev keys.
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
