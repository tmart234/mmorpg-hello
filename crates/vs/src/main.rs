//! Validation Server (VS)
//!
//! High-level trust flow:
//!
//! - A Game Server (GS) connects to VS over QUIC.
//! - GS sends a `JoinRequest` with:
//!   - gs_id
//!   - sw_hash (binary hash of GS build)
//!   - t_unix_ms + nonce (anti-replay)
//!   - ephemeral_pub (fresh per-session key)
//!   - sig_gs (signature using GS's long-term key, binding all of the above)
//!   - gs_pub (the GS long-term public key)
//!
//! - VS verifies:
//!   - sig_gs using gs_pub
//!   - timestamp freshness (anti-replay)
//!   - sw_hash allowlist (TODO, placeholder for now)
//!
//! - If accepted, VS mints a new session_id and stores session runtime state:
//!   - the GS's per-session ephemeral_pub (used to verify heartbeats)
//!   - last_counter and last_seen_ms for liveness
//!
//! - VS replies with `JoinAccept { session_id, sig_vs, vs_pub }` so the GS
//!   learns it is talking to the real VS and knows which session_id it owns.
//!
//! Runtime after join:
//!
//! - VS periodically sends `PlayTicket` to the GS (on fresh bi-streams).
//!   These tickets are signed by VS and contain:
//!   - session_id
//!   - client_binding (who this ticket is for; future anti-alt)
//!   - counter (monotonic)
//!   - not_before_ms / not_after_ms (freshness window)
//!   - prev_ticket_hash (hash chain)
//!
//!   The GS forwards the latest PlayTicket to clients. Clients refuse to send
//!   gameplay input if that ticket expires. This is how VS can revoke a GS
//!   quickly by just stopping tickets.
//!
//! - GS periodically opens a new bi-stream back to VS and sends either:
//!   - `Heartbeat { session_id, gs_counter, gs_time_ms, receipt_tip, sig_gs }`
//!     proving liveness. VS checks monotonic counter and verifies sig_gs
//!     against the per-session ephemeral_pub.
//!   - `TranscriptDigest { session_id, gs_counter, receipt_tip }`
//!     summarizing GS's rolling transcript hash of accepted client inputs.
//!     VS answers with `ProtectedReceipt { ..., sig_vs }`, which is a VS-
//!     signed acknowledgement. Later, VS will refuse to sign if the GS is
//!     cheating.
//!
//! - Watchdog: if heartbeats stall or counters stop increasing, VS closes the
//!   QUIC connection and the session is considered dead.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{heartbeat_sign_bytes, join_request_sign_bytes, now_ms, sha256, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{
        Heartbeat, JoinAccept, JoinRequest, PlayTicket, ProtectedReceipt, Sig, TranscriptDigest,
    },
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{Endpoint, ServerConfig};
use rand::{rngs::OsRng, RngCore};
use rcgen::generate_simple_self_signed;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::sleep;

/// Max allowed join timestamp skew (anti-replay in JoinRequest)
const JOIN_MAX_SKEW_MS: u64 = 10_000; // ~10s dev window

/// How long we'll tolerate no valid heartbeat before killing session
const HEARTBEAT_TIMEOUT_MS: u64 = 5_000; // ~5s dev window

#[derive(Parser, Debug)]
struct Opts {
    /// UDP bind address for the VS QUIC endpoint.
    /// gs-sim defaults to 127.0.0.1:4444
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: String,

    /// VS signing keypair (ed25519) used to sign JoinAccept.sig_vs,
    /// PlayTicket.sig_vs, and ProtectedReceipt.sig_vs
    #[arg(long, default_value = "keys/vs_ed25519.pk8")]
    vs_sk: String,
    #[arg(long, default_value = "keys/vs_ed25519.pub")]
    vs_pk: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // Load (or create) VS signing key
    let (vs_sk_raw, _vs_pk_raw) = load_or_make_keys(&opts.vs_sk, &opts.vs_pk)?;
    let vs_sk = Arc::new(vs_sk_raw);

    // Start QUIC listener
    let (endpoint, _local_addr) = make_endpoint(&opts.bind)?;
    println!("[VS] listening on {}", opts.bind);

    loop {
        let connecting_opt = endpoint.accept().await;
        let Some(connecting) = connecting_opt else {
            break;
        };

        let vs_sk_clone = vs_sk.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(connecting, vs_sk_clone).await {
                eprintln!("[VS] conn error: {e:?}");
            }
        });
    }

    Ok(())
}

/// Handle one GS QUIC connection end-to-end:
/// - authenticate + admit GS
/// - spawn ticket sender loop
/// - spawn stream loop (heartbeats + transcript digests)
/// - spawn watchdog for liveness timeout
async fn handle_connection(connecting: quinn::Connecting, vs_sk: Arc<SigningKey>) -> Result<()> {
    // === handshake ===
    let conn = connecting.await.context("handshake accept")?;
    println!("[VS] new conn from {}", conn.remote_address());

    // first bi-stream: JoinRequest
    let (mut vs_send, mut vs_recv) = conn
        .accept_bi()
        .await
        .context("accept_bi for JoinRequest")?;

    let jr: JoinRequest = recv_msg(&mut vs_recv).await.context("recv JoinRequest")?;

    println!(
        "[VS] got JoinRequest from gs_id={} (ephemeral pub ..{}{})",
        jr.gs_id, jr.ephemeral_pub[0], jr.ephemeral_pub[1]
    );

    // === validate JoinRequest ===

    // 1. Caller proves control of long-term gs_pub, and binds ephemeral_pub.
    let gs_identity_vk = VerifyingKey::from_bytes(&jr.gs_pub).context("bad gs_pub")?;

    let join_bytes = join_request_sign_bytes(
        &jr.gs_id,
        &jr.sw_hash,
        jr.t_unix_ms,
        &jr.nonce,
        &jr.ephemeral_pub,
    );
    if !verify(&gs_identity_vk, &join_bytes, &jr.sig_gs) {
        bail!("JoinRequest sig_gs invalid");
    }

    // 2. Anti-replay freshness
    let now = now_ms();
    let skew = now.abs_diff(jr.t_unix_ms);
    if skew > JOIN_MAX_SKEW_MS {
        bail!("JoinRequest timestamp skew too large: {skew} ms");
    }

    // 3. (TODO) allowlist sw_hash here

    // === mint a session ===
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);

    // Per-connection runtime state
    #[derive(Clone)]
    struct LocalState {
        ephemeral_pub: [u8; 32], // verify heartbeats against this
        last_counter: u64,
        last_seen_ms: u64,
    }

    let state = Arc::new(Mutex::new(LocalState {
        ephemeral_pub: jr.ephemeral_pub,
        last_counter: 0,
        last_seen_ms: now_ms(),
    }));

    // === reply JoinAccept ===
    let sig_vs: Sig = sign(vs_sk.as_ref(), &session_id);
    let ja = JoinAccept {
        session_id,
        sig_vs,
        vs_pub: vs_sk.verifying_key().to_bytes(),
    };

    send_msg(&mut vs_send, &ja)
        .await
        .context("send JoinAccept")?;

    // === spawn runtime tasks ===

    // (1) ticket sender loop: VS → GS PlayTicket every ~2s
    {
        let conn = conn.clone();
        let vs_sk = vs_sk.clone();
        let session_id = session_id;
        tokio::spawn(async move {
            let mut counter: u64 = 0;
            let mut prev_hash: [u8; 32] = [0u8; 32];

            loop {
                sleep(Duration::from_secs(2)).await;

                counter += 1;
                let now = now_ms();
                let not_before = now;
                let not_after = now + 2_000;

                // sign the ticket body with vs_sk
                let body_tuple = (
                    session_id, [0u8; 32], // client_binding placeholder for now
                    counter, not_before, not_after, prev_hash,
                );
                let body_bytes = match bincode::serialize(&body_tuple) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("[VS] ticket serialize failed: {e:?}");
                        break;
                    }
                };
                let sig_vs: Sig = sign(vs_sk.as_ref(), &body_bytes);

                let pt = PlayTicket {
                    session_id,
                    client_binding: [0u8; 32],
                    counter,
                    not_before_ms: not_before,
                    not_after_ms: not_after,
                    prev_ticket_hash: prev_hash,
                    sig_vs,
                };

                // update hash chain for next ticket
                prev_hash = sha256(&body_bytes);

                match conn.open_bi().await {
                    Ok((mut send, _recv)) => {
                        if let Err(e) = send_msg(&mut send, &pt).await {
                            eprintln!("[VS] send PlayTicket failed: {e:?}");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[VS] open_bi for PlayTicket failed: {e:?}");
                        break;
                    }
                }
            }
        });
    }

    // (2) stream loop: GS → VS Heartbeat / TranscriptDigest on fresh bi-streams
    {
        let conn = conn.clone();
        let state = state.clone();
        let session_id = session_id;
        let vs_sk = vs_sk.clone();
        tokio::spawn(async move {
            loop {
                // GS opens new bi-stream for either Heartbeat or TranscriptDigest
                let pair = conn.accept_bi().await;
                let (mut send, mut recv) = match pair {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[VS] accept_bi stream error: {e:?}");
                        break;
                    }
                };

                // We read a tiny framing: 4-byte len LE, then that many bytes.
                let mut len_bytes = [0u8; 4];
                if recv.read_exact(&mut len_bytes).await.is_err() {
                    eprintln!("[VS] stream read len failed");
                    continue;
                }
                let len = u32::from_le_bytes(len_bytes) as usize;

                let mut buf = vec![0u8; len];
                if recv.read_exact(&mut buf).await.is_err() {
                    eprintln!("[VS] stream read body failed");
                    continue;
                }

                // Try TranscriptDigest first.
                if let Ok(td) = bincode::deserialize::<TranscriptDigest>(&buf) {
                    // Build ProtectedReceipt signed by VS.
                    let pr_body =
                        match bincode::serialize(&(td.session_id, td.gs_counter, td.receipt_tip)) {
                            Ok(b) => b,
                            Err(e) => {
                                eprintln!("[VS] ProtectedReceipt serialize body failed: {e:?}");
                                continue;
                            }
                        };

                    let sig_vs: Sig = sign(vs_sk.as_ref(), &pr_body);

                    let pr = ProtectedReceipt {
                        session_id: td.session_id,
                        gs_counter: td.gs_counter,
                        receipt_tip: td.receipt_tip,
                        sig_vs,
                    };

                    if let Err(e) = send_msg(&mut send, &pr).await {
                        eprintln!("[VS] send ProtectedReceipt failed: {e:?}");
                    } else {
                        println!(
                            "[VS] ProtectedReceipt issued for ctr {} (session {}..)",
                            td.gs_counter,
                            hex::encode(&td.session_id[..4])
                        );
                    }

                    continue;
                }

                // Otherwise, treat it as Heartbeat.
                if let Ok(hb) = bincode::deserialize::<Heartbeat>(&buf) {
                    // quick, lock and validate
                    let mut st = state.lock().unwrap();

                    // 1. session must match
                    if hb.session_id != session_id {
                        eprintln!("[VS] heartbeat session mismatch");
                        continue;
                    }

                    // 2. counter monotonic
                    if hb.gs_counter <= st.last_counter {
                        eprintln!(
                            "[VS] heartbeat non-monotonic (got {}, last {})",
                            hb.gs_counter, st.last_counter
                        );
                        continue;
                    }

                    // 3. verify sig_gs using the ephemeral per-session pubkey
                    let eph_vk = match VerifyingKey::from_bytes(&st.ephemeral_pub) {
                        Ok(vk) => vk,
                        Err(e) => {
                            eprintln!("[VS] stored ephemeral_pub invalid: {e:?}");
                            break;
                        }
                    };

                    let hb_bytes = heartbeat_sign_bytes(
                        &hb.session_id,
                        hb.gs_counter,
                        hb.gs_time_ms,
                        &hb.receipt_tip,
                    );
                    if !verify(&eph_vk, &hb_bytes, &hb.sig_gs) {
                        eprintln!("[VS] heartbeat sig BAD");
                        continue;
                    }

                    // passed all checks → record liveness
                    st.last_counter = hb.gs_counter;
                    st.last_seen_ms = now_ms();
                    continue;
                }

                eprintln!("[VS] unknown message on bi-stream");
            }
        });
    }

    // (3) watchdog: kill session if heartbeats stop
    {
        let conn = conn.clone();
        let state = state.clone();
        let session_id = session_id;
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;
                let last_seen_ms = {
                    let st = state.lock().unwrap();
                    st.last_seen_ms
                };
                let idle_ms = now_ms().saturating_sub(last_seen_ms);
                if idle_ms > HEARTBEAT_TIMEOUT_MS {
                    eprintln!(
                        "[VS] heartbeat timeout for session {}.. ({} ms idle) -> closing",
                        hex::encode(&session_id[..4]),
                        idle_ms
                    );
                    conn.close(0u32.into(), b"heartbeat timeout");
                    break;
                }
            }
        });
    }

    Ok(())
}

/// Build QUIC Endpoint bound to `bind` (e.g. "127.0.0.1:4444"),
/// with a fresh self-signed cert "vs.dev".
fn make_endpoint(bind: &str) -> Result<(Endpoint, SocketAddr)> {
    use rustls::{Certificate, PrivateKey};

    // self-signed cert for vs.dev each run (dev mode)
    let cert = generate_simple_self_signed(vec!["vs.dev".into()]).context("self-signed cert")?;
    let cert_der = cert.serialize_der().context("cert der")?;
    let key_der = cert.serialize_private_key_der();

    let cert_chain = vec![Certificate(cert_der)];
    let priv_key = PrivateKey(key_der);

    let server_cfg =
        ServerConfig::with_single_cert(cert_chain, priv_key).context("with_single_cert")?;

    let req_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("bad bind addr: {bind}"))?;

    // bind 0.0.0.0:<port> (or ::/<port>) so gs-sim can hit 127.0.0.1
    let bind_ip = match req_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, req_addr.port());

    let endpoint = Endpoint::server(server_cfg, local_addr).context("Endpoint::server")?;

    Ok((endpoint, local_addr))
}

/// Ensure we have a VS ed25519 signing keypair.
/// If missing, generate dev keys and persist.
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
