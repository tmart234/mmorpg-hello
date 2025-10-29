//! VS (Validation Server)
//!
//! Responsibilities:
//! - Admit GS instances via an authenticated JoinRequest.
//! - Issue short-lived PlayTickets so a GS can prove “VS still blesses me” to clients.
//! - Receive GS heartbeats and enforce liveness / monotonic counters / signature validity.
//! - Receive TranscriptDigest and return a ProtectedReceipt signed by VS.
//! - Kill (revoke) a GS session fast if heartbeats stop.
//!
//! Connection lifecycle for one GS:
//!
//! Step 1: GS connects over QUIC and sends `JoinRequest` containing:
//! `{ gs_id, sw_hash, t_unix_ms, nonce, ephemeral_pub, sig_gs, gs_pub }`.
//! VS validates it and replies with
//! `JoinAccept { session_id, sig_vs, vs_pub }`.
//!
//! Step 2: VS runs three async loops for that GS.
//!
//! (a) Ticket loop:
//! VS opens a new bi-stream about every ~2s and sends a `PlayTicket`:
//!
//! ```text
//! session_id,
//! client_binding,
//! counter,
//! not_before_ms / not_after_ms,
//! prev_ticket_hash,
//! sig_vs
//! ```
//!
//! The ticket is a short-lived “blessing” the GS forwards to clients.
//! Clients refuse to send input without a fresh, valid ticket.
//!
//! (b) Stream loop:
//! GS opens bi-streams back to VS and sends either:
//! - `Heartbeat { session_id, gs_counter, gs_time_ms, receipt_tip, sig_gs }`
//! - `TranscriptDigest { session_id, gs_counter, receipt_tip }`
//!
//! VS validates heartbeats (signature using the GS’s per-session ephemeral key,
//! monotonic counter, freshness) and updates last-seen. For TranscriptDigest,
//! VS returns a `ProtectedReceipt` that’s signed by VS and echoes the digest.
//!
//! (c) Watchdog:
//! VS watches how long it’s been since the last valid heartbeat. If it’s longer
//! than HEARTBEAT_TIMEOUT_MS, VS closes the connection. That’s effectively
//! “this GS is revoked right now.”

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
use quinn::Endpoint;
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

/// Max allowed join timestamp skew (anti-replay on JoinRequest)
const JOIN_MAX_SKEW_MS: u64 = 10_000; // ~10s in dev

/// How long we'll tolerate no valid heartbeat before killing session
const HEARTBEAT_TIMEOUT_MS: u64 = 5_000; // ~5s in dev

#[derive(Parser, Debug)]
struct Opts {
    /// UDP bind address for VS QUIC endpoint. gs-sim defaults to 127.0.0.1:4444
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: String,

    /// VS signing keypair (ed25519) used to sign JoinAccept, PlayTicket,
    /// and ProtectedReceipt.
    #[arg(long, default_value = "keys/vs_ed25519.pk8")]
    vs_sk: String,
    #[arg(long, default_value = "keys/vs_ed25519.pub")]
    vs_pk: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // rustls 0.23+: pick a crypto backend (ring) for this process.
    // If we don't do this, rustls panics at runtime ("Could not automatically determine the process-level CryptoProvider").
    {
        use rustls::crypto::{ring, CryptoProvider};
        CryptoProvider::install_default(ring::default_provider())
            .expect("install ring CryptoProvider");
    }

    // Load (or create) VS signing key
    let (vs_sk_raw, _vs_pk_raw) = load_or_make_keys(&opts.vs_sk, &opts.vs_pk)?;
    let vs_sk = Arc::new(vs_sk_raw);

    // Start QUIC listener
    let (endpoint, _local_addr) = make_endpoint(&opts.bind)?;
    println!("[VS] listening on {}", opts.bind);

    loop {
        // Quinn 0.11: accept() -> Option<Connecting>
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
/// - authenticate/admit GS (JoinRequest / JoinAccept)
/// - spawn ticket loop
/// - spawn stream loop (heartbeats + transcript digests)
/// - spawn watchdog for heartbeat timeout
async fn handle_connection(incoming: quinn::Incoming, vs_sk: Arc<SigningKey>) -> Result<()> {
    // Finish QUIC handshake
    let conn = incoming.await.context("handshake accept")?;
    println!("[VS] new conn from {}", conn.remote_address());

    // FIRST BI-STREAM: JoinRequest from GS, then JoinAccept back
    let (mut vs_send, mut vs_recv) = conn
        .accept_bi()
        .await
        .context("accept_bi for JoinRequest")?;

    let jr: JoinRequest = recv_msg(&mut vs_recv).await.context("recv JoinRequest")?;

    println!(
        "[VS] got JoinRequest from gs_id={} (ephemeral pub ..{:02x}{:02x})",
        jr.gs_id, jr.ephemeral_pub[0], jr.ephemeral_pub[1]
    );

    // ===== validate JoinRequest =====

    // 1. Caller proves control of long-term gs_pub and binds ephemeral_pub.
    let gs_identity_vk = VerifyingKey::from_bytes(&jr.gs_pub).context("bad gs_pub")?;

    let join_bytes = join_request_sign_bytes(
        &jr.gs_id,
        &jr.sw_hash,
        jr.t_unix_ms,
        &jr.nonce,
        &jr.ephemeral_pub,
    );
    let sig_gs_arr: [u8; 64] = jr
        .sig_gs
        .clone()
        .try_into()
        .map_err(|_| anyhow!("JoinRequest sig_gs len != 64"))?;
    if !verify(&gs_identity_vk, &join_bytes, &sig_gs_arr) {
        bail!("JoinRequest sig_gs invalid");
    }

    // 2. Anti-replay timestamp freshness
    let now = now_ms();
    let skew = now.abs_diff(jr.t_unix_ms);
    if skew > JOIN_MAX_SKEW_MS {
        bail!("JoinRequest timestamp skew too large: {skew} ms");
    }

    // 3. TODO: enforce sw_hash allowlist here

    // ===== mint a session =====
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);

    // in-memory per-session state we track for this connection
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

    // ===== reply JoinAccept =====
    let sig_vs: Sig = sign(vs_sk.as_ref(), &session_id).to_vec();

    let ja = JoinAccept {
        session_id,
        sig_vs,
        vs_pub: vs_sk.verifying_key().to_bytes(),
    };

    send_msg(&mut vs_send, &ja)
        .await
        .context("send JoinAccept")?;

    // ===== spawn runtime loops =====

    // 1) ticket loop:
    //    VS → GS PlayTicket every ~2s over a fresh bi-stream.
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

                // Body that VS signs (must match client / GS verification)
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

                let sig_vs_arr: [u8; 64] = sign(vs_sk.as_ref(), &body_bytes);

                let pt = PlayTicket {
                    session_id,
                    client_binding: [0u8; 32],
                    counter,
                    not_before_ms: not_before,
                    not_after_ms: not_after,
                    prev_ticket_hash: prev_hash,
                    sig_vs: sig_vs_arr,
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

    // 2) stream loop:
    //    GS opens a new bi-stream for either:
    //      - Heartbeat { .. }
    //      - TranscriptDigest { .. }
    //
    //    If Heartbeat: validate sig/monotonic/etc, update liveness in `state`.
    //    If TranscriptDigest: reply with ProtectedReceipt signed by VS.
    {
        let conn = conn.clone();
        let vs_sk = vs_sk.clone();
        let session_id = session_id;
        let state_clone = state.clone();

        tokio::spawn(async move {
            loop {
                let pair = conn.accept_bi().await;
                let (mut send, mut recv) = match pair {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[VS] accept_bi stream error: {e:?}");
                        break;
                    }
                };

                // Manual framing read:
                // 4-byte little-endian length prefix, then bincode payload.
                let mut len_buf = [0u8; 4];
                if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut recv, &mut len_buf).await {
                    eprintln!("[VS] stream read len failed: {e:?}");
                    continue;
                }
                let len = u32::from_le_bytes(len_buf) as usize;

                let mut buf = vec![0u8; len];
                if let Err(e) = tokio::io::AsyncReadExt::read_exact(&mut recv, &mut buf).await {
                    eprintln!("[VS] stream read body failed: {e:?}");
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

                    let sig_vs: Sig = sign(vs_sk.as_ref(), &pr_body).to_vec();

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

                // Otherwise try Heartbeat.
                // Otherwise try Heartbeat.
                if let Ok(hb) = bincode::deserialize::<Heartbeat>(&buf) {
                    // Lock state so we can check monotonic counter and liveness.
                    let mut st = state_clone.lock().unwrap();

                    // 1) session must match
                    if hb.session_id != session_id {
                        eprintln!("[VS] heartbeat session mismatch");
                        continue;
                    }

                    // 2) counter monotonic
                    if hb.gs_counter <= st.last_counter {
                        eprintln!(
                            "[VS] heartbeat non-monotonic (got {}, last {})",
                            hb.gs_counter, st.last_counter
                        );
                        continue;
                    }

                    // 3) verify sig_gs using this session's ephemeral_pub
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
                        &hb.sw_hash,
                    );

                    // OLD (bad in a `tokio::spawn` task because of `?`)
                    // let hb_sig_arr: [u8; 64] = hb
                    //     .sig_gs
                    //     .clone()
                    //     .try_into()
                    //     .map_err(|_| anyhow!("Heartbeat sig_gs len != 64"))?;

                    // NEW (no `?`, we just handle it inline)
                    let hb_sig_arr: [u8; 64] = match hb.sig_gs.clone().try_into() {
                        Ok(arr) => arr,
                        Err(_) => {
                            eprintln!("[VS] heartbeat sig_gs wrong length (expected 64)");
                            continue;
                        }
                    };

                    if !verify(&eph_vk, &hb_bytes, &hb_sig_arr) {
                        eprintln!("[VS] heartbeat sig BAD");
                        continue;
                    }

                    // Passed all checks → record liveness
                    st.last_counter = hb.gs_counter;
                    st.last_seen_ms = now_ms();

                    continue;
                }

                eprintln!("[VS] unknown message type on bi-stream");
            }
        });
    }

    // 3) watchdog: kill connection if heartbeats stop
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
/// with a fresh self-signed cert for "vs.dev" (dev mode).
fn make_endpoint(bind: &str) -> Result<(Endpoint, SocketAddr)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    // Self-signed cert for this VS process (dev only).
    let cert = generate_simple_self_signed(vec!["vs.dev".into()]).context("self-signed cert")?;
    let cert_der = CertificateDer::from(cert.serialize_der().context("cert der")?);

    // rcgen gives us a PKCS#8 private key as Vec<u8>.
    // rustls 0.23 represents keys using PrivateKeyDer<'static>.
    let key_der_vec = cert.serialize_private_key_der();
    let priv_key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key_der_vec).into();

    // Build Quinn server config from that cert/key.
    let server_cfg = quinn::ServerConfig::with_single_cert(vec![cert_der], priv_key)
        .context("with_single_cert")?;

    // Parse requested bind addr like "127.0.0.1:4444".
    let req_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("bad bind addr: {bind}"))?;

    // Bind 0.0.0.0:<port> (or ::/<port>) so a GS on localhost can connect.
    let bind_ip = match req_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, req_addr.port());

    let endpoint = Endpoint::server(server_cfg, local_addr).context("Endpoint::server")?;

    Ok((endpoint, local_addr))
}

/// Ensure we have a VS ed25519 signing keypair on disk.
/// If missing, generate dev keys and persist them.
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
