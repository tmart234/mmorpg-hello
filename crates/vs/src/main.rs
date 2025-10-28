//! vs: Validation Server
//!
//! Preruntime
//! - GS connects over QUIC.
//! - GS sends JoinRequest {
//!   gs_id,
//!   sw_hash,
//!   t_unix_ms,
//!   nonce,
//!   ephemeral_pub,  // per-session key
//!   sig_gs,         // signed by long-term GS key
//!   gs_pub          // long-term GS pub
//!   }
//! - VS verifies:
//!   - sig_gs using gs_pub
//!   - timestamp freshness (anti-replay)
//!   - sw_hash allowlist (placeholder for now)
//! - VS mints a session_id and stores SessionState {
//!   gs_ephemeral_pub,
//!   last_counter,
//!   last_seen_ms
//!   }
//! - VS replies JoinAccept { session_id, sig_vs, vs_pub } to bind that GS to a session.
//!
//! Runtime
//! - GS opens new bi-streams to send Heartbeat {
//!   session_id,
//!   gs_counter,
////!   gs_time_ms,
//!   receipt_tip,
//!   sig_gs_ephemeral
//!   }
//!   every ~2s.
//!   VS checks:
//!   - sig_gs_ephemeral against that session's gs_ephemeral_pub
//!   - monotonic counter
//!   - liveness; kill if stalled.
//!
//! - VS opens new bi-streams to send PlayTicket {
//!   session_id,
//!   client_binding,
//!   counter,
//!   not_before_ms,
//!   not_after_ms,
//!   prev_ticket_hash,
//!   sig_vs
//!   }
//!   every ~2s.
//!   Client will use these to prove “this GS is currently blessed by VS.”

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{heartbeat_sign_bytes, join_request_sign_bytes, now_ms, sha256, sign, verify},
    framing::{recv_msg, send_msg},
    proto::{Heartbeat, JoinAccept, JoinRequest, PlayTicket, Sig},
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

/// Max allowed join timestamp skew (anti-replay)
const JOIN_MAX_SKEW_MS: u64 = 10_000; // dev ~10s

/// How long we'll tolerate no valid heartbeat before killing session
const HEARTBEAT_TIMEOUT_MS: u64 = 5_000; // dev ~5s

#[derive(Parser, Debug)]
struct Opts {
    /// UDP bind address for the VS QUIC endpoint.
    /// gs-sim defaults to 127.0.0.1:4444
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: String,

    /// VS signing keypair (ed25519) used to sign JoinAccept.sig_vs
    /// and PlayTicket.sig_vs
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
/// - spawn heartbeat validator, ticket sender, watchdog
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

    // per-session runtime state we track for this conn
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

    // ticket loop: VS → GS PlayTicket every ~2s
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
                    session_id, [0u8; 32], // client_binding placeholder
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

    // heartbeat validator: GS → VS liveness/sanity
    {
        let conn = conn.clone();
        let state = state.clone();
        let session_id = session_id;
        tokio::spawn(async move {
            loop {
                // GS opens new bi-stream for each heartbeat
                let pair = conn.accept_bi().await;
                let (send, mut recv) = match pair {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[VS] accept_bi heartbeat error: {e:?}");
                        break;
                    }
                };
                drop(send);

                let hb = match recv_msg::<Heartbeat>(&mut recv).await {
                    Ok(hb) => hb,
                    Err(e) => {
                        eprintln!("[VS] bad Heartbeat decode: {e:?}");
                        continue;
                    }
                };

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
            }
        });
    }

    // watchdog: kill session if heartbeats stop
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
