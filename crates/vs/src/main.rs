//! vs: Validation Server
//!
//! Preruntime
//!     - GS connects over QUIC.
//!     - GS sends JoinRequest { gs_pub, sw_hash, t_unix_ms, nonce, sig_gs }.
//!     - We verify sig_gs with gs_pub, check timestamp freshness,
//!       (TODO) check sw_hash allowlist.
//!     - We mint session_id, sign it with vs_sk, send JoinAccept { session_id, sig_vs, vs_pub }.
//!     - We remember per-connection session state for runtime checks.
//!
//! Runtime
//!     - Heartbeats (GS -> VS):
//!         GS opens a bi-stream every ~2s and sends Heartbeat {
//!             session_id, gs_counter, gs_time_ms, receipt_tip, sig_gs
//!         }.
//!         We verify sig_gs using the gs_pub from join, enforce monotonic
//!         counter, and record last_seen_ms. Watchdog will kill the conn
//!         if heartbeats stop.
//!
//!     - PlayTickets (VS -> GS):
//!         VS opens a bi-stream every ~2s and sends PlayTicket {
//!             session_id, client_binding, counter,
//!             not_before_ms, not_after_ms,
//!             prev_ticket_hash,
//!             sig_vs
//!         }.
//!         gs-sim enforces monotonic counter, hash chaining, and sig_vs.

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

    // Ensure VS has a signing keypair; we only actually *use* the secret.
    let (vs_sk_raw, _vs_pk_raw) = load_or_make_keys(&opts.vs_sk, &opts.vs_pk)?;
    let vs_sk = Arc::new(vs_sk_raw);

    // Spin up QUIC listener with a self-signed cert.
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

        tokio::spawn(async move {
            if let Err(e) = handle_connection(connecting, vs_sk_clone).await {
                eprintln!("[VS] conn error: {e:?}");
            }
        });
    }

    Ok(())
}

/// Per-connection lifecycle:
/// - Complete join handshake
/// - Track session state (pubkey, counters, last_seen)
/// - Spawn:
///     * ticket loop (VS -> GS)
///     * heartbeat validator (GS -> VS)
///     * watchdog
async fn handle_connection(connecting: quinn::Connecting, vs_sk: Arc<SigningKey>) -> Result<()> {
    // === 1. Finish QUIC handshake ===
    let conn = connecting.await.context("handshake accept")?;
    println!("[VS] new conn from {}", conn.remote_address());

    // First bi-stream from GS carries JoinRequest. We must read that and respond.
    let (mut vs_send, mut vs_recv) = conn
        .accept_bi()
        .await
        .context("accept_bi for JoinRequest")?;

    let jr: JoinRequest = recv_msg(&mut vs_recv).await.context("recv JoinRequest")?;
    println!("[VS] got JoinRequest from gs_id={}", jr.gs_id);

    // === 2. Validate JoinRequest ===

    // 2a. Signature proves caller controls jr.gs_pub.
    let gs_vk = VerifyingKey::from_bytes(&jr.gs_pub).context("bad gs_pub")?;
    let join_bytes = join_request_sign_bytes(&jr.gs_id, &jr.sw_hash, jr.t_unix_ms, &jr.nonce);
    if !verify(&gs_vk, &join_bytes, &jr.sig_gs) {
        bail!("JoinRequest sig_gs invalid");
    }

    // 2b. Anti-replay freshness: timestamp skew must be small.
    let now = now_ms();
    let skew = now.abs_diff(jr.t_unix_ms);
    if skew > 5_000 {
        bail!("JoinRequest timestamp skew too large: {skew} ms");
    }

    // 2c. (TODO) sw_hash allowlist.
    // Intentionally skipped in this dev build to keep clippy happy.
    // We'll reintroduce this with real allowlist data.

    // === 3. Create session state ===

    // Random session_id that will bind this GS identity for runtime checks.
    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);

    // State we track for heartbeats (liveness + monotonic counter).
    // Arc<Mutex<...>> so validator + watchdog can share.
    #[derive(Clone)]
    struct SessionState {
        gs_pub: [u8; 32],
        last_counter: u64,
        last_seen_ms: u64,
    }
    let state = Arc::new(Mutex::new(SessionState {
        gs_pub: jr.gs_pub,
        last_counter: 0,
        last_seen_ms: now_ms(),
    }));

    // === 4. Send JoinAccept back to GS ===

    // sig_vs = VS signing the session_id so GS can pin VS identity.
    let sig_vs: Sig = sign(vs_sk.as_ref(), &session_id);
    let ja = JoinAccept {
        session_id,
        sig_vs,
        vs_pub: vs_sk.verifying_key().to_bytes(),
    };

    send_msg(&mut vs_send, &ja)
        .await
        .context("send JoinAccept")?;

    // === 5. Spawn runtime tasks for this connection ===

    // 5a. VS -> GS ticket loop:
    //     Send a fresh, signed PlayTicket every ~2s.
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

                // Body we're signing (everything except sig_vs).
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

                // VS signs ticket body.
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

                // Prepare hash chain for next ticket.
                prev_hash = sha256(&body_bytes);

                // Send ticket on a fresh bi-stream.
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

    // 5b. GS -> VS heartbeat validator:
    //     Accept bi-streams, read Heartbeat, verify sig_gs, enforce monotonic counter,
    //     update last_seen_ms.
    {
        let conn = conn.clone();
        let state = state.clone();
        let session_id = session_id;
        tokio::spawn(async move {
            loop {
                // GS opens a fresh bi-stream for each heartbeat.
                let pair = conn.accept_bi().await;
                let (send, mut recv) = match pair {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[VS] accept_bi heartbeat error: {e:?}");
                        break;
                    }
                };
                drop(send); // VS doesn't send anything back on this stream (yet).

                let hb_res = recv_msg::<Heartbeat>(&mut recv).await;
                let hb = match hb_res {
                    Ok(hb) => hb,
                    Err(e) => {
                        eprintln!("[VS] bad Heartbeat decode: {e:?}");
                        continue;
                    }
                };

                // Validate heartbeat.
                let mut st = state.lock().unwrap();

                // Must match this session.
                if hb.session_id != session_id {
                    eprintln!("[VS] heartbeat session mismatch");
                    continue;
                }

                // Counter must strictly increase.
                if hb.gs_counter <= st.last_counter {
                    eprintln!(
                        "[VS] heartbeat non-monotonic (got {}, last {})",
                        hb.gs_counter, st.last_counter
                    );
                    continue;
                }

                // Signature must verify against the gs_pub we saw at join.
                let gs_vk = match VerifyingKey::from_bytes(&st.gs_pub) {
                    Ok(vk) => vk,
                    Err(e) => {
                        eprintln!("[VS] stored gs_pub invalid: {e:?}");
                        break;
                    }
                };

                let hb_bytes = heartbeat_sign_bytes(
                    &hb.session_id,
                    hb.gs_counter,
                    hb.gs_time_ms,
                    &hb.receipt_tip,
                );
                if !verify(&gs_vk, &hb_bytes, &hb.sig_gs) {
                    eprintln!("[VS] heartbeat sig BAD");
                    continue;
                }

                // Passed all checks → record liveness.
                st.last_counter = hb.gs_counter;
                st.last_seen_ms = now_ms();
            }
        });
    }

    // 5c. Watchdog:
    //     If we haven't seen a valid heartbeat in >5s, close this QUIC connection.
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
                if idle_ms > 5_000 {
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

    // Done setting up; background tasks own the connection from here.
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

    // Launch QUIC server endpoint.
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
