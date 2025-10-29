// gs-sim: minimal game server simulator.
//
// Responsibilities right now:
//
// 1. Join the Validation Server (VS) over QUIC.
//    - Send JoinRequest proving long-term GS key.
//    - VS replies JoinAccept with session_id + sig_vs.
//
// 2. Stream heartbeats to VS signed with an ephemeral session key (ephemeral_pub).
//
// 3. Receive PlayTickets from VS. Each ticket says:
//    "this GS session is blessed and still alive."
//    - We verify VS signatures and build a hash chain.
//
// 4. Expose a local TCP "client port" on 127.0.0.1:50000.
//    - A fake client (client-sim) connects.
//    - We send it the freshest PlayTicket plus vs_pub in a ServerHello.
//    - Client verifies sig_vs, then sends back ClientInput stapled to that ticket.
//    - We verify that input and log success.
//
// tools/smoke does end-to-end:
//  - start VS
//  - start gs-sim --test-once
//  - start client-sim --smoke-test
//  - assert everyone can prove trust to everyone else
//  - exit cleanly

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{
        file_sha256, heartbeat_sign_bytes, join_request_sign_bytes, now_ms, sha256, sign, verify,
    },
    framing::{recv_msg, send_msg}, // QUIC bincode framing
    proto::{ClientInput, Heartbeat, JoinAccept, JoinRequest, PlayTicket, ServerHello, Sig},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{ClientConfig, Connection, Endpoint};
use rand::{rngs::OsRng, RngCore};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::sleep,
};

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

/// Shared GS runtime state we expose to the local client port.
// Replace the existing struct GsSharedState with this:
struct GsSharedState {
    session_id: [u8; 16],
    vs_pub: [u8; 32],
    latest_ticket: Option<PlayTicket>,
    last_client_nonce: u64,

    last_ticket_ms: u64, // last time we accepted a fresh PlayTicket
    revoked: bool,       // set true if VS stops blessing
}

impl GsSharedState {
    fn new(session_id: [u8; 16], vs_pub: [u8; 32]) -> Self {
        Self {
            session_id,
            vs_pub,
            latest_ticket: None,
            last_client_nonce: 0,
            last_ticket_ms: 0,
            revoked: false,
        }
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // 1. Load/generate long-term GS identity keypair.
    let (gs_sk_long, gs_pk_long) = load_or_make_keys(&opts.gs_sk, &opts.gs_pk)?;

    // 2. Generate per-session ephemeral signing key.
    //    VS will bind this key to the session for runtime auth (heartbeats).
    let eph_sk = SigningKey::generate(&mut OsRng);
    let eph_pub_bytes = eph_sk.verifying_key().to_bytes();

    // 3. Compute "attestation" hash of this binary (dev placeholder).
    let exe = std::env::current_exe()?;
    let sw_hash = file_sha256(&exe)?;

    // 4. QUIC endpoint + connect to VS.
    let (endpoint, server_addr) = make_endpoint_and_addr(&opts.vs)?;
    let conn: Connection = endpoint
        .connect_with(make_client_cfg_insecure()?, server_addr, "vs.dev")?
        .await?;
    println!("[GS] connected to VS at {server_addr}");

    // 5. Send JoinRequest on a fresh bi-stream.
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

    // 6. Verify VS proved identity in JoinAccept.
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

    // 7. Shared state so:
    //    - ticket_listener() can stash latest PlayTicket
    //    - client_port_task() can hand it to client-sim and verify ClientInput
    let shared = Arc::new(Mutex::new(GsSharedState::new(ja.session_id, ja.vs_pub)));

    // 8. Spawn runtime tasks:
    //    a) heartbeat_loop: GS → VS liveness every ~2s
    //    b) ticket_listener: VS → GS PlayTickets every ~2s
    //    c) client_port_task: tiny TCP server for client-sim
    let hb_counter = Arc::new(AtomicU64::new(0));
    let heartbeat_task = tokio::spawn(heartbeat_loop(
        conn.clone(),
        hb_counter.clone(),
        eph_sk.clone(),
        ja.session_id,
    ));

    let tickets_task = tokio::spawn(ticket_listener(conn.clone(), shared.clone(), vs_vk));

    let client_port_task_handle = tokio::spawn(client_port_task(shared.clone()));

    // 9. --test-once mode: sleep a bit so smoke can poke us, then exit 0.
    if opts.test_once {
        sleep(Duration::from_secs(5)).await;

        // Kill background tasks explicitly so clippy doesn't complain
        heartbeat_task.abort();
        tickets_task.abort();
        client_port_task_handle.abort();

        println!("[GS] test_once complete.");
        return Ok(());
    }

    // 10. prod-ish mode: run until a background task dies.
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

/// Heartbeats GS→VS, signed with the ephemeral per-session key.
async fn heartbeat_loop(
    conn: Connection,
    counter: Arc<AtomicU64>,
    eph_sk: SigningKey,
    session_id: [u8; 16],
) -> Result<()> {
    let receipt_tip = [0u8; 32]; // placeholder

    loop {
        sleep(Duration::from_secs(2)).await;

        let c = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let now = now_ms();

        let to_sign = heartbeat_sign_bytes(&session_id, c, now, &receipt_tip);
        let sig_gs = sign(&eph_sk, &to_sign);

        let hb = Heartbeat {
            session_id,
            gs_counter: c,
            gs_time_ms: now,
            receipt_tip,
            sig_gs,
        };

        let pair = conn.open_bi().await;
        let (mut send, _recv) = match pair {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[GS] heartbeat open_bi failed: {e:?}");
                break;
            }
        };

        if let Err(e) = send_msg(&mut send, &hb).await {
            eprintln!("[GS] heartbeat send failed: {e:?}");
        } else {
            println!("[GS] ♥ heartbeat {}", c);
        }
    }

    Ok(())
}

/// VS → GS PlayTickets. We verify VS sig and chain, then stash
/// latest ticket into shared so the client_port_task can hand it to clients.
// Replace the entire function with this:
async fn ticket_listener(
    conn: Connection,
    shared: Arc<Mutex<GsSharedState>>,
    vs_pub: VerifyingKey,
) -> Result<()> {
    // continuity
    let mut last_counter: u64 = 0;
    let mut last_hash: [u8; 32] = [0u8; 32];

    // Spawn a tiny watchdog here that marks revoked if ticket stream stalls.
    // 2.5s grace since tickets are ~2s apart.
    {
        let shared_for_watchdog = Arc::clone(&shared);
        tokio::spawn(async move {
            const LIVENESS_BUDGET_MS: u64 = 2_500;
            loop {
                sleep(Duration::from_millis(250)).await;
                let (revoked_now, idle_ms) = {
                    let guard = shared_for_watchdog.lock().unwrap();
                    let last = guard.last_ticket_ms;
                    let now = now_ms();
                    let idle = now.saturating_sub(last);
                    let should_revoke = last != 0 && idle > LIVENESS_BUDGET_MS;
                    (should_revoke || guard.revoked, idle)
                };

                // flip the bit once
                if revoked_now {
                    let mut guard = shared_for_watchdog.lock().unwrap();
                    if !guard.revoked {
                        guard.revoked = true;
                        eprintln!(
                            "[GS] VS blessing lost (no fresh ticket in {} ms) → session revoked",
                            idle_ms
                        );
                    }
                }
            }
        });
    }

    loop {
        let pair = conn.accept_bi().await;
        let (send, mut recv) = match pair {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[GS] accept_bi error: {e:?}");
                break;
            }
        };
        drop(send); // GS doesn't send back on ticket streams.

        let pt_res = recv_msg::<PlayTicket>(&mut recv).await;
        let pt = match pt_res {
            Ok(pt) => pt,
            Err(e) => {
                eprintln!("[GS] bad ticket: {e:?}");
                continue;
            }
        };

        // 1) counter must strictly increase
        if pt.counter != last_counter + 1 {
            eprintln!(
                "[GS] ticket counter non-monotonic (got {}, expected {})",
                pt.counter,
                last_counter + 1
            );
            break;
        }

        // 2) prev_ticket_hash continuity (chain)
        if pt.prev_ticket_hash != last_hash {
            eprintln!("[GS] ticket prev_hash mismatch");
            break;
        }

        // 3) verify VS sig on ticket body
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

        // 4) time window sanity
        let now = now_ms();
        let fresh = pt.not_before_ms.saturating_sub(500) <= now
            && now <= pt.not_after_ms.saturating_add(500);

        println!("[GS] ticket #{} (time_ok={})", pt.counter, fresh);

        // 5) update continuity
        last_counter = pt.counter;
        last_hash = sha256(&body_bytes);

        // 6) stash for client_port_task + bump liveness clock
        {
            let mut guard = shared.lock().unwrap();
            guard.latest_ticket = Some(pt.clone());
            guard.last_ticket_ms = now; // mark “we’re freshly blessed”
        }
    }

    Ok(())
}

/// Local TCP port for clients.
/// Protocol:
///   GS waits until it has a ticket from VS,
///   then for first incoming TCP client:
///     - send ServerHello {session_id, ticket, vs_pub}
///     - recv ClientInput
///     - verify stapled proof (ticket + nonce)
async fn client_port_task(shared: Arc<Mutex<GsSharedState>>) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:50000")
        .await
        .context("bind client port 50000")?;

    // accept exactly one client for smoke
    let (mut sock, peer_addr) = listener.accept().await.context("accept client-sim")?;
    println!("[GS] client-sim connected from {}", peer_addr);

    // wait until we have at least one PlayTicket from VS
    let (session_id, vs_pub, ticket) = loop {
        {
            let guard = shared.lock().unwrap();
            if let Some(t) = &guard.latest_ticket {
                break (guard.session_id, guard.vs_pub, t.clone());
            }
        }
        sleep(Duration::from_millis(50)).await;
    };

    // If already revoked before first hello, reject immediately.
    {
        let guard = shared.lock().unwrap();
        if guard.revoked {
            bail!("session already revoked (no fresh tickets)");
        }
    }

    // send ServerHello over TCP
    let hello = ServerHello {
        session_id,
        ticket: ticket.clone(),
        vs_pub,
    };
    tcp_send_msg(&mut sock, &hello)
        .await
        .context("send ServerHello to client-sim")?;

    // Now stay in a loop to receive multiple ClientInput packets
    loop {
        // Try to receive the next input from this client.
        let ci: ClientInput = match tcp_recv_msg(&mut sock).await {
            Ok(ci) => ci,
            Err(e) => {
                // If client closed or errored, we're done.
                eprintln!("[GS] client_port_task recv error / disconnect: {e:?}");
                break;
            }
        };

        // Validate this input against current shared state.
        // We do all checks without `.await` while holding the lock briefly.
        let res = {
            let mut guard = shared.lock().unwrap();

            // 0) session not revoked
            if guard.revoked {
                Err(anyhow!("session revoked: rejecting client input"))
            }
            // 1) session must match
            else if ci.session_id != guard.session_id {
                Err(anyhow!("client-sim session_id mismatch"))
            }
            // 2) must be using the most recent ticket we handed out
            else if ci.ticket_counter != ticket.counter {
                Err(anyhow!("client-sim used stale ticket"))
            } else if ci.ticket_sig_vs != ticket.sig_vs {
                Err(anyhow!("client-sim sent wrong sig_vs"))
            } else {
                // 3) verify VS actually signed that ticket body (defense in depth)
                let body_tuple = (
                    ticket.session_id,
                    ticket.client_binding,
                    ticket.counter,
                    ticket.not_before_ms,
                    ticket.not_after_ms,
                    ticket.prev_ticket_hash,
                );
                let body_bytes =
                    bincode::serialize(&body_tuple).context("ticket body serialize")?;

                let vs_vk = VerifyingKey::from_bytes(&guard.vs_pub).context("vs_pub bad")?;
                if !verify(&vs_vk, &body_bytes, &ticket.sig_vs) {
                    Err(anyhow!(
                        "client-sim provided ticket_sig_vs that doesn't verify"
                    ))
                } else {
                    // 4) anti-replay: nonce monotonic
                    if ci.client_nonce <= guard.last_client_nonce {
                        Err(anyhow!("client-sim nonce not monotonic"))
                    } else {
                        // 5) ticket still fresh *now*
                        let now = now_ms();
                        let fresh_now = ticket.not_before_ms.saturating_sub(500) <= now
                            && now <= ticket.not_after_ms.saturating_add(500);
                        if !fresh_now {
                            Err(anyhow!("client-sim ticket is not fresh at input time"))
                        } else {
                            // success: record nonce and log
                            guard.last_client_nonce = ci.client_nonce;
                            println!(
                                "[GS] accepted client input {:?} (nonce={}, ticket_ctr={})",
                                ci.cmd, ci.client_nonce, ci.ticket_counter
                            );
                            Ok(())
                        }
                    }
                }
            }
        };

        if let Err(e) = res {
            eprintln!("[GS] rejecting client input: {e:?}");
            break;
        }

        // loop continues and waits for next ClientInput
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

    // bind wildcards in the same family as VS
    let bind_ip = match server_addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let local_addr = SocketAddr::new(bind_ip, 0);

    let udp = UdpSocket::bind(local_addr)?;
    udp.set_nonblocking(true)?;

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        None, // client-only
        udp,
        Arc::new(TokioRuntime),
    )?;

    Ok((endpoint, server_addr))
}

async fn tcp_recv_msg<T: serde::de::DeserializeOwned>(sock: &mut TcpStream) -> Result<T> {
    let mut len_bytes = [0u8; 4];
    sock.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf).await?;

    let msg: T = bincode::deserialize(&buf)?;
    Ok(msg)
}

async fn tcp_send_msg<T: serde::Serialize>(sock: &mut TcpStream, msg: &T) -> Result<()> {
    let buf = bincode::serialize(msg)?;
    let len = buf.len() as u32;

    sock.write_all(&len.to_le_bytes()).await?;
    sock.write_all(&buf).await?;
    Ok(())
}
