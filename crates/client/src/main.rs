//! client-sim
//!
//! Minimal trusted client stub that talks to a single gs-sim instance over localhost TCP.
//!
//! Flow right now:
//! 1. Connect to gs-sim's "client port" (127.0.0.1:50000).
//! 2. Receive a ServerHello { session_id, ticket, vs_pub }.
//!    - `ticket` is a PlayTicket that originated at VS and was forwarded by the GS.
//!    - We verify VS's signature over that ticket body.
//!    - We check its freshness window (not_before_ms..not_after_ms).
//!
//! 3. While the ticket is still fresh, we keep sending ClientInput packets
//!    back to gs-sim, stapled with:
//!       - that exact ticket counter
//!       - that exact VS signature
//!       - a strictly monotonic client_nonce
//!
//! 4. As soon as the ticket expires, we stop sending commands.
//!
//! This is doing 2 important security behaviors:
//!   - The client REFUSES to play if it doesn't have a fresh VS-blessed ticket.
//!     (If VS revokes the GS, the GS will stop getting fresh tickets,
//!     and this client will freeze automatically.)
//!
//!   - Every input is cryptographically stapled to proof that "this GS was valid
//!     and current at VS" at the moment of input. The GS MUST reject commands
//!     if the ticket is stale or mismatched.

use anyhow::{bail, Context, Result};
use clap::Parser;
use common::{
    crypto::now_ms,
    proto::{ClientCmd, ClientInput, ServerHello},
    tcp_framing::{tcp_recv_msg, tcp_send_msg},
};
use ed25519_dalek::{Signature, VerifyingKey};
use std::time::Duration;
use tokio::{net::TcpStream, time::sleep};

#[derive(Parser, Debug)]
struct Opts {
    /// Where gs-sim is serving the local client port.
    #[arg(long, default_value = "127.0.0.1:50000")]
    gs_addr: String,

    /// If set, we just run a short smoke loop, then exit.
    #[arg(long)]
    smoke_test: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // 1. Connect to GS "client port" (gs-sim exposes this on localhost)
    let mut sock = TcpStream::connect(&opts.gs_addr)
        .await
        .with_context(|| format!("connect to {}", &opts.gs_addr))?;

    // 2. Read ServerHello { session_id, ticket, vs_pub }
    //
    //    ticket = latest PlayTicket from VS that gs-sim is forwarding.
    //    vs_pub = VS' long-term signing key (ed25519 public key).
    //
    let sh: ServerHello = tcp_recv_msg(&mut sock).await.context("recv ServerHello")?;
    let ticket = sh.ticket.clone();

    // Sanity: ticket.session_id should match the session_id GS claims to be under.
    if ticket.session_id != sh.session_id {
        bail!("ServerHello session mismatch between GS and ticket");
    }

    // 3. Verify VS signature on the ticket body.
    //
    // VS signed this tuple EXACTLY (must match VS implementation):
    // (session_id, client_binding, counter, not_before_ms, not_after_ms, prev_ticket_hash)
    //
    let body_tuple = (
        ticket.session_id,
        ticket.client_binding,
        ticket.counter,
        ticket.not_before_ms,
        ticket.not_after_ms,
        ticket.prev_ticket_hash,
    );
    let body_bytes = bincode::serialize(&body_tuple)?;

    let vs_vk = VerifyingKey::from_bytes(&sh.vs_pub).context("vs_pub in ServerHello invalid")?;
    let sig_vs = Signature::from_bytes(&ticket.sig_vs);

    if vs_vk.verify_strict(&body_bytes, &sig_vs).is_err() {
        bail!("VS signature on PlayTicket did not verify");
    }

    // 4. Log initial freshness
    //
    // A PlayTicket has a time window [not_before_ms, not_after_ms].
    // Client refuses to "play" if outside that window.
    //
    let now = now_ms();
    let fresh_now = ticket.not_before_ms.saturating_sub(500) <= now
        && now <= ticket.not_after_ms.saturating_add(500);

    println!(
        "[CLIENT] got ticket #{} (fresh={}) for session {}..",
        ticket.counter,
        fresh_now,
        hex::encode(&ticket.session_id[..4])
    );

    // 5. Main input loop:
    //
    // While the ticket is fresh, keep sending ClientInput.
    // As soon as it goes stale → stop.
    //
    // This models what the real game loop will do:
    // - each frame / tick, we attach the latest VS-blessed ticket proof
    // - if proof expires (VS revoked GS or liveness lost), we STOP SENDING INPUT.
    //
    let mut next_nonce: u64 = 1;

    loop {
        // recompute freshness each iteration
        let now = now_ms();
        let fresh = ticket.not_before_ms.saturating_sub(500) <= now
            && now <= ticket.not_after_ms.saturating_add(500);

        if !fresh {
            println!(
                "[CLIENT] ticket expired; stopping input (session {}.., ctr={})",
                hex::encode(&sh.session_id[..4]),
                ticket.counter
            );
            break;
        }

        // Build ClientInput stapled with proof:
        // - session_id: which GS session this input is for
        // - ticket_counter / ticket_sig_vs: prove GS is still VS-blessed
        // - client_nonce: strictly increasing per-client anti-replay
        // - cmd: gameplay intent (move, fire, etc.)
        //
        let ci = ClientInput {
            session_id: sh.session_id,
            ticket_counter: ticket.counter,
            ticket_sig_vs: ticket.sig_vs,
            client_nonce: next_nonce,
            cmd: ClientCmd::Move { dx: 1.0, dy: 0.0 },
        };

        tcp_send_msg(&mut sock, &ci)
            .await
            .context("send ClientInput")?;

        println!(
            "[CLIENT] sent input with nonce={}, ctr={}",
            next_nonce, ticket.counter
        );

        next_nonce += 1;

        // pretend this is our frame/tick cadence
        sleep(Duration::from_millis(200)).await;

        // for smoke_test, we don't have to run forever.
        if opts.smoke_test && next_nonce > 5 {
            break;
        }
    }

    // Give gs-sim a moment to log acceptance before we exit (esp. in smoke_test)
    sleep(Duration::from_millis(100)).await;

    Ok(())
}
