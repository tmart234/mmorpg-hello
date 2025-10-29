use anyhow::{bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{client_input_sign_bytes, now_ms},
    proto::{ClientCmd, ClientInput, ClientToGs, PlayTicket, ServerHello, WorldSnapshot},
    tcp_framing::{tcp_recv_msg, tcp_send_msg},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::time::Duration;
use tokio::{net::TcpStream, time::sleep};

/// CLI options for the client-sim.
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

    //
    // 1. Connect to GS "client port" (gs-sim exposes this on localhost)
    //
    let mut sock = TcpStream::connect(&opts.gs_addr)
        .await
        .with_context(|| format!("connect to {}", &opts.gs_addr))?;

    //
    // 2. Read ServerHello { session_id, ticket, vs_pub }
    //
    let sh: ServerHello = tcp_recv_msg(&mut sock).await.context("recv ServerHello")?;
    let ticket: PlayTicket = sh.ticket.clone();

    //
    // Generate an ephemeral client keypair for THIS run/session.
    // (Later this can become the player's persistent identity key.)
    //
    let client_sk = SigningKey::generate(&mut OsRng);
    let client_pub = client_sk.verifying_key().to_bytes();

    //
    // Enforce that the ticket is actually meant for us, if it's bound.
    //
    if ticket.client_binding != [0u8; 32] && ticket.client_binding != client_pub {
        bail!("ticket client_binding mismatch: this ticket isn't for our client_pub");
    }

    //
    // Sanity: session_id should match in both hello + ticket.
    //
    if ticket.session_id != sh.session_id {
        bail!("ServerHello session mismatch between GS and ticket");
    }

    //
    // 3. Verify VS signature on the ticket body.
    //
    // VS signed this tuple EXACTLY:
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
    let body_bytes =
        bincode::serialize(&body_tuple).context("serialize PlayTicket body for verify")?;

    let vs_vk = VerifyingKey::from_bytes(&sh.vs_pub).context("vs_pub in ServerHello invalid")?;

    // ticket.sig_vs is [u8; 64], and dalek wants a Signature object.
    let sig_vs = Signature::from_bytes(&ticket.sig_vs);

    if vs_vk.verify_strict(&body_bytes, &sig_vs).is_err() {
        bail!("VS signature on PlayTicket did not verify");
    }

    //
    // 4. Print initial freshness info.
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

    //
    // 5. Main loop:
    // While the ticket is fresh, keep:
    //   - building a signed ClientInput
    //   - wrapping it as ClientToGs::Input(...)
    //   - sending to GS
    //   - reading back WorldSnapshot
    //
    let mut next_nonce: u64 = 1;

    loop {
        // Check that the ticket is still within [not_before_ms, not_after_ms]
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

        // The command we’re about to send this tick.
        // (In the real game this is "move me, cast spell, etc.")
        let this_cmd = ClientCmd::Move { dx: 1.0, dy: 0.0 };

        //
        // Canonical bytes we sign.
        // Must match gs-sim's check using client_input_sign_bytes().
        //
        let sign_bytes = client_input_sign_bytes(
            &sh.session_id,
            ticket.counter,
            &ticket.sig_vs,
            next_nonce,
            &this_cmd,
        );

        // Sign with our ephemeral key.
        let sig = client_sk.sign(&sign_bytes);

        //
        // Build the ClientInput struct.
        //
        let ci = ClientInput {
            session_id: sh.session_id,
            ticket_counter: ticket.counter,
            ticket_sig_vs: ticket.sig_vs, // [u8; 64] coming from VS, stapled in

            client_nonce: next_nonce,
            cmd: this_cmd,

            client_pub,
            client_sig: sig.to_bytes(), // [u8; 64] signature from us
        };

        //
        // Wrap it in the enum the GS expects on the wire.
        //
        let msg = ClientToGs::Input(ci);

        //
        // Send to GS over TCP framing (len prefix + bincode).
        //
        tcp_send_msg(&mut sock, &msg)
            .await
            .context("send ClientInput")?;

        println!(
            "[CLIENT] sent input with nonce={}, ctr={}",
            next_nonce, ticket.counter
        );

        //
        // Read the authoritative WorldSnapshot the GS just sent back.
        //
        match tcp_recv_msg::<WorldSnapshot>(&mut sock).await {
            Ok(ws) => {
                println!(
                    "[CLIENT] snapshot tick={} pos=({:.2}, {:.2}) for session {}..",
                    ws.tick,
                    ws.player_x,
                    ws.player_y,
                    hex::encode(&ws.session_id[..4])
                );
            }
            Err(e) => {
                eprintln!("[CLIENT] failed to recv WorldSnapshot: {e:?}");
                break;
            }
        }

        next_nonce += 1;

        // Pretend this is our frame rate / tick rate.
        sleep(Duration::from_millis(200)).await;

        // In smoke mode, don't run forever.
        if opts.smoke_test && next_nonce > 5 {
            break;
        }
    }

    // Give gs-sim a moment to log acceptance before exit (esp. in smoke_test).
    sleep(Duration::from_millis(100)).await;

    Ok(())
}
