use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use common::{
    crypto::{client_input_sign_bytes, now_ms},
    proto::{ClientCmd, ClientInput, ClientToGs, PlayTicket, ServerHello, WorldSnapshot},
    tcp_framing::{tcp_recv_msg, tcp_send_msg},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::{fs, path::Path, time::Duration};
use tokio::{net::TcpStream, time::sleep};

/// Read the pinned VS public key from disk (keys/vs_ed25519.pub).
/// This is the VS identity we trust for *this* run. If GS tells us
/// a different vs_pub in ServerHello, we treat GS as untrusted.
fn load_pinned_vs_pub() -> Result<[u8; 32]> {
    let bytes =
        fs::read("keys/vs_ed25519.pub").context("read VS pubkey from keys/vs_ed25519.pub")?;

    if bytes.len() != 32 {
        return Err(anyhow!(
            "vs_ed25519.pub length was {}, expected 32",
            bytes.len()
        ));
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes);
    Ok(pk)
}

/// Load or create the player's Ed25519 identity keypair.
/// This is how we get "no login, but still an identity" (and thus bans).
///
/// - On first run:
///     * generate new keypair
///     * save secret -> keys/client_ed25519.pk8
///     * save pub    -> keys/client_ed25519.pub
/// - On later runs: load the same keypair so your pubkey is stable.
///
/// Return (signing_key, client_pub_bytes)
fn load_or_create_client_keys() -> Result<(SigningKey, [u8; 32])> {
    let sk_path = Path::new("keys/client_ed25519.pk8");
    let pk_path = Path::new("keys/client_ed25519.pub");

    if sk_path.exists() && pk_path.exists() {
        let sk_bytes = fs::read(sk_path).context("read client_ed25519.pk8")?;
        let pk_bytes = fs::read(pk_path).context("read client_ed25519.pub")?;

        if sk_bytes.len() != 32 {
            return Err(anyhow!(
                "client_ed25519.pk8 length was {}, expected 32",
                sk_bytes.len()
            ));
        }
        if pk_bytes.len() != 32 {
            return Err(anyhow!(
                "client_ed25519.pub length was {}, expected 32",
                pk_bytes.len()
            ));
        }

        let sk = SigningKey::from_bytes(
            &sk_bytes
                .try_into()
                .map_err(|_| anyhow!("client_sk not 32 bytes"))?,
        );

        let claimed_pub: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("client_pub not 32 bytes"))?;

        // sanity: derived pub must match stored pub, otherwise file got tampered
        let derived_pub = sk.verifying_key().to_bytes();
        if derived_pub != claimed_pub {
            return Err(anyhow!(
                "client key mismatch: stored pub != derived pub from stored sk"
            ));
        }

        Ok((sk, claimed_pub))
    } else {
        fs::create_dir_all("keys").context("mkdir keys")?;

        let sk = SigningKey::generate(&mut OsRng);
        let pub_bytes = sk.verifying_key().to_bytes();

        fs::write(sk_path, sk.to_bytes()).context("write client_ed25519.pk8")?;
        fs::write(pk_path, pub_bytes).context("write client_ed25519.pub")?;

        Ok((sk, pub_bytes))
    }
}

/// Pretty-print a [u8;32] as hex for logging / errors.
fn to_hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

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
    // 0. Load trust roots and identity:
    //    - pinned VS pubkey (who we trust to bless GS)
    //    - persistent client keypair (this is "you")
    //
    let pinned_vs_pub = load_pinned_vs_pub()?;
    let (client_sk, client_pub) = load_or_create_client_keys()?;

    //
    // 1. Connect to GS "client port" (gs-sim exposes this on localhost).
    //
    let mut sock = TcpStream::connect(&opts.gs_addr)
        .await
        .with_context(|| format!("connect to {}", &opts.gs_addr))?;

    //
    // 2. Read ServerHello { session_id, ticket, vs_pub } from GS.
    //
    let sh: ServerHello = tcp_recv_msg(&mut sock).await.context("recv ServerHello")?;
    let ticket: PlayTicket = sh.ticket.clone();

    //
    // 3. Enforce VS key pinning.
    //    We *only* trust a GS that claims to be blessed by the VS we pinned.
    //
    if sh.vs_pub != pinned_vs_pub {
        let got_hex = to_hex32(&sh.vs_pub);
        let want_hex = to_hex32(&pinned_vs_pub);
        bail!(
            "untrusted VS pubkey from GS.\n  got:  {}\n  want: {}",
            got_hex,
            want_hex
        );
    }

    //
    // 4. Enforce that the ticket is meant for us, if it's bound.
    //    ticket.client_binding == [0u8;32] => unbound / any client OK.
    //
    if ticket.client_binding != [0u8; 32] && ticket.client_binding != client_pub {
        bail!("ticket client_binding mismatch: this ticket isn't for our client_pub");
    }

    //
    // 5. Sanity: session_id should match in both hello + ticket.
    //
    if ticket.session_id != sh.session_id {
        bail!("ServerHello session mismatch between GS and ticket");
    }

    //
    // 6. Verify VS signature on the ticket body.
    //
    // VS signed:
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
    // 7. Print initial freshness info (debug / smoke output).
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
    // 8. Main loop:
    // While the ticket is fresh, keep:
    //   - signing inputs with our persistent client_sk
    //   - sending to GS
    //   - reading WorldSnapshot { tick, you, others }
    //
    let mut next_nonce: u64 = 1;

    loop {
        // Check that the ticket is still within [not_before_ms, not_after_ms].
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

        // Command for this tick.
        // Later this will be "Attack {ability=X,target=Y}" etc.
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

        // Sign with our persistent player key.
        let sig = client_sk.sign(&sign_bytes);

        //
        // Build the ClientInput struct we send to GS.
        //
        let ci = ClientInput {
            session_id: sh.session_id,
            ticket_counter: ticket.counter,
            ticket_sig_vs: ticket.sig_vs, // stapled VS signature

            client_nonce: next_nonce,
            cmd: this_cmd,

            client_pub,
            client_sig: sig.to_bytes(), // our ed25519 signature
        };

        //
        // Send to GS.
        //
        let msg = ClientToGs::Input(ci);
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
                let (you_x, you_y) = ws.you;
                println!(
                    "[CLIENT] tick={} you=({:.2},{:.2}) others={} players",
                    ws.tick,
                    you_x,
                    you_y,
                    ws.others.len()
                );
            }
            Err(e) => {
                eprintln!("[CLIENT] failed to recv WorldSnapshot: {e:?}");
                break;
            }
        }

        next_nonce += 1;

        // Simulated frame pacing.
        sleep(Duration::from_millis(200)).await;

        // In smoke mode, don't run forever.
        if opts.smoke_test && next_nonce > 5 {
            break;
        }
    }

    // Let GS log final input accept before we exit (esp in smoke_test).
    sleep(Duration::from_millis(100)).await;

    Ok(())
}
