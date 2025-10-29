use anyhow::{bail, Context, Result};
use clap::Parser;
use common::{
    crypto::now_ms,
    proto::{ClientCmd, ClientInput, ServerHello},
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};

#[derive(Parser, Debug)]
struct Opts {
    /// Where gs-sim is serving the local client port.
    #[arg(long, default_value = "127.0.0.1:50000")]
    gs_addr: String,

    /// If set, we just prove a single round trip then exit.
    #[arg(long)]
    smoke_test: bool,
}

// length-prefixed bincode framing over the TCP stream
async fn tcp_recv_msg<T: DeserializeOwned>(sock: &mut TcpStream) -> Result<T> {
    let mut len_bytes = [0u8; 4];
    sock.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    let mut buf = vec![0u8; len];
    sock.read_exact(&mut buf).await?;

    let msg: T = bincode::deserialize(&buf)?;
    Ok(msg)
}

async fn tcp_send_msg<T: Serialize>(sock: &mut TcpStream, msg: &T) -> Result<()> {
    let buf = bincode::serialize(msg)?;
    let len = buf.len() as u32;

    sock.write_all(&len.to_le_bytes()).await?;
    sock.write_all(&buf).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // Connect to GS "client port"
    let mut sock = TcpStream::connect(&opts.gs_addr)
        .await
        .with_context(|| format!("connect to {}", &opts.gs_addr))?;

    // 1. Read ServerHello { session_id, ticket, vs_pub }
    let sh: ServerHello = tcp_recv_msg(&mut sock).await.context("recv ServerHello")?;

    let ticket = sh.ticket.clone();

    // Sanity: ticket.session_id should match session_id GS says it's running
    if ticket.session_id != sh.session_id {
        bail!("ServerHello session mismatch between GS and ticket");
    }

    // 2. Verify VS signature on ticket body
    //
    // VS signed the tuple:
    // (session_id, client_binding, counter, not_before_ms, not_after_ms, prev_ticket_hash)
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

    // 3. Check freshness window for local decision-making
    let now = now_ms();
    let fresh = ticket.not_before_ms.saturating_sub(500) <= now
        && now <= ticket.not_after_ms.saturating_add(500);

    println!(
        "[CLIENT] got ticket #{} (fresh={}) for session {}..",
        ticket.counter,
        fresh,
        hex::encode(&ticket.session_id[..4])
    );

    // 4. Build one ClientInput to send back to GS.
    // The GS will verify:
    // - session_id matches
    // - ticket_counter matches its freshest ticket
    // - ticket_sig_vs matches
    // - nonce is monotonic
    // - VS sig is still valid
    //
    // For smoke we just send a single "Move".
    let my_nonce: u64 = 1;
    let ci = ClientInput {
        session_id: sh.session_id,
        ticket_counter: ticket.counter,
        ticket_sig_vs: ticket.sig_vs,
        client_nonce: my_nonce,
        cmd: ClientCmd::Move { dx: 1.0, dy: 0.0 },
    };

    tcp_send_msg(&mut sock, &ci)
        .await
        .context("send ClientInput")?;

    println!(
        "[CLIENT] sent input with nonce={}, ctr={}",
        my_nonce, ticket.counter
    );

    if opts.smoke_test {
        // give gs-sim a moment to log acceptance before we exit
        sleep(Duration::from_millis(100)).await;
    }

    Ok(())
}
