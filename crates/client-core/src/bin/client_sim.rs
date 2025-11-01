use anyhow::Result;
use clap::Parser;
use client_core::*;
use common::proto::ClientCmd;
use tokio::time::{sleep, Duration};

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
    let mut sess = connect_and_handshake(&opts.gs_addr).await?;
    let mut nonce = 1_u64;

    loop {
        // simple smoke: move right
        send_input(&mut sess, nonce, ClientCmd::Move { dx: 1.0, dy: 0.0 }).await?;
        let ws = recv_world(&mut sess).await?;
        println!(
            "[CLIENT] tick={} you=({:.2},{:.2})",
            ws.tick, ws.you.0, ws.you.1
        );

        nonce += 1;
        sleep(Duration::from_millis(200)).await;

        if opts.smoke_test && nonce > 5 {
            break;
        }
    }
    Ok(())
}
