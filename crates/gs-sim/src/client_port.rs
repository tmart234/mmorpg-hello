use anyhow::{anyhow, bail, Context, Result};
use common::{
    crypto::{now_ms, verify},
    proto::{ClientInput, ServerHello},
    tcp_framing::{tcp_recv_msg, tcp_send_msg},
};
use ed25519_dalek::VerifyingKey;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    time::{sleep, Duration},
};

use crate::state::Shared;

pub async fn client_port_task(
    shared: Shared,
    revoke_rx_master: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:50000")
        .await
        .context("bind client port 50000")?;

    loop {
        let (sock, peer_addr) = listener.accept().await.context("accept client")?;
        println!("[GS] client connected from {}", peer_addr);

        let shared_clone = shared.clone();
        let mut revoke_rx = revoke_rx_master.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(sock, shared_clone, &mut revoke_rx).await {
                eprintln!("[GS] client handler error: {e:?}");
            }
        });
    }
}

async fn handle_client(
    mut sock: TcpStream,
    shared: Shared,
    revoke_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    // wait until we have at least one PlayTicket from VS
    let (session_id, vs_pub, ticket) = loop {
        {
            let guard = shared.lock().unwrap();
            if guard.revoked {
                bail!("session already revoked (no fresh tickets)");
            }
            if let Some(t) = &guard.latest_ticket {
                break (guard.session_id, guard.vs_pub, t.clone());
            }
        }
        sleep(Duration::from_millis(50)).await;
    };

    // send ServerHello
    let hello = ServerHello {
        session_id,
        ticket: ticket.clone(),
        vs_pub,
    };
    tcp_send_msg(&mut sock, &hello)
        .await
        .context("send ServerHello")?;

    // per-client anti-replay nonce tracking
    let mut last_client_nonce: u64 = 0;

    loop {
        // if VS revoked us, bail immediately
        if *revoke_rx.borrow() {
            bail!("revoked broadcast; disconnecting client now");
        }

        // read next ClientInput
        let ci: ClientInput = match tcp_recv_msg(&mut sock).await {
            Ok(ci) => ci,
            Err(e) => {
                eprintln!("[GS] client disconnected / recv error: {e:?}");
                break;
            }
        };

        {
            let mut guard = shared.lock().unwrap();

            // 0) session not revoked
            if guard.revoked {
                bail!("session revoked: rejecting client input");
            }

            // 1) session must match
            if ci.session_id != guard.session_id {
                bail!("client session_id mismatch");
            }

            // 2) must be using the most recent ticket
            let latest_ticket = guard
                .latest_ticket
                .as_ref()
                .ok_or_else(|| anyhow!("no ticket in shared"))?;

            if ci.ticket_counter != latest_ticket.counter {
                bail!("stale ticket_counter from client");
            }
            if ci.ticket_sig_vs != latest_ticket.sig_vs {
                bail!("wrong sig_vs from client");
            }

            // 3) verify VS actually signed that ticket body
            let body_tuple = (
                latest_ticket.session_id,
                latest_ticket.client_binding,
                latest_ticket.counter,
                latest_ticket.not_before_ms,
                latest_ticket.not_after_ms,
                latest_ticket.prev_ticket_hash,
            );
            let body_bytes = bincode::serialize(&body_tuple).context("ticket body serialize")?;

            let vs_vk = VerifyingKey::from_bytes(&guard.vs_pub).context("vs_pub bad")?;
            if !verify(&vs_vk, &body_bytes, &latest_ticket.sig_vs) {
                bail!("ticket_sig_vs didn't verify");
            }

            // 4) anti-replay: nonce monotonic per client
            if ci.client_nonce <= last_client_nonce {
                bail!("client nonce not monotonic");
            }

            // 5) ticket freshness at time of input
            let now = now_ms();
            let fresh_now = latest_ticket.not_before_ms.saturating_sub(500) <= now
                && now <= latest_ticket.not_after_ms.saturating_add(500);
            if !fresh_now {
                bail!("ticket not fresh at input time");
            }

            // accept this input
            last_client_nonce = ci.client_nonce;

            // fold it into the rolling audit hash so heartbeat can report activity
            guard.incorporate_input(ci.client_nonce, ci.ticket_counter);

            println!(
                "[GS] accepted client input {:?} (nonce={}, ticket_ctr={})",
                ci.cmd, ci.client_nonce, ci.ticket_counter
            );
        }
    }

    Ok(())
}
