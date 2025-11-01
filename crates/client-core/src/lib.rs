pub use anyhow::{anyhow, bail, Context, Result};

use common::{
    crypto::{client_input_sign_bytes, now_ms},
    proto::{ClientCmd, ClientInput, ClientToGs, PlayTicket, ServerHello, WorldSnapshot},
    tcp_framing::{tcp_recv_msg, tcp_send_msg},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::{fs, path::Path};
use tokio::net::TcpStream;

pub struct Session {
    pub sock: TcpStream,
    pub session_id: [u8; 16], // <-- 16 bytes (matches common)
    pub vs_pub: [u8; 32],
    pub ticket: PlayTicket,
    pub client_pub: [u8; 32],
    pub client_sk: SigningKey,
}

// ---------- key / trust roots ----------

/// Read the pinned VS public key from disk (keys/vs_ed25519.pub).
pub fn load_pinned_vs_pub() -> Result<[u8; 32]> {
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

/// Load or create the player's Ed25519 identity keypair; returns (sk, pub_bytes).
pub fn load_or_create_client_keys() -> Result<(SigningKey, [u8; 32])> {
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

        // sanity: derived pub must match stored pub
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

// ---------- connect / handshake ----------

pub async fn connect_and_handshake(gs_addr: &str) -> Result<Session> {
    // 0) roots + identity
    let pinned_vs_pub = load_pinned_vs_pub()?;
    let (client_sk, client_pub) = load_or_create_client_keys()?;

    // 1) connect
    let mut sock = TcpStream::connect(gs_addr)
        .await
        .with_context(|| format!("connect to {}", gs_addr))?;

    // 2) recv ServerHello { session_id, ticket, vs_pub }
    let sh: ServerHello = tcp_recv_msg(&mut sock).await.context("recv ServerHello")?;
    let ticket: PlayTicket = sh.ticket.clone();

    // 3) enforce VS key pinning
    if sh.vs_pub != pinned_vs_pub {
        bail!(
            "untrusted VS pubkey from GS.\n  got:  {:02x?}\n  want: {:02x?}",
            sh.vs_pub,
            pinned_vs_pub
        );
    }

    // 4) enforce ticket client binding (if bound)
    if ticket.client_binding != [0u8; 32] && ticket.client_binding != client_pub {
        bail!("ticket client_binding mismatch: this ticket isn't for our client_pub");
    }

    // 5) session_id must match
    if ticket.session_id != sh.session_id {
        bail!("ServerHello session mismatch between GS and ticket");
    }

    // 6) verify VS signature on ticket
    // VS signed: (session_id, client_binding, counter, not_before_ms, not_after_ms, prev_ticket_hash)
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
    let sig_vs = Signature::from_bytes(&ticket.sig_vs);
    if vs_vk.verify_strict(&body_bytes, &sig_vs).is_err() {
        bail!("VS signature on PlayTicket did not verify");
    }

    // optional freshness check for logs/UX where used
    let _fresh_now = {
        let now = now_ms();
        ticket.not_before_ms.saturating_sub(500) <= now
            && now <= ticket.not_after_ms.saturating_add(500)
    };

    Ok(Session {
        sock,
        session_id: sh.session_id, // <-- [u8;16]
        vs_pub: sh.vs_pub,
        ticket,
        client_pub,
        client_sk,
    })
}

// ---------- per-tick send/recv ----------

/// Sign and send a single input for this session.
pub async fn send_input(sess: &mut Session, nonce: u64, cmd: ClientCmd) -> Result<()> {
    // Canonical bytes; must match GS verification.
    let sign_bytes = client_input_sign_bytes(
        &sess.session_id, // <-- [u8;16]
        sess.ticket.counter,
        &sess.ticket.sig_vs,
        nonce,
        &cmd,
    );
    let sig = sess.client_sk.sign(&sign_bytes);

    let ci = ClientInput {
        session_id: sess.session_id, // <-- [u8;16]
        ticket_counter: sess.ticket.counter,
        ticket_sig_vs: sess.ticket.sig_vs, // [u8;64]
        client_nonce: nonce,
        cmd,
        client_pub: sess.client_pub, // [u8;32]
        client_sig: sig.to_bytes(),  // [u8;64]
    };

    let msg = ClientToGs::Input(ci);
    tcp_send_msg(&mut sess.sock, &msg)
        .await
        .context("send ClientInput")
}

/// Read the authoritative world snapshot from GS.
pub async fn recv_world(sess: &mut Session) -> Result<WorldSnapshot> {
    tcp_recv_msg::<WorldSnapshot>(&mut sess.sock)
        .await
        .context("recv WorldSnapshot")
}
