//! common: shared protocol, crypto, framing.
pub mod proto;
pub mod crypto;
pub mod framing;

use serde::{Deserialize, Serialize};

pub type Sha256 = [u8; 32];
pub type Sig = [u8; 64];
pub type PubKey = [u8; 32];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,
    pub sw_hash: Sha256,
    pub t_unix_ms: u64,
    pub nonce: [u8; 16],
    pub sig_gs: Sig,
    pub gs_pub: PubKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    pub session_id: [u8; 16],
    pub ticket_key_id: u32,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub sig_vs: Sig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayTicket {
    pub session_id: [u8; 16],
    pub client_binding: Sha256,
    pub counter: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub prev_ticket_hash: Sha256,
    pub sig_vs: Sig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Heartbeat {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub gs_time_ms: u64,
    pub receipt_tip: Sha256,
    pub sig_gs: Sig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtectedReceipt {
    pub session_id: [u8; 16],
    pub tick: u64,
    pub inputs_hash: Sha256,
    pub outputs_hash: Sha256,
    pub ticket_counter_ref: u64,
    pub prev_receipt_hash: Sha256,
    pub receipt_hash: Sha256,
    pub sig_vs: Sig,
}

pub mod crypto {
    use super::*;
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, Verifier};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256 as Sha2};

    pub fn now_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }
    pub fn rand_u128() -> u128 { rand::random::<u128>() }

    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h = Sha2::new(); h.update(data); h.finalize().into()
    }
    pub fn file_sha256(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
        use std::io::Read;
        let mut f = std::fs::File::open(path)?;
        let mut h = Sha2::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = f.read(&mut buf)?; if n == 0 { break; }
            h.update(&buf[..n]);
        }
        Ok(h.finalize().into())
    }
    pub fn gen_ed25519() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng); (sk, sk.verifying_key())
    }
    pub fn sign(sk: &SigningKey, msg: &[u8]) -> [u8; 64] { sk.sign(msg).to_bytes() }
    pub fn verify(pk: &VerifyingKey, msg: &[u8], sig: &[u8; 64]) -> bool {
        pk.verify(msg, &Signature::from_bytes(sig).unwrap()).is_ok()
    }

    pub fn join_request_sign_bytes(gs_id: &str, sw_hash: &[u8; 32], t_unix_ms: u64, nonce: &[u8;16]) -> Vec<u8> {
        bincode::serialize(&(gs_id, sw_hash, t_unix_ms, nonce)).unwrap()
    }
    pub fn heartbeat_sign_bytes(session_id: &[u8; 16], gs_counter: u64, gs_time_ms: u64, receipt_tip: &[u8;32]) -> Vec<u8> {
        bincode::serialize(&(session_id, gs_counter, gs_time_ms, receipt_tip)).unwrap()
    }
}

pub mod framing {
    use anyhow::{anyhow, Result};
    use serde::{de::DeserializeOwned, Serialize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub async fn send_msg<T: Serialize>(send: &mut quinn::SendStream, value: &T) -> Result<()> {
        let body = bincode::serialize(value)?;
        let len = (body.len() as u32).to_be_bytes();
        send.write_all(&len).await?;
        send.write_all(&body).await?;
        send.finish().await?;
        Ok(())
    }

    pub async fn recv_msg<T: DeserializeOwned>(recv: &mut quinn::RecvStream) -> Result<T> {
        let mut hdr = [0u8; 4];
        recv.read_exact(&mut hdr).await?;
        let len = u32::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; len];
        recv.read_exact(&mut body).await?;
        bincode::deserialize::<T>(&body).map_err(|e| anyhow!("bincode: {e}"))
    }
}
