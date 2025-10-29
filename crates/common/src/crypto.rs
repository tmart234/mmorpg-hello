use crate::proto::Sig;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256 as Sha2};

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn rand_u128() -> u128 {
    rand::random::<u128>()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha2::new();
    h.update(data);
    h.finalize().into()
}

pub fn file_sha256(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha2::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

pub fn gen_ed25519() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key(); // compute before moving sk
    (sk, vk)
}

pub fn sign(sk: &SigningKey, msg: &[u8]) -> [u8; 64] {
    sk.sign(msg).to_bytes()
}

// ed25519-dalek v2: from_bytes returns a Signature (not a Result)
pub fn verify(pk: &VerifyingKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    pk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

/// VS will verify this signature using gs_pub, and then trust that
/// `ephemeral_pub` belongs to this GS session. After that, all heartbeats
/// are expected to be signed with the ephemeral key, not the long-term key.
pub fn join_request_sign_bytes(
    gs_id: &str,
    sw_hash: &[u8; 32],
    t_unix_ms: u64,
    nonce: &[u8; 16],
    ephemeral_pub: &[u8; 32],
) -> Vec<u8> {
    bincode::serialize(&(gs_id, sw_hash, t_unix_ms, nonce, ephemeral_pub)).unwrap()
}

pub fn heartbeat_sign_bytes(
    session_id: &[u8; 16],
    gs_counter: u64,
    gs_time_ms: u64,
    receipt_tip: &[u8; 32],
) -> Vec<u8> {
    bincode::serialize(&(session_id, gs_counter, gs_time_ms, receipt_tip)).unwrap()
}

pub fn rolling_hash_update(prev: [u8; 32], event_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha2::new();
    h.update(prev);
    h.update(event_bytes);
    h.finalize().into()
}

/// Turn a runtime signature Vec<u8> (should be 64 bytes)
/// into a fixed [u8; 64]. Returns None if it's the wrong length.
pub fn sigvec_to_array64(sig: &Sig) -> Option<[u8; 64]> {
    if sig.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(sig);
    Some(out)
}

/// Canonical bytes the client signs for ClientInput.
/// MUST match on both client and GS.
pub fn client_input_sign_bytes(
    session_id: &[u8; 16],
    ticket_counter: u64,
    ticket_sig_vs: &[u8; 64],
    client_nonce: u64,
    cmd: &crate::proto::ClientCmd,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 8 + 64 + 8 + 1 + 8);

    // session_id
    out.extend_from_slice(session_id);

    // ticket_counter
    out.extend_from_slice(&ticket_counter.to_le_bytes());

    // VS signature stapled to this input
    out.extend_from_slice(ticket_sig_vs);

    // client_nonce
    out.extend_from_slice(&client_nonce.to_le_bytes());

    // command tag + payload
    match cmd {
        crate::proto::ClientCmd::Move { dx, dy } => {
            out.push(0u8); // variant tag for Move
            out.extend_from_slice(&dx.to_le_bytes());
            out.extend_from_slice(&dy.to_le_bytes());
        }
    }

    out
}
