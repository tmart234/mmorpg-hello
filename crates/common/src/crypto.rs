use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256 as Sha2};
use std::io::Read;

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

pub fn rand_u128() -> u128 { rand::random::<u128>() }

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha2::new(); h.update(data); h.finalize().into()
}

pub fn file_sha256(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha2::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

pub fn gen_ed25519() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    (sk, sk.verifying_key())
}

pub fn sign(sk: &SigningKey, m: &[u8]) -> [u8; 64] { sk.sign(m).to_bytes() }

/// ed25519-dalek v2: `Signature::from_bytes` returns a `Signature` (not a Result).
pub fn verify(pk: &VerifyingKey, m: &[u8], sig: &[u8; 64]) -> bool {
    pk.verify(m, &Signature::from_bytes(sig)).is_ok()
}

pub fn join_request_sign_bytes(gs_id: &str, sw_hash: &[u8; 32], t_unix_ms: u64, nonce: &[u8;16]) -> Vec<u8> {
    bincode::serialize(&(gs_id, sw_hash, t_unix_ms, nonce)).unwrap()
}
pub fn heartbeat_sign_bytes(session_id: &[u8;16], gs_counter: u64, gs_time_ms: u64, receipt_tip: &[u8;32]) -> Vec<u8> {
    bincode::serialize(&(session_id, gs_counter, gs_time_ms, receipt_tip)).unwrap()
}
