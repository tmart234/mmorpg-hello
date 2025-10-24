use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use sha2::{Sha256, Digest};

pub fn sha256(data: &[u8]) -> [u8;32] {
    let mut h = Sha256::new(); h.update(data); h.finalize().into()
}
pub fn sign(sk: &SigningKey, m: &[u8]) -> [u8;64] { sk.sign(m).to_bytes() }
pub fn verify(pk: &VerifyingKey, m: &[u8], sig: &[u8;64]) -> bool {
    pk.verify(m, &Signature::from_bytes(sig).unwrap()).is_ok()
}
