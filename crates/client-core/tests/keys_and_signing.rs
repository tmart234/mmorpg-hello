use client_core::load_or_create_client_keys;
use common::crypto::client_input_sign_bytes;
use common::proto::ClientCmd;
use ed25519_dalek::{Signer, VerifyingKey};

#[test]
fn keys_persist_and_signatures_verify() {
    // Generate or load persistent keys
    let (sk, client_pub) = load_or_create_client_keys().expect("load/create keys");

    // Build deterministic message to sign (matches GS verify path)
    let sign_bytes = client_input_sign_bytes(
        &[0x11; 16], // session_id
        1,           // ticket counter
        &[0x22; 64], // stapled VS sig
        999,         // nonce
        &ClientCmd::Move { dx: 0.5, dy: -0.25 },
    );

    // Sign and verify
    let sig = sk.sign(&sign_bytes);
    let vk = VerifyingKey::from_bytes(&client_pub).expect("vk");
    assert!(
        vk.verify_strict(&sign_bytes, &sig).is_ok(),
        "signature must verify"
    );

    // Negative: flip a byte → verify must fail
    let mut tampered = sign_bytes.clone();
    tampered[0] ^= 0xFF;
    assert!(
        vk.verify_strict(&tampered, &sig).is_err(),
        "tamper must fail verify"
    );
}
