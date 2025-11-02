use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

#[test]
fn ticket_body_sign_verify_and_mutation_fails() {
    // This mirrors the tuple you verify in client/GS.
    // (session_id, client_binding, counter, not_before_ms, not_after_ms, prev_ticket_hash)
    let session_id = [0x11; 16];
    let client_binding = [0x22; 32];
    let counter = 42u64;
    let not_before_ms = 1_700_000_000_000u64;
    let not_after_ms = 1_700_000_100_000u64;
    let prev_ticket_hash = [0x33; 32];

    let body = (
        session_id,
        client_binding,
        counter,
        not_before_ms,
        not_after_ms,
        prev_ticket_hash,
    );
    let body_bytes = bincode::serialize(&body).unwrap();

    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = VerifyingKey::from(&sk);

    let sig: Signature = sk.sign(&body_bytes);
    assert!(
        vk.verify_strict(&body_bytes, &sig).is_ok(),
        "baseline verify"
    );

    // Change one field -> verify must fail
    let body_mut = (
        session_id,
        client_binding,
        counter + 1,
        not_before_ms,
        not_after_ms,
        prev_ticket_hash,
    );
    let body_mut_bytes = bincode::serialize(&body_mut).unwrap();
    assert!(
        vk.verify_strict(&body_mut_bytes, &sig).is_err(),
        "mutating fields must break signature"
    );
}
