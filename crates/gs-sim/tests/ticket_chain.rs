use ed25519_dalek::{Signer, SigningKey};
use gs_sim::verify_and_hash_ticket;
use rand::rngs::OsRng;

use common::{crypto::now_ms, proto::PlayTicket};

fn mk_ticket(
    vs_sk: &SigningKey,
    session_id: [u8; 16],
    counter: u64,
    prev_hash: [u8; 32],
    window_ms: u64,
) -> PlayTicket {
    let now = now_ms();
    let nb = now.saturating_sub(10);
    let na = now.saturating_add(window_ms);
    let client_binding = [0u8; 32];

    let body_tuple = (session_id, client_binding, counter, nb, na, prev_hash);
    let body_bytes = bincode::serialize(&body_tuple).unwrap();
    let sig = vs_sk.sign(&body_bytes).to_bytes();

    PlayTicket {
        session_id,
        client_binding,
        counter,
        not_before_ms: nb,
        not_after_ms: na,
        prev_ticket_hash: prev_hash,
        sig_vs: sig,
    }
}

#[test]
fn chain_two_tickets_ok() {
    let vs_sk = SigningKey::generate(&mut OsRng);
    let vs_pk = vs_sk.verifying_key();
    let session_id = *b"0123456789ABCDEF";

    let prev_hash0 = [0u8; 32];
    let t1 = mk_ticket(&vs_sk, session_id, 1, prev_hash0, 5_000);
    let h1 = verify_and_hash_ticket(0, prev_hash0, &t1, &vs_pk).expect("t1 ok");

    let t2 = mk_ticket(&vs_sk, session_id, 2, h1, 5_000);
    let _h2 = verify_and_hash_ticket(1, h1, &t2, &vs_pk).expect("t2 ok");
}

#[test]
fn reject_bad_counter() {
    let vs_sk = SigningKey::generate(&mut OsRng);
    let vs_pk = vs_sk.verifying_key();
    let session_id = *b"0123456789ABCDEF";

    let t1 = mk_ticket(&vs_sk, session_id, 2, [0u8; 32], 5_000);
    assert!(verify_and_hash_ticket(0, [0u8; 32], &t1, &vs_pk).is_err());
}

#[test]
fn reject_bad_prev_hash() {
    let vs_sk = SigningKey::generate(&mut OsRng);
    let vs_pk = vs_sk.verifying_key();
    let session_id = *b"0123456789ABCDEF";

    let wrong_prev = [9u8; 32];
    let t1 = mk_ticket(&vs_sk, session_id, 1, wrong_prev, 5_000);
    assert!(verify_and_hash_ticket(0, [0u8; 32], &t1, &vs_pk).is_err());
}
