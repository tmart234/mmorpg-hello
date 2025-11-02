use common::crypto::client_input_sign_bytes;
use common::proto::ClientCmd;

#[test]
fn canonical_sign_bytes_are_stable() {
    let session_id = [0xAA; 16];
    let ticket_ctr = 7u64;
    let ticket_sig_vs = [0xBB; 64];
    let nonce = 42u64;
    let cmd = ClientCmd::Move { dx: 1.0, dy: 0.0 };

    let a = client_input_sign_bytes(&session_id, ticket_ctr, &ticket_sig_vs, nonce, &cmd);
    let b = client_input_sign_bytes(&session_id, ticket_ctr, &ticket_sig_vs, nonce, &cmd);
    assert_eq!(a, b, "canonical bytes must be deterministic");
}
