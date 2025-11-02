use common::crypto::client_input_sign_bytes;
use common::proto::ClientCmd;

#[test]
fn sign_bytes_differ_when_nonce_differs() {
    let session_id = [0x11; 16];
    let ticket_ctr = 7u64;
    let ticket_sig_vs = [0x22; 64];
    let cmd = ClientCmd::Move { dx: 1.0, dy: 0.0 };

    let a = client_input_sign_bytes(&session_id, ticket_ctr, &ticket_sig_vs, 100, &cmd);
    let b = client_input_sign_bytes(&session_id, ticket_ctr, &ticket_sig_vs, 101, &cmd);

    assert_ne!(a, b, "nonce must perturb canonical sign-bytes");
}
