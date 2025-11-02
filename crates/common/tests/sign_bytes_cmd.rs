use common::crypto::client_input_sign_bytes;
use common::proto::ClientCmd;

#[test]
fn sign_bytes_differ_when_command_differs() {
    let session_id = [0xAA; 16];
    let ticket_ctr = 9u64;
    let ticket_sig_vs = [0xBB; 64];

    let cmd1 = ClientCmd::Move { dx: 1.0, dy: 0.0 };
    let cmd2 = ClientCmd::Move { dx: 0.0, dy: 1.0 };

    let a = client_input_sign_bytes(&session_id, ticket_ctr, &ticket_sig_vs, 1, &cmd1);
    let b = client_input_sign_bytes(&session_id, ticket_ctr, &ticket_sig_vs, 1, &cmd2);

    assert_ne!(
        a, b,
        "changing the command must change canonical sign-bytes"
    );
}
