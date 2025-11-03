use gs_sim::ledger::{Ledger, LedgerEvent};
use std::fs;

#[test]
fn writes_one_line() {
    // Open a short, predictable session file
    let mut led = Ledger::open_for_session("test0").expect("open ledger");

    let sess: [u8; 16] = *b"0123456789abcdef";
    let who: [u8; 32] = [1; 32];
    let opid: [u8; 16] = [2; 16];
    let tip: [u8; 32] = [3; 32];

    let ev = LedgerEvent {
        t_unix_ms: 123,
        session_id: &sess,
        client_pub: &who,
        op: "Move",
        op_id: &opid,
        delta: 0,
        balance_before: 0,
        balance_after: 0,
        receipt_tip: &tip,
    };

    led.append(&ev).expect("append");

    // Read back and sanity-check
    let body = fs::read_to_string("ledger/session_test0.log").expect("read log");
    assert!(body.contains("\"op\":\"Move\""));
    assert!(body.lines().next().unwrap().starts_with("{"));
}
