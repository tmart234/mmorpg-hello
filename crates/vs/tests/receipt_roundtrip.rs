use common::proto::ProtectedReceipt;

#[test]
fn protected_receipt_bincode_roundtrip() {
    let pr = ProtectedReceipt {
        session_id: [0xAB; 16],
        gs_counter: 123,
        receipt_tip: [0xCD; 32],
        sig_vs: vec![0xEF; 64], // <-- Vec<u8>, not [u8; 64]
    };

    let buf = bincode::serialize(&pr).unwrap();
    let back: ProtectedReceipt = bincode::deserialize(&buf).unwrap();

    assert_eq!(back.session_id, [0xAB; 16]);
    assert_eq!(back.gs_counter, 123);
    assert_eq!(back.receipt_tip, [0xCD; 32]);
    assert_eq!(back.sig_vs, vec![0xEF; 64]);
}
