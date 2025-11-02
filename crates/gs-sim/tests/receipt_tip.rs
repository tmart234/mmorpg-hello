use common::crypto::receipt_tip_update;

#[test]
fn receipt_tip_is_deterministic_and_ordered() {
    let prev = [0u8; 32];
    let a = b"A";
    let b = b"B";

    let h1 = receipt_tip_update(&prev, a, b);
    let h2 = receipt_tip_update(&prev, a, b);
    assert_eq!(h1, h2, "deterministic, same inputs");

    let h_swapped = receipt_tip_update(&prev, b, a);
    assert_ne!(h1, h_swapped, "order must matter");

    // changes in previous tip change output
    let mut prev2 = [0u8; 32];
    prev2[0] = 1;
    let h3 = receipt_tip_update(&prev2, a, b);
    assert_ne!(h1, h3);
}
