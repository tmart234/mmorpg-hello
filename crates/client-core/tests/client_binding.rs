use anyhow::{bail, Result};

fn enforce_client_binding(binding: [u8; 32], client_pub: [u8; 32]) -> Result<()> {
    if binding != [0u8; 32] && binding != client_pub {
        bail!("ticket client_binding mismatch");
    }
    Ok(())
}

#[test]
fn accepts_unbound_ticket() {
    assert!(enforce_client_binding([0u8; 32], [1u8; 32]).is_ok());
}

#[test]
fn accepts_matching_binding() {
    let me = [0xCC; 32];
    assert!(enforce_client_binding(me, me).is_ok());
}

#[test]
fn rejects_mismatched_binding() {
    assert!(enforce_client_binding([0xDD; 32], [0xEE; 32]).is_err());
}
