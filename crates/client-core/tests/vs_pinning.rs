use anyhow::{bail, Result};

fn verify_vs_pinned(server_vs_pub: [u8; 32], pinned_vs_pub: [u8; 32]) -> Result<()> {
    if server_vs_pub != pinned_vs_pub {
        bail!("untrusted VS pubkey from GS");
    }
    Ok(())
}

#[test]
fn rejects_vs_pub_mismatch() {
    let pinned = [0x01; 32];
    let server = [0x02; 32];
    assert!(verify_vs_pinned(server, pinned).is_err());
}

#[test]
fn accepts_vs_pub_match() {
    let pinned = [0xAB; 32];
    let server = [0xAB; 32];
    assert!(verify_vs_pinned(server, pinned).is_ok());
}
