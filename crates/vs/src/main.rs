//! vs: Validation Server
//!
//! This is the in-progress local VS used by `tools::smoke`.
//!
//! What this version does:
//! - Ensures we have a dev ed25519 keypair on disk (vs_ed25519.pk8 / .pub).
//! - Announces the address we intend to serve QUIC on (127.0.0.1:4444).
//! - Parks forever so the process stays alive for smoke tests.
//!
//! What we'll add next:
//! - Actual QUIC listener (Quinn endpoint bound to that UDP port).
//! - Accept incoming GS connections.
//! - Read a `JoinRequest` (bincode over a bidirectional QUIC stream).
//! - Reply with a signed `JoinAccept` containing a fresh session_id.
//!
//! We structure it this way so the rest of the workspace (gs-sim, smoke)
//! can start assuming VS has keys, a bind addr, etc., without panicking.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::{fs, path::PathBuf, time::Duration};
use tokio::time::sleep;

// Hardcoded dev defaults for now. Smoke does not pass args to `vs` yet,
// so we keep these here instead of using clap::Parser.
const BIND_ADDR: &str = "127.0.0.1:4444";
const VS_SK_PATH: &str = "keys/vs_ed25519.pk8";
const VS_PK_PATH: &str = "keys/vs_ed25519.pub";

#[tokio::main]
async fn main() -> Result<()> {
    // Make sure VS has a signing keypair we can use to sign JoinAccept.sig_vs.
    // (This mirrors gs-sim's load_or_make_keys logic.)
    let (_vs_sk, _vs_pk) = load_or_make_keys(VS_SK_PATH, VS_PK_PATH)?;

    println!("[VS] dev keypair loaded.");
    println!("[VS] planned QUIC bind address: {BIND_ADDR}");
    println!("[VS] waiting for gs connections (QUIC accept loop TODO)…");

    // Park "forever" so `tools::smoke` sees a running server process.
    loop {
        sleep(Duration::from_secs(3600)).await;
    }

    // The loop above never exits. This block silences the
    // `unreachable_code` lint so `cargo clippy -D warnings` stays happy.
    #[allow(unreachable_code)]
    {
        Ok(())
    }
}

/// Load VS ed25519 keypair from disk if present, else generate a dev pair.
/// This is nearly identical to gs-sim's helper, but lives here so VS has
/// its own long-lived signing identity.
fn load_or_make_keys(sk_path: &str, pk_path: &str) -> Result<(SigningKey, VerifyingKey)> {
    let skp = PathBuf::from(sk_path);
    let pkp = PathBuf::from(pk_path);

    if skp.exists() && pkp.exists() {
        // Happy path: reuse existing keys.
        let sk_bytes = fs::read(&skp).context("read vs_sk")?;
        let pk_bytes = fs::read(&pkp).context("read vs_pk")?;

        let sk = SigningKey::from_bytes(
            &sk_bytes
                .try_into()
                .map_err(|_| anyhow!("vs_sk length != 32"))?,
        );
        let pk = VerifyingKey::from_bytes(
            &pk_bytes
                .try_into()
                .map_err(|_| anyhow!("vs_pk length != 32"))?,
        )?;

        Ok((sk, pk))
    } else {
        // No keys yet? Create a dev pair and persist it.
        fs::create_dir_all("keys").context("mkdir keys")?;

        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();

        fs::write(&skp, sk.to_bytes()).context("write vs_sk")?;
        fs::write(&pkp, pk.to_bytes()).context("write vs_pk")?;

        println!(
            "[VS] generated dev keypair at {}, {}",
            skp.display(),
            pkp.display()
        );

        Ok((sk, pk))
    }
}
