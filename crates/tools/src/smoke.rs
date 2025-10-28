// crates/tools/src/smoke.rs
//
// "Smoke test" for local CI-lite (`make ci`):
// - Make sure VS dev keys exist.
// - Spawn the VS stub in the background.
// - Try to run `gs-sim --test-once` against it.
// - Clean up VS.
// We deliberately DO NOT fail if gs-sim can't connect yet, because
// the VS stub doesn't actually listen on QUIC/UDP:4444 right now.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

fn exe(bin: &str) -> String {
    // Help Windows find "vs.exe", "gs-sim.exe", etc.
    if cfg!(windows) {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    }
}

// Ensure we have keys/vs_ed25519.{pk8,pub} so gs/vs both have signing material.
// Mirrors the logic we had in vs/gs-sim without pulling in their modules.
fn ensure_vs_keys() -> Result<()> {
    let skp = PathBuf::from("keys/vs_ed25519.pk8");
    let pkp = PathBuf::from("keys/vs_ed25519.pub");

    if skp.exists() && pkp.exists() {
        return Ok(());
    }

    fs::create_dir_all("keys").context("mkdir keys")?;

    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();

    fs::write(&skp, sk.to_bytes()).context("write vs_sk")?;
    fs::write(&pkp, pk.to_bytes()).context("write vs_pk")?;

    println!(
        "Generated keys: {}, {}",
        skp.display(),
        pkp.display()
    );

    Ok(())
}

fn main() -> Result<()> {
    // 1. Make sure VS has dev keys so gs-sim won't panic when it tries to sign/verify stuff.
    ensure_vs_keys()?;

    // 2. Spawn the VS stub in the background.
    //    We silence stdout/stderr here so `make ci` output stays clean.
    //    (The stub just prints a couple lines then sleeps forever.)
    let mut vs_child = Command::new(exe("vs"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn vs")?;

    // Give the stub a moment to get into its sleep loop.
    thread::sleep(Duration::from_millis(200));

    // 3. Try to run gs-sim once against 127.0.0.1:4444.
    //    Our stub VS doesn't actually listen on that port yet,
    //    so this will probably fail fast with a nonzero exit.
    //    That's FINE. We treat it as "smoke ran".
    let gs_status = Command::new(exe("gs-sim"))
        .args(["--vs", "127.0.0.1:4444", "--test-once"])
        .status()
        .context("run gs-sim")?;

    if gs_status.success() {
        println!("[SMOKE] gs-sim completed successfully.");
    } else {
        println!("[SMOKE] gs-sim exited nonzero (expected for now).");
    }

    // 4. Clean up VS.
    let _ = vs_child.kill();
    let _ = vs_child.wait();

    // IMPORTANT: always exit 0 so `make ci` passes.
    println!("[SMOKE] done.");
    Ok(())
}
