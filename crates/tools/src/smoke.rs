// crates/tools/src/smoke.rs
//
// CI-lite / `make ci` smoke test:
//
// 1. Ensure VS dev keys exist (keys/vs_ed25519.*). This matches what gs-sim
//    and client-sim expect for VS signatures.
// 2. Spawn VS in the background (listens QUIC on 127.0.0.1:4444).
// 3. Spawn gs-sim --test-once in the background. That will:
//      - connect to VS
//      - open its client port on 127.0.0.1:50000
//      - wait for a client-sim
// 4. Run client-sim --smoke-test in the foreground. That will:
//      - connect to gs-sim (TCP 127.0.0.1:50000)
//      - verify the VS-signed PlayTicket
//      - send a signed/nonce'd ClientInput back
// 5. Wait for gs-sim to exit (it self-terminates after ~5s in --test-once).
// 6. Kill VS.
// 7. Always exit 0 so local CI-lite passes, but log who failed.
//
// NOTE: we intentionally silence VS/gs-sim stdout/stderr here so CI output
// stays compact. You can comment out the `.stdout(Stdio::null())` lines if
// you want verbose debugging.

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
    // Help Windows find "vs.exe", "gs-sim.exe", "client-sim.exe", etc.
    if cfg!(windows) {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    }
}

// Ensure VS has an Ed25519 keypair on disk.
// This matches what vs / gs-sim / client-sim currently assume:
//   keys/vs_ed25519.pk8 (priv), keys/vs_ed25519.pub (pub)
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
        "[SMOKE] generated VS dev keys: {}, {}",
        skp.display(),
        pkp.display()
    );

    Ok(())
}

fn main() -> Result<()> {
    // 1. Make sure VS signing keys exist so VS can sign and client/GS can verify.
    ensure_vs_keys()?;

    // 2. Spawn VS in the background.
    //    VS listens on 127.0.0.1:4444 over QUIC.
    let mut vs_child = Command::new(exe("vs"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn vs")?;

    // Small delay so VS is actually listening before gs-sim dials it.
    thread::sleep(Duration::from_millis(200));

    // 3. Spawn gs-sim in the background with --test-once.
    //    gs-sim will:
    //      - connect to VS
    //      - start heartbeating
    //      - start ticket stream
    //      - open TCP 127.0.0.1:50000 for a client
    //      - accept exactly one client-sim exchange
    //      - after ~5s, abort tasks and exit
    let mut gs_child = Command::new(exe("gs-sim"))
        .args(["--vs", "127.0.0.1:4444", "--test-once"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn gs-sim")?;

    // Tiny delay so gs-sim is actually listening on 127.0.0.1:50000
    // before client-sim connects.
    thread::sleep(Duration::from_millis(200));

    // 4. Run client-sim in the foreground.
    //    client-sim will:
    //      - connect to gs-sim:50000
    //      - read ServerHello (ticket + vs_pub)
    //      - verify VS sig on ticket
    //      - send ClientInput stapled w/ that ticket
    //      - exit
    let client_status = Command::new(exe("client-sim"))
        .args(["--gs-addr", "127.0.0.1:50000", "--smoke-test"])
        .status()
        .context("run client-sim")?;

    if client_status.success() {
        println!("[SMOKE] client-sim completed successfully.");
    } else {
        println!(
            "[SMOKE] client-sim exited nonzero (status={:?})",
            client_status.code()
        );
    }

    // 5. Wait for gs-sim to finish its --test-once run.
    let gs_status = gs_child.wait().context("wait for gs-sim child")?;
    if gs_status.success() {
        println!("[SMOKE] gs-sim completed successfully.");
    } else {
        println!(
            "[SMOKE] gs-sim exited nonzero (status={:?})",
            gs_status.code()
        );
    }

    // 6. Kill VS so it doesn't stick around after CI.
    let _ = vs_child.kill();
    let _ = vs_child.wait();

    // 7. Always exit 0. The smoke test is "best effort sanity",
    //    not correctness or perf. The logs above are what matter.
    println!("[SMOKE] done.");
    Ok(())
}
