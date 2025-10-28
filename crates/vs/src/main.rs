// crates/vs/src/main.rs
// super-minimal VS stub used so the workspace builds and smoke can spawn it.
//
// TODO: replace with the real QUIC listener handshake when Quinn wiring is done.

use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    println!("[VS] stub server up (Quinn listener TODO)");
    println!("[VS] this stub exists just so the workspace builds.");

    // Park "forever" so `tools::smoke` sees a running server.
    loop {
        sleep(Duration::from_secs(3600)).await;
    }
}
