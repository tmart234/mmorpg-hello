// game/src/main.rs

// This binary is gated by the "bin" feature in game/Cargo.toml.
// Enable with: `cargo run -p game --bin game-gs --features bin -- --bind 0.0.0.0:50000`

#[cfg(feature = "bin")]
fn init_tracing() {
    // Initialize tracing subscriber if "bin" feature is on.
    // RUST_LOG controls verbosity, e.g.:
    //   RUST_LOG=info,game=debug,gs_core=debug
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

#[cfg(not(feature = "bin"))]
fn init_tracing() {
    // No-op if the feature isn't enabled.
}

fn main() -> anyhow::Result<()> {
    init_tracing();

    // Very small, zero-dep arg parsing (keep it simple for now).
    // Flags:
    //   --bind <addr:port>     (default from BIND or "0.0.0.0:50000")
    //   --vs-addr <addr:port>  (default from VS_ADDR or "127.0.0.1:4444")
    let mut bind = std::env::var("BIND").unwrap_or_else(|_| "0.0.0.0:50000".to_string());
    let mut vs_addr = std::env::var("VS_ADDR").unwrap_or_else(|_| "127.0.0.1:4444".to_string());

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                if let Some(v) = args.next() {
                    bind = v;
                }
            }
            "--vs-addr" => {
                if let Some(v) = args.next() {
                    vs_addr = v;
                }
            }
            _ => {
                // Ignore unknown flags for now (keeps this minimal).
            }
        }
    }

    tracing::info!(%bind, %vs_addr, "[game-gs] starting");

    // TODO: When gs-core runner is ready, wire it here, e.g.:
    //
    // let rules = game::OurGameRules::default();
    // let env   = game::OurEnvironmentSystem::from_path("ourgame-content/")?;
    // let cfg   = gs_core::Config {
    //     client_bind: bind.parse()?,
    //     vs_addr: vs_addr.parse()?,
    //     ..Default::default()
    // };
    // gs_core::run(rules, env, cfg).await?;
    //
    // For now, just print that we're up and exit cleanly.
    println!(
        "[game-gs] stub runner up. Would bind client port at '{}' and talk to VS at '{}'.",
        bind, vs_addr
    );

    Ok(())
}
