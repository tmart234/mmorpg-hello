// crates/vs/src/ctx.rs
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use std::sync::Arc;

pub const JOIN_MAX_SKEW_MS: u64 = 10_000; // ~10s in dev
pub const HEARTBEAT_TIMEOUT_MS: u64 = 10_000; // ~10s in dev

#[derive(Clone)]
pub struct VsCtx {
    pub vs_sk: Arc<SigningKey>,
    pub sessions: Arc<DashMap<[u8; 16], Session>>,
}

#[derive(Clone)]
pub struct Session {
    pub ephemeral_pub: [u8; 32],
    pub last_counter: u64,
    pub last_seen_ms: u64,
    pub revoked: bool,

    // For ProtectedReceipt de-dup / tidy logs
    pub last_pr_counter: Option<u64>,
    pub last_pr_tip: [u8; 32],
}

impl VsCtx {
    pub fn new(vs_sk: Arc<SigningKey>) -> Self {
        Self {
            vs_sk,
            sessions: Arc::new(DashMap::new()),
        }
    }
}
