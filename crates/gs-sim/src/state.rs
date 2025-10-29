use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::proto::PlayTicket;

/// Per-player world state tracked by GS.
#[derive(Debug, Clone)]
pub struct PlayerState {
    pub x: f32,
    pub y: f32,
    pub last_nonce: u64,
}

/// Global mutable GS session state shared across tasks.
/// Wrapped as `Shared = Arc<Mutex<GsSharedState>>`.
pub struct GsSharedState {
    /// Session ID assigned by VS in JoinAccept.
    pub session_id: [u8; 16],

    /// VS long-term pubkey (as raw bytes). We forward this to clients so they
    /// can verify PlayTicket signatures and pin VS identity.
    pub vs_pub: [u8; 32],

    /// Latest VS-issued PlayTicket we've accepted.
    /// ticket_listener() keeps this fresh.
    pub latest_ticket: Option<PlayTicket>,

    /// When (ms since epoch) we last got a fresh ticket.
    /// Used by the watchdog to detect VS silence and mark us revoked.
    pub last_ticket_ms: u64,

    /// Rolling hash of accepted inputs + authoritative GS outcomes.
    /// heartbeat_loop sends this to VS so VS can notarize what we claim happened.
    pub receipt_tip: [u8; 32],

    /// Has VS effectively revoked us?
    /// ticket_listener/watchdog flips this to true if tickets stop or VS says kill it.
    pub revoked: bool,

    /// All active/known players in this shard keyed by their pubkey.
    /// This lets multiple clients coexist and lets us do per-player
    /// replay protection and position authority.
    pub players: HashMap<[u8; 32], PlayerState>,
}

impl GsSharedState {
    pub fn new(session_id: [u8; 16], vs_pub: [u8; 32]) -> Self {
        Self {
            session_id,
            vs_pub,
            latest_ticket: None,
            last_ticket_ms: 0,
            receipt_tip: [0u8; 32],
            revoked: false,
            players: HashMap::new(),
        }
    }
}

/// Arc<Mutex<...>> alias that the rest of GS code passes around.
pub type Shared = Arc<Mutex<GsSharedState>>;
