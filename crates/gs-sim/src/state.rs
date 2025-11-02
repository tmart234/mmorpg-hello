use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::proto::PlayTicket;
use ed25519_dalek::VerifyingKey;

/// Per-player world state tracked by GS.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlayerState {
    pub x: f32,
    pub y: f32,
    pub last_nonce: u64,
}

/// Global mutable GS session state shared across tasks.
///
/// Wrapped as `Shared = Arc<Mutex<GsShared>>`.
#[derive(Debug)]
pub struct GsShared {
    // Session basics
    pub session_id: [u8; 16],
    pub vs_pub: VerifyingKey,
    pub sw_hash: [u8; 32], // included so heartbeat can attach it

    // World state
    pub players: HashMap<[u8; 32], PlayerState>,

    // Rolling transcript tip advertised in heartbeats
    pub receipt_tip: [u8; 32],

    // Tickets (supporting rollover grace)
    pub latest_ticket: Option<PlayTicket>,
    pub prev_ticket: Option<PlayTicket>,
    pub last_ticket_ms: u64,

    // Trust state
    pub revoked: bool,
}

impl GsShared {
    pub fn new(session_id: [u8; 16], vs_pub: VerifyingKey, sw_hash: [u8; 32]) -> Self {
        Self {
            session_id,
            vs_pub,
            sw_hash,
            players: HashMap::new(),
            receipt_tip: [0u8; 32],
            latest_ticket: None,
            prev_ticket: None,
            last_ticket_ms: 0,
            revoked: false,
        }
    }
}

pub type Shared = Arc<Mutex<GsShared>>;
