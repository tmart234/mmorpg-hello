use std::sync::{Arc, Mutex};

use common::proto::PlayTicket;

/// Shared is Arc<Mutex<...>> so we can pass it around cheaply.
pub type Shared = Arc<Mutex<GsSharedState>>;

/// Everything the GS runtime (heartbeat loop, TCP client handler, ticket stream)
/// needs to coordinate.
pub struct GsSharedState {
    pub session_id: [u8; 16],
    pub vs_pub: [u8; 32],

    /// freshest PlayTicket we got from VS
    pub latest_ticket: Option<PlayTicket>,

    /// last accepted client_nonce (anti-replay)
    pub last_client_nonce: u64,

    /// timestamp of last fresh ticket from VS
    pub last_ticket_ms: u64,

    /// flipped true if VS stops blessing us (watchdog in tickets.rs)
    pub revoked: bool,

    /// rolling hash of all validated ClientInput we've accepted
    pub receipt_tip: [u8; 32],
}

impl GsSharedState {
    pub fn new(session_id: [u8; 16], vs_pub: [u8; 32]) -> Self {
        Self {
            session_id,
            vs_pub,
            latest_ticket: None,
            last_client_nonce: 0,
            last_ticket_ms: 0,
            revoked: false,
            receipt_tip: [0u8; 32],
        }
    }
}
