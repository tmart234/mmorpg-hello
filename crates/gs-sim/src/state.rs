use std::sync::{Arc, Mutex};

use common::proto::PlayTicket;

/// Global mutable GS session state shared across tasks.
///
/// Wrapped as `Shared = Arc<Mutex<GsSharedState>>`.
pub struct GsSharedState {
    /// Session ID assigned by VS in JoinAccept.
    pub session_id: [u8; 16],

    /// VS long-term pubkey (as raw bytes) so clients can verify VS signatures
    /// on PlayTickets without talking to VS directly.
    pub vs_pub: [u8; 32],

    /// Latest VS-issued PlayTicket we've accepted.
    /// client_port_task snapshots this to validate client inputs.
    pub latest_ticket: Option<PlayTicket>,

    /// When (ms since epoch) we last got a fresh ticket.
    /// Used by the watchdog to detect VS silence and mark us revoked.
    pub last_ticket_ms: u64,

    /// Rolling hash of accepted client inputs ("transcript tip").
    /// Heartbeat loop sends this to VS so VS can notarize what we claim happened.
    pub receipt_tip: [u8; 32],

    /// Has VS effectively revoked us?
    /// ticket_listener/watchdog flips this to true if tickets stop or VS says kill it.
    pub revoked: bool,

    /// Last monotonic client_nonce we've accepted from *any* client.
    /// Lets us reject replayed or out-of-order client inputs immediately.
    pub last_client_nonce: u64,
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
            last_client_nonce: 0,
        }
    }
}

/// Arc<Mutex<...>> alias that the rest of GS code passes around.
pub type Shared = Arc<Mutex<GsSharedState>>;
