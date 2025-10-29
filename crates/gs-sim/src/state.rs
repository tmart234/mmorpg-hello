use common::crypto::sha256;
use common::proto::PlayTicket;
use std::sync::{Arc, Mutex};

pub struct GsSharedState {
    pub session_id: [u8; 16],
    pub vs_pub: [u8; 32],

    pub latest_ticket: Option<PlayTicket>,
    pub last_ticket_ms: u64,

    pub revoked: bool,

    // rolling audit hash of accepted ClientInput
    pub receipt_tip: [u8; 32],
}

impl GsSharedState {
    pub fn new(session_id: [u8; 16], vs_pub: [u8; 32]) -> Self {
        Self {
            session_id,
            vs_pub,
            latest_ticket: None,
            last_ticket_ms: 0,
            revoked: false,
            receipt_tip: [0u8; 32],
        }
    }

    /// Fold an accepted client input into the running audit hash.
    pub fn incorporate_input(&mut self, client_nonce: u64, ticket_ctr: u64) {
        let mut data = Vec::with_capacity(self.receipt_tip.len() + self.session_id.len() + 8 + 8);
        data.extend_from_slice(&self.receipt_tip);
        data.extend_from_slice(&self.session_id);
        data.extend_from_slice(&client_nonce.to_le_bytes());
        data.extend_from_slice(&ticket_ctr.to_le_bytes());

        self.receipt_tip = sha256(&data);
    }
}

pub type Shared = Arc<Mutex<GsSharedState>>;
