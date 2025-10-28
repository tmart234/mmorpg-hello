use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

// keep your alias
pub type Sig = [u8; 64];

// Example structs — add the attribute on every Sig field:

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,
    pub sw_hash: [u8; 32],
    pub t_unix_ms: u64,
    pub nonce: [u8; 16],
    #[serde(with = "BigArray")]
    pub sig_gs: Sig,
    pub gs_pub: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    pub session_id: [u8; 16],
    // (any other fields you have…)
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayTicket {
    pub session_id: [u8; 16],
    pub client_binding: [u8; 32],
    pub counter: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub prev_ticket_hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Heartbeat {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub gs_time_ms: u64,
    pub receipt_tip: [u8; 32],
    #[serde(with = "BigArray")]
    pub sig_gs: Sig,
}
