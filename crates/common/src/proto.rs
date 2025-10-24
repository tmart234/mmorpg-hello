use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

pub type Sha256 = [u8; 32];
pub type Sig = [u8; 64];
pub type PubKey = [u8; 32];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,
    pub sw_hash: Sha256,
    pub t_unix_ms: u64,
    pub nonce: [u8; 16],
    #[serde(with = "BigArray")]
    pub sig_gs: Sig, // 64 bytes -> needs BigArray
    pub gs_pub: PubKey, // 32 bytes -> OK without BigArray
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    pub session_id: [u8; 16],
    pub ticket_key_id: u32,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayTicket {
    pub session_id: [u8; 16],
    pub client_binding: Sha256,
    pub counter: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub prev_ticket_hash: Sha256,
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Heartbeat {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub gs_time_ms: u64,
    pub receipt_tip: Sha256,
    #[serde(with = "BigArray")]
    pub sig_gs: Sig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtectedReceipt {
    pub session_id: [u8; 16],
    pub tick: u64,
    pub inputs_hash: Sha256,
    pub outputs_hash: Sha256,
    pub ticket_counter_ref: u64,
    pub prev_receipt_hash: Sha256,
    pub receipt_hash: Sha256,
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,
}
