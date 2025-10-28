use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Ed25519 sig bytes
pub type Sig = [u8; 64];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,
    pub sw_hash: [u8; 32],
    pub t_unix_ms: u64,
    pub nonce: [u8; 16],

    /// fresh per-session pubkey (ephemeral); GS proves ownership in sig_gs
    pub ephemeral_pub: [u8; 32],

    /// sig_gs = ed25519(long_term_gs_sk, join_request_sign_bytes(...))
    #[serde(with = "BigArray")]
    pub sig_gs: Sig,

    /// long-term GS identity pubkey (stable per host / machine)
    pub gs_pub: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    pub session_id: [u8; 16],

    /// sig_vs = ed25519(vs_sk, session_id)
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,

    /// VS's public key so GS can verify sig_vs
    pub vs_pub: [u8; 32],
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
