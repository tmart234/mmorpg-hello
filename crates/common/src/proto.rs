use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

// 64-byte Ed25519 signature
pub type Sig = [u8; 64];

/// Sent GS -> VS during initial join.
/// GS proves identity and binary hash.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,

    // hash of the GS binary (sha256(exe)), dev attestation
    pub sw_hash: [u8; 32],

    // GS local time (ms since unix epoch)
    pub t_unix_ms: u64,

    // 128-bit nonce to make this request unique
    pub nonce: [u8; 16],

    // ed25519 sig by GS over (gs_id, sw_hash, t_unix_ms, nonce)
    #[serde(with = "BigArray")]
    pub sig_gs: Sig,

    // GS public key (ed25519 verify key, 32 bytes)
    pub gs_pub: [u8; 32],
}

/// Sent VS -> GS in response to JoinRequest.
/// VS is granting a live session_id and proving *itself*.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    // Opaque session handle VS generated for this GS
    pub session_id: [u8; 16],

    // VS signature over session_id (ed25519)
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,

    // VS public key so GS can verify sig_vs
    pub vs_pub: [u8; 32],
}

/// VS -> GS runtime ticket.
/// GS will forward this to players in the real flow.
/// For smoke/local it’s mostly timing + monotonic counter.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayTicket {
    pub session_id: [u8; 16],

    // placeholder: which game client this ticket is bound to
    pub client_binding: [u8; 32],

    // monotonic counter from VS
    pub counter: u64,

    // validity window in ms unix time
    pub not_before_ms: u64,
    pub not_after_ms: u64,

    // hash chain of previous tickets, placeholder for now
    pub prev_ticket_hash: [u8; 32],

    // VS signature over the ticket body
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,
}

/// GS -> VS runtime heartbeat.
/// Proves liveness and monotonic counter to VS.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Heartbeat {
    pub session_id: [u8; 16],

    // monotonic counter from GS
    pub gs_counter: u64,

    // GS local time ms
    pub gs_time_ms: u64,

    // placeholder: receipt hash of last authoritative event
    pub receipt_tip: [u8; 32],

    // GS signature over (session_id, gs_counter, gs_time_ms, receipt_tip)
    #[serde(with = "BigArray")]
    pub sig_gs: Sig,
}
