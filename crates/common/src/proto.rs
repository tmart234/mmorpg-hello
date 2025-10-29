use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// 64-byte Ed25519 signature
pub type Sig = [u8; 64];

/// Initial join from GS → VS.
/// VS uses this to authenticate GS and mint a session.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,
    pub sw_hash: [u8; 32],
    pub t_unix_ms: u64,
    pub nonce: [u8; 16],

    /// Per-session ephemeral public key (for runtime signing like heartbeats).
    pub ephemeral_pub: [u8; 32],

    /// sig_gs = Ed25519(gs_sk_longterm, join_request_sign_bytes(...))
    #[serde(with = "BigArray")]
    pub sig_gs: Sig,

    /// Long-term GS public key (identity)
    pub gs_pub: [u8; 32],
}

/// VS → GS once GS is admitted.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    /// Opaque handle for this GS session.
    pub session_id: [u8; 16],

    /// sig_vs = Ed25519(vs_sk, session_id)
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,

    /// VS public key so GS can verify sig_vs.
    pub vs_pub: [u8; 32],
}

/// VS → GS runtime ticket, streamed ~2s.
/// GS forwards (or summarizes) this proof to clients, and clients must echo it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayTicket {
    pub session_id: [u8; 16],
    pub client_binding: [u8; 32],
    pub counter: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub prev_ticket_hash: [u8; 32],

    /// sig_vs = Ed25519(vs_sk, body_tuple)
    #[serde(with = "BigArray")]
    pub sig_vs: Sig,
}

/// GS → VS runtime liveness.
/// Signed by GS's ephemeral key from JoinRequest.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Heartbeat {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub gs_time_ms: u64,
    pub receipt_tip: [u8; 32],

    /// sig_gs = Ed25519(gs_ephemeral_sk, heartbeat_sign_bytes(...))
    #[serde(with = "BigArray")]
    pub sig_gs: Sig,
}

/// GS → client bootstrap message over the local "client port".
/// Tells the client: here is the PlayTicket I just got from VS,
/// here is the VS pubkey to verify it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerHello {
    pub session_id: [u8; 16],
    pub ticket: PlayTicket,
    pub vs_pub: [u8; 32],
}

/// Minimal player command for now.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientCmd {
    Move { dx: f32, dy: f32 },
}

/// Client → GS input packet.
/// Client proves freshness+auth by stapling the latest PlayTicket.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientInput {
    pub session_id: [u8; 16],
    pub ticket_counter: u64,

    /// The VS signature from that PlayTicket.
    #[serde(with = "BigArray")]
    pub ticket_sig_vs: Sig,

    /// Monotonic nonce so GS can reject replay.
    pub client_nonce: u64,

    pub cmd: ClientCmd,
}
