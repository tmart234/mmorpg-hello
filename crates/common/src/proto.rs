use serde::{Deserialize, Serialize};

/// Ed25519 sig bytes (64 bytes)
pub type Sig = [u8; 64];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,
    pub sw_hash: [u8; 32],
    pub t_unix_ms: u64,
    pub nonce: [u8; 16],

    // Per-session ephemeral public key (Ed25519)
    pub ephemeral_pub: [u8; 32],

    // Signature by the GS long-term key over:
    // (gs_id, sw_hash, t_unix_ms, nonce, ephemeral_pub)
    #[serde(with = "serde_big_array::BigArray")]
    pub sig_gs: Sig,

    // Long-term GS pubkey so VS can verify sig_gs
    pub gs_pub: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    pub session_id: [u8; 16],

    // VS proves "this session_id is legit and I'm VS"
    #[serde(with = "serde_big_array::BigArray")]
    pub sig_vs: Sig,

    // VS long-term signing key (Ed25519 pubkey)
    pub vs_pub: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Heartbeat {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub gs_time_ms: u64,

    /// rolling transcript hash the GS claims up to this tick
    pub receipt_tip: [u8; 32],

    // GS signs:
    // heartbeat_sign_bytes(session_id, gs_counter, gs_time_ms, receipt_tip)
    #[serde(with = "serde_big_array::BigArray")]
    pub sig_gs: Sig,
}

/// A ticket blessed by VS that the GS forwards to clients.
/// Client uses this to decide "is this GS valid *right now*?"
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayTicket {
    pub session_id: [u8; 16],

    /// Which client this ticket is for.
    /// [0;32] means "anonymous / anyone".
    pub client_binding: [u8; 32],

    pub counter: u64,
    pub not_before_ms: u64,
    pub not_after_ms: u64,

    /// Hash-chain link to previous ticket body tuple.
    pub prev_ticket_hash: [u8; 32],

    /// VS signature on:
    /// (session_id, client_binding, counter, not_before_ms, not_after_ms, prev_ticket_hash)
    #[serde(with = "serde_big_array::BigArray")]
    pub sig_vs: Sig,
}

/// Sent by GS to the client over TCP before gameplay starts.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerHello {
    pub session_id: [u8; 16],
    pub ticket: PlayTicket,
    pub vs_pub: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientCmd {
    Move { dx: f32, dy: f32 },
    // Future: Fire { ... }, etc.
}

/// Client → GS per-tick input, stapled with cryptographic proof.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientInput {
    pub session_id: [u8; 16],

    /// Which PlayTicket this input is stapled to
    pub ticket_counter: u64,

    /// Exact VS signature bytes from that ticket
    #[serde(with = "serde_big_array::BigArray")]
    pub ticket_sig_vs: Sig,

    /// Strictly increasing per-client anti-replay nonce
    pub client_nonce: u64,

    /// The actual gameplay intent
    pub cmd: ClientCmd,

    /// The client's claimed Ed25519 public key for this session
    pub client_pub: [u8; 32],

    /// Client's signature over the canonical tuple:
    /// (session_id, ticket_counter, ticket_sig_vs, client_nonce, cmd)
    #[serde(with = "serde_big_array::BigArray")]
    pub client_sig: Sig,
}

/// GS → VS: "here's my transcript tip at heartbeat counter C"
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TranscriptDigest {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub receipt_tip: [u8; 32],
}

/// VS → GS: "I saw that transcript. I'm signing it."
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtectedReceipt {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub receipt_tip: [u8; 32],

    /// sig_vs over (session_id, gs_counter, receipt_tip)
    #[serde(with = "serde_big_array::BigArray")]
    pub sig_vs: Sig,
}
