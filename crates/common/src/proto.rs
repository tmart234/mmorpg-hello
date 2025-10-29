use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Unified signature type: ed25519 signature bytes (64 bytes).
/// We send some signatures as Vec<u8> for convenience in a few places
/// (e.g. Heartbeat.sig_gs, ProtectedReceipt.sig_vs) where we haven't
/// switched them to fixed [u8; 64] yet.
pub type Sig = Vec<u8>;

/// GS → VS during admission.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinRequest {
    pub gs_id: String,

    /// Hash of the GS binary (attestation placeholder for now).
    pub sw_hash: [u8; 32],

    /// Wallclock time (ms since Unix epoch) when this was signed.
    pub t_unix_ms: u64,

    /// Anti-replay nonce.
    pub nonce: [u8; 16],

    /// Ephemeral per-session GS public key (Ed25519).
    pub ephemeral_pub: [u8; 32],

    /// Signature by GS long-term key over the canonical JoinRequest body.
    pub sig_gs: Sig,

    /// GS long-term public key (Ed25519).
    pub gs_pub: [u8; 32],
}

/// VS → GS after admitting it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JoinAccept {
    /// VS-minted session ID (random 16 bytes).
    pub session_id: [u8; 16],

    /// VS signature binding this session_id to the GS.
    pub sig_vs: Sig,

    /// VS long-term public key (Ed25519).
    pub vs_pub: [u8; 32],
}

/// VS → GS (and then GS → client).
/// This is "proof GS is currently blessed."
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PlayTicket {
    pub session_id: [u8; 16],

    /// Optional binding to a specific client pubkey.
    /// [0u8;32] means "any client".
    pub client_binding: [u8; 32],

    /// Monotonic counter (1,2,3,...) per session.
    pub counter: u64,

    /// Earliest ms timestamp this ticket is allowed to be used.
    pub not_before_ms: u64,

    /// Latest ms timestamp this ticket is allowed to be used.
    pub not_after_ms: u64,

    /// Hash(chain) of previous ticket body. Lets client/GS detect gaps or forks.
    pub prev_ticket_hash: [u8; 32],

    /// VS signature on the canonical tuple:
    /// (session_id, client_binding, counter, not_before_ms, not_after_ms, prev_ticket_hash)
    #[serde(with = "BigArray")]
    pub sig_vs: [u8; 64],
}

/// GS → client as first message on the local TCP link.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerHello {
    pub session_id: [u8; 16],
    pub ticket: PlayTicket,
    pub vs_pub: [u8; 32],
}

/// Minimal set of player actions for now.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientCmd {
    Move { dx: f32, dy: f32 },
}

/// Client → GS input packet (one per "frame"/tick).
/// The client *must* staple a recent VS PlayTicket proof and sign
/// the whole bundle, so GS can prove to VS "I only processed inputs
/// while I was blessed."
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientInput {
    /// Which GS session this input is for.
    pub session_id: [u8; 16],

    /// Which PlayTicket this input is stapled to.
    pub ticket_counter: u64,

    /// Exact VS signature from that PlayTicket.
    /// (GS will check it matches the latest ticket it forwarded.)
    #[serde(with = "BigArray")]
    pub ticket_sig_vs: [u8; 64],

    /// Client-side strictly monotonic nonce (1,2,3,...).
    pub client_nonce: u64,

    /// The actual command (Move, etc.).
    pub cmd: ClientCmd,

    /// Ephemeral client pubkey (Ed25519) for this run/session.
    pub client_pub: [u8; 32],

    /// Client signature (Ed25519, 64 bytes) over the canonical tuple:
    /// (session_id,
    ///  ticket_counter,
    ///  ticket_sig_vs,
    ///  client_nonce,
    ///  cmd)
    #[serde(with = "BigArray")]
    pub client_sig: [u8; 64],
}

/// GS → client snapshot of game-relevant world state.
/// This is now *multiplayer*.
///
/// - `you`: your authoritative server-side position
/// - `others`: everyone else the GS currently knows about in this shard,
///   expressed as (client_pub, x, y).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WorldSnapshot {
    /// Monotonic "tick" for this connection.
    pub tick: u64,

    /// Your own position per GS sim.
    pub you: (f32, f32),

    /// Other visible entities in the shard.
    /// Each entry: (client_pub, x, y)
    pub others: Vec<([u8; 32], f32, f32)>,
}

/// GS → client: "Here's a fresher PlayTicket from VS, use this now."
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TicketUpdate {
    pub ticket: PlayTicket,
}

/// Messages flowing Client -> GS over the local TCP link.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClientToGs {
    Input(ClientInput),
}

/// Messages flowing GS -> Client over the local TCP link.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum GsToClient {
    ServerHello(ServerHello),
    WorldSnapshot(WorldSnapshot),
    TicketUpdate(TicketUpdate),
}

// -------------------------
// GS <-> VS runtime protocol
// -------------------------

/// GS → VS heartbeat (~2s).
/// Proves liveness and pushes the GS's current transcript tip.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Heartbeat {
    pub session_id: [u8; 16],

    /// Monotonic GS counter (1,2,3,...). VS kills session if it stalls or regresses.
    pub gs_counter: u64,

    /// GS local time in ms (used for debug / replay forensics).
    pub gs_time_ms: u64,

    /// Rolling hash / commitment of all "accepted" client actions so far.
    pub receipt_tip: [u8; 32],

    /// Signature by GS's ephemeral session key over the canonical heartbeat bytes.
    pub sig_gs: Sig,
}

/// GS → VS: "Here's my current transcript digest at counter C."
/// This lets VS issue an attestation that "I saw GS claim this state."
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TranscriptDigest {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub receipt_tip: [u8; 32],
}

/// VS → GS in response to TranscriptDigest.
/// VS signs what GS claimed, so GS can later prove to players (and to us)
/// that it really was under VS oversight when it said "player X took damage",
/// "player Y moved here", etc.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProtectedReceipt {
    pub session_id: [u8; 16],
    pub gs_counter: u64,
    pub receipt_tip: [u8; 32],

    /// VS signature binding (session_id, gs_counter, receipt_tip).
    pub sig_vs: Sig,
}
