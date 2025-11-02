# gs-sim

Authoritative game server (simulator):

- Accepts client connections, validates **PlayTicket** + **signatures**.
- Pipes verified inputs into `gs-core::Runner`.
- Emits **WorldSnapshot** (authoritative state).
- Heartbeats to VS and expects a **ProtectedReceipt** (VS signs transcript tip).
- Supports multiple clients (one task per accept).
- Maintains a rolling **`receipt_tip`**
- Clamps movement server-side (anti-speedhack).

Current status
- ✅ Ticket pinning (hash-chained, short-lived) with rollover grace
- ✅ Signed client inputs, nonce ordering, movement clamp
- ✅ Rolling receipt_tip + ProtectedReceipt loop with VS
- ✅ Heartbeat re-attestation (sw_hash)
- ✅ Multi-client shared state map.
- ⏳ Sequence window & token buckets (edge guards).
- ⏳ AOI/LOS replication.
