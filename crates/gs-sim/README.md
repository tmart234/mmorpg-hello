# gs-sim

Authoritative game server (simulator):

- Accepts client connections, validates **PlayTicket** + **signatures**.
- Pipes verified inputs into `gs-core::Runner`.
- Emits **WorldSnapshot** (authoritative state).
- Heartbeats to VS and expects a **ProtectedReceipt** (VS signs transcript tip).
- Supports multiple clients (one task per accept).

Current status
- ✅ Ticket pinning & client binding enforced.
- ✅ Signed client inputs verified.
- ✅ ProtectedReceipt loop (GS↔VS).
- ⏳ Sequence window & token buckets (edge guards).
- ⏳ AOI/LOS replication.
