# mmo

## High-level Idea
Client <-> GS <-> VS

- **VS (Validation Server)** – Root of truth. Hands out short-lived proofs that a given Game Server is legit. Audits the Game Server’s behavior and can revoke it in seconds.
- **GS (Game Server)** – Runs the actual simulation / match. Talks to VS to stay “blessed.” Talks to clients.
- **Client** – Only talks to GS, but refuses to trust GS unless GS can prove VS is still blessing it.

Flow:
1. GS joins VS with a signed JoinRequest (binds GS identity + ephemeral session key + build sw_hash + freshness).
2. VS accepts and starts issuing short-lived, hash-chained PlayTickets to GS.
3. GS forwards the current PlayTicket to the client.
4. Client attaches the proof (and its own signatures) to each input.
5. GS rejects input if the proof isn’t current / signed / fresh.
6. VS can revoke a GS at runtime; that revocation ripples to all players in ~seconds via ticket starvation + connection close.

Goal: anti-cheat + anti-rogue-host + audit trail, built into the protocol.

---

## Crypto (so far)
Continuous attestation (GS→VS heartbeats):
- VS verifies a per-session ephemeral key and pins the GS sw_hash observed at join. Heartbeats carry:
  - session_id, gs_counter (strictly monotonic), gs_time_ms, receipt_tip (rolling digest), sw_hash, sig_gs.
  - VS enforces: valid signature, monotonic counter, pinned sw_hash. On mismatch → revoke.

Transcript notarization (VS receipts):
- GS periodically sends TranscriptDigest { session_id, gs_counter, receipt_tip, positions }.
- VS returns ProtectedReceipt (signed) echoing { session_id, gs_counter, receipt_tip }.
- This creates a signed audit trail so GS can’t later deny what it claimed happened at counter N.

Short-lived tickets (VS→GS→Client):
- PlayTicket includes { session_id, client_binding (placeholder=0s for now), counter, not_before_ms, not_after_ms, prev_ticket_hash } and VS signature.
- Tickets are rotated ~every 2s with a hash chain (prev_ticket_hash) to prevent reordering. Clients/GS check freshness windows.

Ephemeral session keys:
- Each GS session uses a fresh ephemeral keypair bound inside JoinRequest. VS uses it to verify heartbeats for that session only.

World/physics enforcement (on VS):
- VS measures movement between notarized snapshots (time from heartbeat, positions from digest) and revokes on speed violations.
