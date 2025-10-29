# mmo

## High-level idea

We split authority into two roles:

- **VS (Validation Server)** – Root of truth. Hands out short-lived proofs that a given Game Server is legit. Audits the Game Server’s behavior and can revoke it in seconds.
- **GS (Game Server)** – Runs the actual simulation / match. Talks to VS to stay “blessed.” Talks to clients.
- **Client** – Only talks to GS, but refuses to trust GS unless GS can prove VS is still blessing it *right now*.

Flow:
1. VS blesses GS.
2. GS forwards that blessing (a signed `PlayTicket`) to the client.
3. Client attaches that proof (and its own signature) to every input.
4. GS rejects input if the proof isn’t current / signed / fresh.
5. VS can revoke a GS at runtime, and that revocation ripples to all players in ~seconds.

This is basically anti-cheat + anti-rogue-host + audit trail, built into the protocol.

---

## Components

### `vs/` (Validation Server)

- Admits GS instances.
- Signs `PlayTicket`s so GS can prove it’s still valid.
- Verifies ongoing GS heartbeats for liveness and monotonic counters.
- Issues `ProtectedReceipt`s to checkpoint what the GS claims happened.

#### Join / admission

When a GS wants to join, it opens a QUIC connection and sends a `JoinRequest` containing:

- `gs_id` (string label for this GS instance)
- `sw_hash` (hash of its running binary)
- `t_unix_ms` (timestamp)
- `nonce`
- `ephemeral_pub` (fresh per-session ed25519 pubkey)
- `sig_gs` (signature from GS long-term identity key, binding all of the above)
- `gs_pub` (the GS's long-term public key)

The VS:
- Verifies `sig_gs` using the supplied `gs_pub`.
- Enforces timestamp freshness for anti-replay.
- (Future) enforces allowlist on `sw_hash` so only approved builds are allowed.

If admitted, VS replies with a `JoinAccept`:
- `session_id` (random 16 bytes that identifies this GS session)
- `sig_vs` (VS signature over `session_id`)
- `vs_pub` (VS’s long-term ed25519 public key)

This tells GS: “you’re in, and this is your session handle.”

#### Runtime

For the rest of the session, VS:
- Expects signed heartbeats from GS.
- Streams signed `PlayTicket`s *to* GS.
- (Prototype) accepts transcript digests from GS and issues `ProtectedReceipt`s.

If GS stops heartbeating or fails checks, VS revokes it.

---

### `gs-sim/` (Game Server)

- Connects to VS over QUIC.
- Generates:
  - a long-term identity keypair (or loads it from disk),
  - a fresh per-session (ephemeral) keypair,
  - a `sw_hash` of its running binary.
- Sends `JoinRequest` to VS.
- Receives `JoinAccept` and verifies `sig_vs` using `vs_pub`.

#### Runtime loop

**Heartbeats (GS → VS)**  
Every ~2 seconds, GS sends:

```text
Heartbeat {
  session_id,
  gs_counter,
  gs_time_ms,
  receipt_tip,
  sig_gs  // signed with the ephemeral per-session key
}
