# VS

The **referee** / control plane:

- Issues `PlayTicket`s, **pins GS builds** (allowlist by `sw_hash`), and can **revoke** at any time.
- Audits **asynchronously**: GS sends transcript tips / batches; VS returns **ProtectedReceipt** acknowledging the chain.
- For high-value flows we can add a **grant / 2-phase** scheme (optional).
- If GS looks wrong (non-monotonic ctr, broken chain, impossible deltas, duplicate ids), VS can:
  - freeze accounts,
  - stop issuing tickets to that GS,
  - issue compensations.