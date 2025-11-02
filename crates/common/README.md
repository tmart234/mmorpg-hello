# common

Shared types and utilities used across the workspace.

- **proto/**: wire models (tickets, inputs, snapshots, receipts).
- **crypto/**: helpers (e.g., `client_input_sign_bytes`, time).
- **framing/**: TCP length-prefix helpers and (future) header/seq defs.



Quick check
```bash
cargo test -p common
