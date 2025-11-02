# client-core

Networking + crypto client library and a tiny CLI (`client-sim`) for smoke tests.

- Persists client Ed25519 keys in `keys/` (identity without login).
- Pins `vs_pub` (trust root) from `keys/vs_ed25519.pub`.
- `connect_and_handshake()` reads `ServerHello`, verifies VS signature on ticket, and enforces client_binding.
- `send_input()` signs canonical bytes and sends `ClientToGs::Input`.
- `recv_world()` receives authoritative `WorldSnapshot`.
