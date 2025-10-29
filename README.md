A fast and secure Massively Multiplayer Online framework with decentralized hosting

### Arcitecture
Client <-> Game Server (GS) <-> Verification Server (VS)
- VS blesses GS.
- GS forwards proof of that blessing to client
- client has to echo that proof in every action
- GS rejects input if the proof isn’t current / signed / fresh
