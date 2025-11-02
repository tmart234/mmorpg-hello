# gs-core

Minimal game-logic core.

- `World` and `PlayerState` data structures.
- `GameRules` trait: authoritative per-tick server logic (apply inputs, clamp speed/cooldowns, damage).
- `EnvironmentSystem` trait: ambient effects (weather, hazards).
- `Runner`: calls `env.on_tick()` then `rules.tick()` each frame; updates `world.time_ms`.

This crate is engine-agnostic; networking and auth happens in `gs-sim`.