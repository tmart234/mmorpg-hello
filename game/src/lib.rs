use anyhow::Result;
use gs_core::{EnvironmentSystem, GameRules, Runner, World};
//use tracing::info;

// Minimal rules: move/stamina/cooldowns can be implemented later.
pub struct OurRules;

impl GameRules for OurRules {
    fn tick(&mut self, _dt_ms: u64, _world: &mut World) -> Result<()> {
        // Apply per-player stamina regen, cooldown decrement, clamp speed, etc.
        Ok(())
    }
}

// Minimal environment: placeholder for “city gets attacked” style events.
pub struct OurEnv;

impl EnvironmentSystem for OurEnv {
    fn on_tick(&mut self, _dt_ms: u64, _world: &mut World) -> Result<()> {
        // Drive ambient events here (storm, blackout, NPC raids, anomalies…)
        Ok(())
    }
}

// Small helper to build a runner for tests or the bin.
pub fn make_runner() -> Runner<OurRules, OurEnv> {
    let world = World::default();
    Runner::new(OurRules, OurEnv, world)
}
