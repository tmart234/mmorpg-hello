use anyhow::Result;
use gs_core::{EnvironmentSystem, GameRules, PlayerState, Runner, World};
use std::collections::HashMap;

const KEY: [u8; 32] = [9u8; 32];

struct TestEnv;
impl EnvironmentSystem for TestEnv {
    fn on_tick(&mut self, _dt_ms: u64, world: &mut World) -> Result<()> {
        // Ensure the player exists before rules run
        world.players.entry(KEY).or_insert(PlayerState {
            x: 0.0,
            y: 0.0,
            stamina: 0.0,
            cooldown_ms: 0,
        });
        Ok(())
    }
}

struct TestRules;
impl GameRules for TestRules {
    fn tick(&mut self, _dt_ms: u64, world: &mut World) -> Result<()> {
        // If env ran first, this player exists and we can bump x by 1
        if let Some(p) = world.players.get_mut(&KEY) {
            p.x += 1.0;
        }
        Ok(())
    }
}

#[test]
fn env_runs_before_rules_and_time_advances() {
    let mut runner = Runner::new(
        TestRules,
        TestEnv,
        World {
            players: HashMap::new(),
            time_ms: 0,
        },
    );
    runner.step(50).expect("step ok");

    // Time advances in Runner::step after env+rules
    assert_eq!(runner.world().time_ms, 50);

    // Order proof: player created by env, incremented by rules
    let p = runner.world().players.get(&KEY).expect("player exists");
    assert!((p.x - 1.0).abs() < 1e-6, "rules saw env changes");
}
