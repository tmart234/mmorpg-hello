use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Extremely small "world" placeholder. Expand as needed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct World {
    pub players: HashMap<[u8; 32], PlayerState>,
    pub time_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlayerState {
    pub x: f32,
    pub y: f32,
    pub stamina: f32,
    pub cooldown_ms: u64,
}

/// Game rule hooks (apply inputs, clamp movement, stamina, cooldowns, etc).
pub trait GameRules {
    fn tick(&mut self, dt_ms: u64, world: &mut World) -> Result<()>;
}

/// Environment/system hooks (weather, ambient hazards, city attack events, etc).
pub trait EnvironmentSystem {
    fn on_tick(&mut self, dt_ms: u64, world: &mut World) -> Result<()>;
}

/// A tiny runner the GS can call each frame *after* ticket & sig checks.
pub struct Runner<R: GameRules, E: EnvironmentSystem> {
    rules: R,
    env: E,
    world: World,
}

impl<R: GameRules, E: EnvironmentSystem> Runner<R, E> {
    pub fn new(rules: R, env: E, initial_world: World) -> Self {
        Self {
            rules,
            env,
            world: initial_world,
        }
    }

    /// Call each simulation tick (e.g., 50–100ms) after validating inputs/tickets.
    pub fn step(&mut self, dt_ms: u64) -> Result<()> {
        self.env.on_tick(dt_ms, &mut self.world)?;
        self.rules.tick(dt_ms, &mut self.world)?;
        self.world.time_ms = self.world.time_ms.saturating_add(dt_ms);
        Ok(())
    }

    pub fn world(&self) -> &World {
        &self.world
    }
    pub fn world_mut(&mut self) -> &mut World {
        &mut self.world
    }
}
