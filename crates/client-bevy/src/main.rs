use bevy::prelude::*;
use bevy::time::Fixed;

fn main() {
    App::new()
        .add_plugins(DefaultPlugins)
        // Set fixed timestep to 20 Hz (50 ms) to mirror GS tick cadence
        .insert_resource(Time::<Fixed>::from_hz(20.0))
        .add_systems(Startup, hello_startup)
        .add_systems(FixedUpdate, client_fixed_tick)
        .run();
}

fn hello_startup() {
    info!("Bevy hello world (startup) 👋");
}

fn client_fixed_tick(time_fixed: Res<Time<Fixed>>) {
    // Fires 20x/sec; useful for client-side prediction or local sim
    info!("client fixed tick: {:?} delta", time_fixed.delta());
}
