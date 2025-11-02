use gs_core::{PlayerState, World};
use std::collections::HashMap;

#[test]
fn world_roundtrips_with_bincode() {
    let mut players = HashMap::new();
    players.insert(
        [1u8; 32],
        PlayerState {
            x: 2.5,
            y: -3.0,
            stamina: 7.0,
            cooldown_ms: 250,
        },
    );

    // Struct literal init: avoids clippy::field-reassign-with-default
    let w = World {
        players,
        time_ms: 1234,
    };

    let bytes = bincode::serialize(&w).expect("serialize");
    let back: World = bincode::deserialize(&bytes).expect("deserialize");

    assert_eq!(back.time_ms, 1234);
    let p = back.players.get(&[1u8; 32]).expect("player exists");
    assert!((p.x - 2.5).abs() < 1e-6 && (p.y + 3.0).abs() < 1e-6);
}
