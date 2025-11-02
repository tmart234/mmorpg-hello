use gs_core::{PlayerState, World};

#[test]
fn defaults_are_sane() {
    let p = PlayerState::default();
    assert_eq!(p.x, 0.0);
    assert_eq!(p.y, 0.0);
    assert_eq!(p.stamina, 0.0);
    assert_eq!(p.cooldown_ms, 0);

    let w = World::default();
    assert_eq!(w.time_ms, 0);
    assert!(w.players.is_empty());
}
