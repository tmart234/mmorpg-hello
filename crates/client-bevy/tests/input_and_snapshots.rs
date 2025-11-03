use bevy::prelude::*;
use client_bevy::{clamp_move, gather_input_impl, pump_snapshots_impl};
use common::proto::WorldSnapshot;
use tokio::sync::mpsc;

#[test]
fn clamp_move_caps_length() {
    let (dx, dy) = clamp_move(2.0, 0.0);
    assert!((dx - 1.0).abs() < 1e-6);
    assert!(dy.abs() < 1e-6);

    let (dx, dy) = clamp_move(1.0, 1.0);
    let len = (dx * dx + dy * dy).sqrt();
    assert!((len - 1.0).abs() < 1e-5);
    assert!(dx > 0.0 && dy > 0.0);
}

#[test]
fn gather_input_maps_keys_to_move_cmd() {
    let mut keys = ButtonInput::<KeyCode>::default();
    keys.press(KeyCode::KeyW);
    keys.press(KeyCode::KeyA); // diagonal up-left

    let cmd = gather_input_impl(&keys).expect("should produce a Move");
    if let common::proto::ClientCmd::Move { dx, dy } = cmd {
        let len = (dx * dx + dy * dy).sqrt();
        assert!(dx < 0.0 && dy > 0.0);
        assert!((len - 1.0).abs() < 1e-5);
    } else {
        panic!("expected Move");
    }
}

#[test]
fn pump_snapshots_collects_all_without_runtime() {
    let (tx, mut rx) = mpsc::channel::<WorldSnapshot>(8);
    tx.try_send(WorldSnapshot {
        tick: 1,
        you: (0.0, 0.0),
        others: vec![],
    })
    .unwrap();
    tx.try_send(WorldSnapshot {
        tick: 2,
        you: (1.0, 0.0),
        others: vec![],
    })
    .unwrap();

    let out = pump_snapshots_impl(&mut rx);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].tick, 1);
    assert_eq!(out[1].tick, 2);
}
