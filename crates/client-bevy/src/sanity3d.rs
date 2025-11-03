use bevy::color::palettes::css::RED;
use bevy::prelude::*;
use bevy::math::primitives::Cuboid; // <- needed in 0.17

pub struct Sanity3dPlugin;

impl Plugin for Sanity3dPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Startup, (spawn_camera, spawn_light, spawn_cube))
            .add_systems(Update, spin_cube);
    }
}

#[derive(Component)]
struct Spin;

fn spawn_camera(mut commands: Commands) {
    commands.spawn((
        Camera3d::default(),
        Transform::from_xyz(0.0, 2.5, 8.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));
}

fn spawn_light(mut commands: Commands) {
    commands.spawn((
        DirectionalLight::default(),
        Transform::from_xyz(4.0, 8.0, 4.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));
}

fn spawn_cube(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    // the Mesh::from(..) is important
    let cube_mesh = meshes.add(Mesh::from(Cuboid::new(1.0, 1.0, 1.0)));
    let mat = materials.add(StandardMaterial {
        base_color: RED.into(),
        ..Default::default()
    });

    commands.spawn((
        Mesh3d(cube_mesh),
        MeshMaterial3d(mat),
        Transform::from_translation(Vec3::new(0.0, 0.5, 0.0)),
        Spin,
    ));

    let ground_mesh = meshes.add(Mesh::from(Cuboid::new(8.0, 0.1, 8.0)));
    let ground_mat = materials.add(StandardMaterial::default());
    commands.spawn((
        Mesh3d(ground_mesh),
        MeshMaterial3d(ground_mat),
        Transform::from_translation(Vec3::new(0.0, -0.05, 0.0)),
    ));
}

fn spin_cube(mut q: Query<&mut Transform, With<Spin>>, time: Res<Time>) {
    if let Ok(mut t) = q.single_mut() {  // <- use single_mut()
        t.rotate_y(1.0 * time.delta_secs());
    }
}

