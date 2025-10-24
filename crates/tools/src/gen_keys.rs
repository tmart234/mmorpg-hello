use ed25519_dalek::SigningKey;
use std::fs::{self, File};
use std::io::Write;

fn main() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk = sk.verifying_key();
    fs::create_dir_all("keys").unwrap();

    File::create("keys/vs_ed25519.pk8").unwrap().write_all(&sk.to_bytes()).unwrap();
    File::create("keys/vs_ed25519.pub").unwrap().write_all(&pk.to_bytes()).unwrap();

    println!("Generated keys: keys/vs_ed25519.pk8 + .pub");
}
