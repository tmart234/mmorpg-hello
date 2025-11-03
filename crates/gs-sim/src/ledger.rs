use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(serde::Serialize, Debug)]
pub struct LedgerEvent<'a> {
    pub t_unix_ms: u64,
    pub session_id: &'a [u8; 16],
    pub client_pub: &'a [u8; 32],
    pub op: &'a str, // e.g., "Move" or "SpendCoins"
    pub op_id: &'a [u8; 16],
    pub delta: i64, // negative for spend, positive for grant
    pub balance_before: u64,
    pub balance_after: u64,
    pub receipt_tip: &'a [u8; 32],
}

#[derive(Debug)]
pub struct Ledger {
    file: File,
}

impl Ledger {
    pub fn open_for_session(session_id_hex4: &str) -> std::io::Result<Self> {
        let mut p = PathBuf::from("ledger");
        std::fs::create_dir_all(&p)?;
        p.push(format!("session_{}.log", session_id_hex4));
        let file = OpenOptions::new().create(true).append(true).open(p)?;
        Ok(Self { file }) // ← NO trailing semicolon so this returns Result<Self>
    }

    pub fn append(&mut self, ev: &LedgerEvent) -> std::io::Result<()> {
        let line = serde_json::to_string(ev).expect("serialize ledger event");
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        Ok(()) // ← return Result<(), _>
    }
}
