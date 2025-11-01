use once_cell::sync::Lazy;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub static HEARTBEATS: AtomicU64 = AtomicU64::new(0);
pub static PROTECTED_RECEIPTS: AtomicU64 = AtomicU64::new(0);

pub static LAST_LOGS: Lazy<DashMap<(&'static str, u64), u64>> = Lazy::new(DashMap::new);

/// Deduplicated logging by (tag, bucket_ms) with a TTL-ish budget.
pub fn log_throttled(tag: &'static str, bucket_ms: u64, msg: impl AsRef<str>) {
    use crate::ctx::now_ms;
    let now = now_ms();
    let bucket = now / bucket_ms;

    let key = (tag, bucket);
    let first = LAST_LOGS.insert(key, now).is_none();
    if first {
        println!("[{}] {}", tag, msg.as_ref());
    }
}

pub trait AtomicU64Ext {
    fn inc(&self) -> u64;
}
impl AtomicU64Ext for AtomicU64 {
    fn inc(&self) -> u64 {
        self.fetch_add(1, Ordering::Relaxed) + 1
    }
}

pub fn snapshot() -> (u64, u64) {
    (HEARTBEATS.load(Ordering::Relaxed), PROTECTED_RECEIPTS.load(Ordering::Relaxed))
}
