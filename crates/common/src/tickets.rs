/// Coarse skew allowance for ticket times.
pub const TICKET_MAX_SKEW_MS: u64 = 1_500;

/// Is the ticket valid "now", in a coarse time window?
#[inline]
pub fn ticket_is_fresh(now_ms: u64, not_before_ms: u64, not_after_ms: u64) -> bool {
    let nb = not_before_ms.saturating_sub(TICKET_MAX_SKEW_MS);
    let na = not_after_ms.saturating_add(TICKET_MAX_SKEW_MS);
    now_ms >= nb && now_ms <= na
}
