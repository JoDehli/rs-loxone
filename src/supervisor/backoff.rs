//! Reconnect delays: exponential from 5 s, capped at 60 s, with ±20 % jitter.

use std::time::Duration;

use crate::transport::retry::backoff;

/// First reconnect delay.
pub const RECONNECT_MIN: Duration = Duration::from_secs(5);
/// Longest reconnect delay.
pub const RECONNECT_MAX: Duration = Duration::from_secs(60);
/// A session that stays up this long resets the backoff.
pub const STABLE_AFTER: Duration = Duration::from_secs(60);

/// The wait before reconnect attempt `failed` (0-based count of failures in a row).
/// `unit` is the jitter source in `[0, 1)`; `0.5` means no jitter.
pub fn delay(failed: u32, unit: f64) -> Duration {
    backoff(failed, RECONNECT_MIN, RECONNECT_MAX, unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_from_five_seconds_without_jitter() {
        assert_eq!(delay(0, 0.5), Duration::from_secs(5));
        assert_eq!(delay(1, 0.5), Duration::from_secs(10));
        assert_eq!(delay(2, 0.5), Duration::from_secs(20));
        assert_eq!(delay(3, 0.5), Duration::from_secs(40));
    }

    #[test]
    fn capped_at_sixty_seconds() {
        assert_eq!(delay(4, 0.5), RECONNECT_MAX);
        assert_eq!(delay(30, 0.5), RECONNECT_MAX);
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        assert_eq!(delay(0, 0.0), Duration::from_secs(4));
        let high = delay(0, 0.999_999);
        assert!(high <= Duration::from_secs_f64(6.0));
        assert!(high >= Duration::from_secs(5));
    }
}
