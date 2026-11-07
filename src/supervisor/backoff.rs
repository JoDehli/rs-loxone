//! Reconnect delays: exponential from 5 s, capped at 60 s, with ±20 % jitter.

use std::time::Duration;

use crate::transport::retry::backoff;

/// First reconnect delay.
pub const RECONNECT_MIN: Duration = Duration::from_secs(5);
/// Longest reconnect delay.
pub const RECONNECT_MAX: Duration = Duration::from_secs(60);
/// A session that stays up this long resets the backoff.
pub const STABLE_AFTER: Duration = Duration::from_secs(60);

/// Wait after the Miniserver has no free connection slot (901) or is going down for an
/// update or restart (4007, 4008). Retrying sooner only adds load and fails again.
pub const LONG_WAIT: Duration = Duration::from_secs(300);

/// Whether a reply or close code calls for [`LONG_WAIT`] instead of the normal backoff.
pub fn is_long_wait_code(code: i64) -> bool {
    matches!(code, 901 | 4007 | 4008)
}

/// The wait before reconnect attempt `failed` (0-based count of failures in a row).
/// `unit` is the jitter source in `[0, 1)`; `0.5` means no jitter.
pub fn delay(failed: u32, unit: f64) -> Duration {
    backoff(failed, RECONNECT_MIN, RECONNECT_MAX, unit)
}

/// Like [`delay`], but with [`LONG_WAIT`] as the base when `long` is set. The same ±20 %
/// jitter applies.
pub fn delay_for(failed: u32, long: bool, unit: f64) -> Duration {
    if long {
        backoff(0, LONG_WAIT, LONG_WAIT, unit)
    } else {
        delay(failed, unit)
    }
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
    fn long_wait_codes_are_901_4007_4008_only() {
        for code in [901, 4007, 4008] {
            assert!(is_long_wait_code(code), "{code}");
        }
        for code in [503, 4003, 4006, 200] {
            assert!(!is_long_wait_code(code), "{code}");
        }
    }

    #[test]
    fn long_wait_replaces_the_normal_backoff() {
        assert_eq!(delay_for(0, true, 0.5), LONG_WAIT);
        assert_eq!(delay_for(7, true, 0.5), LONG_WAIT);
        assert_eq!(delay_for(1, false, 0.5), Duration::from_secs(10));
        let low = delay_for(0, true, 0.0);
        assert_eq!(low, Duration::from_secs(240));
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        assert_eq!(delay(0, 0.0), Duration::from_secs(4));
        let high = delay(0, 0.999_999);
        assert!(high <= Duration::from_secs_f64(6.0));
        assert!(high >= Duration::from_secs(5));
    }
}
