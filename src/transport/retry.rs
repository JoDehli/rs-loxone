//! Retry with exponential backoff for transient transport errors.
//!
//! Delay before retry `n` (0-based) is `min(base × 2^n, max)` with ±20 % jitter,
//! Time comes from tokio, so tests can pause it.

use std::future::Future;
use std::time::Duration;

use super::TransportError;

/// Bootstrap attempts (`RECONNECT_TRIES`).
pub const MAX_ATTEMPTS: u32 = 5;
/// Base delay (`RECONNECT_DELAY`).
pub const BASE_DELAY: Duration = Duration::from_secs(5);
/// Delay cap (`MAX_RECONNECT_DELAY`).
pub const MAX_DELAY: Duration = Duration::from_secs(60);

/// Source of jitter in `[0, 1)`. Injected so tests are exact.
pub trait Jitter {
    /// A value in `[0, 1)`.
    fn unit(&mut self) -> f64;
}

/// Jitter from the thread RNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct RandJitter;

impl Jitter for RandJitter {
    fn unit(&mut self) -> f64 {
        rand::random::<f64>()
    }
}

/// Retry settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts, including the first.
    pub max_attempts: u32,
    /// Base delay.
    pub base: Duration,
    /// Cap on a single delay.
    pub max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MAX_ATTEMPTS,
            base: BASE_DELAY,
            max: MAX_DELAY,
        }
    }
}

/// The delay before retry `attempt` (0-based), with `unit` as the jitter source.
///
/// `unit = 0.5` gives no jitter; `0.0` gives −20 %; values near `1.0` give +20 %.
pub fn backoff(attempt: u32, base: Duration, max: Duration, unit: f64) -> Duration {
    let factor = 2u32.checked_pow(attempt).unwrap_or(u32::MAX);
    let raw = base.saturating_mul(factor).min(max).as_secs_f64();
    let jitter = raw * 0.2 * (2.0 * unit - 1.0);
    Duration::from_secs_f64((raw + jitter).max(0.0))
}

/// Run `op` until it succeeds, a non-retryable error occurs, or the attempts run out.
pub async fn with_retry<T, F, Fut>(
    policy: RetryPolicy,
    jitter: &mut impl Jitter,
    mut op: F,
) -> Result<T, TransportError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, TransportError>>,
{
    let mut attempt = 0;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if err.is_retryable() && attempt + 1 < policy.max_attempts => {
                let delay = backoff(attempt, policy.base, policy.max, jitter.unit());
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Fixed(f64);
    impl Jitter for Fixed {
        fn unit(&mut self) -> f64 {
            self.0
        }
    }

    #[test]
    fn backoff_doubles_then_caps() {
        let secs = |n| backoff(n, BASE_DELAY, MAX_DELAY, 0.5).as_secs();
        assert_eq!(secs(0), 5);
        assert_eq!(secs(1), 10);
        assert_eq!(secs(2), 20);
        assert_eq!(secs(3), 40);
        assert_eq!(secs(4), 60, "80 s is capped at 60 s");
        assert_eq!(secs(40), 60, "huge attempt numbers stay capped");
    }

    #[test]
    fn jitter_is_plus_minus_twenty_percent() {
        let low = backoff(0, BASE_DELAY, MAX_DELAY, 0.0).as_secs_f64();
        let high = backoff(0, BASE_DELAY, MAX_DELAY, 1.0).as_secs_f64();
        assert!((low - 4.0).abs() < 1e-9);
        assert!((high - 6.0).abs() < 1e-9);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_503_then_succeeds() {
        let calls = Cell::new(0);
        let start = tokio::time::Instant::now();
        let out = with_retry(RetryPolicy::default(), &mut Fixed(0.5), || {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n < 3 {
                    Err(TransportError::Http { status: 503 })
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert_eq!(out, Ok("ok"));
        assert_eq!(calls.get(), 3);
        assert_eq!(start.elapsed().as_secs(), 5 + 10);
    }

    #[tokio::test(start_paused = true)]
    async fn unauthorised_is_not_retried() {
        let calls = Cell::new(0);
        let out: Result<(), _> = with_retry(RetryPolicy::default(), &mut Fixed(0.5), || {
            calls.set(calls.get() + 1);
            async { Err(TransportError::Http { status: 401 }) }
        })
        .await;
        assert_eq!(out, Err(TransportError::Http { status: 401 }));
        assert_eq!(calls.get(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_max_attempts() {
        let calls = Cell::new(0);
        let out: Result<(), _> = with_retry(RetryPolicy::default(), &mut Fixed(0.5), || {
            calls.set(calls.get() + 1);
            async { Err(TransportError::Unreachable("refused".into())) }
        })
        .await;
        assert!(matches!(out, Err(TransportError::Unreachable(_))));
        assert_eq!(calls.get(), MAX_ATTEMPTS);
    }
}
