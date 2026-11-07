//! Token state and refresh timing.
//!
//! Times are seconds since the Loxone epoch, 2009-01-01 00:00 UTC. The module
//! never reads the clock: the caller passes `now` (use [`loxone_seconds`] to
//! convert a Unix time).

use std::time::Duration;

use super::{AuthError, Secret};

/// Unix time (seconds) of the Loxone epoch, 2009-01-01 00:00 UTC.
pub const LOXONE_EPOCH_UNIX: i64 = 1_230_768_000;
/// Upper bound on the wait between refreshes (`MAX_REFRESH_DELAY`, one day).
pub const MAX_REFRESH_DELAY: Duration = Duration::from_secs(86_400);

/// Convert a Unix time in seconds to seconds since the Loxone epoch.
pub fn loxone_seconds(unix_secs: f64) -> f64 {
    unix_secs - LOXONE_EPOCH_UNIX as f64
}

/// A Miniserver token and its lifetime.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenState {
    token: Secret,
    valid_until: f64,
    /// `key` from the token reply, if the Miniserver sent one.
    pub key: Option<Secret>,
    /// `hashAlg` the token was acquired with, if known.
    pub hash_alg: Option<String>,
    /// True if the Miniserver flags a weak password (`unsecurePass`).
    pub unsecure_password: bool,
    /// Permission bits granted with the token (`tokenRights`), if sent.
    pub token_rights: Option<u32>,
}

impl TokenState {
    /// Create a token state.
    ///
    /// An empty token or a `valid_until` of 0 is an error.
    pub fn new(token: impl Into<String>, valid_until: f64) -> Result<Self, AuthError> {
        let token = token.into();
        if token.is_empty() {
            return Err(AuthError::InvalidToken("empty token".into()));
        }
        if valid_until == 0.0 {
            return Err(AuthError::InvalidToken("valid_until is 0".into()));
        }
        if !valid_until.is_finite() {
            return Err(AuthError::InvalidToken(
                "valid_until is not a number".into(),
            ));
        }
        Ok(Self {
            token: Secret::new(token),
            valid_until,
            key: None,
            hash_alg: None,
            unsecure_password: false,
            token_rights: None,
        })
    }

    /// The token itself. Handle as a secret.
    pub fn token(&self) -> &Secret {
        &self.token
    }

    /// Seconds since the Loxone epoch when the token expires.
    pub fn valid_until(&self) -> f64 {
        self.valid_until
    }

    /// Seconds until expiry at time `now` (negative once expired).
    pub fn seconds_to_expire(&self, now: f64) -> f64 {
        self.valid_until - now
    }

    /// How long to wait before refreshing at time `now`.
    ///
    /// `clamp(trunc(0.5 × seconds_to_expire), 1 s, 86400 s)`.
    pub fn refresh_delay(&self, now: f64) -> Duration {
        let candidate = (self.seconds_to_expire(now) * 0.5).trunc();
        let secs = candidate.clamp(1.0, MAX_REFRESH_DELAY.as_secs_f64());
        Duration::from_secs_f64(secs)
    }

    /// Replace the token and expiry after a successful refresh.
    pub fn renew(&mut self, token: impl Into<String>, valid_until: f64) -> Result<(), AuthError> {
        let fresh = Self::new(token, valid_until)?;
        self.token = fresh.token;
        self.valid_until = fresh.valid_until;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(valid_until: f64) -> TokenState {
        TokenState::new("tok", valid_until).unwrap()
    }

    #[test]
    fn refresh_delay_boundaries() {
        // now = 0, so seconds_to_expire == valid_until.
        assert_eq!(tok(0.5).refresh_delay(0.0), Duration::from_secs(1)); // trunc(0.25)=0 -> 1
        assert_eq!(tok(1.9).refresh_delay(0.0), Duration::from_secs(1)); // trunc(0.95)=0 -> 1
        assert_eq!(tok(2.0).refresh_delay(0.0), Duration::from_secs(1)); // trunc(1.0)=1
        assert_eq!(tok(4.0).refresh_delay(0.0), Duration::from_secs(2));
        assert_eq!(tok(3_600.0).refresh_delay(0.0), Duration::from_secs(1_800));
    }

    #[test]
    fn refresh_delay_clamped_to_one_day() {
        // Two days remaining: half is one day, exactly the cap.
        assert_eq!(tok(172_800.0).refresh_delay(0.0), MAX_REFRESH_DELAY);
        // A year remaining is still capped at one day.
        assert_eq!(tok(365.0 * 86_400.0).refresh_delay(0.0), MAX_REFRESH_DELAY);
    }

    #[test]
    fn expired_token_refreshes_after_one_second() {
        assert_eq!(tok(100.0).refresh_delay(200.0), Duration::from_secs(1));
    }

    #[test]
    fn seconds_to_expire_uses_now() {
        assert_eq!(tok(1_000.0).seconds_to_expire(400.0), 600.0);
    }

    #[test]
    fn empty_token_is_error() {
        assert!(matches!(
            TokenState::new("", 10.0),
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn zero_valid_until_is_error() {
        assert!(matches!(
            TokenState::new("t", 0.0),
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn non_finite_valid_until_is_error() {
        assert!(TokenState::new("t", f64::NAN).is_err());
        assert!(TokenState::new("t", f64::INFINITY).is_err());
        assert!(TokenState::new("t", f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn token_debug_is_redacted() {
        let t = tok(10.0);
        assert!(!format!("{t:?}").contains("tok\""));
    }

    #[test]
    fn loxone_epoch_conversion() {
        assert_eq!(loxone_seconds(LOXONE_EPOCH_UNIX as f64), 0.0);
        assert_eq!(loxone_seconds(LOXONE_EPOCH_UNIX as f64 + 60.0), 60.0);
    }

    #[test]
    fn renew_replaces_token_and_expiry() {
        let mut t = tok(10.0);
        t.renew("new", 500.0).unwrap();
        assert_eq!(t.token().expose(), "new");
        assert_eq!(t.valid_until(), 500.0);
        assert!(t.renew("", 500.0).is_err());
    }
}
