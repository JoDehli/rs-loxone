//! Token renewal.
//!
//! 1. Plain `jdev/sys/getkey`: the reply's `value` is a fresh key.
//! 2. Hash the current token with that key (algorithm from getkey2).
//! 3. `jdev/sys/refreshjwt/<hash>/<user>`, encrypted, on the same salt chain.
//! 4. Code 200: store the new token, save it if a token file is set, and report it.
//!
//! Waiting: the first renewal is due `refresh_delay` after the token was issued. A
//! failed cycle is retried after `attempt_delay`, up to `attempts` times. A cycle that
//! still fails waits `failed_cycle_wait`. After `max_failed_cycles` such cycles in a row,
//! the session reports `AuthFailed` and ends.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::auth::commands;
use crate::auth::hash::token_hash;
use crate::auth::reply::parse_token;
use crate::auth::store::TokenStore;
use crate::auth::token::TokenState;
use crate::auth::{KeyAndSalt, Secret};
use crate::session::commands::Shared;
use crate::session::login::{ensure_200, now_loxone};
use crate::session::{DisconnectReason, Event, SessionError};

/// How often and how fast a failed renewal is retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshPolicy {
    /// Attempts per cycle.
    pub attempts: u32,
    /// Pause between attempts in one cycle.
    pub attempt_delay: Duration,
    /// Failed cycles in a row before the session ends.
    pub max_failed_cycles: u32,
    /// Pause before the next cycle after a failed one.
    pub failed_cycle_wait: Duration,
}

impl Default for RefreshPolicy {
    fn default() -> Self {
        Self {
            attempts: 5,
            attempt_delay: Duration::from_secs(2),
            max_failed_cycles: 10,
            failed_cycle_wait: Duration::from_secs(60),
        }
    }
}

/// One renewal, without retries.
async fn refresh_once(
    shared: &Shared,
    token: &Mutex<TokenState>,
    key2: &KeyAndSalt,
    user: &str,
    version: [u32; 3],
) -> Result<TokenState, SessionError> {
    let getkey = shared
        .request_plain("jdev/sys/getkey", &["sys/getkey"])
        .await?;
    ensure_200(&getkey)?;
    let fresh_key = KeyAndSalt {
        key: Secret::new(getkey.value.clone()),
        salt: String::new(),
        hash_alg: key2.hash_alg,
    };
    let current = token
        .lock()
        .map_err(|_| SessionError::Closed)?
        .token()
        .expose()
        .to_owned();
    let hash = token_hash(&current, &fresh_key)?;
    let reply = shared
        .request(
            &commands::refresh_token(version, &hash, user),
            &["refreshjwt"],
        )
        .await?;
    ensure_200(&reply)?;
    Ok(parse_token(&reply)?)
}

/// The refresh loop. Ends when the session ends, or after too many failed cycles.
pub(crate) async fn run(
    shared: Arc<Shared>,
    token: Arc<Mutex<TokenState>>,
    key2: KeyAndSalt,
    user: String,
    version: [u32; 3],
    policy: RefreshPolicy,
    store: Option<TokenStore>,
) {
    let mut wait = match token.lock() {
        Ok(t) => t.refresh_delay(now_loxone()),
        Err(_) => return,
    };
    let mut failed_cycles = 0u32;
    loop {
        tokio::time::sleep(wait).await;
        let mut renewed = None;
        for attempt in 0..policy.attempts.max(1) {
            match refresh_once(&shared, &token, &key2, &user, version).await {
                Ok(new) => {
                    renewed = Some(new);
                    break;
                }
                // The session has ended: nothing more to do.
                Err(SessionError::Closed) => return,
                Err(err) => {
                    eprintln!(
                        "rs-loxone: token renewal attempt {} failed: {err}",
                        attempt + 1
                    );
                    if attempt + 1 < policy.attempts {
                        tokio::time::sleep(policy.attempt_delay).await;
                    }
                }
            }
        }
        match renewed {
            Some(new) => {
                failed_cycles = 0;
                if let Ok(mut current) = token.lock() {
                    *current = new.clone();
                }
                if let Some(store) = &store {
                    store.save_off_thread(new.clone()).await;
                }
                shared.emit(Event::TokenChanged(new.clone()));
                wait = new.refresh_delay(now_loxone());
            }
            None => {
                failed_cycles += 1;
                if failed_cycles >= policy.max_failed_cycles {
                    shared.emit(Event::AuthFailed {
                        reason: format!("token renewal failed {failed_cycles} cycles in a row"),
                    });
                    // The reader reports the disconnect and the writer closes the socket.
                    shared.stop(DisconnectReason::AuthFailed);
                    return;
                }
                wait = policy.failed_cycle_wait;
            }
        }
    }
}
