//! The login sequence: key exchange, key and salt, then a stored token or the password.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rand::rngs::OsRng;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::auth::AuthError;
use crate::auth::KeyAndSalt;
use crate::auth::commands;
use crate::auth::enc::{ControlDecrypter, EncCipher};
use crate::auth::hash::{credential_hash, token_hash};
use crate::auth::keyexchange::SessionKey;
use crate::auth::reply::{ensure_success, parse_key2, parse_token};
use crate::auth::token::{TokenState, loxone_seconds};
use crate::protocol::ll::LlResponse;
use crate::protocol::message::Message;
use crate::session::frames::FramePairer;
use crate::session::reader::reveal_control;
use crate::session::{SessionConfig, SessionError};
use crate::transport::ws::WsReceiver;

/// How long to wait for one reply during login.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(15);
/// A stored token is used only if more than this many seconds remain.
pub const TOKEN_MIN_REMAINING_SECS: f64 = 100.0;

/// What login leaves behind for the rest of the session.
pub struct Login {
    /// The token in use after login.
    pub token: TokenState,
    /// The getkey2 key and salt (its hash algorithm is used for refresh).
    pub key2: KeyAndSalt,
    /// The session key (AES key and IV). Kept for the connection's lifetime.
    pub session_key: SessionKey,
    /// The encryption state; the salt chain continues from here.
    pub cipher: EncCipher,
    /// True if the stored token was used instead of the password.
    pub used_stored_token: bool,
}

/// A random 16-byte salt, hex encoded.
pub fn random_salt() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Seconds since the Loxone epoch, now.
pub fn now_loxone() -> f64 {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    loxone_seconds(unix)
}

/// Send one encrypted command through the cipher.
async fn send_enc(
    out: &mpsc::Sender<String>,
    cipher: &mut EncCipher,
    cmd: &str,
) -> Result<(), SessionError> {
    let text = cipher.encrypt_command(cmd, &random_salt());
    out.send(text).await.map_err(|_| SessionError::Closed)
}

/// What one decoded message means while waiting for a login reply.
fn match_reply(
    message: Message,
    needle: &str,
    decrypt: Option<&ControlDecrypter>,
) -> Result<Option<LlResponse>, SessionError> {
    match message {
        Message::Text(mut ll) => {
            if let Some(d) = decrypt {
                reveal_control(d, &mut ll);
            }
            Ok((ll.control.contains(needle)).then_some(ll))
        }
        Message::OutOfService => Err(SessionError::OutOfService),
        _ => Ok(None),
    }
}

/// Wait for a reply whose control contains `needle`. Other messages are skipped, as the
/// reader does; an out-of-service message ends the wait with an error.
pub async fn await_reply(
    rx: &mut WsReceiver,
    pairer: &mut FramePairer,
    needle: &str,
    decrypt: Option<&ControlDecrypter>,
) -> Result<LlResponse, SessionError> {
    let deadline = Instant::now() + REPLY_TIMEOUT;
    loop {
        let frame = tokio::time::timeout_at(deadline, rx.next_frame())
            .await
            .map_err(|_| SessionError::Timeout)??
            .ok_or(SessionError::Closed)?;
        match pairer.push(frame) {
            Ok(Some(message)) => {
                if let Some(ll) = match_reply(message, needle, decrypt)? {
                    return Ok(ll);
                }
            }
            Ok(None) => {}
            Err(err) => eprintln!("rs-loxone: skipping undecodable frame during login: {err}"),
        }
    }
}

/// Turn a reply into success or a typed rejection. Same rules as `auth::reply`.
pub(crate) fn ensure_200(ll: &LlResponse) -> Result<(), SessionError> {
    match ensure_success(ll) {
        Ok(()) => Ok(()),
        Err(AuthError::Rejected { code, class }) => Err(SessionError::Rejected { code, class }),
        Err(other) => Err(SessionError::Auth(other)),
    }
}

/// Run the login sequence on a freshly opened connection.
pub async fn login(
    out: &mpsc::Sender<String>,
    rx: &mut WsReceiver,
    cfg: &SessionConfig,
    version: [u32; 3],
    cert_pem: &str,
) -> Result<Login, SessionError> {
    let mut pairer = FramePairer::default();
    let user = cfg.username.as_str();

    // 1. Key exchange (plain).
    let session_key = SessionKey::generate(cert_pem, &mut OsRng)?;
    out.send(session_key.keyexchange_command().to_owned())
        .await
        .map_err(|_| SessionError::Closed)?;
    ensure_200(&await_reply(rx, &mut pairer, "keyexchange", None).await?)?;

    // 2. Key and salt for the user (encrypted, chain starts here).
    let mut cipher = EncCipher::new(&session_key, random_salt());
    let decrypt = cipher.decrypter();
    send_enc(out, &mut cipher, &commands::get_key2(user)).await?;
    let k2 = await_reply(rx, &mut pairer, "getkey2", Some(&decrypt)).await?;
    ensure_200(&k2)?;
    let key2 = parse_key2(&k2)?;

    // 3. A stored token, if it has enough time left.
    if let Some(stored) = &cfg.token
        && stored.seconds_to_expire(now_loxone()) > TOKEN_MIN_REMAINING_SECS
    {
        let hash = token_hash(stored.token().expose(), &key2)?;
        send_enc(out, &mut cipher, &commands::auth_with_token(&hash, user)).await?;
        let r = await_reply(rx, &mut pairer, "withtoken", Some(&decrypt)).await?;
        match r.code {
            200 => {
                let token = stored.clone();
                return finish(out, cipher, session_key, key2, token, true).await;
            }
            // Refused or unknown token: fall back to the password.
            401 | 404 => {}
            _ => ensure_200(&r)?,
        }
    }

    // 4. Password login: getjwt (firmware >= 10.2) or gettoken (older).
    let pw_hash = credential_hash(user, cfg.password.expose(), &key2)?;
    let verb = if commands::uses_jwt(version) {
        "getjwt"
    } else {
        "gettoken"
    };
    send_enc(
        out,
        &mut cipher,
        &commands::request_token(version, &pw_hash, user),
    )
    .await?;
    let tr = await_reply(rx, &mut pairer, verb, Some(&decrypt)).await?;
    ensure_200(&tr)?;
    let token = parse_token(&tr)?;
    finish(out, cipher, session_key, key2, token, false).await
}

/// Enable state updates after a successful login.
async fn finish(
    out: &mpsc::Sender<String>,
    mut cipher: EncCipher,
    session_key: SessionKey,
    key2: KeyAndSalt,
    token: TokenState,
    used_stored_token: bool,
) -> Result<Login, SessionError> {
    send_enc(out, &mut cipher, commands::enable_updates()).await?;
    Ok(Login {
        token,
        key2,
        session_key,
        cipher,
        used_stored_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(control: &str) -> Message {
        let json = format!(r#"{{"LL": {{"control": "{control}", "code": 200, "value": ""}}}}"#);
        Message::Text(LlResponse::parse(json.as_bytes()).unwrap())
    }

    #[test]
    fn matching_text_is_the_reply() {
        let got = match_reply(text("jdev/sys/getkey2/admin"), "getkey2", None).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn other_text_is_skipped() {
        assert!(
            match_reply(text("jdev/sys/getjwt"), "getkey2", None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn out_of_service_ends_the_wait() {
        assert!(matches!(
            match_reply(Message::OutOfService, "getkey2", None),
            Err(SessionError::OutOfService)
        ));
    }
}
