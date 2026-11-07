//! Parsing of auth replies and classification of their codes.

use serde_json::Value;

use super::token::TokenState;
use super::{AuthError, HashAlg, KeyAndSalt, Secret};
use crate::protocol::ll::LlResponse;

/// How the caller should react to a reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyClass {
    /// 200: success.
    Success,
    /// Credentials or rights rejected; do not retry (401, 403, 423, 4003, 4006).
    Hard,
    /// Sent before authentication; the socket may close (420, 400).
    AuthTiming,
    /// The Miniserver is busy or restarting; retry with backoff (503, 901, 4007, 4008).
    Transient,
    /// Any other code: log a warning and treat as transient.
    Other,
}

/// Classify a reply code from the Loxone error list.
pub fn classify(code: i64) -> ReplyClass {
    match code {
        200 => ReplyClass::Success,
        401 | 403 | 423 | 4003 | 4006 => ReplyClass::Hard,
        420 | 400 => ReplyClass::AuthTiming,
        503 | 901 | 4007 | 4008 => ReplyClass::Transient,
        _ => ReplyClass::Other,
    }
}

/// Fail unless the reply code is 200.
pub fn ensure_success(reply: &LlResponse) -> Result<(), AuthError> {
    match classify(reply.code) {
        ReplyClass::Success => Ok(()),
        class => Err(AuthError::Rejected {
            code: reply.code,
            class,
        }),
    }
}

/// Parse a `getkey2` reply: key, salt and hash algorithm.
///
/// A missing `hashAlg` defaults to SHA1.
pub fn parse_key2(reply: &LlResponse) -> Result<KeyAndSalt, AuthError> {
    ensure_success(reply)?;
    let fields = reply.value_as_map();
    let key = str_field(fields, "key")?;
    let salt = str_field(fields, "salt")?;
    if key.is_empty() {
        return Err(AuthError::MissingField("key"));
    }
    if salt.is_empty() {
        return Err(AuthError::MissingField("salt"));
    }
    let alg = fields
        .get("hashAlg")
        .and_then(Value::as_str)
        .unwrap_or("SHA1");
    Ok(KeyAndSalt {
        key: Secret::new(key),
        salt: salt.to_owned(),
        hash_alg: HashAlg::parse(alg)?,
    })
}

/// Parse a token reply from `getjwt`, `gettoken`, `refreshjwt` or `refreshtoken`.
pub fn parse_token(reply: &LlResponse) -> Result<TokenState, AuthError> {
    ensure_success(reply)?;
    let fields = reply.value_as_map();
    let token = str_field(fields, "token")?;
    let valid_until = num_field(fields, "validUntil")?;
    let mut state = TokenState::new(token, valid_until)?;
    if let Some(key) = fields.get("key").and_then(Value::as_str) {
        state.key = Some(Secret::new(key));
    }
    state.unsecure_password = fields
        .get("unsecurePass")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    state.token_rights = fields
        .get("tokenRights")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok());
    Ok(state)
}

fn str_field<'a>(
    fields: &'a serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<&'a str, AuthError> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or(AuthError::MissingField(name))
}

fn num_field(
    fields: &serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<f64, AuthError> {
    match fields.get(name) {
        Some(Value::Number(n)) => n.as_f64().ok_or(AuthError::MissingField(name)),
        Some(Value::String(s)) => s.trim().parse().map_err(|_| AuthError::MissingField(name)),
        _ => Err(AuthError::MissingField(name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ll(text: &str) -> LlResponse {
        LlResponse::parse(text.as_bytes()).unwrap()
    }

    #[test]
    fn classes_match_spec() {
        assert_eq!(classify(200), ReplyClass::Success);
        for c in [401, 403, 423, 4003, 4006] {
            assert_eq!(classify(c), ReplyClass::Hard, "{c}");
        }
        for c in [420, 400] {
            assert_eq!(classify(c), ReplyClass::AuthTiming, "{c}");
        }
        for c in [503, 901, 4007, 4008] {
            assert_eq!(classify(c), ReplyClass::Transient, "{c}");
        }
        assert_eq!(classify(500), ReplyClass::Other);
    }

    #[test]
    fn key2_parses_and_defaults_hash_alg() {
        let r = ll(r#"{"LL": {"control": "jdev/sys/getkey2/admin", "code": 200,
            "value": {"key": "00ff", "salt": "abcd"}}}"#);
        let ks = parse_key2(&r).unwrap();
        assert_eq!(ks.key.expose(), "00ff");
        assert_eq!(ks.salt, "abcd");
        assert_eq!(ks.hash_alg, HashAlg::Sha1);
    }

    #[test]
    fn key2_sha256_and_missing_fields() {
        let ok = ll(r#"{"LL": {"control": "c", "code": 200,
            "value": {"key": "00", "salt": "s", "hashAlg": "SHA256"}}}"#);
        assert_eq!(parse_key2(&ok).unwrap().hash_alg, HashAlg::Sha256);
        let no_key = ll(r#"{"LL": {"control": "c", "code": 200, "value": {"salt": "s"}}}"#);
        assert_eq!(parse_key2(&no_key), Err(AuthError::MissingField("key")));
    }

    #[test]
    fn unknown_hash_alg_is_error() {
        let r = ll(r#"{"LL": {"control": "c", "code": 200,
            "value": {"key": "00", "salt": "s", "hashAlg": "MD5"}}}"#);
        assert!(matches!(parse_key2(&r), Err(AuthError::UnknownHashAlg(_))));
    }

    #[test]
    fn hard_code_is_rejected_without_parsing() {
        let r = ll(r#"{"LL": {"control": "c", "code": 401, "value": ""}}"#);
        assert_eq!(
            parse_key2(&r),
            Err(AuthError::Rejected {
                code: 401,
                class: ReplyClass::Hard
            })
        );
    }

    #[test]
    fn token_parses_all_fields() {
        let r = ll(r#"{"LL": {"control": "c", "code": 200, "value":
            {"token": "eyJ.x.y", "validUntil": 123456, "key": "ab",
             "unsecurePass": true, "tokenRights": 6}}}"#);
        let t = parse_token(&r).unwrap();
        assert_eq!(t.token().expose(), "eyJ.x.y");
        assert_eq!(t.valid_until(), 123456.0);
        assert_eq!(t.key.as_ref().map(Secret::expose), Some("ab"));
        assert!(t.unsecure_password);
        assert_eq!(t.token_rights, Some(6));
    }

    #[test]
    fn token_missing_valid_until_is_error() {
        let r = ll(r#"{"LL": {"control": "c", "code": 200, "value": {"token": "t"}}}"#);
        assert_eq!(parse_token(&r), Err(AuthError::MissingField("validUntil")));
    }

    #[test]
    fn token_empty_is_error() {
        let r =
            ll(r#"{"LL": {"control": "c", "code": 200, "value": {"token": "", "validUntil": 5}}}"#);
        assert!(matches!(parse_token(&r), Err(AuthError::InvalidToken(_))));
    }
}
