//! Hashing for logins, tokens and secured commands.
//!
//! All three follow the Loxone scheme: an inner hash (uppercase hex), then an
//! HMAC keyed with the Miniserver's hex key (lowercase hex output).

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Sha256;

use super::{AuthError, HashAlg, KeyAndSalt};

/// Uppercase hex of `H(data)` with the chosen algorithm.
fn hash_upper(alg: HashAlg, data: &[u8]) -> String {
    use sha1::Digest as _;
    match alg {
        HashAlg::Sha1 => hex::encode_upper(Sha1::digest(data)),
        HashAlg::Sha256 => hex::encode_upper(Sha256::digest(data)),
    }
}

/// Lowercase hex of `HMAC_alg(key, msg)`.
fn hmac_lower(alg: HashAlg, key: &[u8], msg: &[u8]) -> Result<String, AuthError> {
    let invalid = |e: hmac::digest::InvalidLength| AuthError::InvalidKey(e.to_string());
    let out = match alg {
        HashAlg::Sha1 => {
            let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(key).map_err(invalid)?;
            mac.update(msg);
            hex::encode(mac.finalize().into_bytes())
        }
        HashAlg::Sha256 => {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(invalid)?;
            mac.update(msg);
            hex::encode(mac.finalize().into_bytes())
        }
    };
    Ok(out)
}
fn decode_key(ks: &KeyAndSalt) -> Result<Vec<u8>, AuthError> {
    hex::decode(ks.key.expose()).map_err(|_| AuthError::InvalidHex("key"))
}

/// Hash for a password login (`getjwt`/`gettoken`).
///
/// `pwHash = UPPER(H(password ":" salt))`, then
/// `HMAC(key, user ":" pwHash)`.
pub fn credential_hash(user: &str, password: &str, ks: &KeyAndSalt) -> Result<String, AuthError> {
    let pw_hash = hash_upper(ks.hash_alg, format!("{password}:{}", ks.salt).as_bytes());
    let msg = format!("{user}:{pw_hash}");
    hmac_lower(ks.hash_alg, &decode_key(ks)?, msg.as_bytes())
}

/// Hash of a token, for `authwithtoken` and `refreshjwt` (`checktoken` takes the plain token).
///
/// `HMAC(key, token)`, with the key from `getkey2`.
pub fn token_hash(token: &str, ks: &KeyAndSalt) -> Result<String, AuthError> {
    hmac_lower(ks.hash_alg, &decode_key(ks)?, token.as_bytes())
}

/// Hash for a secured command (visualization password).
///
/// `visuHash = UPPER(H(code ":" salt))`, then `HMAC(visualKey, visuHash)`.
/// `vis` is the key and salt from `getvisusalt`, not the session key.
pub fn visual_hash(code: &str, vis: &KeyAndSalt) -> Result<String, AuthError> {
    let inner = hash_upper(vis.hash_alg, format!("{code}:{}", vis.salt).as_bytes());
    hmac_lower(vis.hash_alg, &decode_key(vis)?, inner.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::super::Secret;
    use super::*;

    #[test]
    fn hash_upper_is_uppercase_hex() {
        let h = hash_upper(HashAlg::Sha1, b"abc");
        assert_eq!(h, "A9993E364706816ABA3E25717850C26C9CD0D89D");
    }

    #[test]
    fn hmac_lower_is_lowercase_hex() {
        // RFC 2202 test case 2: HMAC-SHA1("Jefe", "what do ya want for nothing?")
        let h = hmac_lower(HashAlg::Sha1, b"Jefe", b"what do ya want for nothing?").unwrap();
        assert_eq!(h, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    #[test]
    fn bad_hex_key_is_error() {
        let ks = KeyAndSalt {
            key: Secret::new("zz"),
            salt: "s".into(),
            hash_alg: HashAlg::Sha1,
        };
        assert_eq!(token_hash("t", &ks), Err(AuthError::InvalidHex("key")));
    }
}
