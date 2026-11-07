//! Authentication primitives: hashing, key exchange, command encryption and token
//! logic. No I/O, no async. Clock and randomness are injected by the caller.

pub mod commands;
pub mod enc;
#[cfg(test)]
mod enc_kat;
pub mod hash;
pub mod keyexchange;
pub mod reply;
pub mod store;
pub mod token;

use std::fmt;

/// A secret string (key, token, password). `Debug` never prints the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The secret value. Use only where the protocol needs it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Hash algorithm named by the Miniserver's `hashAlg` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-1 (`"SHA1"`).
    Sha1,
    /// SHA-256 (`"SHA256"`).
    Sha256,
}

impl HashAlg {
    /// Parse a `hashAlg` value. Unknown names are an error.
    pub fn parse(name: &str) -> Result<Self, AuthError> {
        match name {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            other => Err(AuthError::UnknownHashAlg(other.to_owned())),
        }
    }
}

/// A key (hex) and salt, as returned by `getkey2` or `getvisusalt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAndSalt {
    /// Hex-encoded HMAC key.
    pub key: Secret,
    /// Salt string.
    pub salt: String,
    /// Hash algorithm for both the inner hash and the HMAC.
    pub hash_alg: HashAlg,
}

/// Errors from the `auth` module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The Miniserver named a hash algorithm this crate does not implement.
    #[error("unknown hash algorithm '{0}'")]
    UnknownHashAlg(String),
    /// A hex field did not decode.
    #[error("invalid hex in {0}")]
    InvalidHex(&'static str),
    /// Key material is unusable (wrong length, bad encoding).
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    /// The Miniserver replied with a non-success code.
    #[error("rejected with code {code} ({class:?})")]
    Rejected { code: i64, class: reply::ReplyClass },
    /// A required field is missing from a reply.
    #[error("missing field '{0}' in reply")]
    MissingField(&'static str),
    /// A firmware version string could not be parsed.
    #[error("invalid firmware version '{0}'")]
    InvalidVersion(String),
    /// A token is empty, or its expiry is missing.
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// The certificate could not be read or has no RSA public key.
    #[error("cannot decrypt a reply: {0}")]
    Decrypt(&'static str),

    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),
}
