//! Command encryption for the `jdev/sys/enc/` wrapper (AES-256-CBC).
//!
//! Plaintext is `salt/<salt>/<cmd>\0` for the first command, and
//! `nextSalt/<old>/<new>/<cmd>\0` for every later command (the PDF's rule of
//! updating the salt on every command). The plaintext is PKCS#7-padded, encrypted
//! with the session AES key and the fixed session IV, base64-encoded, and
//! percent-encoded (URI component) into the command path.

use aes::Aes256;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use super::keyexchange::{AES_KEY_LEN, IV_LEN, SessionKey};

const AES_BLOCK: usize = 16;

/// Everything except RFC 3986 unreserved characters is encoded, so `/`, `+` and
/// `=` in the base64 output are percent-encoded.
const URI_COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Encrypts commands for one connection. The AES key and IV are fixed for the
/// connection; the salt changes on every command.
#[derive(Clone)]
pub struct EncCipher {
    aes_key: [u8; AES_KEY_LEN],
    iv: [u8; IV_LEN],
    current_salt: String,
    sent_any: bool,
}

impl std::fmt::Debug for EncCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncCipher")
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl EncCipher {
    /// Create a cipher for a session. `initial_salt` is the salt used for the first
    /// command (hex, 16 random bytes in production).
    pub fn new(session: &SessionKey, initial_salt: impl Into<String>) -> Self {
        Self {
            aes_key: *session.aes_key(),
            iv: *session.iv(),
            current_salt: initial_salt.into(),
            sent_any: false,
        }
    }

    /// Encrypt `cmd` and return the `jdev/sys/enc/<encoded>` command.
    ///
    /// `next_salt` is used from the second command on; the first command ignores
    /// it and uses the initial salt. Each call with a salt makes it the current one.
    pub fn encrypt_command(&mut self, cmd: &str, next_salt: &str) -> String {
        let plain = if self.sent_any {
            let old = std::mem::replace(&mut self.current_salt, next_salt.to_owned());
            format!("nextSalt/{old}/{next_salt}/{cmd}\0")
        } else {
            format!("salt/{}/{cmd}\0", self.current_salt)
        };
        self.sent_any = true;
        let cipher = STANDARD.encode(self.encrypt_plain(plain.as_bytes()));
        format!(
            "jdev/sys/enc/{}",
            utf8_percent_encode(&cipher, URI_COMPONENT)
        )
    }

    /// Encrypt raw bytes with the session key and IV (PKCS#7 padding).
    pub(super) fn encrypt_plain(&self, plain: &[u8]) -> Vec<u8> {
        let pad = AES_BLOCK - plain.len() % AES_BLOCK;
        let mut buf = Vec::with_capacity(plain.len() + pad);
        buf.extend_from_slice(plain);
        buf.extend(std::iter::repeat_n(pad as u8, pad));
        let enc = cbc::Encryptor::<Aes256>::new(&self.aes_key.into(), &self.iv.into());
        let len = buf.len();
        enc.encrypt_padded::<NoPadding>(&mut buf, len)
            .expect("buffer is a whole number of blocks");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const CERT_PEM: &str = include_str!("../../tests/fixtures/test_cert.pem");

    #[test]
    fn plaintext_is_padded_to_full_blocks() {
        let s = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        let c = EncCipher::new(&s, "00");
        assert_eq!(c.encrypt_plain(b"").len(), 16);
        assert_eq!(c.encrypt_plain(&[0u8; 15]).len(), 16);
        assert_eq!(c.encrypt_plain(&[0u8; 16]).len(), 32);
    }

    #[test]
    fn first_command_uses_salt_prefix_then_next_salt() {
        let s = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        let mut c = EncCipher::new(&s, "aa");
        let first = c.encrypt_command("jdev/sps/io/x/on", "bb");
        assert!(first.starts_with("jdev/sys/enc/"));
        assert_eq!(c.current_salt, "aa", "first command keeps the initial salt");
        let _second = c.encrypt_command("jdev/sps/io/x/off", "cc");
        assert_eq!(c.current_salt, "cc", "salt rotates on the second command");
    }

    #[test]
    fn output_is_percent_encoded_base64() {
        let s = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        let mut c = EncCipher::new(&s, "aa");
        let out = c.encrypt_command("jdev/sps/io/x/on", "bb");
        let payload = out.strip_prefix("jdev/sys/enc/").unwrap();
        assert!(!payload.contains('/') && !payload.contains('+') && !payload.contains('='));
    }
}
