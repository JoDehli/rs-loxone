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
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use super::AuthError;
use super::keyexchange::{AES_KEY_LEN, IV_LEN, SessionKey};

const AES_BLOCK: usize = 16;

/// As Python's `urllib.parse.quote(cipher)` with its default `safe="/"`: `/` stays as it
/// is, `+` and `=` in the base64 output are percent-encoded.
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

/// Decrypts the replies to encrypted commands: `jdev/sys/enc/<base64>` controls.
/// Holds only the connection's key and IV, so it can be shared with the reader without
/// touching the salt chain.
#[derive(Clone)]
pub struct ControlDecrypter {
    aes_key: [u8; AES_KEY_LEN],
    iv: [u8; IV_LEN],
}

impl std::fmt::Debug for ControlDecrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlDecrypter")
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl ControlDecrypter {
    /// Turn a reply control into the plain control text.
    ///
    /// The reply is base64 and not percent-encoded. The plaintext is AES-256-CBC with PKCS#7
    /// padding and may end with NUL bytes. It may start with `salt/<hex>/`, which is removed.
    pub fn reveal(&self, control: &str) -> Result<String, AuthError> {
        let body = control
            .strip_prefix("jdev/sys/enc/")
            .ok_or(AuthError::Decrypt("not an encrypted control"))?;
        let mut buf = STANDARD
            .decode(body)
            .map_err(|_| AuthError::Decrypt("base64"))?;
        if buf.is_empty() || !buf.len().is_multiple_of(AES_BLOCK) {
            return Err(AuthError::Decrypt("block length"));
        }
        let dec = cbc::Decryptor::<Aes256>::new(&self.aes_key.into(), &self.iv.into());
        let len = buf.len();
        let plain = dec
            .decrypt_padded::<NoPadding>(&mut buf[..len])
            .map_err(|_| AuthError::Decrypt("padding"))?;
        let plain = strip_padding(plain);
        let text = std::str::from_utf8(plain).map_err(|_| AuthError::Decrypt("utf-8"))?;
        let text = text.trim_end_matches('\0');
        Ok(strip_salt(text).to_owned())
    }
}

/// Remove the padding from a decrypted reply. Accepts both PKCS#7 (what this crate
/// sends and what the reference client expects) and ZeroBytePadding (zeros to the
/// block boundary, as the Loxone protocol table lists). PKCS#7 is tried first: a valid
/// tail whose value is `n` (1..=16) repeated `n` times is removed; otherwise trailing
/// zero bytes are removed.
fn strip_padding(plain: &[u8]) -> &[u8] {
    if let Some(&n) = plain.last() {
        let n = n as usize;
        if (1..=AES_BLOCK).contains(&n)
            && n <= plain.len()
            && plain[plain.len() - n..].iter().all(|&b| b as usize == n)
        {
            return &plain[..plain.len() - n];
        }
    }
    let end = plain.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &plain[..end]
}

/// Remove the salt prefix from a decrypted control: `salt/<hex>/` or
/// `nextSalt/<old>/<new>/`, as the device sends them.
fn strip_salt(text: &str) -> &str {
    if let Some(rest) = text.strip_prefix("nextSalt/") {
        let mut parts = rest.splitn(3, '/');
        let _old = parts.next();
        let _new = parts.next();
        if let Some(command) = parts.next() {
            return command;
        }
    }
    match text
        .strip_prefix("salt/")
        .and_then(|rest| rest.split_once('/'))
    {
        Some((_, command)) => command,
        None => text,
    }
}

impl EncCipher {
    /// The decrypter for this connection's replies.
    pub fn decrypter(&self) -> ControlDecrypter {
        ControlDecrypter {
            aes_key: self.aes_key,
            iv: self.iv,
        }
    }
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
    fn output_is_percent_encoded_base64_like_python() {
        let s = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        let mut c = EncCipher::new(&s, "aa");
        let out = c.encrypt_command("jdev/sps/io/x/on", "bb");
        let payload = out.strip_prefix("jdev/sys/enc/").unwrap();
        // As Python's quote(): '+' and '=' are encoded, '/' stays as it is.
        assert!(!payload.contains('+') && !payload.contains('='));
    }
}

#[cfg(test)]
mod reveal_tests {
    use super::*;

    fn cipher() -> EncCipher {
        EncCipher {
            aes_key: [7u8; AES_KEY_LEN],
            iv: [9u8; IV_LEN],
            current_salt: "00".into(),
            sent_any: false,
        }
    }

    fn reply(cipher: &EncCipher, plain: &str) -> String {
        let mut bytes = plain.as_bytes().to_vec();
        bytes.push(0);
        format!(
            "jdev/sys/enc/{}",
            STANDARD.encode(cipher.encrypt_plain(&bytes))
        )
    }

    #[test]
    fn reveals_control_and_removes_salt_and_nul() {
        let c = cipher();
        let d = c.decrypter();
        let control = reply(&c, "salt/0a0b/jdev/sps/io/uuid/on");
        assert_eq!(d.reveal(&control).unwrap(), "jdev/sps/io/uuid/on");
    }

    #[test]
    fn reveals_control_without_salt() {
        let c = cipher();
        let control = reply(&c, "refreshjwt/abc/admin");
        assert_eq!(
            c.decrypter().reveal(&control).unwrap(),
            "refreshjwt/abc/admin"
        );
    }

    #[test]
    fn reveals_control_after_next_salt_prefix() {
        let c = cipher();
        let control = reply(&c, "nextSalt/0a0b/0c0d/jdev/sps/checkuservisupwd");
        assert_eq!(
            c.decrypter().reveal(&control).unwrap(),
            "jdev/sps/checkuservisupwd"
        );
    }

    /// Same as `reply`, but padded with zero bytes to the block boundary.
    fn reply_zero_padded(cipher: &EncCipher, plain: &str) -> String {
        let mut bytes = plain.as_bytes().to_vec();
        bytes.push(0);
        while !bytes.len().is_multiple_of(AES_BLOCK) {
            bytes.push(0);
        }
        let mut buf = bytes;
        let enc = cbc::Encryptor::<aes::Aes256>::new(&cipher.aes_key.into(), &cipher.iv.into());
        let len = buf.len();
        enc.encrypt_padded::<NoPadding>(&mut buf, len).unwrap();
        format!("jdev/sys/enc/{}", STANDARD.encode(buf))
    }

    #[test]
    fn reveals_zero_padded_reply() {
        let c = cipher();
        // 16 bytes exactly, so the zero padding is a full extra block of zeros.
        for plain in ["refreshjwt/abc/admin", "jdev/sps/io/uuid/on", "x"] {
            let control = reply_zero_padded(&c, plain);
            assert_eq!(c.decrypter().reveal(&control).unwrap(), plain);
        }
    }

    #[test]
    fn reveals_zero_padded_reply_after_salt() {
        let c = cipher();
        let control = reply_zero_padded(&c, "salt/0a0b/jdev/sps/io/uuid/on");
        assert_eq!(
            c.decrypter().reveal(&control).unwrap(),
            "jdev/sps/io/uuid/on"
        );
    }

    #[test]
    fn rejects_plain_control_and_bad_base64() {
        let d = cipher().decrypter();
        assert!(d.reveal("jdev/sys/getkey").is_err());
        assert!(d.reveal("jdev/sys/enc/!!!").is_err());
    }
}
