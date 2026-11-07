//! RSA session key: a fresh AES-256 key and IV, encrypted to the Miniserver's
//! public key (taken from its X.509 certificate).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::CryptoRngCore;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use super::AuthError;

/// AES-256 key length in bytes.
pub const AES_KEY_LEN: usize = 32;
/// AES CBC IV length in bytes.
pub const IV_LEN: usize = 16;

/// The per-connection AES key and IV, and the `keyexchange` command that carries
/// them to the Miniserver.
#[derive(Clone)]
pub struct SessionKey {
    aes_key: [u8; AES_KEY_LEN],
    iv: [u8; IV_LEN],
    command: String,
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKey")
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl SessionKey {
    /// Generate a session key and encrypt it to the public key in `cert_pem`.
    ///
    /// `cert_pem` is the Miniserver's certificate (`-----BEGIN CERTIFICATE-----`).
    /// The RNG is passed in so callers choose the source; the production path uses
    /// the OS RNG.
    pub fn generate(cert_pem: &str, rng: &mut impl CryptoRngCore) -> Result<Self, AuthError> {
        let public_key = public_key_from_certificate_pem(cert_pem)?;

        let mut aes_key = [0u8; AES_KEY_LEN];
        let mut iv = [0u8; IV_LEN];
        rng.fill_bytes(&mut aes_key);
        rng.fill_bytes(&mut iv);

        let plaintext = format!("{}:{}", hex::encode(aes_key), hex::encode(iv));
        let encrypted = public_key
            .encrypt(rng, Pkcs1v15Encrypt, plaintext.as_bytes())
            .map_err(|e| AuthError::InvalidKey(format!("rsa encrypt: {e}")))?;
        let command = format!("jdev/sys/keyexchange/{}", STANDARD.encode(encrypted));

        Ok(Self {
            aes_key,
            iv,
            command,
        })
    }

    /// Build a session key from known parts. Test-only.
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(aes_key: [u8; AES_KEY_LEN], iv: [u8; IV_LEN]) -> Self {
        Self {
            aes_key,
            iv,
            command: String::new(),
        }
    }

    /// The `jdev/sys/keyexchange/<base64>` command to send in plain text.
    pub fn keyexchange_command(&self) -> &str {
        &self.command
    }

    /// The AES-256 key. Crate-internal: used only for command encryption.
    pub(crate) fn aes_key(&self) -> &[u8; AES_KEY_LEN] {
        &self.aes_key
    }

    /// The AES IV. Crate-internal: used only for command encryption.
    pub(crate) fn iv(&self) -> &[u8; IV_LEN] {
        &self.iv
    }
}

/// Read the RSA public key from a PEM certificate.
///
/// Real Miniservers send a bare SubjectPublicKeyInfo under the `CERTIFICATE` label,
/// not a full X.509 certificate. The header is swapped for `PUBLIC KEY` and the body is
/// imported as a key. Both forms are accepted.
pub fn public_key_from_certificate_pem(cert_pem: &str) -> Result<RsaPublicKey, AuthError> {
    let body = pem_body(cert_pem, "CERTIFICATE").or_else(|_| pem_body(cert_pem, "PUBLIC KEY"))?;
    if let Ok(cert) = Certificate::from_der(&body) {
        let spki = cert
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|e| AuthError::InvalidCertificate(format!("spki: {e}")))?;
        return RsaPublicKey::from_public_key_der(&spki)
            .map_err(|e| AuthError::InvalidCertificate(format!("not an RSA key: {e}")));
    }
    RsaPublicKey::from_public_key_der(&body).map_err(|e| {
        AuthError::InvalidCertificate(format!("neither a certificate nor an RSA key: {e}"))
    })
}

/// Decode the base64 body of a PEM block with the given label.
fn pem_body(pem: &str, label: &str) -> Result<Vec<u8>, AuthError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = pem
        .split_once(&begin)
        .and_then(|(_, rest)| rest.split_once(&end))
        .map(|(body, _)| body)
        .ok_or_else(|| AuthError::InvalidCertificate(format!("no {label} PEM block")))?;
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    STANDARD
        .decode(compact)
        .map_err(|e| AuthError::InvalidCertificate(format!("pem base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    const CERT_PEM: &str = include_str!("../../tests/fixtures/test_cert.pem");
    const KEY_PEM: &str = include_str!("../../tests/fixtures/test_key.pem");
    /// Public key as a Gen 1 Miniserver sends it (public data, not a secret).
    const CERT_PEM_SPKI_BODY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/qM1R4G/tIxKS26bveGen16uxY6b5gACwrWZJlWdGfnzd6xv1Onoa4x35oBf5ArVTGrzgYDBkCdo5D642Tvs0ORGst14/SKWf5UdZSYqgKGPswN35qkCyZhiO/EhXNt5rDsqs8Wt2DyPWTMcKA5PAw4xepKAC4jfWb+vrqUo2EwIDAQAB";

    #[test]
    fn keyexchange_command_has_prefix_and_base64() {
        let sk = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        let cmd = sk.keyexchange_command();
        let payload = cmd.strip_prefix("jdev/sys/keyexchange/").expect("prefix");
        let decoded = STANDARD.decode(payload).expect("standard base64");
        assert_eq!(decoded.len(), 256, "2048-bit RSA ciphertext");
    }

    #[test]
    fn payload_decrypts_to_key_and_iv() {
        let sk = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        let payload = sk
            .keyexchange_command()
            .strip_prefix("jdev/sys/keyexchange/")
            .unwrap();
        let ciphertext = STANDARD.decode(payload).unwrap();
        let private = RsaPrivateKey::from_pkcs8_pem(KEY_PEM).unwrap();
        let plain = private.decrypt(Pkcs1v15Encrypt, &ciphertext).unwrap();
        let expected = format!("{}:{}", hex::encode(sk.aes_key()), hex::encode(sk.iv()));
        assert_eq!(plain, expected.as_bytes());
    }

    #[test]
    fn two_sessions_use_different_keys() {
        let a = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        let b = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        assert_ne!(a.aes_key(), b.aes_key());
        assert_ne!(a.keyexchange_command(), b.keyexchange_command());
    }

    #[test]
    fn bare_spki_under_certificate_label_is_accepted() {
        // Real device format: SubjectPublicKeyInfo under the CERTIFICATE label.
        let spki_pem = format!(
            "-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----",
            CERT_PEM_SPKI_BODY
        );
        assert!(SessionKey::generate(&spki_pem, &mut OsRng).is_ok());
    }

    #[test]
    fn non_key_pem_is_rejected() {
        let bad = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        assert!(matches!(
            SessionKey::generate(bad, &mut OsRng),
            Err(AuthError::InvalidCertificate(_))
        ));
    }

    #[test]
    fn debug_does_not_print_keys() {
        let sk = SessionKey::generate(CERT_PEM, &mut OsRng).unwrap();
        let shown = format!("{sk:?}");
        assert!(!shown.contains(&hex::encode(sk.aes_key())));
        assert!(shown.contains("redacted"));
    }
}
