//! TLS for Gen 2 Miniservers (`wss://`, `https://`).
//!
//! Trust roots: the public CA bundle (`webpki-roots`), plus an optional extra root
//! (`ca_file`) for the Loxone root or a custom certificate. Verification is on by
//! default; `verify = false` turns it off.
//!
//! Gen 1 Miniservers do not use TLS; the plain `ws://` path never builds this config.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use super::TransportError;
use super::url::Scheme;

/// Suffix of the CloudDNS hostname used for local TLS.
pub const CLOUDDNS_SUFFIX: &str = "dyndns.loxonecloud.com";

/// TLS settings chosen by the caller.
#[derive(Clone, PartialEq, Eq)]
pub struct TlsOptions {
    /// Verify the server certificate (default true).
    pub verify: bool,
    /// Extra trust root in PEM form, added to the public CAs.
    pub extra_root_pem: Option<Vec<u8>>,
    /// SHA-256 of the server's certificate (DER). If set, only that certificate is accepted,
    /// and the CA chain and the host name are not checked. Takes precedence over `verify`.
    pub pinned_cert_sha256: Option<[u8; 32]>,
    /// Trust on first use: the first certificate seen for a host name is remembered for the
    /// life of the process, and a different one is refused afterwards. Nothing is stored on
    /// disk, so a restart starts again with the first contact. Ignored if a pin is set.
    pub trust_on_first_use: bool,
    /// File that keeps the remembered certificates between runs (JSON: host name to hex
    /// SHA-256). Only used with `trust_on_first_use`. Without it, memory is per process.
    pub first_use_file: Option<std::path::PathBuf>,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            verify: true,
            extra_root_pem: None,
            pinned_cert_sha256: None,
            trust_on_first_use: false,
            first_use_file: None,
        }
    }
}

impl fmt::Debug for TlsOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsOptions")
            .field("verify", &self.verify)
            .field("extra_root", &self.extra_root_pem.as_ref().map(|_| "<pem>"))
            .field("pinned", &self.pinned_cert_sha256.is_some())
            .field("trust_on_first_use", &self.trust_on_first_use)
            .field("first_use_file", &self.first_use_file)
            .finish()
    }
}

/// Build a rustls client configuration from the options.
pub fn client_config(opts: &TlsOptions) -> Result<Arc<ClientConfig>, TransportError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Tls(format!("protocol versions: {e}")))?;

    let config = if opts.pinned_cert_sha256.is_none() && opts.trust_on_first_use {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FirstUseVerify {
                provider,
                file: opts.first_use_file.clone(),
            }))
            .with_no_client_auth()
    } else if let Some(pin) = opts.pinned_cert_sha256 {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerify { provider, pin }))
            .with_no_client_auth()
    } else if opts.verify {
        let roots = root_store(opts)?;
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify { provider }))
            .with_no_client_auth()
    };
    Ok(Arc::new(config))
}

/// The trust store: public CAs plus the optional extra root.
pub fn root_store(opts: &TlsOptions) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = &opts.extra_root_pem {
        let mut added = 0;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|e| TransportError::Tls(format!("extra root pem: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| TransportError::Tls(format!("extra root: {e}")))?;
            added += 1;
        }
        if added == 0 {
            return Err(TransportError::Tls(
                "extra root contains no certificate".into(),
            ));
        }
    }
    Ok(roots)
}

/// The scheme to use for a Miniserver from its `httpsStatus` value.
///
/// `1` means TLS is available. `2` means a certificate exists but has expired:
/// this is returned as an error so the caller decides, rather than silently
/// falling back to plain text. Any other value (or none) means plain HTTP.
pub fn scheme_from_https_status(status: Option<u8>) -> Result<Scheme, TransportError> {
    match status {
        Some(1) => Ok(Scheme::Https),
        Some(2) => Err(TransportError::Tls(
            "miniserver certificate has expired (httpsStatus 2)".into(),
        )),
        _ => Ok(Scheme::Http),
    }
}

/// Hostname for local TLS through CloudDNS.
///
/// Takes `IPHTTPS` (`ip:port`, or `[ipv6]:port`) and the Miniserver serial number,
/// and returns `{ip-with-minuses}.{snr}.dyndns.loxonecloud.com:{port}`. The PDF
/// describes this construction.
pub fn cloud_dns_host(iphttps: &str, snr: &str) -> Result<String, TransportError> {
    let (ip, port) = split_ip_port(iphttps)
        .ok_or_else(|| TransportError::InvalidUrl(format!("bad IPHTTPS '{iphttps}'")))?;
    let cleaned = if ip.contains(':') {
        ip.replace(':', "-")
    } else {
        ip.replace('.', "-")
    };
    Ok(format!("{cleaned}.{snr}.{CLOUDDNS_SUFFIX}:{port}"))
}

fn split_ip_port(s: &str) -> Option<(&str, u16)> {
    let (ip, port) = if let Some(rest) = s.strip_prefix('[') {
        let (ip, after) = rest.split_once(']')?;
        (ip, after.strip_prefix(':')?)
    } else {
        s.rsplit_once(':')?
    };
    let port: u16 = port.parse().ok()?;
    if ip.is_empty() {
        return None;
    }
    Some((ip, port))
}

/// Accepts only the certificate whose DER SHA-256 equals `pin`. The chain and the host name
/// are not checked; the signature of the handshake is still verified.
#[derive(Debug)]
struct PinVerify {
    provider: Arc<CryptoProvider>,
    pin: [u8; 32],
}

impl ServerCertVerifier for PinVerify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if digest == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned fingerprint".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Certificates remembered by trust on first use: (server name, SHA-256 of the DER).
static FIRST_USE_PINS: std::sync::Mutex<Vec<(String, [u8; 32])>> =
    std::sync::Mutex::new(Vec::new());

/// Trust on first use. The first certificate for a server name is remembered in
/// `FIRST_USE_PINS`; later connections to that name must present the same certificate.
#[derive(Debug)]
struct FirstUseVerify {
    provider: Arc<CryptoProvider>,
    file: Option<std::path::PathBuf>,
}

/// Read the remembered certificates from `path` and add the names that memory does not
/// have yet. A missing or unreadable file adds nothing.
fn merge_first_use_file(pins: &mut Vec<(String, [u8; 32])>, path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&text)
    else {
        return;
    };
    for (name, value) in map {
        let Some(bytes) = value.as_str().and_then(|h| hex::decode(h).ok()) else {
            continue;
        };
        let Ok(digest) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            continue;
        };
        if !pins.iter().any(|(n, _)| *n == name) {
            pins.push((name, digest));
        }
    }
}

/// Write all remembered certificates to `path`, atomically and private.
fn save_first_use_file(pins: &[(String, [u8; 32])], path: &std::path::Path) -> std::io::Result<()> {
    let map: serde_json::Map<String, serde_json::Value> = pins
        .iter()
        .map(|(name, digest)| (name.clone(), serde_json::Value::String(hex::encode(digest))))
        .collect();
    let json = serde_json::to_vec_pretty(&serde_json::Value::Object(map))
        .map_err(std::io::Error::other)?;
    crate::auth::store::write_private_atomic(path, &json)
}

impl ServerCertVerifier for FirstUseVerify {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        let name = server_name.to_str().to_string();
        let mut pins = FIRST_USE_PINS
            .lock()
            .map_err(|_| rustls::Error::General("trust store poisoned".into()))?;
        if let Some(path) = &self.file {
            merge_first_use_file(&mut pins, path);
        }
        match pins.iter().find(|(n, _)| *n == name) {
            None => {
                pins.push((name, digest));
                if let Some(path) = &self.file {
                    // A write failure only means the pin is not kept across restarts.
                    let _ = save_first_use_file(&pins, path);
                }
                Ok(ServerCertVerified::assertion())
            }
            Some((_, known)) if *known == digest => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General(
                "server certificate changed since it was first seen".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accepts any certificate. Used only when the caller sets `verify = false`.
#[derive(Debug)]
struct NoVerify {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// True if an error in the chain is a TLS failure. A rustls error can be wrapped in
/// several `io::Error` layers (hyper and tungstenite both do this), so the search goes
/// into each wrapper. Matches by type, not text, so a URL containing "tls" does not count.
pub fn is_tls_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if e.is::<rustls::Error>() {
            return true;
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && let Some(inner) = io.get_ref()
            && is_tls_error(inner)
        {
            return true;
        }
        current = e.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_error_detected_by_type() {
        let direct = rustls::Error::General("bad".into());
        assert!(is_tls_error(&direct));
        let wrapped = std::io::Error::other(rustls::Error::General("bad".into()));
        assert!(is_tls_error(&wrapped));
        let nested = std::io::Error::other(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::General("bad".into()),
        ));
        assert!(is_tls_error(&nested));
    }

    #[test]
    fn text_containing_tls_is_not_a_tls_error() {
        let plain = std::io::Error::other("connect to tls-box.local failed");
        assert!(!is_tls_error(&plain));
        let timeout = std::io::Error::new(std::io::ErrorKind::TimedOut, "certificate-free url");
        assert!(!is_tls_error(&timeout));
    }

    #[test]
    fn cloud_dns_host_ipv4() {
        assert_eq!(
            cloud_dns_host("10.0.0.5:443", "100-00-00-01").unwrap(),
            "10-0-0-5.100-00-00-01.dyndns.loxonecloud.com:443"
        );
    }

    #[test]
    fn cloud_dns_host_ipv6_strips_brackets() {
        assert_eq!(
            cloud_dns_host("[2001:db8::1]:4523", "100-00-00-01").unwrap(),
            "2001-db8--1.100-00-00-01.dyndns.loxonecloud.com:4523"
        );
    }

    #[test]
    fn cloud_dns_host_rejects_bad_input() {
        assert!(cloud_dns_host("10.0.0.5", "x").is_err());
        assert!(cloud_dns_host("10.0.0.5:notaport", "x").is_err());
        assert!(cloud_dns_host(":443", "x").is_err());
    }

    #[test]
    fn https_status_selects_scheme() {
        assert_eq!(scheme_from_https_status(Some(1)).unwrap(), Scheme::Https);
        assert_eq!(scheme_from_https_status(None).unwrap(), Scheme::Http);
        assert_eq!(scheme_from_https_status(Some(0)).unwrap(), Scheme::Http);
        assert!(matches!(
            scheme_from_https_status(Some(2)),
            Err(TransportError::Tls(_))
        ));
    }

    #[test]
    fn default_trust_store_has_public_roots() {
        let roots = root_store(&TlsOptions::default()).unwrap();
        assert!(roots.len() > 50);
    }

    #[test]
    fn extra_root_without_certificate_is_error() {
        let opts = TlsOptions {
            verify: true,
            extra_root_pem: Some(b"junk".to_vec()),
            pinned_cert_sha256: None,
            trust_on_first_use: false,
            first_use_file: None,
        };
        assert!(root_store(&opts).is_err());
    }

    #[test]
    fn client_config_builds_with_and_without_verification() {
        assert!(client_config(&TlsOptions::default()).is_ok());
        assert!(
            client_config(&TlsOptions {
                verify: false,
                extra_root_pem: None,
                pinned_cert_sha256: None,
                trust_on_first_use: false,
                first_use_file: None,
            })
            .is_ok()
        );
    }
}
