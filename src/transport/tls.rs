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
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self {
            verify: true,
            extra_root_pem: None,
        }
    }
}

impl fmt::Debug for TlsOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsOptions")
            .field("verify", &self.verify)
            .field("extra_root", &self.extra_root_pem.as_ref().map(|_| "<pem>"))
            .finish()
    }
}

/// Build a rustls client configuration from the options.
pub fn client_config(opts: &TlsOptions) -> Result<Arc<ClientConfig>, TransportError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Tls(format!("protocol versions: {e}")))?;

    let config = if opts.verify {
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
        };
        assert!(root_store(&opts).is_err());
    }

    #[test]
    fn client_config_builds_with_and_without_verification() {
        assert!(client_config(&TlsOptions::default()).is_ok());
        assert!(
            client_config(&TlsOptions {
                verify: false,
                extra_root_pem: None
            })
            .is_ok()
        );
    }
}
