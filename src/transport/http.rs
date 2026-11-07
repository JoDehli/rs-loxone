//! HTTP bootstrap: `apiKey`, the structure file and the public key.
//!
//! Security: over `http://` the Basic-auth password is sent unencrypted on every request
//! . `session::plain_http_warning` warns about this at connect.
//! Use `https://` where the Miniserver supports it.
//!
//! These GETs run before the WebSocket opens. Requests use HTTP Basic auth, as the
//! Transient failures are retried with backoff.

use std::time::Duration;

use serde_json::Value;

use super::TransportError;
use super::retry::{Jitter, RandJitter, RetryPolicy, with_retry};
use super::tls::{TlsOptions, client_config, is_tls_error};
use super::url::Endpoint;
use crate::auth::Secret;
use crate::protocol::ll::LlResponse;
use crate::protocol::version::parse_version;

/// Path of the API key and version endpoint.
pub const API_KEY_PATH: &str = "/jdev/cfg/apiKey";
/// Path of the structure file.
pub const STRUCTURE_PATH: &str = "/data/LoxAPP3.json";
/// Path of the Miniserver certificate.
pub const PUBLIC_KEY_PATH: &str = "/jdev/sys/getPublicKey";
/// Per-request timeout (`TIMEOUT`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Redirects followed before giving up.
pub const MAX_REDIRECTS: usize = 10;

/// Settings for the bootstrap client.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// Where the Miniserver is.
    pub endpoint: Endpoint,
    /// User name for Basic auth.
    pub username: String,
    /// Password for Basic auth.
    pub password: Secret,
    /// TLS settings (used only for `https`).
    pub tls: TlsOptions,
    /// Retry settings.
    pub retry: RetryPolicy,
    /// Connect to this address instead of resolving the host. The host name is still
    /// used for SNI and certificate checks. This is how a CloudDNS hostname reaches
    /// a Miniserver on the local IP (see `tls::cloud_dns_host`).
    pub connect_addr: Option<std::net::SocketAddr>,
}

/// The `apiKey` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyInfo {
    /// Firmware version.
    pub version: [u32; 3],
    /// Miniserver MAC address, as sent.
    pub mac: String,
    /// `httpsStatus`: 1 TLS available, 2 certificate expired (Gen 2 only).
    pub https_status: Option<u8>,
    /// `local`: whether the Miniserver regards this connection as local.
    pub local: Option<bool>,
}

/// The structure file bytes and the URL they came from (after redirects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureFile {
    /// The file exactly as the Miniserver sent it.
    pub bytes: Vec<u8>,
    /// Final URL after redirects.
    pub final_url: String,
}

/// Client for the HTTP bootstrap.
#[derive(Debug, Clone)]
pub struct HttpBootstrap {
    base: String,
    client: reqwest::Client,
    username: String,
    password: Secret,
    retry: RetryPolicy,
}

impl HttpBootstrap {
    /// Build the client. Does not connect.
    pub fn new(cfg: BootstrapConfig) -> Result<Self, TransportError> {
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .use_preconfigured_tls((*client_config(&cfg.tls)?).clone());
        if let Some(addr) = cfg.connect_addr {
            builder = builder.resolve(&cfg.endpoint.host, addr);
        }
        let client = builder
            .build()
            .map_err(|e| TransportError::Tls(format!("client build: {e}")))?;
        Ok(Self {
            base: cfg.endpoint.http_base(),
            client,
            username: cfg.username,
            password: cfg.password,
            retry: cfg.retry,
        })
    }

    /// `GET /jdev/cfg/apiKey`: version, MAC, `httpsStatus` and `local`.
    pub async fn api_key(&self) -> Result<ApiKeyInfo, TransportError> {
        self.api_key_with(&mut RandJitter).await
    }

    /// `GET /data/LoxAPP3.json`: the structure file, unchanged.
    pub async fn structure_file(&self) -> Result<StructureFile, TransportError> {
        let (bytes, final_url) = self.get_with_retry(STRUCTURE_PATH, &mut RandJitter).await?;
        Ok(StructureFile { bytes, final_url })
    }

    /// `GET /jdev/sys/getPublicKey`: the Miniserver certificate as PEM text.
    pub async fn public_key_pem(&self) -> Result<String, TransportError> {
        let (body, _) = self
            .get_with_retry(PUBLIC_KEY_PATH, &mut RandJitter)
            .await?;
        let reply = parse_ll(&body)?;
        Ok(reply.value)
    }

    async fn api_key_with(&self, jitter: &mut impl Jitter) -> Result<ApiKeyInfo, TransportError> {
        let (body, _) = self.get_with_retry(API_KEY_PATH, jitter).await?;
        let reply = parse_ll(&body)?;
        // The Miniserver sends single-quoted JSON inside the value; the quotes are
        // replaced before parsing.
        let normalised = reply.value.replace('\'', "\"");
        let value: Value = serde_json::from_str(&normalised)
            .map_err(|e| TransportError::Protocol(format!("apiKey value: {e}")))?;
        let obj = value
            .as_object()
            .ok_or_else(|| TransportError::Protocol("apiKey value is not an object".into()))?;
        let version_text = obj
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| TransportError::Protocol("apiKey has no version".into()))?;
        let version =
            parse_version(version_text).map_err(|e| TransportError::Protocol(e.to_string()))?;
        let mac = obj
            .get("MAC")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let https_status = obj
            .get("httpsStatus")
            .and_then(Value::as_u64)
            .and_then(|v| u8::try_from(v).ok());
        let local = obj.get("local").and_then(Value::as_bool);
        Ok(ApiKeyInfo {
            version,
            mac,
            https_status,
            local,
        })
    }

    async fn get_with_retry(
        &self,
        path: &str,
        jitter: &mut impl Jitter,
    ) -> Result<(Vec<u8>, String), TransportError> {
        with_retry(self.retry, jitter, || self.get_once(path)).await
    }

    async fn get_once(&self, path: &str) -> Result<(Vec<u8>, String), TransportError> {
        let url = format!("{}{path}", self.base);
        let resp = self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(self.password.expose()))
            .send()
            .await
            .map_err(classify_reqwest)?;
        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        if status != 200 {
            return Err(TransportError::Http { status });
        }
        let body = resp.bytes().await.map_err(classify_reqwest)?;
        Ok((body.to_vec(), final_url))
    }
}

/// Parse an LL envelope from a bootstrap reply. A non-200 code inside the envelope
/// is an HTTP-style error.
fn parse_ll(body: &[u8]) -> Result<LlResponse, TransportError> {
    let reply = LlResponse::parse(body).map_err(|e| TransportError::Protocol(e.to_string()))?;
    if reply.code != 200 {
        return Err(match u16::try_from(reply.code) {
            Ok(status) if (400..600).contains(&status) => TransportError::Http { status },
            _ => TransportError::Protocol(format!("LL code {}", reply.code)),
        });
    }
    Ok(reply)
}

/// Map a reqwest error to a transport error. TLS failures are not retried.
fn classify_reqwest(err: reqwest::Error) -> TransportError {
    if is_tls_error(&err) {
        return TransportError::Tls(err.to_string());
    }
    if err.is_timeout() {
        return TransportError::Timeout(err.to_string());
    }
    if let Some(status) = err.status() {
        return TransportError::Http {
            status: status.as_u16(),
        };
    }
    TransportError::Unreachable(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ll_maps_http_style_codes() {
        let body = br#"{"LL": {"control": "c", "code": 503, "value": ""}}"#;
        assert_eq!(
            parse_ll(body).unwrap_err(),
            TransportError::Http { status: 503 }
        );
    }

    #[test]
    fn parse_ll_other_codes_are_protocol_errors() {
        let body = br#"{"LL": {"control": "c", "code": 4003, "value": ""}}"#;
        assert!(matches!(parse_ll(body), Err(TransportError::Protocol(_))));
    }

    #[test]
    fn new_builds_without_connecting() {
        let cfg = BootstrapConfig {
            endpoint: Endpoint::parse("http://127.0.0.1:1").unwrap(),
            username: "admin".into(),
            password: Secret::new("pw"),
            tls: TlsOptions::default(),
            retry: RetryPolicy::default(),
            connect_addr: None,
        };
        assert!(HttpBootstrap::new(cfg).is_ok());
    }
}
