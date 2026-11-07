//! Network transport: HTTP bootstrap, WebSocket, TLS, keepalive.
//!
//! This is the only module that touches sockets. `protocol` and `auth` stay pure.

pub mod http;
pub mod keepalive;
pub mod retry;
pub mod tls;
pub mod url;
pub mod ws;

use std::fmt;

/// Errors from the transport layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The host or URL could not be parsed.
    InvalidUrl(String),
    /// The host could not be reached (refused, DNS, socket error). Retryable.
    Unreachable(String),
    /// A connect or request timed out. Retryable.
    Timeout(String),
    /// The HTTP status was not 200 (503 is retryable).
    Http { status: u16 },
    /// No inbound frame arrived within the watchdog limit. Reconnect.
    ConnectionLost { reason: String },
    /// The WebSocket closed; `code` is the close code, if one was sent.
    Closed { code: Option<u16>, reason: String },
    /// TLS setup or certificate verification failed.
    Tls(String),
    /// A response was not what the protocol expects (bad envelope, bad JSON).
    Protocol(String),
}

impl TransportError {
    /// True if reconnecting or retrying later can succeed.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Unreachable(_)
                | Self::Timeout(_)
                | Self::ConnectionLost { .. }
                | Self::Http { status: 503 }
        )
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(m) => write!(f, "invalid url: {m}"),
            Self::Unreachable(m) => write!(f, "unreachable: {m}"),
            Self::Timeout(m) => write!(f, "timeout: {m}"),
            Self::Http { status } => write!(f, "http status {status}"),
            Self::ConnectionLost { reason } => write!(f, "connection lost: {reason}"),
            Self::Closed { code, reason } => match code {
                Some(c) => write!(f, "closed with code {c}: {reason}"),
                None => write!(f, "closed: {reason}"),
            },
            Self::Tls(m) => write!(f, "tls: {m}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
        }
    }
}

impl std::error::Error for TransportError {}
