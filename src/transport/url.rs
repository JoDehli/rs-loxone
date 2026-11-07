//! Host and URL handling.

use super::TransportError;

/// Path of the WebSocket endpoint.
pub const WS_PATH: &str = "/ws/rfc6455";

/// HTTP or HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plain HTTP (`ws` for the WebSocket).
    Http,
    /// HTTPS (`wss` for the WebSocket).
    Https,
}

impl Scheme {
    /// Default port for the scheme: 80 for HTTP, 443 for HTTPS.
    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

/// A parsed Miniserver endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Scheme to use for HTTP. The WebSocket scheme follows it.
    pub scheme: Scheme,
    /// Host name or IP address (no brackets for IPv6).
    pub host: String,
    /// Port, with the scheme default filled in.
    pub port: u16,
    /// Optional path prefix from the input (usually empty).
    pub path: String,
}

impl Endpoint {
    /// Parse `host`, `host:port`, `http://host[:port][/path]` or `https://…`.
    ///
    /// Without a scheme the endpoint is plain HTTP.
    pub fn parse(input: &str) -> Result<Self, TransportError> {
        let with_scheme = if input.contains("://") {
            input.to_owned()
        } else {
            format!("http://{input}")
        };
        let url = ::url::Url::parse(&with_scheme)
            .map_err(|e| TransportError::InvalidUrl(format!("{input}: {e}")))?;
        let scheme = match url.scheme() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            other => {
                return Err(TransportError::InvalidUrl(format!(
                    "unsupported scheme '{other}'"
                )));
            }
        };
        let host = url
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| TransportError::InvalidUrl(format!("no host in '{input}'")))?;
        // `url` keeps brackets around IPv6 literals; the protocol form has none.
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url.port().unwrap_or_else(|| scheme.default_port());
        let path = url.path().trim_end_matches('/').to_owned();
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    /// The HTTP base URL, for example `http://192.168.1.10` (default port omitted).
    pub fn http_base(&self) -> String {
        format!("{}://{}", self.http_scheme_name(), self.authority())
    }

    /// The WebSocket URL, for example `ws://192.168.1.10/ws/rfc6455`.
    ///
    /// Any path prefix from the input comes before `/ws/rfc6455`.
    pub fn ws_url(&self) -> String {
        format!(
            "{}://{}{}{}",
            self.ws_scheme_name(),
            self.authority(),
            self.path,
            WS_PATH
        )
    }

    /// `ws` for HTTP, `wss` for HTTPS.
    pub fn ws_scheme_name(&self) -> &'static str {
        match self.scheme {
            Scheme::Http => "ws",
            Scheme::Https => "wss",
        }
    }

    fn http_scheme_name(&self) -> &'static str {
        match self.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// `host[:port]`, with IPv6 hosts in brackets and the default port omitted.
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws(input: &str) -> String {
        Endpoint::parse(input).unwrap().ws_url()
    }

    // Expected values, fixed in advance.
    #[test]
    fn known_answers() {
        assert_eq!(ws("192.168.1.10"), "ws://192.168.1.10/ws/rfc6455");
        assert_eq!(ws("192.168.1.10:8080"), "ws://192.168.1.10:8080/ws/rfc6455");
        assert_eq!(ws("http://192.168.1.10"), "ws://192.168.1.10/ws/rfc6455");
        assert_eq!(ws("http://192.168.1.10:80"), "ws://192.168.1.10/ws/rfc6455");
        assert_eq!(
            ws("https://example.loxonecloud.com"),
            "wss://example.loxonecloud.com/ws/rfc6455"
        );
        assert_eq!(
            ws("https://example.loxonecloud.com:443"),
            "wss://example.loxonecloud.com/ws/rfc6455"
        );
        assert_eq!(
            ws("https://example.loxonecloud.com:4523"),
            "wss://example.loxonecloud.com:4523/ws/rfc6455"
        );
        assert_eq!(
            ws("ws-host.local:7777"),
            "ws://ws-host.local:7777/ws/rfc6455"
        );
        assert_eq!(ws("myhost/some/path"), "ws://myhost/some/path/ws/rfc6455");
    }

    #[test]
    fn http_base_omits_default_port() {
        assert_eq!(Endpoint::parse("h:80").unwrap().http_base(), "http://h");
        assert_eq!(
            Endpoint::parse("https://h:443").unwrap().http_base(),
            "https://h"
        );
        assert_eq!(
            Endpoint::parse("h:8080").unwrap().http_base(),
            "http://h:8080"
        );
    }

    #[test]
    fn scheme_drives_ws_scheme() {
        assert_eq!(Endpoint::parse("http://h").unwrap().ws_scheme_name(), "ws");
        assert_eq!(
            Endpoint::parse("https://h").unwrap().ws_scheme_name(),
            "wss"
        );
    }

    #[test]
    fn ipv6_literal_is_bracketed() {
        let e = Endpoint::parse("http://[fd00::1]:8080").unwrap();
        assert_eq!(e.host, "fd00::1");
        assert_eq!(e.ws_url(), "ws://[fd00::1]:8080/ws/rfc6455");
    }

    #[test]
    fn missing_host_is_error() {
        assert!(matches!(
            Endpoint::parse("http://"),
            Err(TransportError::InvalidUrl(_))
        ));
    }

    #[test]
    fn unsupported_scheme_is_error() {
        assert!(matches!(
            Endpoint::parse("ftp://h"),
            Err(TransportError::InvalidUrl(_))
        ));
    }
}
