//! WebSocket connection to the Miniserver (`ws://…/ws/rfc6455`, or `wss://` with TLS).
//!
//! The connection is split into a [`WsSender`] (single writer) and a
//! [`WsReceiver`] (reads frames and records inbound activity for the watchdog).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config};

use super::TransportError;
use super::tls::{TlsOptions, client_config, is_tls_error};
use super::url::{Endpoint, Scheme};

/// Subprotocol the Miniserver expects (PDF: "specify remotecontrol as Sec-WebSocket-Protocol").
pub const SUBPROTOCOL: &str = "remotecontrol";
/// Largest message accepted (`MAX_WEBSOCKET_MESSAGE_SIZE`, 5 MiB).
pub const MAX_MESSAGE_SIZE: usize = 5 * 1024 * 1024;
/// Connect and handshake timeout (`TIMEOUT`, bounded at twice that by the caller).
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Options for opening the WebSocket.
#[derive(Debug, Clone)]
pub struct WsOptions {
    /// TLS settings (used only for `wss`).
    pub tls: TlsOptions,
    /// Connect to this address instead of resolving the host (CloudDNS local TLS).
    pub connect_addr: Option<SocketAddr>,
    /// Timeout for the TCP connect and the handshake.
    pub open_timeout: Duration,
}

impl Default for WsOptions {
    fn default() -> Self {
        Self {
            tls: TlsOptions::default(),
            connect_addr: None,
            open_timeout: OPEN_TIMEOUT,
        }
    }
}

/// A frame as the Miniserver sent it, before any protocol parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawFrame {
    /// A binary frame (a message header or a payload).
    Binary(Vec<u8>),
    /// A text frame.
    Text(String),
}

/// Time of the last inbound frame, shared between the receiver and the watchdog.
#[derive(Debug, Clone)]
pub struct Activity(Arc<Mutex<Instant>>);

impl Activity {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    /// A fresh record, for tests in other modules.
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self::new()
    }

    /// Record that a frame arrived now.
    pub fn touch(&self) {
        if let Ok(mut t) = self.0.lock() {
            *t = Instant::now();
        }
    }

    /// Time since the last inbound frame.
    pub fn silence(&self) -> Duration {
        self.0.lock().map(|t| t.elapsed()).unwrap_or_default()
    }
}

/// Open a WebSocket. Returns the split halves.
pub async fn connect(
    endpoint: &Endpoint,
    opts: &WsOptions,
) -> Result<(WsSender, WsReceiver), TransportError> {
    let url = endpoint.ws_url();
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| TransportError::InvalidUrl(format!("{url}: {e}")))?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );

    let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE_SIZE));
    let connector = match endpoint.scheme {
        Scheme::Http => Connector::Plain,
        Scheme::Https => Connector::Rustls(client_config(&opts.tls)?),
    };

    let target = match opts.connect_addr {
        Some(addr) => addr.to_string(),
        None => format!("{}:{}", endpoint.host, endpoint.port),
    };
    let handshake = async {
        let tcp = TcpStream::connect(&target)
            .await
            .map_err(|e| TransportError::Unreachable(format!("{target}: {e}")))?;
        let _ = tcp.set_nodelay(true);
        client_async_tls_with_config(request, tcp, Some(config), Some(connector))
            .await
            .map_err(classify_ws)
    };
    let (stream, _response) = tokio::time::timeout(opts.open_timeout * 2, handshake)
        .await
        .map_err(|_| TransportError::Timeout(format!("websocket open to {target}")))??;

    let (sink, stream) = stream.split();
    let activity = Activity::new();
    Ok((WsSender { sink }, WsReceiver { stream, activity }))
}

/// The writing half of the WebSocket.
pub struct WsSender {
    sink: futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
}

impl WsSender {
    /// Send a text frame.
    pub async fn send_text(&mut self, text: &str) -> Result<(), TransportError> {
        self.sink
            .send(Message::Text(text.into()))
            .await
            .map_err(classify_ws)
    }

    /// Send a close frame (normal closure). The socket is dropped with the sender.
    pub async fn close(&mut self) -> Result<(), TransportError> {
        let frame = CloseFrame {
            code: CloseCode::Normal,
            reason: "".into(),
        };
        self.sink
            .send(Message::Close(Some(frame)))
            .await
            .map_err(classify_ws)
    }
}

/// The reading half of the WebSocket.
pub struct WsReceiver {
    stream: futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    activity: Activity,
}

impl WsReceiver {
    /// Shared record of inbound activity, for the keepalive watchdog.
    pub fn activity(&self) -> Activity {
        self.activity.clone()
    }

    /// Next data frame, or `None` on a clean close.
    ///
    /// Ping and pong frames count as activity but are not returned. A close with a
    /// code other than 1000 or 1001 is an error carrying the code (for example 4003).
    pub async fn next_frame(&mut self) -> Result<Option<RawFrame>, TransportError> {
        loop {
            let Some(item) = self.stream.next().await else {
                return Ok(None);
            };
            self.activity.touch();
            match item {
                Ok(Message::Binary(b)) => return Ok(Some(RawFrame::Binary(b.to_vec()))),
                Ok(Message::Text(t)) => return Ok(Some(RawFrame::Text(t.to_string()))),
                Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => continue,
                Ok(Message::Close(frame)) => return close_result(frame),
                Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => return Ok(None),
                Err(e) => return Err(classify_ws(e)),
            }
        }
    }
}

fn close_result(frame: Option<CloseFrame>) -> Result<Option<RawFrame>, TransportError> {
    match frame {
        None => Ok(None),
        Some(f) => {
            let code: u16 = f.code.into();
            if code == 1000 || code == 1001 {
                Ok(None)
            } else {
                Err(TransportError::Closed {
                    code: Some(code),
                    reason: f.reason.to_string(),
                })
            }
        }
    }
}

/// Map a tungstenite error to a transport error.
fn classify_ws(err: WsError) -> TransportError {
    match err {
        // tungstenite reports TLS handshake failures as I/O errors; a certificate
        // problem must not be retried, so look for a TLS cause first.
        WsError::Io(e) if is_tls_error(&e) => TransportError::Tls(e.to_string()),
        WsError::Io(e) => TransportError::Unreachable(e.to_string()),
        WsError::Tls(e) => TransportError::Tls(e.to_string()),
        WsError::Http(resp) => TransportError::Http {
            status: resp.status().as_u16(),
        },
        WsError::ConnectionClosed | WsError::AlreadyClosed => TransportError::Closed {
            code: None,
            reason: "connection closed".into(),
        },
        other => TransportError::Protocol(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_codes_1000_and_1001_are_clean() {
        let clean = CloseFrame {
            code: CloseCode::Normal,
            reason: "".into(),
        };
        assert_eq!(close_result(Some(clean)), Ok(None));
        let away = CloseFrame {
            code: CloseCode::Away,
            reason: "".into(),
        };
        assert_eq!(close_result(Some(away)), Ok(None));
    }

    #[test]
    fn close_4003_is_reported_with_code() {
        let blocked = CloseFrame {
            code: CloseCode::Library(4003),
            reason: "blocked".into(),
        };
        assert_eq!(
            close_result(Some(blocked)),
            Err(TransportError::Closed {
                code: Some(4003),
                reason: "blocked".into()
            })
        );
    }

    #[test]
    fn activity_resets_on_touch() {
        let a = Activity::new();
        std::thread::sleep(Duration::from_millis(5));
        assert!(a.silence() >= Duration::from_millis(5));
        a.touch();
        assert!(a.silence() < Duration::from_millis(5));
    }
}
