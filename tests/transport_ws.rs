//! WebSocket behaviour against local mock servers (plain and TLS).

use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rs_loxone::transport::TransportError;
use rs_loxone::transport::tls::TlsOptions;
use rs_loxone::transport::url::Endpoint;
use rs_loxone::transport::ws::{RawFrame, WsOptions, connect};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{Read, Write};
use tokio_tungstenite::tungstenite::accept_hdr;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message};

/// What a server does after the handshake.
#[derive(Clone)]
enum Script {
    /// Echo text frames back, then send these frames, then close normally.
    Send(Vec<Message>),
    /// Send a close frame with this code and stop.
    CloseWith(u16),
    /// Accept TCP but never complete the handshake.
    Stall,
    /// Send these frames without waiting for a client message first.
    Push(Vec<Message>),
}

/// Captured from the handshake and the first frame.
#[derive(Default, Clone)]
struct Seen {
    protocol: Option<String>,
    received_text: Option<String>,
}

fn plain_server(script: Script) -> (SocketAddr, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen_thread = seen.clone();
    thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { break };
            let script = script.clone();
            let seen = seen_thread.clone();
            thread::spawn(move || {
                if let Script::Stall = script {
                    thread::sleep(Duration::from_secs(5));
                    return;
                }
                serve(tcp, script, seen);
            });
        }
    });
    (addr, seen)
}

fn serve<S: Read + Write>(stream: S, script: Script, seen: Arc<Mutex<Seen>>) {
    let seen_cb = seen.clone();
    #[allow(clippy::result_large_err)]
    let callback = move |req: &Request, mut resp: Response| {
        let proto = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        seen_cb.lock().unwrap().protocol = proto.clone();
        if let Some(p) = proto {
            resp.headers_mut()
                .insert("Sec-WebSocket-Protocol", HeaderValue::from_str(&p).unwrap());
        }
        Ok(resp)
    };
    let Ok(mut ws) = accept_hdr(stream, callback) else {
        return;
    };
    match script {
        Script::Send(frames) => {
            if let Ok(Message::Text(t)) = ws.read() {
                seen.lock().unwrap().received_text = Some(t.to_string());
            }
            for f in frames {
                let _ = ws.send(f);
            }
            let _ = ws.close(None);
            let _ = ws.flush();
            // Drain until the client's close reply.
            while ws.read().is_ok() {}
        }
        Script::CloseWith(code) => {
            let frame = CloseFrame {
                code: CloseCode::from(code),
                reason: "test".into(),
            };
            let _ = ws.close(Some(frame));
            let _ = ws.flush();
            while ws.read().is_ok() {}
        }
        Script::Push(frames) => {
            for f in frames {
                let _ = ws.send(f);
            }
            let _ = ws.close(None);
            let _ = ws.flush();
            while ws.read().is_ok() {}
        }
        Script::Stall => {}
    }
}

fn endpoint(addr: SocketAddr) -> Endpoint {
    Endpoint::parse(&format!("http://{addr}")).unwrap()
}

#[tokio::test]
async fn sends_remotecontrol_subprotocol() {
    let (addr, seen) = plain_server(Script::Send(vec![]));
    let (mut tx, mut rx) = connect(&endpoint(addr), &WsOptions::default())
        .await
        .unwrap();
    tx.send_text("keepalive").await.unwrap();
    let _ = rx.next_frame().await;
    assert_eq!(
        seen.lock().unwrap().protocol.as_deref(),
        Some("remotecontrol")
    );
}

#[tokio::test]
async fn text_is_sent_and_frames_arrive_in_order() {
    let frames = vec![
        Message::Binary(vec![3, 2, 0, 0, 24, 0, 0, 0].into()),
        Message::Binary(vec![1u8; 24].into()),
        Message::Text("hello".into()),
    ];
    let (addr, seen) = plain_server(Script::Send(frames));
    let (mut tx, mut rx) = connect(&endpoint(addr), &WsOptions::default())
        .await
        .unwrap();
    tx.send_text("jdev/sps/io/x/on").await.unwrap();
    assert_eq!(
        rx.next_frame().await.unwrap(),
        Some(RawFrame::Binary(vec![3, 2, 0, 0, 24, 0, 0, 0]))
    );
    assert_eq!(
        rx.next_frame().await.unwrap(),
        Some(RawFrame::Binary(vec![1u8; 24]))
    );
    assert_eq!(
        rx.next_frame().await.unwrap(),
        Some(RawFrame::Text("hello".into()))
    );
    assert_eq!(
        rx.next_frame().await.unwrap(),
        None,
        "normal close ends the stream"
    );
    assert_eq!(
        seen.lock().unwrap().received_text.as_deref(),
        Some("jdev/sps/io/x/on")
    );
}

#[tokio::test]
async fn close_4003_is_reported_with_its_code() {
    let (addr, _) = plain_server(Script::CloseWith(4003));
    let (_tx, mut rx) = connect(&endpoint(addr), &WsOptions::default())
        .await
        .unwrap();
    let err = rx.next_frame().await.unwrap_err();
    assert_eq!(
        err,
        TransportError::Closed {
            code: Some(4003),
            reason: "test".into()
        }
    );
}

#[tokio::test]
async fn unreachable_port_is_retryable() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let err = connect(&endpoint(addr), &WsOptions::default())
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(err.is_retryable(), "{err:?}");
}

#[tokio::test]
async fn stalled_handshake_times_out() {
    let (addr, _) = plain_server(Script::Stall);
    let opts = WsOptions {
        open_timeout: Duration::from_millis(100),
        ..WsOptions::default()
    };
    let err = connect(&endpoint(addr), &opts)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(err, TransportError::Timeout(_)), "{err:?}");
}

// ---- TLS (wss) ----

struct TestCert {
    pem: String,
    der: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn test_cert() -> TestCert {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    TestCert {
        pem: ck.cert.pem(),
        der: CertificateDer::from(ck.cert.der().to_vec()),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    }
}

fn tls_server(cert: &TestCert, frames: Vec<Message>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der.clone()], cert.key.clone_key())
            .unwrap(),
    );
    thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { break };
            let conn = ServerConnection::new(config.clone()).unwrap();
            let tls = StreamOwned::new(conn, tcp);
            let frames = frames.clone();
            thread::spawn(move || {
                let seen = Arc::new(Mutex::new(Seen::default()));
                serve(tls, Script::Push(frames), seen);
            });
        }
    });
    addr
}

#[tokio::test]
async fn wss_with_extra_root_delivers_frames() {
    let cert = test_cert();
    let addr = tls_server(&cert, vec![Message::Text("over tls".into())]);
    let ep = Endpoint::parse(&format!("https://localhost:{}", addr.port())).unwrap();
    let opts = WsOptions {
        tls: TlsOptions {
            verify: true,
            extra_root_pem: Some(cert.pem.clone().into_bytes()),
        },
        connect_addr: Some(addr),
        ..WsOptions::default()
    };
    let (_tx, mut rx) = connect(&ep, &opts).await.unwrap();
    assert_eq!(
        rx.next_frame().await.unwrap(),
        Some(RawFrame::Text("over tls".into()))
    );
}

#[tokio::test]
async fn wss_unknown_certificate_is_rejected_by_default() {
    let cert = test_cert();
    let addr = tls_server(&cert, vec![]);
    let ep = Endpoint::parse(&format!("https://localhost:{}", addr.port())).unwrap();
    let opts = WsOptions {
        connect_addr: Some(addr),
        ..WsOptions::default()
    };
    let err = connect(&ep, &opts).await.map(|_| ()).unwrap_err();
    assert!(matches!(err, TransportError::Tls(_)), "{err:?}");
}

#[tokio::test]
async fn writer_delivers_queued_text_through_the_channel() {
    use rs_loxone::transport::keepalive::spawn_writer;
    let (addr, seen) = plain_server(Script::Send(vec![]));
    let (tx_sender, _rx) = connect(&endpoint(addr), &WsOptions::default())
        .await
        .unwrap();
    let (out, writer) = spawn_writer(tx_sender);
    out.send("jdev/sps/enablebinstatusupdate".to_string())
        .await
        .unwrap();
    // Dropping the last sender ends the writer, which sends a close frame.
    drop(out);
    writer.await.unwrap().unwrap();
    // The server thread records the text asynchronously; wait briefly for it.
    let mut got = None;
    for _ in 0..200 {
        got = seen.lock().unwrap().received_text.clone();
        if got.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(got.as_deref(), Some("jdev/sps/enablebinstatusupdate"));
}
