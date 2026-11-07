//! HTTP bootstrap against a local mock Miniserver (std thread, plain HTTP).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::transport::TransportError;
use rs_loxone::transport::http::{BootstrapConfig, HttpBootstrap};
use rs_loxone::transport::retry::RetryPolicy;
use rs_loxone::transport::tls::TlsOptions;
use rs_loxone::transport::url::Endpoint;

/// A canned response: status line, extra headers, body.
#[derive(Clone)]
struct Canned {
    status: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

/// Records of what the server saw.
#[derive(Default)]
struct Seen {
    paths: Vec<String>,
    auth: Vec<String>,
}

/// Serve `responses` in order, one per request, for a path (repeating the last).
fn serve(script: Vec<(String, Canned)>) -> (String, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen_thread = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let text = String::from_utf8_lossy(&buf).to_string();
            let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
            let auth = text
                .lines()
                .find_map(|l| {
                    l.strip_prefix("authorization: ")
                        .or_else(|| l.strip_prefix("Authorization: "))
                })
                .unwrap_or("")
                .trim()
                .to_string();
            let canned = {
                let mut s = seen_thread.lock().unwrap();
                s.paths.push(path.clone());
                s.auth.push(auth);
                let count = s.paths.iter().filter(|p| **p == path).count();
                let entry = script
                    .iter()
                    .filter(|(p, _)| *p == path)
                    .nth(count - 1)
                    .or_else(|| script.iter().rev().find(|(p, _)| *p == path));
                entry.map(|(_, c)| c.clone()).unwrap_or(Canned {
                    status: "404 Not Found",
                    headers: vec![],
                    body: b"".to_vec(),
                })
            };
            let mut head = format!(
                "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                canned.status,
                canned.body.len()
            );
            for (k, v) in &canned.headers {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&canned.body);
        }
    });
    (addr, seen)
}

fn ok(body: &str) -> Canned {
    Canned {
        status: "200 OK",
        headers: vec![],
        body: body.as_bytes().to_vec(),
    }
}

fn status(code: &'static str) -> Canned {
    Canned {
        status: code,
        headers: vec![],
        body: b"".to_vec(),
    }
}

fn client(addr: &str) -> HttpBootstrap {
    HttpBootstrap::new(BootstrapConfig {
        endpoint: Endpoint::parse(&format!("http://{addr}")).unwrap(),
        username: "admin".into(),
        password: Secret::new("s3cret"),
        tls: TlsOptions::default(),
        retry: RetryPolicy {
            max_attempts: 5,
            base: Duration::from_millis(5),
            max: Duration::from_millis(20),
        },
        connect_addr: None,
    })
    .unwrap()
}

const API_KEY_BODY: &str = r#"{"LL": {"control": "dev/cfg/apiKey", "code": "200", "value": "{'version': '12.2.10.6', 'MAC': '50:4F:94:00:00:01', 'httpsStatus': 1, 'local': true}"}}"#;

#[tokio::test]
async fn api_key_parses_single_quoted_value() {
    let (addr, seen) = serve(vec![("/jdev/cfg/apiKey".into(), ok(API_KEY_BODY))]);
    let info = client(&addr).api_key().await.unwrap();
    assert_eq!(info.version, [12, 2, 10]);
    assert_eq!(info.mac, "50:4F:94:00:00:01");
    assert_eq!(info.https_status, Some(1));
    assert_eq!(info.local, Some(true));
    assert_eq!(seen.lock().unwrap().paths, vec!["/jdev/cfg/apiKey"]);
}

#[tokio::test]
async fn sends_basic_auth() {
    let (addr, seen) = serve(vec![("/jdev/cfg/apiKey".into(), ok(API_KEY_BODY))]);
    client(&addr).api_key().await.unwrap();
    // base64("admin:s3cret") == YWRtaW46czNjcmV0
    assert_eq!(seen.lock().unwrap().auth[0], "Basic YWRtaW46czNjcmV0");
}

#[tokio::test]
async fn structure_file_is_returned_unchanged() {
    let json = r#"{"lastModified": "2026-01-01 10:00:00", "controls": {"ä": 1}}"#;
    let (addr, _) = serve(vec![("/data/LoxAPP3.json".into(), ok(json))]);
    let file = client(&addr).structure_file().await.unwrap();
    assert_eq!(file.bytes, json.as_bytes());
}

#[tokio::test]
async fn public_key_pem_is_extracted() {
    let body = r#"{"LL": {"control": "dev/sys/getPublicKey", "code": "200", "value": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}}"#;
    let (addr, _) = serve(vec![("/jdev/sys/getPublicKey".into(), ok(body))]);
    let pem = client(&addr).public_key_pem().await.unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("MIIB"));
}

#[tokio::test]
async fn retries_503_then_succeeds() {
    let (addr, seen) = serve(vec![
        ("/jdev/cfg/apiKey".into(), status("503 Service Unavailable")),
        ("/jdev/cfg/apiKey".into(), status("503 Service Unavailable")),
        ("/jdev/cfg/apiKey".into(), ok(API_KEY_BODY)),
    ]);
    let info = client(&addr).api_key().await.unwrap();
    assert_eq!(info.version, [12, 2, 10]);
    assert_eq!(seen.lock().unwrap().paths.len(), 3);
}

#[tokio::test]
async fn unauthorised_is_not_retried() {
    let (addr, seen) = serve(vec![(
        "/jdev/cfg/apiKey".into(),
        status("401 Unauthorized"),
    )]);
    let err = client(&addr).api_key().await.unwrap_err();
    assert_eq!(err, TransportError::Http { status: 401 });
    assert_eq!(seen.lock().unwrap().paths.len(), 1);
}

#[tokio::test]
async fn gives_up_after_five_503s() {
    let (addr, seen) = serve(vec![(
        "/data/LoxAPP3.json".into(),
        status("503 Service Unavailable"),
    )]);
    let err = client(&addr).structure_file().await.unwrap_err();
    assert_eq!(err, TransportError::Http { status: 503 });
    assert_eq!(seen.lock().unwrap().paths.len(), 5);
}

#[tokio::test]
async fn redirect_is_followed_and_final_url_reported() {
    let redirect = Canned {
        status: "302 Found",
        headers: vec![("Location", "/data/LoxAPP3.json".to_string())],
        body: vec![],
    };
    let (addr, _) = serve(vec![
        ("/jdev/cfg/apiKey".into(), redirect),
        ("/data/LoxAPP3.json".into(), ok("{}")),
    ]);
    let file = client(&addr).structure_file().await.unwrap();
    assert_eq!(file.bytes, b"{}");
    assert!(file.final_url.ends_with("/data/LoxAPP3.json"));
}

#[tokio::test]
async fn unreachable_host_is_reported_as_retryable() {
    // Bind then drop, so the port is closed.
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string();
    let err = client(&addr).api_key().await.unwrap_err();
    assert!(err.is_retryable(), "{err:?}");
}
