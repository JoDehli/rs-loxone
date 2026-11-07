//! A scripted mock Loxone Miniserver for tests.
//!
//! Serves HTTP (`apiKey`, public key, structure file) and WebSocket on one port. It
//! decrypts `jdev/sys/enc/` commands with its test key, checks the salt chain and the
//! hashes, and answers like a Gen 1 device on firmware 17.x:
//!
//! - 200 for accepted commands,
//! - 401 for a broken salt chain or a wrong hash,
//! - 404 for an unknown token or command.
//!
//! It is independent of the `rs-loxone` crate (it computes its own hashes), so any
//! project can use it. Test use only: credentials, keys and ports are fixed test values.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use aes::Aes256;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::percent_decode_str;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::http::HeaderValue;
use tungstenite::{Message, accept_hdr};

/// Structure file timestamp (lastModified), also returned by jdev/sps/LoxAPPversion3.
pub const LAST_MODIFIED: &str = "2026-01-01 10:00:00";

/// Certificate served by `/jdev/sys/getPublicKey` (test only).
const CERT_PEM: &str = include_str!("../../tests/fixtures/test_cert.pem");
/// CA that signed the test certificate (test only). Clients trust this.
const CA_PEM: &str = include_str!("../../tests/fixtures/test_ca.pem");
/// Private key matching the certificate (test only).
const KEY_PEM: &str = include_str!("../../tests/fixtures/test_key.pem");

/// A burst of value states for load tests. Record `i` has the UUID `i` (16 bytes, little
/// endian) and the value `i as f64`, so the receiver can check order and gaps.
#[derive(Debug, Clone, Copy)]
pub struct Flood {
    /// Total number of records.
    pub records: u64,
    /// Records per value-state table (one table is one event on the client).
    pub per_table: usize,
}

/// A fake alarm control that answers secured commands and reports its `armed` state.
#[derive(Debug, Clone)]
pub struct FakeAlarm {
    /// Device UUID (text form) that the commands are addressed to.
    pub uuid: String,
    /// Raw bytes of the `armed` state, as they appear in value-state tables.
    pub armed_state: [u8; 16],
}

/// Behaviour and fixed test values of the mock.
#[derive(Clone, Debug)]
pub struct MockConfig {
    /// User name accepted for login.
    pub user: String,
    /// Password accepted for login.
    pub password: String,
    /// Firmware version reported by `apiKey`.
    pub version: String,
    /// Salt returned for `getkey2`.
    pub key2_salt: String,
    /// Visualization code accepted for secured commands.
    pub visu_code: String,
    /// Value-state records sent right after `enablebinstatusupdate`: (uuid bytes, value).
    pub initial_states: Vec<([u8; 16], f64)>,
    /// If set, close the WebSocket with this code right after `enablebinstatusupdate`.
    pub close_after_enable: Option<u16>,
    /// With `close_after_enable`: only close for the first N enables (None = every time).
    pub close_first_enables: Option<u32>,
    /// Commands (inner text, prefix match) that the mock records but never answers.
    pub mute_prefixes: Vec<String>,
    /// Lifetime of issued tokens, in seconds from now.
    pub token_lifetime_secs: u64,
    /// Answer refreshjwt with 401 (refresh refused).
    pub refuse_refresh: bool,
    /// A fake alarm for secured commands (`on`, `on/0`, `on/1`, `off`).
    pub alarm: Option<FakeAlarm>,
    /// After `enablebinstatusupdate`, send this many value states in a flood (for load tests).
    pub flood: Option<Flood>,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            user: "admin".into(),
            password: "s3cret".into(),
            version: "17.1.7".into(),
            key2_salt: "mocksalt".into(),
            visu_code: "1234".into(),
            initial_states: vec![],
            close_after_enable: None,
            close_first_enables: None,
            mute_prefixes: vec![],
            token_lifetime_secs: 86_400,
            refuse_refresh: false,
            alarm: None,
            flood: None,
        }
    }
}

#[derive(Default)]
struct State {
    /// Armed state of the fake alarm (1.0 or 0.0).
    alarm_armed: f64,
    /// How many times `enablebinstatusupdate` was received, over all connections.
    enables: u32,
    aes_key: Option<[u8; 32]>,
    iv: Option<[u8; 16]>,
    /// Last salt the device has seen in the enc chain.
    last_salt: Option<String>,
    /// Key from getkey2 (hex).
    key2: String,
    /// Key from plain getkey (hex).
    key_plain: String,
    /// Visualization key and salt from getvisusalt.
    visu_key: String,
    visu_salt: String,
    /// Tokens issued by getjwt and refreshjwt.
    tokens: Vec<String>,
    counter: u32,
    /// Decrypted command names (no secrets), for assertions.
    seen: Vec<String>,
}

/// A running mock. The server threads run until the test process ends.
pub struct Mock {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    open_ws: Arc<std::sync::atomic::AtomicUsize>,
}

impl Mock {
    /// Address the mock listens on (use it as `http://addr`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Number of WebSocket connections that are still open.
    pub fn open_ws_connections(&self) -> usize {
        self.open_ws.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Decrypted command names received so far, without secrets.
    pub fn seen(&self) -> Vec<String> {
        self.state.lock().unwrap().seen.clone()
    }
}

/// Start the mock on 127.0.0.1 with an ephemeral port.
pub fn start(config: MockConfig) -> Mock {
    spawn_server(config, None)
}

/// Start the mock with TLS: HTTPS and WSS, like a Gen 2 Miniserver. The server certificate is
/// valid for `localhost` and `127.0.0.1` and signed by the test CA. Trust the CA on the client
/// with [`test_certificate_pem`].
pub fn start_tls(config: MockConfig) -> Mock {
    spawn_server(config, Some(tls_config()))
}

/// The test CA (PEM). Add it as an extra trust root on the client.
pub fn test_certificate_pem() -> &'static str {
    CA_PEM
}

fn tls_config() -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // Server certificate first, then the CA, so the client can build the chain.
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(CERT_PEM.as_bytes())
        .chain(CertificateDer::pem_slice_iter(CA_PEM.as_bytes()))
        .collect::<Result<_, _>>()
        .expect("test certificate");
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM.as_bytes()).expect("test key");
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("certificate and key");
    Arc::new(config)
}

fn spawn_server(config: MockConfig, tls: Option<Arc<rustls::ServerConfig>>) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let state = Arc::new(Mutex::new(State::default()));
    let st = state.clone();
    let open_ws = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let open = open_ws.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let st = st.clone();
            let cfg = config.clone();
            let tls = tls.clone();
            let open = open.clone();
            thread::spawn(move || match tls {
                None => handle_plain(stream, st, cfg, open),
                Some(tls) => {
                    let Ok(conn) = rustls::ServerConnection::new(tls) else {
                        return;
                    };
                    handle_tls(rustls::StreamOwned::new(conn, stream), st, cfg, open);
                }
            });
        }
    });
    Mock {
        addr,
        state,
        open_ws,
    }
}

fn is_websocket(head: &[u8]) -> bool {
    String::from_utf8_lossy(head)
        .to_ascii_lowercase()
        .contains("upgrade: websocket")
}

/// Read a request head (up to the blank line). Returns the bytes read.
fn read_head<R: Read>(r: &mut R) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    while out.len() < 8192 {
        match r.read(&mut byte) {
            Ok(1) => {
                out.push(byte[0]);
                if out.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            _ => break,
        }
    }
    out
}

fn header_value(head: &[u8], name: &str) -> Option<String> {
    String::from_utf8_lossy(head).lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        (k.trim().eq_ignore_ascii_case(name)).then(|| v.trim().to_string())
    })
}

/// The Sec-WebSocket-Accept value for a Sec-WebSocket-Key (RFC 6455).
fn ws_accept_key(key: &str) -> String {
    let mut h = Sha1::new();
    sha1::Digest::update(&mut h, key.as_bytes());
    sha1::Digest::update(&mut h, b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(sha1::Digest::finalize(h))
}

/// Plain connection: peek to choose HTTP or WebSocket, then serve.
fn handle_plain(
    stream: TcpStream,
    st: Arc<Mutex<State>>,
    cfg: MockConfig,
    open: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut head = vec![0u8; 4096];
    let Ok(n) = stream.peek(&mut head) else {
        return;
    };
    if is_websocket(&head[..n]) {
        #[allow(clippy::result_large_err)]
        let callback = |req: &Request, mut resp: Response| {
            if let Some(p) = req.headers().get("Sec-WebSocket-Protocol") {
                resp.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    HeaderValue::from_bytes(p.as_bytes())
                        .unwrap_or_else(|_| HeaderValue::from_static("remotecontrol")),
                );
            }
            Ok(resp)
        };
        let accepted = accept_hdr(stream, callback);
        if let Ok(ws) = accepted {
            open.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ws_loop(ws, st, cfg);
            open.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    } else {
        let mut stream = stream;
        let req = read_head(&mut stream);
        respond_http(&mut stream, &req, &cfg);
    }
}

/// TLS connection: read the head through TLS, then serve HTTP or do the WebSocket
/// handshake by hand (the head is already consumed, so `accept_hdr` cannot be used).
fn handle_tls<S: Read + Write>(
    mut stream: S,
    st: Arc<Mutex<State>>,
    cfg: MockConfig,
    open: Arc<std::sync::atomic::AtomicUsize>,
) {
    let req = read_head(&mut stream);
    if is_websocket(&req) {
        let Some(key) = header_value(&req, "sec-websocket-key") else {
            return;
        };
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: remotecontrol\r\n\r\n",
            ws_accept_key(&key)
        );
        if stream.write_all(resp.as_bytes()).is_err() {
            return;
        }
        let ws = tungstenite::WebSocket::from_raw_socket(
            stream,
            tungstenite::protocol::Role::Server,
            None,
        );
        open.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ws_loop(ws, st, cfg);
        open.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    } else {
        respond_http(&mut stream, &req, &cfg);
    }
}

/// Answer one HTTP request (apiKey, public key, structure file). Connection closes after.
fn respond_http<W: Write>(w: &mut W, req: &[u8], cfg: &MockConfig) {
    let req = String::from_utf8_lossy(req).to_string();
    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
    let body = match path.as_str() {
        "/jdev/cfg/apiKey" => format!(
            r#"{{"LL": {{"control": "dev/cfg/apiKey", "code": "200", "value": "{{'version': '{}', 'MAC': '50:4F:94:10:65:15', 'httpsStatus': null, 'local': true}}"}}}}"#,
            cfg.version
        ),
        "/jdev/sys/getPublicKey" => format!(
            r#"{{"LL": {{"control": "dev/sys/getPublicKey", "code": "200", "value": {}}}}}"#,
            serde_json::to_string(CERT_PEM).unwrap_or_default()
        ),
        "/data/LoxAPP3.json" => {
            format!(r#"{{"lastModified": "{LAST_MODIFIED}", "controls": {{}}}}"#)
        }
        _ => r#"{"LL": {"control": "unknown", "code": "404", "value": ""}}"#.to_string(),
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = w.write_all(head.as_bytes());
    let _ = w.write_all(body.as_bytes());
    let _ = w.flush();
}

/// The WebSocket message loop, shared by plain and TLS connections.
fn ws_loop<S: Read + Write>(
    mut ws: tungstenite::WebSocket<S>,
    st: Arc<Mutex<State>>,
    cfg: MockConfig,
) {
    loop {
        let msg = match ws.read() {
            Ok(m) => m,
            Err(_) => break,
        };
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break,
            _ => continue,
        };
        for out in answer(&text, &st, &cfg) {
            let sent = match out {
                Out::Text(t) => ws.send(Message::Text(t.into())),
                Out::Binary(b) => ws.send(Message::Binary(b.into())),
                Out::Close(code) => {
                    let frame = tungstenite::protocol::CloseFrame {
                        code: tungstenite::protocol::frame::coding::CloseCode::from(code),
                        reason: "mock close".into(),
                    };
                    let _ = ws.send(Message::Close(Some(frame)));
                    let _ = ws.flush();
                    return;
                }
            };
            if sent.is_err() {
                return;
            }
        }
    }
}

enum Out {
    Text(String),
    Binary(Vec<u8>),
    Close(u16),
}

/// The value-state tables of a flood, in order.
fn flood_tables(flood: Flood) -> Vec<Out> {
    let per_table = flood.per_table.max(1) as u64;
    let mut out = Vec::new();
    let mut next = 0u64;
    while next < flood.records {
        let count = per_table.min(flood.records - next);
        let mut payload = Vec::with_capacity(count as usize * 24);
        for i in next..next + count {
            let mut uuid = [0u8; 16];
            uuid[..8].copy_from_slice(&i.to_le_bytes());
            payload.extend_from_slice(&uuid);
            payload.extend_from_slice(&(i as f64).to_le_bytes());
        }
        let mut header = vec![3u8, 2, 0, 0];
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.push(Out::Binary(header));
        out.push(Out::Binary(payload));
        next += count;
    }
    out
}

/// One value-state table with a single entry, as the Miniserver pushes it.
fn value_frame(uuid: &[u8; 16], value: f64) -> Vec<Out> {
    let mut payload = Vec::with_capacity(24);
    payload.extend_from_slice(uuid);
    payload.extend_from_slice(&value.to_le_bytes());
    let mut header = vec![3u8, 2, 0, 0];
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    vec![Out::Binary(header), Out::Binary(payload)]
}

fn ll(control: &str, code: u16, value: Value) -> String {
    json!({"LL": {"control": control, "code": code.to_string(), "value": value}}).to_string()
}

fn answer(text: &str, st: &Arc<Mutex<State>>, cfg: &MockConfig) -> Vec<Out> {
    let mut s = st.lock().unwrap();
    if text == "keepalive" {
        return vec![Out::Binary(vec![3, 6, 0, 0, 0, 0, 0, 0])];
    }
    if let Some(b64) = text.strip_prefix("jdev/sys/keyexchange/") {
        return key_exchange(b64, &mut s);
    }
    if text == "jdev/sys/getkey" {
        s.seen.push("jdev/sys/getkey".into());
        s.key_plain = hex::encode([0x5au8; 40]);
        return vec![Out::Text(ll(
            "dev/sys/getkey",
            200,
            json!(s.key_plain.clone()),
        ))];
    }
    if let Some(payload) = text.strip_prefix("jdev/sys/enc/") {
        let (Some(key), Some(iv)) = (s.aes_key, s.iv) else {
            return vec![Out::Text(ll(text, 401, json!("")))];
        };
        let Some(plain) = decrypt_enc(payload, &key, &iv) else {
            return vec![Out::Text(ll(text, 401, json!("")))];
        };
        let Some(inner) = check_chain(&plain, &mut s) else {
            // Broken salt chain: the device refuses (401, encrypted request failed).
            return vec![Out::Text(ll(text, 401, json!("")))];
        };
        let outs = inner_command(&inner, &mut s, cfg);
        // Like the device: replies to encrypted commands carry an encrypted control.
        return outs
            .into_iter()
            .map(|out| match out {
                Out::Text(text) => Out::Text(encrypt_text_reply(&text, &key, &iv)),
                other => other,
            })
            .collect();
    }
    s.seen.push("unknown".into());
    vec![Out::Text(ll(text, 404, json!("")))]
}

fn key_exchange(b64: &str, s: &mut State) -> Vec<Out> {
    let refuse = || vec![Out::Text(ll("jdev/sys/keyexchange", 401, json!("")))];
    let Ok(key) = RsaPrivateKey::from_pkcs8_pem(KEY_PEM) else {
        return refuse();
    };
    let ct = STANDARD.decode(b64).unwrap_or_default();
    let Ok(plain) = key.decrypt(Pkcs1v15Encrypt, &ct) else {
        return refuse();
    };
    let text = String::from_utf8(plain).unwrap_or_default();
    let (k, iv) = text.split_once(':').unwrap_or(("", ""));
    let mut aes = [0u8; 32];
    let mut ivb = [0u8; 16];
    if hex::decode_to_slice(k, &mut aes).is_err() || hex::decode_to_slice(iv, &mut ivb).is_err() {
        return refuse();
    }
    // A key exchange starts a new connection: its salt chain and connection keys reset.
    // Tokens stay valid across connections, as on the device.
    s.last_salt = None;
    s.key2.clear();
    s.key_plain.clear();
    s.visu_key.clear();
    s.visu_salt.clear();
    s.aes_key = Some(aes);
    s.iv = Some(ivb);
    s.seen.push("jdev/sys/keyexchange".into());
    vec![Out::Text(ll(
        &format!("jdev/sys/keyexchange/{b64}"),
        200,
        json!(""),
    ))]
}

/// Replace the control of a text reply with `jdev/sys/enc/<base64>` of
/// `salt/<hex>/<control>\0`, AES-256-CBC with PKCS#7 padding (as the device sends it).
fn encrypt_text_reply(text: &str, key: &[u8; 32], iv: &[u8; 16]) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(text) else {
        return text.to_string();
    };
    let Some(control) = value["LL"]["control"].as_str().map(str::to_owned) else {
        return text.to_string();
    };
    let mut buf = format!("nextSalt/0a0b0c0d/0e0f1011/{control}\0").into_bytes();
    let pad = 16 - buf.len() % 16;
    buf.extend(std::iter::repeat_n(pad as u8, pad));
    let len = buf.len();
    let enc = cbc::Encryptor::<Aes256>::new(&(*key).into(), &(*iv).into());
    enc.encrypt_padded::<NoPadding>(&mut buf, len)
        .expect("whole blocks");
    value["LL"]["control"] = Value::String(format!("jdev/sys/enc/{}", STANDARD.encode(&buf)));
    value.to_string()
}

/// Percent-decode and base64-decode an enc payload, then AES-256-CBC decrypt and unpad.
fn decrypt_enc(payload: &str, key: &[u8; 32], iv: &[u8; 16]) -> Option<String> {
    let raw = percent_decode_str(payload).decode_utf8().ok()?;
    let mut buf = STANDARD.decode(raw.as_bytes()).ok()?;
    if buf.is_empty() || buf.len() % 16 != 0 {
        return None;
    }
    let dec = cbc::Decryptor::<Aes256>::new(&(*key).into(), &(*iv).into());
    let plain = dec.decrypt_padded::<NoPadding>(&mut buf).ok()?;
    let pad = *plain.last()? as usize;
    if pad == 0 || pad > 16 || pad > plain.len() {
        return None;
    }
    let text = String::from_utf8(plain[..plain.len() - pad].to_vec()).ok()?;
    Some(text.trim_end_matches('\0').to_string())
}

/// Check the salt chain. Returns the inner command, or None if the chain is broken.
fn check_chain(plain: &str, st: &mut State) -> Option<String> {
    if let Some(rest) = plain.strip_prefix("salt/") {
        let (salt, cmd) = rest.split_once('/')?;
        if st.last_salt.is_some() {
            return None; // a plain salt only starts a chain
        }
        st.last_salt = Some(salt.to_string());
        return Some(cmd.to_string());
    }
    let rest = plain.strip_prefix("nextSalt/")?;
    let (old, rest) = rest.split_once('/')?;
    let (new, cmd) = rest.split_once('/')?;
    if st.last_salt.as_deref() != Some(old) {
        return None;
    }
    st.last_salt = Some(new.to_string());
    Some(cmd.to_string())
}

fn inner_command(cmd: &str, s: &mut State, cfg: &MockConfig) -> Vec<Out> {
    if cfg
        .mute_prefixes
        .iter()
        .any(|p| cmd.starts_with(p.as_str()))
    {
        // Recorded, but no reply: lets tests exercise timeouts.
        let name = cmd.split('/').next().unwrap_or("").to_string();
        s.seen.push(format!("muted:{name}"));
        return vec![];
    }
    // Name without secrets: "jdev/sys/getjwt" for jdev commands, the bare verb otherwise.
    let name = if cmd.starts_with("jdev/") {
        cmd.split('/').take(3).collect::<Vec<_>>().join("/")
    } else {
        cmd.split('/').next().unwrap_or("").to_string()
    };
    s.seen.push(name);

    if let Some(user) = cmd.strip_prefix("jdev/sys/getkey2/") {
        if user != cfg.user {
            return vec![Out::Text(ll(cmd, 401, json!("")))];
        }
        s.key2 = hex::encode([0x11u8; 40]);
        return vec![Out::Text(ll(
            &format!("jdev/sys/getkey2/{}", cfg.user),
            200,
            json!({"key": s.key2.clone(), "salt": cfg.key2_salt.clone(), "hashAlg": "SHA256"}),
        ))];
    }

    if let Some(rest) = cmd.strip_prefix("jdev/sys/getjwt/") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() < 2 {
            return vec![Out::Text(ll(cmd, 400, json!("")))];
        }
        let expected = credential_hash(&cfg.user, &cfg.password, &s.key2, &cfg.key2_salt);
        if parts[0] != expected {
            return vec![Out::Text(ll(cmd, 401, json!("")))];
        }
        let token = issue(s);
        return vec![Out::Text(ll(
            &format!("jdev/sys/getjwt/{}", parts[0]),
            200,
            json!({"token": token, "validUntil": valid_until(cfg.token_lifetime_secs), "key": "", "unsecurePass": false, "tokenRights": 1666}),
        ))];
    }

    if let Some(rest) = cmd.strip_prefix("authwithtoken/") {
        let hash = rest.split('/').next().unwrap_or("");
        let valid = s.tokens.iter().any(|t| token_hash(t, &s.key2) == hash);
        let code = if valid { 200 } else { 404 };
        return vec![Out::Text(ll("authwithtoken", code, json!("")))];
    }

    if cmd == "jdev/sps/LoxAPPversion3" {
        // Same value as the structure file's lastModified (the device returns it as text).
        return vec![Out::Text(ll(
            "jdev/sps/LoxAPPversion3",
            200,
            json!(LAST_MODIFIED),
        ))];
    }

    if cmd == "jdev/sps/enablebinstatusupdate" {
        s.enables += 1;
        let mut out = vec![Out::Text(ll(cmd, 200, json!("")))];
        if let Some(flood) = cfg.flood {
            out.extend(flood_tables(flood));
        }
        if !cfg.initial_states.is_empty() {
            let mut payload = Vec::new();
            for (uuid, value) in &cfg.initial_states {
                payload.extend_from_slice(uuid);
                payload.extend_from_slice(&value.to_le_bytes());
            }
            let mut header = vec![3u8, 2, 0, 0];
            header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.push(Out::Binary(header));
            out.push(Out::Binary(payload));
        }
        let close_now = cfg.close_first_enables.is_none_or(|n| s.enables <= n);
        if let (Some(code), true) = (cfg.close_after_enable, close_now) {
            out.push(Out::Close(code));
        }
        return out;
    }

    if let Some(rest) = cmd.strip_prefix("jdev/sys/refreshjwt/") {
        if cfg.refuse_refresh {
            return vec![Out::Text(ll(cmd, 401, json!("")))];
        }
        let hash = rest.split('/').next().unwrap_or("");
        let ok = s.tokens.iter().any(|t| token_hash(t, &s.key_plain) == hash);
        if !ok {
            return vec![Out::Text(ll(cmd, 401, json!("")))];
        }
        let token = issue(s);
        return vec![Out::Text(ll(
            "jdev/sys/refreshjwt",
            200,
            json!({"token": token, "validUntil": valid_until(cfg.token_lifetime_secs), "unsecurePass": false}),
        ))];
    }

    if let Some(user) = cmd.strip_prefix("jdev/sys/getvisusalt/") {
        if user != cfg.user {
            return vec![Out::Text(ll(cmd, 401, json!("")))];
        }
        s.visu_key = hex::encode([0x22u8; 40]);
        s.visu_salt = "visusalt".into();
        return vec![Out::Text(ll(
            "jdev/sys/getvisusalt",
            200,
            json!({"key": s.visu_key.clone(), "salt": s.visu_salt.clone(), "hashAlg": "SHA256"}),
        ))];
    }

    if let Some(rest) = cmd.strip_prefix("jdev/sps/checkuservisupwd/") {
        // Checks the code and runs nothing.
        // The device answers 200 either way; the value is "1" (right) or "0" (wrong).
        let expected = visual_hash(&cfg.visu_code, &s.visu_key, &s.visu_salt);
        let value = if rest == expected { "1" } else { "0" };
        return vec![Out::Text(ll(
            "jdev/sps/checkuservisupwd",
            200,
            json!(value),
        ))];
    }

    if let Some(rest) = cmd.strip_prefix("jdev/sps/ios/") {
        // rest = <hash>/<uuid>/<value>; the value may itself contain '/'.
        let mut parts = rest.splitn(3, '/');
        let hash = parts.next().unwrap_or("");
        let uuid = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        let expected = visual_hash(&cfg.visu_code, &s.visu_key, &s.visu_salt);
        if hash != expected {
            return vec![Out::Text(ll("jdev/sps/ios", 500, json!("")))];
        }
        let mut out = vec![Out::Text(ll("jdev/sps/ios", 200, json!("")))];
        if let Some(alarm) = &cfg.alarm
            && alarm.uuid == uuid
        {
            let armed = match value {
                "on" | "on/0" | "on/1" => Some(1.0),
                "off" => Some(0.0),
                _ => None,
            };
            if let Some(armed) = armed {
                s.alarm_armed = armed;
                out.extend(value_frame(&alarm.armed_state, armed));
            }
        }
        return out;
    }

    if let Some(rest) = cmd.strip_prefix("jdev/sys/checktoken/") {
        let t = rest.split('/').next().unwrap_or("");
        let code = if s.tokens.iter().any(|x| x == t) {
            200
        } else {
            401
        };
        return vec![Out::Text(ll("dev/sys/checktoken", code, json!("")))];
    }

    vec![Out::Text(ll(cmd, 404, json!("")))]
}

/// Token expiry in Loxone seconds: one day from now (the device counts from 2009-01-01).
fn valid_until(lifetime_secs: u64) -> u64 {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    unix.saturating_sub(1_230_768_000) + lifetime_secs
}

fn issue(s: &mut State) -> String {
    s.counter += 1;
    let token = format!("eyJ.mock{}.sig", s.counter);
    s.tokens.push(token.clone());
    token
}

// ---- hashes (same scheme as the Loxone protocol; computed here, not via rs-loxone) ----

fn hash_upper(sha256: bool, data: &[u8]) -> String {
    if sha256 {
        hex::encode_upper(Sha256::digest(data))
    } else {
        hex::encode_upper(<Sha1 as sha1::Digest>::digest(data))
    }
}

fn hmac_lower(sha256: bool, key_hex: &str, msg: &[u8]) -> String {
    let key = hex::decode(key_hex).unwrap_or_default();
    if sha256 {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).expect("hmac key");
        mac.update(msg);
        hex::encode(mac.finalize().into_bytes())
    } else {
        let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(&key).expect("hmac key");
        mac.update(msg);
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Password hash for getjwt: HMAC(key, user ":" UPPER(H(password ":" salt))).
pub fn credential_hash(user: &str, password: &str, key2: &str, salt: &str) -> String {
    let inner = hash_upper(true, format!("{password}:{salt}").as_bytes());
    hmac_lower(true, key2, format!("{user}:{inner}").as_bytes())
}

/// Token hash for authwithtoken and refreshjwt: HMAC(key, token), SHA-256.
pub fn token_hash(token: &str, key_hex: &str) -> String {
    hmac_lower(true, key_hex, token.as_bytes())
}

/// Visualization hash for secured commands: HMAC(visualKey, UPPER(H(code ":" salt))).
pub fn visual_hash(code: &str, visu_key_hex: &str, visu_salt: &str) -> String {
    let inner = hash_upper(true, format!("{code}:{visu_salt}").as_bytes());
    hmac_lower(true, visu_key_hex, inner.as_bytes())
}
