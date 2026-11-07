//! Live smoke test against a real Gen 1 Miniserver. Not run by default.
//!
//! Run with:  cargo test --test live_gen1 -- --ignored --nocapture
//! The address comes from LOX_HOST. Credentials come from the file named by LOX_ENV_FILE, or
//! ~/.config/rs-loxone/miniserver.env (lines LOX_USER=... and LOX_PASS=...).
//! Only status codes and lengths are printed, never the password or the token.

use std::time::Duration;

use rand::RngCore;
use rand::rngs::OsRng;
use rs_loxone::auth::commands::{self, parse_version};
use rs_loxone::auth::enc::EncCipher;
use rs_loxone::auth::hash::{credential_hash, token_hash};
use rs_loxone::auth::keyexchange::SessionKey;
use rs_loxone::auth::reply::{ensure_success, parse_key2, parse_token};
use rs_loxone::auth::{KeyAndSalt, Secret};
use rs_loxone::protocol::header::{HEADER_LEN, parse_header};
use rs_loxone::protocol::ll::LlResponse;
use rs_loxone::protocol::message::{Message, parse_frame};
use rs_loxone::transport::http::{BootstrapConfig, HttpBootstrap};
use rs_loxone::transport::retry::RetryPolicy;
use rs_loxone::transport::tls::TlsOptions;
use rs_loxone::transport::url::Endpoint;
use rs_loxone::transport::ws::{RawFrame, WsOptions, connect};

/// Miniserver address for the live test, from `LOX_HOST` (for example `http://<ip>:443`).
fn host() -> String {
    std::env::var("LOX_HOST").expect("set LOX_HOST, for example http://<miniserver-ip>:443")
}

fn load_credentials() -> (String, String) {
    let path = std::env::var("LOX_ENV_FILE").unwrap_or_else(|_| {
        format!(
            "{}/.config/rs-loxone/miniserver.env",
            std::env::var("HOME").unwrap()
        )
    });
    let text = std::fs::read_to_string(&path).expect("credentials file");
    let mut user = None;
    let mut pass = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("LOX_USER=") {
            user = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("LOX_PASS=") {
            pass = Some(v.trim().to_owned());
        }
    }
    (user.expect("LOX_USER"), pass.expect("LOX_PASS"))
}

/// Hide JWT-looking segments (they start with "eyJ") in printed text.
fn redact(text: &str) -> String {
    text.split('/')
        .map(|seg| {
            if seg.starts_with("eyJ") {
                "<token>"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn random_salt() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Read frames until a text reply whose control contains `needle`. Binary
/// headers are paired with the payload that follows.
async fn wait_for_reply(rx: &mut rs_loxone::transport::ws::WsReceiver, needle: &str) -> LlResponse {
    let mut pending_header = None;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(15), rx.next_frame())
            .await
            .expect("timeout waiting for reply")
            .expect("frame error")
            .expect("connection closed");
        match frame {
            RawFrame::Text(t) => {
                if let Ok(ll) = LlResponse::parse(t.as_bytes()) {
                    println!(
                        "  text reply: control={} code={}",
                        redact(&ll.control),
                        ll.code
                    );
                    if ll.control.contains(needle) {
                        return ll;
                    }
                }
            }
            RawFrame::Binary(b) if b.len() == HEADER_LEN && pending_header.is_none() => {
                let h = parse_header(&b).expect("header");
                pending_header = Some(h);
            }
            RawFrame::Binary(b) => {
                if let Some(Ok(Message::Text(ll))) =
                    pending_header.take().map(|h| parse_frame(&h, &b))
                {
                    println!(
                        "  text reply (framed): control={} code={}",
                        ll.control, ll.code
                    );
                    if ll.control.contains(needle) {
                        return ll;
                    }
                }
            }
        }
    }
}

#[tokio::test]
#[ignore = "live: needs the Gen 1 Miniserver and credentials"]
async fn gen1_login_and_token() {
    let (user, pass) = load_credentials();
    let endpoint = Endpoint::parse(&host()).unwrap();

    // 1. Bootstrap over HTTP.
    let http = HttpBootstrap::new(BootstrapConfig {
        endpoint: endpoint.clone(),
        username: user.clone(),
        password: Secret::new(pass.clone()),
        tls: TlsOptions::default(),
        retry: RetryPolicy::default(),
        connect_addr: None,
    })
    .unwrap();
    let info = http.api_key().await.expect("apiKey");
    println!(
        "1. apiKey: version={:?} https_status={:?} local={:?}",
        info.version, info.https_status, info.local
    );
    let pem = http.public_key_pem().await.expect("public key");
    println!("   public key PEM: {} bytes", pem.len());

    // 2. WebSocket and key exchange (plain).
    let (mut tx, mut rx) = connect(&endpoint, &WsOptions::default())
        .await
        .expect("ws connect");
    println!("2. websocket open");
    let session = SessionKey::generate(&pem, &mut OsRng).expect("session key");
    tx.send_text(session.keyexchange_command()).await.unwrap();
    let ke = wait_for_reply(&mut rx, "keyexchange").await;
    println!("   keyexchange reply code={}", ke.code);

    // Encrypted commands from here on.
    let mut enc = EncCipher::new(&session, random_salt());
    let send_enc = |cmd: String, enc: &mut EncCipher| enc.encrypt_command(&cmd, &random_salt());

    // 3. getkey2 (encrypted).
    tx.send_text(&send_enc(commands::get_key2(&user), &mut enc))
        .await
        .unwrap();
    let k2 = wait_for_reply(&mut rx, "getkey2").await;
    ensure_success(&k2).expect("getkey2 code");
    let ks: KeyAndSalt = parse_key2(&k2).expect("key and salt");
    println!(
        "3. getkey2 ok: hashAlg={:?} key_len={} salt_len={}",
        ks.hash_alg,
        ks.key.expose().len(),
        ks.salt.len()
    );

    // 4. getjwt (encrypted) with the password hash.
    let version = parse_version(&format!(
        "{}.{}.{}",
        info.version[0], info.version[1], info.version[2]
    ))
    .unwrap();
    let pw_hash = credential_hash(&user, &pass, &ks).unwrap();
    tx.send_text(&send_enc(
        commands::request_token(version, &pw_hash, &user),
        &mut enc,
    ))
    .await
    .unwrap();
    let tok_reply = wait_for_reply(&mut rx, "getjwt").await;
    ensure_success(&tok_reply).expect("getjwt code");
    let token = parse_token(&tok_reply).expect("token");
    println!(
        "4. token ok: len={} valid_until={} rights={:?}",
        token.token().expose().len(),
        token.valid_until(),
        token.token_rights
    );

    // 5. Enable state updates and read a few seconds of frames.
    tx.send_text(&send_enc(commands::enable_updates().to_owned(), &mut enc))
        .await
        .unwrap();
    let mut state_frames = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), rx.next_frame()).await {
            Ok(Ok(Some(RawFrame::Binary(_)))) => state_frames += 1,
            Ok(Ok(Some(RawFrame::Text(_)))) => state_frames += 1,
            _ => break,
        }
    }
    println!("5. state frames received in 5 s: {state_frames}");

    // 6. Keepalive (plain).
    tx.send_text(commands::keepalive()).await.unwrap();
    println!("6. keepalive sent");

    // 7. Check the token with the plain token (encrypted); the hash form returns 401 here.
    tx.send_text(&send_enc(
        commands::check_token(token.token().expose(), &user),
        &mut enc,
    ))
    .await
    .unwrap();
    let chk = wait_for_reply(&mut rx, "checktoken").await;
    println!("7. checktoken code={}", chk.code);

    tx.close().await.ok();
}

/// Find the working `checktoken` form. Logs in once, then tries variants on the
/// same session, printing only status codes.
#[tokio::test]
#[ignore = "live: needs the Gen 1 Miniserver and credentials"]
async fn gen1_checktoken_variants() {
    let (user, pass) = load_credentials();
    let endpoint = Endpoint::parse(&host()).unwrap();
    let http = HttpBootstrap::new(BootstrapConfig {
        endpoint: endpoint.clone(),
        username: user.clone(),
        password: Secret::new(pass.clone()),
        tls: TlsOptions::default(),
        retry: RetryPolicy::default(),
        connect_addr: None,
    })
    .unwrap();
    let info = http.api_key().await.expect("apiKey");
    let pem = http.public_key_pem().await.expect("public key");
    let version = info.version;
    let (mut tx, mut rx) = connect(&endpoint, &WsOptions::default()).await.expect("ws");
    let session = SessionKey::generate(&pem, &mut OsRng).expect("session key");
    tx.send_text(session.keyexchange_command()).await.unwrap();
    wait_for_reply(&mut rx, "keyexchange").await;
    let mut enc = EncCipher::new(&session, random_salt());
    tx.send_text(&enc.encrypt_command(&commands::get_key2(&user), &random_salt()))
        .await
        .unwrap();
    let k2 = wait_for_reply(&mut rx, "getkey2").await;
    let ks = parse_key2(&k2).expect("key and salt");
    let pw_hash = credential_hash(&user, &pass, &ks).unwrap();
    tx.send_text(&enc.encrypt_command(
        &commands::request_token(version, &pw_hash, &user),
        &random_salt(),
    ))
    .await
    .unwrap();
    let tok_reply = wait_for_reply(&mut rx, "getjwt").await;
    let token = parse_token(&tok_reply).expect("token");
    let tok_text = token.token().expose().to_owned();
    println!(
        "token len={} token key present={}",
        tok_text.len(),
        token.key.is_some()
    );

    // Variant list: (label, command text before encryption)
    let hash_sha256 = token_hash(&tok_text, &ks).unwrap();
    let mut ks_sha1 = ks.clone();
    ks_sha1.hash_alg = rs_loxone::auth::HashAlg::Sha1;
    let hash_sha1 = token_hash(&tok_text, &ks_sha1).unwrap();
    let variants: Vec<(&str, String, &str)> = vec![
        (
            "A checktoken, hash SHA256 (current)",
            commands::check_token(&hash_sha256, &user),
            "checktoken",
        ),
        (
            "B checktoken, hash SHA1",
            commands::check_token(&hash_sha1, &user),
            "checktoken",
        ),
        (
            "C checktoken, plain token",
            commands::check_token(&tok_text, &user),
            "checktoken",
        ),
    ];
    for (label, cmd, needle) in variants {
        tx.send_text(&enc.encrypt_command(&cmd, &random_salt()))
            .await
            .unwrap();
        let ll = wait_for_reply(&mut rx, needle).await;
        println!("{label}: code={}", ll.code);
    }
    tx.close().await.ok();
}

/// One login: returns the plain token, the connection halves, the key material
/// and the encryption state (keep the cipher; a new one breaks the salt chain).
async fn login_get_token(
    endpoint: &Endpoint,
    pem: &str,
    version: [u32; 3],
    user: &str,
    pass: &str,
) -> (
    String,
    rs_loxone::transport::ws::WsSender,
    rs_loxone::transport::ws::WsReceiver,
    SessionKey,
    KeyAndSalt,
    EncCipher,
) {
    let (mut tx, mut rx) = connect(endpoint, &WsOptions::default()).await.expect("ws");
    let session = SessionKey::generate(pem, &mut OsRng).expect("session key");
    tx.send_text(session.keyexchange_command()).await.unwrap();
    wait_for_reply(&mut rx, "keyexchange").await;
    let mut enc = EncCipher::new(&session, random_salt());
    tx.send_text(&enc.encrypt_command(&commands::get_key2(user), &random_salt()))
        .await
        .unwrap();
    let ks = parse_key2(&wait_for_reply(&mut rx, "getkey2").await).expect("key and salt");
    let pw = credential_hash(user, pass, &ks).unwrap();
    tx.send_text(
        &enc.encrypt_command(&commands::request_token(version, &pw, user), &random_salt()),
    )
    .await
    .unwrap();
    let token = parse_token(&wait_for_reply(&mut rx, "getjwt").await).expect("token");
    (token.token().expose().to_owned(), tx, rx, session, ks, enc)
}

/// Re-encode an `enc` command with percent-encoding that keeps `/` unencoded:
/// base64 `/` stays unencoded, `+` and `=` are encoded.
fn quote_style_enc(cmd: &str) -> String {
    let payload = cmd.strip_prefix("jdev/sys/enc/").expect("enc prefix");
    let raw = percent_encoding::percent_decode_str(payload)
        .decode_utf8()
        .unwrap();
    let mut out = String::from("jdev/sys/enc/");
    for c in raw.chars() {
        match c {
            '+' => out.push_str("%2B"),
            '=' => out.push_str("%3D"),
            other => out.push(other),
        }
    }
    out
}

/// Refresh: fetch a fresh key with plain `jdev/sys/getkey`, then
/// refresh with the token hash computed from that key.
#[tokio::test]
#[ignore = "live: needs the Gen 1 Miniserver and credentials"]
async fn gen1_refresh_with_getkey() {
    let (user, pass) = load_credentials();
    let endpoint = Endpoint::parse(&host()).unwrap();
    let http = HttpBootstrap::new(BootstrapConfig {
        endpoint: endpoint.clone(),
        username: user.clone(),
        password: Secret::new(pass.clone()),
        tls: TlsOptions::default(),
        retry: RetryPolicy::default(),
        connect_addr: None,
    })
    .unwrap();
    let info = http.api_key().await.expect("apiKey");
    let pem = http.public_key_pem().await.expect("public key");
    let version = info.version;

    let (t, mut tx, mut rx, _session, ks, mut enc) =
        login_get_token(&endpoint, &pem, version, &user, &pass).await;

    // Plain getkey: the reply carries a fresh key.
    tx.send_text(commands::get_key()).await.unwrap();
    let gk = wait_for_reply(&mut rx, "sys/getkey").await;
    // The key is taken from the `value` string of the getkey reply.
    let key = gk.value.clone();
    println!("getkey: code={} key_len={}", gk.code, key.len());

    // Hash with the getkey key, same algorithm as the getkey2 reply.
    let mut ks_fresh = ks.clone();
    if std::env::var("KEY_SOURCE").as_deref() != Ok("getkey2") {
        ks_fresh.key = Secret::new(key);
    }
    let hash = token_hash(&t, &ks_fresh).unwrap();
    let style = std::env::var("ENC_STYLE").unwrap_or_else(|_| "quote".into());
    let cmd = enc.encrypt_command(
        &commands::refresh_token(version, &hash, &user),
        &random_salt(),
    );
    let cmd = if style == "quote" {
        quote_style_enc(&cmd)
    } else {
        cmd
    };
    tx.send_text(&cmd).await.unwrap();
    let r = wait_for_reply(&mut rx, "refreshjwt").await;
    println!(
        "refresh with getkey key, enc style {style}: code={}",
        r.code
    );
    if r.code == 200 {
        let new = parse_token(&r).expect("new token");
        println!(
            "  new token: len={} valid_until={}",
            new.token().expose().len(),
            new.valid_until()
        );
    }
    let _ = tx.close().await;
}

/// One value from the credentials file. Never printed.
fn env_value(key: &str) -> String {
    let path = std::env::var("LOX_ENV_FILE").unwrap_or_else(|_| {
        format!(
            "{}/.config/rs-loxone/miniserver.env",
            std::env::var("HOME").unwrap()
        )
    });
    let text = std::fs::read_to_string(&path).expect("credentials file");
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .map(|v| v.trim().to_owned())
        .unwrap_or_else(|| panic!("{key} missing in the credentials file"))
}

/// Check the visualization code with `jdev/sps/checkuservisupwd`. Runs nothing on the
/// Miniserver. Only the two answers are printed, never the code itself.
#[tokio::test]
#[ignore = "live: needs the Gen 1 Miniserver, credentials and LOX_VISU_CODE"]
async fn gen1_visu_code_check() {
    let (user, pass) = load_credentials();
    let visu_code = env_value("LOX_VISU_CODE");
    let cfg = rs_loxone::session::SessionConfig::new(
        Endpoint::parse(&host()).unwrap(),
        user,
        rs_loxone::auth::Secret::new(pass),
    );
    let handler = rs_loxone::session::AsyncHandler(|_e: rs_loxone::session::Event| async {});
    let session = rs_loxone::session::Session::connect(cfg, handler)
        .await
        .expect("login");

    let wrong = session
        .check_visu_code("0000")
        .await
        .expect("check wrong code");
    println!("wrong code 0000 accepted: {wrong}");
    let right = session
        .check_visu_code(&visu_code)
        .await
        .expect("check code");
    println!("configured code accepted: {right}");
    session.close().await;

    assert!(!wrong, "a wrong code must be refused");
    assert!(right, "the configured code must be accepted");
}

/// Arms the alarm with `delayedon/0` (as the Home Assistant integration does), watches its
/// states for 30 s, then disarms it with `off` in any case. Needs LOX_ALARM_UUID and a comma
/// separated LOX_ALARM_STATES list (UUIDs of its states). Only the states are printed.
#[tokio::test]
#[ignore = "live: switches the real alarm on and off"]
async fn gen1_alarm_arm_then_disarm() {
    let (user, pass) = load_credentials();
    let visu = env_value("LOX_VISU_CODE");
    let alarm = std::env::var("LOX_ALARM_UUID").expect("LOX_ALARM_UUID");
    let states: Vec<rs_loxone::protocol::Uuid> = std::env::var("LOX_ALARM_STATES")
        .expect("LOX_ALARM_STATES")
        .split(',')
        .map(|u| u.trim().parse().expect("state uuid"))
        .collect();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let handler = rs_loxone::session::AsyncHandler(move |e: rs_loxone::session::Event| {
        let tx = tx.clone();
        async move {
            if let rs_loxone::session::Event::ValueStates(values) = e {
                let _ = tx.send(values);
            }
        }
    });
    let cfg = rs_loxone::session::SessionConfig::new(
        Endpoint::parse(&host()).unwrap(),
        user,
        rs_loxone::auth::Secret::new(pass),
    );
    let session = rs_loxone::session::Session::connect(cfg, handler)
        .await
        .expect("login");

    let mut last: Vec<Option<f64>> = vec![None; states.len()];
    let mut show =
        |rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<(rs_loxone::protocol::Uuid, f64)>>,
         label: &str| {
            while let Ok(values) = rx.try_recv() {
                for (uuid, value) in values {
                    if let Some(i) = states.iter().position(|s| *s == uuid) {
                        last[i] = Some(value);
                    }
                }
            }
            println!("{label}: {:?}", last);
        };

    tokio::time::sleep(Duration::from_secs(3)).await;
    show(&mut rx, "before");

    let arm_value = std::env::var("LOX_ARM_VALUE").unwrap_or_else(|_| "delayedon/0".into());
    let arm = session.send_secured(&alarm, &arm_value, &visu).await;
    println!("arm ({arm_value}): {arm:?}");
    for i in 1..=6 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        show(&mut rx, &format!("after {}s", i * 5));
    }

    let off = session.send_secured(&alarm, "off", &visu).await;
    println!("disarm (off): {off:?}");
    tokio::time::sleep(Duration::from_secs(5)).await;
    show(&mut rx, "after disarm");

    session.close().await;
    arm.expect("arm command accepted");
    off.expect("disarm command accepted");
}

/// Sends `off` with a wrong visualization code. The alarm is disarmed, so this changes
/// nothing; it only shows what the Miniserver answers for a refused command.
#[tokio::test]
#[ignore = "live: sends a command with a wrong code"]
async fn gen1_alarm_wrong_code_off() {
    let (user, pass) = load_credentials();
    let alarm = std::env::var("LOX_ALARM_UUID").expect("LOX_ALARM_UUID");
    let cfg = rs_loxone::session::SessionConfig::new(
        Endpoint::parse(&host()).unwrap(),
        user,
        rs_loxone::auth::Secret::new(pass),
    );
    let handler = rs_loxone::session::AsyncHandler(|_e: rs_loxone::session::Event| async {});
    let session = rs_loxone::session::Session::connect(cfg, handler)
        .await
        .expect("login");
    let result = session.send_secured(&alarm, "off", "0000").await;
    println!("off with wrong code: {result:?}");
    session.close().await;
}
