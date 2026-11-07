//! Checks that the mock Miniserver behaves as the device does, using the crate's own
//! pieces (transport, auth, protocol) as the client.

use std::time::Duration;

use rand::RngCore;
use rand::rngs::OsRng;
use rs_loxone::auth::Secret;
use rs_loxone::auth::commands;
use rs_loxone::auth::enc::EncCipher;
use rs_loxone::auth::hash::{credential_hash, token_hash};
use rs_loxone::auth::keyexchange::SessionKey;
use rs_loxone::auth::reply::{ensure_success, parse_key2, parse_token};
use rs_loxone::protocol::ll::LlResponse;
use rs_loxone::transport::http::{BootstrapConfig, HttpBootstrap};
use rs_loxone::transport::retry::RetryPolicy;
use rs_loxone::transport::tls::TlsOptions;
use rs_loxone::transport::url::Endpoint;
use rs_loxone::transport::ws::{RawFrame, WsOptions, connect};

use loxone_mock::{MockConfig, start};

const USER: &str = "admin";
const PASSWORD: &str = "s3cret";

fn salt() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

async fn reply(rx: &mut rs_loxone::transport::ws::WsReceiver) -> LlResponse {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), rx.next_frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            RawFrame::Text(t) => return LlResponse::parse(t.as_bytes()).unwrap(),
            RawFrame::Binary(_) => continue,
        }
    }
}

#[tokio::test]
async fn full_login_and_chain_through_the_mock() {
    let mock = start(MockConfig::default());
    let endpoint = Endpoint::parse(&format!("http://{}", mock.addr())).unwrap();
    let http = HttpBootstrap::new(BootstrapConfig {
        endpoint: endpoint.clone(),
        username: USER.into(),
        password: Secret::new(PASSWORD),
        tls: TlsOptions::default(),
        retry: RetryPolicy::default(),
        connect_addr: None,
    })
    .unwrap();
    let info = http.api_key().await.unwrap();
    assert_eq!(info.version, [17, 1, 7]);
    let pem = http.public_key_pem().await.unwrap();

    let (mut tx, mut rx) = connect(&endpoint, &WsOptions::default()).await.unwrap();
    let session = SessionKey::generate(&pem, &mut OsRng).unwrap();
    tx.send_text(session.keyexchange_command()).await.unwrap();
    assert_eq!(reply(&mut rx).await.code, 200);

    let mut enc = EncCipher::new(&session, salt());
    tx.send_text(&enc.encrypt_command(&commands::get_key2(USER), &salt()))
        .await
        .unwrap();
    let r = reply(&mut rx).await;
    ensure_success(&r).unwrap();
    let ks = parse_key2(&r).unwrap();

    let pw = credential_hash(USER, PASSWORD, &ks).unwrap();
    tx.send_text(&enc.encrypt_command(&commands::request_token([17, 1, 7], &pw, USER), &salt()))
        .await
        .unwrap();
    let token = parse_token(&reply(&mut rx).await).unwrap();
    assert!(token.token().expose().starts_with("eyJ.mock"));

    // A valid token authenticates with the getkey2 key.
    let th = token_hash(token.token().expose(), &ks).unwrap();
    tx.send_text(&enc.encrypt_command(&commands::auth_with_token(&th, USER), &salt()))
        .await
        .unwrap();
    assert_eq!(reply(&mut rx).await.code, 200);

    // An unknown token is refused with 404 (as on the device).
    let bad = token_hash("eyJ.nope", &ks).unwrap();
    tx.send_text(&enc.encrypt_command(&commands::auth_with_token(&bad, USER), &salt()))
        .await
        .unwrap();
    assert_eq!(reply(&mut rx).await.code, 404);

    // A second cipher starts a new chain: the device refuses it (401).
    let mut enc2 = EncCipher::new(&session, salt());
    tx.send_text(&enc2.encrypt_command(&commands::get_key2(USER), &salt()))
        .await
        .unwrap();
    assert_eq!(
        reply(&mut rx).await.code,
        401,
        "second chain must be refused"
    );

    assert!(mock.seen().contains(&"jdev/sys/getjwt".to_string()));
}

#[tokio::test]
async fn mock_sends_initial_state_after_enable() {
    let uuid = [0x11u8; 16];
    let mock = start(MockConfig {
        initial_states: vec![(uuid, 1.5)],
        ..MockConfig::default()
    });
    let endpoint = Endpoint::parse(&format!("http://{}", mock.addr())).unwrap();
    let (mut tx, mut rx) = connect(&endpoint, &WsOptions::default()).await.unwrap();
    let http_pem = {
        let http = HttpBootstrap::new(BootstrapConfig {
            endpoint: endpoint.clone(),
            username: USER.into(),
            password: Secret::new(PASSWORD),
            tls: TlsOptions::default(),
            retry: RetryPolicy::default(),
            connect_addr: None,
        })
        .unwrap();
        http.public_key_pem().await.unwrap()
    };
    let session = SessionKey::generate(&http_pem, &mut OsRng).unwrap();
    tx.send_text(session.keyexchange_command()).await.unwrap();
    assert_eq!(reply(&mut rx).await.code, 200);
    let mut enc = EncCipher::new(&session, salt());
    tx.send_text(&enc.encrypt_command("jdev/sps/enablebinstatusupdate", &salt()))
        .await
        .unwrap();
    assert_eq!(reply(&mut rx).await.code, 200);
    // Header then payload: a value-state table with one record.
    let header = match tokio::time::timeout(Duration::from_secs(5), rx.next_frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    {
        RawFrame::Binary(b) => b,
        other => panic!("expected header, got {other:?}"),
    };
    assert_eq!(header[1], 2, "value-state identifier");
    let payload = match rx.next_frame().await.unwrap().unwrap() {
        RawFrame::Binary(b) => b,
        other => panic!("expected payload, got {other:?}"),
    };
    assert_eq!(payload.len(), 24);
    assert_eq!(&payload[..16], &uuid);
}
