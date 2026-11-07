#![cfg(feature = "mock")]
//! Gen 2 style connection: HTTPS and WSS through the session, against the TLS mock.

use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::mock::{MockConfig, start_tls, test_certificate_pem};
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig, SessionError};
use rs_loxone::transport::TransportError;
use rs_loxone::transport::tls::TlsOptions;
use rs_loxone::transport::url::Endpoint;

fn tls_config(addr: std::net::SocketAddr, tls: TlsOptions) -> SessionConfig {
    let mut cfg = SessionConfig::new(
        Endpoint::parse(&format!("https://localhost:{}", addr.port())).unwrap(),
        "admin",
        Secret::new("s3cret"),
    );
    cfg.tls = tls;
    cfg.connect_addr = Some(addr);
    cfg
}

fn trusted() -> TlsOptions {
    TlsOptions {
        verify: true,
        extra_root_pem: Some(test_certificate_pem().as_bytes().to_vec()),
        pinned_cert_sha256: None,
        trust_on_first_use: false,
        first_use_file: None,
    }
}

async fn wait_count(mock: &rs_loxone::mock::Mock, name: &str, want: usize) -> usize {
    for _ in 0..100 {
        let n = mock.seen().iter().filter(|s| s.as_str() == name).count();
        if n >= want {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    mock.seen().iter().filter(|s| s.as_str() == name).count()
}

#[tokio::test]
async fn login_commands_and_structure_work_over_https_and_wss() {
    let mock = start_tls(MockConfig::default());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let handler = AsyncHandler(move |e: Event| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(e);
        }
    });
    let session = Session::connect(tls_config(mock.addr(), trusted()), handler)
        .await
        .unwrap();

    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap(),
        Event::LoggedIn { .. }
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap(),
        Event::TokenChanged(_)
    ));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap(),
        Event::Connected
    );

    session.send_command("jdev/sps/io/AAA/on").await.unwrap();
    assert_eq!(wait_count(&mock, "jdev/sps/io", 1).await, 1);
    let file = session.structure().await.unwrap();
    assert!(file.final_url.starts_with("https://"), "{}", file.final_url);
    assert_eq!(
        session.structure_version().await.unwrap(),
        rs_loxone::mock::LAST_MODIFIED
    );
}

#[tokio::test]
async fn unknown_certificate_is_rejected_by_default() {
    let mock = start_tls(MockConfig::default());
    let handler = AsyncHandler(|_e: Event| async {});
    let err = Session::connect(tls_config(mock.addr(), TlsOptions::default()), handler)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(err, SessionError::Transport(TransportError::Tls(_))),
        "{err:?}"
    );
}

#[tokio::test]
async fn verification_can_be_switched_off_explicitly() {
    let mock = start_tls(MockConfig::default());
    let handler = AsyncHandler(|_e: Event| async {});
    let off = TlsOptions {
        verify: false,
        extra_root_pem: None,
        pinned_cert_sha256: None,
        trust_on_first_use: false,
        first_use_file: None,
    };
    assert!(
        Session::connect(tls_config(mock.addr(), off), handler)
            .await
            .is_ok()
    );
}
