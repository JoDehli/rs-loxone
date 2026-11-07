#![cfg(feature = "mock")]
//! Preflight against the scripted mock: no free event slot and a remote connection are
//! refused before the WebSocket is opened.

use rs_loxone::auth::Secret;
use rs_loxone::mock::{MockConfig, start};
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig, SessionError};
use rs_loxone::transport::url::Endpoint;

fn config(addr: std::net::SocketAddr) -> SessionConfig {
    SessionConfig::new(
        Endpoint::parse(&format!("http://{addr}")).unwrap(),
        "admin",
        Secret::new("s3cret"),
    )
}

async fn connect(cfg: SessionConfig) -> Result<Session, SessionError> {
    Session::connect(cfg, AsyncHandler(|_: Event| async {})).await
}

#[tokio::test]
async fn no_free_event_slot_is_refused_before_login() {
    let mock = start(MockConfig {
        event_slots: false,
        ..MockConfig::default()
    });
    let err = connect(config(mock.addr())).await.err().expect("refused");
    assert_eq!(err, SessionError::NoEventSlots);
    assert!(
        mock.seen()
            .iter()
            .all(|s| !s.starts_with("jdev/sys/getjwt")),
        "no login was attempted"
    );
}

#[tokio::test]
async fn remote_connection_is_refused_when_local_only() {
    let mock = start(MockConfig {
        local: false,
        ..MockConfig::default()
    });
    let mut cfg = config(mock.addr());
    cfg.local_only = true;
    let err = connect(cfg).await.err().expect("refused");
    assert_eq!(err, SessionError::NotLocal);
}

#[tokio::test]
async fn remote_connection_is_allowed_by_default() {
    let mock = start(MockConfig {
        local: false,
        ..MockConfig::default()
    });
    assert!(connect(config(mock.addr())).await.is_ok());
}

#[tokio::test]
async fn free_event_slot_and_local_connect_normally() {
    let mock = start(MockConfig::default());
    let mut cfg = config(mock.addr());
    cfg.local_only = true;
    assert!(connect(cfg).await.is_ok());
}
