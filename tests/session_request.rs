#![cfg(feature = "mock")]
//! Multi-step requests: reply slot, serialization, and timeout.

use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::mock::{Mock, MockConfig, start};
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig, SessionError};
use rs_loxone::transport::url::Endpoint;

fn config(mock: &Mock) -> SessionConfig {
    SessionConfig::new(
        Endpoint::parse(&format!("http://{}", mock.addr())).unwrap(),
        "admin",
        Secret::new("s3cret"),
    )
}

async fn connect(mock: &Mock) -> Session {
    let handler = AsyncHandler(|_e: Event| async {});
    Session::connect(config(mock), handler).await.unwrap()
}

#[tokio::test]
async fn request_gets_its_reply() {
    let mock = start(MockConfig::default());
    let session = connect(&mock).await;
    let reply = session
        .request("jdev/sys/getvisusalt/admin", "getvisusalt")
        .await
        .unwrap();
    assert_eq!(reply.code, 200);
    assert!(reply.control.contains("getvisusalt"));
}

#[tokio::test]
async fn concurrent_requests_run_one_after_another_and_both_succeed() {
    let mock = start(MockConfig::default());
    let session = std::sync::Arc::new(connect(&mock).await);
    let a = {
        let s = session.clone();
        tokio::spawn(async move { s.request("jdev/sys/getvisusalt/admin", "getvisusalt").await })
    };
    let b = {
        let s = session.clone();
        tokio::spawn(async move { s.request("jdev/sys/getvisusalt/admin", "getvisusalt").await })
    };
    assert_eq!(a.await.unwrap().unwrap().code, 200);
    assert_eq!(b.await.unwrap().unwrap().code, 200);
}

#[tokio::test]
async fn silent_command_times_out() {
    let mock = start(MockConfig {
        mute_prefixes: vec!["jdev/sys/getvisusalt".into()],
        ..MockConfig::default()
    });
    let session = connect(&mock).await;
    let started = std::time::Instant::now();
    let err = session
        .request("jdev/sys/getvisusalt/admin", "getvisusalt")
        .await
        .unwrap_err();
    assert_eq!(err, SessionError::Timeout);
    assert!(started.elapsed() >= Duration::from_secs(14));
    assert!(started.elapsed() < Duration::from_secs(20));
}
