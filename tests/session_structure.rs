#![cfg(feature = "mock")]
//! Structure file and its version, against the scripted mock.

use rs_loxone::auth::Secret;
use rs_loxone::mock::{LAST_MODIFIED, MockConfig, start};
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig};
use rs_loxone::transport::url::Endpoint;

async fn connect(addr: std::net::SocketAddr) -> Session {
    let cfg = SessionConfig::new(
        Endpoint::parse(&format!("http://{addr}")).unwrap(),
        "admin",
        Secret::new("s3cret"),
    );
    Session::connect(cfg, AsyncHandler(|_e: Event| async {}))
        .await
        .unwrap()
}

#[tokio::test]
async fn structure_is_returned_unchanged() {
    let mock = start(MockConfig::default());
    let session = connect(mock.addr()).await;
    let file = session.structure().await.unwrap();
    // The bytes parse as JSON, and their lastModified is the one the Miniserver reports.
    let json: serde_json::Value = serde_json::from_slice(&file.bytes).unwrap();
    assert_eq!(json["lastModified"], LAST_MODIFIED);
    assert!(file.final_url.ends_with("/data/LoxAPP3.json"));
}

#[tokio::test]
async fn structure_version_matches_the_file() {
    let mock = start(MockConfig::default());
    let session = connect(mock.addr()).await;
    let version = session.structure_version().await.unwrap();
    assert_eq!(version, LAST_MODIFIED);
    let file = session.structure().await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&file.bytes).unwrap();
    assert_eq!(json["lastModified"].as_str(), Some(version.as_str()));
}
