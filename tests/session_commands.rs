#![cfg(feature = "mock")]
//! Sending commands on a logged-in session, against the scripted mock.

use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::mock::{Mock, MockConfig, start};
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig};
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

/// Wait until the mock has received `want` commands with `name`.
async fn wait_count(mock: &Mock, name: &str, want: usize) -> usize {
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
async fn commands_are_sent_encrypted_and_the_chain_holds() {
    let mock = start(MockConfig::default());
    let session = connect(&mock).await;

    // The mock refuses a broken salt chain and does not record the command. So three
    // recorded commands show that the chain stayed consistent across sends.
    let a = session.send_command("jdev/sps/io/AAA/on").await.unwrap();
    let b = session.send_command("jdev/sps/io/BBB/on").await.unwrap();
    let c = session.send_command("jdev/sps/io/CCC/off").await.unwrap();
    assert!(a < b && b < c, "ids increase");

    assert_eq!(wait_count(&mock, "jdev/sps/io", 3).await, 3);
}

#[tokio::test]
async fn send_command_does_not_wait_for_a_reply() {
    let mock = start(MockConfig::default());
    let session = connect(&mock).await;
    // The mock answers an unknown command with 404; the call still returns at once.
    let started = std::time::Instant::now();
    session.send_command("jdev/sps/io/DDD/on").await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
}
