#![cfg(feature = "mock")]
//! Login through `Session::connect` against the scripted mock Miniserver.

use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::auth::token::TokenState;
use rs_loxone::mock::{Mock, MockConfig, start};
use rs_loxone::session::AsyncHandler;
use rs_loxone::session::{Event, Session, SessionConfig, SessionError};
use rs_loxone::transport::url::Endpoint;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

/// Connect with a handler that forwards every event to a channel, for the tests.
async fn connect_collect(
    cfg: SessionConfig,
) -> Result<(Session, UnboundedReceiver<Event>), SessionError> {
    let (tx, rx) = unbounded_channel();
    let handler = AsyncHandler(move |e: Event| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(e);
        }
    });
    let session = Session::connect(cfg, handler).await?;
    Ok((session, rx))
}

const USER: &str = "admin";
const PASSWORD: &str = "s3cret";

fn config(mock: &Mock, password: &str) -> SessionConfig {
    SessionConfig::new(
        Endpoint::parse(&format!("http://{}", mock.addr())).unwrap(),
        USER,
        Secret::new(password),
    )
}

async fn next_event(rx: &mut UnboundedReceiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("event channel closed")
}

/// Number of times the mock received `name`. The mock may still be handling the last
/// command when the client sees the event, so wait briefly for at least `want`.
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
async fn password_login_emits_token_then_connected() {
    let mock = start(MockConfig::default());
    let (_session, mut rx) = connect_collect(config(&mock, PASSWORD)).await.unwrap();

    match next_event(&mut rx).await {
        Event::TokenChanged(t) => assert!(t.token().expose().starts_with("eyJ.mock")),
        other => panic!("expected TokenChanged, got {other:?}"),
    }
    assert_eq!(next_event(&mut rx).await, Event::Connected);

    assert_eq!(
        wait_count(&mock, "jdev/sys/getjwt", 1).await,
        1,
        "password path uses getjwt"
    );
    assert_eq!(
        wait_count(&mock, "jdev/sps/enablebinstatusupdate", 1).await,
        1,
        "updates enabled"
    );
    assert_eq!(
        wait_count(&mock, "authwithtoken", 1).await,
        0,
        "no stored token given"
    );
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let mock = start(MockConfig::default());
    let err = connect_collect(config(&mock, "wrong"))
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(err, SessionError::Rejected { code: 401, .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn stored_token_is_used_when_still_valid() {
    let mock = start(MockConfig::default());

    // First login: obtain a token the mock knows.
    let (first, mut rx1) = connect_collect(config(&mock, PASSWORD)).await.unwrap();
    let stored: TokenState = first.token().clone();
    assert!(matches!(next_event(&mut rx1).await, Event::TokenChanged(_)));
    assert_eq!(next_event(&mut rx1).await, Event::Connected);
    drop(first);

    // Second login with the stored token: no password hash, authwithtoken instead.
    let mut cfg = config(&mock, PASSWORD);
    cfg.token = Some(stored);
    let (_second, mut rx2) = connect_collect(cfg).await.unwrap();
    assert!(matches!(next_event(&mut rx2).await, Event::TokenChanged(_)));
    assert_eq!(next_event(&mut rx2).await, Event::Connected);

    assert_eq!(
        wait_count(&mock, "authwithtoken", 1).await,
        1,
        "stored token used"
    );
    assert_eq!(
        wait_count(&mock, "jdev/sys/getjwt", 1).await,
        1,
        "only the first login needed getjwt"
    );
}

#[tokio::test]
async fn unknown_stored_token_falls_back_to_password() {
    let mock = start(MockConfig::default());
    let mut cfg = config(&mock, PASSWORD);
    cfg.token = Some(TokenState::new("eyJ.unknown", 563_000_000.0 + 1e9).unwrap());
    let (_s, mut rx) = connect_collect(cfg).await.unwrap();
    assert!(matches!(next_event(&mut rx).await, Event::TokenChanged(_)));
    assert_eq!(next_event(&mut rx).await, Event::Connected);

    assert_eq!(
        wait_count(&mock, "authwithtoken", 1).await,
        1,
        "stored token tried first"
    );
    assert_eq!(
        wait_count(&mock, "jdev/sys/getjwt", 1).await,
        1,
        "then the password path"
    );
}
