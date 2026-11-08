#![cfg(feature = "mock")]
//! `killtoken` through `Session::kill_token` against the scripted mock Miniserver.

use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::mock::{Mock, MockConfig, start};
use rs_loxone::session::AsyncHandler;
use rs_loxone::session::{Event, Session, SessionConfig, SessionError};
use rs_loxone::transport::url::Endpoint;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

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

fn config(mock: &Mock) -> SessionConfig {
    SessionConfig::new(
        Endpoint::parse(&format!("http://{}", mock.addr())).unwrap(),
        USER,
        Secret::new(PASSWORD),
    )
}

async fn next_event(rx: &mut UnboundedReceiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("event channel closed")
}

#[tokio::test]
async fn killed_token_is_refused_on_the_next_login() {
    let mock = start(MockConfig::default());
    let (session, _rx) = connect_collect(config(&mock)).await.unwrap();
    let token = session.token();

    session.kill_token().await.unwrap();
    assert!(
        mock.seen().iter().any(|name| name == "jdev/sys/killtoken"),
        "killtoken was not received: {:?}",
        mock.seen()
    );

    // The same token is no longer accepted, so the login falls back to the password.
    let mut cfg = config(&mock);
    cfg.token = Some(token);
    let (_second, mut rx) = connect_collect(cfg).await.unwrap();
    assert!(matches!(
        next_event(&mut rx).await,
        Event::LoggedIn {
            used_stored_token: false
        }
    ));
}
