#![cfg(feature = "mock")]
//! Token renewal against the scripted mock: renewal keeps the chain and emits events;
//! refused renewals end the session with AuthFailed.

use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::mock::{Mock, MockConfig, start};
use rs_loxone::session::{DisconnectReason, Event, RefreshPolicy, Session, SessionConfig};
use rs_loxone::transport::url::Endpoint;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

fn config(mock: &Mock) -> SessionConfig {
    SessionConfig::new(
        Endpoint::parse(&format!("http://{}", mock.addr())).unwrap(),
        "admin",
        Secret::new("s3cret"),
    )
}

async fn connect_collect(cfg: SessionConfig) -> (Session, UnboundedReceiver<Event>) {
    let (tx, rx) = unbounded_channel();
    let handler = rs_loxone::session::AsyncHandler(move |e: Event| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(e);
        }
    });
    let session = Session::connect(cfg, handler).await.unwrap();
    (session, rx)
}

/// Collect events for `dur`, or until a `Disconnected` arrives.
async fn collect_for(rx: &mut UnboundedReceiver<Event>, dur: Duration) -> Vec<Event> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + dur;
    while let Ok(Some(e)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        let end = matches!(e, Event::Disconnected { .. });
        out.push(e);
        if end {
            break;
        }
    }
    out
}

#[tokio::test]
async fn renewal_emits_new_tokens_and_keeps_the_chain() {
    // A 4 s token is renewed after about 2 s, and then again.
    let mock = start(MockConfig {
        token_lifetime_secs: 4,
        ..MockConfig::default()
    });
    let (_session, mut rx) = connect_collect(config(&mock)).await;
    let events = collect_for(&mut rx, Duration::from_secs(6)).await;

    let token_events = events
        .iter()
        .filter(|e| matches!(e, Event::TokenChanged(_)))
        .count();
    assert!(
        token_events >= 3,
        "login plus at least two renewals, got {token_events}"
    );
    assert!(!events.iter().any(|e| matches!(e, Event::AuthFailed { .. })));
    // Renewals are accepted by the mock only if the salt chain and the hash are right.
    let seen = mock.seen();
    assert!(
        seen.iter()
            .filter(|s| s.as_str() == "jdev/sys/refreshjwt")
            .count()
            >= 2
    );
    assert!(
        seen.iter()
            .filter(|s| s.as_str() == "jdev/sys/getkey")
            .count()
            >= 2
    );
}

#[tokio::test]
async fn refused_renewals_end_the_session_with_auth_failed() {
    let mock = start(MockConfig {
        token_lifetime_secs: 4,
        refuse_refresh: true,
        ..MockConfig::default()
    });
    let mut cfg = config(&mock);
    cfg.refresh = RefreshPolicy {
        attempts: 2,
        attempt_delay: Duration::from_millis(10),
        max_failed_cycles: 2,
        failed_cycle_wait: Duration::from_millis(10),
    };
    let (_session, mut rx) = connect_collect(cfg).await;
    let events = collect_for(&mut rx, Duration::from_secs(8)).await;

    let n = events.len();
    assert!(
        matches!(events[n - 2], Event::AuthFailed { .. }),
        "{events:?}"
    );
    assert_eq!(
        events[n - 1],
        Event::Disconnected {
            reason: DisconnectReason::AuthFailed
        }
    );
}
