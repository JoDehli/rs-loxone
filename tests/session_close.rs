#![cfg(feature = "mock")]
//! Closing a session: last event, socket closed, and closing after AuthFailed.

use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::mock::{Mock, MockConfig, start};
use rs_loxone::session::{
    AsyncHandler, DisconnectReason, Event, RefreshPolicy, Session, SessionConfig,
};
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
    let handler = AsyncHandler(move |e: Event| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(e);
        }
    });
    (Session::connect(cfg, handler).await.unwrap(), rx)
}

/// Wait until the mock sees no open WebSocket connection, or give up after `dur`.
async fn wait_no_open_sockets(mock: &Mock, dur: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + dur;
    loop {
        let n = mock.open_ws_connections();
        if n == 0 || tokio::time::Instant::now() >= deadline {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Events until `Disconnected` arrives (or `dur` passes).
async fn drain(rx: &mut UnboundedReceiver<Event>) -> Vec<Event> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
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
async fn close_sends_requested_disconnect_last_and_closes_the_socket() {
    let mock = start(MockConfig::default());
    let (session, mut rx) = connect_collect(config(&mock)).await;
    assert_eq!(
        wait_no_open_sockets(&mock, Duration::ZERO).await,
        1,
        "one socket open"
    );

    let started = std::time::Instant::now();
    session.close().await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "close must not hang"
    );

    let events = drain(&mut rx).await;
    assert_eq!(
        events.last(),
        Some(&Event::Disconnected {
            reason: DisconnectReason::Requested
        })
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::Disconnected { .. }))
            .count(),
        1
    );
    assert_eq!(
        wait_no_open_sockets(&mock, Duration::from_secs(3)).await,
        0,
        "socket closed"
    );
}

#[tokio::test]
async fn failed_renewals_end_the_session_and_close_the_socket() {
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
    let (session, mut rx) = connect_collect(cfg).await;
    let events = drain(&mut rx).await;
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

    assert_eq!(
        wait_no_open_sockets(&mock, Duration::from_secs(3)).await,
        0,
        "socket closed"
    );
    // Closing an already ended session is still fine.
    session.close().await;
}
