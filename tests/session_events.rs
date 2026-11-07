//! Events and callbacks: order, sync and async handlers, end of connection, and a
//! blocked callback that must not stop the connection from being set up.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use loxone_mock::{Mock, MockConfig, start};
use rs_loxone::auth::Secret;
use rs_loxone::protocol::uuid::Uuid;
use rs_loxone::session::{
    AsyncHandler, DisconnectReason, Event, Session, SessionConfig, SyncHandler,
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

/// Collect all events until `Disconnected` (or until `limit` events).
async fn collect_until_end(mut rx: UnboundedReceiver<Event>) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
        let end = matches!(e, Event::Disconnected { .. });
        out.push(e);
        if end {
            break;
        }
    }
    out
}

fn uuid(byte: u8) -> [u8; 16] {
    [byte; 16]
}

#[tokio::test]
async fn async_handler_gets_connected_then_states_in_order() {
    let u1 = uuid(0x11);
    let u2 = uuid(0x22);
    let mock = start(MockConfig {
        initial_states: vec![(u1, 1.5), (u2, -2.0)],
        ..MockConfig::default()
    });
    let (tx, rx) = unbounded_channel();
    let handler = AsyncHandler(move |e: Event| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(e);
        }
    });
    let _session = Session::connect(config(&mock), handler).await.unwrap();

    // Events: TokenChanged, Connected, the Text reply to enablebinstatusupdate, ValueStates.
    let mut rx = rx;
    let mut events = Vec::new();
    for _ in 0..4 {
        events.push(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert!(matches!(events[0], Event::TokenChanged(_)));
    assert_eq!(events[1], Event::Connected);
    assert!(
        matches!(events[2], Event::Text(_)),
        "enable reply is a text reply"
    );
    match &events[3] {
        Event::ValueStates(v) => {
            assert_eq!(v.len(), 2);
            assert_eq!(v[0].0, Uuid::from_loxone_bytes(u1));
            assert_eq!(v[0].1, 1.5);
            assert_eq!(v[1].0, Uuid::from_loxone_bytes(u2));
            assert_eq!(v[1].1, -2.0);
        }
        other => panic!("expected ValueStates, got {other:?}"),
    }
}

#[tokio::test]
async fn sync_handler_gets_the_same_events() {
    let mock = start(MockConfig {
        initial_states: vec![(uuid(0x33), 7.0)],
        ..MockConfig::default()
    });
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let handler = SyncHandler(move |e: Event| {
        let name = match e {
            Event::TokenChanged(_) => "token",
            Event::Connected => "connected",
            Event::ValueStates(_) => "values",
            Event::Disconnected { .. } => "disconnected",
            _ => "other",
        };
        sink.lock().unwrap().push(name.to_string());
    });
    let _session = Session::connect(config(&mock), handler).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // "other" is the Text reply to enablebinstatusupdate, delivered in order.
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["token", "connected", "other", "values"]
    );
}

#[tokio::test]
async fn closed_connection_ends_with_disconnected_as_last_event() {
    let mock = start(MockConfig {
        close_after_enable: Some(4003),
        ..MockConfig::default()
    });
    let (tx, rx) = unbounded_channel();
    let handler = AsyncHandler(move |e: Event| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(e);
        }
    });
    let _session = Session::connect(config(&mock), handler).await.unwrap();
    let events = collect_until_end(rx).await;
    assert_eq!(
        events.last(),
        Some(&Event::Disconnected {
            reason: DisconnectReason::Closed(Some(4003))
        })
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::Disconnected { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn blocked_callback_does_not_stop_the_connection_setup() {
    let mock = start(MockConfig::default());
    // The handler blocks for a long time on its first event.
    let handler = AsyncHandler(move |_e: Event| async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let started = std::time::Instant::now();
    let _session = tokio::time::timeout(
        Duration::from_secs(5),
        Session::connect(config(&mock), handler),
    )
    .await
    .expect("connect must not wait for the callback")
    .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn event_backlog_returns_to_zero_once_callbacks_have_run() {
    let mock = start(MockConfig {
        initial_states: vec![(uuid(0x44), 3.0)],
        ..MockConfig::default()
    });
    let handler = AsyncHandler(|_e: Event| async {});
    let session = Session::connect(config(&mock), handler).await.unwrap();
    let mut zero = false;
    for _ in 0..100 {
        if session.event_backlog() == 0 {
            zero = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(zero, "backlog did not drain");
}
