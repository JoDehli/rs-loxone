#![cfg(feature = "mock")]
//! The supervisor against the scripted mock Miniserver: reconnects, the outbox, and the
//! stop rules. These run in real time; the first reconnect waits about 5 s.

use std::time::Duration;

use rs_loxone::auth::Secret;
use rs_loxone::mock::{Mock, MockConfig, start};
use rs_loxone::session::{AsyncHandler, DisconnectReason, Event, RefreshPolicy, SessionConfig};
use rs_loxone::supervisor::outbox::Item;
use rs_loxone::supervisor::{self, SupervisorHandle};
use rs_loxone::transport::url::Endpoint;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

const USER: &str = "admin";
const PASSWORD: &str = "s3cret";

fn config(mock: &Mock, password: &str) -> SessionConfig {
    SessionConfig::new(
        Endpoint::parse(&format!("http://{}", mock.addr())).unwrap(),
        USER,
        Secret::new(password),
    )
}

/// Start a supervisor whose events go to a channel the test reads.
fn run(cfg: SessionConfig) -> (SupervisorHandle, UnboundedReceiver<Event>) {
    let (tx, rx) = unbounded_channel();
    let handler = AsyncHandler(move |e: Event| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(e);
        }
    });
    (supervisor::start(cfg, handler), rx)
}

/// Next event, or fail after 20 s.
async fn next(rx: &mut UnboundedReceiver<Event>) -> Event {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("timeout waiting for an event")
        .expect("event channel closed")
}

/// Events up to and including the first one that matches `done`.
async fn until(rx: &mut UnboundedReceiver<Event>, done: impl Fn(&Event) -> bool) -> Vec<Event> {
    let mut seen = Vec::new();
    loop {
        let e = next(rx).await;
        let stop = done(&e);
        seen.push(e);
        if stop {
            return seen;
        }
    }
}

/// How many times the mock received exactly `name` (commands are matched by name).
fn count(mock: &Mock, name: &str) -> usize {
    mock.seen().iter().filter(|s| s.as_str() == name).count()
}

#[tokio::test]
async fn reconnects_after_the_connection_drops() {
    let mock = start(MockConfig {
        close_after_enable: Some(1000),
        close_first_enables: Some(1),
        ..MockConfig::default()
    });
    let (handle, mut rx) = run(config(&mock, PASSWORD));

    let first = until(&mut rx, |e| matches!(e, Event::Connected)).await;
    assert!(matches!(first.last(), Some(Event::Connected)));

    let dropped = until(&mut rx, |e| matches!(e, Event::Disconnected { .. })).await;
    assert!(matches!(dropped.last(), Some(Event::Disconnected { .. })));

    match next(&mut rx).await {
        Event::Reconnecting { attempt, wait, .. } => {
            assert_eq!(attempt, 1);
            assert!(wait >= Duration::from_secs(4) && wait <= Duration::from_secs(6));
        }
        other => panic!("expected Reconnecting, got {other:?}"),
    }

    // The second session comes up and stays up.
    until(&mut rx, |e| matches!(e, Event::Connected)).await;
    handle.close();
    until(&mut rx, |e| matches!(e, Event::Disconnected { .. })).await;
}

#[tokio::test]
async fn command_queued_while_disconnected_is_sent_once_after_reconnect() {
    let mock = start(MockConfig {
        close_after_enable: Some(1000),
        close_first_enables: Some(1),
        ..MockConfig::default()
    });
    let (handle, mut rx) = run(config(&mock, PASSWORD));
    until(&mut rx, |e| matches!(e, Event::Connected)).await;
    until(&mut rx, |e| matches!(e, Event::Reconnecting { .. })).await;

    // Sent while the supervisor waits to reconnect: it must wait in the outbox.
    handle
        .send(Item::Command("jdev/sps/io/test-uuid/on".into()))
        .unwrap();

    until(&mut rx, |e| matches!(e, Event::Connected)).await;
    // Give the second session time to process anything it might resend.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        count(&mock, "jdev/sps/io"),
        1,
        "delivered exactly once; seen: {:?}",
        mock.seen()
    );
    handle.close();
}

#[tokio::test]
async fn command_older_than_max_age_is_dropped_and_reported() {
    let mock = start(MockConfig::default());
    let mut cfg = config(&mock, PASSWORD);
    cfg.max_command_age = Duration::ZERO;
    let (handle, mut rx) = run(cfg);
    let id = handle
        .send(Item::Command("jdev/sps/io/test-uuid/on".into()))
        .unwrap();

    let seen = until(&mut rx, |e| matches!(e, Event::Connected)).await;
    assert!(
        seen.iter()
            .any(|e| matches!(e, Event::CommandDropped { id: dropped, .. } if *dropped == id)),
        "no CommandDropped for id {id}: {seen:?}"
    );
    assert_eq!(count(&mock, "jdev/sps/io"), 0, "not sent");
    handle.close();
}

#[tokio::test]
async fn wrong_password_gives_up_without_retrying() {
    let mock = start(MockConfig::default());
    let (_handle, mut rx) = run(config(&mock, "wrong"));

    let seen = until(&mut rx, |e| matches!(e, Event::GaveUp { .. })).await;
    assert!(
        !seen.iter().any(|e| matches!(e, Event::Reconnecting { .. })),
        "must not retry a refused password"
    );
    // Nothing else follows: the supervisor has stopped.
    let rest = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    assert!(
        !matches!(rest, Ok(Some(_))),
        "unexpected event after GaveUp"
    );
    assert_eq!(
        count(&mock, "jdev/sys/getjwt"),
        1,
        "exactly one password login"
    );
}

#[tokio::test]
async fn close_ends_with_requested_and_does_not_reconnect() {
    let mock = start(MockConfig::default());
    let (handle, mut rx) = run(config(&mock, PASSWORD));
    until(&mut rx, |e| matches!(e, Event::Connected)).await;

    handle.close();
    let seen = until(&mut rx, |e| matches!(e, Event::Disconnected { .. })).await;
    assert!(matches!(
        seen.last(),
        Some(Event::Disconnected {
            reason: DisconnectReason::Requested
        })
    ));

    let rest = tokio::time::timeout(Duration::from_secs(7), rx.recv()).await;
    assert!(!matches!(rest, Ok(Some(_))), "no reconnect after close");
    // The mock notices the close frame a moment later.
    for _ in 0..50 {
        if mock.open_ws_connections() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(mock.open_ws_connections(), 0, "socket closed");
}

#[tokio::test]
async fn send_after_stop_reports_stopped() {
    let mock = start(MockConfig::default());
    let (handle, mut rx) = run(config(&mock, PASSWORD));
    until(&mut rx, |e| matches!(e, Event::Connected)).await;
    handle.close();
    until(&mut rx, |e| matches!(e, Event::Disconnected { .. })).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(handle.send(Item::Command("x".into())).is_err());
}

#[tokio::test]
async fn token_renewal_refused_after_password_login_gives_up() {
    // The Miniserver refuses renewal and issues tokens that expire at once, so every
    // session ends with AuthFailed.
    let mock = start(MockConfig {
        refuse_refresh: true,
        token_lifetime_secs: 3,
        ..MockConfig::default()
    });
    let mut cfg = config(&mock, PASSWORD);
    cfg.refresh = RefreshPolicy {
        attempts: 1,
        attempt_delay: Duration::ZERO,
        max_failed_cycles: 1,
        failed_cycle_wait: Duration::ZERO,
    };
    let (_handle, mut rx) = run(cfg);

    let seen = until(&mut rx, |e| matches!(e, Event::GaveUp { .. })).await;
    let auth_failures = seen
        .iter()
        .filter(|e| matches!(e, Event::AuthFailed { .. }))
        .count();
    assert_eq!(auth_failures, 2, "two sessions ended with AuthFailed");
    assert!(
        seen.iter().any(|e| matches!(e, Event::Reconnecting { .. })),
        "one retry before giving up"
    );
    assert_eq!(
        count(&mock, "jdev/sys/getjwt"),
        2,
        "the retry used the password, not the token"
    );
}

#[tokio::test]
async fn refused_secured_command_is_reported_without_its_code() {
    let mock = start(MockConfig::default());
    let (handle, mut rx) = run(config(&mock, PASSWORD));
    let id = handle
        .send(Item::Secured {
            device_uuid: "5a5a5a5a-1111-2222-ffff403fb0c34b9e".into(),
            value: "off".into(),
            code: zeroize::Zeroizing::new("0000".into()),
        })
        .unwrap();

    let seen = until(&mut rx, |e| matches!(e, Event::CommandFailed { .. })).await;
    let failed = seen.last().unwrap();
    match failed {
        Event::CommandFailed {
            id: failed_id,
            reason,
        } => {
            assert_eq!(*failed_id, id);
            assert!(reason.contains("visualization"), "{reason}");
            assert!(!reason.contains("0000"), "the code must not appear");
        }
        other => panic!("expected CommandFailed, got {other:?}"),
    }
    handle.close();
}

#[tokio::test]
async fn user_disabled_close_gives_up_without_retrying() {
    // The Miniserver closes every session with 4006 (user disabled or changed).
    let mock = start(MockConfig {
        close_after_enable: Some(4006),
        ..MockConfig::default()
    });
    let (_handle, mut rx) = run(config(&mock, PASSWORD));

    let seen = until(&mut rx, |e| matches!(e, Event::GaveUp { .. })).await;
    assert!(
        !seen.iter().any(|e| matches!(e, Event::Reconnecting { .. })),
        "must not retry a disabled user"
    );
    assert_eq!(count(&mock, "jdev/sys/getjwt"), 1, "exactly one login");
}

#[tokio::test]
async fn blocked_user_close_gives_up_without_retrying() {
    // The Miniserver closes every session with 4003 (user blocked after failed logins).
    let mock = start(MockConfig {
        close_after_enable: Some(4003),
        ..MockConfig::default()
    });
    let (_handle, mut rx) = run(config(&mock, PASSWORD));

    let seen = until(&mut rx, |e| matches!(e, Event::GaveUp { .. })).await;
    assert!(
        !seen.iter().any(|e| matches!(e, Event::Reconnecting { .. })),
        "must not retry a blocked user"
    );
    assert_eq!(count(&mock, "jdev/sys/getjwt"), 1, "exactly one login");
}

#[tokio::test]
async fn maintenance_close_waits_five_minutes_before_reconnecting() {
    // The first session is closed with 4007 (Miniserver going down); the next one is fine.
    let mock = start(MockConfig {
        close_after_enable: Some(4007),
        close_first_enables: Some(1),
        ..MockConfig::default()
    });
    let (handle, mut rx) = run(config(&mock, PASSWORD));

    let seen = until(&mut rx, |e| matches!(e, Event::Reconnecting { .. })).await;
    let wait = seen
        .iter()
        .find_map(|e| match e {
            Event::Reconnecting { wait, .. } => Some(*wait),
            _ => None,
        })
        .expect("a Reconnecting event");
    // 300 s with ±20 % jitter.
    assert!(
        wait >= Duration::from_secs(240) && wait <= Duration::from_secs(360),
        "wait was {wait:?}"
    );
    handle.close();
}
