//! A fake alarm control on the mock, with the same commands and answers as the real
//! alarm: `on/1` arms it, `off` disarms it, a wrong visualization code is refused.
//! No real Miniserver is involved; the device UUID and state bytes are made up.

use std::time::Duration;

use loxone_mock::{FakeAlarm, Mock, MockConfig, start};
use rs_loxone::auth::Secret;
use rs_loxone::protocol::Uuid;
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig, SessionError};
use rs_loxone::transport::url::Endpoint;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

const ALARM: &str = "5a5a5a5a-1111-2222-ffff403fb0c34b9e";
const ARMED: [u8; 16] = [0x42; 16];
const CODE: &str = "1234";

fn mock() -> Mock {
    start(MockConfig {
        alarm: Some(FakeAlarm {
            uuid: ALARM.into(),
            armed_state: ARMED,
        }),
        ..MockConfig::default()
    })
}

/// Connect; the returned channel gets the `armed` value every time it is pushed.
async fn connect(mock: &Mock) -> (Session, UnboundedReceiver<f64>) {
    let (tx, rx) = unbounded_channel();
    let armed = Uuid::from_loxone_bytes(ARMED);
    let handler = AsyncHandler(move |e: Event| {
        let tx = tx.clone();
        async move {
            if let Event::ValueStates(values) = e {
                for (uuid, value) in values {
                    if uuid == armed {
                        let _ = tx.send(value);
                    }
                }
            }
        }
    });
    let cfg = SessionConfig::new(
        Endpoint::parse(&format!("http://{}", mock.addr())).unwrap(),
        "admin",
        Secret::new("s3cret"),
    );
    (Session::connect(cfg, handler).await.unwrap(), rx)
}

async fn next_armed(rx: &mut UnboundedReceiver<f64>) -> f64 {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout waiting for the armed state")
        .expect("channel closed")
}

#[tokio::test]
async fn arm_then_disarm_changes_the_armed_state() {
    let mock = mock();
    let (session, mut armed) = connect(&mock).await;

    session.send_secured(ALARM, "on/1", CODE).await.unwrap();
    assert_eq!(next_armed(&mut armed).await, 1.0, "armed after on/1");

    session.send_secured(ALARM, "off", CODE).await.unwrap();
    assert_eq!(next_armed(&mut armed).await, 0.0, "disarmed after off");
}

#[tokio::test]
async fn wrong_code_is_refused_and_changes_nothing() {
    let mock = mock();
    let (session, mut armed) = connect(&mock).await;

    let err = session
        .send_secured(ALARM, "on/1", "0000")
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::WrongVisuCode), "{err:?}");

    // Nothing was pushed: the state is still the initial one (no value change event).
    let quiet = tokio::time::timeout(Duration::from_millis(500), armed.recv()).await;
    assert!(quiet.is_err(), "no armed change after a refused command");
}

#[tokio::test]
async fn visualization_code_is_checked_without_changing_the_alarm() {
    let mock = mock();
    let (session, mut armed) = connect(&mock).await;

    assert!(session.check_visu_code(CODE).await.unwrap());
    assert!(!session.check_visu_code("0000").await.unwrap());
    let quiet = tokio::time::timeout(Duration::from_millis(500), armed.recv()).await;
    assert!(quiet.is_err(), "checking a code changes nothing");
}
