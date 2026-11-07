//! Keepalive and watchdog.
//!
//! One writer task owns the [`WsSender`](super::ws::WsSender). Commands and the
//! keepalive both send text into a channel, so there is only one writer. The
//! keepalive task sends `keepalive` every [`KEEPALIVE_PERIOD`]. If no inbound frame
//! arrived for longer than [`READ_TIMEOUT`], it reports `ConnectionLost` and stops.
//! It does not close the socket: the owner does that.

use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::TransportError;
use super::ws::{Activity, WsSender};

/// Seconds between keepalive commands (`KEEP_ALIVE_PERIOD`).
pub const KEEPALIVE_PERIOD: Duration = Duration::from_secs(30);
/// Silence after which the connection is considered lost (`WEBSOCKET_READ_TIMEOUT`).
pub const READ_TIMEOUT: Duration = Duration::from_secs(90);
/// Capacity of the outbound channel.
pub const OUTBOUND_CAPACITY: usize = 64;

/// Start the writer. Returns the channel to send text into, and the task handle.
///
/// The task ends when every sender is dropped (then it sends a close frame) or when
/// a write fails.
pub fn spawn_writer(
    mut sender: WsSender,
) -> (mpsc::Sender<String>, JoinHandle<Result<(), TransportError>>) {
    let (tx, mut rx) = mpsc::channel::<String>(OUTBOUND_CAPACITY);
    let handle = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            sender.send_text(&text).await?;
        }
        sender.close().await
    });
    (tx, handle)
}

/// Start the writer and stop it on `stop` (value `true`). On stop, the writer sends a close
/// frame and ends. Use this in sessions that must be closed on request.
pub fn spawn_writer_until(
    mut sender: WsSender,
    mut stop: watch::Receiver<bool>,
) -> (mpsc::Sender<String>, JoinHandle<Result<(), TransportError>>) {
    let (tx, mut rx) = mpsc::channel::<String>(OUTBOUND_CAPACITY);
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        break;
                    }
                }
                text = rx.recv() => match text {
                    Some(text) => sender.send_text(&text).await?,
                    None => break,
                },
            }
        }
        sender.close().await
    });
    (tx, handle)
}

/// Start the keepalive and watchdog. The task returns the reason it stopped.
pub fn spawn_keepalive(
    out: mpsc::Sender<String>,
    activity: Activity,
    period: Duration,
    read_timeout: Duration,
) -> JoinHandle<TransportError> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            let silence = activity.silence();
            if silence > read_timeout {
                return TransportError::ConnectionLost {
                    reason: format!(
                        "no inbound frame for {}s (limit {}s)",
                        silence.as_secs(),
                        read_timeout.as_secs()
                    ),
                };
            }
            if out
                .send(crate::auth::commands::keepalive().to_owned())
                .await
                .is_err()
            {
                return TransportError::Closed {
                    code: None,
                    reason: "writer stopped".into(),
                };
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn sends_keepalive_every_period() {
        let (tx, mut rx) = mpsc::channel::<String>(OUTBOUND_CAPACITY);
        let activity = Activity::new_for_test();
        let _task = spawn_keepalive(tx, activity.clone(), KEEPALIVE_PERIOD, READ_TIMEOUT);
        for _ in 0..3 {
            tokio::time::advance(KEEPALIVE_PERIOD).await;
            activity.touch();
            assert_eq!(rx.recv().await.as_deref(), Some("keepalive"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn silence_over_limit_reports_connection_lost() {
        let (tx, mut rx) = mpsc::channel::<String>(OUTBOUND_CAPACITY);
        let activity = Activity::new_for_test();
        let task = spawn_keepalive(tx, activity, KEEPALIVE_PERIOD, READ_TIMEOUT);
        // Ticks at 30, 60, 90 s send keepalive; the tick at 120 s sees 120 s of silence.
        let reason = task.await.unwrap();
        assert!(
            matches!(reason, TransportError::ConnectionLost { .. }),
            "{reason:?}"
        );
        let mut sent = 0;
        while rx.try_recv().is_ok() {
            sent += 1;
        }
        assert_eq!(sent, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_frames_keep_the_connection_alive() {
        let (tx, _rx) = mpsc::channel::<String>(OUTBOUND_CAPACITY);
        let activity = Activity::new_for_test();
        let task = spawn_keepalive(tx, activity.clone(), KEEPALIVE_PERIOD, READ_TIMEOUT);
        for _ in 0..10 {
            tokio::time::advance(Duration::from_secs(60)).await;
            activity.touch();
        }
        assert!(
            !task.is_finished(),
            "watchdog must not fire while frames arrive"
        );
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_stops_when_writer_is_gone() {
        let (tx, rx) = mpsc::channel::<String>(OUTBOUND_CAPACITY);
        drop(rx);
        let activity = Activity::new_for_test();
        let task = spawn_keepalive(tx, activity.clone(), KEEPALIVE_PERIOD, READ_TIMEOUT);
        tokio::time::advance(KEEPALIVE_PERIOD).await;
        activity.touch();
        let reason = task.await.unwrap();
        assert!(
            matches!(reason, TransportError::Closed { .. }),
            "{reason:?}"
        );
    }
}
