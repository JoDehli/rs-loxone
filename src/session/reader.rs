//! The reader task. It only reads frames and hands events over. It never waits for a
//! callback, so reading is never slowed down by user code.
//!
//! The reader is also the place where a session ends: it sends the last `Disconnected`
//! event, stops the keepalive, and tells the writer to close the connection.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use crate::protocol::header::MessageKind;
use crate::protocol::ll::LlResponse;
use crate::protocol::message::Message;
use crate::session::Event;
use crate::session::commands::Shared;
use crate::session::event::DisconnectReason;
use crate::session::frames::FramePairer;
use crate::transport::TransportError;
use crate::transport::ws::WsReceiver;

/// A request waiting for its reply: the reply goes to `tx` if its control contains one of
/// `needles`.
pub(crate) struct Waiter {
    pub needles: Vec<String>,
    pub tx: tokio::sync::oneshot::Sender<LlResponse>,
}

/// How long a reply to a timed-out request is still expected. A reply that never comes must
/// not swallow the replies to later requests.
pub(crate) const ABANDONED_FOR: Duration = Duration::from_secs(30);

/// State shared between requests and the reader. Never held across an await.
#[derive(Default)]
pub(crate) struct Slot {
    /// The request that waits for a reply, if any.
    pub waiter: Option<Waiter>,
    /// Requests that timed out, with their needles and the time they were abandoned. A late
    /// reply that matches one of them is dropped, so it cannot answer the next request.
    pub abandoned: Vec<(Vec<String>, Instant)>,
}

pub(crate) type WaiterSlot = Arc<std::sync::Mutex<Slot>>;

fn matches_any(needles: &[String], ll: &LlResponse) -> bool {
    needles.iter().any(|n| ll.control.contains(n.as_str()))
}

/// Hand the reply to the waiting request if it matches. A reply that matches an abandoned
/// request is dropped (and counts as claimed).
fn claim(slot: &WaiterSlot, ll: &LlResponse, now: Instant) -> bool {
    let Ok(mut slot) = slot.lock() else {
        return false;
    };
    slot.abandoned
        .retain(|(_, since)| now.duration_since(*since) < ABANDONED_FOR);
    if let Some(i) = slot
        .abandoned
        .iter()
        .position(|(needles, _)| matches_any(needles, ll))
    {
        slot.abandoned.remove(i);
        return true;
    }
    let matches = slot
        .waiter
        .as_ref()
        .is_some_and(|w| matches_any(&w.needles, ll));
    if matches && let Some(waiter) = slot.waiter.take() {
        let _ = waiter.tx.send(ll.clone());
    }
    matches
}

/// Replies to encrypted commands carry `jdev/sys/enc/<base64>` as the control. Replace it
/// with the plain control, so the reply can be matched by command name.
pub(crate) fn reveal_control(decrypt: &crate::auth::enc::ControlDecrypter, ll: &mut LlResponse) {
    if !ll.control.starts_with("jdev/sys/enc/") {
        return;
    }
    match decrypt.reveal(&ll.control) {
        Ok(control) => ll.control = control,
        Err(err) => eprintln!("rs-loxone: skipping a reply that does not decrypt: {err}"),
    }
}

/// Map a decoded message to an event. Keepalive replies produce no event.
pub fn map_message(message: Message) -> Option<Event> {
    Some(match message {
        Message::Text(ll) => Event::Text(ll),
        Message::Binary(bytes) => Event::Raw {
            kind: MessageKind::Binary,
            bytes,
        },
        Message::ValueStates(values) => Event::ValueStates(values),
        Message::TextStates(texts) => Event::TextStates(texts),
        Message::Daytimer(bytes) => Event::Raw {
            kind: MessageKind::Daytimer,
            bytes,
        },
        Message::Weather(bytes) => Event::Raw {
            kind: MessageKind::Weather,
            bytes,
        },
        Message::OutOfService => Event::Disconnected {
            reason: DisconnectReason::OutOfService,
        },
        Message::Keepalive => return None,
    })
}

/// Why the connection ended, from a transport error.
pub fn reason_from_transport(err: &TransportError) -> DisconnectReason {
    match err {
        TransportError::Closed { code, .. } => DisconnectReason::Closed(*code),
        other => DisconnectReason::Lost(other.to_string()),
    }
}

/// End the session: record the reason (writer closes), stop the keepalive and deliver the
/// last `Disconnected` event.
fn finish(shared: &Shared, keepalive: &JoinHandle<TransportError>, reason: DisconnectReason) {
    // A reason recorded earlier (close, or a refresh that gave up) takes precedence over the
    // error the socket reports while it is shutting down.
    let reason = shared.stop_reason().unwrap_or(reason);
    shared.stop(reason.clone());
    keepalive.abort();
    shared.emit(Event::Disconnected { reason });
}

/// Read until the session ends. Sends `Disconnected` as the last event.
pub(crate) async fn run(
    mut receiver: WsReceiver,
    shared: Arc<Shared>,
    mut keepalive: JoinHandle<TransportError>,
) {
    let mut pairer = FramePairer::default();
    let mut stop = shared.stop_signal();
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    // Asked to stop (close, or a refresh gave up). Use the recorded reason.
                    let reason = shared.stop_reason().unwrap_or(DisconnectReason::Requested);
                    keepalive.abort();
                    shared.emit(Event::Disconnected { reason });
                    return;
                }
            }
            frame = receiver.next_frame() => match frame {
                Ok(Some(frame)) => match pairer.push(frame) {
                    Ok(Some(mut message)) => {
                        if let Message::Text(ll) = &mut message {
                            reveal_control(&shared.decrypt, ll);
                        }
                        if let Message::Text(ll) = &message
                            && claim(&shared.waiter, ll, Instant::now())
                        {
                            continue;
                        }
                        if let Some(event) = map_message(message) {
                            if let Event::Disconnected { reason } = event {
                                finish(&shared, &keepalive, reason);
                                return;
                            }
                            shared.emit(event);
                        }
                    }
                    Ok(None) => {}
                    Err(err) => eprintln!("rs-loxone: skipping undecodable frame: {err}"),
                },
                Ok(None) => {
                    finish(&shared, &keepalive, DisconnectReason::Closed(None));
                    return;
                }
                Err(err) => {
                    finish(&shared, &keepalive, reason_from_transport(&err));
                    return;
                }
            },
            ended = &mut keepalive => {
                let reason = match ended {
                    Ok(err) => reason_from_transport(&err),
                    Err(_) => DisconnectReason::Lost("keepalive task failed".into()),
                };
                shared.stop(reason.clone());
                shared.emit(Event::Disconnected { reason });
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(control: &str) -> LlResponse {
        let json = format!(r#"{{"LL": {{"control": "{control}", "code": 200, "value": ""}}}}"#);
        LlResponse::parse(json.as_bytes()).unwrap()
    }

    fn waiter_for(needle: &str) -> (Waiter, tokio::sync::oneshot::Receiver<LlResponse>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let waiter = Waiter {
            needles: vec![needle.to_owned()],
            tx,
        };
        (waiter, rx)
    }

    fn slot_waiting_for(needle: &str) -> (WaiterSlot, tokio::sync::oneshot::Receiver<LlResponse>) {
        let (waiter, rx) = waiter_for(needle);
        let slot: WaiterSlot = Arc::new(std::sync::Mutex::new(Slot {
            waiter: Some(waiter),
            ..Slot::default()
        }));
        (slot, rx)
    }

    /// What `Shared::request` does when its reply times out: the waiter is moved to the
    /// abandoned list.
    fn time_out_current(slot: &WaiterSlot, since: Instant) {
        let mut s = slot.lock().unwrap();
        let waiter = s.waiter.take().unwrap();
        s.abandoned.push((waiter.needles, since));
    }

    #[test]
    fn matching_reply_is_claimed() {
        let (slot, mut rx) = slot_waiting_for("refreshjwt");
        assert!(claim(
            &slot,
            &reply("jdev/sys/refreshjwt/abc/admin"),
            Instant::now()
        ));
        assert_eq!(rx.try_recv().unwrap().code, 200);
        assert!(slot.lock().unwrap().waiter.is_none());
    }

    #[test]
    fn unrelated_encrypted_reply_is_not_claimed() {
        let (slot, _rx) = slot_waiting_for("refreshjwt");
        assert!(!claim(&slot, &reply("jdev/sps/ios/uuid/1"), Instant::now()));
        assert!(slot.lock().unwrap().waiter.is_some());
    }

    #[test]
    fn late_reply_does_not_answer_the_next_request() {
        // Request A times out, then request B waits for the same reply type. A's late
        // reply arrives first. It must not answer B.
        let now = Instant::now();
        let (slot, _rx_a) = slot_waiting_for("getvisusalt");
        time_out_current(&slot, now);
        let (waiter_b, mut rx_b) = waiter_for("getvisusalt");
        slot.lock().unwrap().waiter = Some(waiter_b);

        assert!(claim(&slot, &reply("getvisusalt/0a0b"), now));
        assert!(
            rx_b.try_recv().is_err(),
            "the late reply answered request B"
        );
        assert!(claim(&slot, &reply("getvisusalt/0c0d"), now));
        assert!(rx_b.try_recv().is_ok(), "B's own reply did not reach B");
    }

    #[test]
    fn lost_reply_does_not_swallow_later_replies_forever() {
        // A's reply never came. Long after the timeout, B's reply must reach B.
        let t0 = Instant::now();
        let (slot, _rx_a) = slot_waiting_for("getvisusalt");
        time_out_current(&slot, t0);
        let (waiter_b, mut rx_b) = waiter_for("getvisusalt");
        slot.lock().unwrap().waiter = Some(waiter_b);

        let later = t0 + ABANDONED_FOR + Duration::from_secs(1);
        assert!(claim(&slot, &reply("getvisusalt/0c0d"), later));
        assert!(rx_b.try_recv().is_ok());
    }
}
