//! Sending commands, the queue for commands that cannot be sent yet, and requests that
//! wait for a reply.
//!
//! [`Shared`] is the sending side of a session. The session and the token refresh both
//! use it. Encryption, the ready flag and the queue share one lock, so the salt chain
//! stays in order. A request holds `request_lock`, so multi-step flows run one after another.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::time::Instant;

use crate::auth::enc::{ControlDecrypter, EncCipher};
use crate::protocol::ll::LlResponse;
use crate::session::login::random_salt;
use crate::session::reader::{Waiter, WaiterSlot};
use crate::session::{Event, SessionError};

/// How long a request waits for its reply.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// A command waiting for the connection to be ready.
#[derive(Debug)]
pub(crate) struct Pending {
    pub id: u64,
    pub command: String,
    pub queued_at: Instant,
}

/// Sending state, held under one lock.
pub(crate) struct Core {
    pub cipher: EncCipher,
    /// True once login and `enablebinstatusupdate` are done.
    pub ready: bool,
    pub queue: VecDeque<Pending>,
    pub next_id: u64,
}

impl Core {
    pub(crate) fn new(cipher: EncCipher) -> Self {
        Self {
            cipher,
            ready: false,
            queue: VecDeque::new(),
            next_id: 1,
        }
    }
}

/// How many events may wait for the callbacks before a warning is printed.
pub const BACKLOG_WARN_AT: usize = 1000;

/// Counts events that were handed over but not yet handled by the callbacks, and warns once
/// when the count crosses a threshold. The warning is repeated only after the count has
/// dropped to half the threshold again. Reading never waits for this.
pub(crate) struct Backlog {
    count: std::sync::atomic::AtomicUsize,
    warned: std::sync::atomic::AtomicBool,
    threshold: usize,
}

impl Backlog {
    pub(crate) fn new(threshold: usize) -> Self {
        Self {
            count: std::sync::atomic::AtomicUsize::new(0),
            warned: std::sync::atomic::AtomicBool::new(false),
            threshold,
        }
    }

    /// One event was handed over.
    pub(crate) fn added(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        let n = self.count.fetch_add(1, SeqCst) + 1;
        if n >= self.threshold && !self.warned.swap(true, SeqCst) {
            eprintln!(
                "rs-loxone: {n} events are waiting for the callbacks; the callbacks are slower than the connection"
            );
        }
    }

    /// One event was handled by the callbacks.
    pub(crate) fn done(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        let previous = self
            .count
            .try_update(SeqCst, SeqCst, |c| Some(c.saturating_sub(1)))
            .unwrap_or(0);
        let n = previous.saturating_sub(1);
        if n <= self.threshold / 2 {
            self.warned.store(false, SeqCst);
        }
    }

    /// Events waiting for the callbacks right now.
    pub(crate) fn waiting(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The sending side of a session, shared with the refresh task and the reader.
pub(crate) struct Shared {
    pub out: mpsc::Sender<String>,
    pub core: Mutex<Core>,
    pub events: mpsc::UnboundedSender<Event>,
    pub max_command_age: Duration,
    pub waiter: WaiterSlot,
    pub request_lock: Mutex<()>,
    /// Events waiting for the callbacks (for monitoring).
    pub backlog: Arc<Backlog>,
    /// Decrypts the replies to encrypted commands. Holds no salt state.
    pub decrypt: ControlDecrypter,
    /// Set to `true` to end the session (writer closes, reader reports).
    stop: tokio::sync::watch::Sender<bool>,
    /// Why the session is ending. Set once, before `stop` becomes `true`.
    stop_reason: std::sync::Mutex<Option<crate::session::DisconnectReason>>,
}

/// Split queued commands into those still fresh and those older than `max_age`.
/// Order is kept within both lists.
pub(crate) fn split_expired(
    queue: VecDeque<Pending>,
    now: Instant,
    max_age: Duration,
) -> (Vec<Pending>, Vec<(u64, Duration)>) {
    let mut fresh = Vec::new();
    let mut expired = Vec::new();
    for p in queue {
        let age = now.saturating_duration_since(p.queued_at);
        if age > max_age {
            expired.push((p.id, age));
        } else {
            fresh.push(p);
        }
    }
    (fresh, expired)
}

impl Shared {
    /// Create the shared sending state.
    pub(crate) fn new(
        out: mpsc::Sender<String>,
        cipher: EncCipher,
        events: mpsc::UnboundedSender<Event>,
        max_command_age: Duration,
        waiter: WaiterSlot,
        stop: tokio::sync::watch::Sender<bool>,
        backlog: Arc<Backlog>,
    ) -> Arc<Self> {
        let decrypt = cipher.decrypter();
        Arc::new(Self {
            backlog,
            decrypt,
            out,
            core: Mutex::new(Core::new(cipher)),
            events,
            max_command_age,
            waiter,
            request_lock: Mutex::new(()),
            stop,
            stop_reason: std::sync::Mutex::new(None),
        })
    }

    /// Receiver that becomes `true` when the session must stop.
    pub(crate) fn stop_signal(&self) -> tokio::sync::watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// The reason the session stops, if it has been set.
    pub(crate) fn stop_reason(&self) -> Option<crate::session::DisconnectReason> {
        self.stop_reason.lock().ok().and_then(|r| r.clone())
    }

    /// Ask the session to stop. The first reason wins.
    pub(crate) fn stop(&self, reason: crate::session::DisconnectReason) {
        if let Ok(mut r) = self.stop_reason.lock()
            && r.is_none()
        {
            *r = Some(reason);
        }
        let _ = self.stop.send(true);
    }

    /// Send an event to the callbacks. Never waits.
    pub(crate) fn emit(&self, event: Event) {
        self.backlog.added();
        if self.events.send(event).is_err() {
            self.backlog.done();
        }
    }

    /// Send a command, encrypted. Returns its id. Does not wait for a reply.
    /// If the session is not ready, the command is queued.
    pub async fn send_command(&self, command: &str) -> Result<u64, SessionError> {
        let mut core = self.core.lock().await;
        let id = core.next_id;
        core.next_id += 1;
        if core.ready {
            self.transmit(&mut core.cipher, command).await?;
        } else {
            core.queue.push_back(Pending {
                id,
                command: command.to_owned(),
                queued_at: Instant::now(),
            });
        }
        Ok(id)
    }

    /// Encrypt one command with the next salt and hand it to the writer.
    pub(crate) async fn transmit(
        &self,
        cipher: &mut EncCipher,
        command: &str,
    ) -> Result<(), SessionError> {
        let text = cipher.encrypt_command(command, &random_salt());
        self.out.send(text).await.map_err(|_| SessionError::Closed)
    }

    /// Mark the session ready and send the queued commands in order.
    /// Commands older than `max_command_age` are dropped and reported.
    pub(crate) async fn set_ready(&self) -> Result<(), SessionError> {
        let mut core = self.core.lock().await;
        core.ready = true;
        let queue = std::mem::take(&mut core.queue);
        let (fresh, expired) = split_expired(queue, Instant::now(), self.max_command_age);
        for (id, age) in expired {
            self.emit(Event::CommandDropped { id, age });
        }
        for p in fresh {
            self.transmit(&mut core.cipher, &p.command).await?;
        }
        Ok(())
    }

    /// Send an encrypted command and wait for a reply whose control contains any of
    /// `needles`. Requests run one at a time. The reply is not delivered as an event.
    pub async fn request(
        &self,
        command: &str,
        needles: &[&str],
    ) -> Result<LlResponse, SessionError> {
        self.request_inner(command, needles, true).await
    }

    /// Like [`Shared::request`], but the text is sent in plain (not encrypted), as for
    /// `jdev/sys/getkey`.
    pub async fn request_plain(
        &self,
        text: &str,
        needles: &[&str],
    ) -> Result<LlResponse, SessionError> {
        self.request_inner(text, needles, false).await
    }

    async fn request_inner(
        &self,
        text: &str,
        needles: &[&str],
        encrypted: bool,
    ) -> Result<LlResponse, SessionError> {
        let _turn = self.request_lock.lock().await;
        let (tx, rx) = oneshot::channel();
        {
            let mut slot = self.waiter.lock().map_err(|_| SessionError::Closed)?;
            slot.waiter = Some(Waiter {
                needles: needles.iter().map(|n| (*n).to_owned()).collect(),
                tx,
            });
        }
        let sent = {
            let mut core = self.core.lock().await;
            if !core.ready {
                Err(SessionError::NotAuthenticated)
            } else if encrypted {
                self.transmit(&mut core.cipher, text).await
            } else {
                self.out
                    .send(text.to_owned())
                    .await
                    .map_err(|_| SessionError::Closed)
            }
        };
        if let Err(err) = sent {
            self.clear_waiter(false);
            return Err(err);
        }
        let outcome = tokio::time::timeout(REQUEST_TIMEOUT, rx).await;
        self.clear_waiter(outcome.is_err());
        match outcome {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(SessionError::Closed),
            Err(_) => Err(SessionError::Timeout),
        }
    }

    /// Remove the waiter. If the request timed out, its reply may still come: its needles are
    /// kept, so that reply is dropped and cannot answer the next request.
    fn clear_waiter(&self, timed_out: bool) {
        if let Ok(mut slot) = self.waiter.lock()
            && let Some(waiter) = slot.waiter.take()
            && timed_out
        {
            slot.abandoned
                .push((waiter.needles, std::time::Instant::now()));
        }
    }
}

#[cfg(test)]
mod backlog_tests {
    use super::*;

    #[test]
    fn counts_waiting_events() {
        let b = Backlog::new(10);
        b.added();
        b.added();
        assert_eq!(b.waiting(), 2);
        b.done();
        assert_eq!(b.waiting(), 1);
    }

    #[test]
    fn warns_once_when_crossing_and_again_only_after_recovery() {
        let b = Backlog::new(4);
        for _ in 0..3 {
            b.added();
        }
        assert!(!b.warned.load(std::sync::atomic::Ordering::SeqCst));
        b.added(); // 4 = threshold: warned
        assert!(b.warned.load(std::sync::atomic::Ordering::SeqCst));
        b.added(); // still high: no second warning state change
        assert!(b.warned.load(std::sync::atomic::Ordering::SeqCst));
        for _ in 0..4 {
            b.done(); // down to 1: at or below half the threshold (2) -> reset
        }
        assert!(!b.warned.load(std::sync::atomic::Ordering::SeqCst));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(id: u64, queued_at: Instant) -> Pending {
        Pending {
            id,
            command: format!("cmd{id}"),
            queued_at,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn commands_older_than_the_limit_are_dropped_and_order_is_kept() {
        let t0 = Instant::now();
        tokio::time::advance(Duration::from_secs(10)).await;
        let q: VecDeque<Pending> = vec![
            pending(1, t0),
            pending(2, t0 + Duration::from_secs(5)),
            pending(3, t0),
        ]
        .into_iter()
        .collect();
        let (fresh, expired) = split_expired(q, Instant::now(), Duration::from_secs(8));
        let fresh_ids: Vec<u64> = fresh.iter().map(|p| p.id).collect();
        assert_eq!(fresh_ids, vec![2]);
        let expired_ids: Vec<u64> = expired.iter().map(|(id, _)| *id).collect();
        assert_eq!(expired_ids, vec![1, 3]);
    }

    #[tokio::test(start_paused = true)]
    async fn exactly_the_limit_is_still_sent() {
        let t0 = Instant::now();
        tokio::time::advance(Duration::from_secs(30)).await;
        let q: VecDeque<Pending> = vec![pending(1, t0)].into_iter().collect();
        let (fresh, expired) = split_expired(q, Instant::now(), Duration::from_secs(30));
        assert_eq!(fresh.len(), 1);
        assert!(expired.is_empty());
    }
}
