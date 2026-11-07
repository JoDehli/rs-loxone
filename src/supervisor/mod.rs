//! Keeps one Miniserver connection alive: reconnects, the outbox of commands, and
//! authentication escalation. Built on [`session`](crate::session).
//!
//! The supervisor runs three tasks: a dispatcher that calls the caller's handler in
//! order, a runner that opens and watches sessions, and the caller's [`SupervisorHandle`].
//! Sessions hand their events to the dispatcher through a channel that never blocks.

pub mod backoff;
pub mod outbox;

use std::future::Future;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::FutureExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::Instant;

use crate::auth::token::TokenState;
use crate::session::{DisconnectReason, Event, EventHandler, Session, SessionConfig, SessionError};
use outbox::{Item, Outbox, Queued};

/// Close codes after which reconnecting cannot succeed: 4003 (user blocked after too many
/// failed logins; every retry can extend the block) and 4006 (user disabled or changed).
const FATAL_CLOSE_CODES: [u16; 2] = [4003, 4006];

/// The supervisor has stopped and takes no more commands.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SupervisorError {
    /// The supervisor ended (closed, or gave up reconnecting).
    #[error("the supervisor has stopped")]
    Stopped,
}

/// Messages from the handle to the runner.
enum Control {
    Send { id: u64, item: Item, at: Instant },
    Close,
}

/// The caller's side of a running supervisor. Cheap to clone.
#[derive(Clone)]
pub struct SupervisorHandle {
    control: UnboundedSender<Control>,
    next_id: Arc<AtomicU64>,
}

impl SupervisorHandle {
    /// Queue or send a command. Returns the id that a later `CommandDropped` event uses.
    /// Never waits for the network.
    pub fn send(&self, item: Item) -> Result<u64, SupervisorError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.control
            .send(Control::Send {
                id,
                item,
                at: Instant::now(),
            })
            .map_err(|_| SupervisorError::Stopped)?;
        Ok(id)
    }

    /// Stop reconnecting and close the connection. The last event is
    /// `Disconnected { reason: Requested }`.
    pub fn close(&self) {
        let _ = self.control.send(Control::Close);
    }
}

/// Start a supervisor. Returns at once; the first connection is made in the background,
/// and its outcome arrives as events. Must be called inside a Tokio runtime.
pub fn start<H: EventHandler>(mut cfg: SessionConfig, handler: H) -> SupervisorHandle {
    let (events_tx, events_rx) = unbounded_channel();
    let (control_tx, control_rx) = unbounded_channel();
    tokio::spawn(dispatch(events_rx, handler));
    // A token from the file is used only when the caller gave none.
    if cfg.token.is_none()
        && let Some(file) = &cfg.token_file
    {
        cfg.token = file.load(&cfg.endpoint, &cfg.username);
    }
    let runner = Runner {
        outbox: Outbox::new(cfg.max_command_age),
        token: cfg.token.clone(),
        cfg,
        control: control_rx,
        events: events_tx,
        failed: 0,
        auth_failures: 0,
        force_password: false,
    };
    tokio::spawn(runner.run());
    SupervisorHandle {
        control: control_tx,
        next_id: Arc::new(AtomicU64::new(0)),
    }
}

/// Calls the handler for each event, in order. A panic in the handler is caught and the
/// event is skipped, so the loop keeps running.
async fn dispatch<H: EventHandler>(mut events: UnboundedReceiver<Event>, mut handler: H) {
    while let Some(event) = events.recv().await {
        if std::panic::AssertUnwindSafe(handler.handle(event))
            .catch_unwind()
            .await
            .is_err()
        {
            eprintln!("rs-loxone: an event callback panicked; the event was skipped");
        }
    }
}

/// Forwards a session's events to the supervisor's dispatcher. Never blocks. Once the
/// session's `Disconnected` has been forwarded, it signals the runner, so the runner's own
/// events (such as `Reconnecting`) come after it in the stream.
struct Forward {
    events: UnboundedSender<Event>,
    done: Option<tokio::sync::oneshot::Sender<()>>,
}

impl EventHandler for Forward {
    fn handle(&mut self, event: Event) -> impl Future<Output = ()> + Send {
        let ended = matches!(event, Event::Disconnected { .. });
        let _ = self.events.send(event);
        if ended && let Some(done) = self.done.take() {
            let _ = done.send(());
        }
        std::future::ready(())
    }
}

/// How one session ended, from the runner's point of view.
enum Served {
    /// The session ended by itself, with this reason.
    Ended(DisconnectReason),
    /// The caller closed the supervisor (or dropped every handle).
    Closed,
}

struct Runner {
    cfg: SessionConfig,
    control: UnboundedReceiver<Control>,
    events: UnboundedSender<Event>,
    outbox: Outbox,
    /// Newest token, passed to the next session so it can log in without the password.
    token: Option<TokenState>,
    /// Failed connection attempts (or lost sessions) in a row.
    failed: u32,
    /// Token renewal failures in a row.
    auth_failures: u32,
    /// Next login uses the password, not the stored token.
    force_password: bool,
}

impl Runner {
    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    async fn run(mut self) {
        loop {
            let mut cfg = self.cfg.clone();
            cfg.token = if self.force_password {
                None
            } else {
                self.token.clone()
            };
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let forward = Forward {
                events: self.events.clone(),
                done: Some(done_tx),
            };
            let offered_token = cfg.token.is_some();
            let session = match Session::connect(cfg, forward).await {
                Ok(session) => session,
                // The Miniserver refused the login. Retrying would only repeat the refusal.
                // The Miniserver is not local and the caller asked for a local one.
                Err(SessionError::NotLocal) => {
                    self.emit(Event::GaveUp {
                        reason: "the Miniserver sees this connection as remote".into(),
                    });
                    return;
                }
                Err(SessionError::Rejected { .. }) => {
                    self.emit(Event::GaveUp {
                        reason: "the Miniserver refused the login".into(),
                    });
                    return;
                }
                Err(err) => {
                    // The login failed. If it had a stored token, the token may be the reason (the
                    // Miniserver can drop the socket instead of answering), so the next attempt
                    // uses the password. Otherwise every retry would present the same token.
                    if offered_token {
                        self.force_password = true;
                    }
                    let long = matches!(
                        err,
                        SessionError::Rejected { code, .. } if backoff::is_long_wait_code(code)
                    ) || matches!(err, SessionError::NoEventSlots);
                    if self
                        .wait_before_retry(err.to_string(), long)
                        .await
                        .is_break()
                    {
                        return;
                    }
                    continue;
                }
            };
            self.force_password = false;
            let up_since = Instant::now();

            let served = self.serve(&session).await;
            if matches!(served, Served::Ended(_)) {
                // Wait until the session's own Disconnected has passed through `Forward`.
                let _ = tokio::time::timeout(Duration::from_secs(5), done_rx).await;
            }
            self.token = Some(session.token());
            if up_since.elapsed() >= backoff::STABLE_AFTER {
                self.failed = 0;
                self.auth_failures = 0;
            }
            match served {
                Served::Closed => {
                    session.close().await;
                    return;
                }
                Served::Ended(DisconnectReason::Requested) => return,
                Served::Ended(DisconnectReason::AuthFailed) => {
                    self.auth_failures += 1;
                    if self.auth_failures >= 2 {
                        self.emit(Event::GaveUp {
                            reason: "token renewal failed again after a password login".into(),
                        });
                        return;
                    }
                    self.force_password = true;
                    if self
                        .wait_before_retry("token renewal failed".into(), false)
                        .await
                        .is_break()
                    {
                        return;
                    }
                }
                // Blocked or disabled user: like the refused login above, retrying would only
                // repeat the refusal (or extend the block).
                Served::Ended(DisconnectReason::Closed(Some(code)))
                    if FATAL_CLOSE_CODES.contains(&code) =>
                {
                    self.emit(Event::GaveUp {
                        reason: format!("the Miniserver closed the connection with code {code}"),
                    });
                    return;
                }
                Served::Ended(reason) => {
                    let long = matches!(
                        reason,
                        DisconnectReason::Closed(Some(code)) if backoff::is_long_wait_code(i64::from(code))
                    );
                    if self
                        .wait_before_retry(format!("connection ended: {reason:?}"), long)
                        .await
                        .is_break()
                    {
                        return;
                    }
                }
            }
        }
    }

    /// Run one session: send what is queued, then forward commands until it ends.
    async fn serve(&mut self, session: &Session) -> Served {
        // Commands sent while no session existed are still in the control channel. Move
        // them into the outbox first, so the age rule applies to them too.
        let mut close = false;
        while let Ok(ctrl) = self.control.try_recv() {
            match ctrl {
                Control::Send { id, item, at } => self.outbox.push(id, item, at),
                Control::Close => close = true,
            }
        }
        if close {
            return Served::Closed;
        }
        self.flush(session).await;
        loop {
            tokio::select! {
                reason = session.wait_ended() => return Served::Ended(reason),
                ctrl = self.control.recv() => match ctrl {
                    Some(Control::Send { id, item, at }) => {
                        let entry = Queued { id, queued_at: at, item };
                        if !self.report(id, deliver(session, &entry).await) {
                            // The session is gone; keep the command for the next one.
                            self.outbox.requeue_front(vec![entry]);
                        }
                    }
                    Some(Control::Close) | None => return Served::Closed,
                },
            }
        }
    }

    /// Send the outbox in order. Entries that are too old are reported and not sent.
    async fn flush(&mut self, session: &Session) {
        let (fresh, expired) = self.outbox.take(Instant::now());
        for entry in expired {
            self.emit(Event::CommandDropped {
                id: entry.id,
                age: entry.age,
            });
        }
        let mut rest = fresh.into_iter();
        while let Some(entry) = rest.next() {
            if !self.report(entry.id, deliver(session, &entry).await) {
                let mut back = vec![entry];
                back.extend(rest);
                self.outbox.requeue_front(back);
                return;
            }
        }
    }

    /// Report a delivery result. Returns false if the command must stay queued.
    fn report(&self, id: u64, delivery: Delivery) -> bool {
        match delivery {
            Delivery::Sent => true,
            Delivery::Failed(reason) => {
                self.emit(Event::CommandFailed { id, reason });
                true
            }
            Delivery::Unsent => false,
        }
    }

    /// Count a failure, tell the caller, and wait. Commands that arrive while waiting are
    /// queued. Breaks if the caller closes during the wait.
    async fn wait_before_retry(&mut self, reason: String, long: bool) -> ControlFlow<()> {
        self.failed += 1;
        let wait = backoff::delay_for(self.failed - 1, long, jitter_unit());
        self.emit(Event::Reconnecting {
            attempt: self.failed,
            wait,
            reason,
        });
        let sleep = tokio::time::sleep(wait);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => return ControlFlow::Continue(()),
                ctrl = self.control.recv() => match ctrl {
                    Some(Control::Send { id, item, at }) => {
                        self.outbox.push(id, item, at);
                    }
                    Some(Control::Close) | None => {
                        self.emit(Event::Disconnected { reason: DisconnectReason::Requested });
                        return ControlFlow::Break(());
                    }
                },
            }
        }
    }
}

/// Send one entry. `false` means the session could not take it (it is closing), so the
/// caller keeps the entry.
/// What happened to one command when it was handed to the session.
enum Delivery {
    /// Accepted by the session.
    Sent,
    /// The session answered with an error; the command is not retried.
    Failed(String),
    /// The session was closing; the command stays queued for the next one.
    Unsent,
}

async fn deliver(session: &Session, entry: &Queued) -> Delivery {
    let result = match &entry.item {
        Item::Command(text) => session.send_command(text).await.map(|_| ()),
        Item::Secured {
            device_uuid,
            value,
            code,
        } => {
            session
                .send_secured(device_uuid, value, code.as_str())
                .await
        }
    };
    match result {
        Ok(()) => Delivery::Sent,
        Err(SessionError::Closed | SessionError::NotAuthenticated) => Delivery::Unsent,
        Err(err) => Delivery::Failed(err.to_string()),
    }
}

/// A jitter value in `[0, 1)` for the backoff.
fn jitter_unit() -> f64 {
    rand::random::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_reports_stopped_after_runner_is_gone() {
        let (control, rx) = unbounded_channel();
        drop(rx);
        let handle = SupervisorHandle {
            control,
            next_id: Arc::new(AtomicU64::new(0)),
        };
        assert_eq!(
            handle.send(Item::Command("x".into())),
            Err(SupervisorError::Stopped)
        );
    }

    #[test]
    fn ids_are_handed_out_in_order() {
        let (control, _rx) = unbounded_channel();
        let handle = SupervisorHandle {
            control,
            next_id: Arc::new(AtomicU64::new(0)),
        };
        assert_eq!(handle.send(Item::Command("a".into())), Ok(1));
        assert_eq!(handle.send(Item::Command("b".into())), Ok(2));
    }
}
