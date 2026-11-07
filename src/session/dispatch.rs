//! Callbacks for events. The dispatcher calls them one after another, in arrival order.
//!
//! A callback can be synchronous ([`SyncHandler`]) or asynchronous ([`AsyncHandler`]).
//! A panic inside a callback is caught and logged; it does not stop the dispatcher.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};

use futures_util::FutureExt;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::session::Event;

/// Receives events. Implemented by the two adapters below.
pub trait EventHandler: Send + 'static {
    /// Handle one event. The dispatcher waits for this before the next event.
    fn handle(&mut self, event: Event) -> impl Future<Output = ()> + Send;
}

/// Adapter for a synchronous callback.
pub struct SyncHandler<F>(pub F);

impl<F> EventHandler for SyncHandler<F>
where
    F: FnMut(Event) + Send + 'static,
{
    fn handle(&mut self, event: Event) -> impl Future<Output = ()> + Send {
        if catch_unwind(AssertUnwindSafe(|| (self.0)(event))).is_err() {
            eprintln!("rs-loxone: event callback panicked; event dropped");
        }
        std::future::ready(())
    }
}

/// Adapter for an asynchronous callback.
pub struct AsyncHandler<F>(pub F);

impl<F, Fut> EventHandler for AsyncHandler<F>
where
    F: FnMut(Event) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn handle(&mut self, event: Event) -> impl Future<Output = ()> + Send {
        let fut = catch_unwind(AssertUnwindSafe(|| (self.0)(event)));
        async move {
            match fut {
                Ok(fut) => {
                    if AssertUnwindSafe(fut).catch_unwind().await.is_err() {
                        eprintln!("rs-loxone: async event callback panicked; event dropped");
                    }
                }
                Err(_) => eprintln!("event callback panicked; event dropped"),
            }
        }
    }
}

/// Run the dispatcher until `Disconnected` has been handled or the channel closes.
pub(crate) async fn run<H: EventHandler>(
    mut events: UnboundedReceiver<Event>,
    mut handler: H,
    backlog: std::sync::Arc<crate::session::commands::Backlog>,
) {
    while let Some(event) = events.recv().await {
        let last = matches!(event, Event::Disconnected { .. });
        handler.handle(event).await;
        backlog.done();
        if last {
            break;
        }
    }
}
