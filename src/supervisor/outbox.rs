//! The outbox: commands waiting for a connection.
//!
//! Entries keep the plain command text. Encrypted text depends on one connection's salt
//! chain, so it is built only when the command is actually sent. A secured command keeps
//! its visualization code in `Zeroizing`, which clears the memory when the entry leaves.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;
use zeroize::Zeroizing;

/// What the caller asked to send.
#[derive(Clone, PartialEq, Eq)]
pub enum Item {
    /// A plain application command, such as `jdev/sps/io/<uuid>/on`.
    Command(String),
    /// A secured command: `jdev/sps/ios/<hash>/<device uuid>/<value>` after login.
    Secured {
        device_uuid: String,
        value: String,
        code: Zeroizing<String>,
    },
}

// The visualization code must not appear in debug output.
impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Item::Command(text) => f.debug_tuple("Command").field(text).finish(),
            Item::Secured {
                device_uuid, value, ..
            } => f
                .debug_struct("Secured")
                .field("device_uuid", device_uuid)
                .field("value", value)
                .field("code", &"<redacted>")
                .finish(),
        }
    }
}

/// One queued command with its id and the time it was queued.
#[derive(Debug)]
pub struct Queued {
    pub id: u64,
    pub queued_at: Instant,
    pub item: Item,
}

/// An entry that was too old to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expired {
    pub id: u64,
    pub age: Duration,
}

/// Queue of commands, in the order they were sent by the caller.
#[derive(Debug)]
pub struct Outbox {
    entries: VecDeque<Queued>,
    max_age: Duration,
}

impl Outbox {
    /// An empty outbox. Entries older than `max_age` are dropped when taken.
    pub fn new(max_age: Duration) -> Self {
        Self {
            entries: VecDeque::new(),
            max_age,
        }
    }

    /// Queue an item with the id the caller assigned, queued at `at`.
    pub fn push(&mut self, id: u64, item: Item, at: Instant) {
        self.entries.push_back(Queued {
            id,
            queued_at: at,
            item,
        });
    }

    /// Put entries back at the front, keeping their order. Used when a session could not
    /// take them, so they go out before anything queued later.
    pub fn requeue_front(&mut self, entries: Vec<Queued>) {
        for entry in entries.into_iter().rev() {
            self.entries.push_front(entry);
        }
    }

    /// Number of entries waiting.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Take every entry in order. Entries older than `max_age` at `now` are returned as
    /// expired instead of being sent.
    pub fn take(&mut self, now: Instant) -> (Vec<Queued>, Vec<Expired>) {
        let mut fresh = Vec::new();
        let mut expired = Vec::new();
        for entry in self.entries.drain(..) {
            let age = now.saturating_duration_since(entry.queued_at);
            if age > self.max_age {
                expired.push(Expired { id: entry.id, age });
            } else {
                fresh.push(entry);
            }
        }
        (fresh, expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(text: &str) -> Item {
        Item::Command(text.into())
    }

    #[tokio::test(start_paused = true)]
    async fn entries_come_out_in_order_with_ids() {
        let mut ob = Outbox::new(Duration::from_secs(30));
        let t0 = Instant::now();
        ob.push(1, cmd("a"), t0);
        ob.push(2, cmd("b"), t0);
        let (fresh, expired) = ob.take(t0);
        assert_eq!(fresh.iter().map(|q| q.id).collect::<Vec<_>>(), vec![1, 2]);
        assert!(expired.is_empty());
        assert!(ob.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn entry_older_than_max_age_is_expired() {
        let mut ob = Outbox::new(Duration::from_secs(30));
        let t0 = Instant::now();
        ob.push(1, cmd("old"), t0);
        tokio::time::advance(Duration::from_secs(31)).await;
        ob.push(2, cmd("new"), Instant::now());
        let (fresh, expired) = ob.take(Instant::now());
        assert_eq!(
            expired,
            vec![Expired {
                id: 1,
                age: Duration::from_secs(31)
            }]
        );
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].id, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn exactly_max_age_is_still_sent() {
        let mut ob = Outbox::new(Duration::from_secs(30));
        let t0 = Instant::now();
        ob.push(1, cmd("edge"), t0);
        tokio::time::advance(Duration::from_secs(30)).await;
        let (fresh, expired) = ob.take(Instant::now());
        assert_eq!(fresh.len(), 1);
        assert!(expired.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn secured_code_is_redacted_in_debug() {
        let item = Item::Secured {
            device_uuid: "uuid".into(),
            value: "1".into(),
            code: Zeroizing::new("1234".into()),
        };
        let shown = format!("{item:?}");
        assert!(!shown.contains("1234"), "{shown}");
        assert!(shown.contains("redacted"));
    }

    #[tokio::test(start_paused = true)]
    async fn requeued_entries_go_first_in_order() {
        let mut ob = Outbox::new(Duration::from_secs(30));
        let t0 = Instant::now();
        ob.push(1, cmd("a"), t0);
        ob.push(2, cmd("b"), t0);
        let (mut fresh, _) = ob.take(t0);
        let second = fresh.split_off(1);
        ob.push(3, cmd("c"), t0);
        ob.requeue_front(second);
        let (again, _) = ob.take(t0);
        assert_eq!(again.iter().map(|q| q.id).collect::<Vec<_>>(), vec![2, 3]);
    }

    #[tokio::test(start_paused = true)]
    async fn take_empties_the_outbox() {
        let mut ob = Outbox::new(Duration::from_secs(30));
        ob.push(1, cmd("x"), Instant::now());
        assert_eq!(ob.len(), 1);
        let _ = ob.take(Instant::now());
        assert_eq!(ob.len(), 0);
    }
}
