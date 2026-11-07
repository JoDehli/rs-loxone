//! Events delivered to the caller.

use std::time::Duration;

use crate::auth::token::TokenState;
use crate::protocol::header::MessageKind;
use crate::protocol::ll::LlResponse;
use crate::protocol::uuid::Uuid;

/// Why the session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The socket closed. The code is the close code, if one was sent.
    Closed(Option<u16>),
    /// The connection was lost (watchdog or I/O). Carries a short reason, no secrets.
    Lost(String),
    /// The Miniserver is going out of service (identifier 5).
    OutOfService,
    /// The caller asked to close.
    Requested,
    /// Token renewal failed too often.
    AuthFailed,
}

/// Something that happened in the session.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// Logged in. `used_stored_token` is true if the stored token was used (`authwithtoken`)
    /// and false if the password was used and a new token was issued.
    LoggedIn { used_stored_token: bool },
    /// Logged in and state updates are enabled.
    Connected,
    /// Value states, in the order received.
    ValueStates(Vec<(Uuid, f64)>),
    /// Text states, in the order received.
    TextStates(Vec<(Uuid, String)>),
    /// A text reply that no pending request claimed.
    Text(LlResponse),
    /// A frame kind that is not parsed in v1 (daytimer, weather, binary).
    Raw { kind: MessageKind, bytes: Vec<u8> },
    /// A new token was stored (after login or refresh). The caller may persist it.
    TokenChanged(TokenState),
    /// A queued command was dropped because it was older than `max_command_age`.
    /// No command text is included (it may contain secrets).
    CommandDropped { id: u64, age: Duration },
    /// A command was refused or failed when it was sent. The reason is the error text,
    /// never the command itself (it may contain a visualization code).
    CommandFailed { id: u64, reason: String },
    /// Token renewal failed too often; the session ends.
    AuthFailed { reason: String },
    /// Supervisor: waiting before connection attempt `attempt`. Not sent by a session.
    Reconnecting {
        attempt: u32,
        wait: Duration,
        reason: String,
    },
    /// Supervisor: reconnecting has stopped for good. No connection follows.
    GaveUp { reason: String },
    /// The session ended. This is always the last event.
    Disconnected { reason: DisconnectReason },
}
