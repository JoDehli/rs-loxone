//! Low-level async client for the Loxone Miniserver.
//!
//! Modules:
//! - [`protocol`]: pure parsing of Miniserver frames (no I/O).
//! - [`auth`]: hashing, key exchange, command encryption and token logic (no I/O).
//! - [`transport`]: HTTP bootstrap, WebSocket, TLS and keepalive.

pub mod auth;
pub mod protocol;
pub mod session;
pub mod transport;
