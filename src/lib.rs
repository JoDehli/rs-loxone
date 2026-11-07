//! Low-level async client for the Loxone Miniserver.
//!
//! Modules:
//! - [`protocol`]: pure parsing of Miniserver frames (no I/O).
//! - [`auth`]: hashing, key exchange, command encryption and token logic (no I/O).
//! - [`transport`]: HTTP bootstrap, WebSocket, TLS and keepalive.
//! - [`structure`]: the structure file, with lookups by name, type and state.

pub mod auth;
pub mod discover;
pub mod protocol;
pub mod session;
pub mod structure;
pub mod supervisor;
pub mod transport;
