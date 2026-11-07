//! Pure parsing of Miniserver frames. No I/O, no async.

pub mod header;
pub mod ll;
pub mod message;
pub mod uuid;
pub mod version;

pub use header::{FrameHeader, MessageKind, parse_header};
pub use uuid::Uuid;

/// Errors from parsing Miniserver frames.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    /// The header identifier byte is not a known message kind.
    #[error("unknown message identifier {0}")]
    UnknownType(u8),
    /// The payload length does not match the header.
    #[error("payload length mismatch: header says {expected}, got {actual}")]
    LengthMismatch { expected: u32, actual: usize },
    /// The payload is malformed (bad JSON, bad UUID, truncated record).
    #[error("malformed payload: {0}")]
    Malformed(String),
}
