//! Pairing of binary headers with their payloads, and decoding into messages.
//!
//! The Miniserver sends an 8-byte header as one binary frame, then the payload as the
//! next frame. A header with length 0 has no payload frame. Some replies arrive as a
//! plain text frame with no header. An estimated header is followed by an exact one.

use crate::protocol::header::{FrameHeader, HEADER_LEN, MessageKind, parse_header};
use crate::protocol::message::{Message, parse_frame};
use crate::session::SessionError;
use crate::transport::ws::RawFrame;

/// Turns raw frames into messages, one at a time.
#[derive(Debug, Default)]
pub struct FramePairer {
    pending: Option<FrameHeader>,
}

impl FramePairer {
    /// Whether an 8-byte frame is a new header rather than a payload.
    ///
    /// Nothing pending: a header. A pending estimated header: the exact header that
    /// replaces it has the same kind and is not estimated, so anything else is payload.
    /// A pending exact header is followed by its payload, unless the length is 0.
    fn starts_header(&self, bytes: &[u8]) -> bool {
        match &self.pending {
            None => true,
            Some(h) if h.estimated => {
                parse_header(bytes).is_ok_and(|exact| exact.kind == h.kind && !exact.estimated)
            }
            Some(h) => h.payload_len == 0,
        }
    }

    /// Feed one raw frame. Returns a complete message when one is ready.
    pub fn push(&mut self, frame: RawFrame) -> Result<Option<Message>, SessionError> {
        match frame {
            RawFrame::Text(text) => {
                if let Some(h) = self.pending.take() {
                    // A text payload for a pending header.
                    return Ok(Some(parse_frame(&h, text.as_bytes())?));
                }
                // A plain text message with no header.
                let header = FrameHeader {
                    kind: MessageKind::Text,
                    estimated: false,
                    payload_len: text.len() as u32,
                };
                Ok(Some(parse_frame(&header, text.as_bytes())?))
            }
            RawFrame::Binary(bytes) => {
                let is_header = bytes.len() == HEADER_LEN
                    && bytes[0] == crate::protocol::header::MAGIC
                    && self.starts_header(&bytes);
                if is_header {
                    let header = parse_header(&bytes)?;
                    if header.payload_len == 0 && !header.estimated {
                        // No payload frame follows.
                        return Ok(Some(parse_frame(&header, &[])?));
                    }
                    self.pending = Some(header);
                    return Ok(None);
                }
                match self.pending.take() {
                    Some(h) => Ok(Some(parse_frame(&h, &bytes)?)),
                    // Payload without a header: nothing to decode it with.
                    None => Ok(None),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_then_payload_becomes_one_message() {
        let mut p = FramePairer::default();
        let header = vec![3u8, 2, 0, 0, 24, 0, 0, 0];
        assert!(p.push(RawFrame::Binary(header)).unwrap().is_none());
        let msg = p.push(RawFrame::Binary(vec![0u8; 24])).unwrap().unwrap();
        assert!(matches!(msg, Message::ValueStates(v) if v.len() == 1));
    }

    #[test]
    fn zero_length_header_completes_alone() {
        let mut p = FramePairer::default();
        let msg = p
            .push(RawFrame::Binary(vec![3, 6, 0, 0, 0, 0, 0, 0]))
            .unwrap();
        assert_eq!(msg, Some(Message::Keepalive));
    }

    #[test]
    fn estimated_header_is_replaced_by_the_exact_one() {
        let mut p = FramePairer::default();
        assert!(
            p.push(RawFrame::Binary(vec![3, 1, 0x80, 0, 9, 0, 0, 0]))
                .unwrap()
                .is_none()
        );
        assert!(
            p.push(RawFrame::Binary(vec![3, 1, 0, 0, 2, 0, 0, 0]))
                .unwrap()
                .is_none()
        );
        let msg = p.push(RawFrame::Binary(vec![7, 8])).unwrap().unwrap();
        assert_eq!(msg, Message::Binary(vec![7, 8]));
    }

    #[test]
    fn plain_text_is_a_text_message() {
        let mut p = FramePairer::default();
        let t = r#"{"LL": {"control": "c", "code": 200, "value": ""}}"#;
        let msg = p.push(RawFrame::Text(t.into())).unwrap().unwrap();
        assert!(matches!(msg, Message::Text(r) if r.code == 200));
    }

    #[test]
    fn estimated_header_then_payload_of_other_kind_is_payload() {
        let mut p = FramePairer::default();
        assert!(
            p.push(RawFrame::Binary(vec![3, 1, 0x80, 0, 8, 0, 0, 0]))
                .unwrap()
                .is_none()
        );
        // Eight bytes starting with 0x03, but announcing text states, not the binary kind.
        let payload = vec![3, 3, 0, 0, 9, 9, 9, 9];
        let msg = p.push(RawFrame::Binary(payload.clone())).unwrap().unwrap();
        assert_eq!(msg, Message::Binary(payload));
    }

    #[test]
    fn payload_eight_bytes_long_is_not_a_header_when_one_is_pending() {
        let mut p = FramePairer::default();
        assert!(
            p.push(RawFrame::Binary(vec![3, 1, 0, 0, 8, 0, 0, 0]))
                .unwrap()
                .is_none()
        );
        // 8 bytes starting with 0x03, but a header is pending, so it is the payload.
        let msg = p
            .push(RawFrame::Binary(vec![3, 9, 9, 9, 9, 9, 9, 9]))
            .unwrap()
            .unwrap();
        assert_eq!(msg, Message::Binary(vec![3, 9, 9, 9, 9, 9, 9, 9]));
    }
}
