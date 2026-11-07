//! Payload parsers for the Miniserver message types, and frame dispatch.

use super::ProtocolError;
use super::header::{FrameHeader, MessageKind};
use super::ll::{LlResponse, decode_text};
use super::uuid::Uuid;

/// Size of one value-state record: 16-byte UUID + little-endian `f64`.
const VALUE_RECORD_LEN: usize = 24;
/// Size of the UUID fields in a text-state record.
const UUID_LEN: usize = 16;
/// Size of the text-length field in a text-state record.
const TEXT_LEN_FIELD: usize = 4;

/// Parse a value-state table.
///
/// Returns the `(uuid, value)` pairs in order and the number of trailing bytes
/// that did not form a full record (dropped).
pub fn parse_value_states(payload: &[u8]) -> (Vec<(Uuid, f64)>, usize) {
    let (records, rest) = payload.as_chunks::<VALUE_RECORD_LEN>();
    let dropped = rest.len();
    let values = records
        .iter()
        .map(|rec| {
            // chunks_exact guarantees 24 bytes, so these slices always fit.
            let uuid = Uuid::from_loxone_bytes(rec[..16].try_into().expect("16-byte slice"));
            let value = f64::from_le_bytes(rec[16..24].try_into().expect("8-byte slice"));
            (uuid, value)
        })
        .collect();
    (values, dropped)
}

/// Parse a text-state table.
///
/// Each record is: event UUID (16), icon UUID (16, discarded), `u32` LE text
/// length, then the text. The next record starts at the current start rounded up
/// to a multiple of 4, which is what the formula
/// `(floor((4 + len + 16 + 16 - 1) / 4) + 1) * 4` computes.
pub fn parse_text_states(payload: &[u8]) -> Result<Vec<(Uuid, String)>, ProtocolError> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < payload.len() {
        let uuid_end = start + UUID_LEN;
        let icon_end = uuid_end + UUID_LEN;
        let len_end = icon_end + TEXT_LEN_FIELD;
        if len_end > payload.len() {
            return Err(ProtocolError::Malformed(
                "truncated text-state header".into(),
            ));
        }
        let uuid = Uuid::try_from(&payload[start..uuid_end])?;
        let text_len =
            u32::from_le_bytes(payload[icon_end..len_end].try_into().expect("4-byte slice"))
                as usize;
        let text_end = len_end
            .checked_add(text_len)
            .ok_or_else(|| ProtocolError::Malformed("text length overflow".into()))?;
        if text_end > payload.len() {
            return Err(ProtocolError::Malformed("truncated text-state text".into()));
        }
        out.push((uuid, decode_text(&payload[len_end..text_end])));
        let record_len = text_end - start;
        start += record_len.div_ceil(4) * 4;
    }
    Ok(out)
}

/// A parsed Miniserver message.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// Identifier 0: text message (LL envelope).
    Text(LlResponse),
    /// Identifier 1: binary file, as an owned copy.
    Binary(Vec<u8>),
    /// Identifier 2: value states.
    ValueStates(Vec<(Uuid, f64)>),
    /// Identifier 3: text states.
    TextStates(Vec<(Uuid, String)>),
    /// Identifier 4: daytimer states, raw bytes (not parsed).
    Daytimer(Vec<u8>),
    /// Identifier 5: out of service; the server closes the connection.
    OutOfService,
    /// Identifier 6: keepalive reply.
    Keepalive,
    /// Identifier 7: weather states, raw bytes (not parsed).
    Weather(Vec<u8>),
}

/// Parse one frame from its header and payload.
///
/// For a non-estimated header, the payload length must equal the length in the
/// header. For an estimated header the length is only a guess, so no check is made;
/// the caller pairs it with the exact header that follows.
pub fn parse_frame(header: &FrameHeader, payload: &[u8]) -> Result<Message, ProtocolError> {
    if !header.estimated && payload.len() as u64 != u64::from(header.payload_len) {
        return Err(ProtocolError::LengthMismatch {
            expected: header.payload_len,
            actual: payload.len(),
        });
    }
    Ok(match header.kind {
        MessageKind::Text => Message::Text(LlResponse::parse(payload)?),
        MessageKind::Binary => Message::Binary(payload.to_vec()),
        MessageKind::ValueStates => Message::ValueStates(parse_value_states(payload).0),
        MessageKind::TextStates => Message::TextStates(parse_text_states(payload)?),
        MessageKind::Daytimer => Message::Daytimer(payload.to_vec()),
        MessageKind::OutOfService => Message::OutOfService,
        MessageKind::Keepalive => Message::Keepalive,
        MessageKind::Weather => Message::Weather(payload.to_vec()),
        MessageKind::Unknown => {
            return Err(ProtocolError::Malformed(
                "frame is not a Loxone binary header".into(),
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: MessageKind, len: u32) -> FrameHeader {
        FrameHeader {
            kind,
            estimated: false,
            payload_len: len,
        }
    }

    #[test]
    fn value_states_partial_record_is_dropped_and_counted() {
        let mut p = vec![0u8; 24];
        p.extend_from_slice(&[1u8; 10]);
        let (values, dropped) = parse_value_states(&p);
        assert_eq!(values.len(), 1);
        assert_eq!(dropped, 10);
    }

    #[test]
    fn value_states_empty() {
        assert_eq!(parse_value_states(&[]), (vec![], 0));
    }

    #[test]
    fn text_states_truncated_text_is_error() {
        let mut p = vec![0u8; 32];
        p.extend_from_slice(&64u32.to_le_bytes());
        p.extend_from_slice(b"abc");
        assert!(parse_text_states(&p).is_err());
    }

    #[test]
    fn text_states_truncated_header_is_error() {
        assert!(parse_text_states(&[0u8; 10]).is_err());
    }

    #[test]
    fn frame_length_mismatch_is_error() {
        let err = parse_frame(&header(MessageKind::Keepalive, 3), b"ab").unwrap_err();
        assert_eq!(
            err,
            ProtocolError::LengthMismatch {
                expected: 3,
                actual: 2
            }
        );
    }

    #[test]
    fn estimated_header_skips_length_check() {
        let h = FrameHeader {
            kind: MessageKind::Binary,
            estimated: true,
            payload_len: 999,
        };
        assert_eq!(
            parse_frame(&h, b"abc").unwrap(),
            Message::Binary(b"abc".to_vec())
        );
    }

    #[test]
    fn each_identifier_dispatches() {
        assert_eq!(
            parse_frame(&header(MessageKind::OutOfService, 0), b"").unwrap(),
            Message::OutOfService
        );
        assert_eq!(
            parse_frame(&header(MessageKind::Keepalive, 9), b"keepalive").unwrap(),
            Message::Keepalive
        );
        assert_eq!(
            parse_frame(&header(MessageKind::Daytimer, 2), b"ab").unwrap(),
            Message::Daytimer(b"ab".to_vec())
        );
        assert_eq!(
            parse_frame(&header(MessageKind::Weather, 2), b"ab").unwrap(),
            Message::Weather(b"ab".to_vec())
        );
        assert_eq!(
            parse_frame(&header(MessageKind::ValueStates, 0), b"").unwrap(),
            Message::ValueStates(vec![])
        );
        assert_eq!(
            parse_frame(&header(MessageKind::TextStates, 0), b"").unwrap(),
            Message::TextStates(vec![])
        );
        let text = br#"{"LL": {"control": "c", "code": 200, "value": ""}}"#;
        let msg = parse_frame(&header(MessageKind::Text, text.len() as u32), text).unwrap();
        assert!(matches!(msg, Message::Text(r) if r.code == 200));
    }

    #[test]
    fn unknown_kind_is_error() {
        assert!(parse_frame(&header(MessageKind::Unknown, 0), b"").is_err());
    }
}
