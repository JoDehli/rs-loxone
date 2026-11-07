//! The 8-byte binary frame header (`WsBinHdr`).
//!
//! Layout: magic `0x03`, identifier, info flags, reserved, `u32` little-endian length.

use super::ProtocolError;

/// Size of the binary frame header in bytes.
pub const HEADER_LEN: usize = 8;
/// First byte of a Loxone binary header.
pub const MAGIC: u8 = 0x03;
/// Bit 7 of the info byte: the payload length is only estimated.
const ESTIMATED_BIT: u8 = 0x80;

/// The kind of message announced by a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// Identifier 0: text message (LL JSON).
    Text,
    /// Identifier 1: binary file.
    Binary,
    /// Identifier 2: table of value states.
    ValueStates,
    /// Identifier 3: table of text states.
    TextStates,
    /// Identifier 4: table of daytimer states.
    Daytimer,
    /// Identifier 5: out of service; the server closes the connection.
    OutOfService,
    /// Identifier 6: keepalive reply.
    Keepalive,
    /// Identifier 7: table of weather states.
    Weather,
    /// Not a Loxone binary header (magic byte or length missing).
    Unknown,
}

impl MessageKind {
    fn from_identifier(id: u8) -> Result<Self, ProtocolError> {
        Ok(match id {
            0 => Self::Text,
            1 => Self::Binary,
            2 => Self::ValueStates,
            3 => Self::TextStates,
            4 => Self::Daytimer,
            5 => Self::OutOfService,
            6 => Self::Keepalive,
            7 => Self::Weather,
            other => return Err(ProtocolError::UnknownType(other)),
        })
    }
}

/// A parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Kind of the payload that follows.
    pub kind: MessageKind,
    /// True if the announced length is an estimate.
    pub estimated: bool,
    /// Payload length in bytes, as announced.
    pub payload_len: u32,
}

impl FrameHeader {
    /// A header for a frame that is not a Loxone binary header.
    fn unknown() -> Self {
        Self {
            kind: MessageKind::Unknown,
            estimated: false,
            payload_len: 0,
        }
    }
}

/// Parse an 8-byte header.
///
/// Input that is shorter than 8 bytes, or does not start with `0x03`, is not an
/// error: it returns [`MessageKind::Unknown`] with length 0. A binary header with an identifier outside 0–7 is an error.
pub fn parse_header(bytes: &[u8]) -> Result<FrameHeader, ProtocolError> {
    if bytes.len() < HEADER_LEN || bytes[0] != MAGIC {
        return Ok(FrameHeader::unknown());
    }
    let kind = MessageKind::from_identifier(bytes[1])?;
    let estimated = bytes[2] & ESTIMATED_BIT != 0;
    let payload_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    Ok(FrameHeader {
        kind,
        estimated,
        payload_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_header() {
        let h = parse_header(&[0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(
            h,
            FrameHeader {
                kind: MessageKind::Text,
                estimated: false,
                payload_len: 16
            }
        );
    }

    #[test]
    fn estimated_bit_is_bit_seven_of_info() {
        let h = parse_header(&[0x03, 0x02, 0x80, 0x00, 0x18, 0x00, 0x00, 0x00]).unwrap();
        assert!(h.estimated);
        assert_eq!(h.kind, MessageKind::ValueStates);
        assert_eq!(h.payload_len, 24);
    }

    #[test]
    fn length_is_little_endian() {
        let h = parse_header(&[0x03, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04]).unwrap();
        assert_eq!(h.payload_len, 0x0403_0201);
    }

    #[test]
    fn identifiers_map_to_kinds() {
        let kinds = [
            MessageKind::Text,
            MessageKind::Binary,
            MessageKind::ValueStates,
            MessageKind::TextStates,
            MessageKind::Daytimer,
            MessageKind::OutOfService,
            MessageKind::Keepalive,
            MessageKind::Weather,
        ];
        for (id, kind) in kinds.iter().enumerate() {
            let h = parse_header(&[0x03, id as u8, 0, 0, 0, 0, 0, 0]).unwrap();
            assert_eq!(h.kind, *kind, "identifier {id}");
        }
    }

    #[test]
    fn wrong_magic_is_unknown_not_error() {
        let h = parse_header(&[0x7b, 0x00, 0, 0, 1, 0, 0, 0]).unwrap();
        assert_eq!(h.kind, MessageKind::Unknown);
        assert_eq!(h.payload_len, 0);
    }

    #[test]
    fn short_input_is_unknown_not_error() {
        assert_eq!(parse_header(&[]).unwrap().kind, MessageKind::Unknown);
        assert_eq!(
            parse_header(&[0x03, 0x00, 0x00]).unwrap().kind,
            MessageKind::Unknown
        );
    }

    #[test]
    fn unknown_identifier_is_error() {
        let err = parse_header(&[0x03, 0x09, 0, 0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, ProtocolError::UnknownType(9));
    }
}
