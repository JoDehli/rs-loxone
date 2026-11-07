//! Loxone UUIDs: 16 bytes in `bytes_le` order, text form `8-4-4-16` hex.
//!
//! The first three fields are little-endian. The text form matches the keys in
//! `LoxAPP3.json`: the last group is 16 hex
//! digits with no dash inside it.

use std::fmt;
use std::str::FromStr;

use super::ProtocolError;

/// A 128-bit Loxone UUID in its raw (`bytes_le`) byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// Build a UUID from its 16 raw bytes (Loxone byte order).
    pub const fn from_loxone_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 raw bytes (Loxone byte order).
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Uuid {
    type Error = ProtocolError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 16] = slice.try_into().map_err(|_| {
            ProtocolError::Malformed(format!("uuid needs 16 bytes, got {}", slice.len()))
        })?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        let time_low = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let time_mid = u16::from_le_bytes([b[4], b[5]]);
        let time_hi = u16::from_le_bytes([b[6], b[7]]);
        write!(
            f,
            "{time_low:08x}-{time_mid:04x}-{time_hi:04x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl FromStr for Uuid {
    type Err = ProtocolError;

    /// Parse the `8-4-4-16` form. The standard `8-4-4-4-12` form with the same
    /// bytes is also accepted.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        let joined: String = match parts.as_slice() {
            [a, b, c, d] if [a.len(), b.len(), c.len(), d.len()] == [8, 4, 4, 16] => {
                [*a, *b, *c, *d].concat()
            }
            [a, b, c, d, e]
                if [a.len(), b.len(), c.len(), d.len(), e.len()] == [8, 4, 4, 4, 12] =>
            {
                [*a, *b, *c, *d, *e].concat()
            }
            _ => return Err(ProtocolError::Malformed(format!("bad uuid text '{s}'"))),
        };
        let text = joined.as_bytes();
        let mut hex_bytes = [0u8; 16];
        for (i, out) in hex_bytes.iter_mut().enumerate() {
            let pair = std::str::from_utf8(&text[i * 2..i * 2 + 2])
                .map_err(|_| ProtocolError::Malformed(format!("bad uuid text '{s}'")))?;
            *out = u8::from_str_radix(pair, 16)
                .map_err(|_| ProtocolError::Malformed(format!("bad uuid text '{s}'")))?;
        }
        // hex_bytes is in text order: time_low, time_mid, time_hi, then the rest.
        let mut raw = [0u8; 16];
        raw[0..4].copy_from_slice(&hex_bytes[0..4]);
        raw[0..4].reverse();
        raw[4..6].copy_from_slice(&hex_bytes[4..6]);
        raw[4..6].reverse();
        raw[6..8].copy_from_slice(&hex_bytes[6..8]);
        raw[6..8].reverse();
        raw[8..16].copy_from_slice(&hex_bytes[8..16]);
        Ok(Self(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_bytes() {
        let raw: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let u = Uuid::from_loxone_bytes(raw);
        assert_eq!(u.to_string(), "04030201-0605-0807-090a0b0c0d0e0f10");
    }

    #[test]
    fn round_trips_text() {
        let text = "04030201-0605-0807-090a0b0c0d0e0f10";
        let u: Uuid = text.parse().unwrap();
        assert_eq!(u.to_string(), text);
        assert_eq!(u.as_bytes()[0], 0x01);
    }

    #[test]
    fn accepts_standard_form_with_same_bytes() {
        let a: Uuid = "04030201-0605-0807-090a-0b0c0d0e0f10".parse().unwrap();
        let b: Uuid = "04030201-0605-0807-090a0b0c0d0e0f10".parse().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_bad_text() {
        assert!("not-a-uuid".parse::<Uuid>().is_err());
        assert!(
            "04030201-0605-0807-zz0a0b0c0d0e0f10"
                .parse::<Uuid>()
                .is_err()
        );
    }

    #[test]
    fn rejects_wrong_length_bytes() {
        let err = Uuid::try_from(&[0u8; 15][..]).unwrap_err();
        assert!(matches!(err, ProtocolError::Malformed(_)));
    }
}
