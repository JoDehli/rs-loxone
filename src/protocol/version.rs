//! Firmware version strings such as `"12.2.10.6"`.

use super::ProtocolError;

/// Parse a firmware version into `[major, minor, patch]`.
///
/// Missing parts are 0. Parts after the third are ignored. Non-numeric parts are an
/// error.
pub fn parse_version(text: &str) -> Result<[u32; 3], ProtocolError> {
    let mut out = [0u32; 3];
    for (i, part) in text.split('.').take(3).enumerate() {
        out[i] = part
            .trim()
            .parse()
            .map_err(|_| ProtocolError::Malformed(format!("bad version '{text}'")))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_missing_parts_and_ignores_extra() {
        assert_eq!(parse_version("10.2").unwrap(), [10, 2, 0]);
        assert_eq!(parse_version("12.2.10.6").unwrap(), [12, 2, 10]);
        assert_eq!(parse_version("9.0.4").unwrap(), [9, 0, 4]);
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(parse_version("ten.two").is_err());
    }
}
