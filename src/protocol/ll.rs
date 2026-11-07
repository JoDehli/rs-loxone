//! LL response envelope: `{"LL": {"control": ..., "code": ..., "value": ...}}`.

use serde_json::{Map, Value};

use super::ProtocolError;

/// Decode bytes as UTF-8, falling back to Latin-1 (which never fails).
pub fn decode_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

/// A parsed LL response.
#[derive(Debug, Clone, PartialEq)]
pub struct LlResponse {
    /// Status code (`code` or `Code` in the envelope).
    pub code: i64,
    /// Control path with a leading `salt/<hex>` removed.
    pub control: String,
    /// The value as text. For an object value this is its JSON text.
    pub value: String,
    fields: Map<String, Value>,
}

impl LlResponse {
    /// Parse an LL envelope. Bytes are decoded with [`decode_text`].
    pub fn parse(input: &[u8]) -> Result<Self, ProtocolError> {
        let text = decode_text(input);
        let root: Value = serde_json::from_str(&text)
            .map_err(|e| ProtocolError::Malformed(format!("LL json: {e}")))?;
        let ll = root
            .get("LL")
            .and_then(Value::as_object)
            .ok_or_else(|| ProtocolError::Malformed("missing LL object".into()))?;

        let code = ll
            .get("code")
            .or_else(|| ll.get("Code"))
            .ok_or_else(|| ProtocolError::Malformed("missing code".into()))
            .and_then(code_as_i64)?;

        let control = ll
            .get("control")
            .and_then(Value::as_str)
            .ok_or_else(|| ProtocolError::Malformed("missing control".into()))?;
        let control = strip_salt_prefix(control).to_owned();

        let raw_value = ll
            .get("value")
            .ok_or_else(|| ProtocolError::Malformed("missing value".into()))?;
        let (value, fields) = match raw_value {
            Value::Object(obj) => {
                let value = raw_value.to_string();
                let mut fields = Map::new();
                fields.insert("value".into(), Value::String(value.clone()));
                for (k, v) in obj {
                    fields.insert(k.clone(), v.clone());
                }
                (value, fields)
            }
            Value::String(s) => {
                let mut fields = Map::new();
                fields.insert("value".into(), Value::String(s.clone()));
                (s.clone(), fields)
            }
            other => {
                let value = other.to_string();
                let mut fields = Map::new();
                fields.insert("value".into(), Value::String(value.clone()));
                (value, fields)
            }
        };

        Ok(Self {
            code,
            control,
            value,
            fields,
        })
    }

    /// The `value` plus, for an object value, its fields. Object fields win over
    /// the `value` key.
    pub fn value_as_map(&self) -> &Map<String, Value> {
        &self.fields
    }
}

fn code_as_i64(v: &Value) -> Result<i64, ProtocolError> {
    match v {
        Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| ProtocolError::Malformed(format!("code not an integer: {n}"))),
        Value::String(s) => s
            .trim()
            .parse::<i64>()
            .map_err(|_| ProtocolError::Malformed(format!("code not an integer: {s}"))),
        other => Err(ProtocolError::Malformed(format!(
            "code has bad type: {other}"
        ))),
    }
}

/// Remove a leading `salt/<hex>` from a control path.
fn strip_salt_prefix(control: &str) -> &str {
    let Some(rest) = control.strip_prefix("salt/") else {
        return control;
    };
    let hex_len = rest.bytes().take_while(|b| b.is_ascii_hexdigit()).count();
    if hex_len == 0 {
        return control;
    }
    &rest[hex_len..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lowercase_code() {
        let r = LlResponse::parse(
            br#"{"LL": {"control": "dev/cfg/apiKey", "code": "200", "value": "x"}}"#,
        )
        .unwrap();
        assert_eq!(r.code, 200);
        assert_eq!(r.control, "dev/cfg/apiKey");
        assert_eq!(r.value, "x");
    }

    #[test]
    fn parses_capital_code_and_numeric_code() {
        let r =
            LlResponse::parse(br#"{"LL": {"control": "c", "Code": 401, "value": ""}}"#).unwrap();
        assert_eq!(r.code, 401);
    }

    #[test]
    fn strips_salt_prefix() {
        let r = LlResponse::parse(
            br#"{"LL": {"control": "salt/0a1B2c/jdev/sys/getkey2", "code": 200, "value": ""}}"#,
        )
        .unwrap();
        assert_eq!(r.control, "/jdev/sys/getkey2");
    }

    #[test]
    fn object_value_merges_fields() {
        let r = LlResponse::parse(
            br#"{"LL": {"control": "c", "code": 200, "value": {"key": "ab", "salt": "cd"}}}"#,
        )
        .unwrap();
        let m = r.value_as_map();
        assert_eq!(m.get("key").and_then(Value::as_str), Some("ab"));
        assert_eq!(m.get("salt").and_then(Value::as_str), Some("cd"));
        assert!(m.get("value").is_some());
    }

    #[test]
    fn string_value_stays_a_string() {
        let r = LlResponse::parse(br#"{"LL": {"control": "c", "code": 200, "value": "plain"}}"#)
            .unwrap();
        assert_eq!(
            r.value_as_map().get("value").and_then(Value::as_str),
            Some("plain")
        );
    }

    #[test]
    fn missing_field_is_error() {
        assert!(LlResponse::parse(br#"{"LL": {"control": "c", "value": ""}}"#).is_err());
        assert!(LlResponse::parse(br#"{"LL": {"code": 200, "value": ""}}"#).is_err());
        assert!(LlResponse::parse(br#"{"LL": {"control": "c", "code": 200}}"#).is_err());
        assert!(LlResponse::parse(b"not json").is_err());
    }

    #[test]
    fn latin1_fallback_never_fails() {
        // 0xE4 is "ä" in Latin-1 and invalid as a lone UTF-8 byte.
        let mut bytes = br#"{"LL": {"control": "c", "code": 200, "value": ""#.to_vec();
        bytes.push(0xE4);
        bytes.extend_from_slice(br#""}}"#);
        let r = LlResponse::parse(&bytes).unwrap();
        assert_eq!(r.value, "\u{e4}");
    }
}
