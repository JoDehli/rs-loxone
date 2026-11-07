//! Reading the structure file (`LoxAPP3.json`) without the JSON details.
//!
//! The file lists every control with its states, and sub-controls nest inside their
//! parent. This module finds controls by name or type, gives states by name, and
//! produces readable labels for state UUIDs (`Room / Control / state`).
//!
//! ```no_run
//! # fn demo(bytes: &[u8]) -> Result<(), rs_loxone::structure::StructureError> {
//! use rs_loxone::structure::Structure;
//!
//! let structure = Structure::parse(bytes)?;
//! if let Some(shutter) = structure.find("Example shutter") {
//!     println!("{} is a {}", shutter.name(), shutter.kind());
//!     if let Some(position) = shutter.state("position") {
//!         println!("position state: {position}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;

use serde_json::Value;
use thiserror::Error;

/// The structure file could not be read.
#[derive(Debug, Error)]
pub enum StructureError {
    /// The bytes are not JSON, or not a structure file.
    #[error("structure file is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The file has no `controls` section.
    #[error("structure file has no controls")]
    NoControls,
}

/// A parsed structure file with lookup helpers.
#[derive(Debug, Clone)]
pub struct Structure {
    json: Value,
    labels: HashMap<String, String>,
}

impl Structure {
    /// Parse the bytes of `LoxAPP3.json` as the Miniserver sends them.
    pub fn parse(bytes: &[u8]) -> Result<Self, StructureError> {
        let json: Value = serde_json::from_slice(bytes)?;
        let controls = json["controls"]
            .as_object()
            .ok_or(StructureError::NoControls)?;
        let mut labels = HashMap::new();
        for (uuid, control) in controls {
            walk_labels(uuid, control, "", &mut labels);
        }
        Ok(Self { json, labels })
    }

    /// The `lastModified` value, if the file has one.
    pub fn last_modified(&self) -> Option<&str> {
        self.json["lastModified"].as_str()
    }

    /// Every top-level control, in the order the file lists them.
    pub fn controls(&self) -> impl Iterator<Item = Control<'_>> {
        self.json["controls"]
            .as_object()
            .into_iter()
            .flat_map(|map| map.iter())
            .map(|(uuid, value)| Control { uuid, value })
    }

    /// The first control with exactly this name.
    pub fn find(&self, name: &str) -> Option<Control<'_>> {
        self.controls().find(|c| c.name() == name)
    }

    /// Every control with exactly this name (names are not unique in Loxone Config).
    pub fn find_all(&self, name: &str) -> Vec<Control<'_>> {
        self.controls().filter(|c| c.name() == name).collect()
    }

    /// Every control of this type, for example `"Alarm"` or `"Switch"`.
    pub fn of_type(&self, kind: &str) -> Vec<Control<'_>> {
        self.controls().filter(|c| c.kind() == kind).collect()
    }

    /// The control with this UUID, or whose action UUID is this UUID.
    pub fn control(&self, uuid: &str) -> Option<Control<'_>> {
        self.controls()
            .find(|c| c.uuid == uuid || c.action_uuid() == uuid)
    }

    /// A readable label for a UUID: the control, a sub-control, or a state.
    ///
    /// For states the label ends with the state name, for example
    /// `"Example room / Example shutter / position"`.
    pub fn label(&self, uuid: &str) -> Option<&str> {
        self.labels.get(uuid).map(String::as_str)
    }
}

/// One control, sub-control or the top level of a control, borrowed from a [`Structure`].
#[derive(Debug, Clone, Copy)]
pub struct Control<'a> {
    uuid: &'a str,
    value: &'a Value,
}

impl<'a> Control<'a> {
    /// The control's UUID (the key in the `controls` section).
    pub fn uuid(&self) -> &'a str {
        self.uuid
    }

    /// The name as set in Loxone Config.
    pub fn name(&self) -> &'a str {
        self.value["name"].as_str().unwrap_or("")
    }

    /// The control type, for example `"Alarm"`, `"Switch"` or `"Jalousie"`.
    pub fn kind(&self) -> &'a str {
        self.value["type"].as_str().unwrap_or("")
    }

    /// The UUID that commands are sent to (`uuidAction`). Falls back to the control UUID.
    pub fn action_uuid(&self) -> &'a str {
        self.value["uuidAction"].as_str().unwrap_or(self.uuid)
    }

    /// True if commands need the visualization password (`isSecured`).
    pub fn is_secured(&self) -> bool {
        self.value["isSecured"].as_bool().unwrap_or(false)
    }

    /// The UUID of a state, by its key (for example `"position"` or `"armed"`).
    pub fn state(&self, key: &str) -> Option<&'a str> {
        self.value["states"][key].as_str()
    }

    /// Every state as `(key, uuid)`.
    pub fn states(&self) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.value["states"]
            .as_object()
            .into_iter()
            .flat_map(|map| map.iter())
            .filter_map(|(key, value)| value.as_str().map(|uuid| (key.as_str(), uuid)))
    }

    /// The sub-controls of this control, as `(uuid, control)`.
    pub fn sub_controls(&self) -> impl Iterator<Item = Control<'a>> {
        self.value["subControls"]
            .as_object()
            .into_iter()
            .flat_map(|map| map.iter())
            .map(|(uuid, value)| Control { uuid, value })
    }
}

/// Fill in labels for a control, its states and its sub-controls.
fn walk_labels(uuid: &str, control: &Value, parent: &str, out: &mut HashMap<String, String>) {
    let name = control["name"].as_str().unwrap_or(uuid);
    let label = if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent} / {name}")
    };
    out.entry(uuid.to_owned()).or_insert_with(|| label.clone());
    if let Some(action) = control["uuidAction"].as_str() {
        out.entry(action.to_owned())
            .or_insert_with(|| label.clone());
    }
    if let Some(states) = control["states"].as_object() {
        for (key, value) in states {
            let ids: Vec<&str> = match value {
                Value::String(id) => vec![id.as_str()],
                Value::Array(ids) => ids.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            for id in ids {
                out.entry(id.to_owned())
                    .or_insert_with(|| format!("{label} / {key}"));
            }
        }
    }
    if let Some(subs) = control["subControls"].as_object() {
        for (sub_uuid, sub) in subs {
            walk_labels(sub_uuid, sub, &label, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small made-up structure: one room-less shutter and an alarm with a sub-control.
    const SAMPLE: &str = r#"{
        "lastModified": "2026-01-01 10:00:00",
        "controls": {
            "aaaa0001-0000-0001-ffff000000000001": {
                "name": "Example shutter",
                "type": "Jalousie",
                "uuidAction": "aaaa0001-0000-0001-ffff000000000001",
                "isSecured": false,
                "states": { "position": "aaaa0001-0000-0002-ffff000000000002" }
            },
            "bbbb0001-0000-0001-ffff000000000003": {
                "name": "Alarm",
                "type": "Alarm",
                "uuidAction": "bbbb0001-0000-0001-ffff000000000003",
                "isSecured": true,
                "states": { "armed": "bbbb0001-0000-0002-ffff000000000004" },
                "subControls": {
                    "bbbb0001-0000-0001-ffff000000000003/sensors": {
                        "name": "sensors",
                        "type": "Tracker",
                        "uuidAction": "bbbb0001-0000-0001-ffff000000000003/sensors",
                        "isSecured": false,
                        "states": { "entries": "bbbb0001-0000-0003-ffff000000000005" }
                    }
                }
            }
        }
    }"#;

    fn sample() -> Structure {
        Structure::parse(SAMPLE.as_bytes()).unwrap()
    }

    #[test]
    fn finds_controls_by_name_and_type() {
        let s = sample();
        assert_eq!(s.find("Alarm").unwrap().kind(), "Alarm");
        assert_eq!(s.of_type("Jalousie").len(), 1);
        assert!(s.find("Nicht da").is_none());
    }

    #[test]
    fn gives_states_by_key() {
        let s = sample();
        let alarm = s.find("Alarm").unwrap();
        assert_eq!(
            alarm.state("armed"),
            Some("bbbb0001-0000-0002-ffff000000000004")
        );
        assert_eq!(alarm.state("unknown"), None);
        assert!(alarm.is_secured());
        assert!(!s.find("Example shutter").unwrap().is_secured());
    }

    #[test]
    fn sub_controls_are_listed_under_their_parent() {
        let s = sample();
        let subs: Vec<_> = s
            .find("Alarm")
            .unwrap()
            .sub_controls()
            .map(|c| c.name().to_owned())
            .collect();
        assert_eq!(subs, vec!["sensors".to_owned()]);
    }

    #[test]
    fn labels_name_controls_sub_controls_and_states() {
        let s = sample();
        assert_eq!(
            s.label("bbbb0001-0000-0002-ffff000000000004"),
            Some("Alarm / armed")
        );
        assert_eq!(
            s.label("bbbb0001-0000-0003-ffff000000000005"),
            Some("Alarm / sensors / entries")
        );
        assert_eq!(s.label("0000"), None);
    }

    #[test]
    fn finds_a_control_by_action_uuid() {
        let s = sample();
        let c = s.control("bbbb0001-0000-0001-ffff000000000003").unwrap();
        assert_eq!(c.name(), "Alarm");
    }

    #[test]
    fn last_modified_is_read() {
        assert_eq!(sample().last_modified(), Some("2026-01-01 10:00:00"));
    }

    #[test]
    fn rejects_non_json_and_files_without_controls() {
        assert!(matches!(
            Structure::parse(b"nope"),
            Err(StructureError::Json(_))
        ));
        assert!(matches!(
            Structure::parse(br#"{"lastModified": "x"}"#),
            Err(StructureError::NoControls)
        ));
    }
}
