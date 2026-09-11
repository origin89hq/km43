//! Compares what a MAC covers in the specification against what the generator
//! computes.
//!
//! The vectors gate proves the JSON matches the generator. It cannot see the
//! generator going stale against the spec, which is how a field reached a
//! preimage in one and nowhere else.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// The field sequence of every MAC, keyed by its domain label.
pub struct Preimages(BTreeMap<String, Vec<String>>);

impl Preimages {
    /// Reads every `HMAC(key, "label" | field | field)[0..16]` out of the
    /// specification.
    pub fn from_spec(root: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(root.join("docs/PROTOCOL.md"))?;
        let mut out = BTreeMap::new();
        let mut rest = text.as_str();

        while let Some(at) = rest.find("HMAC(") {
            rest = &rest[at + 5..];
            let Some(end) = rest.find(")[0..16]") else {
                continue;
            };
            let Some((label, fields)) = quoted_label(&rest[..end]) else {
                continue;
            };
            out.insert(label, normalise(fields));
        }
        Ok(Self(out))
    }

    /// Reads the same out of the generator's own descriptions.
    pub fn from_vectors(root: &Path) -> Result<Self> {
        let doc = vectors_json(root)?;
        let mut out = BTreeMap::new();
        for entry in doc
            .get("macs")
            .and_then(Value::as_object)
            .context("v1.json has no macs")?
            .values()
        {
            let Some(readable) = entry.get("preimage_readable").and_then(Value::as_str) else {
                continue;
            };
            if let Some((label, fields)) = single_quoted_label(readable) {
                out.insert(label, normalise(fields));
            }
        }
        Ok(Self(out))
    }

    /// Where the two disagree, in words that say which side to change.
    pub fn disagreements(&self, other: &Self) -> Vec<String> {
        let mut wrong = Vec::new();
        for (label, want) in &self.0 {
            match other.0.get(label) {
                None => wrong.push(format!("{label}: in PROTOCOL.md, no vector computes it")),
                Some(have) if have != want => wrong.push(format!(
                    "{label}\n    spec    {}\n    vectors {}",
                    want.join(" | "),
                    have.join(" | ")
                )),
                Some(_) => {}
            }
        }
        for label in other.0.keys() {
            if !self.0.contains_key(label) {
                wrong.push(format!(
                    "{label}: a vector computes it, PROTOCOL.md does not specify it"
                ));
            }
        }
        wrong
    }
}

/// A vector's `preimage` bytes, checked against the fields its description names.
///
/// Without this the two are prose beside prose: a field can be dropped from the
/// concatenation and left in the description, and everything agrees with
/// everything.
pub struct DescribedBytes {
    inputs: Value,
    entries: Vec<(String, Value)>,
}

impl DescribedBytes {
    pub fn load(root: &Path) -> Result<Self> {
        let doc = vectors_json(root)?;
        Ok(Self {
            inputs: doc.get("inputs").context("v1.json has no inputs")?.clone(),
            entries: doc
                .get("macs")
                .and_then(Value::as_object)
                .context("v1.json has no macs")?
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    pub fn disagreements(&self) -> Vec<String> {
        let mut wrong = Vec::new();
        for (name, entry) in &self.entries {
            let (Some(readable), Some(preimage)) = (
                entry.get("preimage_readable").and_then(Value::as_str),
                entry.get("preimage").and_then(Value::as_str),
            ) else {
                continue;
            };
            let Some((label, fields)) = single_quoted_label(readable) else {
                continue;
            };

            let mut want = to_hex(label.as_bytes());
            for field in fields.split('|').map(str::trim).filter(|f| !f.is_empty()) {
                // A variable-width field is always last, so once one appears
                // there is nothing further to pin.
                let Some(bytes) = self.resolve(field) else {
                    break;
                };
                want.push_str(&bytes);
            }
            if !preimage.starts_with(&want) {
                wrong.push(format!(
                    "{name}: the bytes are not the fields the description names\n    \
                     described {readable}\n    expected prefix {want}\n    actual          {}",
                    &preimage[..want.len().min(preimage.len())]
                ));
            }
        }
        wrong
    }

    /// The bytes a named field contributes, or `None` when its width is not fixed.
    fn resolve(&self, field: &str) -> Option<String> {
        let (name, ty) = field.split_once(':').map_or((field, ""), |(a, b)| (a, b));
        let name = name.split_once('[').map_or(name, |(a, _)| a).trim();

        if let Some(v) = self.inputs.get(name) {
            if let Some(s) = v.as_str() {
                return Some(
                    if s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                        s.to_owned()
                    } else {
                        to_hex(s.as_bytes())
                    },
                );
            }
            if let Some(n) = v.as_u64() {
                return match ty {
                    "u8" => Some(format!("{n:02x}")),
                    "u16be" => Some(format!("{n:04x}")),
                    "u32be" => Some(format!("{n:08x}")),
                    "u64be" => Some(format!("{n:016x}")),
                    _ => None,
                };
            }
        }
        // Literals the vectors do not carry as an input.
        match (name, ty) {
            ("outcome", "u8") => Some("01".to_owned()),
            ("0x00000000", _) => Some("00000000".to_owned()),
            _ => None,
        }
    }
}

fn vectors_json(root: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(root.join("docs/protocol/vectors/v1.json"))?;
    Ok(serde_json::from_str(&text)?)
}

/// Splits `… "label" | rest` into the label and the rest.
fn quoted_label(body: &str) -> Option<(String, &str)> {
    let q1 = body.find('"')?;
    let q2 = body[q1 + 1..].find('"')?;
    Some((body[q1 + 1..q1 + 1 + q2].to_owned(), &body[q1 + q2 + 2..]))
}

/// The same for the single-quoted form the vectors use.
fn single_quoted_label(s: &str) -> Option<(String, &str)> {
    let (_, rest) = s.split_once('\'')?;
    let (label, fields) = rest.split_once('\'')?;
    Some((label.to_owned(), fields))
}

/// Reduces a field list to bare names so the two spellings compare.
///
/// The spec writes `device_id` where the vector writes `device_id[16]`. Widths
/// and types are dropped; order and identity are what must match.
fn normalise(s: &str) -> Vec<String> {
    s.split('|')
        .map(|f| {
            let f = f.trim().trim_start_matches(',').trim();
            let f = f.split_once('[').map_or(f, |(a, _)| a);
            let f = f.split_once(':').map_or(f, |(a, _)| a);
            let f = f.split_once('(').map_or(f, |(a, _)| a);
            f.trim().trim_end_matches(')').trim().to_owned()
        })
        .filter(|f| !f.is_empty())
        .collect()
}

fn to_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}
