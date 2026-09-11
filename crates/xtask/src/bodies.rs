//! Holds the published message bodies to the field lists in `PROTOCOL.md`.
//!
//! `preimage.rs` does this for MAC preimages and it exists because a formula
//! changed in the spec and the generator did not follow. A body has the same
//! shape of problem and had nothing watching it: two implementations were
//! written from the document, agreed byte for byte — and a reviewer then
//! renumbered a key *in the document* and every check in the repo stayed green.
//! Agreement between two readers is not agreement with what they read.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// One body's fields, in the order the document lists them.
type Fields = Vec<(u64, String)>;

pub struct Bodies {
    /// Keyed the way the vector file names them: `discover_0x80`.
    bodies: BTreeMap<String, Fields>,
}

impl Bodies {
    /// The field lists in `PROTOCOL.md`, read out of the fenced blocks that
    /// define each message.
    pub fn from_spec(root: &Path) -> Result<Self> {
        let path = root.join("docs/PROTOCOL.md");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;

        let mut bodies = BTreeMap::new();
        let mut name: Option<String> = None;
        let mut fields = Fields::new();
        let mut fenced = false;
        for line in text.lines() {
            if line.starts_with("```") {
                // The fence is the only thing that ends a body. A field's
                // description wraps onto indented lines that carry no number,
                // and reading one of those as the end truncates the list — the
                // first version of this stopped at key 5 of `Hello 0x81` and
                // reported the other twelve as a disagreement.
                Self::keep(&mut bodies, name.take(), &mut fields);
                fenced = !fenced;
                continue;
            }
            if !fenced {
                continue;
            }
            if let Some(found) = heading(line) {
                Self::keep(&mut bodies, name.take(), &mut fields);
                name = Some(found);
            } else if nested(line) {
                // A type the message above embeds — `Value` inside `Snapshot
                // 0x82`, `LogEntry` inside `LogPage`. Its keys are its own and
                // they start again at 1. Without this they append to the message
                // and `snapshot_0x82` reads as an eight-key body with `1` twice,
                // which is a shape no message has.
                Self::keep(&mut bodies, name.take(), &mut fields);
            } else if let (Some(_), Some(pair)) = (name.as_ref(), field(line)) {
                fields.push(pair);
            }
        }
        Self::keep(&mut bodies, name, &mut fields);
        Ok(Self { bodies })
    }

    /// The `body_readable` strings the generator publishes.
    pub fn from_vectors(root: &Path) -> Result<Self> {
        let path = root.join("docs/protocol/vectors/v1.json");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let doc: Value = serde_json::from_str(&text)?;

        let mut bodies = BTreeMap::new();
        let published = doc.get("bodies").and_then(Value::as_object);
        for (name, entry) in published.into_iter().flatten() {
            let Some(readable) = entry.get("body_readable").and_then(Value::as_str) else {
                continue;
            };
            bodies.insert(name.clone(), readable_fields(readable));
        }
        Ok(Self { bodies })
    }

    /// Every body the vectors publish that the document does not agree with.
    ///
    /// A body the document defines and the vectors do not publish is not a
    /// disagreement — most messages have no vector yet, and reporting them
    /// would bury the ones that do under a list nobody reads.
    pub fn disagreements(&self, spec: &Self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, ours) in &self.bodies {
            let Some(theirs) = spec.bodies.get(name) else {
                out.push(format!(
                    "the vectors publish a {name} body and PROTOCOL.md defines no such message"
                ));
                continue;
            };
            if ours != theirs {
                out.push(format!(
                    "{name}: the vectors say {} and PROTOCOL.md says {}",
                    render(ours),
                    render(theirs)
                ));
            }
        }
        out
    }

    fn keep(into: &mut BTreeMap<String, Fields>, name: Option<String>, fields: &mut Fields) {
        if let Some(name) = name
            && !fields.is_empty()
        {
            into.insert(name, std::mem::take(fields));
        }
        fields.clear();
    }
}

/// `Discover  0x80          unauthenticated` becomes `discover_0x80`, which is
/// how the vector file names it.
fn heading(line: &str) -> Option<String> {
    if line.starts_with(char::is_whitespace) {
        return None;
    }
    let mut words = line.split_whitespace();
    let name = words.next()?;
    let opcode = words.next()?;
    if !name.chars().all(|c| c.is_ascii_alphabetic()) || !opcode.starts_with("0x") {
        return None;
    }
    Some(format!("{}_{opcode}", name.to_ascii_lowercase()))
}

/// `Value` on its own line: a type embedded in the message above, rather than a
/// message of its own. One bare word, no opcode, hard against the left margin.
fn nested(line: &str) -> bool {
    let mut words = line.split_whitespace();
    let Some(word) = words.next() else {
        return false;
    };
    !line.starts_with(char::is_whitespace)
        && words.next().is_none()
        && word.chars().all(|c| c.is_ascii_alphanumeric())
}

/// `  8: epoch            u32      provisioning epoch` becomes `(8, "epoch")`.
fn field(line: &str) -> Option<(u64, String)> {
    if !line.starts_with(char::is_whitespace) {
        return None;
    }
    let (number, rest) = line.trim().split_once(':')?;
    let number = number.trim().parse().ok()?;
    let name = rest.split_whitespace().next()?;
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((number, name.to_owned()))
}

/// `{1:protocol_major=1, 2:protocol_minor=0, …}` becomes the same pairs.
fn readable_fields(readable: &str) -> Fields {
    readable
        .trim_matches(['{', '}'])
        .split(',')
        .filter_map(|part| {
            let (number, rest) = part.trim().split_once(':')?;
            let name = rest.split('=').next()?.trim();
            Some((number.trim().parse().ok()?, name.to_owned()))
        })
        .collect()
}

fn render(fields: &Fields) -> String {
    fields
        .iter()
        .map(|(number, name)| format!("{number}:{name}"))
        .collect::<Vec<_>>()
        .join(", ")
}
