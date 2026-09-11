//! Holds the rows and nested bodies the vectors publish to the types
//! `PROTOCOL.md` defines inside a message.
//!
//! `bodies.rs` cannot reach these, in two independent ways, and both were found
//! by moving the artefact rather than by reading the code. A descriptor row
//! rides inside `Inventory 0x8D` as a `row_cbor` blob with no `body_readable`
//! beside it, and that check reads `body_readable` or skips the entry. On the
//! other side its parser treats a bare capitalised word inside a fence as the
//! end of the message above and throws the type's own key list away. So the
//! sixty-one descriptor row keys and the eight of `Sample` and `Series` were
//! published for as long as the rows were unspecified, and the check was green
//! the whole time.
//!
//! This one reads the key numbers out of the published bytes and compares them
//! to the document, which is the only comparison that can go red when a key is
//! renumbered in one place and not the other.

use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// One key of a nested body, as `PROTOCOL.md` lists it.
struct Key {
    number: u64,
    name: String,
    /// Marked `optional` in the document, so a row carrying required keys only
    /// is expected to leave it out.
    optional: bool,
}

/// Every type `PROTOCOL.md` defines inside a message rather than as one of its
/// own: the five descriptor rows, `Sample`, `Series`, and anything later that
/// is written the same way.
pub struct Spec(BTreeMap<String, Vec<Key>>);

impl Spec {
    pub fn read(root: &Path) -> Result<Self> {
        let path = root.join("docs/PROTOCOL.md");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;

        let mut types: BTreeMap<String, Vec<Key>> = BTreeMap::new();
        let mut current: Option<String> = None;
        let mut fenced = false;
        for line in text.lines() {
            if line.starts_with("```") {
                fenced = !fenced;
                current = None;
                continue;
            }
            if !fenced {
                continue;
            }
            if let Some(found) = nested(line) {
                current = Some(found);
            } else if let (Some(name), Some(key)) = (current.as_ref(), key(line)) {
                types.entry(name.clone()).or_default().push(key);
            } else if !line.starts_with(char::is_whitespace) {
                // A blank line, or a heading that carries an opcode and is
                // therefore a message rather than a nested type. Either way the
                // type above has had all its keys.
                current = None;
            }
        }

        if types.is_empty() {
            bail!("PROTOCOL.md defines no nested bodies, which cannot be right");
        }
        Ok(Self(types))
    }

    /// The type a published entry names, matched as written and then with `Row`
    /// on the end — `sample` is `Sample` and `signal` is `SignalRow`.
    fn find(&self, short: &str) -> Option<(&str, &[Key])> {
        self.0
            .iter()
            .find(|(name, _)| {
                name.eq_ignore_ascii_case(short)
                    || name.eq_ignore_ascii_case(&format!("{short}Row"))
            })
            .map(|(name, keys)| (name.as_str(), keys.as_slice()))
    }
}

/// How much of its type a published vector fills in.
#[derive(Clone, Copy)]
enum Fill {
    /// Every key the type has.
    Widest,
    /// Only the keys the document does not mark optional.
    RequiredOnly,
    /// The required keys and the two that make a series' elements nameable.
    Series,
}

impl Fill {
    /// What this vector's bytes ought to carry, in the order a row writes them.
    ///
    /// [`Self::Series`] names its two extra keys rather than numbering them, so
    /// renumbering `ebase` in the document moves what the bytes have to carry —
    /// which is the direction this check has to run in to be worth anything.
    fn wanted(self, keys: &[Key]) -> Vec<&Key> {
        keys.iter()
            .filter(|key| match self {
                Self::Widest => true,
                Self::RequiredOnly => !key.optional,
                Self::Series => !key.optional || key.name == "n" || key.name == "ebase",
            })
            .collect()
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Widest => "at its widest",
            Self::RequiredOnly => "carrying required keys only",
            Self::Series => "carrying its required keys, n and ebase",
        }
    }
}

/// One published vector of a nested body, and the keys its bytes actually hold.
struct Row {
    /// `inventory_0x8D.signal_widest`, so a failure names the entry to open.
    at: String,
    short: String,
    fill: Fill,
    keys: Vec<u64>,
}

/// The nested bodies `vectors/v1.json` publishes, read as key numbers out of
/// the CBOR rather than out of a description beside it.
pub struct Published(Vec<Row>);

impl Published {
    pub fn read(root: &Path) -> Result<Self> {
        let path = root.join("docs/protocol/vectors/v1.json");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let doc: Value = serde_json::from_str(&text)?;

        let mut out = Vec::new();
        let bodies = doc.get("bodies").and_then(Value::as_object);
        for (message, body) in bodies.into_iter().flatten() {
            let Some(entries) = body.as_object() else {
                continue;
            };
            for (entry, value) in entries {
                let Some(cbor) = value.get("row_cbor").and_then(Value::as_str) else {
                    continue;
                };
                let at = format!("{message}.{entry}");
                let (short, fill) = fill(entry).with_context(|| {
                    format!("{at} is a published row whose name says neither type nor fill")
                })?;
                out.push(Row {
                    keys: map_keys(cbor).with_context(|| format!("reading {at}"))?,
                    at,
                    short,
                    fill,
                });
            }
        }

        if out.is_empty() {
            bail!("the vectors publish no rows at all, which cannot be right");
        }
        Ok(Self(out))
    }

    /// Every published row whose keys are not the ones the document gives it.
    pub fn disagreements(&self, spec: &Spec) -> Vec<String> {
        let mut out = Vec::new();
        for row in &self.0 {
            let Some((name, keys)) = spec.find(&row.short) else {
                out.push(format!(
                    "{} publishes a {} and PROTOCOL.md defines no such body",
                    row.at, row.short
                ));
                continue;
            };
            let wanted = row.fill.wanted(keys);
            let numbers: Vec<u64> = wanted.iter().map(|key| key.number).collect();
            if row.keys != numbers {
                out.push(format!(
                    "{}: the bytes carry keys {} and PROTOCOL.md gives {name} {} {}",
                    row.at,
                    render(&row.keys),
                    row.fill.describe(),
                    name_keys(&wanted),
                ));
            }
        }
        out
    }
}

/// `Sample` or `SignalRow` on its own line: a type the message above embeds,
/// rather than a message of its own. One bare word, no opcode, hard against the
/// left margin.
fn nested(line: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    let word = words.next()?;
    let starts_upper = word.starts_with(|c: char| c.is_ascii_uppercase());
    if line.starts_with(char::is_whitespace)
        || words.next().is_some()
        || !starts_upper
        || !word.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(word.to_owned())
}

/// `  8: point        u16      optional; measurement point registry` becomes
/// key 8, named `point`, optional.
fn key(line: &str) -> Option<Key> {
    if !line.starts_with(char::is_whitespace) {
        return None;
    }
    let (number, rest) = line.trim().split_once(':')?;
    let number = number.trim().parse().ok()?;
    let name = rest.split_whitespace().next()?;
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some(Key {
        number,
        name: name.to_owned(),
        optional: rest.contains("optional"),
    })
}

/// `signal_widest` is a `SignalRow` with every key; `signal_required_keys_only`
/// is the same row with only the keys it must carry; `signal_series` is a row
/// that describes a real series and so carries `n` and `ebase` as well.
///
/// A published row that ends in none of the three is refused rather than checked
/// loosely. The looser reading would take `signal_widst` for a row of some new
/// kind and stop comparing it to anything.
fn fill(entry: &str) -> Result<(String, Fill)> {
    if let Some(short) = entry.strip_suffix("_widest") {
        return Ok((short.to_owned(), Fill::Widest));
    }
    if let Some(short) = entry.strip_suffix("_required_keys_only") {
        return Ok((short.to_owned(), Fill::RequiredOnly));
    }
    if let Some(short) = entry.strip_suffix("_series") {
        return Ok((short.to_owned(), Fill::Series));
    }
    bail!("`{entry}` ends in none of `_widest`, `_required_keys_only` or `_series`")
}

/// The keys of a CBOR map, in the order they were written.
///
/// Somebody else's decoder on purpose. `vectors.rs` is the encoder that wrote
/// these bytes, so reading them back with it would compare xtask to itself and
/// agree however wrong both were.
fn map_keys(hex: &str) -> Result<Vec<u64>> {
    let bytes = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            u8::from_str_radix(pair, 16).with_context(|| format!("`{pair}` is not a hex byte"))
        })
        .collect::<Result<Vec<u8>>>()?;

    let value: ciborium::value::Value = ciborium::from_reader(bytes.as_slice())?;
    let ciborium::value::Value::Map(pairs) = value else {
        bail!("a row must be a CBOR map and this one is not");
    };
    pairs
        .iter()
        .map(|(key, _)| {
            let ciborium::value::Value::Integer(number) = key else {
                bail!("a row's keys must be integers and one is not");
            };
            u64::try_from(i128::from(*number)).context("a row key is negative or enormous")
        })
        .collect()
}

fn render(keys: &[u64]) -> String {
    keys.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The document's side named as well as numbered, because `14` and `15` in a
/// disagreement are two numbers and `14:unit, 15:scale` is the pair somebody
/// can go and look at.
fn name_keys(keys: &[&Key]) -> String {
    keys.iter()
        .map(|key| format!("{}:{}", key.number, key.name))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{Fill, Key, fill, key, map_keys, nested};

    /// The line that starts a row body, and the three that look like one.
    #[test]
    fn a_nested_type_is_one_bare_capitalised_word_at_the_margin() {
        assert_eq!(nested("SignalRow").as_deref(), Some("SignalRow"));
        assert_eq!(nested("Sample").as_deref(), Some("Sample"));
        // A message heading carries an opcode, and is not a nested type.
        assert_eq!(nested("Inventory  0x8D              wrapper"), None);
        // A key line is indented.
        assert_eq!(nested("  1: sig          u16"), None);
        assert_eq!(nested(""), None);
    }

    /// **The row body inside `Inventory 0x8D` key 3 must not be read as a type.**
    /// `3: rows [ BusRow | DeviceRow | ... ]` names five types on one indented
    /// line; taking it would open a body called `BusRow` twice and give the
    /// second one no keys.
    #[test]
    fn the_alternation_in_the_wrapper_is_not_five_nested_types() {
        assert_eq!(
            nested(
                "  3: rows         [ BusRow | DeviceRow | ComponentRow | SignalRow | ParamRow ]"
            ),
            None
        );
    }

    #[test]
    fn a_key_carries_its_number_its_name_and_whether_it_is_optional() {
        let required = key("  5: shape        u8       the container: 1 scalar · 2 series")
            .expect("a required key");
        assert_eq!(required.number, 5);
        assert_eq!(required.name, "shape");
        assert!(!required.optional);

        let optional = key("  8: point        u16      optional; measurement point registry")
            .expect("an optional key");
        assert_eq!(optional.number, 8);
        assert!(optional.optional);
    }

    /// A description wraps onto its own indented line carrying no number, and a
    /// parser that took one would invent a key nothing published.
    #[test]
    fn a_wrapped_description_is_not_a_key() {
        assert!(key("                           vendor range, skip-unknown").is_none());
        assert!(key("BusRow").is_none());
    }

    #[test]
    fn a_published_name_says_which_type_and_how_full() {
        let (short, widest) = fill("signal_widest").expect("the widest signal row");
        assert_eq!(short, "signal");
        assert!(matches!(widest, Fill::Widest));

        let (short, bare) = fill("param_required_keys_only").expect("the bare param row");
        assert_eq!(short, "param");
        assert!(matches!(bare, Fill::RequiredOnly));
    }

    /// A vector whose name says neither is a new shape nobody taught this
    /// check, and guessing at it is how a row goes unread.
    #[test]
    fn a_published_name_that_says_neither_is_refused() {
        assert!(fill("signal_narrowest").is_err());
    }

    #[test]
    fn only_the_keys_a_row_must_carry_survive_the_required_fill() {
        let keys = [
            Key {
                number: 1,
                name: "sig".into(),
                optional: false,
            },
            Key {
                number: 2,
                name: "v".into(),
                optional: true,
            },
            Key {
                number: 3,
                name: "q".into(),
                optional: false,
            },
        ];
        let numbers =
            |fill: Fill| -> Vec<u64> { fill.wanted(&keys).iter().map(|key| key.number).collect() };
        assert_eq!(numbers(Fill::Widest), vec![1, 2, 3]);
        assert_eq!(numbers(Fill::RequiredOnly), vec![1, 3]);
    }

    /// `a2 0101 0201` is `{1: 1, 2: 1}`, and the keys are what this reads.
    #[test]
    fn a_rows_keys_are_read_from_its_bytes() {
        assert_eq!(map_keys("a201010201").expect("a two-key map"), vec![1, 2]);
    }

    /// A key above 23 costs its own byte, and one above 255 costs two — a
    /// reader that assumed one width would report `SignalRow`'s key 24 as
    /// something else entirely.
    #[test]
    fn a_key_wider_than_one_byte_is_still_one_key() {
        // {24: 0, 256: 0} — key 24 costs a second byte, key 256 a third.
        assert_eq!(
            map_keys("a218180019010000").expect("a wide-keyed map"),
            vec![24, 256]
        );
    }

    #[test]
    fn something_that_is_not_a_map_is_refused_rather_than_read_as_empty() {
        // `83010203` is the array [1, 2, 3], which has no keys at all.
        assert!(map_keys("83010203").is_err());
        assert!(map_keys("zz").is_err());
    }
}
