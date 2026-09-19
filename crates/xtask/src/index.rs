//! The requirement index the crate ships (#31): every numbered rule of
//! PROTOCOL.md and LINK.md, with the heading it sits under and its first
//! sentence, so a consumer's traceability check walks the rules of the
//! crate it builds against rather than a hand-copied list that drifts the
//! first time a rule is added or renumbered.
//!
//! A rule is allocated where its number in bold, `**P-021**`, opens a line
//! or a list item. The same number in bold inside a sentence is emphasis on
//! a cross-reference, as PROTOCOL.md does with P-185 and P-196 where it
//! records what they replaced, and a number in plain prose is a
//! cross-reference too.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// The documents that number rules, and the letter each numbers them with.
const DOCUMENTS: [(&str, char); 2] = [("docs/PROTOCOL.md", 'P'), ("docs/protocol/LINK.md", 'L')];

/// Digits in a rule's number, always three.
const WIDTH: usize = 3;

pub struct Index {
    rust: String,
}

struct Rule {
    id: String,
    document: &'static str,
    section: String,
    statement: String,
}

impl Index {
    pub const PATH: &'static str = "crates/km43/src/requirements.rs";

    pub fn load(root: &Path) -> Result<Self> {
        let mut rules = Vec::new();
        let mut seen = BTreeSet::new();
        for (document, letter) in DOCUMENTS {
            let text = std::fs::read_to_string(root.join(document))
                .with_context(|| format!("reading {document}"))?;
            for rule in rules_in(&text, document, letter) {
                if !seen.insert(rule.id.clone()) {
                    bail!("{} is numbered twice in {document}", rule.id);
                }
                rules.push(rule);
            }
        }
        Ok(Self { rust: rust(&rules) })
    }

    /// Whether the committed table is not what the documents produce.
    pub fn stale(&self, root: &Path) -> bool {
        std::fs::read_to_string(root.join(Self::PATH)).map_or(true, |c| c != self.rust)
    }

    pub fn write(&self, root: &Path) -> Result<()> {
        let path = root.join(Self::PATH);
        let unchanged = std::fs::read_to_string(&path).is_ok_and(|c| c == self.rust);
        std::fs::write(&path, &self.rust)?;
        if !unchanged {
            println!("wrote {}", Self::PATH);
        }
        Ok(())
    }
}

fn rules_in(text: &str, document: &'static str, letter: char) -> Vec<Rule> {
    let needle = format!("**{letter}-");
    text.match_indices(&needle)
        .filter_map(|(at, _)| {
            let rest = text.get(at.checked_add(needle.len())?..)?;
            let (digits, tail) = rest.split_at_checked(WIDTH)?;
            let after = tail.strip_prefix("**")?;
            if !digits.bytes().all(|b| b.is_ascii_digit()) || !opens_a_line(text, at) {
                return None;
            }
            Some(Rule {
                id: format!("{letter}-{digits}"),
                document,
                section: section_before(text, at),
                statement: statement(after),
            })
        })
        .collect()
}

/// Whether only indentation and a list marker stand between the start of
/// `at`'s line and `at`.
fn opens_a_line(text: &str, at: usize) -> bool {
    let before = text.get(..at).unwrap_or_default();
    let line = before.rsplit('\n').next().unwrap_or(before).trim_start();
    let marker = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| {
            let (number, rest) = line.split_once(". ")?;
            number.bytes().all(|b| b.is_ascii_digit()).then_some(rest)
        })
        .unwrap_or(line);
    marker.trim().is_empty()
}

/// The last heading above `at`, without its hashes.
fn section_before(text: &str, at: usize) -> String {
    text.get(..at)
        .unwrap_or_default()
        .lines()
        .rev()
        .find(|line| line.starts_with('#'))
        .map(|line| line.trim_start_matches('#').trim().to_owned())
        .unwrap_or_default()
}

/// What a rule states: its first sentence, or, where that sentence runs
/// into a fenced block or introduces a list, through the block to where the
/// sentence ends, or through the whole list. No rule is exported cut off.
/// Whitespace collapsed; a fenced block becomes inline code.
fn statement(after: &str) -> String {
    let body = after
        .trim_start()
        .trim_start_matches(['—', '-', ':'])
        .trim_start();
    let mut text = String::new();
    // The lines of a fenced block being read, until its closing fence.
    let mut fence: Option<Vec<&str>> = None;
    let mut in_list = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(code) = fence.as_mut() {
            if trimmed.starts_with("```") {
                text.push_str(" `");
                text.push_str(&code.join(" "));
                text.push_str("` ");
                fence = None;
            } else if !trimmed.is_empty() {
                code.push(trimmed);
            }
            continue;
        }
        if trimmed.starts_with("```") {
            fence = Some(Vec::new());
            continue;
        }
        if trimmed.is_empty() {
            if in_list || ends_a_sentence(&text) {
                break;
            }
            continue;
        }
        if trimmed.starts_with('#') || opens_a_rule(trimmed) {
            break;
        }
        in_list |= is_list_item(trimmed);
        text.push_str(trimmed);
        text.push(' ');
        if !in_list && let Some(end) = sentence_end(&text) {
            text.truncate(end);
            break;
        }
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Where the first sentence of `text` ends, just past its full stop.
fn sentence_end(text: &str) -> Option<usize> {
    text.match_indices(". ")
        .map(|(at, _)| at.saturating_add(1))
        .next()
}

fn ends_a_sentence(text: &str) -> bool {
    text.trim_end().ends_with('.')
}

fn is_list_item(line: &str) -> bool {
    line.starts_with("- ")
        || line.starts_with("* ")
        || line.split_once(". ").is_some_and(|(number, _)| {
            !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
        })
}

fn opens_a_rule(line: &str) -> bool {
    ["**P-", "**L-", "- **P-", "- **L-"]
        .iter()
        .any(|start| line.starts_with(start))
}

fn rust(rules: &[Rule]) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "// Generated by `cargo xtask registry` from docs/PROTOCOL.md and docs/protocol/LINK.md."
    );
    let _ = writeln!(
        o,
        "// Do not edit: a rule is numbered in its document, and this table follows it.\n"
    );
    let _ = writeln!(o, "use crate::Requirement;\n");
    let _ = writeln!(
        o,
        "/// Every numbered rule of KM43, in document order: PROTOCOL.md, then LINK.md."
    );
    let _ = writeln!(o, "pub const REQUIREMENTS: &[Requirement] = &[");
    for rule in rules {
        let _ = writeln!(o, "    Requirement {{");
        let _ = writeln!(o, "        id: {:?},", rule.id);
        let _ = writeln!(o, "        document: {:?},", rule.document);
        let _ = writeln!(o, "        section: {:?},", rule.section);
        let _ = writeln!(o, "        statement: {:?},", rule.statement);
        let _ = writeln!(o, "    }},");
    }
    let _ = writeln!(o, "];");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_in_a_list_item_is_read_and_prose_is_not() {
        let text = "## Heading\n\n**L-010** — The first thing. The second.\n\n- **L-011** It MUST hold.\n\nSee L-012, and the **L-010** above, for more.\n";
        let rules = rules_in(text, "docs/protocol/LINK.md", 'L');
        let ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["L-010", "L-011"]);
        assert_eq!(rules[0].section, "Heading");
        assert_eq!(rules[0].statement, "The first thing.");
        assert_eq!(rules[1].statement, "It MUST hold.");
    }

    #[test]
    fn a_sentence_that_runs_into_a_block_is_taken_to_its_end() {
        let text = "## H\n\n**P-049** — The payload MUST be exactly\n\n```text\nkm43:1:<id>\n```\n\n— the literal `km43` and\nits parts. Then more.\n";
        let rules = rules_in(text, "docs/PROTOCOL.md", 'P');
        assert_eq!(
            rules[0].statement,
            "The payload MUST be exactly `km43:1:<id>` — the literal `km43` and its parts."
        );
    }

    #[test]
    fn a_rule_that_introduces_a_list_carries_the_whole_list() {
        let text = "## H\n\n**P-117** — The override:\n\n1. Is armed once. It MUST clear.\n2. Is single-use.\n\nAfter the list.\n";
        let rules = rules_in(text, "docs/PROTOCOL.md", 'P');
        assert_eq!(
            rules[0].statement,
            "The override: 1. Is armed once. It MUST clear. 2. Is single-use."
        );
    }

    #[test]
    fn a_number_that_is_not_three_digits_is_not_a_rule() {
        let text = "**P-21** is not one, and **P-0215** neither.\n";
        assert!(rules_in(text, "docs/PROTOCOL.md", 'P').is_empty());
    }
}
