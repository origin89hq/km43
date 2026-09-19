//! The numbered rules of KM43 as data, for a consumer's traceability check
//! (#31).
//!
//! A firmware names a test after the rule it proves, `l_014_...`, and its
//! gate refuses a citation of a rule that does not exist. [`REQUIREMENTS`]
//! is what that gate walks. `cargo xtask registry` generates it from
//! PROTOCOL.md and LINK.md, `cargo xtask check` refuses a table the
//! documents no longer produce, and it ships in the package, so a consumer
//! building from crates.io reads the rules of the version it builds
//! against.

/// One numbered rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    /// `P-021` or `L-014`: the letter of its document and three digits.
    pub id: &'static str,
    /// The document that numbers it, from the repository's root.
    pub document: &'static str,
    /// The heading it sits under.
    pub section: &'static str,
    /// Its first sentence, whitespace collapsed.
    pub sentence: &'static str,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::collections::BTreeSet;

    use crate::REQUIREMENTS;

    #[test]
    fn every_rule_is_numbered_once_and_named_by_its_document() {
        let mut seen = BTreeSet::new();
        for rule in REQUIREMENTS {
            assert!(seen.insert(rule.id), "{} twice", rule.id);
            let (letter, digits) = rule.id.split_once('-').expect("a letter and a number");
            assert_eq!(digits.len(), 3, "{}", rule.id);
            assert!(digits.bytes().all(|b| b.is_ascii_digit()), "{}", rule.id);
            let document = match letter {
                "P" => "docs/PROTOCOL.md",
                "L" => "docs/protocol/LINK.md",
                other => panic!("{other} is neither document's letter"),
            };
            assert_eq!(rule.document, document, "{}", rule.id);
            assert!(!rule.sentence.is_empty(), "{} says nothing", rule.id);
            assert!(
                !rule.section.is_empty(),
                "{} sits under no heading",
                rule.id
            );
        }
    }

    #[test]
    fn the_index_holds_the_rules_a_consumer_cites() {
        for id in ["P-001", "L-015", "L-033", "L-034", "L-190", "L-192"] {
            assert!(
                REQUIREMENTS.iter().any(|rule| rule.id == id),
                "{id} is missing"
            );
        }
    }

    #[test]
    fn a_number_no_document_allocates_is_not_in_the_index() {
        assert!(!REQUIREMENTS.iter().any(|rule| rule.id == "L-999"));
        assert!(!REQUIREMENTS.iter().any(|rule| rule.id == "P-000"));
    }
}
