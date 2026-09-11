//! Which numbered requirements have something that can fail standing behind
//! them.
//!
//! The denominator is the specification itself — every `**P-nnn**` in
//! PROTOCOL.md and every `**L-nnn**` in LINK.md — so it moves the moment
//! somebody writes a new rule. The numerator is a test named after the
//! requirement it proves, and only if that test can actually fail: a citation
//! whose body has no assertion is how every traceability matrix ever built came
//! to report full coverage over nothing.
//!
//! When this was written not one test in the workspace stood behind a
//! requirement, so a check that failed on "uncovered" would have been red on its
//! first run and switched off by its second, which is no check at all. What is
//! enforced instead is
//! a ratchet: `traceability.toml` records how many requirements are uncovered
//! and undeclared, and this refuses a count that went up *and* a count that went
//! down without the number being lowered with it. The reasoning is in
//! `docs/protocol/VERIFICATION.md`, section 1.

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Which document a number was allocated in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Doc {
    Protocol,
    Link,
}

impl Doc {
    /// Both, because PROTOCOL.md leans on LINK.md normatively. Counting only
    /// the `P-` numbers would report full coverage while the connection
    /// lifecycle, the heartbeat ladder and the backpressure ladder had nothing
    /// behind them at all.
    const BOTH: [Self; 2] = [Self::Protocol, Self::Link];

    fn path(self) -> &'static str {
        match self {
            Self::Protocol => "docs/PROTOCOL.md",
            Self::Link => "docs/protocol/LINK.md",
        }
    }

    fn letter(self) -> char {
        match self {
            Self::Protocol => 'P',
            Self::Link => 'L',
        }
    }

    fn from_letter(c: char) -> Option<Self> {
        match c.to_ascii_uppercase() {
            'P' => Some(Self::Protocol),
            'L' => Some(Self::Link),
            _ => None,
        }
    }

    /// How many separate obligations each requirement states.
    ///
    /// Counted as `MUST`/`SHALL` occurrences from the bold id to the end of its
    /// paragraph. **It is a smell and not a rule**: `MUST do X and MUST NOT do
    /// the opposite of X` is one behaviour stated twice, and nothing here can
    /// tell that from two obligations. That is why what reads it warns.
    fn obligations_in(self, text: &str) -> BTreeMap<ReqId, usize> {
        let mut out = BTreeMap::new();
        let needle = format!("**{}-", self.letter());
        for (at, _) in text.match_indices(&needle) {
            let Some(rest) = text.get(at.saturating_add(needle.len())..) else {
                continue;
            };
            let Some((digits, tail)) = rest.split_at_checked(ReqId::WIDTH) else {
                continue;
            };
            if !tail.starts_with("**") || !digits.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(number) = digits.parse() else {
                continue;
            };
            let body = tail.split("\n\n").next().unwrap_or_default();
            let obligations =
                body.match_indices("MUST").count() + body.match_indices("SHALL").count();
            out.insert(ReqId { doc: self, number }, obligations);
        }
        out
    }

    /// The house format is `**P-021**` in bold at the head of the paragraph, so
    /// that is what is counted. A number mentioned in running prose is a
    /// cross-reference, not a second requirement.
    fn ids_in(self, text: &str) -> BTreeSet<ReqId> {
        let needle = format!("**{}-", self.letter());
        text.match_indices(&needle)
            .filter_map(|(at, _)| {
                let rest = text.get(at.checked_add(needle.len())?..)?;
                let (digits, tail) = rest.split_at_checked(ReqId::WIDTH)?;
                if !tail.starts_with("**") || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                Some(ReqId {
                    doc: self,
                    number: digits.parse().ok()?,
                })
            })
            .collect()
    }
}

/// One numbered requirement, as `P-021` or `L-014`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
struct ReqId {
    doc: Doc,
    number: u16,
}

impl ReqId {
    /// Three digits, always. `P-21` and `P-021` naming the same rule is two
    /// spellings of one citation, and the set that counts them would hold both.
    const WIDTH: usize = 3;
}

impl FromStr for ReqId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (letter, digits) = s
            .split_once('-')
            .ok_or_else(|| anyhow!("{s:?} is not P-nnn or L-nnn"))?;
        let mut chars = letter.chars();
        let doc = chars
            .next()
            .and_then(Doc::from_letter)
            .filter(|_| chars.next().is_none())
            .ok_or_else(|| anyhow!("{s:?} names no document; requirements are P- or L-"))?;
        if digits.len() != Self::WIDTH || !digits.bytes().all(|b| b.is_ascii_digit()) {
            bail!("{s:?} is not three digits");
        }
        Ok(Self {
            doc,
            number: digits.parse()?,
        })
    }
}

impl TryFrom<String> for ReqId {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl fmt::Display for ReqId {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            w,
            "{}-{:0width$}",
            self.doc.letter(),
            self.number,
            width = Self::WIDTH
        )
    }
}

/// Why a requirement no test can reach is allowed to have no test.
///
/// There is no fifth variant: a `traceability.toml` naming a kind that does not
/// exist fails to parse, at the line that names it. "we have not got round to
/// it" is not one of these, and that is the point — it belongs in the ratchet,
/// where it is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    /// The subject is a connector, a supply rail or a physical gesture. A dated
    /// bench log stands in, named in the reason.
    Hardware,
    /// A check over the corpus rather than over an implementation. It names the
    /// check, and the check has to be one this command runs.
    SpecCheck,
    /// Waiting on something that has not been built. The DEFERRED entry's
    /// trigger is what stops this bucket becoming a graveyard.
    Deferred,
    /// A test can prove the machine did its part and nothing can prove a person
    /// read it. Say so rather than pretending.
    Judgement,
}

impl Kind {
    /// Only a spec-check has something mechanical behind it. The other three
    /// are a written excuse, which is worth having and is not coverage.
    fn is_covered(self) -> bool {
        match self {
            Self::SpecCheck => true,
            Self::Hardware | Self::Deferred | Self::Judgement => false,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        w.write_str(match self {
            Self::Hardware => "hardware",
            Self::SpecCheck => "spec-check",
            Self::Deferred => "deferred",
            Self::Judgement => "judgement",
        })
    }
}

/// One requirement no test can reach, and why.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: ReqId,
    kind: Kind,
    /// The xtask check that stands in, on a `spec-check` and nowhere else.
    #[serde(default)]
    check: Option<String>,
    reason: String,
}

/// The number somebody defends at each audit round.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ratchet {
    uncovered: usize,
}

/// A requirement that states more than one thing, and a word from the name of
/// the test standing behind each clause.
///
/// **Without this a rule with two clauses reads as covered the moment one of
/// them has a test.** P-164 sat that way — the validity clause tested, the
/// concern clause unwritten — and the only thing that said so was a paragraph in
/// a design document. The matrix counted it covered either way, which is worse
/// than counting it uncovered, because nobody goes looking at a number that is
/// already green.
///
/// Matched on a fragment of the test name rather than on a count of tests: two
/// tests about the same clause satisfy a count and prove nothing. Renaming a
/// test that stands behind a clause turns this red, which is the intended
/// behaviour — a rename is exactly when somebody should be asked whether the
/// clause still has a test.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Clauses {
    id: ReqId,
    /// One fragment per clause, each of which has to appear in the name of some
    /// counting test that cites this requirement.
    each: Vec<String>,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declarations {
    ratchet: Ratchet,
    #[serde(default)]
    entry: Vec<Entry>,
    #[serde(default)]
    clauses: Vec<Clauses>,
}

/// A test name or a header that names the requirement it stands behind.
#[derive(Debug)]
struct Citation {
    id: ReqId,
    /// `path:line`, so the report points at the line rather than at the file.
    site: String,
    /// The test's own name, for a requirement that states more than one thing
    /// and declares its clauses. Empty for a `cites:` header, which stands for
    /// a whole file and therefore cannot say which clause it is about.
    name: String,
    state: State,
}

/// Whether a citation is worth anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Counts,
    /// Nothing in the body can fail, so the requirement is uncovered and looks
    /// covered — which is worse than uncovered, because nobody goes looking.
    NoAssertion,
    Ignored,
}

impl State {
    /// The sentence the report ends with, or `None` when the citation counts.
    fn rejection(self) -> Option<&'static str> {
        match self {
            Self::Counts => None,
            Self::NoAssertion => Some("its body contains no assertion"),
            Self::Ignored => Some("it is marked #[ignore]"),
        }
    }
}

/// One `.rs` file, read once and asked several questions.
struct Source {
    path: String,
    text: String,
}

impl Source {
    /// Every `.rs` file in the tree, which is where a citation can live.
    ///
    /// Every file, not every compiled file: a `.rs` that no `mod` declares is
    /// never built and its tests never run, and a citation living in one would
    /// be counted here. Nothing catches that yet, so it is worth knowing about
    /// the first time a requirement looks covered and the test cannot be found
    /// in `cargo test` output.
    fn under(root: &Path) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        Self::walk(root, root, &mut out)?;
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    fn walk(root: &Path, dir: &Path, out: &mut Vec<Self>) -> Result<()> {
        const SKIP: [&str; 4] = ["target", ".git", "node_modules", ".claude"];
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            let name = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            if SKIP.contains(&name) {
                continue;
            }
            if path.is_dir() {
                Self::walk(root, &path, out)?;
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(Self {
                    path: path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                    text: std::fs::read_to_string(&path)?,
                });
            }
        }
        Ok(())
    }

    fn citations(&self) -> Vec<Citation> {
        let mut out = self.named_tests();
        out.extend(self.header_cites());
        out
    }

    /// `fn p_021_a_client_that_never_paired_is_refused`, and it has to be a
    /// `#[test]` — a helper named after a requirement proves nothing.
    ///
    /// The number is read off the name rather than looked up, so a test citing
    /// a rule the spec no longer has is found instead of being invisible.
    fn named_tests(&self) -> Vec<Citation> {
        let mut out = Vec::new();
        for (at, _) in self.text.match_indices("fn ") {
            let rest = self.text.get(at.saturating_add(3)..).unwrap_or_default();
            let Some(id) = test_name_id(rest) else {
                continue;
            };
            let attrs = self.attributes_before(at);
            if !attrs.contains("#[test]") {
                continue;
            }
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            out.push(Citation {
                id,
                site: self.site(at),
                name,
                state: self.state_of(at, attrs),
            });
        }
        out
    }

    fn state_of(&self, at: usize, attrs: &str) -> State {
        if attrs.contains("#[ignore]") {
            State::Ignored
        } else if attrs.contains("should_panic") || self.body_after(at).is_some_and(asserts) {
            State::Counts
        } else {
            State::NoAssertion
        }
    }

    /// The header form, `cites: P-024, P-072` on a module doc line. It survives
    /// a rename, which a test name does not, and it is the only way one test
    /// stands behind two rules without empty shims.
    fn header_cites(&self) -> Vec<Citation> {
        let file_state = self.file_state();
        let mut out = Vec::new();
        for (n, line) in self.text.lines().enumerate() {
            let Some(list) = line
                .trim_start()
                .strip_prefix("//!")
                .map(str::trim_start)
                .and_then(|rest| rest.strip_prefix("cites:"))
            else {
                continue;
            };
            for word in list.split([',', ' ']).filter(|w| !w.is_empty()) {
                if let Ok(id) = word.trim_end_matches('.').parse() {
                    out.push(Citation {
                        id,
                        site: format!("{}:{}", self.path, n.saturating_add(1)),
                        name: String::new(),
                        state: file_state,
                    });
                }
            }
        }
        out
    }

    /// A header cites for the whole file, so the whole file is what has to be
    /// able to fail.
    fn file_state(&self) -> State {
        if self.text.contains("#[ignore]") {
            return State::Ignored;
        }
        let has_asserting_test = self.text.match_indices("fn ").any(|(at, _)| {
            self.attributes_before(at).contains("#[test]")
                && self.body_after(at).is_some_and(asserts)
        });
        if has_asserting_test {
            State::Counts
        } else {
            State::NoAssertion
        }
    }

    /// The run of attribute and doc lines directly above an item, back to the
    /// first line that is neither.
    fn attributes_before(&self, at: usize) -> &str {
        let head = self.text.get(..at).unwrap_or_default();
        let mut start = head.len();
        for line in head.lines().rev() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with('#') && !trimmed.starts_with("//") && !trimmed.is_empty() {
                break;
            }
            if trimmed.is_empty() && start != head.len() {
                break;
            }
            start = start.saturating_sub(line.len().saturating_add(1));
        }
        head.get(start..).unwrap_or_default()
    }

    /// The body of the item whose signature starts at `at`, brace-matched with
    /// strings, chars and comments stepped over — a `"{"` in a fixture would
    /// otherwise close the body early and hide the assertion below it.
    ///
    /// `None` where the braces do not close, and the caller reads that as no
    /// assertion: a citation nobody can read is not coverage.
    fn body_after(&self, at: usize) -> Option<&str> {
        let rest = self.text.get(at..)?;
        let open = rest.find('{')?;
        let mut depth = 0usize;
        let mut mode = Lex::Code;
        let mut escaped = false;
        for (i, c) in rest.char_indices().skip(open) {
            mode = match (mode, c) {
                (Lex::Code, '/') if rest.get(i..i.checked_add(2)?) == Some("//") => Lex::Line,
                (Lex::Code, '/') if rest.get(i..i.checked_add(2)?) == Some("/*") => Lex::Block,
                (Lex::Code, '"') => Lex::Str,
                (Lex::Code, '\'') => Lex::Chr,
                (Lex::Line, '\n') | (Lex::Str, '"') | (Lex::Chr, '\'') if !escaped => Lex::Code,
                (Lex::Block, '/') if i > 0 && rest.get(i.checked_sub(1)?..i) == Some("*") => {
                    Lex::Code
                }
                (m, _) => m,
            };
            escaped = matches!(mode, Lex::Str | Lex::Chr) && c == '\\' && !escaped;
            if !matches!(mode, Lex::Code) {
                continue;
            }
            match c {
                '{' => depth = depth.saturating_add(1),
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return rest.get(open..=i);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn site(&self, at: usize) -> String {
        let line = self
            .text
            .get(..at)
            .unwrap_or_default()
            .bytes()
            .filter(|&b| b == b'\n')
            .count();
        format!("{}:{}", self.path, line.saturating_add(1))
    }
}

/// What the brace matcher is stepping through.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lex {
    Code,
    Line,
    Block,
    Str,
    Chr,
}

/// The requirement a test name opens with, as in `p_021_a_pre_session_client`.
///
/// The citation is a prefix and not a suffix so that `grep p_021` finds every
/// test standing behind the rule, and the rest of the name obeys the house rule
/// of naming the failure rather than the function.
fn test_name_id(name: &str) -> Option<ReqId> {
    let (head, tail) = name.split_at_checked(ReqId::WIDTH.checked_add(2)?)?;
    if !tail.starts_with('_') || head.get(1..2)? != "_" {
        return None;
    }
    format!("{}-{}", head.get(..1)?.to_ascii_uppercase(), head.get(2..)?)
        .parse()
        .ok()
}

/// The token rather than the exact macro, so a helper called
/// `assert_frame_rejected` counts and a comment that talks about asserting does
/// not.
fn asserts(body: &str) -> bool {
    body.lines()
        .map(|l| l.split("//").next().unwrap_or_default())
        .any(|code| code.contains("assert"))
}

/// The specification's requirements, what stands behind each of them, and the
/// number of the ones with nothing.
pub struct Traceability {
    required: BTreeSet<ReqId>,
    citations: Vec<Citation>,
    declared: Vec<Entry>,
    /// Requirements that state more than one thing, and the clause fragments
    /// each of them needs a test for.
    clauses: Vec<Clauses>,
    /// How many obligations each requirement's own text states, for the warning
    /// that finds the next P-164 rather than waiting for somebody to notice one.
    obligations: BTreeMap<ReqId, usize>,
    /// The checks `cargo xtask check` runs, so a nomination naming one that was
    /// renamed is caught rather than read as coverage forever.
    checks: BTreeSet<String>,
    ratchet: usize,
}

impl Traceability {
    /// Beside the documents it accounts for, because it is read with them.
    pub const PATH: &'static str = "docs/protocol/traceability.toml";

    pub fn load(root: &Path) -> Result<Self> {
        let mut required = BTreeSet::new();
        let mut obligations = BTreeMap::new();
        for doc in Doc::BOTH {
            let path = root.join(doc.path());
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            required.extend(doc.ids_in(&text));
            obligations.extend(doc.obligations_in(&text));
        }

        let path = root.join(Self::PATH);
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let declarations: Declarations =
            toml::from_str(&source).with_context(|| format!("parsing {}", path.display()))?;

        let citations = Source::under(root)?
            .iter()
            .flat_map(Source::citations)
            .collect();

        Ok(Self {
            required,
            citations,
            declared: declarations.entry,
            clauses: declarations.clauses,
            obligations,
            checks: check_names(root)?,
            ratchet: declarations.ratchet.uncovered,
        })
    }

    /// A requirement with an asserting citation, or with a check nominated and
    /// running.
    fn covered(&self) -> BTreeSet<ReqId> {
        let mut set: BTreeSet<ReqId> = self
            .citations
            .iter()
            .filter(|c| c.state == State::Counts)
            .map(|c| c.id)
            .collect();
        set.extend(
            self.declared
                .iter()
                .filter(|e| e.kind.is_covered() && self.nomination_runs(e))
                .map(|e| e.id),
        );
        set.retain(|id| self.required.contains(id));
        // A requirement that states more than one thing is covered only when
        // every clause has a test. One clause's test used to be enough, which
        // made a half-built rule read greener than an unbuilt one.
        set.retain(|id| self.missing_clauses(*id).is_empty());
        set
    }

    /// The clauses of a requirement that no counting test names.
    ///
    /// Empty for anything that has not declared clauses, which is almost
    /// everything: this is for rules that say two things, not a tax on rules
    /// that say one.
    fn missing_clauses(&self, id: ReqId) -> Vec<String> {
        let Some(declared) = self.clauses.iter().find(|c| c.id == id) else {
            return Vec::new();
        };
        let names: Vec<&str> = self
            .citations
            .iter()
            .filter(|c| c.id == id && c.state == State::Counts)
            .map(|c| c.name.as_str())
            .collect();
        declared
            .each
            .iter()
            .filter(|fragment| !names.iter().any(|name| name.contains(fragment.as_str())))
            .cloned()
            .collect()
    }

    /// Clause declarations naming a requirement the specification does not have,
    /// so a rule that was renumbered does not leave a declaration standing over
    /// nothing.
    fn clauses_over_nothing(&self) -> Vec<ReqId> {
        self.clauses
            .iter()
            .map(|c| c.id)
            .filter(|id| !self.required.contains(id))
            .collect()
    }

    fn nomination_runs(&self, e: &Entry) -> bool {
        e.check.as_deref().is_some_and(|n| self.checks.contains(n))
    }

    fn declared_untestable(&self) -> BTreeSet<ReqId> {
        let covered = self.covered();
        self.declared
            .iter()
            .map(|e| e.id)
            .filter(|id| self.required.contains(id) && !covered.contains(id))
            .collect()
    }

    fn uncovered(&self) -> Vec<ReqId> {
        let covered = self.covered();
        let declared = self.declared_untestable();
        self.required
            .iter()
            .filter(|id| !covered.contains(id) && !declared.contains(id))
            .copied()
            .collect()
    }

    /// The three counts and the uncovered list, printed whether or not the
    /// check passes. A number nobody sees between the round it was agreed and
    /// the round it is defended is a number nobody is defending.
    pub fn summary(&self) -> String {
        let uncovered = self.uncovered();
        let mut out = format!(
            "traceability: {} covered, {} declared untestable, {} uncovered of {}",
            self.covered().len(),
            self.declared_untestable().len(),
            uncovered.len(),
            self.required.len()
        );
        let names: Vec<String> = uncovered.iter().map(ToString::to_string).collect();
        for line in wrap(&names, 66) {
            let _ = write!(out, "\n  uncovered  {line}");
        }
        for declared in &self.clauses {
            for clause in self.missing_clauses(declared.id) {
                let _ = write!(
                    out,
                    "\n  no clause  {} states `{clause}` and no test names it",
                    declared.id
                );
            }
        }
        for c in &self.citations {
            if let Some(why) = c.state.rejection() {
                let _ = write!(out, "\n  not counted {} cites {} and {why}", c.site, c.id);
            }
        }
        let thin: Vec<String> = self.cited_once().iter().map(ToString::to_string).collect();
        if !thin.is_empty() {
            for line in wrap(&thin, 66) {
                let _ = write!(out, "\n  one test   {line}");
            }
        }
        let bare: Vec<String> = self
            .covered_by_a_header_alone()
            .iter()
            .map(ToString::to_string)
            .collect();
        if !bare.is_empty() {
            let _ = write!(
                out,
                "\n  {} of {} covered rules have no test named after them, only a `cites:` header \
                 claiming them for a whole file:",
                bare.len(),
                self.covered().len()
            );
            for line in wrap(&bare, 66) {
                let _ = write!(out, "\n  header     {line}");
            }
        }
        let states: Vec<String> = self
            .thin_for_what_it_states()
            .into_iter()
            .map(|(id, n)| format!("{id}({n})"))
            .collect();
        if !states.is_empty() {
            let _ = write!(
                out,
                "\n  states two or more things and stands on one test — read each beside its code, \
                 and give it `[[clauses]]` if the reading says two:"
            );
            for line in wrap(&states, 66) {
                let _ = write!(out, "\n  two rules  {line}");
            }
        }
        out
    }

    /// Covered rules that no test is named after.
    ///
    /// A `//! cites:` header is a claim by a **whole file**: any asserting test
    /// in it makes every requirement the header names count. That is the right
    /// mechanism for one test genuinely standing behind two rules, and the wrong
    /// one for a rule the file does not implement — `envelope.rs` claimed P-143's
    /// two refusals, which no test in the tree makes and which no code in the
    /// tree performs, and the matrix counted it covered for as long as the header
    /// had been there.
    ///
    /// Printed because the size of this list is the single most useful number
    /// about how much the count is worth. A warning and not a failure: many of
    /// these are honest — `crc.rs` claiming the CRC rule is a file that is about
    /// nothing else — and a check that cannot tell those apart would be asking
    /// for seventy renames rather than seventy readings.
    fn covered_by_a_header_alone(&self) -> Vec<ReqId> {
        let covered = self.covered();
        let mut out: Vec<ReqId> = covered
            .iter()
            .filter(|id| {
                let mut counting = self
                    .citations
                    .iter()
                    .filter(|c| c.id == **id && c.state == State::Counts)
                    .peekable();
                counting.peek().is_some() && counting.all(|c| c.name.is_empty())
            })
            .copied()
            .collect();
        out.sort_unstable();
        out
    }

    /// Covered rules that state two things and stand on one test.
    ///
    /// **The intersection is the P-164 shape**: it read covered, its text says
    /// `MUST report ...` and `MUST raise ...`, and one test carried both. The
    /// gap was found by somebody reading the requirement beside the code, and
    /// this is that reading done every time the gate runs.
    ///
    /// A warning and never a failure, for the reason [`Self::cited_once`] gives
    /// and one more of its own: `MUST do X and MUST NOT do the opposite` is one
    /// behaviour stated twice, and nothing here can tell that from two
    /// obligations. Making it fail would force a `[[clauses]]` entry for every
    /// one of them, which is filling the file to make a number go down — the
    /// thing `traceability.toml` says out loud it must not become.
    ///
    /// A rule that has declared its clauses is not listed: it has already been
    /// read, and the clause check is what holds it now.
    fn thin_for_what_it_states(&self) -> Vec<(ReqId, usize)> {
        let covered = self.covered();
        let declared: BTreeSet<ReqId> = self.clauses.iter().map(|c| c.id).collect();
        self.cited_once()
            .into_iter()
            .filter(|id| covered.contains(id) && !declared.contains(id))
            .filter_map(|id| {
                let n = self.obligations.get(&id).copied().unwrap_or_default();
                (n >= 2).then_some((id, n))
            })
            .collect()
    }

    /// Requirements standing on a single citation.
    ///
    /// A warning the audit round reads, never a build failure: one test behind a
    /// receiver behaviour usually means somebody wrote the happy path and
    /// stopped, and the house rule asks for a normal, an edge and a
    /// rejection. It cannot tell a rule that genuinely needs one test from a rule
    /// somebody got bored of, which is exactly why it warns rather than refuses.
    fn cited_once(&self) -> Vec<ReqId> {
        let covered = self.covered();
        let mut counted: BTreeMap<ReqId, usize> = BTreeMap::new();
        for c in self.citations.iter().filter(|c| c.state == State::Counts) {
            *counted.entry(c.id).or_default() += 1;
        }
        counted
            .into_iter()
            .filter(|&(id, n)| n == 1 && covered.contains(&id))
            .map(|(id, _)| id)
            .collect()
    }

    /// Everything that is wrong regardless of the count, then the ratchet.
    pub fn verdict(&self) -> Result<(), String> {
        let mut wrong = self.declaration_faults();
        wrong.extend(self.clause_faults());
        wrong.extend(self.citation_faults());
        wrong.extend(self.ratchet_fault());
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(wrong.join("\n\n"))
        }
    }

    fn ratchet_fault(&self) -> Option<String> {
        let real = self.uncovered().len();
        let recorded = self.ratchet;
        match real.cmp(&recorded) {
            std::cmp::Ordering::Equal => None,
            std::cmp::Ordering::Greater => Some(format!(
                "{real} requirements are uncovered and undeclared; {} records {recorded}.\n\
                 Either write a test named after one of them, or declare it in that file with a \
                 kind and a reason. Raising the number to {real} is the third option and it is \
                 the one somebody has to argue for out loud — the count is what the last audit \
                 round agreed to, and the spec gaining a rule is the only reason it should move \
                 up.",
                Self::PATH
            )),
            std::cmp::Ordering::Less => Some(format!(
                "only {real} requirements are uncovered and {} still records {recorded}. Lower \
                 `uncovered` to {real} in this commit.\n\
                 A ratchet nobody tightens rusts open: the slack left behind quietly absorbs the \
                 next rules nobody covers, and the number stops being anything somebody agreed to.",
                Self::PATH
            )),
        }
    }

    /// A clause declaration standing over nothing, or with an empty reason.
    ///
    /// The missing clause itself is **not** a fault here: it makes the
    /// requirement uncovered, which the ratchet already accounts for. Reporting
    /// it twice would make one gap look like two.
    fn clause_faults(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for c in &self.clauses {
            if !seen.insert(c.id) {
                out.push(format!(
                    "{} declares its clauses twice in {}. One rule has one list of the things it \
                     says.",
                    c.id,
                    Self::PATH
                ));
            }
            if c.each.len() < 2 {
                out.push(format!(
                    "{} declares {} clause in {}. A rule that says one thing does not need this \
                     table, and an entry with one fragment is a rename waiting to read as \
                     coverage.",
                    c.id,
                    c.each.len(),
                    Self::PATH
                ));
            }
            if c.reason.trim().is_empty() {
                out.push(format!(
                    "{} declares clauses with an empty reason. The reason is where somebody says \
                     which sentences of the rule these are, and without it the next reader cannot \
                     tell a clause from a test name somebody liked.",
                    c.id
                ));
            }
        }
        for id in self.clauses_over_nothing() {
            out.push(format!(
                "{id} declares clauses in {}, and no document allocates it. A renumbered spec \
                 leaves the declaration standing behind nothing.",
                Self::PATH
            ));
        }
        out
    }

    fn citation_faults(&self) -> Vec<String> {
        self.citations
            .iter()
            .filter(|c| !self.required.contains(&c.id))
            .map(|c| {
                format!(
                    "{} cites {}, which no document allocates. A renumbered spec leaves a test \
                     standing behind nothing, and the matrix counts it anyway.",
                    c.site, c.id
                )
            })
            .collect()
    }

    fn declaration_faults(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for e in &self.declared {
            if !seen.insert(e.id) {
                out.push(format!(
                    "{} is declared twice in {}. Two reasons for one requirement means one of \
                     them is not the reason.",
                    e.id,
                    Self::PATH
                ));
            }
            if !self.required.contains(&e.id) {
                out.push(format!(
                    "{} is declared untestable and {} allocates no such requirement. The spec \
                     moved and the excuse outlived it.",
                    e.id,
                    e.id.doc.path()
                ));
            }
            if e.reason.trim().is_empty() {
                out.push(format!(
                    "{} is declared {} with an empty reason, which is the entry pretending to be \
                     an argument.",
                    e.id, e.kind
                ));
            }
            out.extend(self.nomination_fault(e));
            out.extend(self.stale_declaration(e));
        }
        out
    }

    fn nomination_fault(&self, e: &Entry) -> Option<String> {
        match (e.kind, e.check.as_deref()) {
            (Kind::SpecCheck, None) => Some(format!(
                "{} is declared spec-check and names no check, so nothing stands behind it.",
                e.id
            )),
            (Kind::SpecCheck, Some(name)) if !self.checks.contains(name) => Some(format!(
                "{} nominates `{name}`, which is not one of the checks `cargo xtask check` runs: \
                 {}.\nA nomination naming a check somebody renamed reads as coverage forever.",
                e.id,
                self.checks.iter().cloned().collect::<Vec<_>>().join(", ")
            )),
            (Kind::Hardware | Kind::Deferred | Kind::Judgement, Some(name)) => Some(format!(
                "{} is declared {} and nominates `{name}`. Only a spec-check has a check behind \
                 it; if `{name}` really covers the rule, the kind is spec-check.",
                e.id, e.kind
            )),
            (Kind::SpecCheck, Some(_))
            | (Kind::Hardware | Kind::Deferred | Kind::Judgement, None) => None,
        }
    }

    /// A requirement both declared untestable and cited by a test that passes
    /// is a declaration somebody wrote before the test existed. Delete it — the
    /// file is the list of what nothing can reach, and every stale entry makes
    /// the next reader trust it less.
    fn stale_declaration(&self, e: &Entry) -> Option<String> {
        if e.kind.is_covered() {
            return None;
        }
        let cited = self
            .citations
            .iter()
            .find(|c| c.id == e.id && c.state == State::Counts)?;
        Some(format!(
            "{} is declared {} and {} proves it anyway. Delete the entry.",
            e.id, e.kind, cited.site
        ))
    }
}

/// The checks the runner actually iterates, read out of the array in
/// `check.rs`.
///
/// A hand-kept second list would drift the first time a check was renamed, and
/// the requirement nominating the old name would stay green with nothing under
/// it.
fn check_names(root: &Path) -> Result<BTreeSet<String>> {
    let path: PathBuf = root.join("crates/xtask/src/check.rs");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let (_, rest) = text
        .split_once("for result in [")
        .ok_or_else(|| anyhow!("no check list in {}", path.display()))?;
    let (list, _) = rest
        .split_once("] {")
        .ok_or_else(|| anyhow!("the check list in {} never closes", path.display()))?;
    let names: BTreeSet<String> = list
        .lines()
        .filter_map(|l| {
            l.trim()
                .strip_prefix("checks.")
                .and_then(|call| call.split_once("()"))
                .map(|(name, _)| name.to_owned())
        })
        .filter(|n| n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .collect();
    if names.is_empty() {
        bail!("read no check names out of {}", path.display());
    }
    Ok(names)
}

/// Words to a line, so an uncovered list of a hundred and fifty is eight lines
/// somebody reads rather than a hundred and fifty nobody does.
fn wrap(words: &[String], width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for w in words {
        match lines.last_mut() {
            Some(line) if line.len().saturating_add(w.len()) < width => {
                line.push(' ');
                line.push_str(w);
            }
            _ => lines.push(w.clone()),
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This file is read by the check it implements, so a fixture written out
    /// literally would be a real `#[test]` citing a real requirement and the
    /// count would move because the counter has tests. Every fixture is
    /// assembled instead.
    fn citing_test(id: &str, attrs: &str, body: &str) -> String {
        let name = id.to_ascii_lowercase().replace('-', "_");
        format!(
            "#[{}]\n{attrs}fn {name}_names_the_failure() {{\n    {body}\n}}\n",
            "test"
        )
    }

    fn source(text: String) -> Source {
        Source {
            path: "crates/km43/src/lib.rs".to_owned(),
            text,
        }
    }

    fn known(ids: &[&str]) -> BTreeSet<ReqId> {
        ids.iter().map(|s| s.parse().expect("a test id")).collect()
    }

    #[test]
    fn a_test_named_after_a_requirement_counts_for_it() {
        let s = source(citing_test("P-021", "", "assert_eq!(1, 1);"));
        let cites = s.citations();
        assert_eq!(cites.len(), 1);
        assert_eq!(cites[0].state, State::Counts);
        assert_eq!(cites[0].id.to_string(), "P-021");
    }

    #[test]
    fn a_citing_test_with_no_assertion_is_not_coverage() {
        let s = source(citing_test("P-021", "", "let _ = frame_of(3);"));
        assert_eq!(s.citations()[0].state, State::NoAssertion);
    }

    #[test]
    fn an_ignored_test_stands_behind_nothing() {
        let s = source(citing_test("P-021", "#[ignore]\n", "assert!(true);"));
        assert_eq!(s.citations()[0].state, State::Ignored);
    }

    #[test]
    fn a_helper_named_after_a_requirement_is_not_a_test() {
        let name = "P-021".to_ascii_lowercase().replace('-', "_");
        let s = source(format!("fn {name}_helper() {{\n    assert!(true);\n}}\n"));
        assert!(s.citations().is_empty());
    }

    /// A brace inside a string literal would close the body early, which hides
    /// the assertion under it and reports a real test as one that cannot fail.
    #[test]
    fn a_brace_in_a_string_does_not_end_the_body() {
        let s = source(citing_test(
            "P-021",
            "",
            "let json = \"{ nope }\";\n    assert!(json.len() > 2);",
        ));
        assert_eq!(s.citations()[0].state, State::Counts);
    }

    #[test]
    fn a_header_cites_for_the_whole_file() {
        let mark = "//!";
        let text = format!(
            "{mark} cites: P-024, L-014\n\n{}",
            citing_test("Q-999", "", "assert!(true);")
        );
        let cites = source(text).citations();
        assert_eq!(cites.len(), 2);
        assert!(cites.iter().all(|c| c.state == State::Counts));
    }

    #[test]
    fn a_header_over_a_file_that_cannot_fail_counts_for_nothing() {
        let mark = "//!";
        let text = format!("{mark} cites: P-021\n\nfn helper() {{}}\n");
        assert_eq!(source(text).citations()[0].state, State::NoAssertion);
    }

    #[test]
    fn a_number_in_running_prose_is_not_a_second_requirement() {
        let text = "**P-021** — a rule. See P-021 and **P-022** for the rest.";
        assert_eq!(Doc::Protocol.ids_in(text), known(&["P-021", "P-022"]));
    }

    #[test]
    fn an_empty_document_allocates_nothing() {
        assert!(Doc::Protocol.ids_in("").is_empty());
        assert!(Doc::Link.ids_in("**P-021**").is_empty());
    }

    #[test]
    fn two_spellings_of_one_number_are_refused() {
        assert!("P-21".parse::<ReqId>().is_err());
        assert!("P-0021".parse::<ReqId>().is_err());
        assert!("X-021".parse::<ReqId>().is_err());
        assert!("P021".parse::<ReqId>().is_err());
        assert_eq!(
            "L-014".parse::<ReqId>().expect("valid").to_string(),
            "L-014"
        );
    }

    /// The brace matcher steps over comments as well as strings, or a commented
    /// out fixture would close the body and hide the assertion under it.
    #[test]
    fn a_brace_in_a_comment_does_not_end_the_body() {
        let s = source(citing_test(
            "P-021",
            "",
            "// the old shape was { nope }\n    assert!(true);",
        ));
        assert_eq!(s.citations()[0].state, State::Counts);
    }

    #[test]
    fn an_ordinary_function_is_not_read_as_a_citation() {
        let s =
            source("#[test]\nfn parse_a_frame_of_three() {\n    assert!(true);\n}\n".to_owned());
        assert!(s.citations().is_empty());
    }

    /// A requirement standing on two citations is not thin, and one standing on
    /// a single citation is. Without this, the warning could name everything or
    /// nothing and the audit round would read it either way.
    #[test]
    fn a_requirement_cited_twice_is_not_reported_as_thin() {
        let t = matrix(
            &["P-021", "P-022"],
            vec![
                cite("P-021", State::Counts),
                cite("P-021", State::Counts),
                cite("P-022", State::Counts),
            ],
            vec![],
            0,
        );
        let thin = t.summary();
        assert!(thin.contains("one test   P-022"), "{thin}");
        // The line and not the bare id: `P-021` also appears in the
        // header-only list, and asserting on the id alone made this test
        // about every list the summary prints rather than about this one.
        assert!(
            !thin.contains("one test   P-021"),
            "two citations is not thin: {thin}"
        );
    }

    /// A hundred and eighty uncovered numbers one to a line is a report nobody
    /// reads, and a report nobody reads is the same instrument as no report.
    #[test]
    fn the_uncovered_list_wraps_rather_than_running_down_the_screen() {
        let words: Vec<String> = (0..10).map(|n| format!("P-{n:03}")).collect();
        let lines = wrap(&words, 20);
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(|l| l.len() < 20));
        assert!(wrap(&[], 20).is_empty());
    }

    fn matrix(
        required: &[&str],
        citations: Vec<Citation>,
        declared: Vec<Entry>,
        ratchet: usize,
    ) -> Traceability {
        Traceability {
            required: known(required),
            citations,
            declared,
            clauses: Vec::new(),
            obligations: BTreeMap::new(),
            checks: ["no_response_carries_key_material".to_owned()]
                .into_iter()
                .collect(),
            ratchet,
        }
    }

    fn cite(id: &str, state: State) -> Citation {
        Citation {
            id: id.parse().expect("a test id"),
            site: "crates/km43/src/lib.rs:1".to_owned(),
            name: String::new(),
            state,
        }
    }

    fn entry(id: &str, kind: Kind, check: Option<&str>) -> Entry {
        Entry {
            id: id.parse().expect("a test id"),
            kind,
            check: check.map(ToOwned::to_owned),
            reason: "the subject is a connector".to_owned(),
        }
    }

    #[test]
    fn a_ratchet_that_matches_the_count_passes() {
        let t = matrix(&["P-021", "P-022"], vec![], vec![], 2);
        assert!(t.verdict().is_ok());
        assert!(t.summary().contains("2 uncovered of 2"));
    }

    #[test]
    fn a_requirement_nobody_covers_pushes_the_count_above_the_ratchet() {
        let t = matrix(&["P-021", "P-022", "P-023"], vec![], vec![], 2);
        let e = t
            .verdict()
            .expect_err("three uncovered against a ratchet of two");
        assert!(e.contains("3 requirements are uncovered"));
        assert!(e.contains("records 2"));
    }

    #[test]
    fn a_ratchet_left_slack_after_a_test_lands_is_refused() {
        let t = matrix(
            &["P-021", "P-022"],
            vec![cite("P-021", State::Counts)],
            vec![],
            2,
        );
        let e = t
            .verdict()
            .expect_err("one uncovered against a ratchet of two");
        assert!(e.contains("Lower `uncovered` to 1"));
    }

    #[test]
    fn a_test_that_cannot_fail_does_not_move_the_ratchet() {
        let t = matrix(
            &["P-021", "P-022"],
            vec![cite("P-021", State::NoAssertion)],
            vec![],
            2,
        );
        assert!(t.verdict().is_ok());
        assert!(t.summary().contains("no assertion"));
    }

    /// A citation with a name, so a clause can be matched against it.
    fn named(id: &str, name: &str) -> Citation {
        Citation {
            id: id.parse().expect("a test id"),
            site: "crates/km43/src/frame.rs:1".to_owned(),
            name: name.to_owned(),
            state: State::Counts,
        }
    }

    fn clauses(id: &str, each: &[&str]) -> Clauses {
        Clauses {
            id: id.parse().expect("a test id"),
            each: each.iter().map(|s| (*s).to_owned()).collect(),
            reason: "two sentences joined by MUST and MUST".to_owned(),
        }
    }

    fn with_clauses(
        required: &[&str],
        citations: Vec<Citation>,
        clauses: Vec<Clauses>,
        ratchet: usize,
    ) -> Traceability {
        let mut t = matrix(required, citations, vec![], ratchet);
        t.clauses = clauses;
        t
    }

    /// **A rule that states two things is not covered by one of them.**
    ///
    /// This is the exact shape P-164 was in: the validity clause tested, the
    /// concern clause not written at all, and the matrix reading it as covered
    /// throughout — so a half-built rule looked greener than an unbuilt one and
    /// nobody went looking, because the number was already the right colour.
    #[test]
    fn a_rule_with_two_clauses_is_not_covered_by_a_test_for_one_of_them() {
        let half = with_clauses(
            &["P-164"],
            vec![named(
                "P-164",
                "p_164_a_state_is_never_published_as_its_number",
            )],
            vec![clauses(
                "P-164",
                &["is_never_published", "raises_a_concern"],
            )],
            1,
        );
        assert!(
            half.verdict().is_ok(),
            "one uncovered rule against a ratchet of one"
        );
        assert!(half.summary().contains("0 covered"));
        assert!(
            half.summary()
                .contains("P-164 states `raises_a_concern` and no test names it"),
            "the report has to say which clause, or it is the same silence in a new place"
        );

        let both = with_clauses(
            &["P-164"],
            vec![
                named("P-164", "p_164_a_state_is_never_published_as_its_number"),
                named(
                    "P-164",
                    "p_164_a_state_raises_a_concern_with_the_vendors_code",
                ),
            ],
            vec![clauses(
                "P-164",
                &["is_never_published", "raises_a_concern"],
            )],
            0,
        );
        assert!(both.verdict().is_ok());
        assert!(both.summary().contains("1 covered"));
    }

    /// **A whole-file claim is the weakest thing this matrix counts**, and the
    /// size of that list is the most useful number about what the count is
    /// worth.
    ///
    /// P-143 was the first one read: `envelope.rs` claimed it, no test in the
    /// tree asserts either of its two refusals, and no code in the tree performs
    /// one — the decision belongs to a request dispatcher that does not exist.
    /// The header was standing over nothing for as long as it had been there.
    #[test]
    fn a_rule_only_a_file_header_claims_is_named_for_reading() {
        let t = matrix(
            &["P-143", "P-021"],
            vec![
                cite("P-143", State::Counts),
                named("P-021", "p_021_a_client_that_never_paired_is_refused"),
            ],
            vec![],
            0,
        );
        let summary = t.summary();
        assert!(
            summary.contains("header     P-143"),
            "a rule no test is named after was not surfaced: {summary}"
        );
        assert!(
            !summary.contains("header     P-021"),
            "a rule with a test named after it is not resting on a header: {summary}"
        );
        assert!(
            t.verdict().is_ok(),
            "a warning: many header claims are honest, and failing would ask for \
             seventy renames rather than seventy readings"
        );
    }

    /// **The warning that finds the next P-164 instead of waiting for somebody
    /// to notice one.**
    ///
    /// The clause table only holds rules a person has already read. This is what
    /// produces the reading list: covered, states two things, stands on one
    /// test. P-164 was in exactly that intersection for months and nothing said
    /// so.
    ///
    /// A rule that has declared its clauses drops off the list, because the
    /// clause check holds it now — otherwise the warning would grow with every
    /// rule somebody fixed.
    #[test]
    fn a_covered_rule_that_states_two_things_on_one_test_is_named_for_reading() {
        let mut t = with_clauses(
            &["P-164", "P-021"],
            vec![
                named("P-164", "p_164_a_state_is_never_published_as_its_number"),
                named("P-021", "p_021_a_client_that_never_paired_is_refused"),
            ],
            vec![],
            0,
        );
        t.obligations = [("P-164", 2), ("P-021", 1)]
            .into_iter()
            .map(|(id, n)| (id.parse().expect("a test id"), n))
            .collect();

        let summary = t.summary();
        assert!(
            summary.contains("P-164(2)"),
            "a rule stating two things on one test was not named: {summary}"
        );
        assert!(
            !summary.contains("P-021("),
            "a rule stating one thing does not belong on the reading list: {summary}"
        );
        assert!(
            t.verdict().is_ok(),
            "this is a warning: making it fail would force a clause entry per rule, \
             which is filling the file to make a number go down"
        );

        // Once somebody has read it and written the clauses down, it drops off.
        t.clauses = vec![clauses(
            "P-164",
            &["is_never_published", "raises_a_concern"],
        )];
        assert!(!t.summary().contains("P-164(2)"));
    }

    /// A `cites:` header stands for a whole file and cannot say which clause it
    /// is about, so it never satisfies one. Otherwise a module header would make
    /// every clause of every rule it names look tested.
    #[test]
    fn a_file_header_citation_satisfies_no_clause() {
        let t = with_clauses(
            &["P-164"],
            vec![cite("P-164", State::Counts)],
            vec![clauses(
                "P-164",
                &["is_never_published", "raises_a_concern"],
            )],
            1,
        );
        assert!(t.summary().contains("0 covered"));
        assert!(t.summary().contains("no test names it"));
    }

    /// A declaration over a rule no document allocates, which is what a
    /// renumbered spec leaves behind.
    #[test]
    fn a_clause_declaration_standing_over_nothing_is_a_fault() {
        let t = with_clauses(
            &["P-021"],
            vec![],
            vec![clauses("P-999", &["one_thing", "another"])],
            1,
        );
        let e = t.verdict().expect_err("a rule that is not in the spec");
        assert!(e.contains("P-999"), "{e}");
        assert!(e.contains("no document allocates it"), "{e}");
    }

    /// One fragment is a rename waiting to read as coverage: it looks like a
    /// clause check and cannot fail for the reason the table exists.
    #[test]
    fn a_single_clause_declaration_is_refused() {
        let t = with_clauses(
            &["P-021"],
            vec![named(
                "P-021",
                "p_021_a_client_that_never_paired_is_refused",
            )],
            vec![clauses("P-021", &["never_paired"])],
            0,
        );
        let e = t.verdict().expect_err("a rule that says one thing");
        assert!(e.contains("declares 1 clause"), "{e}");
    }

    /// The reason is where somebody says which sentences of the rule these are.
    #[test]
    fn clauses_declared_with_no_reason_are_not_an_argument() {
        let mut c = clauses("P-021", &["one_thing", "another"]);
        c.reason = "   ".to_owned();
        let t = with_clauses(
            &["P-021"],
            vec![
                named("P-021", "p_021_one_thing"),
                named("P-021", "p_021_another"),
            ],
            vec![c],
            0,
        );
        let e = t
            .verdict()
            .expect_err("a declaration with no argument in it");
        assert!(e.contains("empty reason"), "{e}");
    }

    /// One rule has one list of the things it says.
    #[test]
    fn clauses_declared_twice_for_one_rule_is_a_fault() {
        let t = with_clauses(
            &["P-021"],
            vec![
                named("P-021", "p_021_one_thing"),
                named("P-021", "p_021_another"),
            ],
            vec![
                clauses("P-021", &["one_thing", "another"]),
                clauses("P-021", &["one_thing", "something_else"]),
            ],
            0,
        );
        let e = t.verdict().expect_err("two lists for one rule");
        assert!(e.contains("declares its clauses twice"), "{e}");
    }

    #[test]
    fn a_declared_requirement_leaves_the_ratchet_where_it_was() {
        let t = matrix(
            &["P-021", "P-022"],
            vec![],
            vec![entry("P-021", Kind::Hardware, None)],
            1,
        );
        assert!(t.verdict().is_ok());
        assert!(t.summary().contains("1 declared untestable"));
    }

    #[test]
    fn a_nominated_check_that_runs_is_coverage_and_one_that_does_not_is_a_fault() {
        let good = matrix(
            &["P-021"],
            vec![],
            vec![entry(
                "P-021",
                Kind::SpecCheck,
                Some("no_response_carries_key_material"),
            )],
            0,
        );
        assert!(good.verdict().is_ok());
        assert!(good.summary().contains("1 covered"));

        let bad = matrix(
            &["P-021"],
            vec![],
            vec![entry("P-021", Kind::SpecCheck, Some("checks_the_vibes"))],
            0,
        );
        let e = bad.verdict().expect_err("a check nobody runs");
        assert!(e.contains("checks_the_vibes"));
    }

    #[test]
    fn a_spec_check_that_nominates_nothing_stands_behind_nothing() {
        let t = matrix(
            &["P-021"],
            vec![],
            vec![entry("P-021", Kind::SpecCheck, None)],
            1,
        );
        let e = t.verdict().expect_err("a nomination with no check in it");
        assert!(e.contains("names no check"));
    }

    /// A `hardware` entry that also names a check reads as covered to a person
    /// skimming the file and is not, which is the one direction this file is
    /// not allowed to be wrong in.
    #[test]
    fn a_kind_with_no_check_behind_it_may_not_nominate_one() {
        let t = matrix(
            &["P-021"],
            vec![],
            vec![entry(
                "P-021",
                Kind::Hardware,
                Some("no_response_carries_key_material"),
            )],
            1,
        );
        let e = t.verdict().expect_err("a hardware entry with a nomination");
        assert!(e.contains("the kind is spec-check"));
    }

    #[test]
    fn an_entry_with_no_reason_is_not_an_argument() {
        let mut e = entry("P-021", Kind::Deferred, None);
        e.reason = "   ".to_owned();
        let t = matrix(&["P-021"], vec![], vec![e], 1);
        let err = t.verdict().expect_err("an entry that argues nothing");
        assert!(err.contains("empty reason"));
    }

    #[test]
    fn one_requirement_declared_twice_is_refused() {
        let t = matrix(
            &["P-021"],
            vec![],
            vec![
                entry("P-021", Kind::Deferred, None),
                entry("P-021", Kind::Judgement, None),
            ],
            1,
        );
        let e = t.verdict().expect_err("two reasons for one rule");
        assert!(e.contains("declared twice"));
    }

    #[test]
    fn a_declaration_for_a_requirement_the_spec_dropped_is_refused() {
        let t = matrix(
            &["P-022"],
            vec![],
            vec![entry("P-021", Kind::Deferred, None)],
            1,
        );
        let e = t.verdict().expect_err("an excuse that outlived its rule");
        assert!(e.contains("allocates no such requirement"));
    }

    #[test]
    fn a_declaration_a_test_has_overtaken_is_refused() {
        let t = matrix(
            &["P-021"],
            vec![cite("P-021", State::Counts)],
            vec![entry("P-021", Kind::Judgement, None)],
            0,
        );
        let e = t.verdict().expect_err("a stale declaration");
        assert!(e.contains("Delete the entry"));
    }

    #[test]
    fn a_test_citing_a_number_nothing_allocates_is_refused() {
        let t = matrix(&["P-021"], vec![cite("P-999", State::Counts)], vec![], 1);
        let e = t.verdict().expect_err("a citation of nothing");
        assert!(e.contains("which no document allocates"));
    }

    #[test]
    fn a_kind_nobody_defined_fails_at_the_line_that_names_it() {
        let toml = "[ratchet]\nuncovered = 0\n\n[[entry]]\nid = \"P-021\"\nkind = \"someday\"\nreason = \"soon\"\n";
        let e = toml::from_str::<Declarations>(toml).expect_err("an invented kind");
        assert!(e.to_string().contains("someday"));
    }

    #[test]
    fn a_misspelled_field_is_not_silently_dropped() {
        let toml = "[ratchet]\nuncovered = 0\n\n[[entry]]\nid = \"P-021\"\nkind = \"deferred\"\nreasons = \"soon\"\n";
        assert!(toml::from_str::<Declarations>(toml).is_err());
    }

    #[test]
    fn the_real_check_list_is_readable() {
        let root = crate::check::repo_root().expect("a git checkout");
        let names = check_names(&root).expect("the check list");
        assert!(names.contains("every_requirement_is_cited"));
        assert!(names.len() >= 9);
    }
}
