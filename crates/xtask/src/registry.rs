//! Loads `protocol.toml`, the one place a protocol number is allocated.
//!
//! Every other form — the markdown table, the Rust constants, the TypeScript
//! constants — is generated from it, so two of them cannot disagree.

use anyhow::{Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// How a message is authenticated.
///
/// There is no tenth variant: a `protocol.toml` naming a rule that does not
/// exist fails to parse, at the line that names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Auth {
    /// Nothing: no key exists at this point in the exchange.
    None,
    /// A proof carried inside the body, so the body is decoded before it verifies.
    Proof,
    /// Wrapper-authenticated request. Read-only, carries no counter.
    Wrq,
    /// Wrapper-authenticated response.
    Rsp,
    /// Unsolicited event.
    Evt,
    /// Signed body carrying a per-client counter. Every write is one.
    Signed,
    /// Keyed on the pairing key, which is derived from the printed secret.
    /// Used before any session exists.
    PairKey,
    /// Controller to comms processor. Unauthenticated by design — the link is
    /// internal to the board.
    Link,
    /// Wrapped when the sender holds a session, bare when it does not.
    RspOrBare,
}

impl fmt::Display for Auth {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::Proof => "proof",
            Self::Wrq => "wrq",
            Self::Rsp => "rsp",
            Self::Evt => "evt",
            Self::Signed => "signed",
            Self::PairKey => "pair_key",
            Self::Link => "link",
            Self::RspOrBare => "rsp_or_bare",
        };
        w.write_str(s)
    }
}

/// What an allocated number is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Allocated and specified.
    Live,
    /// Allocated; its body schema is deferred. May still be emitted.
    Reserved,
    /// Allocated; the condition it named is answered elsewhere now. Nothing emits it.
    Withdrawn,
    /// Was used, and is gone. Never reallocated.
    Retired,
}

impl Status {
    fn live() -> Self {
        Self::Live
    }

    /// Whether nothing may emit this number any more.
    ///
    /// `Withdrawn` and `Retired` differ in why — the condition is answered
    /// elsewhere now, against it was used and is gone — and not in what a
    /// generator does about it: neither gets a constant, because a constant is
    /// something a caller can send. `Retired` was inert before this and read as
    /// a decision that had been taken; a retired metric still generated a
    /// `MetricKind` a driver could publish under.
    pub fn is_gone(self) -> bool {
        matches!(self, Self::Withdrawn | Self::Retired)
    }
}

impl fmt::Display for Status {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Live => "live",
            Self::Reserved => "reserved",
            Self::Withdrawn => "withdrawn",
            Self::Retired => "retired",
        };
        w.write_str(s)
    }
}

/// A protocol version, so a typo is a parse error rather than a string nobody compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (major, minor) = s
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("{s:?} is not major.minor"))?;
        Ok(Self {
            major: major.parse()?,
            minor: minor.parse()?,
        })
    }
}

impl TryFrom<String> for Version {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl fmt::Display for Version {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(w, "{}.{}", self.major, self.minor)
    }
}

/// An allocated opcode. Renders the way the table reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(transparent)]
pub struct Opcode(pub u16);

impl Opcode {
    /// How a table cell reads it, with an em dash where the direction does not
    /// exist.
    fn cell(v: Option<Self>) -> String {
        v.map_or_else(|| "—".to_owned(), |o| o.to_string())
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(w, "`0x{:02X}`", self.0)
    }
}

/// The specification with its markdown taken off, so a phrase can be looked for
/// as somebody reads it rather than as somebody typed it.
///
/// `**outcome 2 `superseded`**` and `outcome 2 superseded` are one sentence, and
/// a rule is written whichever way its paragraph wanted emphasis that day. A
/// check that can only find the unemphasised one goes red on a bold marker,
/// which is how a check earns a reputation for crying wolf.
struct Prose(String);

impl Prose {
    fn of(docs: &str) -> Self {
        let plain: String = docs
            .chars()
            .map(|c| if c == '*' || c == '`' { ' ' } else { c })
            .collect();
        Self(plain.split_whitespace().collect::<Vec<_>>().join(" "))
    }

    fn says(&self, phrase: &str) -> bool {
        self.0.contains(phrase)
    }
}

#[derive(Clone, Deserialize)]
pub struct Registry {
    pub meta: Meta,
    pub messages: Vec<Message>,
    #[serde(default)]
    pub message_ranges: Vec<Range>,
    pub errors: Vec<ErrorCode>,
    #[serde(default)]
    pub error_ranges: Vec<CodeRange>,
    pub outcomes: BTreeMap<String, Vec<Outcome>>,
    pub metrics: Vec<Metric>,
    pub events: Vec<Event>,
    pub codes: BTreeMap<String, Vec<Code>>,
    pub enums: BTreeMap<String, Vec<Outcome>>,
    /// Registries where a value this file does not name is **carried** rather
    /// than refused (P-019), and where a vendor range at `0xF000` is part of the
    /// point.
    ///
    /// Open by construction. A space here is open because of the table it is in,
    /// not because its name appears on a list somewhere else — which is the form
    /// this replaced, and which could not go red when a name was misspelled or
    /// when a space was added and the list was not. There is nothing to keep in
    /// sync because there is nothing to disagree with.
    ///
    /// `u16` and not `u8`: every one of these carries a vendor range that does
    /// not fit a byte, which is also why they cannot live in [`Self::enums`].
    #[serde(default)]
    pub open_registries: BTreeMap<String, Vec<Code>>,
    #[serde(default)]
    pub link_errors: Vec<LinkError>,
    #[serde(default)]
    pub client_capability: Vec<ClientCapability>,
    /// The enum spaces that never reach a client. Kept apart from `outcomes`
    /// and `enums` because those are spliced into REGISTRY.md, and eleven
    /// link-local tables in the client protocol's registry would bury the
    /// spaces a client author actually needs. LINK.md's body listings are the
    /// documentation; these rows are the allocation.
    #[serde(default)]
    pub link_messages: Vec<LinkMessage>,
    #[serde(default)]
    pub link_outcomes: BTreeMap<String, Vec<Outcome>>,
    #[serde(default)]
    pub link_enums: BTreeMap<String, Vec<Outcome>>,
    /// What the source read as, so the generated files can say which revision
    /// of the registry they came from.
    #[serde(skip)]
    pub digest: Digest,
}

/// A fingerprint of the registry source, carried into everything generated from
/// it so a build can tell whether the two still agree.
///
/// FNV-1a rather than a real hash: this answers "did the file change", not "did
/// somebody change it on purpose", and it has to run in a build script that
/// must not pull in a dependency to compute it.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Digest(pub u64);

impl Digest {
    pub fn of(source: &str) -> Self {
        // Carriage returns are stripped so a checkout with different line
        // endings does not read as a different registry.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in source.bytes().filter(|&b| b != b'\r') {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Self(h)
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// An error raised on the UART between the two firmwares.
///
/// A separate space from [`ErrorCode`] because three of these reach a client and
/// six never do, and a client that cannot tell them apart treats a link fault as
/// its own request failing.
#[derive(Clone, Deserialize)]
pub struct LinkError {
    pub code: u16,
    /// The identifier a generated constant takes. `meaning` is the sentence a
    /// person reads; a constant named from a sentence is a constant that gets
    /// renamed every time somebody improves the wording.
    pub name: String,
    pub meaning: String,
    pub reaches_client: bool,
    pub status: Status,
}

/// A message on the internal UART.
///
/// Kept out of `messages` because these carry no auth rule to state — the link
/// is unauthenticated by design (L-020) — and a `None` in that column would
/// read as an omission rather than as the decision it is.
#[derive(Clone, Deserialize)]
pub struct LinkMessage {
    pub request: Opcode,
    pub response: Opcode,
    pub name: String,
    pub direction: LinkDirection,
}

/// Which side may send a link-local request. L-001 refuses the other one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkDirection {
    Either,
    CommsToController,
    ControllerToComms,
}

impl fmt::Display for LinkDirection {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        w.write_str(match self {
            Self::Either => "either side",
            Self::CommsToController => "comms → controller",
            Self::ControllerToComms => "controller → comms",
        })
    }
}

/// One bit of the per-client capability mask.
///
/// `granted_to` names the client kinds that get the bit at enrolment, so the
/// grid in the document is derived from one list rather than kept in five
/// columns somebody has to edit together.
///
/// It is a grant list and not a deny list because a `client_kind` allocated
/// later mentions no row here, and under a deny list that kind comes out holding
/// every bit — firmware push included. A default that opens is the one direction
/// this project never defaults.
#[derive(Clone, Deserialize)]
pub struct ClientCapability {
    pub bit: Option<u8>,
    pub range: Option<String>,
    /// Absent on the row that covers the unallocated span, which names nothing.
    pub name: Option<String>,
    pub may: String,
    #[serde(default)]
    pub granted_to: Vec<String>,
    #[serde(default)]
    pub status: Option<Status>,
}

#[derive(Clone, Deserialize)]
pub struct Metric {
    /// The sub-heading this row sits under in the document.
    pub group: String,
    pub kind: u16,
    pub name: String,
    pub unit: String,
    /// `value = wire_integer * 10^scale`, which is how a measurement crosses a
    /// wire that carries no floats.
    pub scale: i8,
    pub status: Status,
}

#[derive(Clone, Deserialize)]
pub struct Event {
    pub kind: u16,
    pub name: String,
    /// A is never dropped; B is dropped first under pressure.
    pub class: EventClass,
    pub status: Status,
}

/// Which records survive a controller under pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum EventClass {
    A,
    B,
}

impl fmt::Display for EventClass {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        w.write_str(match self {
            Self::A => "A",
            Self::B => "B",
        })
    }
}

#[derive(Clone, Deserialize)]
pub struct Code {
    /// One number, or `None` where the row covers a span.
    pub number: Option<u16>,
    pub range: Option<String>,
    pub name: String,
    /// A span of unallocated numbers has no status — nothing is allocated to
    /// have one.
    #[serde(default)]
    pub status: Option<Status>,
}

#[derive(Clone, Deserialize)]
pub struct ErrorCode {
    pub code: u16,
    pub meaning: String,
    /// Whether a receiver will read this code out of a bare body.
    pub macd: bool,
    pub status: Status,
}

#[derive(Clone, Deserialize)]
pub struct CodeRange {
    pub lo: u16,
    pub hi: u16,
    pub name: String,
    pub see: String,
}

#[derive(Clone, Deserialize)]
pub struct Outcome {
    pub value: u8,
    pub name: String,
    #[serde(default = "Status::live")]
    pub status: Status,
    #[serde(default)]
    pub meaning: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct Meta {
    pub protocol: Version,
    /// Spaces where an unrecognised value is surfaced rather than refused, so
    /// the bindings give them an open type instead of a closed enum.
    pub skip_unknown: Vec<String>,
}

/// Opcodes allocated without a message behind them: no body, no auth rule, no
/// generated constant.
#[derive(Clone, Deserialize)]
pub struct Range {
    pub name: String,
    pub see: String,
    pub request_lo: Opcode,
    pub request_hi: Opcode,
    pub response_lo: Opcode,
    pub response_hi: Opcode,
    pub since: Version,
}

#[derive(Clone, Deserialize)]
pub struct Message {
    pub name: String,
    pub request: Option<Opcode>,
    pub response: Option<Opcode>,
    pub auth_request: Option<Auth>,
    pub auth_response: Option<Auth>,
    pub status: Status,
    pub since: Version,
}

impl Message {
    /// The opcode as the table writes it, or an em dash where that direction
    /// does not exist.
    pub fn request_cell(&self) -> String {
        Opcode::cell(self.request)
    }

    pub fn response_cell(&self) -> String {
        Opcode::cell(self.response)
    }

    /// What the table sorts on.
    pub fn sort_key(&self) -> u16 {
        self.request.or(self.response).map_or(u16::MAX, |o| o.0)
    }
}

impl Range {
    pub fn request_cell(&self) -> String {
        format!("{}–{}", self.request_lo, self.request_hi)
    }

    pub fn response_cell(&self) -> String {
        format!("{}–{}", self.response_lo, self.response_hi)
    }
}

impl Registry {
    /// Beside the crate it generates, not under `docs/`. It is the source the
    /// firmware is built from; the Markdown is a rendering of it.
    pub const PATH: &'static str = "crates/km43/protocol.toml";

    /// Reads and validates the registry.
    pub fn load(root: &std::path::Path) -> Result<Self> {
        let path = root.join(Self::PATH);
        let source = std::fs::read_to_string(&path)?;
        let mut reg: Self = toml::from_str(&source)?;
        reg.digest = Digest::of(&source);
        reg.validate()?;
        Ok(reg)
    }

    /// Allocated numbers that no rule anywhere produces.
    ///
    /// A number nothing emits is not live, it is withdrawn — and the difference
    /// matters because a reviewer reading the table concludes the condition is
    /// handled. Four codes sat live and unreachable before this existed, each
    /// describing a refusal no implementation could ever send.
    pub fn unreachable(&self, docs: &str) -> Vec<String> {
        // `enums.*`, `codes.*` and the capability mask are deliberately not
        // swept, and DEFERRED.md entry 11 records it rather than the entry
        // claiming a coverage this does not have. A member of one of those is a
        // label — `provenance = estimated` decides nothing on the wire — so no
        // rule quotes it, and sweeping by member reports all eighteen. Sweeping
        // by space name is worse: it reported four that are reached under their
        // field name (`source` for `time_source`, `section` for
        // `config_section`) and a check that cries wolf gets switched off.
        [
            self.messages_no_rule_names(docs),
            self.errors_no_rule_raises(docs),
            self.outcomes_no_rule_produces(&Prose::of(docs)),
            self.link_numbers_nothing_names(docs),
        ]
        .concat()
    }

    fn messages_no_rule_names(&self, docs: &str) -> Vec<String> {
        self.messages
            .iter()
            .filter(|m| m.status == Status::Live)
            .filter(|m| {
                ![m.request, m.response]
                    .into_iter()
                    .flatten()
                    .any(|op| docs.contains(&op.to_string()))
            })
            .map(|m| {
                format!(
                    "message {} is live and no rule names {} or {}",
                    m.name,
                    Opcode::cell(m.request),
                    Opcode::cell(m.response)
                )
            })
            .collect()
    }

    fn errors_no_rule_raises(&self, docs: &str) -> Vec<String> {
        self.errors
            .iter()
            .filter(|e| e.status == Status::Live)
            .filter(|e| !docs.contains(&format!("error {}", e.code)))
            .map(|e| {
                format!(
                    "error {} ({}) is live and no rule says \"error {}\"",
                    e.code, e.meaning, e.code
                )
            })
            .collect()
    }

    /// An outcome is produced by a rule that names its number **and** its name,
    /// in that order, and by nothing looser.
    ///
    /// The number on its own is not evidence: six spaces allocate an `outcome
    /// 3`, so `Inventory`'s rule vouched for `Readings`' — and it did, for as
    /// long as it took to misspell `unknown_selector` in PROTOCOL.md and watch
    /// this stay green. The name on its own is no better, because four spaces
    /// have an `unauthorised` and two have an `out_of_range`. Either half alone
    /// is satisfied by a rule about a different message.
    fn outcomes_no_rule_produces(&self, prose: &Prose) -> Vec<String> {
        self.outcomes
            .iter()
            .flat_map(|(space, o)| o.iter().map(move |e| (space, e)))
            .filter(|(_, e)| e.status == Status::Live)
            .filter(|(_, e)| !prose.says(&format!("outcome {} {}", e.value, e.name)))
            .map(|(space, e)| {
                format!(
                    "{space} outcome {} `{}` is live and no rule produces it — \
                     one that does says \"outcome {} `{}`\" in those two words",
                    e.value, e.name, e.value, e.name
                )
            })
            .collect()
    }

    /// Every name this registry allows a number to be called by.
    ///
    /// Keyed by the number and not by the space, because the spaces collide on
    /// purpose: `0x0101` is the event kind `value changed` **and** the metric
    /// kind `DC voltage`, and `0x0502` is `concern changed` and
    /// `generator run hours`. A reader meeting the number in prose is entitled
    /// to either name, so a check that demanded one space's would fire on every
    /// legitimate mention of the other's.
    ///
    /// `enums.*` is left out. Its members are `u8`, so their numbers are 1, 2, 3
    /// — which appear in prose for every reason there is, and sweeping them
    /// would report the whole corpus.
    ///
    /// So is [`Self::BIT_POSITIONS`], and for a sharper reason: its numbers are
    /// places in a `u16` rather than values on a wire. `Bit 0` is not `0x0000`,
    /// and the two `0x0000`s in `PROTOCOL.md` are a CRC xorout and a zero word
    /// in a MAC preimage. Excluded by name rather than by a guess about the
    /// numbers, and the name is checked to still exist so that renaming the
    /// space fails here instead of quietly covering nothing.
    pub fn names_by_number(&self) -> Result<BTreeMap<u16, BTreeSet<String>>> {
        if !self.codes.contains_key(Self::BIT_POSITIONS) {
            bail!(
                "no `codes.{}` table. It is excluded from the name sweep because its numbers are \
                 bit positions; if it has been renamed, rename it here too rather than leaving \
                 an exclusion that matches nothing",
                Self::BIT_POSITIONS
            );
        }
        let mut out: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
        let mut add = |number: u16, name: &str| {
            out.entry(number).or_default().insert(name.to_owned());
        };
        for event in &self.events {
            add(event.kind, &event.name);
        }
        for metric in &self.metrics {
            add(metric.kind, &metric.name);
        }
        let spaces = self
            .codes
            .iter()
            .chain(&self.open_registries)
            .filter(|(space, _)| space.as_str() != Self::BIT_POSITIONS);
        for (_, rows) in spaces {
            for row in rows {
                if let Some(number) = row.number {
                    add(number, &row.name);
                }
            }
        }
        Ok(out)
    }

    /// The one space whose numbers are positions rather than values.
    const BIT_POSITIONS: &'static str = "capability_bit";

    fn link_numbers_nothing_names(&self, docs: &str) -> Vec<String> {
        let errors = self
            .link_errors
            .iter()
            .filter(|e| e.status == Status::Live)
            .filter(|e| !docs.contains(&format!("code {}", e.code)))
            .map(|e| {
                format!(
                    "link error {} ({}) is live and no rule says \"code {}\"",
                    e.code, e.meaning, e.code
                )
            });

        let messages = self
            .link_messages
            .iter()
            .filter(|m| !docs.contains(&m.name))
            .map(|m| {
                format!(
                    "link message {} ({}) is allocated and LINK.md never names it",
                    m.name, m.request
                )
            });

        let members = self
            .link_outcomes
            .iter()
            .chain(&self.link_enums)
            .flat_map(|(space, o)| o.iter().map(move |e| (space, e)))
            .filter(|(_, e)| e.status == Status::Live)
            .filter(|(_, e)| !docs.contains(&e.name))
            .map(|(space, e)| {
                format!(
                    "link {space} {} `{}` is live and LINK.md never names it",
                    e.value, e.name
                )
            });

        errors.chain(messages).chain(members).collect()
    }

    /// The one thing the type system cannot catch: the same number twice.
    ///
    /// Auth labels and statuses need no check here — an unknown one fails to
    /// deserialize, naming the line.
    fn validate(&self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for m in &self.messages {
            for op in [m.request, m.response].into_iter().flatten() {
                if !seen.insert(op) {
                    bail!("{} allocates {op}, which is already taken", m.name);
                }
            }
            if m.request.is_none() && m.response.is_none() {
                bail!("{} allocates no opcode at all", m.name);
            }
        }
        for m in &self.link_messages {
            for op in [m.request, m.response] {
                if !seen.insert(op) {
                    bail!("{} allocates {op}, which is already taken", m.name);
                }
            }
        }

        // `skip_unknown` used to be a list of names checked against nothing, so a
        // misspelling was inert: the name sat there looking like a decision while the
        // generated binding stayed closed, and no build ever went red. Two of these
        // names are the top-level `metrics` and `events` tables; the rest must be
        // spaces that actually exist.
        for space in &self.meta.skip_unknown {
            if space != "metric_kind"
                && space != "event_kind"
                && !self.open_registries.contains_key(space)
            {
                bail!(
                    "meta.skip_unknown names `{space}`, which is not a space anything reads. \
                     Open registries are open by being in [[open_registries.*]]; the only names \
                     legal here are `metric_kind` and `event_kind`, which are top-level tables"
                );
            }
        }

        for (space, rows) in &self.open_registries {
            if rows.is_empty() {
                bail!(
                    "open registry `{space}` allocates nothing, so it is a heading and not a space"
                );
            }
            let mut numbers = BTreeSet::new();
            for row in rows {
                let Some(number) = row.number else { continue };
                if !numbers.insert(number) {
                    bail!("open registry `{space}` allocates {number:#06x} twice");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod prose {
    use super::Prose;

    /// The break that started this: `unknown_selector` was misspelt in
    /// PROTOCOL.md and the sweep stayed green, because `outcome 3` was true of
    /// `Inventory`'s rule two sections away. One rule vouching for a different
    /// message's number is a number nothing produces, wearing a tick.
    #[test]
    fn a_number_alone_does_not_produce_an_outcome() {
        let docs = Prose::of("A `what` outside 1..5 is **outcome 3 `unknown_kind`**.");
        assert!(docs.says("outcome 3 unknown_kind"));
        assert!(!docs.says("outcome 3 unknown_selector"));
    }

    /// Four spaces allocate an `unauthorised`, so finding the word says nothing
    /// about which message can answer with it.
    #[test]
    fn a_name_alone_does_not_produce_an_outcome() {
        let docs = Prose::of("`TimeAck` outcome 3 `unauthorised`, `Firmware` outcome 8");
        assert!(docs.says("outcome 3 unauthorised"));
        assert!(!docs.says("outcome 4 unauthorised"));
    }

    /// A rule is emphasised or not depending on what its paragraph wanted that
    /// day, and both readings are the same sentence. A check that goes red on a
    /// bold marker gets a reputation and then gets switched off.
    #[test]
    fn emphasis_and_line_breaks_are_not_part_of_the_sentence() {
        let docs = Prose::of("with outcome\n  **2 `superseded`**, the current `rev`");
        assert!(docs.says("outcome 2 superseded"));
    }
}

#[cfg(test)]
mod names {
    use super::Registry;

    fn loaded() -> Registry {
        let root = crate::check::repo_root().expect("a repo to read the registry from");
        Registry::load(&root).expect("the registry parses")
    }

    /// **The spaces collide on purpose, and that is what stops the sweep crying
    /// wolf.**
    ///
    /// `0x0101` is the event kind `value changed` and the metric kind
    /// `DC voltage`. A sweep that demanded the event name would fire on every
    /// legitimate mention of the metric — and a check with a reputation for
    /// firing on correct prose is a check somebody switches off, which is worse
    /// than not having written it.
    #[test]
    fn a_number_two_spaces_allocate_may_be_called_by_either_name() {
        let names = loaded().names_by_number().expect("the sweep builds");
        let both = names.get(&0x0101).expect("0x0101 is allocated twice");
        assert!(
            both.len() >= 2,
            "0x0101 no longer collides, so this test is watching nothing: {both:?}"
        );
        assert!(both.contains("value changed"), "{both:?}");
        assert!(both.contains("DC voltage"), "{both:?}");
    }

    /// **A bit position is not a wire number, and `Bit 0` is not `0x0000`.**
    ///
    /// The two `0x0000`s in `PROTOCOL.md` are a CRC xorout and a zero word in a
    /// MAC preimage. Sweep the capability mask with the rest and the check
    /// reports both of them on its first run.
    #[test]
    fn a_bit_position_is_not_swept_as_a_number() {
        let names = loaded().names_by_number().expect("the sweep builds");
        let zero = names
            .get(&0)
            .map(|set| set.iter().any(|n| n == "event log readable"));
        assert_ne!(
            zero,
            Some(true),
            "capability bit 0 is being swept as the number 0x0000"
        );
    }
}

#[cfg(test)]
mod allocation {
    use super::{Metric, Registry, Status};

    fn loaded() -> Registry {
        let root = crate::check::repo_root().expect("a repo to read the registry from");
        Registry::load(&root).expect("the registry parses")
    }

    /// **P-012 — a retired number never comes back.**
    ///
    /// The rule's second sentence is what makes the first checkable: retired
    /// numbers stay recorded, so a reuse is the same number allocated twice.
    ///
    /// The failure does not announce itself. Two implementations built a year
    /// apart both read the registry, disagree about what one number means, and
    /// every frame carrying it decodes cleanly into the wrong thing — a metric
    /// read as another metric, an outcome acted on as a different outcome. No
    /// MAC fails and nothing is malformed, so there is no moment at which
    /// either end could notice.
    #[test]
    fn p_012_a_retired_number_that_comes_back_is_refused() {
        let registry = loaded();
        assert!(
            crate::check::no_number_is_allocated_twice(&registry).is_ok(),
            "the registry as committed already allocates a number twice"
        );

        // The fixture is a real retired metric, taken from the file rather than
        // invented, so this cannot pass by testing a number nobody uses.
        let mut retired = registry
            .metrics
            .iter()
            .find(|m| m.status == Status::Retired)
            .cloned()
            .expect("the registry keeps its retired metrics, which is the rule");
        retired.name = "somebody reused a retired number".to_owned();
        retired.status = Status::Live;

        let mut brought_back = loaded();
        brought_back.metrics.push(retired);
        let said = crate::check::no_number_is_allocated_twice(&brought_back)
            .expect_err("a retired metric kind was reallocated and nothing objected");
        assert!(
            said.contains("allocated twice"),
            "the refusal does not say what went wrong: {said}"
        );
    }

    /// The check reads every space the registry numbers, not just the one the
    /// test above happens to use. A check that covered metrics alone would pass
    /// this suite and miss an opcode, an error code or an outcome.
    #[test]
    fn every_numbered_space_is_swept_for_duplicates() {
        let registry = loaded();
        let mut swept = 0;
        for (space, outcomes) in &registry.outcomes {
            let mut reused = registry.clone();
            let mut first = outcomes.first().cloned().expect("a space with a member");
            first.name = "a duplicate".to_owned();
            reused
                .outcomes
                .get_mut(space)
                .expect("the space it came from")
                .push(first);
            assert!(
                crate::check::no_number_is_allocated_twice(&reused).is_err(),
                "outcome space {space} is not swept"
            );
            swept += 1;
        }
        assert!(swept > 0, "no outcome space was exercised");

        let mut reused = registry.clone();
        let first: Metric = registry.metrics.first().cloned().expect("a metric");
        reused.metrics.push(first);
        assert!(crate::check::no_number_is_allocated_twice(&reused).is_err());

        let mut reused = registry.clone();
        let first = registry.errors.first().cloned().expect("an error code");
        reused.errors.push(first);
        assert!(crate::check::no_number_is_allocated_twice(&reused).is_err());

        let mut reused = registry.clone();
        let first = registry.messages.first().cloned().expect("a message");
        reused.messages.push(first);
        assert!(crate::check::no_number_is_allocated_twice(&reused).is_err());
    }
}
