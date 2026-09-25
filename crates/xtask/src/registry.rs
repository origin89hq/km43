//! Loads `protocol.toml`, the one place a protocol number is allocated.
//!
//! Every other form — the markdown table, the Rust constants, the TypeScript
//! constants — is generated from it, so two of them cannot disagree.

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// How a message is authenticated.
///
/// There is no ninth variant: a `protocol.toml` naming a rule that does not
/// exist fails to parse, at the line that names it. What each one means is
/// [`Auth::summary`], which the TypeScript bindings print beside every opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Auth {
    None,
    Handshake,
    PairReply,
    PairSealed,
    Sealed,
    Signed,
    Link,
    SealedOrBare,
}

impl Auth {
    /// The label in a sentence, with the rule that defines it.
    pub fn summary(self) -> &'static str {
        match self {
            Self::None => "Unauthenticated: no key exists yet (P-054).",
            Self::Handshake => {
                "Carries a Noise handshake message, authenticated by the handshake itself \
                 (P-054, P-057)."
            }
            Self::PairReply => {
                "Noise message 2 when the pairing proceeds, otherwise a refusal tagged under \
                 the label's refusal key (P-241)."
            }
            Self::PairSealed => {
                "Sealed with ChaCha20-Poly1305 under the keys the pairing handshake split \
                 into, which open no session and are destroyed after it (P-064)."
            }
            Self::Sealed => {
                "Sealed under the session's keys with ChaCha20-Poly1305 (P-231). Not a write, \
                 so not on the signed list (P-052)."
            }
            Self::Signed => {
                "Sealed like every request, with the operation as its inner body. Every write \
                 is one (P-053)."
            }
            Self::Link => {
                "Controller to comms processor, unauthenticated by design: the link is \
                 internal to the board."
            }
            Self::SealedOrBare => {
                "Sealed when the sender holds a session, bare when it does not (P-142)."
            }
        }
    }
}

impl fmt::Display for Auth {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::Handshake => "handshake",
            Self::PairReply => "pair_reply",
            Self::PairSealed => "pair_sealed",
            Self::Sealed => "sealed",
            Self::Signed => "signed",
            Self::Link => "link",
            Self::SealedOrBare => "sealed_or_bare",
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

    /// What a consumer reading a generated constant needs told about its status,
    /// or `None` for a live one. A reserved number is in the bindings because a
    /// peer may already send it, and without the caveat it reads as specified.
    pub fn caveat(self) -> Option<&'static str> {
        match self {
            Self::Live => None,
            Self::Reserved => Some("Reserved: allocated, and not specified yet."),
            Self::Withdrawn => Some("Withdrawn: nothing emits it."),
            Self::Retired => Some("Retired: never reallocated."),
        }
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

/// BLE identifiers are allocated here and rendered into both client bindings.
#[derive(Clone, Deserialize)]
pub struct Ble {
    /// The primary service advertised for KM43 discovery.
    pub service_uuid: String,
    /// Client writes complete fragment values here.
    pub rx_uuid: String,
    /// Controller fragment notifications originate here.
    pub tx_uuid: String,
    /// Marks the fragment that completes an envelope.
    pub last_flag: u8,
    /// Selects the consecutive index within one envelope.
    pub index_mask: u8,
    /// Initial ATT MTU before negotiation completes.
    pub min_mtu: u16,
    /// Largest negotiated ATT MTU supported by the transport.
    pub max_mtu: u16,
    /// Attribute values cannot exceed this even at the largest MTU.
    pub max_value: u16,
    /// Monotonic inactivity threshold for partial messages.
    pub timeout_ms: u16,
    /// Full-message admission refuses beyond this bound.
    pub tx_capacity: u8,
}

impl Ble {
    /// Stable binding names shared by both generated languages.
    pub fn uuids(&self) -> [(&str, &str, &str); 3] {
        [
            (
                "BLE_SERVICE_UUID",
                &self.service_uuid,
                "Discover this service by UUID on every connection; names and addresses do not establish KM43 identity.",
            ),
            (
                "BLE_RX_UUID",
                &self.rx_uuid,
                "Discover this Write Without Response characteristic by UUID; handles are connection-local.",
            ),
            (
                "BLE_TX_UUID",
                &self.tx_uuid,
                "Enable notifications on this characteristic before sending Discover so controller replies can arrive.",
            ),
        ]
    }

    /// Header masks emitted beside the service identifiers.
    pub fn flags(&self) -> [(&str, u8, &str); 2] {
        [
            (
                "BLE_LAST_FLAG",
                self.last_flag,
                "Set this bit only on the final fragment; a receiver must not deliver an unfinished envelope.",
            ),
            (
                "BLE_INDEX_MASK",
                self.index_mask,
                "Mask out the final flag before checking consecutive indices; a gap or duplicate discards the assembly.",
            ),
        ]
    }

    fn validate(&self) -> Result<()> {
        let mut seen = BTreeSet::new();
        for (name, uuid, _) in self.uuids() {
            if uuid.len() != 36
                || !uuid.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                })
                || !seen.insert(uuid)
            {
                bail!("{name} must be a unique canonical lowercase 128-bit UUID");
            }
        }
        if self.last_flag != 0x80 || self.index_mask != 0x7f {
            bail!("BLE flags must retain P-036's bit layout");
        }
        Ok(())
    }
}

/// Where the WebSocket transport is found, rendered into both client bindings.
///
/// The firmware advertises these and the app browses for them; a service type
/// typed separately into each would agree only until one of them was edited.
#[derive(Clone, Deserialize)]
pub struct WebSocket {
    /// TCP port of the opening handshake, and of the SRV record.
    pub port: u16,
    /// Request-target of the opening handshake.
    pub path: String,
    /// DNS-SD service type, `_name._tcp`.
    pub service: String,
    /// TXT key carrying the `device_id`.
    pub txt_device_id: String,
}

impl WebSocket {
    /// Longest service name RFC 6335 section 5.1 allows between `_` and `._tcp`.
    const MAX_SERVICE_NAME: usize = 15;
    /// Longest TXT key RFC 6763 section 6.4 recommends.
    const MAX_TXT_KEY: usize = 9;

    /// Text constants shared by both generated languages.
    pub fn texts(&self) -> [(&str, &str, &str); 3] {
        [
            (
                "WS_PATH",
                &self.path,
                "Request this path in the opening handshake; the controller refuses any other before upgrading.",
            ),
            (
                "DNSSD_SERVICE",
                &self.service,
                "Browse for this DNS-SD type in `local.`; a result is an address to try, not the controller's identity.",
            ),
            (
                "DNSSD_TXT_DEVICE_ID",
                &self.txt_device_id,
                "TXT key holding the `device_id` as 32 lowercase hex characters; unauthenticated, so Discover and Hello still decide.",
            ),
        ]
    }

    /// The port, with the one thing a caller needs to know about it.
    pub fn port(&self) -> (&'static str, u16, &'static str) {
        (
            "WS_PORT",
            self.port,
            "Listen here and advertise it in SRV; a client reaching a remembered address uses it directly.",
        )
    }

    fn validate(&self) -> Result<()> {
        if self.port == 0 {
            bail!("WS_PORT must be a TCP port, not 0");
        }
        let path_ok = self.path.len() > 1
            && self.path.starts_with('/')
            && self.path.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'_' | b'~')
            });
        if !path_ok {
            bail!(
                "WS_PATH must be an absolute path of unreserved characters, not {:?}",
                self.path
            );
        }
        let name = self
            .service
            .strip_prefix('_')
            .and_then(|s| s.strip_suffix("._tcp"))
            .unwrap_or_default();
        let name_ok = (1..=Self::MAX_SERVICE_NAME).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && name.bytes().any(|b| b.is_ascii_lowercase())
            && !name.starts_with('-')
            && !name.ends_with('-')
            && !name.contains("--");
        if !name_ok {
            bail!(
                "DNSSD_SERVICE must be `_name._tcp` with an RFC 6335 service name, not {:?}",
                self.service
            );
        }
        let key_ok = (1..=Self::MAX_TXT_KEY).contains(&self.txt_device_id.len())
            && self
                .txt_device_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !key_ok {
            bail!(
                "DNSSD_TXT_DEVICE_ID must be 1 to {} lowercase letters, digits or underscores, not {:?}",
                Self::MAX_TXT_KEY,
                self.txt_device_id
            );
        }
        Ok(())
    }
}

/// Bounds shared by each transport rather than allocated again in client code.
#[derive(Clone, Deserialize)]
pub struct Limits {
    /// Complete encoded envelopes must fit this byte budget.
    pub max_payload: u16,
}

/// One limit rendered into both languages with the caller's constraint attached.
pub struct TransportLimit {
    /// Public identifier used by consumers.
    pub name: &'static str,
    /// Rust width appropriate for buffers, MTUs or monotonic time.
    pub rust_type: &'static str,
    /// Registry value widened without losing any source bits.
    pub value: u64,
    /// Why an adapter must respect the limit.
    pub doc: &'static str,
}

#[derive(Clone, Deserialize)]
pub struct Registry {
    /// Envelope bounds used by Rust and TypeScript.
    pub limits: Limits,
    /// The client-visible BLE transport allocation.
    pub ble: Ble,
    /// Where a client finds the WebSocket transport.
    pub websocket: WebSocket,
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
    /// The public equipment dataset's reading vocabulary, pinned beside the
    /// registry so a crosswalk row cannot name a word it does not have.
    #[serde(default)]
    pub dataset: Option<Dataset>,
    /// The one translation from a metric at a place to the dataset's word for
    /// it, as written. [`Self::crosswalk`] is the same rows resolved.
    #[serde(default)]
    pub dataset_metrics: Vec<DatasetMetric>,
    /// [`Self::dataset_metrics`] with every name resolved to the number it
    /// allocates, filled at load so a generator reads rows that already passed.
    #[serde(skip)]
    pub crosswalk: Crosswalk,
    /// What the source read as, so the generated files can say which revision
    /// of the registry they came from.
    #[serde(skip)]
    pub digest: Digest,
}

/// Where the public equipment dataset's vocabulary was pinned from, and the
/// live metric kinds it has no word for.
///
/// Unknown keys are refused here and on [`DatasetMetric`]: a misspelt `role`
/// would otherwise read as no role, which means *any* role, and a word meant
/// for a bank would silently apply to every component.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dataset {
    /// Where the dataset serves the file. Not necessarily where the pinned bytes
    /// came from: that is [`Self::vocabulary_provenance`], as it happened.
    pub vocabulary_url: String,
    /// The pinned copy, beside `protocol.toml`.
    pub vocabulary_file: String,
    pub vocabulary_sha256: String,
    /// How the pinned bytes were obtained — fetched from the URL on a date, or
    /// built from a named change before it was published — so an audit reads
    /// what was done and not what the URL implies.
    pub vocabulary_provenance: String,
    /// Live metric kinds, by name, that are the controller's own business: a
    /// client reads them and an equipment database has no column for them.
    #[serde(default)]
    pub internal: Vec<String>,
}

/// One row of the crosswalk as written: a dataset word, and either the metric
/// at a place that carries it or the reason none does.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetMetric {
    pub name: String,
    pub kind: Option<String>,
    pub role: Option<String>,
    pub point: Option<String>,
    /// The signal domain the word is true for. Absent means `live`, the reading
    /// as it is now; a counter names its window, so `AC energy` is
    /// `ac-energy-total` only over `lifetime` and `ac-energy-today` over `today`.
    pub domain: Option<String>,
    pub absent: Option<String>,
}

/// A crosswalk row with its names resolved to the numbers they allocate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    pub name: String,
    pub kind: u16,
    pub role: Option<u16>,
    pub point: Option<u16>,
    /// Never open: a row that named no domain carries `live`, so a limit or a
    /// yesterday counter cannot borrow an instantaneous reading's word.
    pub domain: u8,
}

/// The crosswalk, resolved: what is carried, most specific row first, and what
/// is not and why.
#[derive(Clone, Debug, Default)]
pub struct Crosswalk {
    pub carried: Vec<Carried>,
    pub absent: Vec<(String, String)>,
}

/// The one field of the dataset's `vocabulary.json` the crosswalk is checked against.
#[derive(Deserialize)]
struct Vocabulary {
    metrics: Vec<String>,
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
    /// Whether a receiver refuses to read this code out of a bare body.
    pub sealed: bool,
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
    /// Keep transport capacities and their documentation identical in both bindings.
    pub fn transport_limits(&self) -> [TransportLimit; 6] {
        [
            TransportLimit {
                name: "MAX_PAYLOAD",
                rust_type: "usize",
                value: u64::from(self.limits.max_payload),
                doc: "An encoded envelope larger than this is refused; size receive buffers for the whole envelope, not just its body.",
            },
            TransportLimit {
                name: "BLE_MIN_MTU",
                rust_type: "u16",
                value: u64::from(self.ble.min_mtu),
                doc: "Use this ATT MTU until negotiation completes; sending larger values early can lose the first request.",
            },
            TransportLimit {
                name: "BLE_MAX_MTU",
                rust_type: "u16",
                value: u64::from(self.ble.max_mtu),
                doc: "Reject ATT MTUs above this transport's supported range before deriving fragment sizes.",
            },
            TransportLimit {
                name: "BLE_MAX_VALUE",
                rust_type: "usize",
                value: u64::from(self.ble.max_value),
                doc: "Cap fragment values at this GATT attribute bound even when the negotiated MTU permits more bytes.",
            },
            TransportLimit {
                name: "BLE_TIMEOUT_MS",
                rust_type: "u64",
                value: u64::from(self.ble.timeout_ms),
                doc: "Discard an incomplete assembly at this inactivity boundary; adapters also close stalled sends at this deadline.",
            },
            TransportLimit {
                name: "BLE_TX_CAPACITY",
                rust_type: "usize",
                value: u64::from(self.ble.tx_capacity),
                doc: "Refuse new messages when this per-direction slot count is occupied; never evict a queued message.",
            },
        ]
    }

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
        reg.crosswalk = reg.resolve_crosswalk()?;
        Ok(reg)
    }

    /// The crosswalk with every name resolved, most specific row first.
    ///
    /// Refuses a row that both names a kind and says the word is absent, one that
    /// does neither, a name no table allocates, and two rows that reach the same
    /// place — which would make a word depend on the order somebody typed them.
    pub fn resolve_crosswalk(&self) -> Result<Crosswalk> {
        let mut carried = Vec::new();
        let mut absent = Vec::new();
        let mut places = BTreeSet::new();
        for row in &self.dataset_metrics {
            match (&row.kind, &row.absent) {
                (Some(kind_name), None) => {
                    let kind = self.metric_number(kind_name).with_context(|| {
                        format!(
                            "dataset word {:?} names metric {kind_name:?}, which is not an \
                             allocated metric",
                            row.name
                        )
                    })?;
                    let role = row
                        .role
                        .as_deref()
                        .map(|r| self.place_number("component_role", r))
                        .transpose()?;
                    let point = row
                        .point
                        .as_deref()
                        .map(|p| self.place_number("measurement_point", p))
                        .transpose()?;
                    let domain = self.domain_number(row.domain.as_deref().unwrap_or("live"))?;
                    if !places.insert((kind, role, point, domain)) {
                        bail!(
                            "dataset word {:?} reaches metric {kind_name:?} at a place another \
                             row already claims; one place carries one word",
                            row.name
                        );
                    }
                    carried.push(Carried {
                        name: row.name.clone(),
                        kind,
                        role,
                        point,
                        domain,
                    });
                }
                (None, Some(why)) => {
                    if row.role.is_some() || row.point.is_some() || row.domain.is_some() {
                        bail!(
                            "dataset word {:?} is absent and names a place, which nothing can \
                             be at",
                            row.name
                        );
                    }
                    // The reason is the whole point of an absent row: without one the row
                    // reads as forgotten, which is what it exists to rule out.
                    if why.trim().is_empty() {
                        bail!(
                            "dataset word {:?} is absent with no reason; say why the protocol \
                             cannot carry it",
                            row.name
                        );
                    }
                    absent.push((row.name.clone(), why.clone()));
                }
                (Some(_), Some(_)) => bail!(
                    "dataset word {:?} both names a kind and says it is absent",
                    row.name
                ),
                (None, None) => bail!(
                    "dataset word {:?} names no kind and gives no reason it is absent",
                    row.name
                ),
            }
        }

        // Most specific first, then by kind and place, so the generated order is a
        // property of the rows and not of the file. A role outranks a point: a row
        // naming only the role sorts before one naming only the point, so a reading
        // that matches both — a bank's cell temperature against a bank row and a
        // cell row — takes the role's word every time rather than whichever tuple
        // happened to sort first.
        carried.sort_by_key(|c| {
            (
                std::cmp::Reverse(Self::specificity(c)),
                c.kind,
                c.role,
                c.point,
                c.domain,
            )
        });
        absent.sort();
        Ok(Crosswalk { carried, absent })
    }

    /// The number of a metric that is still allocated, by its name.
    fn metric_number(&self, name: &str) -> Option<u16> {
        self.metrics
            .iter()
            .filter(|m| !m.status.is_gone())
            .find(|m| m.name == name)
            .map(|m| m.kind)
    }

    /// The number of a row of an open space, by its name. A place that is
    /// withdrawn or retired is not a place a row may name: the generated table
    /// would otherwise keep assigning a word to a number the registry says is gone.
    fn place_number(&self, space: &str, name: &str) -> Result<u16> {
        self.open_registries
            .get(space)
            .and_then(|rows| {
                rows.iter()
                    .filter(|r| r.status.is_some_and(|s| !s.is_gone()))
                    .find(|r| r.name == name)
            })
            .and_then(|r| r.number)
            .with_context(|| format!("no allocated `{space}` row is named {name:?}"))
    }

    /// The value of a signal domain, by its name.
    fn domain_number(&self, name: &str) -> Result<u8> {
        self.enums
            .get("signal_domain")
            .and_then(|rows| {
                rows.iter()
                    .filter(|r| !r.status.is_gone())
                    .find(|r| r.name == name)
            })
            .map(|r| r.value)
            .with_context(|| format!("no allocated `signal_domain` is named {name:?}"))
    }

    /// How narrowly a row names its place: both role and point, the role, the
    /// point, or neither. The role weighs more, which is what makes the order
    /// total when a role-only row and a point-only row both match one reading.
    #[must_use]
    pub fn specificity(row: &Carried) -> u8 {
        match (row.role.is_some(), row.point.is_some()) {
            (true, true) => 3,
            (true, false) => 2,
            (false, true) => 1,
            (false, false) => 0,
        }
    }

    /// The dataset's metric words, read from the pinned copy and refused when its
    /// bytes are not the ones the pin names.
    pub fn vocabulary(&self, root: &std::path::Path) -> Result<Vec<String>> {
        let dataset = self
            .dataset
            .as_ref()
            .context("no [dataset] table pins the vocabulary")?;
        let dir = std::path::Path::new(Self::PATH)
            .parent()
            .context("the registry path has no directory")?;
        let path = root.join(dir).join(&dataset.vocabulary_file);
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&bytes).iter().fold(
            String::new(),
            |mut hex, b| {
                let _ = fmt::Write::write_fmt(&mut hex, format_args!("{b:02x}"));
                hex
            },
        );
        if digest != dataset.vocabulary_sha256 {
            bail!(
                "{} is sha256 {digest}; the pin says {} ({}; served at {}). Review the change \
                 and move the pin",
                path.display(),
                dataset.vocabulary_sha256,
                dataset.vocabulary_provenance,
                dataset.vocabulary_url
            );
        }
        let vocabulary: Vocabulary = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not the dataset's vocabulary", path.display()))?;
        Ok(vocabulary.metrics)
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
    /// in an associated data string. Excluded by name rather than by a guess about the
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
        self.ble.validate()?;
        self.websocket.validate()?;
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
mod crosswalk {
    use super::{DatasetMetric, Registry};

    fn loaded() -> Registry {
        let root = crate::check::repo_root().expect("a repo to read the registry from");
        Registry::load(&root).expect("the registry parses")
    }

    fn row(
        name: &str,
        kind: Option<&str>,
        role: Option<&str>,
        absent: Option<&str>,
    ) -> DatasetMetric {
        DatasetMetric {
            name: name.to_owned(),
            kind: kind.map(str::to_owned),
            role: role.map(str::to_owned),
            point: None,
            domain: None,
            absent: absent.map(str::to_owned),
        }
    }

    /// The value the registry allocates to a signal domain, read from the registry.
    fn domain(reg: &Registry, name: &str) -> u8 {
        reg.enums
            .get("signal_domain")
            .and_then(|rows| rows.iter().find(|r| r.name == name))
            .map(|r| r.value)
            .expect("an allocated domain")
    }

    /// A counter's word depends on its window: the lifetime AC energy is the
    /// dataset's total, today's is its today figure, and yesterday's is nothing.
    #[test]
    fn a_domain_tells_a_total_from_a_day() {
        let reg = loaded();
        let energy = metric(&reg, "AC energy");
        let total = reg
            .crosswalk
            .carried
            .iter()
            .find(|c| c.name == "ac-energy-total")
            .expect("ac-energy-total");
        assert_eq!(total.kind, energy);
        assert_eq!(total.domain, domain(&reg, "lifetime"));
        let today = reg
            .crosswalk
            .carried
            .iter()
            .find(|c| c.name == "ac-energy-today")
            .expect("ac-energy-today");
        assert_eq!(today.domain, domain(&reg, "today"));
        let live = domain(&reg, "live");
        let bank_voltage = reg
            .crosswalk
            .carried
            .iter()
            .find(|c| c.name == "battery-voltage")
            .expect("battery-voltage");
        assert_eq!(
            bank_voltage.domain, live,
            "a row naming no domain is the live reading"
        );
        assert!(
            !reg.crosswalk
                .carried
                .iter()
                .any(|c| c.kind == energy && c.domain == live),
            "a counter is never the live reading"
        );

        let mut reg = loaded();
        let mut bad = row("ac-energy-total", Some("AC energy"), None, None);
        bad.domain = Some("fortnight".to_owned());
        reg.dataset_metrics.push(bad);
        let said = reg
            .resolve_crosswalk()
            .expect_err("fortnight is not a domain");
        assert!(
            said.to_string().contains("no allocated `signal_domain`"),
            "{said}"
        );
    }

    /// The number the registry allocates to a metric, read from the registry so
    /// the test holds no second copy of an allocation.
    fn metric(reg: &Registry, name: &str) -> u16 {
        reg.metrics
            .iter()
            .find(|m| m.name == name)
            .map(|m| m.kind)
            .expect("an allocated metric")
    }

    /// The number the registry allocates to a row of an open space.
    fn place(reg: &Registry, space: &str, name: &str) -> u16 {
        reg.open_registries
            .get(space)
            .and_then(|rows| rows.iter().find(|r| r.name == name))
            .and_then(|r| r.number)
            .expect("an allocated row")
    }

    /// The row a consumer will ask for first: a bank's DC voltage is the
    /// dataset's `battery-voltage`, resolved to the numbers the registry allocates.
    #[test]
    fn a_row_resolves_its_names_to_the_numbers_they_allocate() {
        let reg = loaded();
        let bank_role = place(&reg, "component_role", "battery bank");
        let bank = reg
            .crosswalk
            .carried
            .iter()
            .find(|c| c.name == "battery-voltage" && c.role == Some(bank_role))
            .expect("battery-voltage at the battery bank");
        assert_eq!(bank.kind, metric(&reg, "DC voltage"));
        assert_eq!(bank.point, None);
    }

    /// A misspelt constraint must not read as no constraint: `rol` is not `role`,
    /// and a row with no role means any role.
    #[test]
    fn an_unknown_field_on_a_row_is_refused() {
        let said = toml::from_str::<DatasetMetric>(
            "name = \"battery-voltage\"\nkind = \"DC voltage\"\nrol = \"battery bank\"\n",
        )
        .expect_err("a misspelt key is refused, not ignored");
        assert!(said.to_string().contains("rol"), "{said}");
        assert!(
            toml::from_str::<DatasetMetric>("name = \"tank-level\"\nkind = \"tank level\"\n")
                .is_ok()
        );
    }

    /// A lookup takes the first match, so the plain `temperature` row must come
    /// after every row that names a place.
    #[test]
    fn rows_come_most_specific_first() {
        let order: Vec<u8> = loaded()
            .crosswalk
            .carried
            .iter()
            .map(Registry::specificity)
            .collect();
        let mut sorted = order.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(order, sorted);
    }

    /// A bank's cell temperature matches a row naming the bank and a row naming
    /// the cell. Both are one step specific; the role's row comes first, so the
    /// word is decided by the rule and not by which tuple sorted first.
    #[test]
    fn a_role_outranks_a_point_when_both_match() {
        let mut reg = loaded();
        reg.dataset_metrics.push(DatasetMetric {
            name: "temperature".to_owned(),
            kind: Some("temperature".to_owned()),
            role: None,
            point: Some("cell".to_owned()),
            domain: None,
            absent: None,
        });
        let temperature = metric(&reg, "temperature");
        let bank_role = place(&reg, "component_role", "battery bank");
        let cell_point = place(&reg, "measurement_point", "cell");
        let carried = reg
            .resolve_crosswalk()
            .expect("a point-only row is legal")
            .carried;
        let bank = carried
            .iter()
            .position(|c| c.kind == temperature && c.role == Some(bank_role) && c.point.is_none())
            .expect("the bank's temperature row");
        let cell = carried
            .iter()
            .position(|c| c.kind == temperature && c.role.is_none() && c.point == Some(cell_point))
            .expect("the cell-point temperature row");
        assert!(
            bank < cell,
            "the role's row must lead: bank at {bank}, cell at {cell}"
        );
    }

    #[test]
    fn a_row_that_is_both_carried_and_absent_is_refused() {
        let mut reg = loaded();
        reg.dataset_metrics
            .push(row("pv-power", Some("DC power (signed)"), None, Some("no")));
        let said = reg
            .resolve_crosswalk()
            .expect_err("a row cannot both name a kind and be absent");
        assert!(said.to_string().contains("both names a kind"), "{said}");

        let mut reg = loaded();
        reg.dataset_metrics.push(row("pv-power", None, None, None));
        let said = reg
            .resolve_crosswalk()
            .expect_err("a row must say one or the other");
        assert!(said.to_string().contains("names no kind"), "{said}");
    }

    #[test]
    fn a_name_no_table_allocates_is_refused() {
        let mut reg = loaded();
        reg.dataset_metrics.push(row(
            "pv-power",
            Some("DC power (signed)"),
            Some("solar roof"),
            None,
        ));
        let said = reg
            .resolve_crosswalk()
            .expect_err("solar roof is not a component role");
        assert!(
            said.to_string()
                .contains("no allocated `component_role` row"),
            "{said}"
        );

        let mut reg = loaded();
        reg.dataset_metrics
            .push(row("pv-power", Some("PV array power"), None, None));
        let said = reg
            .resolve_crosswalk()
            .expect_err("PV array power is retired");
        assert!(
            said.to_string().contains("not an allocated metric"),
            "{said}"
        );
    }

    /// A place the registry has retired is not a place; the row that named it
    /// must be refused rather than keep a word on a number nothing emits.
    #[test]
    fn a_retired_place_is_refused() {
        let mut reg = loaded();
        let roles = reg
            .open_registries
            .get_mut("component_role")
            .expect("component roles");
        let heater = roles
            .iter_mut()
            .find(|r| r.name == "heater")
            .expect("a heater role");
        heater.status = Some(super::Status::Retired);
        reg.dataset_metrics.push(row(
            "temperature",
            Some("temperature"),
            Some("heater"),
            None,
        ));
        let said = reg.resolve_crosswalk().expect_err("heater is retired");
        assert!(
            said.to_string()
                .contains("no allocated `component_role` row"),
            "{said}"
        );
    }

    /// An absent row with no reason is a forgotten mapping wearing an excuse.
    #[test]
    fn an_absent_row_must_say_why() {
        for why in ["", "   "] {
            let mut reg = loaded();
            reg.dataset_metrics
                .push(row("cabin-mood", None, None, Some(why)));
            let said = reg
                .resolve_crosswalk()
                .expect_err("an empty reason is no reason");
            assert!(said.to_string().contains("absent with no reason"), "{said}");
        }
    }

    /// Two rows reaching the same place would make the word depend on the order
    /// somebody typed them; the file as committed has none, and adding one fails.
    #[test]
    fn one_place_carries_one_word() {
        let mut reg = loaded();
        reg.dataset_metrics.push(row(
            "load-voltage",
            Some("DC voltage"),
            Some("battery bank"),
            None,
        ));
        let said = reg
            .resolve_crosswalk()
            .expect_err("the bank's DC voltage is already a word");
        assert!(said.to_string().contains("already claims"), "{said}");
    }

    /// The pin is the whole point: a vocabulary whose bytes moved without the
    /// pin moving is a list nobody reviewed.
    #[test]
    fn a_vocabulary_whose_bytes_are_not_the_pinned_ones_is_refused() {
        let root = crate::check::repo_root().expect("a repo");
        let reg = loaded();
        assert!(
            reg.vocabulary(&root)
                .expect("the pinned copy reads")
                .contains(&"pv-voltage".to_owned())
        );

        let mut moved = loaded();
        moved.dataset.as_mut().expect("a pin").vocabulary_sha256 = "0".repeat(64);
        let said = moved.vocabulary(&root).expect_err("the hash disagrees");
        assert!(said.to_string().contains("the pin says"), "{said}");
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
    /// The two `0x0000`s in `PROTOCOL.md` are a CRC xorout and a zero word in an
    /// associated data string. Sweep the capability mask with the rest and the check
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

#[cfg(test)]
mod ble_tests {
    use super::Registry;

    #[test]
    fn ble_uuid_allocation_rejects_duplicate_or_noncanonical_identifiers() {
        let root = crate::check::repo_root().expect("repository");
        let registry = Registry::load(&root).expect("valid registry");
        registry.ble.validate().expect("distinct UUIDs");
        let mut duplicate = registry.ble.clone();
        duplicate.rx_uuid.clone_from(&duplicate.service_uuid);
        assert!(duplicate.validate().is_err());
        for invalid in [
            String::new(),
            "1234".to_owned(),
            registry.ble.service_uuid.to_uppercase(),
            registry.ble.service_uuid.replace('-', "_"),
        ] {
            let mut malformed = registry.ble.clone();
            malformed.service_uuid.clone_from(&invalid);
            assert!(malformed.validate().is_err(), "{invalid}");
        }
    }

    #[test]
    fn ble_header_bits_cannot_overlap_or_move() {
        let root = crate::check::repo_root().expect("repository");
        let registry = Registry::load(&root).expect("valid registry");
        for (flag, mask) in [(0, 127), (128, 255), (64, 63)] {
            let mut ble = registry.ble.clone();
            ble.last_flag = flag;
            ble.index_mask = mask;
            assert!(ble.validate().is_err());
        }
    }
}

#[cfg(test)]
mod websocket_tests {
    use super::{Registry, WebSocket};

    fn allocated() -> WebSocket {
        let root = crate::check::repo_root().expect("repository");
        Registry::load(&root).expect("valid registry").websocket
    }

    #[test]
    fn the_allocated_websocket_discovery_contract_is_accepted() {
        let ws = allocated();
        ws.validate().expect("the registry's own allocation");
        assert_eq!(ws.port().1, ws.port);
        assert_eq!(
            ws.texts().map(|(name, ..)| name),
            ["WS_PATH", "DNSSD_SERVICE", "DNSSD_TXT_DEVICE_ID"]
        );
    }

    /// Each of these is a string the firmware would advertise and the app would
    /// browse for: iOS refuses a malformed type in `NSBonjourServices` at build
    /// time, or worse, browses for it and finds nothing.
    #[test]
    fn a_service_type_that_is_not_an_rfc_6335_name_is_refused() {
        for bad in [
            "",
            "km43._tcp",
            "_km43",
            "_km43._udp",
            "_._tcp",
            "_KM43._tcp",
            "_km43-._tcp",
            "_-km43._tcp",
            "_km--43._tcp",
            "_4343._tcp",
            "_abcdefghijklmnop._tcp",
        ] {
            let mut ws = allocated();
            ws.service = bad.to_owned();
            assert!(ws.validate().is_err(), "{bad:?}");
        }
        let mut ws = allocated();
        ws.service = "_abcdefghijklmno._tcp".to_owned();
        ws.validate()
            .expect("fifteen characters is the RFC 6335 limit, not over it");
    }

    #[test]
    fn a_path_or_port_that_cannot_open_a_handshake_is_refused() {
        for bad in ["", "/", "km43", "/km43?x", "/km 43", "/km43#"] {
            let mut ws = allocated();
            ws.path = bad.to_owned();
            assert!(ws.validate().is_err(), "{bad:?}");
        }
        let mut ws = allocated();
        ws.port = 0;
        assert!(ws.validate().is_err());
    }

    #[test]
    fn a_txt_key_a_browser_would_misread_is_refused() {
        for bad in ["", "ID", "device=id", "device_id_x", "i d"] {
            let mut ws = allocated();
            ws.txt_device_id = bad.to_owned();
            assert!(ws.validate().is_err(), "{bad:?}");
        }
    }
}
