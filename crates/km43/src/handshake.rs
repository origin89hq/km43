//! `Discover 0x80` and the two halves of `Hello` — where a session begins, and
//! the two places in this protocol a value is used before it is authenticated.
//!
//! `Discover 0x80` is the one message with no MAC at all (P-054), so every field
//! in it is a claim the comms processor could have made up. Nothing here derives
//! `Debug` over one: a rendered `model` is sixty-four attacker-chosen bytes in a
//! log somebody reads as if the site had said them, which is P-055 lost to one
//! `?discovery` in a span. P-087 puts `epoch` in that message so a client whose
//! key no longer derives is told why rather than collecting an unexplainable bad
//! proof.
//!
//! The two orderings are structural rather than remembered. A [`HelloClaim`]
//! hands over `client_id` and `client_nonce` — the two fields the key cannot be
//! found without — and nothing else until the proof over the bytes that arrived
//! has checked out, which is P-057's order and what stops P-070's version fields
//! being read off a body a relay wrote. And [`Session::open`] takes no key at
//! all: it derives one from the `session_id` in the envelope, because P-072 says
//! that is the only order that works, and a caller allowed to pass a key in is a
//! caller who can pass the wrong one.
//!
//! cites: P-005, P-006, P-048, P-057, P-070, P-072, P-073, P-074, P-087

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::{Envelope, EnvelopeError, Header, Refusal, SessionId};
use crate::generated::{ErrorCode, MessageType};
use crate::kdf::{ClientId, Enrolment, Epoch, Handshake};
use crate::limits::{
    MAX_CHANNELS, MAX_CLIENTS, MAX_CMD_DEDUP, MAX_EVENT_QUEUE, MAX_INFLIGHT, MAX_PAYLOAD,
    MAX_SESSIONS, MAX_STRING, REQUEST_FRAMING_BYTES, RESPONSE_FRAMING_BYTES,
};
use crate::mac::{ClientKey, HelloProof, MacError, SessionKey, Tag};
use crate::wrapper::{Wrapper, WrapperError};

/// A `device_id`, a `challenge` and a `client_nonce` are all `bstr16`.
const BSTR16: usize = 16;

/// A `text` field at its widest: a two-byte head and [`MAX_STRING`] bytes.
const TEXT_MAX: usize = 2 + MAX_STRING;

const_assert!(
    MAX_STRING >= 24 && MAX_STRING <= 255,
    "a CBOR text head is two bytes only between 24 and 255 — outside that range the three body caps below are each a byte out, and the frame that does not fit gets built at a fully configured site rather than on a bench"
);

/// The widest `Discover 0x80` **body**: eight keys, a 64-byte `model` and two
/// `bstr16`. A controller sizes its answer buffer at this plus the eleven bytes
/// of envelope [`Discovery::write`] puts around it — the name says body, and a
/// buffer sized at this alone refuses the widest model name, which is a failure
/// that waits for a real site rather than showing up on a bench.
pub const MAX_DISCOVER_BODY: usize = 54 + TEXT_MAX;

/// The widest inner body of `Hello 0x01`. A client's scratch is this wide,
/// because the proof covers the encoded bytes (P-048) and the bytes have to
/// exist somewhere before they can be proved.
pub const MAX_HELLO_INNER: usize = 32 + TEXT_MAX;

/// Keys 18 to 29 at the widest their declared types permit, key bytes included.
///
/// **Keys 24 and up cost two CBOR bytes for the key itself**, because a map key
/// is an unsigned integer under the same shortest-form rule as everything else
/// and 24 is where one byte stops holding it. `Hello 0x81` is the only body in
/// this protocol whose key numbers cross that boundary, so nothing had
/// exercised it before.
///
/// `rev` 6 + `digest` 10 + `buses` 3 + three `u16` at 4 + six more at 5 or 4
/// once the key widens = 59.
const TOPOLOGY_REPORT_BYTES: usize = 59;

/// The widest body of `Hello 0x81`: twenty-nine keys, two 64-byte firmware
/// strings and four `u64`.
///
/// The trailing `+ 1` is the map header: twenty-nine pairs is past twenty-three,
/// so the header that cost one byte at seventeen keys costs two.
pub const MAX_HELLO_REPORT: usize = 81 + 2 * TEXT_MAX + TOPOLOGY_REPORT_BYTES + 1;

const_assert!(
    MAX_HELLO_REPORT + RESPONSE_FRAMING_BYTES <= MAX_PAYLOAD,
    "a Hello 0x81 travels under an envelope and a wrapper; a body that fills the payload is the frame a controller builds and then has to refuse with error 5, which is P-185's argument one message over"
);
const_assert!(
    MAX_HELLO_INNER + REQUEST_FRAMING_BYTES <= MAX_PAYLOAD,
    "the inner body of a Hello 0x01 rides inside its payload key inside an envelope, and a client that cannot fit its own handshake never opens a session at all"
);

/// The two version bytes both ends open with.
///
/// P-073's negotiation is [`Version::agreed`], and it is the only place the two
/// numbers are compared — a major that differs refuses, a minor that differs
/// takes the lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// A difference here refuses the session with error 3 (P-073).
    pub major: u8,
    /// A difference here is negotiated down, never assumed away.
    pub minor: u8,
}

impl Version {
    /// The version the shapes in this module describe, which is the one
    /// `docs/PROTOCOL.md` is titled after.
    pub const V1_0: Self = Self { major: 1, minor: 0 };

    /// P-073: a major mismatch refuses the session, a minor mismatch proceeds at
    /// the lower of the two. A newer peer degrades; it never assumes.
    pub fn agreed(self, theirs: Self) -> Result<Self, HandshakeError> {
        if self.major != theirs.major {
            return Err(HandshakeError::MajorMismatch {
                ours: self.major,
                theirs: theirs.major,
            });
        }
        Ok(Self {
            major: self.major,
            minor: self.minor.min(theirs.minor),
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A position in the **log** sequence space (P-074).
///
/// Separate from [`StateSeq`] because the two spaces look identical in a hex
/// dump and comparing them is a client deciding it has missed records it never
/// could have had:
///
/// ```
/// use km43::LogSeq;
/// assert!(LogSeq(2) > LogSeq(1));
/// ```
/// ```compile_fail
/// use km43::{LogSeq, StateSeq};
/// fn behind(log: LogSeq, state: StateSeq) -> bool { log < state }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogSeq(pub u64);

/// The state store's own counter (P-074), which is not a position in the log.
///
/// ```
/// use km43::StateSeq;
/// assert!(StateSeq(2) > StateSeq(1));
/// ```
/// ```compile_fail
/// use km43::{LogSeq, StateSeq};
/// fn ahead(state: StateSeq, log: LogSeq) -> bool { state > log }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StateSeq(pub u64);

/// The eight keys of `Discover 0x80`, by name rather than by number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverKey {
    /// Key 1.
    ProtocolMajor,
    /// Key 2.
    ProtocolMinor,
    /// Key 3, the 16 bytes of P-038 and never their hex rendering.
    DeviceId,
    /// Key 4, what a person reads on a scan list.
    Model,
    /// Key 5, true once at least one client is enrolled.
    Provisioned,
    /// Key 6, true while the physical button has opened a window (P-066).
    PairingOpen,
    /// Key 7, this connection's live challenge (P-060).
    Challenge,
    /// Key 8, the provisioning epoch P-087 put here.
    Epoch,
}

impl DiscoverKey {
    /// How many pairs the body map promises.
    const COUNT: usize = 8;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ProtocolMajor),
            2 => Some(Self::ProtocolMinor),
            3 => Some(Self::DeviceId),
            4 => Some(Self::Model),
            5 => Some(Self::Provisioned),
            6 => Some(Self::PairingOpen),
            7 => Some(Self::Challenge),
            8 => Some(Self::Epoch),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ProtocolMajor => 1,
            Self::ProtocolMinor => 2,
            Self::DeviceId => 3,
            Self::Model => 4,
            Self::Provisioned => 5,
            Self::PairingOpen => 6,
            Self::Challenge => 7,
            Self::Epoch => 8,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ProtocolMajor => "protocol_major",
            Self::ProtocolMinor => "protocol_minor",
            Self::DeviceId => "device_id",
            Self::Model => "model",
            Self::Provisioned => "provisioned",
            Self::PairingOpen => "pairing_open",
            Self::Challenge => "challenge",
            Self::Epoch => "epoch",
        }
    }
}

impl fmt::Display for DiscoverKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Discover 0x80 {} (key {})", self.name(), self.number())
    }
}

/// The two keys of a `Hello 0x01` body: the encoded inner body, and the proof
/// over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloKey {
    /// Key 1, the inner body exactly as the client encoded it.
    Payload,
    /// Key 2, the sixteen bytes of [`Tag`].
    Proof,
}

impl HelloKey {
    const COUNT: usize = 2;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Payload),
            2 => Some(Self::Proof),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Payload => 1,
            Self::Proof => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Payload => "payload",
            Self::Proof => "proof",
        }
    }
}

impl fmt::Display for HelloKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hello 0x01 {} (key {})", self.name(), self.number())
    }
}

/// The five keys of the inner body of `Hello 0x01` — the ones P-070 puts inside
/// the proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerKey {
    /// Key 1.
    ProtocolMajor,
    /// Key 2.
    ProtocolMinor,
    /// Key 3, which names the enrolment and so the key (P-057).
    ClientId,
    /// Key 4, what a person reads in the client list.
    ClientVersion,
    /// Key 5, the client's half of the session salt (P-071).
    ClientNonce,
}

impl InnerKey {
    const COUNT: usize = 5;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ProtocolMajor),
            2 => Some(Self::ProtocolMinor),
            3 => Some(Self::ClientId),
            4 => Some(Self::ClientVersion),
            5 => Some(Self::ClientNonce),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ProtocolMajor => 1,
            Self::ProtocolMinor => 2,
            Self::ClientId => 3,
            Self::ClientVersion => 4,
            Self::ClientNonce => 5,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ProtocolMajor => "protocol_major",
            Self::ProtocolMinor => "protocol_minor",
            Self::ClientId => "client_id",
            Self::ClientVersion => "client_version",
            Self::ClientNonce => "client_nonce",
        }
    }
}

impl fmt::Display for InnerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hello 0x01 inner body {} (key {})",
            self.name(),
            self.number()
        )
    }
}

/// The twenty-nine keys of `Hello 0x81`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKey {
    /// Key 1.
    ProtocolMajor,
    /// Key 2.
    ProtocolMinor,
    /// Key 3, which the envelope carries too and must match.
    SessionId,
    /// Key 4.
    FwController,
    /// Key 5, diagnostic only — a client must not decide on it.
    FwComms,
    /// Key 6, the capability bitfield.
    Capabilities,
    /// Key 7.
    LogOldestSeq,
    /// Key 8.
    LogNewestSeq,
    /// Key 9, which is the state store's space and not the log's (P-074).
    StateSeq,
    /// Key 10.
    TimeKnown,
    /// Key 11, this client's last accepted counter.
    Counter,
    /// Key 12, the first of P-005's reported caps.
    MaxSessions,
    /// Key 13, which P-006 caps at 32.
    MaxChannels,
    /// Key 14.
    MaxClients,
    /// Key 15.
    MaxEventQueue,
    /// Key 16.
    MaxInflight,
    /// Key 17, entries — the ten-minute window is not reported.
    MaxCmdDedup,
    /// Key 18, the topology revision. With key 19 it is one identity (P-149).
    Rev,
    /// Key 19, the topology digest — the leftmost eight bytes of P-148's hash.
    TopoDigest,
    /// Key 20, the first of the topology caps.
    MaxBuses,
    /// Key 21.
    MaxDevices,
    /// Key 22.
    MaxComponents,
    /// Key 23.
    MaxSignals,
    /// Key 24, the shared series-element pool. It implies nothing about key 23
    /// and is reported because a driver's fourteenth pack loses its signal to a
    /// budget the client was never told.
    MaxSeriesElements,
    /// Key 25.
    MaxParams,
    /// Key 26.
    MaxConcerns,
    /// Key 27, selectors per `ReadSignals`.
    MaxSelectors,
    /// Key 28.
    MaxHistorySignals,
    /// Key 29, how deep either `parent` chain may run.
    MaxTopologyDepth,
}

impl ReportKey {
    const COUNT: usize = 29;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ProtocolMajor),
            2 => Some(Self::ProtocolMinor),
            3 => Some(Self::SessionId),
            4 => Some(Self::FwController),
            5 => Some(Self::FwComms),
            6 => Some(Self::Capabilities),
            7 => Some(Self::LogOldestSeq),
            8 => Some(Self::LogNewestSeq),
            9 => Some(Self::StateSeq),
            10 => Some(Self::TimeKnown),
            11 => Some(Self::Counter),
            12 => Some(Self::MaxSessions),
            13 => Some(Self::MaxChannels),
            14 => Some(Self::MaxClients),
            15 => Some(Self::MaxEventQueue),
            16 => Some(Self::MaxInflight),
            17 => Some(Self::MaxCmdDedup),
            18 => Some(Self::Rev),
            19 => Some(Self::TopoDigest),
            20 => Some(Self::MaxBuses),
            21 => Some(Self::MaxDevices),
            22 => Some(Self::MaxComponents),
            23 => Some(Self::MaxSignals),
            24 => Some(Self::MaxSeriesElements),
            25 => Some(Self::MaxParams),
            26 => Some(Self::MaxConcerns),
            27 => Some(Self::MaxSelectors),
            28 => Some(Self::MaxHistorySignals),
            29 => Some(Self::MaxTopologyDepth),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ProtocolMajor => 1,
            Self::ProtocolMinor => 2,
            Self::SessionId => 3,
            Self::FwController => 4,
            Self::FwComms => 5,
            Self::Capabilities => 6,
            Self::LogOldestSeq => 7,
            Self::LogNewestSeq => 8,
            Self::StateSeq => 9,
            Self::TimeKnown => 10,
            Self::Counter => 11,
            Self::MaxSessions => 12,
            Self::MaxChannels => 13,
            Self::MaxClients => 14,
            Self::MaxEventQueue => 15,
            Self::MaxInflight => 16,
            Self::MaxCmdDedup => 17,
            Self::Rev => 18,
            Self::TopoDigest => 19,
            Self::MaxBuses => 20,
            Self::MaxDevices => 21,
            Self::MaxComponents => 22,
            Self::MaxSignals => 23,
            Self::MaxSeriesElements => 24,
            Self::MaxParams => 25,
            Self::MaxConcerns => 26,
            Self::MaxSelectors => 27,
            Self::MaxHistorySignals => 28,
            Self::MaxTopologyDepth => 29,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ProtocolMajor => "protocol_major",
            Self::ProtocolMinor => "protocol_minor",
            Self::SessionId => "session_id",
            Self::FwController => "fw_controller",
            Self::FwComms => "fw_comms",
            Self::Capabilities => "capabilities",
            Self::LogOldestSeq => "log_oldest_seq",
            Self::LogNewestSeq => "log_newest_seq",
            Self::StateSeq => "state_seq",
            Self::TimeKnown => "time_known",
            Self::Counter => "counter",
            Self::MaxSessions => "max_sessions",
            Self::MaxChannels => "max_channels",
            Self::MaxClients => "max_clients",
            Self::MaxEventQueue => "max_event_queue",
            Self::MaxInflight => "max_inflight",
            Self::MaxCmdDedup => "max_cmd_dedup",
            Self::Rev => "rev",
            Self::TopoDigest => "topo_digest",
            Self::MaxBuses => "max_buses",
            Self::MaxDevices => "max_devices",
            Self::MaxComponents => "max_components",
            Self::MaxSignals => "max_signals",
            Self::MaxSeriesElements => "max_series_elements",
            Self::MaxParams => "max_params",
            Self::MaxConcerns => "max_concerns",
            Self::MaxSelectors => "max_selectors",
            Self::MaxHistorySignals => "max_history_signals",
            Self::MaxTopologyDepth => "max_topology_depth",
        }
    }
}

impl fmt::Display for ReportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hello 0x81 {} (key {})", self.name(), self.number())
    }
}

/// A key of any of the four bodies here, so one refusal can name any of them.
///
/// `BodyKey` and not `Key` for the reason `wrapper.rs` gives about `WrapperKey`:
/// this crate is full of keys and none of the others are integers on a wire.
///
/// Four enums rather than one flat list of thirty-two: key 1 is
/// `protocol_major` in a `Discover` and `payload` in a `Hello`, and a single
/// enum would either lose that or spell every variant twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKey {
    /// A key of `Discover 0x80`.
    Discover(DiscoverKey),
    /// A key of the `Hello 0x01` body.
    Hello(HelloKey),
    /// A key of the inner body a `Hello 0x01` proof covers.
    Inner(InnerKey),
    /// A key of `Hello 0x81`.
    Report(ReportKey),
}

impl From<DiscoverKey> for BodyKey {
    fn from(key: DiscoverKey) -> Self {
        Self::Discover(key)
    }
}

impl From<HelloKey> for BodyKey {
    fn from(key: HelloKey) -> Self {
        Self::Hello(key)
    }
}

impl From<InnerKey> for BodyKey {
    fn from(key: InnerKey) -> Self {
        Self::Inner(key)
    }
}

impl From<ReportKey> for BodyKey {
    fn from(key: ReportKey) -> Self {
        Self::Report(key)
    }
}

impl fmt::Display for BodyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discover(key) => key.fmt(f),
            Self::Hello(key) => key.fmt(f),
            Self::Inner(key) => key.fmt(f),
            Self::Report(key) => key.fmt(f),
        }
    }
}

/// Keys 18 to 29: the topology plane's revision, its digest, and the caps
/// P-005 governs one message over.
///
/// `rev` and `digest` are **one identity** (P-149). A client meeting a matching
/// revision with a differing digest has met a controller that edited a
/// descriptor without moving the revision, which is the one silent failure the
/// topology design has — so it refetches and says so out loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topology {
    /// The topology revision the digest and the caps are of.
    pub rev: u32,
    /// The leftmost eight bytes of P-148's hash.
    pub digest: [u8; 8],
    /// The cap on bus rows (P-005).
    pub buses: u8,
    /// The cap on device rows.
    pub devices: u16,
    /// The cap on component rows.
    pub components: u16,
    /// The cap on signal rows.
    pub signals: u16,
    /// A shared pool. It implies nothing about `signals`, which is why it is
    /// reported rather than inferred.
    pub series_elements: u16,
    /// The cap on parameter rows.
    pub params: u16,
    /// The cap on concern rows.
    pub concerns: u16,
    /// The cap on selectors in one `ReadSignals`.
    pub selectors: u8,
    /// The cap on signals with history.
    pub history_signals: u16,
    /// The cap on nesting in the component tree.
    pub topology_depth: u8,
}

impl Topology {
    /// What this controller enforces.
    ///
    /// Literals with a compile-time check under them rather than `as` casts off
    /// the `usize` limits: a narrowing cast is exactly how a cap of 384 is
    /// reported as 128, and the assertion below catches a drift that a cast
    /// would silently absorb. Widening back to `usize` to compare is the safe
    /// direction.
    pub const THIS_CONTROLLER: Self = Self {
        rev: 0,
        digest: [0; 8],
        buses: 8,
        devices: 24,
        components: 160,
        signals: 384,
        series_elements: 512,
        params: 96,
        concerns: 48,
        selectors: 12,
        history_signals: 24,
        topology_depth: 4,
    };

    /// Keys 18 to 29, split out for the reason `Caps::encode` is: twenty-nine
    /// keys in one function is the `too_many_lines` the lint describes.
    fn encode(self, cbor: &mut CborWriter<'_>) -> Result<(), HandshakeError> {
        cbor.key(ReportKey::Rev.number())?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(ReportKey::TopoDigest.number())?;
        cbor.bytes(&self.digest)?;
        for (key, value) in [
            (ReportKey::MaxBuses, u64::from(self.buses)),
            (ReportKey::MaxDevices, u64::from(self.devices)),
            (ReportKey::MaxComponents, u64::from(self.components)),
            (ReportKey::MaxSignals, u64::from(self.signals)),
            (
                ReportKey::MaxSeriesElements,
                u64::from(self.series_elements),
            ),
            (ReportKey::MaxParams, u64::from(self.params)),
            (ReportKey::MaxConcerns, u64::from(self.concerns)),
            (ReportKey::MaxSelectors, u64::from(self.selectors)),
            (
                ReportKey::MaxHistorySignals,
                u64::from(self.history_signals),
            ),
            (ReportKey::MaxTopologyDepth, u64::from(self.topology_depth)),
        ] {
            cbor.key(key.number())?;
            cbor.u64(value)?;
        }
        Ok(())
    }
}

const_assert!(
    Topology::THIS_CONTROLLER.buses as usize == crate::limits::MAX_BUSES
        && Topology::THIS_CONTROLLER.devices as usize == crate::limits::MAX_DEVICES
        && Topology::THIS_CONTROLLER.components as usize == crate::limits::MAX_COMPONENTS
        && Topology::THIS_CONTROLLER.signals as usize == crate::limits::MAX_SIGNALS
        && Topology::THIS_CONTROLLER.series_elements as usize == crate::limits::MAX_SERIES_ELEMENTS
        && Topology::THIS_CONTROLLER.params as usize == crate::limits::MAX_PARAMS
        && Topology::THIS_CONTROLLER.concerns as usize == crate::limits::MAX_CONCERNS
        && Topology::THIS_CONTROLLER.selectors as usize == crate::limits::MAX_SELECTORS
        && Topology::THIS_CONTROLLER.history_signals as usize == crate::limits::MAX_HISTORY_SIGNALS
        && Topology::THIS_CONTROLLER.topology_depth as usize == crate::limits::MAX_TOPOLOGY_DEPTH,
    "a reported cap that is not the enforced one is P-005's whole failure: a client told it may keep more than the controller allows behaves worse than the guess it replaced"
);

/// P-005's keys 12 to 17: what this controller enforces, not what the protocol
/// permits.
///
/// A client uses these in place of anything it was compiled with, so reporting a
/// number the controller does not enforce is worse than reporting nothing —
/// a client told it may keep eight requests in flight collects error 7 all
/// afternoon and tells somebody the site is busy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Key 12.
    pub sessions: u8,
    /// Key 13, which P-006 caps at [`Caps::CHANNEL_CEILING`].
    pub channels: u8,
    /// Key 14.
    pub clients: u8,
    /// Key 15.
    pub event_queue: u16,
    /// Key 16.
    pub inflight: u8,
    /// Key 17, entries.
    pub cmd_dedup: u16,
}

impl Caps {
    /// P-006's ceiling, and it is `MAX_CHANNELS` — the config array a channel
    /// list is stored in. Reported downward from it or refused: a controller
    /// claiming 64 advertises room it has nowhere to put, and the client finds
    /// out at write time with a configuration already built around the number.
    pub const CHANNEL_CEILING: u8 = 32;

    /// What this controller enforces, which is what P-005 says it must report.
    pub const THIS_CONTROLLER: Self = Self {
        sessions: 8,
        channels: 32,
        clients: 8,
        event_queue: 16,
        inflight: 4,
        cmd_dedup: 32,
    };
}

const_assert!(
    MAX_SESSIONS == 8
        && MAX_CHANNELS == 32
        && MAX_CLIENTS == 8
        && MAX_EVENT_QUEUE == 16
        && MAX_INFLIGHT == 4
        && MAX_CMD_DEDUP == 32,
    "P-005 says the controller reports the numbers it enforces. These are those numbers, written here as the u8 and u16 the wire carries because there is no const cast that is not an `as`. Move one in limits.rs and this line is where the two parted company, rather than a site where a client is told a cap nobody keeps"
);
const_assert!(
    Caps::THIS_CONTROLLER.channels <= Caps::CHANNEL_CEILING,
    "P-006 says max_channels is only ever reported downward from 32, and a controller that reports more is advertising config slots it does not have"
);

/// What `Discover 0x80` says about a controller — the only message on this wire
/// with no MAC at all (P-054).
///
/// Every field is a claim a hostile comms processor can make, which is why P-055
/// forbids rendering one as a statement about the site and why there is no
/// derived `Debug` below.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Discovery<'a> {
    /// Keys 1 and 2.
    pub version: Version,
    /// Key 3: the 16 bytes of P-038, not the 32 characters they print as.
    pub device_id: [u8; BSTR16],
    /// Key 4.
    pub model: &'a str,
    /// Key 5.
    pub provisioned: bool,
    /// Key 6.
    pub pairing_open: bool,
    /// Key 7: this connection's live challenge (P-060).
    pub challenge: [u8; BSTR16],
    /// Key 8: P-087's provisioning epoch, so a client whose key no longer
    /// derives is told why.
    pub epoch: Epoch,
}

impl<'a> Discovery<'a> {
    /// Write the whole `Discover 0x80` envelope into `dst`, and hand back its
    /// length. The header must name `DiscoverResponse`.
    pub fn write(&self, header: Header, dst: &mut [u8]) -> Result<usize, HandshakeError> {
        expected(header, MessageType::DiscoverResponse)?;
        let mut cbor = header
            .write(DiscoverKey::COUNT, dst)
            .map_err(HandshakeError::Envelope)?;
        cbor.key(DiscoverKey::ProtocolMajor.number())?;
        cbor.u64(u64::from(self.version.major))?;
        cbor.key(DiscoverKey::ProtocolMinor.number())?;
        cbor.u64(u64::from(self.version.minor))?;
        cbor.key(DiscoverKey::DeviceId.number())?;
        cbor.bytes(&self.device_id)?;
        cbor.key(DiscoverKey::Model.number())?;
        cbor.text(self.model)?;
        cbor.key(DiscoverKey::Provisioned.number())?;
        cbor.bool(self.provisioned)?;
        cbor.key(DiscoverKey::PairingOpen.number())?;
        cbor.bool(self.pairing_open)?;
        cbor.key(DiscoverKey::Challenge.number())?;
        cbor.bytes(&self.challenge)?;
        cbor.key(DiscoverKey::Epoch.number())?;
        cbor.u64(u64::from(self.epoch.get()))?;
        Ok(cbor.finish()?)
    }

    /// Read one out of an envelope that may be anything at all.
    ///
    /// A key this version has never heard of is skipped (P-013); a key that
    /// arrives twice is refused before either copy is used (P-015).
    pub fn decode(envelope: Envelope<'a>) -> Result<Self, HandshakeError> {
        expected(envelope.header(), MessageType::DiscoverResponse)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut slots = DiscoverSlots::empty();
        for _ in 0..pairs {
            let number = body.key()?;
            match DiscoverKey::of(number) {
                Some(key) => slots.fill(key, &mut body)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        slots.complete()
    }
}

/// Written out rather than derived, and it says nothing a hostile peer chose.
///
/// `model` is up to sixty-four bytes somebody else picked and the two `bstr16`
/// are opaque; one `?discovery` in a span and those bytes are in a log a person
/// reads as if the site had said them, which is P-055 lost to a formatter.
impl fmt::Debug for Discovery<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Discovery {{ unauthenticated, model: {} bytes, device_id: {} bytes, challenge: {} bytes }}",
            self.model.len(),
            self.device_id.len(),
            self.challenge.len()
        )
    }
}

/// The inner body of `Hello 0x01`: five keys, encoded once and then covered by
/// the proof exactly as encoded (P-048, P-070).
///
/// On the receiving side it is reachable only past [`HelloClaim::verify`], which
/// is what stops version negotiation running on values a relay chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloInner<'a> {
    /// Keys 1 and 2, which P-070 exists to keep out of a relay's hands.
    pub version: Version,
    /// Key 3: which enrolment is proving itself, and so which `client_key`.
    pub client_id: ClientId,
    /// Key 4.
    pub client_version: &'a str,
    /// Key 5: fresh per handshake, from the client's CSPRNG (P-071).
    pub client_nonce: [u8; BSTR16],
}

impl<'a> HelloInner<'a> {
    /// Encode into `dst` and prove those bytes under `key`.
    ///
    /// The two come back together because P-048 is about bytes: a caller that
    /// could encode once and prove a different encoding would authenticate a
    /// body it never sent.
    pub fn prove<'d>(
        &self,
        key: &ClientKey,
        challenge: &[u8; BSTR16],
        dst: &'d mut [u8],
    ) -> Result<HelloRequest<'d>, HandshakeError> {
        let len = self.encode(dst)?;
        let payload = dst.get(..len).ok_or(CborError::DestinationTooSmall)?;
        let proof = key.hello_proof(&HelloProof {
            challenge,
            client_nonce: &self.client_nonce,
            client_id: self.client_id.get(),
            payload,
        });
        Ok(HelloRequest { payload, proof })
    }

    /// Private, so the only way to put an encoding on the wire is to prove that
    /// same encoding.
    fn encode(&self, dst: &mut [u8]) -> Result<usize, HandshakeError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(InnerKey::COUNT)?;
        cbor.key(InnerKey::ProtocolMajor.number())?;
        cbor.u64(u64::from(self.version.major))?;
        cbor.key(InnerKey::ProtocolMinor.number())?;
        cbor.u64(u64::from(self.version.minor))?;
        cbor.key(InnerKey::ClientId.number())?;
        cbor.u64(u64::from(self.client_id.get()))?;
        cbor.key(InnerKey::ClientVersion.number())?;
        cbor.text(self.client_version)?;
        cbor.key(InnerKey::ClientNonce.number())?;
        cbor.bytes(&self.client_nonce)?;
        Ok(cbor.finish()?)
    }

    fn decode(payload: &'a [u8]) -> Result<Self, HandshakeError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut slots = InnerSlots::empty();
        for _ in 0..pairs {
            let number = body.key()?;
            match InnerKey::of(number) {
                Some(key) => slots.fill(key, &mut body)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        slots.complete()
    }
}

/// A `Hello 0x01` body ready to send: the encoded inner body and the proof over
/// exactly those bytes.
///
/// Produced only by [`HelloInner::prove`], so the payload and the tag cannot
/// come from two different encodings.
pub struct HelloRequest<'a> {
    payload: &'a [u8],
    proof: Tag,
}

impl<'a> HelloRequest<'a> {
    /// The bytes the proof covers, which are the bytes that go on the wire.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The tag, for putting on the wire. Checking one is [`Tag::verify`].
    #[must_use]
    pub const fn proof(&self) -> &Tag {
        &self.proof
    }

    /// Write the whole `Hello 0x01` envelope into `dst`. The header must name
    /// `Hello`.
    pub fn write(&self, header: Header, dst: &mut [u8]) -> Result<usize, HandshakeError> {
        expected(header, MessageType::Hello)?;
        let mut cbor = header
            .write(HelloKey::COUNT, dst)
            .map_err(HandshakeError::Envelope)?;
        cbor.key(HelloKey::Payload.number())?;
        cbor.bytes(self.payload)?;
        cbor.key(HelloKey::Proof.number())?;
        cbor.bytes(self.proof.as_bytes())?;
        Ok(cbor.finish()?)
    }
}

/// The payload length rather than the payload, for the reason `wrapper.rs` gives
/// about a derived `Debug` being an accessor spelled `{:?}`.
impl fmt::Debug for HelloRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HelloRequest {{ payload: {} bytes }}",
            self.payload.len()
        )
    }
}

/// A `Hello 0x01` as it arrived, with a proof nobody has checked.
///
/// P-057's ordering written as a type. `client_id` and `client_nonce` are
/// reachable because no key can be found without them; the fields P-070 protects
/// are not, and [`HelloClaim::verify`] is the only thing that hands them over:
///
/// ```
/// use km43::{ClientId, HelloClaim};
/// fn who(claim: &HelloClaim<'_>) -> ClientId { claim.client_id() }
/// ```
/// ```compile_fail
/// use km43::{HelloClaim, Version};
/// fn what(claim: &HelloClaim<'_>) -> Version { claim.version() }
/// ```
pub struct HelloClaim<'a> {
    payload: &'a [u8],
    proof: &'a [u8],
    inner: HelloInner<'a>,
}

impl<'a> HelloClaim<'a> {
    /// Read one out of an envelope naming `Hello`.
    ///
    /// A key beside `payload` and `proof` is refused rather than skipped: it
    /// would be meaningful and structurally outside the proof, which is P-050's
    /// argument one message over.
    pub fn decode(envelope: Envelope<'a>) -> Result<Self, HandshakeError> {
        expected(envelope.header(), MessageType::Hello)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut payload = Slot::empty();
        let mut proof = Slot::empty();
        for _ in 0..pairs {
            let number = body.key()?;
            let key = HelloKey::of(number).ok_or(HandshakeError::UnknownKey(number))?;
            let value = body.bytes()?;
            match key {
                HelloKey::Payload => payload.fill(key, value)?,
                HelloKey::Proof => proof.fill(key, value)?,
            }
        }
        body.finish()?;
        let payload = payload.taken(HelloKey::Payload)?;
        let proof = proof.taken(HelloKey::Proof)?;
        Ok(Self {
            payload,
            proof,
            inner: HelloInner::decode(payload)?,
        })
    }

    /// Which enrolment claims to be proving itself. Unauthenticated: it selects
    /// a key and licenses nothing else (P-057).
    #[must_use]
    pub const fn client_id(&self) -> ClientId {
        self.inner.client_id
    }

    /// The client's half of the session salt, which the session key cannot be
    /// derived without (P-071). Unauthenticated for the same one step.
    #[must_use]
    pub const fn client_nonce(&self) -> [u8; BSTR16] {
        self.inner.client_nonce
    }

    /// Check the proof over the bytes that arrived (P-048), negotiate the
    /// version (P-073), and only then give up the body.
    pub fn verify(
        self,
        key: &ClientKey,
        challenge: &[u8; BSTR16],
        ours: Version,
    ) -> Result<Accepted<'a>, HandshakeError> {
        let expect = key.hello_proof(&HelloProof {
            challenge,
            client_nonce: &self.inner.client_nonce,
            client_id: self.inner.client_id.get(),
            payload: self.payload,
        });
        expect.verify(self.proof)?;
        Ok(Accepted {
            agreed: ours.agreed(self.inner.version)?,
            inner: self.inner,
        })
    }
}

/// Names and lengths, never the body. A derived `Debug` here would print
/// `client_version` — one of the three fields P-070 spends a MAC on — out of a
/// message nobody has authenticated yet.
impl fmt::Debug for HelloClaim<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HelloClaim {{ unverified, client_id: {}, payload: {} bytes }}",
            self.inner.client_id.get(),
            self.payload.len()
        )
    }
}

/// A `Hello 0x01` whose proof checked out, and the version the two ends settled
/// on (P-073).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted<'a> {
    /// The inner body, now that the proof over its bytes has been checked.
    pub inner: HelloInner<'a>,
    /// The shared major and the lower of the two minors.
    pub agreed: Version,
}

/// The body of `Hello 0x81`, reachable only past the wrapper MAC over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloReport<'a> {
    /// Keys 1 and 2.
    pub version: Version,
    /// Key 3, which the envelope carries too and must match.
    pub session: SessionId,
    /// Key 4.
    pub fw_controller: &'a str,
    /// Key 5: what the comms processor says about itself, diagnostic only.
    pub fw_comms: &'a str,
    /// Key 6, the capability bitfield.
    pub capabilities: u32,
    /// Key 7.
    pub log_oldest_seq: LogSeq,
    /// Key 8.
    pub log_newest_seq: LogSeq,
    /// Key 9, in the state store's space rather than the log's (P-074).
    pub state_seq: StateSeq,
    /// Key 10.
    pub time_known: bool,
    /// Key 11, this client's last accepted counter.
    pub counter: u64,
    /// Keys 12 to 17 (P-005).
    pub caps: Caps,
    /// The topology plane's revision, digest and caps, keys 18 to 29.
    pub topology: Topology,
}

impl<'a> HelloReport<'a> {
    /// Encode the twenty-nine keys into `dst`; the caller wraps and MACs them.
    ///
    /// A `channels` above [`Caps::CHANNEL_CEILING`] is refused here as well as on
    /// decode, because P-006 binds the controller too and a cap nobody keeps is
    /// worse than no cap reported at all.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, HandshakeError> {
        self.caps.within_ceiling()?;
        let mut cbor = CborWriter::new(dst);
        cbor.map(ReportKey::COUNT)?;
        cbor.key(ReportKey::ProtocolMajor.number())?;
        cbor.u64(u64::from(self.version.major))?;
        cbor.key(ReportKey::ProtocolMinor.number())?;
        cbor.u64(u64::from(self.version.minor))?;
        cbor.key(ReportKey::SessionId.number())?;
        cbor.u64(u64::from(u16::from(self.session)))?;
        cbor.key(ReportKey::FwController.number())?;
        cbor.text(self.fw_controller)?;
        cbor.key(ReportKey::FwComms.number())?;
        cbor.text(self.fw_comms)?;
        cbor.key(ReportKey::Capabilities.number())?;
        cbor.u64(u64::from(self.capabilities))?;
        cbor.key(ReportKey::LogOldestSeq.number())?;
        cbor.u64(self.log_oldest_seq.0)?;
        cbor.key(ReportKey::LogNewestSeq.number())?;
        cbor.u64(self.log_newest_seq.0)?;
        cbor.key(ReportKey::StateSeq.number())?;
        cbor.u64(self.state_seq.0)?;
        cbor.key(ReportKey::TimeKnown.number())?;
        cbor.bool(self.time_known)?;
        cbor.key(ReportKey::Counter.number())?;
        cbor.u64(self.counter)?;
        self.caps.encode(&mut cbor)?;
        self.topology.encode(&mut cbor)?;
        Ok(cbor.finish()?)
    }

    /// Private: the only route to one is [`Session::open`], which cannot be
    /// reached without the MAC over these bytes having checked out (P-051).
    fn decode(payload: &'a [u8], envelope: SessionId) -> Result<Self, HandshakeError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut slots = ReportSlots::empty();
        for _ in 0..pairs {
            let number = body.key()?;
            match ReportKey::of(number) {
                Some(key) => slots.fill(key, &mut body)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        let report = slots.complete()?;
        if report.session != envelope {
            return Err(HandshakeError::SessionMismatch {
                envelope,
                body: report.session,
            });
        }
        report.caps.within_ceiling()?;
        Ok(report)
    }
}

impl Caps {
    /// P-006, in the one place both directions go through.
    fn within_ceiling(self) -> Result<(), HandshakeError> {
        if self.channels > Self::CHANNEL_CEILING {
            return Err(HandshakeError::ChannelsAboveCeiling(self.channels));
        }
        Ok(())
    }

    /// Keys 12 to 17, split out because twenty-nine keys in one function is the
    /// `too_many_lines` the lint is describing.
    fn encode(self, cbor: &mut CborWriter<'_>) -> Result<(), HandshakeError> {
        cbor.key(ReportKey::MaxSessions.number())?;
        cbor.u64(u64::from(self.sessions))?;
        cbor.key(ReportKey::MaxChannels.number())?;
        cbor.u64(u64::from(self.channels))?;
        cbor.key(ReportKey::MaxClients.number())?;
        cbor.u64(u64::from(self.clients))?;
        cbor.key(ReportKey::MaxEventQueue.number())?;
        cbor.u64(u64::from(self.event_queue))?;
        cbor.key(ReportKey::MaxInflight.number())?;
        cbor.u64(u64::from(self.inflight))?;
        cbor.key(ReportKey::MaxCmdDedup.number())?;
        cbor.u64(u64::from(self.cmd_dedup))?;
        Ok(())
    }
}

/// A session a client has actually opened: the key P-072 derived, the version
/// P-073 agreed, and what the controller reported.
///
/// No `Debug`, because it holds a [`SessionKey`] and `mac.rs` refuses one on
/// every key type for the reason a bench log makes obvious.
pub struct Session<'a> {
    key: SessionKey,
    version: Version,
    report: HelloReport<'a>,
}

impl<'a> Session<'a> {
    /// P-072, in the one order that works.
    ///
    /// No key comes in: `session_id` is read off the **envelope**, the key is
    /// derived from it, and only then is the body MAC checked.
    pub fn open(
        envelope: Envelope<'a>,
        enrolment: &Enrolment,
        handshake: &Handshake,
        ours: Version,
    ) -> Result<Self, HandshakeError> {
        let header = envelope.header();
        expected(header, MessageType::HelloResponse)?;
        // Handle 0 means *no session* (P-021), so a response arriving at one is
        // not a session to open. Accepted, it derives and MACs under handle 0
        // and hands back a `Session` whose id means nothing was assigned —
        // every later frame keyed at 0, with nothing downstream able to tell,
        // because `Session` does not surrender the id. P-021 names the comms
        // processor stamping 0 as the bug this refuses.
        if let SessionId::None = header.session {
            return Err(HandshakeError::NoHandle);
        }
        // This reads like a bug and is not. `session_id` has not been
        // authenticated at this line — nothing has — and it is used anyway,
        // because the key that would authenticate it is derived from it. What
        // makes it safe is that `session_id` is inside the `rsp` preimage: a
        // comms processor that rewrote it sends us to a different key, and the
        // MAC on the next line fails. There is no ordering in which the check
        // comes first, which is why this function takes no key from its caller.
        let key = enrolment.session_key(handshake, header.session);
        let verified = Wrapper::decode(envelope)?.verify(&key)?;
        let report = HelloReport::decode(verified.payload(), header.session)?;
        Ok(Self {
            key,
            version: ours.agreed(report.version)?,
            report,
        })
    }

    /// The key this session's traffic is authenticated under, in both
    /// directions.
    #[must_use]
    pub const fn key(&self) -> &SessionKey {
        &self.key
    }

    /// The shared major and the lower of the two minors (P-073).
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// What the controller reported, now that the MAC over it has been checked.
    #[must_use]
    pub const fn report(&self) -> &HelloReport<'a> {
        &self.report
    }
}

/// One key's value, and the two rules every body here applies to it.
///
/// A key that arrives twice is refused before either copy is used (P-015) — RFC
/// 8949 §5.6 leaves the resolution to the decoder, and two ends picking
/// differently read different bytes out of one frame. A required key that never
/// arrived is named rather than defaulted, because a default here is a
/// measurement nobody took.
struct Slot<T>(Option<T>);

impl<T> Slot<T> {
    const fn empty() -> Self {
        Self(None)
    }

    fn fill(&mut self, key: impl Into<BodyKey>, value: T) -> Result<(), HandshakeError> {
        if self.0.is_some() {
            return Err(HandshakeError::Duplicate(key.into()));
        }
        self.0 = Some(value);
        Ok(())
    }

    fn taken(self, key: impl Into<BodyKey>) -> Result<T, HandshakeError> {
        self.0.ok_or_else(|| HandshakeError::Missing(key.into()))
    }
}

/// A `bstr16` that has to be exactly sixteen. Free rather than a method: it
/// takes a key and some bytes, and belongs to neither.
fn sixteen(key: impl Into<BodyKey>, raw: &[u8]) -> Result<[u8; BSTR16], HandshakeError> {
    <[u8; BSTR16]>::try_from(raw).map_err(|_| HandshakeError::WrongWidth {
        key: key.into(),
        len: raw.len(),
    })
}

/// The same for a digest, which is eight and not sixteen. A hash truncated to a
/// different width is a hash of something else, and a decoder that accepted any
/// length would compare eight bytes of one against eight of another.
fn eight(key: impl Into<BodyKey>, raw: &[u8]) -> Result<[u8; 8], HandshakeError> {
    <[u8; 8]>::try_from(raw).map_err(|_| HandshakeError::WrongWidth {
        key: key.into(),
        len: raw.len(),
    })
}

/// Refuse an envelope whose `type` is not the message this decoder reads.
///
/// Without it a `Readings 0x8E` body gets read as a `Hello 0x81` — every key
/// it happens to share taken at face value, and the rest reported missing.
fn expected(header: Header, kind: MessageType) -> Result<(), HandshakeError> {
    if header.kind == kind {
        Ok(())
    } else {
        Err(HandshakeError::WrongMessage {
            expected: kind,
            found: header.kind,
        })
    }
}

struct DiscoverSlots<'a> {
    major: Slot<u8>,
    minor: Slot<u8>,
    device_id: Slot<[u8; BSTR16]>,
    model: Slot<&'a str>,
    provisioned: Slot<bool>,
    pairing_open: Slot<bool>,
    challenge: Slot<[u8; BSTR16]>,
    epoch: Slot<Epoch>,
}

impl<'a> DiscoverSlots<'a> {
    const fn empty() -> Self {
        Self {
            major: Slot::empty(),
            minor: Slot::empty(),
            device_id: Slot::empty(),
            model: Slot::empty(),
            provisioned: Slot::empty(),
            pairing_open: Slot::empty(),
            challenge: Slot::empty(),
            epoch: Slot::empty(),
        }
    }

    fn fill(&mut self, key: DiscoverKey, body: &mut CborReader<'a>) -> Result<(), HandshakeError> {
        match key {
            DiscoverKey::ProtocolMajor => self.major.fill(key, body.u8()?),
            DiscoverKey::ProtocolMinor => self.minor.fill(key, body.u8()?),
            DiscoverKey::DeviceId => self.device_id.fill(key, sixteen(key, body.bytes()?)?),
            DiscoverKey::Model => self.model.fill(key, body.text()?),
            DiscoverKey::Provisioned => self.provisioned.fill(key, body.bool()?),
            DiscoverKey::PairingOpen => self.pairing_open.fill(key, body.bool()?),
            DiscoverKey::Challenge => self.challenge.fill(key, sixteen(key, body.bytes()?)?),
            DiscoverKey::Epoch => {
                let raw = body.u32()?;
                let epoch = Epoch::new(raw).ok_or(HandshakeError::ZeroEpoch)?;
                self.epoch.fill(key, epoch)
            }
        }
    }

    fn complete(self) -> Result<Discovery<'a>, HandshakeError> {
        Ok(Discovery {
            version: Version {
                major: self.major.taken(DiscoverKey::ProtocolMajor)?,
                minor: self.minor.taken(DiscoverKey::ProtocolMinor)?,
            },
            device_id: self.device_id.taken(DiscoverKey::DeviceId)?,
            model: self.model.taken(DiscoverKey::Model)?,
            provisioned: self.provisioned.taken(DiscoverKey::Provisioned)?,
            pairing_open: self.pairing_open.taken(DiscoverKey::PairingOpen)?,
            challenge: self.challenge.taken(DiscoverKey::Challenge)?,
            epoch: self.epoch.taken(DiscoverKey::Epoch)?,
        })
    }
}

struct InnerSlots<'a> {
    major: Slot<u8>,
    minor: Slot<u8>,
    client_id: Slot<ClientId>,
    client_version: Slot<&'a str>,
    client_nonce: Slot<[u8; BSTR16]>,
}

impl<'a> InnerSlots<'a> {
    const fn empty() -> Self {
        Self {
            major: Slot::empty(),
            minor: Slot::empty(),
            client_id: Slot::empty(),
            client_version: Slot::empty(),
            client_nonce: Slot::empty(),
        }
    }

    fn fill(&mut self, key: InnerKey, body: &mut CborReader<'a>) -> Result<(), HandshakeError> {
        match key {
            InnerKey::ProtocolMajor => self.major.fill(key, body.u8()?),
            InnerKey::ProtocolMinor => self.minor.fill(key, body.u8()?),
            InnerKey::ClientId => {
                let raw = body.u32()?;
                let id = ClientId::new(raw).ok_or(HandshakeError::NoSuchSlot)?;
                self.client_id.fill(key, id)
            }
            InnerKey::ClientVersion => self.client_version.fill(key, body.text()?),
            InnerKey::ClientNonce => self.client_nonce.fill(key, sixteen(key, body.bytes()?)?),
        }
    }

    fn complete(self) -> Result<HelloInner<'a>, HandshakeError> {
        Ok(HelloInner {
            version: Version {
                major: self.major.taken(InnerKey::ProtocolMajor)?,
                minor: self.minor.taken(InnerKey::ProtocolMinor)?,
            },
            client_id: self.client_id.taken(InnerKey::ClientId)?,
            client_version: self.client_version.taken(InnerKey::ClientVersion)?,
            client_nonce: self.client_nonce.taken(InnerKey::ClientNonce)?,
        })
    }
}

struct ReportSlots<'a> {
    major: Slot<u8>,
    minor: Slot<u8>,
    session: Slot<SessionId>,
    fw_controller: Slot<&'a str>,
    fw_comms: Slot<&'a str>,
    capabilities: Slot<u32>,
    log_oldest_seq: Slot<LogSeq>,
    log_newest_seq: Slot<LogSeq>,
    state_seq: Slot<StateSeq>,
    time_known: Slot<bool>,
    counter: Slot<u64>,
    caps: CapSlots,
    topo: TopoSlots,
}

/// Keys 12 to 17 on their own, so neither `fill` nor `complete` becomes the
/// hundred-line function the lint is describing.
struct CapSlots {
    sessions: Slot<u8>,
    channels: Slot<u8>,
    clients: Slot<u8>,
    event_queue: Slot<u16>,
    inflight: Slot<u8>,
    cmd_dedup: Slot<u16>,
}

struct TopoSlots {
    rev: Slot<u32>,
    digest: Slot<[u8; 8]>,
    buses: Slot<u8>,
    devices: Slot<u16>,
    components: Slot<u16>,
    signals: Slot<u16>,
    series_elements: Slot<u16>,
    params: Slot<u16>,
    concerns: Slot<u16>,
    selectors: Slot<u8>,
    history_signals: Slot<u16>,
    topology_depth: Slot<u8>,
}

impl TopoSlots {
    const fn empty() -> Self {
        Self {
            rev: Slot::empty(),
            digest: Slot::empty(),
            buses: Slot::empty(),
            devices: Slot::empty(),
            components: Slot::empty(),
            signals: Slot::empty(),
            series_elements: Slot::empty(),
            params: Slot::empty(),
            concerns: Slot::empty(),
            selectors: Slot::empty(),
            history_signals: Slot::empty(),
            topology_depth: Slot::empty(),
        }
    }

    fn complete(self) -> Result<Topology, HandshakeError> {
        Ok(Topology {
            rev: self.rev.taken(ReportKey::Rev)?,
            digest: self.digest.taken(ReportKey::TopoDigest)?,
            buses: self.buses.taken(ReportKey::MaxBuses)?,
            devices: self.devices.taken(ReportKey::MaxDevices)?,
            components: self.components.taken(ReportKey::MaxComponents)?,
            signals: self.signals.taken(ReportKey::MaxSignals)?,
            series_elements: self.series_elements.taken(ReportKey::MaxSeriesElements)?,
            params: self.params.taken(ReportKey::MaxParams)?,
            concerns: self.concerns.taken(ReportKey::MaxConcerns)?,
            selectors: self.selectors.taken(ReportKey::MaxSelectors)?,
            history_signals: self.history_signals.taken(ReportKey::MaxHistorySignals)?,
            topology_depth: self.topology_depth.taken(ReportKey::MaxTopologyDepth)?,
        })
    }
}

impl CapSlots {
    const fn empty() -> Self {
        Self {
            sessions: Slot::empty(),
            channels: Slot::empty(),
            clients: Slot::empty(),
            event_queue: Slot::empty(),
            inflight: Slot::empty(),
            cmd_dedup: Slot::empty(),
        }
    }

    fn complete(self) -> Result<Caps, HandshakeError> {
        Ok(Caps {
            sessions: self.sessions.taken(ReportKey::MaxSessions)?,
            channels: self.channels.taken(ReportKey::MaxChannels)?,
            clients: self.clients.taken(ReportKey::MaxClients)?,
            event_queue: self.event_queue.taken(ReportKey::MaxEventQueue)?,
            inflight: self.inflight.taken(ReportKey::MaxInflight)?,
            cmd_dedup: self.cmd_dedup.taken(ReportKey::MaxCmdDedup)?,
        })
    }
}

impl<'a> ReportSlots<'a> {
    const fn empty() -> Self {
        Self {
            major: Slot::empty(),
            minor: Slot::empty(),
            session: Slot::empty(),
            fw_controller: Slot::empty(),
            fw_comms: Slot::empty(),
            capabilities: Slot::empty(),
            log_oldest_seq: Slot::empty(),
            log_newest_seq: Slot::empty(),
            state_seq: Slot::empty(),
            time_known: Slot::empty(),
            counter: Slot::empty(),
            caps: CapSlots::empty(),
            topo: TopoSlots::empty(),
        }
    }

    fn fill(&mut self, key: ReportKey, body: &mut CborReader<'a>) -> Result<(), HandshakeError> {
        match key {
            ReportKey::ProtocolMajor => self.major.fill(key, body.u8()?),
            ReportKey::ProtocolMinor => self.minor.fill(key, body.u8()?),
            ReportKey::SessionId => self.session.fill(key, SessionId::from(body.u16()?)),
            ReportKey::FwController => self.fw_controller.fill(key, body.text()?),
            ReportKey::FwComms => self.fw_comms.fill(key, body.text()?),
            ReportKey::Capabilities => self.capabilities.fill(key, body.u32()?),
            ReportKey::LogOldestSeq => self.log_oldest_seq.fill(key, LogSeq(body.u64()?)),
            ReportKey::LogNewestSeq => self.log_newest_seq.fill(key, LogSeq(body.u64()?)),
            ReportKey::StateSeq => self.state_seq.fill(key, StateSeq(body.u64()?)),
            ReportKey::TimeKnown => self.time_known.fill(key, body.bool()?),
            ReportKey::Counter => self.counter.fill(key, body.u64()?),
            ReportKey::MaxSessions => self.caps.sessions.fill(key, body.u8()?),
            ReportKey::MaxChannels => self.caps.channels.fill(key, body.u8()?),
            ReportKey::MaxClients => self.caps.clients.fill(key, body.u8()?),
            ReportKey::MaxEventQueue => self.caps.event_queue.fill(key, body.u16()?),
            ReportKey::MaxInflight => self.caps.inflight.fill(key, body.u8()?),
            ReportKey::MaxCmdDedup => self.caps.cmd_dedup.fill(key, body.u16()?),
            ReportKey::Rev => self.topo.rev.fill(key, body.u32()?),
            ReportKey::TopoDigest => self.topo.digest.fill(key, eight(key, body.bytes()?)?),
            ReportKey::MaxBuses => self.topo.buses.fill(key, body.u8()?),
            ReportKey::MaxDevices => self.topo.devices.fill(key, body.u16()?),
            ReportKey::MaxComponents => self.topo.components.fill(key, body.u16()?),
            ReportKey::MaxSignals => self.topo.signals.fill(key, body.u16()?),
            ReportKey::MaxSeriesElements => self.topo.series_elements.fill(key, body.u16()?),
            ReportKey::MaxParams => self.topo.params.fill(key, body.u16()?),
            ReportKey::MaxConcerns => self.topo.concerns.fill(key, body.u16()?),
            ReportKey::MaxSelectors => self.topo.selectors.fill(key, body.u8()?),
            ReportKey::MaxHistorySignals => self.topo.history_signals.fill(key, body.u16()?),
            ReportKey::MaxTopologyDepth => self.topo.topology_depth.fill(key, body.u8()?),
        }
    }

    fn complete(self) -> Result<HelloReport<'a>, HandshakeError> {
        Ok(HelloReport {
            version: Version {
                major: self.major.taken(ReportKey::ProtocolMajor)?,
                minor: self.minor.taken(ReportKey::ProtocolMinor)?,
            },
            session: self.session.taken(ReportKey::SessionId)?,
            fw_controller: self.fw_controller.taken(ReportKey::FwController)?,
            fw_comms: self.fw_comms.taken(ReportKey::FwComms)?,
            capabilities: self.capabilities.taken(ReportKey::Capabilities)?,
            log_oldest_seq: self.log_oldest_seq.taken(ReportKey::LogOldestSeq)?,
            log_newest_seq: self.log_newest_seq.taken(ReportKey::LogNewestSeq)?,
            state_seq: self.state_seq.taken(ReportKey::StateSeq)?,
            time_known: self.time_known.taken(ReportKey::TimeKnown)?,
            counter: self.counter.taken(ReportKey::Counter)?,
            caps: self.caps.complete()?,
            topology: self.topo.complete()?,
        })
    }
}

/// Why a handshake body was refused. The three that are not error 1 are the
/// point: a version this implementation does not speak, a proof that did not
/// check out, and whatever the wrapper said — each sends a client somewhere
/// different, and a client told the wrong one retries until it gives up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// A key the body requires that never arrived. Never defaulted: an absent
    /// `challenge` is not sixteen zero bytes.
    Missing(BodyKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(BodyKey),
    /// A key beside `payload` and `proof` in a `Hello 0x01`, which would be
    /// meaningful and outside the proof.
    UnknownKey(i64),
    /// A `bstr16` that was not sixteen bytes, carrying what arrived so a bench
    /// log can say how far off the peer was.
    WrongWidth {
        /// Which field.
        key: BodyKey,
        /// How many bytes actually arrived.
        len: usize,
    },
    /// An envelope whose `type` is not the message this decoder reads.
    WrongMessage {
        /// What the decoder was for.
        expected: MessageType,
        /// What the envelope named.
        found: MessageType,
    },
    /// A `Hello 0x81` whose key 3 is not the `session_id` its key was derived
    /// from (P-072).
    SessionMismatch {
        /// What the envelope said, and so what the key was derived under.
        envelope: SessionId,
        /// What the authenticated body said.
        body: SessionId,
    },
    /// P-073: a major version this implementation does not speak. Error 3.
    MajorMismatch {
        /// This implementation's major.
        ours: u8,
        /// The peer's.
        theirs: u8,
    },
    /// P-006: `max_channels` above 32, which is a cap that cannot fit inside the
    /// frame that carries it. Error 1.
    ChannelsAboveCeiling(u8),
    /// A `client_id` of zero, which names no slot (P-086).
    NoSuchSlot,
    /// An `epoch` of zero, which is FRAM nobody wrote rather than an epoch
    /// (P-085).
    ZeroEpoch,
    /// The response arrived at handle 0, which means *no session* (P-021) and
    /// cannot be one.
    NoHandle,
    /// The `Hello` proof did not check out, or was not sixteen bytes. Error 10.
    Proof(MacError),
    /// The wrapper around a `Hello 0x81`.
    Wrapper(WrapperError),
    /// The envelope this body was written into.
    Envelope(EnvelopeError),
    /// The CBOR underneath the body.
    Cbor(CborError),
}

impl HandshakeError {
    /// What to answer, and in which space.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::MajorMismatch { .. } => Refusal::Client(ErrorCode::ProtocolMajorMismatch),
            Self::Proof(_) => Refusal::Client(ErrorCode::BadMAC),
            Self::Wrapper(why) => why.refusal(),
            Self::Envelope(why) => why.refusal(),
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::UnknownKey(_)
            | Self::WrongWidth { .. }
            | Self::WrongMessage { .. }
            | Self::SessionMismatch { .. }
            | Self::ChannelsAboveCeiling(_)
            | Self::NoSuchSlot
            | Self::ZeroEpoch
            | Self::NoHandle
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl From<CborError> for HandshakeError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<MacError> for HandshakeError {
    fn from(why: MacError) -> Self {
        Self::Proof(why)
    }
}

impl From<WrapperError> for HandshakeError {
    fn from(why: WrapperError) -> Self {
        Self::Wrapper(why)
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "no {key} arrived"),
            Self::Duplicate(key) => write!(f, "{key} arrived twice"),
            Self::UnknownKey(number) => {
                write!(f, "Hello 0x01 key {number} is neither payload nor proof")
            }
            Self::WrongWidth { key, len } => write!(f, "{key} is {len} bytes, not {BSTR16}"),
            Self::WrongMessage { expected, found } => write!(
                f,
                "message type {:#04x} where {:#04x} belongs",
                *found as u8, *expected as u8
            ),
            Self::SessionMismatch { envelope, body } => write!(
                f,
                "session_id {} in the body and {} in the envelope",
                u16::from(*body),
                u16::from(*envelope)
            ),
            Self::MajorMismatch { ours, theirs } => {
                write!(f, "protocol major {theirs} against our {ours}")
            }
            Self::ChannelsAboveCeiling(channels) => write!(
                f,
                "max_channels {channels} above the ceiling of {}",
                Caps::CHANNEL_CEILING
            ),
            Self::NoSuchSlot => f.write_str("client_id 0 names no slot"),
            Self::ZeroEpoch => f.write_str("epoch 0 is FRAM nobody wrote"),
            Self::NoHandle => f.write_str("a session cannot be opened at handle 0"),
            Self::Proof(why) => write!(f, "{why}"),
            Self::Wrapper(why) => write!(f, "wrapper: {why}"),
            Self::Envelope(why) => write!(f, "envelope: {why}"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for HandshakeError {}

const_assert!(
    size_of::<HandshakeError>() <= size_of::<WrapperError>() + size_of::<usize>(),
    "one of these comes back from every handshake decode on a part with 144 KB of RAM. Most of it is the WrapperError already inside it and the rest ride in bit patterns that error was not using; the width is paid on the frames that pass as well as the ones that fail, so a variant that grows it past a word over what it contains is worth arguing about"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::ReqId;
    use crate::kdf::{DeviceId, DeviceSecret, PrintedSecret};
    use crate::mac::Wrapped;
    use crate::render::Rendering;

    /// Wider than any frame below, and narrow enough that a length bug shows as
    /// a refusal in the builder rather than as a passing test.
    const SCRATCH: usize = 512;

    /// Fixtures go in as the hexadecimal the documents publish. Retyping
    /// `0x8a, 0xee, …` by hand is how a digit moves house without anybody
    /// noticing, and this is a `const fn` so a fixture of the wrong width fails
    /// the build rather than a test.
    const fn hex<const N: usize>(text: &str) -> [u8; N] {
        let src = text.as_bytes();
        assert!(src.len() == N * 2, "hex fixture is not the width it claims");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            out[i] = (nibble(src[i * 2]) << 4) | nibble(src[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex fixture is not lowercase hexadecimal"),
        }
    }

    const PRINTED_SECRET: [u8; 32] =
        hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const DEVICE_ID: [u8; BSTR16] = hex("4f524947494e38392044454d4f203031");
    const CHALLENGE: [u8; BSTR16] = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    const CLIENT_NONCE: [u8; BSTR16] = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    const CLIENT_ID: u32 = 7;
    const SESSION: u16 = 3;
    const REQ_ID: u32 = 17;
    const CLIENT_VERSION: &str = "o89-cli 0.1.0";

    /// `hello_proof.inner_body_cbor` from `docs/protocol/vectors/v1.json`.
    const PUBLISHED_INNER: [u8; 40] =
        hex("a5010102000307046d6f38392d636c6920302e312e300550b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");

    /// `hello_proof.out16` from the same file.
    const PUBLISHED_PROOF: [u8; Tag::LEN] = hex("8418a3ffb064b88022622123ce6a4f01");

    /// The `inputs` block of the vector file, as the pair every key on this unit
    /// descends from.
    fn device() -> DeviceSecret {
        DeviceSecret::new(DeviceId::new(DEVICE_ID), PrintedSecret::new(PRINTED_SECRET))
    }

    fn slot() -> ClientId {
        ClientId::new(CLIENT_ID).expect("client_id 7 is a slot")
    }

    fn enrolment() -> Enrolment {
        device().enrolment(Epoch::FIRST, slot())
    }

    fn handshake() -> Handshake {
        Handshake {
            challenge: CHALLENGE,
            client_nonce: CLIENT_NONCE,
        }
    }

    /// The inner body the vectors were computed over, as fields rather than as
    /// bytes — so the encoder is what has to agree with the file.
    fn inner() -> HelloInner<'static> {
        HelloInner {
            version: Version::V1_0,
            client_id: slot(),
            client_version: CLIENT_VERSION,
            client_nonce: CLIENT_NONCE,
        }
    }

    fn header(kind: MessageType) -> Header {
        Header {
            kind,
            session: SessionId::from(SESSION),
            req_id: ReqId(REQ_ID),
        }
    }

    /// The published `hello_proof`, reached through the real derivation ladder
    /// and this module's own encoder.
    ///
    /// Handing `hello_proof` a key pins the preimage and leaves both the ladder
    /// and the encoder free to move. Coming through `DeviceSecret` means a
    /// dropped `epoch`, a swapped HKDF argument, a key written out of order and
    /// a text head one byte wide all arrive as the same red line — and the
    /// vector file is produced by a tool forbidden from importing this crate, so
    /// it is an outside opinion rather than a restatement.
    #[test]
    fn the_published_hello_proof_is_what_this_module_encodes_and_then_proves() {
        let mut scratch = [0u8; MAX_HELLO_INNER];
        let request = inner()
            .prove(&enrolment().client_key(), &CHALLENGE, &mut scratch)
            .expect("the vector's inner body encodes and proves");
        assert_eq!(
            request.payload(),
            &PUBLISHED_INNER[..],
            "this encoder and the published inner body have parted company"
        );
        request
            .proof()
            .verify(&PUBLISHED_PROOF)
            .expect("the published hello_proof is not what this module computes");
    }

    /// The other direction over the same bytes: the published inner body decodes
    /// to the fields the file names, so the encoder and the decoder are not
    /// simply wrong together.
    #[test]
    fn the_published_inner_body_decodes_to_the_fields_the_vector_names() {
        let decoded = HelloInner::decode(&PUBLISHED_INNER).expect("the published body decodes");
        assert_eq!(decoded, inner());
    }

    /// `Discover 0x80` at session 3, `req_id` 17, written out by hand so the tests
    /// below compare against bytes rather than against this crate's own encoder.
    const MODEL: &str = "origin89-v1";
    const DISCOVER_RESPONSE: [u8; 65] = hex(
        "8418800311a80101020003504f524947494e38392044454d4f203031046b6f726967696e38392d763105f506f4\
         0750a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0801",
    );

    fn discovery() -> Discovery<'static> {
        Discovery {
            version: Version::V1_0,
            device_id: DEVICE_ID,
            model: MODEL,
            provisioned: true,
            pairing_open: false,
            challenge: CHALLENGE,
            epoch: Epoch::FIRST,
        }
    }

    /// One frame's bytes, assembled by hand.
    ///
    /// Not through `CborWriter`: it refuses a duplicate key and a key that does
    /// not ascend, which is exactly what half of these fixtures have to send.
    #[derive(Clone, Copy)]
    struct Wire {
        bytes: [u8; SCRATCH],
        len: usize,
    }

    impl Wire {
        /// `[type, session_id, req_id, {`, every integer in the shortest form
        /// that holds it — which is why every fixture keeps `session_id`,
        /// `req_id` and the pair count under 24.
        fn envelope(head: Header, pairs: usize) -> Self {
            let session = u8::try_from(u16::from(head.session)).expect("a one-byte session");
            let req_id = u8::try_from(head.req_id.0).expect("a one-byte req_id");
            let pairs = u8::try_from(pairs).expect("a map of fewer than twenty-four pairs");
            assert!(session < 24 && req_id < 24 && pairs < 24, "one-byte CBOR");
            let mut wire = Self {
                bytes: [0; SCRATCH],
                len: 0,
            };
            wire.push(&[0x84]);
            let kind = head.kind as u8;
            if kind < 24 {
                wire.push(&[kind]);
            } else {
                wire.push(&[0x18, kind]);
            }
            wire.push(&[session, req_id, 0xa0 | pairs]);
            wire
        }

        fn push(&mut self, data: &[u8]) {
            for &byte in data {
                let slot = self
                    .bytes
                    .get_mut(self.len)
                    .expect("the fixture fits the scratch");
                *slot = byte;
                self.len = self.len.saturating_add(1);
            }
        }

        /// A key under 24 and the CBOR value written out, so a fixture can send
        /// a width or a type no encoder would choose.
        fn pair(mut self, key: u8, value: &[u8]) -> Self {
            assert!(key < 24, "the fixture keys are all inline");
            self.push(&[key]);
            self.push(value);
            self
        }

        fn appended(mut self, data: &[u8]) -> Self {
            self.push(data);
            self
        }

        /// One byte of the frame set to something else, for a fixture that
        /// stands in for a relay rewriting a field in flight.
        fn replaced(mut self, at: usize, byte: u8) -> Self {
            let slot = self.bytes.get_mut(at).expect("at is inside the frame");
            *slot = byte;
            self
        }

        fn flipped(mut self, at: usize, bit: u8) -> Self {
            let slot = self.bytes.get_mut(at).expect("at is inside the frame");
            *slot ^= 1 << bit;
            self
        }

        fn cut_to(mut self, len: usize) -> Self {
            assert!(len <= self.len, "a cut is a prefix");
            self.len = len;
            self
        }

        fn bytes(&self) -> &[u8] {
            self.bytes
                .get(..self.len)
                .expect("the length came from the builder")
        }

        /// A key carrying a byte string, in the head form its length calls for.
        fn bstr(mut self, key: u8, value: &[u8]) -> Self {
            assert!(key < 24, "the fixture keys are all inline");
            self.push(&[key]);
            let len = u8::try_from(value.len()).expect("a fixture string under 256 bytes");
            if len < 24 {
                self.push(&[0x40 | len]);
            } else {
                self.push(&[0x58, len]);
            }
            self.push(value);
            self
        }

        fn claimed(&self) -> Result<HelloClaim<'_>, HandshakeError> {
            HelloClaim::decode(Envelope::decode(self.bytes()).map_err(HandshakeError::Envelope)?)
        }

        fn discovered(&self) -> Result<Discovery<'_>, HandshakeError> {
            Discovery::decode(Envelope::decode(self.bytes()).map_err(HandshakeError::Envelope)?)
        }

        /// One byte appended after the body's top-level item, which is what a
        /// missing `finish()` fails to notice.
        fn with_a_trailing_byte(&self) -> Self {
            let mut next = Self {
                bytes: self.bytes,
                len: self.len,
            };
            if let Some(slot) = next.bytes.get_mut(next.len) {
                *slot = 0x01;
                next.len = next.len.saturating_add(1);
            }
            next
        }
    }

    /// Every body decoder calls `finish()`, and deleting any of the four leaves
    /// the whole suite green — nothing fed one a trailing byte.
    ///
    /// What it lets through is a body with something appended after its
    /// top-level map: on the two MAC'd paths the extra byte is inside the
    /// preimage so the tag still holds, and the two ends then disagree about
    /// where the message ended while both believe it authentic.
    #[test]
    fn a_byte_appended_after_a_body_is_refused_rather_than_ignored() {
        assert_eq!(
            discover_wire().with_a_trailing_byte().discovered().err(),
            Some(HandshakeError::Cbor(CborError::TrailingBytes)),
            "a Discover body ran past its map"
        );
        let key = enrolment().client_key();
        let mut scratch = [0u8; MAX_HELLO_INNER];
        let request = inner()
            .prove(&key, &CHALLENGE, &mut scratch)
            .expect("the fixture proves");
        let hello = hello_wire(request.payload(), request.proof().as_bytes());
        assert_eq!(
            hello.with_a_trailing_byte().claimed().err(),
            Some(HandshakeError::Cbor(CborError::TrailingBytes)),
            "a Hello body ran past its map"
        );
    }

    /// A `bstr16` value, head byte and all.
    fn bstr16(value: &[u8; BSTR16]) -> [u8; BSTR16 + 1] {
        let mut out = [0x50u8; BSTR16 + 1];
        for (slot, &byte) in out.iter_mut().skip(1).zip(value) {
            *slot = byte;
        }
        out
    }

    /// A whole `Discover 0x80` body, key by key, so a fixture can leave one out
    /// or send it twice.
    fn discover_wire() -> Wire {
        Wire::envelope(header(MessageType::DiscoverResponse), DiscoverKey::COUNT)
            .pair(1, &[0x01])
            .pair(2, &[0x00])
            .pair(3, &bstr16(&DEVICE_ID))
            .pair(
                4,
                &[
                    0x6b, b'o', b'r', b'i', b'g', b'i', b'n', b'8', b'9', b'-', b'v', b'1',
                ],
            )
            .pair(5, &[0xf5])
            .pair(6, &[0xf4])
            .pair(7, &bstr16(&CHALLENGE))
            .pair(8, &[0x01])
    }

    /// The shape of the one message nobody signs, in both directions and against
    /// fixed bytes. An encoder and a decoder that agree with each other and not
    /// with the document is the mistake this crate has already made once, so the
    /// vector is written by hand rather than by the writer.
    #[test]
    fn a_discover_response_round_trips_through_the_bytes_the_document_shows() {
        let mut buf = [0u8; SCRATCH];
        let len = discovery()
            .write(header(MessageType::DiscoverResponse), &mut buf)
            .expect("the answer is written");
        assert_eq!(
            buf.get(..len).expect("the writer's own length"),
            &DISCOVER_RESPONSE[..],
            "the encoder and the hand-written Discover have parted company"
        );

        let envelope = Envelope::decode(&DISCOVER_RESPONSE).expect("the envelope decodes");
        assert_eq!(
            Discovery::decode(envelope).expect("the body decodes"),
            discovery()
        );
        assert_eq!(discover_wire().bytes(), &DISCOVER_RESPONSE[..]);
    }

    /// P-087 put `epoch` in this message so a client whose key no longer derives
    /// is told why rather than collecting an unexplainable bad proof. Absent, it
    /// must not read as zero, and a zero must not read as an epoch: epoch 0 is
    /// FRAM nobody wrote, and deriving under it mints keys the first successful
    /// write invalidates.
    #[test]
    fn a_discover_with_no_epoch_is_refused_rather_than_read_as_epoch_zero() {
        let without = Wire::envelope(header(MessageType::DiscoverResponse), 7)
            .pair(1, &[0x01])
            .pair(2, &[0x00])
            .pair(3, &bstr16(&DEVICE_ID))
            .pair(4, &[0x60])
            .pair(5, &[0xf5])
            .pair(6, &[0xf4])
            .pair(7, &bstr16(&CHALLENGE));
        assert_eq!(
            without.discovered().err(),
            Some(HandshakeError::Missing(BodyKey::Discover(
                DiscoverKey::Epoch
            ))),
            "a missing epoch must be named, never defaulted"
        );

        let zero = Wire::envelope(header(MessageType::DiscoverResponse), DiscoverKey::COUNT)
            .pair(1, &[0x01])
            .pair(2, &[0x00])
            .pair(3, &bstr16(&DEVICE_ID))
            .pair(4, &[0x60])
            .pair(5, &[0xf5])
            .pair(6, &[0xf4])
            .pair(7, &bstr16(&CHALLENGE))
            .pair(8, &[0x00]);
        assert_eq!(zero.discovered().err(), Some(HandshakeError::ZeroEpoch));

        // And the epoch that arrives is the epoch that was sent, at the top of
        // its own width — a counter that only ever climbs eventually gets there.
        let widest = discover_wire()
            .cut_to(discover_wire().len.saturating_sub(1))
            .appended(&[0x1a, 0xff, 0xff, 0xff, 0xff]);
        let epoch = widest.discovered().expect("the widest epoch decodes").epoch;
        assert_eq!(epoch.get(), u32::MAX);
    }

    /// P-013: a key a newer controller added is skipped rather than refused,
    /// which is what lets an older client keep talking to a unit that has
    /// learned to say more about itself. Nothing in this body is authenticated,
    /// so there is no field to land on the wrong side of a MAC.
    #[test]
    fn a_discover_key_this_version_has_never_heard_of_is_skipped_rather_than_refused() {
        let device = bstr16(&DEVICE_ID);
        let challenge = bstr16(&CHALLENGE);
        let newer = Wire::envelope(header(MessageType::DiscoverResponse), 9)
            .pair(1, &[0x01])
            .pair(2, &[0x00])
            .pair(3, &device)
            .pair(
                4,
                &[
                    0x6b, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x38, 0x39, 0x2d, 0x76, 0x31,
                ],
            )
            .pair(5, &[0xf5])
            .pair(6, &[0xf4])
            .pair(7, &challenge)
            .pair(8, &[0x01])
            .pair(9, &[0x83, 0x01, 0x02, 0x03]);
        assert_eq!(
            newer.discovered().expect("a newer controller's extra key"),
            discovery(),
            "an unknown key must be skipped, not refused and not read"
        );
    }

    /// P-015: the same key twice is refused before either copy is used. RFC 8949
    /// §5.6 leaves the resolution to the decoder — first wins, last wins — and
    /// two ends picking differently read different challenges out of one body,
    /// which is a client proving against something the controller never minted.
    #[test]
    fn a_discover_that_carries_a_key_twice_is_refused_before_either_copy_is_used() {
        let device = bstr16(&DEVICE_ID);
        let challenge = bstr16(&CHALLENGE);
        let other = bstr16(&[0x5a; BSTR16]);
        let twice = Wire::envelope(header(MessageType::DiscoverResponse), 9)
            .pair(1, &[0x01])
            .pair(2, &[0x00])
            .pair(3, &device)
            .pair(4, &[0x60])
            .pair(5, &[0xf5])
            .pair(6, &[0xf4])
            .pair(7, &challenge)
            .pair(7, &other)
            .pair(8, &[0x01]);
        assert_eq!(
            twice.discovered().err(),
            Some(HandshakeError::Duplicate(BodyKey::Discover(
                DiscoverKey::Challenge
            ))),
            "a second challenge must not be resolvable at all"
        );
    }

    /// A `bstr16` that is not sixteen bytes is refused on its width, never
    /// padded out or trimmed to fit. Padded, a client derives a session key from
    /// a challenge with a tail of zeros nobody agreed to, and every frame of the
    /// session fails its MAC with nothing pointing at this line.
    #[test]
    fn a_bstr16_that_is_not_sixteen_bytes_is_refused_rather_than_padded() {
        let device = bstr16(&DEVICE_ID);
        let challenge = bstr16(&CHALLENGE);
        let filler = [0x40u8; 18];
        for len in [0usize, 1, 15, 17] {
            let mut headed = filler;
            *headed.first_mut().expect("a head byte") =
                0x40 | u8::try_from(len).expect("the widths here are small");
            let short = headed
                .get(..len.saturating_add(1))
                .expect("the filler is wider than seventeen");
            let wrong_device = Wire::envelope(header(MessageType::DiscoverResponse), 8)
                .pair(1, &[0x01])
                .pair(2, &[0x00])
                .pair(3, short)
                .pair(4, &[0x60])
                .pair(5, &[0xf5])
                .pair(6, &[0xf4])
                .pair(7, &challenge)
                .pair(8, &[0x01]);
            assert_eq!(
                wrong_device.discovered().err(),
                Some(HandshakeError::WrongWidth {
                    key: BodyKey::Discover(DiscoverKey::DeviceId),
                    len,
                }),
                "a device_id of {len} bytes"
            );

            let wrong_challenge = Wire::envelope(header(MessageType::DiscoverResponse), 8)
                .pair(1, &[0x01])
                .pair(2, &[0x00])
                .pair(3, &device)
                .pair(4, &[0x60])
                .pair(5, &[0xf5])
                .pair(6, &[0xf4])
                .pair(7, short)
                .pair(8, &[0x01]);
            assert_eq!(
                wrong_challenge.discovered().err(),
                Some(HandshakeError::WrongWidth {
                    key: BodyKey::Discover(DiscoverKey::Challenge),
                    len,
                }),
                "a challenge of {len} bytes"
            );
        }
    }

    /// The same five fields as [`PUBLISHED_INNER`] with `client_id` written in
    /// long form: identical meaning, different bytes.
    const LONG_FORM_INNER: [u8; 41] =
        hex("a501010200031807046d6f38392d636c6920302e312e300550b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");

    fn hello_wire(payload: &[u8], proof: &[u8]) -> Wire {
        Wire::envelope(header(MessageType::Hello), HelloKey::COUNT)
            .bstr(1, payload)
            .bstr(2, proof)
    }

    /// A client's `Hello 0x01` from fields to wire and back, ending where P-057
    /// says it must: the fields only on the far side of the proof.
    #[test]
    fn a_hello_goes_out_as_fields_and_comes_back_as_a_proof_that_verifies() {
        let key = enrolment().client_key();
        let mut scratch = [0u8; MAX_HELLO_INNER];
        let request = inner()
            .prove(&key, &CHALLENGE, &mut scratch)
            .expect("the body encodes and proves");

        let mut frame = [0u8; SCRATCH];
        let len = request
            .write(header(MessageType::Hello), &mut frame)
            .expect("the envelope is written");
        assert_eq!(
            frame.get(..len).expect("the writer's own length"),
            hello_wire(request.payload(), request.proof().as_bytes()).bytes(),
            "the encoder and the hand-written Hello have parted company"
        );

        let envelope = Envelope::decode(frame.get(..len).expect("the length")).expect("decodes");
        let claim = HelloClaim::decode(envelope).expect("the body decodes");
        assert_eq!(claim.client_id(), slot());
        assert_eq!(claim.client_nonce(), CLIENT_NONCE);
        let accepted = claim
            .verify(&key, &CHALLENGE, Version::V1_0)
            .expect("the proof this client computed verifies");
        assert_eq!(accepted.inner, inner());
        assert_eq!(accepted.agreed, Version::V1_0);
    }

    /// P-070: the proof covers the whole inner body, so `client_version`,
    /// `protocol_major` and `protocol_minor` cannot be rewritten in flight.
    ///
    /// The frame below is what a hostile comms processor sends: a body it edited
    /// under the proof the client actually computed. Version negotiation running
    /// on those three values is a downgrade with extra steps, and the only thing
    /// between here and there is that the tag moves.
    #[test]
    fn a_body_rewritten_in_flight_does_not_verify_under_the_proof_the_client_sent() {
        let key = enrolment().client_key();
        let mut honest = [0u8; MAX_HELLO_INNER];
        let sent = inner()
            .prove(&key, &CHALLENGE, &mut honest)
            .expect("the honest body proves");
        let proof = *sent.proof();

        let downgrades: [HelloInner<'_>; 3] = [
            HelloInner {
                client_version: "o89-cli 0.0.9",
                ..inner()
            },
            HelloInner {
                version: Version { major: 2, minor: 0 },
                ..inner()
            },
            HelloInner {
                version: Version { major: 1, minor: 9 },
                ..inner()
            },
        ];
        for rewritten in downgrades {
            let mut edited = [0u8; MAX_HELLO_INNER];
            let forged = rewritten
                .prove(&key, &CHALLENGE, &mut edited)
                .expect("the rewritten body encodes");
            assert_ne!(
                forged.payload(),
                sent.payload(),
                "the fixture must differ on the wire, or this test proves nothing"
            );
            let wire = hello_wire(forged.payload(), proof.as_bytes());
            assert_eq!(
                wire.claimed()
                    .expect("the frame parses")
                    .verify(&key, &CHALLENGE, Version::V1_0)
                    .err(),
                Some(HandshakeError::Proof(MacError::Mismatch)),
                "a rewritten {rewritten:?} verified under somebody else's proof"
            );
        }
    }

    /// P-048: the proof is over the payload bytes exactly as they arrived.
    ///
    /// `07` and `1807` are the same CBOR integer and different bytes. A verifier
    /// that decoded and re-encoded before hashing would compute one tag for
    /// both, and so would authenticate a body the sender never sent — which is
    /// the whole of what the proof was there to rule out.
    #[test]
    fn a_re_encoded_inner_body_is_not_the_inner_body_that_arrived() {
        let key = enrolment().client_key();
        assert_eq!(
            HelloInner::decode(&LONG_FORM_INNER).expect("long form decodes"),
            HelloInner::decode(&PUBLISHED_INNER).expect("short form decodes"),
            "the two fixtures must mean the same thing, or this test proves nothing"
        );
        assert_ne!(&LONG_FORM_INNER[..], &PUBLISHED_INNER[..]);

        let wire = hello_wire(&LONG_FORM_INNER, &PUBLISHED_PROOF);
        assert_eq!(
            wire.claimed()
                .expect("the frame parses")
                .verify(&key, &CHALLENGE, Version::V1_0)
                .err(),
            Some(HandshakeError::Proof(MacError::Mismatch)),
            "two encodings of one body shared a proof, so something re-encoded"
        );

        // And the honest pairing of those same bytes does verify, so the
        // refusal above is about the encoding and not about the fixture.
        let over_the_bytes = key.hello_proof(&HelloProof {
            challenge: &CHALLENGE,
            client_nonce: &CLIENT_NONCE,
            client_id: CLIENT_ID,
            payload: &LONG_FORM_INNER,
        });
        assert!(
            hello_wire(&LONG_FORM_INNER, over_the_bytes.as_bytes())
                .claimed()
                .expect("the frame parses")
                .verify(&key, &CHALLENGE, Version::V1_0)
                .is_ok()
        );
    }

    /// P-057's ordering, and the half of it a happy path never exercises: a
    /// proof that does not check out hands back no body at all.
    ///
    /// `client_id` and `client_nonce` are reachable before the check because no
    /// key can be found without them. Everything else is behind `verify`, so a
    /// controller cannot negotiate a version off a body a relay wrote — which is
    /// the only thing P-070 is protecting.
    #[test]
    fn a_hello_whose_proof_fails_hands_back_no_body_to_act_on() {
        let ours = enrolment().client_key();
        let theirs = device()
            .enrolment(Epoch::FIRST, ClientId::new(1).expect("slot 1 is a slot"))
            .client_key();
        let mut scratch = [0u8; MAX_HELLO_INNER];
        let request = inner()
            .prove(&theirs, &CHALLENGE, &mut scratch)
            .expect("some other client's body");
        let wire = hello_wire(request.payload(), request.proof().as_bytes());

        let claim = wire.claimed().expect("the frame parses");
        assert_eq!(claim.client_id(), slot(), "the routing field is readable");
        assert_eq!(claim.client_nonce(), CLIENT_NONCE);
        assert_eq!(
            claim.verify(&ours, &CHALLENGE, Version::V1_0).err(),
            Some(HandshakeError::Proof(MacError::Mismatch))
        );
        assert_eq!(
            HandshakeError::Proof(MacError::Mismatch).refusal().code(),
            10,
            "P-051 answers a failed proof with error 10"
        );

        // The same body against a challenge this connection no longer holds.
        let claim = wire.claimed().expect("the frame parses");
        assert_eq!(
            claim.verify(&theirs, &[0x5a; BSTR16], Version::V1_0).err(),
            Some(HandshakeError::Proof(MacError::Mismatch)),
            "a proof against a stale challenge must not verify"
        );
    }

    /// A key beside `payload` and `proof` is refused rather than skipped.
    ///
    /// This is P-050's argument one message over: a third key here would be
    /// meaningful and structurally outside the proof, which is the classic shape
    /// of the bug — the field lands on the wrong side of the authentication and
    /// every older decoder skips politely past it.
    #[test]
    fn a_key_beside_payload_and_proof_in_a_hello_is_refused_rather_than_skipped() {
        let key = enrolment().client_key();
        let mut scratch = [0u8; MAX_HELLO_INNER];
        let request = inner()
            .prove(&key, &CHALLENGE, &mut scratch)
            .expect("the body proves");

        let extra = Wire::envelope(header(MessageType::Hello), 3)
            .bstr(1, request.payload())
            .bstr(2, request.proof().as_bytes())
            .pair(3, &[0x01]);
        assert_eq!(extra.claimed().err(), Some(HandshakeError::UnknownKey(3)));
        assert_eq!(HandshakeError::UnknownKey(3).refusal().code(), 1);

        // -1 is a legal CBOR key and not a legal Hello key.
        let negative = Wire::envelope(header(MessageType::Hello), 3)
            .appended(&[0x20, 0x01])
            .bstr(1, request.payload())
            .bstr(2, request.proof().as_bytes());
        assert_eq!(
            negative.claimed().err(),
            Some(HandshakeError::UnknownKey(-1))
        );

        // And a key that arrives twice, which RFC 8949 §5.6 leaves to the
        // decoder: last-wins reads a body the proof does not cover.
        let twice = Wire::envelope(header(MessageType::Hello), 3)
            .bstr(1, request.payload())
            .bstr(2, request.proof().as_bytes())
            .bstr(1, &LONG_FORM_INNER);
        assert_eq!(
            twice.claimed().err(),
            Some(HandshakeError::Duplicate(BodyKey::Hello(HelloKey::Payload)))
        );
    }

    /// Zero is the `client_id` a `PairAck` carries when nobody was enrolled, so
    /// it names no slot and there is no key at it. Read as a number, a `Hello`
    /// claiming it sends a controller looking up row zero of a table that counts
    /// from one.
    #[test]
    fn a_hello_claiming_client_id_zero_names_no_slot() {
        let zeroed: [u8; 40] =
            hex("a5010102000300046d6f38392d636c6920302e312e300550b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        let wire = hello_wire(&zeroed, &PUBLISHED_PROOF);
        assert_eq!(wire.claimed().err(), Some(HandshakeError::NoSuchSlot));
    }

    /// Every required inner key, left out one at a time. A body missing one is
    /// refused by name rather than defaulted — an absent `client_nonce` is not
    /// sixteen zero bytes, and a session salted with those is one a controller
    /// with a stuck RNG hands to every client.
    #[test]
    fn an_inner_body_missing_a_required_key_is_refused_by_name() {
        const EVERY: [(InnerKey, &[u8]); 5] = [
            (InnerKey::ProtocolMajor, &[0x01, 0x01]),
            (InnerKey::ProtocolMinor, &[0x02, 0x00]),
            (InnerKey::ClientId, &[0x03, 0x07]),
            (InnerKey::ClientVersion, &[0x04, 0x62, 0x76, 0x31]),
            (
                InnerKey::ClientNonce,
                &[
                    0x05, 0x50, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
                    0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
                ],
            ),
        ];
        for (left_out, _) in EVERY {
            let mut body = [0u8; MAX_HELLO_INNER];
            let mut len = 1;
            *body.first_mut().expect("the map header") = 0xa4;
            for (key, bytes) in EVERY {
                if key == left_out {
                    continue;
                }
                for &byte in bytes {
                    *body.get_mut(len).expect("the body fits") = byte;
                    len = len.saturating_add(1);
                }
            }
            let short = body.get(..len).expect("the length came from the builder");
            assert_eq!(
                HelloInner::decode(short).err(),
                Some(HandshakeError::Missing(BodyKey::Inner(left_out))),
                "a body without {left_out}"
            );
        }
    }

    /// The type-state says an unverified claim has no accessor for the fields
    /// P-070 protects. A derived `Debug` is one, and it took two reviewers
    /// running `format!` to notice the same hole in `wrapper.rs` — the doc-tests
    /// above assert the property by *type*, and a formatter is not a type.
    #[test]
    fn an_unverified_hello_does_not_hand_the_client_version_to_a_formatter() {
        let key = enrolment().client_key();
        let mut ours = [0u8; MAX_HELLO_INNER];
        let mine = inner()
            .prove(&key, &CHALLENGE, &mut ours)
            .expect("the honest body");
        let mut theirs = [0u8; MAX_HELLO_INNER];
        let other = HelloInner {
            client_version: "different-ver",
            ..inner()
        }
        .prove(&key, &CHALLENGE, &mut theirs)
        .expect("a body of the same width and another version");

        let here = hello_wire(mine.payload(), mine.proof().as_bytes());
        let there = hello_wire(other.payload(), other.proof().as_bytes());
        let first = Rendering::<160>::debugged(&here.claimed().expect("parses"));
        let second = Rendering::<160>::debugged(&there.claimed().expect("parses"));
        assert_eq!(
            first.bytes(),
            second.bytes(),
            "two client_versions rendered differently, so the rendering carries one"
        );
        let text = core::str::from_utf8(first.bytes()).expect("a rendering is UTF-8");
        assert!(
            text.contains("unverified"),
            "a reader has to be told the body is nobody's word yet: {text}"
        );
    }

    fn session_key(session: SessionId) -> SessionKey {
        enrolment().session_key(&handshake(), session)
    }

    fn report() -> HelloReport<'static> {
        HelloReport {
            topology: Topology::THIS_CONTROLLER,
            version: Version::V1_0,
            session: SessionId::from(SESSION),
            fw_controller: "0.1.0",
            fw_comms: "0.1.0",
            capabilities: 0x0000_00ff,
            log_oldest_seq: LogSeq(1),
            log_newest_seq: LogSeq(4242),
            state_seq: StateSeq(9),
            time_known: true,
            counter: 66,
            caps: Caps::THIS_CONTROLLER,
        }
    }

    /// The twenty-nine keys, and the length the encoder wrote.
    fn encoded(reported: &HelloReport<'_>) -> ([u8; MAX_HELLO_REPORT], usize) {
        let mut body = [0u8; MAX_HELLO_REPORT];
        let len = reported.encode(&mut body).expect("the report encodes");
        (body, len)
    }

    /// A whole `Hello 0x81` frame, MAC'd under the key the client will derive —
    /// with the body handed in, so a fixture can edit it first.
    fn wrapped(head: Header, body: &[u8]) -> Wire {
        let mac = session_key(head.session).response(&Wrapped {
            kind: head.kind,
            session: head.session,
            req_id: head.req_id,
            payload: body,
        });
        Wire::envelope(head, 2)
            .bstr(1, body)
            .bstr(2, mac.as_bytes())
    }

    /// The controller's answer as a controller builds it.
    fn answered(reported: &HelloReport<'_>, head: Header) -> Wire {
        let (body, len) = encoded(reported);
        wrapped(head, body.get(..len).expect("the writer's own length"))
    }

    impl Wire {
        fn opened(&self) -> Result<Session<'_>, HandshakeError> {
            Session::open(
                Envelope::decode(self.bytes()).map_err(HandshakeError::Envelope)?,
                &enrolment(),
                &handshake(),
                Version::V1_0,
            )
        }
    }

    /// The path this module exists for on the client side: an envelope in, a
    /// session out, and the key derived from the `session_id` the envelope
    /// carried rather than from anything the caller passed.
    #[test]
    fn a_hello_response_opens_a_session_whose_key_came_from_the_envelope() {
        let head = header(MessageType::HelloResponse);
        let wire = answered(&report(), head);
        let session = wire
            .opened()
            .expect("the controller's answer opens a session");
        assert_eq!(*session.report(), report());
        assert_eq!(session.version(), Version::V1_0);

        // The key that came out is the key the next frame is authenticated
        // under, which is the only thing a session is for.
        let onward = Wrapped {
            kind: MessageType::CommandResponse,
            session: head.session,
            req_id: ReqId(REQ_ID),
            payload: &PUBLISHED_INNER,
        };
        session
            .key()
            .response(&onward)
            .verify(session_key(head.session).response(&onward).as_bytes())
            .expect("the session hands back the key it derived");
    }

    /// P-072, and the reason it is safe.
    ///
    /// `session_id` is read off the envelope before anything has authenticated
    /// it, which reads like a bug. It is not, because `session_id` is inside the
    /// `rsp` preimage: a comms processor that rewrites it sends the client to a
    /// different key, and the MAC over a body it did not touch stops matching.
    /// Every rewritten handle below has to come back as a failed MAC rather than
    /// as a session running on somebody else's number.
    #[test]
    fn a_rewritten_session_id_in_the_envelope_yields_a_key_that_fails_the_mac() {
        let head = header(MessageType::HelloResponse);
        let wire = answered(&report(), head);
        assert!(
            wire.opened().is_ok(),
            "the fixture must open, or every rewrite below proves nothing"
        );

        for handle in [1u8, 2, 4, 23] {
            // Element 2 of the envelope: 0x84, the long-form type, then the
            // session_id inline.
            let rewritten = wire.replaced(3, handle);
            assert_eq!(
                rewritten.opened().err(),
                Some(HandshakeError::Wrapper(WrapperError::Mac(
                    MacError::Mismatch
                ))),
                "a session_id rewritten to {handle} opened a session anyway"
            );
        }

        // Zero is refused earlier and for a different reason, so it is not in
        // the loop above: handle 0 means *no session*, and there is no key to
        // derive at it.
        assert_eq!(
            wire.replaced(3, 0).opened().err(),
            Some(HandshakeError::NoHandle),
            "a session_id rewritten to 0 opened a session anyway"
        );
    }

    /// A handle of 0 means *no session* (P-021), so a `Hello 0x81` arriving at
    /// one is not a session however well it verifies.
    ///
    /// The rewrite case above is caught by the MAC. This is the one it cannot
    /// catch: a comms processor that stamps 0 into the envelope **and** key 3,
    /// with the body MAC'd under the key derived at 0, is internally consistent
    /// — the mismatch check compares `None` against `None` and the tag holds.
    /// Accepted, every later frame is keyed at handle 0 and nothing downstream
    /// can tell, because a `Session` does not surrender its id. A default
    /// mistaken for a measurement, which is the one thing this project refuses.
    #[test]
    fn a_hello_that_verifies_at_handle_zero_is_still_not_a_session() {
        let head = Header {
            session: SessionId::None,
            ..header(MessageType::HelloResponse)
        };
        let at_zero = HelloReport {
            session: SessionId::None,
            ..report()
        };
        let wire = answered(&at_zero, head);
        assert_eq!(
            wire.opened().err(),
            Some(HandshakeError::NoHandle),
            "a consistent handle 0 opened a session"
        );
    }

    /// The other half of P-072: key 3 inside the authenticated body has to be
    /// the handle the key was derived under.
    ///
    /// The frame below is MAC'd correctly — a controller that filled key 3 in
    /// from the wrong row builds exactly this — so nothing but the comparison
    /// catches it, and a client that skipped it runs a session whose two halves
    /// disagree about which session it is.
    #[test]
    fn a_hello_response_whose_body_names_another_session_is_refused() {
        let head = header(MessageType::HelloResponse);
        let elsewhere = HelloReport {
            session: SessionId::from(SESSION.saturating_add(1)),
            ..report()
        };
        assert_eq!(
            answered(&elsewhere, head).opened().err(),
            Some(HandshakeError::SessionMismatch {
                envelope: SessionId::from(SESSION),
                body: SessionId::from(SESSION.saturating_add(1)),
            })
        );
    }

    /// P-006: a `Hello 0x81` reporting more than 32 channels is rejected with
    /// error 1, and a controller may not build one either.
    ///
    /// Thirty-two is the config array a channel list is stored in. A device
    /// reporting 64 does not get twice the room; it gets a client that writes
    /// 64 channels and is refused the whole section, having already built a
    /// configuration around the number the controller told it.
    #[test]
    fn a_hello_response_reporting_thirty_three_channels_is_refused_with_error_one() {
        let head = header(MessageType::HelloResponse);
        let ceiling = Caps {
            channels: Caps::CHANNEL_CEILING,
            ..Caps::THIS_CONTROLLER
        };
        let (body, len) = encoded(&HelloReport {
            caps: ceiling,
            ..report()
        });
        let at = body
            .get(..len)
            .expect("the writer's own length")
            .windows(3)
            // Key 13, and 32 in the long form its own width calls for.
            .position(|run| run == [0x0d, 0x18, Caps::CHANNEL_CEILING])
            .expect("key 13 and its value are in the body");

        for channels in [33u8, 34, 36, 64, 255] {
            let mut over = body;
            *over
                .get_mut(at.saturating_add(2))
                .expect("the value of key 13") = channels;
            let edited = over.get(..len).expect("the same length");
            assert_eq!(
                wrapped(head, edited).opened().err(),
                Some(HandshakeError::ChannelsAboveCeiling(channels)),
                "a client must reject a Hello 0x81 reporting {channels} channels"
            );
            assert_eq!(
                HandshakeError::ChannelsAboveCeiling(channels)
                    .refusal()
                    .code(),
                1,
                "P-006 names error 1"
            );

            // And the controller must not build one in the first place.
            let mut scratch = [0u8; MAX_HELLO_REPORT];
            assert_eq!(
                HelloReport {
                    caps: Caps {
                        channels,
                        ..Caps::THIS_CONTROLLER
                    },
                    ..report()
                }
                .encode(&mut scratch)
                .err(),
                Some(HandshakeError::ChannelsAboveCeiling(channels))
            );
        }

        // The ceiling itself is legal, or the test above would pass on a cap of
        // one and say nothing about 32.
        assert!(
            wrapped(head, body.get(..len).expect("the length"))
                .opened()
                .is_ok()
        );
    }

    impl Wire {
        fn opened_as(&self, ours: Version) -> Result<Session<'_>, HandshakeError> {
            Session::open(
                Envelope::decode(self.bytes()).map_err(HandshakeError::Envelope)?,
                &enrolment(),
                &handshake(),
                ours,
            )
        }
    }

    /// P-073: a major mismatch refuses the session with error 3, a minor
    /// mismatch proceeds at the lower of the two. A newer client degrades; it
    /// never assumes.
    ///
    /// The end-to-end half matters as much as the arithmetic: negotiating at
    /// all is something that happens after the MAC, because P-070 spends a proof
    /// on these two bytes precisely so a relay cannot pick them.
    #[test]
    fn a_major_mismatch_refuses_and_a_minor_one_proceeds_at_the_lower_of_the_two() {
        assert_eq!(Version::V1_0.agreed(Version::V1_0), Ok(Version::V1_0));
        let newer = Version { major: 1, minor: 9 };
        let older = Version { major: 1, minor: 2 };
        assert_eq!(newer.agreed(older), Ok(older), "a newer client degrades");
        assert_eq!(older.agreed(newer), Ok(older), "and so does a newer peer");

        for theirs in [0u8, 2, 9, 255] {
            let mismatch = HandshakeError::MajorMismatch { ours: 1, theirs };
            assert_eq!(
                Version::V1_0.agreed(Version {
                    major: theirs,
                    minor: 0
                }),
                Err(mismatch)
            );
            assert_eq!(mismatch.refusal().code(), 3, "P-073 names error 3");
        }

        // A controller a major ahead, through a Hello 0x81 whose MAC is perfect.
        let head = header(MessageType::HelloResponse);
        let ahead = HelloReport {
            version: Version { major: 2, minor: 0 },
            ..report()
        };
        assert_eq!(
            answered(&ahead, head).opened().err(),
            Some(HandshakeError::MajorMismatch { ours: 1, theirs: 2 })
        );

        // A controller a minor ahead: the session opens at ours.
        let minor_ahead = HelloReport {
            version: Version { major: 1, minor: 4 },
            ..report()
        };
        let wire = answered(&minor_ahead, head);
        let session = wire.opened().expect("a minor ahead is not a refusal");
        assert_eq!(session.version(), Version::V1_0);

        // And a client a minor ahead of the controller lands on the controller's.
        let wire = answered(&report(), head);
        let session = wire
            .opened_as(Version { major: 1, minor: 7 })
            .expect("a client a minor ahead degrades");
        assert_eq!(session.version(), Version::V1_0);
    }

    /// The version fields are negotiated after the proof, never before.
    ///
    /// A `Hello 0x01` announcing a major nobody speaks, signed under a key the
    /// controller does not hold, has to come back as a failed proof — otherwise
    /// anything on the path can refuse any client's session by editing one byte,
    /// and P-070's whole argument is that these three fields are not a relay's
    /// to choose.
    #[test]
    fn a_version_is_negotiated_after_the_proof_and_never_before_it() {
        let ours = enrolment().client_key();
        let theirs = device()
            .enrolment(Epoch::FIRST, ClientId::new(1).expect("slot 1 is a slot"))
            .client_key();
        let ahead = HelloInner {
            version: Version { major: 2, minor: 0 },
            ..inner()
        };

        let mut forged = [0u8; MAX_HELLO_INNER];
        let by_somebody_else = ahead
            .prove(&theirs, &CHALLENGE, &mut forged)
            .expect("a body signed under the wrong key");
        assert_eq!(
            hello_wire(
                by_somebody_else.payload(),
                by_somebody_else.proof().as_bytes()
            )
            .claimed()
            .expect("the frame parses")
            .verify(&ours, &CHALLENGE, Version::V1_0)
            .err(),
            Some(HandshakeError::Proof(MacError::Mismatch)),
            "the version was read off a body nobody had authenticated"
        );

        // Signed by the client that really holds the key, the same major is the
        // refusal P-073 asks for.
        let mut honest = [0u8; MAX_HELLO_INNER];
        let genuine = ahead
            .prove(&ours, &CHALLENGE, &mut honest)
            .expect("a body this client really signed");
        assert_eq!(
            hello_wire(genuine.payload(), genuine.proof().as_bytes())
                .claimed()
                .expect("the frame parses")
                .verify(&ours, &CHALLENGE, Version::V1_0)
                .err(),
            Some(HandshakeError::MajorMismatch { ours: 1, theirs: 2 })
        );
    }

    /// P-005: the controller reports the numbers it enforces, and they survive
    /// the trip through the wire unchanged.
    ///
    /// Reporting a number the controller does not enforce is worse than
    /// reporting nothing: a client told it may keep eight requests in flight,
    /// then refused the third with error 7, has been handed a field that made it
    /// behave worse than the compiled-in guess it replaced.
    #[test]
    fn the_caps_a_hello_response_reports_are_the_ones_this_controller_enforces() {
        let caps = Caps::THIS_CONTROLLER;
        assert_eq!(usize::from(caps.sessions), MAX_SESSIONS);
        assert_eq!(usize::from(caps.channels), MAX_CHANNELS);
        assert_eq!(usize::from(caps.clients), MAX_CLIENTS);
        assert_eq!(usize::from(caps.event_queue), MAX_EVENT_QUEUE);
        assert_eq!(usize::from(caps.inflight), MAX_INFLIGHT);
        assert_eq!(usize::from(caps.cmd_dedup), MAX_CMD_DEDUP);

        let head = header(MessageType::HelloResponse);
        let wire = answered(&report(), head);
        let session = wire.opened().expect("the answer opens a session");
        assert_eq!(
            session.report().caps,
            caps,
            "a cap moved somewhere between the encoder and the decoder"
        );
    }

    const EVERY_REPORT_KEY: [ReportKey; ReportKey::COUNT] = [
        ReportKey::ProtocolMajor,
        ReportKey::ProtocolMinor,
        ReportKey::SessionId,
        ReportKey::FwController,
        ReportKey::FwComms,
        ReportKey::Capabilities,
        ReportKey::LogOldestSeq,
        ReportKey::LogNewestSeq,
        ReportKey::StateSeq,
        ReportKey::TimeKnown,
        ReportKey::Counter,
        ReportKey::MaxSessions,
        ReportKey::MaxChannels,
        ReportKey::MaxClients,
        ReportKey::MaxEventQueue,
        ReportKey::MaxInflight,
        ReportKey::MaxCmdDedup,
        ReportKey::Rev,
        ReportKey::TopoDigest,
        ReportKey::MaxBuses,
        ReportKey::MaxDevices,
        ReportKey::MaxComponents,
        ReportKey::MaxSignals,
        ReportKey::MaxSeriesElements,
        ReportKey::MaxParams,
        ReportKey::MaxConcerns,
        ReportKey::MaxSelectors,
        ReportKey::MaxHistorySignals,
        ReportKey::MaxTopologyDepth,
    ];

    /// Twenty-eight of the twenty-nine keys, written independently of
    /// [`HelloReport::encode`] so a fixture can leave any one of them out.
    fn report_without(left_out: ReportKey, dst: &mut [u8]) -> usize {
        let mut cbor = CborWriter::new(dst);
        cbor.map(ReportKey::COUNT.saturating_sub(1))
            .expect("a twenty-eight-pair map");
        for key in EVERY_REPORT_KEY {
            if key == left_out {
                continue;
            }
            cbor.key(key.number()).expect("an ascending key");
            match key {
                ReportKey::SessionId => cbor.u64(u64::from(SESSION)),
                ReportKey::FwController | ReportKey::FwComms => cbor.text("0.1.0"),
                ReportKey::TimeKnown => cbor.bool(true),
                ReportKey::TopoDigest => cbor.bytes(&[0u8; 8]),
                ReportKey::ProtocolMajor
                | ReportKey::ProtocolMinor
                | ReportKey::Capabilities
                | ReportKey::LogOldestSeq
                | ReportKey::LogNewestSeq
                | ReportKey::StateSeq
                | ReportKey::Counter
                | ReportKey::MaxSessions
                | ReportKey::MaxChannels
                | ReportKey::MaxClients
                | ReportKey::MaxEventQueue
                | ReportKey::MaxInflight
                | ReportKey::MaxCmdDedup
                | ReportKey::Rev
                | ReportKey::MaxBuses
                | ReportKey::MaxDevices
                | ReportKey::MaxComponents
                | ReportKey::MaxSignals
                | ReportKey::MaxSeriesElements
                | ReportKey::MaxParams
                | ReportKey::MaxConcerns
                | ReportKey::MaxSelectors
                | ReportKey::MaxHistorySignals
                | ReportKey::MaxTopologyDepth => cbor.u64(1),
            }
            .expect("a value");
        }
        cbor.finish().expect("the body is complete")
    }

    /// Every key of `Hello 0x81`, left out one at a time, and every one of the
    /// twenty-nine refused by name.
    ///
    /// The tempting mistake is to read what is there and default the rest. A
    /// `counter` defaulted to zero is a client that signs its next write with a
    /// number the controller has already accepted, and P-080 refuses it with
    /// error 11 for the rest of the session.
    #[test]
    fn a_hello_response_missing_any_one_key_is_refused_by_name() {
        let head = header(MessageType::HelloResponse);
        for left_out in EVERY_REPORT_KEY {
            let mut body = [0u8; MAX_HELLO_REPORT];
            let len = report_without(left_out, &mut body);
            let short = body.get(..len).expect("the writer's own length");
            assert_eq!(
                wrapped(head, short).opened().err(),
                Some(HandshakeError::Missing(BodyKey::Report(left_out))),
                "a body without {left_out}"
            );
        }

        // All twenty-nine present is the case that must pass, or the loop above is
        // asserting about a body that was never going to decode.
        assert!(answered(&report(), head).opened().is_ok());
    }

    /// Sixty-four bytes, which is [`MAX_STRING`] and so the widest text any of
    /// these bodies can carry.
    const WIDEST_TEXT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The three body caps, against what the encoders actually write.
    ///
    /// A caller sizes a buffer from these before a byte is encoded. One byte
    /// optimistic and the frame that does not fit is the one built at a fully
    /// configured site with a long model name, which is the failure `limits.rs`
    /// records twice already.
    #[test]
    fn the_widest_body_of_each_message_is_the_size_these_caps_promise() {
        assert_eq!(WIDEST_TEXT.len(), MAX_STRING, "the fixture is the cap");
        let widest = Header {
            kind: MessageType::DiscoverResponse,
            session: SessionId::from(0xFFFF),
            req_id: ReqId(u32::MAX),
        };
        let mut buf = [0u8; MAX_PAYLOAD];
        let len = Discovery {
            version: Version {
                major: u8::MAX,
                minor: u8::MAX,
            },
            device_id: [0xFF; BSTR16],
            model: WIDEST_TEXT,
            provisioned: true,
            pairing_open: true,
            challenge: [0xFF; BSTR16],
            epoch: Epoch::new(u32::MAX).expect("the top of the counter is an epoch"),
        }
        .write(widest, &mut buf)
        .expect("the widest Discover fits a payload");
        assert_eq!(
            len,
            11 + MAX_DISCOVER_BODY,
            "eleven bytes of envelope and the widest body"
        );

        let mut scratch = [0u8; MAX_HELLO_INNER];
        let request = HelloInner {
            version: Version {
                major: u8::MAX,
                minor: u8::MAX,
            },
            client_id: ClientId::new(u32::MAX).expect("the top slot is a slot"),
            client_version: WIDEST_TEXT,
            client_nonce: [0xFF; BSTR16],
        }
        .prove(&enrolment().client_key(), &CHALLENGE, &mut scratch)
        .expect("the widest inner body fits its own cap exactly");
        assert_eq!(request.payload().len(), MAX_HELLO_INNER);

        let (_, len) = encoded(&HelloReport {
            topology: Topology {
                rev: u32::MAX,
                digest: [0xFF; 8],
                buses: u8::MAX,
                devices: u16::MAX,
                components: u16::MAX,
                signals: u16::MAX,
                series_elements: u16::MAX,
                params: u16::MAX,
                concerns: u16::MAX,
                selectors: u8::MAX,
                history_signals: u16::MAX,
                topology_depth: u8::MAX,
            },
            version: Version {
                major: u8::MAX,
                minor: u8::MAX,
            },
            session: SessionId::from(0xFFFF),
            fw_controller: WIDEST_TEXT,
            fw_comms: WIDEST_TEXT,
            capabilities: u32::MAX,
            log_oldest_seq: LogSeq(u64::MAX),
            log_newest_seq: LogSeq(u64::MAX),
            state_seq: StateSeq(u64::MAX),
            time_known: true,
            counter: u64::MAX,
            caps: Caps {
                sessions: u8::MAX,
                channels: Caps::CHANNEL_CEILING,
                clients: u8::MAX,
                event_queue: u16::MAX,
                inflight: u8::MAX,
                cmd_dedup: u16::MAX,
            },
        });
        assert_eq!(len, MAX_HELLO_REPORT);
    }

    /// A destination one byte short is refused, never filled to the brim.
    ///
    /// A truncated body still parses at the far end — as a shorter, perfectly
    /// well formed message carrying other fields — so half an answer in a
    /// caller's buffer is worse than no answer at all.
    #[test]
    fn a_body_that_will_not_fit_is_refused_rather_than_truncated() {
        let head = header(MessageType::DiscoverResponse);
        let mut buf = [0u8; SCRATCH];
        let whole = discovery().write(head, &mut buf).expect("the fixture fits");
        for short in 0..whole {
            let mut narrow = [0xAAu8; SCRATCH];
            let dst = narrow.get_mut(..short).expect("short is below the scratch");
            assert!(
                discovery().write(head, dst).is_err(),
                "a {short}-byte destination for a {whole}-byte answer"
            );
        }

        let mut scratch = [0u8; MAX_HELLO_INNER];
        let key = enrolment().client_key();
        for short in 0..PUBLISHED_INNER.len() {
            let dst = scratch.get_mut(..short).expect("short is below the cap");
            assert!(
                inner().prove(&key, &CHALLENGE, dst).is_err(),
                "a {short}-byte scratch for a 44-byte inner body"
            );
        }
    }

    /// An envelope naming another message is refused before its body is read.
    ///
    /// Without it a `Readings 0x8E` gets decoded as a `Hello 0x81`: every key
    /// number the two happen to share taken at face value, and the rest reported
    /// missing, which is a refusal naming the wrong cause at best.
    #[test]
    fn an_envelope_naming_another_message_is_not_decoded_as_this_one() {
        for kind in [
            MessageType::Readings,
            MessageType::ReadingsResponse,
            MessageType::Hello,
            MessageType::ErrorResponse,
        ] {
            let wire = discover_wire();
            let elsewhere = wire.replaced(2, kind as u8);
            assert_eq!(
                elsewhere.discovered().err(),
                Some(HandshakeError::WrongMessage {
                    expected: MessageType::DiscoverResponse,
                    found: kind,
                }),
                "a {kind:?} body read as a Discover"
            );
        }

        let head = header(MessageType::HelloResponse);
        let wire = answered(&report(), head);
        assert_eq!(
            wire.replaced(2, MessageType::ReadLogResponse as u8)
                .opened()
                .err(),
            Some(HandshakeError::WrongMessage {
                expected: MessageType::HelloResponse,
                found: MessageType::ReadLogResponse,
            })
        );
    }

    /// Every key number this version allocates, and nothing either side of it.
    ///
    /// The list and the numbers live in four places apiece — `of`, `number`,
    /// `name` and the encoder — and a key that maps to a number nothing decodes
    /// is a field silently dropped on one side of a link.
    #[test]
    fn every_key_number_maps_back_to_the_key_that_claims_it() {
        for n in 1..=DiscoverKey::COUNT {
            let number = i64::try_from(n).expect("the counts here are small");
            let key = DiscoverKey::of(number).expect("a key this version allocates");
            assert_eq!(key.number(), number);
        }
        for n in 1..=HelloKey::COUNT {
            let number = i64::try_from(n).expect("the counts here are small");
            assert_eq!(HelloKey::of(number).expect("a key").number(), number);
        }
        for n in 1..=InnerKey::COUNT {
            let number = i64::try_from(n).expect("the counts here are small");
            assert_eq!(InnerKey::of(number).expect("a key").number(), number);
        }
        for key in EVERY_REPORT_KEY {
            assert_eq!(
                ReportKey::of(key.number()),
                Some(key),
                "{key} does not decode to itself"
            );
        }

        for outside in [i64::MIN, -1, 0, 30, 31, 255, i64::MAX] {
            assert_eq!(ReportKey::of(outside), None, "key {outside}");
        }
        assert_eq!(DiscoverKey::of(9), None);
        assert_eq!(HelloKey::of(3), None);
        assert_eq!(InnerKey::of(6), None);
    }

    /// Every refusal renders as its own sentence. Two that share a line send
    /// somebody reading a bench log to the wrong half, and the pair here that
    /// somebody will be telling apart is "the proof did not match" and "the
    /// wrapper's tag did not match" — one is a client that proved wrong, the
    /// other is a session key the two ends disagree about.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        let every: [HandshakeError; 16] = [
            HandshakeError::Missing(BodyKey::Discover(DiscoverKey::Challenge)),
            HandshakeError::Missing(BodyKey::Inner(InnerKey::ClientNonce)),
            HandshakeError::Missing(BodyKey::Report(ReportKey::MaxChannels)),
            HandshakeError::Duplicate(BodyKey::Hello(HelloKey::Payload)),
            HandshakeError::UnknownKey(3),
            HandshakeError::WrongWidth {
                key: BodyKey::Discover(DiscoverKey::DeviceId),
                len: 12,
            },
            HandshakeError::WrongMessage {
                expected: MessageType::HelloResponse,
                found: MessageType::Readings,
            },
            HandshakeError::SessionMismatch {
                envelope: SessionId::from(3),
                body: SessionId::from(4),
            },
            HandshakeError::MajorMismatch { ours: 1, theirs: 2 },
            HandshakeError::ChannelsAboveCeiling(33),
            HandshakeError::NoSuchSlot,
            HandshakeError::ZeroEpoch,
            HandshakeError::Proof(MacError::Mismatch),
            HandshakeError::Wrapper(WrapperError::Mac(MacError::Mismatch)),
            HandshakeError::Envelope(EnvelopeError::WrongLength),
            HandshakeError::Cbor(CborError::WrongType),
        ];
        Rendering::<96>::each_says_something_of_its_own(&every);
    }

    /// A `Discovery` says nothing a hostile peer chose.
    ///
    /// `model` is up to sixty-four bytes somebody else picked, and this is the
    /// one message with no MAC at all — one `?discovery` in a span and those
    /// bytes are in a log a person reads as if the site had said them.
    #[test]
    fn a_discovery_does_not_hand_the_bytes_a_hostile_peer_chose_to_a_formatter() {
        let ours = Rendering::<160>::debugged(&discovery());
        let theirs = Rendering::<160>::debugged(&Discovery {
            device_id: [0x5A; BSTR16],
            model: "01234567890",
            challenge: [0xA5; BSTR16],
            ..discovery()
        });
        assert_eq!(
            ours.bytes(),
            theirs.bytes(),
            "two models rendered differently, so the rendering carries one"
        );
        let text = core::str::from_utf8(ours.bytes()).expect("a rendering is UTF-8");
        assert!(
            text.contains("unauthenticated"),
            "a reader has to be told nobody signed this: {text}"
        );
    }

    /// A fixed-seed xorshift, so a failure below reproduces byte for byte.
    struct Xorshift(u64);

    impl Xorshift {
        fn byte(&mut self) -> u8 {
            let mut state = self.0;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            self.0 = state;
            let [low, ..] = state.to_le_bytes();
            low
        }
    }

    /// Whatever a hostile `Discover` response says, it cannot make this decoder
    /// panic — and neither can a link that dropped carrier mid-frame.
    ///
    /// Nothing in this message is authenticated, so the bytes reaching the
    /// decoder are whatever passed a CRC. Every flip, every truncation and a run
    /// of noise has to end in a value or a named refusal, and a value that does
    /// come back has to obey the widths this module promises.
    #[test]
    fn whatever_a_hostile_discover_says_it_cannot_make_the_decoder_panic() {
        let good = discover_wire();
        assert!(
            good.discovered().is_ok(),
            "the fixture must decode, or every mutation below proves nothing"
        );

        for at in 0..good.len {
            for bit in 0..8u8 {
                if let Ok(seen) = good.flipped(at, bit).discovered() {
                    assert!(seen.model.len() <= MAX_STRING, "byte {at} bit {bit}");
                }
            }
        }
        for cut in 0..good.len {
            assert!(
                good.cut_to(cut).discovered().is_err(),
                "a Discover cut at {cut} of {} bytes decoded anyway",
                good.len
            );
        }

        let mut rng = Xorshift(0x2545_F491_4F6C_DD1D);
        let mut noise = [0u8; 96];
        for _ in 0..2048 {
            for slot in &mut noise {
                *slot = rng.byte();
            }
            for len in [0usize, 1, 6, 32, 96] {
                let bytes = noise.get(..len).expect("inside the buffer");
                if let Ok(seen) = Envelope::decode(bytes)
                    .map_err(HandshakeError::Envelope)
                    .and_then(Discovery::decode)
                {
                    assert!(seen.model.len() <= MAX_STRING);
                    assert!(seen.epoch.get() > 0, "epoch zero is not an epoch");
                }
            }
        }
    }
    /// Every strict prefix of a frame is refused, at the envelope or in the
    /// body it carries.
    fn refused_at_every_cut(
        bytes: &[u8],
        decode: impl Fn(Envelope<'_>) -> Result<(), HandshakeError>,
    ) {
        for cut in 0..bytes.len() {
            let prefix = bytes.get(..cut).expect("a prefix");
            let read = Envelope::decode(prefix)
                .map_err(|_| ())
                .and_then(|envelope| decode(envelope).map_err(|_| ()));
            assert!(read.is_err(), "a prefix of {cut} bytes decoded");
        }
        let whole = Envelope::decode(bytes).expect("the whole frame");
        assert!(
            decode(whole).is_ok(),
            "the whole frame must decode, or the loop proves nothing"
        );
    }

    /// The three handshake frames a peer reads, cut at every byte. Each had
    /// tests for a missing key and a wrong width and none for a body that
    /// simply stops.
    #[test]
    fn every_handshake_frame_cut_short_at_any_byte_is_refused() {
        let mut frame = [0u8; SCRATCH];
        let len = discovery()
            .write(header(MessageType::DiscoverResponse), &mut frame)
            .expect("encodes");
        refused_at_every_cut(frame.get(..len).expect("the frame"), |e| {
            Discovery::decode(e).map(|_| ())
        });

        let key = enrolment().client_key();
        let mut scratch = [0u8; MAX_HELLO_INNER];
        let request = inner()
            .prove(&key, &CHALLENGE, &mut scratch)
            .expect("the body encodes and proves");
        let len = request
            .write(header(MessageType::Hello), &mut frame)
            .expect("encodes");
        refused_at_every_cut(frame.get(..len).expect("the frame"), |e| {
            HelloClaim::decode(e).map(|_| ())
        });

        let wire = answered(&report(), header(MessageType::HelloResponse));
        refused_at_every_cut(wire.bytes(), |e| {
            Session::open(e, &enrolment(), &handshake(), Version::V1_0).map(|_| ())
        });
    }
}
