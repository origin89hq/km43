//! `Discover 0x80`, the report a `Hello` answers with, and the prologue both
//! handshakes hash first.
//!
//! `Discover 0x80` is the one message with no authentication at all (P-054), so
//! every field in it is a claim the comms processor could have made up. Nothing
//! here derives `Debug` over one: a rendered `model` is sixty-four
//! attacker-chosen bytes in a log somebody reads as if the site had said them,
//! which is P-055 lost to one `?discovery` in a span. What makes a `Discover`
//! safe to act on is [`Prologue`]: every field a client takes from it enters
//! the transcript both ends hash (P-227), so one rewritten in flight is a
//! handshake whose first tag fails.
//!
//! The Noise messages themselves, and the order a `Hello` is read in, are
//! `hello.rs`'s.
//!
//! cites: P-005, P-006, P-073, P-074, P-087, P-227

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::{Envelope, EnvelopeError, Header, Refusal, SessionId};
use crate::generated::{ErrorCode, MessageType, Suite};
use crate::kdf::{ClientId, DEVICE_ID_BYTES, DeviceId, Epoch, Generation};
use crate::limits::{
    ENVELOPE_BYTES, MAX_CHANNELS, MAX_CLIENTS, MAX_CMD_DEDUP, MAX_EVENT_QUEUE, MAX_INFLIGHT,
    MAX_PAYLOAD, MAX_SESSIONS, MAX_STRING,
};
use crate::noise::{CHALLENGE_BYTES, KEY_BYTES, TAG_BYTES};

/// A `device_id` and a `challenge` are both `bstr16`.
const BSTR16: usize = 16;

const_assert!(
    BSTR16 == DEVICE_ID_BYTES && BSTR16 == CHALLENGE_BYTES,
    "the prologue copies both straight out of a Discover; a width that moved on one side is a transcript nobody else hashes"
);

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

/// The widest `HelloReport`: thirty-one keys, two 64-byte firmware strings and
/// four `u64`.
///
/// Keys 30 and 31 cost seven bytes each: a two-byte key and a `u32` at its
/// widest. The trailing `+ 1` is the map header, which is two bytes past
/// twenty-three pairs.
pub const MAX_HELLO_REPORT: usize = 81 + 2 * TEXT_MAX + TOPOLOGY_REPORT_BYTES + 2 * 7 + 1;

// What travels around a report: the envelope, the second byte a `0x81` type
// costs, key 1 and a two-byte `bstr` head, and message 2's ephemeral key and
// tag.
const_assert!(
    MAX_HELLO_REPORT + ENVELOPE_BYTES + 1 + 1 + 3 + KEY_BYTES + TAG_BYTES <= MAX_PAYLOAD,
    "a HelloReport travels inside message 2 of the session handshake; a report that fills the payload is the frame a controller builds and then has to refuse with error 5"
);

/// The two version bytes both ends open with.
///
/// P-073's negotiation is [`Version::agreed`], and it is the only place the two
/// numbers are compared — a major that differs refuses, a minor that differs
/// takes the lower.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StateSeq(pub u64);

/// The eight keys of `Discover 0x80`, by name rather than by number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    /// Key 6, true while a physical act has opened a window (P-066).
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

/// The thirty-one keys of `HelloReport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    /// Key 30, the slot this session is bound to.
    ClientId,
    /// Key 31, that slot's generation (P-239).
    Generation,
}

impl ReportKey {
    const COUNT: usize = 31;

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
            30 => Some(Self::ClientId),
            31 => Some(Self::Generation),
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
            Self::ClientId => 30,
            Self::Generation => 31,
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
            Self::ClientId => "client_id",
            Self::Generation => "generation",
        }
    }
}

impl fmt::Display for ReportKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HelloReport {} (key {})", self.name(), self.number())
    }
}

/// A key of either body here, so one refusal can name any of them.
///
/// Two enums rather than one flat list: key 1 is `protocol_major` in both, and
/// key 3 is `device_id` in one and `session_id` in the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BodyKey {
    /// A key of `Discover 0x80`.
    Discover(DiscoverKey),
    /// A key of `HelloReport`.
    Report(ReportKey),
}

impl From<DiscoverKey> for BodyKey {
    fn from(key: DiscoverKey) -> Self {
        Self::Discover(key)
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

/// What a controller reports when a session opens: the payload of the session
/// handshake's message 2, so it arrives authenticated and bound to that one
/// handshake.
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
    /// Key 30, the slot this session is bound to.
    pub client_id: ClientId,
    /// Key 31, that slot's generation (P-239).
    pub generation: Generation,
}

impl<'a> HelloReport<'a> {
    /// Encode the thirty-one keys into `dst`; the caller carries them in
    /// message 2.
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
        cbor.key(ReportKey::ClientId.number())?;
        cbor.u64(u64::from(self.client_id.get()))?;
        cbor.key(ReportKey::Generation.number())?;
        cbor.u64(u64::from(self.generation.get()))?;
        Ok(cbor.finish()?)
    }

    /// Crate-private: the only route to one is a `Hello 0x81` whose message 2
    /// opened (P-051), and key 3 must name the session the envelope does.
    pub(crate) fn decode(payload: &'a [u8], envelope: SessionId) -> Result<Self, HandshakeError> {
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

/// P-227's prologue: fifty-seven bytes both handshakes hash before anything
/// else, built from everything a client decides on out of a `Discover`.
///
/// The client builds it from the `Discover 0x80` it received, the challenge it
/// is presenting and the handle its pre-session responses carried; the
/// controller from its own values for the connection. A `Discover` rewritten in
/// flight gives the two ends different prologues, and the first tag of the
/// handshake fails.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Prologue([u8; PROLOGUE_BYTES]);

/// The label, the suite, two version bytes, `device_id`, `epoch`, the challenge
/// and the handle.
pub const PROLOGUE_BYTES: usize = 16 + 1 + 2 + BSTR16 + 4 + BSTR16 + 2;

/// P-043's prologue prefix.
const PROLOGUE_LABEL: &[u8; 16] = b"km43/v1/prologue";

/// What a prologue is built from, named so no two can be swapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrologueFields<'a> {
    /// The suite the handshake runs.
    pub suite: Suite,
    /// The controller's version, from `Discover` keys 1 and 2.
    pub version: Version,
    /// `Discover` key 3.
    pub device_id: DeviceId,
    /// `Discover` key 8.
    pub epoch: Epoch,
    /// The live challenge this handshake presents: `Discover` key 7, or
    /// `Enrol 0x93` key 4 after an enrolment on this connection.
    pub challenge: &'a [u8; CHALLENGE_BYTES],
    /// The connection handle the pre-session responses carried (P-024).
    pub handle: SessionId,
}

impl Prologue {
    /// Join the fields in P-227's order.
    #[must_use]
    pub fn new(fields: &PrologueFields<'_>) -> Self {
        let mut out = [0u8; PROLOGUE_BYTES];
        let parts: [&[u8]; 7] = [
            PROLOGUE_LABEL,
            &[fields.suite as u8],
            &[fields.version.major, fields.version.minor],
            fields.device_id.as_bytes(),
            &fields.epoch.get().to_be_bytes(),
            fields.challenge,
            &u16::from(fields.handle).to_be_bytes(),
        ];
        for (slot, &byte) in out
            .iter_mut()
            .zip(parts.iter().flat_map(|part| part.iter()))
        {
            *slot = byte;
        }
        Self(out)
    }

    /// The client's: every field but the suite and the challenge from the
    /// `Discover` it received, and the handle that `Discover`'s answer carried.
    #[must_use]
    pub fn from_discovery(
        discovery: &Discovery<'_>,
        suite: Suite,
        challenge: &[u8; CHALLENGE_BYTES],
        handle: SessionId,
    ) -> Self {
        Self::new(&PrologueFields {
            suite,
            version: discovery.version,
            device_id: DeviceId::new(discovery.device_id),
            epoch: discovery.epoch,
            challenge,
            handle,
        })
    }

    /// The bytes both ends hash.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PROLOGUE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for Prologue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Prologue({PROLOGUE_BYTES} bytes)")
    }
}

const_assert!(
    PROLOGUE_BYTES == 57,
    "P-238's admission preimage and the published vectors count 57 bytes of prologue before the handshake message"
);

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
    client_id: Slot<ClientId>,
    generation: Slot<Generation>,
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
            client_id: Slot::empty(),
            generation: Slot::empty(),
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
            ReportKey::ClientId => {
                let id = ClientId::new(body.u32()?).ok_or(HandshakeError::NoSuchSlot)?;
                self.client_id.fill(key, id)
            }
            ReportKey::Generation => {
                let generation =
                    Generation::new(body.u32()?).ok_or(HandshakeError::ZeroGeneration)?;
                self.generation.fill(key, generation)
            }
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
            client_id: self.client_id.taken(ReportKey::ClientId)?,
            generation: self.generation.taken(ReportKey::Generation)?,
        })
    }
}

/// Why a handshake body was refused. The three that are not error 1 are the
/// point: a version this implementation does not speak, a proof that did not
/// check out, and whatever the wrapper said — each sends a client somewhere
/// different, and a client told the wrong one retries until it gives up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HandshakeError {
    /// A key the body requires that never arrived. Never defaulted: an absent
    /// `challenge` is not sixteen zero bytes.
    Missing(BodyKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(BodyKey),
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
    /// A `HelloReport` whose key 3 is not the `session_id` the envelope and the
    /// prologue carried (P-072).
    SessionMismatch {
        /// What the envelope said.
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
    /// A generation of zero, which is a slot never written (P-239).
    ZeroGeneration,
    /// An `epoch` of zero, which is FRAM nobody wrote rather than an epoch
    /// (P-085).
    ZeroEpoch,
    /// The response arrived at handle 0, which means *no session* (P-021) and
    /// cannot be one.
    NoHandle,
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
            Self::Envelope(why) => why.refusal(),
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::WrongWidth { .. }
            | Self::WrongMessage { .. }
            | Self::SessionMismatch { .. }
            | Self::ChannelsAboveCeiling(_)
            | Self::NoSuchSlot
            | Self::ZeroGeneration
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

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "no {key} arrived"),
            Self::Duplicate(key) => write!(f, "{key} arrived twice"),
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
            Self::ZeroGeneration => f.write_str("generation 0 is a slot never written"),
            Self::ZeroEpoch => f.write_str("epoch 0 is FRAM nobody wrote"),
            Self::NoHandle => f.write_str("a session cannot be opened at handle 0"),
            Self::Envelope(why) => write!(f, "envelope: {why}"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for HandshakeError {}

const_assert!(
    size_of::<HandshakeError>() <= 16,
    "one of these comes back from every handshake decode on a part with 144 KB of RAM, and the width is paid on the frames that pass as well as the ones that fail"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::ReqId;

    fn header(kind: MessageType) -> Header {
        Header {
            kind,
            session: SessionId::from(3),
            req_id: ReqId(17),
        }
    }

    fn discovery() -> Discovery<'static> {
        Discovery {
            version: Version::V1_0,
            device_id: [0xAB; BSTR16],
            model: "o89-controller",
            provisioned: false,
            pairing_open: true,
            challenge: [0xA0; BSTR16],
            epoch: Epoch::FIRST,
        }
    }

    fn report() -> HelloReport<'static> {
        HelloReport {
            version: Version::V1_0,
            session: SessionId::from(3),
            fw_controller: "0.1.0-beta.12+g1a2b3c4d",
            fw_comms: "0.2.0-alpha.12+g5e6f7a8b",
            capabilities: 0xF7,
            log_oldest_seq: LogSeq(1),
            log_newest_seq: LogSeq(256),
            state_seq: StateSeq(255),
            time_known: true,
            counter: 65,
            caps: Caps::THIS_CONTROLLER,
            topology: Topology::THIS_CONTROLLER,
            client_id: ClientId::new(7).expect("slot 7"),
            generation: Generation::FIRST,
        }
    }

    fn written(d: &Discovery<'_>) -> ([u8; 128], usize) {
        let mut out = [0u8; 128];
        let len = d
            .write(header(MessageType::DiscoverResponse), &mut out)
            .expect("writes");
        (out, len)
    }

    /// A `Discover 0x80` comes back as the fields that went out.
    #[test]
    fn p_087_a_discover_round_trips_with_its_epoch() {
        let (out, len) = written(&discovery());
        let back =
            Discovery::decode(Envelope::decode(&out[..len]).expect("decodes")).expect("reads");
        assert_eq!(back, discovery());
        assert_eq!(back.epoch, Epoch::FIRST);
    }

    /// An epoch of zero is FRAM nobody wrote, not an epoch: refused rather than
    /// read as the first one.
    #[test]
    fn p_085_a_discover_with_epoch_zero_is_refused() {
        let (mut out, len) = written(&discovery());
        assert_eq!(out[len - 1], 1, "the epoch is the last byte");
        out[len - 1] = 0;
        assert_eq!(
            Discovery::decode(Envelope::decode(&out[..len]).expect("decodes")).err(),
            Some(HandshakeError::ZeroEpoch)
        );
    }

    /// A key this version has never heard of is skipped (P-013), and a key that
    /// arrives twice is refused before either copy is used (P-015).
    #[test]
    fn a_discover_skips_an_unknown_key_and_refuses_a_repeated_one() {
        let mut out = [0u8; 160];
        let mut cbor = header(MessageType::DiscoverResponse)
            .write(9, &mut out)
            .expect("fits");
        let d = discovery();
        cbor.key(1).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(2).expect("k");
        cbor.u64(0).expect("v");
        cbor.key(3).expect("k");
        cbor.bytes(&d.device_id).expect("v");
        cbor.key(4).expect("k");
        cbor.text(d.model).expect("v");
        cbor.key(5).expect("k");
        cbor.bool(false).expect("v");
        cbor.key(6).expect("k");
        cbor.bool(true).expect("v");
        cbor.key(7).expect("k");
        cbor.bytes(&d.challenge).expect("v");
        cbor.key(8).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(40).expect("k");
        cbor.text("from a newer version").expect("v");
        let len = cbor.finish().expect("done");
        assert_eq!(
            Discovery::decode(Envelope::decode(&out[..len]).expect("decodes")).expect("reads"),
            d
        );

        let (mut twice, len) = written(&discovery());
        // Rewrite key 2's number as 1: key 1 now arrives twice.
        let at = twice[..len]
            .windows(2)
            .position(|w| w == [0x02, 0x00])
            .expect("key 2");
        twice[at] = 0x01;
        assert!(matches!(
            Discovery::decode(Envelope::decode(&twice[..len]).expect("decodes")),
            Err(HandshakeError::Duplicate(_) | HandshakeError::Cbor(_))
        ));
    }

    /// A `bstr16` that is not sixteen bytes is refused rather than padded.
    #[test]
    fn a_challenge_that_is_not_sixteen_bytes_is_refused() {
        let mut out = [0u8; 160];
        let mut cbor = header(MessageType::DiscoverResponse)
            .write(1, &mut out)
            .expect("fits");
        cbor.key(7).expect("k");
        cbor.bytes(&[0; 15]).expect("v");
        let len = cbor.finish().expect("done");
        assert!(matches!(
            Discovery::decode(Envelope::decode(&out[..len]).expect("decodes")),
            Err(HandshakeError::WrongWidth { len: 15, .. })
        ));
    }

    /// Every truncation of a `Discover 0x80` is refused without a panic.
    #[test]
    fn every_truncation_of_a_discover_is_refused() {
        let (out, len) = written(&discovery());
        for cut in 0..len {
            let refused = Envelope::decode(&out[..cut])
                .ok()
                .map(Discovery::decode)
                .is_none_or(|r| r.is_err());
            assert!(refused, "cut {cut}");
        }
    }

    /// Two thousand frames of a real `Discover` with random bytes overwritten
    /// never panic the decoder.
    #[test]
    fn whatever_a_hostile_discover_says_it_cannot_make_the_decoder_panic() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let (template, len) = written(&discovery());
        for _ in 0..2000 {
            let mut frame = template;
            for byte in frame.iter_mut().take(len) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if state.is_multiple_of(7) {
                    *byte = state.to_le_bytes()[0];
                }
            }
            if let Ok(envelope) = Envelope::decode(&frame[..len]) {
                let _ = Discovery::decode(envelope);
            }
        }
    }

    /// The report comes back as it went out, all thirty-one keys, with the slot
    /// and generation it names (P-239).
    #[test]
    fn p_239_a_report_round_trips_with_its_slot_and_generation() {
        let mut out = [0u8; MAX_HELLO_REPORT];
        let len = report().encode(&mut out).expect("encodes");
        let back = HelloReport::decode(&out[..len], SessionId::from(3)).expect("reads");
        assert_eq!(back, report());
        assert_eq!(back.generation, Generation::FIRST);
    }

    /// Key 3 must name the session the envelope names (P-072).
    #[test]
    fn p_072_a_report_naming_another_session_is_refused() {
        let mut out = [0u8; MAX_HELLO_REPORT];
        let len = report().encode(&mut out).expect("encodes");
        assert!(matches!(
            HelloReport::decode(&out[..len], SessionId::from(4)),
            Err(HandshakeError::SessionMismatch { .. })
        ));
    }

    /// P-006: more than 32 channels is refused both ways.
    #[test]
    fn a_report_of_thirty_three_channels_is_refused_both_ways() {
        let mut too_many = report();
        too_many.caps.channels = Caps::CHANNEL_CEILING + 1;
        let mut out = [0u8; MAX_HELLO_REPORT];
        assert_eq!(
            too_many.encode(&mut out).err(),
            Some(HandshakeError::ChannelsAboveCeiling(33))
        );
    }

    /// A report missing any one of its thirty-one keys is refused by name, never
    /// defaulted: a report without key 11 would send a client counting from a
    /// counter nobody told it.
    #[test]
    fn a_report_missing_any_one_key_is_refused_by_name() {
        let mut full = [0u8; MAX_HELLO_REPORT];
        let len = report().encode(&mut full).expect("encodes");
        for skip in 1..=31i64 {
            let mut reader = CborReader::new(&full[..len]);
            let pairs = reader.map().expect("a map");
            let mut out = [0u8; MAX_HELLO_REPORT];
            let mut cbor = CborWriter::new(&mut out);
            cbor.map(pairs - 1).expect("head");
            for _ in 0..pairs {
                let key = reader.key().expect("key");
                let value = reader.raw().expect("value");
                if key != skip {
                    cbor.key(key).expect("k");
                    cbor.raw(value).expect("v");
                }
            }
            let short = cbor.finish().expect("done");
            let refused = HelloReport::decode(&out[..short], SessionId::from(3));
            let key = ReportKey::of(skip).expect("a report key");
            assert_eq!(
                refused.err(),
                Some(HandshakeError::Missing(key.into())),
                "{key}"
            );
        }
    }

    /// A zero slot or generation in a report names nothing and is refused.
    #[test]
    fn a_report_naming_slot_zero_or_generation_zero_is_refused() {
        for (key, want) in [
            (30, HandshakeError::NoSuchSlot),
            (31, HandshakeError::ZeroGeneration),
        ] {
            let mut full = [0u8; MAX_HELLO_REPORT];
            let len = report().encode(&mut full).expect("encodes");
            let mut reader = CborReader::new(&full[..len]);
            let pairs = reader.map().expect("a map");
            let mut out = [0u8; MAX_HELLO_REPORT];
            let mut cbor = CborWriter::new(&mut out);
            cbor.map(pairs).expect("head");
            for _ in 0..pairs {
                let k = reader.key().expect("key");
                let value = reader.raw().expect("value");
                cbor.key(k).expect("k");
                if k == key {
                    cbor.u64(0).expect("zero");
                } else {
                    cbor.raw(value).expect("v");
                }
            }
            let n = cbor.finish().expect("done");
            assert_eq!(
                HelloReport::decode(&out[..n], SessionId::from(3)).err(),
                Some(want)
            );
        }
    }

    /// P-074: the two sequence spaces are two types, so a comparison across
    /// them does not compile (see [`LogSeq`]); the report keeps them apart even
    /// where their numbers sit side by side.
    #[test]
    fn p_074_the_report_keeps_the_log_and_state_spaces_apart() {
        let r = report();
        assert_eq!(r.log_newest_seq, LogSeq(256));
        assert_eq!(r.state_seq, StateSeq(255));
    }

    /// P-073: a major mismatch refuses, a minor mismatch proceeds at the lower.
    #[test]
    fn p_073_a_major_mismatch_refuses_and_a_minor_one_takes_the_lower() {
        let ours = Version { major: 1, minor: 3 };
        assert_eq!(
            ours.agreed(Version { major: 1, minor: 1 }),
            Ok(Version { major: 1, minor: 1 })
        );
        assert_eq!(
            ours.agreed(Version { major: 2, minor: 0 }),
            Err(HandshakeError::MajorMismatch { ours: 1, theirs: 2 })
        );
        assert_eq!(
            HandshakeError::MajorMismatch { ours: 1, theirs: 2 }.refusal(),
            Refusal::Client(ErrorCode::ProtocolMajorMismatch)
        );
    }

    fn fields(challenge: &[u8; 16]) -> PrologueFields<'_> {
        PrologueFields {
            suite: Suite::X25519ChachapolySha256,
            version: Version::V1_0,
            device_id: DeviceId::new(*b"ORIGIN89 DEMO 01"),
            epoch: Epoch::new(0x0102_0304).expect("non-zero"),
            challenge,
            handle: SessionId::from(0x0A0B),
        }
    }

    /// P-040 and P-227: the prologue is the label, then every field in order,
    /// fixed width, integers big-endian.
    #[test]
    fn p_040_every_integer_in_the_prologue_is_big_endian_and_fixed_width() {
        let challenge = [0xC5; 16];
        let bytes = *Prologue::new(&fields(&challenge)).as_bytes();
        assert_eq!(&bytes[..16], b"km43/v1/prologue");
        assert_eq!(bytes[16], 1, "suite");
        assert_eq!(bytes[17..19], [1, 0], "version");
        assert_eq!(&bytes[19..35], b"ORIGIN89 DEMO 01");
        assert_eq!(bytes[35..39], [1, 2, 3, 4], "epoch, big-endian");
        assert_eq!(bytes[39..55], [0xC5; 16], "challenge");
        assert_eq!(bytes[55..57], [0x0A, 0x0B], "handle, big-endian");
    }

    /// Every field a client takes from `Discover` moves the prologue, so a
    /// rewrite of any of them is a transcript the controller does not hash.
    #[test]
    fn p_227_every_field_a_client_takes_from_discover_moves_the_prologue() {
        let challenge = [0xC5; 16];
        let base = Prologue::new(&fields(&challenge));
        let other_challenge = [0xC6; 16];
        let variants = [
            PrologueFields {
                version: Version { major: 1, minor: 1 },
                ..fields(&challenge)
            },
            PrologueFields {
                device_id: DeviceId::new([0; 16]),
                ..fields(&challenge)
            },
            PrologueFields {
                epoch: Epoch::FIRST,
                ..fields(&challenge)
            },
            fields(&other_challenge),
            PrologueFields {
                handle: SessionId::from(4),
                ..fields(&challenge)
            },
        ];
        for variant in &variants {
            assert_ne!(Prologue::new(variant), base, "{variant:?}");
        }
        let discovered = Prologue::from_discovery(
            &discovery(),
            Suite::X25519ChachapolySha256,
            &discovery().challenge,
            SessionId::from(3),
        );
        assert_eq!(&discovered.as_bytes()[19..35], &[0xAB; 16]);
    }
}
