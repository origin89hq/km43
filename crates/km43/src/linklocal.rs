//! What a receiver does with a link-local frame before it means anything.
//!
//! Three refusals, and each one is a bug in the *sender's* firmware rather than
//! anything a client did. They go back to the side whose bug it is, where
//! somebody can act on them.
//!
//! An opcode the receiver does not know and an opcode from the side the
//! direction column does not permit are **the same code**. The comms processor
//! answering `ClientConnected` at the controller is a bug in the comms
//! processor, and a controller accepting a `CommsRelease` from its own peer has
//! lost the plot about who authorises firmware — but from the receiver's side
//! both are a frame it has no business acting on, so one code covers both and
//! neither firmware has to decide which kind of wrong it is looking at.
//!
//! A link-local frame carries `session_id = 0` always. Session 0 means *the
//! link itself, not a client*, and a connection handle is never 0, so the two
//! uses cannot collide — which is what makes a non-zero session decidable as a
//! controller bug without knowing anything else about the frame. Routing that
//! frame instead delivers a message about the link to whichever unlucky client
//! owns that session number.
//!
//! Nothing about the envelope, the framing or the size limits changes here. A
//! link-local body missing a required key fails exactly the way a client body
//! does, which is why this module holds no parser of its own.

use core::fmt;

use crate::cbor::CborError;
use crate::envelope::SessionId;
use crate::envelope::{LinkEnvelope, LinkHeader};
use crate::generated::{
    ClientConnected, ClientDisconnected, CloseConnection, CloseReason, DisconnectReason,
    LinkDirection, LinkErrorCode, LinkMessageType, LinkTransport, NetConfig, NetConfigOp,
    TimeOffer,
};
use crate::handshake::Version;
use crate::limits::MAX_LINK_TEXT;

impl LinkErrorCode {
    /// Whether this code may be put in front of a client.
    ///
    /// **Three of the nine may and six must not** (L-180). The three are the
    /// ones a client's own frame raised, and it can act on each: it sent a
    /// link-local `type`, it connected before the two firmwares had exchanged
    /// `LinkUp`, or it is holding a handle nobody has. The other six are the two
    /// firmwares talking about each other — a version mismatch between them, a
    /// full connection table, an unauthorised release — and a browser shown one
    /// learns something true about a machine it is not talking to and nothing at
    /// all about its own request.
    ///
    /// Exhaustive on purpose: a tenth code has to be classified here or the
    /// build stops, which is the compiler asking the one question that matters
    /// about a new link error.
    #[must_use]
    pub const fn reaches_a_client(self) -> bool {
        match self {
            Self::LinkTypeOnClientTransport | Self::BeforeLinkUp | Self::UnknownHandle => true,
            Self::WrongSide
            | Self::ConnectionTableFull
            | Self::LinkMajorMismatch
            | Self::TooManyOutstanding
            | Self::NonZeroSession
            | Self::NoAuthorisation => false,
        }
    }
}

/// Which firmware is reading the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The STM32.
    Controller,
    /// The ESP32-C6.
    Comms,
}

impl Side {
    /// The number this side goes out as in `LinkUp` key 3.
    ///
    /// An exhaustive match rather than a constant, so a third role breaks the
    /// build here instead of going out as a number somebody guessed. **The
    /// registry does not allocate this space** — LINK.md states the two values
    /// inline and `REGISTRY.md` has no `link_role` table — so this match is the
    /// only place they are written down, which is worth fixing there rather
    /// than here.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Controller => 1,
            Self::Comms => 2,
        }
    }

    /// The side a `LinkUp` says it is.
    ///
    /// # Errors
    /// A role this version does not allocate. P-014: an unknown discriminant in
    /// a field that decides behaviour is refused, never defaulted — a `LinkUp`
    /// from something claiming to be neither chip is not a peer to guess about.
    pub const fn of(number: u8) -> Result<Self, LinkError> {
        match number {
            1 => Ok(Self::Controller),
            2 => Ok(Self::Comms),
            other => Err(LinkError::UnknownRole(other)),
        }
    }

    /// The other end of the cable.
    const fn other(self) -> Self {
        match self {
            Self::Controller => Self::Comms,
            Self::Comms => Self::Controller,
        }
    }

    /// Which side starts an exchange travelling this way.
    const fn starting(direction: LinkDirection) -> Option<Self> {
        match direction {
            LinkDirection::Either => None,
            LinkDirection::CommsToController => Some(Self::Comms),
            LinkDirection::ControllerToComms => Some(Self::Controller),
        }
    }
}

/// What a receiver does with the frame in front of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intake {
    /// Act on it.
    Act(LinkMessageType),
    /// Refuse it with this code, back to the side that sent it.
    Refuse(LinkErrorCode),
}

/// Read a link-local frame's envelope, deciding whether it may be acted on.
///
/// `opcode` is the raw byte, so an opcode this build does not know is refused
/// here rather than becoming an unreachable arm somewhere downstream.
///
/// The order is deliberate: the opcode has to be known before its direction can
/// be asked about, and a frame from the wrong side is refused whatever its
/// session carried — a receiver that reported the session problem first would
/// send the peer to look at the wrong field.
#[must_use]
pub fn arriving(opcode: u8, at: Side, session: SessionId) -> Intake {
    let Ok(kind) = LinkMessageType::try_from(opcode) else {
        return Intake::Refuse(LinkErrorCode::WrongSide);
    };
    if !permitted(kind, at) {
        return Intake::Refuse(LinkErrorCode::WrongSide);
    }
    if session != SessionId::None {
        return Intake::Refuse(LinkErrorCode::NonZeroSession);
    }
    Intake::Act(kind)
}

/// Whether this side may receive that message.
///
/// The direction column says **who starts the exchange**, which is why the
/// generated table gives a message and its `Ack` the same answer. The two are
/// then received by *opposite* sides: the request crosses the cable, and the
/// acknowledgement comes back to whoever asked.
///
/// The version of this that read the column as *who sends it* refused every ack
/// at the only side that could receive one — a comms processor could not take
/// the answer to its own `ClientConnected`, and L-080 makes it wait for exactly
/// that before it may reuse a handle. The test in place counted how many sides
/// received each opcode and never asked which, so one was always the answer and
/// it was always the wrong one.
fn permitted(kind: LinkMessageType, at: Side) -> bool {
    let Some(started) = Side::starting(kind.direction()) else {
        return true;
    };
    if is_ack(kind) {
        at == started
    } else {
        at == started.other()
    }
}

/// Whether an opcode is an acknowledgement, read off its high bit.
///
/// The same rule as P-020 one range over: `LinkUp 0x60` answers as
/// `LinkUpAck 0xE0`. Read off the number rather than off a name, because a name
/// is a convention nobody checks and the bit is what a receiver has in hand.
const fn is_ack(kind: LinkMessageType) -> bool {
    (kind as u8) & 0x80 != 0
}

/// Which field of a link-local body a refusal is about, so a bench log names a
/// field rather than an offset.
///
/// **One enum across every body on this link, not one per body.** The key
/// *numbers* differ from body to body — key 1 is `protocol_major` in a `LinkUp`
/// and `conn` in a `ClientDisconnected` — so a per-body enum would have to be
/// mapped to a name anyway, and the version of this that was named for `LinkUp`
/// alone got reused by all six other bodies with whatever variant was nearest.
/// A missing `conn` reported `role`, a missing `psk` reported `fw`, and a
/// missing `country` reported `hw`, which is the failure this type exists to
/// prevent doing its opposite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkField {
    ProtocolMajor,
    ProtocolMinor,
    Role,
    Fw,
    BootId,
    Hw,
    NetVersion,
    /// A connection handle. Never 0 on a `ClientConnected`; 0 means *all* on a
    /// `CloseConnection`.
    Conn,
    Uptime,
    Conns,
    Transport,
    Peer,
    Reason,
    Outcome,
    /// How many a `CloseReport` actually closed. Never defaulted.
    Closed,
    Op,
    Ssid,
    Psk,
    Country,
    Hostname,
    UnixMs,
    Source,
    AccuracyMs,
    Server,
}

impl fmt::Display for LinkField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProtocolMajor => "protocol_major",
            Self::ProtocolMinor => "protocol_minor",
            Self::Role => "role",
            Self::Fw => "fw",
            Self::BootId => "boot_id",
            Self::Hw => "hw",
            Self::NetVersion => "net_version",
            Self::Conn => "conn",
            Self::Uptime => "uptime_s",
            Self::Conns => "conns",
            Self::Transport => "transport",
            Self::Peer => "peer",
            Self::Reason => "reason",
            Self::Outcome => "outcome",
            Self::Closed => "closed",
            Self::Op => "op",
            Self::Ssid => "ssid",
            Self::Psk => "psk",
            Self::Country => "country",
            Self::Hostname => "hostname",
            Self::UnixMs => "unix_ms",
            Self::Source => "source",
            Self::AccuracyMs => "accuracy_ms",
            Self::Server => "server",
        })
    }
}

/// Why a link-local body would not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// A required key that never arrived. Never defaulted: an absent `boot_id`
    /// is not zero, and a zero one would compare equal across a reboot.
    Missing(LinkField),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(LinkField),
    /// A `role` this version does not allocate (P-014).
    UnknownRole(u8),
    /// A text field past [`MAX_LINK_TEXT`], carrying what arrived.
    TooLong {
        /// Which field.
        key: LinkField,
        /// How many bytes came.
        len: usize,
    },
    /// `net_version` from the controller, which only the comms processor sends.
    NetVersionFromController,
    /// A `conn` of 0 where a handle is required. L-060 never allocates 0, so it
    /// names no connection — except in `CloseConnection`, where it deliberately
    /// names every one.
    NoSuchConnection,
    /// A `transport` this version does not allocate (P-014).
    UnknownTransport(u8),
    /// A `reason` this version does not allocate (P-014).
    UnknownReason(u8),
    /// An `outcome` this version does not allocate (P-014).
    UnknownOutcome(u8),
    /// An `op` this version does not allocate (P-014).
    UnknownOp(u8),
    /// A passphrase outside WPA's own 8 to 63 bytes (L-131).
    PassphraseLength(usize),
    /// A `country` that is not ISO 3166-1 alpha-2.
    CountryNotTwoBytes(usize),
    /// A `clear` carrying an `ssid` or a `psk`, which L-131 forbids.
    ClearCarriedCredentials,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for LinkError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "link-up carries no {key}"),
            Self::Duplicate(key) => write!(f, "link-up carries {key} twice"),
            Self::UnknownRole(role) => write!(f, "role {role} is not allocated"),
            Self::TooLong { key, len } => {
                write!(f, "{key} is {len} bytes, past the {MAX_LINK_TEXT} allowed")
            }
            Self::NetVersionFromController => {
                f.write_str("net_version arrived from the controller, and only comms sends it")
            }
            Self::NoSuchConnection => f.write_str("conn 0 names no connection"),
            Self::UnknownTransport(raw) => write!(f, "transport {raw} is not allocated"),
            Self::UnknownReason(raw) => write!(f, "reason {raw} is not allocated"),
            Self::UnknownOutcome(raw) => write!(f, "outcome {raw} is not allocated"),
            Self::UnknownOp(raw) => write!(f, "op {raw} is not allocated"),
            Self::PassphraseLength(len) => {
                write!(f, "a passphrase of {len} bytes is outside 8 to 63")
            }
            Self::CountryNotTwoBytes(len) => {
                write!(f, "a country of {len} bytes is not alpha-2")
            }
            Self::ClearCarriedCredentials => {
                f.write_str("a clear carried credentials, which is what it exists to remove")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for LinkError {}

/// `LinkUp 0x60` / `0xE0` — who each chip is, and which boot it is on.
///
/// A mutual statement rather than a query: whoever comes up first says who it
/// is, and the answer says who the other one is. Both directions carry the same
/// fields except `net_version`, which only the comms processor sends.
///
/// **`boot_id` is the field that matters.** What tears every connection down is
/// a *changed* one, not the arrival of this message (L-030, L-042) — so a
/// resend costs nothing and a reboot costs every client a reconnect, which is
/// the correct way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkUp<'a> {
    /// Keys 1 and 2.
    pub version: Version,
    /// Key 3.
    pub role: Side,
    /// Key 4, this sender's own firmware version. The controller stores it and
    /// reports it as `fw_comms` in every client `Hello` (L-031).
    pub fw: &'a str,
    /// Key 5, redrawn randomly on every boot.
    pub boot_id: u32,
    /// Key 6, board revision.
    pub hw: &'a str,
    /// Key 7, comms only: the credential version it has cached, 0 if none.
    pub net_version: Option<u32>,
}

impl<'a> LinkUp<'a> {
    /// How many keys a `LinkUp` carries. Six when `net_version` is absent,
    /// which is every one the controller sends.
    const KEYS: usize = 7;

    /// Write the whole envelope and hand back its length.
    ///
    /// # Errors
    /// A text field past the cap, a `net_version` from the controller, or a
    /// `dst` that will not hold it.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        bounded(LinkField::Fw, self.fw)?;
        bounded(LinkField::Hw, self.hw)?;
        if self.net_version.is_some() && matches!(self.role, Side::Controller) {
            return Err(LinkError::NetVersionFromController);
        }
        let keys = if self.net_version.is_some() {
            LinkUp::KEYS
        } else {
            LinkUp::KEYS - 1
        };
        let mut cbor = header
            .write(keys, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.version.major))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.version.minor))?;
        cbor.key(3)?;
        cbor.u64(u64::from(self.role.number()))?;
        cbor.key(4)?;
        cbor.text(self.fw)?;
        cbor.key(5)?;
        cbor.u64(u64::from(self.boot_id))?;
        cbor.key(6)?;
        cbor.text(self.hw)?;
        if let Some(net_version) = self.net_version {
            cbor.key(7)?;
            cbor.u64(u64::from(net_version))?;
        }
        Ok(cbor.finish()?)
    }

    /// Read one out of a link-local envelope.
    ///
    /// A key beside the seven is skipped (P-013): an unknown extra field is a
    /// newer peer being chatty. An unknown `role` is not — that is P-014, and it
    /// is refused.
    ///
    /// # Errors
    /// A required key absent, a key twice, a role or a length this version does
    /// not take, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'a>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut major = None;
        let mut minor = None;
        let mut role = None;
        let mut fw = None;
        let mut boot_id = None;
        let mut hw = None;
        let mut net_version = None;

        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut major, LinkField::ProtocolMajor, body.u8()?)?,
                2 => once(&mut minor, LinkField::ProtocolMinor, body.u8()?)?,
                3 => once(&mut role, LinkField::Role, Side::of(body.u8()?)?)?,
                4 => {
                    let text = bounded(LinkField::Fw, body.text()?)?;
                    once(&mut fw, LinkField::Fw, text)?;
                }
                5 => once(&mut boot_id, LinkField::BootId, body.u32()?)?,
                6 => {
                    let text = bounded(LinkField::Hw, body.text()?)?;
                    once(&mut hw, LinkField::Hw, text)?;
                }
                7 => once(&mut net_version, LinkField::NetVersion, body.u32()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;

        let role = role.ok_or(LinkError::Missing(LinkField::Role))?;
        if net_version.is_some() && matches!(role, Side::Controller) {
            return Err(LinkError::NetVersionFromController);
        }
        Ok(Self {
            version: Version {
                major: major.ok_or(LinkError::Missing(LinkField::ProtocolMajor))?,
                minor: minor.ok_or(LinkError::Missing(LinkField::ProtocolMinor))?,
            },
            role,
            fw: fw.ok_or(LinkError::Missing(LinkField::Fw))?,
            boot_id: boot_id.ok_or(LinkError::Missing(LinkField::BootId))?,
            hw: hw.ok_or(LinkError::Missing(LinkField::Hw))?,
            net_version,
        })
    }
}

/// Refuse a text field past the cap where it is read, rather than where it is
/// stored.
fn bounded(key: LinkField, text: &str) -> Result<&str, LinkError> {
    if text.len() > MAX_LINK_TEXT {
        return Err(LinkError::TooLong {
            key,
            len: text.len(),
        });
    }
    Ok(text)
}

/// Fill a slot once, refusing the second copy before either is used (P-015).
fn once<T>(slot: &mut Option<T>, key: LinkField, value: T) -> Result<(), LinkError> {
    if slot.is_some() {
        return Err(LinkError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// `Heartbeat 0x61` / `0xE1` — each side saying it is still there, and what it
/// believes the connection table holds.
///
/// `conns` is the number that makes a resync possible: the two sides can
/// disagree about how many connections exist, and this is the only place either
/// finds out (L-120).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    /// Key 1, seconds since this side's boot, saturating.
    pub uptime_s: u32,
    /// Key 2, allocated connection rows this side believes are live.
    pub conns: u8,
}

impl Heartbeat {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut cbor = header
            .write(2, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.uptime_s))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.conns))?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// A required key absent, a key twice, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut uptime_s = None;
        let mut conns = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut uptime_s, LinkField::Uptime, body.u32()?)?,
                2 => once(&mut conns, LinkField::Conns, body.u8()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            uptime_s: uptime_s.ok_or(LinkError::Missing(LinkField::Uptime))?,
            conns: conns.ok_or(LinkError::Missing(LinkField::Conns))?,
        })
    }
}

/// `ClientConnected 0x62` — a transport came up, and the handle the comms
/// processor allocated for it.
///
/// Named `ClientUp` rather than after the message, because the registry already
/// gives that name to the **outcome** enum its ack carries. The same split as
/// `PairRequest` beside `Pair`: a body and the numbers its answer chooses from
/// are two things, and one name for both is how somebody reaches for the wrong
/// one.
///
/// The comms processor allocates every handle itself (L-060), so this is a
/// statement rather than a request: it is the thing that accepts and drops
/// transports, so it is the thing that knows when one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientUp<'a> {
    /// Key 1. Never 0 — that names no connection (L-060).
    pub conn: u16,
    /// Key 2.
    pub transport: LinkTransport,
    /// Key 3: a BLE address, an IP, a cloud account. Shown to a person and
    /// never branched on.
    pub peer: &'a str,
}

impl<'a> ClientUp<'a> {
    /// # Errors
    /// A `conn` of 0, a `peer` past [`MAX_STRING`](crate::MAX_STRING), or a `dst` too small.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        if self.conn == 0 {
            return Err(LinkError::NoSuchConnection);
        }
        let mut cbor = header
            .write(3, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.conn))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.transport as u8))?;
        cbor.key(3)?;
        cbor.text(self.peer)?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// A `conn` of 0, a transport this version does not allocate (P-014), a
    /// required key absent, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'a>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut conn = None;
        let mut transport = None;
        let mut peer = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut conn, LinkField::Conn, body.u16()?)?,
                2 => {
                    let raw = body.u8()?;
                    let kind = LinkTransport::try_from(raw)
                        .map_err(|()| LinkError::UnknownTransport(raw))?;
                    once(&mut transport, LinkField::Transport, kind)?;
                }
                3 => once(&mut peer, LinkField::Peer, body.text()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;
        let conn = conn.ok_or(LinkError::Missing(LinkField::Conn))?;
        // Checked on the way in as well as on the way out. The peer that
        // allocates handles is the one this protocol treats as hostile, so an
        // encoder-side check protects nobody on its own.
        if conn == 0 {
            return Err(LinkError::NoSuchConnection);
        }
        Ok(Self {
            conn,
            transport: transport.ok_or(LinkError::Missing(LinkField::Transport))?,
            peer: peer.ok_or(LinkError::Missing(LinkField::Peer))?,
        })
    }
}

/// `ClientDisconnected 0x63` — a transport went away, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDown {
    /// Key 1, the handle that is going. Never 0.
    pub conn: u16,
    /// Key 2.
    pub reason: DisconnectReason,
}

impl ClientDown {
    /// # Errors
    /// A `conn` of 0, or a `dst` too small.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        if self.conn == 0 {
            return Err(LinkError::NoSuchConnection);
        }
        let mut cbor = header
            .write(2, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.conn))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.reason as u8))?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// A `conn` of 0, a reason this version does not allocate, a key absent, or
    /// CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut conn = None;
        let mut reason = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut conn, LinkField::Conn, body.u16()?)?,
                2 => {
                    let raw = body.u8()?;
                    let why = DisconnectReason::try_from(raw)
                        .map_err(|()| LinkError::UnknownReason(raw))?;
                    once(&mut reason, LinkField::Reason, why)?;
                }
                _ => body.skip()?,
            }
        }
        body.finish()?;
        let conn = conn.ok_or(LinkError::Missing(LinkField::Conn))?;
        if conn == 0 {
            return Err(LinkError::NoSuchConnection);
        }
        Ok(Self {
            conn,
            reason: reason.ok_or(LinkError::Missing(LinkField::Reason))?,
        })
    }
}

/// `CloseConnection 0x64` — the controller telling the comms processor to drop
/// one connection, or every one.
///
/// **`conn = 0` means every connection here**, which is the opposite of what it
/// means on [`ClientUp`]. That is deliberate: it is what the heartbeat resync
/// sends when the two sides disagree about the table, and there is no other way
/// to say *all of them* in one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseConnections {
    /// Key 1. **0 names every connection**, not none.
    pub conn: u16,
    /// Key 2.
    pub reason: CloseReason,
}

impl CloseConnections {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut cbor = header
            .write(2, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.conn))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.reason as u8))?;
        Ok(cbor.finish()?)
    }

    /// Whether this asks for the whole table.
    #[must_use]
    pub const fn is_every_connection(&self) -> bool {
        self.conn == 0
    }

    /// # Errors
    /// A reason this version does not allocate, a key absent, or CBOR that will
    /// not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut conn = None;
        let mut reason = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut conn, LinkField::Conn, body.u16()?)?,
                2 => {
                    let raw = body.u8()?;
                    let why =
                        CloseReason::try_from(raw).map_err(|()| LinkError::UnknownReason(raw))?;
                    once(&mut reason, LinkField::Reason, why)?;
                }
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            conn: conn.ok_or(LinkError::Missing(LinkField::Conn))?,
            reason: reason.ok_or(LinkError::Missing(LinkField::Reason))?,
        })
    }
}

/// `CloseConnectionAck 0xE4` — what happened, and **how many**.
///
/// Named `CloseReport` because `Closed` is already taken, by `o89-core`'s
/// session closing. The third name collision in this module and the third time
/// the compiler has been the one to notice: a link message and the thing it
/// causes are close enough in English to want the same word, and far enough
/// apart in code that sharing one would be a bug waiting.
///
/// The count is the only way the controller learns whether the table it
/// believed in matched the one that existed (L-090). An ack without it would
/// answer *closed* to a resync that closed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseReport {
    /// Key 1.
    pub outcome: CloseConnection,
    /// Key 2, how many were actually closed.
    pub closed: u8,
}

impl CloseReport {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut cbor = header
            .write(2, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.outcome as u8))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.closed))?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// An outcome this version does not allocate, a key absent, or CBOR that
    /// will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut outcome = None;
        let mut closed = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => {
                    let raw = body.u8()?;
                    let said = CloseConnection::try_from(raw)
                        .map_err(|()| LinkError::UnknownOutcome(raw))?;
                    once(&mut outcome, LinkField::Outcome, said)?;
                }
                2 => once(&mut closed, LinkField::Closed, body.u8()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            outcome: outcome.ok_or(LinkError::Missing(LinkField::Outcome))?,
            // **Never defaulted.** A missing count read as zero says the resync
            // closed nothing, which is indistinguishable from a table that was
            // already empty — and those want opposite reactions.
            closed: closed.ok_or(LinkError::Missing(LinkField::Closed))?,
        })
    }
}

/// `NetConfig 0x65` — the controller handing the comms processor the network to
/// join, or telling it to forget one.
///
/// **A `clear` carries neither the passphrase nor the network name (L-131).**
/// The passphrase for the obvious reason: putting it on the internal link one
/// more time to accomplish its own deletion is the opposite of deleting it. The
/// name for a duller one — a controller sending a clear may hold no network to
/// name, and an empty string in that field would be a value meaning *no
/// network* rather than the absence of a field.
///
/// So the two shapes are two variants rather than one struct with four options,
/// and a `clear` that carries credentials is not something a caller can build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetChange<'a> {
    /// Join this network.
    Set {
        /// Key 2, the controller's config version for this section.
        version: u32,
        /// Key 3, at most [`MAX_LINK_TEXT`].
        ssid: &'a str,
        /// Key 4, 8 to 63 bytes (L-131).
        psk: &'a str,
        /// Key 5, exactly two bytes, ISO 3166-1 alpha-2.
        country: &'a str,
        /// Key 6, at most [`MAX_LINK_TEXT`].
        hostname: &'a str,
    },
    /// Forget whatever is stored.
    Clear {
        /// Key 2.
        version: u32,
        /// Key 5.
        country: &'a str,
        /// Key 6.
        hostname: &'a str,
    },
}

/// The passphrase bounds L-131 fixes, which are WPA's own.
const PSK_SHORTEST: usize = 8;
const PSK_LONGEST: usize = 63;
/// ISO 3166-1 alpha-2, and there is no other length.
const COUNTRY_BYTES: usize = 2;

impl<'a> NetChange<'a> {
    /// # Errors
    /// A passphrase outside L-131's bounds, a country that is not two bytes, a
    /// text field past the cap, or a `dst` too small.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let (op, version, country, hostname) = match self {
            Self::Set {
                version,
                country,
                hostname,
                ..
            } => (NetConfigOp::Set, version, country, hostname),
            Self::Clear {
                version,
                country,
                hostname,
            } => (NetConfigOp::Clear, version, country, hostname),
        };
        if country.len() != COUNTRY_BYTES {
            return Err(LinkError::CountryNotTwoBytes(country.len()));
        }
        bounded(LinkField::Hostname, hostname)?;

        let keys = match self {
            Self::Set { ssid, psk, .. } => {
                bounded(LinkField::Ssid, ssid)?;
                if psk.len() < PSK_SHORTEST || psk.len() > PSK_LONGEST {
                    return Err(LinkError::PassphraseLength(psk.len()));
                }
                6
            }
            Self::Clear { .. } => 4,
        };

        let mut cbor = header
            .write(keys, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(u64::from(op as u8))?;
        cbor.key(2)?;
        cbor.u64(u64::from(*version))?;
        if let Self::Set { ssid, psk, .. } = self {
            cbor.key(3)?;
            cbor.text(ssid)?;
            cbor.key(4)?;
            cbor.text(psk)?;
        }
        cbor.key(5)?;
        cbor.text(country)?;
        cbor.key(6)?;
        cbor.text(hostname)?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// A `clear` carrying credentials, an `op` this version does not allocate, a
    /// key absent, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'a>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut op = None;
        let mut version = None;
        let mut ssid = None;
        let mut psk = None;
        let mut country = None;
        let mut hostname = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => {
                    let raw = body.u8()?;
                    let which =
                        NetConfigOp::try_from(raw).map_err(|()| LinkError::UnknownOp(raw))?;
                    once(&mut op, LinkField::Op, which)?;
                }
                2 => once(&mut version, LinkField::NetVersion, body.u32()?)?,
                3 => once(&mut ssid, LinkField::Ssid, body.text()?)?,
                4 => once(&mut psk, LinkField::Psk, body.text()?)?,
                5 => once(&mut country, LinkField::Country, body.text()?)?,
                6 => once(&mut hostname, LinkField::Hostname, body.text()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;

        let version = version.ok_or(LinkError::Missing(LinkField::NetVersion))?;
        let country = country.ok_or(LinkError::Missing(LinkField::Country))?;
        if country.len() != COUNTRY_BYTES {
            return Err(LinkError::CountryNotTwoBytes(country.len()));
        }
        let hostname = bounded(
            LinkField::Hostname,
            hostname.ok_or(LinkError::Missing(LinkField::Hostname))?,
        )?;

        match op.ok_or(LinkError::Missing(LinkField::Op))? {
            NetConfigOp::Set => {
                let psk = psk.ok_or(LinkError::Missing(LinkField::Psk))?;
                if psk.len() < PSK_SHORTEST || psk.len() > PSK_LONGEST {
                    return Err(LinkError::PassphraseLength(psk.len()));
                }
                Ok(Self::Set {
                    version,
                    ssid: bounded(
                        LinkField::Ssid,
                        ssid.ok_or(LinkError::Missing(LinkField::Ssid))?,
                    )?,
                    psk,
                    country,
                    hostname,
                })
            }
            // **Refused, not ignored.** A `clear` that arrived carrying a
            // passphrase already put it on the link; reading past it would make
            // this end complicit in the thing L-131 forbids, and the sender is
            // the one that needs to hear about it.
            NetConfigOp::Clear => {
                if ssid.is_some() || psk.is_some() {
                    return Err(LinkError::ClearCarriedCredentials);
                }
                Ok(Self::Clear {
                    version,
                    country,
                    hostname,
                })
            }
        }
    }
}

/// `TimeOffer 0x66` — the comms processor telling the controller what NTP says.
///
/// Named `ClockOffer` because the registry already gives the bare `TimeOffer`
/// to the **outcome** enum, the same split as `CloseConnections` beside
/// `CloseConnection` and `NetChange` beside `NetConfig`.
///
/// **An offer, not a set.** Every rule that matters is on the answering side —
/// the monotonic floor (L-140), the 5-second cap once the clock is known
/// (L-150), and one offer per 15 minutes (L-151). This type carries the numbers
/// and refuses nothing but a `server` longer than the link's text cap: the
/// controller decides, and it decides differently before and after it knows
/// what time it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockOffer<'a> {
    /// Key 1.
    pub unix_ms: u64,
    /// Key 2. `1` is NTP and is the only source allocated.
    pub source: u8,
    /// Key 3, the comms processor's estimate **of itself**.
    ///
    /// Carried because it is diagnostic and refused as a basis for anything:
    /// L-152 withdrew the one outcome that keyed on it, since a refusal keyed
    /// on a number the untrusted peer writes is a refusal it lifts by writing a
    /// smaller one.
    pub accuracy_ms: u32,
    /// Key 4, diagnostic. Which server said so.
    pub server: &'a str,
}

impl<'a> ClockOffer<'a> {
    /// # Errors
    /// A `server` past the link's text cap, or a `dst` too small.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        bounded(LinkField::Server, self.server)?;
        let mut cbor = header
            .write(4, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(self.unix_ms)?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.source))?;
        cbor.key(3)?;
        cbor.u64(u64::from(self.accuracy_ms))?;
        cbor.key(4)?;
        cbor.text(self.server)?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// A key absent, a key twice, a `server` past the cap, or CBOR that will
    /// not read.
    pub fn decode(envelope: LinkEnvelope<'a>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut unix_ms = None;
        let mut source = None;
        let mut accuracy_ms = None;
        let mut server = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut unix_ms, LinkField::UnixMs, body.u64()?)?,
                2 => once(&mut source, LinkField::Source, body.u8()?)?,
                3 => once(&mut accuracy_ms, LinkField::AccuracyMs, body.u32()?)?,
                4 => {
                    let text = bounded(LinkField::Server, body.text()?)?;
                    once(&mut server, LinkField::Server, text)?;
                }
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            // **Never defaulted, and this one least of all.** A missing
            // `unix_ms` read as 0 is an offer of 1970 that the floor would then
            // have to catch, which is a rule doing a decoder's job.
            unix_ms: unix_ms.ok_or(LinkError::Missing(LinkField::UnixMs))?,
            source: source.ok_or(LinkError::Missing(LinkField::Source))?,
            accuracy_ms: accuracy_ms.ok_or(LinkError::Missing(LinkField::AccuracyMs))?,
            server: server.ok_or(LinkError::Missing(LinkField::Server))?,
        })
    }
}

/// `TimeOfferAck 0xE6` — what the controller decided about an offer.
///
/// Outcome 3 `refused_have_better` is withdrawn by L-152 and the number stays
/// held, which is why the generated enum has a gap at 3: it cannot be written
/// because it does not exist, rather than because a caller remembered not to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeVerdict {
    /// Key 1.
    pub outcome: TimeOffer,
}

impl TimeVerdict {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        outcome_only(header, dst, self.outcome as u8)
    }

    /// # Errors
    /// An outcome this version does not allocate — 3 among them — the key
    /// absent, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        Ok(Self {
            outcome: outcome(envelope, TimeOffer::try_from)?,
        })
    }
}

/// `ClientConnectedAck 0xE2` — whether the controller took the handle.
///
/// **This is what mints the connection's challenge** (L-070). Before it,
/// nothing told the controller a connection had happened at all, and P-060
/// falls back to one device-wide challenge and the two-client livelock it
/// exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientUpAck {
    /// Key 1.
    pub outcome: ClientConnected,
}

impl ClientUpAck {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        outcome_only(header, dst, self.outcome as u8)
    }

    /// # Errors
    /// An outcome this version does not allocate, the key absent, or CBOR that
    /// will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        Ok(Self {
            outcome: outcome(envelope, ClientConnected::try_from)?,
        })
    }
}

/// `ClientDisconnectedAck 0xE3` — the handle is free, and the comms processor
/// may reuse it.
///
/// **L-080 hangs on this arriving**: a comms processor that recycled a handle
/// the moment its socket closed would hand a brand-new client the session the
/// old one left open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDownAck {
    /// Key 1.
    pub outcome: ClientDisconnected,
}

impl ClientDownAck {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        outcome_only(header, dst, self.outcome as u8)
    }

    /// # Errors
    /// An outcome this version does not allocate, the key absent, or CBOR that
    /// will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        Ok(Self {
            outcome: outcome(envelope, ClientDisconnected::try_from)?,
        })
    }
}

/// `NetConfigAck 0xE5` — what the comms processor stored, and what it now
/// holds.
///
/// **The version is not the one it was sent** (L-132). It is what is in NVS
/// after the attempt, and 0 is the honest answer from an empty board — the
/// controller decides whether to push by comparing it, so an ack that echoed
/// the offered version would stop the pushes to a board with no credentials on
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetVerdict {
    /// Key 1.
    pub outcome: NetConfig,
    /// Key 2, what it now holds. **0 when it holds nothing**, and never
    /// defaulted — an absent version read as 0 is a board that failed to store
    /// reporting itself empty, which happens to be right for the wrong reason
    /// and stops being right the moment a write fails over an old credential.
    pub version: u32,
}

impl NetVerdict {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut cbor = header
            .write(2, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.outcome as u8))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.version))?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// An outcome this version does not allocate, a key absent, or CBOR that
    /// will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut said = None;
        let mut version = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => {
                    let raw = body.u8()?;
                    let stored =
                        NetConfig::try_from(raw).map_err(|()| LinkError::UnknownOutcome(raw))?;
                    once(&mut said, LinkField::Outcome, stored)?;
                }
                2 => once(&mut version, LinkField::NetVersion, body.u32()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            outcome: said.ok_or(LinkError::Missing(LinkField::Outcome))?,
            version: version.ok_or(LinkError::Missing(LinkField::NetVersion))?,
        })
    }
}

/// The three acks that carry nothing but an outcome, written once.
///
/// They are three types rather than one generic because each takes a different
/// outcome enum and a caller must not be able to answer a `ClientConnected`
/// with a `NetConfig` outcome. What they share is the shape, and that is a
/// function.
fn outcome_only(header: LinkHeader, dst: &mut [u8], said: u8) -> Result<usize, LinkError> {
    let mut cbor = header
        .write(1, dst)
        .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
    cbor.key(1)?;
    cbor.u64(u64::from(said))?;
    Ok(cbor.finish()?)
}

/// Read the one key those three carry, refusing a number nobody allocated.
fn outcome<T>(
    envelope: LinkEnvelope<'_>,
    known: impl Fn(u8) -> Result<T, ()>,
) -> Result<T, LinkError> {
    let pairs = envelope.keys();
    let mut body = envelope.into_body();
    let mut said = None;
    for _ in 0..pairs {
        match body.key()? {
            1 => {
                let raw = body.u8()?;
                let taken = known(raw).map_err(|()| LinkError::UnknownOutcome(raw))?;
                once(&mut said, LinkField::Outcome, taken)?;
            }
            _ => body.skip()?,
        }
    }
    body.finish()?;
    said.ok_or(LinkError::Missing(LinkField::Outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::CborError;
    use crate::envelope::{EnvelopeError, Refusal};
    use crate::generated::MessageType;

    /// **The wrong side and an unknown opcode are one code.** The comms
    /// processor answering `ClientConnected` at the controller is a bug in the
    /// comms processor; a controller accepting a `CommsRelease` from its own
    /// peer has lost the plot about who authorises firmware. From the
    /// receiver's side both are a frame it has no business acting on.
    #[test]
    fn l_001_a_message_from_the_side_the_column_forbids_is_refused() {
        // ClientConnected travels comms → controller, so the comms processor
        // must never be the one receiving it.
        assert_eq!(
            arriving(
                LinkMessageType::ClientConnected as u8,
                Side::Comms,
                SessionId::None
            ),
            Intake::Refuse(LinkErrorCode::WrongSide)
        );
        // And CloseConnection travels the other way.
        assert_eq!(
            arriving(
                LinkMessageType::CloseConnection as u8,
                Side::Controller,
                SessionId::None
            ),
            Intake::Refuse(LinkErrorCode::WrongSide)
        );
        assert_eq!(LinkErrorCode::WrongSide as u16, 256);
    }

    /// The same code for an opcode nobody allocated, which is the other half of
    /// the argument: one code so neither firmware has to decide which kind of
    /// wrong it is looking at.
    #[test]
    fn l_001_an_opcode_this_build_does_not_know_gets_the_same_code() {
        for unknown in [0x00u8, 0x01, 0x5F, 0x70, 0xDF, 0xF0, 0xFF] {
            assert_eq!(
                arriving(unknown, Side::Controller, SessionId::None),
                Intake::Refuse(LinkErrorCode::WrongSide),
                "opcode {unknown:#04x} was acted on"
            );
        }
    }

    /// Every message the registry allocates is acted on by the side that is
    /// supposed to receive it, or the direction column would be a rule that
    /// refuses everything.
    ///
    /// **This asserts which side, not how many.** The version that counted was
    /// green while every acknowledgement was receivable only at the side that
    /// sends it — one side, the wrong one, and the count could not tell. A
    /// comms processor could not take the answer to its own `ClientConnected`,
    /// and L-080 makes it wait for exactly that before reusing a handle.
    #[test]
    fn l_001_every_allocated_message_reaches_the_side_that_should_have_it() {
        let mut acted = 0;
        for opcode in 0..=u8::MAX {
            let Ok(kind) = LinkMessageType::try_from(opcode) else {
                continue;
            };
            let reached = (
                arriving(opcode, Side::Controller, SessionId::None) == Intake::Act(kind),
                arriving(opcode, Side::Comms, SessionId::None) == Intake::Act(kind),
            );

            // The request crosses the cable; the answer comes back.
            let ack = opcode & 0x80 != 0;
            let want = match kind.direction() {
                LinkDirection::Either => (true, true),
                LinkDirection::CommsToController => (!ack, ack),
                LinkDirection::ControllerToComms => (ack, !ack),
            };
            assert_eq!(
                reached, want,
                "{kind:?} ({opcode:#04x}) reaches (controller, comms) = {reached:?} \
                 and should reach {want:?}"
            );
            acted += 1;
        }
        assert!(acted >= 16, "only {acted} link-local opcodes are allocated");
    }

    /// **A link-local frame carrying a session is a bug in the sender**, and the
    /// only thing routing it achieves is delivering a message about the link to
    /// whichever unlucky client owns that session number. Code 263 goes back to
    /// the side whose bug it is.
    #[test]
    fn l_012_and_l_003_a_link_local_frame_with_a_session_is_refused_not_routed() {
        assert_eq!(
            arriving(
                LinkMessageType::Heartbeat as u8,
                Side::Controller,
                SessionId::from(3)
            ),
            Intake::Refuse(LinkErrorCode::NonZeroSession)
        );
        assert_eq!(LinkErrorCode::NonZeroSession as u16, 263);
        // Session 0 is the link itself, and a handle is never 0, so the two
        // uses cannot collide — which is what makes this decidable.
        assert_eq!(
            arriving(
                LinkMessageType::Heartbeat as u8,
                Side::Controller,
                SessionId::None
            ),
            Intake::Act(LinkMessageType::Heartbeat)
        );
    }

    /// And the wrong side is answered before the session is looked at, because
    /// a receiver that reported the session first would send the peer to read
    /// the wrong field of a frame it should not have sent at all.
    #[test]
    fn l_003_a_frame_that_is_wrong_twice_names_the_first_thing_wrong_with_it() {
        assert_eq!(
            arriving(
                LinkMessageType::ClientConnected as u8,
                Side::Comms,
                SessionId::from(4)
            ),
            Intake::Refuse(LinkErrorCode::WrongSide)
        );
    }

    /// **A link-local opcode is not a client opcode**, and the two spaces do
    /// not overlap — which is what lets one intake decide on the raw byte
    /// before anything has been parsed.
    ///
    /// Not cited as L-010. That requirement says a link-local frame uses the
    /// client envelope unchanged, and there is no decode path for one: the
    /// envelope's type field is a closed `MessageType`, so every link-local
    /// opcode comes back `UnknownType`. This test is the disjointness the
    /// intake above relies on, not the requirement.
    #[test]
    fn the_link_local_opcodes_do_not_collide_with_the_client_ones() {
        for opcode in 0..=u8::MAX {
            let link = LinkMessageType::try_from(opcode).is_ok();
            let client = MessageType::try_from(opcode).is_ok();
            assert!(
                !(link && client),
                "opcode {opcode:#04x} is allocated in both spaces"
            );
        }
    }

    /// **The six that must not reach a client are named, not merely absent.**
    ///
    /// L-180 splits the nine: three are raised by a client's own frame and it
    /// can act on each, and six are the two firmwares talking about each other.
    /// A browser shown `no authorisation` or `link major mismatch` learns
    /// something true about a machine it is not talking to and nothing about its
    /// own request — and the person reading the screen goes looking for a
    /// permission problem in the client.
    ///
    /// Written out one at a time rather than as a range, because the numbers are
    /// contiguous today and the rule is about which fault belongs to whom. A
    /// tenth code allocated in the middle would make a range quietly wrong and
    /// leave this test green.
    #[test]
    fn l_180_only_the_three_a_clients_own_frame_raised_may_reach_it() {
        for code in [
            LinkErrorCode::LinkTypeOnClientTransport,
            LinkErrorCode::BeforeLinkUp,
            LinkErrorCode::UnknownHandle,
        ] {
            assert!(
                code.reaches_a_client(),
                "{code:?} is one of L-180's three and a client that never hears it retries forever"
            );
        }
        for code in [
            LinkErrorCode::WrongSide,
            LinkErrorCode::ConnectionTableFull,
            LinkErrorCode::LinkMajorMismatch,
            LinkErrorCode::TooManyOutstanding,
            LinkErrorCode::NonZeroSession,
            LinkErrorCode::NoAuthorisation,
        ] {
            assert!(
                !code.reaches_a_client(),
                "{code:?} is about the two firmwares and says nothing about a client's request"
            );
        }
        // And the three are 257, 258 and 259, which is what the document names.
        assert_eq!(LinkErrorCode::LinkTypeOnClientTransport as u16, 257);
        assert_eq!(LinkErrorCode::BeforeLinkUp as u16, 258);
        assert_eq!(LinkErrorCode::UnknownHandle as u16, 259);
    }

    /// **Every refusal a client transport actually produces is one a client may
    /// see**, which is the half the classification above cannot check on its own.
    ///
    /// A predicate nothing consults is a comment with a return type. This drives
    /// the one function that turns a client-facing decode into a code on the
    /// wire, over every way an envelope can be refused, and asks L-180 of the
    /// answer.
    #[test]
    fn l_180_no_refusal_from_a_client_transport_carries_a_code_about_the_two_firmwares() {
        for why in [
            EnvelopeError::WrongLength,
            EnvelopeError::UnknownType(0x11),
            EnvelopeError::LinkLocalType(0x60),
            EnvelopeError::Cbor(CborError::WrongType),
        ] {
            if let Refusal::LinkLocal(code) = why.refusal() {
                assert!(
                    code.reaches_a_client(),
                    "{why:?} answers a client with {code:?}, which is about the two firmwares"
                );
            }
        }
    }

    /// **L-020 — a link-local message carries no MAC, and the two chips share
    /// no key for one.**
    ///
    /// While both are on one board, an attacker who can read the link can read
    /// the traces, so a MAC buys nothing — and a shared key would mean the chip
    /// this protocol treats as hostile holds a credential the controller also
    /// holds, which is the reason that matters.
    ///
    /// Checked where it would go wrong rather than by reading the rule back.
    /// The two opcode spaces are **disjoint**: no link-local opcode is a
    /// `MessageType`, so a link-local frame cannot reach `Wrapper` or `Tagged`
    /// at all. There is no code to write that would tag one, which is a stronger
    /// guarantee than a rule saying not to.
    #[test]
    fn l_020_no_link_local_opcode_is_a_client_message_type() {
        use crate::generated::{LinkMessageType, MessageType};

        let mut seen = 0;
        for opcode in 0x00..=0xFFu8 {
            let Ok(link) = LinkMessageType::try_from(opcode) else {
                continue;
            };
            seen += 1;
            assert!(
                MessageType::try_from(opcode).is_err(),
                "{link:?} is also a client message type, so it could be wrapped \
                 and tagged under a session key"
            );
        }
        assert!(
            seen >= 8,
            "the sweep found {seen} link messages, which is too few to be the space"
        );
    }

    /// **L-010 — a link-local frame is the client protocol's frame.**
    ///
    /// Same envelope, same framing, same size limits, unchanged. One parser
    /// rather than two: a second wire format on the same cable is a second
    /// decoder, a second set of limits, and a second place for the two to drift
    /// apart while both still look right.
    ///
    /// So this drives a link frame through the **client** framing — `FrameWriter`
    /// and `FrameReader`, the same `MAX_FRAME` — and reads it with the four
    /// element guard the client path uses. Nothing here is link-specific except
    /// which opcode space the byte came from.
    #[test]
    fn l_010_a_link_local_frame_uses_the_client_framing_unchanged() {
        use crate::envelope::{LinkEnvelope, LinkHeader, ReqId};
        use crate::frame::{FrameReader, FrameWriter, Received};
        use crate::generated::LinkMessageType;
        use crate::limits::MAX_FRAME;

        let header = LinkHeader {
            kind: LinkMessageType::LinkUp,
            // The messages about the cable carry no connection (L-012).
            session: SessionId::None,
            req_id: ReqId(1),
        };
        let mut body = [0u8; 64];
        let mut cbor = header.write(1, &mut body).expect("the envelope opens");
        cbor.key(1).expect("a key");
        cbor.u64(1).expect("a value");
        let len = cbor.finish().expect("it closes");

        // The client framer, byte for byte.
        let mut framed = [0u8; MAX_FRAME];
        let wrote = FrameWriter::new()
            .write(body.get(..len).expect("the body"), &mut framed)
            .expect("the client framer takes a link frame");

        let mut reader = FrameReader::new();
        let mut arrived = None;
        for byte in framed.get(..wrote).expect("the frame") {
            if let Received::Frame(frame) = reader.push(*byte) {
                arrived = Some(frame.to_vec());
            }
        }
        let frame = arrived.expect("the client framer reads back what it wrote");

        let envelope = LinkEnvelope::decode(&frame).expect("the four-element guard takes it");
        assert_eq!(envelope.opcode(), LinkMessageType::LinkUp as u8);
        assert_eq!(envelope.session(), SessionId::None);
        assert_eq!(envelope.req_id(), ReqId(1));
        assert_eq!(envelope.keys(), 1);

        // And the admission decision is still `arriving`'s, reading the raw byte
        // this envelope hands over rather than a kind it decided for itself.
        assert_eq!(
            arriving(envelope.opcode(), Side::Controller, envelope.session()),
            Intake::Act(LinkMessageType::LinkUp)
        );
    }

    /// A client frame on the link is refused, which is L-002 facing the other
    /// way. It decodes — the envelope is the same shape — and `arriving` is what
    /// refuses it, so the two spaces stay disjoint without a second check.
    #[test]
    fn l_002_a_client_message_arriving_on_the_link_is_refused() {
        use crate::envelope::{Header, ReqId};
        use crate::generated::MessageType;

        let mut bytes = [0u8; 64];
        let cbor = Header {
            kind: MessageType::Discover,
            session: SessionId::None,
            req_id: ReqId(1),
        }
        .write(0, &mut bytes)
        .expect("the envelope opens");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("the envelope shape is the same, which is L-010");
        assert_eq!(
            arriving(envelope.opcode(), Side::Controller, envelope.session()),
            Intake::Refuse(LinkErrorCode::WrongSide),
            "a client message was admitted on the link"
        );
    }

    /// An offer round-trips with the numbers it was given, including a server
    /// name at the cap.
    #[test]
    fn an_offer_carries_the_moment_it_names() {
        let offer = ClockOffer {
            unix_ms: 1_786_802_653_000,
            source: 1,
            accuracy_ms: 40,
            server: "0.pool.ntp.org",
        };
        let mut bytes = [0u8; 128];
        let len = offer
            .write(link_header(LinkMessageType::TimeOffer), &mut bytes)
            .expect("it writes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(ClockOffer::decode(envelope).expect("it reads"), offer);
    }

    /// **An absent `unix_ms` is not 1970.** Read as 0 it becomes an offer the
    /// monotonic floor then has to catch, which is a rule doing a decoder's
    /// job — and on a unit whose RTC backup cell has died the floor is the only
    /// thing between an untrusted peer and every timestamp in the log.
    #[test]
    fn an_offer_without_a_time_is_refused_not_defaulted() {
        let mut bytes = [0u8; 128];
        let mut cbor = link_header(LinkMessageType::TimeOffer)
            .write(3, &mut bytes)
            .expect("the envelope opens");
        cbor.key(2).expect("source");
        cbor.u64(1).expect("ntp");
        cbor.key(3).expect("accuracy");
        cbor.u64(40).expect("value");
        cbor.key(4).expect("server");
        cbor.text("0.pool.ntp.org").expect("value");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            ClockOffer::decode(envelope).err(),
            Some(LinkError::Missing(LinkField::UnixMs))
        );
    }

    /// A server name past the link's text cap is refused where it is read, so a
    /// diagnostic field cannot be the thing that overruns a buffer.
    #[test]
    fn an_offer_from_a_server_with_too_long_a_name_is_refused() {
        let long = "n".repeat(MAX_LINK_TEXT + 1);
        let offer = ClockOffer {
            unix_ms: 1_786_802_653_000,
            source: 1,
            accuracy_ms: 40,
            server: &long,
        };
        let mut bytes = [0u8; 256];
        assert_eq!(
            offer
                .write(link_header(LinkMessageType::TimeOffer), &mut bytes)
                .err(),
            Some(LinkError::TooLong {
                key: LinkField::Server,
                len: MAX_LINK_TEXT + 1,
            })
        );
    }

    /// The three outcome-only acks round-trip, each with its own enum.
    #[test]
    fn an_ack_carries_the_outcome_it_was_given() {
        let mut bytes = [0u8; 64];

        let up = ClientUpAck {
            outcome: ClientConnected::RefusedTableFull,
        };
        let len = up
            .write(link_header(LinkMessageType::ClientConnectedAck), &mut bytes)
            .expect("it writes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(ClientUpAck::decode(envelope).expect("it reads"), up);

        let down = ClientDownAck {
            outcome: ClientDisconnected::UnknownHandle,
        };
        let len = down
            .write(
                link_header(LinkMessageType::ClientDisconnectedAck),
                &mut bytes,
            )
            .expect("it writes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(ClientDownAck::decode(envelope).expect("it reads"), down);

        let clock = TimeVerdict {
            outcome: TimeOffer::RefusedRateLimited,
        };
        let len = clock
            .write(link_header(LinkMessageType::TimeOfferAck), &mut bytes)
            .expect("it writes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(TimeVerdict::decode(envelope).expect("it reads"), clock);
    }

    /// **Outcome 3 cannot arrive.** L-152 withdrew `refused_have_better` and
    /// holds the number, because the only accuracy figure on this link is one
    /// the untrusted peer writes about itself — a refusal keyed on it is a
    /// refusal it lifts by writing a smaller number, always in its own favour.
    /// The gap is in the generated enum, so an offer answered 3 is refused
    /// here rather than at whatever reads the outcome next.
    #[test]
    fn a_withdrawn_time_outcome_is_refused_rather_than_read() {
        let mut bytes = [0u8; 64];
        let mut cbor = link_header(LinkMessageType::TimeOfferAck)
            .write(1, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("outcome");
        cbor.u64(3).expect("refused_have_better");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            TimeVerdict::decode(envelope).err(),
            Some(LinkError::UnknownOutcome(3)),
            "a number L-152 withdrew was read as an outcome"
        );
    }

    /// An ack with no outcome in it is refused. There is no benign reading of
    /// an empty ack: it is the whole message.
    #[test]
    fn an_ack_with_no_outcome_is_refused() {
        let mut bytes = [0u8; 64];
        let len = link_header(LinkMessageType::ClientConnectedAck)
            .write(0, &mut bytes)
            .expect("the envelope opens")
            .finish()
            .expect("it closes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            ClientUpAck::decode(envelope).err(),
            Some(LinkError::Missing(LinkField::Outcome))
        );
    }

    /// A `NetConfigAck` round-trips both fields.
    #[test]
    fn a_net_ack_reports_what_it_now_holds() {
        let stored = NetVerdict {
            outcome: NetConfig::Stored,
            version: 7,
        };
        let mut bytes = [0u8; 64];
        let len = stored
            .write(link_header(LinkMessageType::NetConfigAck), &mut bytes)
            .expect("it writes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(NetVerdict::decode(envelope).expect("it reads"), stored);
    }

    /// **A board with an empty NVS answers 0, and 0 is a value.** L-132 makes it
    /// the honest answer from a board holding nothing, and it is what gets that
    /// board provisioned — the controller pushes when the versions differ.
    #[test]
    fn an_empty_board_reports_version_zero_and_gets_provisioned() {
        let empty = NetVerdict {
            outcome: NetConfig::Stored,
            version: 0,
        };
        let mut bytes = [0u8; 64];
        let len = empty
            .write(link_header(LinkMessageType::NetConfigAck), &mut bytes)
            .expect("it writes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(NetVerdict::decode(envelope).expect("it reads").version, 0);
    }

    /// **An absent version is not 0.** They look the same and they are opposite
    /// claims: 0 is a board saying it holds nothing, and absent is a board that
    /// did not say. Read as 0, a failed write over an existing credential
    /// reports an empty board — right by accident until the moment it matters.
    #[test]
    fn a_net_ack_without_a_version_is_refused_not_read_as_empty() {
        let mut bytes = [0u8; 64];
        let mut cbor = link_header(LinkMessageType::NetConfigAck)
            .write(1, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("outcome");
        cbor.u64(3).expect("nvs_write_failed");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            NetVerdict::decode(envelope).err(),
            Some(LinkError::Missing(LinkField::NetVersion))
        );
    }

    fn link_header(kind: LinkMessageType) -> crate::envelope::LinkHeader {
        crate::envelope::LinkHeader {
            kind,
            session: SessionId::None,
            req_id: crate::envelope::ReqId(1),
        }
    }

    fn a_link_up() -> LinkUp<'static> {
        LinkUp {
            version: Version::V1_0,
            role: Side::Comms,
            fw: "o89-esp32 0.1.0",
            boot_id: 0xDEAD_BEEF,
            hw: "esp32-c6-devkitc-1",
            net_version: Some(7),
        }
    }

    /// The ordinary case, read back through the decoder a peer would use rather
    /// than by inspecting fields — that is the comparison that catches a key
    /// written under the wrong number.
    #[test]
    fn a_link_up_round_trips_through_the_wire() {
        let mut bytes = [0u8; 256];
        let len = a_link_up()
            .write(link_header(LinkMessageType::LinkUp), &mut bytes)
            .expect("it encodes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(LinkUp::decode(envelope), Ok(a_link_up()));
    }

    /// The controller sends the same fields **without** key 7, and a decoder
    /// that required it would refuse every `LinkUp` the controller ever sends.
    #[test]
    fn the_controller_sends_no_net_version_and_that_is_not_a_missing_key() {
        let mut bytes = [0u8; 256];
        let controller = LinkUp {
            role: Side::Controller,
            net_version: None,
            ..a_link_up()
        };
        let len = controller
            .write(link_header(LinkMessageType::LinkUp), &mut bytes)
            .expect("it encodes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(LinkUp::decode(envelope), Ok(controller));
    }

    /// **A `net_version` from the controller is refused rather than kept.** The
    /// field is the comms processor's cached credential version; from the other
    /// side it is either a confused peer or something claiming to be one, and a
    /// controller that stored it would be comparing its own number against
    /// itself.
    #[test]
    fn a_net_version_from_the_controller_is_refused() {
        let mut bytes = [0u8; 256];
        let wrong = LinkUp {
            role: Side::Controller,
            net_version: Some(3),
            ..a_link_up()
        };
        assert_eq!(
            wrong
                .write(link_header(LinkMessageType::LinkUp), &mut bytes)
                .err(),
            Some(LinkError::NetVersionFromController),
            "the encoder built a frame the decoder must refuse"
        );
    }

    /// **P-014 on the link: a role nobody allocated is refused, never
    /// defaulted.** A `LinkUp` from something claiming to be neither chip is not
    /// a peer to guess about, and there is no `0 = unknown` anywhere here.
    #[test]
    fn a_role_this_version_does_not_allocate_is_refused() {
        assert_eq!(Side::of(1), Ok(Side::Controller));
        assert_eq!(Side::of(2), Ok(Side::Comms));
        for unallocated in [0u8, 3, 255] {
            assert_eq!(
                Side::of(unallocated),
                Err(LinkError::UnknownRole(unallocated))
            );
        }
    }

    /// A text field past the cap is refused at the field, which is the lesson
    /// the pairing label taught: a value between `MAX_STRING` and what stores it
    /// decodes cleanly and then has nowhere to go.
    #[test]
    fn a_firmware_string_past_the_cap_is_refused_where_it_is_read() {
        const WIDE: &str = "0123456789012345678901234567890123";
        assert!(WIDE.len() > MAX_LINK_TEXT);
        let mut bytes = [0u8; 256];
        assert_eq!(
            LinkUp {
                fw: WIDE,
                ..a_link_up()
            }
            .write(link_header(LinkMessageType::LinkUp), &mut bytes)
            .err(),
            Some(LinkError::TooLong {
                key: LinkField::Fw,
                len: WIDE.len()
            })
        );
    }

    /// **An absent `boot_id` is named rather than defaulted.** A zero one would
    /// compare equal to the next zero across a reboot, and L-042 tears every
    /// connection down on a *changed* `boot_id` — so a default here is a
    /// controller that never notices the radio restarted.
    #[test]
    fn an_absent_boot_id_is_named_rather_than_defaulted() {
        let mut bytes = [0u8; 256];
        // **Every other key present**, so the only thing missing is the one
        // under test. The first version of this omitted keys 4 to 6 as well and
        // was answered `Missing(Fw)` — it never reached `boot_id` at all, and
        // defaulting `boot_id` to zero left it green.
        let mut cbor = link_header(LinkMessageType::LinkUp)
            .write(5, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("major");
        cbor.u64(1).expect("value");
        cbor.key(2).expect("minor");
        cbor.u64(0).expect("value");
        cbor.key(3).expect("role");
        cbor.u64(2).expect("value");
        cbor.key(4).expect("fw");
        cbor.text("o89-esp32 0.1.0").expect("value");
        cbor.key(6).expect("hw");
        cbor.text("rev-b").expect("value");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            LinkUp::decode(envelope).err(),
            Some(LinkError::Missing(LinkField::BootId)),
            "an absent boot_id was defaulted, so a reboot would compare equal to \
             the last one and L-042 would never tear a connection down"
        );
    }

    /// **A refusal names the field that was missing, not a field from another
    /// body.** The type that carries the name was called `LinkUpKey` and was
    /// written for `LinkUp`'s seven keys; every other body then reused whatever
    /// variant was nearest. A missing `conn` on a `ClientDisconnected` came
    /// back as `role`, a missing `psk` on a `NetConfig` as `fw`, and a missing
    /// `country` as `hw`.
    ///
    /// Nothing caught it because nothing asserted the name — 510 tests passed
    /// over it. The whole value of the type is that a bench log names a field
    /// rather than an offset, and it was doing the opposite: naming a field
    /// that was present while the absent one went unmentioned.
    #[test]
    fn a_refusal_names_the_field_that_was_missing() {
        // Each of these carries one key and omits the other, so the answer can
        // only be about the one that is not there.
        /// One body, the keys it does carry, and the field it must name.
        type Case = (LinkMessageType, &'static [(i64, u64)], LinkField);

        let cases: &[Case] = &[
            (LinkMessageType::Heartbeat, &[(2, 0)], LinkField::Uptime),
            (LinkMessageType::Heartbeat, &[(1, 90)], LinkField::Conns),
            (
                LinkMessageType::ClientDisconnected,
                &[(2, 1)],
                LinkField::Conn,
            ),
            (
                LinkMessageType::ClientDisconnected,
                &[(1, 4)],
                LinkField::Reason,
            ),
            (
                LinkMessageType::CloseConnectionAck,
                &[(2, 3)],
                LinkField::Outcome,
            ),
            (
                LinkMessageType::CloseConnectionAck,
                &[(1, 1)],
                LinkField::Closed,
            ),
        ];

        for (kind, keys, want) in cases {
            let mut bytes = [0u8; 64];
            let mut cbor = link_header(*kind)
                .write(keys.len(), &mut bytes)
                .expect("the envelope opens");
            for (key, value) in *keys {
                cbor.key(*key).expect("a key");
                cbor.u64(*value).expect("a value");
            }
            let len = cbor.finish().expect("it closes");
            let frame = bytes.get(..len).expect("the frame");

            let got = match kind {
                LinkMessageType::Heartbeat => Heartbeat::decode(
                    crate::envelope::LinkEnvelope::decode(frame).expect("an envelope"),
                )
                .err(),
                LinkMessageType::ClientDisconnected => ClientDown::decode(
                    crate::envelope::LinkEnvelope::decode(frame).expect("an envelope"),
                )
                .err(),
                LinkMessageType::CloseConnectionAck => CloseReport::decode(
                    crate::envelope::LinkEnvelope::decode(frame).expect("an envelope"),
                )
                .err(),
                other => panic!("this case has no decoder in the table: {other:?}"),
            };

            assert_eq!(
                got,
                Some(LinkError::Missing(*want)),
                "a {kind:?} missing {want} named something else, so a bench log \
                 sends somebody to look at a field that was there"
            );
        }
    }

    /// The same, for the body with the most fields to get wrong. `NetConfig`
    /// has six, four of them text, and three of the four were reported under
    /// another field's name.
    #[test]
    fn a_net_config_refusal_names_its_own_field() {
        for (present, want) in [
            (
                &[(1u8, "set"), (5, "ca"), (6, "o89")][..],
                LinkField::NetVersion,
            ),
            (&[(1, "set"), (2, "1"), (6, "o89")][..], LinkField::Country),
            (&[(1, "set"), (2, "1"), (5, "ca")][..], LinkField::Hostname),
        ] {
            let mut bytes = [0u8; 96];
            let mut cbor = link_header(LinkMessageType::NetConfig)
                .write(present.len(), &mut bytes)
                .expect("the envelope opens");
            for (key, value) in present {
                cbor.key(i64::from(*key)).expect("a key");
                match key {
                    1 => cbor.u64(1).expect("op set"),
                    2 => cbor.u64(1).expect("a version"),
                    _ => cbor.text(value).expect("a value"),
                }
            }
            let len = cbor.finish().expect("it closes");
            let envelope =
                crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
                    .expect("an envelope");
            assert_eq!(
                NetChange::decode(envelope).err(),
                Some(LinkError::Missing(want)),
                "a NetConfig missing {want} named another field"
            );
        }
    }

    /// P-013 one wire over: a key this version does not know is skipped, not
    /// refused. The opposite of the role above, and deliberately so.
    #[test]
    fn a_key_this_version_does_not_know_is_skipped_rather_than_refused() {
        let mut bytes = [0u8; 256];
        let mut cbor = link_header(LinkMessageType::LinkUp)
            .write(7, &mut bytes)
            .expect("the envelope opens");
        for (key, value) in [(1u64, 1u64), (2, 0), (3, 2)] {
            cbor.key(i64::try_from(key).expect("a key")).expect("key");
            cbor.u64(value).expect("value");
        }
        cbor.key(4).expect("fw");
        cbor.text("o89-esp32 0.1.0").expect("value");
        cbor.key(5).expect("boot");
        cbor.u64(9).expect("value");
        cbor.key(6).expect("hw");
        cbor.text("rev-b").expect("value");
        // A key from a newer peer.
        cbor.key(99).expect("unknown");
        cbor.u64(1).expect("value");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        let read = LinkUp::decode(envelope).expect("the unknown key was skipped");
        assert_eq!(read.boot_id, 9);
    }

    /// A heartbeat says two numbers and both matter: one side can be up while
    /// the other has restarted, and `conns` is the only place the two find out
    /// their tables disagree.
    #[test]
    fn a_heartbeat_round_trips_through_the_wire() {
        let beat = Heartbeat {
            uptime_s: 86_400,
            conns: 3,
        };
        let mut bytes = [0u8; 128];
        let len = beat
            .write(link_header(LinkMessageType::Heartbeat), &mut bytes)
            .expect("it encodes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(Heartbeat::decode(envelope), Ok(beat));
    }

    /// Zero connections and zero uptime are real answers, not absences: a chip
    /// one second past boot with nothing connected says exactly this.
    #[test]
    fn a_heartbeat_of_zeroes_is_a_reading_and_not_a_missing_key() {
        let quiet = Heartbeat {
            uptime_s: 0,
            conns: 0,
        };
        let mut bytes = [0u8; 128];
        let len = quiet
            .write(link_header(LinkMessageType::Heartbeat), &mut bytes)
            .expect("it encodes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(Heartbeat::decode(envelope), Ok(quiet));
    }

    /// The ordinary case for a transport coming up.
    #[test]
    fn a_client_connected_round_trips_through_the_wire() {
        let up = ClientUp {
            conn: 4,
            transport: LinkTransport::WifiLocal,
            peer: "192.168.1.44",
        };
        let mut bytes = [0u8; 128];
        let len = up
            .write(link_header(LinkMessageType::ClientConnected), &mut bytes)
            .expect("it encodes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(ClientUp::decode(envelope), Ok(up));
    }

    /// **A `conn` of 0 is refused here, and that is not the same rule as
    /// `CloseConnection`'s.** L-060 never allocates 0, so on this message it
    /// names no connection at all — while on a close it deliberately names every
    /// one. Same field, opposite meanings, which is exactly why each message
    /// checks it rather than a shared helper deciding once.
    #[test]
    fn a_connection_handle_of_zero_is_refused_when_one_comes_up() {
        // Both ways: an encoder that will not build one, and a decoder that will
        // not take one built elsewhere. The comms processor is hostile, so the
        // encoder check protects nobody on its own.
        let mut bytes = [0u8; 128];
        let mut cbor = link_header(LinkMessageType::ClientConnected)
            .write(3, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("conn");
        cbor.u64(0).expect("the handle that names nothing");
        cbor.key(2).expect("transport");
        cbor.u64(4).expect("value");
        cbor.key(3).expect("peer");
        cbor.text("somewhere").expect("value");
        let len = cbor.finish().expect("it closes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            ClientUp::decode(envelope).err(),
            Some(LinkError::NoSuchConnection),
            "a handle of 0 was accepted from the peer that allocates handles"
        );

        let mut bytes = [0u8; 128];
        assert_eq!(
            ClientUp {
                conn: 0,
                transport: LinkTransport::Usb,
                peer: "",
            }
            .write(link_header(LinkMessageType::ClientConnected), &mut bytes)
            .err(),
            Some(LinkError::NoSuchConnection)
        );
    }

    /// P-014 again: a transport nobody allocated is refused rather than guessed.
    /// A client shown as `ble` when it came over the cloud is a person deciding
    /// about a stranger on the internet as though they were in the room.
    #[test]
    fn a_transport_this_version_does_not_allocate_is_refused() {
        let mut bytes = [0u8; 128];
        let mut cbor = link_header(LinkMessageType::ClientConnected)
            .write(3, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("conn");
        cbor.u64(4).expect("value");
        cbor.key(2).expect("transport");
        cbor.u64(0x09).expect("a transport nobody allocated");
        cbor.key(3).expect("peer");
        cbor.text("somewhere").expect("value");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            ClientUp::decode(envelope).err(),
            Some(LinkError::UnknownTransport(0x09))
        );
    }

    /// **The same field means opposite things on two messages, and both are
    /// tested here together so nobody changes one without seeing the other.**
    ///
    /// `conn = 0` names *no* connection when one comes up — L-060 never
    /// allocates it — and names *every* connection on a close, which is what the
    /// heartbeat resync sends. A helper that decided once for both would have to
    /// pick, and either choice is wrong half the time.
    #[test]
    fn a_conn_of_zero_names_nothing_coming_up_and_everything_closing() {
        let mut bytes = [0u8; 128];
        assert_eq!(
            ClientUp {
                conn: 0,
                transport: LinkTransport::Usb,
                peer: "",
            }
            .write(link_header(LinkMessageType::ClientConnected), &mut bytes)
            .err(),
            Some(LinkError::NoSuchConnection),
            "a handle of 0 was accepted where it names nothing"
        );

        let every = CloseConnections {
            conn: 0,
            reason: CloseReason::Shedding,
        };
        let len = every
            .write(link_header(LinkMessageType::CloseConnection), &mut bytes)
            .expect("0 is the whole point of this message");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        let read = CloseConnections::decode(envelope).expect("it decodes");
        assert_eq!(read, every);
        assert!(
            read.is_every_connection(),
            "0 on a close has to mean every connection, or a resync closes nothing"
        );
    }

    /// **The count is the point of the ack**, and an absent one is not zero.
    /// L-090 says the number is the only way the controller learns whether the
    /// table it believed in matched the one that existed — and *closed nothing*
    /// against *the table was already empty* want opposite reactions.
    #[test]
    fn a_close_ack_without_its_count_is_refused_rather_than_read_as_none() {
        let mut bytes = [0u8; 128];
        let mut cbor = link_header(LinkMessageType::CloseConnectionAck)
            .write(1, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("outcome");
        cbor.u64(1).expect("closed");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert!(
            CloseReport::decode(envelope).is_err(),
            "an ack with no count was read as though it had closed nothing"
        );
    }

    /// A disconnect round-trips, and its handle is checked the same way a
    /// connect's is — the peer that allocates them is the untrusted one.
    #[test]
    fn a_client_disconnected_round_trips_and_refuses_a_zero_handle() {
        let down = ClientDown {
            conn: 9,
            reason: DisconnectReason::ClosedByClient,
        };
        let mut bytes = [0u8; 128];
        let len = down
            .write(link_header(LinkMessageType::ClientDisconnected), &mut bytes)
            .expect("it encodes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(ClientDown::decode(envelope), Ok(down));

        assert_eq!(
            ClientDown {
                conn: 0,
                reason: DisconnectReason::ClosedByClient,
            }
            .write(link_header(LinkMessageType::ClientDisconnected), &mut bytes)
            .err(),
            Some(LinkError::NoSuchConnection)
        );
    }

    /// P-014 across all three of the new bodies: a reason or an outcome nobody
    /// allocated is refused rather than guessed at.
    #[test]
    fn a_reason_or_outcome_this_version_does_not_allocate_is_refused() {
        let mut bytes = [0u8; 128];
        let mut cbor = link_header(LinkMessageType::ClientDisconnected)
            .write(2, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("conn");
        cbor.u64(3).expect("value");
        cbor.key(2).expect("reason");
        cbor.u64(0x7F).expect("a reason nobody allocated");
        let len = cbor.finish().expect("it closes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            ClientDown::decode(envelope).err(),
            Some(LinkError::UnknownReason(0x7F))
        );

        let mut cbor = link_header(LinkMessageType::CloseConnectionAck)
            .write(2, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("outcome");
        cbor.u64(0x7E).expect("an outcome nobody allocated");
        cbor.key(2).expect("closed");
        cbor.u64(0).expect("value");
        let len = cbor.finish().expect("it closes");
        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            CloseReport::decode(envelope).err(),
            Some(LinkError::UnknownOutcome(0x7E))
        );
    }

    fn a_set() -> NetChange<'static> {
        NetChange::Set {
            version: 4,
            ssid: "cabin",
            psk: "correct horse battery",
            country: "CA",
            hostname: "o89",
        }
    }

    /// Both shapes round-trip, and a `clear` comes back as a `clear` rather than
    /// a `set` with empty strings.
    #[test]
    fn a_net_config_round_trips_in_both_shapes() {
        let mut bytes = [0u8; 256];
        for change in [
            a_set(),
            NetChange::Clear {
                version: 5,
                country: "CA",
                hostname: "o89",
            },
        ] {
            let len = change
                .write(link_header(LinkMessageType::NetConfig), &mut bytes)
                .expect("it encodes");
            let envelope =
                crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
                    .expect("an envelope");
            assert_eq!(NetChange::decode(envelope), Ok(change));
        }
    }

    /// **L-131 — a clear carries no passphrase, and the type is what enforces
    /// it.** Putting the passphrase on the internal link one more time to
    /// accomplish its own deletion is the opposite of deleting it, and a struct
    /// with four optional fields would let somebody do exactly that.
    ///
    /// This is the half a caller cannot get wrong. The half below is the one an
    /// untrusted peer can still send.
    #[test]
    fn l_131_a_clear_cannot_be_built_carrying_credentials() {
        // `NetChange::Clear` has no `ssid` and no `psk` field, so the frame
        // cannot be constructed. What is asserted here is the encoding: a clear
        // writes four keys and neither of the two that carry secrets.
        let mut bytes = [0u8; 256];
        let len = NetChange::Clear {
            version: 5,
            country: "CA",
            hostname: "o89",
        }
        .write(link_header(LinkMessageType::NetConfig), &mut bytes)
        .expect("it encodes");
        let frame = bytes.get(..len).expect("the frame");
        assert!(
            !frame.windows(5).any(|run| run == b"cabin"),
            "a clear put a network name on the link"
        );
        let envelope = crate::envelope::LinkEnvelope::decode(frame).expect("an envelope");
        assert_eq!(envelope.keys(), 4, "a clear wrote a key it should not have");
    }

    /// The other half of L-131: a `clear` that **arrives** carrying credentials
    /// is refused rather than read past.
    ///
    /// Refused, because reading past it would make this end complicit in the
    /// thing the rule forbids — the secret is already on the link by then, and
    /// the sender is the one who needs to hear about it.
    #[test]
    fn l_131_a_clear_that_arrives_with_credentials_is_refused() {
        let mut bytes = [0u8; 256];
        let mut cbor = link_header(LinkMessageType::NetConfig)
            .write(5, &mut bytes)
            .expect("the envelope opens");
        cbor.key(1).expect("op");
        cbor.u64(2).expect("clear");
        cbor.key(2).expect("version");
        cbor.u64(5).expect("value");
        cbor.key(4).expect("psk");
        cbor.text("correct horse battery").expect("the secret");
        cbor.key(5).expect("country");
        cbor.text("CA").expect("value");
        cbor.key(6).expect("hostname");
        cbor.text("o89").expect("value");
        let len = cbor.finish().expect("it closes");

        let envelope = crate::envelope::LinkEnvelope::decode(bytes.get(..len).expect("the frame"))
            .expect("an envelope");
        assert_eq!(
            NetChange::decode(envelope).err(),
            Some(LinkError::ClearCarriedCredentials)
        );
    }

    /// A passphrase outside WPA's own bounds is refused at the field. Eight is
    /// the shortest a WPA network accepts and 63 the longest, so a value outside
    /// them is one no radio could have used.
    #[test]
    fn a_passphrase_outside_wpas_bounds_is_refused() {
        let mut bytes = [0u8; 256];
        for psk in [
            "short",
            "0123456789012345678901234567890123456789012345678901234567890123",
        ] {
            let change = NetChange::Set {
                version: 4,
                ssid: "cabin",
                psk,
                country: "CA",
                hostname: "o89",
            };
            assert_eq!(
                change
                    .write(link_header(LinkMessageType::NetConfig), &mut bytes)
                    .err(),
                Some(LinkError::PassphraseLength(psk.len())),
                "a passphrase of {} bytes was accepted",
                psk.len()
            );
        }
    }

    /// A country code is exactly two bytes, because ISO 3166-1 alpha-2 has no
    /// other length and a radio told otherwise picks the wrong channel plan.
    #[test]
    fn a_country_that_is_not_alpha_two_is_refused() {
        let mut bytes = [0u8; 256];
        for country in ["", "C", "CAN"] {
            let change = NetChange::Set {
                version: 4,
                ssid: "cabin",
                psk: "correct horse battery",
                country,
                hostname: "o89",
            };
            assert_eq!(
                change
                    .write(link_header(LinkMessageType::NetConfig), &mut bytes)
                    .err(),
                Some(LinkError::CountryNotTwoBytes(country.len()))
            );
        }
    }
}
