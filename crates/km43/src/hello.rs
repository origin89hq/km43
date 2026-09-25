//! `Hello 0x01` and `Hello 0x81`: the session handshake, `Noise_IK`, and the
//! order a controller reads one in.
//!
//! The controller's side is a chain of types, one per step of P-057. An
//! [`HelloArrival`] has only its routing fields and its suite; [`HelloArrival::admit`]
//! checks the admission tag against the slots, costing HMACs and no DH (P-238),
//! and hands back an [`Admitted`] naming the slot; [`Admitted::prove`] runs `es`
//! and `ss`, and only its [`Proved`] gives up the offer. No step can be skipped,
//! because no type offers the next one's data early:
//!
//! ```compile_fail
//! fn version(arrival: &km43::HelloArrival<'_>) -> km43::Version { arrival.offer().version }
//! ```
//!
//! The client's side runs against the controller key it pinned (P-222), never
//! one a `Discover` offered: [`HelloPending::start`] takes an [`Enrolment`] and
//! the enrolment is the only thing that holds the key.
//!
//! cites: P-057, P-070, P-071, P-072, P-073, P-226, P-228, P-238

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::{Envelope, EnvelopeError, Header, Refusal, ReqId, SessionId};
use crate::generated::{ErrorCode, MessageType, Suite};
use crate::handshake::{HandshakeError, HelloReport, MAX_HELLO_REPORT, Prologue, Version};
use crate::kdf::Enrolment;
use crate::limits::MAX_STRING;
use crate::mac::{AdmitKey, MAC_TAG_BYTES as ADMIT_BYTES, MacError};
use crate::noise::{
    Entropy, HelloInitiator, HelloProved, HelloResponder, KEY_BYTES, NoiseError, PublicKey,
    SEALED_KEY_BYTES, StaticKey, TAG_BYTES,
};
use crate::sealed::{ClientChannel, ControllerChannel};

/// The widest `HelloOffer`: a map head, three keys, two version bytes at their
/// widest and a `client_version` of [`MAX_STRING`].
pub const MAX_HELLO_OFFER: usize = 1 + 3 + 2 + 2 + 2 + MAX_STRING;

/// The widest message 1: an ephemeral key, the client key under its tag, and
/// the offer under its tag.
pub const MAX_HELLO_MESSAGE_1: usize = KEY_BYTES + SEALED_KEY_BYTES + MAX_HELLO_OFFER + TAG_BYTES;

/// The widest message 2: an ephemeral key and the report under its tag.
pub const MAX_HELLO_MESSAGE_2: usize = KEY_BYTES + MAX_HELLO_REPORT + TAG_BYTES;

/// The keys of `HelloOffer`, the payload of message 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HelloOfferKey {
    /// Key 1.
    ProtocolMajor,
    /// Key 2.
    ProtocolMinor,
    /// Key 3.
    ClientVersion,
}

impl HelloOfferKey {
    const COUNT: usize = 3;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ProtocolMajor),
            2 => Some(Self::ProtocolMinor),
            3 => Some(Self::ClientVersion),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ProtocolMajor => 1,
            Self::ProtocolMinor => 2,
            Self::ClientVersion => 3,
        }
    }
}

/// The keys of the two `Hello` bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HelloKey {
    /// `Hello 0x01` key 1.
    Suite,
    /// `Hello 0x01` key 2, and `Hello 0x81` key 1.
    Handshake,
    /// `Hello 0x01` key 3.
    Admit,
    /// A key of the offer inside message 1.
    Offer(HelloOfferKey),
}

impl fmt::Display for HelloKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suite => f.write_str("Hello suite (key 1)"),
            Self::Handshake => f.write_str("Hello handshake"),
            Self::Admit => f.write_str("Hello admit (key 3)"),
            Self::Offer(key) => write!(f, "HelloOffer key {}", key.number()),
        }
    }
}

/// What a client offers inside message 1, authenticated by `ss` (P-070).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloOffer<'a> {
    /// Keys 1 and 2.
    pub version: Version,
    /// Key 3, what a person reads in the client list.
    pub client_version: &'a str,
}

impl<'a> HelloOffer<'a> {
    fn encode(&self, dst: &mut [u8]) -> Result<usize, HelloError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(HelloOfferKey::COUNT)?;
        cbor.key(HelloOfferKey::ProtocolMajor.number())?;
        cbor.u64(u64::from(self.version.major))?;
        cbor.key(HelloOfferKey::ProtocolMinor.number())?;
        cbor.u64(u64::from(self.version.minor))?;
        cbor.key(HelloOfferKey::ClientVersion.number())?;
        cbor.text(self.client_version)?;
        Ok(cbor.finish()?)
    }

    fn decode(bytes: &'a [u8]) -> Result<Self, HelloError> {
        let mut body = CborReader::new(bytes);
        let pairs = body.map()?;
        let (mut major, mut minor, mut client_version) = (None, None, None);
        for _ in 0..pairs {
            let number = body.key()?;
            let Some(key) = HelloOfferKey::of(number) else {
                body.skip()?;
                continue;
            };
            let duplicate = match key {
                HelloOfferKey::ProtocolMajor => major.replace(body.u8()?).is_some(),
                HelloOfferKey::ProtocolMinor => minor.replace(body.u8()?).is_some(),
                HelloOfferKey::ClientVersion => client_version.replace(body.text()?).is_some(),
            };
            if duplicate {
                return Err(HelloError::Duplicate(HelloKey::Offer(key)));
            }
        }
        body.finish()?;
        let missing = |key| HelloError::Missing(HelloKey::Offer(key));
        Ok(Self {
            version: Version {
                major: major.ok_or(missing(HelloOfferKey::ProtocolMajor))?,
                minor: minor.ok_or(missing(HelloOfferKey::ProtocolMinor))?,
            },
            client_version: client_version.ok_or(missing(HelloOfferKey::ClientVersion))?,
        })
    }
}

/// A client's `Hello` in flight: message 1 is sent and message 2 is awaited.
///
/// No `Debug`: it holds an ephemeral private key.
pub struct HelloPending {
    initiator: HelloInitiator,
    header: Header,
    ours: Version,
}

impl HelloPending {
    /// Build message 1 against the enrolment's pinned controller key and write
    /// the whole `Hello 0x01` envelope into `dst`. `header` must name `Hello`
    /// and carry the handle the prologue carries (P-072).
    pub fn start(
        prologue: &Prologue,
        enrolment: &Enrolment,
        ephemeral: Entropy,
        offer: &HelloOffer<'_>,
        header: Header,
        dst: &mut [u8],
    ) -> Result<(Self, usize), HelloError> {
        expected(header, MessageType::Hello)?;
        let mut encoded = [0u8; MAX_HELLO_OFFER];
        let len = offer.encode(&mut encoded)?;
        let payload = encoded.get(..len).ok_or(HelloError::TooLargeToWrite)?;
        let mut message = [0u8; MAX_HELLO_MESSAGE_1];
        let (initiator, message_len) = HelloInitiator::start(
            prologue.as_bytes(),
            &enrolment.controller(),
            enrolment.static_key(),
            ephemeral,
            payload,
            &mut message,
        )?;
        let message = message
            .get(..message_len)
            .ok_or(HelloError::TooLargeToWrite)?;
        let admit = enrolment.admit_key()?.admit(prologue, message);
        let mut cbor = header.write(3, dst)?;
        cbor.key(1)?;
        cbor.u64(u64::from(enrolment.suite() as u8))?;
        cbor.key(2)?;
        cbor.bytes(message)?;
        cbor.key(3)?;
        cbor.bytes(admit.as_bytes())?;
        let written = cbor.finish()?;
        Ok((
            Self {
                initiator,
                header,
                ours: offer.version,
            },
            written,
        ))
    }

    /// Read `Hello 0x81`, which must answer this request (P-024), open message 2
    /// under the pinned controller key, and read the report out of it into
    /// `dst`. The version is agreed only now, from values the controller key
    /// vouched for (P-073).
    pub fn finish<'d>(
        self,
        enrolment: &Enrolment,
        envelope: Envelope<'_>,
        dst: &'d mut [u8],
    ) -> Result<Session<'d>, HelloError> {
        let header = envelope.header();
        expected(header, MessageType::HelloResponse)?;
        if header.req_id != self.header.req_id {
            return Err(HelloError::NotThisRequest(header.req_id));
        }
        if let SessionId::None = header.session {
            return Err(HelloError::NoHandle);
        }
        let message = answer_message(envelope)?;
        let (keys, report) = self
            .initiator
            .read_reply(enrolment.static_key(), message, dst)?;
        let report = HelloReport::decode(report, header.session)?;
        let version = self.ours.agreed(report.version)?;
        Ok(Session {
            channel: keys.for_initiator(),
            version,
            report,
        })
    }
}

/// A session a client has opened.
///
/// No `Debug`: it holds the session's keys.
pub struct Session<'d> {
    channel: ClientChannel,
    version: Version,
    report: HelloReport<'d>,
}

impl<'d> Session<'d> {
    /// The keys this session seals and opens under.
    pub fn channel(&mut self) -> &mut ClientChannel {
        &mut self.channel
    }

    /// The shared major and the lower of the two minors (P-073).
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// What the controller reported, authenticated by message 2.
    #[must_use]
    pub const fn report(&self) -> &HelloReport<'d> {
        &self.report
    }

    /// The channel on its own, for a caller that keeps the report elsewhere.
    #[must_use]
    pub fn into_channel(self) -> ClientChannel {
        self.channel
    }
}

/// A `Hello 0x01` as it arrived at the controller: routing, a suite, and bytes
/// nothing has authenticated.
pub struct HelloArrival<'a> {
    header: Header,
    suite: Suite,
    handshake: &'a [u8],
    admit: &'a [u8],
}

impl<'a> HelloArrival<'a> {
    /// Read one out of an envelope naming `Hello`. Exactly keys 1 to 3: a key
    /// beside them would be meaningful and outside everything the handshake
    /// authenticates. An unknown suite is refused here, before any work.
    pub fn decode(envelope: Envelope<'a>) -> Result<Self, HelloError> {
        let header = envelope.header();
        expected(header, MessageType::Hello)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let (mut suite, mut handshake, mut admit) = (None, None, None);
        for _ in 0..pairs {
            let number = body.key()?;
            let (key, duplicate) = match number {
                1 => (HelloKey::Suite, suite.replace(body.u8()?).is_some()),
                2 => (
                    HelloKey::Handshake,
                    handshake.replace(body.bytes()?).is_some(),
                ),
                3 => (HelloKey::Admit, admit.replace(body.bytes()?).is_some()),
                other => return Err(HelloError::UnknownKey(other)),
            };
            if duplicate {
                return Err(HelloError::Duplicate(key));
            }
        }
        body.finish()?;
        let suite = suite.ok_or(HelloError::Missing(HelloKey::Suite))?;
        Ok(Self {
            header,
            suite: Suite::try_from(suite).map_err(|()| HelloError::UnsupportedSuite(suite))?,
            handshake: handshake.ok_or(HelloError::Missing(HelloKey::Handshake))?,
            admit: admit.ok_or(HelloError::Missing(HelloKey::Admit))?,
        })
    }

    /// The routing fields, which the controller echoes (P-026).
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// P-238: the slot whose admission key tags this message, found with HMACs
    /// and no DH. Every key is tried, so how long it takes does not say which
    /// matched; no match is error 12, counted.
    pub fn admit<'k, K: Copy>(
        self,
        prologue: &Prologue,
        slots: impl IntoIterator<Item = (K, &'k AdmitKey)>,
    ) -> Result<Admitted<'a, K>, HelloError> {
        let mut found = None;
        for (slot, key) in slots {
            let verified = key.admit(prologue, self.handshake).verify(self.admit);
            if verified.is_ok() && found.is_none() {
                found = Some(slot);
            }
            if let Err(MacError::WrongWidth(len)) = verified {
                return Err(HelloError::AdmitWidth(len));
            }
        }
        Ok(Admitted {
            slot: found.ok_or(HelloError::NotAdmitted)?,
            header: self.header,
            suite: self.suite,
            handshake: self.handshake,
        })
    }
}

/// A `Hello` whose admission tag matched a slot. The slot is known; nothing
/// the message carries has been read.
pub struct Admitted<'a, K> {
    slot: K,
    header: Header,
    suite: Suite,
    handshake: &'a [u8],
}

impl<K: Copy> Admitted<'_, K> {
    /// Which slot.
    #[must_use]
    pub const fn slot(&self) -> K {
        self.slot
    }

    /// The suite the message named, which must be the slot's (P-226).
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// The suite, which must be the one the slot pinned (P-226), then `es`, then
    /// the client key, which must be `enrolled` — the slot's — then `ss`, which
    /// proves the sender holds it, and only then the offer (P-057).
    pub fn prove<'d>(
        self,
        prologue: &Prologue,
        controller: &StaticKey,
        enrolled: (&PublicKey, Suite),
        dst: &'d mut [u8],
    ) -> Result<Proved<'d, K>, HelloError> {
        let (enrolled, pinned) = enrolled;
        if self.suite != pinned {
            return Err(HelloError::UnsupportedSuite(self.suite as u8));
        }
        let claim = HelloResponder::read_claim(prologue.as_bytes(), controller, self.handshake)?;
        if !claim.claimed().matches(enrolled) {
            return Err(HelloError::KeyMismatch);
        }
        let (responder, offer) = claim.prove(controller, self.handshake, dst)?;
        Ok(Proved {
            slot: self.slot,
            header: self.header,
            offer: HelloOffer::decode(offer)?,
            responder,
        })
    }
}

/// A `Hello` whose client key is proved: the offer is readable and the reply is
/// the only step left.
pub struct Proved<'d, K> {
    slot: K,
    header: Header,
    offer: HelloOffer<'d>,
    responder: HelloProved,
}

impl<'d, K: Copy> Proved<'d, K> {
    /// Which slot.
    #[must_use]
    pub const fn slot(&self) -> K {
        self.slot
    }

    /// What the client offered, authenticated by `ss` (P-070).
    #[must_use]
    pub const fn offer(&self) -> HelloOffer<'d> {
        self.offer
    }

    /// Write `Hello 0x81` — message 2 carrying `report` — into `dst`, echoing
    /// the request's routing fields, and hand back the controller's side of the
    /// session.
    pub fn reply(
        self,
        ephemeral: Entropy,
        report: &HelloReport<'_>,
        dst: &mut [u8],
    ) -> Result<(ControllerChannel, usize), HelloError> {
        let mut encoded = [0u8; MAX_HELLO_REPORT];
        let len = report.encode(&mut encoded)?;
        let payload = encoded.get(..len).ok_or(HelloError::TooLargeToWrite)?;
        let mut message = [0u8; MAX_HELLO_MESSAGE_2];
        let (keys, message_len) = self.responder.reply(ephemeral, payload, &mut message)?;
        let message = message
            .get(..message_len)
            .ok_or(HelloError::TooLargeToWrite)?;
        let header = Header {
            kind: MessageType::HelloResponse,
            ..self.header
        };
        let mut cbor = header.write(1, dst)?;
        cbor.key(1)?;
        cbor.bytes(message)?;
        Ok((keys.for_responder(), cbor.finish()?))
    }
}

/// `Hello 0x81`'s one key: message 2.
fn answer_message(envelope: Envelope<'_>) -> Result<&[u8], HelloError> {
    let pairs = envelope.keys();
    let mut body = envelope.into_body();
    let mut handshake = None;
    for _ in 0..pairs {
        match body.key()? {
            1 => {
                if handshake.replace(body.bytes()?).is_some() {
                    return Err(HelloError::Duplicate(HelloKey::Handshake));
                }
            }
            other => return Err(HelloError::UnknownKey(other)),
        }
    }
    body.finish()?;
    handshake.ok_or(HelloError::Missing(HelloKey::Handshake))
}

fn expected(header: Header, kind: MessageType) -> Result<(), HelloError> {
    if header.kind == kind {
        Ok(())
    } else {
        Err(HelloError::WrongMessage {
            expected: kind,
            found: header.kind,
        })
    }
}

/// Why a `Hello` was refused, and whether it counts against
/// `MAX_AUTH_FAILURES` (P-051).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HelloError {
    /// A key the body does not carry: refused, never skipped.
    UnknownKey(i64),
    /// A key that arrived twice (P-015).
    Duplicate(HelloKey),
    /// A required key that never arrived.
    Missing(HelloKey),
    /// A suite this controller does not implement. Error 19, before anything
    /// else is read (P-226).
    UnsupportedSuite(u8),
    /// No slot's admission key tags this message. Error 12, counted (P-238).
    NotAdmitted,
    /// An admission tag that is not sixteen bytes.
    AdmitWidth(usize),
    /// Message 1 carries a client key that is not the admitted slot's. Error
    /// 10, counted.
    KeyMismatch,
    /// A handshake step failed: a tag, a truncation, a low-order point (P-228).
    /// Error 10, counted.
    Noise(NoiseError),
    /// An envelope naming another message.
    WrongMessage {
        /// What was expected.
        expected: MessageType,
        /// What arrived.
        found: MessageType,
    },
    /// A `Hello 0x81` answering another request (P-024).
    NotThisRequest(ReqId),
    /// A `Hello 0x81` at handle 0, which is no session (P-021).
    NoHandle,
    /// The report, or the version agreement over it.
    Report(HandshakeError),
    /// The output buffer is too small. Ours, not the peer's.
    TooLargeToWrite,
    /// The envelope this was written into.
    Envelope(EnvelopeError),
    /// The CBOR underneath.
    Cbor(CborError),
}

impl HelloError {
    /// What the controller answers. Every answer before a session exists is
    /// bare (P-142).
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::UnsupportedSuite(_) => Refusal::Client(ErrorCode::UnsupportedSuite),
            Self::NotAdmitted => Refusal::Client(ErrorCode::UnknownClient),
            Self::Noise(NoiseError::DestinationTooSmall) => {
                Refusal::Client(ErrorCode::PayloadTooLarge)
            }
            Self::KeyMismatch | Self::Noise(_) | Self::AdmitWidth(_) => {
                Refusal::Client(ErrorCode::AuthenticationFailed)
            }
            Self::Report(why) => why.refusal(),
            Self::Envelope(why) => why.refusal(),
            Self::TooLargeToWrite => Refusal::Client(ErrorCode::PayloadTooLarge),
            Self::UnknownKey(_)
            | Self::Duplicate(_)
            | Self::Missing(_)
            | Self::WrongMessage { .. }
            | Self::NotThisRequest(_)
            | Self::NoHandle
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }

    /// Whether this counts against `MAX_AUTH_FAILURES` (P-051): an admission
    /// tag that matched no slot, a key that was not the slot's, a handshake
    /// step that failed.
    #[must_use]
    pub const fn counts(self) -> bool {
        match self {
            // Our own buffer being too small is not the peer's failure.
            Self::Noise(why) => !matches!(why, NoiseError::DestinationTooSmall),
            Self::NotAdmitted | Self::AdmitWidth(_) | Self::KeyMismatch => true,
            Self::UnknownKey(_)
            | Self::Duplicate(_)
            | Self::Missing(_)
            | Self::UnsupportedSuite(_)
            | Self::WrongMessage { .. }
            | Self::NotThisRequest(_)
            | Self::NoHandle
            | Self::Report(_)
            | Self::TooLargeToWrite
            | Self::Envelope(_)
            | Self::Cbor(_) => false,
        }
    }
}

impl From<CborError> for HelloError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<NoiseError> for HelloError {
    fn from(why: NoiseError) -> Self {
        Self::Noise(why)
    }
}

impl From<HandshakeError> for HelloError {
    fn from(why: HandshakeError) -> Self {
        Self::Report(why)
    }
}

impl From<EnvelopeError> for HelloError {
    fn from(why: EnvelopeError) -> Self {
        Self::Envelope(why)
    }
}

impl fmt::Display for HelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(number) => write!(f, "a Hello body carries key {number}"),
            Self::Duplicate(key) => write!(f, "{key} arrived twice"),
            Self::Missing(key) => write!(f, "no {key} arrived"),
            Self::UnsupportedSuite(suite) => write!(f, "suite {suite} is not implemented"),
            Self::NotAdmitted => f.write_str("no slot's admission key tags this Hello"),
            Self::AdmitWidth(len) => {
                write!(f, "the admission tag is {len} bytes, not {ADMIT_BYTES}")
            }
            Self::KeyMismatch => f.write_str("the Hello carries a key that is not the slot's"),
            Self::Noise(why) => write!(f, "{why}"),
            Self::WrongMessage { expected, found } => write!(
                f,
                "message type {:#04x} where {:#04x} belongs",
                *found as u8, *expected as u8
            ),
            Self::NotThisRequest(req_id) => {
                write!(f, "a Hello 0x81 answering req_id {}", req_id.0)
            }
            Self::NoHandle => f.write_str("a session cannot be opened at handle 0"),
            Self::Report(why) => write!(f, "{why}"),
            Self::TooLargeToWrite => f.write_str("the frame does not fit the buffer"),
            Self::Envelope(why) => write!(f, "envelope: {why}"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for HelloError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{Caps, LogSeq, PrologueFields, StateSeq, Topology};
    use crate::kdf::{ClientId, DeviceId, Epoch, Generation};

    const DEVICE_ID: [u8; 16] = *b"ORIGIN89 DEMO 01";

    fn controller() -> StaticKey {
        StaticKey::from_stored([0x40; 32])
    }

    fn enrolment() -> Enrolment {
        Enrolment::new(
            DeviceId::new(DEVICE_ID),
            controller().public(),
            StaticKey::from_stored([0x60; 32]),
            Suite::X25519ChachapolySha256,
            Epoch::FIRST,
        )
    }

    fn prologue(handle: u16) -> Prologue {
        Prologue::new(&PrologueFields {
            suite: Suite::X25519ChachapolySha256,
            version: Version::V1_0,
            device_id: DeviceId::new(DEVICE_ID),
            epoch: Epoch::FIRST,
            challenge: &[0xC0; 16],
            handle: SessionId::from(handle),
        })
    }

    fn header(kind: MessageType) -> Header {
        Header {
            kind,
            session: SessionId::from(3),
            req_id: ReqId(3),
        }
    }

    fn offer() -> HelloOffer<'static> {
        HelloOffer {
            version: Version::V1_0,
            client_version: "o89-cli 0.1.0",
        }
    }

    fn report() -> HelloReport<'static> {
        HelloReport {
            version: Version::V1_0,
            session: SessionId::from(3),
            fw_controller: "fw",
            fw_comms: "comms",
            capabilities: 0,
            log_oldest_seq: LogSeq(1),
            log_newest_seq: LogSeq(2),
            state_seq: StateSeq(3),
            time_known: false,
            caps: Caps::THIS_CONTROLLER,
            topology: Topology::THIS_CONTROLLER,
            client_id: ClientId::new(7).expect("slot 7"),
            generation: Generation::FIRST,
        }
    }

    fn admit_key() -> AdmitKey {
        controller()
            .admit_key(DeviceId::new(DEVICE_ID), &enrolment().static_key().public())
            .expect("contributory")
    }

    fn hello(prologue: &Prologue) -> (HelloPending, [u8; 256], usize) {
        let mut frame = [0u8; 256];
        let (pending, len) = HelloPending::start(
            prologue,
            &enrolment(),
            Entropy::new([2; 32]),
            &offer(),
            header(MessageType::Hello),
            &mut frame,
        )
        .expect("message 1 writes");
        (pending, frame, len)
    }

    fn arrive(frame: &[u8]) -> HelloArrival<'_> {
        HelloArrival::decode(Envelope::decode(frame).expect("decodes")).expect("a Hello")
    }

    /// The whole session handshake between this crate's two ends: admitted to
    /// the right slot, proved, answered, and opened into a session whose report
    /// is the one sent.
    #[test]
    fn p_226_a_hello_is_admitted_proved_and_answered() {
        let at = prologue(3);
        let (pending, frame, len) = hello(&at);
        let admit = admit_key();
        let other = AdmitKey::from_stored([0x33; 32]);
        let mut plain = [0u8; 256];
        let proved = arrive(&frame[..len])
            .admit(&at, [(2u8, &other), (7u8, &admit)])
            .expect("admitted")
            .prove(
                &at,
                &controller(),
                (
                    &enrolment().static_key().public(),
                    Suite::X25519ChachapolySha256,
                ),
                &mut plain,
            )
            .expect("proved");
        assert_eq!(proved.slot(), 7);
        assert_eq!(proved.offer(), offer());
        let mut answer = [0u8; 512];
        let (_, len) = proved
            .reply(Entropy::new([4; 32]), &report(), &mut answer)
            .expect("answered");
        let mut report_buf = [0u8; 512];
        let session = pending
            .finish(
                &enrolment(),
                Envelope::decode(&answer[..len]).expect("decodes"),
                &mut report_buf,
            )
            .expect("opens");
        assert_eq!(*session.report(), report());
    }

    /// P-238: a `Hello` no slot's key tags is error 12, counted, and it is
    /// refused before any DH — garbage where message 1 belongs is refused at
    /// admission, not by a Noise error it never reached.
    #[test]
    fn p_238_a_hello_no_slot_admits_is_refused_before_any_dh() {
        let at = prologue(3);
        let mut frame = [0u8; 128];
        let mut cbor = header(MessageType::Hello)
            .write(3, &mut frame)
            .expect("fits");
        cbor.key(1).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(2).expect("k");
        cbor.bytes(&[0x5A; 96]).expect("not a Noise message at all");
        cbor.key(3).expect("k");
        cbor.bytes(&[0; 16]).expect("a tag of the right width");
        let len = cbor.finish().expect("done");
        let refused = arrive(&frame[..len])
            .admit(&at, [(7u8, &admit_key())])
            .err();
        assert_eq!(refused, Some(HelloError::NotAdmitted));
        assert!(HelloError::NotAdmitted.counts());
        assert_eq!(
            HelloError::NotAdmitted.refusal(),
            Refusal::Client(ErrorCode::UnknownClient)
        );
    }

    /// The admission tag covers the prologue: a `Hello` replayed onto another
    /// connection is not admitted.
    #[test]
    fn p_238_a_hello_moved_to_another_connection_is_not_admitted() {
        let (_, frame, len) = hello(&prologue(3));
        assert_eq!(
            arrive(&frame[..len])
                .admit(&prologue(4), [(7u8, &admit_key())])
                .err(),
            Some(HelloError::NotAdmitted)
        );
    }

    /// A slot whose admission key matches but whose stored client key is not the
    /// one message 1 carries is error 10, counted: the admission tag selects, the
    /// handshake proves.
    #[test]
    fn a_hello_carrying_another_key_than_its_slot_is_refused() {
        let at = prologue(3);
        let (_, frame, len) = hello(&at);
        let mut plain = [0u8; 256];
        let refused = arrive(&frame[..len])
            .admit(&at, [(7u8, &admit_key())])
            .expect("admitted")
            .prove(
                &at,
                &controller(),
                (
                    &StaticKey::from_stored([0x61; 32]).public(),
                    Suite::X25519ChachapolySha256,
                ),
                &mut plain,
            )
            .err();
        assert_eq!(refused, Some(HelloError::KeyMismatch));
        assert!(HelloError::KeyMismatch.counts());
    }

    /// P-070: an offer rewritten in flight is never read. The admission tag
    /// covers message 1 whole, so a flipped byte of the offer's ciphertext is
    /// refused there, before `ss` would have refused it.
    #[test]
    fn p_070_an_offer_rewritten_in_flight_is_never_read() {
        let at = prologue(3);
        let (_, mut frame, len) = hello(&at);
        // The offer's ciphertext sits just before key 3 and its 17 bytes.
        let at_offer = len - 17 - 2 - 5;
        frame[at_offer] ^= 1;
        let refused = arrive(&frame[..len])
            .admit(&at, [(7u8, &admit_key())])
            .err();
        assert_eq!(refused, Some(HelloError::NotAdmitted));
    }

    /// P-226: a suite this controller does not implement is error 19, before
    /// anything is read.
    #[test]
    fn p_226_an_unknown_suite_is_refused_before_anything_is_read() {
        let mut frame = [0u8; 64];
        let mut cbor = header(MessageType::Hello)
            .write(3, &mut frame)
            .expect("fits");
        cbor.key(1).expect("k");
        cbor.u64(2).expect("suite 2");
        cbor.key(2).expect("k");
        cbor.bytes(&[0; 8]).expect("v");
        cbor.key(3).expect("k");
        cbor.bytes(&[0; 16]).expect("v");
        let len = cbor.finish().expect("done");
        let refused = HelloArrival::decode(Envelope::decode(&frame[..len]).expect("decodes")).err();
        assert_eq!(refused, Some(HelloError::UnsupportedSuite(2)));
        assert_eq!(
            HelloError::UnsupportedSuite(2).refusal(),
            Refusal::Client(ErrorCode::UnsupportedSuite)
        );
    }

    /// P-057: a key beside the three a `Hello` carries is refused, never
    /// skipped: it would sit outside everything the handshake authenticates.
    #[test]
    fn p_057_a_hello_carrying_a_fourth_key_is_refused() {
        let mut frame = [0u8; 64];
        let mut cbor = header(MessageType::Hello)
            .write(4, &mut frame)
            .expect("fits");
        cbor.key(1).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(2).expect("k");
        cbor.bytes(&[0; 8]).expect("v");
        cbor.key(3).expect("k");
        cbor.bytes(&[0; 16]).expect("v");
        cbor.key(4).expect("k");
        cbor.u64(0).expect("v");
        let len = cbor.finish().expect("done");
        assert_eq!(
            HelloArrival::decode(Envelope::decode(&frame[..len]).expect("decodes")).err(),
            Some(HelloError::UnknownKey(4))
        );
    }

    /// P-072: a `Hello 0x81` at handle 0 is not a session, and one answering
    /// another request is not this one's.
    #[test]
    fn p_072_an_answer_at_handle_zero_or_to_another_request_is_refused() {
        let at = prologue(3);
        let (pending, _, _) = hello(&at);
        let mut frame = [0u8; 64];
        let mut cbor = Header {
            session: SessionId::from(0),
            ..header(MessageType::HelloResponse)
        }
        .write(1, &mut frame)
        .expect("fits");
        cbor.key(1).expect("k");
        cbor.bytes(&[0; 48]).expect("v");
        let len = cbor.finish().expect("done");
        let mut out = [0u8; 256];
        assert_eq!(
            pending
                .finish(
                    &enrolment(),
                    Envelope::decode(&frame[..len]).expect("decodes"),
                    &mut out
                )
                .err(),
            Some(HelloError::NoHandle)
        );

        let (pending, _, _) = hello(&at);
        let mut cbor = Header {
            req_id: ReqId(4),
            ..header(MessageType::HelloResponse)
        }
        .write(1, &mut frame)
        .expect("fits");
        cbor.key(1).expect("k");
        cbor.bytes(&[0; 48]).expect("v");
        let len = cbor.finish().expect("done");
        assert_eq!(
            pending
                .finish(
                    &enrolment(),
                    Envelope::decode(&frame[..len]).expect("decodes"),
                    &mut out
                )
                .err(),
            Some(HelloError::NotThisRequest(ReqId(4)))
        );
    }

    /// P-073: a controller answering with another major refuses the session at
    /// the client, from the report message 2 authenticated.
    #[test]
    fn p_073_a_report_in_another_major_refuses_the_session() {
        let at = prologue(3);
        let (pending, frame, len) = hello(&at);
        let mut plain = [0u8; 256];
        let proved = arrive(&frame[..len])
            .admit(&at, [(7u8, &admit_key())])
            .expect("admitted")
            .prove(
                &at,
                &controller(),
                (
                    &enrolment().static_key().public(),
                    Suite::X25519ChachapolySha256,
                ),
                &mut plain,
            )
            .expect("proved");
        let newer = HelloReport {
            version: Version { major: 2, minor: 0 },
            ..report()
        };
        let mut answer = [0u8; 512];
        let (_, len) = proved
            .reply(Entropy::new([4; 32]), &newer, &mut answer)
            .expect("answered");
        let mut out = [0u8; 512];
        assert!(matches!(
            pending.finish(
                &enrolment(),
                Envelope::decode(&answer[..len]).expect("decodes"),
                &mut out
            ),
            Err(HelloError::Report(HandshakeError::MajorMismatch { .. }))
        ));
    }

    /// Every truncation of a `Hello 0x01` is refused, at decode or at
    /// admission, and never panics.
    #[test]
    fn every_truncation_of_a_hello_is_refused() {
        let at = prologue(3);
        let (_, frame, len) = hello(&at);
        for cut in 0..len {
            let Ok(envelope) = Envelope::decode(&frame[..cut]) else {
                continue;
            };
            let admitted = HelloArrival::decode(envelope)
                .is_ok_and(|arrival| arrival.admit(&at, [(7u8, &admit_key())]).is_ok());
            assert!(!admitted, "a Hello cut to {cut} bytes was admitted");
        }
    }

    /// An offer skips a key it does not know (P-013) and refuses one twice.
    #[test]
    fn an_offer_skips_an_unknown_key_and_refuses_a_repeated_one() {
        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(4).expect("head");
        cbor.key(1).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(2).expect("k");
        cbor.u64(0).expect("v");
        cbor.key(3).expect("k");
        cbor.text("x").expect("v");
        cbor.key(9).expect("k");
        cbor.u64(1).expect("v");
        let len = cbor.finish().expect("done");
        assert_eq!(
            HelloOffer::decode(&out[..len])
                .expect("reads")
                .client_version,
            "x"
        );
        // Key 1 twice, in a map the reader otherwise accepts.
        let duplicated = [0xA2, 0x01, 0x01, 0x01, 0x01];
        assert!(HelloOffer::decode(&duplicated).is_err());
    }
}
