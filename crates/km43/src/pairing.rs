//! `Pair 0x0B`/`0x8B` and `Enrol 0x13`/`0x93`: enrolment under the label, as
//! the pairing handshake `Noise_XXpsk0`.
//!
//! Three things here are structural rather than remembered. A client reaches
//! message 3 only through a [`PairProceeding`], and only
//! [`PairPending::read`] makes one, after checking the controller key message 2
//! carries against the fingerprint on the label (P-236) — without that check a
//! label holder with a network position sits in the middle for the life of the
//! enrolment. A refusal is either a tag the label's refusal key verifies
//! (P-241) or nothing a client acts on. And the controller's answer to message
//! 3 can only be written sealed, under the keys that handshake split into.
//!
//! The window, the table and the button are the controller's; what is here is
//! the messages and the order they are read in.
//!
//! cites: P-054, P-057, P-058, P-064, P-105, P-229, P-236, P-240, P-241, P-242, P-250, P-258

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::{Envelope, EnvelopeError, Header, Refusal, ReqId};
use crate::generated::{ClientKind, ErrorCode, MessageType, Pair, Role, Suite};
use crate::handshake::{Prologue, Version};
use crate::kdf::{ClientId, Fingerprint, Generation, Label};
use crate::limits::{MAX_ADMINS, MAX_LABEL, MAX_STRING};
use crate::mac::{MAC_TAG_BYTES as REFUSAL_BYTES, MacError, RefusalKey};
use crate::noise::{
    CHALLENGE_BYTES, Entropy, KEY_BYTES, NoiseError, PairInitiator, PairReplied, PairResponder,
    Psk, PublicKey, SEALED_KEY_BYTES, StaticKey, TAG_BYTES,
};
use crate::sealed::{ClientChannel, ControllerChannel, SealError, Sealed};

/// The widest `PairOffer`: a map head, five keys, two version bytes, a
/// `client_version` of [`MAX_STRING`], a kind and a label of [`MAX_LABEL`].
pub const MAX_PAIR_OFFER: usize = 1 + 5 + 2 + 2 + 2 + MAX_STRING + 2 + 2 + MAX_LABEL;

/// The widest message 1: an ephemeral key and the offer under its tag.
pub const MAX_PAIR_MESSAGE_1: usize = KEY_BYTES + MAX_PAIR_OFFER + TAG_BYTES;

/// Messages 2 and 3 carry an empty map.
const EMPTY_MAP: [u8; 1] = [0xA0];

/// Message 2: an ephemeral key, the controller key under its tag, and the empty
/// map under its tag.
pub const PAIR_MESSAGE_2: usize = KEY_BYTES + SEALED_KEY_BYTES + EMPTY_MAP.len() + TAG_BYTES;

/// Message 3: the client key under its tag, and the empty map under its tag.
pub const PAIR_MESSAGE_3: usize = SEALED_KEY_BYTES + EMPTY_MAP.len() + TAG_BYTES;

/// `Enrol 0x93`'s widest inner body: four keys, an outcome, two `u32` and a
/// challenge.
pub const MAX_ENROL_ANSWER: usize = 1 + 4 + 1 + 5 + 5 + 1 + CHALLENGE_BYTES;

/// The keys of `PairOffer`, the payload of message 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairOfferKey {
    /// Key 1.
    ProtocolMajor,
    /// Key 2.
    ProtocolMinor,
    /// Key 3.
    ClientVersion,
    /// Key 4, which fixes the capability mask (P-105).
    ClientKind,
    /// Key 5, what a person reads in the client list.
    Label,
}

impl PairOfferKey {
    const COUNT: usize = 5;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ProtocolMajor),
            2 => Some(Self::ProtocolMinor),
            3 => Some(Self::ClientVersion),
            4 => Some(Self::ClientKind),
            5 => Some(Self::Label),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ProtocolMajor => 1,
            Self::ProtocolMinor => 2,
            Self::ClientVersion => 3,
            Self::ClientKind => 4,
            Self::Label => 5,
        }
    }
}

/// The keys of the four pairing bodies, so one refusal can name any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairKey {
    /// `Pair 0x0B` key 1.
    Suite,
    /// The Noise message a body carries.
    Handshake,
    /// `Pair 0x8B` key 1, or `Enrol 0x93` key 1.
    Outcome,
    /// `Pair 0x8B` key 3.
    Refusal,
    /// `Enrol 0x93` key 2.
    ClientId,
    /// `Enrol 0x93` key 3.
    Generation,
    /// `Enrol 0x93` key 4.
    NextChallenge,
    /// A key of the offer inside message 1.
    Offer(PairOfferKey),
}

impl fmt::Display for PairKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suite => f.write_str("suite"),
            Self::Handshake => f.write_str("handshake"),
            Self::Outcome => f.write_str("outcome"),
            Self::Refusal => f.write_str("refusal"),
            Self::ClientId => f.write_str("client_id"),
            Self::Generation => f.write_str("generation"),
            Self::NextChallenge => f.write_str("next_challenge"),
            Self::Offer(key) => write!(f, "PairOffer key {}", key.number()),
        }
    }
}

/// What a client offers inside message 1, sealed under the pre-shared key so
/// the comms processor can neither read nor rewrite it (P-105).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairOffer<'a> {
    /// Keys 1 and 2.
    pub version: Version,
    /// Key 3.
    pub client_version: &'a str,
    /// Key 4.
    pub client_kind: ClientKind,
    /// Key 5, compared byte for byte when P-240 looks for a slot to reclaim.
    pub label: &'a str,
}

impl<'a> PairOffer<'a> {
    fn encode(&self, dst: &mut [u8]) -> Result<usize, PairError> {
        if self.label.len() > MAX_LABEL {
            return Err(PairError::LabelTooLong(self.label.len()));
        }
        let mut cbor = CborWriter::new(dst);
        cbor.map(PairOfferKey::COUNT)?;
        cbor.key(PairOfferKey::ProtocolMajor.number())?;
        cbor.u64(u64::from(self.version.major))?;
        cbor.key(PairOfferKey::ProtocolMinor.number())?;
        cbor.u64(u64::from(self.version.minor))?;
        cbor.key(PairOfferKey::ClientVersion.number())?;
        cbor.text(self.client_version)?;
        cbor.key(PairOfferKey::ClientKind.number())?;
        cbor.u64(u64::from(self.client_kind as u8))?;
        cbor.key(PairOfferKey::Label.number())?;
        cbor.text(self.label)?;
        Ok(cbor.finish()?)
    }

    fn decode(bytes: &'a [u8]) -> Result<Self, PairError> {
        let mut body = CborReader::new(bytes);
        let pairs = body.map()?;
        let (mut major, mut minor, mut version, mut kind, mut label) =
            (None, None, None, None, None);
        for _ in 0..pairs {
            let number = body.key()?;
            let Some(key) = PairOfferKey::of(number) else {
                body.skip()?;
                continue;
            };
            let duplicate = match key {
                PairOfferKey::ProtocolMajor => major.replace(body.u8()?).is_some(),
                PairOfferKey::ProtocolMinor => minor.replace(body.u8()?).is_some(),
                PairOfferKey::ClientVersion => version.replace(body.text()?).is_some(),
                PairOfferKey::ClientKind => {
                    let raw = body.u8()?;
                    let parsed =
                        ClientKind::try_from(raw).map_err(|()| PairError::UnknownKind(raw))?;
                    kind.replace(parsed).is_some()
                }
                PairOfferKey::Label => {
                    let text = body.text()?;
                    if text.len() > MAX_LABEL {
                        return Err(PairError::LabelTooLong(text.len()));
                    }
                    label.replace(text).is_some()
                }
            };
            if duplicate {
                return Err(PairError::Duplicate(PairKey::Offer(key)));
            }
        }
        body.finish()?;
        let missing = |key| PairError::Missing(PairKey::Offer(key));
        Ok(Self {
            version: Version {
                major: major.ok_or(missing(PairOfferKey::ProtocolMajor))?,
                minor: minor.ok_or(missing(PairOfferKey::ProtocolMinor))?,
            },
            client_version: version.ok_or(missing(PairOfferKey::ClientVersion))?,
            client_kind: kind.ok_or(missing(PairOfferKey::ClientKind))?,
            label: label.ok_or(missing(PairOfferKey::Label))?,
        })
    }
}

/// The two refusals a controller answers message 1 with (P-241).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairRefusal {
    /// Outcome 2: no window was open (P-066).
    WindowClosed,
    /// Outcome 4: no free slot and no label to reclaim (P-067, P-240).
    TableFull,
}

impl PairRefusal {
    const fn outcome(self) -> Pair {
        match self {
            Self::WindowClosed => Pair::WindowClosed,
            Self::TableFull => Pair::TableFull,
        }
    }
}

/// How an enrolment ended, as `Enrol 0x93` says it. The slot rides inside the
/// two outcomes that name one, so the zero a refusal would carry cannot be read
/// out as slot zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Outcome {
    /// Outcome 1: a free slot now holds the client's key.
    Enrolled(ClientId, Generation),
    /// Outcome 5: P-240 re-keyed the lowest slot with this label.
    Reclaimed(ClientId, Generation),
    /// Outcome 2: the window closed before message 3 arrived.
    WindowClosed,
    /// Outcome 4: the table filled before message 3 arrived.
    TableFull,
    /// Outcome 7: the slot could not be written, so nothing was enrolled.
    NotStored,
}

impl Outcome {
    /// The registry number.
    #[must_use]
    pub const fn code(self) -> Pair {
        match self {
            Self::Enrolled(..) => Pair::Enrolled,
            Self::Reclaimed(..) => Pair::Reclaimed,
            Self::WindowClosed => Pair::WindowClosed,
            Self::TableFull => Pair::TableFull,
            Self::NotStored => Pair::NotStored,
        }
    }

    /// The slot and generation this outcome names, or nothing.
    #[must_use]
    pub const fn slot(self) -> Option<(ClientId, Generation)> {
        match self {
            Self::Enrolled(id, generation) | Self::Reclaimed(id, generation) => {
                Some((id, generation))
            }
            Self::WindowClosed | Self::TableFull | Self::NotStored => None,
        }
    }
}

/// What `Enrol 0x93` carries: how it ended, and the challenge the `Hello` that
/// follows presents (P-058).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrolAnswer {
    /// How the enrolment ended.
    pub outcome: Outcome,
    /// The connection's live challenge now that message 1 spent the other.
    pub next_challenge: [u8; CHALLENGE_BYTES],
}

impl EnrolAnswer {
    /// The inner body, before it is sealed.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, PairError> {
        let slot = self.outcome.slot();
        let mut cbor = CborWriter::new(dst);
        cbor.map(if slot.is_some() { 4 } else { 2 })?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.outcome.code() as u8))?;
        if let Some((id, generation)) = slot {
            cbor.key(2)?;
            cbor.u64(u64::from(id.get()))?;
            cbor.key(3)?;
            cbor.u64(u64::from(generation.get()))?;
        }
        cbor.key(4)?;
        cbor.bytes(&self.next_challenge)?;
        Ok(cbor.finish()?)
    }

    /// Read the inner body back, refusing a slot on an outcome that names none
    /// and a missing one on an outcome that does.
    pub fn decode(bytes: &[u8]) -> Result<Self, PairError> {
        let mut body = CborReader::new(bytes);
        let pairs = body.map()?;
        let (mut outcome, mut id, mut generation, mut challenge) = (None, None, None, None);
        for _ in 0..pairs {
            let number = body.key()?;
            let (key, duplicate) = match number {
                1 => (PairKey::Outcome, outcome.replace(body.u8()?).is_some()),
                2 => (PairKey::ClientId, id.replace(body.u32()?).is_some()),
                3 => (
                    PairKey::Generation,
                    generation.replace(body.u32()?).is_some(),
                ),
                4 => (
                    PairKey::NextChallenge,
                    challenge
                        .replace(
                            <[u8; CHALLENGE_BYTES]>::try_from(body.bytes()?)
                                .map_err(|_| PairError::WrongWidth(PairKey::NextChallenge))?,
                        )
                        .is_some(),
                ),
                _ => {
                    body.skip()?;
                    continue;
                }
            };
            if duplicate {
                return Err(PairError::Duplicate(key));
            }
        }
        body.finish()?;
        let raw = outcome.ok_or(PairError::Missing(PairKey::Outcome))?;
        let code = Pair::try_from(raw).map_err(|()| PairError::UnknownOutcome(raw))?;
        let slot = || -> Result<(ClientId, Generation), PairError> {
            Ok((
                id.and_then(ClientId::new)
                    .ok_or(PairError::Missing(PairKey::ClientId))?,
                generation
                    .and_then(Generation::new)
                    .ok_or(PairError::Missing(PairKey::Generation))?,
            ))
        };
        let none = |outcome| {
            if id.is_some() || generation.is_some() {
                Err(PairError::SlotOnARefusal)
            } else {
                Ok(outcome)
            }
        };
        let outcome = match code {
            Pair::Enrolled => {
                let (id, generation) = slot()?;
                Outcome::Enrolled(id, generation)
            }
            Pair::Reclaimed => {
                let (id, generation) = slot()?;
                Outcome::Reclaimed(id, generation)
            }
            Pair::WindowClosed => none(Outcome::WindowClosed)?,
            Pair::TableFull => none(Outcome::TableFull)?,
            Pair::NotStored => none(Outcome::NotStored)?,
            Pair::Proceed => return Err(PairError::UnknownOutcome(raw)),
        };
        Ok(Self {
            outcome,
            next_challenge: challenge.ok_or(PairError::Missing(PairKey::NextChallenge))?,
        })
    }
}

/// One slot of the client table as P-240 reads it: its number, and what it
/// holds if it is occupied. "Occupied" is P-239's — the record passes its
/// check, says occupied, and was written in the current epoch — and the caller
/// decides it; a slot from an earlier epoch is `None` here.
#[derive(Debug, Clone, Copy)]
pub struct SlotView<'a> {
    /// The slot's `client_id`.
    pub client_id: ClientId,
    /// What an occupied slot holds, or `None` for a free one.
    pub held: Option<Occupant<'a>>,
}

/// What an occupied slot holds that P-240 reads. The role is here because
/// without it a label could reclaim the owner's slot, and a seventh admin could
/// take the row kept for an owner (P-258).
#[derive(Debug, Clone, Copy)]
pub struct Occupant<'a> {
    /// The enrolled client key.
    pub key: PublicKey,
    /// The label it paired under, as the bytes `PairOffer` carried.
    pub label: &'a str,
    /// The role written with the key record (P-250).
    pub role: Role,
}

/// A slot P-240 gives an enrolment and the role the enrolment takes with it.
/// The two are decided together because the role decides which slots were
/// candidates at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Placement {
    /// The slot's `client_id`.
    pub client_id: ClientId,
    /// The role to write with the new key record.
    pub role: Role,
}

/// Which slot P-240 gives an enrolment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Allocation {
    /// The slot that already holds this client key: the same install pairing
    /// again, keeping its role. Answered as a reclaim, because the slot is
    /// re-keyed with a new generation all the same.
    SameKey(Placement),
    /// The lowest free slot (P-086) the role may take, answered `enrolled`.
    Free(Placement),
    /// The lowest `admin` slot whose label is byte-identical, answered
    /// `reclaimed`: the old install's key is erased with it and the role stays
    /// `admin`. A table without an owner never gets here, because admins and a
    /// viewer cannot fill it ([`MAX_ADMINS`]) and step 2 seats the owner first.
    Reclaim(Placement),
    /// Nothing to allocate: `table_full`.
    Full,
}

impl Allocation {
    /// P-240, in its order: the same key, then the lowest free slot, then the
    /// lowest `admin` slot with this exact label, then nothing. `key` is `None`
    /// at message 1, which carries no client key, so the first step is skipped
    /// there and runs at message 3. Labels are compared as bytes, because two
    /// implementations that normalise differently hand one phone another's slot.
    ///
    /// A new enrolment is `owner` when no slot holds one and `admin` otherwise
    /// (P-250), and an `admin` finds no free slot once [`MAX_ADMINS`] hold
    /// `admin` (P-258). A free slot comes before a reclaim because a reclaim
    /// revokes: two phones both called "iPhone" would otherwise take the slot
    /// from each other on every pairing.
    #[must_use]
    pub fn choose(slots: &[SlotView<'_>], key: Option<&PublicKey>, label: &str) -> Self {
        let occupants = || {
            slots
                .iter()
                .filter_map(|slot| Some((slot.client_id, slot.held?)))
        };
        let lowest = |pick: &dyn Fn(&Occupant<'_>) -> bool| {
            occupants()
                .filter(|(_, occupant)| pick(occupant))
                .min_by_key(|(id, _)| id.get())
        };
        if let Some(key) = key
            && let Some((client_id, occupant)) = lowest(&|occupant| occupant.key.matches(key))
        {
            return Self::SameKey(Placement {
                client_id,
                role: occupant.role,
            });
        }
        let holding = |role: Role| {
            occupants()
                .filter(|(_, occupant)| occupant.role == role)
                .count()
        };
        let (role, room) = if holding(Role::Owner) == 0 {
            (Role::Owner, true)
        } else {
            (Role::Admin, holding(Role::Admin) < MAX_ADMINS)
        };
        let free = slots
            .iter()
            .filter(|slot| slot.held.is_none())
            .map(|slot| slot.client_id)
            .min_by_key(|id| id.get());
        if room && let Some(client_id) = free {
            return Self::Free(Placement { client_id, role });
        }
        if let Some((client_id, _)) = lowest(&|occupant| {
            occupant.role == Role::Admin && occupant.label.as_bytes() == label.as_bytes()
        }) {
            return Self::Reclaim(Placement {
                client_id,
                role: Role::Admin,
            });
        }
        Self::Full
    }
}

/// A client's pairing, message 1 sent.
///
/// No `Debug`: it holds an ephemeral private key.
pub struct PairPending {
    initiator: PairInitiator,
    header: Header,
}

impl PairPending {
    /// Build message 1 under the label's pre-shared key and write the whole
    /// `Pair 0x0B` envelope into `dst`. `header` names `Pair` and carries the
    /// handle the prologue carries.
    pub fn start(
        prologue: &Prologue,
        suite: Suite,
        label: &Label,
        ephemeral: Entropy,
        offer: &PairOffer<'_>,
        header: Header,
        dst: &mut [u8],
    ) -> Result<(Self, usize), PairError> {
        expected(header, MessageType::Pair)?;
        let mut encoded = [0u8; MAX_PAIR_OFFER];
        let len = offer.encode(&mut encoded)?;
        let payload = encoded.get(..len).ok_or(PairError::TooLargeToWrite)?;
        let mut message = [0u8; MAX_PAIR_MESSAGE_1];
        let (initiator, message_len) = PairInitiator::start(
            prologue.as_bytes(),
            &label.pair_psk(),
            ephemeral,
            payload,
            &mut message,
        )?;
        let message = message
            .get(..message_len)
            .ok_or(PairError::TooLargeToWrite)?;
        let mut cbor = header.write(2, dst)?;
        cbor.key(1)?;
        cbor.u64(u64::from(suite as u8))?;
        cbor.key(2)?;
        cbor.bytes(message)?;
        Ok((Self { initiator, header }, cbor.finish()?))
    }

    /// Read `Pair 0x8B`. A refusal is believed only if the label's refusal key
    /// verifies its tag over this attempt (P-241); message 2 only if the key
    /// it proves is the one the label's fingerprint names (P-236). Anything
    /// else is P-066's bare error 10 as far as a client is concerned.
    pub fn read(
        self,
        envelope: Envelope<'_>,
        label: &Label,
        fingerprint: &Fingerprint,
    ) -> Result<PairReply, PairError> {
        let header = envelope.header();
        expected(header, MessageType::PairResponse)?;
        if header.req_id != self.header.req_id {
            return Err(PairError::NotThisRequest(header.req_id));
        }
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let (mut outcome, mut handshake, mut refusal) = (None, None, None);
        for _ in 0..pairs {
            let number = body.key()?;
            let (key, duplicate) = match number {
                1 => (PairKey::Outcome, outcome.replace(body.u8()?).is_some()),
                2 => (
                    PairKey::Handshake,
                    handshake.replace(body.bytes()?).is_some(),
                ),
                3 => (PairKey::Refusal, refusal.replace(body.bytes()?).is_some()),
                other => return Err(PairError::UnknownKey(other)),
            };
            if duplicate {
                return Err(PairError::Duplicate(key));
            }
        }
        body.finish()?;
        let raw = outcome.ok_or(PairError::Missing(PairKey::Outcome))?;
        let refused = match Pair::try_from(raw) {
            Ok(Pair::Proceed) => None,
            Ok(Pair::WindowClosed) => Some(PairRefusal::WindowClosed),
            Ok(Pair::TableFull) => Some(PairRefusal::TableFull),
            Ok(Pair::Enrolled | Pair::Reclaimed | Pair::NotStored) | Err(()) => {
                return Err(PairError::UnknownOutcome(raw));
            }
        };
        if let Some(refused) = refused {
            if handshake.is_some() {
                return Err(PairError::UnknownKey(2));
            }
            let tag = refusal.ok_or(PairError::Missing(PairKey::Refusal))?;
            label
                .refusal_key()
                .refusal(self.initiator.handshake_hash(), refused.outcome())
                .verify(tag)?;
            return Ok(PairReply::Refused(refused));
        }
        if refusal.is_some() {
            return Err(PairError::UnknownKey(3));
        }
        let message = handshake.ok_or(PairError::Missing(PairKey::Handshake))?;
        let mut empty = [0u8; PAIR_MESSAGE_2];
        let (replied, _) = self.initiator.read_reply(message, &mut empty)?;
        if !fingerprint.vouches_for(&replied.controller()) {
            return Err(PairError::NotTheLabelsController);
        }
        Ok(PairReply::Proceed(PairProceeding { replied }))
    }
}

/// How the controller answered message 1.
pub enum PairReply {
    /// Message 2, from the controller the label names.
    Proceed(PairProceeding),
    /// A refusal the label's key vouches for.
    Refused(PairRefusal),
}

/// Message 2 checked out against the label; message 3 is the only step left.
pub struct PairProceeding {
    replied: PairReplied,
}

impl PairProceeding {
    /// The controller key the label vouched for, which the client pins.
    #[must_use]
    pub const fn controller(&self) -> PublicKey {
        self.replied.controller()
    }

    /// Write `Enrol 0x13` carrying message 3 with the client's new static
    /// `key`. P-064: the client MUST have kept `key` and
    /// [`PairProceeding::controller`] durably before it calls this, because the
    /// answer can be lost and the controller may already hold the key (P-242).
    pub fn finish(
        self,
        key: &StaticKey,
        header: Header,
        dst: &mut [u8],
    ) -> Result<(EnrolPending, usize), PairError> {
        expected(header, MessageType::Enrol)?;
        let mut message = [0u8; PAIR_MESSAGE_3];
        let (keys, message_len) = self.replied.finish(key, &EMPTY_MAP, &mut message)?;
        let message = message
            .get(..message_len)
            .ok_or(PairError::TooLargeToWrite)?;
        let mut cbor = header.write(1, dst)?;
        cbor.key(1)?;
        cbor.bytes(message)?;
        Ok((
            EnrolPending {
                channel: keys.for_initiator(),
                header,
            },
            cbor.finish()?,
        ))
    }
}

/// Message 3 sent; `Enrol 0x93` is awaited under the keys it split into.
pub struct EnrolPending {
    channel: ClientChannel,
    header: Header,
}

impl EnrolPending {
    /// Open `Enrol 0x93`, which must answer this request, into `dst`, and read
    /// what it says. The keys are dropped afterwards: a pairing opens no
    /// session (P-064).
    pub fn read(
        mut self,
        envelope: Envelope<'_>,
        dst: &mut [u8],
    ) -> Result<EnrolAnswer, PairError> {
        let header = envelope.header();
        expected(header, MessageType::EnrolResponse)?;
        if header.req_id != self.header.req_id {
            return Err(PairError::NotThisRequest(header.req_id));
        }
        let opened = Sealed::decode(envelope)?.open(&mut self.channel.rx, dst)?;
        EnrolAnswer::decode(opened.inner())
    }
}

/// A `Pair 0x0B` as it arrived at the controller.
pub struct PairArrival<'a> {
    header: Header,
    handshake: &'a [u8],
}

impl<'a> PairArrival<'a> {
    /// Read one out of an envelope naming `Pair`: exactly keys 1 and 2, and an
    /// unknown suite refused before any work (P-226).
    pub fn decode(envelope: Envelope<'a>) -> Result<Self, PairError> {
        let header = envelope.header();
        expected(header, MessageType::Pair)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let (mut suite, mut handshake) = (None, None);
        for _ in 0..pairs {
            let number = body.key()?;
            let (key, duplicate) = match number {
                1 => (PairKey::Suite, suite.replace(body.u8()?).is_some()),
                2 => (
                    PairKey::Handshake,
                    handshake.replace(body.bytes()?).is_some(),
                ),
                other => return Err(PairError::UnknownKey(other)),
            };
            if duplicate {
                return Err(PairError::Duplicate(key));
            }
        }
        body.finish()?;
        let suite = suite.ok_or(PairError::Missing(PairKey::Suite))?;
        Suite::try_from(suite).map_err(|()| PairError::UnsupportedSuite(suite))?;
        Ok(Self {
            header,
            handshake: handshake.ok_or(PairError::Missing(PairKey::Handshake))?,
        })
    }

    /// Open message 1 under the label's pre-shared key into `dst`: no DH, one
    /// HKDF chain and one tag. A failure is P-066's bare error 10, counted.
    pub fn open<'d>(
        self,
        prologue: &Prologue,
        psk: &Psk,
        dst: &'d mut [u8],
    ) -> Result<Offered<'d>, PairError> {
        let (requested, offer) =
            PairResponder::read_request(prologue.as_bytes(), psk, self.handshake, dst)?;
        Ok(Offered {
            header: self.header,
            requested,
            offer: PairOffer::decode(offer)?,
        })
    }
}

/// Message 1 opened: the peer holds the label, and the offer is readable.
pub struct Offered<'d> {
    header: Header,
    requested: crate::noise::PairRequested,
    offer: PairOffer<'d>,
}

impl<'d> Offered<'d> {
    /// What the client offered, sealed under the pre-shared key.
    #[must_use]
    pub const fn offer(&self) -> PairOffer<'d> {
        self.offer
    }

    /// Answer `Pair 0x8B` with a refusal tagged under the label's refusal key
    /// (P-241), and abandon the handshake. One HMAC; no DH.
    pub fn refuse(
        self,
        refusal: PairRefusal,
        key: &RefusalKey,
        dst: &mut [u8],
    ) -> Result<usize, PairError> {
        let tag = key.refusal(self.requested.handshake_hash(), refusal.outcome());
        let header = Header {
            kind: MessageType::PairResponse,
            ..self.header
        };
        let mut cbor = header.write(2, dst)?;
        cbor.key(1)?;
        cbor.u64(u64::from(refusal.outcome() as u8))?;
        cbor.key(3)?;
        cbor.bytes(tag.as_bytes())?;
        Ok(cbor.finish()?)
    }

    /// Answer `Pair 0x8B` with outcome 6 and message 2, and wait for message 3.
    pub fn proceed(
        self,
        controller: &StaticKey,
        ephemeral: Entropy,
        dst: &mut [u8],
    ) -> Result<(EnrolAwaiting, usize), PairError> {
        let mut message = [0u8; PAIR_MESSAGE_2];
        let (awaiting, message_len) =
            self.requested
                .reply(controller, ephemeral, &EMPTY_MAP, &mut message)?;
        let message = message
            .get(..message_len)
            .ok_or(PairError::TooLargeToWrite)?;
        let header = Header {
            kind: MessageType::PairResponse,
            ..self.header
        };
        let mut cbor = header.write(2, dst)?;
        cbor.key(1)?;
        cbor.u64(u64::from(Pair::Proceed as u8))?;
        cbor.key(2)?;
        cbor.bytes(message)?;
        Ok((EnrolAwaiting { awaiting }, cbor.finish()?))
    }
}

/// Message 2 sent; the controller waits for message 3.
pub struct EnrolAwaiting {
    awaiting: crate::noise::PairAwaiting,
}

impl EnrolAwaiting {
    /// Read `Enrol 0x13`: exactly key 1, message 3. What comes back names the
    /// client key `se` proved, and holds the keys the answer is sealed under.
    pub fn read(self, envelope: Envelope<'_>) -> Result<Enrolling, PairError> {
        let header = envelope.header();
        expected(header, MessageType::Enrol)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut handshake = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => {
                    if handshake.replace(body.bytes()?).is_some() {
                        return Err(PairError::Duplicate(PairKey::Handshake));
                    }
                }
                other => return Err(PairError::UnknownKey(other)),
            }
        }
        body.finish()?;
        let message = handshake.ok_or(PairError::Missing(PairKey::Handshake))?;
        let mut empty = [0u8; PAIR_MESSAGE_3];
        let (finished, _) = self.awaiting.read_finish(message, &mut empty)?;
        Ok(Enrolling {
            client: finished.client,
            header,
            channel: finished.keys.for_responder(),
        })
    }
}

/// Message 3 opened: the client key is proved, and the answer is the last thing
/// the pairing's keys seal.
pub struct Enrolling {
    client: PublicKey,
    header: Header,
    channel: ControllerChannel,
}

impl Enrolling {
    /// The key to store in the slot P-240 picks.
    #[must_use]
    pub const fn client(&self) -> PublicKey {
        self.client
    }

    /// Seal `Enrol 0x93` into `dst`. The keys are dropped with `self`: a
    /// pairing opens no session.
    pub fn answer(mut self, answer: &EnrolAnswer, dst: &mut [u8]) -> Result<usize, PairError> {
        let mut inner = [0u8; MAX_ENROL_ANSWER];
        let len = answer.encode(&mut inner)?;
        let inner = inner.get(..len).ok_or(PairError::TooLargeToWrite)?;
        let header = Header {
            kind: MessageType::EnrolResponse,
            ..self.header
        };
        Ok(self.channel.tx.seal(header, inner, dst)?)
    }
}

fn expected(header: Header, kind: MessageType) -> Result<(), PairError> {
    if header.kind == kind {
        Ok(())
    } else {
        Err(PairError::WrongMessage {
            expected: kind,
            found: header.kind,
        })
    }
}

/// Why a pairing message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PairError {
    /// A key the body does not carry: refused, never skipped.
    UnknownKey(i64),
    /// A key that arrived twice (P-015).
    Duplicate(PairKey),
    /// A required key that never arrived.
    Missing(PairKey),
    /// A field of the wrong width.
    WrongWidth(PairKey),
    /// A suite this controller does not implement. Error 19 (P-226).
    UnsupportedSuite(u8),
    /// A `client_kind` outside the closed set (P-105): a malformed offer.
    UnknownKind(u8),
    /// A label longer than [`MAX_LABEL`].
    LabelTooLong(usize),
    /// An outcome this message does not carry.
    UnknownOutcome(u8),
    /// A refusal outcome carrying a slot.
    SlotOnARefusal,
    /// A handshake step failed: the wrong label, a rewritten prologue, a
    /// forgery, a low-order point. Error 10, counted (P-066).
    Noise(NoiseError),
    /// A refusal whose tag the label's key does not verify. A client treats it
    /// as error 10 (P-241).
    Refusal(MacError),
    /// Message 2 proved a key the label's fingerprint does not name. The client
    /// abandons the pairing without sending message 3 (P-236).
    NotTheLabelsController,
    /// A response answering another request (P-024).
    NotThisRequest(ReqId),
    /// An envelope naming another message.
    WrongMessage {
        /// What was expected.
        expected: MessageType,
        /// What arrived.
        found: MessageType,
    },
    /// `Enrol 0x93`'s sealed body.
    Sealed(SealError),
    /// The output buffer is too small. Ours, not the peer's.
    TooLargeToWrite,
    /// The envelope this was written into.
    Envelope(EnvelopeError),
    /// The CBOR underneath.
    Cbor(CborError),
}

impl PairError {
    /// What the controller answers. Every answer before `Enrol 0x93` is bare.
    /// `None` where the sealed layer answers with silence (P-233).
    #[must_use]
    pub const fn refusal(self) -> Option<Refusal> {
        match self {
            Self::Sealed(why) => why.refusal(),
            Self::UnsupportedSuite(_) => Some(Refusal::Client(ErrorCode::UnsupportedSuite)),
            Self::Noise(NoiseError::DestinationTooSmall) | Self::TooLargeToWrite => {
                Some(Refusal::Client(ErrorCode::PayloadTooLarge))
            }
            Self::Noise(_) | Self::Refusal(_) | Self::NotTheLabelsController => {
                Some(Refusal::Client(ErrorCode::AuthenticationFailed))
            }
            Self::Envelope(why) => Some(why.refusal()),
            Self::UnknownKey(_)
            | Self::Duplicate(_)
            | Self::Missing(_)
            | Self::WrongWidth(_)
            | Self::UnknownKind(_)
            | Self::LabelTooLong(_)
            | Self::UnknownOutcome(_)
            | Self::SlotOnARefusal
            | Self::NotThisRequest(_)
            | Self::WrongMessage { .. }
            | Self::Cbor(_) => Some(Refusal::Client(ErrorCode::MalformedFrame)),
        }
    }

    /// Whether this counts against `MAX_AUTH_FAILURES` (P-051): a message 1 or
    /// 3 that did not open. A refusal the controller sent is not a failure.
    #[must_use]
    pub const fn counts(self) -> bool {
        match self {
            // Our own buffer being too small is not the peer's failure.
            Self::Noise(why) => !matches!(why, NoiseError::DestinationTooSmall),
            Self::UnknownKey(_)
            | Self::Duplicate(_)
            | Self::Missing(_)
            | Self::WrongWidth(_)
            | Self::UnsupportedSuite(_)
            | Self::UnknownKind(_)
            | Self::LabelTooLong(_)
            | Self::UnknownOutcome(_)
            | Self::SlotOnARefusal
            | Self::Refusal(_)
            | Self::NotTheLabelsController
            | Self::NotThisRequest(_)
            | Self::WrongMessage { .. }
            | Self::Sealed(_)
            | Self::TooLargeToWrite
            | Self::Envelope(_)
            | Self::Cbor(_) => false,
        }
    }
}

impl From<CborError> for PairError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<NoiseError> for PairError {
    fn from(why: NoiseError) -> Self {
        Self::Noise(why)
    }
}

impl From<MacError> for PairError {
    fn from(why: MacError) -> Self {
        Self::Refusal(why)
    }
}

impl From<SealError> for PairError {
    fn from(why: SealError) -> Self {
        Self::Sealed(why)
    }
}

impl From<EnvelopeError> for PairError {
    fn from(why: EnvelopeError) -> Self {
        Self::Envelope(why)
    }
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(number) => write!(f, "a pairing body carries key {number}"),
            Self::Duplicate(key) => write!(f, "{key} arrived twice"),
            Self::Missing(key) => write!(f, "no {key} arrived"),
            Self::WrongWidth(key) => write!(f, "{key} is the wrong width"),
            Self::UnsupportedSuite(suite) => write!(f, "suite {suite} is not implemented"),
            Self::UnknownKind(kind) => write!(f, "client_kind {kind} is not in the registry"),
            Self::LabelTooLong(len) => write!(f, "a label of {len} bytes, past {MAX_LABEL}"),
            Self::UnknownOutcome(raw) => write!(f, "outcome {raw} does not belong here"),
            Self::SlotOnARefusal => f.write_str("a refusal names a slot"),
            Self::Noise(why) => write!(f, "{why}"),
            Self::Refusal(why) => write!(f, "refusal tag: {why}"),
            Self::NotTheLabelsController => {
                f.write_str("the controller key is not the one the label names")
            }
            Self::NotThisRequest(req_id) => write!(f, "an answer to req_id {}", req_id.0),
            Self::WrongMessage { expected, found } => write!(
                f,
                "message type {:#04x} where {:#04x} belongs",
                *found as u8, *expected as u8
            ),
            Self::Sealed(why) => write!(f, "{why}"),
            Self::TooLargeToWrite => f.write_str("the frame does not fit the buffer"),
            Self::Envelope(why) => write!(f, "envelope: {why}"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for PairError {}

const_assert!(
    REFUSAL_BYTES == 16,
    "P-241's refusal is sixteen bytes and Pair 0x8B key 3 carries exactly that"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::PrologueFields;
    use crate::kdf::{DeviceId, Epoch, PrintedSecret};
    use crate::limits::MAX_CLIENTS;

    const DEVICE_ID: [u8; 16] = *b"ORIGIN89 DEMO 01";

    fn label() -> Label {
        Label::new(DeviceId::new(DEVICE_ID), PrintedSecret::new([0x07; 32]))
    }

    fn controller() -> StaticKey {
        StaticKey::from_stored([0x40; 32])
    }

    fn prologue() -> Prologue {
        Prologue::new(&PrologueFields {
            suite: Suite::X25519ChachapolySha256,
            version: Version::V1_0,
            device_id: DeviceId::new(DEVICE_ID),
            epoch: Epoch::FIRST,
            challenge: &[0xA0; 16],
            handle: crate::SessionId::from(3),
        })
    }

    fn header(kind: MessageType, req_id: u32) -> Header {
        Header {
            kind,
            session: crate::SessionId::from(3),
            req_id: ReqId(req_id),
        }
    }

    fn offer() -> PairOffer<'static> {
        PairOffer {
            version: Version::V1_0,
            client_version: "o89-cli 0.1.0",
            client_kind: ClientKind::App,
            label: "kitchen phone",
        }
    }

    fn start() -> (PairPending, [u8; 256], usize) {
        let mut frame = [0u8; 256];
        let (pending, len) = PairPending::start(
            &prologue(),
            Suite::X25519ChachapolySha256,
            &label(),
            Entropy::new([2; 32]),
            &offer(),
            header(MessageType::Pair, 1),
            &mut frame,
        )
        .expect("message 1 writes");
        (pending, frame, len)
    }

    fn opened<'d>(frame: &[u8], plain: &'d mut [u8]) -> Result<Offered<'d>, PairError> {
        PairArrival::decode(Envelope::decode(frame).expect("decodes"))?.open(
            &prologue(),
            &label().pair_psk(),
            plain,
        )
    }

    fn slot() -> (ClientId, Generation) {
        (
            ClientId::new(7).expect("slot 7"),
            Generation::new(2).expect("generation 2"),
        )
    }

    /// The whole enrolment between this crate's two ends, through the label's
    /// fingerprint and the sealed answer.
    #[test]
    fn p_064_a_pairing_proceeds_to_a_sealed_enrolment() {
        let (pending, frame, len) = start();
        let mut plain = [0u8; 256];
        let offered = opened(&frame[..len], &mut plain).expect("opens");
        assert_eq!(offered.offer(), offer());
        let mut answer = [0u8; 256];
        let (awaiting, len) = offered
            .proceed(&controller(), Entropy::new([4; 32]), &mut answer)
            .expect("message 2");
        let PairReply::Proceed(proceeding) = pending
            .read(
                Envelope::decode(&answer[..len]).expect("decodes"),
                &label(),
                &Fingerprint::of(&controller().public()),
            )
            .expect("message 2 checks out")
        else {
            panic!("read as a refusal");
        };
        let client = StaticKey::from_stored([0x60; 32]);
        let mut enrol = [0u8; 256];
        let (enrol_pending, len) = proceeding
            .finish(&client, header(MessageType::Enrol, 2), &mut enrol)
            .expect("message 3");
        let enrolling = awaiting
            .read(Envelope::decode(&enrol[..len]).expect("decodes"))
            .expect("message 3 opens");
        assert_eq!(enrolling.client(), client.public());
        let (id, generation) = slot();
        let sent = EnrolAnswer {
            outcome: Outcome::Enrolled(id, generation),
            next_challenge: [0xC0; 16],
        };
        let len = enrolling.answer(&sent, &mut answer).expect("seals");
        let got = enrol_pending
            .read(
                Envelope::decode(&answer[..len]).expect("decodes"),
                &mut plain,
            )
            .expect("opens");
        assert_eq!(got, sent);
    }

    /// P-236: message 2 from a controller whose key the label does not name is
    /// abandoned before message 3 — the label-holder in the middle.
    #[test]
    fn p_236_a_controller_the_label_does_not_name_is_abandoned() {
        let (pending, frame, len) = start();
        let mut plain = [0u8; 256];
        let impostor = StaticKey::from_stored([0x41; 32]);
        let mut answer = [0u8; 256];
        let (_, len) = opened(&frame[..len], &mut plain)
            .expect("the impostor holds the label too")
            .proceed(&impostor, Entropy::new([4; 32]), &mut answer)
            .expect("message 2");
        assert!(matches!(
            pending.read(
                Envelope::decode(&answer[..len]).expect("decodes"),
                &label(),
                &Fingerprint::of(&controller().public()),
            ),
            Err(PairError::NotTheLabelsController)
        ));
    }

    /// P-066: message 1 under another label is bare error 10, counted.
    #[test]
    fn p_066_message_1_under_another_label_is_refused_and_counted() {
        let (_, frame, len) = start();
        let other = Label::new(DeviceId::new(DEVICE_ID), PrintedSecret::new([0x08; 32]));
        let mut plain = [0u8; 256];
        let refused = PairArrival::decode(Envelope::decode(&frame[..len]).expect("decodes"))
            .expect("a Pair")
            .open(&prologue(), &other.pair_psk(), &mut plain)
            .err()
            .expect("refused");
        assert!(refused.counts());
        assert_eq!(
            refused.refusal(),
            Some(Refusal::Client(ErrorCode::AuthenticationFailed))
        );
    }

    /// P-241: a refusal is believed with its tag, and a comms processor that
    /// turns `window_closed` into `table_full`, or carries message 2 beside it,
    /// is not believed.
    #[test]
    fn p_241_a_refusal_is_believed_only_as_it_was_tagged() {
        let (_, frame, len) = start();
        let mut plain = [0u8; 256];
        let mut refused = [0u8; 64];
        let refused_len = opened(&frame[..len], &mut plain)
            .expect("opens")
            .refuse(
                PairRefusal::WindowClosed,
                &label().refusal_key(),
                &mut refused,
            )
            .expect("writes");
        let fingerprint = Fingerprint::of(&controller().public());
        let (pending, _, _) = start();
        assert!(matches!(
            pending.read(
                Envelope::decode(&refused[..refused_len]).expect("decodes"),
                &label(),
                &fingerprint
            ),
            Ok(PairReply::Refused(PairRefusal::WindowClosed))
        ));

        // The outcome is the envelope body's second byte after the map head.
        let at = refused[..refused_len]
            .windows(2)
            .position(|w| w == [0x01, 0x02])
            .expect("key 1 carries outcome 2");
        let mut relabelled = refused;
        relabelled[at + 1] = Pair::TableFull as u8;
        let (pending, _, _) = start();
        assert!(matches!(
            pending.read(
                Envelope::decode(&relabelled[..refused_len]).expect("decodes"),
                &label(),
                &fingerprint
            ),
            Err(PairError::Refusal(MacError::Mismatch))
        ));
        assert!(!PairError::Refusal(MacError::Mismatch).counts());
    }

    /// A refusal is answered after the label's key opened message 1, so it does
    /// not count against `MAX_AUTH_FAILURES` (P-051).
    #[test]
    fn p_051_a_pairing_refusal_counts_against_nothing() {
        for outcome in [PairRefusal::WindowClosed, PairRefusal::TableFull] {
            let (_, frame, len) = start();
            let mut plain = [0u8; 256];
            let mut out = [0u8; 64];
            assert!(
                opened(&frame[..len], &mut plain)
                    .expect("opens")
                    .refuse(outcome, &label().refusal_key(), &mut out)
                    .is_ok()
            );
        }
    }

    /// P-014 and P-105: a `client_kind` outside the closed set is refused as a
    /// malformed offer, never defaulted to a kind with more authority.
    #[test]
    fn p_014_an_unknown_client_kind_is_refused_not_defaulted() {
        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(5).expect("head");
        cbor.key(1).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(2).expect("k");
        cbor.u64(0).expect("v");
        cbor.key(3).expect("k");
        cbor.text("x").expect("v");
        cbor.key(4).expect("k");
        cbor.u64(9).expect("an unknown kind");
        cbor.key(5).expect("k");
        cbor.text("y").expect("v");
        let len = cbor.finish().expect("done");
        assert_eq!(
            PairOffer::decode(&out[..len]).err(),
            Some(PairError::UnknownKind(9))
        );
        assert_eq!(
            PairError::UnknownKind(9).refusal(),
            Some(Refusal::Client(ErrorCode::MalformedFrame))
        );
    }

    /// A label past `MAX_LABEL` is refused both ways.
    #[test]
    fn p_105_a_label_past_the_cap_is_refused_both_ways() {
        let long = "0123456789abcdef0123456789abcdef0";
        let mut out = [0u8; 128];
        assert_eq!(
            PairOffer {
                label: long,
                ..offer()
            }
            .encode(&mut out)
            .err(),
            Some(PairError::LabelTooLong(33))
        );
    }

    /// P-058: every `Enrol 0x93` carries the next challenge, whatever the
    /// outcome, and only outcomes 1 and 5 name a slot.
    #[test]
    fn p_058_every_enrolment_answer_carries_the_next_challenge() {
        let (id, generation) = slot();
        for outcome in [
            Outcome::Enrolled(id, generation),
            Outcome::Reclaimed(id, generation),
            Outcome::WindowClosed,
            Outcome::TableFull,
            Outcome::NotStored,
        ] {
            let sent = EnrolAnswer {
                outcome,
                next_challenge: [0xC5; 16],
            };
            let mut out = [0u8; MAX_ENROL_ANSWER];
            let len = sent.encode(&mut out).expect("encodes");
            assert_eq!(EnrolAnswer::decode(&out[..len]), Ok(sent), "{outcome:?}");
            let mut reader = CborReader::new(&out[..len]);
            let pairs = reader.map().expect("a map");
            for _ in 0..pairs {
                let key = reader.key().expect("key");
                assert!((1..=4).contains(&key), "{outcome:?} carries key {key}");
                reader.skip().expect("value");
            }
        }
    }

    /// A refusal that names a slot tells the client it holds one it does not,
    /// and the next `Hello` fails for a reason nobody can see.
    #[test]
    fn a_refusal_that_names_a_slot_is_refused() {
        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(3).expect("head");
        cbor.key(1).expect("k");
        cbor.u64(u64::from(Pair::WindowClosed as u8)).expect("v");
        cbor.key(2).expect("k");
        cbor.u64(7).expect("a slot on a refusal");
        cbor.key(4).expect("k");
        cbor.bytes(&[0; 16]).expect("v");
        let len = cbor.finish().expect("done");
        assert_eq!(
            EnrolAnswer::decode(&out[..len]).err(),
            Some(PairError::SlotOnARefusal)
        );
    }

    /// An enrolment answer that names outcome 1 without a slot is refused, not
    /// read as slot zero.
    #[test]
    fn an_enrolled_answer_without_a_slot_is_refused() {
        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(2).expect("head");
        cbor.key(1).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(4).expect("k");
        cbor.bytes(&[0; 16]).expect("v");
        let len = cbor.finish().expect("done");
        assert_eq!(
            EnrolAnswer::decode(&out[..len]).err(),
            Some(PairError::Missing(PairKey::ClientId))
        );
    }

    /// P-054: every bit of `Pair 0x8B`'s message 2 is authenticated; a flip
    /// anywhere in it is refused.
    #[test]
    fn p_054_every_flipped_bit_of_message_2_is_refused() {
        let (_, frame, len) = start();
        let mut plain = [0u8; 256];
        let mut answer = [0u8; 256];
        let (_, answer_len) = opened(&frame[..len], &mut plain)
            .expect("opens")
            .proceed(&controller(), Entropy::new([4; 32]), &mut answer)
            .expect("message 2");
        let message_at = answer_len - PAIR_MESSAGE_2;
        for byte in message_at..answer_len {
            for bit in 0..8 {
                let mut flipped = answer;
                flipped[byte] ^= 1 << bit;
                let (pending, _, _) = start();
                assert!(
                    pending
                        .read(
                            Envelope::decode(&flipped[..answer_len]).expect("decodes"),
                            &label(),
                            &Fingerprint::of(&controller().public()),
                        )
                        .is_err(),
                    "bit {bit} of byte {byte} was accepted"
                );
            }
        }
    }

    /// P-226: a suite this controller does not run is refused before message 1
    /// is opened.
    #[test]
    fn p_226_a_pair_in_an_unknown_suite_is_refused() {
        let (_, mut frame, len) = start();
        // Key 1's value is the body's second byte: `a2 01 01 02 ...`.
        let at = frame[..len]
            .windows(3)
            .position(|w| w == [0xA2, 0x01, 0x01])
            .expect("key 1")
            + 2;
        frame[at] = 2;
        assert!(matches!(
            PairArrival::decode(Envelope::decode(&frame[..len]).expect("decodes")),
            Err(PairError::UnsupportedSuite(2))
        ));
    }

    /// Every truncation of `Pair 0x0B` is refused, never read short.
    #[test]
    fn every_truncation_of_a_pair_is_refused() {
        let (_, frame, len) = start();
        for cut in 0..len {
            let Ok(envelope) = Envelope::decode(&frame[..cut]) else {
                continue;
            };
            let mut plain = [0u8; 256];
            let refused = PairArrival::decode(envelope)
                .and_then(|arrival| arrival.open(&prologue(), &label().pair_psk(), &mut plain))
                .is_err();
            assert!(refused, "a Pair cut to {cut} bytes opened");
        }
    }

    /// `Enrol 0x93` whose seal fails is refused at the client, and the refusal
    /// names the seal.
    #[test]
    fn a_forged_enrolment_answer_is_refused() {
        let mut frame = [0u8; 64];
        let mut cbor = header(MessageType::EnrolResponse, 2)
            .write(2, &mut frame)
            .expect("fits");
        cbor.key(1).expect("k");
        cbor.bytes(&[0; 40]).expect("v");
        cbor.key(2).expect("k");
        cbor.u64(0).expect("v");
        let len = cbor.finish().expect("done");
        let (keys, _) = {
            let (pending, frame1, len1) = start();
            let mut plain = [0u8; 256];
            let mut answer = [0u8; 256];
            let (_, answer_len) = opened(&frame1[..len1], &mut plain)
                .expect("opens")
                .proceed(&controller(), Entropy::new([4; 32]), &mut answer)
                .expect("message 2");
            let PairReply::Proceed(proceeding) = pending
                .read(
                    Envelope::decode(&answer[..answer_len]).expect("decodes"),
                    &label(),
                    &Fingerprint::of(&controller().public()),
                )
                .expect("checks out")
            else {
                panic!("refused");
            };
            let mut enrol = [0u8; 256];
            proceeding
                .finish(
                    &StaticKey::from_stored([0x60; 32]),
                    header(MessageType::Enrol, 2),
                    &mut enrol,
                )
                .expect("message 3")
        };
        let mut plain = [0u8; 64];
        assert!(matches!(
            keys.read(
                Envelope::decode(&frame[..len]).expect("decodes"),
                &mut plain
            ),
            Err(PairError::Sealed(SealError::Open(_)))
        ));
    }

    /// P-066's closed window, as far as this crate reaches: the controller that
    /// finds no window open after message 1 answers with outcome 2 under the
    /// label's refusal tag, and the client reads it as exactly that.
    #[test]
    fn p_066_a_pairing_at_a_closed_window_gets_a_tagged_refusal() {
        let (pending, frame, len) = start();
        let mut plain = [0u8; 256];
        let mut out = [0u8; 64];
        let written = opened(&frame[..len], &mut plain)
            .expect("the label opens message 1")
            .refuse(PairRefusal::WindowClosed, &label().refusal_key(), &mut out)
            .expect("writes");
        assert!(matches!(
            pending.read(
                Envelope::decode(&out[..written]).expect("decodes"),
                &label(),
                &Fingerprint::of(&controller().public()),
            ),
            Ok(PairReply::Refused(PairRefusal::WindowClosed))
        ));
    }

    fn view(id: u32, held: Option<(u8, &'static str, Role)>) -> SlotView<'static> {
        SlotView {
            client_id: ClientId::new(id).expect("a slot"),
            held: held.map(|(key, label, role)| Occupant {
                key: PublicKey::from_bytes([key; 32]),
                label,
                role,
            }),
        }
    }

    /// A table of [`MAX_CLIENTS`] slots: slot 1 the owner, then `admins` admin
    /// slots, then free ones. Built from the limits so the bound moves with them.
    fn owner_and_admins(admins: usize) -> [SlotView<'static>; MAX_CLIENTS] {
        core::array::from_fn(|index| {
            let n = u32::try_from(index + 1).expect("MAX_CLIENTS fits");
            let key = u8::try_from(index + 1).expect("MAX_CLIENTS fits");
            match index {
                0 => view(n, Some((key, "owner phone", Role::Owner))),
                i if i <= admins => view(n, Some((key, "tablet", Role::Admin))),
                _ => view(n, None),
            }
        })
    }

    fn placed(n: u32, role: Role) -> Placement {
        Placement {
            client_id: ClientId::new(n).expect("a slot"),
            role,
        }
    }

    fn key(byte: u8) -> PublicKey {
        PublicKey::from_bytes([byte; 32])
    }

    /// The same key re-pairing takes its own slot back, ahead of a free one, and
    /// keeps the role it had.
    #[test]
    fn p_240_the_same_key_takes_its_own_slot_before_a_free_one() {
        let table = [
            view(1, None),
            view(2, Some((5, "phone", Role::Admin))),
            view(3, None),
        ];
        assert_eq!(
            Allocation::choose(&table, Some(&key(5)), "renamed"),
            Allocation::SameKey(placed(2, Role::Admin))
        );
    }

    /// Message 1 carries no client key, so step 1 cannot run there: the same
    /// install is offered the free slot at message 1 and gets its own at
    /// message 3.
    #[test]
    fn p_240_message_1_has_no_key_and_skips_the_first_step() {
        let table = [
            view(1, Some((4, "owner phone", Role::Owner))),
            view(2, Some((5, "phone", Role::Admin))),
            view(3, None),
        ];
        assert_eq!(
            Allocation::choose(&table, None, "phone"),
            Allocation::Free(placed(3, Role::Admin))
        );
        assert_eq!(
            Allocation::choose(&table, Some(&key(5)), "phone"),
            Allocation::SameKey(placed(2, Role::Admin))
        );
    }

    /// A free slot comes before a reclaim: the second "iPhone" gets a slot of its
    /// own rather than the first one's.
    #[test]
    fn p_240_a_free_slot_comes_before_a_reclaim() {
        let table = [
            view(1, Some((4, "owner phone", Role::Owner))),
            view(2, Some((5, "iPhone", Role::Admin))),
            view(3, None),
        ];
        assert_eq!(
            Allocation::choose(&table, Some(&key(6)), "iPhone"),
            Allocation::Free(placed(3, Role::Admin))
        );
    }

    /// With no free slot, the lowest admin slot with the byte-identical label is
    /// reclaimed, and a label that differs only in case is not a match.
    #[test]
    fn p_240_a_full_table_reclaims_the_lowest_byte_identical_label() {
        let table = [
            view(1, Some((4, "kitchen", Role::Owner))),
            view(2, Some((6, "Phone", Role::Admin))),
            view(3, Some((7, "phone", Role::Admin))),
            view(4, Some((8, "phone", Role::Admin))),
        ];
        assert_eq!(
            Allocation::choose(&table, Some(&key(9)), "phone"),
            Allocation::Reclaim(placed(3, Role::Admin))
        );
        assert_eq!(
            Allocation::choose(&table, Some(&key(9)), "PHONE"),
            Allocation::Full,
            "no case folding"
        );
    }

    /// Nothing held, nothing free and no label to reclaim is `table_full`, and an
    /// empty table gives slot 1.
    #[test]
    fn p_240_nothing_to_allocate_is_full_and_an_empty_table_gives_slot_one() {
        let full = [
            view(1, Some((5, "a", Role::Owner))),
            view(2, Some((6, "b", Role::Admin))),
        ];
        assert_eq!(
            Allocation::choose(&full, Some(&key(9)), "c"),
            Allocation::Full
        );
        assert_eq!(Allocation::choose(&full, None, "c"), Allocation::Full);
        let empty = [view(2, None), view(1, None)];
        assert_eq!(
            Allocation::choose(&empty, Some(&key(9)), "c"),
            Allocation::Free(placed(1, Role::Owner)),
            "P-086: the lowest free slot, whatever order the table is walked in"
        );
    }

    /// The first pairing at the panel is the owner; everybody after is an admin.
    /// A table whose owner was removed makes the next pairing the owner again,
    /// or the site has nobody who can invite one.
    #[test]
    fn p_250_a_label_enrolment_is_owner_only_while_no_slot_holds_owner() {
        let empty = [view(1, None), view(2, None)];
        assert_eq!(
            Allocation::choose(&empty, None, "phone"),
            Allocation::Free(placed(1, Role::Owner))
        );
        let owned = [view(1, Some((4, "phone", Role::Owner))), view(2, None)];
        assert_eq!(
            Allocation::choose(&owned, None, "tablet"),
            Allocation::Free(placed(2, Role::Admin))
        );
        let ownerless = [
            view(1, Some((5, "tablet", Role::Admin))),
            view(2, Some((6, "tv", Role::Viewer))),
            view(3, None),
        ];
        assert_eq!(
            Allocation::choose(&ownerless, None, "phone"),
            Allocation::Free(placed(3, Role::Owner))
        );
    }

    /// Step 1 keeps the role the slot had. A viewer that re-pairs at the panel
    /// is still a viewer, and an owner that re-pairs is still the owner, even
    /// though a new pairing would have been an admin.
    #[test]
    fn p_250_the_same_key_keeps_its_role_whatever_a_new_pairing_would_get() {
        let table = [
            view(1, Some((4, "phone", Role::Owner))),
            view(2, Some((5, "tv", Role::Viewer))),
            view(3, None),
        ];
        assert_eq!(
            Allocation::choose(&table, Some(&key(5)), "tv"),
            Allocation::SameKey(placed(2, Role::Viewer))
        );
        assert_eq!(
            Allocation::choose(&table, Some(&key(4)), "phone"),
            Allocation::SameKey(placed(1, Role::Owner))
        );
    }

    /// One admin short of the bound still gets a free slot; at the bound an
    /// admin finds none, although the table has room, and the row stays for an
    /// owner to be invited into.
    #[test]
    fn p_258_an_admin_past_the_bound_finds_no_free_slot() {
        let short = owner_and_admins(MAX_ADMINS - 1);
        assert_eq!(
            Allocation::choose(&short, None, "laptop"),
            Allocation::Free(placed(
                u32::try_from(MAX_ADMINS + 1).expect("fits"),
                Role::Admin
            ))
        );
        let bound = owner_and_admins(MAX_ADMINS);
        assert!(bound.iter().any(|slot| slot.held.is_none()), "room is left");
        assert_eq!(Allocation::choose(&bound, None, "laptop"), Allocation::Full);
    }

    /// At the bound, an admin pairing under a label an admin slot holds reclaims
    /// that slot rather than taking the free row: the admin count does not move.
    #[test]
    fn p_258_at_the_bound_a_matching_label_reclaims_rather_than_taking_a_free_slot() {
        let bound = owner_and_admins(MAX_ADMINS);
        assert_eq!(
            Allocation::choose(&bound, None, "tablet"),
            Allocation::Reclaim(placed(2, Role::Admin))
        );
    }

    /// An owner may take any free slot: a table the admins have filled to the
    /// bound, with its owner removed, still enrols an owner at the panel.
    #[test]
    fn p_258_an_owner_takes_a_free_slot_past_the_admin_bound() {
        let mut table = owner_and_admins(MAX_ADMINS);
        let first = table.first_mut().expect("MAX_CLIENTS is not zero");
        first.held = None;
        assert_eq!(
            Allocation::choose(&table, None, "new phone"),
            Allocation::Free(placed(1, Role::Owner))
        );
    }

    /// Step 3 considers only slots holding `admin`. A label that matches the
    /// owner's or the viewer's slot never reclaims it; without that, a label
    /// holder standing at the panel takes the site from its owner by naming
    /// their phone.
    #[test]
    fn p_258_a_label_never_reclaims_an_owner_or_viewer_slot() {
        let table = [
            view(1, Some((4, "phone", Role::Owner))),
            view(2, Some((5, "phone", Role::Viewer))),
            view(3, Some((6, "tablet", Role::Admin))),
            view(4, Some((7, "phone", Role::Admin))),
        ];
        assert_eq!(
            Allocation::choose(&table, None, "phone"),
            Allocation::Reclaim(placed(4, Role::Admin))
        );
        let no_admin_match = [
            view(1, Some((4, "phone", Role::Owner))),
            view(2, Some((5, "phone", Role::Viewer))),
            view(3, Some((6, "tablet", Role::Admin))),
        ];
        assert_eq!(
            Allocation::choose(&no_admin_match, None, "phone"),
            Allocation::Full
        );
    }
}
