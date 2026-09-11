//! `Pair 0x0B` and `Pair 0x8B` — enrolment, and the only exchange on this wire
//! whose refusals are authenticated.
//!
//! Two things about these two bodies are unlike everything else here. The proof
//! covers **fields** rather than an encoding, so there is no inner body and
//! every key of both maps is inside a preimage — which is why PROTOCOL.md makes
//! a later key entering that preimage a rule about how a v2 is designed, and
//! why a key this version has never heard of is still **skipped** under P-013.
//! Refusing was tried and reverted: it means a v2 client cannot enrol at a v1
//! controller, and enrolment is the one exchange that needs somebody standing at
//! the panel, so that failure costs a drive. And the refusals carry a real tag: P-064
//! spends one on `window_closed`, `bad_proof` and `table_full` alike, because a
//! refusal the comms processor can forge is a refusal that sends somebody back
//! to the panel to press a button that was never needed.
//!
//! Three shapes are structural rather than remembered. [`Outcome`] holds the
//! slot inside the two variants that name one, so the zero P-086 puts on the
//! wire for the other three cannot be read out as slot zero. [`PairClaim`]
//! hands over `client_nonce` — which the ack refusing it has to be computed
//! over — and nothing else until the proof has checked out, which is P-057's
//! order. And [`PairClaim::verify`] fails with [`BadProof`], which is not a
//! [`PairError`] and carries no `refusal`: a failed pairing proof is answered
//! with outcome 3 and never with a bare error 10 (P-051, P-141), and a type
//! with no error code on it is the one shape a caller cannot get that wrong
//! from.
//!
//! **P-066, P-067 and P-078 were cited here and this file gates none of them.**
//! Each binds an enrolment table and a pairing window that do not exist: the
//! button MUST gate enrolment for 120 seconds, a full table MUST refuse rather
//! than evict, and a `label` byte-identical to an occupied row MUST reclaim it
//! before allocation is even attempted. What is here is the *outcome numbers* —
//! `window_closed`, `table_full`, `reclaimed` — and an outcome a nobody decides
//! is an enum variant, not a gate. Nothing in this tree holds eight rows or
//! knows what a button is.
//!
//! The neighbours that stay are the ones this file really does perform. P-064's
//! *outcome 1 carrying the allocated `client_id`* is checked by
//! `a_client_id_of_zero_with_outcome_enrolled_is_refused`, and P-065's *the
//! response MUST NOT carry a starting counter* is enforced by [`PairAckKey`]
//! having exactly four keys and none of them a counter — a starting counter is
//! unencodable rather than merely unwritten.
//!
//! cites: P-051, P-054, P-057, P-058, P-064, P-065, P-069, P-086, P-088

use core::fmt;

use crate::cbor::{CborError, CborReader};
use crate::envelope::{Envelope, EnvelopeError, Header, Refusal};
use crate::generated::{ClientKind, ErrorCode, MessageType, Pair};
use crate::kdf::{ClientId, Epoch};
use crate::limits::{MAX_LABEL, MAX_PAYLOAD, MAX_STRING};
use crate::mac::{MacError, PairAck, PairKey, PairProof};

/// A `device_id`, a `challenge`, a `client_nonce`, a `next_challenge` and a
/// `proof` are all sixteen bytes.
const BSTR16: usize = 16;

/// A `text` field at its widest: a two-byte head and [`MAX_STRING`] bytes.
const TEXT_MAX: usize = 2 + MAX_STRING;

/// What `[type, session_id, req_id, …]` costs around either body, at the widest
/// each of the three scalars encodes to. The body map's own head is counted
/// with the body.
const ENVELOPE: usize = 11;

const_assert!(
    MAX_STRING >= 24,
    "below 24 a CBOR text head is one byte, not two, and MAX_PAIR_BODY is then a byte wider than any frame that can exist — harmless, except that it is the number a caller sizes a buffer at and the slack hides the day the label cap moves the other way"
);

/// The widest `Pair 0x0B` **body**: a map head, a one-byte `client_kind`, the
/// widest `label`, and two `bstr16`.
///
/// A client sizes its frame buffer at this plus the eleven bytes of envelope
/// [`PairRequest::write`] puts around it. Sized at this alone it refuses the
/// widest label, which is a failure that waits for somebody naming a phone at a
/// panel rather than showing up on a bench.
pub const MAX_PAIR_BODY: usize = 40 + TEXT_MAX;

/// The widest `Pair 0x8B` body: a map head, a one-byte `outcome`, a `client_id`
/// at the top of its width, and two `bstr16`.
pub const MAX_PAIR_ACK_BODY: usize = 45;

const_assert!(
    MAX_PAIR_BODY + ENVELOPE <= MAX_PAYLOAD,
    "a Pair 0x0B carries the one variable-width field in either pairing preimage; a body that fills the payload is a frame the client builds and the controller then refuses with error 5, at the one moment somebody is standing in front of the panel"
);
const_assert!(
    MAX_PAIR_ACK_BODY + ENVELOPE <= MAX_PAYLOAD,
    "the ack is fixed width, so this can only fail by somebody adding a key to it — which is the review this line is asking for, because every key of this body is inside the MAC and a new one would not be"
);

/// The four keys of `Pair 0x0B`, by name rather than by number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairRequestKey {
    /// Key 1, which P-105 fixes the capability mask from and which is attested
    /// by the proof rather than by the comms processor.
    ClientKind,
    /// Key 2, what a person reads in the client list — and the bytes P-078
    /// matches a reclaim against, byte for byte.
    Label,
    /// Key 3, the sixteen bytes of [`crate::Tag`].
    Proof,
    /// Key 4, fresh per attempt from the client's CSPRNG (P-069).
    ClientNonce,
}

impl PairRequestKey {
    /// How many pairs the body map promises.
    const COUNT: usize = 4;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ClientKind),
            2 => Some(Self::Label),
            3 => Some(Self::Proof),
            4 => Some(Self::ClientNonce),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ClientKind => 1,
            Self::Label => 2,
            Self::Proof => 3,
            Self::ClientNonce => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ClientKind => "client_kind",
            Self::Label => "label",
            Self::Proof => "proof",
            Self::ClientNonce => "client_nonce",
        }
    }
}

impl fmt::Display for PairRequestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pair 0x0B {} (key {})", self.name(), self.number())
    }
}

/// The four keys of `Pair 0x8B`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairAckKey {
    /// Key 1, the registry number of what the controller decided.
    Outcome,
    /// Key 2, which is 0 on every outcome but `enrolled` and `reclaimed`.
    ClientId,
    /// Key 3, the sixteen bytes P-064 spends on every outcome including the
    /// three that refuse.
    Mac,
    /// Key 4, the challenge this connection holds now the presented one is
    /// spent (P-058).
    NextChallenge,
}

impl PairAckKey {
    const COUNT: usize = 4;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Outcome),
            2 => Some(Self::ClientId),
            3 => Some(Self::Mac),
            4 => Some(Self::NextChallenge),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Outcome => 1,
            Self::ClientId => 2,
            Self::Mac => 3,
            Self::NextChallenge => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Outcome => "outcome",
            Self::ClientId => "client_id",
            Self::Mac => "mac",
            Self::NextChallenge => "next_challenge",
        }
    }
}

impl fmt::Display for PairAckKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pair 0x8B {} (key {})", self.name(), self.number())
    }
}

/// A key of either pairing body, so one refusal can name either.
///
/// Two enums rather than one flat list of eight, for the reason `handshake.rs`
/// gives about `BodyKey`: key 1 is `client_kind` going out and `outcome` coming
/// back, and a single enum would either lose that or spell every variant twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairBodyKey {
    /// A key of the request.
    Request(PairRequestKey),
    /// A key of the answer.
    Ack(PairAckKey),
}

impl From<PairRequestKey> for PairBodyKey {
    fn from(key: PairRequestKey) -> Self {
        Self::Request(key)
    }
}

impl From<PairAckKey> for PairBodyKey {
    fn from(key: PairAckKey) -> Self {
        Self::Ack(key)
    }
}

impl fmt::Display for PairBodyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(key) => key.fmt(f),
            Self::Ack(key) => key.fmt(f),
        }
    }
}

/// The three fixed-width fields both pairing preimages share.
///
/// One struct because P-069 requires `client_nonce` in **both**, and a proof and
/// the ack answering it computed over two different trios is a client that
/// cannot check the one message that fixes its identity. The `challenge` is the
/// one this connection was issued and is spent on presentation (P-061), so the
/// next attempt's is [`PairResponse::retry`] and never this one again.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    /// The 16 bytes of P-038, not the 32 characters the QR code prints.
    pub device_id: [u8; BSTR16],
    /// The challenge presented, which the proof and the ack both cover.
    pub challenge: [u8; BSTR16],
    /// Fresh per attempt, from the client's CSPRNG (P-069).
    pub client_nonce: [u8; BSTR16],
}

/// Written out rather than derived, and it renders none of the three.
///
/// On a client every byte in here was read off an unauthenticated `Discover
/// 0x80` (P-054) or minted locally; one `?attempt` in a span puts forty-eight
/// bytes somebody else chose into a log a person reads as if the site had said
/// them, which is P-055 lost to a formatter.
impl fmt::Debug for Attempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Attempt { device_id, challenge and client_nonce, none rendered }")
    }
}

/// What the controller decided, and the slot that decision does or does not
/// name.
///
/// The outcome and the `client_id` are one value because they are one decision:
/// P-086 counts slots from 1, so the zero on the wire under `window_closed` is
/// *no slot*, and a caller able to read a `u32` out of a refusal reads that zero
/// as a client. A refusal cannot even be built holding one:
///
/// ```
/// use km43::{ClientId, Outcome};
/// let slot = ClientId::new(7).expect("7 is a slot");
/// assert_eq!(Outcome::Enrolled(slot).slot(), Some(slot));
/// assert_eq!(Outcome::WindowClosed.slot(), None);
/// ```
/// ```compile_fail
/// use km43::{ClientId, Outcome};
/// let refused = Outcome::WindowClosed(ClientId::new(1).expect("a slot"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Outcome 1: a free row was allocated, at P-086's lowest free index.
    Enrolled(ClientId),
    /// Outcome 2: no pairing window was open (P-066). Nothing was verified, so
    /// nothing was spent but the challenge.
    WindowClosed,
    /// Outcome 3: the proof did not check out. It is an outcome rather than
    /// error 10 because P-051's exception says so.
    BadProof,
    /// Outcome 4: eight distinct labels already, and P-067 refuses rather than
    /// evicting somebody's enrolment.
    TableFull,
    /// Outcome 5: P-078's byte-exact `label` match reused an occupied row, with
    /// the counter back to 0 and the mask re-fixed from this proof.
    Reclaimed(ClientId),
}

impl Outcome {
    /// The registry number this goes on the wire as.
    #[must_use]
    pub const fn code(self) -> Pair {
        match self {
            Self::Enrolled(_) => Pair::Enrolled,
            Self::WindowClosed => Pair::WindowClosed,
            Self::BadProof => Pair::BadProof,
            Self::TableFull => Pair::TableFull,
            Self::Reclaimed(_) => Pair::Reclaimed,
        }
    }

    /// The slot this outcome names, or nothing — and the zero key 2 carries for
    /// the three refusals is *that nothing*, never slot zero.
    #[must_use]
    pub const fn slot(self) -> Option<ClientId> {
        match self {
            Self::Enrolled(id) | Self::Reclaimed(id) => Some(id),
            Self::WindowClosed | Self::BadProof | Self::TableFull => None,
        }
    }

    /// Whether this answer cost the controller an HMAC that did **not** check
    /// out — the only thing P-051 counts against `MAX_AUTH_FAILURES`.
    ///
    /// Both halves of that rule are here in one match, and only one of them is
    /// obvious. Counting outcome 3 is what stops `Pair` being an unmetered HMAC
    /// oracle sitting behind the one message type that has to work while
    /// somebody is standing at the panel with a phone. **Not** counting outcomes
    /// 2 and 4 is what stops anybody closing a technician's connection by
    /// sending `Pair` at a controller with no window open: refusing to look at a
    /// proof costs nothing, so it may not spend a threshold that exists to bound
    /// what a peer can make this controller compute.
    #[must_use]
    pub const fn failed_a_proof(self) -> bool {
        match self {
            Self::BadProof => true,
            Self::WindowClosed | Self::TableFull | Self::Enrolled(_) | Self::Reclaimed(_) => false,
        }
    }

    /// Key 2, and the `client_id` the pair-ack preimage covers. Private: the
    /// zero is a wire encoding of absence and a caller handed it would have to
    /// remember that.
    const fn on_the_wire(self) -> u32 {
        match self.slot() {
            Some(id) => id.get(),
            None => 0,
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enrolled(id) => write!(f, "enrolled as client_id {}", id.get()),
            Self::WindowClosed => f.write_str("window_closed"),
            Self::BadProof => f.write_str("bad_proof"),
            Self::TableFull => f.write_str("table_full"),
            Self::Reclaimed(id) => write!(f, "reclaimed as client_id {}", id.get()),
        }
    }
}

/// The two fields of `Pair 0x0B` the proof is computed over — and, on the far
/// side of [`PairClaim::verify`], the two it has been checked over.
///
/// `proof` and `client_nonce` are not here: the tag comes from [`Self::write`]
/// so no caller can send one encoding and prove another, and the nonce belongs
/// to the [`Attempt`] both preimages share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairRequest<'a> {
    /// Key 1. Attested under `pair_key` by somebody at the panel, which is what
    /// P-105 says makes it a sound input and `transport` not one.
    pub client_kind: ClientKind,
    /// Key 2, and the last field of the preimage — the one variable-width field
    /// in either, bounded by [`MAX_STRING`].
    pub label: &'a str,
}

impl PairRequest<'_> {
    /// Write the whole `Pair 0x0B` envelope into `dst`, proving these exact
    /// fields on the way past, and hand back its length.
    ///
    /// One call because the proof covers fields rather than bytes: a caller able
    /// to encode and prove separately could send `label` and prove another, and
    /// the controller would store and authenticate onward a name that was never
    /// on the phone. The header must name `Pair`.
    pub fn write(
        &self,
        key: &PairKey,
        attempt: &Attempt,
        header: Header,
        dst: &mut [u8],
    ) -> Result<usize, PairError> {
        expected(header, MessageType::Pair)?;
        // Refused where the label is typed, not only where it is read. `text()`
        // bounds by `MAX_STRING` and a row holds `MAX_LABEL`, so a 40-byte
        // label was writable, provable and refused by every conforming
        // controller — as a bad frame, which a phone cannot tell from a bad
        // proof.
        if self.label.len() > MAX_LABEL {
            return Err(PairError::WrongWidth {
                key: PairRequestKey::Label.into(),
                len: self.label.len(),
            });
        }
        let proof = key.proof(&PairProof {
            device_id: &attempt.device_id,
            challenge: &attempt.challenge,
            client_nonce: &attempt.client_nonce,
            client_kind: self.client_kind,
            label: self.label,
        });
        let mut cbor = header
            .write(PairRequestKey::COUNT, dst)
            .map_err(PairError::Envelope)?;
        cbor.key(PairRequestKey::ClientKind.number())?;
        cbor.u64(u64::from(self.client_kind as u8))?;
        cbor.key(PairRequestKey::Label.number())?;
        cbor.text(self.label)?;
        cbor.key(PairRequestKey::Proof.number())?;
        cbor.bytes(proof.as_bytes())?;
        cbor.key(PairRequestKey::ClientNonce.number())?;
        cbor.bytes(&attempt.client_nonce)?;
        Ok(cbor.finish()?)
    }
}

/// A `Pair 0x0B` as it arrived, with a proof nobody has checked.
///
/// P-057's ordering written as a type. What comes off one before the proof has
/// checked out is an [`Attempt`] and nothing else — the trio P-064 makes the
/// refusal carry a tag over. `client_kind` and `label` are what the proof exists
/// to attest, and there is no accessor for either:
///
/// ```
/// use km43::{Attempt, PairClaim};
/// fn trio(claim: &PairClaim<'_>) -> Attempt { claim.attempt([0; 16], [0; 16]) }
/// ```
/// ```compile_fail
/// use km43::PairClaim;
/// fn named(claim: &PairClaim<'_>) -> &str { claim.label() }
/// ```
pub struct PairClaim<'a> {
    fields: PairRequest<'a>,
    proof: [u8; BSTR16],
    client_nonce: [u8; BSTR16],
}

impl<'a> PairClaim<'a> {
    /// Read one out of an envelope naming `Pair`.
    ///
    /// A key beside the four is skipped (P-013). Every one of the four is inside
    /// the preimage, so what makes skipping safe is the rule PROTOCOL.md states
    /// for the three bodies whose MAC covers fields: a later key MUST enter it.
    pub fn decode(envelope: Envelope<'a>) -> Result<Self, PairError> {
        expected(envelope.header(), MessageType::Pair)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut slots = RequestSlots::empty();
        for _ in 0..pairs {
            let number = body.key()?;
            // P-013: skipped, not refused. Refusing means a v2 client cannot
            // enrol at a v1 controller, and enrolment is the one exchange that
            // needs somebody standing at the panel — so that failure costs a
            // drive. The corollary in PROTOCOL-RATIONALE is what makes skipping
            // safe: a field whose absence has no sane default is a new message
            // type, not a new key.
            match PairRequestKey::of(number) {
                Some(key) => slots.fill(key, &mut body)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        slots.complete()
    }

    /// The trio both preimages share, with the `client_nonce` taken off this
    /// body rather than from the caller.
    ///
    /// It is unauthenticated here and is used anyway, because P-064 MACs the
    /// refusal too and the pair-ack preimage covers the nonce that *arrived*.
    /// The nonce is not handed out on its own: a controller able to check the
    /// proof against one and MAC the ack over another refuses a client and then
    /// hands it a tag it cannot check.
    #[must_use]
    pub const fn attempt(&self, device_id: [u8; BSTR16], challenge: [u8; BSTR16]) -> Attempt {
        Attempt {
            device_id,
            challenge,
            client_nonce: self.client_nonce,
        }
    }

    /// Check the proof over the fields that arrived, and only then give them up.
    ///
    /// Pass the [`Attempt`] that [`Self::attempt`] built; any other nonce
    /// refuses here rather than leaving the ack MAC'd over a different attempt.
    /// The failure is [`BadProof`] and not a [`PairError`] because P-051 answers
    /// this one condition with outcome 3 rather than with a bare error 10.
    pub fn verify(self, key: &PairKey, attempt: &Attempt) -> Result<PairRequest<'a>, BadProof> {
        let expect = key.proof(&PairProof {
            device_id: &attempt.device_id,
            challenge: &attempt.challenge,
            client_nonce: &attempt.client_nonce,
            client_kind: self.fields.client_kind,
            label: self.fields.label,
        });
        if expect.verify(&self.proof).is_err() {
            return Err(BadProof);
        }
        Ok(self.fields)
    }
}

/// Names and lengths, never the fields. A derived `Debug` here would print
/// `label` — the field P-078 matches rows on — out of a message nobody has
/// authenticated yet, and print it beside a `client_kind` a relay could have
/// chosen.
impl fmt::Debug for PairClaim<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PairClaim {{ unverified, label: {} bytes }}",
            self.fields.label.len()
        )
    }
}

/// A `Pair 0x0B` whose proof did not check out.
///
/// It is deliberately not a [`PairError`] and has no `refusal`: P-051's
/// exception says this condition is answered with `Pair 0x8B` outcome 3 carrying
/// the P-064 MAC, never with a bare error 10. A forged error 10 tells somebody
/// standing at the panel that they mis-scanned a label they scanned correctly,
/// and the only cure they can think of is pressing the button again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadProof;

impl BadProof {
    /// The one thing this condition turns into. It still counts against the
    /// connection's `MAX_AUTH_FAILURES`, which is the other half of P-051's
    /// exception: the outcome says which message answers, not whether the
    /// failure is free. [`Outcome::failed_a_proof`] is what a dispatcher asks,
    /// and the controller's connection rows hold the count.
    #[must_use]
    pub const fn outcome(self) -> Outcome {
        Outcome::BadProof
    }
}

impl fmt::Display for BadProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the pairing proof does not match these fields")
    }
}

impl core::error::Error for BadProof {}

/// The controller's answer — and, on the far side of [`PairAckClaim::verify`],
/// the answer a client has checked.
///
/// `epoch` is in it because the MAC covers it and **the body does not carry
/// it**: P-087 puts it in `Discover 0x80`, and both ends supply it from what
/// they already know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairResponse {
    /// Keys 1 and 2, which are one decision and so one value.
    pub outcome: Outcome,
    /// Covered by the MAC, absent from the body. A verifier passing the wrong
    /// one gets a tag that never checks out with nothing on the wire to point
    /// at, which is why P-087 makes `Discover 0x80` say it.
    pub epoch: Epoch,
    /// Key 4, and the point of this message: the one just presented has been
    /// consumed (P-061) and this replaces it on every outcome (P-058). A client
    /// that keeps proving against the old one is the failure this field exists
    /// to prevent.
    pub next_challenge: [u8; BSTR16],
}

impl PairResponse {
    /// Write the whole `Pair 0x8B` envelope into `dst`, MAC'd over these exact
    /// fields, and hand back its length.
    ///
    /// One call for P-064's reason rather than P-048's: `window_closed`,
    /// `bad_proof` and `table_full` each carry a real tag, and a caller able to
    /// encode an outcome separately from the tag over it could send a refusal
    /// authenticated as something else. The header must name `PairResponse`.
    pub fn write(
        &self,
        key: &PairKey,
        attempt: &Attempt,
        header: Header,
        dst: &mut [u8],
    ) -> Result<usize, PairError> {
        expected(header, MessageType::PairResponse)?;
        let mac = key.ack(&self.covered(attempt));
        let mut cbor = header
            .write(PairAckKey::COUNT, dst)
            .map_err(PairError::Envelope)?;
        cbor.key(PairAckKey::Outcome.number())?;
        cbor.u64(u64::from(self.outcome.code() as u8))?;
        cbor.key(PairAckKey::ClientId.number())?;
        cbor.u64(u64::from(self.outcome.on_the_wire()))?;
        cbor.key(PairAckKey::Mac.number())?;
        cbor.bytes(mac.as_bytes())?;
        cbor.key(PairAckKey::NextChallenge.number())?;
        cbor.bytes(&self.next_challenge)?;
        Ok(cbor.finish()?)
    }

    /// The attempt a second try is proved under: this ack's `next_challenge`
    /// instead of the one just spent (P-058, P-061), and a nonce the client has
    /// minted afresh (P-069).
    ///
    /// Retrying under the spent challenge collects `stale_challenge` forever,
    /// and reusing the nonce is what lets an ack recorded from an earlier
    /// attempt verify against this one.
    #[must_use]
    pub const fn retry(&self, device_id: [u8; BSTR16], client_nonce: [u8; BSTR16]) -> Attempt {
        Attempt {
            device_id,
            challenge: self.next_challenge,
            client_nonce,
        }
    }

    /// The seven fields of the pair-ack preimage, assembled in one place so the
    /// side that writes the tag and the side that checks it cannot assemble it
    /// two ways.
    fn covered<'a>(&'a self, attempt: &'a Attempt) -> PairAck<'a> {
        PairAck {
            device_id: &attempt.device_id,
            challenge: &attempt.challenge,
            client_nonce: &attempt.client_nonce,
            outcome: self.outcome.code(),
            client_id: self.outcome.on_the_wire(),
            epoch: self.epoch.get(),
            next_challenge: &self.next_challenge,
        }
    }
}

/// A `Pair 0x8B` as it arrived, with a MAC nobody has checked.
///
/// Nothing is reachable on one. P-064 says a client discards a response that
/// fails the MAC **rather than enrolling**, and an accessor for `outcome` here
/// would be a client taking its own identity from the comms processor:
///
/// ```compile_fail
/// use km43::{Outcome, PairAckClaim};
/// fn decided(claim: &PairAckClaim) -> Outcome { claim.outcome() }
/// ```
pub struct PairAckClaim {
    outcome: Outcome,
    mac: [u8; BSTR16],
    next_challenge: [u8; BSTR16],
}

impl PairAckClaim {
    /// Read one out of an envelope naming `PairResponse`.
    ///
    /// A fifth key is skipped for the same reason as on the request. P-065 is
    /// why the *four* matter here in particular: a starting counter arriving in
    /// this message would be a counter the network chose, and an attacker who
    /// sets it to `2^64 − 1` has made every write that client ever makes fail as
    /// stale.
    pub fn decode(envelope: Envelope<'_>) -> Result<Self, PairError> {
        expected(envelope.header(), MessageType::PairResponse)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut slots = AckSlots::empty();
        for _ in 0..pairs {
            let number = body.key()?;
            // P-013: skipped, not refused. Refusing means a v2 client cannot
            // enrol at a v1 controller, and enrolment is the one exchange that
            // needs somebody standing at the panel — so that failure costs a
            // drive. The corollary in PROTOCOL-RATIONALE is what makes skipping
            // safe: a field whose absence has no sane default is a new message
            // type, not a new key.
            match PairAckKey::of(number) {
                Some(key) => slots.fill(key, &mut body)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        slots.complete()
    }

    /// Check the MAC and only then give up the answer.
    ///
    /// `epoch` is not in the body and the MAC covers it: pass the one
    /// `Discover 0x80` reported (P-087). Pass a different one and this refuses
    /// with [`MacError::Mismatch`] — indistinguishable, on the wire, from a
    /// forgery, which is exactly why P-087 puts the number where a client can
    /// read it.
    pub fn verify(
        self,
        key: &PairKey,
        attempt: &Attempt,
        epoch: Epoch,
    ) -> Result<PairResponse, PairError> {
        let answer = PairResponse {
            outcome: self.outcome,
            epoch,
            next_challenge: self.next_challenge,
        };
        key.ack(&answer.covered(attempt)).verify(&self.mac)?;
        Ok(answer)
    }
}

/// Nothing but the fact that it has not been checked. Even `outcome` stays out:
/// a bench log that says `enrolled` for a frame whose MAC then failed is the
/// sentence somebody quotes back as evidence the pairing worked.
impl fmt::Debug for PairAckClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairAckClaim { unverified, outcome withheld }")
    }
}

/// One key's value, and the two rules both bodies here apply to it.
///
/// A key that arrives twice is refused before either copy is used (P-015) — RFC
/// 8949 §5.6 leaves the resolution to the decoder, and two ends picking
/// differently prove and verify over different fields. A required key that never
/// arrived is named rather than defaulted: an absent `next_challenge` is not
/// sixteen zero bytes, it is a client with nothing to prove against next.
struct Slot<T>(Option<T>);

impl<T> Slot<T> {
    const fn empty() -> Self {
        Self(None)
    }

    fn fill(&mut self, key: impl Into<PairBodyKey>, value: T) -> Result<(), PairError> {
        if self.0.is_some() {
            return Err(PairError::Duplicate(key.into()));
        }
        self.0 = Some(value);
        Ok(())
    }

    fn taken(self, key: impl Into<PairBodyKey>) -> Result<T, PairError> {
        self.0.ok_or_else(|| PairError::Missing(key.into()))
    }
}

struct RequestSlots<'a> {
    client_kind: Slot<ClientKind>,
    label: Slot<&'a str>,
    proof: Slot<[u8; BSTR16]>,
    client_nonce: Slot<[u8; BSTR16]>,
}

impl<'a> RequestSlots<'a> {
    const fn empty() -> Self {
        Self {
            client_kind: Slot::empty(),
            label: Slot::empty(),
            proof: Slot::empty(),
            client_nonce: Slot::empty(),
        }
    }

    fn fill(&mut self, key: PairRequestKey, body: &mut CborReader<'a>) -> Result<(), PairError> {
        match key {
            PairRequestKey::ClientKind => {
                let raw = body.u8()?;
                let kind =
                    ClientKind::try_from(raw).map_err(|()| PairError::UnknownClientKind(raw))?;
                self.client_kind.fill(key, kind)
            }
            PairRequestKey::Label => self.label.fill(key, stored(key, body.text()?)?),
            PairRequestKey::Proof => self.proof.fill(key, sixteen(key, body.bytes()?)?),
            PairRequestKey::ClientNonce => {
                self.client_nonce.fill(key, sixteen(key, body.bytes()?)?)
            }
        }
    }

    fn complete(self) -> Result<PairClaim<'a>, PairError> {
        Ok(PairClaim {
            fields: PairRequest {
                client_kind: self.client_kind.taken(PairRequestKey::ClientKind)?,
                label: self.label.taken(PairRequestKey::Label)?,
            },
            proof: self.proof.taken(PairRequestKey::Proof)?,
            client_nonce: self.client_nonce.taken(PairRequestKey::ClientNonce)?,
        })
    }
}

struct AckSlots {
    outcome: Slot<Pair>,
    client_id: Slot<u32>,
    mac: Slot<[u8; BSTR16]>,
    next_challenge: Slot<[u8; BSTR16]>,
}

impl AckSlots {
    const fn empty() -> Self {
        Self {
            outcome: Slot::empty(),
            client_id: Slot::empty(),
            mac: Slot::empty(),
            next_challenge: Slot::empty(),
        }
    }

    fn fill(&mut self, key: PairAckKey, body: &mut CborReader<'_>) -> Result<(), PairError> {
        match key {
            PairAckKey::Outcome => {
                let raw = body.u8()?;
                let code = Pair::try_from(raw).map_err(|()| PairError::UnknownOutcome(raw))?;
                self.outcome.fill(key, code)
            }
            PairAckKey::ClientId => self.client_id.fill(key, body.u32()?),
            PairAckKey::Mac => self.mac.fill(key, sixteen(key, body.bytes()?)?),
            PairAckKey::NextChallenge => {
                self.next_challenge.fill(key, sixteen(key, body.bytes()?)?)
            }
        }
    }

    fn complete(self) -> Result<PairAckClaim, PairError> {
        let decided = Decided {
            code: self.outcome.taken(PairAckKey::Outcome)?,
            client_id: self.client_id.taken(PairAckKey::ClientId)?,
        };
        Ok(PairAckClaim {
            outcome: decided.outcome()?,
            mac: self.mac.taken(PairAckKey::Mac)?,
            next_challenge: self.next_challenge.taken(PairAckKey::NextChallenge)?,
        })
    }
}

/// Keys 1 and 2 as they arrived, before the two have been checked against each
/// other.
///
/// They arrive as two fields and mean one thing, and the two combinations the
/// wire can carry and the client table cannot mean are refused here rather than
/// downstream: an `enrolled` naming no slot, and a refusal naming one.
struct Decided {
    code: Pair,
    client_id: u32,
}

impl Decided {
    fn outcome(&self) -> Result<Outcome, PairError> {
        match self.code {
            Pair::Enrolled => Ok(Outcome::Enrolled(self.slot()?)),
            Pair::Reclaimed => Ok(Outcome::Reclaimed(self.slot()?)),
            Pair::WindowClosed => {
                self.no_slot()?;
                Ok(Outcome::WindowClosed)
            }
            Pair::BadProof => {
                self.no_slot()?;
                Ok(Outcome::BadProof)
            }
            Pair::TableFull => {
                self.no_slot()?;
                Ok(Outcome::TableFull)
            }
        }
    }

    /// P-086 counts from 1, so an `enrolled` carrying zero named a client that
    /// does not exist — and a client that took it at face value would derive its
    /// long-term key at slot zero.
    fn slot(&self) -> Result<ClientId, PairError> {
        ClientId::new(self.client_id).ok_or(PairError::NoSuchSlot)
    }

    /// The mirror, and the one that would otherwise pass: a `window_closed`
    /// carrying 3 is a refusal that names somebody else's row, authenticated,
    /// and a client that stored it would answer under a key it never derived.
    fn no_slot(&self) -> Result<(), PairError> {
        match ClientId::new(self.client_id) {
            Some(id) => Err(PairError::SlotOnARefusal(id)),
            None => Ok(()),
        }
    }
}

/// A `bstr16` that has to be exactly sixteen. Free rather than a method: it
/// takes a key and some bytes, and belongs to neither.
fn sixteen(key: impl Into<PairBodyKey>, raw: &[u8]) -> Result<[u8; BSTR16], PairError> {
    <[u8; BSTR16]>::try_from(raw).map_err(|_| PairError::WrongWidth {
        key: key.into(),
        len: raw.len(),
    })
}

/// Refuse a `label` past [`MAX_LABEL`] where the field is read.
///
/// `text()` bounds by `MAX_STRING`, which is 64, and an enrolment row holds 32.
/// Every other `label` in the protocol is written `≤ MAX_LABEL` and this one —
/// the only one that is *stored* — was not, so a client could prove over a
/// 40-byte name, pass, and arrive at a table that cannot hold it. There is no
/// outcome for that: the proof was good and the table was not full.
///
/// Refused here, so a decoded `label` is one an enrolment row can always take.
fn stored(key: PairRequestKey, text: &str) -> Result<&str, PairError> {
    if text.len() > MAX_LABEL {
        return Err(PairError::WrongWidth {
            key: key.into(),
            len: text.len(),
        });
    }
    Ok(text)
}

/// Refuse an envelope whose `type` is not the message this decoder reads.
///
/// Without it a `Pair 0x0B` body gets read as an ack: keys 1 to 4 exist in both
/// and mean `client_kind` where `outcome` belongs, which decodes far enough to
/// be answered.
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

/// Why a pairing body was refused.
///
/// A failed **proof** is not in here and that is the point: it is [`BadProof`],
/// because P-051's exception answers it with an outcome rather than with a code
/// from this list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairError {
    /// A key the body requires that never arrived. Never defaulted: an absent
    /// `next_challenge` is not sixteen zero bytes.
    Missing(PairBodyKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(PairBodyKey),
    /// A `bstr16` that was not sixteen bytes, carrying what arrived so a bench
    /// log can say how far off the peer was.
    WrongWidth {
        /// Which field.
        key: PairBodyKey,
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
    /// A `client_kind` the registry does not allocate, which has no capability
    /// row to fix a mask from (P-105).
    UnknownClientKind(u8),
    /// An `outcome` the registry does not allocate. Error 1 rather than a guess:
    /// a client that treated an unknown outcome as a refusal would give up on an
    /// enrolment a later controller had granted.
    UnknownOutcome(u8),
    /// An `enrolled` or `reclaimed` carrying `client_id` 0, which names no slot
    /// (P-086).
    NoSuchSlot,
    /// A `window_closed`, `bad_proof` or `table_full` carrying a slot number,
    /// which is a refusal claiming a row.
    SlotOnARefusal(ClientId),
    /// The MAC over a `Pair 0x8B`. A client discards rather than enrolling
    /// (P-064), and the likeliest cause of a mismatch nobody can see is an
    /// `epoch` the two ends disagree about.
    Mac(MacError),
    /// The envelope this body was written into.
    Envelope(EnvelopeError),
    /// The CBOR underneath the body.
    Cbor(CborError),
}

impl PairError {
    /// What to answer, and in which space.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Mac(_) => Refusal::Client(ErrorCode::BadMAC),
            Self::Envelope(why) => why.refusal(),
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::WrongWidth { .. }
            | Self::WrongMessage { .. }
            | Self::UnknownClientKind(_)
            | Self::UnknownOutcome(_)
            | Self::NoSuchSlot
            | Self::SlotOnARefusal(_)
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl From<CborError> for PairError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<MacError> for PairError {
    fn from(why: MacError) -> Self {
        Self::Mac(why)
    }
}

impl fmt::Display for PairError {
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
            Self::UnknownClientKind(raw) => {
                write!(f, "client_kind {raw} has no capability row")
            }
            Self::UnknownOutcome(raw) => write!(f, "pairing outcome {raw} is not allocated"),
            Self::NoSuchSlot => f.write_str("client_id 0 names no slot"),
            Self::SlotOnARefusal(id) => {
                write!(f, "a refused pairing named client_id {}", id.get())
            }
            Self::Mac(why) => write!(f, "{why}"),
            Self::Envelope(why) => write!(f, "envelope: {why}"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for PairError {}

const_assert!(
    size_of::<PairError>() == size_of::<usize>() * 3,
    "one of these comes back from every pairing decode on a part with 144 KB of RAM. Sixteen of the twenty-four are WrongWidth's key and length and the rest ride in bit patterns that pair was not using, so every other variant is free; the width is paid on the frames that pass as well as the ones that fail, and a variant that grows it is worth arguing about"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::ReqId;
    use crate::envelope::SessionId;
    use crate::kdf::{DeviceId, DeviceSecret, PrintedSecret};
    use crate::mac::Tag;
    use crate::render::Rendering;

    /// Wider than any frame below, and narrow enough that a length bug shows as
    /// a refusal in the builder rather than as a passing test.
    const SCRATCH: usize = 256;

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
    const NEXT_CHALLENGE: [u8; BSTR16] = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    const CLIENT_NONCE: [u8; BSTR16] = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    const LABEL: &str = "kitchen phone";
    const CLIENT_ID: u32 = 7;
    const SESSION: u16 = 3;
    const REQ_ID: u32 = 17;

    /// `macs.pair_proof.out16` from `docs/protocol/vectors/v1.json`, **retyped**.
    ///
    /// So it is a restatement rather than an outside opinion: change a nibble in
    /// that file and this stays green. What pins these two encoders to the
    /// artefact is `tests/vectors.rs`, which reads it. This is here because it
    /// splits the diagnosis — a wrong tag with the fields assembled here says
    /// the module composed the preimage wrongly, and the same tag wrong there
    /// says the file moved.
    const PUBLISHED_PROOF: [u8; Tag::LEN] = hex("22171c0449d848381e6d99ed7c92d1bd");

    /// `macs.pair_ack_mac.out16` from the same file, retyped for the same
    /// reason.
    const PUBLISHED_ACK: [u8; Tag::LEN] = hex("4a7937d934b87b750a254a05289f030b");

    /// The `inputs` block of the vector file, as the pair every key on this unit
    /// descends from.
    fn device() -> DeviceSecret {
        DeviceSecret::new(DeviceId::new(DEVICE_ID), PrintedSecret::new(PRINTED_SECRET))
    }

    fn slot() -> ClientId {
        ClientId::new(CLIENT_ID).expect("client_id 7 is a slot")
    }

    fn attempt() -> Attempt {
        Attempt {
            device_id: DEVICE_ID,
            challenge: CHALLENGE,
            client_nonce: CLIENT_NONCE,
        }
    }

    fn request() -> PairRequest<'static> {
        PairRequest {
            client_kind: ClientKind::App,
            label: LABEL,
        }
    }

    fn answer(outcome: Outcome) -> PairResponse {
        PairResponse {
            outcome,
            epoch: Epoch::FIRST,
            next_challenge: NEXT_CHALLENGE,
        }
    }

    fn header(kind: MessageType) -> Header {
        Header {
            kind,
            session: SessionId::from(SESSION),
            req_id: ReqId(REQ_ID),
        }
    }

    /// One frame, written by this module and kept beside its length.
    struct Frame {
        bytes: [u8; SCRATCH],
        len: usize,
    }

    impl Frame {
        fn of(len: usize, bytes: [u8; SCRATCH]) -> Self {
            Self { bytes, len }
        }

        fn bytes(&self) -> &[u8] {
            self.bytes
                .get(..self.len)
                .expect("the length came from the writer")
        }

        fn claimed(&self) -> Result<PairClaim<'_>, PairError> {
            PairClaim::decode(Envelope::decode(self.bytes()).map_err(PairError::Envelope)?)
        }

        fn acked(&self) -> Result<PairAckClaim, PairError> {
            PairAckClaim::decode(Envelope::decode(self.bytes()).map_err(PairError::Envelope)?)
        }

        /// One byte of the frame set to something else, for a fixture that
        /// stands in for a relay rewriting a field in flight.
        fn replaced(&self, at: usize, byte: u8) -> Self {
            let mut next = Self {
                bytes: self.bytes,
                len: self.len,
            };
            let slot = next.bytes.get_mut(at).expect("at is inside the frame");
            *slot = byte;
            next
        }

        /// One byte appended after the body's top-level map, which is what a
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

    /// Everything below writes a frame the same way, so it is written once.
    fn sent(fields: &PairRequest<'_>, attempt: &Attempt) -> Frame {
        let mut bytes = [0u8; SCRATCH];
        let len = fields
            .write(
                &device().pair_key(),
                attempt,
                header(MessageType::Pair),
                &mut bytes,
            )
            .expect("the pairing request encodes and proves");
        Frame::of(len, bytes)
    }

    fn answered(response: &PairResponse, attempt: &Attempt) -> Frame {
        let mut bytes = [0u8; SCRATCH];
        let len = response
            .write(
                &device().pair_key(),
                attempt,
                header(MessageType::PairResponse),
                &mut bytes,
            )
            .expect("the pairing answer encodes and MACs");
        Frame::of(len, bytes)
    }

    /// A frame built by hand, so a fixture can send a key twice, leave one out,
    /// or send a width no encoder would choose.
    struct Wire {
        bytes: [u8; SCRATCH],
        len: usize,
    }

    impl Wire {
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

        fn pair(mut self, key: u8, value: &[u8]) -> Self {
            assert!(key < 24, "the fixture keys are all inline");
            self.push(&[key]);
            self.push(value);
            self
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

        fn bytes(&self) -> &[u8] {
            self.bytes
                .get(..self.len)
                .expect("the length came from the builder")
        }

        fn claimed(&self) -> Result<PairClaim<'_>, PairError> {
            PairClaim::decode(Envelope::decode(self.bytes()).map_err(PairError::Envelope)?)
        }

        fn acked(&self) -> Result<PairAckClaim, PairError> {
            PairAckClaim::decode(Envelope::decode(self.bytes()).map_err(PairError::Envelope)?)
        }
    }

    /// A `bstr16` value, head byte and all.
    fn bstr16(value: &[u8; BSTR16]) -> [u8; BSTR16 + 1] {
        let mut out = [0x50u8; BSTR16 + 1];
        for (slot, &byte) in out.iter_mut().skip(1).zip(value) {
            *slot = byte;
        }
        out
    }

    /// A whole `Pair 0x8B` body, key by key.
    fn ack_wire(outcome: u8, client_id: u8) -> Wire {
        Wire::envelope(header(MessageType::PairResponse), PairAckKey::COUNT)
            .pair(1, &[outcome])
            .pair(2, &[client_id])
            .bstr(3, &[0x11; BSTR16])
            .pair(4, &bstr16(&NEXT_CHALLENGE))
    }

    /// The published `pair_proof`, reached through the real derivation ladder
    /// and this module's own encoder.
    ///
    /// Coming through `DeviceSecret` rather than handing `proof` a key means a
    /// dropped `epoch`, a swapped HKDF argument and a field composed in the
    /// wrong order all arrive as the same red line. The tag on the wire is read
    /// back out of the frame rather than off the return value, so an encoder
    /// that proved one `client_kind` and wrote another would show here.
    #[test]
    fn the_published_pair_proof_is_what_this_module_writes_on_the_wire() {
        let frame = sent(&request(), &attempt());
        let claim = frame
            .claimed()
            .expect("the frame this module wrote decodes");
        assert_eq!(
            claim.proof, PUBLISHED_PROOF,
            "this encoder and the published pair proof have parted company"
        );
        assert_eq!(claim.attempt(DEVICE_ID, CHALLENGE), attempt());
        assert_eq!(
            claim
                .verify(&device().pair_key(), &attempt())
                .expect("the proof this client computed verifies"),
            request()
        );
    }

    /// The published `pair_ack_mac`, through the same ladder and this module's
    /// ack encoder — including the `epoch` the body does not carry.
    #[test]
    fn the_published_pair_ack_mac_is_what_this_module_writes_on_the_wire() {
        let frame = answered(&answer(Outcome::Enrolled(slot())), &attempt());
        let claim = frame.acked().expect("the ack this module wrote decodes");
        assert_eq!(
            claim.mac, PUBLISHED_ACK,
            "this encoder and the published pair-ack MAC have parted company"
        );
        assert_eq!(
            claim
                .verify(&device().pair_key(), &attempt(), Epoch::FIRST)
                .expect("the ack this controller computed verifies"),
            answer(Outcome::Enrolled(slot()))
        );
    }

    /// P-064: the refusals are MAC'd too.
    ///
    /// Delete the tag from `window_closed`, `bad_proof` or `table_full` and the
    /// comms processor can forge any of them for free — which sends somebody
    /// standing at the panel back to press a button that was never needed, or
    /// tells them the client table is full when it is empty. Each is written,
    /// decoded and verified here; a refusal that stopped carrying a real tag
    /// fails at the `verify`.
    #[test]
    fn a_refused_pairing_still_carries_a_tag_the_client_can_check() {
        for outcome in [Outcome::WindowClosed, Outcome::BadProof, Outcome::TableFull] {
            let response = answer(outcome);
            let frame = answered(&response, &attempt());
            let verified = frame
                .acked()
                .expect("the refusal decodes")
                .verify(&device().pair_key(), &attempt(), Epoch::FIRST)
                .unwrap_or_else(|why| panic!("{outcome} does not verify: {why}"));
            assert_eq!(verified, response);
            assert_eq!(verified.outcome.slot(), None, "{outcome} named a slot");
            assert_eq!(
                verified.next_challenge, NEXT_CHALLENGE,
                "{outcome} arrived without a live challenge to retry against"
            );
        }
    }

    /// P-058: every outcome carries `next_challenge`, because P-061 spends a
    /// challenge on presentation and not on success.
    ///
    /// Without key 4 a client told `bad_proof` has nothing live to retry
    /// against, and the answer is another `Discover` — the round trip this
    /// requirement deleted, put back on the path where somebody is already
    /// frustrated. Drop the field from the ack and this is the test that fires.
    #[test]
    fn an_ack_with_no_next_challenge_is_refused_rather_than_reusing_the_spent_one() {
        let without = Wire::envelope(header(MessageType::PairResponse), 3)
            .pair(1, &[0x02])
            .pair(2, &[0x00])
            .bstr(3, &[0x11; BSTR16]);
        assert_eq!(
            without.acked().err(),
            Some(PairError::Missing(PairBodyKey::Ack(
                PairAckKey::NextChallenge
            ))),
            "a missing next_challenge must be named, never defaulted"
        );

        // And the replacement is what a retry proves against, not the one the
        // controller has just consumed.
        let response = answer(Outcome::BadProof);
        let second = response.retry(DEVICE_ID, [0x5a; BSTR16]);
        assert_eq!(second.challenge, NEXT_CHALLENGE);
        assert_ne!(
            second.client_nonce, CLIENT_NONCE,
            "P-069 wants a fresh nonce on the second attempt too"
        );
    }

    /// P-069 and P-078: `label` is inside the preimage, so a name rewritten in
    /// flight does not verify.
    ///
    /// Left outside, the comms processor renames a phone at no cost and the
    /// controller stores and authenticates the rewrite — an audit record naming
    /// a device that was never there, and a reclaim pointed at somebody else's
    /// row. The frame below is byte-identical apart from one character of the
    /// label, so nothing but the tag stands between here and there.
    #[test]
    fn a_label_rewritten_in_flight_does_not_verify_under_the_proof_the_client_sent() {
        let honest = sent(&request(), &attempt());
        let at = honest
            .bytes()
            .windows(LABEL.len())
            .position(|window| window == LABEL.as_bytes())
            .expect("the label is on the wire as its own bytes");
        let rewritten = honest.replaced(at, b'K');
        assert_ne!(
            rewritten.bytes(),
            honest.bytes(),
            "the fixture must differ on the wire, or this test proves nothing"
        );
        assert_eq!(
            rewritten
                .claimed()
                .expect("the edited frame still parses")
                .verify(&device().pair_key(), &attempt())
                .err(),
            Some(BadProof),
            "a renamed phone enrolled under somebody else's proof"
        );
    }

    /// The other half of the same preimage: `client_kind` is attested, so a
    /// relay cannot promote a phone to a cloud enrolment on its way past.
    ///
    /// The mask P-105 fixes at enrolment comes from this byte, and a `1` turned
    /// into a `3` is a firmware-pushing client the person at the panel never
    /// authorised.
    #[test]
    fn a_client_kind_raised_in_flight_does_not_verify_either() {
        let honest = sent(&request(), &attempt());
        let at = honest
            .bytes()
            .iter()
            .position(|&byte| byte == 0x01)
            .expect("key 1's value is on the wire");
        let promoted = honest.replaced(at.saturating_add(1), ClientKind::Cloud as u8);
        assert_eq!(
            promoted
                .claimed()
                .expect("the edited frame still parses")
                .verify(&device().pair_key(), &attempt())
                .err(),
            Some(BadProof)
        );
    }

    /// P-086: `client_id` 0 with outcome `enrolled` is refused rather than read
    /// as slot zero.
    ///
    /// **Only outcome 3 counts against `MAX_AUTH_FAILURES`**, and the half
    /// that is not obvious is which two do not.
    ///
    /// Counting `bad_proof` is what stops `Pair` being an unmetered HMAC oracle.
    /// Not counting `window_closed` and `table_full` is what stops anybody
    /// closing a technician's connection by sending `Pair` at a controller with
    /// no window open — those two verify nothing, so a peer reaching them has
    /// made this controller compute nothing, and the threshold bounds compute.
    ///
    /// The two successes are here because they are the arms somebody adds to the
    /// counting side by reflex: a proof that *checked out* is not a failure, and
    /// an enrolment that spent the eighth slot is the client the site belongs to.
    #[test]
    fn p_051_only_a_proof_that_was_computed_and_failed_counts_against_the_shed() {
        assert!(
            Outcome::BadProof.failed_a_proof(),
            "an unmetered HMAC oracle behind the one message somebody uses at the panel"
        );
        for free in [Outcome::WindowClosed, Outcome::TableFull] {
            assert!(
                !free.failed_a_proof(),
                "{free} verifies nothing, so anybody could close a technician's connection with it"
            );
        }
        for good in [
            Outcome::Enrolled(ClientId::new(1).expect("a slot")),
            Outcome::Reclaimed(ClientId::new(8).expect("a slot")),
        ] {
            assert!(!good.failed_a_proof(), "{good} is a proof that checked out");
        }
    }

    /// Taken at face value a client derives its long-term key at slot 0, which
    /// no controller ever allocates, and every frame it sends afterwards fails
    /// its MAC with nothing pointing at this line. The mirror is the one that
    /// would otherwise slip through: a `window_closed` naming a slot is a
    /// refusal claiming somebody else's row.
    #[test]
    fn a_client_id_of_zero_with_outcome_enrolled_is_refused() {
        for outcome in [0x01u8, 0x05] {
            assert_eq!(
                ack_wire(outcome, 0).acked().err(),
                Some(PairError::NoSuchSlot),
                "outcome {outcome} with client_id 0"
            );
        }
        for outcome in [0x02u8, 0x03, 0x04] {
            assert_eq!(
                ack_wire(outcome, 3).acked().err(),
                Some(PairError::SlotOnARefusal(
                    ClientId::new(3).expect("3 is a slot")
                )),
                "outcome {outcome} with client_id 3"
            );
        }
        // And the two that are legal still are, so the rule above refuses on the
        // combination rather than on the outcome.
        for outcome in [0x01u8, 0x05] {
            ack_wire(
                outcome,
                u8::try_from(CLIENT_ID).expect("slot 7 fits a byte"),
            )
            .acked()
            .unwrap_or_else(|why| panic!("outcome {outcome} at slot 7: {why}"));
        }
    }

    /// P-064, and the half every round trip above is blind to: no two answers
    /// over one attempt share a tag.
    ///
    /// Both ends assemble this preimage through one function, so a field dropped
    /// out of it leaves the writer and the verifier agreeing with each other and
    /// with nobody else. `outcome` is the field that costs the most: the three
    /// refusals all carry `client_id` 0, so without it in the preimage a
    /// `bad_proof` and a `window_closed` are interchangeable in flight — and the
    /// comms processor turns "you mis-scanned the label" into "press the button
    /// again", which is the trip P-066 spends a MAC to prevent. `enrolled` and
    /// `reclaimed` at one slot are the pair that differ by nothing else at all.
    ///
    /// This test was written because deleting `outcome` from the preimage left
    /// every other test in this file green.
    #[test]
    fn no_two_answers_over_one_attempt_share_a_tag() {
        const EVERY: usize = 6;
        let other = ClientId::new(1).expect("1 is a slot");
        let outcomes = [
            Outcome::Enrolled(slot()),
            Outcome::Enrolled(other),
            Outcome::WindowClosed,
            Outcome::BadProof,
            Outcome::TableFull,
            Outcome::Reclaimed(slot()),
        ];

        let mut tags = [[0u8; Tag::LEN]; EVERY];
        for (slot_of, outcome) in tags.iter_mut().zip(outcomes) {
            *slot_of = answered(&answer(outcome), &attempt())
                .acked()
                .unwrap_or_else(|why| panic!("{outcome} decodes: {why}"))
                .mac;
        }
        for first in 0..EVERY {
            for second in first.saturating_add(1)..EVERY {
                assert_ne!(
                    tags.get(first).expect("the index came from the list"),
                    tags.get(second).expect("the index came from the list"),
                    "{} and {} share a tag, so one arrives as the other",
                    outcomes.get(first).expect("the index came from the list"),
                    outcomes.get(second).expect("the index came from the list"),
                );
            }
        }
    }

    /// The rest of the pair-ack preimage, each field moved on its own.
    ///
    /// An ack lifted onto another connection, another unit or another
    /// replacement challenge must all fail — the last one hardest, because a
    /// `next_challenge` outside the MAC is the comms processor choosing the value
    /// the following `Hello` proof is computed against, which is the one input to
    /// `session_key` the controller is supposed to own.
    #[test]
    fn an_ack_moved_to_another_connection_or_another_challenge_does_not_verify() {
        let key = device().pair_key();
        let sent_here = answered(&answer(Outcome::Enrolled(slot())), &attempt());

        let elsewhere = Attempt {
            challenge: [0x5a; BSTR16],
            ..attempt()
        };
        let another_unit = Attempt {
            device_id: [0x5a; BSTR16],
            ..attempt()
        };
        for moved in [elsewhere, another_unit] {
            assert_eq!(
                sent_here
                    .acked()
                    .expect("the ack decodes")
                    .verify(&key, &moved, Epoch::FIRST)
                    .err(),
                Some(PairError::Mac(MacError::Mismatch))
            );
        }

        let substituted = PairResponse {
            next_challenge: [0x5a; BSTR16],
            ..answer(Outcome::Enrolled(slot()))
        };
        assert_ne!(
            answered(&substituted, &attempt())
                .acked()
                .expect("it decodes")
                .mac,
            sent_here.acked().expect("it decodes").mac,
            "two next_challenges produced one tag, so the field is outside the MAC"
        );
    }

    /// P-087, from the other side: the MAC covers `epoch` and the body does not
    /// carry it, so a client verifying under the wrong one sees a mismatch and
    /// nothing on the wire explains it.
    ///
    /// That is the whole reason `Discover 0x80` reports the number. Without this
    /// test a verifier that quietly dropped `epoch` from the preimage would pass
    /// every other case here, and a unit that had been factory-reset would refuse
    /// every phone with no way for anybody to tell why.
    #[test]
    fn an_ack_checked_under_another_epoch_does_not_verify() {
        let frame = answered(&answer(Outcome::Enrolled(slot())), &attempt());
        let later = Epoch::new(2).expect("2 is an epoch");
        assert_eq!(
            frame
                .acked()
                .expect("the ack decodes")
                .verify(&device().pair_key(), &attempt(), later)
                .err(),
            Some(PairError::Mac(MacError::Mismatch)),
            "the epoch is not in this preimage, so a reset invalidates nothing"
        );
    }

    /// P-069: an ack recorded from an earlier enrolment must not verify on a
    /// later attempt.
    ///
    /// The nonce is the only input the client chooses, so it is all that stands
    /// between a replayed ack and a second phone being told it is the same
    /// `client_id` as the first.
    #[test]
    fn an_ack_recorded_from_an_earlier_attempt_does_not_verify_on_a_later_one() {
        let recorded = answered(&answer(Outcome::Enrolled(slot())), &attempt());
        let later = Attempt {
            client_nonce: [0x5a; BSTR16],
            ..attempt()
        };
        assert_eq!(
            recorded
                .acked()
                .expect("the recorded ack decodes")
                .verify(&device().pair_key(), &later, Epoch::FIRST)
                .err(),
            Some(PairError::Mac(MacError::Mismatch))
        );
    }

    /// A proof checked against a nonce other than the one that arrived is
    /// refused, rather than passing on the wire value and leaving the two
    /// preimages disagreeing.
    ///
    /// It reads like a caller's own mistake and it is worse than that: the ack
    /// is MAC'd over the [`Attempt`] the controller holds, so a verify that
    /// quietly used the body's nonce while the caller held another would enrol a
    /// client and then hand it a tag it cannot check — the message that fixes
    /// its identity, unverifiable, with the enrolment already made. Taking the
    /// nonce off the claim through [`PairClaim::attempt`] is what makes the two
    /// one value; this is what says the shortcut is not silently equivalent.
    #[test]
    fn a_proof_checked_against_a_nonce_other_than_the_one_that_arrived_does_not_verify() {
        let frame = sent(&request(), &attempt());
        let elsewhere = Attempt {
            client_nonce: [0x5a; BSTR16],
            ..attempt()
        };
        assert_eq!(
            frame
                .claimed()
                .expect("the frame decodes")
                .verify(&device().pair_key(), &elsewhere)
                .err(),
            Some(BadProof)
        );

        // And the trio the claim hands out is the one that does verify.
        let claim = frame.claimed().expect("the frame decodes");
        let trio = claim.attempt(DEVICE_ID, CHALLENGE);
        assert_eq!(
            claim
                .verify(&device().pair_key(), &trio)
                .expect("the nonce off the wire is the nonce in the proof"),
            request()
        );
    }

    /// The same for the challenge: a proof captured on one connection does not
    /// verify on the next, which is the whole reason P-060 mints a fresh one per
    /// connection.
    #[test]
    fn a_proof_captured_on_one_connection_does_not_verify_on_another() {
        let captured = sent(&request(), &attempt());
        let elsewhere = Attempt {
            challenge: [0x5a; BSTR16],
            ..attempt()
        };
        assert_eq!(
            captured
                .claimed()
                .expect("the captured frame decodes")
                .verify(&device().pair_key(), &elsewhere)
                .err(),
            Some(BadProof)
        );
    }

    /// P-088: both proofs are keyed by `pair_key` and never by the printed
    /// secret.
    ///
    /// The comms processor watches every pairing exchange, so signing under
    /// the master secret would hand the one component this protocol calls hostile an
    /// oracle under the secret the whole device rests on. A tag computed under
    /// the wrong key is sixteen bytes of exactly the right shape, so nothing but
    /// the comparison catches it.
    #[test]
    fn a_pairing_answer_signed_under_another_units_key_does_not_verify() {
        let theirs = DeviceSecret::new(
            DeviceId::new([0x5a; BSTR16]),
            PrintedSecret::new(PRINTED_SECRET),
        );
        let mut bytes = [0u8; SCRATCH];
        let len = answer(Outcome::Enrolled(slot()))
            .write(
                &theirs.pair_key(),
                &attempt(),
                header(MessageType::PairResponse),
                &mut bytes,
            )
            .expect("another unit's answer encodes");
        assert_eq!(
            Frame::of(len, bytes)
                .acked()
                .expect("it decodes")
                .verify(&device().pair_key(), &attempt(), Epoch::FIRST)
                .err(),
            Some(PairError::Mac(MacError::Mismatch))
        );
    }

    /// P-013 holds here too: a key this version has never heard of is skipped,
    /// and the four it knows still decode.
    ///
    /// Refusing was tried first, on the argument that every key of both bodies
    /// is inside a preimage so a later one would be meaningful and outside the
    /// MAC. The second half of that is true and is why PROTOCOL.md now requires
    /// a later field to enter the preimage. The first half does not follow:
    /// refusing means a v2 client cannot enrol at a v1 controller, and
    /// enrolment is the one exchange that needs somebody standing at the panel,
    /// so that failure costs a drive rather than a reconnect.
    #[test]
    fn a_pairing_key_this_version_has_never_heard_of_is_skipped_not_refused() {
        // The same four keys without the fifth decode, so what follows is about
        // the extra key rather than anything else in the fixture.
        ack_wire(0x02, 0).acked().expect("the four-key ack decodes");
        let with_a_counter = Wire::envelope(header(MessageType::PairResponse), 5)
            .pair(1, &[0x02])
            .pair(2, &[0x00])
            .bstr(3, &[0x11; BSTR16])
            .pair(4, &bstr16(&NEXT_CHALLENGE))
            .pair(5, &[0x00]);
        with_a_counter
            .acked()
            .expect("a fifth key is skipped, not refused");
    }

    #[test]
    fn a_pairing_body_that_carries_a_key_twice_is_refused_before_either_copy_is_used() {
        let twice = Wire::envelope(header(MessageType::Pair), 5)
            .pair(1, &[0x01])
            .pair(2, &[0x60])
            .pair(2, &[0x61, b'a'])
            .bstr(3, &[0x11; BSTR16])
            .pair(4, &bstr16(&CLIENT_NONCE));
        assert_eq!(
            twice.claimed().err(),
            Some(PairError::Duplicate(PairBodyKey::Request(
                PairRequestKey::Label
            ))),
            "a second label must not be resolvable at all"
        );

        let ack_twice = Wire::envelope(header(MessageType::PairResponse), 5)
            .pair(1, &[0x02])
            .pair(2, &[0x00])
            .bstr(3, &[0x11; BSTR16])
            .pair(4, &bstr16(&NEXT_CHALLENGE))
            .pair(4, &bstr16(&CHALLENGE));
        assert_eq!(
            ack_twice.acked().err(),
            Some(PairError::Duplicate(PairBodyKey::Ack(
                PairAckKey::NextChallenge
            )))
        );
    }

    /// A key the body requires that never arrived is named, never defaulted.
    ///
    /// An absent `client_nonce` read as sixteen zero bytes is a proof computed
    /// over a nonce nobody chose, which is P-069's replay window with the door
    /// held open.
    #[test]
    fn a_pairing_key_that_never_arrived_is_named_rather_than_defaulted() {
        let without_nonce = Wire::envelope(header(MessageType::Pair), 3)
            .pair(1, &[0x01])
            .pair(2, &[0x60])
            .bstr(3, &[0x11; BSTR16]);
        assert_eq!(
            without_nonce.claimed().err(),
            Some(PairError::Missing(PairBodyKey::Request(
                PairRequestKey::ClientNonce
            )))
        );

        let without_mac = Wire::envelope(header(MessageType::PairResponse), 3)
            .pair(1, &[0x02])
            .pair(2, &[0x00])
            .pair(4, &bstr16(&NEXT_CHALLENGE));
        assert_eq!(
            without_mac.acked().err(),
            Some(PairError::Missing(PairBodyKey::Ack(PairAckKey::Mac))),
            "an ack with no tag is the forged refusal P-064 exists to stop"
        );
    }

    /// A `bstr16` that is not sixteen bytes is refused on its width, never
    /// padded out or trimmed to fit.
    ///
    /// Padded, a twelve-byte tag verifies against a forgery whose last four
    /// bytes were never guessed; a padded `next_challenge` is a client proving
    /// against a value with a tail of zeros nobody agreed to.
    #[test]
    fn a_bstr16_that_is_not_sixteen_bytes_is_refused_rather_than_padded() {
        for len in [0usize, 1, 15, 17] {
            let short = [0x11u8; 17];
            let value = short
                .get(..len)
                .expect("the filler is wider than seventeen");

            let proof = Wire::envelope(header(MessageType::Pair), 4)
                .pair(1, &[0x01])
                .pair(2, &[0x60])
                .bstr(3, value)
                .pair(4, &bstr16(&CLIENT_NONCE));
            assert_eq!(
                proof.claimed().err(),
                Some(PairError::WrongWidth {
                    key: PairBodyKey::Request(PairRequestKey::Proof),
                    len,
                }),
                "a proof of {len} bytes"
            );

            let mac = Wire::envelope(header(MessageType::PairResponse), 4)
                .pair(1, &[0x02])
                .pair(2, &[0x00])
                .bstr(3, value)
                .pair(4, &bstr16(&NEXT_CHALLENGE));
            assert_eq!(
                mac.acked().err(),
                Some(PairError::WrongWidth {
                    key: PairBodyKey::Ack(PairAckKey::Mac),
                    len,
                }),
                "a mac of {len} bytes"
            );
        }
    }

    /// A `client_kind` with no registry row is refused at enrolment, because
    /// there is no capability mask to fix from it.
    ///
    /// The same for an outcome nobody allocated: a client that guessed would
    /// either enrol on a number it does not understand or abandon an enrolment a
    /// later controller had granted.
    ///
    /// **P-014, and it is the opposite of P-013 on purpose.** An unknown extra
    /// *field* is a newer peer being chatty and is skipped; an unknown *value*
    /// in a field that decides behaviour is a message whose meaning is not
    /// knowable. There is no `0 = unknown` fallback anywhere in this protocol,
    /// and both refusals below go out as error 1 rather than as a guess.
    #[test]
    fn p_014_a_registry_number_this_version_does_not_allocate_is_refused_rather_than_guessed() {
        let kind = Wire::envelope(header(MessageType::Pair), 4)
            .pair(1, &[0x09])
            .pair(2, &[0x60])
            .bstr(3, &[0x11; BSTR16])
            .pair(4, &bstr16(&CLIENT_NONCE));
        assert_eq!(
            kind.claimed().err(),
            Some(PairError::UnknownClientKind(0x09))
        );
        assert_eq!(
            ack_wire(0x09, 0).acked().err(),
            Some(PairError::UnknownOutcome(0x09))
        );

        // Error 1, not a variant of its own: the body was well formed and its
        // meaning was not knowable, which is what error 1 says.
        for refused in [
            PairError::UnknownClientKind(0x09),
            PairError::UnknownOutcome(0x09),
        ] {
            assert_eq!(
                refused.refusal(),
                Refusal::Client(ErrorCode::MalformedFrame),
                "{refused:?} did not go out as error 1"
            );
        }
    }

    /// Both decoders call `finish()`, and deleting either leaves the suite green
    /// unless something feeds one a trailing byte.
    ///
    /// What it lets through is a body with something appended after its
    /// top-level map. Neither pairing MAC covers the encoding, so the tag still
    /// holds, and the two ends then disagree about where the message ended while
    /// both believe it authentic.
    #[test]
    fn a_byte_appended_after_a_pairing_body_is_refused_rather_than_ignored() {
        assert_eq!(
            sent(&request(), &attempt())
                .with_a_trailing_byte()
                .claimed()
                .err(),
            Some(PairError::Cbor(CborError::TrailingBytes))
        );
        assert_eq!(
            answered(&answer(Outcome::TableFull), &attempt())
                .with_a_trailing_byte()
                .acked()
                .err(),
            Some(PairError::Cbor(CborError::TrailingBytes))
        );
    }

    /// An envelope naming another message is not read as a pairing body.
    ///
    /// Keys 1 to 4 exist in both directions and mean different things in each,
    /// so a request read as an ack decodes far enough to be answered — with a
    /// `client_kind` standing in for an outcome.
    #[test]
    fn a_frame_that_names_another_message_is_not_read_as_a_pairing_body() {
        let frame = sent(&request(), &attempt());
        let envelope = Envelope::decode(frame.bytes()).expect("the frame decodes");
        assert_eq!(
            PairAckClaim::decode(envelope).err(),
            Some(PairError::WrongMessage {
                expected: MessageType::PairResponse,
                found: MessageType::Pair,
            })
        );

        let mut bytes = [0u8; SCRATCH];
        assert_eq!(
            request()
                .write(
                    &device().pair_key(),
                    &attempt(),
                    header(MessageType::PairResponse),
                    &mut bytes
                )
                .err(),
            Some(PairError::WrongMessage {
                expected: MessageType::Pair,
                found: MessageType::PairResponse,
            }),
            "a writer handed the wrong header must refuse before it proves anything"
        );
    }

    /// A label wider than any cap is refused at the writer rather than sent and
    /// refused there, because a truncated label is a different label and P-078
    /// matches rows on the exact bytes. It meets the row's cap first, so the
    /// refusal names the field rather than the CBOR string limit under it.
    #[test]
    fn a_label_wider_than_the_cap_is_refused_before_it_is_proved() {
        const WIDE: &str =
            "a label considerably wider than the sixty-four bytes the protocol allows for one";
        assert!(WIDE.len() > MAX_STRING, "the fixture has to exceed the cap");
        let mut bytes = [0u8; SCRATCH];
        assert_eq!(
            PairRequest {
                client_kind: ClientKind::App,
                label: WIDE,
            }
            .write(
                &device().pair_key(),
                &attempt(),
                header(MessageType::Pair),
                &mut bytes
            )
            .err(),
            Some(PairError::WrongWidth {
                key: PairBodyKey::Request(PairRequestKey::Label),
                len: WIDE.len(),
            })
        );
    }

    /// A label between the two caps decodes to something no enrolment row can
    /// hold, and it arrives with a proof that **verifies**.
    ///
    /// `text()` bounds by `MAX_STRING` and a row holds `MAX_LABEL`, so 40 bytes
    /// was writable, provable and unstorable — and there is no outcome that says
    /// so, because the proof was good and the table was not full. The controller
    /// was left choosing between three lies. Refused at the field instead.
    #[test]
    fn a_label_a_row_cannot_hold_is_refused_before_it_becomes_an_outcome() {
        const OVER: &str = "0123456789012345678901234567890123456789";
        assert!(OVER.len() > MAX_LABEL, "the fixture must exceed a row");
        assert!(
            OVER.len() <= MAX_STRING,
            "and must still be writable as text"
        );
        let refused = Some(PairError::WrongWidth {
            key: PairBodyKey::Request(PairRequestKey::Label),
            len: OVER.len(),
        });

        // Where it is typed: the writer refuses it before a proof is computed.
        let mut bytes = [0u8; SCRATCH];
        assert_eq!(
            PairRequest {
                client_kind: ClientKind::App,
                label: OVER,
            }
            .write(
                &device().pair_key(),
                &attempt(),
                header(MessageType::Pair),
                &mut bytes,
            )
            .err(),
            refused
        );

        // And where it is read, because the other end of the link is not this
        // crate. Built by hand the way the writer would have before it refused.
        let attempt = attempt();
        let proof = device().pair_key().proof(&PairProof {
            device_id: &attempt.device_id,
            challenge: &attempt.challenge,
            client_nonce: &attempt.client_nonce,
            client_kind: ClientKind::App,
            label: OVER,
        });
        let mut cbor = header(MessageType::Pair)
            .write(PairRequestKey::COUNT, &mut bytes)
            .expect("a header");
        cbor.key(PairRequestKey::ClientKind.number()).expect("key");
        cbor.u64(u64::from(ClientKind::App as u8)).expect("kind");
        cbor.key(PairRequestKey::Label.number()).expect("key");
        cbor.text(OVER).expect("a label under MAX_STRING");
        cbor.key(PairRequestKey::Proof.number()).expect("key");
        cbor.bytes(proof.as_bytes()).expect("proof");
        cbor.key(PairRequestKey::ClientNonce.number()).expect("key");
        cbor.bytes(&attempt.client_nonce).expect("nonce");
        let len = cbor.finish().expect("a closed body");

        let envelope = Envelope::decode(bytes.get(..len).expect("the frame")).expect("an envelope");
        assert_eq!(PairClaim::decode(envelope).err(), refused);
    }

    /// An empty label is a label: it is legal on the wire, and the proof over it
    /// is a proof over the fixed fields with nothing at the tail.
    ///
    /// The variable-width field being last is what makes that unambiguous, and a
    /// zero-length one is where an implementation that fed a length prefix would
    /// still look right.
    #[test]
    fn an_empty_label_still_proves_and_still_differs_from_a_named_one() {
        let empty = PairRequest {
            client_kind: ClientKind::App,
            label: "",
        };
        let frame = sent(&empty, &attempt());
        assert_eq!(
            frame
                .claimed()
                .expect("the empty label decodes")
                .verify(&device().pair_key(), &attempt())
                .expect("and proves"),
            empty
        );
        assert_ne!(
            frame.bytes(),
            sent(&request(), &attempt()).bytes(),
            "two labels produced one frame"
        );
    }

    /// The five outcomes render as five different sentences, because the pair
    /// somebody will be telling apart at a panel is "the window was shut" and
    /// "the table is full", and the two need different things done about them.
    #[test]
    fn every_outcome_says_something_of_its_own() {
        let other = ClientId::new(1).expect("1 is a slot");
        let every = [
            Outcome::Enrolled(slot()),
            Outcome::Enrolled(other),
            Outcome::WindowClosed,
            Outcome::BadProof,
            Outcome::TableFull,
            Outcome::Reclaimed(slot()),
        ];
        Rendering::<64>::each_says_something_of_its_own(&every);
    }

    /// The refusals render as different sentences too, and a `BadProof` says
    /// something of its own beside them — it is the one that is not a
    /// `PairError` and the one a bench log most needs to tell from the rest.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        let every = [
            PairError::Missing(PairBodyKey::Ack(PairAckKey::Mac)),
            PairError::Missing(PairBodyKey::Request(PairRequestKey::Label)),
            PairError::Duplicate(PairBodyKey::Ack(PairAckKey::NextChallenge)),
            PairError::WrongWidth {
                key: PairBodyKey::Request(PairRequestKey::Proof),
                len: 12,
            },
            PairError::WrongMessage {
                expected: MessageType::Pair,
                found: MessageType::PairResponse,
            },
            PairError::UnknownClientKind(9),
            PairError::UnknownOutcome(9),
            PairError::NoSuchSlot,
            PairError::SlotOnARefusal(slot()),
            PairError::Mac(MacError::Mismatch),
            PairError::Envelope(EnvelopeError::WrongLength),
            PairError::Cbor(CborError::TrailingBytes),
        ];
        Rendering::<96>::each_says_something_of_its_own(&every);
        assert_eq!(
            Rendering::<64>::displayed(&BadProof).bytes(),
            b"the pairing proof does not match these fields"
        );
    }

    /// Neither claim renders a field somebody else chose.
    ///
    /// A derived `Debug` on either is an accessor spelled `{:?}` — one that
    /// hands out `label` before any proof has checked out, and `outcome` before
    /// the MAC has. Both were reachable in this crate two rounds ago.
    #[test]
    fn an_unverified_pairing_body_renders_no_field_it_carries() {
        let frame = sent(&request(), &attempt());
        let claim = frame.claimed().expect("it decodes");
        let rendered = Rendering::<96>::debugged(&claim);
        assert_eq!(
            rendered.bytes(),
            b"PairClaim { unverified, label: 13 bytes }"
        );
        assert!(
            !rendered
                .bytes()
                .windows(LABEL.len())
                .any(|window| window == LABEL.as_bytes()),
            "the label reached a formatter before anything authenticated it"
        );

        let ack = answered(&answer(Outcome::Enrolled(slot())), &attempt());
        assert_eq!(
            Rendering::<96>::debugged(&ack.acked().expect("it decodes")).bytes(),
            b"PairAckClaim { unverified, outcome withheld }"
        );
        assert_eq!(
            Rendering::<96>::debugged(&attempt()).bytes(),
            b"Attempt { device_id, challenge and client_nonce, none rendered }"
        );
    }

    /// A refusal answers in the space it belongs to, and the failed proof is
    /// deliberately not among them.
    ///
    /// P-051's exception is that `bad_proof` is an outcome rather than error 10,
    /// so `BadProof` has no `refusal` to reach for — this checks the codes the
    /// rest map to, and the type system covers the one that must not exist.
    #[test]
    fn a_malformed_pairing_body_is_error_one_and_a_bad_mac_is_error_ten() {
        assert_eq!(
            PairError::NoSuchSlot.refusal(),
            Refusal::Client(ErrorCode::MalformedFrame)
        );
        assert_eq!(
            PairError::Mac(MacError::Mismatch).refusal(),
            Refusal::Client(ErrorCode::BadMAC)
        );
        assert_eq!(
            PairError::Envelope(EnvelopeError::UnknownType(0x77)).refusal(),
            Refusal::Client(ErrorCode::UnknownMessageType)
        );
        assert_eq!(BadProof.outcome(), Outcome::BadProof);
    }

    /// Every key of both bodies is on the wire as the number the specification
    /// prints, checked in both directions.
    ///
    /// A key renumbered on one side only is a field two implementations read
    /// past each other, and the symptom is a required key reported missing on a
    /// frame that carries it.
    #[test]
    fn every_pairing_key_is_the_number_the_specification_prints() {
        for (key, number) in [
            (PairRequestKey::ClientKind, 1),
            (PairRequestKey::Label, 2),
            (PairRequestKey::Proof, 3),
            (PairRequestKey::ClientNonce, 4),
        ] {
            assert_eq!(key.number(), number);
            assert_eq!(PairRequestKey::of(number), Some(key));
        }
        for (key, number) in [
            (PairAckKey::Outcome, 1),
            (PairAckKey::ClientId, 2),
            (PairAckKey::Mac, 3),
            (PairAckKey::NextChallenge, 4),
        ] {
            assert_eq!(key.number(), number);
            assert_eq!(PairAckKey::of(number), Some(key));
        }
        assert_eq!(PairRequestKey::of(0), None);
        assert_eq!(PairAckKey::of(5), None);
    }

    /// The widest body this module can build fits the buffer the constant
    /// promises, with the envelope around it.
    ///
    /// The number is what a caller sizes a frame buffer at, and one byte short
    /// is a refusal that only ever fires on the longest label somebody types —
    /// at a panel, four hours from a road. The longest label is `MAX_LABEL`,
    /// the row's, and the constant is sized for `MAX_STRING`; the slack is
    /// what keeps the constant true if the row ever grows.
    #[test]
    fn the_widest_pairing_frame_fits_the_buffer_the_constant_promises() {
        const WIDEST: &str = "01234567890123456789012345678901";
        assert_eq!(
            WIDEST.len(),
            MAX_LABEL,
            "the fixture is the row's cap exactly"
        );
        let mut exact = [0u8; MAX_PAIR_BODY + ENVELOPE];
        let len = PairRequest {
            client_kind: ClientKind::App,
            label: WIDEST,
        }
        .write(
            &device().pair_key(),
            &attempt(),
            header(MessageType::Pair),
            &mut exact,
        )
        .expect("the widest label fits the buffer the constant promises");
        assert!(len <= MAX_PAIR_BODY + ENVELOPE);

        let mut ack = [0u8; MAX_PAIR_ACK_BODY + ENVELOPE];
        let widest_slot = ClientId::new(u32::MAX).expect("the top of the counter is a slot");
        let len = answer(Outcome::Enrolled(widest_slot))
            .write(
                &device().pair_key(),
                &attempt(),
                header(MessageType::PairResponse),
                &mut ack,
            )
            .expect("the widest client_id fits too");
        assert!(len <= MAX_PAIR_ACK_BODY + ENVELOPE);
    }
    /// Every strict prefix of a frame is refused, at the envelope or in the
    /// body it carries.
    fn refused_at_every_cut(bytes: &[u8], decode: impl Fn(Envelope<'_>) -> Result<(), PairError>) {
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

    /// Both pairing frames, cut at every byte. The claim decoders read the
    /// fields before any proof is checked, which is exactly where a short body
    /// has to be refused rather than read as a shorter label.
    #[test]
    fn every_pairing_frame_cut_short_at_any_byte_is_refused() {
        let mut bytes = [0u8; SCRATCH];
        let len = request()
            .write(
                &device().pair_key(),
                &attempt(),
                header(MessageType::Pair),
                &mut bytes,
            )
            .expect("encodes");
        refused_at_every_cut(bytes.get(..len).expect("the frame"), |e| {
            PairClaim::decode(e).map(|_| ())
        });

        let frame = answered(&answer(Outcome::Enrolled(slot())), &attempt());
        refused_at_every_cut(frame.bytes(), |e| PairAckClaim::decode(e).map(|_| ()));
    }
}
