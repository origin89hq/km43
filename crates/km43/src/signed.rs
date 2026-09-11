//! `{1: client_id, 2: counter, 3: operation, 4: mac}` — the body every write
//! wears, and the two checks P-080 puts in an order that is not negotiable.
//!
//! Configuration, firmware, time and commands all sign, because authenticating
//! one write and not another is a locked door beside an open one. The wrapper
//! cannot carry them: it has no room for a counter (P-053), and the counter is
//! what makes a captured frame useless a second time.
//!
//! P-080 says verify the MAC, *then* read the counter. Written as a rule that is
//! an ordering somebody obeys on the path they were thinking about; written as
//! the three types below it is the only order that compiles, and the operation
//! is unreachable until both have passed. That matters more than it looks: the
//! counter row lives in FRAM, and a decoder that reads it before checking the
//! MAC spends a write-cycle budget on every forged frame a relay sends.
//!
//! cites: P-053, P-083, P-084, P-110

use core::fmt;
use core::marker::PhantomData;

use crate::cbor::{CborError, CborReader};
use crate::envelope::{Envelope, Header, Refusal};
use crate::generated::{ErrorCode, MessageType};
use crate::kdf::ClientId;
use crate::limits::MAX_OPERATION;
use crate::mac::{MacError, SessionKey, SignedRequest, Tag};

/// The counter that makes a captured write useless a second time.
///
/// Per client and stored `client_id → highest accepted` (P-081); a single
/// device-wide counter livelocks the moment two clients are active, because both
/// read 100, both send 101, and one of them is refused forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Counter(pub u64);

impl Counter {
    /// The next value to send, or `None` at the ceiling.
    ///
    /// `None` rather than a saturating repeat: a counter that does not *exceed*
    /// the stored one is refused with error 11 forever, and P-081's own livelock
    /// paragraph is what that looks like from the client's side — refused, re-
    /// `Hello`, read key 11, send the same number, refused again.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }

    /// Whether this value would be accepted after `last`. Strictly greater —
    /// equal is the replay.
    #[must_use]
    pub const fn is_ahead_of(self, last: Self) -> bool {
        self.0 > last.0
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The four keys of a signed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedKey {
    /// Key 1. On the wire only because it is inside the preimage — P-084 is
    /// emphatic that it is never the lookup key.
    ClientId,
    /// Key 2.
    Counter,
    /// Key 3, the operation body, carried and MAC'd exactly as it arrived.
    Operation,
    /// Key 4.
    Mac,
}

impl SignedKey {
    const COUNT: usize = 4;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ClientId),
            2 => Some(Self::Counter),
            3 => Some(Self::Operation),
            4 => Some(Self::Mac),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ClientId => 1,
            Self::Counter => 2,
            Self::Operation => 3,
            Self::Mac => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ClientId => "client_id",
            Self::Counter => "counter",
            Self::Operation => "operation",
            Self::Mac => "mac",
        }
    }
}

impl fmt::Display for SignedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signed body {} (key {})", self.name(), self.number())
    }
}

/// The four types P-053 signs, read off the `type` rather than passed in.
///
/// A caller allowed to choose could sign a `Time` and send it as a `Command`:
/// the label is the same, and P-046 puts the type in the preimage precisely so
/// that swap fails. Refusing here means it never has to.
fn signs(header: Header) -> Result<(), SignedError> {
    match header.kind {
        MessageType::SetConfig
        | MessageType::Command
        | MessageType::Firmware
        | MessageType::Time => Ok(()),
        MessageType::Discover
        | MessageType::DiscoverResponse
        | MessageType::Hello
        | MessageType::HelloResponse
        | MessageType::Inventory
        | MessageType::InventoryResponse
        | MessageType::Readings
        | MessageType::ReadingsResponse
        | MessageType::Concerns
        | MessageType::ConcernsResponse
        | MessageType::History
        | MessageType::HistoryResponse
        | MessageType::Subscribe
        | MessageType::SubscribeResponse
        | MessageType::EventResponse
        | MessageType::ReadLog
        | MessageType::ReadLogResponse
        | MessageType::GetConfig
        | MessageType::GetConfigResponse
        | MessageType::SetConfigResponse
        | MessageType::CommandResponse
        | MessageType::FirmwareResponse
        | MessageType::TimeResponse
        | MessageType::Pair
        | MessageType::PairResponse
        | MessageType::Goodbye
        | MessageType::GoodbyeResponse
        | MessageType::ErrorResponse => Err(SignedError::NotSigned(header.kind)),
    }
}

/// A signed body ready to send: the operation, and the tag over exactly those
/// bytes and this header.
///
/// [`Signed::over`] is the only constructor and it computes the tag from the
/// same header, `client_id`, `counter` and `operation` that [`Signed::write`]
/// then puts on the wire. `km43/v1/req` covers three envelope scalars as well as
/// the body's own fields, so a caller who could sign one set and send another
/// would authenticate a frame it never sent — which is the argument `wrapper.rs`
/// makes about [`crate::Tagged`], with three more fields to get wrong.
pub struct Signed<'a> {
    header: Header,
    client_id: ClientId,
    counter: Counter,
    operation: &'a [u8],
    mac: Tag,
}

impl<'a> Signed<'a> {
    /// Sign `operation` for this header under `key`.
    ///
    /// The `client_id` is the enrolment acting, and P-084 requires it to be the
    /// one the session was bound to at `Hello` — this end knows which that is,
    /// and the far end checks.
    pub fn over(
        header: Header,
        client_id: ClientId,
        counter: Counter,
        operation: &'a [u8],
        key: &SessionKey,
    ) -> Result<Self, SignedError> {
        signs(header)?;
        within_cap(operation)?;
        let mac = key.signed_request(&SignedRequest {
            kind: header.kind,
            session: header.session,
            req_id: header.req_id,
            client_id: client_id.get(),
            counter: counter.0,
            operation,
        });
        Ok(Self {
            header,
            client_id,
            counter,
            operation,
            mac,
        })
    }

    /// The tag, for a caller assembling a frame some other way. Checking one is
    /// [`SignedClaim::verify`].
    #[must_use]
    pub const fn mac(&self) -> &Tag {
        &self.mac
    }

    /// Write the whole envelope — the three scalars and the four keys — and hand
    /// back its length.
    pub fn write(&self, dst: &mut [u8]) -> Result<usize, SignedError> {
        let mut cbor = self.header.write(SignedKey::COUNT, dst).map_err(short)?;
        cbor.key(SignedKey::ClientId.number()).map_err(short)?;
        cbor.u64(u64::from(self.client_id.get())).map_err(short)?;
        cbor.key(SignedKey::Counter.number()).map_err(short)?;
        cbor.u64(self.counter.0).map_err(short)?;
        cbor.key(SignedKey::Operation.number()).map_err(short)?;
        cbor.bytes(self.operation).map_err(short)?;
        cbor.key(SignedKey::Mac.number()).map_err(short)?;
        cbor.bytes(self.mac.as_bytes()).map_err(short)?;
        cbor.finish().map_err(short)
    }
}

/// Lengths, never the operation — the argument `wrapper.rs` makes about a
/// derived `Debug` being an accessor spelled `{:?}`.
impl fmt::Debug for Signed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signed {{ header: {:?}, client_id: {}, operation: {} bytes }}",
            self.header,
            self.client_id.get(),
            self.operation.len()
        )
    }
}

/// A signed request as it arrived, with a tag nobody has checked.
///
/// Nothing here is reachable: unlike `Hello`, the key does not come from inside
/// the body — the `session_id` on the envelope selects it — so there is no
/// reason for a single field to be readable before the MAC is. P-080 step 1
/// written as a type:
///
/// ```
/// use km43::FreshWrite;
/// fn act<'a>(it: &FreshWrite<'a>) -> &'a [u8] { it.operation() }
/// ```
/// ```compile_fail
/// use km43::SignedClaim;
/// fn act<'a>(it: &SignedClaim<'a>) -> &'a [u8] { it.operation() }
/// ```
/// ```
/// use km43::{Counter, SignedWrite};
/// fn seen(it: &SignedWrite<'_>) -> Counter { it.counter() }
/// ```
/// ```compile_fail
/// use km43::{Counter, SignedClaim};
/// fn seen(it: &SignedClaim<'_>) -> Counter { it.counter() }
/// ```
pub struct SignedClaim<'a> {
    header: Header,
    client_id: ClientId,
    counter: Counter,
    operation: &'a [u8],
    mac: &'a [u8],
}

impl<'a> SignedClaim<'a> {
    /// Read one out of an envelope naming one of P-053's four types.
    ///
    /// A key this version does not know is skipped (P-013): refusing would mean
    /// a v2 client cannot write to a v1 controller, and the rule that makes
    /// skipping safe is the one P-013 states for the other two bodies whose MAC
    /// covers fields — a later key MUST enter the preimage.
    pub fn decode(envelope: Envelope<'a>) -> Result<Self, SignedError> {
        let header = envelope.header();
        signs(header)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut slots = Slots::empty();
        for _ in 0..pairs {
            let number = body.key()?;
            match SignedKey::of(number) {
                Some(key) => slots.fill(key, &mut body)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        slots.complete(header)
    }

    /// The three scalars the preimage covers, which on a verified claim are the
    /// ones that were signed.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// Check the tag (P-080 step 1), then the identity (P-084) — in that order,
    /// and before any caller has read a counter row.
    ///
    /// `bound` is the `client_id` the session was bound to at `Hello`. Key 1 is
    /// on the wire only because it is inside the preimage; the counter row is
    /// selected by the session, never by the body.
    pub fn verify(self, key: &SessionKey, bound: ClientId) -> Result<SignedWrite<'a>, SignedError> {
        let expect = key.signed_request(&SignedRequest {
            kind: self.header.kind,
            session: self.header.session,
            req_id: self.header.req_id,
            client_id: self.client_id.get(),
            counter: self.counter.0,
            operation: self.operation,
        });
        expect.verify(self.mac).map_err(SignedError::Mac)?;
        if self.client_id != bound {
            return Err(SignedError::WrongClient {
                bound,
                body: self.client_id,
            });
        }
        Ok(SignedWrite {
            header: self.header,
            counter: self.counter,
            operation: self.operation,
            state: PhantomData,
        })
    }
}

/// Names and lengths, never the operation nobody has authenticated.
impl fmt::Debug for SignedClaim<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedClaim {{ unverified, header: {:?}, operation: {} bytes }}",
            self.header,
            self.operation.len()
        )
    }
}

/// A write whose MAC checked out and whose `client_id` is the session's.
///
/// Still not the operation: P-080 step 2 has not run, so this frame may be a
/// replay of one that already executed.
///
/// ```
/// use km43::FreshWrite;
/// fn act<'a>(it: &FreshWrite<'a>) -> &'a [u8] { it.operation() }
/// ```
/// ```compile_fail
/// use km43::SignedWrite;
/// fn act<'a>(it: &SignedWrite<'a>) -> &'a [u8] { it.operation() }
/// ```
pub struct SignedWrite<'a> {
    header: Header,
    counter: Counter,
    operation: &'a [u8],
    state: PhantomData<&'a ()>,
}

impl<'a> SignedWrite<'a> {
    /// The three scalars, now that the tag over them has been checked.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The counter this frame carries. Readable here because P-084 has passed,
    /// which is what says which row `last` must come from.
    #[must_use]
    pub const fn counter(&self) -> Counter {
        self.counter
    }

    /// P-080 step 2. `last` is the highest counter already accepted **for the
    /// client this session is bound to** — the row P-084 selected, never one
    /// looked up by the body's key 1.
    pub fn fresh(self, last: Counter) -> Result<FreshWrite<'a>, SignedError> {
        if !self.counter.is_ahead_of(last) {
            return Err(SignedError::StaleCounter {
                last,
                sent: self.counter,
            });
        }
        Ok(FreshWrite {
            header: self.header,
            counter: self.counter,
            operation: self.operation,
        })
    }
}

impl fmt::Debug for SignedWrite<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedWrite {{ header: {:?}, counter: {}, operation: {} bytes }}",
            self.header,
            self.counter,
            self.operation.len()
        )
    }
}

/// A write that is authentic, from the right client, and ahead of everything
/// this client has sent before. The operation is reachable and not before.
///
/// What is left is P-080 steps 3 to 6, and none of it belongs to the wire: the
/// dedup table, the FRAM transaction that persists the counter *before* the
/// operation runs, and the execution itself. This crate holds no store and no
/// clock, so it stops here — but it stops with a type whose name is the thing
/// the caller has proved rather than a tuple it could have assembled.
pub struct FreshWrite<'a> {
    header: Header,
    counter: Counter,
    operation: &'a [u8],
}

impl<'a> FreshWrite<'a> {
    /// The three scalars.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The counter to persist, in the same transaction as the dedup entry and
    /// before the operation runs (P-079, P-080 step 4).
    #[must_use]
    pub const fn counter(&self) -> Counter {
        self.counter
    }

    /// The operation body, exactly as it arrived (P-048) and only now.
    #[must_use]
    pub const fn operation(&self) -> &'a [u8] {
        self.operation
    }
}

impl fmt::Debug for FreshWrite<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FreshWrite {{ header: {:?}, counter: {}, operation: {} bytes }}",
            self.header,
            self.counter,
            self.operation.len()
        )
    }
}

/// Every failure writing a frame is one buffer being too small, whatever layer
/// noticed. One variant rather than a `CborError` a caller has to read twice:
/// a short buffer of ours is not *your frame was garbled*.
///
/// Genuinely free — it takes an error it discards and belongs to no state.
fn short<E>(_why: E) -> SignedError {
    SignedError::TooLargeToWrite
}

/// P-083, in the one place both directions go through.
fn within_cap(operation: &[u8]) -> Result<(), SignedError> {
    if operation.len() > MAX_OPERATION {
        return Err(SignedError::OperationTooLong(operation.len()));
    }
    Ok(())
}

/// What has arrived of a signed body so far.
struct Slots<'a> {
    client_id: Option<u32>,
    counter: Option<u64>,
    operation: Option<&'a [u8]>,
    mac: Option<&'a [u8]>,
}

impl<'a> Slots<'a> {
    const fn empty() -> Self {
        Self {
            client_id: None,
            counter: None,
            operation: None,
            mac: None,
        }
    }

    /// Refuses a key that has already arrived (P-015) before either copy is
    /// used: RFC 8949 §5.6 leaves a repeated key to the decoder, and two
    /// libraries picking differently sign different bytes.
    fn fill(&mut self, key: SignedKey, body: &mut CborReader<'a>) -> Result<(), SignedError> {
        match key {
            SignedKey::ClientId => Self::once(&mut self.client_id, key, body.u32()?),
            SignedKey::Counter => Self::once(&mut self.counter, key, body.u64()?),
            SignedKey::Operation => Self::once(&mut self.operation, key, body.bytes()?),
            SignedKey::Mac => Self::once(&mut self.mac, key, body.bytes()?),
        }
    }

    fn once<T>(slot: &mut Option<T>, key: SignedKey, value: T) -> Result<(), SignedError> {
        if slot.is_some() {
            return Err(SignedError::Duplicate(key));
        }
        *slot = Some(value);
        Ok(())
    }

    fn complete(self, header: Header) -> Result<SignedClaim<'a>, SignedError> {
        let raw = self
            .client_id
            .ok_or(SignedError::Missing(SignedKey::ClientId))?;
        let client_id = ClientId::new(raw).ok_or(SignedError::ClientZero)?;
        let counter = Counter(
            self.counter
                .ok_or(SignedError::Missing(SignedKey::Counter))?,
        );
        let operation = self
            .operation
            .ok_or(SignedError::Missing(SignedKey::Operation))?;
        within_cap(operation)?;
        let mac = self.mac.ok_or(SignedError::Missing(SignedKey::Mac))?;
        if mac.len() != Tag::LEN {
            return Err(SignedError::WrongWidth {
                key: SignedKey::Mac,
                len: mac.len(),
            });
        }
        Ok(SignedClaim {
            header,
            client_id,
            counter,
            operation,
            mac,
        })
    }
}

/// Why a signed request was refused. Four of these carry a code of their own,
/// which is the whole point: a client told "malformed frame" about a stale
/// counter retries the same bytes until it gives up, and P-081 says the cure is
/// to re-read `Hello 0x81` key 11 instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedError {
    /// A required key never arrived (P-015).
    Missing(SignedKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(SignedKey),
    /// A `type` P-053 does not sign. Refused rather than signed under a guess,
    /// which would let a `Time` be sent as a `Command`.
    NotSigned(MessageType),
    /// Key 1 is zero, which P-086 makes *no client* rather than an enrolment.
    ClientZero,
    /// An `operation` past `MAX_OPERATION` (P-083). The body that signs it also
    /// has to fit the payload.
    OperationTooLong(usize),
    /// A key whose byte string is the wrong width — a MAC that is not sixteen.
    WrongWidth {
        /// Which key.
        key: SignedKey,
        /// What arrived.
        len: usize,
    },
    /// The tag did not check out (P-080 step 1).
    Mac(MacError),
    /// Key 1 is not the enrolment this session was bound to at `Hello` (P-084),
    /// refused before a counter row is read or written.
    WrongClient {
        /// What the session was bound to.
        bound: ClientId,
        /// What the body claimed.
        body: ClientId,
    },
    /// A counter that does not exceed the stored one (P-080 step 2) — a replay,
    /// or a client that incremented a value it had already had refused.
    StaleCounter {
        /// The highest already accepted for this client.
        last: Counter,
        /// What arrived.
        sent: Counter,
    },
    /// The frame did not fit the buffer it was being written into. Ours, not the
    /// peer's.
    TooLargeToWrite,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for SignedError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl SignedError {
    /// What to answer. The three that are not error 1 are the three P-080 and
    /// P-084 name by number, and a client acts on each of them differently.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Mac(_) => Refusal::Client(ErrorCode::BadMAC),
            Self::StaleCounter { .. } => Refusal::Client(ErrorCode::CounterNotFresh),
            Self::WrongClient { .. } | Self::ClientZero => {
                Refusal::Client(ErrorCode::UnknownClient)
            }
            Self::TooLargeToWrite | Self::OperationTooLong(_) => {
                Refusal::Client(ErrorCode::PayloadTooLarge)
            }
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::NotSigned(_)
            | Self::WrongWidth { .. }
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for SignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "signed request carries no {key}"),
            Self::Duplicate(key) => write!(f, "signed request carries {key} twice"),
            Self::NotSigned(kind) => write!(
                f,
                "message type {:#04x} is not one of the four that sign",
                *kind as u8
            ),
            Self::ClientZero => {
                f.write_str("signed request claims client_id 0, which is no client")
            }
            Self::OperationTooLong(len) => {
                write!(
                    f,
                    "operation of {len} bytes is past the {MAX_OPERATION} cap"
                )
            }
            Self::WrongWidth { key, len } => {
                write!(f, "{key} arrived {len} bytes wide")
            }
            Self::Mac(why) => write!(f, "{why}"),
            Self::WrongClient { bound, body } => write!(
                f,
                "session is bound to client {} and the body claims {}",
                bound.get(),
                body.get()
            ),
            Self::StaleCounter { last, sent } => {
                write!(f, "counter {sent} does not exceed the accepted {last}")
            }
            Self::TooLargeToWrite => {
                f.write_str("the frame does not fit the buffer it is written into")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for SignedError {}

const_assert!(
    SignedKey::COUNT == 4,
    "the four keys P-053 defines. A fifth would be meaningful and outside the preimage, which is the rule PROTOCOL.md states for the two other bodies whose MAC covers fields rather than an encoding"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ReqId, SessionId};
    use crate::limits::{ENVELOPE_BYTES, MAX_OPERATION_CEILING, MAX_PAYLOAD, SIGNED_BODY_BYTES};
    use crate::render::Rendering;

    /// Wider than any fixture here, narrow enough that a length bug shows as a
    /// refusal rather than as a fixture that happened to fit.
    const SCRATCH: usize = 256;

    const OURS: [u8; 32] = [0x5a; 32];
    const THEIRS: [u8; 32] = [0xa5; 32];

    /// A `Time 0x0A` operation — `{1: 1700000000000, 2: 1}` — rather than
    /// filler, because the operation is opaque to this layer and a fixture that
    /// looked like filler would hide it if it ever stopped being.
    const OPERATION: [u8; 12] = [
        0xa2, 0x01, 0x1b, 0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00, 0x01,
    ];

    fn key(bytes: [u8; 32]) -> SessionKey {
        SessionKey::new(bytes)
    }

    fn client() -> ClientId {
        ClientId::new(7).expect("a real enrolment")
    }

    fn other_client() -> ClientId {
        ClientId::new(9).expect("a real enrolment")
    }

    fn header(kind: MessageType) -> Header {
        Header {
            kind,
            session: SessionId::from(3),
            req_id: ReqId(17),
        }
    }

    fn time() -> Header {
        header(MessageType::Time)
    }

    /// A whole signed `Time 0x0A` frame as a client builds one.
    fn written(head: Header, counter: u64, k: &SessionKey) -> ([u8; SCRATCH], usize) {
        let mut dst = [0u8; SCRATCH];
        let len = Signed::over(head, client(), Counter(counter), &OPERATION, k)
            .expect("the fixture signs")
            .write(&mut dst)
            .expect("the fixture fits the scratch");
        (dst, len)
    }

    /// A frame carrying an operation the caller chose.
    fn written_with(
        head: Header,
        counter: u64,
        operation: &[u8],
        k: &SessionKey,
    ) -> ([u8; SCRATCH], usize) {
        let mut dst = [0u8; SCRATCH];
        let len = Signed::over(head, client(), Counter(counter), operation, k)
            .expect("the fixture signs")
            .write(&mut dst)
            .expect("the fixture fits the scratch");
        (dst, len)
    }

    /// The claim inside a frame this module wrote.
    fn claimed(frame: &[u8; SCRATCH], len: usize) -> SignedClaim<'_> {
        let bytes = frame.get(..len).expect("the writer's own length");
        SignedClaim::decode(Envelope::decode(bytes).expect("it decodes")).expect("the body decodes")
    }

    /// Everything past the tag: decode, verify under `k` as `bound`, and check
    /// the counter against `last`.
    fn walked(
        bytes: &[u8],
        k: &SessionKey,
        bound: ClientId,
        last: u64,
    ) -> Result<Counter, SignedError> {
        let envelope = Envelope::decode(bytes).expect("the fixture's envelope decodes");
        let fresh = SignedClaim::decode(envelope)?
            .verify(k, bound)?
            .fresh(Counter(last))?;
        assert_eq!(fresh.operation(), &OPERATION[..]);
        Ok(fresh.counter())
    }

    /// One body assembled by hand, because half the fixtures below are bodies
    /// `CborWriter` refuses to write: a duplicate key, a key out of order, a MAC
    /// of the wrong width.
    struct Wire {
        bytes: [u8; SCRATCH],
        len: usize,
    }

    impl Wire {
        /// `[0x0A, 3, 17, {` with the type inline, which is what every signed
        /// type is — `0x07` to `0x0A` are all below the CBOR inline ceiling.
        fn envelope(head: Header, pairs: u8) -> Self {
            // The header's own scalars, not a pair of literals. Written with
            // literals first, which made the relabelling fixture below build the
            // frame it was supposed to be moving — a fixture that ignores its
            // argument is a test comparing a thing to itself.
            let session = u8::try_from(u16::from(head.session)).expect("a one-byte session");
            let req_id = u8::try_from(head.req_id.0).expect("a one-byte req_id");
            assert!(session < 24 && req_id < 24 && pairs < 24, "one-byte CBOR");
            let mut wire = Self {
                bytes: [0; SCRATCH],
                len: 0,
            };
            wire.push(&[0x84, head.kind as u8, session, req_id, 0xa0 | pairs]);
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

        fn raw(mut self, data: &[u8]) -> Self {
            self.push(data);
            self
        }

        /// A key carrying a byte string under twenty-four bytes.
        fn bstr(mut self, key: u8, value: &[u8]) -> Self {
            let len = u8::try_from(value.len()).expect("a string under twenty-four bytes");
            assert!(len < 24, "the fixture strings are all short form");
            self.push(&[key, 0x40 | len]);
            self.push(value);
            self
        }

        fn bytes(&self) -> &[u8] {
            self.bytes
                .get(..self.len)
                .expect("the length came from the builder")
        }

        fn claimed(&self) -> Result<SignedClaim<'_>, SignedError> {
            let envelope = Envelope::decode(self.bytes()).expect("the fixture's envelope decodes");
            SignedClaim::decode(envelope)
        }
    }

    /// The list and the numbers live in three places apiece — `of`, `number` and
    /// `name` — and a transposed pair reads perfectly in all three.
    #[test]
    fn every_key_number_maps_back_to_the_key_that_claims_it() {
        for n in 1..=SignedKey::COUNT {
            let number = i64::try_from(n).expect("a small key number");
            let key = SignedKey::of(number).expect("every number below COUNT is a key");
            assert_eq!(key.number(), number);
        }
        assert!(SignedKey::of(0).is_none());
        assert!(SignedKey::of(-1).is_none());
        assert!(SignedKey::of(i64::try_from(SignedKey::COUNT + 1).expect("small")).is_none());
    }

    /// The path this module exists for: a write leaves a client and arrives at a
    /// controller meaning the same thing, with the operation reachable only past
    /// both of P-080's checks.
    #[test]
    fn a_signed_write_arrives_saying_what_the_client_signed() {
        let k = key(OURS);
        let (dst, len) = written(time(), 0x42, &k);
        let bytes = dst.get(..len).expect("the writer's own length");
        assert_eq!(
            walked(bytes, &k, client(), 0x41),
            Ok(Counter(0x42)),
            "a counter one ahead of the stored value is fresh"
        );
    }

    /// P-080 step 2, and the failure it stops is the one the counter exists for:
    /// a relay that captured a `Time` write and sends it again an hour later.
    #[test]
    fn a_captured_write_sent_again_is_refused_on_its_counter() {
        let k = key(OURS);
        let (dst, len) = written(time(), 0x42, &k);
        let bytes = dst.get(..len).expect("the writer's own length");

        // Accepted once.
        assert!(walked(bytes, &k, client(), 0x41).is_ok());

        // The same frame, against a store that has now recorded it. Equal is a
        // replay, not a retry — P-082 says a retry carries a new counter.
        assert_eq!(
            walked(bytes, &k, client(), 0x42),
            Err(SignedError::StaleCounter {
                last: Counter(0x42),
                sent: Counter(0x42),
            })
        );
        assert_eq!(
            walked(bytes, &k, client(), 0xFF),
            Err(SignedError::StaleCounter {
                last: Counter(0xFF),
                sent: Counter(0x42),
            })
        );
    }

    /// P-084, and the half that matters is *where* it fails. A write claiming
    /// another enrolment is refused by `verify`, which never took a `last` —
    /// so the counter row was not read, which is what the rule says in words and
    /// what the two-step type says in code.
    #[test]
    fn a_write_claiming_another_enrolment_is_refused_before_a_counter_is_read() {
        let k = key(OURS);
        let (dst, len) = written(time(), 0x42, &k);
        let bytes = dst.get(..len).expect("the writer's own length");
        let envelope = Envelope::decode(bytes).expect("it decodes");
        let claim = SignedClaim::decode(envelope).expect("the body decodes");

        let refused = claim.verify(&k, other_client());
        assert!(matches!(
            refused,
            Err(SignedError::WrongClient { bound, body })
                if bound == other_client() && body == client()
        ));
        assert_eq!(
            SignedError::WrongClient {
                bound: other_client(),
                body: client(),
            }
            .refusal()
            .code(),
            12,
            "P-084 names error 12"
        );
    }

    /// P-080 step 1 comes first, so a forged frame costs a MAC and never a FRAM
    /// read. Under the wrong key the identity check is not even reached.
    #[test]
    fn a_forged_write_fails_its_mac_before_anything_looks_at_who_sent_it() {
        let (dst, len) = written(time(), 0x42, &key(OURS));
        let bytes = dst.get(..len).expect("the writer's own length");

        // Wrong key *and* a bound client that would also have failed P-084. The
        // MAC error is the one that comes back, which is the ordering.
        assert!(matches!(
            walked(bytes, &key(THEIRS), other_client(), 0),
            Err(SignedError::Mac(_))
        ));
    }

    /// P-046 and P-047 spend six bytes on the type and the `req_id` for this:
    /// a relay that relabels a signed `Time` as a signed `Command`, or moves it
    /// onto another request, produces a tag that no longer checks out.
    #[test]
    fn a_write_relabelled_by_the_relay_no_longer_verifies() {
        let k = key(OURS);
        let signed =
            Signed::over(time(), client(), Counter(0x42), &OPERATION, &k).expect("a Time signs");

        for moved in [
            Header {
                kind: MessageType::Command,
                ..time()
            },
            Header {
                req_id: ReqId(18),
                ..time()
            },
            Header {
                session: SessionId::from(4),
                ..time()
            },
        ] {
            // The captured body and tag, lifted into another envelope — the
            // frame a relay can build for free.
            let wire = Wire::envelope(moved, 4)
                .raw(&[0x01, 0x07, 0x02, 0x18, 0x42, 0x03, 0x4c])
                .raw(&OPERATION)
                .bstr(0x04, signed.mac().as_bytes());
            let claim = wire.claimed().expect("the body still decodes");
            assert!(
                matches!(claim.verify(&k, client()), Err(SignedError::Mac(_))),
                "{moved:?}"
            );
        }
    }

    /// The counter is inside the preimage, so a relay cannot bump it to make a
    /// captured frame fresh again — which is the whole reason it is a signed
    /// field rather than an envelope one.
    #[test]
    fn a_counter_a_relay_edited_no_longer_verifies() {
        let k = key(OURS);
        let signed =
            Signed::over(time(), client(), Counter(0x42), &OPERATION, &k).expect("it signs");
        let wire = Wire::envelope(time(), 4)
            .raw(&[0x01, 0x07, 0x02, 0x18, 0x43, 0x03, 0x4c])
            .raw(&OPERATION)
            .bstr(0x04, signed.mac().as_bytes());
        assert!(matches!(
            wire.claimed().expect("it decodes").verify(&k, client()),
            Err(SignedError::Mac(_))
        ));
    }

    /// The twenty-eight types P-053 does not sign, refused before a tag exists
    /// rather than signed under a guess. The read-only requests and every
    /// response are the wrapper's (P-052), `Hello` and `Pair` prove themselves
    /// from inside (P-057), and `Discover` has no key at all (P-054).
    #[test]
    fn a_message_type_that_does_not_sign_cannot_be_signed_by_this_body() {
        let k = key(OURS);
        for kind in [
            MessageType::Discover,
            MessageType::DiscoverResponse,
            MessageType::Hello,
            MessageType::HelloResponse,
            MessageType::Inventory,
            MessageType::InventoryResponse,
            MessageType::Readings,
            MessageType::ReadingsResponse,
            MessageType::Concerns,
            MessageType::ConcernsResponse,
            MessageType::History,
            MessageType::HistoryResponse,
            MessageType::Subscribe,
            MessageType::SubscribeResponse,
            MessageType::EventResponse,
            MessageType::ReadLog,
            MessageType::ReadLogResponse,
            MessageType::GetConfig,
            MessageType::GetConfigResponse,
            MessageType::SetConfigResponse,
            MessageType::CommandResponse,
            MessageType::FirmwareResponse,
            MessageType::TimeResponse,
            MessageType::Pair,
            MessageType::PairResponse,
            MessageType::Goodbye,
            MessageType::GoodbyeResponse,
            MessageType::ErrorResponse,
        ] {
            assert_eq!(
                Signed::over(header(kind), client(), Counter(1), &OPERATION, &k).map(|_| ()),
                Err(SignedError::NotSigned(kind)),
                "{kind:?} signed"
            );
        }

        // And the four that do.
        for kind in [
            MessageType::SetConfig,
            MessageType::Command,
            MessageType::Firmware,
            MessageType::Time,
        ] {
            assert!(
                Signed::over(header(kind), client(), Counter(1), &OPERATION, &k).is_ok(),
                "{kind:?} refused"
            );
        }
    }

    /// P-083. An operation that fills the payload leaves nothing for the body
    /// that signs it, so the refusal has to land before the frame is built.
    ///
    /// **Both ends.** This test checked only the sender until the cap was
    /// deleted from the decoder on purpose and it stayed green — a name claiming
    /// two halves over one, which is the defect this repo keeps finding in its
    /// own checks. The far end is the one that matters: our sender is not the
    /// one a hostile peer controls.
    #[test]
    fn an_operation_past_the_cap_is_refused_at_both_ends() {
        let k = key(OURS);
        let over = [0xA5u8; MAX_OPERATION + 1];
        assert_eq!(
            Signed::over(time(), client(), Counter(1), &over, &k).map(|_| ()),
            Err(SignedError::OperationTooLong(MAX_OPERATION + 1))
        );

        let at_the_cap = [0xA5u8; MAX_OPERATION];
        assert!(Signed::over(time(), client(), Counter(1), &at_the_cap, &k).is_ok());

        // A body whose only fault is its size, built here because `Signed::over`
        // refuses to make one — which is exactly why the decoder cannot lean on
        // the encoder for this.
        let mut dst = [0u8; MAX_PAYLOAD + 128];
        let mut cbor = time()
            .write(SignedKey::COUNT, &mut dst)
            .expect("the head fits");
        cbor.key(SignedKey::ClientId.number()).expect("key 1");
        cbor.u64(u64::from(client().get())).expect("client_id");
        cbor.key(SignedKey::Counter.number()).expect("key 2");
        cbor.u64(1).expect("counter");
        cbor.key(SignedKey::Operation.number()).expect("key 3");
        cbor.bytes(&over).expect("an operation past the cap");
        cbor.key(SignedKey::Mac.number()).expect("key 4");
        cbor.bytes(&[0u8; 16]).expect("a tag");
        let len = cbor.finish().expect("the fixture fits");

        let envelope =
            Envelope::decode(dst.get(..len).expect("the writer's own length")).expect("it decodes");
        assert_eq!(
            SignedClaim::decode(envelope).map(|_| ()),
            Err(SignedError::OperationTooLong(MAX_OPERATION + 1)),
            "the decoder took an operation the sender would not build"
        );
    }

    /// P-013. A v2 client that adds a key must reach a v1 controller as a write,
    /// not as error 1 — the alternative is a client that cannot set the clock at
    /// a controller nobody has driven out to update.
    #[test]
    fn a_key_this_version_does_not_know_is_skipped() {
        let k = key(OURS);
        let signed =
            Signed::over(time(), client(), Counter(0x42), &OPERATION, &k).expect("it signs");
        let wire = Wire::envelope(time(), 5)
            .raw(&[0x01, 0x07, 0x02, 0x18, 0x42, 0x03, 0x4c])
            .raw(&OPERATION)
            .bstr(0x04, signed.mac().as_bytes())
            .raw(&[0x09, 0x18, 0x63]);
        let fresh = wire
            .claimed()
            .expect("a newer peer's key is skipped")
            .verify(&k, client())
            .expect("the tag still checks out")
            .fresh(Counter(0x41))
            .expect("the counter is ahead");
        assert_eq!(fresh.operation(), &OPERATION[..]);
    }

    /// P-015. Two libraries that resolve a repeated key differently sign
    /// different bytes out of one frame.
    #[test]
    fn a_key_that_arrives_twice_is_refused_before_either_copy_is_used() {
        let wire = Wire::envelope(time(), 5)
            .raw(&[0x01, 0x07])
            .raw(&[0x01, 0x08])
            .raw(&[0x02, 0x18, 0x42, 0x03, 0x4c])
            .raw(&OPERATION)
            .bstr(0x04, &[0u8; 16]);
        assert_eq!(
            wire.claimed().map(|_| ()),
            Err(SignedError::Duplicate(SignedKey::ClientId))
        );
    }

    /// A required key that never arrived is error 1, and the refusal names which
    /// one — a bench log that says "a key is missing" sends somebody through
    /// four candidates.
    #[test]
    fn a_body_missing_a_required_key_says_which_one() {
        let cases = [
            (
                Wire::envelope(time(), 3)
                    .raw(&[0x02, 0x18, 0x42, 0x03, 0x4c])
                    .raw(&OPERATION)
                    .bstr(0x04, &[0u8; 16]),
                SignedKey::ClientId,
            ),
            (
                Wire::envelope(time(), 3)
                    .raw(&[0x01, 0x07, 0x03, 0x4c])
                    .raw(&OPERATION)
                    .bstr(0x04, &[0u8; 16]),
                SignedKey::Counter,
            ),
            (
                Wire::envelope(time(), 3)
                    .raw(&[0x01, 0x07, 0x02, 0x18, 0x42])
                    .bstr(0x04, &[0u8; 16]),
                SignedKey::Operation,
            ),
            (
                Wire::envelope(time(), 3)
                    .raw(&[0x01, 0x07, 0x02, 0x18, 0x42, 0x03, 0x4c])
                    .raw(&OPERATION),
                SignedKey::Mac,
            ),
        ];
        for (wire, missing) in cases {
            assert_eq!(
                wire.claimed().map(|_| ()),
                Err(SignedError::Missing(missing)),
                "{missing}"
            );
        }
    }

    /// A tag of the wrong width is refused on its width rather than compared,
    /// because a comparison that returns early on length is a comparison whose
    /// timing says how much of it matched.
    #[test]
    fn a_mac_that_is_not_sixteen_bytes_is_refused_on_its_width() {
        for len in [0usize, 8, 15, 17, 20] {
            let mac = [0xA5u8; 20];
            let wire = Wire::envelope(time(), 4)
                .raw(&[0x01, 0x07, 0x02, 0x18, 0x42, 0x03, 0x4c])
                .raw(&OPERATION)
                .bstr(0x04, mac.get(..len).expect("a prefix of the fixture"));
            assert_eq!(
                wire.claimed().map(|_| ()),
                Err(SignedError::WrongWidth {
                    key: SignedKey::Mac,
                    len,
                }),
                "a mac of {len} bytes"
            );
        }
    }

    /// P-086 makes 0 *no client*, so a body claiming it is not an enrolment with
    /// an unusual number — it is a frame that names nobody, and error 12 is what
    /// says so.
    #[test]
    fn a_client_id_of_zero_is_no_client_rather_than_a_client_numbered_zero() {
        let wire = Wire::envelope(time(), 4)
            .raw(&[0x01, 0x00, 0x02, 0x18, 0x42, 0x03, 0x4c])
            .raw(&OPERATION)
            .bstr(0x04, &[0u8; 16]);
        assert_eq!(wire.claimed().map(|_| ()), Err(SignedError::ClientZero));
        assert_eq!(SignedError::ClientZero.refusal().code(), 12);
    }

    /// P-081's livelock, reached through the helper meant to prevent it. A
    /// saturating increment hands back a counter that does not exceed the stored
    /// one, so the client is refused, re-`Hello`s, reads key 11, sends the same
    /// number and is refused again — forever, with nothing to point at.
    #[test]
    fn a_counter_at_the_ceiling_has_no_next_rather_than_repeating_itself() {
        assert_eq!(Counter(41).next(), Some(Counter(42)));
        assert_eq!(Counter(u64::MAX - 1).next(), Some(Counter(u64::MAX)));
        assert_eq!(Counter(u64::MAX).next(), None);

        // And the value a saturating version would have produced is one this
        // module refuses, which is why `None` is the honest answer.
        assert!(!Counter(u64::MAX).is_ahead_of(Counter(u64::MAX)));
        assert!(Counter(u64::MAX).is_ahead_of(Counter(u64::MAX - 1)));
    }

    /// Every prefix of a legal frame, because a link that dropped mid-frame must
    /// never leave a shorter signed request that still decodes.
    #[test]
    fn every_truncation_of_a_signed_request_is_refused() {
        let k = key(OURS);
        let (dst, len) = written(time(), 0x42, &k);
        for cut in 0..len {
            let short = dst.get(..cut).expect("a prefix of the frame");
            let refused = Envelope::decode(short)
                .map_err(|_| ())
                .and_then(|e| SignedClaim::decode(e).map_err(|_| ()));
            assert!(refused.is_err(), "decoded {cut} of {len} bytes");
        }
    }

    /// A byte after the body is a second message, or a body somebody edited.
    /// `finish()` catches it, and deleting the call leaves every other test here
    /// green.
    #[test]
    fn a_byte_appended_after_a_signed_request_is_refused() {
        let k = key(OURS);
        let (mut dst, len) = written(time(), 0x42, &k);
        let slot = dst
            .get_mut(len)
            .expect("the scratch is wider than the frame");
        *slot = 0x00;
        let envelope =
            Envelope::decode(dst.get(..=len).expect("one byte more")).expect("it still decodes");
        assert_eq!(
            SignedClaim::decode(envelope).map(|_| ()),
            Err(SignedError::Cbor(CborError::TrailingBytes))
        );
    }

    /// The three codes P-080 and P-084 name by number, and the rest. A client
    /// told "malformed frame" about a stale counter retries the same bytes; one
    /// told error 11 re-reads `Hello 0x81` key 11, which is P-081's cure.
    #[test]
    fn every_refusal_is_answered_with_the_code_its_rule_names() {
        let cases = [
            (SignedError::Mac(MacError::Mismatch), 10u16),
            (
                SignedError::StaleCounter {
                    last: Counter(9),
                    sent: Counter(9),
                },
                11,
            ),
            (
                SignedError::WrongClient {
                    bound: client(),
                    body: other_client(),
                },
                12,
            ),
            (SignedError::ClientZero, 12),
            (SignedError::OperationTooLong(1000), 5),
            (SignedError::TooLargeToWrite, 5),
            (SignedError::Missing(SignedKey::Mac), 1),
            (SignedError::Duplicate(SignedKey::Counter), 1),
            (SignedError::NotSigned(MessageType::Hello), 1),
            (
                SignedError::WrongWidth {
                    key: SignedKey::Mac,
                    len: 12,
                },
                1,
            ),
            (SignedError::Cbor(CborError::WrongType), 1),
        ];
        for (why, code) in cases {
            assert_eq!(why.refusal().code(), code, "{why}");
        }
    }

    /// Every refusal renders as its own sentence. The pair somebody will be
    /// telling apart at a bench is "the key was wrong" and "the counter was
    /// behind", and two that share a line send them to the wrong half.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        let every = [
            SignedError::Missing(SignedKey::ClientId),
            SignedError::Duplicate(SignedKey::Counter),
            SignedError::NotSigned(MessageType::Hello),
            SignedError::ClientZero,
            SignedError::OperationTooLong(1000),
            SignedError::WrongWidth {
                key: SignedKey::Mac,
                len: 12,
            },
            SignedError::Mac(MacError::Mismatch),
            SignedError::WrongClient {
                bound: client(),
                body: other_client(),
            },
            SignedError::StaleCounter {
                last: Counter(9),
                sent: Counter(8),
            },
            SignedError::TooLargeToWrite,
            SignedError::Cbor(CborError::WrongType),
        ];
        Rendering::<112>::each_says_something_of_its_own(&every);
    }

    /// A body on its way out and one that arrived both say lengths and no more.
    /// The operation is the thing a signed request exists to carry, and one
    /// `tracing::debug!(?claim)` would put an unauthenticated one in a log a
    /// person reads.
    #[test]
    fn no_stage_hands_its_operation_to_a_formatter() {
        let k = key(OURS);
        let other = [0x5Au8; OPERATION.len()];

        let ours = Rendering::<200>::debugged(
            &Signed::over(time(), client(), Counter(1), &OPERATION, &k).expect("it signs"),
        );
        let theirs = Rendering::<200>::debugged(
            &Signed::over(time(), client(), Counter(1), &other, &k).expect("it signs"),
        );
        assert_eq!(ours.bytes(), theirs.bytes(), "Signed carries operation");

        // Two claims whose operations differ. `contains("unverified")` and
        // `contains("bytes")` were the whole of this half, and both survive a
        // `Debug` that prints the operation — a check that could not go red on
        // the leak it names.
        let mine = written_with(time(), 1, &OPERATION, &k);
        let yours = written_with(time(), 1, &other, &k);
        let ours = Rendering::<200>::debugged(&claimed(&mine.0, mine.1));
        let theirs = Rendering::<200>::debugged(&claimed(&yours.0, yours.1));
        assert_eq!(
            ours.bytes(),
            theirs.bytes(),
            "two operations rendered differently, so SignedClaim carries operation"
        );
        let text = core::str::from_utf8(ours.bytes()).expect("a rendering is UTF-8");
        assert!(text.contains("unverified"), "{text}");
    }

    /// A destination too small is refused rather than written short: a sender
    /// that reports the bytes it managed puts half a frame on a link and a tag
    /// over a body nobody will see.
    #[test]
    fn a_destination_too_small_is_refused_rather_than_written_short() {
        let k = key(OURS);
        let signed = Signed::over(time(), client(), Counter(1), &OPERATION, &k).expect("it signs");
        let mut full = [0u8; SCRATCH];
        let len = signed.write(&mut full).expect("the frame fits the scratch");

        for short in 0..len {
            let mut dst = [0u8; SCRATCH];
            let room = dst.get_mut(..short).expect("a prefix of the scratch");
            assert_eq!(
                signed.write(room),
                Err(SignedError::TooLargeToWrite),
                "wrote a frame of {len} into {short} bytes"
            );
        }
        let mut exact = [0u8; SCRATCH];
        let room = exact.get_mut(..len).expect("a prefix of the scratch");
        assert_eq!(signed.write(room), Ok(len));
    }

    /// The widest signed request there is, measured rather than counted.
    ///
    /// `limits.rs` derives `MAX_OPERATION` from the body around it, and that
    /// derivation was a hand count: 39 bytes, from a tally that included the
    /// body's map header twice — `ENVELOPE_BYTES` already carries it — under a
    /// comment that enumerated 35. Nothing measured it against the encoder that
    /// produces the body, which is the one thing that cannot be off by one.
    #[test]
    fn the_widest_signed_request_is_the_width_limits_derives() {
        let k = key(OURS);
        let operation = [0xA5u8; MAX_OPERATION];
        let widest = Header {
            kind: MessageType::Time,
            session: SessionId::from(u16::MAX),
            req_id: ReqId(u32::MAX),
        };
        let mut dst = [0u8; MAX_PAYLOAD];
        let len = Signed::over(
            widest,
            ClientId::new(u32::MAX).expect("the top of the space"),
            Counter(u64::MAX),
            &operation,
            &k,
        )
        .expect("an operation at the cap signs")
        .write(&mut dst)
        .expect("the widest signed request must fit a payload");

        assert_eq!(
            len,
            MAX_OPERATION + SIGNED_BODY_BYTES + ENVELOPE_BYTES,
            "the encoder and the derivation in limits.rs have parted company"
        );
        assert_eq!(len, 1009, "the number limits.rs states");
        assert!(len <= MAX_PAYLOAD);

        // And an operation at the ceiling is the last one that frames at all,
        // which is what makes the fifteen bytes below it a margin rather than
        // an accident.
        let ceiling = [0xA5u8; MAX_OPERATION_CEILING];
        let full = Signed::over(
            widest,
            ClientId::new(u32::MAX).expect("the top of the space"),
            Counter(u64::MAX),
            &ceiling,
            &k,
        );
        assert!(
            matches!(full, Err(SignedError::OperationTooLong(_))),
            "the cap refuses it, which is why the ceiling is a ceiling and not the cap"
        );
        assert_eq!(
            MAX_OPERATION_CEILING + SIGNED_BODY_BYTES + ENVELOPE_BYTES,
            MAX_PAYLOAD,
            "the ceiling is exactly what a payload holds"
        );
    }
}
