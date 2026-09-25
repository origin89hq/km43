//! `{1: client_id, 2: counter, 3: operation}` — the inner body every write
//! wears, sealed like every request, and the checks P-080 puts in an order that
//! is not negotiable.
//!
//! Configuration, firmware, time and commands all carry the client's counter,
//! so the controller knows the order of a client's writes and refuses one it
//! has already applied (P-053).
//!
//! P-080 says open the sealed body, *then* check the identity, *then* the
//! counter. Written as a rule that is an ordering somebody obeys on the path
//! they were thinking about; written as the types below it is the only order
//! that compiles. A [`SignedClaim`] comes only out of an [`Opened`] body, so
//! its tag has been checked; it gives up nothing until [`SignedClaim::bind`]
//! has checked P-084; and the operation stays out of reach until
//! [`SignedWrite::fresh`] has checked the counter.
//!
//! cites: P-053, P-080, P-083, P-084, P-110

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::{Header, Refusal, ReqId, SessionId};
use crate::generated::{ErrorCode, MessageType};
use crate::kdf::ClientId;
use crate::limits::{MAX_OPERATION, SIGNED_BODY_BYTES};
use crate::sealed::{Opened, RequestSealer, SealError};

/// The counter that orders a client's writes.
///
/// Per slot (P-081); a single device-wide counter livelocks the moment two
/// clients are active, because both read 100, both send 101, and one of them is
/// refused forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Counter(pub u64);

impl Counter {
    /// The next value to send, or `None` at the ceiling: a counter that does
    /// not *exceed* the stored one is refused forever, so there is no
    /// saturating repeat.
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

/// The three keys of a signed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SignedKey {
    /// Key 1. A second statement of the session's client — P-084 is emphatic
    /// that it is never the lookup key.
    ClientId,
    /// Key 2.
    Counter,
    /// Key 3, the operation body.
    Operation,
}

impl SignedKey {
    const COUNT: usize = 3;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ClientId),
            2 => Some(Self::Counter),
            3 => Some(Self::Operation),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ClientId => 1,
            Self::Counter => 2,
            Self::Operation => 3,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ClientId => "client_id",
            Self::Counter => "counter",
            Self::Operation => "operation",
        }
    }
}

impl fmt::Display for SignedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signed body {} (key {})", self.name(), self.number())
    }
}

/// The four types P-053 signs, read off the `type` rather than passed in, so a
/// `Time` cannot be sent as a `Command`.
const fn signs(kind: MessageType) -> bool {
    match kind {
        MessageType::SetConfig
        | MessageType::Command
        | MessageType::Firmware
        | MessageType::Time => true,
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
        | MessageType::WifiScan
        | MessageType::WifiScanResponse
        | MessageType::WifiStatus
        | MessageType::WifiStatusResponse
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
        | MessageType::Enrol
        | MessageType::EnrolResponse
        | MessageType::Goodbye
        | MessageType::GoodbyeResponse
        | MessageType::ErrorResponse => false,
    }
}

/// A signed body ready to send.
pub struct Signed<'a> {
    kind: MessageType,
    client_id: ClientId,
    counter: Counter,
    operation: &'a [u8],
}

impl<'a> Signed<'a> {
    /// A write of `kind` from `client_id` — the slot the session is bound to,
    /// which the far end checks (P-084).
    pub fn new(
        kind: MessageType,
        client_id: ClientId,
        counter: Counter,
        operation: &'a [u8],
    ) -> Result<Self, SignedError> {
        if !signs(kind) {
            return Err(SignedError::NotSigned(kind));
        }
        within_cap(operation)?;
        Ok(Self {
            kind,
            client_id,
            counter,
            operation,
        })
    }

    /// The inner body, before it is sealed.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, SignedError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(SignedKey::COUNT).map_err(short)?;
        cbor.key(SignedKey::ClientId.number()).map_err(short)?;
        cbor.u64(u64::from(self.client_id.get())).map_err(short)?;
        cbor.key(SignedKey::Counter.number()).map_err(short)?;
        cbor.u64(self.counter.0).map_err(short)?;
        cbor.key(SignedKey::Operation.number()).map_err(short)?;
        cbor.bytes(self.operation).map_err(short)?;
        cbor.finish().map_err(short)
    }

    /// Encode, seal under the session's next `req_id`, and write the whole
    /// envelope into `dst`.
    pub fn seal(
        &self,
        tx: &mut RequestSealer,
        session: SessionId,
        dst: &mut [u8],
    ) -> Result<(ReqId, usize), SignedError> {
        let mut inner = [0u8; MAX_OPERATION + SIGNED_BODY_BYTES];
        let len = self.encode(&mut inner)?;
        let inner = inner.get(..len).ok_or(SignedError::TooLargeToWrite)?;
        Ok(tx.seal(self.kind, session, inner, dst)?)
    }
}

/// Lengths, never the operation.
impl fmt::Debug for Signed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signed {{ kind: {:?}, client_id: {}, operation: {} bytes }}",
            self.kind,
            self.client_id.get(),
            self.operation.len()
        )
    }
}

/// A signed body that opened under the session's key, whose `client_id` has
/// not been checked against the session (P-084). Nothing in it is reachable
/// until it has:
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
///
/// And it is made only out of an [`Opened`] body, so there is no way to read
/// one out of bytes whose tag nobody checked:
///
/// ```compile_fail
/// fn raw(bytes: &[u8]) -> km43::SignedClaim<'_> { km43::SignedClaim::read_bytes(bytes) }
/// ```
pub struct SignedClaim<'a> {
    header: Header,
    client_id: ClientId,
    counter: Counter,
    operation: &'a [u8],
}

impl<'a> SignedClaim<'a> {
    /// Read the signed body out of a sealed request that opened (P-080 step 1).
    ///
    /// A key this version does not know is skipped (P-013): the whole body is
    /// sealed, so a later key is inside the tag by construction.
    pub fn read(opened: &Opened<'a>) -> Result<Self, SignedError> {
        let header = opened.header();
        if !signs(header.kind) {
            return Err(SignedError::NotSigned(header.kind));
        }
        let mut body = CborReader::new(opened.inner());
        let pairs = body.map()?;
        let (mut client_id, mut counter, mut operation) = (None, None, None);
        for _ in 0..pairs {
            let number = body.key()?;
            let Some(key) = SignedKey::of(number) else {
                body.skip()?;
                continue;
            };
            let duplicate = match key {
                SignedKey::ClientId => client_id.replace(body.u32()?).is_some(),
                SignedKey::Counter => counter.replace(body.u64()?).is_some(),
                SignedKey::Operation => operation.replace(body.bytes()?).is_some(),
            };
            if duplicate {
                return Err(SignedError::Duplicate(key));
            }
        }
        body.finish()?;
        let raw = client_id.ok_or(SignedError::Missing(SignedKey::ClientId))?;
        let operation = operation.ok_or(SignedError::Missing(SignedKey::Operation))?;
        within_cap(operation)?;
        Ok(Self {
            header,
            client_id: ClientId::new(raw).ok_or(SignedError::ClientZero)?,
            counter: Counter(counter.ok_or(SignedError::Missing(SignedKey::Counter))?),
            operation,
        })
    }

    /// The three scalars, which the tag covered.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// P-084: key 1 must be the slot the session was bound to at `Hello`,
    /// checked before any caller has read a counter row. The row is selected
    /// by the session, never by the body.
    pub fn bind(self, bound: ClientId) -> Result<SignedWrite<'a>, SignedError> {
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
        })
    }
}

/// Names and lengths, never the operation.
impl fmt::Debug for SignedClaim<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedClaim {{ unbound, header: {:?}, operation: {} bytes }}",
            self.header,
            self.operation.len()
        )
    }
}

/// A write whose `client_id` is the session's. Still not the operation: P-080
/// step 2 has not run, so this frame may be a write that already executed.
///
/// ```compile_fail
/// use km43::SignedWrite;
/// fn act<'a>(it: &SignedWrite<'a>) -> &'a [u8] { it.operation() }
/// ```
pub struct SignedWrite<'a> {
    header: Header,
    counter: Counter,
    operation: &'a [u8],
}

impl<'a> SignedWrite<'a> {
    /// The three scalars.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The counter this frame carries.
    #[must_use]
    pub const fn counter(&self) -> Counter {
        self.counter
    }

    /// P-080 step 2. `last` is the highest counter already accepted for the
    /// slot this session is bound to.
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
/// this client has sent before. P-080 steps 3 to 6 — the dedup table, the FRAM
/// transaction and the execution — belong to the controller.
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

    /// The counter to persist, with the dedup entry and before the operation
    /// runs (P-079, P-080 step 4).
    #[must_use]
    pub const fn counter(&self) -> Counter {
        self.counter
    }

    /// The operation body, exactly as it was sealed, and only now.
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

/// Every failure writing a frame is a buffer too small, whatever layer noticed.
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

/// Why a signed request was refused. Three carry a code of their own, and a
/// client acts on each differently: a stale counter means re-read
/// `HelloReport` key 11 (P-081), not retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SignedError {
    /// A required key never arrived (P-015).
    Missing(SignedKey),
    /// The same key twice (P-015).
    Duplicate(SignedKey),
    /// A `type` P-053 does not sign.
    NotSigned(MessageType),
    /// Key 1 is zero, which is *no client* (P-086).
    ClientZero,
    /// An `operation` past `MAX_OPERATION` (P-083).
    OperationTooLong(usize),
    /// Key 1 is not the slot this session was bound to (P-084).
    WrongClient {
        /// What the session was bound to.
        bound: ClientId,
        /// What the body claimed.
        body: ClientId,
    },
    /// A counter that does not exceed the stored one (P-080 step 2).
    StaleCounter {
        /// The highest already accepted for this client.
        last: Counter,
        /// What arrived.
        sent: Counter,
    },
    /// Sealing it failed.
    Sealed(SealError),
    /// The frame did not fit the buffer it was being written into.
    TooLargeToWrite,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for SignedError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<SealError> for SignedError {
    fn from(why: SealError) -> Self {
        Self::Sealed(why)
    }
}

impl SignedError {
    /// What to answer.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::StaleCounter { .. } => Refusal::Client(ErrorCode::CounterNotFresh),
            Self::WrongClient { .. } | Self::ClientZero => {
                Refusal::Client(ErrorCode::UnknownClient)
            }
            Self::TooLargeToWrite | Self::OperationTooLong(_) => {
                Refusal::Client(ErrorCode::PayloadTooLarge)
            }
            Self::Sealed(why) => match why.refusal() {
                Some(refusal) => refusal,
                None => Refusal::Client(ErrorCode::MalformedFrame),
            },
            Self::Missing(_) | Self::Duplicate(_) | Self::NotSigned(_) | Self::Cbor(_) => {
                Refusal::Client(ErrorCode::MalformedFrame)
            }
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
            Self::WrongClient { bound, body } => write!(
                f,
                "session is bound to client {} and the body claims {}",
                bound.get(),
                body.get()
            ),
            Self::StaleCounter { last, sent } => {
                write!(f, "counter {sent} does not exceed the accepted {last}")
            }
            Self::Sealed(why) => write!(f, "{why}"),
            Self::TooLargeToWrite => {
                f.write_str("the frame does not fit the buffer it is written into")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for SignedError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Envelope;
    use crate::limits::MAX_PAYLOAD;
    use crate::sealed::{Sealed, channels};

    /// A `Time 0x0A` operation — `{1: 1700000000000, 2: 1}` — rather than filler.
    const OPERATION: [u8; 12] = [
        0xa2, 0x01, 0x1b, 0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00, 0x01,
    ];

    fn client() -> ClientId {
        ClientId::new(7).expect("slot 7")
    }

    /// Seal a write with `inner` as its body, open it at the controller, and
    /// read the claim — the path every signed request takes.
    fn arrive(
        kind: MessageType,
        inner: &[u8],
        check: impl FnOnce(Result<SignedClaim<'_>, SignedError>),
    ) {
        let (mut c, mut k) = channels([1; 32], [2; 32]);
        let mut frame = [0u8; MAX_PAYLOAD];
        let (_, len) =
            c.tx.seal(kind, SessionId::from(3), inner, &mut frame)
                .expect("seals");
        let mut plain = [0u8; MAX_PAYLOAD];
        let opened = Sealed::decode(Envelope::decode(&frame[..len]).expect("decodes"))
            .expect("sealed")
            .open(&mut k.rx, &mut plain)
            .expect("opens");
        check(SignedClaim::read(&opened));
    }

    fn body(counter: u64, client_id: u32, operation: &[u8]) -> ([u8; 128], usize) {
        let mut out = [0u8; 128];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(3).expect("head");
        cbor.key(1).expect("k");
        cbor.u64(u64::from(client_id)).expect("v");
        cbor.key(2).expect("k");
        cbor.u64(counter).expect("v");
        cbor.key(3).expect("k");
        cbor.bytes(operation).expect("v");
        let len = cbor.finish().expect("done");
        (out, len)
    }

    /// P-053 and P-080: a signed write goes out sealed like every request and
    /// arrives with its operation only past the identity and the counter.
    #[test]
    fn p_080_a_write_arrives_past_the_identity_and_the_counter_in_that_order() {
        let (mut c, mut k) = channels([1; 32], [2; 32]);
        let mut frame = [0u8; MAX_PAYLOAD];
        Signed::new(MessageType::Time, client(), Counter(9), &OPERATION)
            .expect("Time signs")
            .seal(&mut c.tx, SessionId::from(3), &mut frame)
            .expect("seals");
        let len = frame.iter().rposition(|&b| b != 0).map_or(0, |at| at + 1);
        let mut plain = [0u8; MAX_PAYLOAD];
        let opened = Sealed::decode(Envelope::decode(&frame[..len]).expect("decodes"))
            .expect("sealed")
            .open(&mut k.rx, &mut plain)
            .expect("opens");
        let fresh = SignedClaim::read(&opened)
            .expect("a signed body")
            .bind(client())
            .expect("the session's slot")
            .fresh(Counter(8))
            .expect("9 is ahead of 8");
        assert_eq!(fresh.operation(), OPERATION);
        assert_eq!(fresh.counter(), Counter(9));
    }

    /// P-084: key 1 naming another slot is refused before any counter is read.
    #[test]
    fn p_084_a_write_claiming_another_slot_is_refused_before_the_counter() {
        let (inner, len) = body(9, 8, &OPERATION);
        arrive(MessageType::Time, &inner[..len], |claim| {
            let refused = claim.expect("reads").bind(client()).err();
            assert!(matches!(refused, Some(SignedError::WrongClient { .. })));
            assert_eq!(
                refused.map(SignedError::refusal),
                Some(Refusal::Client(ErrorCode::UnknownClient))
            );
        });
    }

    /// P-080 step 2: a counter that does not exceed the stored one is error 11.
    #[test]
    fn p_080_a_counter_that_does_not_exceed_the_stored_one_is_refused() {
        let (inner, len) = body(9, 7, &OPERATION);
        arrive(MessageType::Time, &inner[..len], |claim| {
            let refused = claim
                .expect("reads")
                .bind(client())
                .expect("bound")
                .fresh(Counter(9))
                .err();
            assert_eq!(
                refused,
                Some(SignedError::StaleCounter {
                    last: Counter(9),
                    sent: Counter(9)
                })
            );
            assert_eq!(
                refused.map(SignedError::refusal),
                Some(Refusal::Client(ErrorCode::CounterNotFresh))
            );
        });
    }

    /// P-083: an operation past the cap is refused at both ends, and the cap
    /// sits under the ceiling the sealed frame leaves.
    #[test]
    fn p_083_an_operation_past_the_cap_is_refused_at_both_ends() {
        let long = [0xA5u8; MAX_OPERATION + 1];
        assert_eq!(
            Signed::new(MessageType::Time, client(), Counter(1), &long).err(),
            Some(SignedError::OperationTooLong(MAX_OPERATION + 1))
        );
        let (mut c, _) = channels([1; 32], [2; 32]);
        let widest = [0xA5u8; MAX_OPERATION];
        let mut frame = [0u8; MAX_PAYLOAD];
        let (_, len) = Signed::new(MessageType::Command, client(), Counter(u64::MAX), &widest)
            .expect("the widest legal operation")
            .seal(&mut c.tx, SessionId::from(0xFFFF), &mut frame)
            .expect("fits a payload");
        assert!(len <= MAX_PAYLOAD);

        let mut out = [0u8; MAX_PAYLOAD];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(3).expect("head");
        cbor.key(1).expect("k");
        cbor.u64(7).expect("v");
        cbor.key(2).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(3).expect("k");
        cbor.bytes(&long).expect("v");
        let n = cbor.finish().expect("done");
        arrive(MessageType::Time, &out[..n], |claim| {
            assert_eq!(
                claim.err(),
                Some(SignedError::OperationTooLong(MAX_OPERATION + 1))
            );
        });
    }

    /// P-053: only the four writes sign, and a type that does not is refused
    /// rather than signed under a guess.
    #[test]
    fn p_053_only_the_four_writes_sign() {
        for kind in [
            MessageType::SetConfig,
            MessageType::Command,
            MessageType::Firmware,
            MessageType::Time,
        ] {
            assert!(Signed::new(kind, client(), Counter(1), &OPERATION).is_ok());
        }
        assert_eq!(
            Signed::new(MessageType::ReadLog, client(), Counter(1), &OPERATION).err(),
            Some(SignedError::NotSigned(MessageType::ReadLog))
        );
        let (inner, len) = body(1, 7, &OPERATION);
        arrive(MessageType::GetConfig, &inner[..len], |claim| {
            assert_eq!(
                claim.err(),
                Some(SignedError::NotSigned(MessageType::GetConfig))
            );
        });
    }

    /// P-048: the operation is carried as bytes inside the sealed body and read
    /// out as exactly those bytes, even an encoding this crate would not write.
    #[test]
    fn p_048_the_operation_is_the_bytes_that_were_sealed() {
        let loose = [0xB8, 0x00];
        let (inner, len) = body(1, 7, &loose);
        arrive(MessageType::SetConfig, &inner[..len], |claim| {
            let fresh = claim
                .expect("reads")
                .bind(client())
                .expect("bound")
                .fresh(Counter(0))
                .expect("fresh");
            assert_eq!(fresh.operation(), loose);
        });
    }

    /// A key this version does not know is skipped (P-013): the body is sealed
    /// whole, so it is inside the tag. A key twice and a missing one are refused.
    #[test]
    fn an_unknown_key_is_skipped_and_a_repeated_or_missing_one_refused() {
        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(4).expect("head");
        cbor.key(1).expect("k");
        cbor.u64(7).expect("v");
        cbor.key(2).expect("k");
        cbor.u64(1).expect("v");
        cbor.key(3).expect("k");
        cbor.bytes(&OPERATION).expect("v");
        cbor.key(9).expect("k");
        cbor.u64(0).expect("v");
        let len = cbor.finish().expect("done");
        arrive(MessageType::Time, &out[..len], |claim| {
            assert!(claim.is_ok());
        });

        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(2).expect("head");
        cbor.key(1).expect("k");
        cbor.u64(7).expect("v");
        cbor.key(3).expect("k");
        cbor.bytes(&OPERATION).expect("v");
        let len = cbor.finish().expect("done");
        arrive(MessageType::Time, &out[..len], |claim| {
            assert_eq!(claim.err(), Some(SignedError::Missing(SignedKey::Counter)));
        });

        let (inner, len) = body(1, 0, &OPERATION);
        arrive(MessageType::Time, &inner[..len], |claim| {
            assert_eq!(claim.err(), Some(SignedError::ClientZero));
        });
    }

    /// A counter at the ceiling has no next, rather than repeating itself.
    #[test]
    fn a_counter_at_the_ceiling_has_no_next() {
        assert_eq!(Counter(u64::MAX).next(), None);
        assert_eq!(Counter(1).next(), Some(Counter(2)));
        assert!(Counter(2).is_ahead_of(Counter(1)));
        assert!(!Counter(1).is_ahead_of(Counter(1)));
    }
}
