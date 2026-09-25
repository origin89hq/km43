//! The four writes, whose inner body is the operation itself, sealed like every
//! request (P-053). Nothing is wrapped around it: the session is the only
//! statement of who sent it, and P-022's window is what refuses it twice.
//!
//! A [`SignedWrite`] comes only out of an [`Opened`] body, so the operation is
//! never in reach before its tag verified, and only for a type on the signed
//! list, so a sealed `GetConfig` cannot be handed to a write handler.
//!
//! cites: P-048, P-053, P-083, P-110

use core::fmt;

use crate::envelope::{Header, Refusal, ReqId, SessionId};
use crate::generated::{ErrorCode, MessageType};
use crate::limits::MAX_OPERATION;
use crate::sealed::{Opened, RequestSealer, SealError};

/// The seven types P-053 signs, read off the `type` rather than passed in, so a
/// `Time` cannot be sent as a `Command` nor a `Remove` as an `Approve`.
const fn signs(kind: MessageType) -> bool {
    match kind {
        MessageType::SetConfig
        | MessageType::Command
        | MessageType::Firmware
        | MessageType::Time
        | MessageType::Invite
        | MessageType::Approve
        | MessageType::Remove => true,
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
        | MessageType::Vouch
        | MessageType::VouchResponse
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
        | MessageType::Clients
        | MessageType::ClientsResponse
        | MessageType::InviteResponse
        | MessageType::ApproveResponse
        | MessageType::RemoveResponse
        | MessageType::ErrorResponse => false,
    }
}

/// A write ready to seal.
pub struct Signed<'a> {
    kind: MessageType,
    operation: &'a [u8],
}

impl<'a> Signed<'a> {
    /// A write of `kind` carrying `operation`, the encoded operation body.
    pub fn new(kind: MessageType, operation: &'a [u8]) -> Result<Self, SignedError> {
        if !signs(kind) {
            return Err(SignedError::NotSigned(kind));
        }
        within_cap(operation)?;
        Ok(Self { kind, operation })
    }

    /// Seal the operation under the session's next `req_id` and write the whole
    /// envelope into `dst`.
    pub fn seal(
        &self,
        tx: &mut RequestSealer,
        session: SessionId,
        dst: &mut [u8],
    ) -> Result<(ReqId, usize), SignedError> {
        Ok(tx.seal(self.kind, session, self.operation, dst)?)
    }
}

/// Lengths, never the operation.
impl fmt::Debug for Signed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signed {{ kind: {:?}, operation: {} bytes }}",
            self.kind,
            self.operation.len()
        )
    }
}

/// A write that opened under the session's key. It is made only out of an
/// [`Opened`] body, so there is no way to read one out of bytes whose tag
/// nobody checked:
///
/// ```
/// fn act<'a>(it: &km43::SignedWrite<'a>) -> &'a [u8] { it.operation() }
/// ```
/// ```compile_fail
/// fn raw(bytes: &[u8]) -> km43::SignedWrite<'_> { km43::SignedWrite::read_bytes(bytes) }
/// ```
pub struct SignedWrite<'a> {
    header: Header,
    operation: &'a [u8],
}

impl<'a> SignedWrite<'a> {
    /// The write out of a sealed request that opened (P-080 step 1).
    pub fn read(opened: &Opened<'a>) -> Result<Self, SignedError> {
        let header = opened.header();
        if !signs(header.kind) {
            return Err(SignedError::NotSigned(header.kind));
        }
        let operation = opened.inner();
        within_cap(operation)?;
        Ok(Self { header, operation })
    }

    /// The three scalars, which the tag covered.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The operation body exactly as it was sealed, which is what P-120
    /// hashes: re-encoding it first would make a retry miss its own entry.
    #[must_use]
    pub const fn operation(&self) -> &'a [u8] {
        self.operation
    }
}

/// Names and lengths, never the operation.
impl fmt::Debug for SignedWrite<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignedWrite {{ header: {:?}, operation: {} bytes }}",
            self.header,
            self.operation.len()
        )
    }
}

/// P-083, in the one place both directions go through.
fn within_cap(operation: &[u8]) -> Result<(), SignedError> {
    if operation.len() > MAX_OPERATION {
        return Err(SignedError::OperationTooLong(operation.len()));
    }
    Ok(())
}

/// Why a write was refused before its handler saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SignedError {
    /// A `type` P-053 does not sign.
    NotSigned(MessageType),
    /// An operation past `MAX_OPERATION` (P-083).
    OperationTooLong(usize),
    /// Sealing or opening it failed.
    Sealed(SealError),
}

impl From<SealError> for SignedError {
    fn from(why: SealError) -> Self {
        Self::Sealed(why)
    }
}

impl SignedError {
    /// What to answer. `None` where the sealed layer answers with silence
    /// (P-022, P-233): a replayed write is dropped, not refused, or a relay
    /// that replays one collects a second response to a request already
    /// answered.
    #[must_use]
    pub const fn refusal(self) -> Option<Refusal> {
        match self {
            Self::Sealed(why) => why.refusal(),
            Self::OperationTooLong(_) => Some(Refusal::Client(ErrorCode::PayloadTooLarge)),
            Self::NotSigned(_) => Some(Refusal::Client(ErrorCode::MalformedFrame)),
        }
    }
}

impl fmt::Display for SignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSigned(kind) => write!(
                f,
                "message type {:#04x} is not one of the four that sign",
                *kind as u8
            ),
            Self::OperationTooLong(len) => {
                write!(
                    f,
                    "operation of {len} bytes is past the {MAX_OPERATION} cap"
                )
            }
            Self::Sealed(why) => write!(f, "{why}"),
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

    /// A `Time 0x0A` operation — `{1: 1700000000000}` — rather than filler.
    const OPERATION: [u8; 11] = [
        0xa1, 0x01, 0x1b, 0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00,
    ];

    /// Seal `inner` as a `kind`, open it at the controller, and read the write
    /// out of it — the path every signed request takes.
    fn arrive(
        kind: MessageType,
        inner: &[u8],
        check: impl FnOnce(Result<SignedWrite<'_>, SignedError>),
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
        check(SignedWrite::read(&opened));
    }

    /// P-053 and P-080: a write goes out sealed like every request, and the
    /// operation that comes out of the tag is the one that went in, with
    /// nothing around it.
    #[test]
    fn p_080_a_write_opens_to_exactly_its_operation() {
        let (mut c, mut k) = channels([1; 32], [2; 32]);
        let mut frame = [0u8; MAX_PAYLOAD];
        let (_, len) = Signed::new(MessageType::Time, &OPERATION)
            .expect("Time signs")
            .seal(&mut c.tx, SessionId::from(3), &mut frame)
            .expect("seals");
        let mut plain = [0u8; MAX_PAYLOAD];
        let opened = Sealed::decode(Envelope::decode(&frame[..len]).expect("decodes"))
            .expect("sealed")
            .open(&mut k.rx, &mut plain)
            .expect("opens");
        let write = SignedWrite::read(&opened).expect("a write");
        assert_eq!(write.operation(), OPERATION);
        assert_eq!(write.header().kind, MessageType::Time);
    }

    /// P-022 and P-233: a relay that replays a write gets nothing back, and it
    /// never reaches the handler. A handler that lifts the sealed layer's error
    /// with `?` must not turn its silence into error 1, or the replay collects
    /// a second response.
    #[test]
    fn p_233_a_replayed_write_is_not_answered_through_signed_error() {
        let (mut c, mut k) = channels([1; 32], [2; 32]);
        let mut frame = [0u8; MAX_PAYLOAD];
        let (_, len) = Signed::new(MessageType::Time, &OPERATION)
            .expect("Time signs")
            .seal(&mut c.tx, SessionId::from(3), &mut frame)
            .expect("seals");
        let mut plain = [0u8; MAX_PAYLOAD];
        let mut open = |plain: &mut [u8]| -> Result<(), SignedError> {
            let envelope = Envelope::decode(&frame[..len]).expect("decodes");
            Sealed::decode(envelope)?.open(&mut k.rx, plain)?;
            Ok(())
        };
        open(&mut plain).expect("the first arrival opens");
        let replayed = open(&mut plain).expect_err("the replay is refused");
        assert_eq!(replayed, SignedError::Sealed(SealError::Replayed(1)));
        assert_eq!(replayed.refusal(), None);
    }

    /// P-083: an operation past the cap is refused at both ends, and the widest
    /// legal one still fits a payload under the widest session handle.
    #[test]
    fn p_083_an_operation_past_the_cap_is_refused_at_both_ends() {
        let long = [0xA5u8; MAX_OPERATION + 1];
        assert_eq!(
            Signed::new(MessageType::Time, &long).err(),
            Some(SignedError::OperationTooLong(MAX_OPERATION + 1))
        );
        let (mut c, _) = channels([1; 32], [2; 32]);
        let widest = [0xA5u8; MAX_OPERATION];
        let mut frame = [0u8; MAX_PAYLOAD];
        let (_, len) = Signed::new(MessageType::Command, &widest)
            .expect("the widest legal operation")
            .seal(&mut c.tx, SessionId::from(0xFFFF), &mut frame)
            .expect("fits a payload");
        assert!(len <= MAX_PAYLOAD);

        arrive(MessageType::Time, &long, |write| {
            let refused = write.err();
            assert_eq!(
                refused,
                Some(SignedError::OperationTooLong(MAX_OPERATION + 1))
            );
            assert_eq!(
                refused.and_then(SignedError::refusal),
                Some(Refusal::Client(ErrorCode::PayloadTooLarge))
            );
        });
    }

    /// P-053: only the four writes sign, and a type that does not is refused
    /// rather than signed under a guess, at either end.
    #[test]
    fn p_053_only_the_four_writes_sign() {
        for kind in [
            MessageType::SetConfig,
            MessageType::Command,
            MessageType::Firmware,
            MessageType::Time,
        ] {
            assert!(Signed::new(kind, &OPERATION).is_ok());
        }
        assert_eq!(
            Signed::new(MessageType::ReadLog, &OPERATION).err(),
            Some(SignedError::NotSigned(MessageType::ReadLog))
        );
        arrive(MessageType::GetConfig, &OPERATION, |write| {
            let refused = write.err();
            assert_eq!(
                refused,
                Some(SignedError::NotSigned(MessageType::GetConfig))
            );
            assert_eq!(
                refused.and_then(SignedError::refusal),
                Some(Refusal::Client(ErrorCode::MalformedFrame))
            );
        });
    }

    /// P-048: the operation is read out as exactly the bytes that were sealed,
    /// even an encoding this crate would not write, because the dedup table
    /// hashes those bytes and a re-encoding would make a retry miss its entry.
    #[test]
    fn p_048_the_operation_is_the_bytes_that_were_sealed() {
        let loose = [0xB8, 0x00];
        arrive(MessageType::SetConfig, &loose, |write| {
            assert_eq!(write.expect("reads").operation(), loose);
        });
    }

    /// An empty operation is still a write the handler has to refuse, not one
    /// this layer drops: whether `{}` means anything is the operation's
    /// decoder's question.
    #[test]
    fn an_empty_operation_reaches_the_handler() {
        arrive(MessageType::Time, &[], |write| {
            assert_eq!(write.expect("reads").operation(), [0u8; 0]);
        });
    }
}
