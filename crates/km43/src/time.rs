//! `Time 0x0A` / `TimeAck 0x8A` — the one write that changes what every later
//! log record claims about when it happened.
//!
//! [`TimeOperation`] is key 3 of a signed body, never a wrapper's payload: the
//! write is signed (P-110) and the MAC covers these bytes exactly as they
//! arrived, so `signed.rs` carries them and this file only reads them once
//! the tag has checked out.
//!
//! [`TimeAck`]'s `at` is an `Option` because a refused first set has no clock
//! to report, and a zero there reads as 1970 (P-093). The one outcome that
//! cannot omit it is `accepted`: the clock has just been set, so an accepted
//! answer without the time it was set to is a controller that moved the clock
//! and will not say where, and [`TimeAck::new`] refuses to build one.
//!
//! The operation carries no source. A signed write is always `client` in the
//! `time set` record (P-111), so key 2, which once said so, is retired and
//! skipped like any key this build does not know: a client that still sends
//! `ntp-via-comms` there cannot get its own write logged as NTP.
//!
//! cites: P-013, P-015, P-093, P-110

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{ErrorCode, Time};

/// `at` at full `u64` width: the map head, a one-byte key and nine bytes. A
/// destination this long always fits.
pub const MAX_TIME_OPERATION_BYTES: usize = 11;

/// A one-byte `outcome` and `at` at full `u64` width: the map head, two
/// one-byte keys, one byte and nine.
pub const MAX_TIME_ACK_BYTES: usize = 13;

/// The keys of the `Time 0x0A` operation body. Key 2 is retired (P-012) and
/// is not one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimeKey {
    /// Key 1, milliseconds since the epoch.
    At,
}

impl TimeKey {
    const COUNT: usize = 1;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::At),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::At => 1,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::At => "at",
        }
    }
}

impl fmt::Display for TimeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Time 0x0A {} (key {})", self.name(), self.number())
    }
}

/// The two keys of `TimeAck 0x8A`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimeAckKey {
    /// Key 1, from the registry's `Time` outcome space.
    Outcome,
    /// Key 2, the controller's clock after the write, omitted when it has
    /// never been set (P-093).
    At,
}

impl TimeAckKey {
    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Outcome),
            2 => Some(Self::At),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Outcome => 1,
            Self::At => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Outcome => "outcome",
            Self::At => "at",
        }
    }
}

impl fmt::Display for TimeAckKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TimeAck 0x8A {} (key {})", self.name(), self.number())
    }
}

/// A key of either body here, so one refusal can name either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimeBodyKey {
    /// A key of the `Time 0x0A` operation body.
    Operation(TimeKey),
    /// A key of `TimeAck 0x8A`.
    Ack(TimeAckKey),
}

impl From<TimeKey> for TimeBodyKey {
    fn from(key: TimeKey) -> Self {
        Self::Operation(key)
    }
}

impl From<TimeAckKey> for TimeBodyKey {
    fn from(key: TimeAckKey) -> Self {
        Self::Ack(key)
    }
}

impl fmt::Display for TimeBodyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(key) => key.fmt(f),
            Self::Ack(key) => key.fmt(f),
        }
    }
}

/// The operation a client signs to set the clock. `at` is required: a set with
/// no time is not a set. Who set it is not the client's to say; the `time set`
/// record names `client` because this message moved the clock (P-111).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimeOperation {
    /// Key 1, milliseconds since the epoch. Whether it is plausible is the
    /// controller's decision (P-113, P-114), not the decoder's.
    pub at: u64,
}

impl TimeOperation {
    /// Encode the operation body. The caller signs these bytes as key 3.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, TimeError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(TimeKey::COUNT)?;
        cbor.key(TimeKey::At.number())?;
        cbor.u64(self.at)?;
        Ok(cbor.finish()?)
    }

    /// Read the operation out of a signed body whose tag has already verified.
    pub fn decode(operation: &[u8]) -> Result<Self, TimeError> {
        let mut body = CborReader::new(operation);
        let pairs = body.map()?;
        let mut at = None;
        for _ in 0..pairs {
            match TimeKey::of(body.key()?) {
                Some(key @ TimeKey::At) => once(&mut at, key, body.u64()?)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            at: at.ok_or(TimeError::Missing(TimeKey::At.into()))?,
        })
    }
}

/// The controller's answer to a set. An error rather than an ack is what a set
/// that never reached the handler gets — the rate limit is error 7 (P-118) —
/// so every value here is a decision about the time itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TimeAck {
    outcome: Time,
    at: Option<u64>,
}

impl TimeAck {
    /// `at` is the clock after the write, and `None` only when it has never
    /// been set. An `accepted` outcome has just set it, so it refuses `None`.
    pub const fn new(outcome: Time, at: Option<u64>) -> Result<Self, TimeError> {
        match (outcome, at) {
            (Time::Accepted, None) => Err(TimeError::AcceptedWithoutClock),
            (Time::Accepted | Time::Rejected | Time::Unauthorised | Time::NeedsButton, _) => {
                Ok(Self { outcome, at })
            }
        }
    }

    /// Key 1.
    #[must_use]
    pub const fn outcome(self) -> Time {
        self.outcome
    }

    /// Key 2: the controller's clock after the write, `None` when it has never
    /// been set.
    #[must_use]
    pub const fn at(self) -> Option<u64> {
        self.at
    }

    /// Encode the ack body. The caller wraps and MACs it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, TimeError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(if self.at.is_some() { 2 } else { 1 })?;
        cbor.key(TimeAckKey::Outcome.number())?;
        cbor.u64(self.outcome as u64)?;
        if let Some(at) = self.at {
            cbor.key(TimeAckKey::At.number())?;
            cbor.u64(at)?;
        }
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &[u8]) -> Result<Self, TimeError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut outcome, mut at) = (None, None);
        for _ in 0..pairs {
            match TimeAckKey::of(body.key()?) {
                Some(key @ TimeAckKey::Outcome) => {
                    let number = body.u8()?;
                    let value =
                        Time::try_from(number).map_err(|()| TimeError::UnknownOutcome(number))?;
                    once(&mut outcome, key, value)?;
                }
                Some(key @ TimeAckKey::At) => once(&mut at, key, body.u64()?)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        let outcome = outcome.ok_or(TimeError::Missing(TimeAckKey::Outcome.into()))?;
        Self::new(outcome, at)
    }
}

fn once<T>(slot: &mut Option<T>, key: impl Into<TimeBodyKey>, value: T) -> Result<(), TimeError> {
    if slot.is_some() {
        return Err(TimeError::Duplicate(key.into()));
    }
    *slot = Some(value);
    Ok(())
}

/// Why a `Time` or `TimeAck` body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimeError {
    /// A required key never arrived (P-015).
    Missing(TimeBodyKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(TimeBodyKey),
    /// The `Time` outcome space does not allocate this value.
    UnknownOutcome(u8),
    /// Outcome 1 with no `at`: the clock moved and the answer does not say where.
    AcceptedWithoutClock,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for TimeError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl TimeError {
    /// What to answer. All of these are error 1: a body that does not say
    /// what time was asked for, or what became of it, has no knowable meaning.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::UnknownOutcome(_)
            | Self::AcceptedWithoutClock
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "clock body carries no {key}"),
            Self::Duplicate(key) => write!(f, "clock body carries {key} twice"),
            Self::UnknownOutcome(value) => write!(f, "unallocated TimeAck outcome {value}"),
            Self::AcceptedWithoutClock => {
                f.write_str("TimeAck accepted a set and carries no clock to say where it went")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for TimeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    /// One `at` at each CBOR width a `u64` can take, and the edges of the
    /// one-byte form.
    const OPERATIONS: [TimeOperation; 7] = [
        TimeOperation { at: 0 },
        TimeOperation { at: 23 },
        TimeOperation { at: 24 },
        TimeOperation { at: 0x1_0000 },
        TimeOperation { at: 0x1_0000_0000 },
        TimeOperation {
            at: 1_700_000_000_000,
        },
        TimeOperation { at: u64::MAX },
    ];

    const OUTCOMES: [Time; 4] = [
        Time::Accepted,
        Time::Rejected,
        Time::Unauthorised,
        Time::NeedsButton,
    ];

    /// Every ack the type admits at the widths that matter: absent, zero, and
    /// full width, for each outcome that may carry each.
    fn acks() -> impl Iterator<Item = TimeAck> {
        OUTCOMES.into_iter().flat_map(|outcome| {
            [None, Some(0), Some(1_700_000_000_000), Some(u64::MAX)]
                .into_iter()
                .filter_map(move |at| TimeAck::new(outcome, at).ok())
        })
    }

    fn encoded_operation(op: TimeOperation) -> ([u8; MAX_TIME_OPERATION_BYTES + 4], usize) {
        let mut dst = [0; MAX_TIME_OPERATION_BYTES + 4];
        let len = op.encode(&mut dst).expect("fits the declared cap");
        (dst, len)
    }

    fn encoded_ack(ack: TimeAck) -> ([u8; MAX_TIME_ACK_BYTES + 4], usize) {
        let mut dst = [0; MAX_TIME_ACK_BYTES + 4];
        let len = ack.encode(&mut dst).expect("fits the declared cap");
        (dst, len)
    }

    /// The cap is what a firmware sizes a stack buffer from. One byte short and
    /// the widest clock it will ever be told is a set it cannot build.
    #[test]
    fn the_widest_bodies_fill_their_caps_exactly_and_one_byte_less_refuses() {
        let mut widest = 0;
        for op in OPERATIONS {
            let (dst, len) = encoded_operation(op);
            widest = widest.max(len);
            assert_eq!(TimeOperation::decode(&dst[..len]), Ok(op));
            for cap in 0..len {
                let mut short = [0; MAX_TIME_OPERATION_BYTES];
                assert!(op.encode(&mut short[..cap]).is_err(), "accepted {cap}");
            }
        }
        assert_eq!(widest, MAX_TIME_OPERATION_BYTES);

        let mut widest = 0;
        for ack in acks() {
            let (dst, len) = encoded_ack(ack);
            widest = widest.max(len);
            assert_eq!(TimeAck::decode(&dst[..len]), Ok(ack));
            for cap in 0..len {
                let mut short = [0; MAX_TIME_ACK_BYTES];
                assert!(ack.encode(&mut short[..cap]).is_err(), "accepted {cap}");
            }
        }
        assert_eq!(widest, MAX_TIME_ACK_BYTES);
    }

    /// A resynchronising receiver hands the decoder whatever it has. Every cut
    /// of every body is refused rather than read short, and a byte past the
    /// end is refused rather than ignored.
    #[test]
    fn every_truncation_and_a_trailing_byte_is_refused() {
        for op in OPERATIONS {
            let (dst, len) = encoded_operation(op);
            for cut in 0..len {
                assert!(TimeOperation::decode(&dst[..cut]).is_err(), "cut {cut}");
            }
            assert_eq!(
                TimeOperation::decode(&dst[..=len]),
                Err(TimeError::Cbor(CborError::TrailingBytes))
            );
        }
        for ack in acks() {
            let (dst, len) = encoded_ack(ack);
            for cut in 0..len {
                assert!(TimeAck::decode(&dst[..cut]).is_err(), "cut {cut}");
            }
            assert_eq!(
                TimeAck::decode(&dst[..=len]),
                Err(TimeError::Cbor(CborError::TrailingBytes))
            );
        }
    }

    /// A refused first set has no clock to report. If absence decoded as 0 a
    /// client would show the controller's time as 1 January 1970, which is a
    /// plausible wrong measurement rather than an honest *unknown*.
    #[test]
    fn p_093_a_timeack_without_at_is_absent_and_never_zero() {
        let unset = TimeAck::decode(&[0xa1, 1, 2]).expect("rejected, never set");
        assert_eq!(unset.outcome(), Time::Rejected);
        assert_eq!(unset.at(), None);

        let zero = TimeAck::decode(&[0xa2, 1, 2, 2, 0]).expect("rejected at the epoch");
        assert_eq!(zero.at(), Some(0));
        assert_ne!(unset, zero);

        let (dst, len) = encoded_ack(unset);
        assert_eq!(&dst[..len], &[0xa1, 1, 2], "absent must not be written");
    }

    /// Outcome 1 says the clock moved. Without `at` it says so without saying
    /// where, and the client that set it cannot tell whether its own time was
    /// the one that landed.
    #[test]
    fn an_accepted_timeack_without_at_is_refused_both_ways() {
        assert_eq!(
            TimeAck::new(Time::Accepted, None),
            Err(TimeError::AcceptedWithoutClock)
        );
        assert_eq!(
            TimeAck::decode(&[0xa1, 1, 1]),
            Err(TimeError::AcceptedWithoutClock)
        );
        for outcome in [Time::Rejected, Time::Unauthorised, Time::NeedsButton] {
            assert!(TimeAck::new(outcome, None).is_ok(), "{outcome:?}");
        }
    }

    #[test]
    fn p_015_missing_and_repeated_keys_are_refused() {
        for (bytes, want) in [
            (&[0xa0][..], TimeError::Missing(TimeKey::At.into())),
            (&[0xa1, 2, 1][..], TimeError::Missing(TimeKey::At.into())),
            (
                &[0xa2, 1, 0, 1, 0][..],
                TimeError::Duplicate(TimeKey::At.into()),
            ),
        ] {
            assert_eq!(TimeOperation::decode(bytes), Err(want), "{bytes:02x?}");
        }
        for (bytes, want) in [
            (&[0xa0][..], TimeError::Missing(TimeAckKey::Outcome.into())),
            (
                &[0xa1, 2, 0][..],
                TimeError::Missing(TimeAckKey::Outcome.into()),
            ),
            (
                &[0xa2, 1, 2, 1, 2][..],
                TimeError::Duplicate(TimeAckKey::Outcome.into()),
            ),
            (
                &[0xa3, 1, 1, 2, 0, 2, 0][..],
                TimeError::Duplicate(TimeAckKey::At.into()),
            ),
        ] {
            assert_eq!(TimeAck::decode(bytes), Err(want), "{bytes:02x?}");
        }
    }

    /// A number the registry never allocated is a sender this build cannot
    /// understand, not an outcome to guess at. Zero is the value a sender that
    /// forgot to set the field writes.
    #[test]
    fn unallocated_outcomes_are_refused() {
        for number in [0u8, 5, 23] {
            assert_eq!(
                TimeAck::decode(&[0xa1, 1, number]),
                Err(TimeError::UnknownOutcome(number))
            );
        }
        assert!(TimeAck::decode(&[0xa1, 1, 0x19, 1, 1]).is_err());
    }

    /// Key 2 once carried a `source`, and a client that sent `2` there could
    /// have had its own signed write logged as NTP from the comms processor,
    /// the inversion P-111 exists to prevent. It is retired: whatever a sender
    /// still puts there, allocated, unallocated or the wrong type, is skipped,
    /// and the operation that comes out has nothing in it to name who set the
    /// clock. This is the codec's half only; the `time set` record P-111 asks
    /// for has no handler producing it yet, so nothing here claims P-111.
    #[test]
    fn a_retired_source_key_is_skipped_and_never_written() {
        for bytes in [
            &[0xa2, 1, 5, 2, 2][..],
            &[0xa2, 2, 2, 1, 5],
            &[0xa2, 1, 5, 2, 1],
            &[0xa2, 1, 5, 2, 0],
            &[0xa2, 1, 5, 2, 0xf5],
            &[0xa2, 1, 5, 2, 0x19, 1, 1],
        ] {
            assert_eq!(
                TimeOperation::decode(bytes),
                Ok(TimeOperation { at: 5 }),
                "{bytes:02x?}"
            );
        }
        assert_eq!(
            TimeOperation::decode(&[0xa1, 2, 2]),
            Err(TimeError::Missing(TimeKey::At.into())),
            "the retired key does not stand in for `at`"
        );

        let (dst, len) = encoded_operation(TimeOperation { at: 5 });
        assert_eq!(&dst[..len], &[0xa1, 1, 5], "key 2 is never written");
    }

    /// The wrong CBOR type under a known key is refused rather than coerced: a
    /// negative time or a boolean outcome is not a value either body has.
    #[test]
    fn a_known_key_of_the_wrong_type_is_refused() {
        for bytes in [
            &[0xa1, 1, 0x20][..],
            &[0xa1, 1, 0xf6],
            &[0xa1, 1, 0xf5],
            &[0x81, 1],
        ] {
            assert!(TimeOperation::decode(bytes).is_err(), "{bytes:02x?}");
        }
        for bytes in [&[0xa1, 1, 0xf5][..], &[0xa2, 1, 2, 2, 0x20], &[0x81, 1]] {
            assert!(TimeAck::decode(bytes).is_err(), "{bytes:02x?}");
        }
    }

    /// A v2 sender adds a key; a v1 reader skips it (P-013) and keeps the ones
    /// it knows, whether the stranger comes first or last.
    #[test]
    fn p_013_unknown_keys_are_skipped_before_and_after_the_known_ones() {
        for op in OPERATIONS {
            let (mut dst, len) = encoded_operation(op);
            dst[0] += 1;
            dst[len..len + 4].copy_from_slice(&[0x18, 99, 0x81, 0]);
            assert_eq!(TimeOperation::decode(&dst[..len + 4]), Ok(op));
        }
        assert_eq!(
            TimeOperation::decode(&[0xa2, 3, 0x61, b'x', 1, 5]),
            Ok(TimeOperation { at: 5 })
        );
        for ack in acks() {
            let (mut dst, len) = encoded_ack(ack);
            dst[0] += 1;
            dst[len..len + 4].copy_from_slice(&[0x18, 99, 0x81, 0]);
            assert_eq!(TimeAck::decode(&dst[..len + 4]), Ok(ack));
        }
    }

    #[test]
    fn refusals_render_and_map_to_malformed_frame() {
        let errors = [
            TimeError::Missing(TimeKey::At.into()),
            TimeError::Missing(TimeAckKey::At.into()),
            TimeError::Duplicate(TimeKey::At.into()),
            TimeError::Duplicate(TimeAckKey::Outcome.into()),
            TimeError::UnknownOutcome(0),
            TimeError::AcceptedWithoutClock,
            TimeError::Cbor(CborError::WrongType),
        ];
        Rendering::<100>::each_says_something_of_its_own(&errors);
        for error in errors {
            assert_eq!(error.refusal(), Refusal::Client(ErrorCode::MalformedFrame));
        }
    }
}
