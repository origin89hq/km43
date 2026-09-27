//! Durable clock, comms recovery and log-integrity records. The kind selects
//! the body schema; the event envelope remains readable for unknown kinds.
//!
//! cites: P-215, L-116

use core::{fmt, num::NonZeroU32};

use crate::{
    CborError, CborReader, CborWriter, ErrorCode, EventKind, HeldDownReason, Refusal, TimeSource,
};

/// Two full-width timestamps and a source occupy at most 23 bytes. An encoder
/// refuses a smaller destination when the selected body does not fit.
pub const CONTROLLER_RECORD_MAX_BYTES: usize = 23;

/// Class A bodies produced by the clock, recovery ladder and stored-log reader.
/// Counts saturate at `u32::MAX`, which means at least that many (P-215).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ControllerRecord {
    /// Clock values in milliseconds since epoch, with absence distinct from zero.
    TimeSet {
        /// The previous clock, absent if it was unknown.
        old: Option<u64>,
        /// The clock after the accepted change.
        new: u64,
        /// The client-facing source, never the link-local NTP source number.
        source: TimeSource,
    },
    /// Failed stored records in one scan; no identifier from damaged bytes is trusted.
    RecordFailedCrc {
        /// At least one failed record, including repeated discoveries in later scans.
        count: NonZeroU32,
    },
    /// The ladder's first rung, reached by silence or backpressure.
    CommsLinkLost,
    /// A completed rail cycle counted in the ladder's rolling hour.
    CommsPowerCycled {
        /// Cycles in the preceding hour, including this one.
        count: NonZeroU32,
    },
    /// The recovery pause and the rail state actually chosen for it.
    CommsUnrecoverable {
        /// True for the board exception that leaves the rail on and uncycled.
        rail_on: bool,
    },
    /// A backpressure shed counted in the same rolling hour as the escalation.
    SessionsShed {
        /// Sessions shed in the preceding hour, including this one.
        count: NonZeroU32,
    },
    /// Non-frame bytes from one comms boot attempt, including a silent attempt.
    CommsBootNoise {
        /// Bytes before the first valid `LinkUp` or abandonment of the attempt.
        count: u32,
    },
    /// The one record a boot leaves when the controller declines to link (L-116).
    CommsHeldDown {
        /// Which of L-115's two conditions holds for the rest of the boot.
        reason: HeldDownReason,
    },
}

impl ControllerRecord {
    /// The registry kind to put beside this body in the event envelope.
    #[must_use]
    pub const fn kind(self) -> EventKind {
        match self {
            Self::TimeSet { .. } => EventKind::TIME_SET,
            Self::RecordFailedCrc { .. } => EventKind::RECORD_FAILED_CRC,
            Self::CommsLinkLost => EventKind::COMMS_LINK_LOST,
            Self::CommsPowerCycled { .. } => EventKind::COMMS_POWER_CYCLED,
            Self::CommsUnrecoverable { .. } => EventKind::COMMS_UNRECOVERABLE,
            Self::SessionsShed { .. } => EventKind::SESSIONS_SHED_FOR_BACKPRESSURE,
            Self::CommsBootNoise { .. } => EventKind::COMMS_BOOT_NOISE,
            Self::CommsHeldDown { .. } => EventKind::COMMS_HELD_DOWN,
        }
    }

    /// Encode only the body, for Event key 4 or a stored log entry.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ControllerRecordError> {
        let mut body = CborWriter::new(dst);
        match *self {
            Self::TimeSet { old, new, source } => {
                body.map(if old.is_some() { 3 } else { 2 })?;
                if let Some(old) = old {
                    body.key(1)?;
                    body.u64(old)?;
                }
                body.key(2)?;
                body.u64(new)?;
                body.key(3)?;
                body.u64(source as u64)?;
            }
            Self::CommsLinkLost => body.map(0)?,
            Self::RecordFailedCrc { count }
            | Self::CommsPowerCycled { count }
            | Self::SessionsShed { count } => {
                body.map(1)?;
                body.key(1)?;
                body.u64(u64::from(count.get()))?;
            }
            Self::CommsUnrecoverable { rail_on } => {
                body.map(1)?;
                body.key(1)?;
                body.bool(rail_on)?;
            }
            Self::CommsBootNoise { count } => {
                body.map(1)?;
                body.key(1)?;
                body.u64(u64::from(count))?;
            }
            Self::CommsHeldDown { reason } => {
                body.map(1)?;
                body.key(1)?;
                body.u64(reason as u64)?;
            }
        }
        Ok(body.finish()?)
    }

    /// Decode a known controller body, skipping extension keys and refusing
    /// missing, repeated or invalid known values. Other kinds remain opaque.
    pub fn decode(kind: EventKind, payload: &[u8]) -> Result<Self, ControllerRecordError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut old, mut new, mut source, mut count, mut rail_on, mut reason) =
            (None, None, None, None, None, None);
        for _ in 0..pairs {
            match (kind, body.key()?) {
                (EventKind::TIME_SET, 1) => once(&mut old, 1, body.u64()?)?,
                (EventKind::TIME_SET, 2) => once(&mut new, 2, body.u64()?)?,
                (EventKind::TIME_SET, 3) => {
                    let number = body.u8()?;
                    let value = TimeSource::try_from(number)
                        .map_err(|()| ControllerRecordError::UnknownSource(number))?;
                    once(&mut source, 3, value)?;
                }
                (EventKind::COMMS_UNRECOVERABLE, 1) => once(&mut rail_on, 1, body.bool()?)?,
                (EventKind::COMMS_HELD_DOWN, 1) => {
                    let number = body.u8()?;
                    let value = HeldDownReason::try_from(number)
                        .map_err(|()| ControllerRecordError::UnknownReason(number))?;
                    once(&mut reason, 1, value)?;
                }
                (
                    EventKind::RECORD_FAILED_CRC
                    | EventKind::COMMS_POWER_CYCLED
                    | EventKind::SESSIONS_SHED_FOR_BACKPRESSURE
                    | EventKind::COMMS_BOOT_NOISE,
                    1,
                ) => once(&mut count, 1, body.u32()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;
        match kind {
            EventKind::TIME_SET => Ok(Self::TimeSet {
                old,
                new: new.ok_or(ControllerRecordError::MissingKey(2))?,
                source: source.ok_or(ControllerRecordError::MissingKey(3))?,
            }),
            EventKind::COMMS_LINK_LOST => Ok(Self::CommsLinkLost),
            EventKind::COMMS_UNRECOVERABLE => Ok(Self::CommsUnrecoverable {
                rail_on: rail_on.ok_or(ControllerRecordError::MissingKey(1))?,
            }),
            EventKind::RECORD_FAILED_CRC => Ok(Self::RecordFailedCrc {
                count: nonzero(count)?,
            }),
            EventKind::COMMS_POWER_CYCLED => Ok(Self::CommsPowerCycled {
                count: nonzero(count)?,
            }),
            EventKind::SESSIONS_SHED_FOR_BACKPRESSURE => Ok(Self::SessionsShed {
                count: nonzero(count)?,
            }),
            EventKind::COMMS_BOOT_NOISE => Ok(Self::CommsBootNoise {
                count: count.ok_or(ControllerRecordError::MissingKey(1))?,
            }),
            EventKind::COMMS_HELD_DOWN => Ok(Self::CommsHeldDown {
                reason: reason.ok_or(ControllerRecordError::MissingKey(1))?,
            }),
            _ => Err(ControllerRecordError::UnknownKind(kind)),
        }
    }
}

fn once<T>(slot: &mut Option<T>, key: u8, value: T) -> Result<(), ControllerRecordError> {
    if slot.is_some() {
        return Err(ControllerRecordError::DuplicateKey(key));
    }
    *slot = Some(value);
    Ok(())
}

fn nonzero(count: Option<u32>) -> Result<NonZeroU32, ControllerRecordError> {
    NonZeroU32::new(count.ok_or(ControllerRecordError::MissingKey(1))?)
        .ok_or(ControllerRecordError::ZeroCount)
}

/// A refusal to interpret a controller event body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ControllerRecordError {
    /// The kind belongs to another codec or a newer registry.
    UnknownKind(EventKind),
    /// A required key never arrived.
    MissingKey(u8),
    /// A known key arrived twice.
    DuplicateKey(u8),
    /// The time-source space does not allocate this value.
    UnknownSource(u8),
    /// The held-down reason space does not allocate this value.
    UnknownReason(u8),
    /// An action record claimed that no action occurred.
    ZeroCount,
    /// The underlying CBOR or destination was invalid.
    Cbor(CborError),
}

impl From<CborError> for ControllerRecordError {
    fn from(value: CborError) -> Self {
        Self::Cbor(value)
    }
}

impl ControllerRecordError {
    /// These failures prevent interpretation of a known body. An unknown kind
    /// can still be carried by the event envelope under P-019.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::UnknownKind(_)
            | Self::MissingKey(_)
            | Self::DuplicateKey(_)
            | Self::UnknownSource(_)
            | Self::UnknownReason(_)
            | Self::ZeroCount
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for ControllerRecordError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind(kind) => write!(out, "no controller body schema for kind {}", kind.0),
            Self::MissingKey(key) => write!(out, "controller record missing key {key}"),
            Self::DuplicateKey(key) => write!(out, "controller record repeats key {key}"),
            Self::UnknownSource(value) => write!(out, "unallocated time source {value}"),
            Self::UnknownReason(value) => write!(out, "unallocated held-down reason {value}"),
            Self::ZeroCount => out.write_str("controller action record has a zero count"),
            Self::Cbor(why) => write!(out, "{why}"),
        }
    }
}

impl core::error::Error for ControllerRecordError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    fn records() -> [ControllerRecord; 14] {
        [
            ControllerRecord::TimeSet {
                old: None,
                new: 0,
                source: TimeSource::NtpViaComms,
            },
            ControllerRecord::TimeSet {
                old: Some(0),
                new: u64::MAX,
                source: TimeSource::Client,
            },
            ControllerRecord::TimeSet {
                old: Some(u64::MAX),
                new: 0,
                source: TimeSource::Client,
            },
            ControllerRecord::TimeSet {
                old: Some(u64::MAX),
                new: u64::MAX,
                source: TimeSource::Client,
            },
            ControllerRecord::RecordFailedCrc {
                count: NonZeroU32::MAX,
            },
            ControllerRecord::CommsLinkLost,
            ControllerRecord::CommsPowerCycled {
                count: NonZeroU32::MAX,
            },
            ControllerRecord::CommsUnrecoverable { rail_on: false },
            ControllerRecord::CommsUnrecoverable { rail_on: true },
            ControllerRecord::SessionsShed {
                count: NonZeroU32::MAX,
            },
            ControllerRecord::CommsBootNoise { count: 0 },
            ControllerRecord::CommsBootNoise { count: u32::MAX },
            ControllerRecord::CommsHeldDown {
                reason: HeldDownReason::NoDeviceId,
            },
            ControllerRecord::CommsHeldDown {
                reason: HeldDownReason::RevisionsSpent,
            },
        ]
    }

    #[test]
    fn p_215_absence_zero_and_full_width_values_survive() {
        let mut widest = 0;
        for record in records() {
            let mut dst = [0; CONTROLLER_RECORD_MAX_BYTES];
            let len = record.encode(&mut dst).expect("fits the declared cap");
            widest = widest.max(len);
            assert_eq!(
                ControllerRecord::decode(record.kind(), &dst[..len]),
                Ok(record)
            );
            for cap in 0..len {
                assert!(
                    record.encode(&mut dst[..cap]).is_err(),
                    "accepted destination {cap}"
                );
            }
        }
        assert_eq!(widest, CONTROLLER_RECORD_MAX_BYTES);
    }

    #[test]
    fn p_215_every_truncation_and_trailing_byte_is_refused() {
        for record in records() {
            let mut dst = [0; CONTROLLER_RECORD_MAX_BYTES + 1];
            let len = record.encode(&mut dst).expect("fits");
            for cut in 0..len {
                assert!(ControllerRecord::decode(record.kind(), &dst[..cut]).is_err());
            }
            assert_eq!(
                ControllerRecord::decode(record.kind(), &dst[..=len]),
                Err(ControllerRecordError::Cbor(CborError::TrailingBytes))
            );
        }
    }

    #[test]
    fn p_215_required_counts_refuse_absence_zero_duplicates_and_overflow() {
        for kind in [
            EventKind::RECORD_FAILED_CRC,
            EventKind::COMMS_POWER_CYCLED,
            EventKind::SESSIONS_SHED_FOR_BACKPRESSURE,
            EventKind::COMMS_BOOT_NOISE,
        ] {
            assert_eq!(
                ControllerRecord::decode(kind, &[0xa0]),
                Err(ControllerRecordError::MissingKey(1))
            );
            assert_eq!(
                ControllerRecord::decode(kind, &[0xa2, 1, 1, 1, 2]),
                Err(ControllerRecordError::DuplicateKey(1))
            );
            for invalid in [
                &[0xa1, 1, 0xf5][..],
                &[0xa1, 1, 0x20],
                &[0xa1, 1, 0x1b, 0, 0, 0, 1, 0, 0, 0, 0],
            ] {
                assert!(ControllerRecord::decode(kind, invalid).is_err());
            }
            let zero = ControllerRecord::decode(kind, &[0xa1, 1, 0]);
            if kind == EventKind::COMMS_BOOT_NOISE {
                assert_eq!(zero, Ok(ControllerRecord::CommsBootNoise { count: 0 }));
            } else {
                assert_eq!(zero, Err(ControllerRecordError::ZeroCount));
            }
        }
    }

    #[test]
    fn p_215_time_requires_new_and_source_and_never_defaults_old() {
        let kind = EventKind::TIME_SET;
        for (bytes, error) in [
            (&[0xa1, 3, 1][..], ControllerRecordError::MissingKey(2)),
            (&[0xa1, 2, 0][..], ControllerRecordError::MissingKey(3)),
            (
                &[0xa2, 2, 0, 3, 0][..],
                ControllerRecordError::UnknownSource(0),
            ),
            (
                &[0xa2, 2, 0, 3, 3][..],
                ControllerRecordError::UnknownSource(3),
            ),
            (
                &[0xa4, 1, 0, 1, 0, 2, 1, 3, 1][..],
                ControllerRecordError::DuplicateKey(1),
            ),
            (
                &[0xa3, 2, 0, 2, 0, 3, 1][..],
                ControllerRecordError::DuplicateKey(2),
            ),
            (
                &[0xa3, 2, 0, 3, 1, 3, 1][..],
                ControllerRecordError::DuplicateKey(3),
            ),
        ] {
            assert_eq!(ControllerRecord::decode(kind, bytes), Err(error));
        }
        assert_eq!(
            ControllerRecord::decode(kind, &[0xa2, 2, 0, 3, 1]),
            Ok(ControllerRecord::TimeSet {
                old: None,
                new: 0,
                source: TimeSource::Client
            })
        );
        assert_eq!(
            ControllerRecord::decode(kind, &[0xa3, 1, 0, 2, 0, 3, 1]),
            Ok(ControllerRecord::TimeSet {
                old: Some(0),
                new: 0,
                source: TimeSource::Client
            })
        );
        for bytes in [
            &[0xa3, 1, 0xf6, 2, 0, 3, 1][..],
            &[0xa2, 2, 0x20, 3, 1],
            &[0xa2, 2, 0, 3, 0xf5],
        ] {
            assert!(ControllerRecord::decode(kind, bytes).is_err());
        }
    }

    #[test]
    fn p_215_rail_branch_is_required_boolean_and_extensions_are_skipped() {
        let kind = EventKind::COMMS_UNRECOVERABLE;
        assert_eq!(
            ControllerRecord::decode(kind, &[0xa0]),
            Err(ControllerRecordError::MissingKey(1))
        );
        assert_eq!(
            ControllerRecord::decode(kind, &[0xa2, 1, 0xf5, 1, 0xf4]),
            Err(ControllerRecordError::DuplicateKey(1))
        );
        assert!(ControllerRecord::decode(kind, &[0xa1, 1, 1]).is_err());
        for record in records() {
            let mut dst = [0; CONTROLLER_RECORD_MAX_BYTES + 4];
            let len = record.encode(&mut dst).expect("fits");
            dst[0] += 1;
            dst[len..len + 4].copy_from_slice(&[0x18, 99, 0x81, 0]);
            assert_eq!(
                ControllerRecord::decode(record.kind(), &dst[..len + 4]),
                Ok(record)
            );
        }
        assert_eq!(
            ControllerRecord::decode(EventKind::BOOT, &[0xa0]),
            Err(ControllerRecordError::UnknownKind(EventKind::BOOT))
        );
        assert!(ControllerRecord::decode(EventKind::COMMS_LINK_LOST, &[0x80]).is_err());
    }

    /// Reason 0 is an allocated value, not an absent one: a decoder that read
    /// `{1: 0}` as missing would lose the commoner of the two causes.
    #[test]
    fn l_116_each_reason_survives_the_wire() {
        let kind = EventKind::COMMS_HELD_DOWN;
        for (bytes, reason) in [
            ([0xa1, 1, 0], HeldDownReason::NoDeviceId),
            ([0xa1, 1, 1], HeldDownReason::RevisionsSpent),
        ] {
            let record = ControllerRecord::CommsHeldDown { reason };
            assert_eq!(ControllerRecord::decode(kind, &bytes), Ok(record));
            let mut dst = [0; CONTROLLER_RECORD_MAX_BYTES];
            let len = record.encode(&mut dst).expect("fits");
            assert_eq!(dst.get(..len), Some(&bytes[..]));
            assert_eq!(record.kind(), kind);
        }
    }

    /// An empty body must not read as either cause. Defaulting it would turn a
    /// record that says nothing into "no `device_id`", which sends somebody to
    /// reprovision a unit whose pairing window was the problem.
    #[test]
    fn l_116_a_missing_reason_is_refused() {
        let kind = EventKind::COMMS_HELD_DOWN;
        assert_eq!(
            ControllerRecord::decode(kind, &[0xa0]),
            Err(ControllerRecordError::MissingKey(1))
        );
        assert_eq!(
            ControllerRecord::decode(kind, &[0xa1, 2, 0]),
            Err(ControllerRecordError::MissingKey(1))
        );
    }

    /// Two reasons in one record is two answers to one question, and taking
    /// either one hides the other.
    #[test]
    fn l_116_a_repeated_reason_is_refused() {
        let kind = EventKind::COMMS_HELD_DOWN;
        for bytes in [[0xa2, 1, 0, 1, 1], [0xa2, 1, 1, 1, 1]] {
            assert_eq!(
                ControllerRecord::decode(kind, &bytes),
                Err(ControllerRecordError::DuplicateKey(1))
            );
        }
    }

    /// A reason from a newer registry is refused rather than rendered as one of
    /// the two a reader knows, as P-215 refuses an unallocated time source.
    #[test]
    fn l_116_an_unallocated_reason_is_refused() {
        let kind = EventKind::COMMS_HELD_DOWN;
        for (bytes, value) in [(&[0xa1, 1, 2][..], 2), (&[0xa1, 1, 0x18, 0xff], 255)] {
            assert_eq!(
                ControllerRecord::decode(kind, bytes),
                Err(ControllerRecordError::UnknownReason(value))
            );
        }
        for bytes in [
            &[0xa1, 1, 0x19, 1, 0][..],
            &[0xa1, 1, 0x20],
            &[0xa1, 1, 0xf4],
        ] {
            assert!(matches!(
                ControllerRecord::decode(kind, bytes),
                Err(ControllerRecordError::Cbor(_))
            ));
        }
    }

    #[test]
    fn refusals_render_and_map_to_malformed_body() {
        let errors = [
            ControllerRecordError::MissingKey(2),
            ControllerRecordError::DuplicateKey(1),
            ControllerRecordError::UnknownKind(EventKind::BOOT),
            ControllerRecordError::UnknownSource(0),
            ControllerRecordError::UnknownReason(2),
            ControllerRecordError::ZeroCount,
            ControllerRecordError::Cbor(CborError::WrongType),
        ];
        Rendering::<100>::each_says_something_of_its_own(&errors);
        for error in errors {
            assert_eq!(error.refusal(), Refusal::Client(ErrorCode::MalformedFrame));
        }
    }
}
