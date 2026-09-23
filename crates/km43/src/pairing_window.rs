//! The controller's pairing-window report changes radio reachability, never
//! enrolment permission. Link provenance, retry history and radio lifetime
//! remain the firmware's responsibility under L-194 through L-196.

use core::num::NonZeroU64;

use crate::cbor::CborError;
use crate::{LinkEnvelope, LinkError, LinkField, LinkHeader};

/// P-066's maximum window, also bounding the comms processor's local timer.
pub const MAX_PAIRING_WINDOW_MS: u32 = 120_000;

/// A validated snapshot; zero remaining time explicitly closes the window.
/// Retransmitting it must not restart the receiver's deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PairingWindowNotice {
    revision: NonZeroU64,
    remaining_ms: u32,
}

impl PairingWindowNotice {
    /// Reject a duration longer than the physical pairing window. The revision
    /// identifies a state change within one controller boot, not an enrolment.
    pub fn new(revision: NonZeroU64, remaining_ms: u32) -> Result<Self, LinkError> {
        if remaining_ms > MAX_PAIRING_WINDOW_MS {
            return Err(LinkError::PairingWindowTooLong(remaining_ms));
        }
        Ok(Self {
            revision,
            remaining_ms,
        })
    }

    /// A retry carries this same revision even if its acknowledgement was lost.
    #[must_use]
    pub const fn revision(self) -> NonZeroU64 {
        self.revision
    }

    /// Zero means closed; it never stands in for an absent report.
    #[must_use]
    pub const fn remaining_ms(self) -> u32 {
        self.remaining_ms
    }

    /// Write the snapshot without converting its duration into a new deadline.
    pub fn write(self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut body = header
            .write(2, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        body.key(1)?;
        body.u64(self.revision.get())?;
        body.key(2)?;
        body.u64(u64::from(self.remaining_ms))?;
        Ok(body.finish()?)
    }

    /// Validate the complete body before a caller changes radio availability.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut revision = None;
        let mut remaining = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => {
                    let value =
                        NonZeroU64::new(body.u64()?).ok_or(LinkError::ZeroPairingRevision)?;
                    crate::linklocal::once(&mut revision, LinkField::PairingRevision, value)?;
                }
                2 => {
                    let value = body.u32()?;
                    crate::linklocal::once(&mut remaining, LinkField::RemainingMs, value)?;
                }
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Self::new(
            revision.ok_or(LinkError::Missing(LinkField::PairingRevision))?,
            remaining.ok_or(LinkError::Missing(LinkField::RemainingMs))?,
        )
    }
}

/// Echoes the processed revision, including a stale or duplicate report.
/// It makes no assertion about enrolment or radio readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PairingWindowAck {
    /// The request's non-zero revision, independent of its envelope request id.
    pub revision: NonZeroU64,
}

impl PairingWindowAck {
    /// An acknowledgement carries no duration that could renew a window.
    pub fn write(self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut body = header
            .write(1, dst)
            .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))?;
        body.key(1)?;
        body.u64(self.revision.get())?;
        Ok(body.finish()?)
    }

    /// Refuse an absent, duplicated or zero revision instead of guessing which
    /// report the peer processed.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut revision = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => {
                    let value =
                        NonZeroU64::new(body.u64()?).ok_or(LinkError::ZeroPairingRevision)?;
                    crate::linklocal::once(&mut revision, LinkField::PairingRevision, value)?;
                }
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            revision: revision.ok_or(LinkError::Missing(LinkField::PairingRevision))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Intake, LinkErrorCode, LinkMessageType, ReqId, SessionId, Side, arriving};

    fn header(kind: LinkMessageType) -> LinkHeader {
        LinkHeader {
            kind,
            session: SessionId::None,
            req_id: ReqId(7),
        }
    }

    fn envelope(bytes: &[u8]) -> LinkEnvelope<'_> {
        LinkEnvelope::decode(bytes).expect("envelope reads")
    }

    #[test]
    fn l_193_closed_short_and_maximum_windows_keep_their_revision() {
        for remaining in [0, 1, MAX_PAIRING_WINDOW_MS] {
            for revision in [1, u64::MAX] {
                let notice =
                    PairingWindowNotice::new(NonZeroU64::new(revision).unwrap(), remaining)
                        .expect("bounded window");
                let mut bytes = [0; 64];
                let len = notice
                    .write(header(LinkMessageType::PairingWindow), &mut bytes)
                    .unwrap();
                let read = PairingWindowNotice::decode(envelope(&bytes[..len])).unwrap();
                assert_eq!(read, notice);
                assert_eq!(read.revision().get(), revision);
                assert_eq!(read.remaining_ms(), remaining);
                assert_eq!(
                    envelope(&bytes[..len]).opcode(),
                    LinkMessageType::PairingWindow as u8
                );
            }
        }
    }

    #[test]
    fn l_193_a_window_longer_than_the_physical_window_is_refused() {
        for remaining in [MAX_PAIRING_WINDOW_MS + 1, u32::MAX] {
            assert_eq!(
                PairingWindowNotice::new(NonZeroU64::MIN, remaining),
                Err(LinkError::PairingWindowTooLong(remaining))
            );
            let mut bytes = [0; 64];
            let mut body = header(LinkMessageType::PairingWindow)
                .write(2, &mut bytes)
                .unwrap();
            body.key(1).unwrap();
            body.u64(1).unwrap();
            body.key(2).unwrap();
            body.u64(u64::from(remaining)).unwrap();
            let len = body.finish().unwrap();
            assert_eq!(
                PairingWindowNotice::decode(envelope(&bytes[..len])),
                Err(LinkError::PairingWindowTooLong(remaining))
            );
        }
    }

    #[test]
    fn l_193_missing_zero_duplicate_and_wrong_type_fields_are_refused() {
        // Bodies deliberately bypass the writer so malformed maps reach the decoder.
        let cases: &[(&[u8], LinkError)] = &[
            (&[0xa0], LinkError::Missing(LinkField::PairingRevision)),
            (&[0xa1, 1, 1], LinkError::Missing(LinkField::RemainingMs)),
            (
                &[0xa1, 2, 0],
                LinkError::Missing(LinkField::PairingRevision),
            ),
            (&[0xa2, 1, 0, 2, 0], LinkError::ZeroPairingRevision),
            (
                &[0xa3, 1, 1, 1, 2, 2, 0],
                LinkError::Duplicate(LinkField::PairingRevision),
            ),
            (
                &[0xa3, 1, 1, 2, 0, 2, 1],
                LinkError::Duplicate(LinkField::RemainingMs),
            ),
        ];
        for (body, expected) in cases {
            let mut bytes = [0; 64];
            bytes[..5].copy_from_slice(&[0x84, 0x18, LinkMessageType::PairingWindow as u8, 0, 7]);
            bytes[5..5 + body.len()].copy_from_slice(body);
            assert_eq!(
                PairingWindowNotice::decode(envelope(&bytes[..5 + body.len()])),
                Err(*expected)
            );
        }
        for body in [
            &[0xa2, 1, 1, 2, 0xf5][..],                         // boolean duration
            &[0xa2, 1, 1, 2, 0x1b, 0, 0, 0, 1, 0, 0, 0, 0][..], // wider than u32
            &[0xa2, 1, 0x20, 2, 0][..],                         // negative revision
        ] {
            let mut bytes = [0; 64];
            bytes[..5].copy_from_slice(&[0x84, 0x18, LinkMessageType::PairingWindow as u8, 0, 7]);
            bytes[5..5 + body.len()].copy_from_slice(body);
            assert!(PairingWindowNotice::decode(envelope(&bytes[..5 + body.len()])).is_err());
        }
    }

    #[test]
    fn l_193_ack_requires_a_nonzero_revision_and_skips_unknown_keys() {
        for revision in [NonZeroU64::MIN, NonZeroU64::MAX] {
            let ack = PairingWindowAck { revision };
            let mut bytes = [0; 64];
            let len = ack
                .write(header(LinkMessageType::PairingWindowAck), &mut bytes)
                .unwrap();
            assert_eq!(PairingWindowAck::decode(envelope(&bytes[..len])), Ok(ack));
        }
        for (body, error) in [
            (&[0xa0][..], LinkError::Missing(LinkField::PairingRevision)),
            (&[0xa1, 1, 0][..], LinkError::ZeroPairingRevision),
            (
                &[0xa2, 1, 1, 1, 2][..],
                LinkError::Duplicate(LinkField::PairingRevision),
            ),
        ] {
            let mut bytes = [0; 64];
            bytes[..5].copy_from_slice(&[
                0x84,
                0x18,
                LinkMessageType::PairingWindowAck as u8,
                0,
                7,
            ]);
            bytes[5..5 + body.len()].copy_from_slice(body);
            assert_eq!(
                PairingWindowAck::decode(envelope(&bytes[..5 + body.len()])),
                Err(error)
            );
        }
        let mut bytes = [0; 64];
        let mut body = header(LinkMessageType::PairingWindow)
            .write(3, &mut bytes)
            .unwrap();
        for (key, value) in [(1, 1), (2, 120_000), (3, 999)] {
            body.key(key).unwrap();
            body.u64(value).unwrap();
        }
        let len = body.finish().unwrap();
        assert_eq!(
            PairingWindowNotice::decode(envelope(&bytes[..len]))
                .unwrap()
                .remaining_ms(),
            120_000
        );
        assert_eq!(
            PairingWindowAck::decode(envelope(&bytes[..len]))
                .unwrap()
                .revision,
            NonZeroU64::MIN
        );
    }

    #[test]
    fn every_truncation_and_short_destination_is_refused() {
        let notice = PairingWindowNotice::new(NonZeroU64::MAX, MAX_PAIRING_WINDOW_MS).unwrap();
        let ack = PairingWindowAck {
            revision: NonZeroU64::MAX,
        };
        let mut bytes = [0; 64];
        let len = notice
            .write(header(LinkMessageType::PairingWindow), &mut bytes)
            .unwrap();
        for cut in 0..len {
            assert!(
                LinkEnvelope::decode(&bytes[..cut])
                    .map_err(|_| ())
                    .and_then(|e| PairingWindowNotice::decode(e).map_err(|_| ()))
                    .is_err()
            );
            let mut short = [0; 64];
            assert!(
                notice
                    .write(header(LinkMessageType::PairingWindow), &mut short[..cut])
                    .is_err()
            );
        }
        let len = ack
            .write(header(LinkMessageType::PairingWindowAck), &mut bytes)
            .unwrap();
        for cut in 0..len {
            assert!(
                LinkEnvelope::decode(&bytes[..cut])
                    .map_err(|_| ())
                    .and_then(|e| PairingWindowAck::decode(e).map_err(|_| ()))
                    .is_err()
            );
            let mut short = [0; 64];
            assert!(
                ack.write(header(LinkMessageType::PairingWindowAck), &mut short[..cut])
                    .is_err()
            );
        }
    }

    #[test]
    fn malformed_ack_values_and_trailing_bytes_are_refused() {
        for body in [
            &[0xa1, 1, 0xf5][..], // boolean revision
            &[0xa1, 1, 0x20][..], // negative revision
            &[0xa1, 1, 1, 0][..], // trailing item
        ] {
            let mut bytes = [0; 64];
            bytes[..5].copy_from_slice(&[
                0x84,
                0x18,
                LinkMessageType::PairingWindowAck as u8,
                0,
                7,
            ]);
            bytes[5..5 + body.len()].copy_from_slice(body);
            assert!(PairingWindowAck::decode(envelope(&bytes[..5 + body.len()])).is_err());
        }
        let notice = PairingWindowNotice::new(NonZeroU64::MIN, 0).unwrap();
        let mut bytes = [0; 64];
        let len = notice
            .write(header(LinkMessageType::PairingWindow), &mut bytes)
            .unwrap();
        assert!(PairingWindowNotice::decode(envelope(&bytes[..=len])).is_err());
    }

    #[test]
    fn pairing_reports_and_acks_follow_the_controller_to_comms_direction() {
        let request = LinkMessageType::PairingWindow;
        let ack = LinkMessageType::PairingWindowAck;
        assert_eq!(
            arriving(request as u8, Side::Comms, SessionId::None),
            Intake::Act(request)
        );
        assert_eq!(
            arriving(ack as u8, Side::Controller, SessionId::None),
            Intake::Act(ack)
        );
        assert_eq!(
            arriving(request as u8, Side::Controller, SessionId::None),
            Intake::Refuse(LinkErrorCode::WrongSide)
        );
        assert_eq!(
            arriving(ack as u8, Side::Comms, SessionId::None),
            Intake::Refuse(LinkErrorCode::WrongSide)
        );
        for (kind, receiver) in [(request, Side::Comms), (ack, Side::Controller)] {
            assert_eq!(
                arriving(kind as u8, receiver, SessionId::from(1)),
                Intake::Refuse(LinkErrorCode::NonZeroSession)
            );
        }
    }
}
