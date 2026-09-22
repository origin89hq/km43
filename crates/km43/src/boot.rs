//! The `0x0601 boot` body: why the controller came up, what its clock kept,
//! and what the run before it said last.
//!
//! The record is written before anything else a boot does, into the log that
//! outlives the RAM the reason was read from. A boot after a night unplugged
//! is the one nobody had a probe on, so its reset reason and the state of the
//! RTC's backup domain are worth something only if they are in the log (L-143).
//!
//! **The last words ride with the reason that explains them.** A watchdog
//! reset may carry the task that stopped checking in and how late it was; a
//! panic always carries where it happened, because a panic is only told apart
//! from a software reset by the words it left. Neither may ride on another
//! reason: a power cut with a panic site beside it is a record that
//! contradicts itself, and a reader cannot tell which half is true (P-214).
//! The task index and the file hash belong to the image that was running, as
//! a panic site always has.
//!
//! cites: P-214

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{BootReason, ErrorCode};

/// The most bytes a boot body takes: a panic, whose file hash and line are
/// each a full `u32`.
pub const BOOT_MAX_BYTES: usize = 21;

/// The task that stopped checking in before the watchdog fired, as the
/// previous run wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Starved {
    /// Key 5, the task's index in the image that was running.
    pub task: u8,
    /// Key 6, how far past its window it was when the feed was withheld, in
    /// milliseconds.
    pub overdue_ms: u32,
}

/// Where the previous run panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PanicSite {
    /// Key 7, a hash of the source file's path, resolved against the image
    /// that was running.
    pub file: u32,
    /// Key 8, the line.
    pub line: u32,
}

/// Why the controller came up, with the last words that belong to that reason
/// and to no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BootCause {
    /// Power-on, power-down or brown-out, which one flag reports.
    Power,
    /// The independent watchdog, with the task that starved it when the
    /// previous run got as far as saying so.
    Watchdog(Option<Starved>),
    /// A reset the image asked for without panicking.
    SoftwareReset,
    /// A panic, and where.
    Panic(PanicSite),
    /// The reset pin.
    PinReset,
    /// An option-byte reload: the image banks swapped.
    OptionByteReload,
    /// The window watchdog.
    WindowWatchdog,
    /// An illegal entry into a low-power mode.
    LowPowerEntry,
}

impl BootCause {
    /// The reason as the registry numbers it, which is key 1.
    #[must_use]
    pub const fn reason(self) -> BootReason {
        match self {
            Self::Power => BootReason::Power,
            Self::Watchdog(_) => BootReason::Watchdog,
            Self::SoftwareReset => BootReason::SoftwareReset,
            Self::Panic(_) => BootReason::Panic,
            Self::PinReset => BootReason::PinReset,
            Self::OptionByteReload => BootReason::OptionByteReload,
            Self::WindowWatchdog => BootReason::WindowWatchdog,
            Self::LowPowerEntry => BootReason::LowPowerEntry,
        }
    }
}

/// An `0x0601 boot` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Boot {
    /// Key 1, and keys 5 to 8 when the reason carries last words.
    pub cause: BootCause,
    /// Key 2, `false` when the RTC reported its backup domain invalid: the
    /// calendar did not survive, and the time is not known (L-143).
    pub backup_valid: bool,
    /// Key 3, whether the RTC runs from its crystal, ready and selected.
    /// Anything else keeps time badly or not at all.
    pub rtc_crystal: bool,
    /// Key 4, whether this reset power-cycled the comms processor.
    pub rail_cycled: bool,
}

impl Boot {
    /// Write the body into `dst`. A destination too small is refused.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, BootError> {
        let mut cbor = CborWriter::new(dst);
        let words = match self.cause {
            BootCause::Watchdog(Some(_)) | BootCause::Panic(_) => 2,
            BootCause::Power
            | BootCause::Watchdog(None)
            | BootCause::SoftwareReset
            | BootCause::PinReset
            | BootCause::OptionByteReload
            | BootCause::WindowWatchdog
            | BootCause::LowPowerEntry => 0,
        };
        cbor.map(4 + words)?;
        cbor.key(1)?;
        cbor.u64(self.cause.reason() as u64)?;
        cbor.key(2)?;
        cbor.bool(self.backup_valid)?;
        cbor.key(3)?;
        cbor.bool(self.rtc_crystal)?;
        cbor.key(4)?;
        cbor.bool(self.rail_cycled)?;
        match self.cause {
            BootCause::Watchdog(Some(starved)) => {
                cbor.key(5)?;
                cbor.u64(u64::from(starved.task))?;
                cbor.key(6)?;
                cbor.u64(u64::from(starved.overdue_ms))?;
            }
            BootCause::Panic(site) => {
                cbor.key(7)?;
                cbor.u64(u64::from(site.file))?;
                cbor.key(8)?;
                cbor.u64(u64::from(site.line))?;
            }
            BootCause::Power
            | BootCause::Watchdog(None)
            | BootCause::SoftwareReset
            | BootCause::PinReset
            | BootCause::OptionByteReload
            | BootCause::WindowWatchdog
            | BootCause::LowPowerEntry => {}
        }
        Ok(cbor.finish()?)
    }

    /// Read one back, refusing a missing key, a reason this version does not
    /// allocate, and last words that do not belong to the reason (P-214).
    pub fn decode(payload: &[u8]) -> Result<Self, BootError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut reason, mut backup_valid, mut rtc_crystal, mut rail_cycled) =
            (None, None, None, None);
        let (mut task, mut overdue_ms, mut file, mut line) = (None, None, None, None);
        for _ in 0..pairs {
            match body.key()? {
                1 => {
                    let number = body.u8()?;
                    let known = BootReason::try_from(number)
                        .map_err(|()| BootError::UnknownReason(number))?;
                    once(&mut reason, 1, known)?;
                }
                2 => once(&mut backup_valid, 2, body.bool()?)?,
                3 => once(&mut rtc_crystal, 3, body.bool()?)?,
                4 => once(&mut rail_cycled, 4, body.bool()?)?,
                5 => once(&mut task, 5, body.u8()?)?,
                6 => once(&mut overdue_ms, 6, body.u32()?)?,
                7 => once(&mut file, 7, body.u32()?)?,
                8 => once(&mut line, 8, body.u32()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;
        let reason = reason.ok_or(BootError::MissingKey(1))?;
        let starved = match (task, overdue_ms) {
            (Some(task), Some(overdue_ms)) => Some(Starved { task, overdue_ms }),
            (None, None) => None,
            (Some(_), None) => return Err(BootError::MissingKey(6)),
            (None, Some(_)) => return Err(BootError::MissingKey(5)),
        };
        let site = match (file, line) {
            (Some(file), Some(line)) => Some(PanicSite { file, line }),
            (None, None) => None,
            (Some(_), None) => return Err(BootError::MissingKey(8)),
            (None, Some(_)) => return Err(BootError::MissingKey(7)),
        };
        let cause = match (reason, starved, site) {
            (BootReason::Watchdog, starved, None) => BootCause::Watchdog(starved),
            (BootReason::Panic, None, Some(site)) => BootCause::Panic(site),
            (BootReason::Panic, None, None) => return Err(BootError::MissingKey(7)),
            (BootReason::Power, None, None) => BootCause::Power,
            (BootReason::SoftwareReset, None, None) => BootCause::SoftwareReset,
            (BootReason::PinReset, None, None) => BootCause::PinReset,
            (BootReason::OptionByteReload, None, None) => BootCause::OptionByteReload,
            (BootReason::WindowWatchdog, None, None) => BootCause::WindowWatchdog,
            (BootReason::LowPowerEntry, None, None) => BootCause::LowPowerEntry,
            (
                BootReason::Power
                | BootReason::Watchdog
                | BootReason::SoftwareReset
                | BootReason::Panic
                | BootReason::PinReset
                | BootReason::OptionByteReload
                | BootReason::WindowWatchdog
                | BootReason::LowPowerEntry,
                _,
                _,
            ) => return Err(BootError::WordsWithoutTheirReason(reason)),
        };
        Ok(Self {
            cause,
            backup_valid: backup_valid.ok_or(BootError::MissingKey(2))?,
            rtc_crystal: rtc_crystal.ok_or(BootError::MissingKey(3))?,
            rail_cycled: rail_cycled.ok_or(BootError::MissingKey(4))?,
        })
    }
}

/// Keep the first value of a key and refuse a second: two decoders that
/// resolved a repeat differently would read two records out of one (P-015).
fn once<T>(slot: &mut Option<T>, key: u8, value: T) -> Result<(), BootError> {
    if slot.is_some() {
        return Err(BootError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// Why a boot body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BootError {
    /// A required key never arrived (P-015), or half of a pair of last words.
    MissingKey(u8),
    /// A key carried twice (P-015).
    Duplicate(u8),
    /// A boot reason this version does not allocate, or one it retired.
    UnknownReason(u8),
    /// Last words beside a reason they do not explain (P-214).
    WordsWithoutTheirReason(BootReason),
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for BootError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl BootError {
    /// What to answer: every refusal is a body whose meaning cannot be
    /// trusted, which is what error 1 says.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::MissingKey(_)
            | Self::Duplicate(_)
            | Self::UnknownReason(_)
            | Self::WordsWithoutTheirReason(_)
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for BootError {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey(k) => write!(w, "a boot record with no key {k}"),
            Self::Duplicate(k) => write!(w, "a boot record carrying key {k} twice"),
            Self::UnknownReason(n) => write!(w, "boot reason {n} is not allocated"),
            Self::WordsWithoutTheirReason(reason) => write!(
                w,
                "last words beside boot reason {}, which they do not explain",
                *reason as u8
            ),
            Self::Cbor(why) => write!(w, "{why}"),
        }
    }
}

impl core::error::Error for BootError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    fn boot(cause: BootCause) -> Boot {
        Boot {
            cause,
            backup_valid: true,
            rtc_crystal: true,
            rail_cycled: true,
        }
    }

    fn encoded(boot: &Boot) -> ([u8; 64], usize) {
        let mut out = [0u8; 64];
        let len = boot.encode(&mut out).expect("encodes");
        (out, len)
    }

    const EVERY_CAUSE: [BootCause; 10] = [
        BootCause::Power,
        BootCause::Watchdog(None),
        BootCause::Watchdog(Some(Starved {
            task: 3,
            overdue_ms: 31_000,
        })),
        BootCause::SoftwareReset,
        BootCause::Panic(PanicSite {
            file: 0xDEAD_BEEF,
            line: 212,
        }),
        BootCause::PinReset,
        BootCause::OptionByteReload,
        BootCause::WindowWatchdog,
        BootCause::LowPowerEntry,
        BootCause::Watchdog(Some(Starved {
            task: u8::MAX,
            overdue_ms: u32::MAX,
        })),
    ];

    /// Every reason round trips with every combination of the three flags,
    /// and the reason on the wire is the registry's.
    #[test]
    fn every_boot_reads_back_with_its_backup_domain_as_it_was() {
        for cause in EVERY_CAUSE {
            for flags in 0u8..8 {
                let sent = Boot {
                    cause,
                    backup_valid: flags & 1 != 0,
                    rtc_crystal: flags & 2 != 0,
                    rail_cycled: flags & 4 != 0,
                };
                let (out, len) = encoded(&sent);
                let read = Boot::decode(out.get(..len).expect("written")).expect("decodes");
                assert_eq!(read, sent);
            }
        }
        // A dead backup cell is what the record exists to say.
        let dead = Boot {
            backup_valid: false,
            ..boot(BootCause::Power)
        };
        let (out, len) = encoded(&dead);
        assert_eq!(
            out.get(..len),
            Some([0xA4, 0x01, 0x01, 0x02, 0xF4, 0x03, 0xF5, 0x04, 0xF5].as_slice())
        );
    }

    /// The widest body is a panic with a full-width file hash and line, and it
    /// is exactly the bound.
    #[test]
    fn the_widest_boot_body_is_the_bound() {
        let widest = boot(BootCause::Panic(PanicSite {
            file: u32::MAX,
            line: u32::MAX,
        }));
        let (_, len) = encoded(&widest);
        assert_eq!(len, BOOT_MAX_BYTES);
        for cause in EVERY_CAUSE {
            let (_, len) = encoded(&boot(cause));
            assert!(len <= BOOT_MAX_BYTES, "{cause:?} took {len}");
        }
        let mut small = [0u8; BOOT_MAX_BYTES - 1];
        assert!(widest.encode(&mut small).is_err());
    }

    /// Last words ride only with the reason they explain: a starved task on a
    /// power cut, a panic site on a watchdog, or a panic with no site is a
    /// record that contradicts itself.
    #[test]
    fn p_214_last_words_beside_another_reason_are_refused() {
        // A power-on body with keys 7 and 8 bolted on.
        let power_with_site = [
            0xA6, 0x01, 0x01, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x07, 0x01, 0x08, 0x02,
        ];
        assert_eq!(
            Boot::decode(&power_with_site),
            Err(BootError::WordsWithoutTheirReason(BootReason::Power))
        );
        // A watchdog carrying a panic site.
        let watchdog_with_site = [
            0xA6, 0x01, 0x02, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x07, 0x01, 0x08, 0x02,
        ];
        assert_eq!(
            Boot::decode(&watchdog_with_site),
            Err(BootError::WordsWithoutTheirReason(BootReason::Watchdog))
        );
        // A panic carrying a starved task instead of its site.
        let panic_with_task = [
            0xA6, 0x01, 0x05, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x05, 0x01, 0x06, 0x02,
        ];
        assert_eq!(
            Boot::decode(&panic_with_task),
            Err(BootError::WordsWithoutTheirReason(BootReason::Panic))
        );
        // A panic with no site: told from a software reset by nothing.
        let bare_panic = [0xA4, 0x01, 0x05, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5];
        assert_eq!(Boot::decode(&bare_panic), Err(BootError::MissingKey(7)));
        // Half a pair.
        let half_starved = [
            0xA5, 0x01, 0x02, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x05, 0x01,
        ];
        assert_eq!(Boot::decode(&half_starved), Err(BootError::MissingKey(6)));
        let half_site = [
            0xA5, 0x01, 0x05, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x08, 0x02,
        ];
        assert_eq!(Boot::decode(&half_site), Err(BootError::MissingKey(7)));
    }

    /// The retired brown-out and a number nobody allocated are both refused,
    /// and every required key is required.
    #[test]
    fn a_retired_reason_an_unknown_one_or_a_missing_key_is_refused() {
        let brown_out = [0xA4, 0x01, 0x03, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5];
        assert_eq!(Boot::decode(&brown_out), Err(BootError::UnknownReason(3)));
        let unknown = [0xA4, 0x01, 0x0A, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5];
        assert_eq!(Boot::decode(&unknown), Err(BootError::UnknownReason(10)));
        let zero = [0xA4, 0x01, 0x00, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5];
        assert_eq!(Boot::decode(&zero), Err(BootError::UnknownReason(0)));
        // Each of the four required keys, dropped in turn.
        let pairs = [[0x01u8, 0x01], [0x02, 0xF5], [0x03, 0xF5], [0x04, 0xF5]];
        for (dropped, key) in [1u8, 2, 3, 4].into_iter().enumerate() {
            let mut body = [0xA3u8; 7];
            let kept = pairs
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != dropped)
                .flat_map(|(_, pair)| pair.iter().copied());
            for (slot, byte) in body.iter_mut().skip(1).zip(kept) {
                *slot = byte;
            }
            assert_eq!(Boot::decode(&body), Err(BootError::MissingKey(key)));
        }
        // A key this version does not know is skipped, not refused.
        let later = [
            0xA5, 0x01, 0x01, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x09, 0x00,
        ];
        assert_eq!(Boot::decode(&later), Ok(boot(BootCause::Power)));
        // A flag that is not a bool is the wrong type.
        let not_bool = [0xA4, 0x01, 0x01, 0x02, 0x01, 0x03, 0xF5, 0x04, 0xF5];
        assert_eq!(
            Boot::decode(&not_bool),
            Err(BootError::Cbor(CborError::WrongType))
        );
    }

    /// A key carried twice is refused rather than resolved, whichever key it
    /// is and whether or not the two values agree: a reader that kept the
    /// last would read a panic where one that kept the first reads a power cut.
    #[test]
    fn p_015_a_boot_body_carrying_a_key_twice_is_refused() {
        // Reason 1 and then reason 5, with a site: the last one would read as a panic.
        let two_reasons = [
            0xA7, 0x01, 0x01, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x01, 0x05, 0x07, 0x01, 0x08,
            0x02,
        ];
        assert_eq!(Boot::decode(&two_reasons), Err(BootError::Duplicate(1)));
        // The same flag twice, agreeing with itself.
        let same_flag = [
            0xA5, 0x01, 0x01, 0x02, 0xF5, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5,
        ];
        assert_eq!(Boot::decode(&same_flag), Err(BootError::Duplicate(2)));
        // Each of the last words' keys, repeated.
        let task_twice = [
            0xA7, 0x01, 0x02, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x05, 0x01, 0x05, 0x01, 0x06,
            0x02,
        ];
        assert_eq!(Boot::decode(&task_twice), Err(BootError::Duplicate(5)));
        let line_twice = [
            0xA7, 0x01, 0x05, 0x02, 0xF5, 0x03, 0xF5, 0x04, 0xF5, 0x07, 0x01, 0x08, 0x02, 0x08,
            0x03,
        ];
        assert_eq!(Boot::decode(&line_twice), Err(BootError::Duplicate(8)));
    }

    /// Every truncation of every shape is refused, never read as a shorter
    /// record, and garbage never panics.
    #[test]
    fn every_cut_of_a_boot_body_is_refused() {
        for cause in EVERY_CAUSE {
            let (out, len) = encoded(&boot(cause));
            for cut in 0..len {
                assert!(
                    Boot::decode(out.get(..cut).expect("a prefix")).is_err(),
                    "{cause:?} cut at {cut}"
                );
            }
        }
        for seed in 0u8..=255 {
            let noise = [seed; BOOT_MAX_BYTES];
            let _ = Boot::decode(&noise);
        }
    }

    /// Every refusal is error 1 and reads as its own sentence.
    #[test]
    fn every_boot_refusal_is_a_malformed_body_with_its_own_sentence() {
        const EVERY: [BootError; 5] = [
            BootError::MissingKey(2),
            BootError::Duplicate(2),
            BootError::UnknownReason(3),
            BootError::WordsWithoutTheirReason(BootReason::Power),
            BootError::Cbor(CborError::WrongType),
        ];
        Rendering::<96>::each_says_something_of_its_own(&EVERY);
        for why in EVERY {
            assert_eq!(why.refusal(), Refusal::Client(ErrorCode::MalformedFrame));
        }
    }
}
