//! What the radio can hear and what it did with the network it was given.
//!
//! The comms processor scans and reports; the controller holds the latest of
//! each and answers clients from it. The list and the join state are that
//! processor's account of itself (P-221, L-207), so everything here is a shape
//! to check and nothing is a fact to act on.
//!
//! One list type serves both hops. The controller relays the link result's rows
//! into `WifiScan 0x91` byte for byte, which is why `Ap` is the same row on both
//! and why [`ScanList`] keeps what it decoded as the bytes it arrived in.
//!
//! cites: P-013, P-015, P-217, P-219, L-200, L-201, L-202, L-204

use core::fmt;
use core::num::NonZeroU32;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::config::MAX_SSID;
use crate::envelope::{LinkEnvelope, LinkHeader, Refusal};
use crate::generated::{
    ErrorCode, EventKind, ScanRefusal, ScanState, WifiBand, WifiFailure, WifiScan as ScanStarted,
    WifiScanResult as ScanOutcomeCode, WifiSecurity, WifiState,
};
use crate::limits::MAX_SCAN_APS;
use crate::linklocal::LinkError;

/// The highest channel number any band allocates, 6 GHz's 233.
pub const MAX_CHANNEL: u8 = 233;

/// Which key of which body a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WifiField {
    /// `WifiScan 0x11` key 1.
    Refresh,
    /// `WifiScan 0x91` key 1, or the scan number on the link.
    Scan,
    /// `WifiScan 0x91` key 2.
    Refused,
    /// `WifiScan 0x91` key 3.
    AgeMs,
    /// The rows of a list.
    Aps,
    /// The count beside a list.
    Unlisted,
    /// `Ap` key 1.
    Ssid,
    /// `Ap` key 2.
    Rssi,
    /// `Ap` key 3.
    Security,
    /// `Ap` key 4.
    Band,
    /// `Ap` key 5.
    Channel,
    /// `WifiStatus 0x92` key 1.
    Section,
    /// The section version the radio is acting on.
    Version,
    /// The join state.
    State,
    /// The failure beside `failed`.
    Reason,
    /// The address beside `joined`.
    Ipv4,
    /// A link acknowledgement's outcome.
    Outcome,
}

impl fmt::Display for WifiField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refresh => "refresh",
            Self::Scan => "scan",
            Self::Refused => "refused",
            Self::AgeMs => "age_ms",
            Self::Aps => "aps",
            Self::Unlisted => "unlisted",
            Self::Ssid => "ssid",
            Self::Rssi => "rssi",
            Self::Security => "security",
            Self::Band => "band",
            Self::Channel => "channel",
            Self::Section => "section",
            Self::Version => "version",
            Self::State => "state",
            Self::Reason => "reason",
            Self::Ipv4 => "ipv4",
            Self::Outcome => "outcome",
        })
    }
}

/// Why a scan or status body would not read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum WifiError {
    /// A required key that never arrived. Never defaulted: a missing `rssi` is
    /// not 0 dBm, and a missing `section` is not an unwritten one.
    Missing(WifiField),
    /// The same key twice (P-015).
    Duplicate(WifiField),
    /// A value a closed space does not allocate (P-014).
    Unallocated {
        /// Which field.
        field: WifiField,
        /// What arrived.
        raw: u8,
    },
    /// An SSID that is empty or longer than [`MAX_SSID`] (L-202).
    SsidLength(usize),
    /// An `rssi` that is not an `i8`.
    RssiOutOfRange(i32),
    /// A channel of 0 or past [`MAX_CHANNEL`].
    ChannelOutOfRange(u8),
    /// More rows than [`MAX_SCAN_APS`].
    TooManyAccessPoints(usize),
    /// A row stronger than the one before it (L-202).
    OutOfOrder,
    /// Two rows for one SSID (L-202).
    SsidRepeated,
    /// `age_ms`, `aps` and `unlisted` not all present or all absent (P-217),
    /// or a link result whose rows disagree with its outcome (L-201).
    ListIncomplete,
    /// A refusal beside a running scan, which a refresh joins instead (P-218).
    RefusedWhileRunning,
    /// `version` and `state` not both present or both absent (P-219).
    ReportIncomplete,
    /// A `reason` without `failed`, or `failed` without one (P-219, L-204).
    ReasonDisagrees,
    /// An `ipv4` without `joined`, or `joined` without one (P-219, L-204).
    AddressDisagrees,
    /// An `ipv4` that is not four bytes.
    Ipv4Length(usize),
    /// A scan number of 0, which L-200 never allocates.
    ZeroScan,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for WifiError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl WifiError {
    /// Every one of these is a body that does not mean what it says, which
    /// P-015 answers with error 1.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::Unallocated { .. }
            | Self::SsidLength(_)
            | Self::RssiOutOfRange(_)
            | Self::ChannelOutOfRange(_)
            | Self::TooManyAccessPoints(_)
            | Self::OutOfOrder
            | Self::SsidRepeated
            | Self::ListIncomplete
            | Self::RefusedWhileRunning
            | Self::ReportIncomplete
            | Self::ReasonDisagrees
            | Self::AddressDisagrees
            | Self::Ipv4Length(_)
            | Self::ZeroScan
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for WifiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(f, "no {field}"),
            Self::Duplicate(field) => write!(f, "{field} twice"),
            Self::Unallocated { field, raw } => write!(f, "{field} {raw} is not allocated"),
            Self::SsidLength(len) => write!(f, "an SSID of {len} bytes is outside 1 to {MAX_SSID}"),
            Self::RssiOutOfRange(dbm) => write!(f, "rssi {dbm} is not an i8"),
            Self::ChannelOutOfRange(channel) => {
                write!(f, "channel {channel} is outside 1 to {MAX_CHANNEL}")
            }
            Self::TooManyAccessPoints(count) => {
                write!(
                    f,
                    "{count} access points is past the {MAX_SCAN_APS} a list holds"
                )
            }
            Self::OutOfOrder => f.write_str("a row is stronger than the one before it"),
            Self::SsidRepeated => f.write_str("two rows name one SSID"),
            Self::ListIncomplete => f.write_str("a list without its age or count, or the reverse"),
            Self::RefusedWhileRunning => f.write_str("a refusal beside a running scan"),
            Self::ReportIncomplete => f.write_str("a version without a state, or the reverse"),
            Self::ReasonDisagrees => f.write_str("a reason and a state that disagree"),
            Self::AddressDisagrees => f.write_str("an address and a state that disagree"),
            Self::Ipv4Length(len) => write!(f, "an IPv4 address of {len} bytes"),
            Self::ZeroScan => f.write_str("scan 0 names no scan"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for WifiError {}

fn once<T>(slot: &mut Option<T>, field: WifiField, value: T) -> Result<(), WifiError> {
    if slot.is_some() {
        return Err(WifiError::Duplicate(field));
    }
    *slot = Some(value);
    Ok(())
}

fn closed<T>(field: WifiField, raw: u8, known: Result<T, ()>) -> Result<T, WifiError> {
    known.map_err(|()| WifiError::Unallocated { field, raw })
}

fn scan_number(raw: u32) -> Result<NonZeroU32, WifiError> {
    NonZeroU32::new(raw).ok_or(WifiError::ZeroScan)
}

/// One access point as the radio heard it: the strongest for its SSID (L-202).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AccessPoint<'a> {
    /// Key 1, 1 to [`MAX_SSID`] bytes of UTF-8. A hidden network has no row.
    pub ssid: &'a str,
    /// Key 2, dBm.
    pub rssi: i8,
    /// Key 3. `open` and `other` are networks the section cannot join.
    pub security: WifiSecurity,
    /// Key 4.
    pub band: WifiBand,
    /// Key 5, 1 to [`MAX_CHANNEL`], numbered within `band`.
    pub channel: u8,
}

impl<'a> AccessPoint<'a> {
    fn check(&self) -> Result<(), WifiError> {
        if self.ssid.is_empty() || self.ssid.len() > MAX_SSID {
            return Err(WifiError::SsidLength(self.ssid.len()));
        }
        if self.channel == 0 || self.channel > MAX_CHANNEL {
            return Err(WifiError::ChannelOutOfRange(self.channel));
        }
        Ok(())
    }

    fn encode_into(&self, cbor: &mut CborWriter<'_>) -> Result<(), WifiError> {
        self.check()?;
        cbor.map(5)?;
        cbor.key(1)?;
        cbor.text(self.ssid)?;
        cbor.key(2)?;
        cbor.i32(i32::from(self.rssi))?;
        cbor.key(3)?;
        cbor.u64(self.security as u64)?;
        cbor.key(4)?;
        cbor.u64(self.band as u64)?;
        cbor.key(5)?;
        cbor.u64(u64::from(self.channel))?;
        Ok(())
    }

    fn decode_from(cbor: &mut CborReader<'a>) -> Result<Self, WifiError> {
        let pairs = cbor.map()?;
        let (mut ssid, mut rssi, mut security, mut band, mut channel) =
            (None, None, None, None, None);
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(&mut ssid, WifiField::Ssid, cbor.text()?)?,
                2 => {
                    let dbm = cbor.i32()?;
                    let dbm = i8::try_from(dbm).map_err(|_| WifiError::RssiOutOfRange(dbm))?;
                    once(&mut rssi, WifiField::Rssi, dbm)?;
                }
                3 => {
                    let raw = cbor.u8()?;
                    let known = closed(WifiField::Security, raw, WifiSecurity::try_from(raw))?;
                    once(&mut security, WifiField::Security, known)?;
                }
                4 => {
                    let raw = cbor.u8()?;
                    let known = closed(WifiField::Band, raw, WifiBand::try_from(raw))?;
                    once(&mut band, WifiField::Band, known)?;
                }
                5 => once(&mut channel, WifiField::Channel, cbor.u8()?)?,
                _ => cbor.skip()?,
            }
        }
        let row = Self {
            ssid: ssid.ok_or(WifiError::Missing(WifiField::Ssid))?,
            rssi: rssi.ok_or(WifiError::Missing(WifiField::Rssi))?,
            security: security.ok_or(WifiError::Missing(WifiField::Security))?,
            band: band.ok_or(WifiError::Missing(WifiField::Band))?,
            channel: channel.ok_or(WifiError::Missing(WifiField::Channel))?,
        };
        row.check()?;
        Ok(row)
    }
}

#[derive(Clone, Copy)]
enum Rows<'a> {
    /// Rows a sender built, checked when the list was made.
    Built(&'a [AccessPoint<'a>]),
    /// The CBOR array as it arrived, walked and checked once on decode.
    Read { array: &'a [u8], count: usize },
}

/// A scan's rows and the count of what it left out, checked against L-202 on
/// the way in and on the way out: at most [`MAX_SCAN_APS`], one row per SSID,
/// strongest first.
///
/// A decoded list keeps its rows as the bytes they arrived in, so the
/// controller relays a link result into `WifiScan 0x91` without re-encoding
/// anything and without an array of rows on its stack.
#[derive(Clone, Copy)]
pub struct ScanList<'a> {
    rows: Rows<'a>,
    unlisted: u16,
}

impl<'a> ScanList<'a> {
    /// Check the rows a comms processor is about to send. `unlisted` counts
    /// the access points heard and left out, saturating (L-202).
    pub fn new(rows: &'a [AccessPoint<'a>], unlisted: u16) -> Result<Self, WifiError> {
        let list = Self {
            rows: Rows::Built(rows),
            unlisted,
        };
        list.check()?;
        Ok(list)
    }

    /// Access points heard and not listed.
    #[must_use]
    pub const fn unlisted(&self) -> u16 {
        self.unlisted
    }

    /// How many rows. Zero is a scan that heard nothing, which is an answer.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.rows {
            Rows::Built(rows) => rows.len(),
            Rows::Read { count, .. } => count,
        }
    }

    /// Whether the radio heard nothing it could list.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The rows, strongest first.
    #[must_use]
    pub fn iter(&self) -> AccessPoints<'a> {
        match self.rows {
            Rows::Built(rows) => AccessPoints {
                built: rows.iter(),
                read: CborReader::new(&[]),
                left: 0,
                header: Ok(()),
            },
            Rows::Read { array, count } => {
                let mut read = CborReader::new(array);
                // Checked on decode, so the header reads; a failure here is
                // reported by the first `next` rather than hidden.
                let header = read.array().map(|_| ());
                AccessPoints {
                    built: [].iter(),
                    read,
                    left: count,
                    header,
                }
            }
        }
    }

    fn check(&self) -> Result<(), WifiError> {
        if self.len() > MAX_SCAN_APS {
            return Err(WifiError::TooManyAccessPoints(self.len()));
        }
        let mut seen: [&str; MAX_SCAN_APS] = [""; MAX_SCAN_APS];
        let mut weaker_than = i8::MAX;
        for (at, row) in self.iter().enumerate() {
            let row = row?;
            row.check()?;
            if row.rssi > weaker_than {
                return Err(WifiError::OutOfOrder);
            }
            weaker_than = row.rssi;
            let earlier = seen.get(..at).ok_or(WifiError::TooManyAccessPoints(at))?;
            if earlier.contains(&row.ssid) {
                return Err(WifiError::SsidRepeated);
            }
            let slot = seen.get_mut(at).ok_or(WifiError::TooManyAccessPoints(at))?;
            *slot = row.ssid;
        }
        Ok(())
    }

    fn encode_rows(&self, cbor: &mut CborWriter<'_>) -> Result<(), WifiError> {
        match self.rows {
            Rows::Built(rows) => {
                cbor.array(rows.len())?;
                for row in rows {
                    row.encode_into(cbor)?;
                }
            }
            Rows::Read { array, .. } => cbor.raw(array)?,
        }
        Ok(())
    }

    fn read(array: &'a [u8], unlisted: u16) -> Result<Self, WifiError> {
        let mut cbor = CborReader::new(array);
        let count = cbor.array()?;
        if count > MAX_SCAN_APS {
            return Err(WifiError::TooManyAccessPoints(count));
        }
        let list = Self {
            rows: Rows::Read { array, count },
            unlisted,
        };
        list.check()?;
        Ok(list)
    }
}

/// Two lists are equal when their rows and counts are, whichever side of the
/// wire each was built on.
impl PartialEq for ScanList<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.unlisted == other.unlisted
            && self.len() == other.len()
            && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl Eq for ScanList<'_> {}

impl fmt::Debug for ScanList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanList")
            .field("rows", &self.len())
            .field("unlisted", &self.unlisted)
            .finish()
    }
}

impl<'a> IntoIterator for &ScanList<'a> {
    type Item = Result<AccessPoint<'a>, WifiError>;
    type IntoIter = AccessPoints<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The rows of a [`ScanList`]. A decoded list was checked whole before it was
/// handed out, so an `Err` here means the bytes changed underneath it.
///
/// Built rows come from the slice and read rows from the reader; one of the
/// two is always empty.
pub struct AccessPoints<'a> {
    built: core::slice::Iter<'a, AccessPoint<'a>>,
    read: CborReader<'a>,
    left: usize,
    header: Result<(), CborError>,
}

impl<'a> Iterator for AccessPoints<'a> {
    type Item = Result<AccessPoint<'a>, WifiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(row) = self.built.next() {
            return Some(Ok(*row));
        }
        if self.left == 0 {
            return None;
        }
        self.left = self.left.saturating_sub(1);
        if let Err(why) = self.header {
            self.left = 0;
            return Some(Err(WifiError::Cbor(why)));
        }
        Some(AccessPoint::decode_from(&mut self.read))
    }
}

/// Take a list's three keys as they arrived and insist they came together.
fn held(
    age: Option<u32>,
    rows: Option<&[u8]>,
    unlisted: Option<u16>,
) -> Result<Option<(u32, ScanList<'_>)>, WifiError> {
    match (age, rows, unlisted) {
        (None, None, None) => Ok(None),
        (Some(age), Some(rows), Some(unlisted)) => Ok(Some((age, ScanList::read(rows, unlisted)?))),
        _ => Err(WifiError::ListIncomplete),
    }
}

/// `WifiScan 0x11`, inside its wrapper. `refresh` is required: a request that
/// did not say whether to scan does not get a scan guessed for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScanRequest {
    /// Key 1. False reads the list held and moves no radio.
    pub refresh: bool,
}

impl ScanRequest {
    /// Encode the inner body the wrapper carries.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, WifiError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(1)?;
        cbor.key(1)?;
        cbor.bool(self.refresh)?;
        Ok(cbor.finish()?)
    }

    /// Read the inner body after the wrapper's tag has verified.
    pub fn decode(payload: &[u8]) -> Result<Self, WifiError> {
        let mut cbor = CborReader::new(payload);
        let pairs = cbor.map()?;
        let mut refresh = None;
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(&mut refresh, WifiField::Refresh, cbor.bool()?)?,
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        Ok(Self {
            refresh: refresh.ok_or(WifiError::Missing(WifiField::Refresh))?,
        })
    }
}

/// The list the controller holds, with how long it has held it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldList<'a> {
    /// Key 3, milliseconds on P-004's tick since the list arrived, saturating.
    pub age_ms: u32,
    /// Keys 4 and 5.
    pub list: ScanList<'a>,
}

/// `WifiScan 0x91`: the state of the most recent scan and the list from the
/// most recent one that completed (P-217).
///
/// Built through [`ScanAnswer::new`], which refuses a refusal beside a running
/// scan; the list is an `Option` because *no list* and *an empty list* are two
/// different answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanAnswer<'a> {
    scan: ScanState,
    refused: Option<ScanRefusal>,
    held: Option<HeldList<'a>>,
}

impl<'a> ScanAnswer<'a> {
    /// A refresh that meets a running scan joins it (P-218), so `running`
    /// with a refusal is a contradiction and is refused here.
    pub const fn new(
        scan: ScanState,
        refused: Option<ScanRefusal>,
        held: Option<HeldList<'a>>,
    ) -> Result<Self, WifiError> {
        if matches!(scan, ScanState::Running) && refused.is_some() {
            return Err(WifiError::RefusedWhileRunning);
        }
        Ok(Self {
            scan,
            refused,
            held,
        })
    }

    /// Key 1.
    #[must_use]
    pub const fn scan(&self) -> ScanState {
        self.scan
    }

    /// Key 2, present only when a refresh was asked for and started nothing.
    #[must_use]
    pub const fn refused(&self) -> Option<ScanRefusal> {
        self.refused
    }

    /// Keys 3 to 5, absent when no scan has completed since boot.
    #[must_use]
    pub const fn held(&self) -> Option<HeldList<'a>> {
        self.held
    }

    /// Encode the inner body the wrapper carries.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, WifiError> {
        let keys = 1 + usize::from(self.refused.is_some()) + 3 * usize::from(self.held.is_some());
        let mut cbor = CborWriter::new(dst);
        cbor.map(keys)?;
        cbor.key(1)?;
        cbor.u64(self.scan as u64)?;
        if let Some(refused) = self.refused {
            cbor.key(2)?;
            cbor.u64(refused as u64)?;
        }
        if let Some(held) = self.held {
            cbor.key(3)?;
            cbor.u64(u64::from(held.age_ms))?;
            cbor.key(4)?;
            held.list.encode_rows(&mut cbor)?;
            cbor.key(5)?;
            cbor.u64(u64::from(held.list.unlisted))?;
        }
        Ok(cbor.finish()?)
    }

    /// Read the inner body after the wrapper's tag has verified.
    pub fn decode(payload: &'a [u8]) -> Result<Self, WifiError> {
        let mut cbor = CborReader::new(payload);
        let pairs = cbor.map()?;
        let (mut scan, mut refused, mut age, mut rows, mut unlisted) =
            (None, None, None, None, None);
        for _ in 0..pairs {
            match cbor.key()? {
                1 => {
                    let raw = cbor.u8()?;
                    let known = closed(WifiField::Scan, raw, ScanState::try_from(raw))?;
                    once(&mut scan, WifiField::Scan, known)?;
                }
                2 => {
                    let raw = cbor.u8()?;
                    let known = closed(WifiField::Refused, raw, ScanRefusal::try_from(raw))?;
                    once(&mut refused, WifiField::Refused, known)?;
                }
                3 => once(&mut age, WifiField::AgeMs, cbor.u32()?)?,
                4 => once(&mut rows, WifiField::Aps, cbor.raw()?)?,
                5 => once(&mut unlisted, WifiField::Unlisted, cbor.u16()?)?,
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        let held = held(age, rows, unlisted)?.map(|(age_ms, list)| HeldList { age_ms, list });
        Self::new(
            scan.ok_or(WifiError::Missing(WifiField::Scan))?,
            refused,
            held,
        )
    }
}

/// What the radio is doing, with the field each state owes and no other
/// (P-219, L-204). A `failed` with no reason or a `joined` with no address
/// cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Radio {
    /// Holds no network or no radio metadata, and is not trying.
    Off,
    /// Trying, with no outcome for this version since the comms processor booted.
    Joining,
    /// Associated, at this IPv4 address.
    Joined {
        /// The address the network assigned.
        ipv4: [u8; 4],
    },
    /// Not joined, still trying, and this was the most recent failure.
    Failed {
        /// Why.
        reason: WifiFailure,
    },
}

impl Radio {
    /// The registry's number for this state.
    #[must_use]
    pub const fn state(self) -> WifiState {
        match self {
            Self::Off => WifiState::Off,
            Self::Joining => WifiState::Joining,
            Self::Joined { .. } => WifiState::Joined,
            Self::Failed { .. } => WifiState::Failed,
        }
    }

    const fn keys(self) -> usize {
        match self {
            Self::Off | Self::Joining => 1,
            Self::Joined { .. } | Self::Failed { .. } => 2,
        }
    }

    /// The state and its one dependent field, at `first` and the two keys
    /// after it. The link numbers them from 2 and the client from 3.
    fn encode_into(self, first: i64, cbor: &mut CborWriter<'_>) -> Result<(), WifiError> {
        cbor.key(first)?;
        cbor.u64(self.state() as u64)?;
        match self {
            Self::Off | Self::Joining => {}
            Self::Failed { reason } => {
                cbor.key(first.saturating_add(1))?;
                cbor.u64(reason as u64)?;
            }
            Self::Joined { ipv4 } => {
                cbor.key(first.saturating_add(2))?;
                cbor.bytes(&ipv4)?;
            }
        }
        Ok(())
    }

    fn of(
        state: WifiState,
        reason: Option<WifiFailure>,
        ipv4: Option<&[u8]>,
    ) -> Result<Self, WifiError> {
        let failed = matches!(state, WifiState::Failed);
        let joined = matches!(state, WifiState::Joined);
        if reason.is_some() != failed {
            return Err(WifiError::ReasonDisagrees);
        }
        if ipv4.is_some() != joined {
            return Err(WifiError::AddressDisagrees);
        }
        Ok(match (state, reason, ipv4) {
            (WifiState::Off, _, _) => Self::Off,
            (WifiState::Joining, _, _) => Self::Joining,
            (WifiState::Joined, _, Some(bytes)) => Self::Joined {
                ipv4: <[u8; 4]>::try_from(bytes).map_err(|_| WifiError::Ipv4Length(bytes.len()))?,
            },
            (WifiState::Failed, Some(reason), _) => Self::Failed { reason },
            (WifiState::Joined, _, None) => return Err(WifiError::AddressDisagrees),
            (WifiState::Failed, None, _) => return Err(WifiError::ReasonDisagrees),
        })
    }
}

/// The comms processor's report: which section version the radio is acting on
/// (L-205), and what it is doing with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RadioReport {
    /// The version of the credentials in use; 0 after an unwritten clear.
    pub version: u32,
    /// The state and the field it owes.
    pub radio: Radio,
}

/// The keys one status body can carry, read loosely and checked together.
#[derive(Default)]
struct StatusKeys<'a> {
    section: Option<u32>,
    version: Option<u32>,
    state: Option<WifiState>,
    reason: Option<WifiFailure>,
    ipv4: Option<&'a [u8]>,
}

impl<'a> StatusKeys<'a> {
    /// Read `pairs` keys of a status map whose `version` is at key `first`
    /// and whose state and dependents follow it, with `section` at key 1 when
    /// `first` is 2.
    fn read(cbor: &mut CborReader<'a>, pairs: usize, first: i64) -> Result<Self, WifiError> {
        let mut keys = Self::default();
        for _ in 0..pairs {
            let key = cbor.key()?;
            let at = key.checked_sub(first);
            match (key, at) {
                (1, _) if first == 2 => once(&mut keys.section, WifiField::Section, cbor.u32()?)?,
                (_, Some(0)) => once(&mut keys.version, WifiField::Version, cbor.u32()?)?,
                (_, Some(1)) => {
                    let raw = cbor.u8()?;
                    let known = closed(WifiField::State, raw, WifiState::try_from(raw))?;
                    once(&mut keys.state, WifiField::State, known)?;
                }
                (_, Some(2)) => {
                    let raw = cbor.u8()?;
                    let known = closed(WifiField::Reason, raw, WifiFailure::try_from(raw))?;
                    once(&mut keys.reason, WifiField::Reason, known)?;
                }
                (_, Some(3)) => once(&mut keys.ipv4, WifiField::Ipv4, cbor.bytes()?)?,
                _ => cbor.skip()?,
            }
        }
        Ok(keys)
    }

    fn report(&self) -> Result<Option<RadioReport>, WifiError> {
        match (self.version, self.state) {
            (None, None) => {
                if self.reason.is_some() {
                    return Err(WifiError::ReasonDisagrees);
                }
                if self.ipv4.is_some() {
                    return Err(WifiError::AddressDisagrees);
                }
                Ok(None)
            }
            (Some(version), Some(state)) => Ok(Some(RadioReport {
                version,
                radio: Radio::of(state, self.reason, self.ipv4)?,
            })),
            (Some(_), None) | (None, Some(_)) => Err(WifiError::ReportIncomplete),
        }
    }
}

/// `WifiStatus 0x92`: the section version the controller holds, and the
/// comms processor's latest report from its current boot, if there is one
/// (P-219).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct WifiStatus {
    /// Key 1, the network section's version; 0 when it was never written.
    pub section: u32,
    /// Keys 2 to 5. `None` after link loss or a comms reboot, until the
    /// radio reports again.
    pub report: Option<RadioReport>,
}

impl WifiStatus {
    /// Encode the inner body the wrapper carries.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, WifiError> {
        let mut cbor = CborWriter::new(dst);
        self.encode_into(&mut cbor)?;
        Ok(cbor.finish()?)
    }

    fn encode_into(&self, cbor: &mut CborWriter<'_>) -> Result<(), WifiError> {
        let report_keys = self.report.map_or(0, |report| 1 + report.radio.keys());
        cbor.map(1 + report_keys)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.section))?;
        if let Some(report) = self.report {
            cbor.key(2)?;
            cbor.u64(u64::from(report.version))?;
            report.radio.encode_into(3, cbor)?;
        }
        Ok(())
    }

    /// Read the inner body after the wrapper's tag has verified.
    pub fn decode(payload: &[u8]) -> Result<Self, WifiError> {
        let mut cbor = CborReader::new(payload);
        let pairs = cbor.map()?;
        let keys = StatusKeys::read(&mut cbor, pairs, 2)?;
        cbor.finish()?;
        Ok(Self {
            section: keys.section.ok_or(WifiError::Missing(WifiField::Section))?,
            report: keys.report()?,
        })
    }
}

/// `0x0806 wifi status changed`, carried in `Event 0x04` key 4. The keys of
/// [`WifiStatus`], with the report required: a record says what changed, and
/// the controller writes none while it holds no report (P-220).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct WifiStatusChanged {
    /// Key 1.
    pub section: u32,
    /// Keys 2 to 5.
    pub report: RadioReport,
}

impl WifiStatusChanged {
    /// The registry kind to put beside this body in the event envelope.
    pub const KIND: EventKind = EventKind::WIFI_STATUS_CHANGED;

    /// Encode only the body, for `Event` key 4 or a stored log entry.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, WifiError> {
        WifiStatus {
            section: self.section,
            report: Some(self.report),
        }
        .encode(dst)
    }

    /// Read the body out of an event whose kind is [`Self::KIND`].
    pub fn decode(payload: &[u8]) -> Result<Self, WifiError> {
        let status = WifiStatus::decode(payload)?;
        Ok(Self {
            section: status.section,
            report: status
                .report
                .ok_or(WifiError::Missing(WifiField::Version))?,
        })
    }
}

/// Open a link envelope, mapping a short destination the way every link body does.
fn link_body(header: LinkHeader, keys: usize, dst: &mut [u8]) -> Result<CborWriter<'_>, LinkError> {
    header
        .write(keys, dst)
        .map_err(|_| LinkError::Cbor(CborError::DestinationTooSmall))
}

/// Read a link body's single scan-number key, as `WifiScan 0x6A` and
/// `WifiScanResultAck 0xEB` both carry it.
fn scan_only(envelope: LinkEnvelope<'_>) -> Result<NonZeroU32, LinkError> {
    let pairs = envelope.keys();
    let mut cbor = envelope.into_body();
    let mut scan = None;
    for _ in 0..pairs {
        match cbor.key()? {
            1 => once(&mut scan, WifiField::Scan, scan_number(cbor.u32()?)?)?,
            _ => cbor.skip()?,
        }
    }
    cbor.finish()?;
    Ok(scan.ok_or(WifiError::Missing(WifiField::Scan))?)
}

fn write_scan_only(
    scan: NonZeroU32,
    header: LinkHeader,
    dst: &mut [u8],
) -> Result<usize, LinkError> {
    let mut cbor = link_body(header, 1, dst)?;
    cbor.key(1)?;
    cbor.u64(u64::from(scan.get()))?;
    Ok(cbor.finish()?)
}

/// `WifiScan 0x6A`: the controller asking for one scan, numbered so the result
/// can be told from a late one (L-200).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScanOrder {
    /// Key 1, from 1 in each controller boot.
    pub scan: NonZeroU32,
}

impl ScanOrder {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        write_scan_only(self.scan, header, dst)
    }

    /// # Errors
    /// A missing, repeated or zero scan number, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        Ok(Self {
            scan: scan_only(envelope)?,
        })
    }
}

/// `WifiScanAck 0xEA`: whether the comms processor started the scan (L-200).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScanOrderVerdict {
    /// Key 1. Anything but `started` is a failed scan at the controller (L-203).
    pub outcome: ScanStarted,
}

impl ScanOrderVerdict {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut cbor = link_body(header, 1, dst)?;
        cbor.key(1)?;
        cbor.u64(self.outcome as u64)?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// An outcome this version does not allocate, a key absent or repeated, or
    /// CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut cbor = envelope.into_body();
        let mut outcome = None;
        for _ in 0..pairs {
            match cbor.key()? {
                1 => {
                    let raw = cbor.u8()?;
                    let known = closed(WifiField::Outcome, raw, ScanStarted::try_from(raw))?;
                    once(&mut outcome, WifiField::Outcome, known)?;
                }
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        Ok(Self {
            outcome: outcome.ok_or(WifiError::Missing(WifiField::Outcome))?,
        })
    }
}

/// `WifiScanResult 0x6B`: the one answer to a started scan (L-201). A failed
/// scan carries no list, so it cannot be mistaken for one that heard nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResult<'a> {
    /// Key 1, the `WifiScan` this answers.
    pub scan: NonZeroU32,
    /// Keys 3 and 4 when the scan completed; `None` when it failed.
    pub list: Option<ScanList<'a>>,
}

impl<'a> ScanResult<'a> {
    /// The registry's outcome for this result.
    #[must_use]
    pub const fn outcome(&self) -> ScanOutcomeCode {
        if self.list.is_some() {
            ScanOutcomeCode::Complete
        } else {
            ScanOutcomeCode::Failed
        }
    }

    /// # Errors
    /// `dst` will not hold it, or a row breaks L-202.
    pub fn write(&self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut cbor = link_body(header, if self.list.is_some() { 4 } else { 2 }, dst)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.scan.get()))?;
        cbor.key(2)?;
        cbor.u64(self.outcome() as u64)?;
        if let Some(list) = self.list {
            cbor.key(3)?;
            list.encode_rows(&mut cbor)?;
            cbor.key(4)?;
            cbor.u64(u64::from(list.unlisted))?;
        }
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// A missing or zero scan, an unallocated outcome, a list that disagrees
    /// with the outcome or breaks L-202, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'a>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut cbor = envelope.into_body();
        let (mut scan, mut outcome, mut rows, mut unlisted) = (None, None, None, None);
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(&mut scan, WifiField::Scan, scan_number(cbor.u32()?)?)?,
                2 => {
                    let raw = cbor.u8()?;
                    let known = closed(WifiField::Outcome, raw, ScanOutcomeCode::try_from(raw))?;
                    once(&mut outcome, WifiField::Outcome, known)?;
                }
                3 => once(&mut rows, WifiField::Aps, cbor.raw()?)?,
                4 => once(&mut unlisted, WifiField::Unlisted, cbor.u16()?)?,
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        let scan = scan.ok_or(WifiError::Missing(WifiField::Scan))?;
        let outcome = outcome.ok_or(WifiError::Missing(WifiField::Outcome))?;
        let list = match (outcome, rows, unlisted) {
            (ScanOutcomeCode::Complete, Some(rows), Some(unlisted)) => {
                Some(ScanList::read(rows, unlisted)?)
            }
            (ScanOutcomeCode::Failed, None, None) => None,
            (ScanOutcomeCode::Complete | ScanOutcomeCode::Failed, _, _) => {
                return Err(WifiError::ListIncomplete.into());
            }
        };
        Ok(Self { scan, list })
    }
}

/// `WifiScanResultAck 0xEB`: the controller has the result for this scan, or
/// has discarded it as late (L-203).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ScanResultAck {
    /// Key 1, echoing the result's.
    pub scan: NonZeroU32,
}

impl ScanResultAck {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        write_scan_only(self.scan, header, dst)
    }

    /// # Errors
    /// A missing, repeated or zero scan number, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        Ok(Self {
            scan: scan_only(envelope)?,
        })
    }
}

impl RadioReport {
    /// `WifiState 0x6C`, sent once linked and on every change, one at a time
    /// (L-204, L-206).
    ///
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        let mut cbor = link_body(header, 1 + self.radio.keys(), dst)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.version))?;
        self.radio.encode_into(2, &mut cbor)?;
        Ok(cbor.finish()?)
    }

    /// # Errors
    /// A missing version or state, a reason or address the state does not
    /// own, an unallocated value, or CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut cbor = envelope.into_body();
        let keys = StatusKeys::read(&mut cbor, pairs, 1)?;
        cbor.finish()?;
        Ok(keys
            .report()?
            .ok_or(WifiError::Missing(WifiField::Version))?)
    }
}

/// `WifiStateAck 0xEC`: an empty map. The report is answered, not echoed; the
/// `req_id` is what matches the two (L-013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RadioReportAck;

impl RadioReportAck {
    /// # Errors
    /// `dst` will not hold it.
    pub fn write(self, header: LinkHeader, dst: &mut [u8]) -> Result<usize, LinkError> {
        Ok(link_body(header, 0, dst)?.finish()?)
    }

    /// Keys a newer peer adds are skipped (P-013).
    ///
    /// # Errors
    /// CBOR that will not read.
    pub fn decode(envelope: LinkEnvelope<'_>) -> Result<Self, LinkError> {
        let pairs = envelope.keys();
        let mut cbor = envelope.into_body();
        for _ in 0..pairs {
            cbor.key()?;
            cbor.skip()?;
        }
        cbor.finish()?;
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{
        AP_MAX_BYTES, INNER_BODY_BYTES, MAX_PAYLOAD, SCAN_ANSWER_HEADER_BYTES,
        SCAN_RESULT_HEADER_BYTES, WIFI_STATUS_MAX_BYTES,
    };
    use crate::{Intake, LinkErrorCode, LinkMessageType, ReqId, SessionId, Side, arriving};

    const NAMES: [&str; MAX_SCAN_APS] = [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa7",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa8",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf",
    ];

    fn widest(ssid: &str) -> AccessPoint<'_> {
        AccessPoint {
            ssid,
            rssi: i8::MIN,
            security: WifiSecurity::Wpa3Personal,
            band: WifiBand::Ghz6,
            channel: MAX_CHANNEL,
        }
    }

    fn widest_rows() -> [AccessPoint<'static>; MAX_SCAN_APS] {
        NAMES.map(widest)
    }

    fn row(ssid: &str, rssi: i8) -> AccessPoint<'_> {
        AccessPoint {
            ssid,
            rssi,
            security: WifiSecurity::Wpa2Personal,
            band: WifiBand::Ghz24,
            channel: 6,
        }
    }

    fn header(kind: LinkMessageType) -> LinkHeader {
        LinkHeader {
            kind,
            session: SessionId::None,
            req_id: ReqId(u32::MAX),
        }
    }

    fn envelope(bytes: &[u8]) -> LinkEnvelope<'_> {
        LinkEnvelope::decode(bytes).expect("envelope reads")
    }

    /// The rows written without the list's own checks, so a decoder meets a
    /// list no honest sender builds.
    fn raw_rows<'d>(rows: &[AccessPoint<'_>], dst: &'d mut [u8]) -> &'d [u8] {
        let mut cbor = CborWriter::new(dst);
        cbor.array(rows.len()).expect("header");
        for row in rows {
            row.encode_into(&mut cbor).expect("row");
        }
        let len = cbor.finish().expect("fits");
        dst.get(..len).expect("written")
    }

    /// A `WifiScan 0x91` holding exactly these keys, by number, with the rows
    /// as given.
    fn answer_with(keys: &[i64], rows: &[u8], dst: &mut [u8]) -> usize {
        let mut cbor = CborWriter::new(dst);
        cbor.map(keys.len()).expect("map");
        for &key in keys {
            cbor.key(key).expect("key");
            match key {
                1 => cbor.u64(ScanState::Complete as u64).expect("scan"),
                3 => cbor.u64(5).expect("age"),
                4 => cbor.raw(rows).expect("rows"),
                5 => cbor.u64(0).expect("unlisted"),
                other => panic!("no key {other} in this helper"),
            }
        }
        cbor.finish().expect("fits")
    }

    #[test]
    fn l_202_the_widest_full_list_is_what_the_limits_budget_on_both_hops() {
        let rows = widest_rows();
        let list = ScanList::new(&rows, u16::MAX).expect("sixteen distinct rows");

        let mut one = [0; 64];
        let mut cbor = CborWriter::new(&mut one);
        widest(NAMES[0]).encode_into(&mut cbor).expect("row");
        assert_eq!(cbor.finish(), Ok(AP_MAX_BYTES));

        let answer = ScanAnswer::new(
            ScanState::Complete,
            Some(ScanRefusal::Unauthorised),
            Some(HeldList {
                age_ms: u32::MAX,
                list,
            }),
        )
        .expect("a refusal beside a completed scan");
        let mut body = [0; MAX_PAYLOAD];
        let len = answer.encode(&mut body).expect("fits");
        assert_eq!(len, SCAN_ANSWER_HEADER_BYTES + MAX_SCAN_APS * AP_MAX_BYTES);
        assert!(len <= INNER_BODY_BYTES);

        let result = ScanResult {
            scan: NonZeroU32::MAX,
            list: Some(list),
        };
        let mut frame = [0; MAX_PAYLOAD];
        let len = result
            .write(header(LinkMessageType::WifiScanResult), &mut frame)
            .expect("fits");
        assert_eq!(len, SCAN_RESULT_HEADER_BYTES + MAX_SCAN_APS * AP_MAX_BYTES);

        let status = WifiStatus {
            section: u32::MAX,
            report: Some(RadioReport {
                version: u32::MAX,
                radio: Radio::Joined { ipv4: [255; 4] },
            }),
        };
        let mut body = [0; 64];
        assert_eq!(status.encode(&mut body), Ok(WIFI_STATUS_MAX_BYTES));
    }

    /// A controller relays the comms processor's rows into the client answer.
    /// Re-encoding them there would be a second writer for one list, so the
    /// bytes that arrive are the bytes that leave.
    #[test]
    fn l_202_a_relayed_list_leaves_as_the_bytes_it_arrived_in() {
        let rows = [row("cabin", -40), row("neighbour", -71), row("barn", -71)];
        let result = ScanResult {
            scan: NonZeroU32::MIN,
            list: Some(ScanList::new(&rows, 3).expect("ordered")),
        };
        let mut frame = [0; 256];
        let len = result
            .write(header(LinkMessageType::WifiScanResult), &mut frame)
            .expect("fits");
        let read = ScanResult::decode(envelope(&frame[..len])).expect("reads");
        let relayed = read.list.expect("complete");
        assert_eq!(relayed, ScanList::new(&rows, 3).expect("ordered"));

        let built = ScanAnswer::new(
            ScanState::Complete,
            None,
            Some(HeldList {
                age_ms: 12,
                list: ScanList::new(&rows, 3).expect("ordered"),
            }),
        )
        .expect("valid");
        let relay = ScanAnswer::new(
            ScanState::Complete,
            None,
            Some(HeldList {
                age_ms: 12,
                list: relayed,
            }),
        )
        .expect("valid");
        let (mut a, mut b) = ([0; 256], [0; 256]);
        let a_len = built.encode(&mut a).expect("fits");
        let b_len = relay.encode(&mut b).expect("fits");
        assert_eq!(a.get(..a_len), b.get(..b_len));
        let names: [&str; 3] =
            [0, 1, 2].map(|at| relayed.iter().nth(at).expect("a row").expect("reads").ssid);
        assert_eq!(names, ["cabin", "neighbour", "barn"]);
    }

    #[test]
    fn l_202_one_row_per_ssid_strongest_first_and_no_more_than_the_cap() {
        let weaker_first = [row("cabin", -80), row("barn", -40)];
        let repeated = [row("cabin", -40), row("cabin", -80)];
        let mut seventeen = [row("x", 0); MAX_SCAN_APS + 1];
        for (at, slot) in seventeen.iter_mut().enumerate() {
            *slot = row(NAMES.get(at % MAX_SCAN_APS).expect("a name"), -50);
        }
        assert_eq!(ScanList::new(&weaker_first, 0), Err(WifiError::OutOfOrder));
        assert_eq!(ScanList::new(&repeated, 0), Err(WifiError::SsidRepeated));
        assert_eq!(
            ScanList::new(&seventeen, 0),
            Err(WifiError::TooManyAccessPoints(MAX_SCAN_APS + 1))
        );
        assert!(ScanList::new(&[], 0).expect("heard nothing").is_empty());

        for (rows, error) in [
            (&weaker_first[..], WifiError::OutOfOrder),
            (&repeated[..], WifiError::SsidRepeated),
            (
                &seventeen[..],
                WifiError::TooManyAccessPoints(MAX_SCAN_APS + 1),
            ),
        ] {
            let mut array = [0; 1024];
            let array = raw_rows(rows, &mut array);
            let mut body = [0; 1024];
            let len = answer_with(&[1, 3, 4, 5], array, &mut body);
            assert_eq!(ScanAnswer::decode(&body[..len]), Err(error));
        }
    }

    #[test]
    fn l_202_an_empty_or_long_ssid_a_bad_channel_or_a_wide_rssi_is_refused() {
        let long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(long.len(), MAX_SSID + 1);
        for (ap, error) in [
            (row("", -40), WifiError::SsidLength(0)),
            (row(long, -40), WifiError::SsidLength(MAX_SSID + 1)),
            (
                AccessPoint {
                    channel: 0,
                    ..row("cabin", -40)
                },
                WifiError::ChannelOutOfRange(0),
            ),
            (
                AccessPoint {
                    channel: MAX_CHANNEL + 1,
                    ..row("cabin", -40)
                },
                WifiError::ChannelOutOfRange(MAX_CHANNEL + 1),
            ),
        ] {
            let rows = [ap];
            assert_eq!(ScanList::new(&rows, 0), Err(error));
            let mut cbor_bytes = [0; 128];
            let mut cbor = CborWriter::new(&mut cbor_bytes);
            assert_eq!(ap.encode_into(&mut cbor), Err(error));
        }

        // An rssi a radio cannot report as an i8.
        for (dbm, raw) in [(-129, &[0x38, 0x80][..]), (128, &[0x18, 0x80][..])] {
            let mut body = [0; 64];
            let mut at = 0;
            for byte in [0x81, 0xa5, 1, 0x61, b'x', 2]
                .iter()
                .chain(raw)
                .chain(&[3, 2, 4, 1, 5, 6])
            {
                body[at] = *byte;
                at += 1;
            }
            let mut cbor = CborReader::new(&body[1..at]);
            assert_eq!(
                AccessPoint::decode_from(&mut cbor),
                Err(WifiError::RssiOutOfRange(dbm))
            );
        }
    }

    #[test]
    fn p_217_keys_travel_together_or_not_at_all() {
        let rows = [row("cabin", -40)];
        let mut array = [0; 64];
        let array = raw_rows(&rows, &mut array);
        for keys in [
            &[1, 3][..],
            &[1, 4],
            &[1, 5],
            &[1, 3, 4],
            &[1, 3, 5],
            &[1, 4, 5],
        ] {
            let mut body = [0; 128];
            let len = answer_with(keys, array, &mut body);
            assert_eq!(
                ScanAnswer::decode(&body[..len]),
                Err(WifiError::ListIncomplete),
                "{keys:?}"
            );
        }
        let mut body = [0; 128];
        let len = answer_with(&[1], array, &mut body);
        assert_eq!(
            ScanAnswer::decode(&body[..len]).expect("no list").held(),
            None
        );

        // An empty list is a list: the radio heard nothing, which is not the
        // same body as no list at all.
        let mut empty = [0; 4];
        let empty = raw_rows(&[], &mut empty);
        let len = answer_with(&[1, 3, 4, 5], empty, &mut body);
        let held = ScanAnswer::decode(&body[..len])
            .expect("an empty list")
            .held()
            .expect("held");
        assert!(held.list.is_empty());
        assert_eq!(held.age_ms, 5);
    }

    #[test]
    fn every_scan_answer_round_trips_and_a_running_scan_is_never_refused() {
        let rows = [row("cabin", -40), row("barn", -60)];
        let list = ScanList::new(&rows, 2).expect("ordered");
        let held = Some(HeldList { age_ms: 0, list });
        for (scan, refused, held) in [
            (ScanState::None, None, None),
            (ScanState::None, Some(ScanRefusal::RadioOff), None),
            (ScanState::Running, None, held),
            (ScanState::Complete, Some(ScanRefusal::TooSoon), held),
            (ScanState::Failed, Some(ScanRefusal::LinkDown), held),
            (ScanState::Failed, None, None),
        ] {
            let answer = ScanAnswer::new(scan, refused, held).expect("valid");
            let mut body = [0; 256];
            let len = answer.encode(&mut body).expect("fits");
            assert_eq!(ScanAnswer::decode(&body[..len]), Ok(answer));
        }
        assert_eq!(
            ScanAnswer::new(ScanState::Running, Some(ScanRefusal::TooSoon), None),
            Err(WifiError::RefusedWhileRunning)
        );
        // Running with a refusal, written by hand: the decoder refuses it too.
        let body = [0xa2, 1, ScanState::Running as u8, 2, 1];
        assert_eq!(
            ScanAnswer::decode(&body),
            Err(WifiError::RefusedWhileRunning)
        );
    }

    #[test]
    fn a_scan_request_says_whether_to_scan_or_is_refused() {
        for refresh in [false, true] {
            let mut body = [0; 8];
            let len = ScanRequest { refresh }.encode(&mut body).expect("fits");
            assert_eq!(
                ScanRequest::decode(&body[..len]),
                Ok(ScanRequest { refresh })
            );
        }
        assert_eq!(
            ScanRequest::decode(&[0xa0]),
            Err(WifiError::Missing(WifiField::Refresh))
        );
        assert_eq!(
            ScanRequest::decode(&[0xa2, 1, 0xf5, 1, 0xf4]),
            Err(WifiError::Duplicate(WifiField::Refresh))
        );
        assert!(ScanRequest::decode(&[0xa1, 1, 1]).is_err());
        assert_eq!(
            ScanRequest::decode(&[0xa2, 1, 0xf5, 9, 0]),
            Ok(ScanRequest { refresh: true })
        );
    }

    fn reports() -> [RadioReport; 5] {
        [
            RadioReport {
                version: 0,
                radio: Radio::Off,
            },
            RadioReport {
                version: 3,
                radio: Radio::Joining,
            },
            RadioReport {
                version: 3,
                radio: Radio::Joined {
                    ipv4: [192, 168, 1, 40],
                },
            },
            RadioReport {
                version: 3,
                radio: Radio::Failed {
                    reason: WifiFailure::AuthFailed,
                },
            },
            RadioReport {
                version: u32::MAX,
                radio: Radio::Failed {
                    reason: WifiFailure::Other,
                },
            },
        ]
    }

    #[test]
    fn p_219_keys_present_exactly_as_the_state_owes_them_round_trip() {
        let mut body = [0; 32];
        for section in [0, 4, u32::MAX] {
            let unknown = WifiStatus {
                section,
                report: None,
            };
            let len = unknown.encode(&mut body).expect("fits");
            assert_eq!(WifiStatus::decode(&body[..len]), Ok(unknown));
            for report in reports() {
                let status = WifiStatus {
                    section,
                    report: Some(report),
                };
                let len = status.encode(&mut body).expect("fits");
                assert_eq!(WifiStatus::decode(&body[..len]), Ok(status));
                let record = WifiStatusChanged { section, report };
                assert_eq!(record.encode(&mut body), Ok(len));
                assert_eq!(WifiStatusChanged::decode(&body[..len]), Ok(record));
            }
        }
        assert_eq!(WifiStatusChanged::KIND, EventKind::WIFI_STATUS_CHANGED);
    }

    #[test]
    fn p_219_keys_present_exactly_or_the_body_is_refused() {
        let joined = WifiState::Joined as u8;
        let failed = WifiState::Failed as u8;
        let off = WifiState::Off as u8;
        let cases: &[(&[u8], WifiError)] = &[
            (&[0xa0], WifiError::Missing(WifiField::Section)),
            (&[0xa2, 1, 0, 2, 1], WifiError::ReportIncomplete),
            (&[0xa2, 1, 0, 3, off], WifiError::ReportIncomplete),
            (&[0xa2, 1, 0, 4, 1], WifiError::ReasonDisagrees),
            (
                &[0xa2, 1, 0, 5, 0x44, 1, 2, 3, 4],
                WifiError::AddressDisagrees,
            ),
            (&[0xa3, 1, 0, 2, 1, 3, failed], WifiError::ReasonDisagrees),
            (
                &[0xa4, 1, 0, 2, 1, 3, off, 4, 1],
                WifiError::ReasonDisagrees,
            ),
            (&[0xa3, 1, 0, 2, 1, 3, joined], WifiError::AddressDisagrees),
            // An address beside a state that does not own one is refused, not
            // dropped: a joining radio has no address to report.
            (
                &[
                    0xa4,
                    1,
                    0,
                    2,
                    1,
                    3,
                    WifiState::Joining as u8,
                    5,
                    0x44,
                    1,
                    2,
                    3,
                    4,
                ],
                WifiError::AddressDisagrees,
            ),
            (
                &[0xa5, 1, 0, 2, 1, 3, failed, 4, 1, 5, 0x44, 1, 2, 3, 4],
                WifiError::AddressDisagrees,
            ),
            (
                &[0xa4, 1, 0, 2, 1, 3, failed, 5, 0x44, 1, 2, 3, 4],
                WifiError::ReasonDisagrees,
            ),
            (
                &[0xa4, 1, 0, 2, 1, 3, joined, 5, 0x43, 1, 2, 3],
                WifiError::Ipv4Length(3),
            ),
            (
                &[0xa3, 1, 0, 2, 1, 3, 9],
                WifiError::Unallocated {
                    field: WifiField::State,
                    raw: 9,
                },
            ),
            (
                &[0xa4, 1, 0, 2, 1, 3, failed, 4, 0],
                WifiError::Unallocated {
                    field: WifiField::Reason,
                    raw: 0,
                },
            ),
            (
                &[0xa2, 1, 0, 1, 0],
                WifiError::Duplicate(WifiField::Section),
            ),
        ];
        for (body, error) in cases {
            assert_eq!(WifiStatus::decode(body), Err(*error), "{body:02x?}");
        }
        // The record carries a report or it is not a record.
        assert_eq!(
            WifiStatusChanged::decode(&[0xa1, 1, 0]),
            Err(WifiError::Missing(WifiField::Version))
        );
        // A newer controller's extra key is skipped (P-013).
        assert_eq!(
            WifiStatus::decode(&[0xa2, 1, 7, 6, 0]),
            Ok(WifiStatus {
                section: 7,
                report: None
            })
        );
    }

    #[test]
    fn l_204_reason_and_address_belong_to_their_state_on_the_link_too() {
        for report in reports() {
            let mut frame = [0; 64];
            let len = report
                .write(header(LinkMessageType::WifiState), &mut frame)
                .expect("fits");
            assert_eq!(RadioReport::decode(envelope(&frame[..len])), Ok(report));
        }
        let joined = WifiState::Joined as u8;
        let failed = WifiState::Failed as u8;
        let cases: &[(&[u8], WifiError)] = &[
            (&[0xa0], WifiError::Missing(WifiField::Version)),
            (&[0xa1, 1, 1], WifiError::ReportIncomplete),
            (&[0xa1, 2, 1], WifiError::ReportIncomplete),
            (&[0xa2, 1, 1, 2, failed], WifiError::ReasonDisagrees),
            (&[0xa2, 1, 1, 2, joined], WifiError::AddressDisagrees),
            (
                &[0xa3, 1, 1, 2, WifiState::Joining as u8, 3, 1],
                WifiError::ReasonDisagrees,
            ),
            (
                &[0xa3, 1, 1, 2, WifiState::Off as u8, 4, 0x44, 1, 2, 3, 4],
                WifiError::AddressDisagrees,
            ),
        ];
        for (body, error) in cases {
            let mut frame = [0; 64];
            let head = [0x84, 0x18, LinkMessageType::WifiState as u8, 0, 7];
            frame[..5].copy_from_slice(&head);
            frame[5..5 + body.len()].copy_from_slice(body);
            assert_eq!(
                RadioReport::decode(envelope(&frame[..5 + body.len()])),
                Err(LinkError::Wifi(*error)),
                "{body:02x?}"
            );
        }
    }

    #[test]
    fn l_200_scan_number_is_never_zero_in_an_order_or_an_ack() {
        for kind in [
            LinkMessageType::WifiScan,
            LinkMessageType::WifiScanResultAck,
        ] {
            let mut frame = [0; 16];
            let head = [0x84, 0x18, kind as u8, 0, 7];
            frame[..5].copy_from_slice(&head);
            for (body, error) in [
                (&[0xa1, 1, 0][..], WifiError::ZeroScan),
                (&[0xa0][..], WifiError::Missing(WifiField::Scan)),
                (
                    &[0xa2, 1, 1, 1, 2][..],
                    WifiError::Duplicate(WifiField::Scan),
                ),
            ] {
                frame[5..5 + body.len()].copy_from_slice(body);
                let bytes = &frame[..5 + body.len()];
                let want = Err(LinkError::Wifi(error));
                assert_eq!(ScanOrder::decode(envelope(bytes)).map(|_| ()), want);
                assert_eq!(ScanResultAck::decode(envelope(bytes)).map(|_| ()), want);
            }
        }
        for scan in [NonZeroU32::MIN, NonZeroU32::MAX] {
            let mut frame = [0; 16];
            let len = ScanOrder { scan }
                .write(header(LinkMessageType::WifiScan), &mut frame)
                .expect("fits");
            assert_eq!(
                ScanOrder::decode(envelope(&frame[..len])),
                Ok(ScanOrder { scan })
            );
            let len = ScanResultAck { scan }
                .write(header(LinkMessageType::WifiScanResultAck), &mut frame)
                .expect("fits");
            assert_eq!(
                ScanResultAck::decode(envelope(&frame[..len])),
                Ok(ScanResultAck { scan })
            );
        }
        for outcome in [
            ScanStarted::Started,
            ScanStarted::RefusedBusy,
            ScanStarted::RefusedRadioOff,
        ] {
            let mut frame = [0; 16];
            let verdict = ScanOrderVerdict { outcome };
            let len = verdict
                .write(header(LinkMessageType::WifiScanAck), &mut frame)
                .expect("fits");
            assert_eq!(
                ScanOrderVerdict::decode(envelope(&frame[..len])),
                Ok(verdict)
            );
        }
        let frame = [
            0x84,
            0x18,
            LinkMessageType::WifiScanAck as u8,
            0,
            7,
            0xa1,
            1,
            4,
        ];
        assert_eq!(
            ScanOrderVerdict::decode(envelope(&frame)),
            Err(LinkError::Wifi(WifiError::Unallocated {
                field: WifiField::Outcome,
                raw: 4
            }))
        );
    }

    #[test]
    fn l_201_list_exactly_when_complete() {
        let complete = ScanOutcomeCode::Complete as u8;
        let failed = ScanOutcomeCode::Failed as u8;
        let cases: &[&[u8]] = &[
            &[0xa2, 1, 1, 2, complete],
            &[0xa3, 1, 1, 2, complete, 3, 0x80],
            &[0xa3, 1, 1, 2, complete, 4, 0],
            &[0xa3, 1, 1, 2, failed, 3, 0x80],
            &[0xa3, 1, 1, 2, failed, 4, 0],
            &[0xa4, 1, 1, 2, failed, 3, 0x80, 4, 0],
        ];
        for body in cases {
            let mut frame = [0; 32];
            let head = [0x84, 0x18, LinkMessageType::WifiScanResult as u8, 0, 7];
            frame[..5].copy_from_slice(&head);
            frame[5..5 + body.len()].copy_from_slice(body);
            assert_eq!(
                ScanResult::decode(envelope(&frame[..5 + body.len()])),
                Err(LinkError::Wifi(WifiError::ListIncomplete)),
                "{body:02x?}"
            );
        }
        let failed = ScanResult {
            scan: NonZeroU32::MIN,
            list: None,
        };
        let heard_nothing = ScanResult {
            scan: NonZeroU32::MIN,
            list: Some(ScanList::new(&[], 0).expect("empty")),
        };
        for result in [failed, heard_nothing] {
            let mut frame = [0; 32];
            let len = result
                .write(header(LinkMessageType::WifiScanResult), &mut frame)
                .expect("fits");
            let read = ScanResult::decode(envelope(&frame[..len])).expect("reads");
            assert_eq!(read, result);
        }
        assert_eq!(failed.outcome(), ScanOutcomeCode::Failed);
        assert_eq!(heard_nothing.outcome(), ScanOutcomeCode::Complete);
    }

    #[test]
    fn the_state_ack_is_empty_and_skips_what_a_newer_peer_adds() {
        let mut frame = [0; 16];
        let len = RadioReportAck
            .write(header(LinkMessageType::WifiStateAck), &mut frame)
            .expect("fits");
        assert_eq!(frame.get(len - 1), Some(&0xa0));
        assert_eq!(
            RadioReportAck::decode(envelope(&frame[..len])),
            Ok(RadioReportAck)
        );
        let extra = [
            0x84,
            0x18,
            LinkMessageType::WifiStateAck as u8,
            0,
            7,
            0xa1,
            9,
            1,
        ];
        assert_eq!(RadioReportAck::decode(envelope(&extra)), Ok(RadioReportAck));
    }

    type Writer<'w> = &'w dyn Fn(LinkHeader, &mut [u8]) -> Result<usize, LinkError>;

    #[test]
    fn every_truncation_and_short_destination_is_refused() {
        let rows = [row("cabin", -40), row("barn", -60)];
        let list = ScanList::new(&rows, 1).expect("ordered");
        let mut frames: [([u8; 128], usize, LinkMessageType); 5] =
            [([0; 128], 0, LinkMessageType::WifiScan); 5];
        let scan = NonZeroU32::MAX;
        let writes: [(LinkMessageType, Writer<'_>); 5] = [
            (LinkMessageType::WifiScan, &|h, d| {
                ScanOrder { scan }.write(h, d)
            }),
            (LinkMessageType::WifiScanAck, &|h, d| {
                ScanOrderVerdict {
                    outcome: ScanStarted::RefusedRadioOff,
                }
                .write(h, d)
            }),
            (LinkMessageType::WifiScanResult, &|h, d| {
                ScanResult {
                    scan,
                    list: Some(list),
                }
                .write(h, d)
            }),
            (LinkMessageType::WifiScanResultAck, &|h, d| {
                ScanResultAck { scan }.write(h, d)
            }),
            (LinkMessageType::WifiState, &|h, d| reports()[2].write(h, d)),
        ];
        for ((kind, write), slot) in writes.iter().zip(frames.iter_mut()) {
            slot.1 = write(header(*kind), &mut slot.0).expect("fits");
            slot.2 = *kind;
            for cut in 0..slot.1 {
                let mut short = [0; 128];
                assert!(
                    write(header(*kind), &mut short[..cut]).is_err(),
                    "{kind:?} {cut}"
                );
            }
        }
        for (bytes, len, kind) in &frames {
            for cut in 0..*len {
                let Ok(env) = LinkEnvelope::decode(&bytes[..cut]) else {
                    continue;
                };
                let read = match kind {
                    LinkMessageType::WifiScan => ScanOrder::decode(env).map(|_| ()),
                    LinkMessageType::WifiScanAck => ScanOrderVerdict::decode(env).map(|_| ()),
                    LinkMessageType::WifiScanResult => ScanResult::decode(env).map(|_| ()),
                    LinkMessageType::WifiScanResultAck => ScanResultAck::decode(env).map(|_| ()),
                    LinkMessageType::WifiState => RadioReport::decode(env).map(|_| ()),
                    other => panic!("{other:?} is not written above"),
                };
                assert!(read.is_err(), "{kind:?} cut at {cut}");
            }
        }

        let answer = ScanAnswer::new(
            ScanState::Complete,
            None,
            Some(HeldList { age_ms: 9, list }),
        )
        .expect("valid");
        let status = WifiStatus {
            section: 3,
            report: Some(reports()[3]),
        };
        let mut body = [0; 128];
        let len = answer.encode(&mut body).expect("fits");
        for cut in 0..len {
            assert!(ScanAnswer::decode(&body[..cut]).is_err(), "answer {cut}");
            assert!(answer.encode(&mut [0; 128][..cut]).is_err());
        }
        assert!(
            ScanAnswer::decode(&body[..=len]).is_err(),
            "a trailing byte"
        );
        let len = status.encode(&mut body).expect("fits");
        for cut in 0..len {
            assert!(WifiStatus::decode(&body[..cut]).is_err(), "status {cut}");
            assert!(status.encode(&mut [0; 128][..cut]).is_err());
        }
    }

    #[test]
    fn scan_orders_travel_to_comms_and_reports_travel_to_the_controller() {
        for (kind, receiver) in [
            (LinkMessageType::WifiScan, Side::Comms),
            (LinkMessageType::WifiScanAck, Side::Controller),
            (LinkMessageType::WifiScanResult, Side::Controller),
            (LinkMessageType::WifiScanResultAck, Side::Comms),
            (LinkMessageType::WifiState, Side::Controller),
            (LinkMessageType::WifiStateAck, Side::Comms),
        ] {
            let other = match receiver {
                Side::Comms => Side::Controller,
                Side::Controller => Side::Comms,
            };
            assert_eq!(
                arriving(kind as u8, receiver, SessionId::None),
                Intake::Act(kind)
            );
            assert_eq!(
                arriving(kind as u8, other, SessionId::None),
                Intake::Refuse(LinkErrorCode::WrongSide)
            );
            assert_eq!(
                arriving(kind as u8, receiver, SessionId::from(1)),
                Intake::Refuse(LinkErrorCode::NonZeroSession)
            );
        }
    }
}
