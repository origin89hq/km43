//! The `q` byte, and the rule that there is no slot for a number when there is
//! no number.
//!
//! One byte carries two answers that the old `quality` word ran together:
//! **validity**, which is *is this usable now*, and **provenance**, which is
//! *where did it come from*. Separating them is what makes `counted` **and**
//! `stale` sayable — `0x22`, the case a single word could not express.
//!
//! P-196's invariant is enforced here rather than described: a value key exists
//! exactly when there is a value. Not a zero, not a sentinel, not a last-known
//! reading under a byte that says the sensor is broken. `0xFFFF` at a scale of
//! −2 is 655.35 V, which is a plausible number on a 450 V unit, and every rule
//! downstream — a frost behaviour, an alarm threshold, an aggregate — would act
//! on it.
//!
//! cites: P-185, P-196, P-197, P-198, P-199

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{ErrorCode, Provenance, Validity};
use crate::ident::{Id, IdError};
use crate::limits::{
    MAX_READINGS_BYTES, MAX_SAMPLES, MAX_SELECTORS, MAX_SERIES, MAX_SERIES_LEN, SAMPLE_MAX_BYTES,
    SERIES_MAX_BYTES,
};

/// A reading's two answers in one byte: `validity << 4 | provenance`.
///
/// Named `SignalQuality` and not `Quality` only because the retired five-value
/// `quality` enum still occupies that name until it is withdrawn. It takes the
/// plain word then — there will be one of these, and this is it.
///
/// A newtype rather than a bare `u8` because the two halves are only ever
/// meaningful together, and because the one thing a caller must not be able to
/// do is build a `q` that says there is a number when there is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SignalQuality(u8);

impl SignalQuality {
    /// A reading that carries a number.
    ///
    /// Refuses a validity that has no value to carry, and refuses
    /// [`Provenance::None`], which is what *there is no number* is spelled as.
    /// Both are P-196 in the one direction that publishes a lie.
    pub fn carrying(validity: Validity, provenance: Provenance) -> Result<Self, QualityError> {
        if !Self::has_value(validity) {
            return Err(QualityError::NoValueToCarry(validity));
        }
        if matches!(provenance, Provenance::None) {
            return Err(QualityError::CarryingWithoutProvenance);
        }
        Ok(Self(Self::pack(validity, provenance)))
    }

    /// A reading that carries nothing, because there is nothing to carry.
    ///
    /// Provenance is `0` and not the source it *would* have come from: a
    /// provenance beside no value is a claim about a number nobody has.
    pub fn absent(validity: Validity) -> Result<Self, QualityError> {
        if Self::has_value(validity) {
            return Err(QualityError::ValueOmitted(validity));
        }
        Ok(Self(Self::pack(validity, Provenance::None)))
    }

    /// Whether this `q` says a value key must be present.
    ///
    /// The single place the question is answered, so an encoder and a decoder
    /// cannot disagree about it — which they did once, in a different protocol,
    /// as a snapshot that carried a zero for a probe that was not there.
    #[must_use]
    pub const fn carries_value(self) -> bool {
        Self::has_value(self.validity_of())
    }

    #[must_use]
    /// The wire byte: validity in the high nibble, provenance in the low.
    pub const fn byte(self) -> u8 {
        self.0
    }

    /// Read one off the wire. An unallocated half is refused rather than
    /// rounded to the nearest known one (P-165 does not let a decoder pick).
    pub fn from_byte(raw: u8) -> Result<Self, QualityError> {
        let validity =
            Validity::try_from(raw >> 4).map_err(|()| QualityError::UnknownValidity(raw >> 4))?;
        let provenance = Provenance::try_from(raw & 0x0F)
            .map_err(|()| QualityError::UnknownProvenance(raw & 0x0F))?;
        // The pair has to agree, not just each half on its own: `ok` with
        // provenance 0 says there is a number and names no source for it, and
        // `absent` with `measured` says an instrument read something that is
        // not there.
        if Self::has_value(validity) == matches!(provenance, Provenance::None) {
            return Err(QualityError::Disagree {
                validity,
                provenance,
            });
        }
        Ok(Self(raw))
    }

    #[must_use]
    /// The validity half.
    pub const fn validity_of(self) -> Validity {
        match self.0 >> 4 {
            0x2 => Validity::Stale,
            0x3 => Validity::Initialising,
            0x4 => Validity::Unsupported,
            0x5 => Validity::SensorFault,
            0x6 => Validity::OutOfRange,
            0x7 => Validity::Absent,
            0x8 => Validity::UnnamedState,
            // Only reachable through `from_byte`, which has already refused an
            // unallocated one, or through a constructor that packed it.
            _ => Validity::Ok,
        }
    }

    /// Where the number came from, for a behaviour that will only act on some
    /// sources.
    ///
    /// Read as a **set** and never as a threshold. The numbers are an allocation
    /// order, not a trust order: `5 reported` sits above `4 estimated` and is the
    /// more authoritative of the two — a BMS stating its own charge-current limit
    /// is the best figure on the bus, and a behaviour comparing `>=` would refuse
    /// it while accepting an inference.
    #[must_use]
    pub const fn provenance_of(self) -> Provenance {
        match self.0 & 0x0F {
            0x1 => Provenance::Measured,
            0x2 => Provenance::Counted,
            0x3 => Provenance::Derived,
            0x4 => Provenance::Estimated,
            0x5 => Provenance::Reported,
            0x6 => Provenance::Commanded,
            // Same reasoning as `validity_of`: an unallocated half cannot reach
            // here, because every route in packed it or refused it.
            _ => Provenance::None,
        }
    }

    const fn has_value(validity: Validity) -> bool {
        matches!(validity, Validity::Ok | Validity::Stale)
    }

    const fn pack(validity: Validity, provenance: Provenance) -> u8 {
        ((validity as u8) << 4) | (provenance as u8)
    }
}

/// A scalar reading: one signal, and a value only if there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Sample {
    /// Key 1, the signal.
    pub sig: Id,
    /// Present exactly when `q` says so, which is what `new` will not let a
    /// caller get wrong.
    value: Option<i32>,
    /// Key 3, and what decides whether keys 2 and 4 are present.
    pub q: SignalQuality,
    /// Seconds on P-004's tick. REQUIRED when validity is `stale`.
    age: Option<u32>,
}

impl Sample {
    /// Build one, refusing every shape P-196 forbids.
    ///
    /// The four refusals are the whole point: a value where the `q` says there
    /// is none, no value where it says there is, a `stale` reading with no age,
    /// and an age on a reading that is current. Each has shipped somewhere as a
    /// zero that read as a measurement.
    pub fn new(
        sig: Id,
        q: SignalQuality,
        value: Option<i32>,
        age: Option<u32>,
    ) -> Result<Self, QualityError> {
        match (q.carries_value(), value) {
            (true, None) => return Err(QualityError::ValueOmitted(q.validity_of())),
            (false, Some(_)) => return Err(QualityError::NoValueToCarry(q.validity_of())),
            _ => {}
        }
        let stale = matches!(q.validity_of(), Validity::Stale);
        if stale && age.is_none() {
            return Err(QualityError::StaleWithoutAge);
        }
        if !stale && age.is_some() {
            return Err(QualityError::AgeWithoutStaleness(q.validity_of()));
        }
        Ok(Self { sig, value, q, age })
    }

    #[must_use]
    /// Key 2, present exactly when `q` carries a value.
    pub const fn value(&self) -> Option<i32> {
        self.value
    }

    #[must_use]
    /// Key 4, present exactly when the reading is stale.
    pub const fn age(&self) -> Option<u32> {
        self.age
    }

    /// Keys 1 to 4. Key 2 is written exactly when there is a number, so a
    /// reading with none has no slot a decoder could read a zero out of.
    pub fn encode(&self, cbor: &mut CborWriter<'_>) -> Result<(), CborError> {
        let pairs = 2 + usize::from(self.value.is_some()) + usize::from(self.age.is_some());
        cbor.map(pairs)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.sig.get()))?;
        if let Some(value) = self.value {
            cbor.key(2)?;
            cbor.i32(value)?;
        }
        cbor.key(3)?;
        cbor.u64(u64::from(self.q.byte()))?;
        if let Some(age) = self.age {
            cbor.key(4)?;
            cbor.u64(u64::from(age))?;
        }
        Ok(())
    }

    /// Read one back.
    ///
    /// Every check lives in [`Sample::new`] rather than here, which is the whole
    /// design: the four shapes P-196 forbids — a value where the `q` says there
    /// is none, no value where it says there is, a `stale` reading with no age,
    /// and an age on a reading that is current — are refused on the way in and
    /// on the way out by the same code. A decoder with its own opinion about
    /// them is how an encoder and a decoder come to disagree, which is what put
    /// a zero on a room card for a probe that was not there.
    ///
    /// Written because nothing could read a reading back: a controller could
    /// encode one and a client could count them and learn nothing else.
    pub fn decode(body: &mut CborReader<'_>) -> Result<Self, ReadingsError> {
        let pairs = body.map()?;
        let (mut sig, mut value, mut q, mut age) = (None, None, None, None);
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut sig, 1, Id::new(body.u16()?)?)?,
                2 => once(&mut value, 2, body.i32()?)?,
                3 => once(&mut q, 3, body.u8()?)?,
                4 => once(&mut age, 4, body.u32()?)?,
                // P-013: a key this version has never heard of is skipped, not
                // refused. A v2 controller must reach a v1 client as the reading
                // it is.
                _ => body.skip()?,
            }
        }
        let sig = sig.ok_or(ReadingsError::MissingResponse(1))?;
        let q = SignalQuality::from_byte(q.ok_or(ReadingsError::MissingResponse(3))?)?;
        Self::new(sig, q, value, age).map_err(ReadingsError::from)
    }
}

/// A series reading: `n` elements, each with its own validity, and integers for
/// exactly the ones that have a number.
///
/// **Position is identity here**, which is why an element with no reading is not
/// simply omitted from key 3 — it has no integer anywhere in the message, and
/// key 2's byte at that position says why. One open cell-sense wire blanks one
/// cell and not the other fifteen, and no absent element is a byte that decodes
/// to a plausible voltage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Series<'a> {
    /// Key 1, the signal.
    pub sig: Id,
    q: &'a [SignalQuality],
    values: &'a [i32],
    age: Option<u32>,
}

impl<'a> Series<'a> {
    /// Build one, refusing every length disagreement P-197 makes error 1.
    ///
    /// The counting rule is the whole of it: key 3 holds one integer per element
    /// whose validity carries a value, in ascending element order. Get it wrong
    /// by one and every element after the gap reads the next one's number —
    /// sixteen cells, all plausible, all shifted.
    pub fn new(
        sig: Id,
        q: &'a [SignalQuality],
        values: &'a [i32],
        age: Option<u32>,
    ) -> Result<Self, QualityError> {
        if q.len() < 2 || q.len() > crate::limits::MAX_SERIES_LEN {
            return Err(QualityError::SeriesLength(q.len()));
        }
        let carrying = q.iter().filter(|one| one.carries_value()).count();
        if values.len() != carrying {
            return Err(QualityError::ValueCount {
                want: carrying,
                got: values.len(),
            });
        }
        let stale = q
            .iter()
            .any(|one| matches!(one.validity_of(), Validity::Stale));
        if stale && age.is_none() {
            return Err(QualityError::StaleWithoutAge);
        }
        if !stale && age.is_some() {
            return Err(QualityError::AgeWithoutStaleness(Validity::Ok));
        }
        Ok(Self {
            sig,
            q,
            values,
            age,
        })
    }

    #[must_use]
    /// Elements in the series.
    pub const fn len(&self) -> usize {
        self.q.len()
    }

    #[must_use]
    /// Never, once built: a series is two elements or more.
    pub const fn is_empty(&self) -> bool {
        self.q.is_empty()
    }

    /// The value at one position, or `None` because that element has none.
    ///
    /// Walks the `q` bytes to find how many values precede this position, which
    /// is the same counting the encoder does — one rule, one place, so a reader
    /// and a writer cannot disagree about which integer belongs to which cell.
    #[must_use]
    pub fn value_at(&self, index: usize) -> Option<i32> {
        let here = self.q.get(index)?;
        if !here.carries_value() {
            return None;
        }
        let before = self
            .q
            .get(..index)?
            .iter()
            .filter(|one| one.carries_value())
            .count();
        self.values.get(before).copied()
    }

    /// Check one encoded `Series` against itself, and say which signal it is and
    /// how many elements it has.
    ///
    /// This is P-197 on the side that renders. [`Self::new`] holds the counting
    /// rule for anything this crate builds, and a controller somewhere else does
    /// not have this crate — so a receiver that trusts key 3's length reads
    /// every element after a gap as the next one's number. Sixteen cells, all
    /// plausible, all shifted by one, and the one that matters is the one
    /// somebody drives four hours to replace.
    pub fn check(payload: &[u8]) -> Result<(u16, usize), ReadingsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut sig, mut carrying, mut elements, mut integers, mut age, mut stale) =
            (None, None, None, None, None, false);
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut sig, 1, Id::new(body.u16()?)?.get())?,
                2 => {
                    let bytes = body.bytes()?;
                    let mut with_value = 0usize;
                    for raw in bytes {
                        let q = SignalQuality::from_byte(*raw)?;
                        if q.carries_value() {
                            with_value = with_value.saturating_add(1);
                        }
                        stale |= matches!(q.validity_of(), Validity::Stale);
                    }
                    once(&mut elements, 2, bytes.len())?;
                    carrying = Some(with_value);
                }
                3 => {
                    let n = body.array()?;
                    for _ in 0..n {
                        body.i32()?;
                    }
                    once(&mut integers, 3, n)?;
                }
                4 => once(&mut age, 4, body.u32()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;

        let elements = elements.ok_or(ReadingsError::MissingResponse(2))?;
        let want = carrying.ok_or(ReadingsError::MissingResponse(2))?;
        let got = integers.ok_or(ReadingsError::MissingResponse(3))?;
        if want != got {
            return Err(QualityError::ValueCount { want, got }.into());
        }
        if !(2..=MAX_SERIES_LEN).contains(&elements) {
            return Err(QualityError::SeriesLength(elements).into());
        }
        if stale && age.is_none() {
            return Err(QualityError::StaleWithoutAge.into());
        }
        if !stale && age.is_some() {
            return Err(QualityError::AgeWithoutStaleness(Validity::Ok).into());
        }
        Ok((sig.ok_or(ReadingsError::MissingResponse(1))?, elements))
    }

    /// Keys 1 to 4.
    pub fn encode(&self, cbor: &mut CborWriter<'_>, scratch: &mut [u8]) -> Result<(), CborError> {
        let bytes = scratch
            .get_mut(..self.q.len())
            .ok_or(CborError::DestinationTooSmall)?;
        for (slot, one) in bytes.iter_mut().zip(self.q) {
            *slot = one.byte();
        }
        let pairs = 3 + usize::from(self.age.is_some());
        cbor.map(pairs)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.sig.get()))?;
        cbor.key(2)?;
        cbor.bytes(bytes)?;
        cbor.key(3)?;
        cbor.array(self.values.len())?;
        for value in self.values {
            cbor.i32(*value)?;
        }
        if let Some(age) = self.age {
            cbor.key(4)?;
            cbor.u64(u64::from(age))?;
        }
        Ok(())
    }
}

/// One selector of a `ReadSignals`, naming exactly one thing.
///
/// An enum rather than three `Option<u16>` because *exactly one of the three* is
/// otherwise a check somebody has to remember to run, and error 1 is what the
/// client gets when they forget. A variant cannot hold two, and [`Id`] cannot
/// hold 0 — which is what P-198 says about `cmp` in particular, where the
/// tempting reading of 0 is *the device itself* and the answer is a `dev`
/// selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Sel {
    /// This device and, transitively, every device whose `parent` chain reaches it.
    Dev(Id),
    /// This component and, transitively, every component whose `parent` chain reaches it.
    Cmp(Id),
    /// One signal.
    Sig(Id),
}

impl Sel {
    const fn key(self) -> i64 {
        match self {
            Self::Dev(_) => 1,
            Self::Cmp(_) => 2,
            Self::Sig(_) => 3,
        }
    }

    #[must_use]
    /// The id, whichever of the three things it names.
    pub const fn id(self) -> Id {
        match self {
            Self::Dev(id) | Self::Cmp(id) | Self::Sig(id) => id,
        }
    }

    fn encode(self, cbor: &mut CborWriter<'_>) -> Result<(), CborError> {
        cbor.map(1)?;
        cbor.key(self.key())?;
        cbor.u64(u64::from(self.id().get()))
    }

    fn decode(body: &mut CborReader<'_>) -> Result<Self, ReadingsError> {
        let pairs = body.map()?;
        if pairs != 1 {
            return Err(ReadingsError::SelectorNamesNotOne(pairs));
        }
        let key = body.key()?;
        let id = Id::new(body.u16()?)?;
        match key {
            1 => Ok(Self::Dev(id)),
            2 => Ok(Self::Cmp(id)),
            3 => Ok(Self::Sig(id)),
            other => Err(ReadingsError::UnknownSelectorKey(other)),
        }
    }
}

/// A `ReadSignals 0x0E`: which signals, and where to resume.
///
/// Owns its selectors rather than borrowing them, so decoding does not hand the
/// caller a buffer to keep alive. Twelve of them is [`MAX_SELECTORS`] and a
/// thirteenth is refused rather than dropped — a silently truncated selection
/// answers a question nobody asked, and `total` would agree with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadSignals {
    /// Key 1, the revision the client holds.
    pub rev: u32,
    /// The `sig` to resume at, inclusive. 0 means from the beginning, and is the
    /// one place 0 is legal here because it is a cursor and not an id.
    pub from: u16,
    sel: [Option<Sel>; MAX_SELECTORS],
    used: usize,
}

impl ReadSignals {
    /// Every signal the controller has, from `from` onwards.
    #[must_use]
    pub const fn everything(rev: u32, from: u16) -> Self {
        Self {
            rev,
            from,
            sel: [None; MAX_SELECTORS],
            used: 0,
        }
    }

    /// Narrow the request. Refuses past the cap rather than dropping the last.
    pub fn select(&mut self, sel: Sel) -> Result<(), ReadingsError> {
        let slot = self
            .sel
            .get_mut(self.used)
            .ok_or(ReadingsError::TooManySelectors)?;
        *slot = Some(sel);
        self.used = self.used.saturating_add(1);
        Ok(())
    }

    /// The selectors in the order they were added. Empty means every signal.
    pub fn selectors(&self) -> impl Iterator<Item = Sel> + '_ {
        self.sel.iter().take(self.used).filter_map(|one| *one)
    }

    #[must_use]
    /// No selector, so every signal from `from` onwards.
    pub const fn is_everything(&self) -> bool {
        self.used == 0
    }

    /// Write the body into `dst`; selectors go out in the order they were added.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ReadingsError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(if self.is_everything() { 2 } else { 3 })?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.rev))?;
        if !self.is_everything() {
            cbor.key(2)?;
            cbor.array(self.used)?;
            for sel in self.selectors() {
                sel.encode(&mut cbor)?;
            }
        }
        cbor.key(3)?;
        cbor.u64(u64::from(self.from))?;
        Ok(cbor.finish()?)
    }

    /// Read one back, refusing more selectors than the cap.
    pub fn decode(payload: &[u8]) -> Result<Self, ReadingsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut rev, mut from) = (None, None);
        let mut out = Self::everything(0, 0);
        let mut selectors = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut rev, 1, body.u32()?)?,
                2 => {
                    once(&mut selectors, 2, ())?;
                    let count = body.array()?;
                    if count > MAX_SELECTORS {
                        return Err(ReadingsError::TooManySelectors);
                    }
                    for _ in 0..count {
                        out.select(Sel::decode(&mut body)?)?;
                    }
                }
                3 => once(&mut from, 3, body.u16()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;
        out.rev = rev.ok_or(ReadingsError::MissingRequest(1))?;
        out.from = from.ok_or(ReadingsError::MissingRequest(3))?;
        Ok(out)
    }
}

/// What a `Readings 0x8E` answers. Evaluated in ascending order, first match
/// wins (P-199).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReadingsOutcome {
    /// Answered, in whole or in part.
    Ok,
    /// The `rev` named was neither 0 nor current. Key 2 carries the current one.
    Superseded,
    /// A `Sel` names a `dev`, `cmp` or `sig` that does not exist at this `rev`.
    UnknownSelector,
    /// `from` is greater than the largest `sig` in the resolved selection.
    OutOfRange,
}

impl ReadingsOutcome {
    /// The registry's allocation, through the generated enum, so a renumbered
    /// outcome stops this compiling rather than becoming a second table.
    const fn registered(self) -> crate::generated::Readings {
        match self {
            Self::Ok => crate::generated::Readings::Ok,
            Self::Superseded => crate::generated::Readings::Superseded,
            Self::UnknownSelector => crate::generated::Readings::UnknownSelector,
            Self::OutOfRange => crate::generated::Readings::OutOfRange,
        }
    }

    const fn number(self) -> u8 {
        self.registered() as u8
    }

    fn of(number: u8) -> Option<Self> {
        Some(match crate::generated::Readings::try_from(number).ok()? {
            crate::generated::Readings::Ok => Self::Ok,
            crate::generated::Readings::Superseded => Self::Superseded,
            crate::generated::Readings::UnknownSelector => Self::UnknownSelector,
            crate::generated::Readings::OutOfRange => Self::OutOfRange,
        })
    }
}

/// The most rows one page can hold, whichever kind they are.
const MAX_READINGS_ROWS: usize = MAX_SAMPLES + MAX_SERIES;

/// One encoded row's length and which array it belongs to.
#[derive(Clone, Copy)]
struct Slot {
    len: usize,
    series: bool,
}

/// A page of readings under construction: scalars and series in one byte budget.
///
/// The rows arrive in `sig` ascending order because that is the order P-198
/// fixes, so the two kinds interleave — and they are stored in arrival order in
/// one buffer, then walked twice at encode time to fill key 4 and key 5. One
/// buffer rather than two because the cap is on the **sum**: sizing each kind at
/// its own arm would reserve 1,577 bytes to spend 880 of them.
pub struct ReadingsPage {
    scratch: [u8; MAX_READINGS_BYTES],
    slots: [Slot; MAX_READINGS_ROWS],
    used: usize,
    samples: usize,
    series: usize,
    /// The `sig` to pass back as `from`, or 0 when this page ends the selection.
    next: u16,
}

impl Default for ReadingsPage {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadingsPage {
    #[must_use]
    /// An empty page.
    pub const fn new() -> Self {
        Self {
            scratch: [0u8; MAX_READINGS_BYTES],
            slots: [Slot {
                len: 0,
                series: false,
            }; MAX_READINGS_ROWS],
            used: 0,
            samples: 0,
            series: 0,
            next: 0,
        }
    }

    /// Try to add a scalar reading, and say whether the page took it.
    ///
    /// `Ok(false)` is a full page and not an error: the caller sets `next` to
    /// this signal's `sig` and sends what it has. Both arms are checked — the
    /// row count for this kind, and the shared byte budget — and the byte arm is
    /// measured against what the row actually encoded to rather than its worst
    /// case, which is what lets a page of narrow samples carry more than the
    /// widest-case arithmetic allows.
    pub fn push_sample(&mut self, sample: &Sample) -> Result<bool, ReadingsError> {
        if self.samples >= MAX_SAMPLES {
            self.next = sample.sig.get();
            return Ok(false);
        }
        let mut one = [0u8; SAMPLE_MAX_BYTES];
        let mut cbor = CborWriter::new(&mut one);
        sample.encode(&mut cbor)?;
        let len = cbor.finish()?;
        if !self.keep(&one, len, false)? {
            self.next = sample.sig.get();
            return Ok(false);
        }
        self.samples = self.samples.saturating_add(1);
        Ok(true)
    }

    /// The same for a series, against its own row arm and the shared byte one.
    pub fn push_series(&mut self, series: &Series<'_>) -> Result<bool, ReadingsError> {
        if self.series >= MAX_SERIES {
            self.next = series.sig.get();
            return Ok(false);
        }
        let mut one = [0u8; SERIES_MAX_BYTES];
        let mut q = [0u8; MAX_SERIES_LEN];
        let mut cbor = CborWriter::new(&mut one);
        series.encode(&mut cbor, &mut q)?;
        let len = cbor.finish()?;
        if !self.keep(&one, len, true)? {
            self.next = series.sig.get();
            return Ok(false);
        }
        self.series = self.series.saturating_add(1);
        Ok(true)
    }

    fn keep(&mut self, row: &[u8], len: usize, series: bool) -> Result<bool, ReadingsError> {
        let end = self.used.saturating_add(len);
        let rows = self.samples.saturating_add(self.series);
        if end > MAX_READINGS_BYTES || rows >= MAX_READINGS_ROWS {
            return Ok(false);
        }
        let slot = self
            .scratch
            .get_mut(self.used..end)
            .ok_or(ReadingsError::RowTooLong(len))?;
        let src = row.get(..len).ok_or(ReadingsError::RowTooLong(len))?;
        slot.copy_from_slice(src);
        let record = self
            .slots
            .get_mut(rows)
            .ok_or(ReadingsError::RowTooLong(len))?;
        *record = Slot { len, series };
        self.used = end;
        Ok(true)
    }

    #[must_use]
    /// Scalar readings taken.
    pub const fn samples(&self) -> usize {
        self.samples
    }

    #[must_use]
    /// Series taken.
    pub const fn series(&self) -> usize {
        self.series
    }

    #[must_use]
    /// Bytes the rows occupy.
    pub const fn len(&self) -> usize {
        self.used
    }

    #[must_use]
    /// No row yet.
    pub const fn is_empty(&self) -> bool {
        self.samples == 0 && self.series == 0
    }

    /// The `sig` a client passes back as `from`; 0 when this page ended it.
    #[must_use]
    pub const fn next(&self) -> u16 {
        self.next
    }

    /// Write one of the two arrays, in the order the rows were pushed.
    ///
    /// Walks the slots accumulating an offset, which is how a row's bytes are
    /// found without storing an offset per row. Nothing is re-encoded: each row
    /// goes through [`CborWriter::raw`], which checks it is exactly one
    /// well-formed item and copies it.
    fn encode_array(&self, cbor: &mut CborWriter<'_>, series: bool) -> Result<(), ReadingsError> {
        let count = if series { self.series } else { self.samples };
        cbor.array(count)?;
        let mut at = 0usize;
        for slot in self
            .slots
            .iter()
            .take(self.samples.saturating_add(self.series))
        {
            let end = at.saturating_add(slot.len);
            let row = self
                .scratch
                .get(at..end)
                .ok_or(ReadingsError::RowTooLong(slot.len))?;
            if slot.series == series {
                let mut reader = CborReader::new(row);
                cbor.raw(reader.raw()?)?;
            }
            at = end;
        }
        Ok(())
    }
}

/// A `Readings 0x8E` body.
///
/// No `Debug`: the page it borrows is a kilobyte of encoded rows, and a derived
/// one prints all of it.
#[derive(Clone, Copy)]
pub struct ReadingsBody<'a> {
    /// Key 1, the log position the page is current as of.
    pub seq: u64,
    /// Key 2, the topology revision the signals are read against.
    pub rev: u32,
    /// Omitted when the clock has never been set. Never a zero — a zero here is
    /// 1970 and reads as a timestamp.
    pub at: Option<u64>,
    /// Key 8. Anything but `Ok` carries no rows and no cursor (P-199).
    pub outcome: ReadingsOutcome,
    /// Key 7, the signals the selection resolves to.
    pub total: u16,
    /// Present only on outcome 1. Every other outcome answered nothing (P-199).
    pub page: Option<&'a ReadingsPage>,
}

impl ReadingsBody<'_> {
    /// Encode the body, refusing the shape P-199 forbids rather than writing it.
    ///
    /// `next = 0` is the natural encoding of *nothing follows*, so a response
    /// that answered nothing is otherwise shaped exactly like one that answered
    /// everything — and on outcome 4 the `rev` matches, so nothing else fires.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ReadingsError> {
        let answered = matches!(self.outcome, ReadingsOutcome::Ok);
        if !answered && self.page.is_some_and(|p| !p.is_empty()) {
            return Err(ReadingsError::AnsweredNothing(self.outcome));
        }
        let page = self.page.filter(|_| answered);
        let next = page.map_or(0, ReadingsPage::next);
        let samples = page.is_some_and(|p| p.samples() > 0);
        let series = page.is_some_and(|p| p.series() > 0);

        let pairs = 5 + usize::from(self.at.is_some()) + usize::from(samples) + usize::from(series);
        let mut cbor = CborWriter::new(dst);
        cbor.map(pairs)?;
        cbor.key(1)?;
        cbor.u64(self.seq)?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.rev))?;
        if let Some(at) = self.at {
            cbor.key(3)?;
            cbor.u64(at)?;
        }
        if let Some(page) = page.filter(|_| samples) {
            cbor.key(4)?;
            page.encode_array(&mut cbor, false)?;
        }
        if let Some(page) = page.filter(|_| series) {
            cbor.key(5)?;
            page.encode_array(&mut cbor, true)?;
        }
        cbor.key(6)?;
        cbor.u64(u64::from(next))?;
        cbor.key(7)?;
        cbor.u64(u64::from(self.total))?;
        cbor.key(8)?;
        cbor.u64(u64::from(self.outcome.number()))?;
        Ok(cbor.finish()?)
    }
}

/// What a client reads out of a `Readings 0x8E`, before it looks at the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReadingsHeader {
    /// Key 1, the log position the readings are current as of.
    pub seq: u64,
    /// Key 2, the topology revision they were read against.
    pub rev: u32,
    /// Key 3, absent while the clock has never been set.
    pub at: Option<u64>,
    /// Key 8. Anything but `Ok` answered nothing, and rows or a cursor beside it are refused.
    pub outcome: ReadingsOutcome,
    /// Key 6, the `sig` to resume at; 0 when the selection is complete.
    pub next: u16,
    /// Key 7, how many signals the selection resolves to, across every page.
    pub total: u16,
    /// How many rows key 4 carried.
    pub samples: usize,
    /// How many rows key 5 carried.
    pub series: usize,
}

impl ReadingsHeader {
    /// Read the body, refusing what [`ReadingsBody::encode`] refuses to write.
    ///
    /// A receiver that accepts a page-that-answered-nothing is a receiver that
    /// will render it, which is the half of the rule that decides what somebody
    /// sees at 2 a.m.
    pub fn decode(payload: &[u8]) -> Result<Self, ReadingsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut seq, mut rev, mut at, mut next, mut total, mut outcome) =
            (None, None, None, None, None, None);
        let (mut samples, mut series) = (None, None);
        for _ in 0..pairs {
            match body.key()? {
                1 => once(&mut seq, 1, body.u64()?)?,
                2 => once(&mut rev, 2, body.u32()?)?,
                3 => once(&mut at, 3, body.u64()?)?,
                4 => once(&mut samples, 4, Self::count(&mut body)?)?,
                5 => once(&mut series, 5, Self::count(&mut body)?)?,
                6 => once(&mut next, 6, body.u16()?)?,
                7 => once(&mut total, 7, body.u16()?)?,
                8 => once(&mut outcome, 8, body.u8()?)?,
                _ => body.skip()?,
            }
        }
        body.finish()?;

        let samples = samples.unwrap_or(0);
        let series = series.unwrap_or(0);
        let number = outcome.ok_or(ReadingsError::MissingResponse(8))?;
        let outcome = ReadingsOutcome::of(number).ok_or(ReadingsError::UnknownOutcome(number))?;
        let next = next.ok_or(ReadingsError::MissingResponse(6))?;
        if !matches!(outcome, ReadingsOutcome::Ok) && (next != 0 || samples > 0 || series > 0) {
            return Err(ReadingsError::AnsweredNothing(outcome));
        }
        Ok(Self {
            seq: seq.ok_or(ReadingsError::MissingResponse(1))?,
            rev: rev.ok_or(ReadingsError::MissingResponse(2))?,
            at,
            outcome,
            next,
            total: total.ok_or(ReadingsError::MissingResponse(7))?,
            samples,
            series,
        })
    }

    /// Walk the samples in a body, in the order they were written.
    ///
    /// A callback rather than an iterator because nothing here allocates and a
    /// borrowing iterator over a CBOR cursor buys a lifetime for no gain. The
    /// count comes back so a caller can check it against
    /// [`ReadingsHeader::samples`] — the two disagreeing means the body said one
    /// thing in its header and another in its rows.
    ///
    /// This lives here rather than in a client because a second walk of the same
    /// bytes is a second opinion about them.
    pub fn for_each_sample<F>(payload: &[u8], mut each: F) -> Result<usize, ReadingsError>
    where
        F: FnMut(Sample),
    {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut samples = None;
        for _ in 0..pairs {
            let key = body.key()?;
            if key == 4 {
                once(&mut samples, 4, body.raw()?)?;
            } else {
                body.skip()?;
            }
        }
        body.finish()?;
        let Some(samples) = samples else {
            return Ok(0);
        };
        // Refuse a repeated array before delivering anything to the callback.
        let mut body = CborReader::new(samples);
        let rows = body.array()?;
        for _ in 0..rows {
            each(Sample::decode(&mut body)?);
        }
        Ok(rows)
    }

    fn count(body: &mut CborReader<'_>) -> Result<usize, ReadingsError> {
        let n = body.array()?;
        for _ in 0..n {
            body.skip()?;
        }
        Ok(n)
    }
}

fn once<T>(slot: &mut Option<T>, key: u8, value: T) -> Result<(), ReadingsError> {
    if slot.is_some() {
        return Err(ReadingsError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// Why a `ReadSignals` or a `Readings` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReadingsError {
    /// A recognized key appeared twice (P-015).
    Duplicate(u8),
    /// 0 handed to an id space that reserves it as the paging sentinel.
    ZeroId,
    /// A `Sel` carrying none of the three keys, or two of them.
    SelectorNamesNotOne(usize),
    /// A `Sel` key this version does not allocate.
    UnknownSelectorKey(i64),
    /// More than [`MAX_SELECTORS`]. Refused, never truncated: a silently
    /// shortened selection answers a question nobody asked and `total` agrees
    /// with it.
    TooManySelectors,
    /// A required key of a `ReadSignals` never arrived (P-015).
    MissingRequest(u8),
    /// A required key of a `Readings` never arrived (P-015).
    MissingResponse(u8),
    /// A row longer than the buffer built for its kind, which is a bound in
    /// `limits.rs` being wrong rather than a page to end.
    RowTooLong(usize),
    /// An outcome other than 1 carrying rows or a cursor, which P-199 forbids.
    AnsweredNothing(ReadingsOutcome),
    /// An outcome number this version does not allocate.
    UnknownOutcome(u8),
    /// The reading underneath was refused.
    Quality(QualityError),
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for ReadingsError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<IdError> for ReadingsError {
    /// Restated rather than carried, so a `ReadSignals` refusal reads in one
    /// vocabulary. Matched rather than mapped, so an [`IdError`] that grows a
    /// variant breaks here instead of arriving as the wrong sentence.
    fn from(why: IdError) -> Self {
        match why {
            IdError::Zero => Self::ZeroId,
        }
    }
}

impl From<QualityError> for ReadingsError {
    fn from(why: QualityError) -> Self {
        Self::Quality(why)
    }
}

impl ReadingsError {
    /// What to answer. A row past its byte bound is error 5, as a wrapper too
    /// large to write is; too many selectors is not, because the bytes fit and
    /// it is the shape that is wrong. Everything else is a body whose meaning
    /// cannot be trusted, which is what error 1 says.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::RowTooLong(_) => Refusal::Client(ErrorCode::PayloadTooLarge),
            Self::Quality(why) => why.refusal(),
            Self::Duplicate(_)
            | Self::ZeroId
            | Self::SelectorNamesNotOne(_)
            | Self::UnknownSelectorKey(_)
            | Self::TooManySelectors
            | Self::MissingRequest(_)
            | Self::MissingResponse(_)
            | Self::AnsweredNothing(_)
            | Self::UnknownOutcome(_)
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for ReadingsError {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(k) => write!(w, "a readings map carrying key {k} twice"),
            Self::ZeroId => w.write_str("0 is the end-of-paging sentinel and never an id"),
            Self::SelectorNamesNotOne(n) => {
                write!(w, "a selector naming {n} things, and it names exactly one")
            }
            Self::UnknownSelectorKey(k) => write!(w, "selector key {k} is not allocated"),
            Self::TooManySelectors => {
                write!(w, "more than {MAX_SELECTORS} selectors in one request")
            }
            Self::MissingRequest(k) => write!(w, "a ReadSignals with no key {k}"),
            Self::MissingResponse(k) => write!(w, "a Readings with no key {k}"),
            Self::RowTooLong(n) => write!(w, "a row of {n} bytes, past its own bound"),
            Self::AnsweredNothing(o) => write!(
                w,
                "outcome {} carrying rows or a cursor, and it answered nothing",
                o.number()
            ),
            Self::UnknownOutcome(n) => write!(w, "readings outcome {n} is not allocated"),
            Self::Quality(why) => write!(w, "{why}"),
            Self::Cbor(why) => write!(w, "{why}"),
        }
    }
}

impl core::error::Error for ReadingsError {}

/// Why a reading was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum QualityError {
    /// A validity that carries no number, handed one.
    NoValueToCarry(Validity),
    /// A validity that carries a number, handed none.
    ValueOmitted(Validity),
    /// A number with no source named. `0` is *there is no number*, so it cannot
    /// sit beside one.
    CarryingWithoutProvenance,
    /// `stale` means *this is old*, and how old is the only thing that makes it
    /// usable. Without it a client renders a two-hour-old voltage as current.
    StaleWithoutAge,
    /// An age on a reading that is not stale, which is a duration describing
    /// nothing.
    AgeWithoutStaleness(Validity),
    /// The two halves contradict each other.
    Disagree {
        /// What the reading said about its number.
        validity: Validity,
        /// Where it said the number came from.
        provenance: Provenance,
    },
    /// A validity this version does not allocate.
    UnknownValidity(u8),
    /// A provenance this version does not allocate.
    UnknownProvenance(u8),
    /// A series of no elements, one element, or more than `MAX_SERIES_LEN`.
    SeriesLength(usize),
    /// Key 3 holds a different number of integers than key 2 has elements
    /// carrying values. Off by one and every element after the gap reads the
    /// next one's number.
    ValueCount {
        /// How many elements carry values.
        want: usize,
        /// How many integers key 3 held.
        got: usize,
    },
}

impl QualityError {
    /// What to answer, and it is error 1 for all of them: a reading whose two
    /// halves disagree about whether there is a number is a byte whose meaning
    /// is not knowable, and none of these is a size.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::NoValueToCarry(_)
            | Self::ValueOmitted(_)
            | Self::CarryingWithoutProvenance
            | Self::StaleWithoutAge
            | Self::AgeWithoutStaleness(_)
            | Self::Disagree { .. }
            | Self::UnknownValidity(_)
            | Self::UnknownProvenance(_)
            | Self::SeriesLength(_)
            | Self::ValueCount { .. } => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for QualityError {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoValueToCarry(v) => write!(w, "validity {} carries no number", *v as u8),
            Self::ValueOmitted(v) => write!(w, "validity {} needs a number and had none", *v as u8),
            Self::CarryingWithoutProvenance => {
                w.write_str("a number with provenance 0, which means there is no number")
            }
            Self::StaleWithoutAge => w.write_str("a stale reading with no age"),
            Self::AgeWithoutStaleness(v) => {
                write!(w, "an age on validity {}, which is not stale", *v as u8)
            }
            Self::Disagree {
                validity,
                provenance,
            } => write!(
                w,
                "validity {} and provenance {} disagree about whether there is a number",
                *validity as u8, *provenance as u8
            ),
            Self::UnknownValidity(n) => write!(w, "validity {n} is not allocated"),
            Self::UnknownProvenance(n) => write!(w, "provenance {n} is not allocated"),
            Self::SeriesLength(n) => write!(w, "a series of {n} elements"),
            Self::ValueCount { want, got } => {
                write!(
                    w,
                    "{want} elements carry a value and {got} integers arrived"
                )
            }
        }
    }
}

impl core::error::Error for QualityError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::{ENUM_SPACE_MEMBERS, EnumSpace};
    use crate::render::Rendering;

    /// No two refusals read as one sentence, and each carries the code P-141
    /// leaves for a body that never reached a handler: error 5 for a row past
    /// its byte bound, error 1 for the rest, too many selectors included,
    /// because its bytes fit and it is the shape that is wrong.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [ReadingsError; 13] = [
            ReadingsError::Duplicate(1),
            ReadingsError::ZeroId,
            ReadingsError::SelectorNamesNotOne(2),
            ReadingsError::UnknownSelectorKey(9),
            ReadingsError::TooManySelectors,
            ReadingsError::MissingRequest(1),
            ReadingsError::MissingResponse(2),
            ReadingsError::RowTooLong(300),
            ReadingsError::AnsweredNothing(ReadingsOutcome::OutOfRange),
            ReadingsError::UnknownOutcome(9),
            ReadingsError::Quality(QualityError::StaleWithoutAge),
            ReadingsError::Cbor(CborError::WrongType),
            ReadingsError::Quality(QualityError::CarryingWithoutProvenance),
        ];
        Rendering::<96>::each_says_something_of_its_own(&EVERY);
        for why in EVERY {
            let want = if matches!(why, ReadingsError::RowTooLong(_)) {
                Refusal::Client(ErrorCode::PayloadTooLarge)
            } else {
                Refusal::Client(ErrorCode::MalformedFrame)
            };
            assert_eq!(why.refusal(), want, "{why}");
        }
    }

    /// A reading whose two halves disagree is a byte whose meaning is not
    /// knowable, so every quality refusal is error 1 and none reads as
    /// another. `Disagree` and `CarryingWithoutProvenance` are the pair that
    /// could most easily have shared a sentence.
    #[test]
    fn every_quality_refusal_says_something_of_its_own() {
        const EVERY: [QualityError; 10] = [
            QualityError::NoValueToCarry(Validity::Absent),
            QualityError::ValueOmitted(Validity::Ok),
            QualityError::CarryingWithoutProvenance,
            QualityError::StaleWithoutAge,
            QualityError::AgeWithoutStaleness(Validity::Ok),
            QualityError::Disagree {
                validity: Validity::Absent,
                provenance: Provenance::Measured,
            },
            QualityError::UnknownValidity(9),
            QualityError::UnknownProvenance(9),
            QualityError::SeriesLength(1),
            QualityError::ValueCount { want: 3, got: 2 },
        ];
        Rendering::<96>::each_says_something_of_its_own(&EVERY);
        for why in EVERY {
            assert_eq!(
                why.refusal(),
                Refusal::Client(ErrorCode::MalformedFrame),
                "{why}"
            );
        }
    }

    fn id(value: u16) -> Id {
        Id::new(value).expect("a non-zero id")
    }

    /// **A set that names nothing is not the same as a value that is not in
    /// it**, and a caller that cannot tell them apart sends somebody to the
    /// wrong place.
    ///
    /// A device reporting charge stage 9 against a space this build knows is a
    /// charger running newer firmware — surfaced, never mapped onto the nearest
    /// stage. A signal drawn from a space with *no members at all* is a
    /// registry entry somebody left half written: it reads `unnamed_state` at
    /// every poll forever, and the fix is in a config file rather than in a
    /// cabinet. `members()` answers `None` for the second so the two can be
    /// told apart; `names()` collapses both to false, which is why the caller
    /// that cares asks the first.
    #[test]
    fn a_space_that_names_nothing_is_told_from_a_value_that_is_not_named() {
        // Allocated with members, by the registry's own table.
        assert_eq!(
            EnumSpace::GENERATOR_STATE.members(),
            Some([1, 2, 3, 4, 5, 6].as_slice())
        );
        assert!(EnumSpace::GENERATOR_STATE.names(3));
        assert!(
            !EnumSpace::GENERATOR_STATE.names(9),
            "a state this build has not heard of is not named"
        );

        // Allocated, reserved, and empty on purpose — the design has not
        // settled what a charge stage is. `None` is what says so.
        assert_eq!(
            EnumSpace::CHARGE_STAGE.members(),
            None,
            "a reserved space with no member table names nothing, and says which"
        );
        assert!(!EnumSpace::CHARGE_STAGE.names(3));

        // A space nobody allocated at all answers the same way, which is the
        // honest answer: this build cannot name anything in it either.
        assert_eq!(EnumSpace(0xF001).members(), None);
    }

    /// **The table is bisected, so it has to be sorted — on both axes.**
    ///
    /// `binary_search` on an unsorted slice does not fail loudly, it returns
    /// `Err` for something that is present. A member would silently stop being
    /// named, and a healthy generator would start reporting `unnamed_state`
    /// for `running`.
    #[test]
    fn the_member_table_is_sorted_or_the_bisect_lies() {
        // Checked by walking neighbours rather than by sorting a copy: there is
        // no allocator on the target and none in these tests either, so the two
        // cannot disagree about what the code under test is allowed to do.
        assert!(
            ENUM_SPACE_MEMBERS.windows(2).all(|pair| match pair {
                [(before, _), (after, _)] => before < after,
                _ => true,
            }),
            "spaces are bisected by id, so they ascend and never repeat"
        );

        for &(space, members) in ENUM_SPACE_MEMBERS {
            assert!(
                members.windows(2).all(|pair| match pair {
                    [before, after] => before < after,
                    _ => true,
                }),
                "space {space:#06x}'s members are bisected too"
            );
            assert!(
                !members.is_empty(),
                "space {space:#06x} is present and empty, which is the one state \
                 `members()` cannot report"
            );
        }
    }

    /// **The rule, and the number it exists to stop.** `0xFFFF` at the
    /// registry's scale of −2 is 655.35 V — a plausible reading on a 450 V unit,
    /// well formed, on time, and indistinguishable from a measurement by
    /// anything downstream. A validity that says the unit does not have this
    /// register cannot carry it, so the encoder has no slot to put it in.
    #[test]
    fn p_196_a_validity_that_carries_no_number_cannot_be_handed_one() {
        for validity in [
            Validity::Unsupported,
            Validity::SensorFault,
            Validity::OutOfRange,
            Validity::Absent,
            Validity::UnnamedState,
            Validity::Initialising,
        ] {
            let q = SignalQuality::absent(validity).expect("carries nothing");
            assert!(!q.carries_value());
            assert_eq!(
                Sample::new(id(1), q, Some(65535), None).unwrap_err(),
                QualityError::NoValueToCarry(validity),
                "validity {} was handed 0xFFFF and took it",
                validity as u8
            );
        }
    }

    /// The other direction: a validity that means *there is a number here* must
    /// have one. A decoder that filled the gap would be inventing a reading.
    #[test]
    fn p_196_a_validity_that_needs_a_number_cannot_go_without_one() {
        let q = SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("legal");
        assert_eq!(
            Sample::new(id(1), q, None, None).unwrap_err(),
            QualityError::ValueOmitted(Validity::Ok)
        );
    }

    /// `counted` **and** `stale` is `0x22` — the case one word could not say,
    /// and the reason the byte carries two answers rather than one.
    #[test]
    fn p_196_counted_and_stale_is_one_byte_and_says_both() {
        let q = SignalQuality::carrying(Validity::Stale, Provenance::Counted).expect("legal");
        assert_eq!(q.byte(), 0x22);
        assert_eq!(q.validity_of(), Validity::Stale);
        assert!(q.carries_value(), "stale carries the last known value");
    }

    /// `stale` means *this is old*, and how old is what makes it usable. A
    /// client with no age renders a two-hour-old cell voltage as current, and a
    /// balancing decision is made on it.
    #[test]
    fn p_196_a_stale_reading_without_an_age_is_refused() {
        let q = SignalQuality::carrying(Validity::Stale, Provenance::Measured).expect("legal");
        assert_eq!(
            Sample::new(id(1), q, Some(3900), None).unwrap_err(),
            QualityError::StaleWithoutAge
        );
        assert!(Sample::new(id(1), q, Some(3900), Some(7200)).is_ok());
    }

    /// An age on a reading that is current is a duration describing nothing, and
    /// a client that renders it shows a fresh value as two hours old.
    #[test]
    fn p_196_an_age_on_a_current_reading_is_refused() {
        let q = SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("legal");
        assert_eq!(
            Sample::new(id(1), q, Some(24800), Some(8)).unwrap_err(),
            QualityError::AgeWithoutStaleness(Validity::Ok)
        );
    }

    /// Each half legal and the pair not. `ok` with provenance 0 says there is a
    /// number and names no source; `absent` with `measured` says an instrument
    /// read something that is not there.
    #[test]
    fn p_196_the_two_halves_must_agree_and_not_merely_each_be_allocated() {
        assert_eq!(
            SignalQuality::from_byte(0x10).unwrap_err(),
            QualityError::Disagree {
                validity: Validity::Ok,
                provenance: Provenance::None,
            },
            "ok with no source"
        );
        assert_eq!(
            SignalQuality::from_byte(0x71).unwrap_err(),
            QualityError::Disagree {
                validity: Validity::Absent,
                provenance: Provenance::Measured,
            },
            "absent, measured"
        );
        assert!(SignalQuality::from_byte(0x22).is_ok(), "counted and stale");
    }

    /// An unallocated half is refused rather than rounded to the nearest known
    /// one. P-165 surfaces an unrecognised value; it does not let a decoder pick.
    #[test]
    fn p_196_an_unallocated_half_is_refused_rather_than_rounded() {
        assert_eq!(
            SignalQuality::from_byte(0x91).unwrap_err(),
            QualityError::UnknownValidity(9)
        );
        assert_eq!(
            SignalQuality::from_byte(0x1F).unwrap_err(),
            QualityError::UnknownProvenance(0xF)
        );
    }

    /// **The encoded bytes carry no integer a reader could take for the
    /// reading.** Not "key 2 is absent" — the actual bytes, checked for the
    /// number, because the failure this guards is a value arriving in a slot
    /// nobody meant to leave open.
    #[test]
    fn p_196_an_absent_reading_encodes_no_integer_that_could_be_read_as_one() {
        let q = SignalQuality::absent(Validity::Unsupported).expect("carries nothing");
        let sample = Sample::new(id(0x0101), q, None, None).expect("legal");

        let mut dst = [0u8; 32];
        let mut cbor = CborWriter::new(&mut dst);
        sample.encode(&mut cbor).expect("encodes");
        let len = cbor.finish().expect("finished");
        let bytes = dst.get(..len).expect("encoded");

        // `{1: 257, 3: 0x40}` — three keys would be four bytes longer, and the
        // sentinel's own bytes appear nowhere.
        assert_eq!(bytes, &[0xA2, 0x01, 0x19, 0x01, 0x01, 0x03, 0x18, 0x40]);
        assert!(
            !bytes.windows(2).any(|w| w == [0xFF, 0xFF]),
            "0xFFFF reached the wire"
        );
        assert!(
            !bytes.contains(&0x02),
            "key 2 is not in a body that has no number"
        );
    }
    /// A signal id of 0 is the paging sentinel and never a signal (P-208), and
    /// `Sample.sig` was a bare `u16`. A bounced sig-0 row set `next` to 0, which
    /// the wire reads as *the selection is complete*.
    #[test]
    fn a_sample_naming_signal_zero_is_refused_where_it_is_read() {
        let mut dst = [0u8; 16];
        let mut cbor = CborWriter::new(&mut dst);
        cbor.map(2).expect("a map");
        cbor.key(1).expect("key");
        cbor.u64(0).expect("sig 0");
        cbor.key(3).expect("key");
        let nothing = SignalQuality::absent(Validity::Absent).expect("nothing to carry");
        cbor.u64(u64::from(nothing.byte())).expect("q");
        let len = cbor.finish().expect("a body");
        assert_eq!(
            Sample::decode(&mut CborReader::new(dst.get(..len).expect("the body"))),
            Err(ReadingsError::ZeroId)
        );
        assert_eq!(
            Id::new(0).err(),
            Some(IdError::Zero),
            "and it cannot be built either"
        );
    }

    /// Every strict prefix is refused, and only the whole body reads.
    fn refused_at_every_cut<T: core::fmt::Debug>(
        bytes: &[u8],
        decode: impl Fn(&[u8]) -> Result<T, ReadingsError>,
    ) {
        for cut in 0..bytes.len() {
            assert!(
                decode(bytes.get(..cut).expect("a prefix")).is_err(),
                "a prefix of {cut} bytes decoded"
            );
        }
        assert!(
            decode(bytes).is_ok(),
            "the whole body must decode, or the loop proves nothing"
        );
    }

    /// The four readings decoders had no truncation test between them. A
    /// resynchronising receiver hands every one of these arbitrary prefixes.
    #[test]
    fn every_readings_body_cut_short_at_any_byte_is_refused() {
        let mut out = [0u8; MAX_READINGS_BYTES + 64];

        let len = ReadSignals::everything(41, 7)
            .encode(&mut out)
            .expect("encodes");
        refused_at_every_cut(out.get(..len).expect("the body"), ReadSignals::decode);

        let page = ReadingsPage::new();
        let len = ReadingsBody {
            seq: 9,
            rev: 41,
            at: None,
            outcome: ReadingsOutcome::Ok,
            total: 0,
            page: Some(&page),
        }
        .encode(&mut out)
        .expect("encodes");
        refused_at_every_cut(out.get(..len).expect("the body"), ReadingsHeader::decode);

        let measured =
            SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("a reading");
        let nothing = SignalQuality::absent(Validity::Absent).expect("nothing to carry");
        let q = [measured, nothing];
        let series = Series::new(id(0x0101), &q, &[24800], None).expect("legal");
        let mut scratch = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        series.encode(&mut cbor, &mut scratch).expect("encodes");
        let len = cbor.finish().expect("a body");
        refused_at_every_cut(out.get(..len).expect("the body"), Series::check);

        let sample = Sample::new(id(3), measured, Some(30), None).expect("legal");
        let mut cbor = CborWriter::new(&mut out);
        sample.encode(&mut cbor).expect("encodes");
        let len = cbor.finish().expect("a body");
        refused_at_every_cut(out.get(..len).expect("the body"), |bytes| {
            Sample::decode(&mut CborReader::new(bytes))
        });
    }
}

#[cfg(test)]
mod series_tests {
    use super::*;

    fn id(value: u16) -> Id {
        Id::new(value).expect("a non-zero id")
    }

    fn ok() -> SignalQuality {
        SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("legal")
    }

    fn broken() -> SignalQuality {
        SignalQuality::absent(Validity::SensorFault).expect("carries nothing")
    }

    /// **One open sense wire blanks one cell.** Fifteen good readings survive,
    /// and the bad one has no integer anywhere in the message rather than a
    /// placeholder somebody's balancing decision would act on.
    #[test]
    fn p_197_one_bad_element_does_not_blank_the_other_fifteen() {
        let mut q = [ok(); 16];
        q[2] = broken();
        let values: [i32; 15] = [3900; 15];
        let series = Series::new(id(7), &q, &values, None).expect("legal");

        assert_eq!(series.len(), 16);
        assert_eq!(series.value_at(2), None, "the open wire");
        for index in (0..16).filter(|i| *i != 2) {
            assert_eq!(series.value_at(index), Some(3900), "cell {index}");
        }
    }

    /// The counting rule, from the other side: `value_at` walks the same bytes
    /// the encoder counted, so a reader and a writer cannot disagree about which
    /// integer belongs to which cell.
    #[test]
    fn p_197_a_value_belongs_to_the_element_whose_byte_earned_it() {
        let q = [broken(), ok(), broken(), ok()];
        let values = [111, 222];
        let series = Series::new(id(7), &q, &values, None).expect("legal");
        assert_eq!(series.value_at(0), None);
        assert_eq!(series.value_at(1), Some(111));
        assert_eq!(series.value_at(2), None);
        assert_eq!(series.value_at(3), Some(222), "not 111 shifted along");
    }

    /// Off by one is refused rather than encoded. Every element after the gap
    /// would otherwise read the next one's number — sixteen cells, all
    /// plausible, all shifted, and the wrong one gets replaced.
    #[test]
    fn p_197_a_value_count_that_disagrees_with_the_bytes_is_refused() {
        let q = [ok(), broken(), ok()];
        assert_eq!(
            Series::new(id(7), &q, &[1, 2, 3], None).unwrap_err(),
            QualityError::ValueCount { want: 2, got: 3 }
        );
        assert_eq!(
            Series::new(id(7), &q, &[1], None).unwrap_err(),
            QualityError::ValueCount { want: 2, got: 1 }
        );
        assert!(Series::new(id(7), &q, &[1, 2], None).is_ok());
    }

    /// A series is two or more elements and never longer than the cap a decoder
    /// sized its array at before a byte arrived.
    #[test]
    fn p_197_a_series_outside_its_bounds_is_refused() {
        let one = [ok()];
        assert_eq!(
            Series::new(id(7), &one, &[1], None).unwrap_err(),
            QualityError::SeriesLength(1)
        );
        let too_many = [ok(); crate::limits::MAX_SERIES_LEN + 1];
        let values = [1i32; crate::limits::MAX_SERIES_LEN + 1];
        assert_eq!(
            Series::new(id(7), &too_many, &values, None).unwrap_err(),
            QualityError::SeriesLength(crate::limits::MAX_SERIES_LEN + 1)
        );
    }

    /// **The bytes, not the fields.** Key 2 is `n` bytes whatever happens to the
    /// values, and key 3 is shorter than key 2 exactly when an element has no
    /// reading — so the gap is visible on the wire rather than inferred.
    #[test]
    fn p_197_the_encoded_series_has_one_q_byte_per_element_and_no_placeholder() {
        let q = [ok(), broken(), ok()];
        let series = Series::new(id(0x0101), &q, &[24800, 24900], None).expect("legal");

        let mut scratch = [0u8; 16];
        let mut dst = [0u8; 64];
        let mut cbor = CborWriter::new(&mut dst);
        series.encode(&mut cbor, &mut scratch).expect("encodes");
        let len = cbor.finish().expect("finished");
        let bytes = dst.get(..len).expect("encoded");

        // `{1: 257, 2: h'115011', 3: [24800, 24900]}` — three q bytes for three
        // elements, two integers for the two that have one.
        assert_eq!(
            bytes.get(..9),
            Some(&[0xA3, 0x01, 0x19, 0x01, 0x01, 0x02, 0x43, 0x11, 0x50][..]),
            "key 2 is a three-byte string and the middle element is 0x50"
        );
        assert!(
            bytes.windows(2).any(|w| w == [0x03, 0x82]),
            "key 3 is an array of two, not of three"
        );
    }

    /// **An unrecognised validity costs the whole series, and it has to.**
    ///
    /// This is the one place P-165's *surface that one row and do not
    /// invalidate the message* cannot be met at element granularity, and the
    /// reason is P-197's own encoding. Key 3 holds one integer per element whose
    /// validity carries a value, and [`Series::value_at`] finds an element's
    /// integer by counting the carriers **before** it. A validity this build
    /// cannot name is a validity it cannot ask `carries_value` about — so it
    /// cannot know whether that element consumed an integer, and being wrong by
    /// one shifts every remaining cell onto its neighbour's number.
    ///
    /// Sixteen cells, all plausible, all off by one, and the one that matters is
    /// the one somebody drives four hours to replace. Refusing the row is the
    /// honest answer and the page around it is untouched — which is what P-165
    /// means by *that one row* for a series, and why its validity clause is
    /// amended in `TOPOLOGY-DESIGN.md` rather than implemented as written.
    #[test]
    fn p_197_an_unnameable_validity_costs_the_row_because_the_rest_cannot_be_located() {
        let q = [ok(), broken(), ok()];
        let series = Series::new(id(0x0101), &q, &[24800, 24900], None).expect("legal");

        let mut scratch = [0u8; 16];
        let mut dst = [0u8; 64];
        let mut cbor = CborWriter::new(&mut dst);
        series.encode(&mut cbor, &mut scratch).expect("encodes");
        let len = cbor.finish().expect("finished");
        let mut bytes = [0u8; 64];
        bytes
            .get_mut(..len)
            .expect("room")
            .copy_from_slice(dst.get(..len).expect("encoded"));

        // As published, it checks out: three elements, two integers.
        assert_eq!(
            Series::check(bytes.get(..len).expect("encoded")),
            Ok((0x0101, 3)),
            "the fixture must check out before it is broken, or this proves nothing"
        );

        // Now a controller a version newer sends validity 9 on the middle
        // element. The `q` string is at a known offset from the assertion in
        // `p_197_the_encoded_series_has_one_q_byte_per_element_and_no_placeholder`.
        let at = bytes
            .get(..len)
            .expect("encoded")
            .windows(3)
            .position(|w| w == [0x43, 0x11, 0x50])
            .expect("the three-byte q string")
            .saturating_add(2);
        *bytes.get_mut(at).expect("the middle q byte") = 0x91;

        assert_eq!(
            Series::check(bytes.get(..len).expect("encoded")),
            Err(ReadingsError::Quality(QualityError::UnknownValidity(9))),
            "an unnameable validity was accepted, and every integer after it is now \
             attributed to the wrong cell"
        );
    }

    /// P-179: one age describes the oldest stale element, and a series with none
    /// carries no age at all.
    #[test]
    fn p_197_an_age_rides_a_series_exactly_when_an_element_is_stale() {
        let fresh = [ok(), ok()];
        assert_eq!(
            Series::new(id(7), &fresh, &[1, 2], Some(8)).unwrap_err(),
            QualityError::AgeWithoutStaleness(Validity::Ok)
        );

        let stale = SignalQuality::carrying(Validity::Stale, Provenance::Measured).expect("legal");
        let mixed = [ok(), stale];
        assert_eq!(
            Series::new(id(7), &mixed, &[1, 2], None).unwrap_err(),
            QualityError::StaleWithoutAge
        );
        assert!(
            Series::new(id(7), &mixed, &[1, 2], Some(7200)).is_ok(),
            "the oldest stale element's age, and the fresh one keeps its own value"
        );
    }
}

#[cfg(test)]
mod selection {
    use super::{Id, IdError, ReadSignals, ReadingsError, Sel};
    use crate::limits::MAX_SELECTORS;

    fn id(v: u16) -> Id {
        Id::new(v).expect("a non-zero id")
    }

    /// A driver that allocates `sig = 0` makes `next = 0` unreadable: a client
    /// cannot tell *resume at signal 0* from *the selection is complete*, so it
    /// either stops a page early or loops on page one for ever. The id space
    /// refuses 0 rather than every reader having to know.
    #[test]
    fn p_198_zero_is_the_paging_sentinel_and_never_an_id() {
        assert_eq!(Id::new(0), Err(IdError::Zero));
        assert_eq!(id(1).get(), 1);
    }

    /// `cmp = 0` reads as *the device itself* to anybody who has not read the
    /// rule, and device scope is a `dev` selector. Two encoders disagreeing
    /// about it is two dashboards showing different sets of signals for one
    /// request.
    #[test]
    fn p_198_a_component_selector_cannot_mean_the_whole_device() {
        // There is no `Sel::Cmp(0)` to build: the id refuses first, so the rule
        // is the type rather than a check at the far end of the wire.
        assert_eq!(Id::new(0), Err(IdError::Zero));
        assert_eq!(Sel::Cmp(id(4)).id().get(), 4);

        // And a 0 that arrives anyway is refused on the way in.
        // {1:rev=41, 2:[{2:cmp=0}], 3:from=0}
        let body = [
            0xA3, 0x01, 0x18, 0x29, 0x02, 0x81, 0xA1, 0x02, 0x00, 0x03, 0x00,
        ];
        assert_eq!(ReadSignals::decode(&body), Err(ReadingsError::ZeroId));
    }

    /// A thirteenth selector dropped instead of refused answers a narrower
    /// question than the one asked, and `total` agrees with the narrower one —
    /// so nothing downstream can tell.
    #[test]
    fn p_198_a_selector_past_the_cap_is_refused_and_not_dropped() {
        let mut req = ReadSignals::everything(41, 0);
        for n in 1..=MAX_SELECTORS {
            let n = u16::try_from(n).expect("the cap fits a u16");
            req.select(Sel::Sig(id(n))).expect("under the cap");
        }
        assert_eq!(
            req.select(Sel::Sig(id(99))),
            Err(ReadingsError::TooManySelectors)
        );
        assert_eq!(req.selectors().count(), MAX_SELECTORS);
    }

    #[test]
    fn p_198_a_request_survives_the_round_trip_with_its_selectors_in_order() {
        let mut req = ReadSignals::everything(41, 7);
        req.select(Sel::Dev(id(3))).expect("room");
        req.select(Sel::Cmp(id(9))).expect("room");
        req.select(Sel::Sig(id(21))).expect("room");

        let mut buf = [0u8; 128];
        let len = req.encode(&mut buf).expect("a request encodes");
        let back =
            ReadSignals::decode(buf.get(..len).expect("the written prefix")).expect("and decodes");

        assert_eq!(back.rev, 41);
        assert_eq!(back.from, 7);
        let want = [Sel::Dev(id(3)), Sel::Cmp(id(9)), Sel::Sig(id(21))];
        assert_eq!(back.selectors().count(), want.len());
        for (got, want) in back.selectors().zip(want) {
            assert_eq!(got, want);
        }
    }

    /// *Every signal* is the request a fresh client makes, and it is key 2
    /// absent rather than an empty array — an empty array of selectors resolves
    /// to nothing, which is the opposite answer.
    #[test]
    fn p_198_no_selectors_means_every_signal_and_not_none() {
        let req = ReadSignals::everything(41, 0);
        assert!(req.is_everything());

        let mut buf = [0u8; 32];
        let len = req.encode(&mut buf).expect("encodes");
        let bytes = buf.get(..len).expect("the written prefix");
        assert_eq!(
            bytes.first(),
            Some(&0xA2),
            "an empty selection wrote a key 2 that resolves to nothing"
        );

        let back = ReadSignals::decode(bytes).expect("decodes");
        assert!(back.is_everything());
    }

    /// A `Sel` carrying two of the three keys is two questions in one selector,
    /// and a receiver that picks one is a receiver answering a request nobody
    /// sent. It is error 1.
    #[test]
    fn p_198_a_selector_naming_two_things_is_refused() {
        // {1:rev=41, 2:[{1:dev=3, 3:sig=9}], 3:from=0}
        let body = [
            0xA3, 0x01, 0x18, 0x29, 0x02, 0x81, 0xA2, 0x01, 0x03, 0x03, 0x09, 0x03, 0x00,
        ];
        assert_eq!(
            ReadSignals::decode(&body),
            Err(ReadingsError::SelectorNamesNotOne(2))
        );
    }
}

#[cfg(test)]
mod page {
    use super::{
        Id, ReadingsBody, ReadingsError, ReadingsHeader, ReadingsOutcome, ReadingsPage, Sample,
        Series, SignalQuality,
    };

    fn id(value: u16) -> Id {
        Id::new(value).expect("a non-zero id")
    }
    use crate::cbor::{CborError, CborReader, CborWriter};
    use crate::generated::{Provenance, Validity};
    use crate::limits::{MAX_READINGS_BYTES, MAX_SAMPLES, MAX_SERIES, MAX_SERIES_LEN};

    fn ok() -> SignalQuality {
        SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("carries a number")
    }

    fn broken() -> SignalQuality {
        SignalQuality::absent(Validity::SensorFault).expect("carries nothing")
    }

    fn sample(sig: u16, value: i32) -> Sample {
        Sample::new(id(sig), ok(), Some(value), None).expect("a plain reading")
    }

    fn page_of(samples: &[Sample]) -> ReadingsPage {
        let mut page = ReadingsPage::new();
        for one in samples {
            assert!(
                page.push_sample(one).expect("a sample encodes"),
                "page full"
            );
        }
        page
    }

    /// The two kinds interleave in `sig` order, because P-198 orders the whole
    /// selection by `sig` and a page is a prefix of that order. They still have
    /// to come out under key 4 and key 5 as two arrays, each in ascending order
    /// — the first draft of this walked one buffer once and put a series in the
    /// scalar array, which parses, MAC-verifies and renders a cell string as a
    /// single number.
    #[test]
    fn p_198_interleaved_kinds_come_out_as_two_arrays_still_in_order() {
        let q = [ok(); 2];
        let values = [11, 12];
        let series = Series::new(id(4), &q, &values, None).expect("a two-element series");

        let mut page = ReadingsPage::new();
        assert!(page.push_sample(&sample(3, 30)).expect("sig 3"));
        assert!(page.push_series(&series).expect("sig 4"));
        assert!(page.push_sample(&sample(5, 50)).expect("sig 5"));

        assert_eq!(page.samples(), 2);
        assert_eq!(page.series(), 1);

        let mut buf = [0u8; MAX_READINGS_BYTES + 64];
        let body = ReadingsBody {
            seq: 9,
            rev: 41,
            at: None,
            outcome: ReadingsOutcome::Ok,
            total: 3,
            page: Some(&page),
        };
        let len = body.encode(&mut buf).expect("a body encodes");
        let bytes = buf.get(..len).expect("the written prefix");

        let head = ReadingsHeader::decode(bytes).expect("and decodes");
        assert_eq!(head.samples, 2);
        assert_eq!(head.series, 1);
        assert_eq!(head.seq, 9);
        assert_eq!(head.rev, 41);
        assert_eq!(head.total, 3);
        assert_eq!(head.next, 0);
        assert_eq!(head.outcome, ReadingsOutcome::Ok);
    }

    /// `next = 0` is the natural encoding of *nothing follows*, so a response
    /// that answered nothing is otherwise shaped exactly like one that answered
    /// everything — and on outcome 4 the `rev` matches, so nothing else fires.
    /// The client stamps a cache it never assembled.
    #[test]
    fn p_199_an_outcome_that_answered_nothing_cannot_carry_rows() {
        let page = page_of(&[sample(3, 30)]);
        let body = ReadingsBody {
            seq: 9,
            rev: 41,
            at: None,
            outcome: ReadingsOutcome::Superseded,
            total: 0,
            page: Some(&page),
        };
        let mut buf = [0u8; 256];
        assert_eq!(
            body.encode(&mut buf),
            Err(ReadingsError::AnsweredNothing(ReadingsOutcome::Superseded))
        );
    }

    /// The rule has to hold on the receiving side too, because that is the side
    /// that caches. A sender somewhere else does not have this crate.
    #[test]
    fn p_199_a_receiver_refuses_the_page_a_sender_would_not_write() {
        // {1:seq=9, 2:rev=41, 6:next=7, 7:total=3, 8:outcome=2}
        let body = [
            0xA5, 0x01, 0x09, 0x02, 0x18, 0x29, 0x06, 0x07, 0x07, 0x03, 0x08, 0x02,
        ];
        assert_eq!(
            ReadingsHeader::decode(&body),
            Err(ReadingsError::AnsweredNothing(ReadingsOutcome::Superseded))
        );
    }

    /// A page that fills says so and names where to resume, rather than
    /// truncating and reporting a complete walk. `Ok(false)` is not an error:
    /// the caller sends what it has and the cursor is the signal that did not
    /// fit.
    #[test]
    fn p_198_a_full_page_names_the_signal_it_stopped_at() {
        let mut page = ReadingsPage::new();
        let mut sig = 1u16;
        loop {
            let one = sample(sig, i32::from(sig));
            if !page.push_sample(&one).expect("a sample encodes") {
                break;
            }
            sig = sig.checked_add(1).expect("the loop ends first");
            assert!(sig < 500, "the page never filled");
        }
        assert_eq!(
            page.next(),
            sig,
            "the cursor is not the signal that bounced"
        );
        assert_eq!(page.samples(), MAX_SAMPLES);
    }

    /// Seven is the series row arm, and a page refuses the eighth rather than
    /// dropping an element of one to make it fit.
    #[test]
    fn p_198_the_eighth_series_is_refused_and_none_is_shortened() {
        let q = [ok(); MAX_SERIES_LEN];
        let values = [7i32; MAX_SERIES_LEN];

        // Ascending sigs and not one repeated id, so the cursor can only be
        // right for one reason. With every series at sig 9 the assertion below
        // passes whether the cursor came from the row that bounced or from
        // anywhere else, which is a check that compares nothing.
        let mut page = ReadingsPage::new();
        let mut sig = 1u16;
        let stopped = loop {
            let one = Series::new(id(sig), &q, &values, None).expect("a series");
            if !page.push_series(&one).expect("a series encodes") {
                break sig;
            }
            sig = sig.checked_add(1).expect("the loop ends first");
            assert!(sig < 100, "the row arm never bound");
        };

        assert_eq!(page.series(), MAX_SERIES);
        assert_eq!(page.next(), stopped);
        assert!(page.len() <= MAX_READINGS_BYTES);
    }

    /// The byte arm only ever binds on a **mixed** page — 40 samples is 800
    /// bytes and 7 series is 777, both under the 880 cap on their own, and only
    /// together do they exceed it. So a page that stops on bytes rather than on
    /// rows is the case a single-kind test cannot reach, and its cursor is the
    /// one that had nothing watching it: a page that stopped for want of room
    /// and reported `next = 0` says *the selection is complete* and the client
    /// never asks again.
    #[test]
    fn p_198_a_page_that_stops_on_bytes_names_its_cursor_too() {
        let q = [ok(); MAX_SERIES_LEN];
        // `i32::MIN` and not a small number: a series of sixteen 7s encodes to
        // 40 bytes, not the 111 the bound is derived for, and a page of those
        // never reaches the byte arm at all. The first version of this test
        // used 7 and reported the row arm while claiming to prove the other.
        let values = [i32::MIN; MAX_SERIES_LEN];

        let mut page = ReadingsPage::new();
        let mut sig = 1u16;
        for _ in 0..MAX_SERIES {
            let wide = Series::new(id(sig), &q, &values, None).expect("a full-width series");
            assert!(page.push_series(&wide).expect("a series encodes"));
            sig = sig.checked_add(1).expect("seven fits");
        }

        // Seven full-width series is 777 of the 880 bytes. What is left will not
        // take forty samples, so the next arm to bind is the byte one.
        let stopped = loop {
            let one = sample(sig, i32::MAX);
            if !page.push_sample(&one).expect("a sample encodes") {
                break sig;
            }
            sig = sig.checked_add(1).expect("the loop ends first");
            assert!(sig < 200, "the page never filled");
        };

        assert!(
            page.samples() < MAX_SAMPLES,
            "the sample row arm bound first, so this is not the byte arm after \
             all: {} samples of {MAX_SAMPLES}",
            page.samples()
        );
        assert_eq!(page.next(), stopped);
        assert!(page.len() <= MAX_READINGS_BYTES);
    }

    /// Both ends of the `i32` range survive the wire unchanged, and a number
    /// wider than it is refused rather than taken.
    ///
    /// The refusal is the half that matters. A clamped value is a lie nothing
    /// downstream can detect: a shunt reporting a five-million-amp fault
    /// surfaces as 2 147 483 647, and every rule reading it sees a real,
    /// enormous current. The wire has a word for this — `6 out_of_range`, with
    /// no value at all — and P-185 says to use it.
    #[test]
    fn p_185_a_number_wider_than_an_i32_is_refused_and_never_clamped() {
        for edge in [i32::MIN, i32::MAX, 0, -1] {
            let one = sample(7, edge);
            let mut buf = [0u8; 32];
            let mut cbor = CborWriter::new(&mut buf);
            one.encode(&mut cbor).expect("a sample encodes");
            let len = cbor.finish().expect("and finishes");

            let mut back = CborReader::new(buf.get(..len).expect("the written prefix"));
            assert_eq!(back.map().expect("a map"), 3);
            assert_eq!(back.key().expect("key 1"), 1);
            assert_eq!(back.u16().expect("sig"), 7);
            assert_eq!(back.key().expect("key 2"), 2);
            assert_eq!(back.i32().expect("the value"), edge);
        }

        // 2^31 is one past the top: {1:7, 2:2147483648, 3:0x11}
        let over = [
            0xA3, 0x01, 0x07, 0x02, 0x1A, 0x80, 0x00, 0x00, 0x00, 0x03, 0x11,
        ];
        let mut wide = CborReader::new(&over);
        assert_eq!(wide.map().expect("a map"), 3);
        assert_eq!(wide.key().expect("key 1"), 1);
        assert_eq!(wide.u16().expect("sig"), 7);
        assert_eq!(wide.key().expect("key 2"), 2);
        assert_eq!(wide.i32(), Err(CborError::IntegerOutOfRange));
    }

    /// An absent reading has no value key at all, so there is no slot a decoder
    /// could read a zero out of — and no plausible number where the missing one
    /// was. This is the end-to-end version: through the page, through the body,
    /// and looked for in the bytes.
    #[test]
    fn p_196_a_broken_sensor_puts_no_number_on_the_wire() {
        let absent =
            Sample::new(id(3), broken(), None, None).expect("a reading with nothing in it");
        let page = page_of(&[absent]);

        let mut buf = [0u8; 256];
        let body = ReadingsBody {
            seq: 1,
            rev: 41,
            at: None,
            outcome: ReadingsOutcome::Ok,
            total: 1,
            page: Some(&page),
        };
        let len = body.encode(&mut buf).expect("encodes");
        let bytes = buf.get(..len).expect("the written prefix");

        // Key 2 is the value key inside a `Sample`. The sample's map is
        // {1:sig, 3:q}, so the pair `0x02` followed by anything must not appear
        // inside it.
        let sample_map = bytes
            .windows(2)
            .position(|w| w == [0xA2, 0x01])
            .expect("the sample's map header");
        let inside = bytes.get(sample_map..).expect("the rest of the body");
        assert_eq!(
            inside.get(2),
            Some(&0x03),
            "a value key sits where there is no value"
        );
    }

    /// A reading survives the round trip it could not make before this decoder
    /// existed.
    #[test]
    fn a_reading_survives_being_read_back() {
        let q = SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("ok carries");
        let sample = Sample::new(id(0x0101), q, Some(12_650), None).expect("legal");

        let mut buf = [0u8; 64];
        let mut cbor = CborWriter::new(&mut buf);
        sample.encode(&mut cbor).expect("it encodes");
        let len = cbor.finish().expect("it finishes");

        let mut reader = CborReader::new(buf.get(..len).expect("the bytes"));
        let back = Sample::decode(&mut reader).expect("it decodes");
        assert_eq!(back.sig.get(), 0x0101);
        assert_eq!(back.value(), Some(12_650));
        assert_eq!(back.q, q);
    }

    /// And so does an absence, which is the one that must not come back as a
    /// number.
    #[test]
    fn an_absence_reads_back_as_an_absence() {
        let q = SignalQuality::absent(Validity::Absent).expect("absent carries nothing");
        let sample = Sample::new(id(0x0302), q, None, None).expect("legal");

        let mut buf = [0u8; 64];
        let mut cbor = CborWriter::new(&mut buf);
        sample.encode(&mut cbor).expect("it encodes");
        let len = cbor.finish().expect("it finishes");

        let mut reader = CborReader::new(buf.get(..len).expect("the bytes"));
        let back = Sample::decode(&mut reader).expect("it decodes");
        assert_eq!(
            back.value(),
            None,
            "an absent reading came back with a number"
        );
    }

    /// **The room card, arriving over the wire.** A frame that says *there is no
    /// reading* and carries a number anyway is refused rather than believed —
    /// and it is refused by the same code that refuses it on the way in, so the
    /// encoder and the decoder cannot come to disagree about it.
    #[test]
    fn a_number_under_an_absent_quality_is_refused_on_the_way_in() {
        let q = SignalQuality::absent(Validity::Absent).expect("absent carries nothing");
        let mut buf = [0u8; 64];
        let mut cbor = CborWriter::new(&mut buf);
        cbor.map(3).expect("map");
        cbor.key(1).expect("k1");
        cbor.u64(0x0302).expect("sig");
        cbor.key(2).expect("k2");
        cbor.i32(0)
            .expect("the zero somebody would read as a temperature");
        cbor.key(3).expect("k3");
        cbor.u64(u64::from(q.byte())).expect("q");
        let len = cbor.finish().expect("it finishes");

        let mut reader = CborReader::new(buf.get(..len).expect("the bytes"));
        assert!(
            Sample::decode(&mut reader).is_err(),
            "a zero was accepted for a probe that is not there"
        );
    }

    /// A stale reading with no age is the other direction of the same rule: a
    /// reader cannot tell how old it is, so it must not be handed over at all.
    #[test]
    fn a_stale_reading_with_no_age_is_refused_on_the_way_in() {
        let q = SignalQuality::carrying(Validity::Stale, Provenance::Measured).expect("stale");
        let mut buf = [0u8; 64];
        let mut cbor = CborWriter::new(&mut buf);
        cbor.map(3).expect("map");
        cbor.key(1).expect("k1");
        cbor.u64(0x0101).expect("sig");
        cbor.key(2).expect("k2");
        cbor.i32(12_000).expect("value");
        cbor.key(3).expect("k3");
        cbor.u64(u64::from(q.byte())).expect("q");
        let len = cbor.finish().expect("it finishes");

        let mut reader = CborReader::new(buf.get(..len).expect("the bytes"));
        assert!(
            Sample::decode(&mut reader).is_err(),
            "a stale reading arrived with no way to know how stale"
        );
    }

    /// The rows come back, in order, with the header's count agreeing.
    #[test]
    fn every_sample_in_a_body_is_walked() {
        let ok = SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("ok");
        let gone = SignalQuality::absent(Validity::Absent).expect("absent");
        let mut page = ReadingsPage::new();
        page.push_sample(&Sample::new(id(1), ok, Some(12_650), None).expect("one"))
            .expect("it fits");
        page.push_sample(&Sample::new(id(2), gone, None, None).expect("two"))
            .expect("it fits");

        let body = ReadingsBody {
            seq: 7,
            rev: 1,
            at: None,
            outcome: ReadingsOutcome::Ok,
            total: 2,
            page: Some(&page),
        };
        let mut buf = [0u8; 512];
        let len = body.encode(&mut buf).expect("it encodes");
        let payload = buf.get(..len).expect("the bytes");

        let header = ReadingsHeader::decode(payload).expect("the header");
        // A fixed array, because this crate has no allocator — which is the
        // claim it is built on and the compiler holds it even here.
        let mut got = [(0u16, None::<i32>); 4];
        let mut at = 0usize;
        let walked = ReadingsHeader::for_each_sample(payload, |s| {
            if let Some(slot) = got.get_mut(at) {
                *slot = (s.sig.get(), s.value());
            }
            at += 1;
        })
        .expect("walk");

        assert_eq!(walked, header.samples, "the header and the rows disagreed");
        assert_eq!(got.first(), Some(&(1, Some(12_650))));
        assert_eq!(
            got.get(1),
            Some(&(2, None)),
            "the absence came back as a number"
        );
    }

    // Repeating an optional or empty field must not erase its first occurrence.
    #[test]
    fn p_015_sample_refuses_each_repeated_key() {
        for key in 1u8..=4 {
            for separated in [false, true] {
                let mut out = [0u8; 256];
                let mut used = 1;
                out[0] = if separated { 0xa3 } else { 0xa2 };
                for occurrence in 0..2 {
                    if separated && occurrence == 1 {
                        out[used..used + 3].copy_from_slice(&[0x18, 99, 0]);
                        used += 3;
                    }
                    out[used] = key;
                    used += 1;
                    let mut cbor = CborWriter::new(&mut out[used..]);
                    match key {
                        3 => cbor.u64(u64::from(ok().byte())),
                        _ => cbor.u64(1),
                    }
                    .expect("value");
                    used += cbor.finish().expect("value length");
                }
                let bytes = &out[..used];
                let why = Sample::decode(&mut CborReader::new(bytes))
                    .map(|_| ())
                    .expect_err("duplicate refused");
                assert_eq!(
                    why,
                    ReadingsError::Duplicate(key),
                    "key {key}, separated {separated}"
                );
                assert_eq!(
                    why.refusal(),
                    crate::Refusal::Client(crate::ErrorCode::MalformedFrame)
                );
            }
        }
    }

    // Repeating an optional or empty field must not erase its first occurrence.
    #[test]
    fn p_015_series_refuses_each_repeated_key() {
        for key in 1u8..=4 {
            for separated in [false, true] {
                let mut out = [0u8; 256];
                let mut used = 1;
                out[0] = if separated { 0xa3 } else { 0xa2 };
                for occurrence in 0..2 {
                    if separated && occurrence == 1 {
                        out[used..used + 3].copy_from_slice(&[0x18, 99, 0]);
                        used += 3;
                    }
                    out[used] = key;
                    used += 1;
                    let mut cbor = CborWriter::new(&mut out[used..]);
                    match key {
                        2 => cbor.bytes(&[ok().byte(), ok().byte()]),
                        3 => cbor.array(0),
                        _ => cbor.u64(1),
                    }
                    .expect("value");
                    used += cbor.finish().expect("value length");
                }
                let bytes = &out[..used];
                let why = Series::check(bytes)
                    .map(|_| ())
                    .expect_err("duplicate refused");
                assert_eq!(
                    why,
                    ReadingsError::Duplicate(key),
                    "key {key}, separated {separated}"
                );
                assert_eq!(
                    why.refusal(),
                    crate::Refusal::Client(crate::ErrorCode::MalformedFrame)
                );
            }
        }
    }

    // Repeating an optional or empty field must not erase its first occurrence.
    #[test]
    fn p_015_read_signals_refuses_each_repeated_key() {
        use super::ReadSignals;
        for key in 1u8..=3 {
            for separated in [false, true] {
                let mut out = [0u8; 256];
                let mut used = 1;
                out[0] = if separated { 0xa3 } else { 0xa2 };
                for occurrence in 0..2 {
                    if separated && occurrence == 1 {
                        out[used..used + 3].copy_from_slice(&[0x18, 99, 0]);
                        used += 3;
                    }
                    out[used] = key;
                    used += 1;
                    let mut cbor = CborWriter::new(&mut out[used..]);
                    match key {
                        2 => cbor.array(0),
                        _ => cbor.u64(1),
                    }
                    .expect("value");
                    used += cbor.finish().expect("value length");
                }
                let bytes = &out[..used];
                let why = ReadSignals::decode(bytes)
                    .map(|_| ())
                    .expect_err("duplicate refused");
                assert_eq!(
                    why,
                    ReadingsError::Duplicate(key),
                    "key {key}, separated {separated}"
                );
                assert_eq!(
                    why.refusal(),
                    crate::Refusal::Client(crate::ErrorCode::MalformedFrame)
                );
            }
        }
    }

    // Repeating an optional or empty field must not erase its first occurrence.
    #[test]
    fn p_015_readings_header_refuses_each_repeated_key() {
        for key in 1u8..=8 {
            for separated in [false, true] {
                let mut out = [0u8; 256];
                let mut used = 1;
                out[0] = if separated { 0xa3 } else { 0xa2 };
                for occurrence in 0..2 {
                    if separated && occurrence == 1 {
                        out[used..used + 3].copy_from_slice(&[0x18, 99, 0]);
                        used += 3;
                    }
                    out[used] = key;
                    used += 1;
                    let mut cbor = CborWriter::new(&mut out[used..]);
                    match key {
                        4 | 5 => cbor.array(0),
                        _ => cbor.u64(1),
                    }
                    .expect("value");
                    used += cbor.finish().expect("value length");
                }
                let bytes = &out[..used];
                let why = ReadingsHeader::decode(bytes)
                    .map(|_| ())
                    .expect_err("duplicate refused");
                assert_eq!(
                    why,
                    ReadingsError::Duplicate(key),
                    "key {key}, separated {separated}"
                );
                assert_eq!(
                    why.refusal(),
                    crate::Refusal::Client(crate::ErrorCode::MalformedFrame)
                );
            }
        }
    }

    // Repeating an optional or empty field must not erase its first occurrence.
    #[test]
    fn p_015_sample_walk_refuses_each_repeated_key() {
        for key in 4u8..=4 {
            for separated in [false, true] {
                let mut out = [0u8; 256];
                let mut used = 1;
                out[0] = if separated { 0xa3 } else { 0xa2 };
                for occurrence in 0..2 {
                    if separated && occurrence == 1 {
                        out[used..used + 3].copy_from_slice(&[0x18, 99, 0]);
                        used += 3;
                    }
                    out[used] = key;
                    used += 1;
                    let mut cbor = CborWriter::new(&mut out[used..]);
                    cbor.array(0).expect("value");
                    used += cbor.finish().expect("value length");
                }
                let bytes = &out[..used];
                let why = ReadingsHeader::for_each_sample(bytes, |_| panic!("empty array"))
                    .map(|_| ())
                    .expect_err("duplicate refused");
                assert_eq!(
                    why,
                    ReadingsError::Duplicate(key),
                    "key {key}, separated {separated}"
                );
                assert_eq!(
                    why.refusal(),
                    crate::Refusal::Client(crate::ErrorCode::MalformedFrame)
                );
            }
        }
    }
    #[test]
    fn p_015_a_repeated_sample_array_delivers_no_readings() {
        let sample = Sample::new(id(1), ok(), Some(42), None).expect("sample");
        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(1).expect("map");
        cbor.key(4).expect("samples");
        cbor.array(1).expect("one sample");
        sample.encode(&mut cbor).expect("sample");
        let len = cbor.finish().expect("body");
        let mut delivered = 0;
        assert_eq!(
            ReadingsHeader::for_each_sample(&out[..len], |_| delivered += 1),
            Ok(1)
        );
        assert_eq!(delivered, 1);
        out[0] = 0xa2;
        out[len..len + 2].copy_from_slice(&[4, 0x80]);
        delivered = 0;
        assert_eq!(
            ReadingsHeader::for_each_sample(&out[..len + 2], |_| delivered += 1),
            Err(ReadingsError::Duplicate(4))
        );
        assert_eq!(delivered, 0);
    }
}
