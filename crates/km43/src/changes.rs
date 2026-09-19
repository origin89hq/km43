//! The three records that say something about the site moved: a signal's
//! validity, the topology, a device's presence.
//!
//! Two of them carry an **array** because one RS-485 pair going intermittent at
//! −30 °C flips every signal behind it in one pass — up to 384 at the site cap —
//! and class A events are never dropped. One event per signal is 384 events into
//! a queue of sixteen across eight sessions, every one of which then gets closed
//! and reconnects and replays the burst; the ladder puts the controller's radio
//! off the air and writes `comms link lost` against a chip that answered every
//! heartbeat. An array is what makes that eight ticks of one event.
//!
//! What decides how many go in a tick is P-182's coalescing, which is not here.
//! This is the shape on the wire and the refusals a receiver owes it.
//!
//! cites: P-212, P-213

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{ErrorCode, Presence, TopologyChangeReason};
use crate::ident::{Id, IdError};
use crate::limits::{
    MAX_EVENT_BODY, MAX_PRESENCE_SWEEP, MAX_VALIDITY_SWEEP, PCHANGE_MAX_BYTES, VCHANGE_MAX_BYTES,
};
use crate::readings::{QualityError, SignalQuality};

/// One signal's validity moving, inside an `0x0102`.
///
/// `prev` is the last `q` this controller **announced** for the signal and not
/// the last it observed. Coalescing means a signal can move twice between two
/// events, so the observed one describes a transition the client was never told
/// about — and the client compares `prev` against what it holds, which is what
/// it was last sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VChange {
    /// Key 1, the signal that moved.
    pub sig: Id,
    /// Key 2, the quality it moved to.
    pub q: SignalQuality,
    /// Key 3, the quality last announced for it, which is what the client holds.
    pub prev: SignalQuality,
}

impl VChange {
    fn encode(self, cbor: &mut CborWriter<'_>) -> Result<(), CborError> {
        cbor.map(3)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.sig.get()))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.q.byte()))?;
        cbor.key(3)?;
        cbor.u64(u64::from(self.prev.byte()))
    }

    fn decode(payload: &[u8]) -> Result<Self, ChangeError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut sig, mut q, mut prev) = (None, None, None);
        for _ in 0..pairs {
            match body.key()? {
                1 => sig = Some(Id::new(body.u16()?)?),
                2 => q = Some(SignalQuality::from_byte(body.u8()?)?),
                3 => prev = Some(SignalQuality::from_byte(body.u8()?)?),
                _ => body.skip()?,
            }
        }
        body.finish()?;
        let q = q.ok_or(ChangeError::MissingEntry(2))?;
        let prev = prev.ok_or(ChangeError::MissingEntry(3))?;
        if q == prev {
            return Err(ChangeError::WentNowhere);
        }
        Ok(Self {
            sig: sig.ok_or(ChangeError::MissingEntry(1))?,
            q,
            prev,
        })
    }
}

/// One device's presence moving, inside an `0x0902`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PChange {
    /// Key 1, the device that moved.
    pub dev: Id,
    /// Key 2, the presence it moved to.
    pub presence: Presence,
    /// Key 3, the presence it moved from. Unlike `VChange` key 3 this is the
    /// last value **held**, not the last announced (P-212).
    pub prev: Presence,
}

impl PChange {
    fn encode(self, cbor: &mut CborWriter<'_>) -> Result<(), CborError> {
        cbor.map(3)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.dev.get()))?;
        cbor.key(2)?;
        cbor.u64(self.presence as u64)?;
        cbor.key(3)?;
        cbor.u64(self.prev as u64)
    }

    fn decode(payload: &[u8]) -> Result<Self, ChangeError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut dev, mut presence, mut prev) = (None, None, None);
        let read = |body: &mut CborReader<'_>| -> Result<Presence, ChangeError> {
            let number = body.u8()?;
            Presence::try_from(number).map_err(|()| ChangeError::UnknownPresence(number))
        };
        for _ in 0..pairs {
            match body.key()? {
                1 => dev = Some(Id::new(body.u16()?)?),
                2 => presence = Some(read(&mut body)?),
                3 => prev = Some(read(&mut body)?),
                _ => body.skip()?,
            }
        }
        body.finish()?;
        let presence = presence.ok_or(ChangeError::MissingEntry(2))?;
        let prev = prev.ok_or(ChangeError::MissingEntry(3))?;
        if presence == prev {
            return Err(ChangeError::WentNowhere);
        }
        Ok(Self {
            dev: dev.ok_or(ChangeError::MissingEntry(1))?,
            presence,
            prev,
        })
    }
}

/// A coalesced array under construction, for either of the two sweep bodies.
///
/// One buffer and a count, and entries measured as they are encoded rather than
/// at their worst case — the same shape the page builders use, and for the same
/// reason: a sweep of narrow entries carries more than the widest-case
/// arithmetic allows, and the arithmetic is what the cap was derived from.
struct Sweep<const ROWS: usize, const WIDTH: usize> {
    scratch: [u8; MAX_EVENT_BODY],
    used: usize,
    rows: usize,
}

impl<const ROWS: usize, const WIDTH: usize> Sweep<ROWS, WIDTH> {
    const fn new() -> Self {
        Self {
            scratch: [0u8; MAX_EVENT_BODY],
            used: 0,
            rows: 0,
        }
    }

    /// Try to take one, and say whether it fitted. `Ok(false)` is a full event
    /// and not an error: P-182 carries the rest to the next tick.
    fn push(
        &mut self,
        write: impl Fn(&mut CborWriter<'_>) -> Result<(), CborError>,
    ) -> Result<bool, ChangeError> {
        if self.rows >= ROWS {
            return Ok(false);
        }
        let mut one = [0u8; WIDTH];
        let mut cbor = CborWriter::new(&mut one);
        write(&mut cbor)?;
        let len = cbor.finish()?;
        let end = self.used.saturating_add(len);
        if end > MAX_EVENT_BODY {
            return Ok(false);
        }
        let slot = self
            .scratch
            .get_mut(self.used..end)
            .ok_or(ChangeError::EntryTooLong(len))?;
        let src = one.get(..len).ok_or(ChangeError::EntryTooLong(len))?;
        slot.copy_from_slice(src);
        self.used = end;
        self.rows = self.rows.saturating_add(1);
        Ok(true)
    }

    fn write(&self, cbor: &mut CborWriter<'_>) -> Result<(), ChangeError> {
        let packed = self
            .scratch
            .get(..self.used)
            .ok_or(ChangeError::EntryTooLong(self.used))?;
        let mut reader = CborReader::new(packed);
        cbor.array(self.rows)?;
        for _ in 0..self.rows {
            cbor.raw(reader.raw()?)?;
        }
        Ok(())
    }

    /// What has been taken, positioned to walk, and how many.
    ///
    /// A range past the scratch cannot happen — `push` is the only thing that
    /// moves `used` and it checks first — and if it did, this yields a reader
    /// that fails on the first entry rather than an empty one. An empty walk
    /// would say the event carried nothing, which is the single answer a caller
    /// marking what a client was told must never be given.
    fn taken(&self) -> (CborReader<'_>, usize) {
        (
            CborReader::new(self.scratch.get(..self.used).unwrap_or(&[])),
            self.rows,
        )
    }
}

/// An `0x0102 signal validity changed` body under construction.
///
/// No `Debug`: it is most of an event body of packed entries.
pub struct ValidityChanged {
    /// Key 1, the topology revision the sweep was taken at.
    pub rev: u32,
    entries: Sweep<MAX_VALIDITY_SWEEP, VCHANGE_MAX_BYTES>,
}

impl ValidityChanged {
    #[must_use]
    /// An empty sweep at `rev`.
    pub const fn new(rev: u32) -> Self {
        Self {
            rev,
            entries: Sweep::new(),
        }
    }

    /// Try to add one, and say whether this event took it.
    pub fn push(&mut self, change: &VChange) -> Result<bool, ChangeError> {
        if change.q == change.prev {
            return Err(ChangeError::WentNowhere);
        }
        self.entries.push(|cbor| change.encode(cbor))
    }

    #[must_use]
    /// Entries taken so far.
    pub const fn len(&self) -> usize {
        self.entries.rows
    }

    #[must_use]
    /// No entry yet, which `encode` refuses rather than writes (P-212).
    pub const fn is_empty(&self) -> bool {
        self.entries.rows == 0
    }

    /// The entries this event holds, before anything is encoded.
    ///
    /// A controller marks a signal announced from what the record carries rather
    /// than from what it offered the builder, so *what the client was told* and
    /// *what went on the wire* cannot come apart at the one entry that did not
    /// fit.
    #[must_use]
    pub fn entries(&self) -> VChanges<'_> {
        let (body, left) = self.entries.taken();
        VChanges { body, left }
    }

    /// Encode it, refusing an empty array rather than writing one (P-212).
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ChangeError> {
        if self.is_empty() {
            return Err(ChangeError::NothingChanged);
        }
        let mut cbor = CborWriter::new(dst);
        cbor.map(2)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(2)?;
        self.entries.write(&mut cbor)?;
        Ok(cbor.finish()?)
    }

    /// Read one, refusing what [`Self::encode`] refuses to write.
    pub fn decode(payload: &[u8]) -> Result<(u32, VChanges<'_>), ChangeError> {
        let (rev, body, left) = sweep(payload)?;
        Ok((rev, VChanges { body, left }))
    }
}

/// An `0x0902 device presence changed` body under construction.
pub struct PresenceChanged {
    /// Key 1, the topology revision the sweep was taken at.
    pub rev: u32,
    entries: Sweep<MAX_PRESENCE_SWEEP, PCHANGE_MAX_BYTES>,
}

impl PresenceChanged {
    #[must_use]
    /// An empty sweep at `rev`.
    pub const fn new(rev: u32) -> Self {
        Self {
            rev,
            entries: Sweep::new(),
        }
    }

    /// Take one entry. `Ok(false)` means the sweep is full and the entry was not taken; a
    /// change to the presence the device already had is refused.
    pub fn push(&mut self, change: &PChange) -> Result<bool, ChangeError> {
        if change.presence == change.prev {
            return Err(ChangeError::WentNowhere);
        }
        self.entries.push(|cbor| change.encode(cbor))
    }

    #[must_use]
    /// Entries taken so far.
    pub const fn len(&self) -> usize {
        self.entries.rows
    }

    #[must_use]
    /// No entry yet, which `encode` refuses rather than writes (P-212).
    pub const fn is_empty(&self) -> bool {
        self.entries.rows == 0
    }

    /// The entries this event holds, before anything is encoded. `0x0102`'s
    /// twin, and it exists for the same reason: a controller marks a device
    /// announced from what the record carries rather than from what it offered.
    #[must_use]
    pub fn entries(&self) -> PChanges<'_> {
        let (body, left) = self.entries.taken();
        PChanges { body, left }
    }

    /// Write the body, refusing an empty sweep.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ChangeError> {
        if self.is_empty() {
            return Err(ChangeError::NothingChanged);
        }
        let mut cbor = CborWriter::new(dst);
        cbor.map(2)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(2)?;
        self.entries.write(&mut cbor)?;
        Ok(cbor.finish()?)
    }

    /// Read `rev` and an iterator over the entries, after walking the body to its end.
    pub fn decode(payload: &[u8]) -> Result<(u32, PChanges<'_>), ChangeError> {
        let (rev, body, left) = sweep(payload)?;
        Ok((rev, PChanges { body, left }))
    }
}

/// The shared read of a sweep body: `rev`, and the array positioned to walk.
///
/// The whole body is walked to its end **before** an entry is handed out. This
/// used to return the moment key 2 was found, so anything after the array —
/// bytes of a second body, garbage from a resynchronising receiver — was
/// accepted without being looked at, and a body cut short inside the array
/// was a record that iterated cleanly up to the cut.
fn sweep(payload: &[u8]) -> Result<(u32, CborReader<'_>, usize), ChangeError> {
    let mut body = CborReader::new(payload);
    let pairs = body.map()?;
    let (mut rev, mut entries) = (None, None);
    for _ in 0..pairs {
        match body.key()? {
            1 => rev = Some(body.u32()?),
            // Taken as bytes, which proves the array is well formed to its
            // last byte; the iterator then reads a slice this walk has vouched
            // for.
            2 => entries = Some(body.raw()?),
            _ => body.skip()?,
        }
    }
    body.finish()?;
    let rev = rev.ok_or(ChangeError::MissingBody(1))?;
    let mut entries = CborReader::new(entries.ok_or(ChangeError::MissingBody(2))?);
    let left = entries.array()?;
    if left == 0 {
        return Err(ChangeError::NothingChanged);
    }
    Ok((rev, entries, left))
}

/// The entries of an `0x0102`, decoded on demand.
pub struct VChanges<'a> {
    body: CborReader<'a>,
    left: usize,
}

impl Iterator for VChanges<'_> {
    type Item = Result<VChange, ChangeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left = self.left.saturating_sub(1);
        Some(
            self.body
                .raw()
                .map_err(ChangeError::from)
                .and_then(VChange::decode),
        )
    }
}

/// The entries of an `0x0902`, decoded on demand.
pub struct PChanges<'a> {
    body: CborReader<'a>,
    left: usize,
}

impl Iterator for PChanges<'_> {
    type Item = Result<PChange, ChangeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left = self.left.saturating_sub(1);
        Some(
            self.body
                .raw()
                .map_err(ChangeError::from)
                .and_then(PChange::decode),
        )
    }
}

/// An `0x0901 topology changed` body.
///
/// The one of the three that carries no array: a revision moves once, for one
/// reason, however many rows it took with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TopologyChanged {
    /// The revision this moved **to**.
    pub rev: u32,
    /// Key 2, why the revision moved.
    pub reason: TopologyChangeReason,
    /// Descriptor rows added and removed, of every kind. At `1 boot` these are
    /// what the tables hold rather than a delta from nothing (P-213).
    pub added: u16,
    /// Key 4, the other half of the count above.
    pub removed: u16,
}

impl TopologyChanged {
    /// Write the body into `dst`. A destination too small is refused with nothing written to it.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ChangeError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(4)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(2)?;
        cbor.u64(self.reason as u64)?;
        cbor.key(3)?;
        cbor.u64(u64::from(self.added))?;
        cbor.key(4)?;
        cbor.u64(u64::from(self.removed))?;
        Ok(cbor.finish()?)
    }

    /// Read one back, refusing a missing key or a reason this version does not allocate.
    pub fn decode(payload: &[u8]) -> Result<Self, ChangeError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut rev, mut reason, mut added, mut removed) = (None, None, None, None);
        for _ in 0..pairs {
            match body.key()? {
                1 => rev = Some(body.u32()?),
                2 => {
                    let number = body.u8()?;
                    reason = Some(
                        TopologyChangeReason::try_from(number)
                            .map_err(|()| ChangeError::UnknownReason(number))?,
                    );
                }
                3 => added = Some(body.u16()?),
                4 => removed = Some(body.u16()?),
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            rev: rev.ok_or(ChangeError::MissingBody(1))?,
            reason: reason.ok_or(ChangeError::MissingBody(2))?,
            added: added.ok_or(ChangeError::MissingBody(3))?,
            removed: removed.ok_or(ChangeError::MissingBody(4))?,
        })
    }
}

/// Why a change record was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChangeError {
    /// 0 handed to an id space that reserves it as the paging sentinel.
    ZeroId,
    /// An entry whose new value is the one it moved from. Not a change, and a
    /// client that renders one draws a transition nobody made.
    WentNowhere,
    /// A sweep body with no entries. A record saying nothing happened is a
    /// byte on a metered link and a wake-up on a phone (P-212).
    NothingChanged,
    /// A required key of an entry never arrived (P-015).
    MissingEntry(u8),
    /// A required key of the body never arrived (P-015).
    MissingBody(u8),
    /// A presence this version does not allocate. Closed under P-019.
    UnknownPresence(u8),
    /// A topology-change reason this version does not allocate.
    UnknownReason(u8),
    /// An entry longer than its own bound, which is `limits.rs` being wrong
    /// rather than an event to end.
    EntryTooLong(usize),
    /// The `q` byte underneath was refused.
    Quality(QualityError),
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for ChangeError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<QualityError> for ChangeError {
    fn from(why: QualityError) -> Self {
        Self::Quality(why)
    }
}

impl From<IdError> for ChangeError {
    fn from(why: IdError) -> Self {
        match why {
            IdError::Zero => Self::ZeroId,
        }
    }
}

impl ChangeError {
    /// What to answer. An entry past its own bound is error 5, as a wrapper too
    /// large to write is; everything else is a body whose meaning cannot be
    /// trusted, which is what error 1 says. The code lives here rather than at
    /// the caller because a caller left to invent one once answered a rate
    /// limit `rejected`.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::EntryTooLong(_) => Refusal::Client(ErrorCode::PayloadTooLarge),
            Self::Quality(why) => why.refusal(),
            Self::ZeroId
            | Self::WentNowhere
            | Self::NothingChanged
            | Self::MissingEntry(_)
            | Self::MissingBody(_)
            | Self::UnknownPresence(_)
            | Self::UnknownReason(_)
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for ChangeError {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroId => w.write_str("0 is the end-of-paging sentinel and never an id"),
            Self::WentNowhere => {
                w.write_str("a change to the value it moved from, which is not a change")
            }
            Self::NothingChanged => {
                w.write_str("a sweep with no entries, which is a record saying nothing happened")
            }
            Self::MissingEntry(k) => write!(w, "a sweep entry with no key {k}"),
            Self::MissingBody(k) => write!(w, "a change record with no key {k}"),
            Self::UnknownPresence(n) => write!(w, "presence {n} is not allocated"),
            Self::UnknownReason(n) => write!(w, "topology change reason {n} is not allocated"),
            Self::EntryTooLong(n) => write!(w, "a sweep entry of {n} bytes, past its own bound"),
            Self::Quality(why) => write!(w, "{why}"),
            Self::Cbor(why) => write!(w, "{why}"),
        }
    }
}

impl core::error::Error for ChangeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::{Provenance, Validity};
    use crate::render::Rendering;

    /// No two refusals read as one sentence, and each carries the code P-141
    /// leaves for a body that never reached a handler: error 5 for an entry
    /// past its bound, error 1 for the rest. Until this map existed the code
    /// was the caller's to invent, which is how a rate-limited `Time` once came
    /// to be answered `rejected`.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [ChangeError; 10] = [
            ChangeError::ZeroId,
            ChangeError::WentNowhere,
            ChangeError::NothingChanged,
            ChangeError::MissingEntry(1),
            ChangeError::MissingBody(2),
            ChangeError::UnknownPresence(9),
            ChangeError::UnknownReason(9),
            ChangeError::EntryTooLong(500),
            ChangeError::Quality(QualityError::StaleWithoutAge),
            ChangeError::Cbor(CborError::WrongType),
        ];
        Rendering::<96>::each_says_something_of_its_own(&EVERY);
        for why in EVERY {
            let want = if matches!(why, ChangeError::EntryTooLong(_)) {
                Refusal::Client(ErrorCode::PayloadTooLarge)
            } else {
                Refusal::Client(ErrorCode::MalformedFrame)
            };
            assert_eq!(why.refusal(), want, "{why}");
        }
    }

    fn id(value: u16) -> Id {
        Id::new(value).expect("a non-zero id")
    }

    fn ok() -> SignalQuality {
        SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("a reading")
    }

    fn absent() -> SignalQuality {
        SignalQuality::absent(Validity::Absent).expect("nothing to carry")
    }

    /// **One pair going intermittent flips every signal behind it, and that has
    /// to be one event.**
    ///
    /// 384 signals at the site cap, a queue of sixteen, eight sessions, and
    /// class A is never dropped — so one event per signal closes every session,
    /// the reconnect replays the burst from the log and closes them again, and
    /// the ladder takes the radio off the air blaming a chip that answered every
    /// heartbeat. The array is what makes it eight ticks of one event.
    #[test]
    fn a_whole_pair_going_quiet_is_one_event_and_not_one_per_signal() {
        let mut sweep = ValidityChanged::new(41);
        let mut taken = 0;
        for n in 1..=384u16 {
            let change = VChange {
                sig: id(n),
                q: absent(),
                prev: ok(),
            };
            if sweep.push(&change).expect("encodes") {
                taken += 1;
            } else {
                break;
            }
        }
        assert_eq!(
            taken, MAX_VALIDITY_SWEEP,
            "the sweep took a different number of signals than its cap"
        );
        assert_eq!(sweep.len(), MAX_VALIDITY_SWEEP);

        let mut out = [0u8; MAX_EVENT_BODY];
        let len = sweep.encode(&mut out).expect("a full sweep encodes");
        assert!(len <= MAX_EVENT_BODY, "a sweep past the event body budget");

        let bytes = out.get(..len).expect("what was written");
        let (rev, entries) = ValidityChanged::decode(bytes).expect("it decodes");
        assert_eq!(rev, 41);
        let mut seen = 0;
        for (n, entry) in entries.enumerate() {
            let entry = entry.expect("an entry this crate wrote");
            assert_eq!(entry.sig.get(), u16::try_from(n).expect("small") + 1);
            seen += 1;
        }
        assert_eq!(seen, MAX_VALIDITY_SWEEP);
    }

    /// The presence sweep against its own cap, which is the device table's.
    #[test]
    fn a_presence_sweep_stops_at_the_devices_there_are() {
        let mut sweep = PresenceChanged::new(41);
        let mut taken = 0;
        for n in 1..=64u16 {
            let change = PChange {
                dev: id(n),
                presence: Presence::Offline,
                prev: Presence::Online,
            };
            if sweep.push(&change).expect("encodes") {
                taken += 1;
            } else {
                break;
            }
        }
        assert_eq!(taken, MAX_PRESENCE_SWEEP);

        let mut out = [0u8; MAX_EVENT_BODY];
        let len = sweep.encode(&mut out).expect("encodes");
        let (rev, entries) =
            PresenceChanged::decode(out.get(..len).expect("written")).expect("decodes");
        assert_eq!(rev, 41);
        assert_eq!(entries.count(), MAX_PRESENCE_SWEEP);
    }

    /// **What the builder says it took has to be what the bytes carry.**
    ///
    /// A controller marks a signal announced from [`ValidityChanged::entries`],
    /// and the difference against the announced byte is the only thing that
    /// remembers a move — nothing is queued. So an entry counted as taken and
    /// missing from the array is a validity change lost for good: the client
    /// holds a `q` nothing will correct, and the store believes it has been told.
    #[test]
    fn what_the_builder_says_it_took_is_what_the_bytes_carry() {
        let mut sweep = ValidityChanged::new(41);
        for n in 1..=60u16 {
            if !sweep
                .push(&VChange {
                    sig: id(n),
                    q: absent(),
                    prev: ok(),
                })
                .expect("encodes")
            {
                break;
            }
        }

        let mut out = [0u8; MAX_EVENT_BODY];
        let len = sweep.encode(&mut out).expect("a full sweep encodes");
        let (_, encoded) =
            ValidityChanged::decode(out.get(..len).expect("written")).expect("reads");

        assert_eq!(
            sweep.entries().count(),
            sweep.len(),
            "the walk and the count disagree"
        );

        let mut paired = 0;
        for (built, sent) in sweep.entries().zip(encoded) {
            assert_eq!(
                built.expect("an entry this crate wrote"),
                sent.expect("an entry this crate encoded"),
                "an entry the builder holds is not the one that went out"
            );
            paired += 1;
        }
        assert_eq!(
            paired, MAX_VALIDITY_SWEEP,
            "the two walks are different lengths, so one of them is short"
        );
    }

    /// **A record saying nothing happened is refused on both sides (P-212).**
    ///
    /// It costs a byte on a metered link and a wake-up on a phone. That the
    /// coalescing cannot produce one is not the point — a rule that produced one
    /// would be a bug, and this is where it says so.
    #[test]
    fn p_212_a_sweep_with_no_entries_is_refused() {
        let mut out = [0u8; MAX_EVENT_BODY];
        assert_eq!(
            ValidityChanged::new(41).encode(&mut out),
            Err(ChangeError::NothingChanged)
        );
        assert_eq!(
            PresenceChanged::new(41).encode(&mut out),
            Err(ChangeError::NothingChanged)
        );

        // And a peer that writes one anyway is refused on the way in.
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(2).expect("a map");
        cbor.key(1).expect("rev");
        cbor.u64(41).expect("rev");
        cbor.key(2).expect("e");
        cbor.array(0).expect("an empty sweep");
        let len = cbor.finish().expect("a handmade body");
        let bytes = out.get(..len).expect("what was written");
        assert!(matches!(
            ValidityChanged::decode(bytes),
            Err(ChangeError::NothingChanged)
        ));
        assert!(matches!(
            PresenceChanged::decode(bytes),
            Err(ChangeError::NothingChanged)
        ));
    }

    /// An entry whose new value is the one it moved from is not a change, and is
    /// refused at the builder rather than sent and sorted out later.
    #[test]
    fn an_entry_that_went_nowhere_is_refused() {
        let mut sweep = ValidityChanged::new(41);
        assert_eq!(
            sweep.push(&VChange {
                sig: id(9),
                q: ok(),
                prev: ok(),
            }),
            Err(ChangeError::WentNowhere)
        );

        let mut presence = PresenceChanged::new(41);
        assert_eq!(
            presence.push(&PChange {
                dev: id(3),
                presence: Presence::Online,
                prev: Presence::Online,
            }),
            Err(ChangeError::WentNowhere)
        );
    }

    /// **`prev` is the last one announced, and that is what a client holds.**
    ///
    /// A signal that went `ok` → `stale` → `absent` between two events arrives
    /// as one entry. Set `prev` from the last thing observed and it says
    /// `stale`, which the client was never told and cannot match against what it
    /// holds; set it from the last announced and it says `ok`, which is exactly
    /// what the client has on screen.
    #[test]
    fn p_212_prev_is_the_last_one_announced_and_not_the_last_observed() {
        let announced = ok();
        let now = absent();
        let mut sweep = ValidityChanged::new(41);
        assert!(
            sweep
                .push(&VChange {
                    sig: id(9),
                    q: now,
                    prev: announced,
                })
                .expect("encodes")
        );

        let mut out = [0u8; MAX_EVENT_BODY];
        let len = sweep.encode(&mut out).expect("encodes");
        let (_, mut entries) =
            ValidityChanged::decode(out.get(..len).expect("written")).expect("decodes");
        let entry = entries.next().expect("one entry").expect("it decodes");
        assert_eq!(
            entry.prev, announced,
            "prev is not the q the client was last sent"
        );
        assert_eq!(entry.q, now);
    }

    /// A topology change round trips, and its reason is a closed space.
    #[test]
    fn p_213_a_topology_change_says_why_the_revision_moved() {
        for reason in [
            TopologyChangeReason::Boot,
            TopologyChangeReason::ConfigWrite,
            TopologyChangeReason::SubDeviceAdopted,
            TopologyChangeReason::SubDeviceRemoved,
            TopologyChangeReason::DeviceReplaced,
        ] {
            let moved = TopologyChanged {
                rev: 42,
                reason,
                added: 17,
                removed: 3,
            };
            let mut out = [0u8; 64];
            let len = moved.encode(&mut out).expect("encodes");
            assert_eq!(
                TopologyChanged::decode(out.get(..len).expect("written")),
                Ok(moved)
            );
        }
    }

    /// **The first `0x0901` after a restart carries what the tables hold.**
    ///
    /// Zero counts at boot would be a controller reporting it came up with no
    /// topology, on the one event where a client has the least other evidence.
    /// The rule is P-213's; what this pins is that the body can say it — a
    /// `1 boot` carrying real counts encodes and reads back as one.
    #[test]
    fn p_213_a_boot_reports_the_rows_it_came_up_with_rather_than_a_delta() {
        let booted = TopologyChanged {
            rev: 1,
            reason: TopologyChangeReason::Boot,
            added: 312,
            removed: 0,
        };
        let mut out = [0u8; 64];
        let len = booted.encode(&mut out).expect("encodes");
        let read = TopologyChanged::decode(out.get(..len).expect("written")).expect("decodes");
        assert_eq!(read.added, 312, "a boot that reported no topology");
        assert_eq!(read.reason, TopologyChangeReason::Boot);
    }

    /// A reason or a presence this version does not allocate is refused rather
    /// than carried. Both spaces are closed under P-019.
    #[test]
    fn a_reason_or_a_presence_this_version_does_not_allocate_is_refused() {
        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(4).expect("a map");
        for (k, v) in [(1i64, 42u64), (2, 9), (3, 0), (4, 0)] {
            cbor.key(k).expect("a key");
            cbor.u64(v).expect("a value");
        }
        let len = cbor.finish().expect("handmade");
        assert_eq!(
            TopologyChanged::decode(out.get(..len).expect("written")),
            Err(ChangeError::UnknownReason(9))
        );

        let mut cbor = CborWriter::new(&mut out);
        cbor.map(2).expect("a map");
        cbor.key(1).expect("rev");
        cbor.u64(41).expect("rev");
        cbor.key(2).expect("e");
        cbor.array(1).expect("one entry");
        cbor.map(3).expect("an entry");
        for (k, v) in [(1i64, 3u64), (2, 7), (3, 1)] {
            cbor.key(k).expect("a key");
            cbor.u64(v).expect("a value");
        }
        let len = cbor.finish().expect("handmade");
        let (_, mut entries) =
            PresenceChanged::decode(out.get(..len).expect("written")).expect("the body reads");
        assert_eq!(entries.next(), Some(Err(ChangeError::UnknownPresence(7))));
    }

    /// Every truncation of a sweep and of a topology change is refused, and
    /// none panics. A resynchronising receiver hands a decoder arbitrary bytes.
    #[test]
    fn a_change_record_cut_short_is_refused_and_never_panics() {
        let mut sweep = ValidityChanged::new(41);
        for n in 1..=3u16 {
            assert!(
                sweep
                    .push(&VChange {
                        sig: id(n),
                        q: absent(),
                        prev: ok(),
                    })
                    .expect("encodes")
            );
        }
        let mut out = [0u8; MAX_EVENT_BODY];
        let len = sweep.encode(&mut out).expect("encodes");
        for cut in 0..len {
            let short = out.get(..cut).expect("a prefix");
            assert!(
                ValidityChanged::decode(short).is_err(),
                "a prefix of {cut} bytes decoded as a sweep"
            );
        }
        assert!(ValidityChanged::decode(out.get(..len).expect("the body")).is_ok());

        let moved = TopologyChanged {
            rev: 42,
            reason: TopologyChangeReason::ConfigWrite,
            added: 1,
            removed: 1,
        };
        let mut small = [0u8; 64];
        let len = moved.encode(&mut small).expect("encodes");
        for cut in 0..len {
            assert!(TopologyChanged::decode(small.get(..cut).expect("a prefix")).is_err());
        }

        for byte in 0..=u8::MAX {
            let noise = [byte, byte, byte, byte];
            assert!(TopologyChanged::decode(&noise).is_err());
            assert!(ValidityChanged::decode(&noise).is_err());
            assert!(PresenceChanged::decode(&noise).is_err());
        }
    }

    /// The body was read as far as key 2 and no further, so bytes after the
    /// array were never looked at. Three of them here; a whole second body
    /// would have passed the same way.
    #[test]
    fn a_sweep_body_with_bytes_after_its_array_is_refused() {
        let mut sweep = ValidityChanged::new(41);
        assert!(
            sweep
                .push(&VChange {
                    sig: id(1),
                    q: absent(),
                    prev: ok(),
                })
                .expect("encodes")
        );
        let mut out = [0u8; MAX_EVENT_BODY + 3];
        let len = sweep.encode(&mut out).expect("encodes");
        assert!(ValidityChanged::decode(out.get(..len).expect("the body")).is_ok());
        for tail in out.get_mut(len..len + 3).expect("room for a tail") {
            *tail = 0xff;
        }
        assert!(
            ValidityChanged::decode(out.get(..len + 3).expect("the body and a tail")).is_err(),
            "a body with three bytes after its array was accepted"
        );
    }

    /// `0x0901` had an encoder and a decoder that agreed with each other and
    /// had never been asked by a test. Read back whole, refused at every cut.
    #[test]
    fn a_topology_change_reads_back_and_is_refused_at_every_cut() {
        let change = TopologyChanged {
            rev: 42,
            reason: TopologyChangeReason::DeviceReplaced,
            added: 3,
            removed: 1,
        };
        let mut out = [0u8; 32];
        let len = change.encode(&mut out).expect("encodes");
        assert_eq!(
            TopologyChanged::decode(out.get(..len).expect("the body")),
            Ok(change)
        );
        for cut in 0..len {
            assert!(
                TopologyChanged::decode(out.get(..cut).expect("a prefix")).is_err(),
                "a prefix of {cut} bytes decoded"
            );
        }
    }

    /// The presence sweep had no truncation test at all, and the validity one
    /// asserted nothing. Both read a body the same way, so both are refused at
    /// every cut.
    #[test]
    fn a_presence_sweep_cut_short_at_any_byte_is_refused() {
        let mut sweep = PresenceChanged::new(41);
        assert!(
            sweep
                .push(&PChange {
                    dev: id(3),
                    presence: Presence::Offline,
                    prev: Presence::Online,
                })
                .expect("encodes")
        );
        let mut out = [0u8; MAX_EVENT_BODY];
        let len = sweep.encode(&mut out).expect("encodes");
        for cut in 0..len {
            assert!(
                PresenceChanged::decode(out.get(..cut).expect("a prefix")).is_err(),
                "a prefix of {cut} bytes decoded as a sweep"
            );
        }
        let (rev, entries) =
            PresenceChanged::decode(out.get(..len).expect("the body")).expect("whole");
        assert_eq!(rev, 41);
        assert_eq!(entries.count(), 1);
    }
}
