//! `ReadConcerns 0x0F` / `Concerns 0x8F` — what is wrong at the site, as state.
//!
//! Three conditional-presence rules live here rather than in a paragraph, and
//! each is a sentence somebody would otherwise have to remember: key 12 `vns` is
//! present exactly when key 11 `raw` is, key 5 `elem` needs the key 4 `sig` that
//! tells a client which `ebase` to add it to, and key 9 `age` is always there.
//! Two of the three are held by types that cannot express the wrong shape, and
//! the third by a field that is not an `Option`.
//!
//! The decoder is not the encoder read backwards. A controller at the other end
//! of the link does not have this crate, so every rule the builder holds by
//! construction is checked again on the way in — a row carrying a vendor code
//! from nobody, or an element of no signal, arrives well formed and MAC-verified
//! and means nothing a client can render.

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::generated::{ConcernState, Condition, Severity, VendorNamespace};
use crate::ident::{Id, IdError};
use crate::limits::{
    CONCERN_MAX_BYTES, MAX_CONCERN_PAGE_BYTES, MAX_CONCERN_PAGE_ROWS, MAX_SERIES_LEN,
};

/// A 1-based position within a series signal, which is **not** the label a
/// person reads.
///
/// P-206 joins the two: the label is the signal's `ebase` + this − 1. Fixture 3
/// pins pack 2 to `ebase = 17`, where position 7 is the cell painted 23 — and an
/// encoder that wrote 23 here would be describing a cell in the other pack.
///
/// Bounded above as well as below, which is what keeps it one byte on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ElementAt(u8);

impl ElementAt {
    /// Refuses 0, which would render as `ebase` − 1, and anything past
    /// [`MAX_SERIES_LEN`], which is the length no series exceeds — a number
    /// above it is a **label** somebody has written where a position belongs,
    /// and that is the one mistake P-206 exists to catch.
    pub fn new(position: u8) -> Result<Self, ConcernsError> {
        if position == 0 {
            return Err(ConcernsError::ZeroElement);
        }
        if usize::from(position) > MAX_SERIES_LEN {
            return Err(ConcernsError::ElementPastSeries(position));
        }
        Ok(Self(position))
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The source's own code for a condition, and the namespace that reads it.
///
/// One value and not two fields, because key 12 is REQUIRED when key 11 is
/// present and absent otherwise — and two `Option`s hold exactly the pair that
/// rule forbids. A raw code with no namespace is a number from nobody; a
/// namespace with no code names a vendor and says nothing about them. Two
/// vendors both use `0x0021` for different things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorCode {
    /// Preserved verbatim. Never normalised and never mapped onto a
    /// [`Condition`] — that is what key 6 is for, and a vendor code translated
    /// into a guess is the translation this project refuses.
    pub raw: u32,
    /// Whose code it is.
    pub vns: VendorNamespace,
}

/// A device, or one component of it.
///
/// `cmp = 0` is the device as a whole (P-200), and it is reachable only through
/// [`Self::device`] — so a caller cannot put a bare 0 in the component position
/// and mean a component, which is the confusion the reservation exists against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Part {
    dev: Id,
    cmp: u16,
}

impl Part {
    /// The whole device, which is `cmp = 0` on the wire.
    #[must_use]
    pub const fn device(dev: Id) -> Self {
        Self { dev, cmp: 0 }
    }

    /// One component of it.
    #[must_use]
    pub const fn component(dev: Id, cmp: Id) -> Self {
        Self {
            dev,
            cmp: cmp.get(),
        }
    }

    #[must_use]
    pub const fn dev(self) -> Id {
        self.dev
    }

    /// Key 3 as it goes out, where 0 means the device as a whole.
    #[must_use]
    pub const fn cmp(self) -> u16 {
        self.cmp
    }

    #[must_use]
    pub const fn is_device(self) -> bool {
        self.cmp == 0
    }
}

/// What a concern is about, as far down as the source could say.
///
/// Fused rather than two optional keys, because an element with no signal is
/// unanswerable: *cell 7* of what? P-206's rendering needs the signal to find
/// `ebase`, so a client handed a position without one cannot print the label at
/// all — it has a number and no way to turn it into the one painted on the cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// The device or the component, and nothing narrower.
    Part(Part),
    /// One signal on that part.
    Signal(Part, Id),
    /// One element of a series signal, by position.
    Element(Part, Id, ElementAt),
}

impl Subject {
    #[must_use]
    pub const fn part(self) -> Part {
        match self {
            Self::Part(part) | Self::Signal(part, _) | Self::Element(part, _, _) => part,
        }
    }

    /// Key 4, absent when the concern is about the part as a whole.
    #[must_use]
    pub const fn sig(self) -> Option<Id> {
        match self {
            Self::Part(_) => None,
            Self::Signal(_, sig) | Self::Element(_, sig, _) => Some(sig),
        }
    }

    /// Key 5, absent unless the concern is about one element.
    #[must_use]
    pub const fn at(self) -> Option<ElementAt> {
        match self {
            Self::Part(_) | Self::Signal(_, _) => None,
            Self::Element(_, _, at) => Some(at),
        }
    }
}

/// The keys of a `Concern`, so a decoder branches on a name rather than on a
/// literal that could be typed one out, and a refusal says `cid` rather than
/// `1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcernKey {
    Cid = 1,
    Dev = 2,
    Cmp = 3,
    Sig = 4,
    Elem = 5,
    Cond = 6,
    Sev = 7,
    State = 8,
    Age = 9,
    Since = 10,
    Raw = 11,
    Vns = 12,
    Seq = 13,
}

impl ConcernKey {
    const fn name(self) -> &'static str {
        match self {
            Self::Cid => "cid",
            Self::Dev => "dev",
            Self::Cmp => "cmp",
            Self::Sig => "sig",
            Self::Elem => "elem",
            Self::Cond => "cond",
            Self::Sev => "sev",
            Self::State => "state",
            Self::Age => "age",
            Self::Since => "since",
            Self::Raw => "raw",
            Self::Vns => "vns",
            Self::Seq => "seq",
        }
    }

    const fn of(key: i64) -> Option<Self> {
        match key {
            1 => Some(Self::Cid),
            2 => Some(Self::Dev),
            3 => Some(Self::Cmp),
            4 => Some(Self::Sig),
            5 => Some(Self::Elem),
            6 => Some(Self::Cond),
            7 => Some(Self::Sev),
            8 => Some(Self::State),
            9 => Some(Self::Age),
            10 => Some(Self::Since),
            11 => Some(Self::Raw),
            12 => Some(Self::Vns),
            13 => Some(Self::Seq),
            _ => None,
        }
    }
}

/// One row of a `Concerns 0x8F`.
///
/// Every field is public because not one of them can be set to a shape the wire
/// forbids: [`Subject`] cannot hold an element without a signal, [`VendorCode`]
/// cannot hold a code without a namespace, and `age` is not an `Option` because
/// P-211 says it is always there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Concern {
    /// Key 1. Stable for as long as the row lives, and never reallocated before
    /// the record announcing its clear is committed (P-180).
    pub cid: Id,
    /// Keys 2 to 5.
    pub subject: Subject,
    /// Key 6, normalised. Skip-unknown under P-019, so a condition nobody has
    /// allocated still renders with its number rather than being dropped.
    pub cond: Condition,
    /// Key 7. What band this sits in, which is what decided admission.
    pub sev: Severity,
    /// Key 8.
    pub state: ConcernState,
    /// Key 9. Seconds on P-004's tick since first observed, always present, and
    /// carried across a restart or the row is not restored at all (P-211).
    pub age: u32,
    /// Key 10. Omitted when the clock has never been set — never a zero, which
    /// is 1970 and reads as a date (P-093).
    pub since: Option<u64>,
    /// Keys 11 and 12, together or not at all.
    pub code: Option<VendorCode>,
    /// Key 13. The log position of the record that opened the row, so a client
    /// replaying from a `seq` it holds can tell which concerns it has already
    /// been told about.
    pub seq: u64,
}

impl Concern {
    /// Keys 1 to 13, ascending, with the optional ones written only when they
    /// are there.
    pub fn encode(&self, cbor: &mut CborWriter<'_>) -> Result<(), CborError> {
        let subject = self.subject;
        let pairs = 8
            + usize::from(subject.sig().is_some())
            + usize::from(subject.at().is_some())
            + usize::from(self.since.is_some())
            + if self.code.is_some() { 2 } else { 0 };
        cbor.map(pairs)?;
        cbor.key(ConcernKey::Cid as i64)?;
        cbor.u64(u64::from(self.cid.get()))?;
        cbor.key(ConcernKey::Dev as i64)?;
        cbor.u64(u64::from(subject.part().dev().get()))?;
        cbor.key(ConcernKey::Cmp as i64)?;
        cbor.u64(u64::from(subject.part().cmp()))?;
        if let Some(sig) = subject.sig() {
            cbor.key(ConcernKey::Sig as i64)?;
            cbor.u64(u64::from(sig.get()))?;
        }
        if let Some(at) = subject.at() {
            cbor.key(ConcernKey::Elem as i64)?;
            cbor.u64(u64::from(at.get()))?;
        }
        cbor.key(ConcernKey::Cond as i64)?;
        cbor.u64(u64::from(self.cond.0))?;
        cbor.key(ConcernKey::Sev as i64)?;
        cbor.u64(self.sev as u64)?;
        cbor.key(ConcernKey::State as i64)?;
        cbor.u64(self.state as u64)?;
        cbor.key(ConcernKey::Age as i64)?;
        cbor.u64(u64::from(self.age))?;
        if let Some(since) = self.since {
            cbor.key(ConcernKey::Since as i64)?;
            cbor.u64(since)?;
        }
        if let Some(code) = self.code {
            cbor.key(ConcernKey::Raw as i64)?;
            cbor.u64(u64::from(code.raw))?;
            cbor.key(ConcernKey::Vns as i64)?;
            cbor.u64(u64::from(code.vns.0))?;
        }
        cbor.key(ConcernKey::Seq as i64)?;
        cbor.u64(self.seq)?;
        Ok(())
    }

    /// Read one row, refusing every shape [`Self::encode`] will not write.
    ///
    /// This is the half that matters, because the other end of the link is not
    /// this crate. A row with `raw` and no `vns` is a code from nobody rendered
    /// as a bare number; a row with `elem` and no `sig` is a position with no
    /// `ebase` to add it to, which a client either drops or prints as a cell
    /// number from the wrong pack.
    pub fn decode(payload: &[u8]) -> Result<Self, ConcernsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut cid, mut dev, mut cmp, mut sig, mut elem) = (None, None, None, None, None);
        let (mut cond, mut sev, mut state, mut age) = (None, None, None, None);
        let (mut since, mut raw, mut vns, mut seq) = (None, None, None, None);
        for _ in 0..pairs {
            match ConcernKey::of(body.key()?) {
                Some(ConcernKey::Cid) => cid = Some(Id::new(body.u16()?)?),
                Some(ConcernKey::Dev) => dev = Some(Id::new(body.u16()?)?),
                Some(ConcernKey::Cmp) => cmp = Some(body.u16()?),
                Some(ConcernKey::Sig) => sig = Some(Id::new(body.u16()?)?),
                Some(ConcernKey::Elem) => elem = Some(ElementAt::new(body.u8()?)?),
                Some(ConcernKey::Cond) => cond = Some(Condition(body.u16()?)),
                Some(ConcernKey::Sev) => {
                    let number = body.u8()?;
                    sev = Some(
                        Severity::try_from(number)
                            .map_err(|()| ConcernsError::UnknownSeverity(number))?,
                    );
                }
                Some(ConcernKey::State) => {
                    let number = body.u8()?;
                    state = Some(
                        ConcernState::try_from(number)
                            .map_err(|()| ConcernsError::UnknownState(number))?,
                    );
                }
                Some(ConcernKey::Age) => age = Some(body.u32()?),
                Some(ConcernKey::Since) => since = Some(body.u64()?),
                Some(ConcernKey::Raw) => raw = Some(body.u32()?),
                Some(ConcernKey::Vns) => vns = Some(VendorNamespace(body.u16()?)),
                Some(ConcernKey::Seq) => seq = Some(body.u64()?),
                // A key a newer peer allocated. Skipped, never refused — that is
                // P-013, and refusing here would drop a whole page of concerns
                // because one row grew a field.
                None => body.skip()?,
            }
        }
        body.finish()?;

        let part = match cmp.ok_or(ConcernsError::MissingRow(ConcernKey::Cmp))? {
            0 => Part::device(dev.ok_or(ConcernsError::MissingRow(ConcernKey::Dev))?),
            other => Part::component(
                dev.ok_or(ConcernsError::MissingRow(ConcernKey::Dev))?,
                Id::new(other)?,
            ),
        };
        let subject = match (sig, elem) {
            (Some(sig), Some(at)) => Subject::Element(part, sig, at),
            (Some(sig), None) => Subject::Signal(part, sig),
            (None, None) => Subject::Part(part),
            (None, Some(_)) => return Err(ConcernsError::ElementWithoutSignal),
        };
        let code = match (raw, vns) {
            (Some(raw), Some(vns)) => Some(VendorCode { raw, vns }),
            (None, None) => None,
            (Some(_), None) => return Err(ConcernsError::CodeWithoutNamespace),
            (None, Some(_)) => return Err(ConcernsError::NamespaceWithoutCode),
        };

        Ok(Self {
            cid: cid.ok_or(ConcernsError::MissingRow(ConcernKey::Cid))?,
            subject,
            cond: cond.ok_or(ConcernsError::MissingRow(ConcernKey::Cond))?,
            sev: sev.ok_or(ConcernsError::MissingRow(ConcernKey::Sev))?,
            state: state.ok_or(ConcernsError::MissingRow(ConcernKey::State))?,
            age: age.ok_or(ConcernsError::MissingRow(ConcernKey::Age))?,
            since,
            code,
            seq: seq.ok_or(ConcernsError::MissingRow(ConcernKey::Seq))?,
        })
    }
}

/// An `0x0501 concern raised` body: a row entering the table.
///
/// Key 2 is the same [`Concern`] the page carries, encoded by the same code.
/// A second shape meaning nearly the same thing is two decoders to keep in step
/// and one of them will be the one nobody exercises — the raise path is rarer
/// than the page path by exactly the margin that hides a bug until a pack goes
/// out of balance in February.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcernRaised {
    pub rev: u32,
    pub concern: Concern,
}

impl ConcernRaised {
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ConcernsError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(2)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(2)?;
        self.concern.encode(&mut cbor)?;
        Ok(cbor.finish()?)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ConcernsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut rev, mut concern) = (None, None);
        for _ in 0..pairs {
            match body.key()? {
                1 => rev = Some(body.u32()?),
                // Read as the bytes it arrived as and decoded by the row's own
                // code, so the two paths cannot drift.
                2 => concern = Some(Concern::decode(body.raw()?)?),
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            rev: rev.ok_or(ConcernsError::MissingEvent(1))?,
            concern: concern.ok_or(ConcernsError::MissingEvent(2))?,
        })
    }
}

/// An `0x0502 concern changed` body: a row this client already holds moving.
///
/// Five fields and not the row, because the client has the row. What it does
/// not have is which state the controller moved **from**, and P-096 lets a
/// record go missing — so without key 6 a lifecycle that skipped a state and one
/// where a record was dropped are the same two frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcernChanged {
    pub rev: u32,
    pub cid: Id,
    /// Carried for the client that never saw the raise. *Concern 12 is over* is
    /// unrenderable; *the pack's under-temperature protection is over* is a
    /// sentence, and it costs six bytes.
    pub dev: Id,
    pub cond: Condition,
    /// The state it moved to. `5 cleared` is the row leaving the table (P-180).
    pub state: ConcernState,
    /// The state it moved from.
    pub prev: ConcernState,
}

impl ConcernChanged {
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ConcernsError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(6)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.cid.get()))?;
        cbor.key(3)?;
        cbor.u64(u64::from(self.dev.get()))?;
        cbor.key(4)?;
        cbor.u64(u64::from(self.cond.0))?;
        cbor.key(5)?;
        cbor.u64(self.state as u64)?;
        cbor.key(6)?;
        cbor.u64(self.prev as u64)?;
        Ok(cbor.finish()?)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ConcernsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut rev, mut cid, mut dev) = (None, None, None);
        let (mut cond, mut state, mut prev) = (None, None, None);
        let read_state = |body: &mut CborReader<'_>| -> Result<ConcernState, ConcernsError> {
            let number = body.u8()?;
            ConcernState::try_from(number).map_err(|()| ConcernsError::UnknownState(number))
        };
        for _ in 0..pairs {
            match body.key()? {
                1 => rev = Some(body.u32()?),
                2 => cid = Some(Id::new(body.u16()?)?),
                3 => dev = Some(Id::new(body.u16()?)?),
                4 => cond = Some(Condition(body.u16()?)),
                5 => state = Some(read_state(&mut body)?),
                6 => prev = Some(read_state(&mut body)?),
                _ => body.skip()?,
            }
        }
        body.finish()?;

        let state = state.ok_or(ConcernsError::MissingEvent(5))?;
        let prev = prev.ok_or(ConcernsError::MissingEvent(6))?;
        // A transition to the state it was already in is not a transition, and
        // a client that renders it draws a change nobody made.
        if state == prev {
            return Err(ConcernsError::WentNowhere(state));
        }
        Ok(Self {
            rev: rev.ok_or(ConcernsError::MissingEvent(1))?,
            cid: cid.ok_or(ConcernsError::MissingEvent(2))?,
            dev: dev.ok_or(ConcernsError::MissingEvent(3))?,
            cond: cond.ok_or(ConcernsError::MissingEvent(4))?,
            state,
            prev,
        })
    }
}

/// What a `Concerns 0x8F` answers. Evaluated in ascending order, first match
/// wins (P-199).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcernsOutcome {
    /// Answered, in whole or in part. **An empty table is this**, with no rows
    /// and `next = 0` — *nothing is wrong at this site* is an answer, and a
    /// client that reads a refusal instead shows a screen with no state on it.
    Ok,
    /// The `rev` named was neither 0 nor current (P-146).
    Superseded,
    /// `from` is greater than the largest `cid` the table holds.
    OutOfRange,
}

impl ConcernsOutcome {
    const fn number(self) -> u8 {
        match self {
            Self::Ok => 1,
            Self::Superseded => 2,
            Self::OutOfRange => 3,
        }
    }

    const fn of(number: u8) -> Option<Self> {
        match number {
            1 => Some(Self::Ok),
            2 => Some(Self::Superseded),
            3 => Some(Self::OutOfRange),
            _ => None,
        }
    }
}

/// A page of concerns under construction.
///
/// Rows go in one at a time, each encoded into a scratch and measured, so the
/// byte arm is checked against what the row actually cost rather than against
/// its worst case. The row arm is the one that binds here — twelve rows at their
/// widest are 756 bytes against 832 — and the byte arm stays because a later key
/// on `Concern` must not turn a legal page into a frame the controller builds
/// and then refuses (P-208).
pub struct ConcernsPage {
    scratch: [u8; MAX_CONCERN_PAGE_BYTES],
    used: usize,
    rows: usize,
    /// The `cid` to pass back as `from`, or 0 when this page ends the walk.
    next: u16,
}

impl Default for ConcernsPage {
    fn default() -> Self {
        Self::new()
    }
}

impl ConcernsPage {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scratch: [0u8; MAX_CONCERN_PAGE_BYTES],
            used: 0,
            rows: 0,
            next: 0,
        }
    }

    /// Try to add a row, and say whether the page took it.
    ///
    /// `Ok(false)` is a full page and not an error: the caller has the row that
    /// did not fit, and its `cid` is where the next page resumes. A row is never
    /// split, so a page that cannot take a whole one takes none of it.
    pub fn push(&mut self, concern: &Concern) -> Result<bool, ConcernsError> {
        if self.rows >= MAX_CONCERN_PAGE_ROWS {
            self.next = concern.cid.get();
            return Ok(false);
        }
        let mut one = [0u8; CONCERN_MAX_BYTES];
        let mut cbor = CborWriter::new(&mut one);
        concern.encode(&mut cbor)?;
        let len = cbor.finish()?;
        let end = self.used.saturating_add(len);
        if end > MAX_CONCERN_PAGE_BYTES {
            self.next = concern.cid.get();
            return Ok(false);
        }
        let slot = self
            .scratch
            .get_mut(self.used..end)
            .ok_or(ConcernsError::RowTooLong(len))?;
        let src = one.get(..len).ok_or(ConcernsError::RowTooLong(len))?;
        slot.copy_from_slice(src);
        self.used = end;
        self.rows = self.rows.saturating_add(1);
        Ok(true)
    }

    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// The encoded length of the rows, which is the byte arm's side of P-208.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.used
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// The `cid` a client passes back as `from`; 0 when this page ended the walk.
    #[must_use]
    pub const fn next(&self) -> u16 {
        self.next
    }

    /// Write key 3, in the order the rows were pushed.
    ///
    /// Nothing is re-encoded: each row goes through [`CborWriter::raw`], which
    /// checks it is exactly one well-formed item and copies it.
    fn encode_rows(&self, cbor: &mut CborWriter<'_>) -> Result<(), ConcernsError> {
        let packed = self
            .scratch
            .get(..self.used)
            .ok_or(ConcernsError::RowTooLong(self.used))?;
        let mut reader = CborReader::new(packed);
        cbor.array(self.rows)?;
        for _ in 0..self.rows {
            cbor.raw(reader.raw()?)?;
        }
        Ok(())
    }
}

/// A `ReadConcerns 0x0F`: which revision the client holds, and where to resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadConcerns {
    pub rev: u32,
    /// The `cid` to resume at, inclusive. 0 means from the beginning, and is the
    /// one place 0 is legal here because it is a cursor and not an id.
    pub from: u16,
}

impl ReadConcerns {
    #[must_use]
    pub const fn new(rev: u32, from: u16) -> Self {
        Self { rev, from }
    }

    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ConcernsError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(2)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.from))?;
        Ok(cbor.finish()?)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ConcernsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut rev, mut from) = (None, None);
        for _ in 0..pairs {
            match body.key()? {
                1 => rev = Some(body.u32()?),
                2 => from = Some(body.u16()?),
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            rev: rev.ok_or(ConcernsError::MissingRequest(1))?,
            from: from.ok_or(ConcernsError::MissingRequest(2))?,
        })
    }
}

/// A `Concerns 0x8F` body.
///
/// No `Debug`: the page it borrows is most of a kilobyte of encoded rows, and a
/// derived one prints all of it.
#[derive(Clone, Copy)]
pub struct ConcernsBody<'a> {
    pub rev: u32,
    /// Key 2, and the pin a walk is held against (P-210).
    pub seq: u64,
    /// Key 5. Every row the walk returns, the `cleared` ones included (P-209).
    pub total: u16,
    /// Key 6. **Saturates rather than wraps**: a site that has refused more than
    /// 65,535 concerns needs a bigger table either way, and a count that wrapped
    /// would say it had refused almost none.
    pub refused: u16,
    pub outcome: ConcernsOutcome,
    /// Present only on outcome 1. Every other outcome answered nothing (P-199).
    pub page: Option<&'a ConcernsPage>,
}

impl ConcernsBody<'_> {
    /// Encode the body, refusing the shape P-199 forbids rather than writing it.
    ///
    /// `next = 0` is the natural encoding of *nothing follows*, so a response
    /// that answered nothing is otherwise shaped exactly like one that answered
    /// everything — and on outcome 3 the `rev` matches, so nothing else fires.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ConcernsError> {
        let answered = matches!(self.outcome, ConcernsOutcome::Ok);
        if !answered && self.page.is_some_and(|page| !page.is_empty()) {
            return Err(ConcernsError::AnsweredNothing(self.outcome));
        }
        let page = self.page.filter(|_| answered);
        let next = page.map_or(0, ConcernsPage::next);
        let rows = page.is_some_and(|page| page.rows() > 0);

        let mut cbor = CborWriter::new(dst);
        cbor.map(6 + usize::from(rows))?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(2)?;
        cbor.u64(self.seq)?;
        if let Some(page) = page.filter(|_| rows) {
            cbor.key(3)?;
            page.encode_rows(&mut cbor)?;
        }
        cbor.key(4)?;
        cbor.u64(u64::from(next))?;
        cbor.key(5)?;
        cbor.u64(u64::from(self.total))?;
        cbor.key(6)?;
        cbor.u64(u64::from(self.refused))?;
        cbor.key(7)?;
        cbor.u64(u64::from(self.outcome.number()))?;
        Ok(cbor.finish()?)
    }
}

/// What a client reads out of a `Concerns 0x8F` before it looks at the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcernsHeader {
    pub rev: u32,
    pub seq: u64,
    pub next: u16,
    pub total: u16,
    pub refused: u16,
    pub outcome: ConcernsOutcome,
    /// How many rows key 3 carried. Compared against `total` and `next`, this is
    /// how a client tells a short page from a torn one.
    pub rows: usize,
}

impl ConcernsHeader {
    /// Read the body, refusing what [`ConcernsBody::encode`] refuses to write.
    ///
    /// A receiver that accepts a page-that-answered-nothing is a receiver that
    /// will render it, and on outcome 3 there is nothing else to say the page is
    /// empty for a reason.
    pub fn decode(payload: &[u8]) -> Result<Self, ConcernsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut rev, mut seq, mut next) = (None, None, None);
        let (mut total, mut refused, mut outcome) = (None, None, None);
        let mut rows = 0usize;
        for _ in 0..pairs {
            match body.key()? {
                1 => rev = Some(body.u32()?),
                2 => seq = Some(body.u64()?),
                3 => {
                    let n = body.array()?;
                    for _ in 0..n {
                        body.skip()?;
                    }
                    rows = n;
                }
                4 => next = Some(body.u16()?),
                5 => total = Some(body.u16()?),
                6 => refused = Some(body.u16()?),
                7 => outcome = Some(body.u8()?),
                _ => body.skip()?,
            }
        }
        body.finish()?;

        let number = outcome.ok_or(ConcernsError::MissingResponse(7))?;
        let outcome = ConcernsOutcome::of(number).ok_or(ConcernsError::UnknownOutcome(number))?;
        let next = next.ok_or(ConcernsError::MissingResponse(4))?;
        if !matches!(outcome, ConcernsOutcome::Ok) && (next != 0 || rows > 0) {
            return Err(ConcernsError::AnsweredNothing(outcome));
        }
        if rows > MAX_CONCERN_PAGE_ROWS {
            return Err(ConcernsError::PagePastRowCap(rows));
        }
        Ok(Self {
            rev: rev.ok_or(ConcernsError::MissingResponse(1))?,
            seq: seq.ok_or(ConcernsError::MissingResponse(2))?,
            next,
            total: total.ok_or(ConcernsError::MissingResponse(5))?,
            refused: refused.ok_or(ConcernsError::MissingResponse(6))?,
            outcome,
            rows,
        })
    }
}

/// The rows of one page, decoded on demand.
///
/// An iterator of `Result` rather than a decode-them-all, because there is no
/// allocator to put twelve decoded rows in, and a caller that stops at the first
/// refusal should not have paid for the rest.
pub struct ConcernRows<'a> {
    body: CborReader<'a>,
    left: usize,
}

impl<'a> ConcernRows<'a> {
    /// Find key 3 in a body and walk it.
    ///
    /// Reads the payload rather than borrowing anything from a
    /// [`ConcernsHeader`], so a client that only wants `total` and `next` never
    /// decodes a row at all — which is the ordinary case, because those two are
    /// what decide whether to ask for another page.
    ///
    /// A body with no key 3 is an empty walk and not an error: outcome 1 with no
    /// rows is how *nothing is wrong at this site* is said.
    pub fn of(payload: &'a [u8]) -> Result<Self, ConcernsError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        for _ in 0..pairs {
            if body.key()? == 3 {
                let left = body.array()?;
                return Ok(Self { body, left });
            }
            body.skip()?;
        }
        Ok(Self { body, left: 0 })
    }
}

impl Iterator for ConcernRows<'_> {
    type Item = Result<Concern, ConcernsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left = self.left.saturating_sub(1);
        Some(
            self.body
                .raw()
                .map_err(ConcernsError::from)
                .and_then(Concern::decode),
        )
    }
}

/// Why a `ReadConcerns` or a `Concerns` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcernsError {
    /// 0 handed to an id space that reserves it as the paging sentinel.
    ZeroId,
    /// A 1-based position given as 0, which would render as `ebase` − 1.
    ZeroElement,
    /// A position past the longest series there is, which is a label that has
    /// been written where a position belongs.
    ElementPastSeries(u8),
    /// Key 5 with no key 4: a position with no signal to find an `ebase` on.
    ElementWithoutSignal,
    /// Key 11 with no key 12: a vendor's own code with nobody to read it.
    CodeWithoutNamespace,
    /// Key 12 with no key 11: a vendor named and nothing said about them.
    NamespaceWithoutCode,
    /// A severity this version does not allocate. Closed under P-019, so it is
    /// refused rather than carried.
    UnknownSeverity(u8),
    /// A concern state this version does not allocate. Closed for the same
    /// reason, and the one that decides whether a charger may start.
    UnknownState(u8),
    /// A required key of a `ReadConcerns` never arrived (P-015).
    MissingRequest(u8),
    /// A required key of a `Concerns` never arrived (P-015).
    MissingResponse(u8),
    /// A required key of a `Concern` row never arrived (P-015).
    MissingRow(ConcernKey),
    /// A required key of an `0x0501` or `0x0502` body never arrived (P-015).
    MissingEvent(u8),
    /// An `0x0502` whose new state is the one it moved from. Not a transition,
    /// and a client that renders it draws a change nobody made.
    WentNowhere(ConcernState),
    /// A row longer than [`CONCERN_MAX_BYTES`], which is a bound in `limits.rs`
    /// being wrong rather than a page to end.
    RowTooLong(usize),
    /// More rows than [`MAX_CONCERN_PAGE_ROWS`], which a decoder cannot hold.
    PagePastRowCap(usize),
    /// An outcome other than 1 carrying rows or a cursor, which P-199 forbids.
    AnsweredNothing(ConcernsOutcome),
    /// An outcome number this version does not allocate.
    UnknownOutcome(u8),
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for ConcernsError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<IdError> for ConcernsError {
    /// Restated rather than carried, so a `Concerns` refusal reads in one
    /// vocabulary. Matched rather than mapped, so an [`IdError`] that grows a
    /// variant breaks here instead of arriving as the wrong sentence.
    fn from(why: IdError) -> Self {
        match why {
            IdError::Zero => Self::ZeroId,
        }
    }
}

impl fmt::Display for ConcernsError {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroId => w.write_str("0 is the end-of-paging sentinel and never an id"),
            Self::ZeroElement => w.write_str("an element position is 1-based and never 0"),
            Self::ElementPastSeries(n) => write!(
                w,
                "element position {n} is past the longest series, so it is a label and not a position"
            ),
            Self::ElementWithoutSignal => {
                w.write_str("an element position with no signal to find its ebase on")
            }
            Self::CodeWithoutNamespace => {
                w.write_str("a vendor code with no namespace, which is a number from nobody")
            }
            Self::NamespaceWithoutCode => w.write_str(
                "a vendor namespace with no code, which names a vendor and says nothing",
            ),
            Self::UnknownSeverity(n) => write!(w, "severity {n} is not allocated"),
            Self::UnknownState(n) => write!(w, "concern state {n} is not allocated"),
            Self::MissingRequest(k) => write!(w, "a ReadConcerns with no key {k}"),
            Self::MissingResponse(k) => write!(w, "a Concerns with no key {k}"),
            Self::MissingRow(k) => write!(w, "a Concern with no {}", k.name()),
            Self::MissingEvent(k) => write!(w, "a concern event with no key {k}"),
            Self::WentNowhere(s) => write!(
                w,
                "a concern change from state {} to itself, which is not a change",
                *s as u8
            ),
            Self::RowTooLong(n) => write!(w, "a concern of {n} bytes, past its own bound"),
            Self::PagePastRowCap(n) => write!(w, "a page of {n} rows, past the row cap"),
            Self::AnsweredNothing(o) => write!(
                w,
                "outcome {} carrying rows or a cursor, and it answered nothing",
                o.number()
            ),
            Self::UnknownOutcome(n) => write!(w, "concerns outcome {n} is not allocated"),
            Self::Cbor(why) => write!(w, "{why}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{CONCERNS_HEADER_BYTES, INNER_BODY_BYTES};

    fn id(value: u16) -> Id {
        Id::new(value).expect("a non-zero id")
    }

    fn at(position: u8) -> ElementAt {
        ElementAt::new(position).expect("a 1-based position inside a series")
    }

    /// Pack 2's cell 23, which is element **7** of a half-string signal whose
    /// `ebase` is 17. Every optional key present, so this is the row the byte
    /// budget was derived from.
    fn widest() -> Concern {
        Concern {
            cid: id(u16::MAX),
            subject: Subject::Element(
                Part::component(id(u16::MAX), id(u16::MAX)),
                id(u16::MAX),
                at(7),
            ),
            cond: Condition(0x4A12),
            sev: Severity::Protection,
            state: ConcernState::Active,
            age: u32::MAX,
            since: Some(u64::MAX),
            code: Some(VendorCode {
                raw: u32::MAX,
                vns: VendorNamespace(u16::MAX),
            }),
            seq: u64::MAX,
        }
    }

    /// The narrowest legal row: a whole device, no signal, no element, no
    /// timestamp, no vendor code.
    fn narrowest() -> Concern {
        Concern {
            cid: id(1),
            subject: Subject::Part(Part::device(id(1))),
            cond: Condition(1),
            sev: Severity::Info,
            state: ConcernState::Cleared,
            age: 0,
            since: None,
            code: None,
            seq: 0,
        }
    }

    fn encoded(concern: &Concern, into: &mut [u8]) -> usize {
        let mut cbor = CborWriter::new(into);
        concern
            .encode(&mut cbor)
            .expect("a row the encoder accepts");
        cbor.finish().expect("a finished row")
    }

    /// Build a row by hand, so a shape this encoder will not write can still be
    /// handed to the decoder. That is the only way to test what a controller at
    /// the other end of the link might send, and every key of a `Concern` is an
    /// unsigned integer, so one helper covers all thirteen.
    fn handmade(pairs: &[(i64, u64)], into: &mut [u8]) -> usize {
        let mut cbor = CborWriter::new(into);
        cbor.map(pairs.len()).expect("a map");
        for (key, value) in pairs {
            cbor.key(*key).expect("a key");
            cbor.u64(*value).expect("a value");
        }
        cbor.finish().expect("a handmade row")
    }

    /// Every required key, in ascending order, as a decoder must see them.
    fn required() -> [(i64, u64); 8] {
        [
            (1, 9),
            (2, 3),
            (3, 0),
            (6, 0x4A12),
            (7, Severity::Protection as u64),
            (8, ConcernState::Active as u64),
            (9, 6 * 3600),
            (13, 41),
        ]
    }

    /// **The row-width table is a check on the encoder and not a second copy of
    /// it.**
    ///
    /// `MAX_CONCERN_PAGE_ROWS` is 12 because twelve widest rows fit the byte
    /// cap, and that arithmetic is only true while a widest row is 63 bytes. Add
    /// a key to `Concern` and the constant in `limits.rs` is quietly wrong: the
    /// controller builds a legal page and then refuses the frame, and the client
    /// is told nothing about the rows it will never be sent.
    #[test]
    fn the_widest_row_is_the_width_the_page_cap_was_derived_from() {
        let mut out = [0u8; CONCERN_MAX_BYTES];
        assert_eq!(
            encoded(&widest(), &mut out),
            CONCERN_MAX_BYTES,
            "a widest Concern is no longer the width limits.rs divides the byte cap by"
        );
    }

    /// The other end of that arithmetic: twelve of them, measured rather than
    /// assumed, against the cap they are divided into.
    ///
    /// This is also what says the byte arm of P-208 is a **backstop** here and
    /// not a binding cap — 756 against 832, with 76 bytes of margin. The day a
    /// key takes that margin, this goes red before a controller builds a frame
    /// it cannot send.
    #[test]
    fn p_208_the_byte_arm_is_a_backstop_and_the_row_arm_is_what_binds() {
        let mut page = ConcernsPage::new();
        for n in 1..=MAX_CONCERN_PAGE_ROWS {
            // Ids above 255, or the `cid` costs one byte instead of three and
            // these stop being widest rows while still looking like them.
            let mut row = widest();
            row.cid = id(60_000 + u16::try_from(n).expect("a small offset"));
            assert!(page.push(&row).expect("encodes"), "row {n} must fit");
        }
        assert_eq!(page.rows(), MAX_CONCERN_PAGE_ROWS);
        assert_eq!(page.len(), MAX_CONCERN_PAGE_ROWS * CONCERN_MAX_BYTES);
        assert!(
            page.len() <= MAX_CONCERN_PAGE_BYTES,
            "twelve widest rows no longer fit the byte cap they were sized against"
        );

        let mut out = [0u8; INNER_BODY_BYTES];
        let body = ConcernsBody {
            rev: 41,
            seq: u64::MAX,
            total: u16::MAX,
            refused: u16::MAX,
            outcome: ConcernsOutcome::Ok,
            page: Some(&page),
        };
        let len = body.encode(&mut out).expect("a widest page");
        assert!(
            len <= CONCERNS_HEADER_BYTES + MAX_CONCERN_PAGE_BYTES,
            "a widest body is past the header and cap it was budgeted from"
        );
        assert!(len <= INNER_BODY_BYTES, "a body the frame cannot carry");
    }

    /// A row with every optional key, and a row with none, both come back the
    /// same on the other side.
    #[test]
    fn a_row_survives_the_round_trip_at_both_of_its_widths() {
        for concern in [widest(), narrowest()] {
            let mut out = [0u8; CONCERN_MAX_BYTES];
            let len = encoded(&concern, &mut out);
            let back = Concern::decode(out.get(..len).expect("what was written"))
                .expect("what this crate wrote, this crate reads");
            assert_eq!(back, concern);
        }
    }

    /// **Four subjects, and the one that matters is the fourth.**
    ///
    /// *The pack is in protection* and *cell 23 of the pack is over voltage*
    /// send somebody to different places, and the difference on the wire is two
    /// optional keys. A shape that collapsed to another would be a technician
    /// pulling a pack to find one cell, or standing in front of a rack looking
    /// for a fault nobody located.
    #[test]
    fn every_subject_shape_arrives_as_the_shape_it_left_as() {
        let part = Part::component(id(3), id(57));
        let whole = Part::device(id(3));
        for subject in [
            Subject::Part(whole),
            Subject::Part(part),
            Subject::Signal(part, id(204)),
            Subject::Element(part, id(204), at(7)),
        ] {
            let mut concern = narrowest();
            concern.subject = subject;
            let mut out = [0u8; CONCERN_MAX_BYTES];
            let len = encoded(&concern, &mut out);
            let back =
                Concern::decode(out.get(..len).expect("what was written")).expect("a legal row");
            assert_eq!(back.subject, subject);
        }
    }

    /// `cmp = 0` is the device as a whole and not a missing component, which is
    /// the one place a zero id is legal (P-200).
    #[test]
    fn p_200_a_zero_component_is_the_device_and_not_a_refusal() {
        let mut out = [0u8; CONCERN_MAX_BYTES];
        let len = handmade(&required(), &mut out);
        let back = Concern::decode(out.get(..len).expect("what was written")).expect("a legal row");
        assert!(back.subject.part().is_device());
        assert_eq!(back.subject.part().cmp(), 0);
    }

    /// A `cid` of 0 makes `next = 0` unreadable, so the row is refused on the
    /// way in rather than at the client that cannot tell a finished walk from
    /// one that resumes at concern 0.
    #[test]
    fn p_200_a_row_carrying_concern_zero_is_refused() {
        let mut pairs = required();
        pairs[0].1 = 0;
        let mut out = [0u8; CONCERN_MAX_BYTES];
        let len = handmade(&pairs, &mut out);
        assert_eq!(
            Concern::decode(out.get(..len).expect("what was written")),
            Err(ConcernsError::ZeroId)
        );
    }

    /// **A position with no signal has no `ebase` to be added to.**
    ///
    /// P-206 makes key 5 a position and the label `ebase` + `elem` − 1, so a
    /// client handed a 7 with no signal cannot print 23 — it prints 7, which is
    /// a cell in the other pack, or it drops the row and shows nothing about a
    /// cell that is over voltage.
    #[test]
    fn an_element_with_no_signal_to_read_it_against_is_refused() {
        // Key 5 carrying a position, and no key 4 anywhere in the row.
        let pairs = [
            (1i64, 9u64),
            (2, 3),
            (3, 0),
            (5, 7),
            (6, 0x4A12),
            (7, Severity::Protection as u64),
            (8, ConcernState::Active as u64),
            (9, 6 * 3600),
            (13, 41),
        ];
        let mut out = [0u8; CONCERN_MAX_BYTES];
        let len = handmade(&pairs, &mut out);
        assert_eq!(
            Concern::decode(out.get(..len).expect("what was written")),
            Err(ConcernsError::ElementWithoutSignal)
        );
    }

    /// **The fixture-3 mistake, refused at the type.**
    ///
    /// Still not named after **P-206**, and the reason has changed twice. *There
    /// is no `ebase` in the tree* stopped being true when a `SignalRow` grew key
    /// 12; *nothing decodes a descriptor row* stopped being true when
    /// [`RowSlots`] arrived. What is left is that this test is the half a
    /// `Concern` can check on its own — a position is not a label — and the half
    /// that needs the row it names lives with the row, in `inventory.rs`.
    ///
    /// Pack 2's cell 23 is element 7 of a signal whose `ebase` is 17. An encoder
    /// that writes 23 here has written the label where the position belongs, and
    /// both numbers are small integers that parse and MAC-verify. A series is at
    /// most `MAX_SERIES_LEN` elements, so a 23 cannot be a position and is
    /// refused rather than rendered as a cell in the wrong pack.
    #[test]
    fn a_label_written_where_a_position_belongs_is_refused() {
        assert_eq!(ElementAt::new(0), Err(ConcernsError::ZeroElement));
        assert_eq!(
            ElementAt::new(23),
            Err(ConcernsError::ElementPastSeries(23))
        );
        assert_eq!(at(16).get(), 16);
    }

    /// **A code from nobody, and a nobody with no code.**
    ///
    /// Key 12 is REQUIRED with key 11 and absent without it. Two vendors both
    /// use `0x0021` and mean different things by it, so a raw code with no
    /// namespace renders as a bare number somebody will look up in the wrong
    /// manual — and a namespace alone names a vendor and says nothing at all.
    #[test]
    fn a_vendor_code_and_its_namespace_arrive_together_or_neither_arrives() {
        for (half, want) in [
            ((11i64, 0x21u64), ConcernsError::CodeWithoutNamespace),
            ((12, 7), ConcernsError::NamespaceWithoutCode),
        ] {
            let pairs = [
                (1i64, 9u64),
                (2, 3),
                (3, 0),
                (6, 0x4A12),
                (7, Severity::Protection as u64),
                (8, ConcernState::Active as u64),
                (9, 6 * 3600),
                half,
                (13, 41),
            ];
            let mut out = [0u8; CONCERN_MAX_BYTES];
            let len = handmade(&pairs, &mut out);
            assert_eq!(
                Concern::decode(out.get(..len).expect("what was written")),
                Err(want)
            );
        }
    }

    /// `severity` and `concern_state` are closed spaces under P-019, so a value
    /// nobody has allocated is refused rather than carried.
    ///
    /// This is the one place carrying would be worse than refusing: the state
    /// decides whether a condition is over, and a client that renders an
    /// unknown one as *something* has been given a reason to start a charger.
    #[test]
    fn a_severity_or_a_state_this_version_does_not_allocate_is_refused() {
        for (key, value, want) in [
            (7i64, 9u64, ConcernsError::UnknownSeverity(9)),
            (8, 6, ConcernsError::UnknownState(6)),
        ] {
            let mut pairs = required();
            for pair in &mut pairs {
                if pair.0 == key {
                    pair.1 = value;
                }
            }
            let mut out = [0u8; CONCERN_MAX_BYTES];
            let len = handmade(&pairs, &mut out);
            assert_eq!(
                Concern::decode(out.get(..len).expect("what was written")),
                Err(want)
            );
        }
    }

    /// A `cond` nobody has allocated still arrives, because the condition
    /// registry is open (P-019).
    ///
    /// *Protection, pack 2, cell 23, code 0x4A12* is a sentence somebody can act
    /// on. Refusing the row because one number is new would lose the whole of
    /// it, and the number is the least important part.
    #[test]
    fn a_condition_nobody_has_allocated_still_reaches_the_screen() {
        let mut pairs = required();
        pairs[3].1 = 0xF123;
        let mut out = [0u8; CONCERN_MAX_BYTES];
        let len = handmade(&pairs, &mut out);
        let back = Concern::decode(out.get(..len).expect("what was written")).expect("carried");
        assert_eq!(back.cond, Condition(0xF123));
    }

    /// A key a newer peer added is skipped and the row still arrives (P-013).
    ///
    /// Refusing would drop a page of concerns because one row grew a field,
    /// which is a site going dark on a client one version behind.
    #[test]
    fn a_key_a_newer_peer_added_is_skipped_rather_than_refusing_the_row() {
        let mut pairs = [(0i64, 0u64); 9];
        for (slot, pair) in pairs.iter_mut().zip(required()) {
            *slot = pair;
        }
        pairs[8] = (14, 1);
        let mut out = [0u8; CONCERN_MAX_BYTES];
        let len = handmade(&pairs, &mut out);
        let back = Concern::decode(out.get(..len).expect("what was written")).expect("skipped");
        assert_eq!(back.cid, id(9));
    }

    /// A page stops at the row cap and names the row that did not fit, which is
    /// the `cid` the next page resumes at.
    #[test]
    fn p_208_a_page_stops_at_the_row_cap_and_names_where_it_resumes() {
        let mut page = ConcernsPage::new();
        for n in 1..=MAX_CONCERN_PAGE_ROWS {
            let mut row = narrowest();
            row.cid = id(u16::try_from(n).expect("a small id"));
            assert!(page.push(&row).expect("encodes"), "row {n} must fit");
        }
        let mut past = narrowest();
        past.cid = id(13);
        assert!(
            !page.push(&past).expect("encodes"),
            "a thirteenth row fitted"
        );
        assert_eq!(page.rows(), MAX_CONCERN_PAGE_ROWS);
        assert_eq!(
            page.next(),
            13,
            "the cursor does not name the row that did not fit"
        );
    }

    /// Every page length from empty to full survives the round trip, with the
    /// row count and the cursor arriving as they left.
    #[test]
    fn a_page_of_every_length_round_trips() {
        for rows in 0..=MAX_CONCERN_PAGE_ROWS {
            let mut page = ConcernsPage::new();
            for n in 1..=rows {
                let mut row = widest();
                row.cid = id(u16::try_from(n).expect("a small id"));
                assert!(page.push(&row).expect("encodes"));
            }
            let body = ConcernsBody {
                rev: 41,
                seq: 1234,
                total: u16::try_from(rows).expect("a small total"),
                refused: 0,
                outcome: ConcernsOutcome::Ok,
                page: Some(&page),
            };
            let mut out = [0u8; INNER_BODY_BYTES];
            let len = body.encode(&mut out).expect("a page of any length");
            let bytes = out.get(..len).expect("what was written");

            let header = ConcernsHeader::decode(bytes).expect("a page this crate wrote");
            assert_eq!(header.rows, rows);
            assert_eq!(header.total, u16::try_from(rows).expect("a small total"));
            assert_eq!(header.next, 0, "a complete page asked to be resumed");
            assert_eq!(header.seq, 1234);

            let mut seen = 0usize;
            for (n, row) in ConcernRows::of(bytes).expect("the rows").enumerate() {
                let row = row.expect("a row this crate wrote");
                assert_eq!(row.cid.get(), u16::try_from(n).expect("a small id") + 1);
                seen = seen.saturating_add(1);
            }
            assert_eq!(seen, rows, "the walk did not return every row on the page");
        }
    }

    /// **An empty table is an answer.**
    ///
    /// Outcome 1 with no rows and `next = 0` says *nothing is wrong at this
    /// site*. Answered as a refusal it would put a client's screen into an error
    /// state on the best day of the year, and key 3 is simply absent rather than
    /// an empty array — one way to say nothing, not two.
    #[test]
    fn an_empty_table_is_outcome_one_and_not_a_refusal() {
        let page = ConcernsPage::new();
        let body = ConcernsBody {
            rev: 41,
            seq: 7,
            total: 0,
            refused: 0,
            outcome: ConcernsOutcome::Ok,
            page: Some(&page),
        };
        let mut out = [0u8; INNER_BODY_BYTES];
        let len = body.encode(&mut out).expect("an empty page");
        let bytes = out.get(..len).expect("what was written");
        let header = ConcernsHeader::decode(bytes).expect("an empty page is legal");
        assert_eq!(header.outcome, ConcernsOutcome::Ok);
        assert_eq!(header.rows, 0);
        assert_eq!(header.total, 0);
        assert_eq!(header.next, 0);
        assert_eq!(ConcernRows::of(bytes).expect("no rows").count(), 0);
    }

    /// **An outcome that answered nothing carries nothing, on both sides.**
    ///
    /// `next = 0` is the natural encoding of *nothing follows*, so a response
    /// that answered nothing is otherwise shaped exactly like one that answered
    /// everything — and on outcome 3 the `rev` matches, so nothing else fires
    /// and a client stamps a table it never read.
    #[test]
    fn p_199_an_outcome_that_answered_nothing_carries_no_rows_and_no_cursor() {
        let mut page = ConcernsPage::new();
        assert!(page.push(&narrowest()).expect("encodes"));
        let mut out = [0u8; INNER_BODY_BYTES];

        for outcome in [ConcernsOutcome::Superseded, ConcernsOutcome::OutOfRange] {
            let body = ConcernsBody {
                rev: 41,
                seq: 7,
                total: 1,
                refused: 0,
                outcome,
                page: Some(&page),
            };
            assert_eq!(
                body.encode(&mut out),
                Err(ConcernsError::AnsweredNothing(outcome)),
                "a refusal was written carrying the rows it refused to answer with"
            );

            // And a peer that writes it anyway is refused on the way in: the
            // receiving side is where the table gets rendered.
            let mut cbor = CborWriter::new(&mut out);
            cbor.map(3).expect("a map");
            cbor.key(1).expect("rev");
            cbor.u64(41).expect("rev");
            cbor.key(4).expect("next");
            cbor.u64(9).expect("next");
            cbor.key(7).expect("outcome");
            cbor.u64(u64::from(outcome.number())).expect("outcome");
            let len = cbor.finish().expect("a handmade body");
            assert_eq!(
                ConcernsHeader::decode(out.get(..len).expect("what was written")),
                Err(ConcernsError::AnsweredNothing(outcome))
            );
        }
    }

    /// An outcome number this version does not allocate is refused rather than
    /// read as success or failure (P-165 does not let a decoder pick).
    #[test]
    fn an_outcome_this_version_does_not_allocate_is_refused() {
        let mut out = [0u8; 64];
        let mut cbor = CborWriter::new(&mut out);
        cbor.map(6).expect("a map");
        for (key, value) in [(1u64, 41u64), (2, 7), (4, 0), (5, 0), (6, 0), (7, 9)] {
            cbor.key(i64::try_from(key).expect("a small key"))
                .expect("a key");
            cbor.u64(value).expect("a value");
        }
        let len = cbor.finish().expect("a handmade body");
        assert_eq!(
            ConcernsHeader::decode(out.get(..len).expect("what was written")),
            Err(ConcernsError::UnknownOutcome(9))
        );
    }

    /// **A raise carries the whole row, and it is the row the page carries.**
    ///
    /// The same `Concern`, the same bytes, the same decoder. Two shapes meaning
    /// nearly the same thing would be two decoders to keep in step, and the
    /// raise path is exercised more rarely than the page path by exactly the
    /// margin that hides a bug until a pack goes out of balance in February.
    #[test]
    fn a_raise_carries_the_row_the_page_would_have_carried() {
        let raised = ConcernRaised {
            rev: 41,
            concern: widest(),
        };
        let mut out = [0u8; CONCERN_MAX_BYTES + 16];
        let len = raised.encode(&mut out).expect("a raise encodes");
        let bytes = out.get(..len).expect("what was written");
        assert_eq!(ConcernRaised::decode(bytes), Ok(raised));

        // Key 2's bytes are exactly what the row encoder writes on its own.
        let mut row = [0u8; CONCERN_MAX_BYTES];
        let row_len = encoded(&widest(), &mut row);
        let row = row.get(..row_len).expect("the row");
        assert!(
            bytes.windows(row_len).any(|w| w == row),
            "the raise re-encoded the row instead of carrying it"
        );
    }

    /// **A change that went nowhere is refused.**
    ///
    /// `state` equal to `prev` is not a transition. A client that renders one
    /// draws a change nobody made, and on a screen somebody checks at 2 a.m. a
    /// protection that appears to have just moved is a reason to drive out.
    #[test]
    fn a_change_from_a_state_to_itself_is_refused() {
        let changed = ConcernChanged {
            rev: 41,
            cid: id(12),
            dev: id(3),
            cond: Condition::UNDER_TEMPERATURE,
            state: ConcernState::Cleared,
            prev: ConcernState::LatchedCleared,
        };
        let mut out = [0u8; 64];
        let len = changed.encode(&mut out).expect("a change encodes");
        assert_eq!(
            ConcernChanged::decode(out.get(..len).expect("what was written")),
            Ok(changed)
        );

        let nowhere = ConcernChanged {
            prev: ConcernState::Cleared,
            ..changed
        };
        let len = nowhere.encode(&mut out).expect("it still encodes");
        assert_eq!(
            ConcernChanged::decode(out.get(..len).expect("what was written")),
            Err(ConcernsError::WentNowhere(ConcernState::Cleared))
        );
    }

    /// **`prev` is what makes a hole in `seq` legible (P-096).**
    ///
    /// A row that went `active` → `active_acked` → `latched_cleared` while the
    /// middle record went missing arrives as one frame. Without the state it
    /// moved from, that is indistinguishable from a controller that skipped a
    /// state; with it, the client sees that what it holds is not what the
    /// controller moved from and reconciles instead of rendering a lifecycle
    /// that never happened.
    #[test]
    fn p_096_a_client_can_tell_a_missed_record_from_a_skipped_state() {
        let held = ConcernState::Active;
        let arrived = ConcernChanged {
            rev: 41,
            cid: id(12),
            dev: id(3),
            cond: Condition::UNDER_TEMPERATURE,
            state: ConcernState::LatchedCleared,
            prev: ConcernState::ActiveAcked,
        };
        let mut out = [0u8; 64];
        let len = arrived.encode(&mut out).expect("encodes");
        let read = ConcernChanged::decode(out.get(..len).expect("what was written"))
            .expect("a legal change");
        assert_ne!(
            read.prev, held,
            "the client holds active and this moved from active_acked, so a record went missing"
        );
    }

    /// A state neither side allocates is refused rather than carried, in both
    /// positions. `concern_state` is closed under P-019, and the state is what
    /// decides whether a condition is over.
    #[test]
    fn a_state_this_version_does_not_allocate_is_refused_in_either_position() {
        for (key, want) in [(5i64, 6u64), (6, 7)] {
            let mut out = [0u8; 64];
            let mut cbor = CborWriter::new(&mut out);
            cbor.map(6).expect("a map");
            for (k, v) in [
                (1i64, 41u64),
                (2, 12),
                (3, 3),
                (4, 4),
                (5, u64::from(ConcernState::Cleared as u8)),
                (6, u64::from(ConcernState::Active as u8)),
            ] {
                cbor.key(k).expect("a key");
                cbor.u64(if k == key { want } else { v }).expect("a value");
            }
            let len = cbor.finish().expect("a handmade change");
            assert_eq!(
                ConcernChanged::decode(out.get(..len).expect("what was written")),
                Err(ConcernsError::UnknownState(
                    u8::try_from(want).expect("a small state")
                ))
            );
        }
    }

    /// Every truncation of either event body is refused, and none panics.
    #[test]
    fn a_concern_event_cut_short_is_refused_and_never_panics() {
        let mut out = [0u8; CONCERN_MAX_BYTES + 16];
        let raise = ConcernRaised {
            rev: 41,
            concern: widest(),
        };
        let len = raise.encode(&mut out).expect("encodes");
        for cut in 0..len {
            assert!(ConcernRaised::decode(out.get(..cut).expect("a prefix")).is_err());
        }

        let mut small = [0u8; 64];
        let change = ConcernChanged {
            rev: 41,
            cid: id(12),
            dev: id(3),
            cond: Condition::UNDER_TEMPERATURE,
            state: ConcernState::Cleared,
            prev: ConcernState::LatchedCleared,
        };
        let len = change.encode(&mut small).expect("encodes");
        for cut in 0..len {
            assert!(ConcernChanged::decode(small.get(..cut).expect("a prefix")).is_err());
        }
    }

    /// A `ReadConcerns` round trips, and `from = 0` is legal because it is a
    /// cursor rather than an id.
    #[test]
    fn a_read_concerns_round_trips_and_zero_means_from_the_beginning() {
        for from in [0u16, 1, 13, u16::MAX] {
            let want = ReadConcerns::new(41, from);
            let mut out = [0u8; 32];
            let len = want.encode(&mut out).expect("a request");
            assert_eq!(
                ReadConcerns::decode(out.get(..len).expect("what was written")),
                Ok(want)
            );
        }
    }

    /// A request missing a required key is refused, naming which one (P-015).
    #[test]
    fn a_read_concerns_missing_a_key_says_which_one() {
        for (present, missing) in [(2i64, 1u8), (1, 2)] {
            let mut out = [0u8; 32];
            let mut cbor = CborWriter::new(&mut out);
            cbor.map(1).expect("a map");
            cbor.key(present).expect("a key");
            cbor.u64(41).expect("a value");
            let len = cbor.finish().expect("a handmade request");
            assert_eq!(
                ReadConcerns::decode(out.get(..len).expect("what was written")),
                Err(ConcernsError::MissingRequest(missing))
            );
        }
    }

    /// **A resynchronising receiver hands a decoder arbitrary bytes.**
    ///
    /// Every prefix of a real body, and a sweep of single bytes, must come back
    /// as a refusal. Not one of them may panic: a controller that unwinds on a
    /// truncated frame is a controller that stops answering at a site four hours
    /// from a road, and a frame cut short is the ordinary shape of a bad radio.
    #[test]
    fn a_frame_cut_short_or_made_of_noise_is_refused_and_never_panics() {
        let mut page = ConcernsPage::new();
        for n in 1..=3u16 {
            let mut row = widest();
            row.cid = id(n);
            assert!(page.push(&row).expect("encodes"));
        }
        let body = ConcernsBody {
            rev: 41,
            seq: 7,
            total: 3,
            refused: 2,
            outcome: ConcernsOutcome::Ok,
            page: Some(&page),
        };
        let mut out = [0u8; INNER_BODY_BYTES];
        let len = body.encode(&mut out).expect("a page");
        let whole = out.get(..len).expect("what was written");

        for cut in 0..len {
            let short = whole.get(..cut).expect("a prefix");
            assert!(
                ConcernsHeader::decode(short).is_err(),
                "a body cut at {cut} of {len} was accepted"
            );
            // The row walk must not panic on one either, whatever it answers.
            if let Ok(rows) = ConcernRows::of(short) {
                for row in rows {
                    let _ = row;
                }
            }
        }

        for byte in 0..=u8::MAX {
            let noise = [byte, byte, byte, byte];
            assert!(ConcernsHeader::decode(&noise).is_err());
            assert!(Concern::decode(&noise).is_err());
            assert!(ReadConcerns::decode(&noise).is_err());
        }
    }

    /// **A row missing any required key is refused, and says which one.**
    ///
    /// Eight keys and not the three this started with, because the three were
    /// chosen and the other five were not — and a decoder that defaults `cond`
    /// to 0 or `sev` to `info` produces a row that renders, which is worse than
    /// one that does not arrive. A protection shown as an `info` is a line
    /// somebody scrolls past.
    ///
    /// There is deliberately no test here named after **P-211**. This proves its
    /// *always present* clause and nothing proves the other one — the row does
    /// not survive a restart, because there is no `age` on a concern in
    /// the controller and no FRAM path to carry it. A rule half proved under its own
    /// number reads greener than one nobody has touched, and nobody goes looking
    /// at a number that is already green.
    #[test]
    fn a_row_missing_any_required_key_is_refused_and_says_which() {
        for missing in [
            ConcernKey::Cid,
            ConcernKey::Dev,
            ConcernKey::Cmp,
            ConcernKey::Cond,
            ConcernKey::Sev,
            ConcernKey::State,
            ConcernKey::Age,
            ConcernKey::Seq,
        ] {
            let mut pairs = [(0i64, 0u64); 7];
            let mut n = 0;
            for pair in required() {
                if pair.0 == missing as i64 {
                    continue;
                }
                pairs[n] = pair;
                n = n.saturating_add(1);
            }
            let mut out = [0u8; CONCERN_MAX_BYTES];
            let len = handmade(&pairs, &mut out);
            assert_eq!(
                Concern::decode(out.get(..len).expect("what was written")),
                Err(ConcernsError::MissingRow(missing)),
                "a row with no {} was accepted",
                missing.name()
            );
        }
    }
}
