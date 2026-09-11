//! `ReadLog 0x05` / `0x85` — going backwards on purpose, which is the one thing
//! the live stream refuses to do.
//!
//! A page is not a frame. It travels inside one, under an envelope, a wrapper
//! and a MAC, and `MAX_LOG_PAGE_BYTES` is 896 rather than 1024 because of it —
//! an earlier revision put a full payload of page inside a full payload, which
//! cannot happen. When a page fills it comes back with `complete = false` rather
//! than growing.
//!
//! P-099's clamp is P-104's `max(from_seq, oldest_seq)` word for word, and that
//! is deliberate: the same fall off the same ring answered two ways in two
//! messages is a difference somebody has to discover at a site. `subscribe.rs`
//! holds the other half.
//!
//! cites: P-099
//!
//! [`crate::MAX_LOG_PAGE_BYTES`] and [`crate::MAX_LOG_PAGE_ENTRIES`] are the two
//! caps a page stops at.

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::event::{Event, EventError};
use crate::generated::{ErrorCode, EventKind};
use crate::handshake::LogSeq;
use crate::limits::{MAX_LOG_PAGE_BYTES, MAX_LOG_PAGE_ENTRIES};

/// The two keys of `ReadLog 0x05`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadLogKey {
    /// Key 1, clamped up to `oldest_seq` by P-099.
    FromSeq,
    /// Key 2, clamped down to [`MAX_LOG_PAGE_ENTRIES`].
    MaxEntries,
}

impl ReadLogKey {
    const COUNT: usize = 2;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::FromSeq),
            2 => Some(Self::MaxEntries),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::FromSeq => 1,
            Self::MaxEntries => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::FromSeq => "from_seq",
            Self::MaxEntries => "max_entries",
        }
    }
}

impl fmt::Display for ReadLogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReadLog 0x05 {} (key {})", self.name(), self.number())
    }
}

/// The four keys of `LogPage 0x85`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageKey {
    /// Key 1.
    Entries,
    /// Key 2, the cursor to pass back.
    NextSeq,
    /// Key 3.
    OldestSeq,
    /// Key 4.
    Complete,
}

impl PageKey {
    const COUNT: usize = 4;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Entries),
            2 => Some(Self::NextSeq),
            3 => Some(Self::OldestSeq),
            4 => Some(Self::Complete),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Entries => 1,
            Self::NextSeq => 2,
            Self::OldestSeq => 3,
            Self::Complete => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Entries => "entries",
            Self::NextSeq => "next_seq",
            Self::OldestSeq => "oldest_seq",
            Self::Complete => "complete",
        }
    }
}

impl fmt::Display for PageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogPage 0x85 {} (key {})", self.name(), self.number())
    }
}

/// A key of either body here, so one refusal can name either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadLogBodyKey {
    /// A key of `ReadLog 0x05`.
    Request(ReadLogKey),
    /// A key of `LogPage 0x85`.
    Page(PageKey),
}

impl From<ReadLogKey> for ReadLogBodyKey {
    fn from(key: ReadLogKey) -> Self {
        Self::Request(key)
    }
}

impl From<PageKey> for ReadLogBodyKey {
    fn from(key: PageKey) -> Self {
        Self::Page(key)
    }
}

impl fmt::Display for ReadLogBodyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(key) => key.fmt(f),
            Self::Page(key) => key.fmt(f),
        }
    }
}

/// One record inside a page.
///
/// The same four keys as an `Event 0x04` body, and a different type on purpose.
/// The specification names them apart because a rule written about one was being
/// read onto the other: P-056 rejects an `Event` whose `seq` goes backwards, and
/// a page of these goes backwards by construction. [`crate::EventMark::accept`]
/// takes an `Event`, so one of these cannot reach it.
///
/// ```compile_fail
/// use km43::{EventMark, LogEntry};
/// fn feed(mark: &mut EventMark, entry: &LogEntry<'_>) { let _ = mark.accept(entry); }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogEntry<'a> {
    /// Key 1.
    pub seq: LogSeq,
    /// Key 2, and `None` means the clock had never been set when this was
    /// written — which is a thing an old record genuinely is.
    pub at: Option<u64>,
    /// Key 3.
    pub kind: EventKind,
    body: &'a [u8],
}

impl<'a> LogEntry<'a> {
    /// A record for a page. The body's schema is deferred per kind, so this
    /// checks its shape and carries it, exactly as an event's does.
    pub fn new(
        seq: LogSeq,
        at: Option<u64>,
        kind: EventKind,
        body: &'a [u8],
    ) -> Result<Self, ReadLogError> {
        Ok(Self::from_event(Event::new(seq, at, kind, body)?))
    }

    /// Key 4 as it was written.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// The codec lives on `Event` and is shared rather than copied — the two
    /// carry the same four keys, which is the document's own reason for giving
    /// them two names.
    const fn from_event(event: Event<'a>) -> Self {
        Self {
            seq: event.seq,
            at: event.at,
            kind: event.kind,
            body: event.body(),
        }
    }

    fn as_event(self) -> Result<Event<'a>, ReadLogError> {
        Ok(Event::new(self.seq, self.at, self.kind, self.body)?)
    }

    fn encode(self, cbor: &mut CborWriter<'_>) -> Result<(), ReadLogError> {
        self.as_event()?.encode_into(cbor)?;
        Ok(())
    }

    fn decode(body: &mut CborReader<'a>) -> Result<Self, ReadLogError> {
        Ok(Self::from_event(Event::decode_from(body)?))
    }
}

/// The body of `ReadLog 0x05`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadLog {
    /// Key 1.
    pub from_seq: LogSeq,
    /// Key 2. A client may ask for more; [`ReadLog::page_size`] is what it gets.
    pub max_entries: u16,
}

impl ReadLog {
    /// What the controller will actually put in one page: the client's ask,
    /// clamped down to [`MAX_LOG_PAGE_ENTRIES`].
    ///
    /// Clamped rather than refused — a client asking for a thousand is asking
    /// for as many as it can have, and answering error 1 to that is a catch-up
    /// that never starts.
    #[must_use]
    pub fn page_size(self) -> usize {
        usize::from(self.max_entries).min(MAX_LOG_PAGE_ENTRIES)
    }

    /// P-099. If `from_seq` is behind the ring the controller answers from
    /// `oldest_seq`, so the client can see it lost data — silent loss is the
    /// failure this rule exists to prevent.
    ///
    /// It is `max(from_seq, oldest_seq)`, which is P-104's `SubscribeAck` clamp
    /// word for word.
    #[must_use]
    pub fn start_at(self, oldest: LogSeq) -> LogSeq {
        LogSeq(self.from_seq.0.max(oldest.0))
    }

    /// Encode the two keys.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, ReadLogError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(ReadLogKey::COUNT)?;
        cbor.key(ReadLogKey::FromSeq.number())?;
        cbor.u64(self.from_seq.0)?;
        cbor.key(ReadLogKey::MaxEntries.number())?;
        cbor.u64(u64::from(self.max_entries))?;
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &[u8]) -> Result<Self, ReadLogError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut from_seq = None;
        let mut max_entries = None;
        for _ in 0..pairs {
            let number = body.key()?;
            match ReadLogKey::of(number) {
                Some(key @ ReadLogKey::FromSeq) => once(&mut from_seq, key, body.u64()?)?,
                Some(key @ ReadLogKey::MaxEntries) => once(&mut max_entries, key, body.u16()?)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            from_seq: LogSeq(from_seq.ok_or(ReadLogError::Missing(ReadLogKey::FromSeq.into()))?),
            max_entries: max_entries.ok_or(ReadLogError::Missing(ReadLogKey::MaxEntries.into()))?,
        })
    }
}

/// The body of `LogPage 0x85`.
///
/// `entries` is a fixed array of [`MAX_LOG_PAGE_ENTRIES`] with a length beside
/// it. A sixty-fifth is refused rather than dropped, and a page that fills comes
/// back with `complete = false` — the client passes `next_seq` back and asks
/// again, which is the whole of the paging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogPage<'a> {
    entries: [LogEntry<'a>; MAX_LOG_PAGE_ENTRIES],
    len: usize,
    /// Key 2, the cursor to pass back. Maintained by [`Self::push`] rather than
    /// set, because P-029 makes it the caller's easiest mistake.
    next_seq: LogSeq,
    /// Key 3, what the controller still holds.
    pub oldest_seq: LogSeq,
    /// Key 4, true when this page caught up to the newest record.
    pub complete: bool,
}

impl<'a> LogPage<'a> {
    /// An empty page whose cursor is where reading will resume.
    ///
    /// `resume_at` is only the answer while the page stays empty — every
    /// [`Self::push`] carries the cursor past the record it took.
    #[must_use]
    pub const fn new(resume_at: LogSeq, oldest_seq: LogSeq, complete: bool) -> Self {
        Self {
            // A slot past `len` is never encoded and never handed out. Kind 0
            // is unallocated and its body is the empty map, so if one ever is,
            // it is a record naming nothing rather than a plausible one.
            entries: [LogEntry {
                seq: LogSeq(0),
                at: None,
                kind: EventKind(0),
                body: &[0xa0],
            }; MAX_LOG_PAGE_ENTRIES],
            len: 0,
            next_seq: resume_at,
            oldest_seq,
            complete,
        }
    }

    /// Add a record, refusing past [`MAX_LOG_PAGE_ENTRIES`] rather than
    /// evicting one. A page that is full is a page that reports
    /// `complete = false`, not a page that quietly loses its oldest record.
    ///
    /// **This is what moves the cursor**, past the highest `seq` the page
    /// carries rather than to it. Every `seq` bound in this protocol names the
    /// first position included and `next_seq` is fed straight back into a
    /// `ReadLog`'s `from_seq`, so a cursor pointing *at* the last record
    /// re-delivers it — one duplicate at every page boundary, on the one message
    /// somebody reads when they are trying to find out what went wrong.
    ///
    /// Highest rather than last, because nothing here requires a page's entries
    /// to ascend.
    pub fn push(&mut self, entry: LogEntry<'a>) -> Result<(), ReadLogError> {
        // Refused, not saturated: a record at the ceiling has no *past*, and a
        // cursor that saturates points at the record it just delivered, which
        // is the P-029 duplicate the paragraph above exists to prevent.
        // `Event::accept` refuses the same ceiling on the way in.
        let past = LogSeq(
            entry
                .seq
                .0
                .checked_add(1)
                .ok_or(ReadLogError::SeqAtTheCeiling)?,
        );
        let slot = self
            .entries
            .get_mut(self.len)
            .ok_or(ReadLogError::PageFull(MAX_LOG_PAGE_ENTRIES))?;
        *slot = entry;
        self.len = self.len.saturating_add(1);
        if past.0 > self.next_seq.0 {
            self.next_seq = past;
        }
        Ok(())
    }

    /// The cursor a client passes back to continue.
    #[must_use]
    pub const fn next_seq(&self) -> LogSeq {
        self.next_seq
    }

    /// The records this page carries, oldest first — or in whatever order the
    /// controller wrote them. Nothing here requires them to ascend: conformance
    /// item 8 says a page whose entries go backwards is accepted, because the
    /// rule that forbids it is P-056 and P-056 is about the live stream.
    #[must_use]
    pub fn entries(&self) -> &[LogEntry<'a>] {
        self.entries.get(..self.len).unwrap_or(&[])
    }

    /// Encode the four keys, into at most [`MAX_LOG_PAGE_BYTES`] of `dst`.
    ///
    /// The cap is applied to the buffer rather than checked after the fact, so
    /// a page that outgrows it is refused as *too long for a page* and not as
    /// *your buffer was small*. Those are different findings at a bench, and
    /// the second one sends somebody to enlarge a buffer that is the right size.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ReadLogError> {
        let capped = dst.len() >= MAX_LOG_PAGE_BYTES;
        let room = if capped {
            dst.get_mut(..MAX_LOG_PAGE_BYTES)
                .ok_or(ReadLogError::PageTooLong(MAX_LOG_PAGE_BYTES))?
        } else {
            dst
        };
        let mut cbor = CborWriter::new(room);
        cbor.map(PageKey::COUNT)?;
        cbor.key(PageKey::Entries.number())?;
        cbor.array(self.len)?;
        for entry in self.entries() {
            entry.encode(&mut cbor).map_err(|why| match why {
                ReadLogError::Entry(EventError::Cbor(CborError::DestinationTooSmall))
                | ReadLogError::Cbor(CborError::DestinationTooSmall)
                    if capped =>
                {
                    ReadLogError::PageTooLong(MAX_LOG_PAGE_BYTES)
                }
                other => other,
            })?;
        }
        cbor.key(PageKey::NextSeq.number())?;
        cbor.u64(self.next_seq.0)?;
        cbor.key(PageKey::OldestSeq.number())?;
        cbor.u64(self.oldest_seq.0)?;
        cbor.key(PageKey::Complete.number())?;
        cbor.bool(self.complete)?;
        cbor.finish().map_err(|why| {
            if capped && why == CborError::DestinationTooSmall {
                ReadLogError::PageTooLong(MAX_LOG_PAGE_BYTES)
            } else {
                ReadLogError::Cbor(why)
            }
        })
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &'a [u8]) -> Result<Self, ReadLogError> {
        if payload.len() > MAX_LOG_PAGE_BYTES {
            return Err(ReadLogError::PageTooLong(payload.len()));
        }
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut entries = None;
        let mut next_seq = None;
        let mut oldest_seq = None;
        let mut complete = None;
        for _ in 0..pairs {
            let number = body.key()?;
            match PageKey::of(number) {
                Some(key @ PageKey::Entries) => {
                    once(&mut entries, key, Self::entries_from(&mut body)?)?;
                }
                Some(key @ PageKey::NextSeq) => once(&mut next_seq, key, body.u64()?)?,
                Some(key @ PageKey::OldestSeq) => once(&mut oldest_seq, key, body.u64()?)?,
                Some(key @ PageKey::Complete) => once(&mut complete, key, body.bool()?)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        let (entries, len) = entries.ok_or(ReadLogError::Missing(PageKey::Entries.into()))?;
        let mut page = Self::new(
            LogSeq(next_seq.ok_or(ReadLogError::Missing(PageKey::NextSeq.into()))?),
            LogSeq(oldest_seq.ok_or(ReadLogError::Missing(PageKey::OldestSeq.into()))?),
            complete.ok_or(ReadLogError::Missing(PageKey::Complete.into()))?,
        );
        page.entries = entries;
        page.len = len;
        Ok(page)
    }

    /// The array, refused on its declared length before a record is read — so a
    /// page claiming a thousand entries costs one comparison rather than a
    /// thousand decodes.
    fn entries_from(
        body: &mut CborReader<'a>,
    ) -> Result<([LogEntry<'a>; MAX_LOG_PAGE_ENTRIES], usize), ReadLogError> {
        let count = body.array()?;
        if count > MAX_LOG_PAGE_ENTRIES {
            return Err(ReadLogError::PageFull(MAX_LOG_PAGE_ENTRIES));
        }
        let mut page = Self::new(LogSeq(0), LogSeq(0), false);
        for _ in 0..count {
            page.push(LogEntry::decode(body)?)?;
        }
        Ok((page.entries, page.len))
    }
}

fn once<T>(
    slot: &mut Option<T>,
    key: impl Into<ReadLogBodyKey>,
    value: T,
) -> Result<(), ReadLogError> {
    if slot.is_some() {
        return Err(ReadLogError::Duplicate(key.into()));
    }
    *slot = Some(value);
    Ok(())
}

/// Why a log read was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadLogError {
    /// A required key never arrived (P-015).
    Missing(ReadLogBodyKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(ReadLogBodyKey),
    /// More entries than a page holds, refused on the array's declared length
    /// rather than after sixty-four have been decoded.
    PageFull(usize),
    /// A record at `u64::MAX`, past which there is no cursor to hand out.
    SeqAtTheCeiling,
    /// A page past `MAX_LOG_PAGE_BYTES`. A page is not a frame — it travels
    /// inside one, under an envelope and a wrapper — and a full one comes back
    /// with `complete = false` rather than growing.
    PageTooLong(usize),
    /// A record inside the page was refused.
    Entry(EventError),
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for ReadLogError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl From<EventError> for ReadLogError {
    fn from(why: EventError) -> Self {
        Self::Entry(why)
    }
}

impl ReadLogError {
    /// What to answer.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::PageTooLong(_) => Refusal::Client(ErrorCode::PayloadTooLarge),
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::PageFull(_)
            | Self::SeqAtTheCeiling
            | Self::Entry(_)
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for ReadLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "log read carries no {key}"),
            Self::Duplicate(key) => write!(f, "log read carries {key} twice"),
            Self::PageFull(cap) => write!(f, "a page holds at most {cap} entries"),
            Self::SeqAtTheCeiling => {
                f.write_str("a record at the sequence ceiling has no cursor past it")
            }
            Self::PageTooLong(len) => {
                write!(
                    f,
                    "a page of {len} bytes is past the {MAX_LOG_PAGE_BYTES} cap"
                )
            }
            Self::Entry(why) => write!(f, "{why}"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for ReadLogError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventMark;
    use crate::render::Rendering;

    const SCRATCH: usize = MAX_LOG_PAGE_BYTES + 64;
    const BODY: [u8; 3] = [0xa1, 0x01, 0x03];

    /// **A cursor that stops on the last record re-delivers it.** Every `seq`
    /// bound in this protocol names the first position included, and `next_seq`
    /// is fed straight back into a `ReadLog`'s `from_seq` — so a page handing
    /// back the seq of its own last record costs one duplicate at every page
    /// boundary, on the one message somebody reads when they are trying to work
    /// out what went wrong.
    ///
    /// The cursor is maintained by `push` rather than supplied, so the wrong
    /// value is not something a caller can hold.
    #[test]
    fn p_029_the_cursor_a_page_hands_back_is_past_its_last_record() {
        let mut page = LogPage::new(LogSeq(7), LogSeq(3), false);
        assert_eq!(
            page.next_seq(),
            LogSeq(7),
            "an empty page resumes where it was told to"
        );

        for seq in [7, 8, 11] {
            page.push(entry(seq)).expect("three records fit");
        }
        assert_eq!(
            page.next_seq(),
            LogSeq(12),
            "the cursor stopped on a record the client has already been handed"
        );

        // The client passes it straight back, and the next read starts past the
        // page rather than on its last record.
        let resume = ReadLog {
            from_seq: page.next_seq(),
            max_entries: 8,
        };
        assert_eq!(resume.start_at(LogSeq(3)), LogSeq(12));
        assert!(
            page.entries()
                .iter()
                .all(|e| e.seq.0 < resume.start_at(LogSeq(3)).0),
            "the next read would return a record this page already carried"
        );
    }

    /// Highest, not last. Nothing requires a page's entries to ascend —
    /// conformance item 8 accepts one that goes backwards — so a cursor taken
    /// from the final slot would rewind the client to a record it has had.
    #[test]
    fn p_029_a_page_whose_records_go_backwards_still_hands_back_the_highest() {
        let mut page = LogPage::new(LogSeq(1), LogSeq(1), false);
        for seq in [9, 4] {
            page.push(entry(seq)).expect("two records fit");
        }
        assert_eq!(page.next_seq(), LogSeq(10));
    }

    fn entry(seq: u64) -> LogEntry<'static> {
        LogEntry::new(LogSeq(seq), None, EventKind::RECORDS_DROPPED, &BODY)
            .expect("the fixture is a map")
    }

    fn page(seqs: &[u64], complete: bool) -> LogPage<'static> {
        let resume = seqs.first().map_or(1, |s| *s);
        let mut page = LogPage::new(LogSeq(resume), LogSeq(1), complete);
        for &seq in seqs {
            page.push(entry(seq)).expect("the fixture fits");
        }
        page
    }

    fn round_tripped(sent: &LogPage<'_>) -> ([u8; SCRATCH], usize) {
        let mut dst = [0u8; SCRATCH];
        let len = sent.encode(&mut dst).expect("the fixture encodes");
        (dst, len)
    }

    /// The list and the numbers live in three places apiece.
    #[test]
    fn every_key_number_maps_back_to_the_key_that_claims_it() {
        for n in 1..=ReadLogKey::COUNT {
            let number = i64::try_from(n).expect("small");
            assert_eq!(ReadLogKey::of(number).expect("a key").number(), number);
        }
        assert!(ReadLogKey::of(0).is_none());
        assert!(ReadLogKey::of(3).is_none());
        for n in 1..=PageKey::COUNT {
            let number = i64::try_from(n).expect("small");
            assert_eq!(PageKey::of(number).expect("a key").number(), number);
        }
        assert!(PageKey::of(0).is_none());
        assert!(PageKey::of(-1).is_none());
        assert!(PageKey::of(5).is_none());
    }

    /// P-099. A client that fell off the ring is answered from what the
    /// controller still holds, so it can *see* it lost data — silent loss is
    /// the failure the rule exists to prevent.
    #[test]
    fn p_099_a_read_from_behind_the_ring_is_answered_from_what_is_left() {
        let asked = ReadLog {
            from_seq: LogSeq(3),
            max_entries: 64,
        };
        assert_eq!(asked.start_at(LogSeq(10)), LogSeq(10), "clamped up");

        // Inside the ring, and exactly at its oldest: taken as asked, because
        // P-029 says that record is delivered.
        for from in [10u64, 11, 1000] {
            let asked = ReadLog {
                from_seq: LogSeq(from),
                max_entries: 64,
            };
            assert_eq!(asked.start_at(LogSeq(10)), LogSeq(from));
        }
    }

    /// The clamp is P-104's `SubscribeAck` arithmetic word for word. The same
    /// fall off the same ring answered two ways in two messages is a difference
    /// somebody has to discover at a site — so the two are compared here rather
    /// than left to agree by habit.
    #[test]
    fn p_099_and_p_104_clamp_the_same_fall_off_the_same_ring_the_same_way() {
        use crate::subscribe::{LogExtent, Replay, Subscribe, SubscribeAck};

        for (from, oldest, newest) in [
            (3u64, 10u64, 42u64),
            (10, 10, 42),
            (20, 10, 42),
            (99, 10, 42),
        ] {
            let read = ReadLog {
                from_seq: LogSeq(from),
                max_entries: 64,
            }
            .start_at(LogSeq(oldest));

            let extent = LogExtent::holding(LogSeq(oldest), LogSeq(newest)).expect("an extent");
            let ack = SubscribeAck::answer(
                Subscribe {
                    replay: Replay::From(LogSeq(from)),
                },
                extent,
            )
            .expect("it answers");

            assert_eq!(
                read,
                ack.accepted_from_seq(),
                "ReadLog from {from} and Subscribe from {from} disagree about a ring at {oldest}"
            );
        }
    }

    /// A client asking for more than a page holds is asking for as many as it
    /// can have. Refusing that with error 1 is a catch-up that never starts.
    #[test]
    fn a_client_asking_for_more_entries_than_a_page_holds_is_clamped_not_refused() {
        for asked in [0u16, 1, 63, 64, 65, 1000, u16::MAX] {
            let want = ReadLog {
                from_seq: LogSeq(1),
                max_entries: asked,
            }
            .page_size();
            assert!(want <= MAX_LOG_PAGE_ENTRIES, "asked {asked}, got {want}");
            assert_eq!(want, usize::from(asked).min(MAX_LOG_PAGE_ENTRIES));
        }
    }

    /// A page out and back, records included.
    #[test]
    fn a_page_arrives_carrying_the_records_it_left_with() {
        let sent = page(&[10, 11, 12], false);
        let (dst, len) = round_tripped(&sent);
        let read = LogPage::decode(dst.get(..len).expect("the length")).expect("it decodes");
        assert_eq!(read.entries().len(), 3);
        assert_eq!(read.next_seq, LogSeq(13));
        assert_eq!(read.oldest_seq, LogSeq(1));
        assert!(!read.complete);
        assert_eq!(read.entries().first().map(|e| e.seq), Some(LogSeq(10)));
        assert_eq!(read.entries().first().map(LogEntry::body), Some(&BODY[..]));
    }

    /// Conformance item 8: **a `LogPage` whose entries go backwards is
    /// accepted**. Going backwards is what a catch-up does, and the rule that
    /// forbids it — P-056 — is written about the live stream. Reading it onto a
    /// page is the mistake the two names exist to prevent.
    #[test]
    fn a_page_whose_entries_go_backwards_is_accepted() {
        let sent = page(&[12, 11, 10], true);
        let (dst, len) = round_tripped(&sent);
        let read = LogPage::decode(dst.get(..len).expect("the length")).expect("it decodes");
        assert_eq!(read.entries().len(), 3);
        for (entry, want) in read.entries().iter().zip([12u64, 11, 10]) {
            assert_eq!(entry.seq, LogSeq(want), "the order the controller wrote");
        }
    }

    /// Refusing beats evicting. A page that fills reports `complete = false` and
    /// the client asks again from `next_seq`; a page that quietly drops its
    /// oldest record is a catch-up with a hole in it that nothing can point at.
    #[test]
    fn a_sixty_fifth_entry_is_refused_rather_than_dropping_the_first() {
        let mut page = LogPage::new(LogSeq(1), LogSeq(1), false);
        for seq in 0..MAX_LOG_PAGE_ENTRIES {
            let at = u64::try_from(seq).expect("small") + 1;
            page.push(entry(at)).expect("sixty-four fit");
        }
        assert_eq!(
            page.push(entry(99)),
            Err(ReadLogError::PageFull(MAX_LOG_PAGE_ENTRIES))
        );
        assert_eq!(page.entries().len(), MAX_LOG_PAGE_ENTRIES);
        assert_eq!(
            page.entries().first().map(|e| e.seq),
            Some(LogSeq(1)),
            "a refusal must not evict"
        );

        // And on the way in, refused on the array's declared length before a
        // record is decoded.
        //
        // Two guards, and the cheap case belongs to the lower one: `cbor.rs`
        // already refuses a container claiming more items than the input could
        // hold at one byte each, so a header claiming a thousand with nothing
        // behind it never reaches here. What reaches here is the header that is
        // *plausible* — sixty-five items with sixty-five bytes behind them —
        // and that is the one a page has to refuse on its own cap.
        let mut claiming = [0x00u8; 80];
        claiming[0] = 0xa1;
        claiming[1] = 0x01;
        claiming[2] = 0x98;
        claiming[3] = 0x41;
        assert_eq!(
            LogPage::decode(&claiming),
            Err(ReadLogError::PageFull(MAX_LOG_PAGE_ENTRIES)),
            "sixty-five entries with the bytes to back the claim"
        );
        assert_eq!(
            LogPage::decode(&[0xa1, 0x01, 0x99, 0x03, 0xe8]),
            Err(ReadLogError::Cbor(CborError::EndOfInput)),
            "a thousand with nothing behind it is the codec's refusal, not ours"
        );
    }

    /// A page is not a frame. An earlier revision put 1024 bytes of page inside
    /// a 1024-byte payload, which cannot happen — so the cap is checked where
    /// the bytes are, on both ends.
    #[test]
    fn a_page_past_its_cap_is_refused_at_both_ends() {
        let big = [0xA5u8; MAX_LOG_PAGE_BYTES + 1];
        assert_eq!(
            LogPage::decode(&big),
            Err(ReadLogError::PageTooLong(MAX_LOG_PAGE_BYTES + 1))
        );

        // Sixty-four records with a wide body each, which is more than a page
        // holds even though it is fewer than sixty-five entries.
        // `{1: <a 32-byte string>}` — a legal record whose only fault, sixty-four
        // times over, is its size.
        let mut wide = [0x5au8; 36];
        wide[0] = 0xa1;
        wide[1] = 0x01;
        wide[2] = 0x58;
        wide[3] = 0x20;
        let mut page = LogPage::new(LogSeq(1), LogSeq(1), false);
        for seq in 0..MAX_LOG_PAGE_ENTRIES {
            let at = u64::try_from(seq).expect("small") + 1;
            page.push(
                LogEntry::new(LogSeq(at), Some(u64::MAX), EventKind(0xFFFF), &wide)
                    .expect("a legal record"),
            )
            .expect("sixty-four fit by count");
        }
        let mut dst = [0u8; SCRATCH];
        assert!(
            matches!(page.encode(&mut dst), Err(ReadLogError::PageTooLong(_))),
            "sixty-four wide records fit by count and not by bytes"
        );
    }

    /// The two types carry the same four keys and are not interchangeable. The
    /// signature half lives on [`LogEntry`] itself, because a doc test written
    /// here is inside `#[cfg(test)]` and rustdoc never collects it.
    #[test]
    fn a_log_entry_cannot_be_fed_to_the_live_streams_replay_mark() {
        // The positive half: an Event can. The compile_fail twin on `LogEntry`
        // is the one that matters, and it is paired so neither passes for an
        // unrelated reason.
        let event = crate::event::Event::new(LogSeq(5), None, EventKind::RECORDS_DROPPED, &BODY)
            .expect("a record");
        let mut mark = EventMark::accepting_from(LogSeq(5));
        assert!(mark.accept(&event).is_ok());
    }

    /// P-013 on both bodies.
    #[test]
    fn a_key_this_version_does_not_know_is_skipped() {
        // `{1: 9, 2: 8, 9: true}`
        assert_eq!(
            ReadLog::decode(&[0xa3, 0x01, 0x09, 0x02, 0x08, 0x09, 0xf5]),
            Ok(ReadLog {
                from_seq: LogSeq(9),
                max_entries: 8
            })
        );
        // `{1: [], 2: 1, 3: 1, 4: true, 9: 99}`
        let read = LogPage::decode(&[
            0xa5, 0x01, 0x80, 0x02, 0x01, 0x03, 0x01, 0x04, 0xf5, 0x09, 0x18, 0x63,
        ])
        .expect("a newer peer's key is skipped");
        assert!(read.complete);
        assert!(read.entries().is_empty());
    }

    /// P-015 on both bodies.
    #[test]
    fn a_key_that_arrives_twice_is_refused_before_either_copy_is_used() {
        assert_eq!(
            ReadLog::decode(&[0xa3, 0x01, 0x09, 0x01, 0x0a, 0x02, 0x08]),
            Err(ReadLogError::Duplicate(ReadLogBodyKey::Request(
                ReadLogKey::FromSeq
            )))
        );
        assert_eq!(
            LogPage::decode(&[
                0xa5, 0x01, 0x80, 0x02, 0x01, 0x02, 0x02, 0x03, 0x01, 0x04, 0xf5
            ]),
            Err(ReadLogError::Duplicate(ReadLogBodyKey::Page(
                PageKey::NextSeq
            )))
        );
    }

    /// A required key that never arrived is error 1, and the refusal says which.
    #[test]
    fn a_body_missing_a_required_key_says_which_one() {
        assert_eq!(
            ReadLog::decode(&[0xa1, 0x02, 0x08]),
            Err(ReadLogError::Missing(ReadLogBodyKey::Request(
                ReadLogKey::FromSeq
            )))
        );
        assert_eq!(
            ReadLog::decode(&[0xa1, 0x01, 0x09]),
            Err(ReadLogError::Missing(ReadLogBodyKey::Request(
                ReadLogKey::MaxEntries
            )))
        );
        let cases = [
            (
                &[0xa3, 0x02, 0x01, 0x03, 0x01, 0x04, 0xf5][..],
                PageKey::Entries,
            ),
            (
                &[0xa3, 0x01, 0x80, 0x03, 0x01, 0x04, 0xf5][..],
                PageKey::NextSeq,
            ),
            (
                &[0xa3, 0x01, 0x80, 0x02, 0x01, 0x04, 0xf5][..],
                PageKey::OldestSeq,
            ),
            (
                &[0xa3, 0x01, 0x80, 0x02, 0x01, 0x03, 0x01][..],
                PageKey::Complete,
            ),
        ];
        for (body, missing) in cases {
            assert_eq!(
                LogPage::decode(body),
                Err(ReadLogError::Missing(ReadLogBodyKey::Page(missing))),
                "{missing}"
            );
        }
    }

    /// Every prefix of a legal page.
    #[test]
    fn every_truncation_of_a_page_is_refused() {
        let (dst, len) = round_tripped(&page(&[10, 11], true));
        for cut in 0..len {
            assert!(
                LogPage::decode(dst.get(..cut).expect("a prefix")).is_err(),
                "decoded {cut} of {len} bytes"
            );
        }
        assert!(LogPage::decode(dst.get(..len).expect("the whole")).is_ok());
    }

    /// A byte after the page is a second message, or one somebody edited.
    #[test]
    fn a_byte_appended_after_a_page_is_refused() {
        let (mut dst, len) = round_tripped(&page(&[10], true));
        let slot = dst.get_mut(len).expect("the scratch is wider");
        *slot = 0x00;
        assert_eq!(
            LogPage::decode(dst.get(..=len).expect("one more")),
            Err(ReadLogError::Cbor(CborError::TrailingBytes))
        );
    }

    /// Every refusal renders as its own sentence and answers the code its
    /// condition names.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [ReadLogError; 6] = [
            ReadLogError::Missing(ReadLogBodyKey::Page(PageKey::Entries)),
            ReadLogError::Duplicate(ReadLogBodyKey::Request(ReadLogKey::FromSeq)),
            ReadLogError::PageFull(64),
            ReadLogError::PageTooLong(2000),
            ReadLogError::Entry(EventError::SeqAtTheCeiling),
            ReadLogError::Cbor(CborError::WrongType),
        ];
        Rendering::<112>::each_says_something_of_its_own(&EVERY);
        assert_eq!(ReadLogError::PageTooLong(2000).refusal().code(), 5);
        assert_eq!(ReadLogError::PageFull(64).refusal().code(), 1);
    }
    /// A record at `u64::MAX` has no position after it. Saturating the cursor
    /// left `next_seq` pointing *at* the delivered record, which is the P-029
    /// duplicate `push`'s own doc says it prevents. Refused, and the page is
    /// left as it was.
    #[test]
    fn a_record_at_the_sequence_ceiling_is_refused_rather_than_given_a_cursor_onto_itself() {
        let mut page = LogPage::new(LogSeq(1), LogSeq(1), false);
        assert_eq!(
            page.push(entry(u64::MAX)),
            Err(ReadLogError::SeqAtTheCeiling)
        );
        page.push(entry(5))
            .expect("a refusal leaves the page usable");
        let mut dst = [0u8; 256];
        let len = page.encode(&mut dst).expect("one record encodes");
        let back = LogPage::decode(dst.get(..len).expect("the page")).expect("it reads back");
        assert_eq!(
            back.next_seq,
            LogSeq(6),
            "the cursor is past the one record that was taken"
        );
    }
}
