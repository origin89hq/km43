//! `Event 0x04` — the only message that arrives without having been asked for,
//! and the mark that stops one arriving twice.
//!
//! The body is deliberately opaque here. Every event kind's schema is deferred
//! (DEFERRED.md entry 10), so this module carries key 4 as the bytes it arrived
//! as and refuses to guess: it checks that they are a well-formed CBOR map and
//! reads not one key inside. A decoder that invented a schema would be two
//! implementations disagreeing about a record that is already in the log.
//!
//! What is *not* deferred is the anti-replay. P-056's mark is one `u64` per
//! session and it is the whole defence: the comms processor can hold a
//! separately-MAC'd event and deliver it again an hour later, and the tag still
//! verifies because it is the same event under the same session key.
//!
//! cites: P-056, P-096

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{ErrorCode, EventKind};
use crate::handshake::LogSeq;
use crate::limits::MAX_EVENT_BODY;

/// The four keys of `Event 0x04`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKey {
    /// Key 1, strictly increasing but **not** contiguous (P-096).
    Seq,
    /// Key 2, optional, and omitted when the clock has never been set (P-093).
    At,
    /// Key 3, an **open** set — a kind this build cannot name is surfaced, not
    /// refused (P-019).
    Kind,
    /// Key 4, whose schema is deferred for every kind.
    Body,
}

impl EventKey {
    const COUNT: usize = 4;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Seq),
            2 => Some(Self::At),
            3 => Some(Self::Kind),
            4 => Some(Self::Body),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Seq => 1,
            Self::At => 2,
            Self::Kind => 3,
            Self::Body => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Seq => "seq",
            Self::At => "at",
            Self::Kind => "kind",
            Self::Body => "body",
        }
    }
}

impl fmt::Display for EventKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Event 0x04 {} (key {})", self.name(), self.number())
    }
}

/// One record on its way to a screen.
///
/// `body` is borrowed and uninterpreted. It is validated as a CBOR map and
/// nothing more, because every kind's schema is deferred — so a client that
/// cannot name the kind still gets a `seq` it can advance its mark with, which
/// is what P-019 asks for and what keeps one unknown record from stopping the
/// stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event<'a> {
    /// Key 1.
    pub seq: LogSeq,
    /// Key 2, and `None` means the clock has never been set rather than 1970.
    pub at: Option<u64>,
    /// Key 3.
    pub kind: EventKind,
    body: &'a [u8],
}

impl<'a> Event<'a> {
    /// A record to send. `body` is the kind's own map, encoded by whoever knows
    /// its schema — which is nobody yet, so this checks its shape and carries it.
    pub fn new(
        seq: LogSeq,
        at: Option<u64>,
        kind: EventKind,
        body: &'a [u8],
    ) -> Result<Self, EventError> {
        shaped(body)?;
        Ok(Self {
            seq,
            at,
            kind,
            body,
        })
    }

    /// Key 4 as it arrived. A caller that knows the kind's schema decodes it;
    /// this module does not, and will not until one is written down.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Encode the three or four keys this record carries.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, EventError> {
        let mut cbor = CborWriter::new(dst);
        self.encode_into(&mut cbor)?;
        Ok(cbor.finish()?)
    }

    /// The same keys, into a writer already standing somewhere — inside a
    /// `LogPage`'s array, which is the only other place these four appear.
    pub(crate) fn encode_into(&self, cbor: &mut CborWriter<'_>) -> Result<(), EventError> {
        cbor.map(EventKey::COUNT - usize::from(self.at.is_none()))?;
        cbor.key(EventKey::Seq.number())?;
        cbor.u64(self.seq.0)?;
        if let Some(at) = self.at {
            cbor.key(EventKey::At.number())?;
            cbor.u64(at)?;
        }
        cbor.key(EventKey::Kind.number())?;
        cbor.u64(u64::from(self.kind.0))?;
        cbor.key(EventKey::Body.number())?;
        cbor.raw(self.body)?;
        Ok(())
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &'a [u8]) -> Result<Self, EventError> {
        let mut body = CborReader::new(payload);
        let read = Self::decode_from(&mut body)?;
        body.finish()?;
        Ok(read)
    }

    /// The same keys, out of a reader already standing somewhere.
    pub(crate) fn decode_from(body: &mut CborReader<'a>) -> Result<Self, EventError> {
        let pairs = body.map()?;
        let mut seq = None;
        let mut at = None;
        let mut kind = None;
        let mut carried = None;
        for _ in 0..pairs {
            let number = body.key()?;
            match EventKey::of(number) {
                Some(EventKey::Seq) => once(&mut seq, EventKey::Seq, body.u64()?)?,
                Some(EventKey::At) => once(&mut at, EventKey::At, body.u64()?)?,
                Some(EventKey::Kind) => once(&mut kind, EventKey::Kind, body.u16()?)?,
                Some(EventKey::Body) => once(&mut carried, EventKey::Body, body.raw()?)?,
                None => body.skip()?,
            }
        }
        let carried = carried.ok_or(EventError::Missing(EventKey::Body))?;
        shaped(carried)?;
        Ok(Self {
            seq: LogSeq(seq.ok_or(EventError::Missing(EventKey::Seq))?),
            at,
            kind: EventKind(kind.ok_or(EventError::Missing(EventKey::Kind))?),
            body: carried,
        })
    }
}

/// P-056's mark: the lowest `seq` this session will still accept.
///
/// One `u64`, and it is the whole of the in-session anti-replay. Every event is
/// separately MAC'd under the session key (P-098), so a relay that holds one and
/// delivers it again an hour later hands over a frame whose tag verifies — the
/// tag says *the controller wrote this*, never *and you have not seen it*.
///
/// Phrased as a floor rather than a high-water line on purpose. Written as *not
/// greater than the highest accepted*, the rule discards the first replayed
/// event of every subscription — `accepted_from_seq` names a position that is
/// delivered (P-029), so the record at exactly that position is not greater than
/// the mark. One record per subscription, always the oldest one asked for, and
/// on a stream that is quiet for eleven months of the year that record is as
/// likely as not the alarm somebody subscribed to find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventMark(LogSeq);

impl EventMark {
    /// The mark a `SubscribeAck` sets: its `accepted_from_seq`, which is the
    /// first position that will be delivered.
    ///
    /// Without the reset, a second `Subscribe` from an earlier position delivers
    /// events the client is then obliged to reject one by one, and the catch-up
    /// P-094 exists to guarantee does nothing at all.
    #[must_use]
    pub const fn accepting_from(accepted_from_seq: LogSeq) -> Self {
        Self(accepted_from_seq)
    }

    /// The lowest `seq` still acceptable.
    #[must_use]
    pub const fn floor(self) -> LogSeq {
        self.0
    }

    /// Take one event, and move the mark past it.
    ///
    /// It takes the `Event` rather than a bare `seq`, so a [`crate::LogEntry`]
    /// cannot reach it: a page of log entries goes backwards by construction,
    /// and P-056 is written about the live stream. The specification says the
    /// two carry the same four keys and gives that as the reason they have
    /// different names — this is the same reason, spelled as a signature.
    ///
    /// A `seq` above the mark with a gap under it is accepted: P-096 says the
    /// space is strictly increasing and **not** contiguous, so a hole is a thing
    /// to surface rather than a frame to refuse — refusing it would make one
    /// dropped class B record stop the stream.
    pub fn accept(&mut self, event: &Event<'_>) -> Result<(), EventError> {
        let seq = event.seq;
        if seq.0 < self.0.0 {
            return Err(EventError::Replayed { floor: self.0, seq });
        }
        let next = seq.0.checked_add(1).ok_or(EventError::SeqAtTheCeiling)?;
        self.0 = LogSeq(next);
        Ok(())
    }
}

/// Key 4 has to be a map, and it has to be one this reader can walk to the end.
///
/// Genuinely free: it takes bytes and belongs to no state. What it does *not* do
/// is read a key — every kind's schema is deferred, and a decoder that guessed
/// one would be the second implementation of a record already in the log.
fn shaped(body: &[u8]) -> Result<(), EventError> {
    if body.len() > MAX_EVENT_BODY {
        return Err(EventError::BodyTooLong(body.len()));
    }
    let mut cbor = CborReader::new(body);
    let pairs = cbor.map()?;
    for _ in 0..pairs {
        cbor.key()?;
        cbor.skip()?;
    }
    cbor.finish()?;
    Ok(())
}

fn once<T>(slot: &mut Option<T>, key: EventKey, value: T) -> Result<(), EventError> {
    if slot.is_some() {
        return Err(EventError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// Why an event was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    /// A required key never arrived (P-015). Key 2 is optional and is not here.
    Missing(EventKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(EventKey),
    /// Key 4 is longer than a frame can carry it in.
    BodyTooLong(usize),
    /// An event at or below the mark (P-056) — the same record delivered twice,
    /// which is what a relay holding a separately-MAC'd frame can do for free.
    Replayed {
        /// The lowest `seq` still acceptable.
        floor: LogSeq,
        /// What arrived.
        seq: LogSeq,
    },
    /// A `seq` at `u64::MAX` leaves no position above it for the mark. Two
    /// centuries of records at one a second, so this is a refusal and not a wrap.
    SeqAtTheCeiling,
    /// The CBOR underneath was refused — including key 4 not being a map.
    Cbor(CborError),
}

impl From<CborError> for EventError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl EventError {
    /// What to answer — and for a replay, nothing.
    ///
    /// P-055 and P-142 both land here: an event arrives unsolicited on a session
    /// the client holds, so a refusal is the client declining to act rather than
    /// a code it puts on the wire. Error 1 is what a *controller* would answer if
    /// one of these ever reached it, which is the direction that never happens.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::BodyTooLong(_)
            | Self::Replayed { .. }
            | Self::SeqAtTheCeiling
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "event carries no {key}"),
            Self::Duplicate(key) => write!(f, "event carries {key} twice"),
            Self::BodyTooLong(len) => {
                write!(
                    f,
                    "event body of {len} bytes is past the {MAX_EVENT_BODY} cap"
                )
            }
            Self::Replayed { floor, seq } => write!(
                f,
                "event at seq {} is below the {} this session will still accept",
                seq.0, floor.0
            ),
            Self::SeqAtTheCeiling => f.write_str("the event seq is at the last position there is"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for EventError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    const SCRATCH: usize = 128;

    /// A `records dropped` body — `{1: 3}` — rather than filler, because key 4
    /// is opaque to this layer and a fixture that looked like filler would hide
    /// it if it ever stopped being.
    const BODY: [u8; 3] = [0xa1, 0x01, 0x03];

    /// The fixture the mark takes, since it accepts a record rather than a
    /// number — which is the point of the signature.
    fn event_at(seq: u64) -> Event<'static> {
        event(seq, None, EventKind::RECORDS_DROPPED)
    }

    fn event(seq: u64, at: Option<u64>, kind: EventKind) -> Event<'static> {
        Event::new(LogSeq(seq), at, kind, &BODY).expect("the fixture is a map")
    }

    fn round_tripped(sent: &Event<'_>) -> ([u8; SCRATCH], usize) {
        let mut dst = [0u8; SCRATCH];
        let len = sent.encode(&mut dst).expect("the fixture encodes");
        (dst, len)
    }

    /// The list and the numbers live in three places apiece.
    #[test]
    fn every_key_number_maps_back_to_the_key_that_claims_it() {
        for n in 1..=EventKey::COUNT {
            let number = i64::try_from(n).expect("a small key number");
            let key = EventKey::of(number).expect("a key");
            assert_eq!(key.number(), number);
        }
        assert!(EventKey::of(0).is_none());
        assert!(EventKey::of(-1).is_none());
        assert!(EventKey::of(5).is_none());
    }

    /// A record arrives saying what the controller wrote, body included and
    /// unread.
    #[test]
    fn an_event_arrives_carrying_the_body_it_left_with() {
        let sent = event(4242, Some(1_700_000_000_000), EventKind::RECORDS_DROPPED);
        let (dst, len) = round_tripped(&sent);
        let read = Event::decode(dst.get(..len).expect("the length")).expect("it decodes");
        assert_eq!(read, sent);
        assert_eq!(read.body(), &BODY[..], "key 4 moved");
        assert_eq!(read.seq, LogSeq(4242));
        assert_eq!(read.kind, EventKind::RECORDS_DROPPED);
    }

    /// P-019. A firmware two versions newer publishes a kind this build has
    /// never heard of, and the record still arrives with a `seq` the client can
    /// advance its mark with — because refusing it would stop the stream on a
    /// record nobody needed to read.
    #[test]
    fn an_event_kind_this_build_cannot_name_still_carries_its_seq() {
        for kind in [EventKind(0x0999), EventKind(0xF001), EventKind(0xFFFF)] {
            let sent = event(7, None, kind);
            let (dst, len) = round_tripped(&sent);
            let read = Event::decode(dst.get(..len).expect("the length")).expect("it decodes");
            assert_eq!(read.kind, kind);
            assert_eq!(read.seq, LogSeq(7), "an unnamed kind lost its position");
            assert_eq!(read.body(), &BODY[..], "and its body is carried, not read");
        }
    }

    /// P-093. A controller whose clock has never been set omits key 2 rather
    /// than sending a zero, because 1970 is a plausible wrong answer to *when*.
    #[test]
    fn p_093_a_record_from_a_controller_with_no_clock_omits_the_time() {
        let sent = event(9, None, EventKind::RECORDS_DROPPED);
        let (dst, len) = round_tripped(&sent);
        // Three keys, and key 2 is not among them.
        assert_eq!(
            dst.get(..len),
            Some(
                &[
                    0xa3, 0x01, 0x09, 0x03, 0x19, 0x07, 0x01, 0x04, 0xa1, 0x01, 0x03
                ][..]
            )
        );
        let read = Event::decode(dst.get(..len).expect("the length")).expect("it decodes");
        assert_eq!(read.at, None);
    }

    /// P-056, and the failure it stops is the one a separately-MAC'd event
    /// invites: the comms processor holds a copy and delivers it again an hour
    /// later. The tag verifies — it says *the controller wrote this*, never
    /// *and you have not seen it*.
    #[test]
    fn p_056_an_event_delivered_twice_is_refused_the_second_time() {
        let mut mark = EventMark::accepting_from(LogSeq(10));
        assert!(
            mark.accept(&event_at(10)).is_ok(),
            "P-029: that record is delivered"
        );
        assert_eq!(
            mark.accept(&event_at(10)),
            Err(EventError::Replayed {
                floor: LogSeq(11),
                seq: LogSeq(10),
            })
        );
        // And anything older, which is the replay window a relay actually has.
        assert!(mark.accept(&event_at(9)).is_err());
        assert!(mark.accept(&event_at(0)).is_err());
    }

    /// P-056's floor, and why it is a floor. Written as *not greater than the
    /// highest accepted*, the rule discards the first replayed event of every
    /// subscription — the oldest record the client asked for, which on a stream
    /// quiet for eleven months is as likely as not the alarm they subscribed to
    /// find.
    #[test]
    fn p_056_the_first_record_a_subscription_asked_for_is_delivered() {
        let mut mark = EventMark::accepting_from(LogSeq(42));
        assert_eq!(mark.floor(), LogSeq(42));
        assert!(
            mark.accept(&event_at(42)).is_ok(),
            "accepted_from_seq names a position that IS delivered"
        );
        assert_eq!(mark.floor(), LogSeq(43));

        // A later Subscribe resets it, or the catch-up P-094 guarantees does
        // nothing at all.
        let mut mark = EventMark::accepting_from(LogSeq(5));
        assert!(mark.accept(&event_at(5)).is_ok());
    }

    /// P-096. The space is strictly increasing and **not** contiguous, so a hole
    /// is a thing to surface rather than a frame to refuse — refusing one would
    /// make a single dropped class B record stop the stream.
    #[test]
    fn p_096_a_hole_in_the_sequence_does_not_stop_the_stream() {
        let mut mark = EventMark::accepting_from(LogSeq(1));
        assert!(mark.accept(&event_at(1)).is_ok());
        assert!(mark.accept(&event_at(2)).is_ok());
        // 3, 4 and 5 were dropped under pressure, failed a CRC, or never left
        // the comms processor. The stream continues.
        assert!(mark.accept(&event_at(6)).is_ok());
        assert_eq!(mark.floor(), LogSeq(7));
        // But the hole does not license going backwards into it.
        assert!(mark.accept(&event_at(4)).is_err());
    }

    /// Two centuries of records at one a second, so the ceiling is a refusal
    /// rather than a wrap back onto a position already delivered.
    #[test]
    fn a_seq_at_the_ceiling_leaves_no_position_above_it() {
        let mut mark = EventMark::accepting_from(LogSeq(u64::MAX));
        assert_eq!(
            mark.accept(&event_at(u64::MAX)),
            Err(EventError::SeqAtTheCeiling)
        );
    }

    /// Key 4 is a map whose schema is deferred, so the one thing this module can
    /// check is its shape. A body that is an array, a byte string or an integer
    /// is refused — a decoder that took any of them would be inventing the
    /// schema it is waiting for.
    #[test]
    fn a_body_that_is_not_a_map_is_refused_rather_than_carried() {
        for body in [&[0x80][..], &[0x40][..], &[0x00][..], &[0xf5][..]] {
            assert_eq!(
                Event::new(LogSeq(1), None, EventKind::RECORDS_DROPPED, body),
                Err(EventError::Cbor(CborError::WrongType)),
                "{body:?} carried as a body"
            );
        }
    }

    /// A body that is a map and then some. `raw` walks the item to prove it is
    /// well formed, so a caller cannot smuggle a second item past a reader that
    /// only looked at the first byte.
    #[test]
    fn a_body_with_a_second_item_after_it_is_refused() {
        assert_eq!(
            Event::new(LogSeq(1), None, EventKind::RECORDS_DROPPED, &[0xa0, 0x00]),
            Err(EventError::Cbor(CborError::TrailingBytes))
        );
        // And a map that promises a pair it does not deliver.
        assert_eq!(
            Event::new(LogSeq(1), None, EventKind::RECORDS_DROPPED, &[0xa1, 0x01]),
            Err(EventError::Cbor(CborError::EndOfInput))
        );
    }

    /// P-013. A v2 controller adding a key to the record must reach a v1 client
    /// as an event, not as an error — one firmware update must not blank every
    /// stream in the field.
    #[test]
    fn a_key_this_version_does_not_know_is_skipped() {
        // `{1: 9, 3: 0x0701, 4: {1:3}, 9: true}`
        let body = [
            0xa4, 0x01, 0x09, 0x03, 0x19, 0x07, 0x01, 0x04, 0xa1, 0x01, 0x03, 0x09, 0xf5,
        ];
        let read = Event::decode(&body).expect("a newer peer's key is skipped");
        assert_eq!(read.seq, LogSeq(9));
        assert_eq!(read.body(), &BODY[..]);
    }

    /// P-015. Two libraries resolving a repeated key differently read different
    /// records out of one authenticated message.
    #[test]
    fn a_key_that_arrives_twice_is_refused_before_either_copy_is_used() {
        // `{1: 9, 1: 10, 3: 0x0701, 4: {}}`
        assert_eq!(
            Event::decode(&[
                0xa4, 0x01, 0x09, 0x01, 0x0a, 0x03, 0x19, 0x07, 0x01, 0x04, 0xa0
            ]),
            Err(EventError::Duplicate(EventKey::Seq))
        );
        // And key 4, which is the one carried verbatim.
        assert_eq!(
            Event::decode(&[
                0xa4, 0x01, 0x09, 0x03, 0x19, 0x07, 0x01, 0x04, 0xa0, 0x04, 0xa0
            ]),
            Err(EventError::Duplicate(EventKey::Body))
        );
    }

    /// A required key that never arrived is error 1, and the refusal names which
    /// one. Key 2 is optional and is not among them.
    #[test]
    fn a_record_missing_a_required_key_says_which_one() {
        let cases = [
            (&[0xa2, 0x03, 0x01, 0x04, 0xa0][..], EventKey::Seq),
            (&[0xa2, 0x01, 0x09, 0x04, 0xa0][..], EventKey::Kind),
            (&[0xa2, 0x01, 0x09, 0x03, 0x01][..], EventKey::Body),
        ];
        for (body, missing) in cases {
            assert_eq!(
                Event::decode(body),
                Err(EventError::Missing(missing)),
                "{missing}"
            );
        }
        // Key 2 absent is a record, not a refusal.
        assert!(Event::decode(&[0xa3, 0x01, 0x09, 0x03, 0x01, 0x04, 0xa0]).is_ok());
    }

    /// A body past what a frame can carry it in, refused before the record is
    /// built rather than after the frame is.
    #[test]
    fn a_body_past_the_cap_is_refused_rather_than_framed() {
        let mut wide = [0xa0u8; MAX_EVENT_BODY + 1];
        // A map of one pair whose value fills the rest, so it is a legal item
        // and its only fault is its size.
        wide[0] = 0xa1;
        wide[1] = 0x01;
        wide[2] = 0x59;
        let len = MAX_EVENT_BODY + 1 - 5;
        wide[3] = u8::try_from(len >> 8).expect("a two-byte length");
        wide[4] = u8::try_from(len & 0xff).expect("a two-byte length");
        assert_eq!(
            Event::new(LogSeq(1), None, EventKind::RECORDS_DROPPED, &wide),
            Err(EventError::BodyTooLong(MAX_EVENT_BODY + 1))
        );
    }

    /// Every prefix of a legal record, because a link that dropped mid-frame
    /// must never leave a shorter event that still decodes.
    #[test]
    fn every_truncation_of_an_event_is_refused() {
        let (dst, len) = round_tripped(&event(9, Some(7), EventKind::RECORDS_DROPPED));
        for cut in 0..len {
            assert!(
                Event::decode(dst.get(..cut).expect("a prefix")).is_err(),
                "decoded {cut} of {len} bytes"
            );
        }
        assert!(Event::decode(dst.get(..len).expect("the whole")).is_ok());
    }

    /// A byte after the record is a second message, or one somebody edited.
    #[test]
    fn a_byte_appended_after_an_event_is_refused() {
        let (mut dst, len) = round_tripped(&event(9, None, EventKind::RECORDS_DROPPED));
        let slot = dst.get_mut(len).expect("the scratch is wider");
        *slot = 0x00;
        assert_eq!(
            Event::decode(dst.get(..=len).expect("one more")),
            Err(EventError::Cbor(CborError::TrailingBytes))
        );
    }

    /// Every refusal renders as its own sentence. The pair somebody tells apart
    /// at a bench is "this record is old" and "this record is malformed".
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [EventError; 6] = [
            EventError::Missing(EventKey::Seq),
            EventError::Duplicate(EventKey::Body),
            EventError::BodyTooLong(2000),
            EventError::Replayed {
                floor: LogSeq(11),
                seq: LogSeq(10),
            },
            EventError::SeqAtTheCeiling,
            EventError::Cbor(CborError::WrongType),
        ];
        Rendering::<112>::each_says_something_of_its_own(&EVERY);
        for why in EVERY {
            assert_eq!(why.refusal().code(), 1, "{why}");
        }
    }
}
