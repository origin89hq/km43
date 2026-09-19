//! `Subscribe 0x03` / `0x83` — where a client's event stream starts, and the
//! one field that decides how much history arrives.
//!
//! `accepted_from_seq` is the whole message. Answer the client's own 0 and a
//! controller replays the entire retained ring at somebody who asked for
//! nothing behind them; answer `current_seq` and it replays nothing, ever.
//! Both obey every other rule in the document, which is why P-104 exists and
//! why the arithmetic lives in one function here rather than at each call site.
//!
//! cites: P-095, P-104, P-144

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::ErrorCode;
use crate::handshake::LogSeq;

/// The one key of `Subscribe 0x03`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SubscribeKey {
    /// Key 1. Zero is the sentinel, not a position (P-144).
    FromSeq,
}

impl SubscribeKey {
    const COUNT: usize = 1;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::FromSeq),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::FromSeq => 1,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::FromSeq => "from_seq",
        }
    }
}

impl fmt::Display for SubscribeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Subscribe 0x03 {} (key {})", self.name(), self.number())
    }
}

/// The four keys of `SubscribeAck 0x83`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AckKey {
    /// Key 1, the first position that will be delivered (P-029).
    AcceptedFromSeq,
    /// Key 2.
    OldestSeq,
    /// Key 3.
    CurrentSeq,
    /// Key 4.
    Gap,
}

impl AckKey {
    const COUNT: usize = 4;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::AcceptedFromSeq),
            2 => Some(Self::OldestSeq),
            3 => Some(Self::CurrentSeq),
            4 => Some(Self::Gap),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::AcceptedFromSeq => 1,
            Self::OldestSeq => 2,
            Self::CurrentSeq => 3,
            Self::Gap => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::AcceptedFromSeq => "accepted_from_seq",
            Self::OldestSeq => "oldest_seq",
            Self::CurrentSeq => "current_seq",
            Self::Gap => "gap",
        }
    }
}

impl fmt::Display for AckKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubscribeAck 0x83 {} (key {})",
            self.name(),
            self.number()
        )
    }
}

/// A key of either body here, so one refusal can name either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SubscribeBodyKey {
    /// A key of `Subscribe 0x03`.
    Request(SubscribeKey),
    /// A key of `SubscribeAck 0x83`.
    Ack(AckKey),
}

impl From<SubscribeKey> for SubscribeBodyKey {
    fn from(key: SubscribeKey) -> Self {
        Self::Request(key)
    }
}

impl From<AckKey> for SubscribeBodyKey {
    fn from(key: AckKey) -> Self {
        Self::Ack(key)
    }
}

impl fmt::Display for SubscribeBodyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(key) => key.fmt(f),
            Self::Ack(key) => key.fmt(f),
        }
    }
}

/// What a client asked for: everything from a position, or nothing behind it.
///
/// The sentinel as a type. Key 1 carries 0 for *live only*, and P-144 says 0 is
/// not a position — so a `LogSeq` here would be one value meaning two things,
/// and the arithmetic P-104 spells out is exactly the arithmetic that gets it
/// wrong when they are confused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Replay {
    /// Key 1 was 0: deliver nothing that already exists.
    LiveOnly,
    /// Key 1 named a position. It may be behind the ring — that is what `gap`
    /// is for — but it is a position.
    From(LogSeq),
}

impl Replay {
    /// What goes on the wire: 0 for *live only*, the position otherwise.
    const fn wire(self) -> u64 {
        match self {
            Self::LiveOnly => 0,
            Self::From(at) => at.0,
        }
    }

    /// Read one off the wire. 0 is the sentinel and everything else is a
    /// position (P-144).
    const fn of(raw: u64) -> Self {
        match raw {
            0 => Self::LiveOnly,
            at => Self::From(LogSeq(at)),
        }
    }
}

/// What the log holds, which is the input P-104's arithmetic needs.
///
/// A log holding nothing is a state and not a missing value: under P-144 a
/// `seq` of 0 means *no record*, which is what makes `current_seq + 1` come out
/// as 1 — the position the first record will take — rather than one past a
/// record nobody wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LogExtent {
    oldest: LogSeq,
    newest: LogSeq,
}

impl LogExtent {
    /// A log with no record in it yet.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            oldest: LogSeq(0),
            newest: LogSeq(0),
        }
    }

    /// A log holding everything from `oldest` to `newest`.
    ///
    /// Both are positions, so neither is 0 (P-144), and `oldest` cannot be past
    /// `newest` — a ring that reports the two the wrong way round makes P-104's
    /// `max` pick the value P-099 was clamping away from.
    pub const fn holding(oldest: LogSeq, newest: LogSeq) -> Result<Self, SubscribeError> {
        if oldest.0 == 0 || newest.0 == 0 {
            return Err(SubscribeError::ZeroIsNotAPosition);
        }
        if oldest.0 > newest.0 {
            return Err(SubscribeError::OldestPastNewest);
        }
        Ok(Self { oldest, newest })
    }

    /// Key 2.
    #[must_use]
    pub const fn oldest(self) -> LogSeq {
        self.oldest
    }

    /// Key 3, and 0 when the log holds nothing.
    #[must_use]
    pub const fn newest(self) -> LogSeq {
        self.newest
    }
}

/// The body of `Subscribe 0x03`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Subscribe {
    /// Key 1.
    pub replay: Replay,
}

impl Subscribe {
    /// Encode the one key. The caller wraps and MACs it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, SubscribeError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(SubscribeKey::COUNT)?;
        cbor.key(SubscribeKey::FromSeq.number())?;
        cbor.u64(self.replay.wire())?;
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &[u8]) -> Result<Self, SubscribeError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut from_seq = None;
        for _ in 0..pairs {
            let number = body.key()?;
            match SubscribeKey::of(number) {
                Some(key) => {
                    if from_seq.is_some() {
                        return Err(SubscribeError::Duplicate(key.into()));
                    }
                    from_seq = Some(body.u64()?);
                }
                None => body.skip()?,
            }
        }
        body.finish()?;
        let raw = from_seq.ok_or(SubscribeError::Missing(SubscribeKey::FromSeq.into()))?;
        Ok(Self {
            replay: Replay::of(raw),
        })
    }
}

/// The body of `SubscribeAck 0x83`.
///
/// Built by [`SubscribeAck::answer`] rather than as a literal, because key 1 is
/// P-104's arithmetic and a field somebody fills in by hand is the field two
/// implementations disagree about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SubscribeAck {
    accepted_from_seq: LogSeq,
    extent: LogExtent,
    gap: bool,
}

impl SubscribeAck {
    /// P-104 and P-095, in the one place both go through.
    ///
    /// `accepted_from_seq` is `current_seq + 1` for *live only* and
    /// `max(from_seq, oldest_seq)` otherwise — the second is P-099's `ReadLog`
    /// clamp word for word, because the same fall off the same ring answered two
    /// ways is a difference somebody has to discover at a site.
    pub fn answer(request: Subscribe, log: LogExtent) -> Result<Self, SubscribeError> {
        let (accepted, gap) = match request.replay {
            Replay::LiveOnly => {
                let next = log
                    .newest
                    .0
                    .checked_add(1)
                    .ok_or(SubscribeError::LogAtTheCeiling)?;
                // P-095 exempts the sentinel: a client that asked for nothing
                // behind it must not be told, every single time, that it lost
                // data it never wanted.
                (LogSeq(next), false)
            }
            Replay::From(at) => (LogSeq(at.0.max(log.oldest.0)), at.0 < log.oldest.0),
        };
        Ok(Self {
            accepted_from_seq: accepted,
            extent: log,
            gap,
        })
    }

    /// Key 1: the first position that will be delivered (P-029).
    #[must_use]
    pub const fn accepted_from_seq(self) -> LogSeq {
        self.accepted_from_seq
    }

    /// Key 2.
    #[must_use]
    pub const fn oldest_seq(self) -> LogSeq {
        self.extent.oldest
    }

    /// Key 3.
    #[must_use]
    pub const fn current_seq(self) -> LogSeq {
        self.extent.newest
    }

    /// Key 4: the client fell off the ring and knows precisely that it did.
    #[must_use]
    pub const fn gap(self) -> bool {
        self.gap
    }

    /// Encode the four keys.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, SubscribeError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(AckKey::COUNT)?;
        cbor.key(AckKey::AcceptedFromSeq.number())?;
        cbor.u64(self.accepted_from_seq.0)?;
        cbor.key(AckKey::OldestSeq.number())?;
        cbor.u64(self.extent.oldest.0)?;
        cbor.key(AckKey::CurrentSeq.number())?;
        cbor.u64(self.extent.newest.0)?;
        cbor.key(AckKey::Gap.number())?;
        cbor.bool(self.gap)?;
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &[u8]) -> Result<Self, SubscribeError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut slots = AckSlots::empty();
        for _ in 0..pairs {
            let number = body.key()?;
            match AckKey::of(number) {
                Some(key) => slots.fill(key, &mut body)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        slots.complete()
    }
}

/// What has arrived of a `SubscribeAck` so far.
struct AckSlots {
    accepted: Option<u64>,
    oldest: Option<u64>,
    current: Option<u64>,
    gap: Option<bool>,
}

impl AckSlots {
    const fn empty() -> Self {
        Self {
            accepted: None,
            oldest: None,
            current: None,
            gap: None,
        }
    }

    fn fill(&mut self, key: AckKey, body: &mut CborReader<'_>) -> Result<(), SubscribeError> {
        match key {
            AckKey::AcceptedFromSeq => Self::once(&mut self.accepted, key, body.u64()?),
            AckKey::OldestSeq => Self::once(&mut self.oldest, key, body.u64()?),
            AckKey::CurrentSeq => Self::once(&mut self.current, key, body.u64()?),
            AckKey::Gap => Self::once(&mut self.gap, key, body.bool()?),
        }
    }

    fn once<T>(slot: &mut Option<T>, key: AckKey, value: T) -> Result<(), SubscribeError> {
        if slot.is_some() {
            return Err(SubscribeError::Duplicate(key.into()));
        }
        *slot = Some(value);
        Ok(())
    }

    fn complete(self) -> Result<SubscribeAck, SubscribeError> {
        let accepted = self
            .accepted
            .ok_or(SubscribeError::Missing(AckKey::AcceptedFromSeq.into()))?;
        let oldest = self
            .oldest
            .ok_or(SubscribeError::Missing(AckKey::OldestSeq.into()))?;
        let current = self
            .current
            .ok_or(SubscribeError::Missing(AckKey::CurrentSeq.into()))?;
        let gap = self
            .gap
            .ok_or(SubscribeError::Missing(AckKey::Gap.into()))?;
        // An extent the controller could not have held is a message whose
        // arithmetic cannot be trusted, and key 1 is derived from exactly these
        // two. A log that reports nothing reports both as 0 (P-144).
        let extent = if oldest == 0 && current == 0 {
            LogExtent::empty()
        } else {
            LogExtent::holding(LogSeq(oldest), LogSeq(current))?
        };
        Ok(SubscribeAck {
            accepted_from_seq: LogSeq(accepted),
            extent,
            gap,
        })
    }
}

/// Why a subscription was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SubscribeError {
    /// A required key never arrived (P-015).
    Missing(SubscribeBodyKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(SubscribeBodyKey),
    /// A `seq` of 0 offered as a position (P-144). Zero means *no record*, and
    /// a log that holds one holds it at 1.
    ZeroIsNotAPosition,
    /// An extent whose oldest record is past its newest — a ring reporting its
    /// two ends the wrong way round, which makes P-104's `max` pick the value
    /// P-099 clamps away from.
    OldestPastNewest,
    /// A log at `u64::MAX` has no next position to accept a live-only
    /// subscription from. Two centuries of records at one a second, so this is
    /// a refusal rather than a wrap.
    LogAtTheCeiling,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for SubscribeError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl SubscribeError {
    /// What to answer. All of these are error 1: a body whose arithmetic cannot
    /// be trusted is a frame whose meaning is not knowable, which is what error
    /// 1 says.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::ZeroIsNotAPosition
            | Self::OldestPastNewest
            | Self::LogAtTheCeiling
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for SubscribeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "subscription carries no {key}"),
            Self::Duplicate(key) => write!(f, "subscription carries {key} twice"),
            Self::ZeroIsNotAPosition => {
                f.write_str("seq 0 is no record rather than a position a log holds")
            }
            Self::OldestPastNewest => f.write_str("the log's oldest record is past its newest"),
            Self::LogAtTheCeiling => {
                f.write_str("the log is at the last position there is, so there is no next one")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for SubscribeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    const SCRATCH: usize = 64;

    fn holding(oldest: u64, newest: u64) -> LogExtent {
        LogExtent::holding(LogSeq(oldest), LogSeq(newest)).expect("a real extent")
    }

    fn answered(replay: Replay, log: LogExtent) -> SubscribeAck {
        SubscribeAck::answer(Subscribe { replay }, log).expect("the fixture answers")
    }

    /// The list and the numbers live in three places apiece, and a transposed
    /// pair reads perfectly in all three.
    #[test]
    fn every_key_number_maps_back_to_the_key_that_claims_it() {
        for n in 1..=SubscribeKey::COUNT {
            let number = i64::try_from(n).expect("a small key number");
            let key = SubscribeKey::of(number).expect("a key");
            assert_eq!(key.number(), number);
        }
        assert!(SubscribeKey::of(0).is_none());
        assert!(SubscribeKey::of(2).is_none());

        for n in 1..=AckKey::COUNT {
            let number = i64::try_from(n).expect("a small key number");
            let key = AckKey::of(number).expect("a key");
            assert_eq!(key.number(), number);
        }
        assert!(AckKey::of(0).is_none());
        assert!(AckKey::of(-1).is_none());
        assert!(AckKey::of(5).is_none());
    }

    /// P-104's first half. *Live only* means the first position **after**
    /// everything that already exists — answer `current_seq` and the controller
    /// has promised the client the newest record it explicitly asked not to
    /// receive.
    #[test]
    fn p_104_a_live_only_subscription_starts_one_past_the_newest_record() {
        let ack = answered(Replay::LiveOnly, holding(10, 42));
        assert_eq!(ack.accepted_from_seq(), LogSeq(43));
        assert!(!ack.gap(), "asking for nothing behind you is not a gap");

        // And on a log that has never wrapped, where oldest is the first record.
        assert_eq!(
            answered(Replay::LiveOnly, holding(1, 1)).accepted_from_seq(),
            LogSeq(2)
        );
    }

    /// P-144, which is what makes P-104 need no exception for an empty log. A
    /// controller with nothing written yet answers 1 — the position the first
    /// record will take — rather than one past a record nobody wrote.
    #[test]
    fn p_144_a_subscription_to_an_empty_log_starts_at_the_first_position() {
        let ack = answered(Replay::LiveOnly, LogExtent::empty());
        assert_eq!(ack.accepted_from_seq(), LogSeq(1));
        assert_eq!(ack.oldest_seq(), LogSeq(0), "no record is 0, not 1");
        assert_eq!(ack.current_seq(), LogSeq(0));
        assert!(!ack.gap());

        // A position is never 0, in either end of an extent.
        assert_eq!(
            LogExtent::holding(LogSeq(0), LogSeq(4)),
            Err(SubscribeError::ZeroIsNotAPosition)
        );
        assert_eq!(
            LogExtent::holding(LogSeq(4), LogSeq(0)),
            Err(SubscribeError::ZeroIsNotAPosition)
        );
    }

    /// P-104's second half: `max(from_seq, oldest_seq)`, which is P-099's
    /// `ReadLog` clamp word for word. The same fall off the same ring answered
    /// two ways in two messages is a difference somebody has to discover.
    #[test]
    fn p_104_a_replay_from_behind_the_ring_is_clamped_up_to_what_the_ring_holds() {
        // Behind the ring: clamped up.
        assert_eq!(
            answered(Replay::From(LogSeq(3)), holding(10, 42)).accepted_from_seq(),
            LogSeq(10)
        );
        // Inside the ring: taken as asked.
        assert_eq!(
            answered(Replay::From(LogSeq(20)), holding(10, 42)).accepted_from_seq(),
            LogSeq(20)
        );
        // Exactly the oldest: P-029 says that record is delivered, so it is not
        // clamped past itself.
        assert_eq!(
            answered(Replay::From(LogSeq(10)), holding(10, 42)).accepted_from_seq(),
            LogSeq(10)
        );
        // Past the newest: P-104 is total, and the position it names is the one
        // the client asked for.
        assert_eq!(
            answered(Replay::From(LogSeq(1000)), holding(10, 42)).accepted_from_seq(),
            LogSeq(1000)
        );
    }

    /// P-095. The client fell off the ring and knows precisely that it did —
    /// and the sentinel is exempt, or a client that deliberately asked for
    /// nothing behind it is told it lost data it never wanted, every time.
    #[test]
    fn p_095_falling_off_the_ring_is_a_gap_and_asking_for_nothing_is_not() {
        assert!(answered(Replay::From(LogSeq(3)), holding(10, 42)).gap());
        assert!(!answered(Replay::From(LogSeq(10)), holding(10, 42)).gap());
        assert!(!answered(Replay::From(LogSeq(11)), holding(10, 42)).gap());

        // The exemption, on a ring that has wrapped — where `0 < oldest_seq` is
        // unconditionally true and a naive rule reports a gap forever.
        assert!(!answered(Replay::LiveOnly, holding(10, 42)).gap());
        assert!(!answered(Replay::LiveOnly, holding(9_999, 10_000)).gap());
    }

    /// The sentinel as a type. Key 1 carries one number meaning two things, and
    /// the arithmetic that tells them apart is the arithmetic that gets it
    /// wrong when they are confused.
    #[test]
    fn a_from_seq_of_zero_is_live_only_and_not_a_request_for_position_zero() {
        assert_eq!(Replay::of(0), Replay::LiveOnly);
        assert_eq!(Replay::of(1), Replay::From(LogSeq(1)));
        assert_eq!(Replay::LiveOnly.wire(), 0);
        assert_eq!(Replay::From(LogSeq(1)).wire(), 1);

        // And it round-trips through the body rather than only through itself.
        for replay in [
            Replay::LiveOnly,
            Replay::From(LogSeq(1)),
            Replay::From(LogSeq(u64::MAX)),
        ] {
            let mut dst = [0u8; SCRATCH];
            let len = Subscribe { replay }.encode(&mut dst).expect("it encodes");
            assert_eq!(
                Subscribe::decode(dst.get(..len).expect("the length")),
                Ok(Subscribe { replay })
            );
        }
    }

    /// The whole ack, out and back, meaning the same thing at both ends.
    #[test]
    fn an_ack_arrives_saying_what_the_controller_answered() {
        for (replay, log) in [
            (Replay::LiveOnly, holding(10, 42)),
            (Replay::LiveOnly, LogExtent::empty()),
            (Replay::From(LogSeq(3)), holding(10, 42)),
            (Replay::From(LogSeq(20)), holding(10, 42)),
        ] {
            let sent = answered(replay, log);
            let mut dst = [0u8; SCRATCH];
            let len = sent.encode(&mut dst).expect("it encodes");
            assert_eq!(
                SubscribeAck::decode(dst.get(..len).expect("the length")),
                Ok(sent),
                "{replay:?}"
            );
        }
    }

    /// A ring that reports its two ends the wrong way round makes P-104's `max`
    /// pick the value P-099 exists to clamp away from — so a client asking for
    /// position 5 of a log claiming oldest 40 and newest 10 would be answered
    /// 40, a position that log does not hold.
    #[test]
    fn an_extent_whose_oldest_is_past_its_newest_is_refused() {
        assert_eq!(
            LogExtent::holding(LogSeq(40), LogSeq(10)),
            Err(SubscribeError::OldestPastNewest)
        );
        assert!(LogExtent::holding(LogSeq(10), LogSeq(10)).is_ok());

        // And it is refused on the way in as well, because the arithmetic a
        // client checks is derived from exactly these two.
        let body = [0xa4, 0x01, 0x05, 0x02, 0x18, 0x28, 0x03, 0x0a, 0x04, 0xf4];
        assert_eq!(
            SubscribeAck::decode(&body),
            Err(SubscribeError::OldestPastNewest)
        );
    }

    /// Two centuries of records at one a second, so the ceiling is a refusal
    /// rather than a wrap onto position 0 — which P-144 says is no position.
    #[test]
    fn a_log_at_the_last_position_has_no_next_one_to_subscribe_from() {
        let full = holding(1, u64::MAX);
        assert_eq!(
            SubscribeAck::answer(
                Subscribe {
                    replay: Replay::LiveOnly
                },
                full
            ),
            Err(SubscribeError::LogAtTheCeiling)
        );
        // A replay from a position still works there — nothing is added.
        assert!(
            SubscribeAck::answer(
                Subscribe {
                    replay: Replay::From(LogSeq(u64::MAX))
                },
                full
            )
            .is_ok()
        );
    }

    /// P-013. A v2 client that subscribes with a filter must reach a v1
    /// controller as a subscription, not as error 1.
    #[test]
    fn a_key_this_version_does_not_know_is_skipped() {
        // `{1: 7, 9: true}`
        assert_eq!(
            Subscribe::decode(&[0xa2, 0x01, 0x07, 0x09, 0xf5]),
            Ok(Subscribe {
                replay: Replay::From(LogSeq(7))
            })
        );
        // `{1: 5, 2: 1, 3: 9, 4: false, 9: 99}`
        let ack = SubscribeAck::decode(&[
            0xa5, 0x01, 0x05, 0x02, 0x01, 0x03, 0x09, 0x04, 0xf4, 0x09, 0x18, 0x63,
        ])
        .expect("a newer peer's key is skipped");
        assert_eq!(ack.accepted_from_seq(), LogSeq(5));
    }

    /// P-015. Two libraries that resolve a repeated key differently read
    /// different subscriptions out of one authenticated message.
    #[test]
    fn a_key_that_arrives_twice_is_refused_before_either_copy_is_used() {
        assert_eq!(
            Subscribe::decode(&[0xa2, 0x01, 0x07, 0x01, 0x08]),
            Err(SubscribeError::Duplicate(SubscribeBodyKey::Request(
                SubscribeKey::FromSeq
            )))
        );
        assert_eq!(
            SubscribeAck::decode(&[
                0xa5, 0x01, 0x05, 0x01, 0x06, 0x02, 0x01, 0x03, 0x09, 0x04, 0xf4
            ]),
            Err(SubscribeError::Duplicate(SubscribeBodyKey::Ack(
                AckKey::AcceptedFromSeq
            )))
        );
    }

    /// A required key that never arrived is error 1, and the refusal names
    /// which one.
    #[test]
    fn a_body_missing_a_required_key_says_which_one() {
        assert_eq!(
            Subscribe::decode(&[0xa0]),
            Err(SubscribeError::Missing(SubscribeBodyKey::Request(
                SubscribeKey::FromSeq
            )))
        );
        let cases = [
            (
                &[0xa3, 0x02, 0x01, 0x03, 0x09, 0x04, 0xf4][..],
                AckKey::AcceptedFromSeq,
            ),
            (
                &[0xa3, 0x01, 0x05, 0x03, 0x09, 0x04, 0xf4][..],
                AckKey::OldestSeq,
            ),
            (
                &[0xa3, 0x01, 0x05, 0x02, 0x01, 0x04, 0xf4][..],
                AckKey::CurrentSeq,
            ),
            (&[0xa3, 0x01, 0x05, 0x02, 0x01, 0x03, 0x09][..], AckKey::Gap),
        ];
        for (body, missing) in cases {
            assert_eq!(
                SubscribeAck::decode(body),
                Err(SubscribeError::Missing(SubscribeBodyKey::Ack(missing))),
                "{missing}"
            );
        }
    }

    /// `gap` is a CBOR bool, major 7, one byte — never 0 and 1. An encoder that
    /// writes it as a number is a decoder's error 1.
    #[test]
    fn the_gap_flag_is_a_bool_and_not_a_number() {
        let mut dst = [0u8; SCRATCH];
        let len = answered(Replay::From(LogSeq(3)), holding(10, 42))
            .encode(&mut dst)
            .expect("it encodes");
        assert_eq!(
            dst.get(..len),
            Some(&[0xa4, 0x01, 0x0a, 0x02, 0x0a, 0x03, 0x18, 0x2a, 0x04, 0xf5][..])
        );

        // `{1:5, 2:1, 3:9, 4:1}` — the flag as a number.
        assert_eq!(
            SubscribeAck::decode(&[0xa4, 0x01, 0x05, 0x02, 0x01, 0x03, 0x09, 0x04, 0x01]),
            Err(SubscribeError::Cbor(CborError::WrongType))
        );
    }

    /// Every prefix of a legal body, because a link that dropped mid-frame must
    /// never leave a shorter subscription that still decodes.
    #[test]
    fn every_truncation_of_an_ack_is_refused() {
        let mut dst = [0u8; SCRATCH];
        let len = answered(Replay::From(LogSeq(3)), holding(10, 42))
            .encode(&mut dst)
            .expect("it encodes");
        for cut in 0..len {
            assert!(
                SubscribeAck::decode(dst.get(..cut).expect("a prefix")).is_err(),
                "decoded {cut} of {len} bytes"
            );
        }
        assert!(SubscribeAck::decode(dst.get(..len).expect("the whole")).is_ok());
    }

    /// A byte after the body is a second message, or one somebody edited.
    #[test]
    fn a_byte_appended_after_an_ack_is_refused() {
        let mut dst = [0u8; SCRATCH];
        let len = answered(Replay::LiveOnly, holding(10, 42))
            .encode(&mut dst)
            .expect("it encodes");
        let slot = dst.get_mut(len).expect("the scratch is wider");
        *slot = 0x00;
        assert_eq!(
            SubscribeAck::decode(dst.get(..=len).expect("one more")),
            Err(SubscribeError::Cbor(CborError::TrailingBytes))
        );
    }

    /// Every refusal is error 1, listed rather than collapsed so a variant that
    /// is not has to say so.
    #[test]
    fn every_refusal_is_answered_with_error_one() {
        for why in [
            SubscribeError::Missing(SubscribeBodyKey::Ack(AckKey::Gap)),
            SubscribeError::Duplicate(SubscribeBodyKey::Request(SubscribeKey::FromSeq)),
            SubscribeError::ZeroIsNotAPosition,
            SubscribeError::OldestPastNewest,
            SubscribeError::LogAtTheCeiling,
            SubscribeError::Cbor(CborError::WrongType),
        ] {
            assert_eq!(why.refusal().code(), 1, "{why}");
        }
    }

    /// Every refusal renders as its own sentence.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [SubscribeError; 6] = [
            SubscribeError::Missing(SubscribeBodyKey::Ack(AckKey::Gap)),
            SubscribeError::Duplicate(SubscribeBodyKey::Request(SubscribeKey::FromSeq)),
            SubscribeError::ZeroIsNotAPosition,
            SubscribeError::OldestPastNewest,
            SubscribeError::LogAtTheCeiling,
            SubscribeError::Cbor(CborError::WrongType),
        ];
        Rendering::<96>::each_says_something_of_its_own(&EVERY);
    }

    /// A `Subscribe` cut at any byte is refused, never read as a shorter
    /// request. A resynchronising receiver hands the decoder arbitrary prefixes.
    #[test]
    fn a_subscribe_cut_short_at_any_byte_is_refused() {
        let mut dst = [0u8; 32];
        let len = Subscribe {
            replay: Replay::From(LogSeq(41)),
        }
        .encode(&mut dst)
        .expect("it encodes");
        for cut in 0..len {
            assert!(
                Subscribe::decode(dst.get(..cut).expect("a prefix")).is_err(),
                "a prefix of {cut} bytes decoded"
            );
        }
        assert!(Subscribe::decode(dst.get(..len).expect("the body")).is_ok());
    }
}
