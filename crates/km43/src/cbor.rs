//! The restricted CBOR this protocol speaks, over buffers the caller owns.
//!
//! Most of what is here is refusal, and that is the point. Indefinite lengths,
//! tags, floats and every simple value except `true` and `false` mean nothing on
//! this wire (P-018), so accepting one would be reading bytes no encoder on the
//! other side ever meant to send. Map keys are integers (P-011), and a key this
//! version has never heard of is skipped rather than refused (P-013), which is
//! what lets a controller survive a newer client being chatty.
//!
//! The reader is handed hostile bytes — whatever arrived between two delimiters
//! and happened to pass a CRC. It never indexes, never recurses, and every step
//! consumes at least one byte, so any input at all ends in a value or a named
//! refusal. Nesting is counted against [`MAX_DEPTH`] on an explicit stack rather
//! than on the call stack: there is no stack guard on this part, so a body four
//! hundred containers deep has to be a refusal rather than a reset.
//!
//! Duplicate keys (P-015) are not decided here. This layer hands the keys over
//! in the order they arrived; only a body decoder knows which numbers it
//! recognises and which it has already seen.
//!
//! cites: P-010, P-011, P-013, P-015, P-016, P-018

use crate::limits::{MAX_DEPTH, MAX_STRING};
use core::fmt;

/// One slot per container a message can be inside. One more than this is
/// refused with [`CborError::DepthExceeded`]; nothing is evicted, nothing grows.
const NESTING: usize = MAX_DEPTH as usize;

/// Why a CBOR item was refused. Every variant means the message stops here —
/// there is no partial read and no repair, because a body that is not exactly
/// what this protocol describes is a body whose meaning is not knowable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborError {
    /// The item runs past the bytes there are, which is what a truncated frame
    /// looks like from the inside.
    EndOfInput,
    /// Bytes left over after the top-level item. One implementation reading a
    /// field a second one never sees, inside a frame both authenticated, starts
    /// here.
    TrailingBytes,
    /// A second top-level item, which a message is never allowed to be.
    TrailingItem,
    /// A container still owes items — the header promised more than arrived, or
    /// more than the writer went on to write.
    Unfinished,
    /// An indefinite-length item, or the break byte that would end one.
    IndefiniteLength,
    /// A tag. Nothing in this protocol wears one.
    TagNotAllowed,
    /// A float (P-018). There is no FPU to read one with, and two languages
    /// rounding the same float differently is a defect nobody sees in a dump.
    FloatNotAllowed,
    /// `null`, `undefined`, or any other simple value that is not `true` or
    /// `false`. A missing reading is an absent key, never a null.
    SimpleValueNotAllowed,
    /// Additional information 28, 29 or 30, which RFC 8949 leaves ill-formed.
    ReservedHead,
    /// A map key that is not an integer (P-011).
    KeyNotInteger,
    /// A key written where a value belongs, or a value where a map's key does.
    MisplacedKey,
    /// Map keys that do not strictly ascend (P-016), which is also how the
    /// writer catches the same key written twice.
    KeysNotAscending,
    /// More nested containers than [`MAX_DEPTH`].
    DepthExceeded,
    /// A text string longer than [`MAX_STRING`].
    StringTooLong,
    /// A text string that is not UTF-8.
    InvalidUtf8,
    /// A well-formed item of a type this field does not carry.
    WrongType,
    /// An integer outside the range of the field reading it.
    IntegerOutOfRange,
    /// The destination cannot hold the item, and nothing was written.
    DestinationTooSmall,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let said = match self {
            Self::EndOfInput => "CBOR item runs past the end of the input",
            Self::TrailingBytes => "bytes left over after the CBOR item",
            Self::TrailingItem => "a second top-level CBOR item",
            Self::Unfinished => "a CBOR container still owes items",
            Self::IndefiniteLength => "indefinite-length CBOR item",
            Self::TagNotAllowed => "CBOR tag",
            Self::FloatNotAllowed => "floating point on the wire",
            Self::SimpleValueNotAllowed => "CBOR simple value other than true or false",
            Self::ReservedHead => "reserved CBOR additional information",
            Self::KeyNotInteger => "map key is not an integer",
            Self::MisplacedKey => "map key where a value belongs, or the reverse",
            Self::KeysNotAscending => "map keys do not strictly ascend",
            Self::DepthExceeded => "nested past the depth limit",
            Self::StringTooLong => "text string longer than the limit",
            Self::InvalidUtf8 => "text string is not UTF-8",
            Self::WrongType => "CBOR item is not the type this field carries",
            Self::IntegerOutOfRange => "integer outside the range of its field",
            Self::DestinationTooSmall => "destination buffer too small",
        };
        f.write_str(said)
    }
}

impl core::error::Error for CborError {}

const_assert!(
    size_of::<CborError>() == 1,
    "a refusal comes back from every parse on a part with 144 KB of RAM, so one that grew past a byte would be paid for on every frame"
);

/// CBOR's three-bit major type. The two this protocol never carries are variants
/// rather than a fallthrough, so the match that refuses them cannot forget one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Major {
    Unsigned,
    Negative,
    Bytes,
    Text,
    Array,
    Map,
    Tag,
    Simple,
}

impl Major {
    const fn bits(self) -> u8 {
        match self {
            Self::Unsigned => 0,
            Self::Negative => 1,
            Self::Bytes => 2,
            Self::Text => 3,
            Self::Array => 4,
            Self::Map => 5,
            Self::Tag => 6,
            Self::Simple => 7,
        }
    }

    const fn of(byte: u8) -> Self {
        match byte >> 5 {
            0 => Self::Unsigned,
            1 => Self::Negative,
            2 => Self::Bytes,
            3 => Self::Text,
            4 => Self::Array,
            5 => Self::Map,
            6 => Self::Tag,
            // Shifting a byte right by five leaves nothing above seven.
            7.. => Self::Simple,
        }
    }
}

/// How many bytes of argument follow the head byte. Which one a value gets *is*
/// shortest form, and picking the wrong one at 23/24 or 65535/65536 is the
/// classic CBOR defect: invisible to a round trip, loud to any other decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    Inline,
    One,
    Two,
    Four,
    Eight,
}

impl Width {
    const fn of(argument: u64) -> Self {
        if argument < 24 {
            Self::Inline
        } else if argument <= 0xFF {
            Self::One
        } else if argument <= 0xFFFF {
            Self::Two
        } else if argument <= 0xFFFF_FFFF {
            Self::Four
        } else {
            Self::Eight
        }
    }

    const fn bytes(self) -> usize {
        match self {
            Self::Inline => 0,
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    /// The low five bits of the head byte. `low` is the argument's own least
    /// significant byte, which is the whole argument when it fits inline.
    const fn info(self, low: u8) -> u8 {
        match self {
            Self::Inline => low,
            Self::One => 24,
            Self::Two => 25,
            Self::Four => 26,
            Self::Eight => 27,
        }
    }
}

/// One item's head: what it is, and — for the two that borrow — the bytes
/// themselves, so that after reading a head the position is at an item boundary
/// rather than halfway through a string somebody still has to remember to skip.
#[derive(Debug, Clone, Copy)]
enum Head<'a> {
    Unsigned(u64),
    /// The argument `n` of a negative integer, which encodes `-1 - n`.
    Negative(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(usize),
    Map(usize),
    Bool(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nesting {
    Array,
    Map,
}

/// One open container and what it still owes. A map counts its keys and its
/// values separately, which is what makes an even count a key position.
#[derive(Debug, Clone, Copy)]
struct Open {
    kind: Nesting,
    remaining: usize,
    /// The last key written into this map, so the next can be required to exceed
    /// it. Absent until a key is written — never a zero standing in for one.
    last_key: Option<u64>,
}

/// The containers a message is currently inside. Reader and writer ask it the
/// same three questions — is this a key position, is the innermost container
/// finished, is there room for one more — so the arithmetic exists once.
#[derive(Debug, Clone, Copy)]
struct Nest {
    open: [Open; NESTING],
    depth: usize,
}

impl Nest {
    const EMPTY: Open = Open {
        kind: Nesting::Array,
        remaining: 0,
        last_key: None,
    };

    const fn new() -> Self {
        Self {
            open: [Self::EMPTY; NESTING],
            depth: 0,
        }
    }

    fn innermost(&self) -> Option<&Open> {
        self.open.get(self.depth.checked_sub(1)?)
    }

    /// Close every container that owes nothing. Called before an item rather
    /// than after one, so a chain of containers each holding a single container
    /// still counts as the nesting it is instead of collapsing to one level.
    fn settle(&mut self) {
        while let Some(top) = self.innermost() {
            if top.remaining != 0 {
                return;
            }
            self.depth = self.depth.saturating_sub(1);
        }
    }

    fn at_key(&self) -> bool {
        match self.innermost() {
            Some(top) => matches!(top.kind, Nesting::Map) && top.remaining % 2 == 0,
            None => false,
        }
    }

    fn count_item(&mut self) -> Result<(), CborError> {
        let Some(index) = self.depth.checked_sub(1) else {
            return Ok(());
        };
        // The index is below `depth`, which never exceeds the stack. Refusing
        // rather than carrying on keeps that an assumption somebody can check
        // instead of one the accounting quietly depends on.
        let top = self.open.get_mut(index).ok_or(CborError::DepthExceeded)?;
        top.remaining = top.remaining.saturating_sub(1);
        Ok(())
    }

    /// Whether another level would fit. Asked before a container's head byte is
    /// written, because `push` refusing afterwards leaves that byte behind.
    fn has_room(&self) -> bool {
        self.depth < self.open.len()
    }

    fn push(&mut self, kind: Nesting, items: usize) -> Result<(), CborError> {
        let slot = self
            .open
            .get_mut(self.depth)
            .ok_or(CborError::DepthExceeded)?;
        *slot = Open {
            kind,
            remaining: items,
            last_key: None,
        };
        self.depth = self.depth.saturating_add(1);
        Ok(())
    }

    /// Record a key and refuse one that does not exceed the last, which catches
    /// an unsorted map (P-016) and a repeated key with the same comparison.
    fn take_key(&mut self, key: u64) -> Result<(), CborError> {
        let index = self.depth.checked_sub(1).ok_or(CborError::MisplacedKey)?;
        let top = self.open.get_mut(index).ok_or(CborError::DepthExceeded)?;
        if let Some(last) = top.last_key
            && key <= last
        {
            return Err(CborError::KeysNotAscending);
        }
        top.last_key = Some(key);
        Ok(())
    }
}

/// Read the two simple values this protocol carries and refuse the rest. Free
/// rather than a method because it decides on one byte and touches no state.
fn simple<'a>(info: u8) -> Result<Head<'a>, CborError> {
    match info {
        20 => Ok(Head::Bool(false)),
        21 => Ok(Head::Bool(true)),
        25..=27 => Err(CborError::FloatNotAllowed),
        28..=30 => Err(CborError::ReservedHead),
        31.. => Err(CborError::IndefiniteLength),
        0..=19 | 22..=24 => Err(CborError::SimpleValueNotAllowed),
    }
}

/// Reads one message out of bytes that may be anything at all.
///
/// Every method returns a value or a named refusal; nothing here panics and
/// nothing indexes. A refusal ends the message — there is no resuming a parse
/// that has already read something it could not make sense of.
#[derive(Debug)]
pub struct CborReader<'a> {
    bytes: &'a [u8],
    next: usize,
    nest: Nest,
}

impl<'a> CborReader<'a> {
    /// A reader over one message: an envelope lifted out of a frame, or a
    /// `payload` byte string lifted out of an authenticated wrapper.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            next: 0,
            nest: Nest::new(),
        }
    }

    /// The element count of an array; the elements follow, and the reader counts
    /// them down as they are read.
    pub fn array(&mut self) -> Result<usize, CborError> {
        match self.head()? {
            Head::Array(count) => Ok(count),
            Head::Unsigned(_)
            | Head::Negative(_)
            | Head::Bytes(_)
            | Head::Text(_)
            | Head::Map(_)
            | Head::Bool(_) => Err(CborError::WrongType),
        }
    }

    /// The pair count of a map. Read each pair as a [`CborReader::key`] and then
    /// its value, or [`CborReader::skip`] the value of a key you do not know.
    pub fn map(&mut self) -> Result<usize, CborError> {
        match self.head()? {
            Head::Map(pairs) => Ok(pairs),
            Head::Unsigned(_)
            | Head::Negative(_)
            | Head::Bytes(_)
            | Head::Text(_)
            | Head::Array(_)
            | Head::Bool(_) => Err(CborError::WrongType),
        }
    }

    /// A map key, which P-011 says is an integer and nothing else. A negative
    /// key is read rather than refused so an unknown one can still be skipped.
    pub fn key(&mut self) -> Result<i64, CborError> {
        match self.head()? {
            Head::Unsigned(value) => i64::try_from(value).map_err(|_| CborError::IntegerOutOfRange),
            Head::Negative(argument) => Self::negative(argument),
            Head::Bytes(_) | Head::Text(_) | Head::Array(_) | Head::Map(_) | Head::Bool(_) => {
                Err(CborError::KeyNotInteger)
            }
        }
    }

    /// An unsigned integer. A negative one is out of range rather than the wrong
    /// type: the field is an integer field, the value just cannot live in it.
    pub fn u64(&mut self) -> Result<u64, CborError> {
        self.unsigned()
    }

    /// An unsigned integer that has to fit a `u32`, which `req_id` is (P-022).
    pub fn u32(&mut self) -> Result<u32, CborError> {
        u32::try_from(self.unsigned()?).map_err(|_| CborError::IntegerOutOfRange)
    }

    /// An unsigned integer that has to fit a `u16`, such as a `session_id`.
    pub fn u16(&mut self) -> Result<u16, CborError> {
        u16::try_from(self.unsigned()?).map_err(|_| CborError::IntegerOutOfRange)
    }

    /// An unsigned integer that has to fit a `u8`, such as an envelope `type`.
    pub fn u8(&mut self) -> Result<u8, CborError> {
        u8::try_from(self.unsigned()?).map_err(|_| CborError::IntegerOutOfRange)
    }

    /// A signed integer no wider than `i32`, which is what P-185 bounds every
    /// value position on this wire to, so that a full body still fits a payload.
    pub fn i32(&mut self) -> Result<i32, CborError> {
        match self.head()? {
            Head::Unsigned(value) => i32::try_from(value).map_err(|_| CborError::IntegerOutOfRange),
            Head::Negative(argument) => {
                i32::try_from(Self::negative(argument)?).map_err(|_| CborError::IntegerOutOfRange)
            }
            Head::Bytes(_) | Head::Text(_) | Head::Array(_) | Head::Map(_) | Head::Bool(_) => {
                Err(CborError::WrongType)
            }
        }
    }

    /// `true` or `false`. Nothing else in major type 7 gets this far.
    pub fn bool(&mut self) -> Result<bool, CborError> {
        match self.head()? {
            Head::Bool(value) => Ok(value),
            Head::Unsigned(_)
            | Head::Negative(_)
            | Head::Bytes(_)
            | Head::Text(_)
            | Head::Array(_)
            | Head::Map(_) => Err(CborError::WrongType),
        }
    }

    /// A byte string, borrowed out of the input rather than copied. Not bounded
    /// by [`MAX_STRING`]: the wrapper's `payload` is one of these and it is most
    /// of a frame.
    pub fn bytes(&mut self) -> Result<&'a [u8], CborError> {
        match self.head()? {
            Head::Bytes(raw) => Ok(raw),
            Head::Unsigned(_)
            | Head::Negative(_)
            | Head::Text(_)
            | Head::Array(_)
            | Head::Map(_)
            | Head::Bool(_) => Err(CborError::WrongType),
        }
    }

    /// A UTF-8 string, borrowed out of the input. Longer than [`MAX_STRING`] is
    /// refused rather than truncated, because a truncated string is a different
    /// string.
    pub fn text(&mut self) -> Result<&'a str, CborError> {
        match self.head()? {
            Head::Text(text) => Ok(text),
            Head::Unsigned(_)
            | Head::Negative(_)
            | Head::Bytes(_)
            | Head::Array(_)
            | Head::Map(_)
            | Head::Bool(_) => Err(CborError::WrongType),
        }
    }

    /// Consume one item of any type without interpreting it, which is what P-013
    /// needs to survive a newer sender's extra keys. Containers are walked on the
    /// nesting stack, so a deep one is [`CborError::DepthExceeded`] rather than a
    /// walk off the end of the call stack.
    pub fn skip(&mut self) -> Result<(), CborError> {
        self.nest.settle();
        let floor = self.nest.depth;
        self.head()?;
        loop {
            self.nest.settle();
            if self.nest.depth <= floor {
                return Ok(());
            }
            self.head()?;
        }
    }

    /// The next item's own bytes, verbatim, with the reader left past it.
    ///
    /// For a value whose schema this version does not have: `Event 0x04` key 4
    /// is a map whose contents are deferred per kind, and a decoder that read
    /// inside it would be inventing the schema it is waiting for. Walking the
    /// item still proves it is well formed — this hands over bytes it could
    /// parse, not bytes nobody looked at.
    pub fn raw(&mut self) -> Result<&'a [u8], CborError> {
        let from = self.next;
        self.skip()?;
        self.bytes.get(from..self.next).ok_or(CborError::EndOfInput)
    }

    /// Refuse a message that stopped inside a container or that has bytes left
    /// over. Both are how two implementations come to read one authenticated
    /// frame differently.
    pub fn finish(mut self) -> Result<(), CborError> {
        self.nest.settle();
        if self.nest.depth != 0 {
            return Err(CborError::Unfinished);
        }
        if self.next < self.bytes.len() {
            return Err(CborError::TrailingBytes);
        }
        Ok(())
    }

    fn negative(argument: u64) -> Result<i64, CborError> {
        // `try_from` is the refusal that fires. It bounds the argument at
        // `i64::MAX`, whose `-1 - n` is exactly `i64::MIN`, so the `checked_sub`
        // below can never return `None` — it is here because the house rule
        // forbids a bare subtraction, not because it is a second check.
        let argument = i64::try_from(argument).map_err(|_| CborError::IntegerOutOfRange)?;
        (-1i64)
            .checked_sub(argument)
            .ok_or(CborError::IntegerOutOfRange)
    }

    fn unsigned(&mut self) -> Result<u64, CborError> {
        match self.head()? {
            Head::Unsigned(value) => Ok(value),
            Head::Negative(_) => Err(CborError::IntegerOutOfRange),
            Head::Bytes(_) | Head::Text(_) | Head::Array(_) | Head::Map(_) | Head::Bool(_) => {
                Err(CborError::WrongType)
            }
        }
    }

    /// Read one item's head, refuse a non-integer where a map key belongs, and
    /// account for the item in the container that owes it.
    fn head(&mut self) -> Result<Head<'a>, CborError> {
        self.nest.settle();
        let at_key = self.nest.at_key();
        let first = *self.bytes.get(self.next).ok_or(CborError::EndOfInput)?;
        self.next = self.next.saturating_add(1);
        let head = self.decode(first)?;
        if at_key {
            match head {
                Head::Unsigned(_) | Head::Negative(_) => {}
                Head::Bytes(_) | Head::Text(_) | Head::Array(_) | Head::Map(_) | Head::Bool(_) => {
                    return Err(CborError::KeyNotInteger);
                }
            }
        }
        self.nest.count_item()?;
        match head {
            Head::Array(count) => self.nest.push(Nesting::Array, count)?,
            Head::Map(pairs) => {
                let items = pairs.checked_mul(2).ok_or(CborError::EndOfInput)?;
                self.nest.push(Nesting::Map, items)?;
            }
            Head::Unsigned(_)
            | Head::Negative(_)
            | Head::Bytes(_)
            | Head::Text(_)
            | Head::Bool(_) => {}
        }
        Ok(head)
    }

    fn decode(&mut self, first: u8) -> Result<Head<'a>, CborError> {
        let info = first & 0x1F;
        match Major::of(first) {
            Major::Unsigned => Ok(Head::Unsigned(self.argument(info)?)),
            Major::Negative => Ok(Head::Negative(self.argument(info)?)),
            Major::Bytes => {
                let len = self.length(info)?;
                Ok(Head::Bytes(self.take(len)?))
            }
            Major::Text => {
                let len = self.length(info)?;
                if len > MAX_STRING {
                    return Err(CborError::StringTooLong);
                }
                let raw = self.take(len)?;
                core::str::from_utf8(raw)
                    .map(Head::Text)
                    .map_err(|_| CborError::InvalidUtf8)
            }
            Major::Array => Ok(Head::Array(self.count(info, 1)?)),
            Major::Map => Ok(Head::Map(self.count(info, 2)?)),
            Major::Tag => Err(CborError::TagNotAllowed),
            Major::Simple => simple(info),
        }
    }

    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        let width = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            28..=30 => return Err(CborError::ReservedHead),
            31.. => return Err(CborError::IndefiniteLength),
        };
        let mut value = 0u64;
        for &byte in self.take(width)? {
            value = (value << 8) | u64::from(byte);
        }
        Ok(value)
    }

    fn length(&mut self, info: u8) -> Result<usize, CborError> {
        usize::try_from(self.argument(info)?).map_err(|_| CborError::EndOfInput)
    }

    /// A container's item count, refused if the input could not hold that many
    /// items even at one byte each. That check is also what stops a map's pair
    /// count from overflowing when it is doubled.
    fn count(&mut self, info: u8, per_item: usize) -> Result<usize, CborError> {
        let count = self.length(info)?;
        let items = count.checked_mul(per_item).ok_or(CborError::EndOfInput)?;
        if items > self.bytes.len().saturating_sub(self.next) {
            return Err(CborError::EndOfInput);
        }
        Ok(count)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CborError> {
        let all = self.bytes;
        let start = self.next;
        let end = start.checked_add(len).ok_or(CborError::EndOfInput)?;
        let slice = all.get(start..end).ok_or(CborError::EndOfInput)?;
        self.next = end;
        Ok(slice)
    }
}

/// Writes RFC 8949 §4.2 deterministic CBOR into a buffer the caller owns.
///
/// Shortest-form integers and ascending map keys are enforced rather than
/// intended: a key that does not exceed the last one is refused, which is also
/// how a key written twice is caught. P-017 says authentication must not depend
/// on any of this, and it does not — determinism here is for the person reading
/// a hex dump.
#[derive(Debug)]
pub struct CborWriter<'a> {
    dst: &'a mut [u8],
    next: usize,
    nest: Nest,
}

impl<'a> CborWriter<'a> {
    /// A writer over a buffer the caller sized. A buffer one byte short is
    /// refused, never truncated: a short encoding still parses at the far end,
    /// so it arrives looking like a well-formed message carrying other fields.
    #[must_use]
    pub fn new(dst: &'a mut [u8]) -> Self {
        Self {
            dst,
            next: 0,
            nest: Nest::new(),
        }
    }

    /// Open an array of exactly `len` items. [`CborWriter::finish`] refuses if
    /// fewer arrive, because a header promising four and delivering three is a
    /// frame the far end drops.
    pub fn array(&mut self, len: usize) -> Result<(), CborError> {
        self.open_item()?;
        // Before the head byte. Asked after it, the refusal leaves a stray byte
        // in a buffer the caller was told was untouched — and the caller has no
        // way to know how much to rewind.
        if !self.nest.has_room() {
            return Err(CborError::DepthExceeded);
        }
        self.head(Major::Array, Self::argument(len)?, 0)?;
        self.nest.count_item()?;
        self.nest.push(Nesting::Array, len)
    }

    /// Open a map of exactly `pairs` key-value pairs. Every key goes through
    /// [`CborWriter::key`], which is what enforces the ordering.
    pub fn map(&mut self, pairs: usize) -> Result<(), CborError> {
        self.open_item()?;
        if !self.nest.has_room() {
            return Err(CborError::DepthExceeded);
        }
        self.head(Major::Map, Self::argument(pairs)?, 0)?;
        self.nest.count_item()?;
        let items = pairs.checked_mul(2).ok_or(CborError::DestinationTooSmall)?;
        self.nest.push(Nesting::Map, items)
    }

    /// A map key, which must exceed the previous key of the same map (P-016).
    /// Calling it where a value belongs is [`CborError::MisplacedKey`].
    ///
    /// `i64` rather than `u64` so the two halves share a domain: the reader
    /// hands keys back as `i64`, and a writer willing to emit `0x1b ff…` builds
    /// a body its own reader refuses with `IntegerOutOfRange`.
    pub fn key(&mut self, key: i64) -> Result<(), CborError> {
        let key = u64::try_from(key).map_err(|_| CborError::IntegerOutOfRange)?;
        self.nest.settle();
        if !self.nest.at_key() {
            return Err(CborError::MisplacedKey);
        }
        self.nest.take_key(key)?;
        self.head(Major::Unsigned, key, 0)?;
        self.nest.count_item()
    }

    /// An unsigned integer, in the shortest form that holds it.
    pub fn u64(&mut self, value: u64) -> Result<(), CborError> {
        self.open_item()?;
        self.head(Major::Unsigned, value, 0)?;
        self.nest.count_item()
    }

    /// A signed integer no wider than `i32` (P-185), in the shortest form that
    /// holds it.
    pub fn i32(&mut self, value: i32) -> Result<(), CborError> {
        self.open_item()?;
        let magnitude = u64::from(value.unsigned_abs());
        if value < 0 {
            // A negative integer encodes `-1 - value`, so the argument is the
            // magnitude less one — and taking the magnitude unsigned is what
            // keeps `i32::MIN` from overflowing on the way in.
            self.head(Major::Negative, magnitude.saturating_sub(1), 0)?;
        } else {
            self.head(Major::Unsigned, magnitude, 0)?;
        }
        self.nest.count_item()
    }

    /// `true` or `false`, the only two simple values on this wire.
    pub fn bool(&mut self, value: bool) -> Result<(), CborError> {
        self.open_item()?;
        self.head(Major::Simple, if value { 21 } else { 20 }, 0)?;
        self.nest.count_item()
    }

    /// A byte string. Not bounded by [`MAX_STRING`] — the wrapper's `payload` is
    /// one of these and it is most of a frame.
    pub fn bytes(&mut self, value: &[u8]) -> Result<(), CborError> {
        self.open_item()?;
        self.head(Major::Bytes, Self::argument(value.len())?, value.len())?;
        self.emit(value)?;
        self.nest.count_item()
    }

    /// A UTF-8 string. Longer than [`MAX_STRING`] is refused here rather than
    /// sent and refused there.
    pub fn text(&mut self, value: &str) -> Result<(), CborError> {
        self.open_item()?;
        let raw = value.as_bytes();
        if raw.len() > MAX_STRING {
            return Err(CborError::StringTooLong);
        }
        self.head(Major::Text, Self::argument(raw.len())?, raw.len())?;
        self.emit(raw)?;
        self.nest.count_item()
    }

    /// The encoded length, or a refusal if a container is still owed items.
    pub fn finish(mut self) -> Result<usize, CborError> {
        self.nest.settle();
        if self.nest.depth != 0 {
            return Err(CborError::Unfinished);
        }
        Ok(self.next)
    }

    fn argument(len: usize) -> Result<u64, CborError> {
        u64::try_from(len).map_err(|_| CborError::DestinationTooSmall)
    }

    /// What every non-key write does before its bytes: refuse a second top-level
    /// item, and refuse a value where a map's key belongs.
    /// One already-encoded item, copied in as it stands.
    ///
    /// The counterpart of [`CborReader::raw`], and the same argument: the caller
    /// holds a value this version has no schema for, so re-encoding it would be
    /// re-encoding a guess. `item` must be exactly one well-formed item — the
    /// writer counts it as one and does not look inside.
    pub fn raw(&mut self, item: &[u8]) -> Result<(), CborError> {
        self.open_item()?;
        let mut walk = CborReader::new(item);
        walk.skip()?;
        walk.finish()?;
        self.emit(item)?;
        self.nest.count_item()
    }

    fn open_item(&mut self) -> Result<(), CborError> {
        self.nest.settle();
        if self.nest.at_key() {
            return Err(CborError::MisplacedKey);
        }
        if self.nest.depth == 0 && self.next != 0 {
            return Err(CborError::TrailingItem);
        }
        Ok(())
    }

    /// The head byte and its argument in the shortest form that holds it. Room
    /// for `payload` bytes of string is checked here too, so an item that will
    /// not fit is refused before any of it is written.
    fn head(&mut self, major: Major, argument: u64, payload: usize) -> Result<(), CborError> {
        let width = Width::of(argument);
        let big_endian = argument.to_be_bytes();
        let [.., low] = big_endian;
        let from = big_endian
            .len()
            .checked_sub(width.bytes())
            .ok_or(CborError::DestinationTooSmall)?;
        let tail = big_endian
            .get(from..)
            .ok_or(CborError::DestinationTooSmall)?;
        let total = tail
            .len()
            .checked_add(1)
            .and_then(|head| head.checked_add(payload))
            .ok_or(CborError::DestinationTooSmall)?;
        self.ensure(total)?;
        self.emit(&[(major.bits() << 5) | width.info(low)])?;
        self.emit(tail)
    }

    fn ensure(&self, len: usize) -> Result<(), CborError> {
        let end = self
            .next
            .checked_add(len)
            .ok_or(CborError::DestinationTooSmall)?;
        if end > self.dst.len() {
            return Err(CborError::DestinationTooSmall);
        }
        Ok(())
    }

    fn emit(&mut self, data: &[u8]) -> Result<(), CborError> {
        let slot = self.reserve(data.len())?;
        for (out, &byte) in slot.iter_mut().zip(data) {
            *out = byte;
        }
        Ok(())
    }

    fn reserve(&mut self, len: usize) -> Result<&mut [u8], CborError> {
        let start = self.next;
        let end = start
            .checked_add(len)
            .ok_or(CborError::DestinationTooSmall)?;
        if end > self.dst.len() {
            return Err(CborError::DestinationTooSmall);
        }
        self.next = end;
        self.dst
            .get_mut(start..end)
            .ok_or(CborError::DestinationTooSmall)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Room for anything below, which is a frame at its widest plus the slack a
    /// deliberately oversized case needs.
    const SCRATCH: usize = 1400;

    /// `skip()` settles its containers before it takes its floor. Swapping those
    /// two lines leaves every other test green while `skip` silently
    /// under-consumes: after a typed read that closed a container, the floor is
    /// taken a level too high, `skip` returns at the item's header, and the
    /// caller reads that item's own contents as the next sibling.
    #[test]
    fn a_skip_after_a_read_that_closed_a_container_still_consumes_the_whole_item() {
        // [[1], [2], 3]
        let bytes = [0x83, 0x81, 0x01, 0x81, 0x02, 0x03];
        let mut reader = CborReader::new(&bytes);
        assert_eq!(reader.array(), Ok(3));
        assert_eq!(reader.array(), Ok(1));
        assert_eq!(reader.u64(), Ok(1));
        reader.skip().expect("the second element");
        assert_eq!(reader.u64(), Ok(3), "skip stopped at the array header");
        assert_eq!(reader.finish(), Ok(()));
    }

    /// An empty container costs no items and one level of nesting. Not counting
    /// that level makes the reader accept a body one deeper than the writer will
    /// build — two ends disagreeing about whether a frame they both
    /// authenticated is legal, which is the worst kind of disagreement to have.
    #[test]
    fn an_empty_container_at_the_bottom_is_still_a_level_of_nesting() {
        let limit = usize::from(MAX_DEPTH);
        let mut over = [0x81_u8; 64];
        let bottom = over
            .get_mut(limit)
            .expect("the fixture is wider than eight");
        *bottom = 0x80;
        let past = over
            .get(..limit.saturating_add(1))
            .expect("the fixture is wider than nine");
        assert_eq!(Whole::new(past).skipped(), Err(CborError::DepthExceeded));

        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        for _ in 0..limit {
            writer.array(1).expect("eight levels are allowed");
        }
        assert_eq!(writer.array(0), Err(CborError::DepthExceeded));
    }

    /// The argument of a negative integer is unsigned, so `0x3b ff…` means
    /// −2^64 and fits nothing we have. Folded to the floor rather than refused,
    /// a key nobody sent arrives as `i64::MIN` and a body decoder matches on it.
    #[test]
    fn a_negative_wider_than_an_i64_is_refused_rather_than_folded_to_the_floor() {
        let widest = [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            CborReader::new(&widest).key(),
            Err(CborError::IntegerOutOfRange)
        );
        let over = [0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            CborReader::new(&over).key(),
            Err(CborError::IntegerOutOfRange)
        );
        // The last argument that does fit is exactly i64::MIN.
        let edge = [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(CborReader::new(&edge).key(), Ok(i64::MIN));
    }

    /// A refused container must leave the destination as it found it. The depth
    /// check used to sit after the head byte, so a ninth `array(1)` returned
    /// `DepthExceeded` having already written `0x81` into the caller's buffer —
    /// which the doc above promises it does not, and which no caller can rewind.
    #[test]
    fn a_container_refused_for_depth_writes_no_byte_at_all() {
        let mut buf = [0xAA_u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        for _ in 0..usize::from(MAX_DEPTH) {
            writer.array(1).expect("eight levels are allowed");
        }
        assert_eq!(writer.array(1), Err(CborError::DepthExceeded));
        assert_eq!(writer.map(1), Err(CborError::DepthExceeded));
        let past = buf
            .get(usize::from(MAX_DEPTH)..)
            .expect("the fixture is wider than the depth cap");
        assert!(
            past.iter().all(|&b| b == 0xAA),
            "a refused container left a head byte behind"
        );
    }

    /// The writer must not build a key its own reader refuses. `key` took a
    /// `u64` while the reader hands keys back as `i64`, so anything at or above
    /// 2^63 encoded fine and came back `IntegerOutOfRange`.
    #[test]
    fn a_key_the_writer_accepts_is_one_the_reader_can_read_back() {
        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.map(1).expect("a one-pair map");
        writer.key(i64::MAX).expect("the widest legal key");
        writer.u64(1).expect("a value");
        let n = writer.finish().expect("the map is complete");
        let encoded = buf.get(..n).expect("the encoding fits");
        let mut reader = CborReader::new(encoded);
        assert_eq!(reader.map(), Ok(1));
        assert_eq!(reader.key(), Ok(i64::MAX));
    }

    /// One item a vector writes, so the tables below are data rather than code.
    #[derive(Debug, Clone, Copy)]
    enum Item<'a> {
        U(u64),
        I(i32),
        Bool(bool),
        Bytes(&'a [u8]),
        Text(&'a str),
        Array(usize),
        Map(usize),
        Key(i64),
    }

    impl Item<'_> {
        fn write(self, writer: &mut CborWriter<'_>) -> Result<(), CborError> {
            match self {
                Self::U(value) => writer.u64(value),
                Self::I(value) => writer.i32(value),
                Self::Bool(value) => writer.bool(value),
                Self::Bytes(value) => writer.bytes(value),
                Self::Text(value) => writer.text(value),
                Self::Array(len) => writer.array(len),
                Self::Map(pairs) => writer.map(pairs),
                Self::Key(key) => writer.key(key),
            }
        }

        /// Encode a whole vector, refusing anything left open.
        fn write_all(items: &[Self], dst: &mut [u8]) -> Result<usize, CborError> {
            let mut writer = CborWriter::new(dst);
            for item in items {
                item.write(&mut writer)?;
            }
            writer.finish()
        }

        /// The same, into a buffer wide enough for anything below.
        fn encode(items: &[Self]) -> ([u8; SCRATCH], usize) {
            let mut buf = [0u8; SCRATCH];
            let len = Self::write_all(items, &mut buf).expect("the vector must encode");
            (buf, len)
        }

        /// Assert a vector's exact bytes, which is the only claim worth making
        /// about an encoder.
        fn encodes_to(items: &[Self], want: &[u8]) {
            let (buf, len) = Self::encode(items);
            let got = buf.get(..len).expect("the length comes from the writer");
            assert_eq!(got, want, "encoding of {items:?}");
        }
    }

    /// Reads one complete message, so a vector asserts on the value *and* on
    /// there being nothing after it.
    struct Whole<'a> {
        reader: CborReader<'a>,
    }

    impl<'a> Whole<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self {
                reader: CborReader::new(bytes),
            }
        }

        fn u64(self) -> Result<u64, CborError> {
            let Self { mut reader } = self;
            let value = reader.u64()?;
            reader.finish()?;
            Ok(value)
        }

        fn i32(self) -> Result<i32, CborError> {
            let Self { mut reader } = self;
            let value = reader.i32()?;
            reader.finish()?;
            Ok(value)
        }

        fn bool(self) -> Result<bool, CborError> {
            let Self { mut reader } = self;
            let value = reader.bool()?;
            reader.finish()?;
            Ok(value)
        }

        fn bytes(self) -> Result<&'a [u8], CborError> {
            let Self { mut reader } = self;
            let value = reader.bytes()?;
            reader.finish()?;
            Ok(value)
        }

        fn text(self) -> Result<&'a str, CborError> {
            let Self { mut reader } = self;
            let value = reader.text()?;
            reader.finish()?;
            Ok(value)
        }

        /// Walk the whole message without interpreting it, which is the path a
        /// hostile body takes.
        fn skipped(self) -> Result<(), CborError> {
            let Self { mut reader } = self;
            reader.skip()?;
            reader.finish()
        }
    }

    /// A fixed-seed xorshift, so a failure below reproduces byte for byte.
    struct Xorshift(u64);

    impl Xorshift {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn raw(&mut self) -> u64 {
            let mut state = self.0;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            self.0 = state;
            state
        }

        fn byte(&mut self) -> u8 {
            let [low, ..] = self.raw().to_le_bytes();
            low
        }

        /// Half structural bytes, half noise. Heads that open containers are
        /// where the interesting paths are, and pure noise almost never lands on
        /// one.
        fn fill(&mut self, buf: &mut [u8], palette: &[u8]) {
            for slot in buf.iter_mut() {
                let raw = self.byte();
                *slot = if raw.is_multiple_of(2) {
                    let pick = usize::from(self.byte()) % palette.len();
                    *palette
                        .get(pick)
                        .expect("the index is taken modulo the len")
                } else {
                    self.byte()
                };
            }
        }
    }

    /// RFC 8949 Appendix A, which is agreement with the world rather than with
    /// ourselves. A round trip passes just as happily when both ends are wrong in
    /// the same direction, and that mistake has already been made in this crate.
    #[test]
    fn the_rfc_8949_appendix_a_encodings_are_the_bytes_this_writer_emits() {
        // The head-width boundary, which a round trip cannot see: an encoder and
        // a decoder that both put 24 in the low five bits agree with each other
        // and with nobody else.
        Item::encodes_to(
            &[Item::Text("abcdefghijklmnopqrstuvw")],
            &[
                0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
                0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
            ],
        );
        Item::encodes_to(
            &[Item::Text("abcdefghijklmnopqrstuvwx")],
            &[
                0x78, 0x18, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
                0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
            ],
        );
        // Appendix A's UTF-8 rows. A label is UTF-8 and somebody will name a
        // room with an accent in it; a length that counts characters rather than
        // bytes passes every ASCII case in this table and fails these three.
        Item::encodes_to(&[Item::Text("\u{fc}")], &[0x62, 0xc3, 0xbc]);
        Item::encodes_to(&[Item::Text("\u{6c34}")], &[0x63, 0xe6, 0xb0, 0xb4]);
        Item::encodes_to(&[Item::Text("\u{10151}")], &[0x64, 0xf0, 0x90, 0x85, 0x91]);
        Item::encodes_to(&[Item::U(0)], &[0x00]);
        Item::encodes_to(&[Item::U(1)], &[0x01]);
        Item::encodes_to(&[Item::U(10)], &[0x0a]);
        Item::encodes_to(&[Item::U(23)], &[0x17]);
        Item::encodes_to(&[Item::U(24)], &[0x18, 0x18]);
        Item::encodes_to(&[Item::U(25)], &[0x18, 0x19]);
        Item::encodes_to(&[Item::U(100)], &[0x18, 0x64]);
        Item::encodes_to(&[Item::U(1000)], &[0x19, 0x03, 0xe8]);
        Item::encodes_to(&[Item::U(1_000_000)], &[0x1a, 0x00, 0x0f, 0x42, 0x40]);
        Item::encodes_to(
            &[Item::U(u64::MAX)],
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
        Item::encodes_to(&[Item::I(-1)], &[0x20]);
        Item::encodes_to(&[Item::I(-10)], &[0x29]);
        Item::encodes_to(&[Item::I(-100)], &[0x38, 0x63]);
        Item::encodes_to(&[Item::Bytes(&[])], &[0x40]);
        Item::encodes_to(
            &[Item::Bytes(&[0x01, 0x02, 0x03, 0x04])],
            &[0x44, 0x01, 0x02, 0x03, 0x04],
        );
        Item::encodes_to(&[Item::Text("")], &[0x60]);
        Item::encodes_to(&[Item::Text("a")], &[0x61, 0x61]);
        Item::encodes_to(&[Item::Text("IETF")], &[0x64, 0x49, 0x45, 0x54, 0x46]);
        Item::encodes_to(&[Item::Array(0)], &[0x80]);
        Item::encodes_to(
            &[Item::Array(3), Item::U(1), Item::U(2), Item::U(3)],
            &[0x83, 0x01, 0x02, 0x03],
        );
        Item::encodes_to(&[Item::Map(0)], &[0xa0]);
        Item::encodes_to(
            &[
                Item::Map(2),
                Item::Key(1),
                Item::U(2),
                Item::Key(3),
                Item::U(4),
            ],
            &[0xa2, 0x01, 0x02, 0x03, 0x04],
        );
        Item::encodes_to(&[Item::Bool(false)], &[0xf4]);
        Item::encodes_to(&[Item::Bool(true)], &[0xf5]);
    }

    /// The other direction of the same table. An encoder and a decoder that
    /// agree with each other and not with the RFC is exactly what the vectors
    /// exist to catch, so both directions are checked against the table itself.
    #[test]
    fn the_rfc_8949_appendix_a_encodings_read_back_as_the_values_the_table_names() {
        let empty: &[u8] = &[];
        assert_eq!(Whole::new(&[0x00]).u64(), Ok(0));
        assert_eq!(Whole::new(&[0x01]).u64(), Ok(1));
        assert_eq!(Whole::new(&[0x0a]).u64(), Ok(10));
        assert_eq!(Whole::new(&[0x17]).u64(), Ok(23));
        assert_eq!(Whole::new(&[0x18, 0x18]).u64(), Ok(24));
        assert_eq!(Whole::new(&[0x18, 0x19]).u64(), Ok(25));
        assert_eq!(Whole::new(&[0x18, 0x64]).u64(), Ok(100));
        assert_eq!(Whole::new(&[0x19, 0x03, 0xe8]).u64(), Ok(1000));
        assert_eq!(
            Whole::new(&[0x1a, 0x00, 0x0f, 0x42, 0x40]).u64(),
            Ok(1_000_000)
        );
        assert_eq!(
            Whole::new(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).u64(),
            Ok(u64::MAX)
        );
        assert_eq!(Whole::new(&[0x20]).i32(), Ok(-1));
        assert_eq!(Whole::new(&[0x29]).i32(), Ok(-10));
        assert_eq!(Whole::new(&[0x38, 0x63]).i32(), Ok(-100));
        assert_eq!(Whole::new(&[0x40]).bytes(), Ok(empty));
        assert_eq!(
            Whole::new(&[0x44, 0x01, 0x02, 0x03, 0x04]).bytes(),
            Ok(&[0x01, 0x02, 0x03, 0x04][..])
        );
        assert_eq!(Whole::new(&[0x60]).text(), Ok(""));
        assert_eq!(Whole::new(&[0x61, 0x61]).text(), Ok("a"));
        assert_eq!(
            Whole::new(&[0x64, 0x49, 0x45, 0x54, 0x46]).text(),
            Ok("IETF")
        );
        assert_eq!(Whole::new(&[0x80]).skipped(), Ok(()));
        assert_eq!(Whole::new(&[0x83, 0x01, 0x02, 0x03]).skipped(), Ok(()));
        assert_eq!(Whole::new(&[0xa0]).skipped(), Ok(()));
        assert_eq!(
            Whole::new(&[0xa2, 0x01, 0x02, 0x03, 0x04]).skipped(),
            Ok(())
        );
        assert_eq!(Whole::new(&[0xf4]).bool(), Ok(false));
        assert_eq!(Whole::new(&[0xf5]).bool(), Ok(true));
    }

    /// The classic CBOR defect, and it is invisible to a round trip: an encoder
    /// that spends two bytes on 23, or eight on 65536, agrees with itself
    /// perfectly and with nothing else. Each pair below straddles a boundary.
    #[test]
    fn an_integer_takes_the_shortest_form_on_both_sides_of_every_boundary() {
        Item::encodes_to(&[Item::U(23)], &[0x17]);
        Item::encodes_to(&[Item::U(24)], &[0x18, 0x18]);
        Item::encodes_to(&[Item::U(255)], &[0x18, 0xff]);
        Item::encodes_to(&[Item::U(256)], &[0x19, 0x01, 0x00]);
        Item::encodes_to(&[Item::U(65_535)], &[0x19, 0xff, 0xff]);
        Item::encodes_to(&[Item::U(65_536)], &[0x1a, 0x00, 0x01, 0x00, 0x00]);
        Item::encodes_to(&[Item::U(4_294_967_295)], &[0x1a, 0xff, 0xff, 0xff, 0xff]);
        Item::encodes_to(
            &[Item::U(4_294_967_296)],
            &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
    }

    /// The same boundaries for a negative integer, whose argument is one less
    /// than its magnitude — so it changes width one step earlier than the
    /// tempting reading suggests, and -256 is still a two-byte encoding.
    #[test]
    fn a_negative_integer_changes_width_at_its_argument_not_its_magnitude() {
        Item::encodes_to(&[Item::I(-24)], &[0x37]);
        Item::encodes_to(&[Item::I(-25)], &[0x38, 0x18]);
        Item::encodes_to(&[Item::I(-256)], &[0x38, 0xff]);
        Item::encodes_to(&[Item::I(-257)], &[0x39, 0x01, 0x00]);
        Item::encodes_to(&[Item::I(i32::MIN)], &[0x3a, 0x7f, 0xff, 0xff, 0xff]);
        assert_eq!(
            Whole::new(&[0x3a, 0x7f, 0xff, 0xff, 0xff]).i32(),
            Ok(i32::MIN)
        );
    }

    /// One past `i32::MIN`. P-185 bounds every value position to `i32` so a full
    /// body fits a payload; a decoder that widened it silently would let a sender
    /// ask for the frame that gets built and then refused.
    #[test]
    fn an_integer_wider_than_its_field_is_refused_rather_than_wrapped() {
        assert_eq!(
            Whole::new(&[0x3a, 0x80, 0x00, 0x00, 0x00]).i32(),
            Err(CborError::IntegerOutOfRange)
        );
        assert_eq!(
            Whole::new(&[0x1a, 0x80, 0x00, 0x00, 0x00]).i32(),
            Err(CborError::IntegerOutOfRange)
        );
        let mut reader = CborReader::new(&[0x19, 0x01, 0x00]);
        assert_eq!(reader.u8(), Err(CborError::IntegerOutOfRange));
        let mut reader = CborReader::new(&[0x1a, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(reader.u16(), Err(CborError::IntegerOutOfRange));
        let mut reader = CborReader::new(&[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(reader.u32(), Err(CborError::IntegerOutOfRange));
        // A negative where an unsigned field is: an integer that is out of
        // range, rather than the wrong type — the distinction a caller acts on.
        let mut reader = CborReader::new(&[0x20]);
        assert_eq!(reader.u64(), Err(CborError::IntegerOutOfRange));
    }

    /// Indefinite lengths turn a bounded parse into an unbounded one: a receiver
    /// has nothing to size a buffer from until a break arrives that a hostile
    /// sender need never send.
    #[test]
    fn an_indefinite_length_item_is_refused_rather_than_reassembled() {
        for first in [0x5f_u8, 0x7f, 0x9f, 0xbf, 0xff, 0x1f, 0x3f] {
            let bytes = [first];
            assert_eq!(
                Whole::new(&bytes).skipped(),
                Err(CborError::IndefiniteLength),
                "head byte {first:#04x}"
            );
        }
    }

    /// A tag says "read the next item as something else", which is a decision
    /// this protocol never hands to the sender.
    #[test]
    fn a_tag_is_refused_because_nothing_here_wears_one() {
        assert_eq!(
            Whole::new(&[0xc0, 0x00]).skipped(),
            Err(CborError::TagNotAllowed)
        );
        assert_eq!(
            Whole::new(&[0xd8, 0x18, 0x41, 0x00]).skipped(),
            Err(CborError::TagNotAllowed)
        );
    }

    /// P-018: there is no FPU on this part, and two languages rounding the same
    /// float differently is a defect nobody can see in a hex dump. A decoder
    /// that accepted one is how a float would get onto this wire at all.
    #[test]
    fn a_float_never_reaches_a_behaviour() {
        assert_eq!(
            Whole::new(&[0xf9, 0x00, 0x00]).skipped(),
            Err(CborError::FloatNotAllowed)
        );
        assert_eq!(
            Whole::new(&[0xfa, 0x47, 0xc3, 0x50, 0x00]).skipped(),
            Err(CborError::FloatNotAllowed)
        );
        assert_eq!(
            Whole::new(&[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a]).skipped(),
            Err(CborError::FloatNotAllowed)
        );
    }

    /// An unknown state of charge is not 0 %, and the way it becomes 0 % is a
    /// decoder that reads `null` as a value at all. There is no null here.
    #[test]
    fn null_and_undefined_are_not_a_missing_reading() {
        for first in [0xf6_u8, 0xf7, 0xe0, 0xf0, 0xf8] {
            let bytes = [first];
            assert_eq!(
                Whole::new(&bytes).skipped(),
                Err(CborError::SimpleValueNotAllowed),
                "head byte {first:#04x}"
            );
        }
    }

    /// Additional information 28, 29 and 30 are ill-formed in RFC 8949. A
    /// decoder that guessed a width for one would read a field out of whatever
    /// bytes happened to follow it.
    #[test]
    fn a_reserved_head_is_refused_rather_than_guessed_at() {
        for first in [0x1c_u8, 0x1d, 0x1e, 0x5c, 0x9d, 0xbe, 0xfc, 0xfd, 0xfe] {
            let bytes = [first];
            assert_eq!(
                Whole::new(&bytes).skipped(),
                Err(CborError::ReservedHead),
                "head byte {first:#04x}"
            );
        }
    }

    /// P-011: a field number is a number. A text key is how a body definition
    /// stops being a fixed table and becomes a string comparison somebody has to
    /// keep in step across two languages.
    #[test]
    fn a_text_key_is_refused_because_a_field_number_is_not_a_word() {
        // {"a": 0}
        assert_eq!(
            Whole::new(&[0xa1, 0x61, 0x61, 0x00]).skipped(),
            Err(CborError::KeyNotInteger)
        );
        // {[]: 0} — a container key is refused by the same check.
        assert_eq!(
            Whole::new(&[0xa1, 0x80, 0x00]).skipped(),
            Err(CborError::KeyNotInteger)
        );
        // {true: 0}
        assert_eq!(
            Whole::new(&[0xa1, 0xf5, 0x00]).skipped(),
            Err(CborError::KeyNotInteger)
        );
        // The refusal survives being read rather than skipped, which is the path
        // a body decoder actually takes.
        let mut reader = CborReader::new(&[0xa1, 0x61, 0x61, 0x00]);
        assert_eq!(reader.map(), Ok(1));
        assert_eq!(reader.key(), Err(CborError::KeyNotInteger));
    }

    /// P-013: a v1 controller has to survive a v2 client being chatty. The
    /// failure this prevents is a site that stops answering the afternoon
    /// somebody ships a client that sends one extra field.
    #[test]
    fn an_unknown_key_is_skipped_rather_than_refusing_a_newer_sender() {
        let (buf, len) = Item::encode(&[
            Item::Map(3),
            Item::Key(1),
            Item::U(7),
            // The v2 sender's extra field, and it is a whole nested body.
            Item::Key(9),
            Item::Map(2),
            Item::Key(1),
            Item::Array(2),
            Item::Text("hello"),
            Item::Bytes(&[0xde, 0xad]),
            Item::Key(2),
            Item::Bool(true),
            Item::Key(11),
            Item::U(42),
        ]);
        let message = buf.get(..len).expect("the writer's own length");
        let mut reader = CborReader::new(message);
        assert_eq!(reader.map(), Ok(3));

        assert_eq!(reader.key(), Ok(1));
        assert_eq!(reader.u64(), Ok(7));

        assert_eq!(reader.key(), Ok(9));
        reader.skip().expect("an unknown key's value is skipped");

        assert_eq!(reader.key(), Ok(11));
        assert_eq!(reader.u64(), Ok(42));

        reader.finish().expect("the body ends exactly there");
    }

    /// The one place recursion would have lived. A body nested past
    /// [`MAX_DEPTH`] has to be a refusal rather than a reset: there is no stack
    /// guard on this part, so the fault would arrive as an unexplained reboot at
    /// a site four hours from a road.
    #[test]
    fn nesting_past_max_depth_is_refused_before_the_stack_runs_out() {
        let limit = usize::from(MAX_DEPTH);

        // Exactly at the limit, with a scalar at the bottom, is accepted.
        let mut deep = [0x81_u8; 64];
        let floor = deep
            .get_mut(limit)
            .expect("the fixture is wider than eight");
        *floor = 0x00;
        let at_limit = deep
            .get(..limit.saturating_add(1))
            .expect("the fixture is wider than eight");
        assert_eq!(Whole::new(at_limit).skipped(), Ok(()));

        // One deeper is refused, and refused while skipping — which is the path
        // a body nobody interprets takes.
        let mut deeper = [0x81_u8; 64];
        let floor = deeper
            .get_mut(limit.saturating_add(1))
            .expect("the fixture is wider than nine");
        *floor = 0x00;
        let past_limit = deeper
            .get(..limit.saturating_add(2))
            .expect("the fixture is wider than nine");
        assert_eq!(
            Whole::new(past_limit).skipped(),
            Err(CborError::DepthExceeded)
        );
    }

    /// Every container on the way down counts, even when each holds exactly one
    /// item. An accounting that closed a parent as soon as its last item started
    /// would collapse this chain to one level and let a body of any depth
    /// through — the whole limit, gone, with every other test still green.
    #[test]
    fn a_chain_of_single_item_containers_still_counts_as_nesting() {
        let mut deeper = [0xa1_u8; 64];
        let limit = usize::from(MAX_DEPTH);
        // {1: {1: ... }} nested one past the limit: a key, then the next map.
        let mut at = 0usize;
        for _ in 0..limit.saturating_add(1) {
            let head = deeper.get_mut(at).expect("the fixture is wide enough");
            *head = 0xa1;
            let key = deeper
                .get_mut(at.saturating_add(1))
                .expect("the fixture is wide enough");
            *key = 0x01;
            at = at.saturating_add(2);
        }
        let value = deeper.get_mut(at).expect("the fixture is wide enough");
        *value = 0x00;
        let past_limit = deeper.get(..=at).expect("the fixture is wide enough");
        assert_eq!(
            Whole::new(past_limit).skipped(),
            Err(CborError::DepthExceeded)
        );
    }

    /// The writer is held to the same depth, so a controller cannot build a body
    /// that its own decoder would refuse.
    #[test]
    fn the_writer_refuses_to_nest_deeper_than_it_could_read_back() {
        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        for _ in 0..usize::from(MAX_DEPTH) {
            writer.array(1).expect("eight levels are allowed");
        }
        assert_eq!(writer.array(1), Err(CborError::DepthExceeded));
    }

    /// A string truncated to fit is a different string, and one that arrives
    /// longer than the buffer sized for it is how a receiver is overrun. Both
    /// sides refuse at the same number.
    #[test]
    fn a_string_longer_than_max_string_is_refused_rather_than_truncated() {
        let long = [b'x'; 128];
        let at_limit = core::str::from_utf8(long.get(..MAX_STRING).expect("128 covers 64"))
            .expect("ASCII is UTF-8");
        let past_limit = core::str::from_utf8(
            long.get(..MAX_STRING.saturating_add(1))
                .expect("128 covers 65"),
        )
        .expect("ASCII is UTF-8");

        let (buf, len) = Item::encode(&[Item::Text(at_limit)]);
        let encoded = buf.get(..len).expect("the writer's own length");
        assert_eq!(Whole::new(encoded).text(), Ok(at_limit));

        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        assert_eq!(writer.text(past_limit), Err(CborError::StringTooLong));

        // And on the way in, where the bytes are hostile rather than ours: a
        // text header claiming 65 bytes, with the 65 bytes actually there.
        let mut arriving = [b'x'; 67];
        let head = arriving.get_mut(..2).expect("67 covers 2");
        for (slot, byte) in head.iter_mut().zip([0x78_u8, 65]) {
            *slot = byte;
        }
        assert_eq!(
            Whole::new(&arriving).skipped(),
            Err(CborError::StringTooLong),
            "a 65-byte text string must be refused on arrival"
        );
    }

    /// [`MAX_STRING`] bounds text, not bytes. The wrapper's `payload` is a byte
    /// string carrying most of a frame, so a byte string held to 64 would refuse
    /// every authenticated message on the wire.
    #[test]
    fn the_payload_byte_string_is_not_bounded_by_max_string() {
        let payload = [0xa5_u8; 900];
        let (buf, len) = Item::encode(&[Item::Bytes(&payload)]);
        let encoded = buf.get(..len).expect("the writer's own length");
        assert_eq!(Whole::new(encoded).bytes(), Ok(&payload[..]));
    }

    /// Every length, because an off-by-one in a length header bites at exactly
    /// one size and a spot check at 4 and at 100 walks straight past it.
    #[test]
    fn a_string_of_every_legal_length_survives_the_round_trip() {
        let source = [b'q'; MAX_STRING];
        for len in 0..=MAX_STRING {
            let text = core::str::from_utf8(source.get(..len).expect("len is inside the array"))
                .expect("ASCII is UTF-8");
            let (buf, encoded) = Item::encode(&[Item::Text(text)]);
            let message = buf.get(..encoded).expect("the writer's own length");
            assert_eq!(Whole::new(message).text(), Ok(text), "text of {len} bytes");
        }

        let raw = [0x5a_u8; 300];
        for len in 0..=raw.len() {
            let value = raw.get(..len).expect("len is inside the array");
            let (buf, encoded) = Item::encode(&[Item::Bytes(value)]);
            let message = buf.get(..encoded).expect("the writer's own length");
            assert_eq!(Whole::new(message).bytes(), Ok(value), "bytes of {len}");
        }
    }

    /// Text that is not UTF-8 is refused rather than carried, because a string
    /// nobody can decode is a field two implementations disagree about.
    #[test]
    fn a_text_string_that_is_not_utf8_is_refused() {
        assert_eq!(
            Whole::new(&[0x62, 0xff, 0xfe]).skipped(),
            Err(CborError::InvalidUtf8)
        );
        // A truncated multi-byte sequence is the same refusal.
        assert_eq!(
            Whole::new(&[0x62, 0xc3, 0x28]).skipped(),
            Err(CborError::InvalidUtf8)
        );
    }

    /// Every prefix of a valid message. A frame cut short by a link that dropped
    /// carrier must never read as a shorter valid message — it must be refused,
    /// at every single cut point.
    #[test]
    fn every_truncation_of_a_valid_message_is_refused() {
        let (buf, len) = Item::encode(&[
            Item::Array(4),
            Item::U(0x81),
            Item::U(1),
            Item::U(4_294_967_295),
            Item::Map(3),
            Item::Key(1),
            Item::Text("cabin"),
            Item::Key(2),
            Item::Bytes(&[0xde, 0xad, 0xbe, 0xef]),
            Item::Key(3),
            Item::Array(2),
            Item::I(-1000),
            Item::Bool(true),
        ]);
        let whole = buf.get(..len).expect("the writer's own length");
        Whole::new(whole)
            .skipped()
            .expect("the whole message parses");

        for cut in 0..len {
            let prefix = whole.get(..cut).expect("cut is below len");
            assert!(
                Whole::new(prefix).skipped().is_err(),
                "a message cut at {cut} of {len} bytes must be refused"
            );
        }
    }

    /// The reader is handed whatever survived a CRC, which is not the same as
    /// whatever an encoder meant. Every input has to end in a value or a named
    /// refusal, and every step has to consume a byte — the step count is what
    /// would catch a parse that stood still.
    #[test]
    fn no_byte_sequence_makes_the_reader_panic_or_stall() {
        // Heads that open containers, plus tag, break and float, so the noise
        // spends its time in the structural paths instead of reading integers.
        let palette = [
            0x00, 0x18, 0x1b, 0x1c, 0x1f, 0x40, 0x58, 0x5f, 0x60, 0x78, 0x7f, 0x80, 0x81, 0x82,
            0x9f, 0xa0, 0xa1, 0xa2, 0xbf, 0xc0, 0xd8, 0xf4, 0xf5, 0xf6, 0xf9, 0xfb, 0xff,
        ];
        let mut rng = Xorshift::new(0x2545_f491_4f6c_dd1d);
        let mut buf = [0u8; 24];
        for _ in 0..4096 {
            let len = usize::from(rng.byte()) % buf.len().saturating_add(1);
            rng.fill(&mut buf, &palette);
            let input = buf.get(..len).expect("len is bounded by the buffer");
            let mut reader = CborReader::new(input);
            let mut steps = 0usize;
            while reader.skip().is_ok() {
                steps = steps.saturating_add(1);
                assert!(
                    steps <= len,
                    "{steps} items out of {len} bytes: a step consumed nothing"
                );
            }
        }
    }

    /// The same noise through the typed accessors rather than `skip`, because a
    /// body decoder reaches for those and they take a different path through the
    /// head. Any of them may refuse; none of them may panic.
    #[test]
    fn no_byte_sequence_makes_a_typed_read_panic() {
        let palette = [
            0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0, 0x18, 0x1b, 0xff, 0x5f,
        ];
        let mut rng = Xorshift::new(0x9e37_79b9_7f4a_7c15);
        let mut buf = [0u8; 16];
        for _ in 0..2048 {
            let len = usize::from(rng.byte()) % buf.len().saturating_add(1);
            rng.fill(&mut buf, &palette);
            let input = buf.get(..len).expect("len is bounded by the buffer");
            let mut reader = CborReader::new(input);
            let _ = reader.array();
            let _ = reader.key();
            let _ = reader.u8();
            let _ = reader.i32();
            let _ = reader.text();
            let _ = reader.bytes();
            let _ = reader.bool();
            let _ = reader.map();
            let _ = reader.skip();
            let _ = reader.finish();
        }
    }

    /// A container header claiming more items than the frame could hold at one
    /// byte each is a truncated frame, and believing it is how a decoder spends
    /// the afternoon on a map of eighteen quintillion pairs.
    #[test]
    fn a_container_claiming_more_items_than_the_frame_holds_is_refused() {
        assert_eq!(
            Whole::new(&[0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).skipped(),
            Err(CborError::EndOfInput)
        );
        assert_eq!(
            Whole::new(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).skipped(),
            Err(CborError::EndOfInput)
        );
        // And a string header doing the same thing.
        assert_eq!(
            Whole::new(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).skipped(),
            Err(CborError::EndOfInput)
        );
        // An array of three with one byte left is refused as the truncation it
        // is, rather than as whatever that byte happens to be. Without the
        // check at the header this reports a float on the wire, and somebody
        // spends the morning looking for an encoder that never sent one.
        assert_eq!(
            Whole::new(&[0x83, 0xf9]).skipped(),
            Err(CborError::EndOfInput)
        );
    }

    /// Nothing at all is not an empty map and not a zero. It is the absence of a
    /// message, and it has to say so.
    #[test]
    fn an_empty_input_is_end_of_input_rather_than_a_zero() {
        assert_eq!(Whole::new(&[]).u64(), Err(CborError::EndOfInput));
        assert_eq!(Whole::new(&[]).skipped(), Err(CborError::EndOfInput));
        let mut reader = CborReader::new(&[]);
        assert_eq!(reader.map(), Err(CborError::EndOfInput));
    }

    /// Bytes after the item are how one implementation reads a field a second
    /// one never sees, inside a frame both of them authenticated.
    #[test]
    fn bytes_after_the_top_level_item_are_refused() {
        assert_eq!(
            Whole::new(&[0x00, 0x00]).u64(),
            Err(CborError::TrailingBytes)
        );
        assert_eq!(
            Whole::new(&[0x81, 0x01, 0xf5]).skipped(),
            Err(CborError::TrailingBytes)
        );
        // A message that stops inside its container is the other half.
        assert_eq!(
            Whole::new(&[0x82, 0x01]).skipped(),
            Err(CborError::EndOfInput)
        );
        let mut reader = CborReader::new(&[0x82, 0x01, 0x02]);
        assert_eq!(reader.array(), Ok(2));
        assert_eq!(reader.u64(), Ok(1));
        assert_eq!(reader.finish(), Err(CborError::Unfinished));
    }

    /// P-016 wants sorted keys and the writer is where that is decided. A key
    /// that repeats is caught by the same comparison, which is what P-015 needs:
    /// two libraries resolving a duplicate key differently read different bytes
    /// out of one authenticated message.
    #[test]
    fn a_map_written_with_unsorted_or_repeated_keys_is_refused() {
        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.map(2).expect("a map opens");
        writer.key(3).expect("the first key is free");
        writer.u64(0).expect("its value");
        assert_eq!(writer.key(1), Err(CborError::KeysNotAscending));

        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.map(2).expect("a map opens");
        writer.key(1).expect("the first key is free");
        writer.u64(0).expect("its value");
        assert_eq!(writer.key(1), Err(CborError::KeysNotAscending));

        // A nested map starts its own ordering rather than continuing the outer
        // one — otherwise key 1 inside would look like a repeat of key 1 out.
        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.map(1).expect("a map opens");
        writer.key(5).expect("the outer key");
        writer.map(1).expect("a nested map");
        writer.key(1).expect("the inner map's keys start again");
        writer.u64(0).expect("its value");
        assert_eq!(writer.finish(), Ok(5));
    }

    /// A header that promises four items and delivers three is a frame the far
    /// end drops, built by a controller that believed it had sent a snapshot.
    #[test]
    fn a_container_promised_more_items_than_it_got_is_refused_at_finish() {
        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.array(3).expect("an array opens");
        writer.u64(1).expect("one");
        writer.u64(2).expect("two");
        assert_eq!(writer.finish(), Err(CborError::Unfinished));

        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.map(2).expect("a map opens");
        writer.key(1).expect("a key");
        assert_eq!(writer.finish(), Err(CborError::Unfinished));
    }

    /// A key where a value belongs, or a value where a key belongs, is a caller
    /// bug that would otherwise leave a map whose keys are somebody's values.
    #[test]
    fn a_value_where_a_map_key_belongs_is_refused() {
        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.map(1).expect("a map opens");
        assert_eq!(writer.text("one"), Err(CborError::MisplacedKey));

        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.map(1).expect("a map opens");
        assert_eq!(writer.u64(1), Err(CborError::MisplacedKey));

        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.array(1).expect("an array opens");
        assert_eq!(writer.key(1), Err(CborError::MisplacedKey));

        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        assert_eq!(writer.key(1), Err(CborError::MisplacedKey));
    }

    /// One message per frame. A writer that appended a second top-level item
    /// would produce bytes whose tail every conforming reader throws away.
    #[test]
    fn a_second_top_level_item_is_refused() {
        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.u64(1).expect("the message");
        assert_eq!(writer.u64(2), Err(CborError::TrailingItem));

        let mut buf = [0u8; SCRATCH];
        let mut writer = CborWriter::new(&mut buf);
        writer.array(1).expect("an array opens");
        writer.u64(1).expect("its only item");
        assert_eq!(writer.bool(true), Err(CborError::TrailingItem));
    }

    /// A destination one byte short is refused rather than truncated, at every
    /// length: a short encoding still parses at the far end, so it arrives
    /// looking like a well-formed message carrying different fields.
    #[test]
    fn a_destination_one_byte_short_is_refused_rather_than_truncated() {
        let items = [
            Item::Array(3),
            Item::U(1_000_000),
            Item::Text("frost"),
            Item::Map(1),
            Item::Key(2),
            Item::Bytes(&[1, 2, 3, 4, 5]),
        ];
        let (_, full) = Item::encode(&items);
        for short in 0..full {
            let mut buf = [0u8; SCRATCH];
            let dst = buf.get_mut(..short).expect("short is below the buffer");
            assert_eq!(
                Item::write_all(&items, dst),
                Err(CborError::DestinationTooSmall),
                "a {short}-byte destination for a {full}-byte message"
            );
        }
        let mut buf = [0u8; SCRATCH];
        let dst = buf.get_mut(..full).expect("full is below the buffer");
        assert_eq!(Item::write_all(&items, dst), Ok(full));

        // And the refusal comes before a byte is written, not partway through
        // it: a head byte left in the buffer with no string behind it is half
        // an item a caller could still hand to the framer.
        let mut buf = [0xaa_u8; 3];
        let mut writer = CborWriter::new(&mut buf);
        assert_eq!(writer.text("abcd"), Err(CborError::DestinationTooSmall));
        assert_eq!(buf, [0xaa, 0xaa, 0xaa], "a refused item wrote something");
    }

    /// P-016 binds encoders, and P-017 says the MAC is over the bytes as
    /// received. So a long-form integer from a sloppy sender is read rather than
    /// refused — this test is here to make that a decision somebody took rather
    /// than one nobody noticed.
    #[test]
    fn a_long_form_integer_is_read_rather_than_refused() {
        assert_eq!(Whole::new(&[0x18, 0x17]).u64(), Ok(23));
        assert_eq!(Whole::new(&[0x19, 0x00, 0x00]).u64(), Ok(0));
        assert_eq!(Whole::new(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 1]).u64(), Ok(1));
    }

    /// The envelope of P-010 read element by element, which is the shape
    /// everything else on this wire is wrapped in. Eleven bytes of envelope is
    /// what the payload arithmetic in `limits.rs` spends, and this is where that
    /// number meets an encoder.
    #[test]
    fn an_envelope_reads_element_by_element_and_ends_where_it_says() {
        let (buf, len) = Item::encode(&[
            Item::Array(4),
            Item::U(0x81),
            Item::U(0x0102),
            Item::U(4_294_967_295),
            Item::Map(2),
            Item::Key(1),
            Item::U(12),
            Item::Key(13),
            Item::U(32),
        ]);
        let message = buf.get(..len).expect("the writer's own length");
        // 1 array header + 2 type + 3 session_id + 5 req_id = 11, then a body of
        // map header, two keys and their values.
        assert_eq!(len, 17, "eleven bytes of envelope and six of body");

        let mut reader = CborReader::new(message);
        assert_eq!(reader.array(), Ok(4));
        assert_eq!(reader.u8(), Ok(0x81));
        assert_eq!(reader.u16(), Ok(0x0102));
        assert_eq!(reader.u32(), Ok(4_294_967_295));
        assert_eq!(reader.map(), Ok(2));
        assert_eq!(reader.key(), Ok(1));
        assert_eq!(reader.u64(), Ok(12));
        assert_eq!(reader.key(), Ok(13));
        assert_eq!(reader.u64(), Ok(32));
        assert_eq!(reader.finish(), Ok(()));
    }

    /// A negative map key is read rather than refused, so a key this version has
    /// never heard of can still be skipped under P-013.
    #[test]
    fn a_negative_map_key_is_read_so_its_value_can_be_skipped() {
        // {-1: true, 1: 0}
        let bytes = [0xa2, 0x20, 0xf5, 0x01, 0x00];
        let mut reader = CborReader::new(&bytes);
        assert_eq!(reader.map(), Ok(2));
        assert_eq!(reader.key(), Ok(-1));
        reader.skip().expect("its value is skipped");
        assert_eq!(reader.key(), Ok(1));
        assert_eq!(reader.u64(), Ok(0));
        assert_eq!(reader.finish(), Ok(()));
    }

    /// Every refusal renders as its own sentence. Two variants sharing a line is
    /// a log entry that names the wrong cause at 2 a.m., and an empty one is a
    /// log entry that names nothing at all.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [CborError; 18] = [
            CborError::EndOfInput,
            CborError::TrailingBytes,
            CborError::TrailingItem,
            CborError::Unfinished,
            CborError::IndefiniteLength,
            CborError::TagNotAllowed,
            CborError::FloatNotAllowed,
            CborError::SimpleValueNotAllowed,
            CborError::ReservedHead,
            CborError::KeyNotInteger,
            CborError::MisplacedKey,
            CborError::KeysNotAscending,
            CborError::DepthExceeded,
            CborError::StringTooLong,
            CborError::InvalidUtf8,
            CborError::WrongType,
            CborError::IntegerOutOfRange,
            CborError::DestinationTooSmall,
        ];
        let mut rendered = [[0u8; 64]; EVERY.len()];
        let mut lengths = [0usize; EVERY.len()];
        for (index, error) in EVERY.iter().enumerate() {
            let slot = rendered
                .get_mut(index)
                .expect("the buffer is as long as the list");
            let written = render(*error, slot);
            assert!(written > 0, "{error:?} renders as nothing");
            let length = lengths
                .get_mut(index)
                .expect("the buffer is as long as the list");
            *length = written;
        }
        for first in 0..EVERY.len() {
            for second in first.saturating_add(1)..EVERY.len() {
                assert_ne!(
                    said(&rendered, &lengths, first),
                    said(&rendered, &lengths, second),
                    "refusals {first} and {second} render the same sentence"
                );
            }
        }
    }

    /// Renders a refusal into a fixed buffer, since there is no `String` here.
    fn render(error: CborError, into: &mut [u8]) -> usize {
        use core::fmt::Write as _;

        struct Sink<'a> {
            into: &'a mut [u8],
            written: usize,
        }

        impl fmt::Write for Sink<'_> {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                for &byte in text.as_bytes() {
                    let slot = self.into.get_mut(self.written).ok_or(fmt::Error)?;
                    *slot = byte;
                    self.written = self.written.saturating_add(1);
                }
                Ok(())
            }
        }

        let mut sink = Sink { into, written: 0 };
        write!(sink, "{error}").expect("every refusal fits sixty-four bytes");
        sink.written
    }

    fn said<'a>(rendered: &'a [[u8; 64]], lengths: &[usize], index: usize) -> &'a [u8] {
        let whole = rendered.get(index).expect("the index came from the list");
        let len = *lengths.get(index).expect("the index came from the list");
        whole.get(..len).expect("the length came from the render")
    }

    /// The value carried verbatim, both ways.
    ///
    /// `Event 0x04` key 4 is a map whose schema is deferred per kind, so it
    /// crosses this codec unread. "Unread" is the point and "unchecked" is not:
    /// both halves walk the item, so what is carried is bytes that *could* be
    /// parsed rather than bytes nobody looked at.
    #[test]
    fn an_item_this_version_has_no_schema_for_crosses_unread_but_not_unchecked() {
        // Out: `{9: {1: 3}}` with the inner map handed over already encoded.
        let inner = [0xa1u8, 0x01, 0x03];
        let mut dst = [0u8; 16];
        let mut w = CborWriter::new(&mut dst);
        w.map(1).expect("a map of one");
        w.key(9).expect("a key");
        w.raw(&inner).expect("one well-formed item");
        let len = w.finish().expect("it closes");
        assert_eq!(dst.get(..len), Some(&[0xa1, 0x09, 0xa1, 0x01, 0x03][..]));

        // Back: the same bytes, and the reader standing past them.
        let mut r = CborReader::new(dst.get(..len).expect("the length"));
        assert_eq!(r.map(), Ok(1));
        assert_eq!(r.key(), Ok(9));
        assert_eq!(r.raw(), Ok(&inner[..]));
        assert_eq!(r.finish(), Ok(()));
    }

    /// The writer walks what it is handed, so a caller cannot smuggle two items
    /// — or half of one — through a field the far end will count as one.
    ///
    /// Deleting that walk left every test in the crate green, because the one
    /// caller checks its own body first. A public primitive whose safety rests
    /// on its callers being careful is a primitive with no check at all.
    #[test]
    fn an_item_that_is_not_exactly_one_well_formed_item_is_not_carried() {
        for (bytes, why) in [
            (&[0xa0u8, 0x00][..], CborError::TrailingBytes),
            (&[0xa1, 0x01][..], CborError::EndOfInput),
            (&[][..], CborError::EndOfInput),
            (&[0x1b, 0x00][..], CborError::EndOfInput),
        ] {
            let mut dst = [0u8; 32];
            let mut w = CborWriter::new(&mut dst);
            w.map(1).expect("a map of one");
            w.key(9).expect("a key");
            assert_eq!(w.raw(bytes), Err(why), "{bytes:?} was carried");
        }
    }

    /// A nested item comes back whole rather than as its first level, because
    /// `raw` walks to the end of the item and not to the end of its head.
    #[test]
    fn a_nested_item_comes_back_whole() {
        // `{1: {2: [3, 4]}}`
        let frame = [0xa1u8, 0x01, 0xa1, 0x02, 0x82, 0x03, 0x04];
        let mut r = CborReader::new(&frame);
        assert_eq!(r.map(), Ok(1));
        assert_eq!(r.key(), Ok(1));
        assert_eq!(r.raw(), Ok(&[0xa1u8, 0x02, 0x82, 0x03, 0x04][..]));
        assert_eq!(r.finish(), Ok(()));
    }
}
