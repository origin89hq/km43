//! `Command 0x08` / `Ack 0x88` — the operation a client signs to act on an
//! output, and what the controller says became of it.
//!
//! [`CommandOperation`] is key 3 of a signed body, never a wrapper's payload:
//! the MAC covers these bytes exactly as they arrived, and the controller's
//! dedup table hashes those same bytes (P-120), so `signed.rs` carries them and
//! this file only reads them once the tag and the counter have both passed.
//!
//! `args` is carried as the map's own bytes and never read. Its schema is
//! deferred per kind until an output is granted authority (DEFERRED entry 8),
//! and a decoder that looked inside would be inventing the schema it is
//! waiting for — the argument `Event 0x04` key 4 makes. Walking it still
//! proves it is one well-formed map.
//!
//! `kind` is refused when the registry does not allocate it (P-019). A kind
//! nobody allocated is a command nobody can say the meaning of, and the
//! controller must not reserve a dedup entry or spend a counter on one.
//!
//! cites: P-013, P-015, P-019

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{Command, CommandKind, ErrorCode};
use crate::limits::MAX_STRING;

/// `Ack 0x88` at its widest: the map head, three one-byte keys, `cmd_id` at
/// full `u32` width, a one-byte outcome, and a `detail` of [`MAX_STRING`]
/// bytes behind its two-byte head. A destination this long always fits.
pub const MAX_COMMAND_ACK_BYTES: usize = 1 + (1 + 5) + (1 + 1) + (1 + 2 + MAX_STRING);

/// The keys of the `Command 0x08` operation body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandKey {
    /// Key 1, client-generated and unique per command.
    CmdId,
    /// Key 2, from the registry's command kinds.
    Kind,
    /// Key 3, the arguments, whose schema is deferred per kind.
    Args,
}

impl CommandKey {
    const COUNT: usize = 3;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::CmdId),
            2 => Some(Self::Kind),
            3 => Some(Self::Args),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::CmdId => 1,
            Self::Kind => 2,
            Self::Args => 3,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::CmdId => "cmd_id",
            Self::Kind => "kind",
            Self::Args => "args",
        }
    }
}

impl fmt::Display for CommandKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Command 0x08 {} (key {})", self.name(), self.number())
    }
}

/// The three keys of `Ack 0x88`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandAckKey {
    /// Key 1, the `cmd_id` this answers.
    CmdId,
    /// Key 2, from the registry's `Command` outcome space.
    Outcome,
    /// Key 3, a sentence for a person, at most [`MAX_STRING`] bytes.
    Detail,
}

impl CommandAckKey {
    const COUNT: usize = 3;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::CmdId),
            2 => Some(Self::Outcome),
            3 => Some(Self::Detail),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::CmdId => 1,
            Self::Outcome => 2,
            Self::Detail => 3,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::CmdId => "cmd_id",
            Self::Outcome => "outcome",
            Self::Detail => "detail",
        }
    }
}

impl fmt::Display for CommandAckKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ack 0x88 {} (key {})", self.name(), self.number())
    }
}

/// A key of either body here, so one refusal can name either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandBodyKey {
    /// A key of the `Command 0x08` operation body.
    Operation(CommandKey),
    /// A key of `Ack 0x88`.
    Ack(CommandAckKey),
}

impl From<CommandKey> for CommandBodyKey {
    fn from(key: CommandKey) -> Self {
        Self::Operation(key)
    }
}

impl From<CommandAckKey> for CommandBodyKey {
    fn from(key: CommandAckKey) -> Self {
        Self::Ack(key)
    }
}

impl fmt::Display for CommandBodyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(key) => key.fmt(f),
            Self::Ack(key) => key.fmt(f),
        }
    }
}

/// The operation a client signs to act on an output. All three keys are
/// required: a command with no id cannot be deduplicated, one with no kind
/// cannot be executed, and one with no arguments is a sender that left out a
/// key rather than one that had nothing to say — an empty map says that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommandOperation<'a> {
    /// Key 1. With the session's `client_id` and the operation's hash, the
    /// dedup table's key (P-120).
    pub cmd_id: u32,
    /// Key 2.
    pub kind: CommandKind,
    /// Key 3: one well-formed CBOR map, its bytes exactly as they arrived.
    pub args: &'a [u8],
}

impl<'a> CommandOperation<'a> {
    /// Encode the operation body. The caller signs these bytes as key 3.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, CommandError> {
        a_map(self.args)?;
        let mut cbor = CborWriter::new(dst);
        cbor.map(CommandKey::COUNT)?;
        cbor.key(CommandKey::CmdId.number())?;
        cbor.u64(u64::from(self.cmd_id))?;
        cbor.key(CommandKey::Kind.number())?;
        cbor.u64(self.kind as u64)?;
        cbor.key(CommandKey::Args.number())?;
        cbor.raw(self.args)?;
        Ok(cbor.finish()?)
    }

    /// Read the operation out of a signed body whose tag has already verified.
    pub fn decode(operation: &'a [u8]) -> Result<Self, CommandError> {
        let mut body = CborReader::new(operation);
        let pairs = body.map()?;
        let (mut cmd_id, mut kind, mut args) = (None, None, None);
        for _ in 0..pairs {
            match CommandKey::of(body.key()?) {
                Some(key @ CommandKey::CmdId) => once(&mut cmd_id, key, body.u32()?)?,
                Some(key @ CommandKey::Kind) => {
                    let number = body.u16()?;
                    let value = CommandKind::try_from(number)
                        .map_err(|()| CommandError::UnknownKind(number))?;
                    once(&mut kind, key, value)?;
                }
                Some(key @ CommandKey::Args) => {
                    let raw = body.raw()?;
                    a_map(raw)?;
                    once(&mut args, key, raw)?;
                }
                None => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            cmd_id: cmd_id.ok_or(CommandError::Missing(CommandKey::CmdId.into()))?,
            kind: kind.ok_or(CommandError::Missing(CommandKey::Kind.into()))?,
            args: args.ok_or(CommandError::Missing(CommandKey::Args.into()))?,
        })
    }
}

/// The controller's answer to a `Command`. An error rather than an ack is
/// what a command that never reached the dedup table gets — a bad MAC, a stale
/// counter, a counter that would not persist — so every value here is a
/// decision about this `cmd_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CommandAck<'a> {
    /// Key 1, echoed from the operation.
    pub cmd_id: u32,
    /// Key 2.
    pub outcome: Command,
    /// Key 3, for a person, never something to branch on. Longer than
    /// [`MAX_STRING`] is refused on both sides rather than truncated.
    pub detail: &'a str,
}

impl<'a> CommandAck<'a> {
    /// Encode the ack body. The caller wraps and MACs it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, CommandError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(CommandAckKey::COUNT)?;
        cbor.key(CommandAckKey::CmdId.number())?;
        cbor.u64(u64::from(self.cmd_id))?;
        cbor.key(CommandAckKey::Outcome.number())?;
        cbor.u64(self.outcome as u64)?;
        cbor.key(CommandAckKey::Detail.number())?;
        cbor.text(self.detail)?;
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &'a [u8]) -> Result<Self, CommandError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut cmd_id, mut outcome, mut detail) = (None, None, None);
        for _ in 0..pairs {
            match CommandAckKey::of(body.key()?) {
                Some(key @ CommandAckKey::CmdId) => once(&mut cmd_id, key, body.u32()?)?,
                Some(key @ CommandAckKey::Outcome) => {
                    let number = body.u8()?;
                    let value = Command::try_from(number)
                        .map_err(|()| CommandError::UnknownOutcome(number))?;
                    once(&mut outcome, key, value)?;
                }
                Some(key @ CommandAckKey::Detail) => once(&mut detail, key, body.text()?)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            cmd_id: cmd_id.ok_or(CommandError::Missing(CommandAckKey::CmdId.into()))?,
            outcome: outcome.ok_or(CommandError::Missing(CommandAckKey::Outcome.into()))?,
            detail: detail.ok_or(CommandError::Missing(CommandAckKey::Detail.into()))?,
        })
    }
}

/// Refuse `args` that are not one map, the shape a kind's schema will be
/// written against, or that carry one of its keys twice (P-015): a later
/// schema decoder and a client could each pick a different copy.
///
/// Keys are compared pairwise rather than by order, because a receiver reads
/// an unsorted map from a sloppy sender (P-016 binds encoders). Quadratic in
/// the pairs, which `MAX_OPERATION` bounds, and it needs no table.
fn a_map(args: &[u8]) -> Result<(), CommandError> {
    let mut walk = CborReader::new(args);
    let pairs = walk.map().map_err(|_| CommandError::ArgsNotAMap)?;
    for seen in 0..pairs {
        let key = walk.key()?;
        walk.skip()?;
        let mut earlier = CborReader::new(args);
        earlier.map()?;
        for _ in 0..seen {
            if earlier.key()? == key {
                return Err(CommandError::ArgsKeyRepeated(key));
            }
            earlier.skip()?;
        }
    }
    walk.finish()?;
    Ok(())
}

fn once<T>(
    slot: &mut Option<T>,
    key: impl Into<CommandBodyKey>,
    value: T,
) -> Result<(), CommandError> {
    if slot.is_some() {
        return Err(CommandError::Duplicate(key.into()));
    }
    *slot = Some(value);
    Ok(())
}

/// Why a `Command` operation or an `Ack` body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandError {
    /// A required key never arrived (P-015).
    Missing(CommandBodyKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(CommandBodyKey),
    /// A `kind` the registry does not allocate (P-019).
    UnknownKind(u16),
    /// An outcome the `Command` outcome space does not allocate.
    UnknownOutcome(u8),
    /// `args` is not a map.
    ArgsNotAMap,
    /// `args` carries this key twice (P-015).
    ArgsKeyRepeated(i64),
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for CommandError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl CommandError {
    /// What to answer. All of these are error 1: a command whose id, kind or
    /// shape cannot be read has no knowable meaning, and nothing about it may
    /// be remembered or executed.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::UnknownKind(_)
            | Self::UnknownOutcome(_)
            | Self::ArgsNotAMap
            | Self::ArgsKeyRepeated(_)
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "command body carries no {key}"),
            Self::Duplicate(key) => write!(f, "command body carries {key} twice"),
            Self::UnknownKind(value) => write!(f, "unallocated command kind {value:#06x}"),
            Self::UnknownOutcome(value) => write!(f, "unallocated Ack outcome {value}"),
            Self::ArgsNotAMap => f.write_str("Command 0x08 args (key 3) is not a map"),
            Self::ArgsKeyRepeated(key) => {
                write!(f, "Command 0x08 args (key 3) carries key {key} twice")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for CommandError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    const KINDS: [CommandKind; 6] = [
        CommandKind::StartGenerator,
        CommandKind::StopGenerator,
        CommandKind::RunExerciseCycleNow,
        CommandKind::SetOutput,
        CommandKind::AcknowledgeConcern,
        CommandKind::ClearOverride,
    ];

    const OUTCOMES: [Command; 8] = [
        Command::Accepted,
        Command::Rejected,
        Command::Duplicate,
        Command::Inhibited,
        Command::Unauthorised,
        Command::Shadowed,
        Command::StaleTopology,
        Command::WrongTarget,
    ];

    /// `cmd_id` at each CBOR width a `u32` can take, and the edges of the
    /// one-byte form.
    const IDS: [u32; 6] = [0, 23, 24, 0x100, 0x1_0000, u32::MAX];

    /// An empty map, a small one, and one nested inside another.
    const ARGS: [&[u8]; 3] = [&[0xa0], &[0xa1, 1, 0x19, 3, 0x84], &[0xa1, 1, 0xa1, 2, 3]];

    /// A `detail` of every length up to the cap, one byte of text repeated.
    const FULL: &str = "0123456789012345678901234567890123456789012345678901234567890123";
    const _: () = assert!(FULL.len() == MAX_STRING);
    const _: () = assert!(MAX_STRING + 1 == 65, "the head below spells the length");

    fn operations() -> impl Iterator<Item = CommandOperation<'static>> {
        IDS.into_iter().flat_map(|cmd_id| {
            KINDS.into_iter().flat_map(move |kind| {
                ARGS.into_iter()
                    .map(move |args| CommandOperation { cmd_id, kind, args })
            })
        })
    }

    fn acks() -> impl Iterator<Item = CommandAck<'static>> {
        IDS.into_iter().flat_map(|cmd_id| {
            OUTCOMES.into_iter().flat_map(move |outcome| {
                [0, 1, 23, 24, MAX_STRING]
                    .into_iter()
                    .map(move |len| CommandAck {
                        cmd_id,
                        outcome,
                        detail: FULL.get(..len).expect("a prefix of the full detail"),
                    })
            })
        })
    }

    fn encoded_operation(op: CommandOperation<'_>) -> ([u8; 32], usize) {
        let mut dst = [0; 32];
        let len = op.encode(&mut dst).expect("fits");
        (dst, len)
    }

    fn encoded_ack(ack: CommandAck<'_>) -> ([u8; MAX_COMMAND_ACK_BYTES + 4], usize) {
        let mut dst = [0; MAX_COMMAND_ACK_BYTES + 4];
        let len = ack.encode(&mut dst).expect("fits the declared cap");
        (dst, len)
    }

    /// The cap is what a controller sizes the stack buffer for its answer from.
    /// One byte short and the widest `rejected` it has to send — the one that
    /// tells a client its `cmd_id` was reused (P-124) — is an ack it cannot
    /// build.
    #[test]
    fn the_widest_ack_fills_its_cap_exactly_and_one_byte_less_refuses() {
        let mut widest = 0;
        for ack in acks() {
            let (dst, len) = encoded_ack(ack);
            widest = widest.max(len);
            assert_eq!(CommandAck::decode(&dst[..len]), Ok(ack));
            for cap in 0..len {
                let mut short = [0; MAX_COMMAND_ACK_BYTES];
                assert!(ack.encode(&mut short[..cap]).is_err(), "accepted {cap}");
            }
        }
        assert_eq!(widest, MAX_COMMAND_ACK_BYTES);
    }

    #[test]
    fn every_operation_round_trips_with_its_args_byte_for_byte() {
        for op in operations() {
            let (dst, len) = encoded_operation(op);
            let back = CommandOperation::decode(&dst[..len]).expect("its own encoding");
            assert_eq!(back, op);
            assert_eq!(back.args, op.args, "args must come back as they went");
        }
    }

    /// A resynchronising receiver hands the decoder whatever it has. Every cut
    /// of every body is refused rather than read short, and a byte past the
    /// end is refused rather than ignored.
    #[test]
    fn every_truncation_and_a_trailing_byte_is_refused() {
        for op in operations() {
            let (dst, len) = encoded_operation(op);
            for cut in 0..len {
                assert!(CommandOperation::decode(&dst[..cut]).is_err(), "cut {cut}");
            }
            assert_eq!(
                CommandOperation::decode(&dst[..=len]),
                Err(CommandError::Cbor(CborError::TrailingBytes))
            );
        }
        for ack in acks() {
            let (dst, len) = encoded_ack(ack);
            for cut in 0..len {
                assert!(CommandAck::decode(&dst[..cut]).is_err(), "cut {cut}");
            }
            assert_eq!(
                CommandAck::decode(&dst[..=len]),
                Err(CommandError::Cbor(CborError::TrailingBytes))
            );
        }
    }

    #[test]
    fn p_015_missing_and_repeated_keys_are_refused() {
        let missing = |key: CommandKey| Err(CommandError::Missing(key.into()));
        let twice = |key: CommandKey| Err(CommandError::Duplicate(key.into()));
        for (bytes, want) in [
            (&[0xa0][..], missing(CommandKey::CmdId)),
            (
                &[0xa2, 2, 0x19, 1, 1, 3, 0xa0][..],
                missing(CommandKey::CmdId),
            ),
            (&[0xa2, 1, 7, 3, 0xa0][..], missing(CommandKey::Kind)),
            (&[0xa2, 1, 7, 2, 0x19, 1, 1][..], missing(CommandKey::Args)),
            (&[0xa2, 1, 7, 1, 8][..], twice(CommandKey::CmdId)),
            (
                &[0xa3, 1, 7, 2, 0x19, 1, 1, 2, 0x19, 1, 2][..],
                twice(CommandKey::Kind),
            ),
            (
                &[0xa4, 1, 7, 2, 0x19, 1, 1, 3, 0xa0, 3, 0xa0][..],
                twice(CommandKey::Args),
            ),
        ] {
            assert_eq!(CommandOperation::decode(bytes), want, "{bytes:02x?}");
        }
        let missing = |key: CommandAckKey| Err(CommandError::Missing(key.into()));
        let twice = |key: CommandAckKey| Err(CommandError::Duplicate(key.into()));
        for (bytes, want) in [
            (&[0xa0][..], missing(CommandAckKey::CmdId)),
            (&[0xa2, 2, 1, 3, 0x60][..], missing(CommandAckKey::CmdId)),
            (&[0xa2, 1, 7, 3, 0x60][..], missing(CommandAckKey::Outcome)),
            (&[0xa2, 1, 7, 2, 1][..], missing(CommandAckKey::Detail)),
            (&[0xa2, 1, 7, 1, 7][..], twice(CommandAckKey::CmdId)),
            (&[0xa3, 1, 7, 2, 1, 2, 3][..], twice(CommandAckKey::Outcome)),
            (
                &[0xa4, 1, 7, 2, 1, 3, 0x60, 3, 0x60][..],
                twice(CommandAckKey::Detail),
            ),
        ] {
            assert_eq!(CommandAck::decode(bytes), want, "{bytes:02x?}");
        }
    }

    /// A kind nobody allocated is a command whose meaning nobody can state. It
    /// is refused at the decoder, so a controller never reserves a dedup entry
    /// or persists a counter for one. Zero is what a sender that forgot the
    /// field writes; `0x8000` is the bench range, which this build does not
    /// speak (DEFERRED entry 8).
    #[test]
    fn p_019_an_unallocated_kind_is_refused() {
        for number in [0u16, 0x100, 0x104, 0x202, 0x8000, u16::MAX] {
            let [hi, lo] = number.to_be_bytes();
            let bytes = [0xa3, 1, 7, 2, 0x19, hi, lo, 3, 0xa0];
            assert_eq!(
                CommandOperation::decode(&bytes),
                Err(CommandError::UnknownKind(number)),
                "{number:#06x}"
            );
        }
        // A kind wider than the registry's `u16` is out of range, not unknown.
        assert_eq!(
            CommandOperation::decode(&[0xa3, 1, 7, 2, 0x1a, 0, 1, 0, 0, 3, 0xa0]),
            Err(CommandError::Cbor(CborError::IntegerOutOfRange))
        );
    }

    #[test]
    fn p_019_an_unallocated_outcome_is_refused() {
        for number in [0u8, 9, 23, u8::MAX] {
            let mut dst = [0; 8];
            let mut cbor = CborWriter::new(&mut dst);
            cbor.map(3).expect("fits");
            cbor.key(1).expect("fits");
            cbor.u64(7).expect("fits");
            cbor.key(2).expect("fits");
            cbor.u64(u64::from(number)).expect("fits");
            cbor.key(3).expect("fits");
            cbor.text("").expect("fits");
            let len = cbor.finish().expect("a whole map");
            assert_eq!(
                CommandAck::decode(&dst[..len]),
                Err(CommandError::UnknownOutcome(number)),
                "{number}"
            );
        }
    }

    /// `args` is the one value here whose contents nobody has specified. It is
    /// walked, so it cannot hide trailing garbage or a float, and it must be a
    /// map, because that is the shape a kind's schema will be written against.
    #[test]
    fn args_that_are_not_one_well_formed_map_are_refused_both_ways() {
        for args in [&[0x80][..], &[0x07], &[0x60], &[0xf5]] {
            let mut bytes = [0xa3, 1, 7, 2, 0x19, 1, 1, 3, 0, 0];
            let at = bytes.len() - 2;
            bytes[at..at + args.len()].copy_from_slice(args);
            let len = at + args.len();
            assert_eq!(
                CommandOperation::decode(&bytes[..len]),
                Err(CommandError::ArgsNotAMap),
                "{args:02x?}"
            );
            let op = CommandOperation {
                cmd_id: 7,
                kind: CommandKind::StartGenerator,
                args,
            };
            assert_eq!(op.encode(&mut [0; 32]), Err(CommandError::ArgsNotAMap));
        }
        // A float inside the map is refused by the walk (P-018), not carried.
        assert_eq!(
            CommandOperation::decode(&[0xa3, 1, 7, 2, 0x19, 1, 1, 3, 0xa1, 1, 0xf9, 0, 0]),
            Err(CommandError::Cbor(CborError::FloatNotAllowed))
        );
        // Two items handed to the encoder as one are refused, not spliced in.
        let op = CommandOperation {
            cmd_id: 7,
            kind: CommandKind::StartGenerator,
            args: &[0xa0, 0xa0],
        };
        assert!(op.encode(&mut [0; 32]).is_err());
    }

    /// P-015 for the one map this body carries unread: a key twice is refused
    /// on both sides, wherever the copies sit, while unique keys out of order
    /// are still read, because P-016 binds the encoder and not the receiver.
    #[test]
    fn p_015_args_carrying_a_key_twice_are_refused_both_ways() {
        for (args, key) in [
            (&[0xa2, 1, 0, 1, 1][..], 1),
            (&[0xa3, 1, 0, 2, 0, 1, 1][..], 1),
            (&[0xa3, 0x20, 0, 2, 0x81, 0, 0x20, 1][..], -1),
            (&[0xa2, 5, 0xa1, 1, 0, 5, 0][..], 5),
        ] {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&[0xa3, 1, 7, 2, 0x19, 1, 1, 3]);
            bytes[8..8 + args.len()].copy_from_slice(args);
            assert_eq!(
                CommandOperation::decode(&bytes[..8 + args.len()]),
                Err(CommandError::ArgsKeyRepeated(key)),
                "{args:02x?}"
            );
            let op = CommandOperation {
                cmd_id: 7,
                kind: CommandKind::StartGenerator,
                args,
            };
            assert_eq!(
                op.encode(&mut [0; 32]),
                Err(CommandError::ArgsKeyRepeated(key))
            );
        }
        let unsorted = [0xa3, 1, 7, 2, 0x19, 1, 1, 3, 0xa2, 2, 0, 1, 1];
        assert_eq!(
            CommandOperation::decode(&unsorted).map(|op| op.args),
            Ok(&unsorted[8..])
        );
    }

    /// A `detail` past the cap is refused rather than truncated, because a
    /// truncated sentence is a different sentence.
    #[test]
    fn a_detail_past_the_cap_is_refused_on_both_sides() {
        let long = [b'x'; MAX_STRING + 1];
        let ack = CommandAck {
            cmd_id: 7,
            outcome: Command::Rejected,
            detail: core::str::from_utf8(&long).expect("ascii"),
        };
        assert_eq!(
            ack.encode(&mut [0; MAX_COMMAND_ACK_BYTES + 8]),
            Err(CommandError::Cbor(CborError::StringTooLong))
        );
        let head = [0xa3, 1, 7, 2, 2, 3, 0x78, 65];
        let mut bytes = [0; 8 + MAX_STRING + 1];
        bytes[..8].copy_from_slice(&head);
        bytes[8..].copy_from_slice(&long);
        assert_eq!(
            CommandAck::decode(&bytes),
            Err(CommandError::Cbor(CborError::StringTooLong))
        );
    }

    /// The wrong CBOR type under a known key is refused rather than coerced.
    #[test]
    fn a_known_key_of_the_wrong_type_is_refused() {
        for bytes in [
            &[0xa3, 1, 0x20, 2, 0x19, 1, 1, 3, 0xa0][..],
            &[0xa3, 1, 0x61, b'7', 2, 0x19, 1, 1, 3, 0xa0],
            &[0xa3, 1, 7, 2, 0xf5, 3, 0xa0],
            &[0x83, 7, 0x19, 1, 1, 0xa0],
        ] {
            assert!(CommandOperation::decode(bytes).is_err(), "{bytes:02x?}");
        }
        for bytes in [
            &[0xa3, 1, 0x20, 2, 1, 3, 0x60][..],
            &[0xa3, 1, 7, 2, 0xf5, 3, 0x60],
            &[0xa3, 1, 7, 2, 1, 3, 0x40],
            &[0x83, 7, 1, 0x60],
        ] {
            assert!(CommandAck::decode(bytes).is_err(), "{bytes:02x?}");
        }
    }

    /// A v2 sender adds a key; a v1 reader skips it (P-013) and keeps the ones
    /// it knows, whether the stranger comes first or last.
    #[test]
    fn p_013_unknown_keys_are_skipped_before_and_after_the_known_ones() {
        for op in operations() {
            let (mut dst, len) = encoded_operation(op);
            dst[0] += 1;
            dst[len..len + 4].copy_from_slice(&[0x18, 99, 0x81, 0]);
            assert_eq!(CommandOperation::decode(&dst[..len + 4]), Ok(op));
        }
        assert_eq!(
            CommandOperation::decode(&[0xa4, 0, 0x61, b'x', 1, 7, 2, 0x19, 1, 1, 3, 0xa0]),
            Ok(CommandOperation {
                cmd_id: 7,
                kind: CommandKind::StartGenerator,
                args: &[0xa0],
            })
        );
        for ack in acks() {
            let (mut dst, len) = encoded_ack(ack);
            dst[0] += 1;
            dst[len..len + 4].copy_from_slice(&[0x18, 99, 0x81, 0]);
            assert_eq!(CommandAck::decode(&dst[..len + 4]), Ok(ack));
        }
    }

    #[test]
    fn refusals_render_and_map_to_malformed_frame() {
        let errors = [
            CommandError::Missing(CommandKey::CmdId.into()),
            CommandError::Missing(CommandAckKey::Detail.into()),
            CommandError::Duplicate(CommandKey::Args.into()),
            CommandError::Duplicate(CommandAckKey::Outcome.into()),
            CommandError::UnknownKind(0),
            CommandError::UnknownOutcome(0),
            CommandError::ArgsNotAMap,
            CommandError::ArgsKeyRepeated(-1),
            CommandError::Cbor(CborError::WrongType),
        ];
        Rendering::<100>::each_says_something_of_its_own(&errors);
        for error in errors {
            assert_eq!(error.refusal(), Refusal::Client(ErrorCode::MalformedFrame));
        }
    }
}
