//! `COBS( envelope | crc16 ) 0x00` — the only thing on the UART, in either direction.
//!
//! Building a frame is the easy half. The half that matters is reading one out of
//! a stream that may start anywhere: a receiver that just powered up, or one that
//! lost bytes to a DMA buffer that filled, is holding rubbish and finds its
//! footing again by reading to the next `0x00` (P-030). That makes [`FrameReader`]
//! the one piece here a hostile peer controls completely, so it is total — every
//! byte handed in is consumed, nothing is indexed, and no input makes it loop.
//!
//! A refusal comes back so a bench log can count it. It is never an answer on the
//! wire: P-031 drops a bad frame silently, because a receiver that replies to
//! corruption has built an amplifier out of one flipped bit.
//!
//! cites: P-002, P-030, P-031, P-032

use core::fmt;
use core::mem;

use crate::cobs::{self, CobsError, max_encoded_len};
use crate::crc::crc16;
use crate::limits::{MAX_FRAME, MAX_PAYLOAD};

/// The byte that ends every frame, and the only one a frame body cannot contain.
/// That exclusivity is the whole reason COBS is here.
pub const DELIMITER: u8 = 0x00;

/// The CRC-16 rides inside the COBS encoding, little-endian, straight after the
/// envelope it covers.
const CRC_BYTES: usize = 2;

/// The most encoded bytes between two delimiters. [`MAX_FRAME`] counts the
/// delimiter and the body is everything before it.
const MAX_ENCODED: usize = MAX_FRAME - 1;

/// A decoded frame: the envelope with its CRC still on the end.
const MAX_DECODED: usize = MAX_PAYLOAD + CRC_BYTES;

/// An upper bound on the wire length of a frame carrying `payload` bytes,
/// delimiter included. Size a destination with this — [`FrameWriter::write`]
/// refuses a shorter one rather than truncating.
#[must_use]
pub const fn max_frame_len(payload: usize) -> usize {
    max_encoded_len(payload.saturating_add(CRC_BYTES)).saturating_add(1)
}

const _: () = {
    // A receiver sizes its buffer at MAX_FRAME before a byte arrives. If a legal
    // payload could be framed into more than that, the frames it refused as
    // overlong would be ones we sent it ourselves.
    assert!(max_frame_len(MAX_PAYLOAD) <= MAX_FRAME);
};

/// Why a frame was refused. Every variant means the frame is gone: there is no
/// NAK at this layer (P-031), so a caller counts these and answers nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FrameError {
    /// More envelope than [`MAX_PAYLOAD`], on the way out or on the way in.
    PayloadTooLong,
    /// The destination cannot hold the frame. Size it with [`max_frame_len`].
    DestinationTooSmall,
    /// [`MAX_FRAME`] bytes went by with no delimiter, so whatever this is, it is
    /// not something we could have been sent.
    FrameTooLong,
    /// COBS refused the bytes between two delimiters (P-032), and this carries
    /// which way — a bench log that says only "bad frame" is worth little.
    Cobs(CobsError),
    /// Fewer than two bytes came out of the decoder, so there is no CRC in there
    /// to check. Two delimiters with a little noise between them.
    MissingCrc,
    /// The CRC did not match (P-031). Dropped, silently, and counted.
    BadCrc,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLong => f.write_str("envelope longer than a payload"),
            Self::DestinationTooSmall => f.write_str("destination buffer too small for the frame"),
            Self::FrameTooLong => f.write_str("frame longer than the receive buffer"),
            Self::Cobs(why) => write!(f, "{why}"),
            Self::MissingCrc => f.write_str("frame too short to hold a CRC"),
            Self::BadCrc => f.write_str("frame failed its CRC"),
        }
    }
}

impl core::error::Error for FrameError {}

const _: () = {
    // One of these is held per frame on a part with 144 KB of RAM. The COBS
    // refusal it wraps has spare values in its own byte, so carrying which way
    // COBS refused costs nothing — and a build where it started costing should
    // fail here rather than be noticed in review.
    assert!(size_of::<FrameError>() == 1);
};

/// Builds `COBS( envelope | crc16 ) 0x00` into a buffer the caller owns.
///
/// It holds the envelope-and-CRC scratch that COBS has to encode from, which is
/// a kilobyte — keep one beside the link rather than on a task's stack.
pub struct FrameWriter {
    /// The envelope with its CRC appended, which is what actually gets encoded.
    /// Its length **is** the payload cap: an envelope that does not fit here is
    /// one over [`MAX_PAYLOAD`], and there is only one place that is decided.
    body: [u8; MAX_DECODED],
}

impl Default for FrameWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameWriter {
    /// A writer with nothing in it. Cheap, but a kilobyte wide.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            body: [0u8; MAX_DECODED],
        }
    }

    /// Frame `payload` into `dst` and return the wire length, delimiter included.
    ///
    /// Size `dst` with [`max_frame_len`]; a shorter one is refused before a byte
    /// of it is touched. Whether a call succeeds depends on the two lengths and
    /// never on what is in the payload — a frame that fits on a bank of zeroes
    /// and not on a bank of readings is a fault that waits for a busy site.
    pub fn write(&mut self, payload: &[u8], dst: &mut [u8]) -> Result<usize, FrameError> {
        let end = payload
            .len()
            .checked_add(CRC_BYTES)
            .ok_or(FrameError::PayloadTooLong)?;
        // Against the bound rather than against what this payload happens to
        // encode to, so a half-written encoding is never left in a caller's
        // buffer for it to send anyway.
        if dst.len() < max_frame_len(payload.len()) {
            return Err(FrameError::DestinationTooSmall);
        }
        let body = self.body.get_mut(..end).ok_or(FrameError::PayloadTooLong)?;

        let crc = crc16(payload).to_le_bytes();
        for (slot, &byte) in body.iter_mut().zip(payload.iter().chain(crc.iter())) {
            *slot = byte;
        }

        let encoded = cobs::encode(body, dst).map_err(|why| match why {
            // Encoding only ever runs out of room, and the room is the caller's.
            CobsError::DestinationTooSmall => FrameError::DestinationTooSmall,
            CobsError::EmptyFrame
            | CobsError::ZeroCodeByte
            | CobsError::ZeroInBlock
            | CobsError::BlockRunsPastEnd => FrameError::Cobs(why),
        })?;

        let slot = dst
            .get_mut(encoded)
            .ok_or(FrameError::DestinationTooSmall)?;
        *slot = DELIMITER;
        Ok(encoded.saturating_add(1))
    }
}

/// What one byte did. A frame borrows the reader until the next byte goes in,
/// which is what saves copying it out again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[must_use = "a dropped frame and a dropped refusal look the same to a caller that ignores this"]
pub enum Received<'a> {
    /// Nothing to hand up: the frame is still arriving, or the line is idle.
    Nothing,
    /// A frame arrived between two delimiters and its CRC held.
    Frame(&'a [u8]),
    /// The bytes between two delimiters were not a frame. Count it; do not
    /// answer it (P-031).
    Dropped(FrameError),
    /// A part-arrived frame was thrown away because nothing followed it.
    ///
    /// **Not the same as `Dropped`**: nothing was refused, a sender stopped.
    /// They point at different things — a bad CRC is noise on the line, and
    /// this is the other end going away — and a counter that added them
    /// together would hide whichever was rarer.
    Abandoned,
}

/// Reads frames out of a byte stream that may start anywhere.
///
/// One byte per call, because that is the only shape that cannot lose a frame
/// boundary — every call consumes its byte and a frame comes back only when its
/// delimiter arrives. The 50 ms incomplete-frame timeout in the framing section
/// of `docs/PROTOCOL.md` is the caller's, and [`FrameReader::discard`] is what it
/// calls.
pub struct FrameReader {
    /// The encoded bytes since the last delimiter. Never contains a zero — a
    /// zero is the delimiter and ends the run instead of joining it.
    encoded: [u8; MAX_ENCODED],
    /// How much of `encoded` is live, and where the next byte goes.
    at: usize,
    /// The run in progress already passed [`MAX_ENCODED`]. Its remaining bytes
    /// are dropped rather than wrapped over the start of the buffer, and the
    /// delimiter that finally ends it reports [`FrameError::FrameTooLong`].
    overlong: bool,
    /// The decoded envelope and its CRC. Its length is the cap on the way in
    /// too: a sender's envelope over [`MAX_PAYLOAD`] is a frame that will not
    /// fit here, so "does not fit" and "over the cap" are one fact.
    decoded: [u8; MAX_DECODED],
    /// Milliseconds since the last byte, accumulated by [`tick`](Self::tick).
    ///
    /// Saturating, so a link left idle for a month does not wrap back under the
    /// timeout and make a stale run look fresh.
    waiting: u32,
}

/// How long a part-arrived frame may sit before it is thrown away.
///
/// The framing section of `docs/PROTOCOL.md` fixes this at 50 ms. Longer and a
/// stalled sender's head merges into the next frame; shorter and a slow sender
/// on a busy line has its own frames cut in half.
pub const INCOMPLETE_AFTER_MS: u32 = 50;

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    /// A reader mid-stream by assumption: the first bytes are treated as the
    /// start of a frame rather than as rubbish to skip. A receiver that skipped
    /// to the first delimiter would throw away the first frame of every link
    /// that came up cleanly, which is most of them.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            encoded: [0u8; MAX_ENCODED],
            at: 0,
            overlong: false,
            decoded: [0u8; MAX_DECODED],
            waiting: 0,
        }
    }

    /// Feed one byte.
    ///
    /// A [`Received::Dropped`] is a local diagnosis for a counter, never a reply:
    /// P-031 has no NAK at this layer because the request layer already retries,
    /// and a link-level retransmit duplicates commands.
    ///
    /// A caller with a clock wants [`tick`](Self::tick), which is this plus the
    /// incomplete-frame timeout.
    pub fn push(&mut self, byte: u8) -> Received<'_> {
        if byte != DELIMITER {
            self.hold(byte);
            return Received::Nothing;
        }

        // A frame ended, whole or not, so nothing is waiting on more bytes.
        self.waiting = 0;
        let len = mem::replace(&mut self.at, 0);
        if mem::replace(&mut self.overlong, false) {
            return Received::Dropped(FrameError::FrameTooLong);
        }
        if len == 0 {
            // A delimiter with nothing in front of it is an idle line, or the
            // tail of a run already refused. Reporting it would bury the refusal
            // that matters under a stream of zeroes.
            return Received::Nothing;
        }

        match self.take(len) {
            Ok(envelope) => Received::Frame(envelope),
            Err(why) => Received::Dropped(why),
        }
    }

    /// Throw away the run in progress, which is what the incomplete-frame
    /// timeout does. Without it the tail of a frame that stopped mid-flight sits
    /// in the buffer and merges into the next one.
    pub fn discard(&mut self) {
        self.at = 0;
        self.overlong = false;
        self.waiting = 0;
    }

    /// Feed one byte, or say how long nothing has arrived.
    ///
    /// **This is the incomplete-frame timeout, and it is here because it cannot
    /// be tested anywhere else.** The reader has no clock and must not grow one
    /// — it runs on two different parts and in a host test — so the caller
    /// supplies elapsed milliseconds and the rule lives with the buffer it
    /// protects. A caller holding the deadline instead has an invariant away
    /// from its data, which is one somebody forgets to maintain, silently.
    ///
    /// The failure it prevents: a frame that stops mid-flight — a controller
    /// reset, a cable pulled — leaves its head in the buffer, and the next
    /// frame's bytes join it. The two together fail a CRC that neither would
    /// have failed alone, so the bad frame arrives *after* the fault rather
    /// than at it, and somebody looks in the wrong place.
    ///
    /// `None` means nothing arrived in that interval. A byte resets the clock,
    /// because a sender still sending has not stalled.
    pub fn tick(&mut self, byte: Option<u8>, since_ms: u32) -> Received<'_> {
        let Some(byte) = byte else {
            self.waiting = self.waiting.saturating_add(since_ms);
            // A run has to be open for the timeout to mean anything: an idle
            // line with an empty buffer is the ordinary state of this link.
            if self.at > 0 && self.waiting >= INCOMPLETE_AFTER_MS {
                self.discard();
                return Received::Abandoned;
            }
            return Received::Nothing;
        };
        self.waiting = 0;
        self.push(byte)
    }

    /// Keep one byte of the run, or mark the run overlong and drop it. Refusing
    /// beats evicting: wrapping over the start of the buffer would hand up a
    /// frame stitched out of two halves that were never sent together.
    fn hold(&mut self, byte: u8) {
        match self.encoded.get_mut(self.at) {
            Some(slot) => {
                *slot = byte;
                self.at = self.at.saturating_add(1);
            }
            None => self.overlong = true,
        }
    }

    /// Decode one delimiter-to-delimiter run and check its CRC, handing back the
    /// envelope the CRC covered — not a slice somebody re-derived afterwards.
    fn take(&mut self, len: usize) -> Result<&[u8], FrameError> {
        // `at` never passes MAX_ENCODED, so a run that will not fit is the same
        // refusal the overlong flag gives rather than a new one to reason about.
        let body = self.encoded.get(..len).ok_or(FrameError::FrameTooLong)?;

        let filled = cobs::decode(body, &mut self.decoded).map_err(|why| match why {
            // The destination is exactly a payload and its CRC, so "too small"
            // here is the sender's envelope over the cap, not our buffer wrong.
            CobsError::DestinationTooSmall => FrameError::PayloadTooLong,
            CobsError::EmptyFrame
            | CobsError::ZeroCodeByte
            | CobsError::ZeroInBlock
            | CobsError::BlockRunsPastEnd => FrameError::Cobs(why),
        })?;

        // A run too short to hold a CRC saturates to an empty envelope, and the
        // two-byte pattern below is what refuses it. Checking the length first as
        // well would add a branch that can never be taken, and a check nobody can
        // watch fail is not a check.
        let envelope_len = filled.saturating_sub(CRC_BYTES);
        let Some((envelope, &[low, high])) = self
            .decoded
            .get(..filled)
            .and_then(|frame| frame.split_at_checked(envelope_len))
        else {
            return Err(FrameError::MissingCrc);
        };

        if crc16(envelope) != u16::from_le_bytes([low, high]) {
            return Err(FrameError::BadCrc);
        }
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DELIMITER, FrameError, FrameReader, FrameWriter, MAX_DECODED, MAX_ENCODED, Received,
        max_frame_len,
    };
    use crate::cobs::CobsError;
    use crate::limits::{MAX_FRAME, MAX_PAYLOAD};
    use core::fmt::Write;

    /// The widest frame anything here builds, so every fixture buffer is the one
    /// size and none of them is a hand-counted number.
    const CAP: usize = max_frame_len(MAX_PAYLOAD);

    /// Payload, and the bytes that must appear on the wire for it.
    ///
    /// Computed by hand from the framing table in `docs/PROTOCOL.md` — CRC-16
    /// over the CBOR-encoded envelope, appended little-endian, the pair
    /// COBS-encoded, then the delimiter — and never from `FrameWriter`.
    ///
    /// Everything else in this file is a round trip, and a round trip proves the
    /// writer and the reader agree with each other. It cannot notice both of
    /// them being wrong in the same direction: XOR a constant into the CRC on
    /// both sides and every other test here still passes, while every frame this
    /// controller emits becomes unreadable to any conforming peer. `cobs.rs` is
    /// anchored by the paper's table and `crc.rs` by `0x29B1`; this is what
    /// anchors the layer that composes them.
    const WIRE: &[(&[u8], &[u8])] = &[
        (&[], &[0x03, 0xFF, 0xFF, 0x00]),
        (&[0x00], &[0x01, 0x03, 0xF0, 0xE1, 0x00]),
        (
            &[0x11, 0x22, 0x00, 0x33],
            &[0x03, 0x11, 0x22, 0x04, 0x33, 0x45, 0x07, 0x00],
        ),
    ];

    #[test]
    fn a_frame_this_controller_builds_is_one_another_implementation_can_read() {
        let mut writer = FrameWriter::new();
        let mut dst = [0u8; CAP];
        for (payload, wire) in WIRE {
            let n = writer.write(payload, &mut dst).expect("fixture must build");
            assert_eq!(
                dst.get(..n),
                Some(*wire),
                "the bytes on the wire moved for payload {payload:?}"
            );
        }
    }

    #[test]
    fn a_frame_from_another_implementation_is_one_this_controller_reads() {
        for (payload, wire) in WIRE {
            let mut line = Line::watching(payload);
            line.feed(wire);
            assert_eq!(line.frames, 1, "one frame, from {wire:?}");
            assert_eq!(
                line.echoes, 1,
                "and it carried the payload it was built from"
            );
        }
    }

    /// A reader with the stream's outcomes kept beside it, so a test can say what
    /// came out without an allocator: how many frames, how many refusals, the
    /// last refusal, and how many of those frames were the payload we sent.
    struct Line {
        reader: FrameReader,
        expected: [u8; MAX_PAYLOAD],
        expected_len: usize,
        frames: usize,
        echoes: usize,
        dropped: usize,
        last: Option<FrameError>,
    }

    impl Line {
        fn new() -> Self {
            Self {
                reader: FrameReader::new(),
                expected: [0u8; MAX_PAYLOAD],
                expected_len: 0,
                frames: 0,
                echoes: 0,
                dropped: 0,
                last: None,
            }
        }

        /// A line already watching for a payload, for the common case.
        fn watching(payload: &[u8]) -> Self {
            let mut line = Self::new();
            line.expecting(payload);
            line
        }

        /// The payload this line should hand back; frames equal to it are counted
        /// as echoes, so a test never has to trust the *last* frame it saw. It
        /// can change mid-stream, because what comes after a refusal is a
        /// different frame.
        fn expecting(&mut self, payload: &[u8]) {
            let slot = self
                .expected
                .get_mut(..payload.len())
                .expect("a fixture payload fits a payload");
            slot.copy_from_slice(payload);
            self.expected_len = payload.len();
        }

        fn feed(&mut self, bytes: &[u8]) {
            for &byte in bytes {
                match self.reader.push(byte) {
                    Received::Nothing => {}
                    Received::Frame(payload) => {
                        self.frames += 1;
                        if Some(payload) == self.expected.get(..self.expected_len) {
                            self.echoes += 1;
                        }
                    }
                    Received::Dropped(why) => {
                        self.dropped += 1;
                        self.last = Some(why);
                    }
                    // `push` never abandons — only `tick` does, and this
                    // harness has no clock to give it.
                    Received::Abandoned => unreachable!("push does not time out"),
                }
            }
        }
    }

    /// The payload shapes the round trip runs over. An enum rather than a handful
    /// of closures, so a shape that is added has to be handled everywhere.
    #[derive(Clone, Copy)]
    enum Fill {
        /// Nothing for COBS to lift out, which is the worst case for overhead and
        /// the only fill that reaches a full-length frame.
        NoZeroes,
        /// A zero every other byte, which is a code byte per pair.
        EveryOtherZero,
        /// Zeros where they fall, and every other byte value on the way past.
        Sawtooth,
    }

    impl Fill {
        const ALL: [Self; 3] = [Self::NoZeroes, Self::EveryOtherZero, Self::Sawtooth];

        fn byte(self, i: usize) -> u8 {
            match self {
                Self::NoZeroes => 0xA5,
                Self::EveryOtherZero => {
                    if i.is_multiple_of(2) {
                        0x00
                    } else {
                        0x5A
                    }
                }
                Self::Sawtooth => u8::try_from(i % 256).expect("i % 256 is a byte"),
            }
        }

        /// A full-width payload of this shape, sliced to the length under test.
        fn payload(self) -> [u8; MAX_PAYLOAD] {
            let mut buf = [0u8; MAX_PAYLOAD];
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = self.byte(i);
            }
            buf
        }
    }

    #[test]
    fn every_payload_length_up_to_the_cap_survives_a_round_trip() {
        // The off-by-one this is looking for only bites on a frame of one
        // particular length: a block boundary at 254, the last byte of the
        // buffer, an empty payload whose CRC is the only thing in the frame.
        let mut writer = FrameWriter::new();
        let mut wire = [0u8; CAP];

        for fill in Fill::ALL {
            let buf = fill.payload();
            for len in 0..=MAX_PAYLOAD {
                let payload = buf.get(..len).expect("len <= MAX_PAYLOAD");
                let n = writer
                    .write(payload, &mut wire)
                    .expect("the fixture buffer is sized by max_frame_len");
                assert!(n <= max_frame_len(len), "the wire bound broke at {len}");
                assert!(n <= MAX_FRAME, "a legal payload built an illegal frame");
                assert!(n > len, "a frame is never as short as its payload");

                let frame = wire.get(..n).expect("n <= CAP");
                assert_eq!(frame.last(), Some(&DELIMITER), "no delimiter at {len}");
                let body = frame.get(..n - 1).expect("a frame is at least a delimiter");
                assert!(
                    !body.contains(&DELIMITER),
                    "a zero inside the body would end the frame early at {len}"
                );

                let mut line = Line::watching(payload);
                line.feed(frame);
                assert_eq!(line.frames, 1, "one frame in, one frame out at {len}");
                assert_eq!(line.echoes, 1, "a different payload came back at {len}");
                assert_eq!(line.dropped, 0, "a good frame was refused at {len}");
            }
        }
    }

    #[test]
    fn a_payload_over_the_cap_is_refused_before_a_byte_is_copied() {
        // The failure is a controller that builds a frame it then has to refuse,
        // at a fully configured site, with nothing to fall back on. It is refused
        // here, where the caller still knows what it was trying to send.
        let mut writer = FrameWriter::new();
        let payload = [0xA5u8; MAX_PAYLOAD + 1];
        let mut wire = [0x7Eu8; CAP + 8];

        assert_eq!(
            writer.write(&payload, &mut wire),
            Err(FrameError::PayloadTooLong)
        );
        assert!(
            wire.iter().all(|&byte| byte == 0x7E),
            "the destination was written to before the refusal"
        );

        let at_the_cap = payload.get(..MAX_PAYLOAD).expect("one under the fixture");
        assert_eq!(writer.write(at_the_cap, &mut wire), Ok(MAX_FRAME));
    }

    #[test]
    fn a_destination_one_byte_short_is_refused_never_truncated() {
        // A truncated frame still frames at the far end: it decodes, and if its
        // CRC happens to hold it arrives as a well-formed frame carrying a
        // payload nobody sent. Refusing is the only safe answer.
        let mut writer = FrameWriter::new();
        let payload = [0x11u8, 0x22, 0x00, 0x33];

        let mut exact = [0u8; 8];
        let n = writer
            .write(&payload, &mut exact)
            .expect("eight bytes is room for a four-byte payload");
        assert_eq!(n, 8, "four payload, two crc, one code, one delimiter");

        // One byte short, and the encoder must not have started. It writes as it
        // goes, so without the length check first this buffer holds most of a
        // frame and a caller that ignored the refusal would send it.
        let mut short = [0x7Eu8; 7];
        assert_eq!(
            writer.write(&payload, &mut short),
            Err(FrameError::DestinationTooSmall)
        );
        assert!(
            short.iter().all(|&byte| byte == 0x7E),
            "half an encoding was left behind in a buffer we refused"
        );

        let mut nothing = [0u8; 0];
        assert_eq!(
            writer.write(&[], &mut nothing),
            Err(FrameError::DestinationTooSmall)
        );
    }

    #[test]
    fn the_bound_a_caller_sizes_its_buffer_with_covers_the_block_boundary() {
        // A caller sizes its transmit buffer from this once and never looks
        // again. The round trip above proves no length beats the bound; this
        // proves the bound is the right size rather than merely generous, at the
        // 254-byte block boundary where the off-by-one hides.
        assert_eq!(max_frame_len(0), 4, "one code byte, two crc, one delimiter");
        assert_eq!(max_frame_len(1), 5);
        assert_eq!(
            max_frame_len(251),
            255,
            "253 body bytes are still one block"
        );
        assert_eq!(
            max_frame_len(252),
            257,
            "254 body bytes, and the next costs"
        );
        assert_eq!(max_frame_len(MAX_PAYLOAD), MAX_FRAME);
        assert_eq!(max_frame_len(usize::MAX), usize::MAX, "no wrap at the top");
    }

    #[test]
    fn two_frames_run_together_are_rejected_not_concatenated() {
        // The delimiter is the only thing separating two messages. Lose one and
        // the bytes still decode — COBS chains straight on into the next frame's
        // code byte — so what comes out is one longer envelope that was never
        // sent. The CRC is what stands between that and a command being obeyed.
        let mut writer = FrameWriter::new();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        let one = writer
            .write(&[0x11, 0x22, 0x33], &mut first)
            .expect("room for three bytes");
        let two = writer
            .write(&[0x44, 0x55, 0x66], &mut second)
            .expect("room for three bytes");

        let mut line = Line::watching(&[0x11, 0x22, 0x33]);
        // Everything of the first frame except its delimiter, then all of the
        // second: exactly what a link that dropped one byte delivers.
        line.feed(first.get(..one - 1).expect("a frame ends in a delimiter"));
        line.feed(second.get(..two).expect("the whole second frame"));

        assert_eq!(
            line.frames, 0,
            "two frames were merged into one and believed"
        );
        assert_eq!(line.dropped, 1);
        assert_eq!(line.last, Some(FrameError::BadCrc));
    }

    #[test]
    fn garbage_before_the_first_delimiter_does_not_eat_the_frame_after_it() {
        // A receiver powered up mid-transmission, or one that lost bytes to a
        // full DMA buffer. P-030: read to the next zero and carry on. The frame
        // after the garbage has to arrive, or the link never recovers.
        let mut writer = FrameWriter::new();
        let mut wire = [0u8; 32];
        let n = writer
            .write(&[0xDE, 0xAD, 0xBE, 0xEF], &mut wire)
            .expect("room for four bytes");

        let mut line = Line::watching(&[0xDE, 0xAD, 0xBE, 0xEF]);
        line.feed(&[0x7F, 0x11, 0x99, 0x02, DELIMITER]);
        line.feed(wire.get(..n).expect("the whole frame"));

        assert_eq!(line.dropped, 1, "the garbage run was not refused");
        assert_eq!(
            line.last,
            Some(FrameError::Cobs(CobsError::BlockRunsPastEnd)),
            "a refusal that does not say which way leaves a bench log saying nothing"
        );
        assert_eq!(line.frames, 1);
        assert_eq!(line.echoes, 1, "the frame after the garbage did not read");
    }

    #[test]
    fn a_corrupted_frame_is_dropped_and_the_next_one_still_reads() {
        // Recovery is the requirement, not refusal. A reader that refuses a bad
        // frame and then stays out of step has turned one flipped bit into a link
        // that is down until somebody drives out to it.
        let mut writer = FrameWriter::new();
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        let one = writer
            .write(&[0x01, 0x02, 0x03, 0x04], &mut first)
            .expect("room for four bytes");
        let two = writer
            .write(&[0x05, 0x06, 0x07, 0x08], &mut second)
            .expect("room for four bytes");
        let slot = first
            .get_mut(2)
            .expect("a frame this long has a third byte");
        *slot ^= 0x40;

        let mut line = Line::watching(&[0x05, 0x06, 0x07, 0x08]);
        line.feed(first.get(..one).expect("the whole corrupted frame"));
        line.feed(second.get(..two).expect("the whole second frame"));

        assert_eq!(line.dropped, 1);
        assert_eq!(line.last, Some(FrameError::BadCrc));
        assert_eq!(line.frames, 1);
        assert_eq!(
            line.echoes, 1,
            "the frame after the corrupted one did not read"
        );
    }

    #[test]
    fn a_single_bit_flip_never_delivers_a_payload_nobody_sent() {
        // This is the reason the CRC is in the frame at all. Flip one bit
        // anywhere in the wire bytes — a code byte, an envelope byte, the CRC,
        // the delimiter itself — and what comes out must be the payload that
        // went in, or nothing. Anything else is a flipped bit in a setpoint
        // arriving as a command nobody asked for, at a site nobody is standing
        // in.
        //
        // One flip in 9456 is not *detected*, and it is written down here rather
        // than tuned out of the vectors. A 253-byte sawtooth payload encodes to
        // a full 0xFF block that ends exactly on the delimiter; flipping that
        // delimiter to 0x01 leaves a trailing empty block, which COBS decodes as
        // nothing at all and hands back the very same bytes. It fails safe: the
        // corruption was in the framing, the envelope arrived whole, and the CRC
        // over it still holds. The underlying fact is that `cobs::decode` accepts
        // an encoding its own encoder would never produce — a trailing 0x01 block
        // after a full 0xFF block decodes to the same bytes as no block at all —
        // which is why this particular flip is invisible rather than caught.
        let mut writer = FrameWriter::new();
        let mut wire = [0u8; CAP];
        let mut compared = 0usize;
        let mut undetected: Option<(usize, usize, u8)> = None;

        for len in [0usize, 1, 2, 3, 7, 64, 253, 254, 255, 300] {
            let buf = Fill::Sawtooth.payload();
            let payload = buf.get(..len).expect("len is under a payload");
            let n = writer
                .write(payload, &mut wire)
                .expect("sized by the bound");

            // Without this the whole test could pass by never reading anything.
            let mut clean = Line::watching(payload);
            clean.feed(wire.get(..n).expect("the whole frame"));
            assert_eq!(clean.echoes, 1, "the control frame did not read at {len}");

            for index in 0..n {
                for bit in 0u8..8 {
                    let mut corrupted = wire;
                    let slot = corrupted.get_mut(index).expect("index < n <= CAP");
                    *slot ^= 1u8 << bit;

                    let mut line = Line::watching(payload);
                    line.feed(corrupted.get(..n).expect("the whole corrupted frame"));
                    // A flip in the delimiter leaves the run open; close it, or
                    // the test would pass by never finishing a frame at all.
                    line.feed(&[DELIMITER]);

                    assert_eq!(
                        line.frames, line.echoes,
                        "a payload nobody sent came out of len {len} byte {index} bit {bit}"
                    );
                    if line.echoes > 0 {
                        assert_eq!(undetected, None, "a second flip went undetected");
                        undetected = Some((len, index, bit));
                    }
                    compared += 1;
                }
            }
        }

        // Two checks in this repo once reported "all pass" while comparing
        // nothing at all. This one says out loud how much it compared, and which
        // single flip it knows is invisible.
        assert_eq!(
            compared,
            8 * 1182,
            "the flip count moved; the vectors changed"
        );
        assert_eq!(
            undetected,
            Some((253, 256, 0)),
            "the delimiter after a full COBS block is the one flip that is invisible"
        );
    }

    #[test]
    fn a_frame_longer_than_the_buffer_is_refused_and_the_next_one_reads() {
        // There is no length field, so "too long" is only knowable by running
        // out of buffer. The bytes past the end are dropped rather than wrapped
        // over the start, which would hand up a frame stitched from two halves.
        let mut line = Line::watching(&[0x11, 0x22]);
        let overlong = [0xA5u8; MAX_FRAME + 64];
        line.feed(&overlong);
        assert_eq!(line.frames, 0);
        assert_eq!(line.dropped, 0, "nothing is decided until the delimiter");

        line.feed(&[DELIMITER]);
        assert_eq!(line.dropped, 1);
        assert_eq!(line.last, Some(FrameError::FrameTooLong));

        let mut writer = FrameWriter::new();
        let mut wire = [0u8; 32];
        let n = writer
            .write(&[0x11, 0x22], &mut wire)
            .expect("room for two bytes");
        line.feed(wire.get(..n).expect("the whole frame"));
        assert_eq!(line.echoes, 1, "the reader never came back into step");
    }

    #[test]
    fn a_run_one_byte_over_the_buffer_is_the_one_that_is_refused() {
        // The boundary itself: the longest legal frame must read, and one byte
        // more must not. An off-by-one here is a full-length frame refused at a
        // busy site and nowhere else.
        let mut at_the_edge = Line::new();
        let body = [0xA5u8; MAX_ENCODED];
        at_the_edge.feed(&body);
        at_the_edge.feed(&[DELIMITER]);
        assert_eq!(
            at_the_edge.last,
            Some(FrameError::Cobs(CobsError::BlockRunsPastEnd)),
            "a full-length run must reach the decoder, not the length refusal"
        );

        let mut one_over = Line::new();
        one_over.feed(&body);
        one_over.feed(&[0xA5, DELIMITER]);
        assert_eq!(one_over.last, Some(FrameError::FrameTooLong));
    }

    #[test]
    fn an_envelope_over_the_cap_is_refused_before_it_can_overrun_the_buffer() {
        // A run inside the frame buffer can still decode to more than a payload:
        // 1031 code bytes of `01` are 1030 implied zeros, four more than a full
        // envelope and its CRC. The buffer it will not fit in *is* the cap, so
        // the overrun is a refusal rather than a length nobody checked — and the
        // refusal has to say "too long", because a bench log reading "bad CRC"
        // sends somebody looking at the cable.
        let mut line = Line::new();
        line.feed(&[0x01u8; MAX_ENCODED]);
        line.feed(&[DELIMITER]);
        assert_eq!(line.frames, 0);
        assert_eq!(line.last, Some(FrameError::PayloadTooLong));

        // And the reader is still in step afterwards.
        let mut writer = FrameWriter::new();
        let mut wire = [0u8; 32];
        let n = writer.write(&[0x77], &mut wire).expect("room for one byte");
        line.expecting(&[0x77]);
        line.feed(wire.get(..n).expect("the whole frame"));
        assert_eq!(line.echoes, 1);
    }

    #[test]
    fn a_timeout_in_the_middle_of_a_burst_of_noise_does_not_refuse_the_next_frame() {
        // A burst long enough to overrun the buffer, and then the line goes
        // quiet: the incomplete-frame timeout fires with the run still marked
        // overlong. Forgetting that mark leaves it set, and the next good frame's
        // delimiter reports FrameTooLong — one burst of noise costing a frame
        // that arrived perfectly, which is exactly the failure `discard` is for.
        let mut line = Line::watching(&[0x99, 0x88]);
        line.feed(&[0xA5u8; MAX_FRAME + 8]);
        line.reader.discard();

        let mut writer = FrameWriter::new();
        let mut wire = [0u8; 32];
        let n = writer
            .write(&[0x99, 0x88], &mut wire)
            .expect("room for two bytes");
        line.feed(wire.get(..n).expect("the whole frame"));

        assert_eq!(line.dropped, 0, "the burst was still being held against us");
        assert_eq!(line.echoes, 1);
    }

    #[test]
    fn a_run_with_no_room_for_a_crc_is_not_an_empty_frame() {
        // `01 00` decodes to nothing at all and `02 11 00` to a single byte.
        // Neither carries a CRC, and treating the first as an empty envelope
        // would hand the layer above a frame assembled out of line noise.
        let mut line = Line::new();
        line.feed(&[0x01, DELIMITER]);
        assert_eq!(line.last, Some(FrameError::MissingCrc));
        line.feed(&[0x02, 0x11, DELIMITER]);
        assert_eq!(line.dropped, 2);
        assert_eq!(line.last, Some(FrameError::MissingCrc));
        assert_eq!(line.frames, 0);
    }

    #[test]
    fn an_idle_line_of_delimiters_is_not_a_stream_of_refusals() {
        // A quiet UART that reads as zeroes, or the tail of a frame already
        // refused. One refusal per zero would bury the one that meant something.
        let mut line = Line::new();
        line.feed(&[DELIMITER; 64]);
        assert_eq!(line.dropped, 0);
        assert_eq!(line.frames, 0);

        let mut writer = FrameWriter::new();
        let mut wire = [0u8; 32];
        let n = writer.write(&[0x42], &mut wire).expect("room for one byte");
        let mut after = Line::watching(&[0x42]);
        after.feed(&[DELIMITER; 8]);
        after.feed(wire.get(..n).expect("the whole frame"));
        assert_eq!(after.echoes, 1);
    }

    #[test]
    fn a_frame_that_stopped_mid_flight_does_not_merge_into_the_next_one() {
        // The 50 ms incomplete-frame timeout, which only works if the reader can
        // be told to forget. Without it the half-frame left in the buffer joins
        // the next one and both are lost instead of one.
        let mut writer = FrameWriter::new();
        let mut wire = [0u8; 32];
        let n = writer
            .write(&[0x31, 0x41, 0x59], &mut wire)
            .expect("room for three bytes");

        let mut line = Line::watching(&[0x31, 0x41, 0x59]);
        line.feed(&[0x05, 0x06, 0x07]);
        line.reader.discard();
        line.feed(wire.get(..n).expect("the whole frame"));

        assert_eq!(line.frames, 1);
        assert_eq!(
            line.echoes, 1,
            "the abandoned half-frame merged into this one"
        );
        assert_eq!(line.dropped, 0);
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_never_hand_up_more_than_a_payload() {
        // A resynchronising receiver is handed whatever was on the wire, by
        // definition (P-032). The seed is fixed so a failure here is a bug report
        // somebody can replay rather than a story about a run that once went red.
        let mut state = 0x1234_5678_u32;
        let mut reader = FrameReader::new();
        let mut pushed = 0usize;

        for _ in 0..4096 {
            for _ in 0..64 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let byte = u8::try_from(state & 0xFF).expect("a masked byte");
                // Counted inside the arms, not after the match. Incremented
                // unconditionally it restated the loop bounds and would have held
                // even if `push` returned without looking at the byte — a counter
                // no branch can skip is an assertion about the loop, not about the
                // code under it.
                match reader.push(byte) {
                    Received::Nothing | Received::Dropped(_) => pushed += 1,
                    Received::Frame(payload) => {
                        assert!(payload.len() <= MAX_PAYLOAD, "a frame over the cap got out");
                        pushed += 1;
                    }
                    Received::Abandoned => unreachable!("push does not time out"),
                }
            }
        }
        assert_eq!(
            pushed,
            4096 * 64,
            "every byte must land in exactly one outcome"
        );
    }

    /// A fixed sink, so a refusal can be rendered without an allocator.
    struct Rendered {
        bytes: [u8; 96],
        len: usize,
    }

    impl Write for Rendered {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for &byte in s.as_bytes() {
                let slot = self.bytes.get_mut(self.len).ok_or(core::fmt::Error)?;
                *slot = byte;
                self.len += 1;
            }
            Ok(())
        }
    }

    impl Rendered {
        fn of(error: FrameError) -> Self {
            let mut out = Self {
                bytes: [0u8; 96],
                len: 0,
            };
            write!(&mut out, "{error}").expect("a refusal fits in 96 bytes");
            out
        }

        fn text(&self) -> &[u8] {
            self.bytes.get(..self.len).unwrap_or(&[])
        }
    }

    #[test]
    fn every_refusal_says_a_different_thing() {
        // Six variants that all printed "bad frame" would leave a bench log
        // saying only that something was wrong, which is what it already knew.
        const ALL: [FrameError; 6] = [
            FrameError::PayloadTooLong,
            FrameError::DestinationTooSmall,
            FrameError::FrameTooLong,
            FrameError::Cobs(CobsError::ZeroInBlock),
            FrameError::MissingCrc,
            FrameError::BadCrc,
        ];
        for (i, &error) in ALL.iter().enumerate() {
            let said = Rendered::of(error);
            assert!(!said.text().is_empty(), "{error:?} rendered nothing");
            for &other in ALL.iter().skip(i + 1) {
                assert_ne!(said.text(), Rendered::of(other).text());
            }
        }
    }

    #[test]
    fn the_buffers_are_sized_from_the_limits_and_not_by_hand() {
        // Both were counted by hand once in this repo and both were wrong. The
        // reader's buffer must hold the longest frame the writer can build, and
        // the decoded buffer must hold exactly a payload and its CRC.
        assert_eq!(MAX_ENCODED, MAX_FRAME - 1, "the delimiter is not stored");
        assert_eq!(MAX_DECODED, MAX_PAYLOAD + 2);
        assert_eq!(max_frame_len(MAX_PAYLOAD), MAX_FRAME);
    }

    /// **A frame that stopped mid-flight does not join the next one.**
    ///
    /// The failure this prevents is displaced rather than loud: a controller
    /// resets halfway through sending, its head sits in the buffer, and the
    /// next frame's bytes land behind it. The two together fail a CRC that
    /// neither would have failed alone — so the bad frame arrives *after* the
    /// fault instead of at it, and somebody spends the afternoon looking at the
    /// frame that was fine.
    #[test]
    fn a_frame_that_stopped_mid_flight_does_not_merge_into_the_next() {
        let mut writer = FrameWriter::new();
        let mut whole = [0u8; MAX_FRAME];
        let len = writer
            .write(b"a whole frame", &mut whole)
            .expect("it frames");
        let whole = whole.get(..len).expect("the frame");

        let mut reader = FrameReader::new();
        // Half of a frame, and then the sender dies.
        for &byte in whole.get(..len / 2).expect("half a frame") {
            assert!(matches!(reader.tick(Some(byte), 1), Received::Nothing));
        }

        // Silence. Nothing yet at 49 ms, because a slow sender on a busy line
        // is not a stalled one.
        assert!(matches!(reader.tick(None, 49), Received::Nothing));
        assert!(
            matches!(reader.tick(None, 1), Received::Abandoned),
            "a run open past the timeout was kept"
        );

        // And now a whole frame arrives, on a clean buffer.
        let mut got = None;
        for &byte in whole {
            if let Received::Frame(payload) = reader.tick(Some(byte), 1) {
                got = Some(payload.to_vec());
            }
        }
        assert_eq!(
            got.as_deref(),
            Some(&b"a whole frame"[..]),
            "the frame after a stall was corrupted by what was left of the one before"
        );
    }

    /// **An idle line is not an abandoned frame.** This link spends almost all
    /// of its time with nothing on it, and a reader that reported a timeout
    /// every 50 ms would bury every real one under it.
    #[test]
    fn an_idle_line_with_nothing_buffered_reports_nothing() {
        let mut reader = FrameReader::new();
        for _ in 0..100 {
            assert!(
                matches!(reader.tick(None, 50), Received::Nothing),
                "an empty buffer timed out"
            );
        }
    }

    /// **A byte resets the clock**, or a frame arriving slowly — one byte per
    /// 40 ms, which is what a stuttering sender looks like — would be cut in
    /// half by its own timeout.
    #[test]
    fn a_slow_sender_is_not_mistaken_for_a_stalled_one() {
        let mut writer = FrameWriter::new();
        let mut whole = [0u8; MAX_FRAME];
        let len = writer.write(b"slow", &mut whole).expect("it frames");
        let whole = whole.get(..len).expect("the frame");

        let mut reader = FrameReader::new();
        let mut got = None;
        for &byte in whole {
            // Just inside the timeout, every byte, all the way through.
            assert!(matches!(reader.tick(None, 40), Received::Nothing));
            if let Received::Frame(payload) = reader.tick(Some(byte), 0) {
                got = Some(payload.to_vec());
            }
        }
        assert_eq!(
            got.as_deref(),
            Some(&b"slow"[..]),
            "a frame that arrived slowly was thrown away as a stall"
        );
    }
    /// A frame cut at any byte and then delimited is never handed up as a
    /// frame. A COBS prefix can itself be a valid encoding, so what stands
    /// between a cut and a shorter message being obeyed is the CRC, and this
    /// is the test that says the CRC does that job at every length.
    #[test]
    fn a_frame_cut_at_any_byte_and_then_delimited_never_hands_up_a_frame() {
        let payload = [0x11, 0x22, 0x00, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0x88];
        let mut writer = FrameWriter::new();
        let mut wire = [0u8; 64];
        let len = writer
            .write(&payload, &mut wire)
            .expect("room for the frame");
        assert_eq!(
            wire.get(len - 1).copied(),
            Some(DELIMITER),
            "the writer ends a frame with the delimiter"
        );
        for cut in 0..len - 1 {
            let mut line = Line::watching(&payload);
            line.feed(wire.get(..cut).expect("a prefix"));
            line.feed(&[DELIMITER]);
            assert_eq!(line.frames, 0, "a frame cut at {cut} bytes was handed up");
        }
        let mut line = Line::watching(&payload);
        line.feed(wire.get(..len).expect("the whole frame"));
        assert_eq!(line.echoes, 1, "the whole frame is handed up once");
    }
}
