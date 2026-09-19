//! COBS framing — Cheshire & Baker, 1999 — over buffers the caller owns.
//!
//! The whole point is that `0x00` gets to mean *frame ends here* and nothing
//! else. With every zero lifted out of the body, a receiver holding rubbish
//! resynchronises by reading to the next zero (P-030) rather than trusting a
//! length field this wire format deliberately does not carry.
//!
//! Both directions write into a slice the caller sized, so nothing here
//! allocates and nothing grows. A destination one byte short is **refused**,
//! never truncated: a short encoding still frames correctly at the far end, so
//! it arrives looking like a well-formed frame carrying a different payload,
//! and that is the failure nobody spots.
//!
//! [`encode`] and [`decode`] are inverses over plain byte slices and keep no
//! state between calls — the same shape as a CRC, which is why they are
//! functions and not methods on a codec object.
//!
//! cites: P-030, P-032

use core::fmt;

/// The largest code byte. A block that reaches it holds 254 non-zero bytes and
/// **no** zero after them, so it is closed only when another byte turns up —
/// closing it eagerly appends a zero that was never in the data.
const MAX_CODE: u8 = 0xFF;

/// The most data bytes one block can carry. The code counts itself, so this is
/// one less than [`MAX_CODE`].
const MAX_BLOCK_DATA: usize = 254;

/// Why a COBS buffer was refused. Every variant means *no bytes were produced* —
/// none of them is a shorter answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CobsError {
    /// The destination cannot hold the result. Size it with [`max_encoded_len`]
    /// when encoding; when decoding, the frame's own length always suffices.
    DestinationTooSmall,
    /// No bytes at all between two delimiters, so there is not even a code byte.
    EmptyFrame,
    /// A code byte of `0x00` (P-032). A code is `1..=255`; zero ends a frame.
    ZeroCodeByte,
    /// A `0x00` where a block's data belongs — the tail of one frame and the
    /// head of another, run together by a link that lost the delimiter.
    ZeroInBlock,
    /// A block claiming more bytes than the frame holds (P-032), which is what a
    /// truncated frame looks like from the inside.
    BlockRunsPastEnd,
}

impl fmt::Display for CobsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let said = match self {
            Self::DestinationTooSmall => "destination buffer too small",
            Self::EmptyFrame => "empty COBS frame, no code byte",
            Self::ZeroCodeByte => "zero code byte inside a COBS frame",
            Self::ZeroInBlock => "zero byte inside a COBS block",
            Self::BlockRunsPastEnd => "COBS block runs past the end of the frame",
        };
        f.write_str(said)
    }
}

impl core::error::Error for CobsError {}

const _: () = {
    // The receive path holds one of these per frame on a part with 144 KB of
    // RAM. A refusal that grew past a byte would be paid for on every frame, so
    // it is worth a build failure rather than somebody noticing in review.
    assert!(size_of::<CobsError>() == 1);
};

/// An upper bound on the encoded length of `payload` bytes: one code byte per
/// 254, plus one. Exact below 254 and a byte generous at each boundary above.
#[must_use]
pub const fn max_encoded_len(payload: usize) -> usize {
    payload
        .saturating_add(payload / MAX_BLOCK_DATA)
        .saturating_add(1)
}

/// Encode `src` into `dst` and return the encoded length. The trailing `0x00`
/// delimiter is the caller's to append — this writes the frame body, which never
/// contains a zero. A `dst` too small is refused, never truncated — no length
/// comes back and no shorter frame is left behind. Size it with
/// [`max_encoded_len`].
pub fn encode(src: &[u8], dst: &mut [u8]) -> Result<usize, CobsError> {
    // Decided before a byte is written, so a refused call leaves `dst` untouched
    // rather than holding half an encoding a caller might send anyway. Without
    // this the refusal came partway through, and only `FrameWriter`'s own length
    // check kept it out of reach.
    if dst.len() < max_encoded_len(src.len()) {
        return Err(CobsError::DestinationTooSmall);
    }
    let mut encoder = Encoder::new(dst)?;
    for &byte in src {
        encoder.push(byte)?;
    }
    encoder.finish()
}

/// Decode one frame's body — the bytes between two delimiters, delimiters not
/// included — into `dst`. The result is always shorter than the frame, so a
/// `dst` as long as `src` always fits. Every way a frame can be malformed is a
/// refusal rather than a repair, which is what P-032 requires.
pub fn decode(src: &[u8], dst: &mut [u8]) -> Result<usize, CobsError> {
    if src.is_empty() {
        return Err(CobsError::EmptyFrame);
    }
    Decoder::new(src, dst).run()
}

/// Holds back one byte per block for its code, which is the whole trick.
struct Encoder<'a> {
    dst: &'a mut [u8],
    /// Index of the byte held back for the current block's code.
    code_at: usize,
    /// Next free index in `dst`.
    next: usize,
    /// One more than the number of non-zero bytes in the current block.
    code: u8,
}

impl<'a> Encoder<'a> {
    fn new(dst: &'a mut [u8]) -> Result<Self, CobsError> {
        if dst.is_empty() {
            return Err(CobsError::DestinationTooSmall);
        }
        Ok(Self {
            dst,
            code_at: 0,
            next: 1,
            code: 1,
        })
    }

    fn push(&mut self, byte: u8) -> Result<(), CobsError> {
        if self.code == MAX_CODE {
            // 254 non-zero bytes have gone by. The block ends, and it ends here
            // rather than in `finish` because there is a byte to start the next
            // one with — a full block at the end of the data opens nothing.
            self.close()?;
        }
        if byte == 0 {
            self.close()
        } else {
            self.put(byte)
        }
    }

    fn put(&mut self, byte: u8) -> Result<(), CobsError> {
        let slot = self
            .dst
            .get_mut(self.next)
            .ok_or(CobsError::DestinationTooSmall)?;
        *slot = byte;
        self.next += 1;
        // A full block is closed at the top of `push`, so `code` is at most 0xFE
        // here and the saturation is unreachable.
        self.code = self.code.saturating_add(1);
        Ok(())
    }

    /// Write the finished block's code and hold back a byte for the next one.
    fn close(&mut self) -> Result<(), CobsError> {
        let slot = self
            .dst
            .get_mut(self.code_at)
            .ok_or(CobsError::DestinationTooSmall)?;
        *slot = self.code;
        if self.next >= self.dst.len() {
            return Err(CobsError::DestinationTooSmall);
        }
        self.code_at = self.next;
        self.next += 1;
        self.code = 1;
        Ok(())
    }

    fn finish(self) -> Result<usize, CobsError> {
        let slot = self
            .dst
            .get_mut(self.code_at)
            .ok_or(CobsError::DestinationTooSmall)?;
        *slot = self.code;
        Ok(self.next)
    }
}

/// Walks a frame block by block, putting back the zeros the encoder lifted out.
struct Decoder<'src, 'dst> {
    src: &'src [u8],
    read: usize,
    dst: &'dst mut [u8],
    written: usize,
}

impl<'src, 'dst> Decoder<'src, 'dst> {
    fn new(src: &'src [u8], dst: &'dst mut [u8]) -> Self {
        Self {
            src,
            read: 0,
            dst,
            written: 0,
        }
    }

    fn run(mut self) -> Result<usize, CobsError> {
        while let Some(&code) = self.src.get(self.read) {
            if code == 0 {
                return Err(CobsError::ZeroCodeByte);
            }
            self.read += 1;
            self.copy_block(code)?;
            // The zero a block implies is data only when another block follows:
            // the last one is the delimiter, which the caller already stripped.
            // A full block implies no zero at all.
            if code != MAX_CODE && self.read < self.src.len() {
                self.put(0)?;
            }
        }
        Ok(self.written)
    }

    fn copy_block(&mut self, code: u8) -> Result<(), CobsError> {
        let src = self.src;
        // `code` is never zero here, so the subtraction never saturates.
        let end = self
            .read
            .saturating_add(usize::from(code).saturating_sub(1));
        let block = src.get(self.read..end).ok_or(CobsError::BlockRunsPastEnd)?;
        for &byte in block {
            if byte == 0 {
                return Err(CobsError::ZeroInBlock);
            }
            self.put(byte)?;
        }
        self.read = end;
        Ok(())
    }

    fn put(&mut self, byte: u8) -> Result<(), CobsError> {
        let slot = self
            .dst
            .get_mut(self.written)
            .ok_or(CobsError::DestinationTooSmall)?;
        *slot = byte;
        self.written += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CobsError, Decoder, Encoder, decode, encode, max_encoded_len};
    use core::fmt::Write;

    /// `first`, `first + 1`, … — the ascending runs the paper's long examples are
    /// built from, kept here so a vector can be read against the table rather
    /// than against this file's own idea of what encoding means.
    const fn ramp<const N: usize>(first: u8) -> [u8; N] {
        let mut out = [0u8; N];
        let mut i = 0;
        let mut value = first;
        while i < N {
            out[i] = value;
            value = value.wrapping_add(1);
            i += 1;
        }
        out
    }

    fn encoded(src: &[u8], buf: &mut [u8]) -> usize {
        encode(src, buf).expect("the fixture buffer is sized for the vector")
    }

    fn decoded(frame: &[u8], buf: &mut [u8]) -> usize {
        decode(frame, buf).expect("the paper's encoding must decode")
    }

    /// The paper's short examples, byte for byte. With the long ones below,
    /// these are the only tests here that compare against the world instead of
    /// against ourselves.
    const PAPER_SHORT: &[(&[u8], &[u8])] = &[
        (&[0x00], &[0x01, 0x01]),
        (&[0x00, 0x00], &[0x01, 0x01, 0x01]),
        (&[0x00, 0x11, 0x00], &[0x01, 0x02, 0x11, 0x01]),
        (&[0x11, 0x22, 0x00, 0x33], &[0x03, 0x11, 0x22, 0x02, 0x33]),
        (&[0x11, 0x22, 0x33, 0x44], &[0x05, 0x11, 0x22, 0x33, 0x44]),
        (&[0x11, 0x00, 0x00, 0x00], &[0x02, 0x11, 0x01, 0x01, 0x01]),
    ];

    #[test]
    fn the_papers_short_examples_encode_and_decode_byte_for_byte() {
        let mut buf = [0u8; 16];
        let mut back = [0u8; 16];
        for &(raw, want) in PAPER_SHORT {
            let n = encoded(raw, &mut buf);
            assert_eq!(buf.get(..n), Some(want), "encoding {raw:02x?}");
            let m = decoded(want, &mut back);
            assert_eq!(back.get(..m), Some(raw), "decoding {want:02x?}");
        }
    }

    #[test]
    fn a_full_block_at_the_end_of_the_data_does_not_open_another() {
        // Paper: 01 02 … FD FE  ->  FF 01 02 … FD FE. 254 in, 255 out.
        // The encoder this replaced opened a block for the byte that never came
        // and emitted a trailing 01, and every round trip still passed because
        // the decoder ate it again.
        let src: [u8; 254] = ramp(0x01);
        let mut buf = [0u8; 512];
        let n = encoded(&src, &mut buf);
        assert_eq!(n, 255, "a full block must not open a block it never fills");
        assert_eq!(buf.first(), Some(&0xFF));
        assert_eq!(buf.get(1..255), Some(&src[..]));

        let mut back = [0u8; 512];
        let m = decoded(buf.get(..n).expect("just encoded"), &mut back);
        assert_eq!(m, 254);
        assert_eq!(back.get(..m), Some(&src[..]));
    }

    #[test]
    fn a_leading_zero_costs_one_byte_and_leaves_the_run_intact() {
        // Paper: 00 01 02 … FD FE  ->  01 FF 01 02 … FD FE. 255 in, 256 out.
        let run: [u8; 254] = ramp(0x01);
        let mut src = [0u8; 255];
        src.get_mut(1..).expect("255 long").copy_from_slice(&run);

        let mut buf = [0u8; 512];
        let n = encoded(&src, &mut buf);
        assert_eq!(n, 256);
        assert_eq!(buf.get(..2), Some(&[0x01, 0xFF][..]));
        assert_eq!(buf.get(2..256), Some(&run[..]));

        let mut back = [0u8; 512];
        let m = decoded(buf.get(..n).expect("just encoded"), &mut back);
        assert_eq!(back.get(..m), Some(&src[..]));
    }

    #[test]
    fn one_byte_past_a_full_block_starts_a_second_block() {
        // Paper: 01 02 … FE FF  ->  FF 01 02 … FD FE 02 FF. 255 in, 257 out.
        let src: [u8; 255] = ramp(0x01);
        let run: [u8; 254] = ramp(0x01);

        let mut buf = [0u8; 512];
        let n = encoded(&src, &mut buf);
        assert_eq!(n, 257);
        assert_eq!(buf.first(), Some(&0xFF));
        assert_eq!(buf.get(1..255), Some(&run[..]));
        assert_eq!(buf.get(255..257), Some(&[0x02, 0xFF][..]));

        let mut back = [0u8; 512];
        let m = decoded(buf.get(..n).expect("just encoded"), &mut back);
        assert_eq!(back.get(..m), Some(&src[..]));
    }

    #[test]
    fn a_zero_after_a_full_block_is_not_swallowed_by_the_block() {
        // Paper: 02 03 … FE FF 00  ->  FF 02 03 … FE FF 01 01. 255 in, 257 out.
        //
        // This is the one that was wrong. The encoder closed the full block and
        // opened the next in the same step, so the trailing zero closed *that*
        // block instead of adding one and the zero vanished — and the decoder,
        // wrong in the mirror image, put it back. Every round trip passed.
        let run: [u8; 254] = ramp(0x02);
        let mut src = [0u8; 255];
        src.get_mut(..254).expect("255 long").copy_from_slice(&run);

        let mut buf = [0u8; 512];
        let n = encoded(&src, &mut buf);
        assert_eq!(n, 257, "the trailing zero must cost two bytes, not none");
        assert_eq!(buf.first(), Some(&0xFF));
        assert_eq!(buf.get(1..255), Some(&run[..]));
        assert_eq!(buf.get(255..257), Some(&[0x01, 0x01][..]));

        let mut back = [0u8; 512];
        let m = decoded(buf.get(..n).expect("just encoded"), &mut back);
        assert_eq!(m, 255, "the zero must come back out");
        assert_eq!(back.get(..m), Some(&src[..]));
    }

    #[test]
    fn a_zero_one_byte_short_of_a_full_block_still_ends_it() {
        // Paper: 03 04 … FE FF 00 01  ->  FE 03 04 … FE FF 02 01. 255 in, 256 out.
        let run: [u8; 253] = ramp(0x03);
        let mut src = [0u8; 255];
        src.get_mut(..253).expect("255 long").copy_from_slice(&run);
        *src.get_mut(254).expect("255 long") = 0x01;

        let mut buf = [0u8; 512];
        let n = encoded(&src, &mut buf);
        assert_eq!(n, 256);
        assert_eq!(buf.first(), Some(&0xFE));
        assert_eq!(buf.get(1..254), Some(&run[..]));
        assert_eq!(buf.get(254..256), Some(&[0x02, 0x01][..]));

        let mut back = [0u8; 512];
        let m = decoded(buf.get(..n).expect("just encoded"), &mut back);
        assert_eq!(back.get(..m), Some(&src[..]));
    }

    /// The fill patterns the round trip runs over. An enum rather than a handful
    /// of closures, so a pattern that is added has to be handled everywhere.
    #[derive(Clone, Copy)]
    enum Fill {
        AllZeroes,
        NoZeroes,
        EveryOtherZero,
        RunOf254ThenZeroes,
        Sawtooth,
    }

    impl Fill {
        const ALL: [Self; 5] = [
            Self::AllZeroes,
            Self::NoZeroes,
            Self::EveryOtherZero,
            Self::RunOf254ThenZeroes,
            Self::Sawtooth,
        ];

        fn byte(self, i: usize) -> u8 {
            match self {
                Self::AllZeroes => 0x00,
                Self::NoZeroes => 0xA5,
                Self::EveryOtherZero => {
                    if i.is_multiple_of(2) {
                        0x00
                    } else {
                        0x5A
                    }
                }
                Self::RunOf254ThenZeroes => {
                    if i < 254 {
                        0x7E
                    } else {
                        0x00
                    }
                }
                Self::Sawtooth => u8::try_from(i % 256).expect("i % 256 is a byte"),
            }
        }
    }

    #[test]
    fn every_length_up_to_three_hundred_survives_a_round_trip() {
        // Worth saying plainly, because it is exactly what went wrong here: a
        // round trip only proves the encoder and the decoder agree with *each
        // other*. It cannot prove either agrees with the world. The pair this
        // replaced lost a zero at the 254-byte boundary and passed every length
        // in this loop, because the decoder invented the same zero back. The
        // paper's table above is the only thing in this file that catches that,
        // which is why it is written first.
        const MAX_PAYLOAD: usize = 300;
        let mut src = [0u8; MAX_PAYLOAD];
        let mut frame = [0u8; max_encoded_len(MAX_PAYLOAD)];
        let mut back = [0u8; MAX_PAYLOAD];

        for fill in Fill::ALL {
            for (i, byte) in src.iter_mut().enumerate() {
                *byte = fill.byte(i);
            }
            for len in 0..=MAX_PAYLOAD {
                let payload = src.get(..len).expect("len <= MAX_PAYLOAD");
                let n = encode(payload, &mut frame).expect("sized by max_encoded_len");
                assert!(n <= max_encoded_len(len), "overhead bound broken at {len}");
                let body = frame.get(..n).expect("n <= frame.len()");
                assert!(
                    !body.contains(&0x00),
                    "an encoded frame with a zero in it would end early at {len}"
                );
                let m = decode(body, &mut back).expect("our own encoding must decode");
                assert_eq!(m, len, "the length changed across a round trip");
                assert_eq!(back.get(..m), Some(payload));
            }
        }
    }

    #[test]
    fn an_empty_payload_is_one_code_byte_and_comes_back_empty() {
        let mut buf = [0u8; 4];
        let n = encoded(&[], &mut buf);
        assert_eq!(buf.get(..n), Some(&[0x01][..]));
        let mut back = [0u8; 4];
        assert_eq!(decode(&[0x01], &mut back), Ok(0));
    }

    #[test]
    fn an_empty_frame_has_no_code_byte_to_read() {
        // Two delimiters in a row: an idle line, or the tail of a frame that was
        // already discarded. There is nothing to decode and nothing to guess.
        let mut back = [0u8; 4];
        assert_eq!(decode(&[], &mut back), Err(CobsError::EmptyFrame));
    }

    #[test]
    fn a_zero_code_byte_is_corruption_and_not_an_empty_block() {
        // P-032. Read as a block length it would be minus one, so treating it as
        // anything but corruption means guessing at what the sender meant.
        let mut back = [0u8; 8];
        assert_eq!(decode(&[0x00], &mut back), Err(CobsError::ZeroCodeByte));
        assert_eq!(
            decode(&[0x02, 0x11, 0x00, 0x01], &mut back),
            Err(CobsError::ZeroCodeByte)
        );
        // A caller that forgot to strip the delimiter is told, not indulged.
        assert_eq!(
            decode(&[0x01, 0x00], &mut back),
            Err(CobsError::ZeroCodeByte)
        );
    }

    #[test]
    fn a_zero_inside_a_block_means_two_frames_ran_together() {
        // A well-formed frame body has no zero anywhere. One in a data position
        // is a delimiter that went missing, so the bytes are the end of one
        // frame and the start of another — decoding them into a single payload
        // hands the CRC layer a frame that was never sent.
        let mut back = [0u8; 8];
        assert_eq!(
            decode(&[0x03, 0x11, 0x00], &mut back),
            Err(CobsError::ZeroInBlock)
        );
    }

    #[test]
    fn a_block_running_past_the_end_is_refused_not_clamped() {
        // P-032. Clamping to what is left would produce a shorter payload that
        // still parses, which is the corruption a CRC is least likely to see.
        let mut back = [0u8; 512];
        assert_eq!(
            decode(&[0x05, 0x11, 0x22], &mut back),
            Err(CobsError::BlockRunsPastEnd)
        );
        assert_eq!(
            decode(&[0xFF, 0x01, 0x02], &mut back),
            Err(CobsError::BlockRunsPastEnd)
        );
    }

    #[test]
    fn a_frame_truncated_by_one_byte_is_refused() {
        // The line dropped the last byte before the delimiter. Nothing in what
        // is left says so except the block that now runs off the end.
        let mut buf = [0u8; 32];
        let n = encoded(&[0x11, 0x22, 0x00, 0x33], &mut buf);
        let mut back = [0u8; 32];
        let short = buf.get(..n - 1).expect("shorter than what we encoded");
        assert_eq!(decode(short, &mut back), Err(CobsError::BlockRunsPastEnd));
    }

    #[test]
    fn a_destination_one_byte_short_is_refused_never_truncated() {
        // The refusal is the whole point: a truncated encoding still frames, so
        // it arrives looking like a valid frame with a different payload in it.
        let src = [0x11, 0x22, 0x00, 0x33];
        let mut exact = [0u8; 5];
        assert_eq!(encode(&src, &mut exact), Ok(5));

        // Filled with a sentinel first, because "refused" and "refused after
        // writing three bytes into the caller's buffer" are different promises
        // and only one of them is safe. The refusal used to arrive partway
        // through, and only the frame layer's own length check kept anybody from
        // meeting it.
        let mut short = [0x7Eu8; 4];
        assert_eq!(
            encode(&src, &mut short),
            Err(CobsError::DestinationTooSmall)
        );
        assert!(
            short.iter().all(|&b| b == 0x7E),
            "half an encoding was left in a buffer we refused"
        );
        let mut nothing = [0u8; 0];
        assert_eq!(
            encode(&[], &mut nothing),
            Err(CobsError::DestinationTooSmall)
        );

        let frame = [0x03, 0x11, 0x22, 0x02, 0x33];
        let mut room = [0u8; 4];
        assert_eq!(decode(&frame, &mut room), Ok(4));
        let mut cramped = [0u8; 3];
        assert_eq!(
            decode(&frame, &mut cramped),
            Err(CobsError::DestinationTooSmall)
        );
    }

    #[test]
    fn a_trailing_zero_needs_the_code_byte_the_bound_accounts_for() {
        // The last zero of a payload has nothing after it, so it costs a code
        // byte with no data behind it. A destination sized to the payload alone
        // is one short, and the refusal is what says so.
        let mut tight = [0u8; 1];
        assert_eq!(
            encode(&[0x00], &mut tight),
            Err(CobsError::DestinationTooSmall)
        );
        let mut room = [0u8; 2];
        assert_eq!(encode(&[0x00], &mut room), Ok(2));
    }

    #[test]
    fn arbitrary_bytes_are_refused_or_decoded_but_never_panic() {
        // A resynchronising receiver is handed whatever was on the wire, by
        // definition (P-032): it must not panic, allocate, or loop unboundedly.
        let mut dst = [0u8; 64];
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                let _ = decode(&[first, second], &mut dst);
                let _ = decode(&[first, second, first], &mut dst);
            }
        }

        let mut state = 0x1234_5678_u32;
        let mut frame = [0u8; 64];
        for _ in 0..2000 {
            for byte in &mut frame {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = u8::try_from(state >> 24).expect("the top byte of a u32");
            }
            let _ = decode(&frame, &mut dst);
        }
    }

    #[test]
    fn the_size_bound_covers_the_boundary_it_is_there_for() {
        assert_eq!(max_encoded_len(0), 1);
        assert_eq!(max_encoded_len(1), 2);
        assert_eq!(max_encoded_len(253), 254);
        assert!(max_encoded_len(254) >= 255, "the paper's full block");
        assert!(
            max_encoded_len(255) >= 257,
            "254 non-zero bytes then a zero"
        );
        assert_eq!(max_encoded_len(usize::MAX), usize::MAX);
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
        fn of(error: CobsError) -> Self {
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
        // Five variants that all printed "COBS error" would leave a bench log
        // saying only that something was wrong with the frame.
        const ALL: [CobsError; 5] = [
            CobsError::DestinationTooSmall,
            CobsError::EmptyFrame,
            CobsError::ZeroCodeByte,
            CobsError::ZeroInBlock,
            CobsError::BlockRunsPastEnd,
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
    fn an_encoder_with_no_room_for_the_first_code_byte_refuses_at_once() {
        // The code byte is held back before any data is written, so a zero-length
        // destination has to fail here rather than at the first byte pushed.
        let mut nothing = [0u8; 0];
        assert!(Encoder::new(&mut nothing).is_err());
        let mut one = [0u8; 1];
        assert!(Encoder::new(&mut one).is_ok());
    }

    #[test]
    fn a_decoder_over_a_frame_of_one_code_byte_writes_nothing() {
        let mut dst = [0u8; 4];
        assert_eq!(Decoder::new(&[0x01], &mut dst).run(), Ok(0));
    }
}
