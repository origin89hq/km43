//! The two bytes that decide whether a frame is real.
//!
//! A frame failing this CRC is dropped silently — no NAK, nothing logged at the
//! far end — so it is the only thing standing between line noise on the UART and
//! a command the controller acts on. That is why the tests below care more about
//! the corruption it has to catch than about the one value it has to produce.
//! The framing section of `docs/PROTOCOL.md` says what it covers and in which
//! byte order it goes on the wire.
//!
//! cites: P-031

/// `x^16 + x^12 + x^5 + 1`, applied unreflected: the bit shifted out of the top
/// of the register is the one that decides whether the polynomial is mixed back
/// in.
const POLY: u16 = 0x1021;

/// All ones, not zero. A register of zeroes stays zero while it is fed zero
/// bytes, so `\0` and `\0\0\0` would checksum alike and a frame that lost its
/// leading padding would still pass.
const INIT: u16 = 0xFFFF;

/// CRC-16/CCITT-FALSE — poly `0x1021`, init `0xFFFF`, no reflection, no final
/// XOR, check value `0x29B1`. The framing layer runs it over the encoded
/// envelope bytes only and puts it on the wire little-endian, which is *not* the
/// order that leaves a zero residue, so a receiver recomputes and compares
/// rather than expecting the whole frame to checksum to zero.
#[must_use]
pub const fn crc16(mut data: &[u8]) -> u16 {
    // Bitwise, not a 256-entry table: the table costs 512 bytes of a ~256 KB
    // image to buy cycles this link has to spare, since even a maximum-length
    // frame is well under a millisecond of M0+ time at the rate frames arrive.
    let mut crc = INIT;
    while let Some((&byte, rest)) = data.split_first() {
        // The byte enters the top half of the register. `from_be_bytes` is that
        // widening shift written so a `const fn` needs no cast to do it.
        crc ^= u16::from_be_bytes([byte, 0]);
        let mut bit: u8 = 0;
        while bit < 8 {
            crc = if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ POLY
            };
            bit = bit.saturating_add(1);
        }
        data = rest;
    }
    crc
}

/// The published check value, asserted where nobody can skip it: a build that
/// computes anything else for `"123456789"` fails to compile rather than
/// shipping a controller that agrees with no other implementation.
const _: () = assert!(crc16(b"123456789") == 0x29B1);

#[cfg(test)]
mod tests {
    use super::crc16;

    /// Long enough that a wrong feedback tap has room to alias, short enough
    /// that flipping every bit in it stays instant.
    const MESSAGE_LEN: usize = 300;

    /// Neither a ramp nor text, so a bug that only shows on high bits or on
    /// repeated bytes has somewhere to show.
    fn pseudorandom_message() -> [u8; MESSAGE_LEN] {
        let mut message = [0u8; MESSAGE_LEN];
        let mut state: u8 = 0x5A;
        for slot in &mut message {
            state = state.wrapping_mul(37).wrapping_add(11);
            *slot = state;
        }
        message
    }

    /// The nine digits with two trailing bytes, the way a frame carries its CRC.
    fn with_trailer(message: &[u8; 9], trailer: [u8; 2]) -> [u8; 11] {
        let mut framed = [0u8; 11];
        let (body, tail) = framed.split_at_mut(9);
        body.copy_from_slice(message);
        tail.copy_from_slice(&trailer);
        framed
    }

    /// At least seven different things are called "CRC-16", and the wrong one
    /// still produces a plausible two bytes for every frame — the failure only
    /// shows up as the comms processor dropping everything the controller sends
    /// and neither end saying why. `0x29B1` over the ASCII digits is the value
    /// the world publishes for CCITT-FALSE specifically.
    #[test]
    fn the_check_value_29b1_is_what_makes_this_ccitt_false_and_not_a_near_relative() {
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    /// The other published CCITT-FALSE vector, and the one that catches the
    /// commonest way to get the init wrong: two zero bytes must give `0x1D0F`.
    /// A register started at zero returns `0x0000` here.
    #[test]
    fn two_zero_bytes_give_1d0f_which_a_zero_init_can_never_produce() {
        assert_eq!(crc16(&[0x00, 0x00]), 0x1D0F);
    }

    /// No input is not a zero CRC. Returning `0x0000` for an empty slice is how
    /// a receiver ends up accepting a frame that is nothing but two zero bytes
    /// of "checksum" and a delimiter.
    #[test]
    fn an_empty_message_checksums_to_the_init_not_to_zero() {
        assert_eq!(crc16(&[]), 0xFFFF);
    }

    /// One byte still runs all eight shifts. A loop written `for _ in 1..8` gets
    /// the check value wrong too, but only after nine bytes of drift — this says
    /// it on the first byte, where it is readable.
    #[test]
    fn a_single_byte_runs_all_eight_shifts() {
        assert_eq!(crc16(b"A"), 0xB915);
        assert_eq!(crc16(&[0x00]), 0xE1F0);
        assert_eq!(crc16(&[0xFF]), 0xFF00);
    }

    /// Padding is not free. Every zero byte has to move the register, or a frame
    /// padded out to a buffer boundary carries the same CRC as the frame without
    /// the padding, and a length that got corrupted stops being visible.
    #[test]
    fn runs_of_zeroes_of_different_lengths_do_not_share_a_crc() {
        let zeroes = [0u8; 16];
        let cases = [
            (1usize, 0xE1F0u16),
            (2, 0x1D0F),
            (3, 0xCC9C),
            (4, 0x84C0),
            (8, 0x313E),
            (16, 0x6A0A),
        ];

        let mut seen = [0u16; 6];
        for (slot, (len, want)) in seen.iter_mut().zip(cases.iter()) {
            let run = zeroes.get(..*len).expect("run fits the fixture");
            assert_eq!(crc16(run), *want, "crc of {len} zero bytes");
            *slot = *want;
        }

        for (index, first) in seen.iter().enumerate() {
            for second in seen.iter().skip(index.saturating_add(1)) {
                assert_ne!(first, second, "two zero runs of different length agreed");
            }
        }
    }

    /// The property the framing layer actually leans on. A CRC that agrees with
    /// a corrupted frame is worse than no CRC, because the layer above stops
    /// looking: it hands up an envelope it believes, and one flipped bit in a
    /// setpoint becomes a command nobody asked for. Flip every bit of a
    /// frame-sized message in turn; not one of them may go unnoticed.
    #[test]
    fn every_single_bit_flip_in_a_frame_sized_message_changes_the_crc() {
        let message = pseudorandom_message();
        let clean = crc16(&message);

        let mut compared = 0usize;
        for byte_index in 0..MESSAGE_LEN {
            for bit in 0u8..8 {
                let mut corrupted = message;
                let slot = corrupted.get_mut(byte_index).expect("index is in range");
                *slot ^= 1u8 << bit;
                assert_ne!(
                    crc16(&corrupted),
                    clean,
                    "bit {bit} of byte {byte_index} slipped through"
                );
                compared = compared.saturating_add(1);
            }
        }

        // Two checks in this repo once reported "all pass" while comparing
        // nothing at all. This one states out loud how many comparisons it made.
        assert_eq!(compared, MESSAGE_LEN.saturating_mul(8));
    }

    /// A sum is not a CRC. Anything that folds bytes together without a position
    /// term returns the same value for a frame whose fields arrived transposed,
    /// which is one of the shapes corruption on a shared bus actually takes.
    #[test]
    fn the_same_bytes_in_another_order_are_not_the_same_crc() {
        assert_ne!(crc16(b"AB"), crc16(b"BA"));
        assert_ne!(crc16(&[0x01, 0x02, 0x03]), crc16(&[0x03, 0x02, 0x01]));
    }

    /// The residue trick — checksum the message with its own CRC appended and
    /// expect zero — holds only when the CRC is appended big-endian. Our wire
    /// carries it little-endian, so a receiver written around a zero residue
    /// rejects every good frame and the link looks dead in both directions.
    #[test]
    fn the_wires_little_endian_crc_does_not_leave_a_zero_residue() {
        let message = b"123456789";
        let crc = crc16(message);

        assert_eq!(crc16(&with_trailer(message, crc.to_be_bytes())), 0x0000);
        assert_ne!(crc16(&with_trailer(message, crc.to_le_bytes())), 0x0000);
    }
}
