//! The controller's random bit generator, because the part it runs on has none.
//!
//! Every ephemeral key and every challenge the controller uses is a draw from
//! here (P-237). The state is thirty-two bytes written at manufacture, and each
//! draw replaces it with a one-way function of itself before the draw may be
//! used, so a state read out with a probe yields the draws after it and none
//! before.
//!
//! The rule that is easy to get wrong is the order: the advanced state has to be
//! durable before the draw is used, or a reset at the wrong moment draws the
//! same value again — the same challenge, the same ephemeral, and a recorded
//! `Hello` accepted a second time. So [`Drbg::draw`] takes the storage itself,
//! as a [`DrbgStore`], writes the advanced state, reads it back, compares, and
//! only then hands out the draw. There is no way to a draw that skips the
//! store:
//!
//! ```compile_fail
//! fn early(drbg: km43::Drbg) -> km43::Entropy { drbg.draw().1 }
//! ```
//!
//! What the crate cannot check is that the store is durable: a `DrbgStore` that
//! keeps the state in RAM satisfies the type and not P-237.
//!
//! cites: P-237

use core::fmt;

use hmac::{KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::noise::{Entropy, KEY_BYTES};

type HmacSha256 = hmac::Hmac<Sha256>;

/// SHA-256's block, the width a 32-byte HMAC key is zero-padded to.
const BLOCK_BYTES: usize = 64;

/// What separates a draw from the state that replaces it. Controller-local:
/// no other implementation computes these, so they are not in P-043's table.
const OUT: &[u8] = b"km43/v1/drbg-out";
const NEXT: &[u8] = b"km43/v1/drbg-next";

/// The generator between draws. No `Debug`, no `Clone`: a copy is a second
/// generator that will draw what this one draws.
pub struct Drbg {
    state: Zeroizing<[u8; KEY_BYTES]>,
}

impl Drbg {
    /// The state as it was read back out of storage, whole and checked by the
    /// caller's own integrity check. A state that cannot be read back intact
    /// is P-237's refusal and never a fresh one: re-initialising is how every
    /// unit returns to the sequence it started with.
    #[must_use]
    pub fn from_stored(state: [u8; KEY_BYTES]) -> Self {
        Self {
            state: Zeroizing::new(state),
        }
    }

    /// Advance the state, write it to `store`, read it back, and release one
    /// draw only if the read-back is the state that was written. On any
    /// failure the generator is gone: P-237 refuses every `Pair` and `Hello`
    /// until a state can be read back, and the caller starts again from
    /// [`Drbg::from_stored`] over what the store holds.
    pub fn draw<S: DrbgStore>(self, store: &mut S) -> Result<(Self, Entropy), DrbgError> {
        self.draw_mixing(&[], store)
    }

    /// The same, folding `extra` into the next state: ADC noise, or bytes the
    /// comms processor offered. It passes through the secret state, so a source
    /// that is known or chosen by somebody else adds nothing and takes nothing
    /// away.
    pub fn draw_mixing<S: DrbgStore>(
        self,
        extra: &[u8],
        store: &mut S,
    ) -> Result<(Self, Entropy), DrbgError> {
        let next = keyed(&self.state, &[NEXT, extra]);
        let out = keyed(&self.state, &[OUT]);
        store.write(&next).map_err(|_| DrbgError::NotStored)?;
        let read_back = Zeroizing::new(store.read().map_err(|_| DrbgError::NotStored)?);
        if !bool::from(next.as_slice().ct_eq(read_back.as_slice())) {
            return Err(DrbgError::NotStored);
        }
        Ok((Self { state: next }, Entropy::new(*out)))
    }
}

/// Where the generator's state lives between draws: FRAM on the controller.
///
/// `write` must reach durable storage before it returns, and `read` must read
/// it back from there rather than from a copy in RAM; [`Drbg::draw`] compares
/// the two and will not release a draw whose successor is not what was read.
pub trait DrbgStore {
    /// Why a write or read failed. Only its occurrence matters here.
    type Error;

    /// Persist `state`.
    fn write(&mut self, state: &[u8; KEY_BYTES]) -> Result<(), Self::Error>;

    /// Read the state back.
    fn read(&mut self) -> Result<[u8; KEY_BYTES], Self::Error>;
}

/// HMAC-SHA256 keyed by the state, over `parts` joined.
fn keyed(state: &[u8; KEY_BYTES], parts: &[&[u8]]) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut block = Zeroizing::new([0u8; BLOCK_BYTES]);
    for (slot, &byte) in block.iter_mut().zip(state) {
        *slot = byte;
    }
    let mut mac = HmacSha256::new((&*block).into());
    for part in parts {
        mac.update(part);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// Why a draw was withheld.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DrbgError {
    /// The advanced state did not read back as written. P-237: refuse every
    /// `Pair` and `Hello`, and raise the class A concern.
    NotStored,
}

impl fmt::Display for DrbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the advanced generator state did not read back as written")
    }
}

impl core::error::Error for DrbgError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store that keeps what it was given, or a fault injected into it.
    #[derive(Default)]
    struct Fram {
        state: [u8; KEY_BYTES],
        lose_writes: bool,
        fail_reads: bool,
    }

    impl DrbgStore for Fram {
        type Error = ();
        fn write(&mut self, state: &[u8; KEY_BYTES]) -> Result<(), ()> {
            if !self.lose_writes {
                self.state = *state;
            }
            Ok(())
        }
        fn read(&mut self) -> Result<[u8; KEY_BYTES], ()> {
            if self.fail_reads {
                Err(())
            } else {
                Ok(self.state)
            }
        }
    }

    /// Successive draws differ, and a generator restarted from what the store
    /// holds carries on where the first left off rather than repeating it.
    #[test]
    fn p_237_draws_never_repeat_across_a_restart() {
        let mut fram = Fram {
            state: [7; 32],
            ..Fram::default()
        };
        let mut drbg = Drbg::from_stored(fram.state);
        let mut seen = [[0u8; 16]; 32];
        for i in 0..16 {
            let (next, out) = drbg.draw(&mut fram).expect("stored");
            seen[i] = out.into_challenge();
            assert!(!seen[..i].contains(&seen[i]), "draw {i} repeated");
            drbg = next;
        }
        // A reset: the generator in RAM is gone, and the store is what is left.
        let mut drbg = Drbg::from_stored(fram.state);
        for i in 16..32 {
            let (next, out) = drbg.draw(&mut fram).expect("stored");
            seen[i] = out.into_challenge();
            assert!(
                !seen[..i].contains(&seen[i]),
                "draw {i} repeated after a restart"
            );
            drbg = next;
        }
    }

    /// A write that did not land withholds the draw: the next boot would read
    /// the old state and draw this value again.
    #[test]
    fn p_237_a_draw_whose_state_did_not_read_back_is_withheld() {
        let mut lost = Fram {
            state: [9; 32],
            lose_writes: true,
            ..Fram::default()
        };
        assert_eq!(
            Drbg::from_stored([9; 32]).draw(&mut lost).err(),
            Some(DrbgError::NotStored)
        );
        let mut unreadable = Fram {
            state: [9; 32],
            fail_reads: true,
            ..Fram::default()
        };
        assert_eq!(
            Drbg::from_stored([9; 32]).draw(&mut unreadable).err(),
            Some(DrbgError::NotStored)
        );
    }

    /// The draw is not the state that follows it, so a draw published as a
    /// challenge in every `Discover` says nothing about the next one.
    #[test]
    fn a_draw_is_not_the_state_it_leaves_behind() {
        let mut fram = Fram {
            state: [3; 32],
            ..Fram::default()
        };
        let (_, out) = Drbg::from_stored([3; 32]).draw(&mut fram).expect("stored");
        assert_ne!(out.into_challenge()[..], fram.state[..16]);
    }

    /// Mixing changes the sequence after it, whatever the bytes: a comms
    /// processor offering zeros still moves the state somewhere it cannot
    /// predict without the state.
    #[test]
    fn mixed_bytes_move_the_next_state() {
        let mut plain = Fram::default();
        let mut mixed = Fram::default();
        Drbg::from_stored([5; 32]).draw(&mut plain).expect("stored");
        Drbg::from_stored([5; 32])
            .draw_mixing(&[0; 32], &mut mixed)
            .expect("stored");
        assert_ne!(plain.state, mixed.state);
    }
}
