//! The three HMAC tags on this wire: the pairing refusal (P-241), the `Hello`
//! admission tag (P-238) and the vouch (P-244). The first two are checked
//! before any key agreement, which is the whole reason they are HMACs and not
//! Noise messages: a DH costs this controller a quarter of a second, and these
//! are the two places a peer that has proved nothing gets an answer. The vouch
//! is an HMAC because its reader is a verifier off this wire, long after the
//! session that asked for it.
//!
//! A preimage cannot be started without its label, because `Preimage::under`
//! is the only constructor and it takes a [`Domain`] (P-043). And a key cannot
//! tag a preimage belonging to another: [`RefusalKey`] has the refusal and
//! nothing else, [`AdmitKey`] the admission tag, [`VouchKey`] the vouch.
//!
//! [`Tag`] has no `PartialEq`, so `==` on a tag does not compile. A comparison
//! that stops at the first differing byte is a forgery oracle one byte at a
//! time, and [`Tag::verify`] goes through `subtle` instead.
//!
//! cites: P-041, P-043, P-238, P-241, P-244

use core::fmt;

use hmac::{KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

/// Holds the `subtle` import down: swapping `ct_eq` for `==` in
/// [`Tag::verify`] passes every test, because a timing property is not
/// observable from a test process. Naming the function here makes deleting the
/// dependency a build error rather than a quiet loss.
const _: fn(&[u8], &[u8]) -> subtle::Choice = <[u8] as subtle::ConstantTimeEq>::ct_eq;

type HmacSha256 = hmac::Hmac<Sha256>;

/// An HMAC's state is two SHA-256 cores and a block buffer, and a key passes
/// through them; `sha2`'s `zeroize` feature is what clears them on drop.
const _: () = {
    const fn clears_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    clears_on_drop::<Sha256>();
};

/// Every key here is an HKDF output asked for `L = 32`.
const KEY_BYTES: usize = 32;

/// SHA-256's digest.
const DIGEST_BYTES: usize = 32;

/// SHA-256's block, the width RFC 2104 pads a key to.
const BLOCK_BYTES: usize = 64;

/// P-041's leftmost sixteen: a 128-bit authentication tag.
pub(crate) const TAG_BYTES: usize = 16;

const_assert!(
    TAG_BYTES <= DIGEST_BYTES && KEY_BYTES <= BLOCK_BYTES,
    "the tag is the digest's leftmost bytes and the key is zero-padded to one block; either wider and the zip below silently truncates"
);

/// The three MAC labels of P-043's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Domain {
    /// A pairing refusal (P-241).
    PairRefused,
    /// A `Hello`'s admission tag (P-238).
    HelloAdmit,
    /// A vouch for an enrolment (P-244).
    Vouch,
}

impl Domain {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PairRefused => "km43/v1/pair-refused",
            Self::HelloAdmit => "km43/v1/hello-admit",
            Self::Vouch => "km43/v1/vouch",
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Sixteen bytes of HMAC, and only [`Tag::verify`] may compare them.
#[derive(Clone, Copy)]
pub struct Tag([u8; TAG_BYTES]);

impl Tag {
    /// The bytes, for the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TAG_BYTES] {
        &self.0
    }

    /// Constant time, and a candidate of any other width is refused rather
    /// than compared as a prefix.
    pub fn verify(&self, candidate: &[u8]) -> Result<(), MacError> {
        if candidate.len() != TAG_BYTES {
            return Err(MacError::WrongWidth(candidate.len()));
        }
        if bool::from(self.0.as_slice().ct_eq(candidate)) {
            Ok(())
        } else {
            Err(MacError::Mismatch)
        }
    }
}

/// A tag is not secret, but it is not something to print either: one in a log
/// is one a reader compares by eye, which is the comparison this type exists to
/// stop.
impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tag(16 bytes)")
    }
}

/// Why a tag was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacError {
    /// The candidate was not sixteen bytes.
    WrongWidth(usize),
    /// The candidate was sixteen bytes and not these.
    Mismatch,
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongWidth(len) => write!(f, "a tag is sixteen bytes, not {len}"),
            Self::Mismatch => f.write_str("the tag does not verify"),
        }
    }
}

impl core::error::Error for MacError {}

/// The key a pairing refusal is tagged under, derived from the label (P-088).
///
/// No `Debug` and cleared on drop, like every key in this crate.
pub struct RefusalKey(Zeroizing<[u8; KEY_BYTES]>);

impl RefusalKey {
    pub(crate) const fn new(key: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self(key)
    }

    /// P-241's tag over the handshake hash after message 1 and the outcome.
    #[must_use]
    pub fn refusal(&self, h1: &[u8; KEY_BYTES], outcome: crate::generated::Pair) -> Tag {
        Preimage::under(&self.0, Domain::PairRefused)
            .bytes(h1)
            .bytes(&[outcome as u8])
            .tag()
    }
}

/// One enrolment's admission key: HKDF over `X25519(is, CS)` (P-238).
///
/// The controller stores it in the slot and the client derives it when it needs
/// it; the raw bytes leave only through [`AdmitKey::to_stored`].
pub struct AdmitKey(Zeroizing<[u8; KEY_BYTES]>);

impl AdmitKey {
    pub(crate) const fn new(key: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self(key)
    }

    /// The key as the controller read it back out of a slot.
    #[must_use]
    pub fn from_stored(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The bytes, for the one caller that writes them into a slot.
    #[must_use]
    pub fn to_stored(&self) -> Zeroizing<[u8; KEY_BYTES]> {
        Zeroizing::new(*self.0)
    }

    /// P-238's tag over the prologue and message 1 exactly as it travels.
    #[must_use]
    pub fn admit(&self, prologue: &crate::Prologue, handshake: &[u8]) -> Tag {
        Preimage::under(&self.0, Domain::HelloAdmit)
            .bytes(prologue.as_bytes())
            .bytes(handshake)
            .tag()
    }
}

/// The key one vouch is tagged under: HKDF over `X25519(cs, VS)` (P-244).
///
/// Derived for one answer and dropped with it; nothing stores one, so there is
/// no way in from stored bytes and no way out.
pub struct VouchKey(Zeroizing<[u8; KEY_BYTES]>);

impl VouchKey {
    pub(crate) const fn new(key: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self(key)
    }

    /// P-244's tag over the statement, fields in the order the spec writes them.
    #[must_use]
    pub fn tag(&self, statement: &crate::VouchStatement) -> Tag {
        Preimage::under(&self.0, Domain::Vouch)
            .bytes(statement.device_id.as_bytes())
            .bytes(&statement.epoch.get().to_be_bytes())
            .bytes(&statement.client_id.get().to_be_bytes())
            .bytes(&statement.generation.get().to_be_bytes())
            .bytes(statement.nonce.as_bytes())
            .bytes(statement.binding.as_bytes())
            .tag()
    }
}

/// One preimage under construction: keyed, with its label already fed.
struct Preimage(HmacSha256);

impl Preimage {
    fn under(key: &[u8; KEY_BYTES], domain: Domain) -> Self {
        let mut block = Zeroizing::new([0u8; BLOCK_BYTES]);
        for (slot, &byte) in block.iter_mut().zip(key) {
            *slot = byte;
        }
        let mut mac = HmacSha256::new((&*block).into());
        mac.update(domain.as_str().as_bytes());
        Self(mac)
    }

    fn bytes(mut self, value: &[u8]) -> Self {
        self.0.update(value);
        self
    }

    /// P-041's truncation: the **leftmost** sixteen bytes.
    fn tag(self) -> Tag {
        let mut digest: [u8; DIGEST_BYTES] = self.0.finalize().into_bytes().into();
        let mut out = [0u8; TAG_BYTES];
        for (slot, &byte) in out.iter_mut().zip(&digest) {
            *slot = byte;
        }
        digest.zeroize();
        Tag(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl crate::residue::Unpadded for RefusalKey {}
    impl crate::residue::Unpadded for AdmitKey {}
    impl crate::residue::Unpadded for VouchKey {}
    use crate::generated::Pair;

    /// RFC 4231 test case 2 through the same keyed block this file builds, so
    /// a padding mistake shows up against the world rather than against us.
    #[test]
    fn the_padded_key_is_rfc_4231s_hmac() {
        let mut block = [0u8; BLOCK_BYTES];
        for (slot, &byte) in block.iter_mut().zip(b"Jefe") {
            *slot = byte;
        }
        let mut mac = HmacSha256::new((&block).into());
        mac.update(b"what do ya want for nothing?");
        let digest: [u8; DIGEST_BYTES] = mac.finalize().into_bytes().into();
        assert_eq!(
            digest[..4],
            [0x5b, 0xdc, 0xc1, 0x46],
            "RFC 4231 case 2 begins 5bdcc146"
        );
    }

    /// The two labels are distinct, so a refusal tag is never an admission tag
    /// under the same key bytes.
    #[test]
    fn a_refusal_and_an_admission_under_one_key_differ() {
        let key = Zeroizing::new([0x33; KEY_BYTES]);
        let refusal = RefusalKey::new(key.clone()).refusal(&[0; KEY_BYTES], Pair::WindowClosed);
        let admit = Preimage::under(&key, Domain::HelloAdmit)
            .bytes(&[0; KEY_BYTES])
            .bytes(&[Pair::WindowClosed as u8])
            .tag();
        assert!(refusal.verify(admit.as_bytes()).is_err());
    }

    /// A refusal is bound to its outcome: `window_closed` does not verify as
    /// `table_full`, so the comms processor cannot turn one into the other.
    #[test]
    fn p_241_a_refusal_does_not_verify_under_another_outcome() {
        let key = RefusalKey::new(Zeroizing::new([0x11; KEY_BYTES]));
        let h1 = [0x22; KEY_BYTES];
        let closed = key.refusal(&h1, Pair::WindowClosed);
        let full = key.refusal(&h1, Pair::TableFull);
        assert!(closed.verify(closed.as_bytes()).is_ok());
        assert_eq!(closed.verify(full.as_bytes()), Err(MacError::Mismatch));
    }

    /// A refusal is bound to its attempt: the same outcome over another
    /// message 1's hash does not verify, so a recorded refusal cannot be
    /// replayed onto the next attempt.
    #[test]
    fn p_241_a_refusal_does_not_verify_for_another_attempt() {
        let key = RefusalKey::new(Zeroizing::new([0x11; KEY_BYTES]));
        let first = key.refusal(&[0x22; KEY_BYTES], Pair::WindowClosed);
        let second = key.refusal(&[0x23; KEY_BYTES], Pair::WindowClosed);
        assert_eq!(first.verify(second.as_bytes()), Err(MacError::Mismatch));
    }

    /// Every single-bit flip of a tag is refused, and so is every width that
    /// is not sixteen, including a correct prefix.
    #[test]
    fn every_flipped_bit_and_every_wrong_width_is_refused() {
        let key = RefusalKey::new(Zeroizing::new([0x44; KEY_BYTES]));
        let tag = key.refusal(&[0x55; KEY_BYTES], Pair::TableFull);
        for byte in 0..TAG_BYTES {
            for bit in 0..8 {
                let mut flipped = *tag.as_bytes();
                flipped[byte] ^= 1 << bit;
                assert_eq!(tag.verify(&flipped), Err(MacError::Mismatch));
            }
        }
        assert_eq!(tag.verify(&[]), Err(MacError::WrongWidth(0)));
        assert_eq!(
            tag.verify(&tag.as_bytes()[..15]),
            Err(MacError::WrongWidth(15))
        );
    }

    /// A dropped key leaves nothing behind in the memory it was dropped from:
    /// the refusal key is the label's, and the admission key opens a slot.
    #[test]
    fn a_dropped_key_leaves_nothing_behind() {
        let residue: [u8; KEY_BYTES] =
            crate::residue::after_drop(RefusalKey::new(Zeroizing::new([0x5A; KEY_BYTES])));
        assert_eq!(residue, [0; KEY_BYTES]);
        let residue: [u8; KEY_BYTES] =
            crate::residue::after_drop(AdmitKey::from_stored([0x5A; KEY_BYTES]));
        assert_eq!(residue, [0; KEY_BYTES]);
        let residue: [u8; KEY_BYTES] =
            crate::residue::after_drop(VouchKey::new(Zeroizing::new([0x5A; KEY_BYTES])));
        assert_eq!(residue, [0; KEY_BYTES]);
    }

    /// The vouch label is not the admission label. A client that sends its own
    /// key as the verifier's gets a vouch key over its admission key's IKM, and
    /// the labels are what keep the tag it receives from being one it could
    /// replay as an admission tag (P-043, P-244).
    #[test]
    fn a_vouch_and_an_admission_over_one_preimage_differ() {
        let key = Zeroizing::new([0x66; KEY_BYTES]);
        let vouch = Preimage::under(&key, Domain::Vouch).bytes(&[0x77; 8]).tag();
        let admit = Preimage::under(&key, Domain::HelloAdmit)
            .bytes(&[0x77; 8])
            .tag();
        assert_eq!(vouch.verify(admit.as_bytes()), Err(MacError::Mismatch));
    }
}
