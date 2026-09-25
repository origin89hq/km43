//! What the printed label is still allowed to derive, and the identifiers an
//! enrolment is named by.
//!
//! The label derives two keys and nothing else (P-088): the pre-shared key a
//! pairing handshake mixes in first, and the key a pairing refusal is tagged
//! under. In v1 it derived every client's key at every epoch, so a label
//! photographed once held every slot for the life of the unit. Every other key
//! now comes from a handshake or from the controller's own random bit generator
//! ([`crate::Drbg`]), and a [`Label`] has no method that could mint one.
//!
//! Every derivation is HKDF-SHA256 with `salt`, `IKM` and `info` passed
//! **separately** (P-042), which is why the two extract arguments are two
//! newtypes rather than two `&[u8]` in a row.
//!
//! cites: P-042, P-043, P-044, P-085, P-086, P-088, P-236, P-244

use core::fmt;
use core::num::NonZeroU32;

use hkdf::HkdfExtract;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::mac::{AdmitKey, RefusalKey, VouchKey};
use crate::noise::{KEY_BYTES, Psk, PublicKey};

mod stored;
pub use stored::*;

/// P-044's entropy, decoded from the QR code's 64 characters.
const PRINTED_SECRET_BYTES: usize = 32;

/// P-038's `device_id`, as the 16 bytes and never their hex rendering.
pub(crate) const DEVICE_ID_BYTES: usize = 16;

/// SHA-256's digest, which is HKDF's `HashLen`.
const DIGEST_BYTES: usize = 32;

/// P-236's fingerprint: the leftmost sixteen bytes of a SHA-256.
pub const FINGERPRINT_BYTES: usize = 16;

/// RFC 5869 §2.3's counter byte. `T(1)` is the only block computed here.
const FIRST_BLOCK: u8 = 1;

const_assert!(
    KEY_BYTES == DIGEST_BYTES,
    "the expand here stops at T(1); a wider key needs T(2)"
);

/// The four HKDF `info` labels of P-043's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Derivation {
    /// The pairing's pre-shared key (P-088).
    PairPsk,
    /// The key a pairing refusal is tagged under (P-241).
    PairRefusal,
    /// One enrolment's admission key (P-238).
    AdmitKey,
    /// The key one vouch is tagged under (P-244).
    VouchKey,
}

impl Derivation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PairPsk => "km43/v1/pair-psk",
            Self::PairRefusal => "km43/v1/pair-refusal",
            Self::AdmitKey => "km43/v1/admit-key",
            Self::VouchKey => "km43/v1/vouch-key",
        }
    }
}

impl fmt::Display for Derivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// P-044's 32 bytes of entropy — the decoded QR payload, never the printed
/// text, and never a key itself (P-088).
///
/// No `Debug`, and cleared on drop, so a client that clears its own copy is not
/// left with this one in freed memory.
pub struct PrintedSecret([u8; PRINTED_SECRET_BYTES]);

impl PrintedSecret {
    /// The decoded 32 bytes of P-044, not the 64 characters they print as.
    #[must_use]
    pub const fn new(bytes: [u8; PRINTED_SECRET_BYTES]) -> Self {
        Self(bytes)
    }
}

impl Drop for PrintedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// P-038's sixteen bytes, as bytes and never their hex rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceId([u8; DEVICE_ID_BYTES]);

impl DeviceId {
    /// The 16 bytes of P-038, not the 32 characters the QR code prints.
    #[must_use]
    pub const fn new(bytes: [u8; DEVICE_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// The bytes, for a prologue or a salt.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEVICE_ID_BYTES] {
        &self.0
    }
}

/// P-085's factory-reset counter, and the ownership generation a site's
/// history is keyed by.
///
/// Zero is not an epoch: it starts at 1 and only ever climbs, so a zero is FRAM
/// nobody wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Epoch(NonZeroU32);

impl Epoch {
    /// What a unit leaves the factory holding (P-085).
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// The counter as it was read back out of FRAM, or nothing if that read
    /// gave a zero.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(epoch) => Some(Self(epoch)),
            None => None,
        }
    }

    /// The counter as it goes into a `Discover` answer and a prologue.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// P-086's slot index in the client table, counting from 1.
///
/// Zero is what the wire carries when nobody was enrolled, so it names no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientId(NonZeroU32);

impl ClientId {
    /// The slot P-086 allocated, or nothing if the caller passed the zero that
    /// means *no client*.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    /// The number as it goes on the wire.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Where this client's row sits in a table that holds one per slot. P-086
    /// counts from one, so every such table subtracts one, here and nowhere
    /// else. `None` is a `client_id` too large for this machine's `usize`.
    #[must_use]
    pub fn slot(self) -> Option<usize> {
        usize::try_from(self.0.get().saturating_sub(1)).ok()
    }
}

/// How many times a slot has been re-keyed (P-239). With the epoch and the
/// `client_id` it names one enrolment and never a second.
///
/// Zero is a slot that was never written, so no enrolment carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Generation(NonZeroU32);

impl Generation {
    /// The generation of a slot's first enrolment.
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// The generation as it was read back, or nothing for a zero.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(generation) => Some(Self(generation)),
            None => None,
        }
    }

    /// The number as it goes on the wire.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// The generation a re-key writes, or nothing when this one is the last a
    /// `u32` holds: P-239 refuses to issue a generation twice, so a slot that
    /// has reached the top is a slot that cannot be written again.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// The two things P-049's QR code carries that a key is derived from: the
/// `device_id` and the `printed_secret`.
///
/// It derives the pairing's two keys and nothing else. Dropping it clears the
/// printed secret; the `device_id` is printed on the label and left alone.
pub struct Label {
    device_id: DeviceId,
    printed_secret: PrintedSecret,
}

impl Label {
    /// The pair a controller reads out of its own store, or a client decodes
    /// from the QR code it has just scanned.
    #[must_use]
    pub const fn new(device_id: DeviceId, printed_secret: PrintedSecret) -> Self {
        Self {
            device_id,
            printed_secret,
        }
    }

    /// Which controller the label is stuck to.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The pre-shared key a pairing handshake mixes in first (P-088).
    #[must_use]
    pub fn pair_psk(&self) -> Psk {
        Psk::new(self.derive(Derivation::PairPsk))
    }

    /// The key a pairing refusal is tagged under (P-241).
    #[must_use]
    pub fn refusal_key(&self) -> RefusalKey {
        RefusalKey::new(self.derive(Derivation::PairRefusal))
    }

    fn derive(&self, derivation: Derivation) -> Zeroizing<[u8; KEY_BYTES]> {
        Prk::of(Salt(&self.device_id.0), Ikm(&self.printed_secret.0))
            .expand(derivation)
            .key()
    }
}

/// P-238's admission key from the DH both ends can compute.
pub(crate) fn admit_key(device_id: DeviceId, shared: &[u8; KEY_BYTES]) -> AdmitKey {
    AdmitKey::new(
        Prk::of(Salt(&device_id.0), Ikm(shared))
            .expand(Derivation::AdmitKey)
            .key(),
    )
}

/// P-244's vouch key from the DH between the controller and one verifier.
pub(crate) fn vouch_key(device_id: DeviceId, shared: &[u8; KEY_BYTES]) -> VouchKey {
    VouchKey::new(
        Prk::of(Salt(&device_id.0), Ikm(shared))
            .expand(Derivation::VouchKey)
            .key(),
    )
}

/// The fingerprint of a controller key that P-236 prints on the label.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; FINGERPRINT_BYTES]);

impl Fingerprint {
    /// The label prefix of P-043's table, which is a hash prefix.
    const LABEL: &'static [u8] = b"km43/v1/controller-fp";

    /// `SHA-256("km43/v1/controller-fp" | CS)[0..16]`.
    #[must_use]
    pub fn of(controller: &PublicKey) -> Self {
        let mut digest = Sha256::new();
        digest.update(Self::LABEL);
        digest.update(controller.as_bytes());
        let full: [u8; DIGEST_BYTES] = digest.finalize().into();
        let mut out = [0u8; FINGERPRINT_BYTES];
        for (slot, &byte) in out.iter_mut().zip(&full) {
            *slot = byte;
        }
        Self(out)
    }

    /// The sixteen bytes a label printed.
    #[must_use]
    pub const fn from_label(bytes: [u8; FINGERPRINT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Whether `controller` is the key this label vouches for. Constant time,
    /// though nothing here is secret, so the comparison reads the same as
    /// every other one in the crate.
    #[must_use]
    pub fn vouches_for(&self, controller: &PublicKey) -> bool {
        bool::from(self.0.ct_eq(&Self::of(controller).0))
    }

    /// The bytes, for printing.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_BYTES] {
        &self.0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fingerprint(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// RFC 5869's `salt`, named so it cannot be passed as the IKM.
#[derive(Clone, Copy)]
struct Salt<'a>(&'a [u8]);

/// RFC 5869's `IKM`, named for the same reason.
#[derive(Clone, Copy)]
struct Ikm<'a>(&'a [u8]);

/// RFC 5869 §2.2's pseudorandom key, cleared on drop.
struct Prk([u8; DIGEST_BYTES]);

impl Drop for Prk {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Prk {
    fn of(salt: Salt<'_>, ikm: Ikm<'_>) -> Self {
        let mut extract = HkdfExtract::<Sha256>::new(Some(salt.0));
        extract.input_ikm(ikm.0);
        Self(extract.finalize().0.into())
    }

    /// Opens an `info` with P-043's label, which is the only way a derivation
    /// here begins.
    fn expand(&self, derivation: Derivation) -> Expand {
        let mut extract = HkdfExtract::<Sha256>::new(Some(&self.0));
        extract.input_ikm(derivation.as_str().as_bytes());
        Expand(extract)
    }
}

/// One `info` under construction.
struct Expand(HkdfExtract<Sha256>);

impl Expand {
    /// RFC 5869 §2.3 at `L` = `HashLen`: `T(1) = HMAC(PRK, info | 0x01)`.
    /// Going through extract removes a `Result` whose only arm, `L > 255 ×
    /// HashLen`, cannot happen against a fixed 32-byte array.
    fn key(mut self) -> Zeroizing<[u8; KEY_BYTES]> {
        self.0.input_ikm(&[FIRST_BLOCK]);
        Zeroizing::new(self.0.finalize().0.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl crate::residue::Unpadded for PrintedSecret {}
    impl crate::residue::Unpadded for Label {}

    /// The expand is RFC 5869's with the counter byte appended, checked against
    /// test case 1 of the RFC: a derivation that is HKDF-shaped and not HKDF
    /// agrees with itself and nobody else.
    #[test]
    fn the_expand_is_rfc_5869_test_case_1() {
        let salt: [u8; 13] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
        let prk = Prk::of(Salt(&salt), Ikm(&[0x0b; 22]));
        let mut extract = HkdfExtract::<Sha256>::new(Some(&prk.0));
        extract.input_ikm(&[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
        let t1: [u8; 32] = *Expand(extract).key();
        assert_eq!(
            t1[..8],
            [0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a],
            "RFC 5869 A.1's OKM begins 3cb25f25faacd57a"
        );
    }

    /// The label's two keys differ: one label, one `info` each. A refusal key
    /// equal to the pre-shared key would make the refusal tag an oracle on the
    /// key that opens message 1.
    #[test]
    fn p_088_the_label_derives_two_distinct_keys() {
        let label = Label::new(DeviceId::new([0xAB; 16]), PrintedSecret::new([0xCD; 32]));
        let psk = label.derive(Derivation::PairPsk);
        let refusal = label.derive(Derivation::PairRefusal);
        assert_ne!(*psk, *refusal);
    }

    /// The `device_id` salts both: two units whose labels were printed with the
    /// same secret by mistake still pair under different keys.
    #[test]
    fn the_device_id_salts_the_label_keys() {
        let one = Label::new(DeviceId::new([0x01; 16]), PrintedSecret::new([0xCD; 32]));
        let two = Label::new(DeviceId::new([0x02; 16]), PrintedSecret::new([0xCD; 32]));
        assert_ne!(
            *one.derive(Derivation::PairPsk),
            *two.derive(Derivation::PairPsk)
        );
    }

    /// A fingerprint vouches for its own key and for no other, including one
    /// that differs in a single bit.
    #[test]
    fn p_236_a_fingerprint_vouches_for_one_key() {
        let key = PublicKey::from_bytes([0x42; KEY_BYTES]);
        let fp = Fingerprint::of(&key);
        assert!(fp.vouches_for(&key));
        let mut other = [0x42; KEY_BYTES];
        other[31] ^= 1;
        assert!(!fp.vouches_for(&PublicKey::from_bytes(other)));
        assert!(!Fingerprint::from_label([0; FINGERPRINT_BYTES]).vouches_for(&key));
    }

    /// A generation climbs and stops at the top rather than wrapping to a
    /// value an earlier enrolment already had.
    #[test]
    fn p_239_a_generation_never_wraps() {
        assert_eq!(
            Generation::FIRST.next().map(Generation::get),
            Some(2),
            "one re-key after the first enrolment"
        );
        let last = Generation::new(u32::MAX).expect("non-zero");
        assert_eq!(last.next(), None);
        assert_eq!(Generation::new(0), None, "zero is a slot never written");
    }

    /// Zero is refused for all three identifiers: an unwritten epoch, no slot,
    /// a slot never written.
    #[test]
    fn a_zero_names_nothing() {
        assert_eq!(Epoch::new(0), None);
        assert_eq!(ClientId::new(0), None);
        assert_eq!(Generation::new(0), None);
        assert_eq!(ClientId::new(1).and_then(ClientId::slot), Some(0));
    }

    /// The printed secret is the one thing on the label that is secret; a
    /// dropped copy leaves nothing behind, and neither does a dropped label.
    #[test]
    fn p_088_a_dropped_printed_secret_leaves_nothing_behind() {
        let residue: [u8; 32] = crate::residue::after_drop(PrintedSecret::new([0xCD; 32]));
        assert_eq!(residue, [0; 32]);
        let residue: [u8; 48] = crate::residue::after_drop(Label::new(
            DeviceId::new([0xAB; 16]),
            PrintedSecret::new([0xCD; 32]),
        ));
        assert!(
            !residue.contains(&0xCD),
            "the printed secret survived: {residue:02x?}"
        );
    }
}
