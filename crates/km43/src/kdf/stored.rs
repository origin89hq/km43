//! An enrolment a client keeps across a restart, so a relaunched app says
//! `Hello` again without anybody at the panel.
//!
//! What is kept is the client's own key pair, the controller key it pinned and
//! the suite it enrolled under — never the printed secret, and nothing derived
//! from it (P-222). In v1 a phone that kept the label could mint itself back in
//! after a factory reset; now the label derives no key a session uses, and what
//! a phone keeps is only good for the slot it was stored in.
//!
//! cites: P-222

use core::fmt;

use zeroize::{Zeroize as _, Zeroizing};

use super::{ClientId, DEVICE_ID_BYTES, DeviceId, Epoch, Generation};
use crate::generated::Suite;
use crate::handshake::Discovery;
use crate::mac::AdmitKey;
use crate::noise::{KEY_BYTES, NoiseError, PublicKey, StaticKey};

/// The leading byte of the layout below. A different byte is a layout this
/// build cannot read, and decoding refuses it rather than guessing. Format 1
/// held a label-derived key and is refused on purpose.
const FORMAT: u8 = 2;

/// Format, `device_id`, controller key, client private key, suite, epoch,
/// `client_id` and generation (both 0 while unknown).
const STORED_BYTES: usize = 1 + DEVICE_ID_BYTES + KEY_BYTES + KEY_BYTES + 1 + 4 + 4 + 4;

/// A client's enrolment in memory: its key pair and the controller it pinned.
///
/// No `Debug`, no `Clone`: it holds a private key.
pub struct Enrolment {
    device_id: DeviceId,
    controller: PublicKey,
    key: StaticKey,
    suite: Suite,
    epoch: Epoch,
    slot: Option<(ClientId, Generation)>,
}

impl Enrolment {
    /// What a pairing leaves a client holding once message 2 has checked out
    /// against the label, before it sends message 3 (P-064): the slot is not
    /// known yet, and may never be told if `Enrol 0x93` is lost (P-242).
    #[must_use]
    pub const fn new(
        device_id: DeviceId,
        controller: PublicKey,
        key: StaticKey,
        suite: Suite,
        epoch: Epoch,
    ) -> Self {
        Self {
            device_id,
            controller,
            key,
            suite,
            epoch,
            slot: None,
        }
    }

    /// The same enrolment, now told which slot it holds: by `Enrol 0x93`, or by
    /// the `HelloReport` of a session it opened.
    #[must_use]
    pub const fn with_slot(mut self, client_id: ClientId, generation: Generation) -> Self {
        self.slot = Some((client_id, generation));
        self
    }

    /// Which controller.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// The controller key the client pinned. A `Hello` runs against this one
    /// and never one a `Discover` offered (P-222).
    #[must_use]
    pub const fn controller(&self) -> PublicKey {
        self.controller
    }

    /// The client's own key pair.
    #[must_use]
    pub const fn static_key(&self) -> &StaticKey {
        &self.key
    }

    /// The suite the slot pinned (P-226).
    #[must_use]
    pub const fn suite(&self) -> Suite {
        self.suite
    }

    /// The epoch the enrolment was made in.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The slot and its generation, once the controller has said.
    #[must_use]
    pub const fn slot(&self) -> Option<(ClientId, Generation)> {
        self.slot
    }

    /// P-238's admission key, which the client derives rather than keeps.
    pub fn admit_key(&self) -> Result<AdmitKey, NoiseError> {
        self.key.admit_key(self.device_id, &self.controller)
    }

    /// A copy to keep across a restart.
    #[must_use]
    pub fn stored(&self) -> StoredEnrolment {
        StoredEnrolment {
            device_id: self.device_id,
            controller: self.controller,
            secret: self.key.to_stored(),
            suite: self.suite,
            epoch: self.epoch,
            slot: self.slot,
        }
    }
}

/// An enrolment as it sits in storage: known to belong to some controller, not
/// yet known to belong to the one answering.
///
/// It gives out no key. The only way from here to an [`Enrolment`] is
/// [`StoredEnrolment::restore`], which compares it with a `Discover`:
///
/// ```compile_fail
/// fn key(stored: &km43::StoredEnrolment) -> &km43::StaticKey {
///     stored.static_key()
/// }
/// ```
pub struct StoredEnrolment {
    device_id: DeviceId,
    controller: PublicKey,
    secret: Zeroizing<[u8; KEY_BYTES]>,
    suite: Suite,
    epoch: Epoch,
    slot: Option<(ClientId, Generation)>,
}

impl StoredEnrolment {
    /// The width of every encoding. Storage that hands back a different length
    /// handed back something else.
    pub const LEN: usize = STORED_BYTES;

    /// Write the fixed-width encoding into `dst`. `dst` holds the private key
    /// afterwards, so clear it once storage has it.
    pub fn encode(&self, dst: &mut [u8; Self::LEN]) {
        let epoch = self.epoch.get().to_be_bytes();
        let (client_id, generation) = self
            .slot
            .map_or((0, 0), |(id, generation)| (id.get(), generation.get()));
        let client_id = client_id.to_be_bytes();
        let generation = generation.to_be_bytes();
        let suite = [self.suite as u8];
        let fields = [FORMAT]
            .iter()
            .chain(self.device_id.as_bytes())
            .chain(self.controller.as_bytes())
            .chain(self.secret.iter())
            .chain(&suite)
            .chain(&epoch)
            .chain(&client_id)
            .chain(&generation);
        for (slot, &byte) in dst.iter_mut().zip(fields) {
            *slot = byte;
        }
    }

    /// Read back what [`StoredEnrolment::encode`] wrote, treating the bytes as
    /// anything at all: storage is outside this crate.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoredEnrolmentError> {
        let wrong = StoredEnrolmentError::WrongLength(bytes.len());
        if bytes.len() != STORED_BYTES {
            return Err(wrong);
        }
        let (&format, rest) = bytes.split_first().ok_or(wrong)?;
        if format != FORMAT {
            return Err(StoredEnrolmentError::UnknownFormat(format));
        }
        let (device_id, rest) = rest.split_first_chunk::<DEVICE_ID_BYTES>().ok_or(wrong)?;
        let (controller, rest) = rest.split_first_chunk::<KEY_BYTES>().ok_or(wrong)?;
        let (secret, rest) = rest.split_first_chunk::<KEY_BYTES>().ok_or(wrong)?;
        let (&suite, rest) = rest.split_first().ok_or(wrong)?;
        let (epoch, rest) = rest.split_first_chunk::<4>().ok_or(wrong)?;
        let (client_id, rest) = rest.split_first_chunk::<4>().ok_or(wrong)?;
        let (generation, _) = rest.split_first_chunk::<4>().ok_or(wrong)?;
        let slot = match (
            ClientId::new(u32::from_be_bytes(*client_id)),
            Generation::new(u32::from_be_bytes(*generation)),
        ) {
            (Some(id), Some(generation)) => Some((id, generation)),
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => return Err(StoredEnrolmentError::HalfASlot),
        };
        let mut secret = Zeroizing::new(*secret);
        let decoded = Self {
            device_id: DeviceId::new(*device_id),
            controller: PublicKey::from_bytes(*controller),
            secret: secret.clone(),
            suite: Suite::try_from(suite)
                .map_err(|()| StoredEnrolmentError::UnknownSuite(suite))?,
            epoch: Epoch::new(u32::from_be_bytes(*epoch)).ok_or(StoredEnrolmentError::ZeroEpoch)?,
            slot,
        };
        secret.zeroize();
        Ok(decoded)
    }

    /// The enrolment, if `discovery` is the controller it was made with.
    ///
    /// Only the `device_id` is compared. `Discover` is unauthenticated (P-054),
    /// so a differing epoch is a reason to expect the `Hello` to fail, never a
    /// reason to throw a key away on the strength of a field a relay can
    /// rewrite (P-222); the `Hello` against the pinned controller key is what
    /// decides.
    pub fn restore(&self, discovery: &Discovery<'_>) -> Result<Enrolment, StoredEnrolmentError> {
        if DeviceId::new(discovery.device_id) != self.device_id {
            return Err(StoredEnrolmentError::OtherController);
        }
        Ok(Enrolment {
            device_id: self.device_id,
            controller: self.controller,
            key: StaticKey::from_stored(*self.secret),
            suite: self.suite,
            epoch: self.epoch,
            slot: self.slot,
        })
    }
}

/// Why a stored enrolment could not be read or used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StoredEnrolmentError {
    /// Storage handed back this many bytes rather than [`StoredEnrolment::LEN`].
    WrongLength(usize),
    /// The leading byte names a layout this build does not know.
    UnknownFormat(u8),
    /// A suite this build does not implement.
    UnknownSuite(u8),
    /// The epoch field is zero, which P-085 never allocates.
    ZeroEpoch,
    /// A `client_id` without a generation or the reverse: the two are written
    /// together or not at all.
    HalfASlot,
    /// The stored enrolment belongs to a different `device_id`: try the next
    /// address (P-225).
    OtherController,
}

impl fmt::Display for StoredEnrolmentError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(len) => write!(
                out,
                "stored enrolment is {len} bytes, not {}; pair again",
                StoredEnrolment::LEN
            ),
            Self::UnknownFormat(format) => {
                write!(
                    out,
                    "stored enrolment format {format} is unknown; pair again"
                )
            }
            Self::UnknownSuite(suite) => write!(out, "stored enrolment names suite {suite}"),
            Self::ZeroEpoch => out.write_str("stored enrolment has epoch 0; pair again"),
            Self::HalfASlot => out.write_str("stored enrolment names half a slot; pair again"),
            Self::OtherController => {
                out.write_str("stored enrolment is for another controller; try another address")
            }
        }
    }
}

impl core::error::Error for StoredEnrolmentError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Version;
    use crate::noise::Entropy;

    const DEVICE_ID: [u8; DEVICE_ID_BYTES] = [0xAB; DEVICE_ID_BYTES];

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("a non-zero epoch")
    }

    fn enrolment() -> Enrolment {
        let controller = StaticKey::generate(Entropy::new([0x40; 32])).public();
        Enrolment::new(
            DeviceId::new(DEVICE_ID),
            controller,
            StaticKey::generate(Entropy::new([0x60; 32])),
            Suite::X25519ChachapolySha256,
            epoch(3),
        )
        .with_slot(
            ClientId::new(7).expect("a slot"),
            Generation::new(2).expect("a generation"),
        )
    }

    fn encoded() -> [u8; StoredEnrolment::LEN] {
        let mut out = [0u8; StoredEnrolment::LEN];
        enrolment().stored().encode(&mut out);
        out
    }

    fn discovery(device_id: [u8; DEVICE_ID_BYTES], epoch: Epoch) -> Discovery<'static> {
        Discovery {
            version: Version::V1_0,
            device_id,
            model: "o89-controller",
            provisioned: true,
            pairing_open: false,
            challenge: [0x11; 16],
            epoch,
        }
    }

    /// An app that paired, quit and came back could only pair again. Stored,
    /// encoded, decoded and restored, it must hold the same key and the same
    /// pinned controller, which the admission key is a function of.
    #[test]
    fn p_222_a_restored_enrolment_is_the_one_that_was_stored() {
        let stored = StoredEnrolment::decode(&encoded()).expect("its own encoding decodes");
        let restored = stored
            .restore(&discovery(DEVICE_ID, epoch(3)))
            .expect("the same controller");
        let paired = enrolment();
        assert_eq!(restored.static_key().public(), paired.static_key().public());
        assert_eq!(restored.controller(), paired.controller());
        assert_eq!(restored.slot(), paired.slot());
        let (a, b) = (
            restored.admit_key().expect("contributory"),
            paired.admit_key().expect("contributory"),
        );
        assert_eq!(*a.to_stored(), *b.to_stored());
    }

    /// A differing epoch is not a reason to throw the key away: the `Discover`
    /// saying so is unauthenticated, and a relay that could make a phone forget
    /// its key would send its owner back to the panel on demand (P-222).
    #[test]
    fn p_222_a_differing_epoch_does_not_discard_the_enrolment() {
        let stored = StoredEnrolment::decode(&encoded()).expect("decodes");
        for current in [epoch(4), epoch(2), epoch(u32::MAX)] {
            assert!(stored.restore(&discovery(DEVICE_ID, current)).is_ok());
        }
    }

    /// Two controllers in one app: a key kept for the first is not offered to
    /// the second.
    #[test]
    fn p_222_a_key_for_another_controller_is_refused() {
        let stored = StoredEnrolment::decode(&encoded()).expect("decodes");
        let mut other = DEVICE_ID;
        other[15] ^= 1;
        assert_eq!(
            stored.restore(&discovery(other, epoch(3))).err(),
            Some(StoredEnrolmentError::OtherController)
        );
    }

    /// The layout is pinned field by field: an encoder and decoder that swapped
    /// two fields together would round trip and misread every enrolment kept
    /// before the swap.
    #[test]
    fn the_encoding_is_the_layout_it_claims() {
        let bytes = encoded();
        assert_eq!(bytes[0], FORMAT);
        assert_eq!(bytes[1..17], DEVICE_ID);
        assert_eq!(bytes[17..49], *enrolment().controller().as_bytes());
        assert_eq!(bytes[81], Suite::X25519ChachapolySha256 as u8);
        assert_eq!(bytes[82..86], [0, 0, 0, 3]);
        assert_eq!(bytes[86..90], [0, 0, 0, 7]);
        assert_eq!(bytes[90..94], [0, 0, 0, 2]);
    }

    /// An enrolment whose `Enrol 0x93` was lost has no slot yet (P-242), and it
    /// round trips as one with none rather than as slot zero.
    #[test]
    fn p_242_an_enrolment_with_no_slot_yet_round_trips() {
        let without = Enrolment::new(
            DeviceId::new(DEVICE_ID),
            StaticKey::generate(Entropy::new([0x40; 32])).public(),
            StaticKey::generate(Entropy::new([0x60; 32])),
            Suite::X25519ChachapolySha256,
            epoch(1),
        );
        let mut bytes = [0u8; StoredEnrolment::LEN];
        without.stored().encode(&mut bytes);
        let back = StoredEnrolment::decode(&bytes)
            .expect("decodes")
            .restore(&discovery(DEVICE_ID, epoch(1)))
            .expect("same controller");
        assert_eq!(back.slot(), None);
    }

    /// Every truncation and an extension is refused, and none panics.
    #[test]
    fn every_truncation_and_an_extension_is_refused() {
        let full = encoded();
        for len in 0..StoredEnrolment::LEN {
            assert_eq!(
                StoredEnrolment::decode(&full[..len]).err(),
                Some(StoredEnrolmentError::WrongLength(len))
            );
        }
        let mut longer = [0u8; StoredEnrolment::LEN + 1];
        longer[..StoredEnrolment::LEN].copy_from_slice(&full);
        assert_eq!(
            StoredEnrolment::decode(&longer).err(),
            Some(StoredEnrolmentError::WrongLength(StoredEnrolment::LEN + 1))
        );
    }

    /// Format 1 held a label-derived key: a build that read it would be sending
    /// a key no controller holds any more. Every byte but this format's is
    /// refused.
    #[test]
    fn every_other_format_byte_is_refused() {
        for format in (0..=u8::MAX).filter(|&f| f != FORMAT) {
            let mut bytes = encoded();
            bytes[0] = format;
            assert_eq!(
                StoredEnrolment::decode(&bytes).err(),
                Some(StoredEnrolmentError::UnknownFormat(format))
            );
        }
    }

    /// Zero is not an epoch; a slot without a generation is half a write; an
    /// unknown suite is not one this build can run.
    #[test]
    fn a_zero_epoch_half_a_slot_and_an_unknown_suite_are_refused() {
        let mut bytes = encoded();
        bytes[82..86].fill(0);
        assert_eq!(
            StoredEnrolment::decode(&bytes).err(),
            Some(StoredEnrolmentError::ZeroEpoch)
        );
        let mut bytes = encoded();
        bytes[90..94].fill(0);
        assert_eq!(
            StoredEnrolment::decode(&bytes).err(),
            Some(StoredEnrolmentError::HalfASlot)
        );
        let mut bytes = encoded();
        bytes[81] = 9;
        assert_eq!(
            StoredEnrolment::decode(&bytes).err(),
            Some(StoredEnrolmentError::UnknownSuite(9))
        );
    }

    /// P-222: nothing the label derives reaches storage. A client that paired
    /// under a label whose secret is a run of `0xCD` keeps an enrolment with no
    /// byte of that secret, of the pre-shared key or of the refusal key in it —
    /// the stored form is a key pair and a pinned key, and the label is gone.
    #[test]
    fn p_222_the_stored_bytes_carry_no_printed_secret() {
        use crate::kdf::{Label, PrintedSecret};
        let label = Label::new(DeviceId::new(DEVICE_ID), PrintedSecret::new([0xCD; 32]));
        let _ = (label.pair_psk(), label.refusal_key());
        let bytes = encoded();
        assert!(
            !bytes.windows(4).any(|w| w == [0xCD; 4]),
            "a printed-secret run reached storage: {bytes:02x?}"
        );
        assert_eq!(
            StoredEnrolment::LEN,
            94,
            "format, id, two keys, suite and three u32"
        );
    }
}
