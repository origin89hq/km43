//! An enrolment a client can write to its own secure storage and read back
//! after a restart, so a relaunched app does not need a pairing window to say
//! `Hello` again.
//!
//! What is stored is the one key the controller issued, never the printed
//! secret it came from (P-222). That secret derives a key for every slot at
//! every epoch, so a phone that kept it could mint itself back in after a
//! factory reset, which is the thing P-085 exists to stop. A stored key is
//! scoped to one `device_id`, one `epoch` and one `client_id`, and restoring it
//! checks the first two against the controller that is answering.
//!
//! cites: P-222

use core::fmt;

use zeroize::Zeroize as _;

use super::{ClientId, DERIVED_KEY_BYTES, DEVICE_ID_BYTES, DeviceId, Enrolment, Epoch};
use crate::handshake::Discovery;

/// The leading byte of the layout below. A different byte is a layout this
/// build cannot read, and decoding refuses it rather than guessing.
const FORMAT_V1: u8 = 1;

/// Format, `device_id`, `epoch`, `client_id`, key.
const STORED_BYTES: usize = 1 + DEVICE_ID_BYTES + 4 + 4 + DERIVED_KEY_BYTES;

/// A client's enrolment as it sits in storage: known to have been derived for
/// some controller, not yet known to belong to the one that is answering.
///
/// It gives out no key. The only way from here to an [`Enrolment`] is
/// [`StoredEnrolment::restore`], which compares it with a `Discover`, so a key
/// kept for another controller or an earlier epoch cannot be sent by mistake:
///
/// ```compile_fail
/// fn key(stored: &km43::StoredEnrolment) -> km43::ClientKey {
///     stored.client_key()
/// }
/// ```
///
/// No `Debug`, and the key is cleared on drop, for the reasons the other keys
/// have neither.
pub struct StoredEnrolment {
    device_id: DeviceId,
    epoch: Epoch,
    client_id: ClientId,
    key: [u8; DERIVED_KEY_BYTES],
}

impl Drop for StoredEnrolment {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Enrolment {
    /// A copy of this enrolment to keep across a restart, taken right after
    /// `Pair` succeeds and before the printed secret is thrown away.
    #[must_use]
    pub const fn stored(&self) -> StoredEnrolment {
        StoredEnrolment {
            device_id: self.device_id,
            epoch: self.epoch,
            client_id: self.client_id,
            key: self.key,
        }
    }
}

impl StoredEnrolment {
    /// The width of every encoding. Storage that hands back a different length
    /// handed back something else.
    pub const LEN: usize = STORED_BYTES;

    /// Write the fixed-width encoding into `dst`: a format byte, the 16-byte
    /// `device_id`, `epoch` and `client_id` as big-endian `u32`, then the key.
    ///
    /// `dst` holds the key afterwards, so clear it once it has been handed to
    /// storage.
    pub fn encode(&self, dst: &mut [u8; Self::LEN]) {
        let epoch = self.epoch.get().to_be_bytes();
        let client_id = self.client_id.get().to_be_bytes();
        let fields = [FORMAT_V1]
            .iter()
            .chain(&self.device_id.0)
            .chain(&epoch)
            .chain(&client_id)
            .chain(&self.key);
        for (slot, &byte) in dst.iter_mut().zip(fields) {
            *slot = byte;
        }
    }

    /// Read back what [`StoredEnrolment::encode`] wrote.
    ///
    /// Storage is outside this crate, so the bytes are treated as anything at
    /// all: a wrong length, a format this build does not know, and a zero
    /// `epoch` or `client_id` are refused, and nothing here panics on them.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoredEnrolmentError> {
        let wrong = StoredEnrolmentError::WrongLength(bytes.len());
        if bytes.len() != STORED_BYTES {
            return Err(wrong);
        }
        let (&format, rest) = bytes.split_first().ok_or(wrong)?;
        if format != FORMAT_V1 {
            return Err(StoredEnrolmentError::UnknownFormat(format));
        }
        let (device_id, rest) = rest.split_first_chunk::<DEVICE_ID_BYTES>().ok_or(wrong)?;
        let (epoch, rest) = rest.split_first_chunk::<4>().ok_or(wrong)?;
        let (client_id, rest) = rest.split_first_chunk::<4>().ok_or(wrong)?;
        let (key, _) = rest.split_first_chunk::<DERIVED_KEY_BYTES>().ok_or(wrong)?;
        Ok(Self {
            device_id: DeviceId::new(*device_id),
            epoch: Epoch::new(u32::from_be_bytes(*epoch)).ok_or(StoredEnrolmentError::ZeroEpoch)?,
            client_id: ClientId::new(u32::from_be_bytes(*client_id))
                .ok_or(StoredEnrolmentError::ZeroClientId)?,
            key: *key,
        })
    }

    /// The enrolment, if `discovery` is the controller and the epoch it was
    /// derived for.
    ///
    /// `Discover` carries no MAC (P-054), so this guards against the wrong
    /// controller or a factory reset, not against a relay: the `Hello` proof is
    /// what the controller checks. Either error means pair again.
    pub fn restore(&self, discovery: &Discovery<'_>) -> Result<Enrolment, StoredEnrolmentError> {
        if DeviceId::new(discovery.device_id) != self.device_id {
            return Err(StoredEnrolmentError::OtherController);
        }
        if discovery.epoch != self.epoch {
            return Err(StoredEnrolmentError::OtherEpoch {
                stored: self.epoch,
                current: discovery.epoch,
            });
        }
        Ok(Enrolment {
            device_id: self.device_id,
            epoch: self.epoch,
            client_id: self.client_id,
            key: self.key,
        })
    }
}

/// Why a stored enrolment could not be read or used. Every variant ends the
/// same way for the client, which is pairing again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StoredEnrolmentError {
    /// Storage handed back this many bytes rather than
    /// [`StoredEnrolment::LEN`].
    WrongLength(usize),
    /// The leading byte names a layout this build does not know.
    UnknownFormat(u8),
    /// The epoch field is zero, which P-085 never allocates.
    ZeroEpoch,
    /// The `client_id` field is zero, which names no slot (P-086).
    ZeroClientId,
    /// The stored key belongs to a different `device_id`.
    OtherController,
    /// The controller has been factory reset since, or reports an epoch
    /// behind the one the key was derived at (P-085, P-087).
    OtherEpoch {
        /// The epoch the key was derived at.
        stored: Epoch,
        /// The epoch the controller's `Discover` reports.
        current: Epoch,
    },
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
            Self::ZeroEpoch => out.write_str("stored enrolment has epoch 0; pair again"),
            Self::ZeroClientId => out.write_str("stored enrolment has client_id 0; pair again"),
            Self::OtherController => {
                out.write_str("stored enrolment is for another controller; pair again")
            }
            Self::OtherEpoch { stored, current } => write!(
                out,
                "stored enrolment is for epoch {}, the controller is at epoch {}; pair again",
                stored.get(),
                current.get()
            ),
        }
    }
}

impl core::error::Error for StoredEnrolmentError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Version;
    use crate::kdf::{DeviceSecret, PrintedSecret};
    use crate::mac::HelloProof;

    const DEVICE_ID: [u8; DEVICE_ID_BYTES] = [0xAB; DEVICE_ID_BYTES];
    const CLIENT_ID: u32 = 7;

    fn device() -> DeviceSecret {
        DeviceSecret::new(DeviceId::new(DEVICE_ID), PrintedSecret::new([0xCD; 32]))
    }

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("a non-zero epoch")
    }

    fn enrolment() -> Enrolment {
        device().enrolment(epoch(3), ClientId::new(CLIENT_ID).expect("seven is a slot"))
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

    /// Two enrolments hold the same key when they prove the same `Hello`
    /// identically. `Tag` has no `PartialEq`, so the proof is compared through
    /// the one comparison it offers.
    fn same_key(a: &Enrolment, b: &Enrolment) -> bool {
        let fields = HelloProof {
            challenge: &[0x11; 16],
            client_nonce: &[0x22; 16],
            client_id: CLIENT_ID,
            payload: b"hello",
        };
        a.client_key()
            .hello_proof(&fields)
            .verify(b.client_key().hello_proof(&fields).as_bytes())
            .is_ok()
    }

    /// The failure the issue came from: an app that paired, quit and came back
    /// could only pair again. Stored, encoded, decoded and restored, the key
    /// has to prove a `Hello` exactly as the one derived at pairing did.
    #[test]
    fn a_restored_enrolment_proves_hello_as_the_paired_one_did() {
        let stored = StoredEnrolment::decode(&encoded()).expect("its own encoding decodes");
        let restored = stored
            .restore(&discovery(DEVICE_ID, epoch(3)))
            .expect("the same controller at the same epoch");
        let paired = enrolment();
        assert_eq!(restored.client_id(), paired.client_id());
        assert!(
            same_key(&restored, &paired),
            "the restored key is not the paired one"
        );
    }

    /// The layout is what another build of this crate reads back after an app
    /// update, so it is pinned here field by field rather than only round
    /// tripped: an encoder and decoder that swapped `epoch` and `client_id`
    /// together would round trip and still misread every stored enrolment
    /// written before the swap.
    #[test]
    fn the_encoding_is_format_device_id_epoch_client_id_key() {
        let bytes = encoded();
        let (format, rest) = bytes.split_first().expect("not empty");
        assert_eq!(*format, FORMAT_V1);
        let (device_id, rest) = rest.split_first_chunk::<16>().expect("device_id");
        assert_eq!(*device_id, DEVICE_ID);
        let (epoch, rest) = rest.split_first_chunk::<4>().expect("epoch");
        assert_eq!(*epoch, [0, 0, 0, 3]);
        let (client_id, key) = rest.split_first_chunk::<4>().expect("client_id");
        assert_eq!(*client_id, [0, 0, 0, 7]);
        assert_eq!(key, enrolment().key);
    }

    /// The printed secret derives a key for every slot at every epoch. None of
    /// its bytes may reach storage, or the stored form is the label again.
    #[test]
    fn p_222_the_stored_bytes_carry_no_printed_secret() {
        let bytes = encoded();
        assert!(
            !bytes.contains(&0xCD),
            "a printed-secret byte reached storage: {bytes:02x?}"
        );
    }

    /// Two controllers in one app: a key kept for the first must not be sent
    /// to the second, where it would only ever fail its proof and look like a
    /// broken controller.
    #[test]
    fn p_222_a_key_for_another_controller_is_refused() {
        let stored = StoredEnrolment::decode(&encoded()).expect("decodes");
        let mut other = DEVICE_ID;
        if let Some(last) = other.last_mut() {
            *last ^= 1;
        }
        assert_eq!(
            stored.restore(&discovery(other, epoch(3))).err(),
            Some(StoredEnrolmentError::OtherController)
        );
    }

    /// A factory reset moves the epoch, and the key a phone kept from before it
    /// is dead (P-085). The error names both epochs so the app can say the
    /// controller was reset rather than show an unexplained `bad_proof`.
    #[test]
    fn p_222_a_key_from_an_earlier_epoch_is_refused() {
        let stored = StoredEnrolment::decode(&encoded()).expect("decodes");
        for current in [epoch(4), epoch(2), epoch(u32::MAX)] {
            assert_eq!(
                stored.restore(&discovery(DEVICE_ID, current)).err(),
                Some(StoredEnrolmentError::OtherEpoch {
                    stored: epoch(3),
                    current,
                })
            );
        }
    }

    /// Storage that lost the tail of a write, or appended to one, hands back a
    /// length this layout never has. Every length from empty to one past full
    /// except the right one is refused, and none of them panics.
    #[test]
    fn every_truncation_and_an_extension_is_refused() {
        let full = encoded();
        for len in 0..StoredEnrolment::LEN {
            let cut = full.get(..len).expect("a prefix");
            assert_eq!(
                StoredEnrolment::decode(cut).err(),
                Some(StoredEnrolmentError::WrongLength(len))
            );
        }
        let mut longer = [0u8; StoredEnrolment::LEN + 1];
        for (slot, byte) in longer.iter_mut().zip(full) {
            *slot = byte;
        }
        assert_eq!(
            StoredEnrolment::decode(&longer).err(),
            Some(StoredEnrolmentError::WrongLength(StoredEnrolment::LEN + 1))
        );
    }

    /// A newer build that changed the layout writes a different first byte. An
    /// older build reading it back must refuse, not read the new fields as the
    /// old ones.
    #[test]
    fn every_other_format_byte_is_refused() {
        for format in (0..=u8::MAX).filter(|&f| f != FORMAT_V1) {
            let mut bytes = encoded();
            if let Some(first) = bytes.first_mut() {
                *first = format;
            }
            assert_eq!(
                StoredEnrolment::decode(&bytes).err(),
                Some(StoredEnrolmentError::UnknownFormat(format))
            );
        }
    }

    /// Zero is not an epoch and not a slot. Decoding either would put a key in
    /// memory under coordinates no controller ever issued.
    #[test]
    fn a_zero_epoch_or_client_id_is_refused() {
        let mut bytes = encoded();
        for at in 17..21 {
            if let Some(byte) = bytes.get_mut(at) {
                *byte = 0;
            }
        }
        assert_eq!(
            StoredEnrolment::decode(&bytes).err(),
            Some(StoredEnrolmentError::ZeroEpoch)
        );

        let mut bytes = encoded();
        for at in 21..25 {
            if let Some(byte) = bytes.get_mut(at) {
                *byte = 0;
            }
        }
        assert_eq!(
            StoredEnrolment::decode(&bytes).err(),
            Some(StoredEnrolmentError::ZeroClientId)
        );
    }

    /// Every error says to pair again, which is the one thing the app does
    /// with any of them.
    #[test]
    fn every_error_tells_the_client_to_pair_again() {
        let errors = [
            StoredEnrolmentError::WrongLength(3),
            StoredEnrolmentError::UnknownFormat(9),
            StoredEnrolmentError::ZeroEpoch,
            StoredEnrolmentError::ZeroClientId,
            StoredEnrolmentError::OtherController,
            StoredEnrolmentError::OtherEpoch {
                stored: epoch(3),
                current: epoch(4),
            },
        ];
        for error in errors {
            let mut text = Text::default();
            fmt::write(&mut text, format_args!("{error}")).expect("fits");
            assert!(
                text.as_str().ends_with("; pair again"),
                "{error:?} renders as {:?}",
                text.as_str()
            );
        }
    }

    /// A fixed buffer for `Display`, since there is no allocator here.
    struct Text {
        buf: [u8; 128],
        len: usize,
    }

    impl Default for Text {
        fn default() -> Self {
            Self {
                buf: [0; 128],
                len: 0,
            }
        }
    }

    impl Text {
        fn as_str(&self) -> &str {
            core::str::from_utf8(self.buf.get(..self.len).expect("within")).expect("utf-8")
        }
    }

    impl fmt::Write for Text {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
            self.buf
                .get_mut(self.len..end)
                .ok_or(fmt::Error)?
                .copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    impl crate::residue::Unpadded for StoredEnrolment {}

    const_assert!(
        core::mem::size_of::<StoredEnrolment>() == DEVICE_ID_BYTES + 4 + 4 + DERIVED_KEY_BYTES
    );

    /// The stored copy lives as long as the app holds it between reading
    /// storage and restoring. Its key has to go when it does.
    #[test]
    fn a_dropped_stored_enrolment_loses_its_key() {
        let stored = enrolment().stored();
        let residue: [u8; 56] = crate::residue::after_drop(stored);
        assert_eq!(
            residue.iter().filter(|&&b| b != 0).count(),
            DEVICE_ID_BYTES + 2,
            "only the device_id, epoch and client_id may survive: {residue:02x?}"
        );
    }
}
