//! The controller telling one verifier that the client asking holds an
//! enrolment in this generation and asked for this account (P-244).
//!
//! Three parties touch a vouch, and each has one door. The client sends a
//! [`VouchRequest`] carrying what the verifier issued. The controller answers it
//! with [`VouchRequest::answer`], which takes the epoch and the slot as
//! arguments because the request has no field to take them from. The verifier
//! checks a [`VouchClaim`] against its own [`VouchIssue`], and a [`Vouched`]
//! exists only once that check has passed.
//!
//! cites: P-244, P-245, P-247

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{ErrorCode, Vouch};
use crate::kdf::{ClientId, DeviceId, Epoch, Fingerprint, Generation};
use crate::mac::TAG_BYTES;
use crate::noise::{KEY_BYTES, PublicKey, StaticKey};

/// The verifier's nonce: sixteen bytes, used for one vouch.
pub const VOUCH_NONCE_BYTES: usize = 16;

/// The account binding the verifier issues: thirty-two bytes it never issues
/// to a second account (P-248).
pub const BINDING_BYTES: usize = 32;

/// A nonce the verifier drew for one vouch. Its freshness is the verifier's to
/// judge; the controller only tags it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VouchNonce([u8; VOUCH_NONCE_BYTES]);

impl VouchNonce {
    /// The bytes the verifier issued.
    #[must_use]
    pub const fn new(bytes: [u8; VOUCH_NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    /// The bytes, for the preimage and the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VOUCH_NONCE_BYTES] {
        &self.0
    }
}

/// The verifier's name for one account. Opaque here: the controller tags it
/// and has no way to know whose it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AccountBinding([u8; BINDING_BYTES]);

impl AccountBinding {
    /// The bytes the verifier issued.
    #[must_use]
    pub const fn new(bytes: [u8; BINDING_BYTES]) -> Self {
        Self(bytes)
    }

    /// The bytes, for the preimage and the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BINDING_BYTES] {
        &self.0
    }
}

/// What a vouch tag covers, in P-244's order.
///
/// Anybody can build one; it means nothing until a tag under the vouch key
/// verifies over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct VouchStatement {
    /// The controller's.
    pub device_id: DeviceId,
    /// The controller's current epoch: the ownership generation.
    pub epoch: Epoch,
    /// The slot the asking session is bound to.
    pub client_id: ClientId,
    /// That slot's generation.
    pub generation: Generation,
    /// The verifier's, for this vouch alone.
    pub nonce: VouchNonce,
    /// The verifier's, for one account.
    pub binding: AccountBinding,
}

/// Which key of a vouch body a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum VouchField {
    /// `Vouch 0x14` key 1.
    Verifier,
    /// `Vouch 0x14` key 2.
    Nonce,
    /// `Vouch 0x14` key 3.
    Binding,
    /// `Vouch 0x94` key 1.
    Outcome,
    /// `Vouch 0x94` key 2.
    Epoch,
    /// `Vouch 0x94` key 3.
    ClientId,
    /// `Vouch 0x94` key 4.
    Generation,
    /// `Vouch 0x94` key 5.
    Tag,
}

impl fmt::Display for VouchField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Verifier => "verifier",
            Self::Nonce => "nonce",
            Self::Binding => "binding",
            Self::Outcome => "outcome",
            Self::Epoch => "epoch",
            Self::ClientId => "client_id",
            Self::Generation => "generation",
            Self::Tag => "tag",
        })
    }
}

/// Why a vouch body would not read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum VouchError {
    /// A required key that never arrived.
    Missing(VouchField),
    /// The same key twice (P-015).
    Duplicate(VouchField),
    /// A byte string of the wrong width.
    WrongWidth(VouchField),
    /// A zero where an epoch, a slot or a generation belongs: none of them
    /// names anything at zero.
    Zero(VouchField),
    /// An outcome the registry does not allocate.
    UnknownOutcome(u8),
    /// Keys 2 to 5 beside `bad_verifier`, or any of them missing beside
    /// `vouched`.
    OutcomeDisagrees,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for VouchError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl VouchError {
    /// Every one of these is a body that does not mean what it says, which
    /// P-015 answers with error 1.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::WrongWidth(_)
            | Self::Zero(_)
            | Self::UnknownOutcome(_)
            | Self::OutcomeDisagrees
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for VouchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(f, "no {field}"),
            Self::Duplicate(field) => write!(f, "{field} twice"),
            Self::WrongWidth(field) => write!(f, "{field} is the wrong width"),
            Self::Zero(field) => write!(f, "{field} 0 names nothing"),
            Self::UnknownOutcome(raw) => write!(f, "vouch outcome {raw} is not allocated"),
            Self::OutcomeDisagrees => f.write_str("the keys present disagree with the outcome"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for VouchError {}

fn once<T>(slot: &mut Option<T>, field: VouchField, value: T) -> Result<(), VouchError> {
    if slot.is_some() {
        return Err(VouchError::Duplicate(field));
    }
    *slot = Some(value);
    Ok(())
}

fn fixed<const N: usize>(field: VouchField, bytes: &[u8]) -> Result<[u8; N], VouchError> {
    <[u8; N]>::try_from(bytes).map_err(|_| VouchError::WrongWidth(field))
}

/// `Vouch 0x14`: what the verifier issued, carried to the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VouchRequest {
    /// Key 1, `VS`.
    pub verifier: PublicKey,
    /// Key 2.
    pub nonce: VouchNonce,
    /// Key 3.
    pub binding: AccountBinding,
}

impl VouchRequest {
    /// Encode the inner body the sealed wrapper carries.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, VouchError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(3)?;
        cbor.key(1)?;
        cbor.bytes(self.verifier.as_bytes())?;
        cbor.key(2)?;
        cbor.bytes(self.nonce.as_bytes())?;
        cbor.key(3)?;
        cbor.bytes(self.binding.as_bytes())?;
        Ok(cbor.finish()?)
    }

    /// Read the inner body after the wrapper's tag has verified.
    pub fn decode(payload: &[u8]) -> Result<Self, VouchError> {
        let mut cbor = CborReader::new(payload);
        let pairs = cbor.map()?;
        let (mut verifier, mut nonce, mut binding) = (None, None, None);
        for _ in 0..pairs {
            match cbor.key()? {
                1 => {
                    let key = fixed::<KEY_BYTES>(VouchField::Verifier, cbor.bytes()?)?;
                    once(&mut verifier, VouchField::Verifier, key)?;
                }
                2 => {
                    let bytes = fixed(VouchField::Nonce, cbor.bytes()?)?;
                    once(&mut nonce, VouchField::Nonce, bytes)?;
                }
                3 => {
                    let bytes = fixed(VouchField::Binding, cbor.bytes()?)?;
                    once(&mut binding, VouchField::Binding, bytes)?;
                }
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        Ok(Self {
            verifier: PublicKey::from_bytes(
                verifier.ok_or(VouchError::Missing(VouchField::Verifier))?,
            ),
            nonce: VouchNonce::new(nonce.ok_or(VouchError::Missing(VouchField::Nonce))?),
            binding: AccountBinding::new(binding.ok_or(VouchError::Missing(VouchField::Binding))?),
        })
    }

    /// The controller's answer (P-244, P-245). The epoch and the slot are the
    /// controller's own, passed here because the request cannot carry them;
    /// `bound` is the slot the session that sent this is bound to.
    #[must_use]
    pub fn answer(
        &self,
        controller: &StaticKey,
        device_id: DeviceId,
        epoch: Epoch,
        bound: (ClientId, Generation),
    ) -> VouchAnswer {
        let (client_id, generation) = bound;
        let Ok(key) = controller.vouch_key(device_id, &self.verifier) else {
            return VouchAnswer::BadVerifier;
        };
        let tag = key.tag(&VouchStatement {
            device_id,
            epoch,
            client_id,
            generation,
            nonce: self.nonce,
            binding: self.binding,
        });
        VouchAnswer::Vouched {
            epoch,
            client_id,
            generation,
            tag: *tag.as_bytes(),
        }
    }
}

/// `Vouch 0x94`.
///
/// The tag is carried as bytes because nobody who reads this body can check
/// it: the client does not hold a key that derives the vouch key, and the
/// verifier checks it through [`VouchIssue::verify`].
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum VouchAnswer {
    /// Outcome 1, and keys 2 to 5.
    Vouched {
        /// Key 2.
        epoch: Epoch,
        /// Key 3.
        client_id: ClientId,
        /// Key 4.
        generation: Generation,
        /// Key 5.
        tag: [u8; TAG_BYTES],
    },
    /// Outcome 2: a low-order verifier key, and nothing else (P-245).
    BadVerifier,
}

impl VouchAnswer {
    /// Encode the inner body the sealed wrapper carries.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, VouchError> {
        let mut cbor = CborWriter::new(dst);
        match self {
            Self::Vouched {
                epoch,
                client_id,
                generation,
                tag,
            } => {
                cbor.map(5)?;
                cbor.key(1)?;
                cbor.u64(u64::from(Vouch::Vouched as u8))?;
                cbor.key(2)?;
                cbor.u64(u64::from(epoch.get()))?;
                cbor.key(3)?;
                cbor.u64(u64::from(client_id.get()))?;
                cbor.key(4)?;
                cbor.u64(u64::from(generation.get()))?;
                cbor.key(5)?;
                cbor.bytes(tag)?;
            }
            Self::BadVerifier => {
                cbor.map(1)?;
                cbor.key(1)?;
                cbor.u64(u64::from(Vouch::BadVerifier as u8))?;
            }
        }
        Ok(cbor.finish()?)
    }

    /// Read the inner body after the wrapper's tag has verified.
    pub fn decode(payload: &[u8]) -> Result<Self, VouchError> {
        let mut cbor = CborReader::new(payload);
        let pairs = cbor.map()?;
        let (mut outcome, mut epoch, mut client_id, mut generation, mut tag) =
            (None, None, None, None, None);
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(&mut outcome, VouchField::Outcome, cbor.u8()?)?,
                2 => once(&mut epoch, VouchField::Epoch, cbor.u32()?)?,
                3 => once(&mut client_id, VouchField::ClientId, cbor.u32()?)?,
                4 => once(&mut generation, VouchField::Generation, cbor.u32()?)?,
                5 => {
                    let bytes = fixed(VouchField::Tag, cbor.bytes()?)?;
                    once(&mut tag, VouchField::Tag, bytes)?;
                }
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        let raw = outcome.ok_or(VouchError::Missing(VouchField::Outcome))?;
        match Vouch::try_from(raw).map_err(|()| VouchError::UnknownOutcome(raw))? {
            Vouch::Vouched => match (epoch, client_id, generation, tag) {
                (Some(epoch), Some(client_id), Some(generation), Some(tag)) => Ok(Self::Vouched {
                    epoch: Epoch::new(epoch).ok_or(VouchError::Zero(VouchField::Epoch))?,
                    client_id: ClientId::new(client_id)
                        .ok_or(VouchError::Zero(VouchField::ClientId))?,
                    generation: Generation::new(generation)
                        .ok_or(VouchError::Zero(VouchField::Generation))?,
                    tag,
                }),
                _ => Err(VouchError::OutcomeDisagrees),
            },
            Vouch::BadVerifier => {
                if epoch.is_some() || client_id.is_some() || generation.is_some() || tag.is_some() {
                    Err(VouchError::OutcomeDisagrees)
                } else {
                    Ok(Self::BadVerifier)
                }
            }
        }
    }
}

/// What the verifier holds from issuing a vouch request: step 2 of P-247.
///
/// Every field comes from the verifier's own records and none from the caller,
/// which is what makes another account's vouch and an earlier epoch's fail at
/// the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VouchIssue {
    /// The controller of the generation the caller asks to link.
    pub device_id: DeviceId,
    /// The generation the caller asks to link.
    pub epoch: Epoch,
    /// The nonce issued, already recorded as spent (P-247 step 1).
    pub nonce: VouchNonce,
    /// The binding issued with it, for the account now presenting it.
    pub binding: AccountBinding,
}

/// What the caller hands the verifier: the controller key it pinned, and
/// `Vouch 0x94`'s slot and tag.
#[derive(Debug, Clone, Copy)]
pub struct VouchClaim {
    /// `CS` as the caller's client pinned it (P-222). A claim, until P-247's
    /// fingerprint check.
    pub controller: PublicKey,
    /// Key 3.
    pub client_id: ClientId,
    /// Key 4.
    pub generation: Generation,
    /// Key 5.
    pub tag: [u8; TAG_BYTES],
}

/// Why a verifier refused a vouch, in the order P-247 checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum VouchRefusal {
    /// The verifier holds no manufacturing record for this `device_id`
    /// (P-249). Nothing the caller could offer stands in for one.
    NoRecord,
    /// `CS` does not hash to the manufacturing record's fingerprint. The
    /// caller may hold its private half, so its tag proves nothing.
    WrongController,
    /// `X25519(vs, CS)` was all zero.
    LowOrderController,
    /// The tag is not the one the verifier computes over its own statement:
    /// another account's binding, another epoch, another nonce, another slot,
    /// or a forgery.
    TagMismatch,
}

impl fmt::Display for VouchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoRecord => "no manufacturing record names this device",
            Self::WrongController => "the controller key is not the one this device was made with",
            Self::LowOrderController => "the controller key is a low-order point",
            Self::TagMismatch => "the tag does not vouch for this statement",
        })
    }
}

impl core::error::Error for VouchRefusal {}

/// A statement whose tag verified: the only thing a verifier should link on.
///
/// There is no constructor, so a statement nobody verified cannot be passed
/// where one is required:
///
/// ```compile_fail
/// # use km43::{Vouched, VouchStatement};
/// fn link(_: Vouched) {}
/// fn forge(statement: VouchStatement) -> Vouched {
///     Vouched { statement }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Vouched {
    statement: VouchStatement,
}

impl Vouched {
    /// What the controller vouched for.
    #[must_use]
    pub const fn statement(&self) -> &VouchStatement {
        &self.statement
    }
}

impl VouchIssue {
    /// P-247 steps 2 to 4. `record` is the fingerprint the manufacturing
    /// record holds for this `device_id` (P-249), or `None` when the verifier
    /// holds none, never one the caller supplied. Step 1, the nonce, is the
    /// caller's to have done first, since only the verifier's store knows what
    /// it issued.
    pub fn verify(
        &self,
        verifier: &StaticKey,
        record: Option<&Fingerprint>,
        claim: &VouchClaim,
    ) -> Result<Vouched, VouchRefusal> {
        let printed = record.ok_or(VouchRefusal::NoRecord)?;
        if !printed.vouches_for(&claim.controller) {
            return Err(VouchRefusal::WrongController);
        }
        let key = verifier
            .vouch_key(self.device_id, &claim.controller)
            .map_err(|_| VouchRefusal::LowOrderController)?;
        let statement = VouchStatement {
            device_id: self.device_id,
            epoch: self.epoch,
            client_id: claim.client_id,
            generation: claim.generation,
            nonce: self.nonce,
            binding: self.binding,
        };
        key.tag(&statement)
            .verify(&claim.tag)
            .map_err(|_| VouchRefusal::TagMismatch)?;
        Ok(Vouched { statement })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::Entropy;

    const DEVICE: DeviceId = DeviceId::new(*b"ORIGIN89 TEST 01");

    fn controller() -> StaticKey {
        StaticKey::generate(Entropy::new([0x40; KEY_BYTES]))
    }

    fn verifier() -> StaticKey {
        StaticKey::generate(Entropy::new([0xA0; KEY_BYTES]))
    }

    fn epoch(raw: u32) -> Epoch {
        Epoch::new(raw).expect("non-zero")
    }

    fn slot() -> (ClientId, Generation) {
        (
            ClientId::new(7).expect("non-zero"),
            Generation::new(3).expect("non-zero"),
        )
    }

    fn request(binding: u8) -> VouchRequest {
        VouchRequest {
            verifier: verifier().public(),
            nonce: VouchNonce::new([0xB0; VOUCH_NONCE_BYTES]),
            binding: AccountBinding::new([binding; BINDING_BYTES]),
        }
    }

    fn issue(binding: u8, at: u32) -> VouchIssue {
        VouchIssue {
            device_id: DEVICE,
            epoch: epoch(at),
            nonce: VouchNonce::new([0xB0; VOUCH_NONCE_BYTES]),
            binding: AccountBinding::new([binding; BINDING_BYTES]),
        }
    }

    /// The claim a client forwards: its pinned controller key and the answer.
    fn claim(answer: VouchAnswer, pinned: PublicKey) -> VouchClaim {
        let VouchAnswer::Vouched {
            client_id,
            generation,
            tag,
            ..
        } = answer
        else {
            panic!("the controller refused a good verifier key");
        };
        VouchClaim {
            controller: pinned,
            client_id,
            generation,
            tag,
        }
    }

    fn printed() -> Fingerprint {
        Fingerprint::of(&controller().public())
    }

    /// The whole path: the controller tags from its own state, and the
    /// verifier, holding only `vs`, the fingerprint and what it issued, accepts
    /// it and learns the slot that asked.
    #[test]
    fn p_244_a_vouch_the_controller_tags_is_one_the_verifier_accepts() {
        let answer = request(0xD0).answer(&controller(), DEVICE, epoch(4), slot());
        let vouched = issue(0xD0, 4)
            .verify(
                &verifier(),
                Some(&printed()),
                &claim(answer, controller().public()),
            )
            .expect("an honest vouch verifies");
        assert_eq!(vouched.statement().client_id, slot().0);
        assert_eq!(vouched.statement().generation, slot().1);
        assert_eq!(vouched.statement().epoch, epoch(4));
    }

    /// The epoch and the slot are the controller's, not the request's: a
    /// request has no field that could name another one, and the answer
    /// carries exactly what was tagged.
    #[test]
    fn p_244_the_answer_carries_the_epoch_and_slot_the_controller_tagged() {
        let VouchAnswer::Vouched {
            epoch: tagged,
            client_id,
            generation,
            ..
        } = request(0xD0).answer(&controller(), DEVICE, epoch(9), slot())
        else {
            panic!("refused a good verifier key");
        };
        assert_eq!(
            (tagged, client_id, generation),
            (epoch(9), slot().0, slot().1)
        );
    }

    /// A low-order `VS` makes the vouch key a constant anybody computes, so the
    /// controller refuses it rather than tagging under it. The all-zero point
    /// and the point of order one are both refused.
    #[test]
    fn p_245_a_low_order_verifier_key_gets_no_tag() {
        for point in [[0u8; KEY_BYTES], {
            let mut one = [0u8; KEY_BYTES];
            one[0] = 1;
            one
        }] {
            let low = VouchRequest {
                verifier: PublicKey::from_bytes(point),
                ..request(0xD0)
            };
            assert!(matches!(
                low.answer(&controller(), DEVICE, epoch(1), slot()),
                VouchAnswer::BadVerifier
            ));
        }
    }

    /// A vouch minted for one account does not link a site in another. The
    /// verifier tags the binding it issued to the account presenting it, so a
    /// phone that forwards another account's vouch is refused at the tag.
    #[test]
    fn p_247_another_accounts_vouch_is_refused() {
        let answer = request(0xD0).answer(&controller(), DEVICE, epoch(1), slot());
        assert_eq!(
            issue(0xD1, 1).verify(
                &verifier(),
                Some(&printed()),
                &claim(answer, controller().public())
            ),
            Err(VouchRefusal::TagMismatch)
        );
    }

    /// A vouch from an earlier generation does not link a later one. After a
    /// factory reset the old phone's slot is free and it cannot ask again, but a
    /// vouch it kept from before would otherwise claim the new owner's
    /// generation.
    #[test]
    fn p_247_an_earlier_epochs_vouch_does_not_link_a_later_one() {
        let answer = request(0xD0).answer(&controller(), DEVICE, epoch(1), slot());
        assert_eq!(
            issue(0xD0, 2).verify(
                &verifier(),
                Some(&printed()),
                &claim(answer, controller().public())
            ),
            Err(VouchRefusal::TagMismatch)
        );
    }

    /// A caller that hands the verifier a controller key of its own can tag
    /// anything under it, and the tag verifies. Only the manufacturing record's
    /// fingerprint refuses it, and it must be checked first.
    #[test]
    fn p_247_a_controller_key_the_caller_chose_is_refused_though_its_tag_verifies() {
        let impostor = StaticKey::generate(Entropy::new([0x50; KEY_BYTES]));
        let forged = request(0xD0).answer(&impostor, DEVICE, epoch(1), slot());
        let claim = claim(forged, impostor.public());
        assert!(
            issue(0xD0, 1)
                .verify(
                    &verifier(),
                    Some(&Fingerprint::of(&impostor.public())),
                    &claim
                )
                .is_ok(),
            "without the record, the forgery passes: this is what step 3 is for"
        );
        assert_eq!(
            issue(0xD0, 1).verify(&verifier(), Some(&printed()), &claim),
            Err(VouchRefusal::WrongController)
        );
    }

    /// A unit whose record has not reached the verifier cannot be linked, and
    /// the fingerprint a caller would happily supply for it is not accepted in
    /// its place. Without the `Option`, a verifier with no record reaches for a
    /// default, and the only fingerprint to hand is the caller's.
    #[test]
    fn p_249_a_device_with_no_manufacturing_record_is_refused() {
        let answer = request(0xD0).answer(&controller(), DEVICE, epoch(1), slot());
        assert_eq!(
            issue(0xD0, 1).verify(&verifier(), None, &claim(answer, controller().public())),
            Err(VouchRefusal::NoRecord)
        );
    }

    /// A vouch names the slot that asked. A phone that rewrites the slot it
    /// forwards, to claim another enrolment's, is refused at the tag.
    #[test]
    fn a_vouch_forwarded_under_another_slot_is_refused() {
        let answer = request(0xD0).answer(&controller(), DEVICE, epoch(1), slot());
        let mut moved = claim(answer, controller().public());
        moved.client_id = ClientId::new(1).expect("non-zero");
        assert_eq!(
            issue(0xD0, 1).verify(&verifier(), Some(&printed()), &moved),
            Err(VouchRefusal::TagMismatch)
        );
    }

    /// Every single-bit flip of the tag is refused.
    #[test]
    fn every_flipped_bit_of_a_vouch_tag_is_refused() {
        let answer = request(0xD0).answer(&controller(), DEVICE, epoch(1), slot());
        let good = claim(answer, controller().public());
        for byte in 0..TAG_BYTES {
            for bit in 0..8 {
                let mut flipped = good;
                flipped.tag[byte] ^= 1 << bit;
                assert_eq!(
                    issue(0xD0, 1).verify(&verifier(), Some(&printed()), &flipped),
                    Err(VouchRefusal::TagMismatch)
                );
            }
        }
    }

    #[test]
    fn a_request_round_trips_and_every_truncation_is_refused() {
        let mut buf = [0u8; 128];
        let len = request(0xD0).encode(&mut buf).expect("fits");
        let bytes = &buf[..len];
        assert_eq!(VouchRequest::decode(bytes), Ok(request(0xD0)));
        for cut in 0..len {
            assert!(VouchRequest::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }

    /// A key of the wrong width is refused, not padded or cut: a 31-byte
    /// verifier key read as a prefix would tag under a key nobody holds.
    #[test]
    fn a_request_with_a_short_key_or_a_missing_binding_is_refused() {
        let mut buf = [0u8; 128];
        let mut cbor = CborWriter::new(&mut buf);
        cbor.map(3).expect("fits");
        cbor.key(1).expect("fits");
        cbor.bytes(&[0x11; KEY_BYTES - 1]).expect("fits");
        cbor.key(2).expect("fits");
        cbor.bytes(&[0xB0; VOUCH_NONCE_BYTES]).expect("fits");
        cbor.key(3).expect("fits");
        cbor.bytes(&[0xD0; BINDING_BYTES]).expect("fits");
        let len = cbor.finish().expect("fits");
        assert_eq!(
            VouchRequest::decode(&buf[..len]),
            Err(VouchError::WrongWidth(VouchField::Verifier))
        );

        let mut cbor = CborWriter::new(&mut buf);
        cbor.map(2).expect("fits");
        cbor.key(1).expect("fits");
        cbor.bytes(&[0x11; KEY_BYTES]).expect("fits");
        cbor.key(2).expect("fits");
        cbor.bytes(&[0xB0; VOUCH_NONCE_BYTES]).expect("fits");
        let len = cbor.finish().expect("fits");
        assert_eq!(
            VouchRequest::decode(&buf[..len]),
            Err(VouchError::Missing(VouchField::Binding))
        );
    }

    #[test]
    fn both_answers_round_trip_and_every_truncation_is_refused() {
        let vouched = request(0xD0).answer(&controller(), DEVICE, epoch(2), slot());
        for answer in [vouched, VouchAnswer::BadVerifier] {
            let mut buf = [0u8; 64];
            let len = answer.encode(&mut buf).expect("fits");
            let bytes = &buf[..len];
            let again = VouchAnswer::decode(bytes).expect("reads back");
            let mut rewritten = [0u8; 64];
            let relen = again.encode(&mut rewritten).expect("fits");
            assert_eq!(&rewritten[..relen], bytes);
            for cut in 0..len {
                assert!(VouchAnswer::decode(&bytes[..cut]).is_err(), "cut at {cut}");
            }
        }
    }

    /// A refusal carrying a slot, or a vouch missing its tag, is a body that
    /// contradicts itself; neither is read as the half that suits the reader.
    #[test]
    fn an_answer_whose_keys_disagree_with_its_outcome_is_refused() {
        let mut buf = [0u8; 64];
        let mut cbor = CborWriter::new(&mut buf);
        cbor.map(2).expect("fits");
        cbor.key(1).expect("fits");
        cbor.u64(u64::from(Vouch::BadVerifier as u8)).expect("fits");
        cbor.key(3).expect("fits");
        cbor.u64(7).expect("fits");
        let len = cbor.finish().expect("fits");
        assert_eq!(
            VouchAnswer::decode(&buf[..len]).map(|_| ()),
            Err(VouchError::OutcomeDisagrees)
        );

        let mut cbor = CborWriter::new(&mut buf);
        cbor.map(4).expect("fits");
        cbor.key(1).expect("fits");
        cbor.u64(u64::from(Vouch::Vouched as u8)).expect("fits");
        for key in 2..=4 {
            cbor.key(key).expect("fits");
            cbor.u64(1).expect("fits");
        }
        let len = cbor.finish().expect("fits");
        assert_eq!(
            VouchAnswer::decode(&buf[..len]).map(|_| ()),
            Err(VouchError::OutcomeDisagrees)
        );
    }

    /// Zero names no epoch, slot or generation, and an unallocated outcome is
    /// not guessed at.
    #[test]
    fn a_zero_slot_or_an_unknown_outcome_is_refused() {
        let mut buf = [0u8; 64];
        let mut cbor = CborWriter::new(&mut buf);
        cbor.map(5).expect("fits");
        cbor.key(1).expect("fits");
        cbor.u64(u64::from(Vouch::Vouched as u8)).expect("fits");
        cbor.key(2).expect("fits");
        cbor.u64(1).expect("fits");
        cbor.key(3).expect("fits");
        cbor.u64(0).expect("fits");
        cbor.key(4).expect("fits");
        cbor.u64(1).expect("fits");
        cbor.key(5).expect("fits");
        cbor.bytes(&[0; TAG_BYTES]).expect("fits");
        let len = cbor.finish().expect("fits");
        assert_eq!(
            VouchAnswer::decode(&buf[..len]).map(|_| ()),
            Err(VouchError::Zero(VouchField::ClientId))
        );

        let mut cbor = CborWriter::new(&mut buf);
        cbor.map(1).expect("fits");
        cbor.key(1).expect("fits");
        cbor.u64(3).expect("fits");
        let len = cbor.finish().expect("fits");
        assert_eq!(
            VouchAnswer::decode(&buf[..len]).map(|_| ()),
            Err(VouchError::UnknownOutcome(3))
        );
    }
}
