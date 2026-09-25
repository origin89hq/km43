//! An owner-approved invite: how a phone that never visits the controller gets a
//! slot, when every message between it and the controller passes through a
//! cloud that may be hostile.
//!
//! The relay can substitute a key in either direction, so two people compare six
//! digits over a channel it does not carry (P-251). Six digits over values the
//! relay chooses would be a search, not a check: it would try keys until the
//! digits matched. So the invitee commits to its key and a secret nonce before
//! the controller draws its own, and reveals the nonce only once it holds the
//! controller's. [`InviteeStart`] has no way to hand the nonce out, and only
//! [`InviteeStart::receive`], which needs the controller's nonce, makes the
//! [`Invitee`] that does:
//!
//! ```compile_fail
//! fn early(start: &km43::InviteeStart) -> km43::Reveal {
//!     start.reveal()
//! }
//! ```
//!
//! The proof and the confirmation are HMACs under the enrolment's admission key
//! (P-238), which only a holder of the invitee's private key or of the
//! controller's can compute. The proof binds the controller key to the
//! controller without a person: an invitee told a relay's key fails at
//! `Approve`. The confirmation binds it to the invitee, but only a person
//! comparing the digits binds the invitee's key, and an [`Invitee`] keeps its
//! enrolment only once somebody says they matched:
//!
//! ```compile_fail
//! fn skip(invitee: km43::Invitee, confirm: &[u8; 16]) {
//!     let id = km43::ClientId::new(2).unwrap();
//!     let generation = km43::Generation::FIRST;
//!     let _ = invitee.keep(confirm, id, generation);
//! }
//! ```
//!
//! cites: P-251

use core::fmt;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::generated::{Role, Suite};
use crate::kdf::{ClientId, DeviceId, Enrolment, Epoch, Generation};
use crate::mac::{AdmitKey, MacError, Tag};
use crate::noise::{Entropy, KEY_BYTES, NoiseError, PublicKey, StaticKey};

/// The controller's nonce, the invitee's nonce: sixteen bytes each.
pub const INVITE_NONCE_BYTES: usize = 16;

/// A commitment is a whole SHA-256.
pub const COMMITMENT_BYTES: usize = 32;

/// `device_id`, `CS`, epoch, suite, role, inviter, its generation, `IS`,
/// `N_c`, `N_i`.
pub const INVITE_TRANSCRIPT_BYTES: usize =
    16 + KEY_BYTES + 4 + 1 + 1 + 4 + 4 + KEY_BYTES + INVITE_NONCE_BYTES + INVITE_NONCE_BYTES;

/// How many values the digits take: six decimal digits.
const SAS_MODULUS: u32 = 1_000_000;

const_assert!(
    INVITE_TRANSCRIPT_BYTES == 126,
    "P-251's transcript is 126 bytes and the published vectors count them"
);

/// P-043's two hash prefixes for an invite.
const COMMIT_LABEL: &[u8] = b"km43/v1/invite-commit";
const SAS_LABEL: &[u8] = b"km43/v1/invite-sas";

/// The controller's nonce, drawn when an admin or owner proposes the invite.
/// It is also the invite's name: `Approve` and `Clients` carry it, and nothing
/// else numbers invites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InviteNonce(pub [u8; INVITE_NONCE_BYTES]);

/// The invitee's nonce, secret until it holds the controller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reveal(pub [u8; INVITE_NONCE_BYTES]);

/// `SHA-256("km43/v1/invite-commit" | IS | N_i)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Commitment(pub [u8; COMMITMENT_BYTES]);

impl Commitment {
    /// The invitee's commitment to its key and its nonce.
    #[must_use]
    pub fn of(invitee: &PublicKey, reveal: &Reveal) -> Self {
        let mut digest = Sha256::new();
        digest.update(COMMIT_LABEL);
        digest.update(invitee.as_bytes());
        digest.update(reveal.0);
        Self(digest.finalize().into())
    }

    /// Whether `reveal` opens this commitment for `invitee`.
    #[must_use]
    pub fn opens(&self, invitee: &PublicKey, reveal: &Reveal) -> bool {
        bool::from(self.0.ct_eq(&Self::of(invitee, reveal).0))
    }
}

/// The six digits two people read to each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Sas(u32);

impl Sas {
    /// The number, below one million.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Always six digits, leading zeros kept: `004217` read aloud as "four two one
/// seven" is a different number to somebody listening for six.
impl fmt::Display for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

/// Everything an invite's transcript names, in P-251's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invitation {
    /// The controller the invite is for.
    pub device_id: DeviceId,
    /// Its key, `CS`.
    pub controller: PublicKey,
    /// The ownership generation the invite belongs to (P-085).
    pub epoch: Epoch,
    /// The suite the slot will pin.
    pub suite: Suite,
    /// The role the slot will hold.
    pub role: Role,
    /// The slot that proposed it.
    pub inviter: ClientId,
    /// That slot's generation when it proposed.
    pub inviter_generation: Generation,
    /// The invitee's key, `IS`.
    pub invitee: PublicKey,
    /// The controller's nonce, `N_c`.
    pub nonce: InviteNonce,
    /// The invitee's nonce, `N_i`.
    pub reveal: Reveal,
}

impl Invitation {
    /// The transcript both MACs and the digits are computed over.
    #[must_use]
    pub fn transcript(&self) -> [u8; INVITE_TRANSCRIPT_BYTES] {
        let mut out = [0u8; INVITE_TRANSCRIPT_BYTES];
        let epoch = self.epoch.get().to_be_bytes();
        let inviter = self.inviter.get().to_be_bytes();
        let generation = self.inviter_generation.get().to_be_bytes();
        let parts: [&[u8]; 10] = [
            self.device_id.as_bytes(),
            self.controller.as_bytes(),
            &epoch,
            &[self.suite as u8],
            &[self.role as u8],
            &inviter,
            &generation,
            self.invitee.as_bytes(),
            &self.nonce.0,
            &self.reveal.0,
        ];
        for (slot, &byte) in out
            .iter_mut()
            .zip(parts.iter().flat_map(|part| part.iter()))
        {
            *slot = byte;
        }
        out
    }

    /// `u32be(SHA-256("km43/v1/invite-sas" | transcript)[0..4]) mod 1 000 000`.
    #[must_use]
    pub fn sas(&self) -> Sas {
        let mut digest = Sha256::new();
        digest.update(SAS_LABEL);
        digest.update(self.transcript());
        let full: [u8; 32] = digest.finalize().into();
        let [a, b, c, d, ..] = full;
        Sas(u32::from_be_bytes([a, b, c, d]) % SAS_MODULUS)
    }
}

/// What the inviter's app relays to the invitee once the controller has
/// answered `Invite`: everything in the transcript but the invitee's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteDetails {
    /// The controller.
    pub device_id: DeviceId,
    /// The controller key the invitee will pin if the digits match.
    pub controller: PublicKey,
    /// The ownership generation.
    pub epoch: Epoch,
    /// The suite.
    pub suite: Suite,
    /// The role the invitee is being given.
    pub role: Role,
    /// Who proposed it.
    pub inviter: ClientId,
    /// That slot's generation.
    pub inviter_generation: Generation,
    /// `InviteAck 0x95` key 2.
    pub nonce: InviteNonce,
}

/// The invitee before it has heard from the controller: a key pair and a
/// committed nonce, and no way to reveal the nonce.
///
/// No `Debug`: it holds a private key.
pub struct InviteeStart {
    key: StaticKey,
    reveal: Reveal,
}

impl InviteeStart {
    /// A fresh key pair and nonce, both from the invitee's CSPRNG.
    #[must_use]
    pub fn new(key: Entropy, nonce: [u8; INVITE_NONCE_BYTES]) -> Self {
        Self {
            key: StaticKey::generate(key),
            reveal: Reveal(nonce),
        }
    }

    /// `IS`, which the inviter proposes.
    #[must_use]
    pub const fn public(&self) -> PublicKey {
        self.key.public()
    }

    /// What the inviter proposes beside `IS`.
    #[must_use]
    pub fn commitment(&self) -> Commitment {
        Commitment::of(&self.key.public(), &self.reveal)
    }

    /// Take the controller's nonce and everything else the inviter relayed.
    /// Refuses a controller key that makes the agreement zero (P-228).
    pub fn receive(self, details: &InviteDetails) -> Result<Invitee, InviteError> {
        let invitation = Invitation {
            device_id: details.device_id,
            controller: details.controller,
            epoch: details.epoch,
            suite: details.suite,
            role: details.role,
            inviter: details.inviter,
            inviter_generation: details.inviter_generation,
            invitee: self.key.public(),
            nonce: details.nonce,
            reveal: self.reveal,
        };
        let admit = self.key.admit_key(details.device_id, &details.controller)?;
        Ok(Invitee {
            key: self.key,
            invitation,
            admit,
        })
    }
}

/// The invitee once it holds the controller's nonce: it may reveal its own,
/// prove its key and show the digits.
///
/// No `Debug`: it holds a private key.
pub struct Invitee {
    key: StaticKey,
    invitation: Invitation,
    admit: AdmitKey,
}

impl Invitee {
    /// `N_i`, sent back through the relay with the proof.
    #[must_use]
    pub const fn reveal(&self) -> Reveal {
        self.invitation.reveal
    }

    /// P-251's proof, sent back through the relay.
    #[must_use]
    pub fn proof(&self) -> Tag {
        self.invitation.proof(&self.admit)
    }

    /// The digits this invitee's person reads out.
    #[must_use]
    pub fn sas(&self) -> Sas {
        self.invitation.sas()
    }

    /// The person confirmed the digits matched what the owner read. Only then
    /// is the confirmation worth checking: without it, the confirmation proves
    /// only that whoever sent it holds the key the relay named (P-251).
    #[must_use]
    pub const fn digits_matched(self) -> Matched {
        Matched(self)
    }
}

/// An invitee whose person said the digits matched.
///
/// No `Debug`: it holds a private key.
pub struct Matched(Invitee);

impl Matched {
    /// Check the controller's confirmation for the slot `Approve` named, and
    /// hand back the enrolment to keep (P-222).
    pub fn keep(
        self,
        confirm: &[u8],
        client_id: ClientId,
        generation: Generation,
    ) -> Result<Enrolment, InviteError> {
        let Invitee {
            key,
            invitation,
            admit,
        } = self.0;
        admit
            .invite_confirm(&invitation.transcript(), client_id, generation)
            .verify(confirm)?;
        Ok(Enrolment::new(
            invitation.device_id,
            invitation.controller,
            key,
            invitation.suite,
            invitation.epoch,
        )
        .with_slot(client_id, generation))
    }
}

impl Invitation {
    fn proof(&self, admit: &AdmitKey) -> Tag {
        admit.invite_proof(&self.transcript())
    }

    /// The controller's side of an approval: the commitment opens, the
    /// agreement is not zero, and the proof verifies. What comes back holds the
    /// admission key the slot will store (P-238) and makes the confirmation.
    pub fn verify(
        &self,
        commitment: &Commitment,
        proof: &[u8],
        controller: &StaticKey,
    ) -> Result<Verified, InviteError> {
        if !commitment.opens(&self.invitee, &self.reveal) {
            return Err(InviteError::CommitmentDoesNotOpen);
        }
        if !controller.public().matches(&self.controller) {
            return Err(InviteError::NotThisController);
        }
        let admit = controller.admit_key(self.device_id, &self.invitee)?;
        self.proof(&admit).verify(proof)?;
        Ok(Verified {
            transcript: self.transcript(),
            admit,
        })
    }
}

/// An approval whose proof verified.
///
/// No `Debug`: it holds the admission key.
pub struct Verified {
    transcript: [u8; INVITE_TRANSCRIPT_BYTES],
    admit: AdmitKey,
}

impl Verified {
    /// P-251's confirmation for the slot the key was written to.
    #[must_use]
    pub fn confirm(&self, client_id: ClientId, generation: Generation) -> Tag {
        self.admit
            .invite_confirm(&self.transcript, client_id, generation)
    }

    /// The admission key, for the slot's key record.
    #[must_use]
    pub const fn admit_key(&self) -> &AdmitKey {
        &self.admit
    }
}

/// Why an invite's cryptography refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InviteError {
    /// The revealed nonce does not open the commitment the invite carries: the
    /// relay changed the key or the nonce. `Approve` outcome 6.
    CommitmentDoesNotOpen,
    /// The transcript names a controller key that is not this controller's.
    NotThisController,
    /// The agreement came out zero: a low-order key (P-228). Outcome 6.
    Agreement(NoiseError),
    /// A proof or a confirmation that does not verify. Outcome 6 at the
    /// controller; at the invitee, a confirmation not to keep.
    Tag(MacError),
}

impl From<NoiseError> for InviteError {
    fn from(why: NoiseError) -> Self {
        Self::Agreement(why)
    }
}

impl From<MacError> for InviteError {
    fn from(why: MacError) -> Self {
        Self::Tag(why)
    }
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitmentDoesNotOpen => {
                f.write_str("the revealed nonce does not open the invite's commitment")
            }
            Self::NotThisController => f.write_str("the invite names another controller key"),
            Self::Agreement(why) => write!(f, "{why}"),
            Self::Tag(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for InviteError {}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE: [u8; 16] = *b"ORIGIN89 DEMO 01";

    fn controller() -> StaticKey {
        StaticKey::generate(Entropy::new([0x40; 32]))
    }

    fn details(controller: PublicKey, nonce: u8) -> InviteDetails {
        InviteDetails {
            device_id: DeviceId::new(DEVICE),
            controller,
            epoch: Epoch::FIRST,
            suite: Suite::X25519ChachapolySha256,
            role: Role::Admin,
            inviter: ClientId::new(1).expect("a slot"),
            inviter_generation: Generation::FIRST,
            nonce: InviteNonce([nonce; 16]),
        }
    }

    fn invitee() -> InviteeStart {
        InviteeStart::new(Entropy::new([0x61; 32]), [0x71; 16])
    }

    /// The controller's view of the invite: what it stored at `Invite`, and
    /// the nonce the invitee revealed.
    fn as_controller_sees(start_key: PublicKey, reveal: Reveal, d: &InviteDetails) -> Invitation {
        Invitation {
            device_id: d.device_id,
            controller: d.controller,
            epoch: d.epoch,
            suite: d.suite,
            role: d.role,
            inviter: d.inviter,
            inviter_generation: d.inviter_generation,
            invitee: start_key,
            nonce: d.nonce,
            reveal,
        }
    }

    /// The honest run: the controller verifies the proof, the invitee checks
    /// the confirmation, and both ends show the same digits.
    #[test]
    fn p_251_an_honest_invite_verifies_at_both_ends() {
        let cs = controller();
        let start = invitee();
        let commitment = start.commitment();
        let is = start.public();
        let d = details(cs.public(), 0x51);
        let invitee = start.receive(&d).expect("contributory");
        let seen = as_controller_sees(is, invitee.reveal(), &d);
        let verified = seen
            .verify(&commitment, invitee.proof().as_bytes(), &cs)
            .expect("the proof verifies");
        assert_eq!(seen.sas(), invitee.sas());
        let id = ClientId::new(4).expect("a slot");
        let confirm = verified.confirm(id, Generation::FIRST);
        let kept = invitee
            .digits_matched()
            .keep(confirm.as_bytes(), id, Generation::FIRST)
            .expect("the confirmation verifies");
        assert!(kept.controller().matches(&cs.public()));
        assert_eq!(kept.slot(), Some((id, Generation::FIRST)));
    }

    /// A relay that swaps the invitee's key for its own, committing to it
    /// properly, passes the controller's checks: only the digits catch it. They
    /// must differ, or the person comparing them catches nothing.
    #[test]
    fn p_251_a_substituted_invitee_key_changes_the_digits() {
        let cs = controller();
        let d = details(cs.public(), 0x52);
        let honest = invitee().receive(&d).expect("contributory");
        let relay = InviteeStart::new(Entropy::new([0x62; 32]), [0x72; 16])
            .receive(&d)
            .expect("contributory");
        assert_ne!(honest.sas(), relay.sas());
    }

    /// A relay that tells the invitee a key of its own for the controller: the
    /// invitee's proof is under the wrong agreement and fails at the real
    /// controller, whether or not anybody compares the digits.
    #[test]
    fn p_251_an_invitee_told_another_controller_key_fails_the_proof() {
        let cs = controller();
        let fake = StaticKey::generate(Entropy::new([0x41; 32]));
        let start = invitee();
        let commitment = start.commitment();
        let is = start.public();
        let told = details(fake.public(), 0x53);
        let invitee = start.receive(&told).expect("contributory");
        let truth = details(cs.public(), 0x53);
        let seen = as_controller_sees(is, invitee.reveal(), &truth);
        assert!(matches!(
            seen.verify(&commitment, invitee.proof().as_bytes(), &cs),
            Err(InviteError::Tag(MacError::Mismatch))
        ));
        assert_ne!(seen.sas(), invitee.sas());
    }

    /// The reveal is bound by the commitment: a relay cannot pick a different
    /// nonce after seeing the controller's, which is what would let it search
    /// for matching digits.
    #[test]
    fn p_251_a_reveal_that_does_not_open_the_commitment_is_refused() {
        let cs = controller();
        let start = invitee();
        let commitment = start.commitment();
        let is = start.public();
        let d = details(cs.public(), 0x54);
        let invitee = start.receive(&d).expect("contributory");
        let mut other = invitee.reveal();
        other.0[0] ^= 1;
        let seen = as_controller_sees(is, other, &d);
        assert_eq!(
            seen.verify(&commitment, invitee.proof().as_bytes(), &cs)
                .err(),
            Some(InviteError::CommitmentDoesNotOpen)
        );
    }

    /// Every field of the transcript is bound: change any byte of it and the
    /// proof no longer verifies. A field left out would be one the relay could
    /// rewrite — the role above all.
    #[test]
    fn p_251_every_transcript_byte_is_bound_by_the_proof() {
        let cs = controller();
        let start = invitee();
        let is = start.public();
        let d = details(cs.public(), 0x55);
        let invitee = start.receive(&d).expect("contributory");
        let seen = as_controller_sees(is, invitee.reveal(), &d);
        let admit = cs.admit_key(seen.device_id, &is).expect("contributory");
        let proof = invitee.proof();
        let transcript = seen.transcript();
        for index in 0..INVITE_TRANSCRIPT_BYTES {
            let mut changed = transcript;
            changed[index] ^= 0x01;
            assert!(
                admit
                    .invite_proof(&changed)
                    .verify(proof.as_bytes())
                    .is_err(),
                "byte {index} of the transcript is not bound"
            );
        }
        let mut role = seen;
        role.role = Role::Owner;
        assert_ne!(role.sas(), seen.sas(), "the role changes the digits");
    }

    /// A confirmation for one slot does not vouch for another, and a forged
    /// one is not kept.
    #[test]
    fn p_251_a_confirmation_for_another_slot_is_not_kept() {
        let cs = controller();
        let start = invitee();
        let commitment = start.commitment();
        let is = start.public();
        let d = details(cs.public(), 0x56);
        let invitee = start.receive(&d).expect("contributory");
        let seen = as_controller_sees(is, invitee.reveal(), &d);
        let verified = seen
            .verify(&commitment, invitee.proof().as_bytes(), &cs)
            .expect("verifies");
        let confirm = verified.confirm(ClientId::new(4).expect("slot"), Generation::FIRST);
        let refused = invitee.digits_matched().keep(
            confirm.as_bytes(),
            ClientId::new(5).expect("slot"),
            Generation::FIRST,
        );
        assert!(matches!(refused, Err(InviteError::Tag(MacError::Mismatch))));
    }

    /// A controller key that is a low-order point is refused before any proof
    /// is made: the agreement would be a constant the relay knows (P-228).
    #[test]
    fn p_251_a_low_order_controller_key_is_refused() {
        let zero = PublicKey::from_bytes([0; 32]);
        assert!(matches!(
            invitee().receive(&details(zero, 0x57)),
            Err(InviteError::Agreement(NoiseError::LowOrderPoint))
        ));
    }

    /// The digits always print six wide, leading zeros included.
    #[test]
    fn the_digits_keep_their_leading_zeros() {
        struct Out([u8; 8], usize);
        impl fmt::Write for Out {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                for &b in s.as_bytes() {
                    *self.0.get_mut(self.1).ok_or(fmt::Error)? = b;
                    self.1 += 1;
                }
                Ok(())
            }
        }
        for (value, text) in [(0, b"000000"), (4217, b"004217"), (999_999, b"999999")] {
            let mut out = Out([0; 8], 0);
            fmt::write(&mut out, format_args!("{}", Sas(value))).expect("fits");
            assert_eq!(&out.0[..out.1], text);
        }
    }
}
