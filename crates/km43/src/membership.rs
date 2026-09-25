//! `Invite 0x15`, `Approve 0x16` and `Remove 0x17`, and their acks: the three
//! signed writes that change who is enrolled (P-246, P-249, P-250).
//!
//! Each operation is its write's sealed inner body, read only once that body
//! has opened, as every signed write is (P-048). An answer's optional keys are tied to
//! its outcome in the type: an [`InviteAck`] carries a nonce exactly when it
//! says `proposed`, and an [`ApproveAck`] a slot and a confirmation exactly
//! when it says `enrolled`. A decline carries no reveal and no proof, and an
//! [`ApproveOperation`] that declines has nowhere to put one.
//!
//! cites: P-013, P-015

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{Approve, ClientKind, ErrorCode, Invite, InviteDecision, Remove, Role};
use crate::invite::{COMMITMENT_BYTES, Commitment, INVITE_NONCE_BYTES, InviteNonce, Reveal};
use crate::kdf::{ClientId, Generation};
use crate::limits::MAX_LABEL;
use crate::noise::{KEY_BYTES, PublicKey, TAG_BYTES};

/// Every key at its widest: a one-byte role and kind, two 32-byte strings and
/// a label of `MAX_LABEL`, whose text head is two bytes.
pub const MAX_INVITE_OPERATION_BYTES: usize = 110;

/// Outcome 1 with its nonce.
pub const MAX_INVITE_ACK_BYTES: usize = 21;

/// An approval: the nonce, the decision, the reveal and the proof.
pub const MAX_APPROVE_OPERATION_BYTES: usize = 57;

/// Outcome 1 with a `client_id` and generation at full `u32` width and the
/// confirmation.
pub const MAX_APPROVE_ACK_BYTES: usize = 33;

/// A `client_id` and a generation at full `u32` width.
pub const MAX_REMOVE_OPERATION_BYTES: usize = 13;

/// The outcome alone.
pub const MAX_REMOVE_ACK_BYTES: usize = 3;

/// The keys of the `Invite 0x15` operation body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InviteKey {
    /// Key 1, the role the invite would enrol.
    Role,
    /// Key 2, `IS`.
    Invitee,
    /// Key 3, P-251's commitment.
    Commitment,
    /// Key 4, what the invitee will say it is.
    ClientKind,
    /// Key 5, what a person sees in the list.
    Label,
}

impl InviteKey {
    const COUNT: usize = 5;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Role),
            2 => Some(Self::Invitee),
            3 => Some(Self::Commitment),
            4 => Some(Self::ClientKind),
            5 => Some(Self::Label),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Role => 1,
            Self::Invitee => 2,
            Self::Commitment => 3,
            Self::ClientKind => 4,
            Self::Label => 5,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Role => "role",
            Self::Invitee => "invitee",
            Self::Commitment => "commitment",
            Self::ClientKind => "client_kind",
            Self::Label => "label",
        }
    }
}

/// The keys of `InviteAck 0x95`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InviteAckKey {
    /// Key 1.
    Outcome,
    /// Key 2, `N_c`, with outcome 1 only.
    Nonce,
}

impl InviteAckKey {
    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Outcome),
            2 => Some(Self::Nonce),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Outcome => 1,
            Self::Nonce => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Outcome => "outcome",
            Self::Nonce => "nonce",
        }
    }
}

/// The keys of the `Approve 0x16` operation body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ApproveKey {
    /// Key 1, `N_c`.
    Nonce,
    /// Key 2, approve or decline.
    Decision,
    /// Key 3, `N_i`, with an approval only.
    Reveal,
    /// Key 4, P-251's proof, with an approval only.
    Proof,
}

impl ApproveKey {
    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Nonce),
            2 => Some(Self::Decision),
            3 => Some(Self::Reveal),
            4 => Some(Self::Proof),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Nonce => 1,
            Self::Decision => 2,
            Self::Reveal => 3,
            Self::Proof => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Nonce => "nonce",
            Self::Decision => "decision",
            Self::Reveal => "reveal",
            Self::Proof => "proof",
        }
    }
}

/// The keys of `ApproveAck 0x96`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ApproveAckKey {
    /// Key 1.
    Outcome,
    /// Key 2, with outcome 1 only.
    ClientId,
    /// Key 3, with outcome 1 only.
    Generation,
    /// Key 4, P-251's confirmation, with outcome 1 only.
    Confirm,
}

impl ApproveAckKey {
    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Outcome),
            2 => Some(Self::ClientId),
            3 => Some(Self::Generation),
            4 => Some(Self::Confirm),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Outcome => 1,
            Self::ClientId => 2,
            Self::Generation => 3,
            Self::Confirm => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Outcome => "outcome",
            Self::ClientId => "client_id",
            Self::Generation => "generation",
            Self::Confirm => "confirm",
        }
    }
}

/// The keys of the `Remove 0x17` operation body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RemoveKey {
    /// Key 1, the slot.
    ClientId,
    /// Key 2, the enrolment in it.
    Generation,
}

impl RemoveKey {
    const COUNT: usize = 2;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::ClientId),
            2 => Some(Self::Generation),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::ClientId => 1,
            Self::Generation => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::ClientId => "client_id",
            Self::Generation => "generation",
        }
    }
}

/// A key of any body here, so one refusal names the body and the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MembershipKey {
    /// A key of the `Invite 0x15` operation.
    Invite(InviteKey),
    /// A key of `InviteAck 0x95`.
    InviteAck(InviteAckKey),
    /// A key of the `Approve 0x16` operation.
    Approve(ApproveKey),
    /// A key of `ApproveAck 0x96`.
    ApproveAck(ApproveAckKey),
    /// A key of the `Remove 0x17` operation.
    Remove(RemoveKey),
    /// Key 1 of `RemoveAck 0x97`, its only key.
    RemoveAckOutcome,
}

impl fmt::Display for MembershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (body, name, number) = match self {
            Self::Invite(k) => ("Invite 0x15", k.name(), k.number()),
            Self::InviteAck(k) => ("InviteAck 0x95", k.name(), k.number()),
            Self::Approve(k) => ("Approve 0x16", k.name(), k.number()),
            Self::ApproveAck(k) => ("ApproveAck 0x96", k.name(), k.number()),
            Self::Remove(k) => ("Remove 0x17", k.name(), k.number()),
            Self::RemoveAckOutcome => ("RemoveAck 0x97", "outcome", 1),
        };
        write!(f, "{body} {name} (key {number})")
    }
}

/// An admin or owner proposing a key for a slot (P-246). The label is
/// borrowed from the body it was read out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteOperation<'a> {
    /// Key 1.
    pub role: Role,
    /// Key 2.
    pub invitee: PublicKey,
    /// Key 3.
    pub commitment: Commitment,
    /// Key 4, shown and deciding nothing (P-105).
    pub client_kind: ClientKind,
    /// Key 5, 1 to `MAX_LABEL` bytes.
    pub label: &'a str,
}

impl<'a> InviteOperation<'a> {
    /// Encode the operation body. The caller seals these bytes as the write.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, MembershipError> {
        label_fits(self.label)?;
        let mut cbor = CborWriter::new(dst);
        cbor.map(InviteKey::COUNT)?;
        cbor.key(InviteKey::Role.number())?;
        cbor.u64(u64::from(self.role as u8))?;
        cbor.key(InviteKey::Invitee.number())?;
        cbor.bytes(self.invitee.as_bytes())?;
        cbor.key(InviteKey::Commitment.number())?;
        cbor.bytes(&self.commitment.0)?;
        cbor.key(InviteKey::ClientKind.number())?;
        cbor.u64(u64::from(self.client_kind as u8))?;
        cbor.key(InviteKey::Label.number())?;
        cbor.text(self.label)?;
        Ok(cbor.finish()?)
    }

    /// Read the operation out of a sealed body that has already opened.
    pub fn decode(operation: &'a [u8]) -> Result<Self, MembershipError> {
        let mut body = CborReader::new(operation);
        let pairs = body.map()?;
        let (mut role, mut invitee, mut commitment, mut kind, mut label) =
            (None, None, None, None, None);
        for _ in 0..pairs {
            match InviteKey::of(body.key()?) {
                Some(key @ InviteKey::Role) => {
                    let number = body.u8()?;
                    let value = Role::try_from(number)
                        .map_err(|()| MembershipError::UnknownRole(number))?;
                    once(&mut role, MembershipKey::Invite(key), value)?;
                }
                Some(key @ InviteKey::Invitee) => {
                    let bytes = fixed::<KEY_BYTES>(&mut body, MembershipKey::Invite(key))?;
                    once(&mut invitee, MembershipKey::Invite(key), bytes)?;
                }
                Some(key @ InviteKey::Commitment) => {
                    let bytes = fixed::<COMMITMENT_BYTES>(&mut body, MembershipKey::Invite(key))?;
                    once(&mut commitment, MembershipKey::Invite(key), bytes)?;
                }
                Some(key @ InviteKey::ClientKind) => {
                    let number = body.u8()?;
                    let value = ClientKind::try_from(number)
                        .map_err(|()| MembershipError::UnknownClientKind(number))?;
                    once(&mut kind, MembershipKey::Invite(key), value)?;
                }
                Some(key @ InviteKey::Label) => {
                    let text = body.text()?;
                    label_fits(text)?;
                    once(&mut label, MembershipKey::Invite(key), text)?;
                }
                None => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            role: role.ok_or(missing(InviteKey::Role))?,
            invitee: PublicKey::from_bytes(invitee.ok_or(missing(InviteKey::Invitee))?),
            commitment: Commitment(commitment.ok_or(missing(InviteKey::Commitment))?),
            client_kind: kind.ok_or(missing(InviteKey::ClientKind))?,
            label: label.ok_or(missing(InviteKey::Label))?,
        })
    }
}

/// The controller's answer to a proposal. The nonce names the invite from here
/// on, so outcome 1 carries it and nothing else does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InviteAck {
    outcome: Invite,
    nonce: Option<InviteNonce>,
}

impl InviteAck {
    /// A pending invite and its name.
    #[must_use]
    pub const fn proposed(nonce: InviteNonce) -> Self {
        Self {
            outcome: Invite::Proposed,
            nonce: Some(nonce),
        }
    }

    /// A refusal. `proposed` is not one, and has to name its invite.
    pub const fn refused(outcome: Invite) -> Result<Self, MembershipError> {
        match outcome {
            Invite::Proposed => Err(MembershipError::ProposedWithoutNonce),
            Invite::Unauthorised
            | Invite::InvitesFull
            | Invite::KnownKey
            | Invite::TableFull
            | Invite::NoBudget => Ok(Self {
                outcome,
                nonce: None,
            }),
        }
    }

    /// Key 1.
    #[must_use]
    pub const fn outcome(self) -> Invite {
        self.outcome
    }

    /// Key 2: present exactly when the outcome is `proposed`.
    #[must_use]
    pub const fn nonce(self) -> Option<InviteNonce> {
        self.nonce
    }

    /// Encode the ack body. The caller seals it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, MembershipError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(if self.nonce.is_some() { 2 } else { 1 })?;
        cbor.key(InviteAckKey::Outcome.number())?;
        cbor.u64(u64::from(self.outcome as u8))?;
        if let Some(nonce) = self.nonce {
            cbor.key(InviteAckKey::Nonce.number())?;
            cbor.bytes(&nonce.0)?;
        }
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload that has already opened.
    pub fn decode(payload: &[u8]) -> Result<Self, MembershipError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut outcome, mut nonce) = (None, None);
        for _ in 0..pairs {
            match InviteAckKey::of(body.key()?) {
                Some(key @ InviteAckKey::Outcome) => {
                    let number = body.u8()?;
                    let value = Invite::try_from(number)
                        .map_err(|()| MembershipError::UnknownOutcome(number))?;
                    once(&mut outcome, MembershipKey::InviteAck(key), value)?;
                }
                Some(key @ InviteAckKey::Nonce) => {
                    let bytes =
                        fixed::<INVITE_NONCE_BYTES>(&mut body, MembershipKey::InviteAck(key))?;
                    once(&mut nonce, MembershipKey::InviteAck(key), bytes)?;
                }
                None => body.skip()?,
            }
        }
        body.finish()?;
        let outcome = outcome.ok_or(MembershipError::Missing(MembershipKey::InviteAck(
            InviteAckKey::Outcome,
        )))?;
        match (outcome, nonce) {
            (Invite::Proposed, Some(nonce)) => Ok(Self::proposed(InviteNonce(nonce))),
            (Invite::Proposed, None) => Err(MembershipError::ProposedWithoutNonce),
            (_, Some(_)) => Err(MembershipError::Unexpected(MembershipKey::InviteAck(
                InviteAckKey::Nonce,
            ))),
            (_, None) => Self::refused(outcome),
        }
    }
}

/// What an `Approve` decides, with what an approval needs and a decline does
/// not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Decision {
    /// Enrol the invitee, if the reveal opens the commitment and the proof
    /// verifies (P-249 step 5).
    Approve {
        /// Key 3, `N_i`.
        reveal: Reveal,
        /// Key 4, P-251's proof.
        proof: [u8; TAG_BYTES],
    },
    /// Withdraw the invite.
    Decline,
}

/// An owner deciding an invite, or an inviter withdrawing its own (P-249).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ApproveOperation {
    /// Key 1.
    pub nonce: InviteNonce,
    /// Keys 2, 3 and 4.
    pub decision: Decision,
}

impl ApproveOperation {
    /// Encode the operation body. The caller seals these bytes as the write.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, MembershipError> {
        let mut cbor = CborWriter::new(dst);
        let (decision, pairs) = match self.decision {
            Decision::Approve { .. } => (InviteDecision::Approve, 4),
            Decision::Decline => (InviteDecision::Decline, 2),
        };
        cbor.map(pairs)?;
        cbor.key(ApproveKey::Nonce.number())?;
        cbor.bytes(&self.nonce.0)?;
        cbor.key(ApproveKey::Decision.number())?;
        cbor.u64(u64::from(decision as u8))?;
        match self.decision {
            Decision::Approve { reveal, proof } => {
                cbor.key(ApproveKey::Reveal.number())?;
                cbor.bytes(&reveal.0)?;
                cbor.key(ApproveKey::Proof.number())?;
                cbor.bytes(&proof)?;
            }
            Decision::Decline => {}
        }
        Ok(cbor.finish()?)
    }

    /// Read the operation out of a sealed body that has already opened.
    pub fn decode(operation: &[u8]) -> Result<Self, MembershipError> {
        let mut body = CborReader::new(operation);
        let pairs = body.map()?;
        let (mut nonce, mut decision, mut reveal, mut proof) = (None, None, None, None);
        for _ in 0..pairs {
            match ApproveKey::of(body.key()?) {
                Some(key @ ApproveKey::Nonce) => {
                    let bytes =
                        fixed::<INVITE_NONCE_BYTES>(&mut body, MembershipKey::Approve(key))?;
                    once(&mut nonce, MembershipKey::Approve(key), bytes)?;
                }
                Some(key @ ApproveKey::Decision) => {
                    let number = body.u8()?;
                    let value = InviteDecision::try_from(number)
                        .map_err(|()| MembershipError::UnknownDecision(number))?;
                    once(&mut decision, MembershipKey::Approve(key), value)?;
                }
                Some(key @ ApproveKey::Reveal) => {
                    let bytes =
                        fixed::<INVITE_NONCE_BYTES>(&mut body, MembershipKey::Approve(key))?;
                    once(&mut reveal, MembershipKey::Approve(key), bytes)?;
                }
                Some(key @ ApproveKey::Proof) => {
                    let bytes = fixed::<TAG_BYTES>(&mut body, MembershipKey::Approve(key))?;
                    once(&mut proof, MembershipKey::Approve(key), bytes)?;
                }
                None => body.skip()?,
            }
        }
        body.finish()?;
        let nonce = InviteNonce(nonce.ok_or(MembershipError::Missing(MembershipKey::Approve(
            ApproveKey::Nonce,
        )))?);
        let decision =
            match decision.ok_or(MembershipError::Missing(MembershipKey::Approve(
                ApproveKey::Decision,
            )))? {
                InviteDecision::Approve => Decision::Approve {
                    reveal: Reveal(reveal.ok_or(MembershipError::Missing(
                        MembershipKey::Approve(ApproveKey::Reveal),
                    ))?),
                    proof: proof.ok_or(MembershipError::Missing(MembershipKey::Approve(
                        ApproveKey::Proof,
                    )))?,
                },
                InviteDecision::Decline => {
                    if reveal.is_some() {
                        return Err(MembershipError::Unexpected(MembershipKey::Approve(
                            ApproveKey::Reveal,
                        )));
                    }
                    if proof.is_some() {
                        return Err(MembershipError::Unexpected(MembershipKey::Approve(
                            ApproveKey::Proof,
                        )));
                    }
                    Decision::Decline
                }
            };
        Ok(Self { nonce, decision })
    }
}

/// The slot an approval wrote, and the controller's word that it wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Enrolled {
    /// Key 2.
    pub client_id: ClientId,
    /// Key 3.
    pub generation: Generation,
    /// Key 4, P-251's confirmation, which the invitee checks before it keeps
    /// anything.
    pub confirm: [u8; TAG_BYTES],
}

/// The controller's answer to an `Approve`. A slot and a confirmation arrive
/// with `enrolled` and never with anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ApproveAck {
    outcome: Approve,
    enrolled: Option<Enrolled>,
}

impl ApproveAck {
    /// The invitee has a slot.
    #[must_use]
    pub const fn enrolled(enrolled: Enrolled) -> Self {
        Self {
            outcome: Approve::Enrolled,
            enrolled: Some(enrolled),
        }
    }

    /// Anything but `enrolled`, which has to say where.
    pub const fn other(outcome: Approve) -> Result<Self, MembershipError> {
        match outcome {
            Approve::Enrolled => Err(MembershipError::EnrolledWithoutSlot),
            Approve::Declined
            | Approve::Unauthorised
            | Approve::UnknownInvite
            | Approve::InviterGone
            | Approve::Refused
            | Approve::KnownKey
            | Approve::TableFull
            | Approve::NotStored => Ok(Self {
                outcome,
                enrolled: None,
            }),
        }
    }

    /// Key 1.
    #[must_use]
    pub const fn outcome(self) -> Approve {
        self.outcome
    }

    /// Keys 2 to 4: present exactly when the outcome is `enrolled`.
    #[must_use]
    pub const fn slot(self) -> Option<Enrolled> {
        self.enrolled
    }

    /// Encode the ack body. The caller seals it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, MembershipError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(if self.enrolled.is_some() { 4 } else { 1 })?;
        cbor.key(ApproveAckKey::Outcome.number())?;
        cbor.u64(u64::from(self.outcome as u8))?;
        if let Some(enrolled) = self.enrolled {
            cbor.key(ApproveAckKey::ClientId.number())?;
            cbor.u64(u64::from(enrolled.client_id.get()))?;
            cbor.key(ApproveAckKey::Generation.number())?;
            cbor.u64(u64::from(enrolled.generation.get()))?;
            cbor.key(ApproveAckKey::Confirm.number())?;
            cbor.bytes(&enrolled.confirm)?;
        }
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload that has already opened.
    pub fn decode(payload: &[u8]) -> Result<Self, MembershipError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut outcome, mut client_id, mut generation, mut confirm) = (None, None, None, None);
        for _ in 0..pairs {
            match ApproveAckKey::of(body.key()?) {
                Some(key @ ApproveAckKey::Outcome) => {
                    let number = body.u8()?;
                    let value = Approve::try_from(number)
                        .map_err(|()| MembershipError::UnknownOutcome(number))?;
                    once(&mut outcome, MembershipKey::ApproveAck(key), value)?;
                }
                Some(key @ ApproveAckKey::ClientId) => {
                    let id = ClientId::new(body.u32()?)
                        .ok_or(MembershipError::Zero(MembershipKey::ApproveAck(key)))?;
                    once(&mut client_id, MembershipKey::ApproveAck(key), id)?;
                }
                Some(key @ ApproveAckKey::Generation) => {
                    let value = Generation::new(body.u32()?)
                        .ok_or(MembershipError::Zero(MembershipKey::ApproveAck(key)))?;
                    once(&mut generation, MembershipKey::ApproveAck(key), value)?;
                }
                Some(key @ ApproveAckKey::Confirm) => {
                    let bytes = fixed::<TAG_BYTES>(&mut body, MembershipKey::ApproveAck(key))?;
                    once(&mut confirm, MembershipKey::ApproveAck(key), bytes)?;
                }
                None => body.skip()?,
            }
        }
        body.finish()?;
        let outcome = outcome.ok_or(MembershipError::Missing(MembershipKey::ApproveAck(
            ApproveAckKey::Outcome,
        )))?;
        match outcome {
            Approve::Enrolled => Ok(Self::enrolled(Enrolled {
                client_id: client_id.ok_or(MembershipError::EnrolledWithoutSlot)?,
                generation: generation.ok_or(MembershipError::EnrolledWithoutSlot)?,
                confirm: confirm.ok_or(MembershipError::EnrolledWithoutSlot)?,
            })),
            Approve::Declined
            | Approve::Unauthorised
            | Approve::UnknownInvite
            | Approve::InviterGone
            | Approve::Refused
            | Approve::KnownKey
            | Approve::TableFull
            | Approve::NotStored => {
                let stray = [
                    client_id.map(|_| ApproveAckKey::ClientId),
                    generation.map(|_| ApproveAckKey::Generation),
                    confirm.map(|_| ApproveAckKey::Confirm),
                ];
                match stray.into_iter().flatten().next() {
                    Some(key) => Err(MembershipError::Unexpected(MembershipKey::ApproveAck(key))),
                    None => Self::other(outcome),
                }
            }
        }
    }
}

/// An owner or admin ending one enrolment (P-250). It names the generation, so
/// a retry that arrives after the slot changed hands removes nobody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoveOperation {
    /// Key 1.
    pub client_id: ClientId,
    /// Key 2.
    pub generation: Generation,
}

impl RemoveOperation {
    /// Encode the operation body. The caller seals these bytes as the write.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, MembershipError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(RemoveKey::COUNT)?;
        cbor.key(RemoveKey::ClientId.number())?;
        cbor.u64(u64::from(self.client_id.get()))?;
        cbor.key(RemoveKey::Generation.number())?;
        cbor.u64(u64::from(self.generation.get()))?;
        Ok(cbor.finish()?)
    }

    /// Read the operation out of a sealed body that has already opened.
    pub fn decode(operation: &[u8]) -> Result<Self, MembershipError> {
        let mut body = CborReader::new(operation);
        let pairs = body.map()?;
        let (mut client_id, mut generation) = (None, None);
        for _ in 0..pairs {
            match RemoveKey::of(body.key()?) {
                Some(key @ RemoveKey::ClientId) => {
                    let id = ClientId::new(body.u32()?)
                        .ok_or(MembershipError::Zero(MembershipKey::Remove(key)))?;
                    once(&mut client_id, MembershipKey::Remove(key), id)?;
                }
                Some(key @ RemoveKey::Generation) => {
                    let value = Generation::new(body.u32()?)
                        .ok_or(MembershipError::Zero(MembershipKey::Remove(key)))?;
                    once(&mut generation, MembershipKey::Remove(key), value)?;
                }
                None => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            client_id: client_id.ok_or(MembershipError::Missing(MembershipKey::Remove(
                RemoveKey::ClientId,
            )))?,
            generation: generation.ok_or(MembershipError::Missing(MembershipKey::Remove(
                RemoveKey::Generation,
            )))?,
        })
    }
}

/// The controller's answer to a `Remove`: an outcome and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RemoveAck(pub Remove);

impl RemoveAck {
    /// Encode the ack body. The caller seals it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, MembershipError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(1)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.0 as u8))?;
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload that has already opened.
    pub fn decode(payload: &[u8]) -> Result<Self, MembershipError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut outcome = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => {
                    let number = body.u8()?;
                    let value = Remove::try_from(number)
                        .map_err(|()| MembershipError::UnknownOutcome(number))?;
                    once(&mut outcome, MembershipKey::RemoveAckOutcome, value)?;
                }
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self(outcome.ok_or(MembershipError::Missing(
            MembershipKey::RemoveAckOutcome,
        ))?))
    }
}

const fn missing(key: InviteKey) -> MembershipError {
    MembershipError::Missing(MembershipKey::Invite(key))
}

fn label_fits(label: &str) -> Result<(), MembershipError> {
    match label.len() {
        0 => Err(MembershipError::EmptyLabel),
        len if len > MAX_LABEL => Err(MembershipError::LabelTooLong(len)),
        _ => Ok(()),
    }
}

/// A byte string that has to be exactly `N` long: a key, a nonce, a tag.
fn fixed<const N: usize>(
    body: &mut CborReader<'_>,
    key: MembershipKey,
) -> Result<[u8; N], MembershipError> {
    let bytes = body.bytes()?;
    bytes
        .try_into()
        .map_err(|_| MembershipError::WrongLength(key, bytes.len()))
}

fn once<T>(slot: &mut Option<T>, key: MembershipKey, value: T) -> Result<(), MembershipError> {
    if slot.is_some() {
        return Err(MembershipError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// Why an `Invite`, `Approve` or `Remove` body, or an answer to one, was
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MembershipError {
    /// A required key never arrived (P-015).
    Missing(MembershipKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(MembershipKey),
    /// A key the outcome or decision it sits beside does not carry.
    Unexpected(MembershipKey),
    /// A key, nonce or tag of the wrong length: the length it had.
    WrongLength(MembershipKey, usize),
    /// A `client_id` or generation of zero, which names no enrolment.
    Zero(MembershipKey),
    /// A role the registry does not allocate.
    UnknownRole(u8),
    /// A `client_kind` the registry does not allocate (P-105).
    UnknownClientKind(u8),
    /// A decision the registry does not allocate.
    UnknownDecision(u8),
    /// An outcome the body's outcome space does not allocate.
    UnknownOutcome(u8),
    /// A label with nothing in it: a row nobody can tell from another.
    EmptyLabel,
    /// A label past `MAX_LABEL`: its length.
    LabelTooLong(usize),
    /// `proposed` without the nonce that names the invite.
    ProposedWithoutNonce,
    /// `enrolled` without the slot, the generation or the confirmation.
    EnrolledWithoutSlot,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for MembershipError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl MembershipError {
    /// What to answer. All of these are error 1: a body that cannot say who
    /// is being invited, approved or removed has no meaning to act on, and an
    /// unallocated `client_kind` is a malformed operation (P-105).
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::Unexpected(_)
            | Self::WrongLength(..)
            | Self::Zero(_)
            | Self::UnknownRole(_)
            | Self::UnknownClientKind(_)
            | Self::UnknownDecision(_)
            | Self::UnknownOutcome(_)
            | Self::EmptyLabel
            | Self::LabelTooLong(_)
            | Self::ProposedWithoutNonce
            | Self::EnrolledWithoutSlot
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for MembershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "no {key}"),
            Self::Duplicate(key) => write!(f, "{key} twice"),
            Self::Unexpected(key) => write!(f, "{key} beside an outcome that does not carry it"),
            Self::WrongLength(key, len) => write!(f, "{key} of {len} bytes"),
            Self::Zero(key) => write!(f, "{key} of zero, which names no enrolment"),
            Self::UnknownRole(value) => write!(f, "unallocated role {value}"),
            Self::UnknownClientKind(value) => write!(f, "unallocated client_kind {value}"),
            Self::UnknownDecision(value) => write!(f, "unallocated invite decision {value}"),
            Self::UnknownOutcome(value) => write!(f, "unallocated outcome {value}"),
            Self::EmptyLabel => f.write_str("an invite with an empty label"),
            Self::LabelTooLong(len) => write!(f, "a label of {len} bytes, past {MAX_LABEL}"),
            Self::ProposedWithoutNonce => f.write_str("an invite proposed without its nonce"),
            Self::EnrolledWithoutSlot => {
                f.write_str("an approval enrolled without its slot, generation or confirmation")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for MembershipError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    const LABEL: &str = "an invited phone that says so!!!";

    const INVITE_OUTCOMES: [Invite; 6] = [
        Invite::Proposed,
        Invite::Unauthorised,
        Invite::InvitesFull,
        Invite::KnownKey,
        Invite::TableFull,
        Invite::NoBudget,
    ];

    const APPROVE_OUTCOMES: [Approve; 9] = [
        Approve::Enrolled,
        Approve::Declined,
        Approve::Unauthorised,
        Approve::UnknownInvite,
        Approve::InviterGone,
        Approve::Refused,
        Approve::KnownKey,
        Approve::TableFull,
        Approve::NotStored,
    ];

    const REMOVE_OUTCOMES: [Remove; 5] = [
        Remove::Removed,
        Remove::Gone,
        Remove::Protected,
        Remove::Unauthorised,
        Remove::NotStored,
    ];

    fn invites() -> impl Iterator<Item = InviteOperation<'static>> {
        [Role::Owner, Role::Admin, Role::Viewer]
            .into_iter()
            .flat_map(|role| {
                ["x", LABEL].into_iter().map(move |label| InviteOperation {
                    role,
                    invitee: PublicKey::from_bytes([0xA5; KEY_BYTES]),
                    commitment: Commitment([0x3C; COMMITMENT_BYTES]),
                    client_kind: ClientKind::App,
                    label,
                })
            })
    }

    fn invite_acks() -> impl Iterator<Item = InviteAck> {
        INVITE_OUTCOMES.into_iter().map(|outcome| match outcome {
            Invite::Proposed => InviteAck::proposed(InviteNonce([0xD0; INVITE_NONCE_BYTES])),
            Invite::Unauthorised
            | Invite::InvitesFull
            | Invite::KnownKey
            | Invite::TableFull
            | Invite::NoBudget => InviteAck::refused(outcome).expect("a refusal"),
        })
    }

    fn approvals() -> [ApproveOperation; 2] {
        let nonce = InviteNonce([0xD0; INVITE_NONCE_BYTES]);
        [
            ApproveOperation {
                nonce,
                decision: Decision::Approve {
                    reveal: Reveal([0x30; INVITE_NONCE_BYTES]),
                    proof: [0x77; TAG_BYTES],
                },
            },
            ApproveOperation {
                nonce,
                decision: Decision::Decline,
            },
        ]
    }

    fn slot(id: u32, generation: u32) -> Enrolled {
        Enrolled {
            client_id: ClientId::new(id).expect("a slot"),
            generation: Generation::new(generation).expect("a generation"),
            confirm: [0x5E; TAG_BYTES],
        }
    }

    fn approve_acks() -> impl Iterator<Item = ApproveAck> {
        APPROVE_OUTCOMES
            .into_iter()
            .flat_map(|outcome| match outcome {
                Approve::Enrolled => [
                    Some(ApproveAck::enrolled(slot(2, 1))),
                    Some(ApproveAck::enrolled(slot(u32::MAX, u32::MAX))),
                ],
                Approve::Declined
                | Approve::Unauthorised
                | Approve::UnknownInvite
                | Approve::InviterGone
                | Approve::Refused
                | Approve::KnownKey
                | Approve::TableFull
                | Approve::NotStored => [
                    Some(ApproveAck::other(outcome).expect("not enrolled")),
                    None,
                ],
            })
            .flatten()
    }

    fn removals() -> [RemoveOperation; 3] {
        [(1, 1), (24, 0x1_0000), (u32::MAX, u32::MAX)].map(|(id, generation)| RemoveOperation {
            client_id: ClientId::new(id).expect("a slot"),
            generation: Generation::new(generation).expect("a generation"),
        })
    }

    /// Every body round-trips; the widest fills its cap exactly and every
    /// shorter destination refuses; every cut is refused, and so is a byte
    /// past the end; and a key this build does not know is skipped (P-013).
    /// Returns the widest encoding, which the caller compares with the cap.
    fn walk<T: Copy + PartialEq + fmt::Debug>(
        values: impl IntoIterator<Item = T>,
        encode: impl Fn(T, &mut [u8]) -> Result<usize, MembershipError>,
        decode: impl Fn(&[u8]) -> Result<T, MembershipError>,
    ) -> usize {
        let mut widest = 0;
        for value in values {
            let mut dst = [0u8; 128];
            let len = encode(value, &mut dst).expect("fits");
            widest = widest.max(len);
            assert_eq!(decode(&dst[..len]), Ok(value));
            for cap in 0..len {
                let mut short = [0u8; 128];
                assert!(
                    encode(value, &mut short[..cap]).is_err(),
                    "encoded into {cap}"
                );
                assert!(decode(&dst[..cap]).is_err(), "decoded a cut at {cap}");
            }
            assert_eq!(
                decode(&dst[..=len]),
                Err(MembershipError::Cbor(CborError::TrailingBytes))
            );
            dst[0] += 1;
            dst[len..len + 4].copy_from_slice(&[0x18, 99, 0x81, 0]);
            assert_eq!(decode(&dst[..len + 4]), Ok(value), "an unknown key");
        }
        widest
    }

    #[test]
    fn every_body_round_trips_fills_its_cap_and_refuses_every_cut() {
        let mut widest = 0;
        for op in invites() {
            let mut dst = [0u8; 128];
            let len = op.encode(&mut dst).expect("fits");
            widest = widest.max(len);
            assert_eq!(InviteOperation::decode(&dst[..len]), Ok(op));
            for cap in 0..len {
                let mut short = [0u8; 128];
                assert!(op.encode(&mut short[..cap]).is_err(), "encoded into {cap}");
                assert!(InviteOperation::decode(&dst[..cap]).is_err(), "cut {cap}");
            }
            assert_eq!(
                InviteOperation::decode(&dst[..=len]),
                Err(MembershipError::Cbor(CborError::TrailingBytes))
            );
            dst[0] += 1;
            dst[len..len + 4].copy_from_slice(&[0x18, 99, 0x81, 0]);
            assert_eq!(InviteOperation::decode(&dst[..len + 4]), Ok(op));
        }
        assert_eq!(widest, MAX_INVITE_OPERATION_BYTES);

        let cases = [
            (
                walk(invite_acks(), InviteAck::encode, InviteAck::decode),
                MAX_INVITE_ACK_BYTES,
            ),
            (
                walk(
                    approvals(),
                    ApproveOperation::encode,
                    ApproveOperation::decode,
                ),
                MAX_APPROVE_OPERATION_BYTES,
            ),
            (
                walk(approve_acks(), ApproveAck::encode, ApproveAck::decode),
                MAX_APPROVE_ACK_BYTES,
            ),
            (
                walk(removals(), RemoveOperation::encode, RemoveOperation::decode),
                MAX_REMOVE_OPERATION_BYTES,
            ),
            (
                walk(
                    REMOVE_OUTCOMES.map(RemoveAck),
                    RemoveAck::encode,
                    RemoveAck::decode,
                ),
                MAX_REMOVE_ACK_BYTES,
            ),
        ];
        for (index, (widest, cap)) in cases.into_iter().enumerate() {
            assert_eq!(widest, cap, "body {index}");
        }
    }

    /// `proposed` is the only answer that names an invite, and a client told
    /// `proposed` with no nonce has nothing to hand the invitee or approve by.
    #[test]
    fn an_invite_ack_carries_a_nonce_exactly_when_proposed() {
        assert_eq!(
            InviteAck::refused(Invite::Proposed),
            Err(MembershipError::ProposedWithoutNonce)
        );
        assert_eq!(
            InviteAck::decode(&[0xa1, 1, 1]),
            Err(MembershipError::ProposedWithoutNonce)
        );
        let mut with_nonce = [0u8; 21];
        with_nonce[..5].copy_from_slice(&[0xa2, 1, 2, 2, 0x50]);
        assert_eq!(
            InviteAck::decode(&with_nonce),
            Err(MembershipError::Unexpected(MembershipKey::InviteAck(
                InviteAckKey::Nonce
            ))),
            "a refusal that names an invite"
        );
        let ack = InviteAck::refused(Invite::NoBudget).expect("a refusal");
        assert_eq!(ack.nonce(), None);
    }

    /// An `enrolled` without its slot is a phone told it has one without being
    /// told which; any other outcome carrying one is a slot nobody wrote.
    #[test]
    fn an_approve_ack_carries_a_slot_exactly_when_enrolled() {
        assert_eq!(
            ApproveAck::other(Approve::Enrolled),
            Err(MembershipError::EnrolledWithoutSlot)
        );
        let mut dst = [0u8; MAX_APPROVE_ACK_BYTES];
        let len = ApproveAck::enrolled(slot(2, 1))
            .encode(&mut dst)
            .expect("fits");
        // Outcome 1 with key 4 dropped: the map says three pairs.
        let cut = len - 1 - TAG_BYTES - 1;
        dst[0] = 0xa3;
        assert_eq!(
            ApproveAck::decode(&dst[..cut]),
            Err(MembershipError::EnrolledWithoutSlot)
        );
        // The same keys under outcome 2.
        let len = ApproveAck::enrolled(slot(2, 1))
            .encode(&mut dst)
            .expect("fits");
        dst[2] = Approve::Declined as u8;
        assert_eq!(
            ApproveAck::decode(&dst[..len]),
            Err(MembershipError::Unexpected(MembershipKey::ApproveAck(
                ApproveAckKey::ClientId
            )))
        );
    }

    /// A decline has no reveal and no proof to carry, and an approval without
    /// either is one the controller cannot check (P-249 step 5).
    #[test]
    fn a_decline_carries_no_reveal_and_an_approval_carries_both() {
        let [approve, decline] = approvals();
        let mut dst = [0u8; MAX_APPROVE_OPERATION_BYTES];
        let len = approve.encode(&mut dst).expect("fits");
        dst[20] = InviteDecision::Decline as u8;
        assert_eq!(
            ApproveOperation::decode(&dst[..len]),
            Err(MembershipError::Unexpected(MembershipKey::Approve(
                ApproveKey::Reveal
            )))
        );
        let len = decline.encode(&mut dst).expect("fits");
        dst[len - 1] = InviteDecision::Approve as u8;
        assert_eq!(
            ApproveOperation::decode(&dst[..len]),
            Err(MembershipError::Missing(MembershipKey::Approve(
                ApproveKey::Reveal
            )))
        );
    }

    /// A key, a commitment, a nonce or a tag one byte short or one byte long is
    /// refused rather than padded or cut to fit: a 31-byte key padded with a
    /// zero is a different key, and the digits would be computed over it.
    #[test]
    fn a_fixed_width_string_of_any_other_length_is_refused() {
        for len in [0usize, 15, 17, 31, 33] {
            let mut body = [0u8; 64];
            let mut cbor = CborWriter::new(&mut body);
            cbor.map(1).expect("fits");
            cbor.key(1).expect("fits");
            cbor.bytes(&[0; 64][..len]).expect("fits");
            let n = cbor.finish().expect("fits");
            let want = if len == INVITE_NONCE_BYTES {
                MembershipError::Missing(MembershipKey::Approve(ApproveKey::Decision))
            } else {
                MembershipError::WrongLength(MembershipKey::Approve(ApproveKey::Nonce), len)
            };
            assert_eq!(ApproveOperation::decode(&body[..n]), Err(want), "{len}");
        }
        let op = invites().next().expect("an invite");
        let mut dst = [0u8; 128];
        let len = op.encode(&mut dst).expect("fits");
        // Key 2's head says 32 bytes; say 31 and drop one.
        assert_eq!(dst[4], 0x58);
        dst[5] = 31;
        let mut short = [0u8; 128];
        short[..37].copy_from_slice(&dst[..37]);
        short[37..len - 1].copy_from_slice(&dst[38..len]);
        assert_eq!(
            InviteOperation::decode(&short[..len - 1]),
            Err(MembershipError::WrongLength(
                MembershipKey::Invite(InviteKey::Invitee),
                31
            ))
        );
    }

    /// A zero `client_id` or generation names no enrolment. Read as one, a
    /// `Remove` of slot 0 would reach a table indexed from 1 (P-086).
    #[test]
    fn a_zero_slot_or_generation_is_refused() {
        assert_eq!(
            RemoveOperation::decode(&[0xa2, 1, 0, 2, 1]),
            Err(MembershipError::Zero(MembershipKey::Remove(
                RemoveKey::ClientId
            )))
        );
        assert_eq!(
            RemoveOperation::decode(&[0xa2, 1, 1, 2, 0]),
            Err(MembershipError::Zero(MembershipKey::Remove(
                RemoveKey::Generation
            )))
        );
        let mut dst = [0u8; MAX_APPROVE_ACK_BYTES];
        let len = ApproveAck::enrolled(slot(2, 1))
            .encode(&mut dst)
            .expect("fits");
        dst[4] = 0;
        assert_eq!(
            ApproveAck::decode(&dst[..len]),
            Err(MembershipError::Zero(MembershipKey::ApproveAck(
                ApproveAckKey::ClientId
            )))
        );
    }

    /// A label is what a person tells two rows apart by. Empty, the owner
    /// approving an invite cannot say whose it is; past `MAX_LABEL`, the client
    /// list cannot hold it. Both ends refuse.
    #[test]
    fn an_empty_or_overlong_label_is_refused_both_ways() {
        let base = invites().next().expect("an invite");
        let long = "0123456789abcdef0123456789abcdefX";
        for (label, want) in [
            ("", MembershipError::EmptyLabel),
            (long, MembershipError::LabelTooLong(MAX_LABEL + 1)),
        ] {
            let op = InviteOperation { label, ..base };
            let mut dst = [0u8; 128];
            assert_eq!(op.encode(&mut dst), Err(want));
            let mut cbor = CborWriter::new(&mut dst);
            cbor.map(1).expect("fits");
            cbor.key(InviteKey::Label.number()).expect("fits");
            cbor.text(label).expect("fits");
            let n = cbor.finish().expect("fits");
            assert_eq!(InviteOperation::decode(&dst[..n]), Err(want));
        }
    }

    #[test]
    fn p_015_missing_and_repeated_keys_are_refused() {
        assert_eq!(
            RemoveOperation::decode(&[0xa1, 2, 1]),
            Err(MembershipError::Missing(MembershipKey::Remove(
                RemoveKey::ClientId
            )))
        );
        assert_eq!(
            RemoveOperation::decode(&[0xa3, 1, 1, 2, 1, 1, 2]),
            Err(MembershipError::Duplicate(MembershipKey::Remove(
                RemoveKey::ClientId
            )))
        );
        assert_eq!(
            RemoveAck::decode(&[0xa0]),
            Err(MembershipError::Missing(MembershipKey::RemoveAckOutcome))
        );
        assert_eq!(
            RemoveAck::decode(&[0xa2, 1, 1, 1, 2]),
            Err(MembershipError::Duplicate(MembershipKey::RemoveAckOutcome))
        );
        assert_eq!(
            InviteAck::decode(&[0xa0]),
            Err(MembershipError::Missing(MembershipKey::InviteAck(
                InviteAckKey::Outcome
            )))
        );
        assert_eq!(
            ApproveAck::decode(&[0xa2, 1, 2, 1, 2]),
            Err(MembershipError::Duplicate(MembershipKey::ApproveAck(
                ApproveAckKey::Outcome
            )))
        );
        assert_eq!(
            InviteOperation::decode(&[0xa1, 1, 2]),
            Err(MembershipError::Missing(MembershipKey::Invite(
                InviteKey::Invitee
            )))
        );
        assert_eq!(
            InviteOperation::decode(&[0xa2, 1, 2, 1, 2]),
            Err(MembershipError::Duplicate(MembershipKey::Invite(
                InviteKey::Role
            )))
        );
    }

    /// A number the registry never allocated is a sender this build cannot
    /// understand, not a value to guess at. Zero is what a sender that forgot
    /// the field writes, and the first value past each space is the next one
    /// somebody will allocate.
    #[test]
    fn unallocated_roles_kinds_decisions_and_outcomes_are_refused() {
        for number in [0u8, 4] {
            assert_eq!(
                InviteOperation::decode(&[0xa1, 1, number]),
                Err(MembershipError::UnknownRole(number))
            );
        }
        for number in [0u8, 5] {
            assert_eq!(
                InviteOperation::decode(&[0xa1, 4, number]),
                Err(MembershipError::UnknownClientKind(number))
            );
        }
        for number in [0u8, 3] {
            assert_eq!(
                ApproveOperation::decode(&[0xa1, 2, number]),
                Err(MembershipError::UnknownDecision(number))
            );
        }
        for (number, invite, approve, remove) in [(0u8, true, true, true), (7, true, false, true)] {
            assert_eq!(
                InviteAck::decode(&[0xa1, 1, number]).is_err(),
                invite,
                "{number}"
            );
            assert_eq!(
                ApproveAck::decode(&[0xa1, 1, number]).is_err(),
                approve,
                "{number}"
            );
            assert_eq!(RemoveAck::decode(&[0xa1, 1, number]).is_err(), remove);
        }
        assert_eq!(
            ApproveAck::decode(&[0xa1, 1, 10]),
            Err(MembershipError::UnknownOutcome(10))
        );
        assert_eq!(
            RemoveAck::decode(&[0xa1, 1, 6]),
            Err(MembershipError::UnknownOutcome(6))
        );
    }

    /// The wrong CBOR type under a known key is refused rather than coerced.
    #[test]
    fn a_known_key_of_the_wrong_type_is_refused() {
        for bytes in [&[0xa1, 1, 0xf5][..], &[0xa1, 2, 0x01], &[0x81, 1]] {
            assert!(InviteOperation::decode(bytes).is_err(), "{bytes:02x?}");
            assert!(ApproveOperation::decode(bytes).is_err(), "{bytes:02x?}");
            assert!(RemoveOperation::decode(bytes).is_err(), "{bytes:02x?}");
        }
        assert!(RemoveOperation::decode(&[0xa1, 1, 0x20]).is_err());
        assert!(RemoveOperation::decode(&[0xa1, 1, 0x1b, 1, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(InviteAck::decode(&[0xa1, 1, 0xf5]).is_err());
        assert!(ApproveAck::decode(&[0xa1, 1, 0x20]).is_err());
        assert!(RemoveAck::decode(&[0x81, 1]).is_err());
    }

    #[test]
    fn refusals_render_and_map_to_malformed_frame() {
        let errors = [
            MembershipError::Missing(MembershipKey::Invite(InviteKey::Role)),
            MembershipError::Duplicate(MembershipKey::Remove(RemoveKey::Generation)),
            MembershipError::Unexpected(MembershipKey::Approve(ApproveKey::Proof)),
            MembershipError::WrongLength(MembershipKey::ApproveAck(ApproveAckKey::Confirm), 3),
            MembershipError::Zero(MembershipKey::RemoveAckOutcome),
            MembershipError::UnknownRole(9),
            MembershipError::UnknownClientKind(9),
            MembershipError::UnknownDecision(9),
            MembershipError::UnknownOutcome(9),
            MembershipError::EmptyLabel,
            MembershipError::LabelTooLong(40),
            MembershipError::ProposedWithoutNonce,
            MembershipError::EnrolledWithoutSlot,
            MembershipError::Cbor(CborError::WrongType),
        ];
        Rendering::<100>::each_says_something_of_its_own(&errors);
        for error in errors {
            assert_eq!(error.refusal(), Refusal::Client(ErrorCode::MalformedFrame));
        }
    }
}
