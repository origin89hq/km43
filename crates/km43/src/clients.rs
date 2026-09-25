//! `Clients 0x18` / `0x98`: who is enrolled and who has been proposed, in one
//! answer an owner and an admin both read (P-251).
//!
//! The answer is also where an owner reads an invite's transcript before
//! approving it (P-257), so an [`InviteRow`] carries every field of it the
//! controller holds and an owner's app does not take any of them from the
//! relay. A decoded answer keeps its rows as the bytes they arrived in and
//! checks them once, so a controller builds one from its tables and a client
//! reads one without an array of rows on either stack.
//!
//! cites: P-013, P-015

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{ClientKind, ErrorCode, Role, Suite};
use crate::invite::{INVITE_NONCE_BYTES, InviteNonce};
use crate::kdf::{ClientId, Generation};
use crate::limits::{INVITE_TTL_MS, MAX_CLIENTS, MAX_INVITES, MAX_LABEL};
use crate::noise::{KEY_BYTES, PublicKey};

/// The longest `expires_in` an invite can carry: P-253's deadline in seconds.
const MAX_EXPIRES_IN: u64 = INVITE_TTL_MS / 1000;

/// A field of either row or of the answer around them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientsField {
    /// `Clients 0x98` key 1.
    Clients,
    /// `Clients 0x98` key 2.
    Invites,
    /// `ClientRow` key 1.
    ClientId,
    /// `ClientRow` key 2.
    Generation,
    /// Key 3 of `ClientRow`, key 2 of `InviteRow`.
    Role,
    /// Key 4 of `ClientRow`, key 6 of `InviteRow`.
    ClientKind,
    /// Key 5 of `ClientRow`, key 7 of `InviteRow`.
    Label,
    /// `InviteRow` key 1.
    Nonce,
    /// `InviteRow` key 3.
    Invitee,
    /// `InviteRow` key 4.
    Inviter,
    /// `InviteRow` key 5.
    InviterGeneration,
    /// `InviteRow` key 8.
    ExpiresIn,
    /// `InviteRow` key 9.
    Suite,
}

impl fmt::Display for ClientsField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Clients => "Clients 0x98 clients (key 1)",
            Self::Invites => "Clients 0x98 invites (key 2)",
            Self::ClientId => "ClientRow client_id (key 1)",
            Self::Generation => "ClientRow generation (key 2)",
            Self::Role => "role",
            Self::ClientKind => "client_kind",
            Self::Label => "label",
            Self::Nonce => "InviteRow nonce (key 1)",
            Self::Invitee => "InviteRow invitee (key 3)",
            Self::Inviter => "InviteRow inviter (key 4)",
            Self::InviterGeneration => "InviteRow inviter_generation (key 5)",
            Self::ExpiresIn => "InviteRow expires_in (key 8)",
            Self::Suite => "InviteRow suite (key 9)",
        })
    }
}

/// One occupied slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientRow<'a> {
    /// Key 1.
    pub client_id: ClientId,
    /// Key 2, the enrolment a `Remove 0x17` names.
    pub generation: Generation,
    /// Key 3.
    pub role: Role,
    /// Key 4, shown and deciding nothing (P-105).
    pub client_kind: ClientKind,
    /// Key 5, up to `MAX_LABEL` bytes. A pairing may have sent an empty one.
    pub label: &'a str,
}

/// One pending invite: every field of P-257's transcript the controller holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteRow<'a> {
    /// Key 1, `N_c`: the invite's name.
    pub nonce: InviteNonce,
    /// Key 2.
    pub role: Role,
    /// Key 3, `IS`.
    pub invitee: PublicKey,
    /// Key 4.
    pub inviter: ClientId,
    /// Key 5.
    pub inviter_generation: Generation,
    /// Key 6.
    pub client_kind: ClientKind,
    /// Key 7, 1 to `MAX_LABEL` bytes, as the `Invite` carried it.
    pub label: &'a str,
    /// Key 8, seconds left on P-253's monotonic deadline, at most an hour.
    pub expires_in: u32,
    /// Key 9, the suite the slot will pin.
    pub suite: Suite,
}

/// What both row types share, so one list type holds either.
trait Row<'a>: Copy + PartialEq {
    /// The most rows a list of these may hold.
    const MAX: usize;
    /// The field a list of these is under, for a refusal.
    const FIELD: ClientsField;
    fn check(&self) -> Result<(), ClientsError>;
    fn encode_into(&self, cbor: &mut CborWriter<'_>) -> Result<(), ClientsError>;
    fn decode_from(cbor: &mut CborReader<'a>) -> Result<Self, ClientsError>;
    /// Whether `self` may follow `earlier` in the list.
    fn follows(&self, earlier: &Self) -> Result<(), ClientsError>;
}

impl<'a> Row<'a> for ClientRow<'a> {
    const MAX: usize = MAX_CLIENTS;
    const FIELD: ClientsField = ClientsField::Clients;

    fn check(&self) -> Result<(), ClientsError> {
        if self.label.len() > MAX_LABEL {
            return Err(ClientsError::LabelLength(self.label.len()));
        }
        Ok(())
    }

    fn encode_into(&self, cbor: &mut CborWriter<'_>) -> Result<(), ClientsError> {
        self.check()?;
        cbor.map(5)?;
        cbor.key(1)?;
        cbor.u64(u64::from(self.client_id.get()))?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.generation.get()))?;
        cbor.key(3)?;
        cbor.u64(u64::from(self.role as u8))?;
        cbor.key(4)?;
        cbor.u64(u64::from(self.client_kind as u8))?;
        cbor.key(5)?;
        cbor.text(self.label)?;
        Ok(())
    }

    fn decode_from(cbor: &mut CborReader<'a>) -> Result<Self, ClientsError> {
        let pairs = cbor.map()?;
        let (mut id, mut generation, mut role, mut kind, mut label) =
            (None, None, None, None, None);
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(
                    &mut id,
                    ClientsField::ClientId,
                    client_id(cbor, ClientsField::ClientId)?,
                )?,
                2 => once(
                    &mut generation,
                    ClientsField::Generation,
                    generation_of(cbor, ClientsField::Generation)?,
                )?,
                3 => once(&mut role, ClientsField::Role, role_of(cbor)?)?,
                4 => once(&mut kind, ClientsField::ClientKind, kind_of(cbor)?)?,
                5 => once(&mut label, ClientsField::Label, cbor.text()?)?,
                _ => cbor.skip()?,
            }
        }
        let row = Self {
            client_id: id.ok_or(ClientsError::Missing(ClientsField::ClientId))?,
            generation: generation.ok_or(ClientsError::Missing(ClientsField::Generation))?,
            role: role.ok_or(ClientsError::Missing(ClientsField::Role))?,
            client_kind: kind.ok_or(ClientsError::Missing(ClientsField::ClientKind))?,
            label: label.ok_or(ClientsError::Missing(ClientsField::Label))?,
        };
        row.check()?;
        Ok(row)
    }

    fn follows(&self, earlier: &Self) -> Result<(), ClientsError> {
        if self.client_id.get() <= earlier.client_id.get() {
            return Err(ClientsError::SlotsOutOfOrder);
        }
        Ok(())
    }
}

impl<'a> Row<'a> for InviteRow<'a> {
    const MAX: usize = MAX_INVITES;
    const FIELD: ClientsField = ClientsField::Invites;

    fn check(&self) -> Result<(), ClientsError> {
        if self.label.is_empty() || self.label.len() > MAX_LABEL {
            return Err(ClientsError::LabelLength(self.label.len()));
        }
        if u64::from(self.expires_in) > MAX_EXPIRES_IN {
            return Err(ClientsError::ExpiresTooLate(self.expires_in));
        }
        Ok(())
    }

    fn encode_into(&self, cbor: &mut CborWriter<'_>) -> Result<(), ClientsError> {
        self.check()?;
        cbor.map(9)?;
        cbor.key(1)?;
        cbor.bytes(&self.nonce.0)?;
        cbor.key(2)?;
        cbor.u64(u64::from(self.role as u8))?;
        cbor.key(3)?;
        cbor.bytes(self.invitee.as_bytes())?;
        cbor.key(4)?;
        cbor.u64(u64::from(self.inviter.get()))?;
        cbor.key(5)?;
        cbor.u64(u64::from(self.inviter_generation.get()))?;
        cbor.key(6)?;
        cbor.u64(u64::from(self.client_kind as u8))?;
        cbor.key(7)?;
        cbor.text(self.label)?;
        cbor.key(8)?;
        cbor.u64(u64::from(self.expires_in))?;
        cbor.key(9)?;
        cbor.u64(u64::from(self.suite as u8))?;
        Ok(())
    }

    fn decode_from(cbor: &mut CborReader<'a>) -> Result<Self, ClientsError> {
        let pairs = cbor.map()?;
        let (mut nonce, mut role, mut key, mut proposer, mut generation) =
            (None, None, None, None, None);
        let (mut kind, mut label, mut expires_in, mut suite) = (None, None, None, None);
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(
                    &mut nonce,
                    ClientsField::Nonce,
                    fixed::<INVITE_NONCE_BYTES>(cbor, ClientsField::Nonce)?,
                )?,
                2 => once(&mut role, ClientsField::Role, role_of(cbor)?)?,
                3 => once(
                    &mut key,
                    ClientsField::Invitee,
                    fixed::<KEY_BYTES>(cbor, ClientsField::Invitee)?,
                )?,
                4 => once(
                    &mut proposer,
                    ClientsField::Inviter,
                    client_id(cbor, ClientsField::Inviter)?,
                )?,
                5 => once(
                    &mut generation,
                    ClientsField::InviterGeneration,
                    generation_of(cbor, ClientsField::InviterGeneration)?,
                )?,
                6 => once(&mut kind, ClientsField::ClientKind, kind_of(cbor)?)?,
                7 => once(&mut label, ClientsField::Label, cbor.text()?)?,
                8 => once(&mut expires_in, ClientsField::ExpiresIn, cbor.u32()?)?,
                9 => {
                    let raw = cbor.u8()?;
                    let known = Suite::try_from(raw).map_err(|()| ClientsError::Unallocated {
                        field: ClientsField::Suite,
                        raw,
                    })?;
                    once(&mut suite, ClientsField::Suite, known)?;
                }
                _ => cbor.skip()?,
            }
        }
        let missing = ClientsError::Missing;
        let row = Self {
            nonce: InviteNonce(nonce.ok_or(missing(ClientsField::Nonce))?),
            role: role.ok_or(missing(ClientsField::Role))?,
            invitee: PublicKey::from_bytes(key.ok_or(missing(ClientsField::Invitee))?),
            inviter: proposer.ok_or(missing(ClientsField::Inviter))?,
            inviter_generation: generation.ok_or(missing(ClientsField::InviterGeneration))?,
            client_kind: kind.ok_or(missing(ClientsField::ClientKind))?,
            label: label.ok_or(missing(ClientsField::Label))?,
            expires_in: expires_in.ok_or(missing(ClientsField::ExpiresIn))?,
            suite: suite.ok_or(missing(ClientsField::Suite))?,
        };
        row.check()?;
        Ok(row)
    }

    fn follows(&self, earlier: &Self) -> Result<(), ClientsError> {
        if self.nonce == earlier.nonce {
            return Err(ClientsError::InviteRepeated);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Rows<'a, R> {
    /// Rows a controller built from its tables.
    Built(&'a [R]),
    /// The CBOR array as it arrived, walked and checked once on decode.
    Read { array: &'a [u8], count: usize },
}

impl<'a, R: Row<'a>> Rows<'a, R> {
    const fn len(&self) -> usize {
        match self {
            Self::Built(rows) => rows.len(),
            Self::Read { count, .. } => *count,
        }
    }

    fn iter(&self) -> RowIter<'a, R> {
        match *self {
            Self::Built(rows) => RowIter {
                built: rows.iter(),
                read: CborReader::new(&[]),
                left: 0,
                header: Ok(()),
            },
            Self::Read { array, count } => {
                let mut read = CborReader::new(array);
                // Checked on decode, so the header reads; a failure here is
                // reported by the first `next` rather than hidden.
                let header = read.array().map(|_| ());
                RowIter {
                    built: [].iter(),
                    read,
                    left: count,
                    header,
                }
            }
        }
    }

    /// Every row checked, and each against every row before it: slots strictly
    /// ascending, no invite twice. Eight rows and four, so the square is small.
    fn check(&self) -> Result<(), ClientsError> {
        if self.len() > R::MAX {
            return Err(ClientsError::TooMany(R::FIELD, self.len()));
        }
        for (at, row) in self.iter().enumerate() {
            let row = row?;
            row.check()?;
            for earlier in self.iter().take(at) {
                row.follows(&earlier?)?;
            }
        }
        Ok(())
    }

    fn encode(&self, cbor: &mut CborWriter<'_>) -> Result<(), ClientsError> {
        match self {
            Self::Built(rows) => {
                cbor.array(rows.len())?;
                for row in *rows {
                    row.encode_into(cbor)?;
                }
            }
            Self::Read { array, .. } => cbor.raw(array)?,
        }
        Ok(())
    }

    fn read(array: &'a [u8]) -> Result<Self, ClientsError> {
        let count = CborReader::new(array).array()?;
        if count > R::MAX {
            return Err(ClientsError::TooMany(R::FIELD, count));
        }
        let rows = Self::Read { array, count };
        rows.check()?;
        Ok(rows)
    }

    fn same(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

/// The rows of one list. A decoded answer was checked whole before it was
/// handed out, so an `Err` here means the bytes changed underneath it.
struct RowIter<'a, R> {
    built: core::slice::Iter<'a, R>,
    read: CborReader<'a>,
    left: usize,
    header: Result<(), CborError>,
}

impl<'a, R: Row<'a>> Iterator for RowIter<'a, R> {
    type Item = Result<R, ClientsError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(row) = self.built.next() {
            return Some(Ok(*row));
        }
        if self.left == 0 {
            return None;
        }
        self.left = self.left.saturating_sub(1);
        if let Err(why) = self.header {
            self.left = 0;
            return Some(Err(ClientsError::Cbor(why)));
        }
        Some(R::decode_from(&mut self.read))
    }
}

/// `Clients 0x98`: every occupied slot, lowest first, and every pending
/// invite, at most `MAX_CLIENTS` and `MAX_INVITES` (P-251, P-253).
#[derive(Clone, Copy)]
pub struct ClientsAnswer<'a> {
    clients: Rows<'a, ClientRow<'a>>,
    invites: Rows<'a, InviteRow<'a>>,
}

impl<'a> ClientsAnswer<'a> {
    /// Check the controller's rows: slots strictly ascending, no invite twice,
    /// every label and deadline in bounds.
    pub fn new(
        clients: &'a [ClientRow<'a>],
        invites: &'a [InviteRow<'a>],
    ) -> Result<Self, ClientsError> {
        let answer = Self {
            clients: Rows::Built(clients),
            invites: Rows::Built(invites),
        };
        answer.clients.check()?;
        answer.invites.check()?;
        Ok(answer)
    }

    /// The occupied slots, lowest first.
    pub fn clients(&self) -> impl Iterator<Item = Result<ClientRow<'a>, ClientsError>> {
        self.clients.iter()
    }

    /// The pending invites, oldest first.
    pub fn invites(&self) -> impl Iterator<Item = Result<InviteRow<'a>, ClientsError>> {
        self.invites.iter()
    }

    /// How many slots and how many invites.
    #[must_use]
    pub const fn counts(&self) -> (usize, usize) {
        (self.clients.len(), self.invites.len())
    }

    /// Encode the inner body the sealed body carries.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ClientsError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(2)?;
        cbor.key(1)?;
        self.clients.encode(&mut cbor)?;
        cbor.key(2)?;
        self.invites.encode(&mut cbor)?;
        Ok(cbor.finish()?)
    }

    /// Read the inner body once it has opened.
    pub fn decode(payload: &'a [u8]) -> Result<Self, ClientsError> {
        let mut cbor = CborReader::new(payload);
        let pairs = cbor.map()?;
        let (mut clients, mut invites) = (None, None);
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(&mut clients, ClientsField::Clients, cbor.raw()?)?,
                2 => once(&mut invites, ClientsField::Invites, cbor.raw()?)?,
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        Ok(Self {
            clients: Rows::read(clients.ok_or(ClientsError::Missing(ClientsField::Clients))?)?,
            invites: Rows::read(invites.ok_or(ClientsError::Missing(ClientsField::Invites))?)?,
        })
    }
}

/// Two answers are equal when their rows are, whichever side built each.
impl PartialEq for ClientsAnswer<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.clients.same(&other.clients) && self.invites.same(&other.invites)
    }
}

impl Eq for ClientsAnswer<'_> {}

impl fmt::Debug for ClientsAnswer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientsAnswer")
            .field("clients", &self.clients.len())
            .field("invites", &self.invites.len())
            .finish()
    }
}

fn client_id(cbor: &mut CborReader<'_>, field: ClientsField) -> Result<ClientId, ClientsError> {
    ClientId::new(cbor.u32()?).ok_or(ClientsError::Zero(field))
}

fn generation_of(
    cbor: &mut CborReader<'_>,
    field: ClientsField,
) -> Result<Generation, ClientsError> {
    Generation::new(cbor.u32()?).ok_or(ClientsError::Zero(field))
}

fn role_of(cbor: &mut CborReader<'_>) -> Result<Role, ClientsError> {
    let raw = cbor.u8()?;
    Role::try_from(raw).map_err(|()| ClientsError::Unallocated {
        field: ClientsField::Role,
        raw,
    })
}

fn kind_of(cbor: &mut CborReader<'_>) -> Result<ClientKind, ClientsError> {
    let raw = cbor.u8()?;
    ClientKind::try_from(raw).map_err(|()| ClientsError::Unallocated {
        field: ClientsField::ClientKind,
        raw,
    })
}

fn fixed<const N: usize>(
    cbor: &mut CborReader<'_>,
    field: ClientsField,
) -> Result<[u8; N], ClientsError> {
    let bytes = cbor.bytes()?;
    bytes
        .try_into()
        .map_err(|_| ClientsError::WrongLength(field, bytes.len()))
}

fn once<T>(slot: &mut Option<T>, field: ClientsField, value: T) -> Result<(), ClientsError> {
    if slot.is_some() {
        return Err(ClientsError::Duplicate(field));
    }
    *slot = Some(value);
    Ok(())
}

/// Why a `Clients 0x98` was refused, built or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientsError {
    /// A required key never arrived (P-015).
    Missing(ClientsField),
    /// The same key twice (P-015).
    Duplicate(ClientsField),
    /// A value its registry table does not allocate.
    Unallocated {
        /// Which field.
        field: ClientsField,
        /// What it carried.
        raw: u8,
    },
    /// A `client_id` or generation of zero, which names no enrolment.
    Zero(ClientsField),
    /// A nonce or key of the wrong length: the length it had.
    WrongLength(ClientsField, usize),
    /// A label past `MAX_LABEL`, or an invite's empty one: its length.
    LabelLength(usize),
    /// An `expires_in` past P-253's hour: a deadline no invite can have.
    ExpiresTooLate(u32),
    /// More rows than the table holds: the list and its count.
    TooMany(ClientsField, usize),
    /// A slot not above the one before it: out of order, or the same slot
    /// twice.
    SlotsOutOfOrder,
    /// The same invite twice.
    InviteRepeated,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for ClientsError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl ClientsError {
    /// What to answer: error 1. A client list that cannot be read cannot be
    /// approved from, and a controller that built one has a table to repair.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::Unallocated { .. }
            | Self::Zero(_)
            | Self::WrongLength(..)
            | Self::LabelLength(_)
            | Self::ExpiresTooLate(_)
            | Self::TooMany(..)
            | Self::SlotsOutOfOrder
            | Self::InviteRepeated
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for ClientsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(field) => write!(f, "no {field}"),
            Self::Duplicate(field) => write!(f, "{field} twice"),
            Self::Unallocated { field, raw } => write!(f, "unallocated {field} {raw}"),
            Self::Zero(field) => write!(f, "{field} of zero, which names no enrolment"),
            Self::WrongLength(field, len) => write!(f, "{field} of {len} bytes"),
            Self::LabelLength(len) => write!(f, "a label of {len} bytes"),
            Self::ExpiresTooLate(secs) => {
                write!(f, "an invite expiring in {secs} s, past {MAX_EXPIRES_IN}")
            }
            Self::TooMany(field, count) => write!(f, "{count} rows under {field}"),
            Self::SlotsOutOfOrder => f.write_str("client rows not in ascending slot order"),
            Self::InviteRepeated => f.write_str("the same invite listed twice"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for ClientsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{
        CLIENT_ROW_MAX_BYTES, CLIENTS_HEADER_BYTES, CLIENTS_MAX_BYTES, INVITE_ROW_MAX_BYTES,
    };
    use crate::render::Rendering;

    const LABEL: &str = "0123456789abcdef0123456789abcdef";
    const MAX_EXPIRES: u32 = 3600;

    fn client(id: u32, label: &'static str) -> ClientRow<'static> {
        ClientRow {
            client_id: ClientId::new(id).expect("a slot"),
            generation: Generation::new(u32::MAX).expect("a generation"),
            role: Role::Admin,
            client_kind: ClientKind::App,
            label,
        }
    }

    fn invite(first: u8, label: &'static str) -> InviteRow<'static> {
        InviteRow {
            nonce: InviteNonce([first; INVITE_NONCE_BYTES]),
            role: Role::Owner,
            invitee: PublicKey::from_bytes([0xA5; KEY_BYTES]),
            inviter: ClientId::new(u32::MAX).expect("a slot"),
            inviter_generation: Generation::new(u32::MAX).expect("a generation"),
            client_kind: ClientKind::Browser,
            label,
            expires_in: MAX_EXPIRES,
            suite: Suite::X25519ChachapolySha256,
        }
    }

    /// Eight slots at the top of the `u32` range, so every id is five bytes.
    fn widest_clients() -> [ClientRow<'static>; MAX_CLIENTS] {
        core::array::from_fn(|at| {
            let offset = u32::try_from(MAX_CLIENTS - at).expect("small");
            client(u32::MAX - offset + 1, LABEL)
        })
    }

    fn widest_invites() -> [InviteRow<'static>; MAX_INVITES] {
        core::array::from_fn(|at| invite(u8::try_from(at).expect("small"), LABEL))
    }

    fn encoded(answer: &ClientsAnswer<'_>) -> ([u8; CLIENTS_MAX_BYTES + 8], usize) {
        let mut dst = [0; CLIENTS_MAX_BYTES + 8];
        let len = answer.encode(&mut dst).expect("fits");
        (dst, len)
    }

    /// The widest answer the tables can hold fills `CLIENTS_MAX_BYTES` exactly,
    /// and the parts add up the way `limits.rs` says they do. A cap that is
    /// only above the real width is a cap nothing measured.
    #[test]
    fn a_full_table_and_full_invites_fill_the_cap_exactly() {
        let (clients, invites) = (widest_clients(), widest_invites());
        let answer = ClientsAnswer::new(&clients, &invites).expect("valid");
        let (_, len) = encoded(&answer);
        assert_eq!(len, CLIENTS_MAX_BYTES);

        let mut one = [0u8; 128];
        let mut cbor = CborWriter::new(&mut one);
        clients[0].encode_into(&mut cbor).expect("fits");
        assert_eq!(cbor.finish(), Ok(CLIENT_ROW_MAX_BYTES));
        let mut cbor = CborWriter::new(&mut one);
        invites[0].encode_into(&mut cbor).expect("fits");
        assert_eq!(cbor.finish(), Ok(INVITE_ROW_MAX_BYTES));
        let empty = ClientsAnswer::new(&[], &[]).expect("valid");
        assert_eq!(encoded(&empty).1, CLIENTS_HEADER_BYTES);

        for cap in 0..len {
            let mut short = [0u8; CLIENTS_MAX_BYTES];
            assert!(
                answer.encode(&mut short[..cap]).is_err(),
                "encoded into {cap}"
            );
        }
    }

    /// A resynchronising receiver hands the decoder whatever it has. Every cut
    /// is refused and so is a byte past the end, for a full answer, a small one
    /// and an empty one.
    #[test]
    fn every_answer_round_trips_and_every_cut_is_refused() {
        let (clients, invites) = (widest_clients(), widest_invites());
        let small_clients = [client(1, ""), client(3, "x")];
        let small_invites = [invite(9, "y")];
        for answer in [
            ClientsAnswer::new(&clients, &invites).expect("valid"),
            ClientsAnswer::new(&small_clients, &small_invites).expect("valid"),
            ClientsAnswer::new(&small_clients, &[]).expect("valid"),
            ClientsAnswer::new(&[], &[]).expect("valid"),
        ] {
            let (dst, len) = encoded(&answer);
            let read = ClientsAnswer::decode(&dst[..len]).expect("reads back");
            assert_eq!(read, answer);
            assert_eq!(read.counts(), answer.counts());
            for (a, b) in read.clients().zip(answer.clients()) {
                assert_eq!(a, b);
            }
            for (a, b) in read.invites().zip(answer.invites()) {
                assert_eq!(a, b);
            }
            let (again, again_len) = encoded(&read);
            assert_eq!(
                &again[..again_len],
                &dst[..len],
                "a read answer re-encodes as it came"
            );
            for cut in 0..len {
                assert!(ClientsAnswer::decode(&dst[..cut]).is_err(), "cut {cut}");
            }
            assert_eq!(
                ClientsAnswer::decode(&dst[..=len]),
                Err(ClientsError::Cbor(CborError::TrailingBytes))
            );
        }
    }

    /// Nine slots is a table no controller has, and five invites is past the
    /// table P-253 holds. Both refused whether built or read.
    #[test]
    fn more_rows_than_either_table_holds_are_refused() {
        let nine: [ClientRow<'static>; MAX_CLIENTS + 1] =
            core::array::from_fn(|at| client(u32::try_from(at + 1).expect("small"), "x"));
        assert_eq!(
            ClientsAnswer::new(&nine, &[]),
            Err(ClientsError::TooMany(
                ClientsField::Clients,
                MAX_CLIENTS + 1
            ))
        );
        let five: [InviteRow<'static>; MAX_INVITES + 1] =
            core::array::from_fn(|at| invite(u8::try_from(at).expect("small"), "x"));
        assert_eq!(
            ClientsAnswer::new(&[], &five),
            Err(ClientsError::TooMany(
                ClientsField::Invites,
                MAX_INVITES + 1
            ))
        );
        // The same rows written out whole, so the count is what refuses them
        // and not a read that ran out of bytes.
        let mut body = [0u8; 1024];
        let mut cbor = CborWriter::new(&mut body);
        cbor.map(2).expect("fits");
        cbor.key(1).expect("fits");
        cbor.array(nine.len()).expect("fits");
        for row in &nine {
            row.encode_into(&mut cbor).expect("fits");
        }
        cbor.key(2).expect("fits");
        cbor.array(five.len()).expect("fits");
        for row in &five {
            row.encode_into(&mut cbor).expect("fits");
        }
        let len = cbor.finish().expect("fits");
        assert_eq!(
            ClientsAnswer::decode(&body[..len]),
            Err(ClientsError::TooMany(
                ClientsField::Clients,
                MAX_CLIENTS + 1
            ))
        );
    }

    /// The list is lowest slot first and one row per slot, and an invite is
    /// listed once. A list that breaks either is a table that is broken, and an
    /// owner approving from it could be reading the wrong invite's digits.
    #[test]
    fn slots_out_of_order_or_repeated_and_repeated_invites_are_refused() {
        for rows in [
            [client(2, "a"), client(1, "b")],
            [client(4, "a"), client(4, "b")],
        ] {
            assert_eq!(
                ClientsAnswer::new(&rows, &[]),
                Err(ClientsError::SlotsOutOfOrder)
            );
        }
        let twice = [invite(7, "a"), invite(1, "b"), invite(7, "c")];
        assert_eq!(
            ClientsAnswer::new(&[], &twice),
            Err(ClientsError::InviteRepeated)
        );

        // The same refusals reading: encode a valid answer, then swap two rows.
        let rows = [client(1, "a"), client(2, "b")];
        let answer = ClientsAnswer::new(&rows, &[]).expect("valid");
        let (mut dst, len) = encoded(&answer);
        let first = dst.iter().position(|&b| b == 0xa5).expect("a row");
        let size = (len - first - 2) / 2;
        let mut swapped = [0u8; 64];
        swapped[..size].copy_from_slice(&dst[first + size..first + 2 * size]);
        swapped[size..2 * size].copy_from_slice(&dst[first..first + size]);
        dst[first..first + 2 * size].copy_from_slice(&swapped[..2 * size]);
        assert_eq!(
            ClientsAnswer::decode(&dst[..len]),
            Err(ClientsError::SlotsOutOfOrder)
        );
    }

    /// A slot's label came from a pairing and may be empty; an invite's came
    /// from `Invite`, which refuses an empty one (P-252). Neither may pass
    /// `MAX_LABEL`, and an invite may not claim a deadline past P-253's hour.
    #[test]
    fn labels_and_deadlines_out_of_bounds_are_refused() {
        let long = "0123456789abcdef0123456789abcdefX";
        assert!(ClientsAnswer::new(&[client(1, "")], &[]).is_ok());
        assert_eq!(
            ClientsAnswer::new(&[client(1, long)], &[]),
            Err(ClientsError::LabelLength(MAX_LABEL + 1))
        );
        assert_eq!(
            ClientsAnswer::new(&[], &[invite(1, "")]),
            Err(ClientsError::LabelLength(0))
        );
        let late = InviteRow {
            expires_in: MAX_EXPIRES + 1,
            ..invite(1, "x")
        };
        assert_eq!(
            ClientsAnswer::new(&[], &[late]),
            Err(ClientsError::ExpiresTooLate(MAX_EXPIRES + 1))
        );
    }

    /// A one-slot answer with one field of its row replaced by `value`, or with
    /// an extra key 9 when `key` is 9, and what the reader says about it.
    fn with_client_field(
        body: &mut [u8; 128],
        key: i64,
        value: &[u8],
    ) -> Result<(usize, usize), ClientsError> {
        let mut cbor = CborWriter::new(body);
        cbor.map(2)?;
        cbor.key(1)?;
        cbor.array(1)?;
        cbor.map(if key == 9 { 6 } else { 5 })?;
        for (k, v) in [(1, &[1][..]), (2, &[1]), (3, &[2]), (4, &[1]), (5, &[0x60])] {
            cbor.key(k)?;
            cbor.raw(if k == key { value } else { v })?;
        }
        if key == 9 {
            cbor.key(9)?;
            cbor.raw(value)?;
        }
        cbor.key(2)?;
        cbor.array(0)?;
        let len = cbor.finish()?;
        ClientsAnswer::decode(&body[..len]).map(|answer| answer.counts())
    }

    #[test]
    fn a_zero_slot_or_an_unallocated_value_in_a_row_is_refused() {
        let mut body = [0u8; 128];
        assert_eq!(with_client_field(&mut body, 0, &[]), Ok((1, 0)));
        for (key, value, want) in [
            (1, &[0][..], ClientsError::Zero(ClientsField::ClientId)),
            (2, &[0], ClientsError::Zero(ClientsField::Generation)),
            (
                3,
                &[4],
                ClientsError::Unallocated {
                    field: ClientsField::Role,
                    raw: 4,
                },
            ),
            (
                4,
                &[0],
                ClientsError::Unallocated {
                    field: ClientsField::ClientKind,
                    raw: 0,
                },
            ),
            (5, &[0x01], ClientsError::Cbor(CborError::WrongType)),
        ] {
            assert_eq!(
                with_client_field(&mut body, key, value),
                Err(want),
                "key {key}"
            );
        }
    }

    /// A v2 row adds a key; a v1 reader skips it (P-013). So does the answer.
    #[test]
    fn p_013_unknown_keys_in_a_row_and_in_the_answer_are_skipped() {
        let mut body = [0u8; 128];
        assert_eq!(with_client_field(&mut body, 9, &[0x81, 0]), Ok((1, 0)));
        assert_eq!(
            ClientsAnswer::decode(&[0xa3, 1, 0x80, 0x18, 99, 0xf5, 2, 0x80]).map(|a| a.counts()),
            Ok((0, 0))
        );
    }

    #[test]
    fn p_015_a_missing_or_repeated_list_is_refused() {
        assert_eq!(
            ClientsAnswer::decode(&[0xa1, 2, 0x80]),
            Err(ClientsError::Missing(ClientsField::Clients))
        );
        assert_eq!(
            ClientsAnswer::decode(&[0xa1, 1, 0x80]),
            Err(ClientsError::Missing(ClientsField::Invites))
        );
        assert_eq!(
            ClientsAnswer::decode(&[0xa3, 1, 0x80, 1, 0x80, 2, 0x80]),
            Err(ClientsError::Duplicate(ClientsField::Clients))
        );
        let mut body = [0u8; 128];
        let mut cbor = CborWriter::new(&mut body);
        cbor.map(2).expect("fits");
        cbor.key(1).expect("fits");
        cbor.array(1).expect("fits");
        cbor.map(1).expect("fits");
        cbor.key(1).expect("fits");
        cbor.u64(1).expect("fits");
        cbor.key(2).expect("fits");
        cbor.array(0).expect("fits");
        let len = cbor.finish().expect("fits");
        assert_eq!(
            ClientsAnswer::decode(&body[..len]),
            Err(ClientsError::Missing(ClientsField::Generation))
        );
    }

    /// An owner computes the digits from an `InviteRow`, so a nonce or key one
    /// byte off is a transcript that matches nothing, and a suite this build
    /// does not run is one it cannot compute them for at all.
    #[test]
    fn an_invite_row_with_a_short_nonce_or_key_or_an_unknown_suite_is_refused() {
        let rows = [invite(1, "x")];
        let answer = ClientsAnswer::new(&[], &rows).expect("valid");
        let (dst, len) = encoded(&answer);
        // The row's key 1 head, 0x50, says sixteen bytes; say fifteen.
        let at = dst.iter().position(|&b| b == 0x50).expect("the nonce head");
        let mut short = dst;
        short[at] = 0x4f;
        let mut cut = [0u8; CLIENTS_MAX_BYTES + 8];
        cut[..=at].copy_from_slice(&short[..=at]);
        cut[at + 1..len - 1].copy_from_slice(&short[at + 2..len]);
        assert_eq!(
            ClientsAnswer::decode(&cut[..len - 1]),
            Err(ClientsError::WrongLength(ClientsField::Nonce, 15))
        );
        // The last byte is key 9's suite.
        let mut suite = dst;
        suite[len - 1] = 2;
        assert_eq!(
            ClientsAnswer::decode(&suite[..len]),
            Err(ClientsError::Unallocated {
                field: ClientsField::Suite,
                raw: 2
            })
        );
    }

    #[test]
    fn refusals_render_and_map_to_malformed_frame() {
        let errors = [
            ClientsError::Missing(ClientsField::Clients),
            ClientsError::Duplicate(ClientsField::Invites),
            ClientsError::Unallocated {
                field: ClientsField::Suite,
                raw: 2,
            },
            ClientsError::Zero(ClientsField::Inviter),
            ClientsError::WrongLength(ClientsField::Invitee, 31),
            ClientsError::LabelLength(33),
            ClientsError::ExpiresTooLate(3601),
            ClientsError::TooMany(ClientsField::Clients, 9),
            ClientsError::SlotsOutOfOrder,
            ClientsError::InviteRepeated,
            ClientsError::Cbor(CborError::WrongType),
        ];
        Rendering::<100>::each_says_something_of_its_own(&errors);
        for error in errors {
            assert_eq!(error.refusal(), Refusal::Client(ErrorCode::MalformedFrame));
        }
    }
}
