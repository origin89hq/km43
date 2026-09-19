//! `ReadInventory 0x0D` / `Inventory 0x8D` — the cold plane, paged.
//!
//! Five row kinds travel in one message because they are all descriptors and
//! they all move together under one `rev`. They also share **one encoder**: a
//! static field table per kind and a single loop over it, rather than a codec
//! each. That is a flash decision and not a taste one — generics monomorphise,
//! and the budget on this part is a ~256 KB image rather than 144 KB of RAM.
//!
//! A page ends on whichever arm binds first, its byte cap or its row cap
//! (P-208), and a row is never split. The builder encodes each row into a
//! [`MAX_ROW_BYTES`] scratch, measures what came out, and appends it with
//! [`CborWriter::raw`] only if it fits what is left — so the cap is applied to
//! bytes that exist rather than to a prediction about them.
//!
//! The row-width table in `docs/protocol/TOPOLOGY-DESIGN.md` is a **check** on
//! this encoder and not a second copy of it. `a_row_at_its_widest_is_the_width_the_document_derives`
//! is what keeps the two honest, and it is a `#[test]` rather than a
//! `const_assert!` because [`CborWriter`] is not `const fn`. Two formulas for
//! one bound lived in `limits.rs` once, for COBS, and disagreed by a byte at
//! every multiple of 254 while both stayed safe.
//!
//! Status: the wire this implements is a proposal. Nothing here is reachable
//! from a rule in a settled document yet, which is why every number it uses is
//! `reserved` in the registry.

use core::fmt;

use sha2::{Digest as _, Sha256};

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::concerns::ElementAt;
use crate::envelope::Refusal;
use crate::generated::{
    Bucket, Direction, ErrorCode, Inventory, InventoryKind, Shape, SignalDomain, Transport, Vtype,
};
use crate::limits::{
    MAX_COMPONENT_CMDS, MAX_INVENTORY_PAGE_BYTES, MAX_INVENTORY_PAGE_ROWS, MAX_ROW_BYTES,
    MAX_SERIES_LEN,
};

/// What one key of a descriptor row carries.
///
/// Six shapes cover all five row kinds, which is the point: a seventh would be a
/// row kind asking for its own encoder, and the whole design of this module is
/// that there is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldType {
    /// A small unsigned discriminant or index.
    U8,
    /// An id, a registry number, or a count.
    U16,
    /// A revision.
    U32,
    /// A value, bounded to `i32` by P-185.
    I32,
    /// UTF-8, bounded by the caller's own cap.
    Text,
    /// A bus address, as the bus defines one.
    Bytes,
    /// A `cmds` list.
    U16List,
}

/// One key of one row kind: its number, what it carries, and whether it may be
/// absent.
///
/// `optional` is the whole of P-015 in this module. A key that is not marked
/// here is REQUIRED, and a row that omits one is refused rather than encoded
/// short — because a receiver that accepts a short row has to invent the
/// missing field, and every invention this protocol has ever made was a
/// default that read as a measurement.
#[derive(Debug, Clone, Copy)]
struct Field {
    key: u8,
    ty: FieldType,
    optional: bool,
}

const fn req(key: u8, ty: FieldType) -> Field {
    Field {
        key,
        ty,
        optional: false,
    }
}

const fn opt(key: u8, ty: FieldType) -> Field {
    Field {
        key,
        ty,
        optional: true,
    }
}

use FieldType::{Bytes, I32, Text, U8, U16, U16List, U32};

/// `BusRow`: a physical port.
const BUS_FIELDS: &[Field] = &[
    req(1, U8),   // bus, 1..MAX_BUSES; 0 is the controller's own local I/O
    req(2, U8),   // transport
    opt(3, Text), // label
    opt(4, U32),  // rate
];

/// `DeviceRow`: one serial-numbered enclosure.
const DEVICE_FIELDS: &[Field] = &[
    req(1, U16),      // dev; 0 is the controller itself
    req(2, U8),       // bus
    opt(3, Bytes),    // addr — required on an addressed transport (P-189)
    req(4, U16),      // product
    req(5, U16),      // dialect
    req(6, U16),      // role
    opt(7, U16),      // parent
    opt(8, Text),     // serial
    opt(9, Text),     // hw
    opt(10, Text),    // fw
    opt(11, Text),    // label
    req(12, U32),     // since
    opt(13, U16List), // cmds — absent means this device accepts none (P-175)
];

/// `ComponentRow`: where every instance number lives.
const COMPONENT_FIELDS: &[Field] = &[
    req(1, U16),     // cmp; 0 is reserved and never allocated (P-174)
    req(2, U16),     // dev
    opt(3, U16),     // parent
    req(4, U16),     // role
    opt(5, U16),     // index
    opt(6, U16),     // rollup
    opt(7, Text),    // label
    opt(8, U16List), // cmds
    req(9, U32),     // since — not optional, which is the trap in the width table
];

/// `SignalRow`: a quantity on a device, at a component or at the device itself.
const SIGNAL_FIELDS: &[Field] = &[
    req(1, U16),   // sig
    req(2, U16),   // dev
    req(3, U16),   // cmp; 0 is the device as a whole
    req(4, U16),   // kind
    req(5, U8),    // shape
    req(6, U8),    // vtype
    req(7, U8),    // domain
    opt(8, U16),   // point
    opt(9, U8),    // dir
    opt(10, U8),   // n — required iff shape is 2
    opt(11, U16),  // erole
    opt(12, U16),  // ebase
    opt(13, U16),  // esp — required iff vtype is 3 or 4
    opt(14, U8),   // unit — required iff kind is in the vendor range (P-160)
    opt(15, U8),   // scale
    opt(16, U16),  // vns
    opt(17, U8),   // hist
    opt(18, Text), // label
];

/// `ParamRow`: what a device says about itself and does not change with the
/// weather. It carries no validity, deliberately — see the design document.
const PARAM_FIELDS: &[Field] = &[
    req(1, U16),   // pid
    req(2, U16),   // dev
    req(3, U16),   // cmp
    req(4, U16),   // kind
    opt(5, I32),   // v — absent means never read
    req(6, U8),    // vtype
    req(7, U8),    // domain
    opt(8, U16),   // point
    opt(9, U8),    // dir
    opt(10, U16),  // esp
    opt(11, I32),  // lo
    opt(12, I32),  // hi
    opt(13, U16),  // via
    opt(14, U8),   // unit
    opt(15, U8),   // scale
    opt(16, U16),  // vns
    opt(17, Text), // label
];

/// One key's value, or its absence.
///
/// `Absent` is a variant rather than an `Option<Value>` so a row is one flat
/// slice the encoder walks in step with its field table. The two are checked
/// against each other on every row: a length disagreement is a bug in the
/// caller, not a short row on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    U8(u8),
    U16(u16),
    U32(u32),
    I32(i32),
    Text(&'a str),
    Bytes(&'a [u8]),
    U16List(CmdList),
    /// This key is not present in this row.
    Absent,
}

/// A `cmds` array: the command kinds one device or component accepts.
///
/// It carries its elements rather than pointing at them because a reader has to
/// put them somewhere and there is no allocator to put them in — a CBOR array of
/// integers is not a `[u16]` anybody can borrow. The cap is the type's, so a
/// fifth command is refused at the line that built the list rather than dropped
/// somewhere a person would have to notice a missing button to find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CmdList {
    /// Zero-filled past `len`, which is what makes the derived `PartialEq`
    /// compare two lists and not two lots of leftovers.
    items: [u16; MAX_COMPONENT_CMDS],
    len: u8,
}

impl CmdList {
    /// Refused empty: absence is how *none* is spelled (P-201), so an empty
    /// `cmds` and no `cmds` would be two encodings of one fact and a driver that
    /// wrote the first is one nobody can tell from a bug.
    pub fn new(items: &[u16]) -> Result<Self, InventoryError> {
        if items.is_empty() {
            return Err(InventoryError::EmptyCmds);
        }
        let Ok(len) = u8::try_from(items.len()) else {
            return Err(InventoryError::TooManyCmds(items.len()));
        };
        let mut held = [0u16; MAX_COMPONENT_CMDS];
        let room = held
            .get_mut(..items.len())
            .ok_or(InventoryError::TooManyCmds(items.len()))?;
        room.copy_from_slice(items);
        Ok(Self { items: held, len })
    }

    #[must_use]
    /// The command kinds, in the order the row gave them.
    pub fn as_slice(&self) -> &[u16] {
        self.items.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

/// Which of the five tables a row is read against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    Bus,
    Device,
    Component,
    Signal,
    Param,
}

impl RowKind {
    /// The registry's allocation, through the generated enum, so a renumbered
    /// kind stops this compiling rather than becoming a second table.
    const fn registered(self) -> InventoryKind {
        match self {
            Self::Bus => InventoryKind::Buses,
            Self::Device => InventoryKind::Devices,
            Self::Component => InventoryKind::Components,
            Self::Signal => InventoryKind::Signals,
            Self::Param => InventoryKind::Parameters,
        }
    }

    /// The `what` a `ReadInventory` names this kind by.
    #[must_use]
    pub const fn number(self) -> u8 {
        self.registered() as u8
    }

    /// `what` back to a kind. Anything else is outcome 3 `unknown_kind` rather
    /// than an error, because the request parsed — it simply named a table that
    /// does not exist.
    #[must_use]
    pub fn from_number(what: u8) -> Option<Self> {
        Some(match InventoryKind::try_from(what).ok()? {
            InventoryKind::Buses => Self::Bus,
            InventoryKind::Devices => Self::Device,
            InventoryKind::Components => Self::Component,
            InventoryKind::Signals => Self::Signal,
            InventoryKind::Parameters => Self::Param,
        })
    }

    const fn fields(self) -> &'static [Field] {
        match self {
            Self::Bus => BUS_FIELDS,
            Self::Device => DEVICE_FIELDS,
            Self::Component => COMPONENT_FIELDS,
            Self::Signal => SIGNAL_FIELDS,
            Self::Param => PARAM_FIELDS,
        }
    }

    /// The keys of this row whose presence another key's value decides.
    ///
    /// Empty for the three kinds that have none, and it is the whole of P-204
    /// plus the two conditions the field lists state for `n` and `esp`.
    const fn conditional(self) -> &'static [(u8, When)] {
        match self {
            Self::Bus | Self::Device | Self::Component => &[],
            Self::Signal => SIGNAL_CONDITIONS,
            Self::Param => PARAM_CONDITIONS,
        }
    }

    /// The keys of this row that carry a member of a closed space rather than a
    /// number.
    ///
    /// `product`, `dialect` and the two `role`s are **not** here and must not
    /// be: P-019 gives them a vendor range and skip-unknown, so a number this
    /// build does not recognise is a channel it shows unnamed rather than a row
    /// it refuses.
    const fn closed(self) -> &'static [(u8, Closed)] {
        match self {
            Self::Bus => BUS_MEMBERS,
            Self::Device | Self::Component => &[],
            Self::Signal => SIGNAL_MEMBERS,
            Self::Param => PARAM_MEMBERS,
        }
    }
}

/// A key whose value is drawn from a closed registry space.
///
/// A bare `u8` standing for one of these is a list of legal values somebody has
/// to remember to check, and nobody did: a `SignalRow` carrying `domain 200`
/// encoded, published and measured as a width. What a client does with it is the
/// failure — `domain` is what says whether a number is *now* or *yesterday's
/// peak*, so an unrecognised one either blanks a reading or renders yesterday's
/// maximum as the present.
///
/// None of these has a vendor range (P-019), so a value outside the space is
/// error 1 rather than a value to skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Closed {
    /// `BusRow` key 2 — what the port physically is.
    Transport,
    /// `SignalRow` key 5 — scalar or series, which is which of the two arrays a
    /// reading travels in.
    Shape,
    /// Key 6 on a signal and a parameter alike — what one value *is*.
    ValueType,
    /// Key 7 — live, lifetime, today, a limit, a maximum.
    Domain,
    /// Key 9 — which way positive points.
    Direction,
    /// `SignalRow` key 17 — the finest bucket this signal is kept at.
    Bucket,
}

impl Closed {
    /// The largest number this space allocates.
    ///
    /// Read rather than named, so a width derived from it cannot go stale: the
    /// design's objection to costing a field by its space was that a space can
    /// gain a member and a width assuming otherwise is a page that overruns.
    /// Nothing assumes — an allocation moves this, and the check below it.
    #[must_use]
    pub fn widest(self) -> u8 {
        (0..=u8::MAX)
            .rev()
            .find(|value| self.holds(*value))
            .unwrap_or(0)
    }

    fn holds(self, value: u8) -> bool {
        match self {
            Self::Transport => Transport::try_from(value).is_ok(),
            Self::Shape => Shape::try_from(value).is_ok(),
            Self::ValueType => Vtype::try_from(value).is_ok(),
            Self::Domain => SignalDomain::try_from(value).is_ok(),
            Self::Direction => Direction::try_from(value).is_ok(),
            Self::Bucket => Bucket::try_from(value).is_ok(),
        }
    }
}

impl fmt::Display for Closed {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        w.write_str(match self {
            Self::Transport => "transport",
            Self::Shape => "shape",
            Self::ValueType => "value type",
            Self::Domain => "signal domain",
            Self::Direction => "direction",
            Self::Bucket => "history bucket",
        })
    }
}

const BUS_MEMBERS: &[(u8, Closed)] = &[(2, Closed::Transport)];

/// A signal carries five of the six. `hist` is here as well as being optional:
/// present means *this signal is stored for history*, and the value is which
/// bucket — so a number outside the space is a signal kept at nothing.
const SIGNAL_MEMBERS: &[(u8, Closed)] = &[
    (SHAPE_KEY, Closed::Shape),
    (VTYPE_KEY, Closed::ValueType),
    (7, Closed::Domain),
    (9, Closed::Direction),
    (17, Closed::Bucket),
];

/// A parameter has no shape and no history, and its `esp` sits where a signal's
/// `dir` does not — which is the difference a shared table would hide.
const PARAM_MEMBERS: &[(u8, Closed)] = &[
    (VTYPE_KEY, Closed::ValueType),
    (7, Closed::Domain),
    (9, Closed::Direction),
];

/// What decides whether a conditional key has to be there.
///
/// A closed set rather than a predicate, because these are the conditions this
/// protocol version states — a sixth should be argued for against the field
/// lists rather than passed in as a closure by whoever needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// The row's `kind` is in P-019's vendor range, so the registry cannot
    /// answer for its unit, its scale, or whose namespace it is (P-204).
    KindIsAVendorsOwn,
    /// `shape` is 2, so the row describes a series and a decoder sizes its
    /// arrays from `n`.
    ShapeIsASeries,
    /// `vtype` is 3 `enum` or 4 `flags`, so the value is a member of a space and
    /// `esp` is the only thing that names which.
    ValueComesFromASpace,
}

impl When {
    /// Where the registry stops answering and the row has to (P-019).
    const VENDOR_RANGE: u16 = 0xF000;
    /// `shape 2` is a series.
    const SERIES: u16 = 2;
    const ENUM: u16 = 3;
    const FLAGS: u16 = 4;

    fn holds(self, row: &Row<'_>) -> bool {
        match self {
            Self::KindIsAVendorsOwn => row
                .number(KIND_KEY)
                .is_some_and(|k| k >= Self::VENDOR_RANGE),
            Self::ShapeIsASeries => row.number(SHAPE_KEY) == Some(Self::SERIES),
            Self::ValueComesFromASpace => row
                .number(VTYPE_KEY)
                .is_some_and(|v| v == Self::ENUM || v == Self::FLAGS),
        }
    }
}

impl fmt::Display for When {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        w.write_str(match self {
            Self::KindIsAVendorsOwn => "the kind is a vendor's own",
            Self::ShapeIsASeries => "the shape is a series",
            Self::ValueComesFromASpace => "the value is drawn from an enum space",
        })
    }
}

/// `kind` is key 4 on both rows that carry a conditional unit.
const KIND_KEY: u8 = 4;
/// `shape` is key 5, and only a `SignalRow` has one.
const SHAPE_KEY: u8 = 5;
/// `vtype` is key 6 on a `SignalRow` and on a `ParamRow` alike.
const VTYPE_KEY: u8 = 6;
/// `n` is key 10, and it is how many elements a series has.
const N_KEY: u8 = 10;
/// `ebase` is key 12: the **label** of element 0, not its position (P-206).
const EBASE_KEY: u8 = 12;

/// A `SignalRow`'s keys another key decides: `n` for a series, `esp` for a value
/// drawn from a space, and the three the registry cannot answer for when the
/// kind is a vendor's own.
const SIGNAL_CONDITIONS: &[(u8, When)] = &[
    (10, When::ShapeIsASeries),
    (13, When::ValueComesFromASpace),
    (14, When::KindIsAVendorsOwn),
    (15, When::KindIsAVendorsOwn),
    (16, When::KindIsAVendorsOwn),
];

/// A `ParamRow` has no shape, so it carries the other two — and its `esp` is key
/// 10 where a signal's is 13, which is the difference a shared table would hide.
const PARAM_CONDITIONS: &[(u8, When)] = &[
    (10, When::ValueComesFromASpace),
    (14, When::KindIsAVendorsOwn),
    (15, When::KindIsAVendorsOwn),
    (16, When::KindIsAVendorsOwn),
];

impl fmt::Display for RowKind {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        w.write_str(match self {
            Self::Bus => "bus",
            Self::Device => "device",
            Self::Component => "component",
            Self::Signal => "signal",
            Self::Param => "parameter",
        })
    }
}

/// One descriptor row: which table it is read against, and one value per key of
/// that table in order.
#[derive(Debug, Clone, Copy)]
pub struct Row<'a> {
    kind: RowKind,
    values: &'a [Value<'a>],
}

impl<'a> Row<'a> {
    /// A row, refused here if it does not match its table.
    ///
    /// Checked on construction rather than on encode so a caller that got the
    /// shape wrong hears about it once, at the line that built the row, instead
    /// of once per page.
    pub fn new(kind: RowKind, values: &'a [Value<'a>]) -> Result<Self, InventoryError> {
        let fields = kind.fields();
        if values.len() != fields.len() {
            return Err(InventoryError::RowShape {
                kind,
                want: fields.len(),
                got: values.len(),
            });
        }
        // `cmp` and `sig` are numbered from 1: 0 is the paging sentinel on the
        // request side and reserved on the row (P-174). A row carrying it names
        // nothing and, handed back as `next`, reads as *the kind is complete*.
        if matches!(kind, RowKind::Component | RowKind::Signal)
            && matches!(values.first(), Some(Value::U16(0)))
        {
            return Err(InventoryError::ReservedZero { kind, key: 1 });
        }
        for (field, value) in fields.iter().zip(values) {
            if matches!(value, Value::Absent) {
                if field.optional {
                    continue;
                }
                return Err(InventoryError::MissingRequired {
                    kind,
                    key: field.key,
                });
            }
            if !value.fits(field.ty) {
                return Err(InventoryError::WrongType {
                    kind,
                    key: field.key,
                });
            }
        }
        let row = Self { kind, values };
        row.members_hold()?;
        row.conditions_hold()?;
        row.every_element_can_be_named()?;
        Ok(row)
    }

    /// Every key that names a member of a closed space names one that exists.
    ///
    /// Checked **before** the conditions, because two of these keys are what the
    /// conditions read: a row carrying `shape 200` should be refused for having
    /// no such shape, rather than for carrying an `n` while it is not true that
    /// the shape is a series.
    fn members_hold(&self) -> Result<(), InventoryError> {
        for &(key, space) in self.kind.closed() {
            let Some(Value::U8(value)) = self.value(key) else {
                continue;
            };
            if !space.holds(*value) {
                return Err(InventoryError::NotAMember {
                    kind: self.kind,
                    key,
                    space,
                    value: *value,
                });
            }
        }
        Ok(())
    }

    /// Every element this row declares can be pointed at and can be printed.
    ///
    /// Two bounds the field list states and the types cannot, checked through the
    /// same [`Self::labels`] a client reads the row through — so a row is refused
    /// where a person can act on it rather than at the moment somebody needs the
    /// number. `n` past [`MAX_SERIES_LEN`] declares elements no `Concern` can
    /// name, because [`ElementAt`] stops there; `ebase` near the top of `u16`
    /// runs out of labels before it runs out of elements.
    ///
    /// `sig` from 1 and `cmp` 0 reserved are checked in [`Self::new`], and the
    /// six closed-set keys (`shape`, `vtype`, `domain`, `dir`, `hist`,
    /// `transport`) against their generated enums.
    fn every_element_can_be_named(&self) -> Result<(), InventoryError> {
        let Some(labels) = self.labels() else {
            return Ok(());
        };
        if labels.elements() < ElementLabels::SHORTEST {
            return Err(InventoryError::SeriesTooShort(labels.elements()));
        }
        if usize::from(labels.elements()) > MAX_SERIES_LEN {
            return Err(InventoryError::SeriesTooLong(labels.elements()));
        }
        labels
            .base()
            .checked_add(u16::from(labels.elements()).saturating_sub(1))
            .ok_or(InventoryError::LabelPastRange {
                base: labels.base(),
                at: labels.elements(),
            })?;
        Ok(())
    }

    /// The keys `Field` could not describe.
    ///
    /// **`req`/`opt` is binary and three of these keys are neither**, so each was
    /// a comment reading *REQUIRED iff* beside an `opt(...)` and a check
    /// nowhere. A series row with no `n` makes a decoder size an array from a key
    /// that is not there; an enum row with no `esp` publishes a number with no
    /// space to name it, which is P-164's failure arriving one layer down; and a
    /// standard kind carrying its own `unit` is a second source of truth for the
    /// number on the screen, which is P-204 in as many words.
    fn conditions_hold(&self) -> Result<(), InventoryError> {
        for &(key, when) in self.kind.conditional() {
            let wanted = when.holds(self);
            let there = !matches!(self.value(key), None | Some(Value::Absent));
            if wanted && !there {
                return Err(InventoryError::MissingConditional {
                    kind: self.kind,
                    key,
                    when,
                });
            }
            if !wanted && there {
                return Err(InventoryError::UnexpectedConditional {
                    kind: self.kind,
                    key,
                    when,
                });
            }
        }
        Ok(())
    }

    /// One key's value, by key number rather than by position.
    fn value(&self, key: u8) -> Option<&Value<'a>> {
        let at = self.kind.fields().iter().position(|f| f.key == key)?;
        self.values.get(at)
    }

    /// One key's value as a number, which is all a condition reads.
    fn number(&self, key: u8) -> Option<u16> {
        match self.value(key)? {
            Value::U8(v) => Some(u16::from(*v)),
            Value::U16(v) => Some(*v),
            Value::U32(_)
            | Value::I32(_)
            | Value::Text(_)
            | Value::Bytes(_)
            | Value::U16List(_)
            | Value::Absent => None,
        }
    }

    #[must_use]
    /// Which table this row belongs to.
    pub const fn kind(&self) -> RowKind {
        self.kind
    }

    /// One key's value, or `None` for a key this table does not have and for one
    /// this row left out. A caller that needs to tell those apart is asking
    /// about the table, not about the row.
    #[must_use]
    pub fn get(&self, key: u8) -> Option<Value<'a>> {
        match self.value(key)? {
            Value::Absent => None,
            held => Some(*held),
        }
    }

    /// What this row's elements are called, or `None` if it describes a scalar.
    ///
    /// **`ebase` absent is read as 1** — P-206, and the whole reason this is a
    /// method rather than a `get` at the call site. A client that reads the
    /// missing key as 0 numbers every cell of every unlabelled string one lower
    /// than the number painted on it, which is a fault report that sends
    /// somebody to the wrong cell without ever looking wrong.
    #[must_use]
    pub fn labels(&self) -> Option<ElementLabels> {
        if !matches!(self.kind, RowKind::Signal) || self.number(SHAPE_KEY) != Some(When::SERIES) {
            return None;
        }
        let elements = u8::try_from(self.number(N_KEY)?).ok()?;
        Some(ElementLabels {
            base: self.number(EBASE_KEY).unwrap_or(ElementLabels::UNLABELLED),
            elements,
        })
    }

    /// The one encoder. Every row kind comes through here, walking its own
    /// table, which is why adding a sixth kind is a table and not a function.
    fn encode(&self, cbor: &mut CborWriter<'_>) -> Result<(), InventoryError> {
        // **One expression for the header's count and the loop's skip.** They
        // were two: a `filter().count()` over `self.values`, and a `continue`
        // over `fields().zip(self.values)`. The zip stops at the shorter side
        // and the count did not, so a row with more values than its table has
        // fields wrote a map header promising pairs the body never produced.
        //
        // `CborWriter::finish` catches that — an under-filled map is
        // `Unfinished`, so the divergence was refused rather than put on the
        // wire. What this buys is that a row which is legal in every other
        // respect stops being refusable at all: two statements of *which values
        // are present* are two things to disagree, and now there is one.
        let present = self
            .kind
            .fields()
            .iter()
            .zip(self.values)
            .filter(|(_, value)| !matches!(value, Value::Absent));
        cbor.map(present.clone().count())?;
        for (field, value) in present {
            cbor.key(i64::from(field.key))?;
            match value {
                Value::U8(v) => cbor.u64(u64::from(*v))?,
                Value::U16(v) => cbor.u64(u64::from(*v))?,
                Value::U32(v) => cbor.u64(u64::from(*v))?,
                Value::I32(v) => cbor.i32(*v)?,
                Value::Text(v) => cbor.text(v)?,
                Value::Bytes(v) => cbor.bytes(v)?,
                Value::U16List(v) => {
                    cbor.array(v.as_slice().len())?;
                    for one in v.as_slice() {
                        cbor.u64(u64::from(*one))?;
                    }
                }
                // Filtered out above, so this cannot happen — and it is a
                // refusal rather than an `unreachable!` because on a Cortex-M0+
                // a panic is a reset, and *this cannot happen* is a claim about
                // code that has not been written yet. A row refused encodes
                // nothing; a row that panics takes the controller with it.
                Value::Absent => {
                    return Err(InventoryError::WrongType {
                        kind: self.kind,
                        key: field.key,
                    });
                }
            }
        }
        Ok(())
    }

    /// What this row costs on the wire, measured rather than predicted.
    ///
    /// A row that will not fit [`MAX_ROW_BYTES`] is refused at registration —
    /// where a person can act on it — rather than silently ending a page.
    pub fn encoded_len(&self) -> Result<usize, InventoryError> {
        let mut scratch = [0u8; MAX_ROW_BYTES];
        let mut cbor = CborWriter::new(&mut scratch);
        self.encode(&mut cbor)?;
        Ok(cbor.finish()?)
    }
}

impl Value<'_> {
    const fn fits(&self, ty: FieldType) -> bool {
        matches!(
            (self, ty),
            (Self::U8(_), FieldType::U8)
                | (Self::U16(_), FieldType::U16)
                | (Self::U32(_), FieldType::U32)
                | (Self::I32(_), FieldType::I32)
                | (Self::Text(_), FieldType::Text)
                | (Self::Bytes(_), FieldType::Bytes)
                | (Self::U16List(_), FieldType::U16List)
        )
    }
}

/// What a series signal's elements are called, read off its row.
///
/// The two numbers are not interchangeable and the whole of P-206 is keeping
/// them apart: `elements` is how many there are, and `base` is what the first
/// one is *called*. A 32-cell string travels as two 16-element signals with
/// `base` 1 and 17, so element 7 of the second is cell 23 — the number painted
/// on the rack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElementLabels {
    base: u16,
    elements: u8,
}

impl ElementLabels {
    /// What a row that says nothing about labels means: the elements are
    /// numbered from one, the way somebody counting them out loud would.
    pub const UNLABELLED: u16 = 1;

    /// A series of one is a scalar wearing a series' shape, and it costs a
    /// reader an array, a length and an element loop to render one number.
    pub const SHORTEST: u8 = 2;

    /// The label of element 0 — what a row's `ebase` says, or 1 where it says
    /// nothing.
    #[must_use]
    pub const fn base(self) -> u16 {
        self.base
    }

    #[must_use]
    /// How many elements the row declares.
    pub const fn elements(self) -> u8 {
        self.elements
    }

    /// What to print for the element a `Concern` names by position.
    ///
    /// `at` is 1-based and the label of element 0 is `base`, so this is
    /// `base + at − 1`. Refused rather than wrapped when the sum leaves `u16`:
    /// a label that does not exist printed as a small number is a cell somebody
    /// can find, in the wrong pack.
    pub fn label_of(self, at: ElementAt) -> Result<u16, InventoryError> {
        if at.get() > self.elements {
            return Err(InventoryError::PositionPastSeries {
                at: at.get(),
                elements: self.elements,
            });
        }
        self.base
            .checked_add(u16::from(at.get()).saturating_sub(1))
            .ok_or(InventoryError::LabelPastRange {
                base: self.base,
                at: at.get(),
            })
    }
}

/// Where one row's values land while it is being read.
///
/// The encoder borrows the caller's slice; a reader has nothing to borrow from,
/// so the slots live here and one buffer is reused down a page. Everything after
/// [`Self::decode`] is [`Row`] again — the same field table and the same checks,
/// walked in the other direction, so a row this crate refuses to write is a row
/// it refuses to read.
pub struct RowSlots<'a> {
    values: [Value<'a>; MAX_ROW_KEYS],
}

/// One value per key of the widest table, which is a `SignalRow`'s eighteen.
const MAX_ROW_KEYS: usize = 18;

const_assert!(
    BUS_FIELDS.len() <= MAX_ROW_KEYS
        && DEVICE_FIELDS.len() <= MAX_ROW_KEYS
        && COMPONENT_FIELDS.len() <= MAX_ROW_KEYS
        && SIGNAL_FIELDS.len() <= MAX_ROW_KEYS
        && PARAM_FIELDS.len() <= MAX_ROW_KEYS,
    "a row kind grew past the slots a reader reserves for one"
);

impl Default for RowSlots<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> RowSlots<'a> {
    #[must_use]
    /// Empty slots to decode a row's values into.
    pub const fn new() -> Self {
        Self {
            values: [Value::Absent; MAX_ROW_KEYS],
        }
    }

    /// Read one row against a table, refusing every shape [`Row::new`] refuses.
    ///
    /// The kind comes from the page's `what` rather than from the row, because a
    /// row does not say which table it belongs to — that is what makes the five
    /// share one encoder, and it is why a caller that gets `what` wrong reads a
    /// component's `role` as a signal's `kind`.
    pub fn decode(&mut self, kind: RowKind, bytes: &'a [u8]) -> Result<Row<'_>, InventoryError> {
        self.values = [Value::Absent; MAX_ROW_KEYS];
        let fields = kind.fields();
        let mut body = CborReader::new(bytes);
        let pairs = body.map()?;
        for _ in 0..pairs {
            let number = body.key()?;
            let at = u8::try_from(number)
                .ok()
                .and_then(|key| fields.iter().position(|f| f.key == key));
            let Some(at) = at else {
                // A key a newer peer allocated. Skipped, never refused — P-013,
                // and refusing here would drop a whole topology because one row
                // grew a field.
                body.skip()?;
                continue;
            };
            let field = fields.get(at).ok_or(InventoryError::RowShape {
                kind,
                want: fields.len(),
                got: at,
            })?;
            let slot = self.values.get_mut(at).ok_or(InventoryError::RowShape {
                kind,
                want: MAX_ROW_KEYS,
                got: at,
            })?;
            if !matches!(slot, Value::Absent) {
                return Err(InventoryError::DuplicateRowKey {
                    kind,
                    key: field.key,
                });
            }
            *slot = field.ty.read(&mut body)?;
        }
        body.finish()?;
        let values = self
            .values
            .get(..fields.len())
            .ok_or(InventoryError::RowShape {
                kind,
                want: fields.len(),
                got: MAX_ROW_KEYS,
            })?;
        Row::new(kind, values)
    }
}

impl FieldType {
    /// One value, read as this table says it is written.
    ///
    /// A value of the wrong major type comes back as a `CborError` rather than a
    /// `WrongType`: the encode side can put a `Text` under a `U16` key by
    /// passing the wrong variant, but a reader never gets that far — the bytes
    /// either are an unsigned integer or they are not.
    fn read<'a>(self, body: &mut CborReader<'a>) -> Result<Value<'a>, InventoryError> {
        Ok(match self {
            Self::U8 => Value::U8(body.u8()?),
            Self::U16 => Value::U16(body.u16()?),
            Self::U32 => Value::U32(body.u32()?),
            Self::I32 => Value::I32(body.i32()?),
            Self::Text => Value::Text(body.text()?),
            Self::Bytes => Value::Bytes(body.bytes()?),
            Self::U16List => {
                let len = body.array()?;
                let mut held = [0u16; MAX_COMPONENT_CMDS];
                let room = held
                    .get_mut(..len)
                    .ok_or(InventoryError::TooManyCmds(len))?;
                for one in room.iter_mut() {
                    *one = body.u16()?;
                }
                Value::U16List(CmdList::new(room)?)
            }
        })
    }
}

/// A page of descriptor rows, built by measuring rather than predicting.
///
/// The rows are held as the bytes they encoded to, because that is what the two
/// arms are counted in and what [`CborWriter::raw`] hands straight through. It
/// is also what P-173's digest is defined over — the bytes as they appear in a
/// page, so neither side ever re-encodes.
pub struct Page {
    kind: RowKind,
    scratch: [u8; MAX_INVENTORY_PAGE_BYTES],
    used: usize,
    rows: usize,
    /// The id to pass back as `from`, or 0 when this page ends the kind.
    next: u16,
}

impl Page {
    #[must_use]
    /// An empty page of one kind.
    pub const fn new(kind: RowKind) -> Self {
        Self {
            kind,
            scratch: [0u8; MAX_INVENTORY_PAGE_BYTES],
            used: 0,
            rows: 0,
            next: 0,
        }
    }

    /// Try to add a row, and say whether the page took it.
    ///
    /// `Ok(false)` is a full page and not an error: the caller sets `next` to
    /// this row's id and sends what it has. That is P-208's two arms — rows or
    /// bytes, whichever binds first — and the byte arm is checked against what
    /// the row actually encoded to rather than against its worst case.
    pub fn push(&mut self, row: &Row<'_>, id: u16) -> Result<bool, InventoryError> {
        if row.kind() != self.kind {
            return Err(InventoryError::WrongKind {
                page: self.kind,
                row: row.kind(),
            });
        }
        if self.rows >= MAX_INVENTORY_PAGE_ROWS {
            self.next = id;
            return Ok(false);
        }
        let mut one = [0u8; MAX_ROW_BYTES];
        let mut cbor = CborWriter::new(&mut one);
        row.encode(&mut cbor)?;
        let len = cbor.finish()?;

        let end = self.used.saturating_add(len);
        if end > MAX_INVENTORY_PAGE_BYTES {
            self.next = id;
            return Ok(false);
        }
        let slot = self
            .scratch
            .get_mut(self.used..end)
            .ok_or(InventoryError::RowTooLong(len))?;
        let src = one.get(..len).ok_or(InventoryError::RowTooLong(len))?;
        slot.copy_from_slice(src);
        self.used = end;
        self.rows = self.rows.saturating_add(1);
        Ok(true)
    }

    #[must_use]
    /// Which table the page carries rows of.
    pub const fn kind(&self) -> RowKind {
        self.kind
    }

    #[must_use]
    /// Rows taken so far.
    pub const fn rows(&self) -> usize {
        self.rows
    }

    #[must_use]
    /// Bytes the rows occupy.
    pub const fn len(&self) -> usize {
        self.used
    }

    #[must_use]
    /// No row yet.
    pub const fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// The id a client passes back as `from`; 0 when this page ended the kind.
    #[must_use]
    pub const fn next(&self) -> u16 {
        self.next
    }

    /// The encoded rows, in order, exactly as they will appear on the wire.
    #[must_use]
    pub fn encoded_rows(&self) -> &[u8] {
        self.scratch.get(..self.used).unwrap_or(&[])
    }

    /// Write the `rows` array into a body under construction.
    ///
    /// Each row goes through [`CborWriter::raw`], which walks it once to check
    /// it is exactly one well-formed item and then copies it. Nothing is
    /// re-encoded, which is what lets P-173 hash these bytes on both sides.
    pub fn encode_into(&self, cbor: &mut CborWriter<'_>) -> Result<(), InventoryError> {
        cbor.array(self.rows)?;
        let mut reader = CborReader::new(self.encoded_rows());
        for _ in 0..self.rows {
            cbor.raw(reader.raw()?)?;
        }
        Ok(())
    }
}

/// The four keys of `ReadInventory 0x0D`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadInventoryKey {
    /// Key 1, the revision the client is assembling; 0 on the first call.
    Rev,
    /// Key 2, which of the five tables.
    What,
    /// Key 3, the first row id to include — P-029, so the row at it arrives.
    From,
    /// Key 4, parameters of one device. `what = 5` only.
    Dev,
}

impl ReadInventoryKey {
    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Rev),
            2 => Some(Self::What),
            3 => Some(Self::From),
            4 => Some(Self::Dev),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Rev => 1,
            Self::What => 2,
            Self::From => 3,
            Self::Dev => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Rev => "rev",
            Self::What => "what",
            Self::From => "from",
            Self::Dev => "dev",
        }
    }
}

impl fmt::Display for ReadInventoryKey {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            w,
            "ReadInventory 0x0D {} (key {})",
            self.name(),
            self.number()
        )
    }
}

/// The seven keys of `Inventory 0x8D`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryKey {
    /// Key 1, the controller's current revision — on every page, so a torn walk
    /// is detectable in a field that is already there (P-152, P-153).
    Rev,
    /// Key 2, echoed so the response is self-describing.
    What,
    /// Key 3, the rows. Empty unless the outcome is 1.
    Rows,
    /// Key 4, the id to pass back as `from`; 0 when this page ends the kind.
    Next,
    /// Key 5, rows of this kind at this rev — of this `dev` too, when the
    /// request named one.
    Total,
    /// Key 6.
    Outcome,
    /// Key 7, present iff the outcome is 1 and key 4 is 0 (P-190).
    Digest,
}

impl InventoryKey {
    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Rev),
            2 => Some(Self::What),
            3 => Some(Self::Rows),
            4 => Some(Self::Next),
            5 => Some(Self::Total),
            6 => Some(Self::Outcome),
            7 => Some(Self::Digest),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Rev => 1,
            Self::What => 2,
            Self::Rows => 3,
            Self::Next => 4,
            Self::Total => 5,
            Self::Outcome => 6,
            Self::Digest => 7,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Rev => "rev",
            Self::What => "what",
            Self::Rows => "rows",
            Self::Next => "next",
            Self::Total => "total",
            Self::Outcome => "outcome",
            Self::Digest => "digest",
        }
    }
}

impl fmt::Display for InventoryKey {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(w, "Inventory 0x8D {} (key {})", self.name(), self.number())
    }
}

/// How an `Inventory 0x8D` answered, and the only thing that decides whether
/// keys 3, 4 and 7 carry anything (P-190).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryOutcome {
    Ok,
    /// The `rev` named was neither 0 nor current. The rows are empty and key 1
    /// carries the current one, so a client learns what to ask for next.
    Superseded,
    /// `what` is not in 1..5. The request parsed; it named a table that does
    /// not exist.
    UnknownKind,
    /// `from` is past the last row the request resolves to.
    OutOfRange,
}

impl InventoryOutcome {
    /// The registry's allocation, through the generated enum, so a renumbered
    /// outcome stops this compiling rather than becoming a second table.
    const fn registered(self) -> Inventory {
        match self {
            Self::Ok => Inventory::Ok,
            Self::Superseded => Inventory::Superseded,
            Self::UnknownKind => Inventory::UnknownKind,
            Self::OutOfRange => Inventory::OutOfRange,
        }
    }

    const fn number(self) -> u8 {
        self.registered() as u8
    }

    fn of(number: u8) -> Option<Self> {
        Some(match Inventory::try_from(number).ok()? {
            Inventory::Ok => Self::Ok,
            Inventory::Superseded => Self::Superseded,
            Inventory::UnknownKind => Self::UnknownKind,
            Inventory::OutOfRange => Self::OutOfRange,
        })
    }
}

/// The body of `ReadInventory 0x0D`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadInventory {
    /// Key 1, the revision the client holds.
    pub rev: u32,
    /// Key 2, the kind as `RowKind::number` gives it; one nobody allocates is outcome 3, not a refusal.
    pub what: u8,
    /// Key 3, the id to resume at, inclusive; 0 means from the beginning.
    pub from: u16,
    /// `what = 5` only. Absent means every device's parameters.
    pub dev: Option<u16>,
}

impl ReadInventory {
    /// Write the body into `dst`. `dev` goes out only when present, so a request for every device's parameters carries no key 4.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, InventoryError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(if self.dev.is_some() { 4 } else { 3 })?;
        cbor.key(ReadInventoryKey::Rev.number())?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(ReadInventoryKey::What.number())?;
        cbor.u64(u64::from(self.what))?;
        cbor.key(ReadInventoryKey::From.number())?;
        cbor.u64(u64::from(self.from))?;
        if let Some(dev) = self.dev {
            cbor.key(ReadInventoryKey::Dev.number())?;
            cbor.u64(u64::from(dev))?;
        }
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    ///
    /// `what` is carried as the byte it arrived as rather than resolved to a
    /// [`RowKind`] here: an unallocated one is outcome 3 in the response, not an
    /// error, and turning it into a refusal at the decoder would lose the
    /// difference.
    pub fn decode(payload: &[u8]) -> Result<Self, InventoryError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut rev, mut what, mut from, mut dev) = (None, None, None, None);
        for _ in 0..pairs {
            match ReadInventoryKey::of(body.key()?) {
                Some(k @ ReadInventoryKey::Rev) => once(&mut rev, k, body.u32()?)?,
                Some(k @ ReadInventoryKey::What) => once(&mut what, k, body.u8()?)?,
                Some(k @ ReadInventoryKey::From) => once(&mut from, k, body.u16()?)?,
                Some(k @ ReadInventoryKey::Dev) => once(&mut dev, k, body.u16()?)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            rev: rev.ok_or(InventoryError::Missing(ReadInventoryKey::Rev))?,
            what: what.ok_or(InventoryError::Missing(ReadInventoryKey::What))?,
            from: from.ok_or(InventoryError::Missing(ReadInventoryKey::From))?,
            dev,
        })
    }
}

/// One key of a `ReadInventory` seen twice is error 1, refused before either
/// copy is used.
fn once<T>(slot: &mut Option<T>, key: ReadInventoryKey, value: T) -> Result<(), InventoryError> {
    if slot.is_some() {
        return Err(InventoryError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// The body of `Inventory 0x8D`.
///
/// The rows are borrowed as the bytes a [`Page`] built, so this never re-encodes
/// one. That is P-173's requirement and not a convenience: the digest is defined
/// over the bytes as they appear in a page, and a body that rebuilt them would
/// be hashing a second opinion.
pub struct InventoryBody<'a> {
    /// Key 1, the revision the rows are of; a client compares it against the one it asked with.
    pub rev: u32,
    /// Key 2, echoed so the response is self-describing.
    pub what: u8,
    /// Key 6. Anything but `Ok` means the page carries no rows and no digest (P-190).
    pub outcome: InventoryOutcome,
    /// Key 5, rows of this kind at `rev`.
    pub total: u16,
    /// Present only on outcome 1 — every other outcome answers nothing (P-190).
    pub page: Option<&'a Page>,
    /// The topology digest, on the last page of a complete walk.
    pub digest: Option<[u8; 8]>,
}

impl InventoryBody<'_> {
    /// Encode the body, refusing a combination P-190 forbids rather than
    /// emitting it.
    ///
    /// A response that answered nothing must not carry a digest, and `next = 0`
    /// is the natural encoding of *nothing follows* — so without this check a
    /// client meeting outcome 4 sees a matching `rev`, a zero cursor and a
    /// whole-topology digest, and stamps a cache it never assembled.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, InventoryError> {
        let answered = matches!(self.outcome, InventoryOutcome::Ok);
        let next = if answered {
            self.page.map_or(0, Page::next)
        } else {
            0
        };
        if !answered && (self.page.is_some_and(|p| !p.is_empty()) || self.digest.is_some()) {
            return Err(InventoryError::AnsweredNothing(self.outcome));
        }
        if self.digest.is_some() && next != 0 {
            return Err(InventoryError::DigestMidWalk);
        }

        let pairs = 6 + usize::from(self.digest.is_some());
        let mut cbor = CborWriter::new(dst);
        cbor.map(pairs)?;
        cbor.key(InventoryKey::Rev.number())?;
        cbor.u64(u64::from(self.rev))?;
        cbor.key(InventoryKey::What.number())?;
        cbor.u64(u64::from(self.what))?;
        cbor.key(InventoryKey::Rows.number())?;
        match self.page.filter(|_| answered) {
            Some(page) => page.encode_into(&mut cbor)?,
            None => cbor.array(0)?,
        }
        cbor.key(InventoryKey::Next.number())?;
        cbor.u64(u64::from(next))?;
        cbor.key(InventoryKey::Total.number())?;
        cbor.u64(u64::from(self.total))?;
        cbor.key(InventoryKey::Outcome.number())?;
        cbor.u64(u64::from(self.outcome.number()))?;
        if let Some(digest) = self.digest {
            cbor.key(InventoryKey::Digest.number())?;
            cbor.bytes(&digest)?;
        }
        Ok(cbor.finish()?)
    }
}

/// What a client reads out of an `Inventory 0x8D`.
///
/// The rows come back as the bytes they arrived as, walked one at a time. A
/// client that wants to check the digest concatenates exactly these, which is
/// the half of P-173 that lives on this side of the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryHeader {
    /// Key 1, the revision the page is of. Differing from the request's, the walk is torn (P-152).
    pub rev: u32,
    /// Key 2, the kind echoed back, so a page can be matched to the request it answers.
    pub what: u8,
    /// Key 6. Anything but `Ok` answered nothing, and rows or a digest beside it are refused.
    pub outcome: InventoryOutcome,
    /// Key 4, the id to pass back as `from`; 0 when this page ends the kind.
    pub next: u16,
    /// Key 5, rows of this kind at `rev`, or of this `dev` when the request named one.
    pub total: u16,
    /// How many rows key 3 carried.
    pub rows: usize,
    /// Key 7, on the last page of a complete walk and nowhere else (P-190).
    pub digest: Option<[u8; 8]>,
}

impl InventoryHeader {
    /// Read the body, refusing the same combinations [`InventoryBody::encode`]
    /// refuses to write. A receiver that accepts one is a receiver that will
    /// cache under it.
    pub fn decode(payload: &[u8]) -> Result<Self, InventoryError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let (mut rev, mut what, mut next, mut total, mut outcome, mut digest, mut rows) =
            (None, None, None, None, None, None, None);
        for _ in 0..pairs {
            match InventoryKey::of(body.key()?) {
                Some(InventoryKey::Rev) => rev = Some(body.u32()?),
                Some(InventoryKey::What) => what = Some(body.u8()?),
                Some(InventoryKey::Rows) => {
                    let n = body.array()?;
                    for _ in 0..n {
                        body.skip()?;
                    }
                    rows = Some(n);
                }
                Some(InventoryKey::Next) => next = Some(body.u16()?),
                Some(InventoryKey::Total) => total = Some(body.u16()?),
                Some(InventoryKey::Outcome) => outcome = Some(body.u8()?),
                Some(InventoryKey::Digest) => {
                    let bytes = body.bytes()?;
                    let mut out = [0u8; 8];
                    if bytes.len() != out.len() {
                        return Err(InventoryError::DigestWidth(bytes.len()));
                    }
                    out.copy_from_slice(bytes);
                    digest = Some(out);
                }
                None => body.skip()?,
            }
        }
        body.finish()?;

        let number = outcome.ok_or(InventoryError::MissingResponse(InventoryKey::Outcome))?;
        let outcome = InventoryOutcome::of(number).ok_or(InventoryError::UnknownOutcome(number))?;
        let next = next.ok_or(InventoryError::MissingResponse(InventoryKey::Next))?;
        let rows = rows.ok_or(InventoryError::MissingResponse(InventoryKey::Rows))?;

        if !matches!(outcome, InventoryOutcome::Ok) && (rows != 0 || digest.is_some()) {
            return Err(InventoryError::AnsweredNothing(outcome));
        }
        if digest.is_some() && next != 0 {
            return Err(InventoryError::DigestMidWalk);
        }

        Ok(Self {
            rev: rev.ok_or(InventoryError::MissingResponse(InventoryKey::Rev))?,
            what: what.ok_or(InventoryError::MissingResponse(InventoryKey::What))?,
            outcome,
            next,
            total: total.ok_or(InventoryError::MissingResponse(InventoryKey::Total))?,
            rows,
            digest,
        })
    }
}

/// P-148's domain label. ASCII, no trailing NUL, and nineteen bytes.
///
/// A third kind of domain input beside P-043's two: not a MAC preimage prefix
/// and not an HKDF `info`, but a hash-domain prefix. It carries `v1` so a later
/// encoding cannot make every deployed client surface "controller faulty"
/// forever on a healthy site.
pub const TOPO_DIGEST_LABEL: &[u8] = b"km43/v1/topo-digest";

/// The topology digest, accumulated over descriptor rows in canonical order (P-148).
///
/// **Over the bytes, never over a re-encoding.** The controller feeds the rows
/// its encoder produced; a client feeds the rows it received, which
/// [`CborReader::raw`] hands over whole. Neither side decodes and rebuilds, so
/// P-017 and P-048's rule survives a hash that is computed on both ends — which
/// is the only way two implementations can agree on one.
///
/// Canonical order is `what` ascending, then the row's own id ascending inside
/// a kind. The kind half is enforced here; the id half is the page builder's,
/// because that is the only place that sees ids.
pub struct TopoDigest {
    hash: Sha256,
    last: Option<RowKind>,
}

impl TopoDigest {
    /// Start one for a revision.
    ///
    /// `rev` is in the preimage so a digest can never be lifted from one
    /// revision to another — the pair is one identity (P-149), and a hash that
    /// did not cover the revision would let a controller report last week's.
    #[must_use]
    pub fn new(rev: u32) -> Self {
        let mut hash = Sha256::new();
        hash.update(TOPO_DIGEST_LABEL);
        hash.update(rev.to_be_bytes());
        Self { hash, last: None }
    }

    /// Absorb one page's rows, in the order it built them.
    ///
    /// Refuses a kind that goes backwards. Two controllers that walk their
    /// tables in different orders would otherwise publish different digests for
    /// the same topology, and P-149 turns that into every client on the site
    /// surfacing a controller fault.
    pub fn absorb(&mut self, page: &Page) -> Result<(), InventoryError> {
        let kind = page.kind();
        if self.last.is_some_and(|last| kind.number() < last.number()) {
            return Err(InventoryError::RowsOutOfOrder {
                after: self.last.unwrap_or(kind),
                got: kind,
            });
        }
        self.last = Some(kind);
        self.hash.update(page.encoded_rows());
        Ok(())
    }

    /// The leftmost eight bytes, which is what `Hello 0x81` key 19 and
    /// `Inventory 0x8D` key 7 carry.
    #[must_use]
    pub fn finish(self) -> [u8; 8] {
        let full = self.hash.finalize();
        let mut out = [0u8; 8];
        out.copy_from_slice(full.get(..8).unwrap_or(&[0; 8]));
        out
    }
}

/// What a page or a row was refused for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryError {
    /// The value slice does not match the row kind's table.
    RowShape {
        kind: RowKind,
        want: usize,
        got: usize,
    },
    /// A key the table marks required was `Absent`.
    MissingRequired { kind: RowKind, key: u8 },
    /// A value of the wrong shape for the key it sits under.
    WrongType { kind: RowKind, key: u8 },
    /// An empty `cmds`, where absence is what *none* is spelled as (P-201).
    EmptyCmds,
    /// More commands than [`MAX_COMPONENT_CMDS`], which is a component that
    /// should be a parent and a child rather than a list to truncate.
    TooManyCmds(usize),
    /// The same key twice in one row (P-015). RFC 8949 §5.6 leaves which one
    /// wins to the decoder, so two clients would render one authenticated row
    /// differently.
    DuplicateRowKey { kind: RowKind, key: u8 },
    /// A `cmp` or a `sig` of 0, which is reserved (P-174): it names nothing,
    /// and handed back as a cursor it says the kind is complete.
    ReservedZero { kind: RowKind, key: u8 },
    /// A `Concern` naming a position past the end of the series it names.
    PositionPastSeries { at: u8, elements: u8 },
    /// A number under a key whose space does not allocate it. Not skip-unknown:
    /// none of the six has a vendor range (P-019).
    NotAMember {
        kind: RowKind,
        key: u8,
        space: Closed,
        value: u8,
    },
    /// A series of fewer than two, which is a scalar with an array around it.
    SeriesTooShort(u8),
    /// A series longer than [`MAX_SERIES_LEN`], whose top elements no `Concern`
    /// can name — `ElementAt` stops there, so a fault on cell 20 of a 32-element
    /// signal has no position to travel in.
    SeriesTooLong(u8),
    /// A series whose labels run off the end of `u16`. There is no such label,
    /// and one printed after wrapping is a cell somebody can find in the wrong
    /// pack (P-206).
    LabelPastRange { base: u16, at: u8 },
    /// A key another key's value makes REQUIRED, left out.
    MissingConditional { kind: RowKind, key: u8, when: When },
    /// A key that is only legal under a condition this row does not meet.
    UnexpectedConditional { kind: RowKind, key: u8, when: When },
    /// A row of one kind pushed onto a page of another. `what` is echoed in the
    /// response, so a page carrying two kinds is a response that lies about
    /// itself.
    WrongKind { page: RowKind, row: RowKind },
    /// A row past [`MAX_ROW_BYTES`], which is a driver to refuse at
    /// registration rather than a page to end.
    RowTooLong(usize),
    /// A required key of a `ReadInventory` never arrived (P-015).
    Missing(ReadInventoryKey),
    /// A required key of an `Inventory` never arrived (P-015).
    MissingResponse(InventoryKey),
    /// An outcome other than 1 carrying rows or a digest, which P-190 forbids:
    /// a response that answered nothing must not look like one that did.
    AnsweredNothing(InventoryOutcome),
    /// A digest on a page that is not the last of a walk. Key 7 is the whole
    /// topology's, so a mid-walk one is a client stamping a partial cache.
    DigestMidWalk,
    /// A digest that is not the leftmost eight bytes of anything.
    DigestWidth(usize),
    /// An outcome number this version does not allocate.
    UnknownOutcome(u8),
    /// Rows fed to a digest with `what` going backwards. Canonical order is not
    /// a preference: two controllers walking their tables differently would
    /// publish different digests for one topology.
    RowsOutOfOrder { after: RowKind, got: RowKind },
    /// The same key twice (P-015).
    Duplicate(ReadInventoryKey),
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for InventoryError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl InventoryError {
    /// What to answer. A row past [`MAX_ROW_BYTES`] is error 5, as a wrapper too
    /// large to write is; too many `cmds` is not, because the bytes fit and it
    /// is the shape that is wrong. Everything else is a body whose meaning
    /// cannot be trusted, which is what error 1 says.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::RowTooLong(_) => Refusal::Client(ErrorCode::PayloadTooLarge),
            Self::RowShape { .. }
            | Self::MissingRequired { .. }
            | Self::WrongType { .. }
            | Self::EmptyCmds
            | Self::TooManyCmds(_)
            | Self::DuplicateRowKey { .. }
            | Self::ReservedZero { .. }
            | Self::PositionPastSeries { .. }
            | Self::NotAMember { .. }
            | Self::SeriesTooShort(_)
            | Self::SeriesTooLong(_)
            | Self::LabelPastRange { .. }
            | Self::MissingConditional { .. }
            | Self::UnexpectedConditional { .. }
            | Self::WrongKind { .. }
            | Self::Missing(_)
            | Self::MissingResponse(_)
            | Self::AnsweredNothing(_)
            | Self::DigestMidWalk
            | Self::DigestWidth(_)
            | Self::UnknownOutcome(_)
            | Self::RowsOutOfOrder { .. }
            | Self::Duplicate(_)
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for InventoryError {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RowShape { kind, want, got } => {
                write!(w, "a {kind} row wants {want} values and got {got}")
            }
            Self::MissingRequired { kind, key } => {
                write!(w, "a {kind} row left required key {key} absent")
            }
            Self::WrongType { kind, key } => {
                write!(w, "a {kind} row carries the wrong shape under key {key}")
            }
            Self::EmptyCmds => w.write_str("an empty cmds array, where none is spelled as absence"),
            Self::TooManyCmds(n) => write!(w, "{n} commands is past what one row may accept"),
            Self::DuplicateRowKey { kind, key } => {
                write!(w, "a {kind} row carries key {key} twice")
            }
            Self::ReservedZero { kind, key } => {
                write!(w, "a {kind} row's key {key} is 0, which is reserved")
            }
            Self::PositionPastSeries { at, elements } => {
                write!(w, "element {at} of a series with {elements} of them")
            }
            Self::NotAMember {
                kind,
                key,
                space,
                value,
            } => write!(w, "a {kind} row's key {key} is {value} and no {space} is"),
            Self::SeriesTooShort(n) => write!(w, "a series of {n} is a scalar"),
            Self::SeriesTooLong(n) => {
                write!(w, "a series of {n} has elements no concern can name")
            }
            Self::LabelPastRange { base, at } => {
                write!(w, "element {at} of a series based at {base} has no label")
            }
            Self::MissingConditional { kind, key, when } => {
                write!(w, "a {kind} row left key {key} absent and {when}")
            }
            Self::UnexpectedConditional { kind, key, when } => {
                write!(
                    w,
                    "a {kind} row carries key {key} and it is not true that {when}"
                )
            }
            Self::WrongKind { page, row } => {
                write!(w, "a {row} row does not belong on a {page} page")
            }
            Self::RowTooLong(n) => write!(w, "a row of {n} bytes is past MAX_ROW_BYTES"),
            Self::Missing(key) => write!(w, "{key} never arrived"),
            Self::Duplicate(key) => write!(w, "{key} arrived twice"),
            Self::MissingResponse(key) => write!(w, "{key} never arrived"),
            Self::AnsweredNothing(o) => {
                write!(
                    w,
                    "outcome {} answered nothing and carried something",
                    o.number()
                )
            }
            Self::DigestMidWalk => {
                w.write_str("a whole-topology digest on a page that is not the last")
            }
            Self::DigestWidth(n) => write!(w, "a digest of {n} bytes is not eight"),
            Self::UnknownOutcome(n) => write!(w, "outcome {n} is not allocated"),
            Self::RowsOutOfOrder { after, got } => {
                write!(w, "a {got} page after a {after} one is not canonical order")
            }
            Self::Cbor(why) => write!(w, "{why}"),
        }
    }
}

impl core::error::Error for InventoryError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{MAX_ADDR, MAX_COMPONENT_CMDS, MAX_IDENT, MAX_LABEL, MAX_SERIES_LEN};
    use crate::render::Rendering;

    /// No two refusals read as one sentence, and each carries the code P-141
    /// leaves for a body that never reached a handler: error 5 for a row past
    /// its byte bound, error 1 for the rest, too many `cmds` included, because
    /// its bytes fit and it is the shape that is wrong.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [InventoryError; 25] = [
            InventoryError::RowShape {
                kind: RowKind::Bus,
                want: 5,
                got: 4,
            },
            InventoryError::MissingRequired {
                kind: RowKind::Device,
                key: 2,
            },
            InventoryError::WrongType {
                kind: RowKind::Component,
                key: 3,
            },
            InventoryError::EmptyCmds,
            InventoryError::TooManyCmds(9),
            InventoryError::DuplicateRowKey {
                kind: RowKind::Signal,
                key: 4,
            },
            InventoryError::ReservedZero {
                kind: RowKind::Param,
                key: 1,
            },
            InventoryError::PositionPastSeries {
                at: 17,
                elements: 16,
            },
            InventoryError::NotAMember {
                kind: RowKind::Bus,
                key: 2,
                space: Closed::Transport,
                value: 9,
            },
            InventoryError::SeriesTooShort(1),
            InventoryError::SeriesTooLong(40),
            InventoryError::LabelPastRange {
                base: u16::MAX,
                at: 2,
            },
            InventoryError::MissingConditional {
                kind: RowKind::Signal,
                key: 8,
                when: When::ShapeIsASeries,
            },
            InventoryError::UnexpectedConditional {
                kind: RowKind::Signal,
                key: 8,
                when: When::KindIsAVendorsOwn,
            },
            InventoryError::WrongKind {
                page: RowKind::Bus,
                row: RowKind::Device,
            },
            InventoryError::RowTooLong(300),
            InventoryError::Missing(ReadInventoryKey::What),
            InventoryError::MissingResponse(InventoryKey::Rev),
            InventoryError::AnsweredNothing(InventoryOutcome::OutOfRange),
            InventoryError::DigestMidWalk,
            InventoryError::DigestWidth(7),
            InventoryError::UnknownOutcome(9),
            InventoryError::RowsOutOfOrder {
                after: RowKind::Signal,
                got: RowKind::Bus,
            },
            InventoryError::Duplicate(ReadInventoryKey::Rev),
            InventoryError::Cbor(CborError::WrongType),
        ];
        Rendering::<128>::each_says_something_of_its_own(&EVERY);
        for why in EVERY {
            let want = if matches!(why, InventoryError::RowTooLong(_)) {
                Refusal::Client(ErrorCode::PayloadTooLarge)
            } else {
                Refusal::Client(ErrorCode::MalformedFrame)
            };
            assert_eq!(why.refusal(), want, "{why}");
        }
    }

    const LABEL: &str = "01234567890123456789012345678901"; // MAX_LABEL
    const IDENT: &str = "012345678901234567890123"; // MAX_IDENT
    const ADDR: &[u8] = &[0xFF; MAX_ADDR];
    const CMDS: &[u16] = &[0xFFFF; 4]; // MAX_COMPONENT_CMDS
    pub(super) const SERIES_LEN: u8 = 16; // MAX_SERIES_LEN, as the u8 key 10 carries

    fn cmds(items: &[u16]) -> CmdList {
        CmdList::new(items).expect("a bounded, non-empty cmds array")
    }

    /// Every optional key present, every string at its cap, and every number at
    /// the widest it may **legally** carry — which is its type for an open field
    /// and its space for a closed one.
    pub(super) fn widest(kind: RowKind) -> [Value<'static>; MAX_ROW_KEYS] {
        let mut out = [Value::Absent; MAX_ROW_KEYS];
        for (slot, field) in out.iter_mut().zip(kind.fields()) {
            *slot = match field.ty {
                FieldType::U8 => Value::U8(u8::MAX),
                FieldType::U16 => Value::U16(u16::MAX),
                FieldType::U32 => Value::U32(u32::MAX),
                FieldType::I32 => Value::I32(i32::MIN),
                FieldType::Text => Value::Text(if matches!(kind, RowKind::Device) {
                    IDENT
                } else {
                    LABEL
                }),
                FieldType::Bytes => Value::Bytes(ADDR),
                FieldType::U16List => Value::U16List(cmds(CMDS)),
            };
            // **`shape` and `vtype` are costed at the condition and not at the
            // type, and they are the only two that are.** Every optional key
            // present is what makes a row widest, and `n` and `esp` are only
            // legal when these two carry exactly those values — so the widest
            // row that can exist carries them at one byte each. That is not the
            // *this controller's value* reasoning the table above rejects: a
            // space gaining members cannot move a number the condition pins.
            if let Some(&(_, space)) = kind.closed().iter().find(|(key, _)| *key == field.key) {
                *slot = Value::U8(space.widest());
            }
            // `shape` and `vtype` are pinned below their spaces as well as by
            // them: `n` and `esp` are legal *only* at exactly these two values,
            // so a row carrying every optional key carries these.
            if field.key == SHAPE_KEY && matches!(kind, RowKind::Signal) {
                *slot = Value::U8(2);
            }
            if field.key == VTYPE_KEY && matches!(kind, RowKind::Signal | RowKind::Param) {
                *slot = Value::U8(4);
            }
            // And `n` and `ebase` are costed at their **ranges**, for the same
            // reason: a series longer than `MAX_SERIES_LEN` has elements no
            // `Concern` can name, and a base that leaves room for fewer than `n`
            // labels promises cells that do not exist. The widest legal series is
            // sixteen elements ending at `u16::MAX`, which is one byte for `n`
            // where `u8::MAX` costs two and no change at all for `ebase`.
            if field.key == N_KEY && matches!(kind, RowKind::Signal) {
                *slot = Value::U8(SERIES_LEN);
            }
            if field.key == EBASE_KEY && matches!(kind, RowKind::Signal) {
                *slot = Value::U16(u16::MAX - u16::from(SERIES_LEN) + 1);
            }
        }
        out
    }

    /// The fixtures above are string literals, and a cap that moved would leave
    /// them measuring nothing. This is what stops "at its widest" quietly
    /// becoming "at the width somebody typed in once".
    #[test]
    fn the_widest_fixtures_are_still_at_the_caps_they_are_named_for() {
        assert_eq!(LABEL.len(), MAX_LABEL, "LABEL must be exactly MAX_LABEL");
        assert_eq!(IDENT.len(), MAX_IDENT, "IDENT must be exactly MAX_IDENT");
        assert_eq!(ADDR.len(), MAX_ADDR, "ADDR must be exactly MAX_ADDR");
        assert_eq!(
            CMDS.len(),
            MAX_COMPONENT_CMDS,
            "CMDS must be exactly the cap"
        );
        assert_eq!(
            usize::from(SERIES_LEN),
            MAX_SERIES_LEN,
            "SERIES_LEN must be exactly the cap, as the u8 key 10 carries"
        );
    }

    /// **The check that stops the row-width table becoming a second copy of the
    /// encoder.** The document derives Bus 47, Device 170, Component 80,
    /// Signal 90 and Param 98 by hand; these are what the encoder actually
    /// writes, and the two have to agree or one of them is wrong.
    ///
    /// **This sentence has been true and unread three times.** The five numbers
    /// above have not changed since they were derived; what changed is the
    /// encoder, which wrote 48/96/101, then 48/94/100, then 48/93/100, and the
    /// table was edited each time to match it. Every round the hand derivation
    /// was right and the encoder was missing a check the field list already
    /// stated — the conditional keys, then `n` and `ebase`'s ranges, then the six
    /// closed spaces. A check whose two sides can both be edited only holds if
    /// the person editing knows which side is the witness.
    ///
    /// A `#[test]` and not a `const_assert!`: `CborWriter` is not `const fn`, so
    /// the assertion an earlier draft of the design prescribed could not have
    /// compiled. That is the same shape as the COBS bound this crate already
    /// carried twice — two formulas, both safe, disagreeing at every multiple of
    /// 254 with nothing going red.
    #[test]
    fn a_row_at_its_widest_is_the_width_the_document_derives() {
        // `DeviceRow`'s three strings are MAX_IDENT and its label is MAX_LABEL,
        // so it is measured on its own below rather than through the helper.
        for (kind, want) in [
            (RowKind::Bus, 47),
            (RowKind::Component, 80),
            // A row is widest with every optional key present and every value at
            // the widest it may **legally** carry — the type where the field is
            // open, the space where it is closed. Seven of a signal's keys are
            // pinned below their type: `shape` and `vtype` by the conditions
            // that make `n` and `esp` legal, `n` and `ebase` by the ranges the
            // field list states, and `domain`, `dir` and `hist` by their spaces.
            //
            // The fixture asks each space for its largest member rather than
            // naming it, so allocating a twenty-fourth moves this number and
            // says so here. That is the answer to the objection the design
            // raised against costing by space, and it is why the rule can be
            // uniform: a derivation that re-runs is not an assumption.
            (RowKind::Signal, 90),
            (RowKind::Param, 98),
        ] {
            let values = widest(kind);
            let n = kind.fields().len();
            let row = Row::new(kind, values.get(..n).expect("fits")).expect("legal");
            assert_eq!(
                row.encoded_len().expect("a widest row fits its scratch"),
                want,
                "{kind} row at its widest"
            );
        }
    }

    /// `DeviceRow` carries three `MAX_IDENT` strings and one `MAX_LABEL`, which
    /// the uniform helper cannot express — and getting that wrong is a 24-byte
    /// error in the widest row of the five.
    #[test]
    fn a_device_row_at_its_widest_is_a_hundred_and_seventy_bytes() {
        let values = [
            Value::U16(u16::MAX),
            Value::U8(u8::MAX),
            Value::Bytes(ADDR),
            Value::U16(u16::MAX),
            Value::U16(u16::MAX),
            Value::U16(u16::MAX),
            Value::U16(u16::MAX),
            Value::Text(IDENT),
            Value::Text(IDENT),
            Value::Text(IDENT),
            Value::Text(LABEL),
            Value::U32(u32::MAX),
            Value::U16List(cmds(CMDS)),
        ];
        let row = Row::new(RowKind::Device, &values).expect("legal");
        let widest = row.encoded_len().expect("fits");
        assert_eq!(widest, 170);
        // The margin, measured rather than asserted as a literal: the scratch has
        // to hold the widest row this encoder can produce, and the gap between
        // them is what absorbs a row gaining a key.
        assert_eq!(
            MAX_ROW_BYTES.checked_sub(widest),
            Some(14),
            "the margin the document states, over the width this encoder writes"
        );
    }

    /// A row with every optional key absent is the other end of the table, and
    /// it is what the walk arithmetic in the design is costed on.
    #[test]
    fn a_row_with_every_optional_key_absent_is_the_narrowest_legal_one() {
        // Small values, not `u8::MAX`: the ceiling asks how many rows could ever
        // arrive, so it is the row at its cheapest and not its required keys at
        // their widest. The committed vector settled this one — it built the
        // genuinely narrowest row and disagreed with this test by two bytes.
        let values = [Value::U8(1), Value::U8(1), Value::Absent, Value::Absent];
        let row = Row::new(RowKind::Bus, &values).expect("required keys only is legal");
        assert_eq!(
            row.encoded_len().expect("fits"),
            5,
            "map header 1 + bus 2 + transport 2, which is INVENTORY_PAGE_ROWS_CEILING's divisor"
        );
    }

    /// P-015 in this module: a key the table does not mark optional cannot be
    /// left out. A short row would make a receiver invent the missing field.
    #[test]
    fn a_required_key_left_absent_is_refused_rather_than_encoded_short() {
        let mut values = widest(RowKind::Component);
        values[8] = Value::Absent; // key 9 `since`, which is required
        let n = RowKind::Component.fields().len();
        assert_eq!(
            Row::new(RowKind::Component, values.get(..n).expect("fits")).unwrap_err(),
            InventoryError::MissingRequired {
                kind: RowKind::Component,
                key: 9,
            }
        );
    }

    /// **A standard kind carrying its own `unit` is a second source of truth for
    /// the number on a screen** (P-204).
    ///
    /// The registry answers for the unit and the scale of every kind below
    /// `0xF000`, and a row that carries them again is two answers to *what is
    /// this in*. Above it the registry cannot answer at all, so the row must.
    /// `Field` says required or optional and cannot say *iff*, so this was a
    /// comment beside an `opt(...)` and no check anywhere.
    #[test]
    fn p_204_a_unit_rides_a_vendors_own_kind_and_never_a_kind_the_registry_names() {
        // Positions, not key numbers: keys run 1..n on both rows, so `kind` is
        // key 4 at slot 3 and `unit`, `scale` and `vns` are keys 14, 15 and 16.
        const KIND_AT: usize = 3;
        const VENDOR_ANSWERS: [usize; 3] = [13, 14, 15];
        for kind in [RowKind::Signal, RowKind::Param] {
            let n = kind.fields().len();
            let mut values = widest(kind);

            // A standard kind, with the three keys still there.
            *values.get_mut(KIND_AT).expect("slot") = Value::U16(0x0101);
            assert_eq!(
                Row::new(kind, values.get(..n).expect("fits")).unwrap_err(),
                InventoryError::UnexpectedConditional {
                    kind,
                    key: 14,
                    when: When::KindIsAVendorsOwn
                },
                "a kind the registry names carried its own unit"
            );

            // A vendor's own kind with them left out.
            let mut values = widest(kind);
            for at in VENDOR_ANSWERS {
                *values.get_mut(at).expect("slot") = Value::Absent;
            }
            assert_eq!(
                Row::new(kind, values.get(..n).expect("fits")).unwrap_err(),
                InventoryError::MissingConditional {
                    kind,
                    key: 14,
                    when: When::KindIsAVendorsOwn
                },
                "a kind nothing can answer for arrived with no unit"
            );
        }
    }

    /// **A series row with no `n` makes a decoder size an array from a key that
    /// is not there**, and an enum row with no `esp` publishes a number with no
    /// space to name it — P-164's failure one layer down, in the descriptor.
    #[test]
    fn a_conditional_key_is_refused_both_when_it_is_missing_and_when_it_should_not_be_there() {
        let n = RowKind::Signal.fields().len();

        // Shape says series and `n` is gone.
        let mut values = widest(RowKind::Signal);
        *values.get_mut(9).expect("key 10 n") = Value::Absent;
        assert_eq!(
            Row::new(RowKind::Signal, values.get(..n).expect("fits")).unwrap_err(),
            InventoryError::MissingConditional {
                kind: RowKind::Signal,
                key: 10,
                when: When::ShapeIsASeries
            }
        );

        // Shape says scalar and `n` is there anyway.
        let mut values = widest(RowKind::Signal);
        *values.get_mut(4).expect("key 5 shape") = Value::U8(1);
        assert_eq!(
            Row::new(RowKind::Signal, values.get(..n).expect("fits")).unwrap_err(),
            InventoryError::UnexpectedConditional {
                kind: RowKind::Signal,
                key: 10,
                when: When::ShapeIsASeries
            }
        );

        // A vtype that names no space, with `esp` still on the row.
        let mut values = widest(RowKind::Signal);
        *values.get_mut(4).expect("key 5 shape") = Value::U8(1);
        *values.get_mut(9).expect("key 10 n") = Value::Absent;
        *values.get_mut(5).expect("key 6 vtype") = Value::U8(1);
        assert_eq!(
            Row::new(RowKind::Signal, values.get(..n).expect("fits")).unwrap_err(),
            InventoryError::UnexpectedConditional {
                kind: RowKind::Signal,
                key: 13,
                when: When::ValueComesFromASpace
            }
        );
    }

    /// **An empty `cmds` array is not how *none* is spelled** (P-201).
    ///
    /// Absence means that scope accepts no commands, so an empty array is a
    /// second encoding of one fact — and a driver that writes it is one nobody
    /// can tell from a driver with a bug. It is error 1 on the wire, and it was
    /// encoding cleanly here until this: the row builder checked required
    /// against optional and never looked inside a list.
    ///
    /// The refusal is at the type now rather than in the row builder, which is
    /// what lets a reader share it — a `cmds` that arrives empty on the wire is
    /// refused by the same line that refuses one a driver builds.
    #[test]
    fn p_201_an_empty_cmds_array_is_refused_where_absence_is_what_none_means() {
        assert_eq!(CmdList::new(&[]), Err(InventoryError::EmptyCmds));
        assert_eq!(
            CmdList::new(&[1, 2, 3, 4, 5]),
            Err(InventoryError::TooManyCmds(5)),
            "a fifth command is a component that should be a parent and a child"
        );

        for kind in [RowKind::Device, RowKind::Component] {
            let mut values = widest(kind);
            let n = kind.fields().len();
            let at = kind
                .fields()
                .iter()
                .position(|f| matches!(f.ty, FieldType::U16List))
                .expect("both rows carry cmds");

            // And absence itself is legal, which is the half that must not move.
            *values.get_mut(at).expect("the slot") = Value::Absent;
            Row::new(kind, values.get(..n).expect("fits")).expect("no cmds is a legal row");
        }
    }

    /// A value of the wrong shape under a key is a caller bug, and it is caught
    /// where the row is built rather than once per page.
    #[test]
    fn a_value_of_the_wrong_shape_is_refused_at_the_row() {
        let mut values = widest(RowKind::Bus);
        values[0] = Value::Text(LABEL); // key 1 `bus` is a u8
        assert_eq!(
            Row::new(RowKind::Bus, values.get(..4).expect("fits")).unwrap_err(),
            InventoryError::WrongType {
                kind: RowKind::Bus,
                key: 1,
            }
        );
    }

    /// The row arm. Forty-eight narrow rows fill a page before its bytes do,
    /// and the forty-ninth is refused rather than splitting or evicting.
    #[test]
    fn p_208_a_page_stops_at_the_row_cap_when_the_rows_are_narrow() {
        let values = [Value::U8(1), Value::U8(1), Value::Absent, Value::Absent];
        let row = Row::new(RowKind::Bus, &values).expect("legal");
        let mut page = Page::new(RowKind::Bus);
        for id in 1..=MAX_INVENTORY_PAGE_ROWS {
            assert!(
                page.push(&row, u16::try_from(id).expect("fits"))
                    .expect("encodes"),
                "row {id} must fit"
            );
        }
        assert!(
            !page.push(&row, 49).expect("encodes"),
            "the row cap binds before the byte cap for a narrow row"
        );
        assert_eq!(page.rows(), MAX_INVENTORY_PAGE_ROWS);
        assert_eq!(page.next(), 49, "the cursor names the row that did not fit");
    }

    /// The byte arm. Five widest device rows are 850 bytes and a sixth would be
    /// 1,020 against a cap of 880, so the bytes bind first and the row cap of
    /// 48 never gets near.
    #[test]
    fn p_208_a_page_stops_at_the_byte_cap_when_the_rows_are_wide() {
        let values = [
            Value::U16(u16::MAX),
            Value::U8(u8::MAX),
            Value::Bytes(ADDR),
            Value::U16(u16::MAX),
            Value::U16(u16::MAX),
            Value::U16(u16::MAX),
            Value::U16(u16::MAX),
            Value::Text(IDENT),
            Value::Text(IDENT),
            Value::Text(IDENT),
            Value::Text(LABEL),
            Value::U32(u32::MAX),
            Value::U16List(cmds(CMDS)),
        ];
        let row = Row::new(RowKind::Device, &values).expect("legal");
        let mut page = Page::new(RowKind::Device);
        for id in 1..=5u16 {
            assert!(page.push(&row, id).expect("encodes"), "device row {id}");
        }
        assert!(
            !page.push(&row, 6).expect("encodes"),
            "a sixth widest device row is past the byte cap"
        );
        assert_eq!(page.rows(), 5, "the document's rows-per-page for a device");
        assert_eq!(page.len(), 5 * 170);
        assert!(page.len() <= MAX_INVENTORY_PAGE_BYTES);
    }

    /// A page carries one kind, and `what` is echoed in the response — so a page
    /// holding two kinds is a response that lies about itself.
    #[test]
    fn a_row_of_another_kind_does_not_belong_on_this_page() {
        let bus = [Value::U8(1), Value::U8(1), Value::Absent, Value::Absent];
        let row = Row::new(RowKind::Bus, &bus).expect("legal");
        let mut page = Page::new(RowKind::Signal);
        assert_eq!(
            page.push(&row, 1),
            Err(InventoryError::WrongKind {
                page: RowKind::Signal,
                row: RowKind::Bus,
            })
        );
    }

    /// The rows go onto the wire as the bytes they encoded to, never re-encoded
    /// — which is what lets P-173 hash them on both sides without either party
    /// running an encoder over a decode.
    #[test]
    fn the_rows_reach_the_body_as_the_bytes_they_encoded_to() {
        let values = [Value::U8(3), Value::U8(1), Value::Absent, Value::Absent];
        let row = Row::new(RowKind::Bus, &values).expect("legal");

        let mut page = Page::new(RowKind::Bus);
        assert!(page.push(&row, 3).expect("encodes"));
        let row_len = page.len();

        let mut dst = [0u8; 64];
        let mut cbor = CborWriter::new(&mut dst);
        page.encode_into(&mut cbor).expect("the array fits");
        let len = cbor.finish().expect("finished");

        // `[ {1: 3, 2: 1} ]` — a one-element array header, then the row's own
        // bytes verbatim. The page holds those bytes and hands them over; if this
        // ever needs an encoder to reproduce them, P-173's preimage has stopped
        // being something two implementations can agree on.
        assert_eq!(dst.first(), Some(&0x81), "one-element array");
        assert_eq!(len, 1 + row_len, "the header, and the row unchanged");
        assert_eq!(
            dst.get(1..len),
            page.encoded_rows().get(..row_len),
            "the row's bytes are copied, not rebuilt"
        );
    }

    /// `MAX_SERIES_LEN` is what a `SignalRow`'s `n` is bounded by, and the row
    /// table has to be able to carry it.
    #[test]
    fn a_series_signal_row_carries_its_length_and_its_element_base() {
        let mut values = widest(RowKind::Signal);
        values[9] = Value::U8(u8::try_from(MAX_SERIES_LEN).expect("fits a byte"));
        values[11] = Value::U16(17); // pack 2's half-string, ebase 17
        let n = RowKind::Signal.fields().len();
        let row = Row::new(RowKind::Signal, values.get(..n).expect("fits")).expect("legal");
        assert!(row.encoded_len().expect("fits") <= MAX_ROW_BYTES);
    }

    fn bus_row() -> [Value<'static>; 4] {
        [Value::U8(3), Value::U8(1), Value::Absent, Value::Absent]
    }

    /// A request arrives carrying what it left with, optional key and all.
    #[test]
    fn a_read_inventory_arrives_carrying_what_it_left_with() {
        for dev in [None, Some(7)] {
            let want = ReadInventory {
                rev: 41,
                what: RowKind::Param.number(),
                from: 0,
                dev,
            };
            let mut dst = [0u8; 32];
            let len = want.encode(&mut dst).expect("encodes");
            assert_eq!(
                ReadInventory::decode(dst.get(..len).expect("encoded")).expect("decodes"),
                want
            );
        }
    }

    /// P-015: a key the body does not mark optional cannot be left out, and a
    /// decoder that filled it in would be inventing a revision.
    #[test]
    fn a_read_inventory_missing_its_rev_is_refused_rather_than_defaulted() {
        let mut dst = [0u8; 32];
        let mut cbor = CborWriter::new(&mut dst);
        cbor.map(2).expect("map");
        cbor.key(2).expect("key");
        cbor.u64(1).expect("what");
        cbor.key(3).expect("key");
        cbor.u64(0).expect("from");
        let len = cbor.finish().expect("finished");
        assert_eq!(
            ReadInventory::decode(dst.get(..len).expect("encoded")).unwrap_err(),
            InventoryError::Missing(ReadInventoryKey::Rev)
        );
    }

    /// An unallocated `what` is outcome 3 in the response and not a refusal
    /// here — the request parsed, it simply named a table that does not exist.
    #[test]
    fn p_147_an_unallocated_what_reaches_the_handler_rather_than_failing_to_decode() {
        let want = ReadInventory {
            rev: 1,
            what: 9,
            from: 0,
            dev: None,
        };
        let mut dst = [0u8; 32];
        let len = want.encode(&mut dst).expect("encodes");
        let got = ReadInventory::decode(dst.get(..len).expect("encoded")).expect("decodes");
        assert_eq!(got.what, 9);
        assert_eq!(
            RowKind::from_number(got.what),
            None,
            "and resolves to nothing"
        );
    }

    /// A page of rows goes out and comes back with the same count, and the row
    /// bytes on the wire are the ones the page built.
    #[test]
    fn an_inventory_page_arrives_carrying_the_rows_it_left_with() {
        let values = bus_row();
        let row = Row::new(RowKind::Bus, &values).expect("legal");
        let mut page = Page::new(RowKind::Bus);
        for id in 1..=3u16 {
            assert!(page.push(&row, id).expect("encodes"));
        }
        let body = InventoryBody {
            rev: 41,
            what: RowKind::Bus.number(),
            outcome: InventoryOutcome::Ok,
            total: 3,
            page: Some(&page),
            digest: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        };
        let mut dst = [0u8; 128];
        let len = body.encode(&mut dst).expect("encodes");
        let got = InventoryHeader::decode(dst.get(..len).expect("encoded")).expect("decodes");
        assert_eq!(got.rows, 3);
        assert_eq!(got.rev, 41);
        assert_eq!(got.next, 0, "the page ended the kind");
        assert_eq!(got.digest, Some([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(got.outcome, InventoryOutcome::Ok);
    }

    /// **P-190, from the writing side.** `next = 0` is the natural encoding of
    /// *nothing follows*, so an outcome that answered nothing must not also
    /// carry a digest — otherwise a client meeting outcome 4 sees a matching
    /// `rev`, a zero cursor and a whole-topology digest, and stamps a cache it
    /// never assembled.
    #[test]
    fn p_145_a_response_that_answered_nothing_cannot_carry_a_digest() {
        let body = InventoryBody {
            rev: 41,
            what: RowKind::Bus.number(),
            outcome: InventoryOutcome::OutOfRange,
            total: 3,
            page: None,
            digest: Some([0; 8]),
        };
        let mut dst = [0u8; 128];
        assert_eq!(
            body.encode(&mut dst).unwrap_err(),
            InventoryError::AnsweredNothing(InventoryOutcome::OutOfRange)
        );
    }

    /// **P-190, from the reading side.** A receiver that accepts the shape the
    /// encoder refuses to write is a receiver that will cache under it, and the
    /// two halves of a rule enforced on one side only is the half that is not
    /// enforced.
    #[test]
    fn p_145_a_received_response_that_answered_nothing_and_carries_a_digest_is_refused() {
        let mut dst = [0u8; 128];
        let mut cbor = CborWriter::new(&mut dst);
        cbor.map(7).expect("map");
        for (key, value) in [(1u8, 41u64), (2, 1)] {
            cbor.key(i64::from(key)).expect("key");
            cbor.u64(value).expect("value");
        }
        cbor.key(3).expect("key");
        cbor.array(0).expect("no rows");
        for (key, value) in [(4u8, 0u64), (5, 3), (6, 4)] {
            cbor.key(i64::from(key)).expect("key");
            cbor.u64(value).expect("value");
        }
        cbor.key(7).expect("key");
        cbor.bytes(&[0u8; 8]).expect("digest");
        let len = cbor.finish().expect("finished");
        assert_eq!(
            InventoryHeader::decode(dst.get(..len).expect("encoded")).unwrap_err(),
            InventoryError::AnsweredNothing(InventoryOutcome::OutOfRange)
        );
    }

    /// A digest is the whole topology's, so one on a page with a cursor is a
    /// client being handed a partial cache to stamp.
    #[test]
    fn p_145_a_digest_cannot_ride_a_page_that_is_not_the_last() {
        let values = bus_row();
        let row = Row::new(RowKind::Bus, &values).expect("legal");
        let mut page = Page::new(RowKind::Bus);
        for id in 1..=MAX_INVENTORY_PAGE_ROWS {
            page.push(&row, u16::try_from(id).expect("fits"))
                .expect("encodes");
        }
        page.push(&row, 49).expect("encodes"); // fills, so next is 49
        assert_eq!(page.next(), 49);
        let body = InventoryBody {
            rev: 41,
            what: RowKind::Bus.number(),
            outcome: InventoryOutcome::Ok,
            total: 49,
            page: Some(&page),
            digest: Some([0; 8]),
        };
        let mut dst = [0u8; 1024];
        assert_eq!(
            body.encode(&mut dst).unwrap_err(),
            InventoryError::DigestMidWalk
        );
    }

    /// An outcome number this version does not allocate is refused rather than
    /// read as one it does. P-165 surfaces an unrecognised value; it does not
    /// let a decoder pick the nearest.
    #[test]
    fn an_unallocated_outcome_is_refused_rather_than_rounded_to_a_known_one() {
        let mut dst = [0u8; 128];
        let mut cbor = CborWriter::new(&mut dst);
        cbor.map(6).expect("map");
        for (key, value) in [(1u8, 41u64), (2, 1)] {
            cbor.key(i64::from(key)).expect("key");
            cbor.u64(value).expect("value");
        }
        cbor.key(3).expect("key");
        cbor.array(0).expect("rows");
        for (key, value) in [(4u8, 0u64), (5, 0), (6, 9)] {
            cbor.key(i64::from(key)).expect("key");
            cbor.u64(value).expect("value");
        }
        let len = cbor.finish().expect("finished");
        assert_eq!(
            InventoryHeader::decode(dst.get(..len).expect("encoded")).unwrap_err(),
            InventoryError::UnknownOutcome(9)
        );
    }

    /// P-146: the controller does not pin a walk. A `rev` that is neither 0 nor
    /// current is answered `superseded` with an empty array and the current
    /// revision in key 1 — so a torn walk is detectable in a field that is
    /// already on every page, and the client learns what to ask for next.
    #[test]
    fn p_146_a_superseded_walk_is_answered_with_the_current_rev_and_nothing_else() {
        let body = InventoryBody {
            rev: 42,
            what: RowKind::Bus.number(),
            outcome: InventoryOutcome::Superseded,
            total: 0,
            page: None,
            digest: None,
        };
        let mut dst = [0u8; 64];
        let len = body.encode(&mut dst).expect("encodes");
        let got = InventoryHeader::decode(dst.get(..len).expect("encoded")).expect("decodes");
        assert_eq!(got.outcome, InventoryOutcome::Superseded);
        assert_eq!(got.rev, 42, "the rev to walk under next");
        assert_eq!(got.rows, 0, "a superseded page answers nothing");
        assert_eq!(got.next, 0);
        assert_eq!(got.digest, None);
    }

    fn page_of(kind: RowKind, values: &[Value<'_>]) -> Page {
        let row = Row::new(kind, values).expect("legal");
        let mut page = Page::new(kind);
        assert!(page.push(&row, 1).expect("encodes"));
        page
    }

    fn labelled_component(label: &str) -> [Value<'_>; 9] {
        [
            Value::U16(7),
            Value::U16(1),
            Value::Absent,
            Value::U16(4),
            Value::Absent,
            Value::Absent,
            Value::Text(label),
            Value::Absent,
            Value::U32(41),
        ]
    }

    /// **The one silent failure this design has, and the only test that can see
    /// it.** A label edited without the revision moving leaves `rev` matching at
    /// every client, so nothing refetches — P-149 exists for exactly this, and
    /// it is prose unless the digest covers the label's bytes.
    ///
    /// It does because the preimage is the row as encoded, and a row carries its
    /// label. A digest over the rows the controller *holds* — offsets into FRAM,
    /// as the RAM table describes them — would not move here, and this test
    /// would stay green while the defect shipped.
    #[test]
    fn p_149_a_label_edited_without_bumping_rev_moves_the_digest() {
        let before = {
            let values = labelled_component("pump house");
            let mut d = TopoDigest::new(41);
            d.absorb(&page_of(RowKind::Component, &values))
                .expect("absorbs");
            d.finish()
        };
        let after = {
            let values = labelled_component("pump hous");
            let mut d = TopoDigest::new(41);
            d.absorb(&page_of(RowKind::Component, &values))
                .expect("absorbs");
            d.finish()
        };
        assert_ne!(
            before, after,
            "a label edit under a fixed rev must move the digest, or P-149 is prose"
        );
    }

    /// The revision is in the preimage, so a digest cannot be lifted from one
    /// revision to another. Same rows, different `rev`, different digest.
    #[test]
    fn p_149_the_same_rows_under_a_different_rev_are_a_different_digest() {
        let values = labelled_component("pump house");
        let one = {
            let mut d = TopoDigest::new(41);
            d.absorb(&page_of(RowKind::Component, &values))
                .expect("absorbs");
            d.finish()
        };
        let two = {
            let mut d = TopoDigest::new(42);
            d.absorb(&page_of(RowKind::Component, &values))
                .expect("absorbs");
            d.finish()
        };
        assert_ne!(one, two, "rev is in the preimage");
    }

    /// Canonical order is `what` ascending. Two controllers that walk their
    /// tables differently would otherwise publish different digests for one
    /// topology, and P-149 turns that into every client on the site surfacing a
    /// controller fault against a healthy one.
    #[test]
    fn p_148_rows_fed_out_of_canonical_order_are_refused() {
        let bus = [Value::U8(1), Value::U8(1), Value::Absent, Value::Absent];
        let values = labelled_component("pump house");
        let mut d = TopoDigest::new(41);
        d.absorb(&page_of(RowKind::Component, &values))
            .expect("components are what 3");
        assert_eq!(
            d.absorb(&page_of(RowKind::Bus, &bus)).unwrap_err(),
            InventoryError::RowsOutOfOrder {
                after: RowKind::Component,
                got: RowKind::Bus,
            },
            "buses are what 1 and cannot follow components"
        );
    }

    /// The digest is over the bytes as they appear in a page, so a client that
    /// concatenates what it received gets what the controller computed. Neither
    /// side re-encodes, which is P-017 and P-048 surviving a hash computed on
    /// both ends.
    #[test]
    fn p_148_the_preimage_is_the_label_the_rev_and_the_row_bytes() {
        let values = labelled_component("pump house");
        let page = page_of(RowKind::Component, &values);

        let mut by_hand = Sha256::new();
        by_hand.update(TOPO_DIGEST_LABEL);
        by_hand.update(41u32.to_be_bytes());
        by_hand.update(page.encoded_rows());
        let full = by_hand.finalize();

        let mut d = TopoDigest::new(41);
        d.absorb(&page).expect("absorbs");
        assert_eq!(
            d.finish().as_slice(),
            full.get(..8).expect("a sha256 is longer than eight bytes"),
            "the leftmost eight of SHA-256 over label, rev, rows"
        );
        assert_eq!(
            TOPO_DIGEST_LABEL.len(),
            19,
            "the label is nineteen ASCII bytes"
        );
    }
    /// The field lists said `cmp` 0 is reserved and `sig` counts from 1, and
    /// nothing checked either. A component row at 0 names nothing; a signal
    /// row at 0, bounced off a full page, comes back as `next = 0`, which is
    /// *this kind is complete*.
    #[test]
    fn a_component_or_signal_row_at_zero_is_refused() {
        for kind in [RowKind::Component, RowKind::Signal] {
            let mut values = widest(kind);
            values[0] = Value::U16(0);
            let n = kind.fields().len();
            assert_eq!(
                Row::new(kind, values.get(..n).expect("fits")).unwrap_err(),
                InventoryError::ReservedZero { kind, key: 1 }
            );
        }
    }

    /// Every strict prefix is refused, and only the whole body reads.
    fn refused_at_every_cut<T: core::fmt::Debug>(
        bytes: &[u8],
        decode: impl Fn(&[u8]) -> Result<T, InventoryError>,
    ) {
        for cut in 0..bytes.len() {
            assert!(
                decode(bytes.get(..cut).expect("a prefix")).is_err(),
                "a prefix of {cut} bytes decoded"
            );
        }
        assert!(
            decode(bytes).is_ok(),
            "the whole body must decode, or the loop proves nothing"
        );
    }

    /// Neither the request nor the response header had a truncation test. A
    /// resynchronising receiver hands both arbitrary prefixes.
    #[test]
    fn an_inventory_request_or_header_cut_short_at_any_byte_is_refused() {
        let mut out = [0u8; 128];
        let len = ReadInventory {
            rev: 1,
            what: RowKind::Param.number(),
            from: 0,
            dev: Some(3),
        }
        .encode(&mut out)
        .expect("encodes");
        refused_at_every_cut(out.get(..len).expect("the body"), ReadInventory::decode);

        let values = bus_row();
        let row = Row::new(RowKind::Bus, &values).expect("legal");
        let mut page = Page::new(RowKind::Bus);
        assert!(page.push(&row, 1).expect("encodes"));
        let len = InventoryBody {
            rev: 41,
            what: RowKind::Bus.number(),
            outcome: InventoryOutcome::Ok,
            total: 1,
            page: Some(&page),
            digest: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        }
        .encode(&mut out)
        .expect("encodes");
        refused_at_every_cut(out.get(..len).expect("the body"), InventoryHeader::decode);
    }
}

/// Reading a row back, which is the half a client does.
///
/// The rules here bind a **reader**, so most of these fixtures are bytes rather
/// than builders: a duplicate key and a key nobody has allocated are both things
/// this crate will not write and has to survive receiving.
#[cfg(test)]
mod reading {
    use super::*;
    use crate::concerns::ElementAt;

    /// Pack 2 of a 32-cell string: sixteen cells, and the first is called 17.
    ///
    /// `sig` 204 at `cmp` 57, which is the signal `vectors/v1.json`'s concern
    /// page names when it reports cell 23.
    const PACK_TWO: &[(u8, u64)] = &[
        (1, 204),    // sig
        (2, 3),      // dev
        (3, 57),     // cmp
        (4, 0x0201), // kind
        (5, 2),      // shape: series
        (6, 1),      // vtype
        (7, 1),      // domain
        (10, 16),    // n
        (12, 17),    // ebase
    ];

    /// One row's keys, edited — the way to put a row on the wire that no builder
    /// here will write. Fixed, because this crate has no allocator in its tests
    /// either, so a fixture cannot disagree with the target about a bound.
    struct Pairs {
        items: [(u8, u64); MAX_ROW_KEYS],
        len: usize,
    }

    impl Pairs {
        fn of(from: &[(u8, u64)]) -> Self {
            let mut items = [(0u8, 0u64); MAX_ROW_KEYS];
            items
                .get_mut(..from.len())
                .expect("a row's keys fit its own table")
                .copy_from_slice(from);
            Self {
                items,
                len: from.len(),
            }
        }

        fn held(&self) -> &[(u8, u64)] {
            self.items.get(..self.len).unwrap_or(&[])
        }

        fn at(&self, key: u8) -> usize {
            self.held()
                .iter()
                .position(|(k, _)| *k == key)
                .expect("a key this fixture carries")
        }

        fn set(mut self, key: u8, value: u64) -> Self {
            let at = self.at(key);
            *self.items.get_mut(at).expect("the slot") = (key, value);
            self
        }

        fn without(mut self, key: u8) -> Self {
            let at = self.at(key);
            self.items.copy_within(at.saturating_add(1)..self.len, at);
            self.len = self.len.saturating_sub(1);
            self
        }

        /// Appended, so the caller has to pick a key above every other one for
        /// the map to stay in P-016's order.
        fn plus(mut self, key: u8, value: u64) -> Self {
            *self.items.get_mut(self.len).expect("room for one more") = (key, value);
            self.len = self.len.saturating_add(1);
            self
        }

        /// The map, written straight out with no builder in the way.
        fn bytes(&self, dst: &mut [u8; MAX_ROW_BYTES]) -> usize {
            let mut cbor = CborWriter::new(dst);
            cbor.map(self.len).expect("a map header");
            for (key, value) in self.held() {
                cbor.key(i64::from(*key)).expect("a key");
                cbor.u64(*value).expect("a value");
            }
            cbor.finish().expect("a whole map")
        }
    }

    /// What a signal row says its elements are called.
    fn labels(pairs: &Pairs) -> ElementLabels {
        let mut bytes = [0u8; MAX_ROW_BYTES];
        let len = pairs.bytes(&mut bytes);
        RowSlots::new()
            .decode(RowKind::Signal, bytes.get(..len).expect("what was written"))
            .expect("a legal signal row")
            .labels()
            .expect("a series row describes a series")
    }

    /// Why a row was refused, for the fixtures that are supposed to be.
    fn refused(kind: RowKind, pairs: &Pairs) -> InventoryError {
        let mut bytes = [0u8; MAX_ROW_BYTES];
        let len = pairs.bytes(&mut bytes);
        RowSlots::new()
            .decode(kind, bytes.get(..len).expect("what was written"))
            .expect_err("this fixture is supposed to be refused")
    }

    fn at(position: u8) -> ElementAt {
        ElementAt::new(position).expect("a 1-based position inside a series")
    }

    /// **What was written is what reads back.**
    ///
    /// One field table drives both directions, so this is the check that they
    /// really are one: a key the encoder walks and the reader does not would
    /// come back `Absent` under a row that carries it.
    #[test]
    fn a_row_reads_back_as_the_values_it_was_written_from() {
        for kind in [
            RowKind::Bus,
            RowKind::Device,
            RowKind::Component,
            RowKind::Signal,
            RowKind::Param,
        ] {
            let values = tests::widest(kind);
            let want = values.get(..kind.fields().len()).expect("fits");
            let row = Row::new(kind, want).expect("a legal row");
            let mut page = Page::new(kind);
            assert!(page.push(&row, 1).expect("room on an empty page"));

            let mut slots = RowSlots::new();
            let read = slots
                .decode(kind, page.encoded_rows())
                .expect("a row this crate wrote is a row it reads");
            assert_eq!(read.kind(), kind);
            for (field, value) in kind.fields().iter().zip(want) {
                assert_eq!(
                    read.get(field.key),
                    match value {
                        Value::Absent => None,
                        held => Some(*held),
                    },
                    "{kind} key {}",
                    field.key
                );
            }
        }
    }

    /// **A rack nobody numbered starts at one, not at zero.**
    ///
    /// P-206: a `SignalRow` that omits `ebase` is read as `ebase = 1`. Nothing
    /// on the wire means *unlabelled*, so a reader that takes the missing key as
    /// 0 numbers every cell of every unnumbered string one below what somebody
    /// counting them out loud would say, and a fault report naming cell 6 sends
    /// them to the seventh.
    #[test]
    fn p_206_a_row_that_says_nothing_about_labels_numbers_its_elements_from_one() {
        let bare = labels(&Pairs::of(PACK_TWO).without(EBASE_KEY));
        assert_eq!(bare.base(), 1, "an absent ebase is 1 and never 0");
        assert_eq!(bare.elements(), 16);
        assert_eq!(
            bare.label_of(at(1)).expect("a legal position"),
            1,
            "the first element of an unlabelled series is called 1"
        );
        assert_eq!(bare.label_of(at(16)).expect("a legal position"), 16);
    }

    /// **Element 7 of pack 2 is cell 23, and printing 7 sends somebody to the
    /// other pack.**
    ///
    /// A 32-cell string is longer than one series may be, so it travels as two
    /// 16-element signals with `ebase` 1 and 17. `Concern` key 5 is the
    /// **position**, so the label is `ebase` + `elem` − 1. Both 7 and 23 parse,
    /// both MAC-verify, and the difference between them is four hours of driving
    /// and the wrong cell pulled.
    #[test]
    fn p_206_element_seven_of_the_second_pack_is_cell_twenty_three() {
        let pack = labels(&Pairs::of(PACK_TWO));
        assert_eq!(pack.base(), 17);
        assert_eq!(
            pack.label_of(at(7)).expect("a legal position"),
            23,
            "ebase 17 + position 7 - 1"
        );
        // Both ends, because an off-by-one lives at exactly one of them: pack 2
        // starts at cell 17 and ends at cell 32, where the string ends.
        assert_eq!(pack.label_of(at(1)).expect("a legal position"), 17);
        assert_eq!(pack.label_of(at(16)).expect("a legal position"), 32);
    }

    /// A position past the end of the series it names has no label at all.
    ///
    /// [`ElementAt`] already refuses a number past [`MAX_SERIES_LEN`], which is
    /// what catches a label written where a position belongs. This is the other
    /// half, and only the row can answer it: a legal position against a series
    /// that is shorter than the position.
    #[test]
    fn a_position_past_the_end_of_a_series_is_refused_rather_than_labelled() {
        let four = labels(&Pairs::of(PACK_TWO).set(N_KEY, 4));
        assert_eq!(four.elements(), 4);
        assert_eq!(
            four.label_of(at(7)),
            Err(InventoryError::PositionPastSeries { at: 7, elements: 4 }),
            "a series of four has no seventh element to name"
        );
        assert_eq!(four.label_of(at(4)).expect("the last one"), 20);
    }

    /// **A series based near the top of `u16` runs out of labels before it runs
    /// out of elements, and the row is refused rather than the label.**
    ///
    /// Wrapping prints cell 0 for the top of the string, which is a number
    /// somebody can find on some other rack. The refusal is at the row and not
    /// at the render because that is where somebody can act on it: a driver that
    /// declares sixteen cells based at `u16::MAX` fails to register the signal,
    /// rather than registering it and being unrenderable from element 2 on.
    #[test]
    fn p_206_a_series_whose_labels_leave_u16_is_refused_rather_than_wrapped() {
        assert_eq!(
            refused(
                RowKind::Signal,
                &Pairs::of(PACK_TWO).set(EBASE_KEY, u64::from(u16::MAX))
            ),
            InventoryError::LabelPastRange {
                base: u16::MAX,
                at: 16
            },
            "sixteen cells cannot start at the last label there is"
        );
        // One below the edge is legal, and its top element is the last label
        // `u16` has. Off-by-one lives here and nowhere else.
        let edge = labels(&Pairs::of(PACK_TWO).set(EBASE_KEY, u64::from(u16::MAX) - 15));
        assert_eq!(edge.label_of(at(16)).expect("the top cell"), u16::MAX);
    }

    /// **A number under a key whose space does not allocate it is refused, and
    /// the six keys that carry one are refused for the right reason.**
    ///
    /// `domain` is what says whether a number is *now* or *yesterday's peak*, so
    /// an unrecognised one either blanks a reading or renders yesterday's
    /// maximum as the present. `shape` decides which of two arrays a reading
    /// travels in, so a third value is a signal whose readings can never be
    /// delivered. Each was a bare `u8` with a list of legal values in a comment
    /// and a check nowhere, and `signal_widest` published `domain 200`,
    /// `dir 255` and `hist 255` as a *width*.
    #[test]
    fn a_number_no_registry_space_allocates_is_refused_at_the_row() {
        for (kind, key, space) in [
            (RowKind::Bus, 2u8, Closed::Transport),
            (RowKind::Signal, SHAPE_KEY, Closed::Shape),
            (RowKind::Signal, VTYPE_KEY, Closed::ValueType),
            (RowKind::Signal, 7, Closed::Domain),
            (RowKind::Signal, 9, Closed::Direction),
            (RowKind::Signal, 17, Closed::Bucket),
            (RowKind::Param, 7, Closed::Domain),
            (RowKind::Param, 9, Closed::Direction),
        ] {
            let mut values = tests::widest(kind);
            let at = kind
                .fields()
                .iter()
                .position(|f| f.key == key)
                .expect("a key this row carries");
            *values.get_mut(at).expect("the slot") = Value::U8(u8::MAX);
            assert_eq!(
                Row::new(kind, values.get(..kind.fields().len()).expect("fits"))
                    .expect_err("255 is nobody's member"),
                InventoryError::NotAMember {
                    kind,
                    key,
                    space,
                    value: u8::MAX
                },
                "{kind} key {key}"
            );
        }
    }

    /// **The map header and the body are one expression, and this is what says
    /// so.**
    ///
    /// They were two: a `filter().count()` over `self.values` and a `continue`
    /// over `fields().zip(self.values)`. The zip stops at the shorter side and
    /// the count did not, so a row carrying more values than its table has
    /// fields promised pairs the body never produced.
    ///
    /// Split again, this test fails at `finish` rather than at the header
    /// assertion, and that is worth knowing: the CBOR writer refuses an
    /// under-filled map, so the divergence was never silent. It was a row that
    /// could not be encoded at all.
    ///
    /// `Row::new` refuses that row, which is why this reaches past it to the
    /// struct directly. The invariant it is holding is not *rows are the right
    /// length* — that has its own test — it is *the encoder cannot be made to
    /// disagree with itself*, and splitting those two expressions again is what
    /// this goes red for.
    #[test]
    fn a_row_longer_than_its_table_cannot_make_the_header_promise_pairs_the_body_owes() {
        let kind = RowKind::Bus;
        let fields = kind.fields().len();
        let mut values = tests::widest(kind).to_vec();
        values.truncate(fields);
        // One more than the table has fields, which `Row::new` would refuse.
        values.push(Value::U8(9));

        let row = Row {
            kind,
            values: &values,
        };
        let mut buffer = [0_u8; MAX_ROW_BYTES];
        let mut cbor = CborWriter::new(&mut buffer);
        row.encode(&mut cbor).expect("the fields all encode");
        let wrote = cbor.finish().expect("a complete map");

        // The header's count is the low five bits of a small CBOR map head, and
        // `finish` refusing an unfinished one is the other half of the check.
        let head = *buffer
            .get(..wrote)
            .and_then(<[u8]>::first)
            .expect("a header");
        assert_eq!(head >> 5, 5, "a CBOR map header");
        assert_eq!(
            usize::from(head & 0x1F),
            fields,
            "the header counted a value the body had no field to write"
        );
    }

    /// **`product`, `dialect` and the two `role`s must NOT be refused**, and this
    /// is the test that says so out loud.
    ///
    /// P-019 gives them a vendor range and skip-unknown: a number this build does
    /// not recognise is a channel shown unnamed, not a row dropped. Blanking a
    /// snapshot because somebody hung a vendor meter next to the frost probe is
    /// the worse failure by a distance, and it is one line of over-eager checking
    /// away.
    ///
    /// It asks the row for the number back rather than only asking it to be
    /// built. *Not refused* is half of *surfaced*: a row that accepts `0xF001`
    /// and hands back something else is the same blanked channel by a longer
    /// route, and construction returning `Ok` cannot tell the two apart.
    #[test]
    fn p_019_a_vendors_own_number_is_not_refused_where_the_registry_stops() {
        for (kind, key) in [
            (RowKind::Device, 4u8), // product
            (RowKind::Device, 5),   // dialect
            (RowKind::Device, 6),   // role
            (RowKind::Component, 4),
        ] {
            let mut values = tests::widest(kind);
            let at = kind
                .fields()
                .iter()
                .position(|f| f.key == key)
                .expect("a key this row carries");
            *values.get_mut(at).expect("the slot") = Value::U16(0xF001);
            let row = Row::new(kind, values.get(..kind.fields().len()).expect("fits"))
                .expect("a vendor's own number is a row this crate carries");
            assert_eq!(
                row.get(key),
                Some(Value::U16(0xF001)),
                "{kind} key {key} took a vendor's number and did not carry it"
            );
        }
    }

    /// **A series longer than `MAX_SERIES_LEN` has elements no `Concern` can
    /// name**, and one shorter than two is a scalar with an array around it.
    ///
    /// `ElementAt` stops at `MAX_SERIES_LEN`, so a 32-element signal can be
    /// registered and published and then a fault on its cell 20 has no position
    /// to travel in — which is exactly why a 32-cell string is two signals. The
    /// range was in the field list and nothing read it: `signal_widest`
    /// published a series of 255 for as long as the row existed.
    #[test]
    fn a_series_no_concern_can_point_into_is_refused_at_the_row() {
        assert_eq!(
            refused(
                RowKind::Signal,
                &Pairs::of(PACK_TWO).set(N_KEY, u64::from(tests::SERIES_LEN) + 1)
            ),
            InventoryError::SeriesTooLong(17)
        );
        assert_eq!(
            refused(RowKind::Signal, &Pairs::of(PACK_TWO).set(N_KEY, 1)),
            InventoryError::SeriesTooShort(1),
            "a series of one is a scalar wearing a series' shape"
        );
        // Both ends of the legal range still build.
        assert_eq!(labels(&Pairs::of(PACK_TWO).set(N_KEY, 2)).elements(), 2);
        assert_eq!(
            labels(&Pairs::of(PACK_TWO).set(N_KEY, u64::from(tests::SERIES_LEN))).elements(),
            16
        );
    }

    /// A scalar has no elements, so there is nothing to label and nothing to
    /// default.
    #[test]
    fn a_scalar_signal_describes_no_series_at_all() {
        let scalar = Pairs::of(PACK_TWO)
            .without(EBASE_KEY)
            .without(N_KEY)
            .set(SHAPE_KEY, 1);
        let mut bytes = [0u8; MAX_ROW_BYTES];
        let len = scalar.bytes(&mut bytes);
        let mut slots = RowSlots::new();
        let row = slots
            .decode(RowKind::Signal, bytes.get(..len).expect("what was written"))
            .expect("a legal scalar row");
        assert_eq!(row.labels(), None);
    }

    /// **The same key twice is refused rather than resolved** (P-015).
    ///
    /// RFC 8949 §5.6 leaves which one wins to the decoder, so two clients render
    /// one row differently — and the row is authenticated, so neither of them
    /// has any reason to doubt what it is showing.
    ///
    /// The bytes are written out by hand because [`CborWriter`] refuses to emit
    /// them: P-016 makes it write strictly ascending keys, and the reader is not
    /// allowed to require that (P-017 — a MAC must not depend on canonical
    /// order). So this row is exactly the shape only the other end can produce.
    #[test]
    fn p_015_a_row_that_carries_one_key_twice_is_refused() {
        let twice: &[u8] = &[
            0xA8, // a map of eight pairs, seven distinct keys
            0x01, 0x18, 0xCC, // 1: 204
            0x01, 0x18, 0xCD, // 1: 205 — the same key, a different signal
            0x02, 0x03, // 2: 3
            0x03, 0x18, 0x39, // 3: 57
            0x04, 0x19, 0x02, 0x01, // 4: 513
            0x05, 0x01, // 5: scalar
            0x06, 0x01, // 6: vtype
            0x07, 0x01, // 7: domain
        ];
        assert_eq!(
            RowSlots::new()
                .decode(RowKind::Signal, twice)
                .expect_err("one key twice is refused"),
            InventoryError::DuplicateRowKey {
                kind: RowKind::Signal,
                key: 1
            }
        );
    }

    /// **A key a newer controller allocated is skipped, not refused** (P-013).
    ///
    /// Refusing would drop a whole topology because one row grew a field, and
    /// the client that dropped it would draw a site with nothing on it.
    #[test]
    fn p_013_a_key_this_version_does_not_allocate_is_skipped() {
        let newer = Pairs::of(PACK_TWO).plus(99, 1_234);
        let mut bytes = [0u8; MAX_ROW_BYTES];
        let len = newer.bytes(&mut bytes);
        let mut slots = RowSlots::new();
        let row = slots
            .decode(RowKind::Signal, bytes.get(..len).expect("what was written"))
            .expect("a row that grew a key is still a row");
        assert_eq!(row.get(1), Some(Value::U16(204)));
        assert_eq!(row.labels().expect("still a series").base(), 17);
    }

    /// **A row that arrives short is refused, not filled in.**
    ///
    /// The reader runs the checks the builder runs, so a required key that never
    /// arrived is the same error in both directions. A receiver that accepts a
    /// short row has to invent the missing field, and every invention this
    /// protocol has made was a default somebody read as a measurement.
    #[test]
    fn p_015_a_row_that_arrives_without_a_required_key_is_refused() {
        assert_eq!(
            refused(RowKind::Signal, &Pairs::of(PACK_TWO).without(7)),
            InventoryError::MissingRequired {
                kind: RowKind::Signal,
                key: 7
            }
        );
    }

    /// **A series with no length cannot arrive either**, which is what sharing
    /// one table buys.
    ///
    /// The condition was written for the builder — P-204's shape, one layer
    /// down — and the reader inherits it, so a row that says *series* and never
    /// says how long is refused on the way in as well as on the way out.
    #[test]
    fn a_series_row_that_never_says_how_long_it_is_is_refused_on_arrival() {
        assert_eq!(
            refused(RowKind::Signal, &Pairs::of(PACK_TWO).without(N_KEY)),
            InventoryError::MissingConditional {
                kind: RowKind::Signal,
                key: N_KEY,
                when: When::ShapeIsASeries
            }
        );
    }
}
