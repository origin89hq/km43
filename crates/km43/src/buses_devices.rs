//! `0x0003 buses and devices`: what is wired to the controller and how to talk
//! to it.
//!
//! One body type serves both directions, and its device id says which:
//! [`BusesAndDevicesWrite`] carries an optional `dev` because a client adds a
//! device by leaving it out, and [`BusesAndDevicesRead`] carries a required one
//! because every device the controller holds has been given one (P-262). The
//! controller turns the first into the second with
//! [`BusesAndDevicesWrite::accept`], which is the only place an id is handed
//! out.
//!
//! Decoding checks what the bytes alone can say. Everything that depends on
//! the board, the dialects the firmware drives and the caps it reports is
//! [`BusesAndDevices::check`], against a [`SiteRules`] the caller builds from
//! its own tables. Either way a refusal is a [`ConfigError`], and
//! [`ConfigError::answer`] says whether it is error 1 or outcome 3.
//!
//! cites: P-101, P-187, P-202, P-261, P-262, P-263, P-264, P-265

use core::fmt;
use core::num::{NonZeroU16, NonZeroU32};

use crate::cbor::{CborReader, CborWriter};
use crate::config::{ConfigError, SectionKey};
use crate::generated::{
    DeviceOption, DeviceRole, Dialect, Direction, Parity, Product, PylontechVersion, Transport,
};
use crate::limits::{MAX_ADDR, MAX_CONFIG_BUSES, MAX_CONFIG_DEVICES};

/// The widest body the limits derivation in `PROTOCOL.md` costs: eight buses
/// and sixteen devices with every key at its widest value.
pub const MAX_BUSES_AND_DEVICES_BYTES: usize = 901;

// The widest write fits a signed operation, and the widest answer fits a sealed
// response, with the header each message puts in front of it.
const_assert!(
    crate::config_messages::CONFIG_HEADER_BYTES + MAX_BUSES_AND_DEVICES_BYTES
        <= crate::limits::MAX_OPERATION
);
const_assert!(
    crate::config_messages::CONFIG_HEADER_BYTES + MAX_BUSES_AND_DEVICES_BYTES
        <= crate::limits::INNER_BODY_BYTES
);

/// A key of the buses and devices body, at any of its four levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BusesAndDevicesKey {
    /// Body key 1, the bus list.
    Buses,
    /// Body key 2, the device list.
    Devices,
    /// `BusEntry` key 1.
    Bus,
    /// `BusEntry` key 2.
    Rate,
    /// `BusEntry` key 3.
    DataBits,
    /// `BusEntry` key 4.
    Parity,
    /// `BusEntry` key 5.
    StopBits,
    /// `DeviceEntry` key 1.
    Dev,
    /// `DeviceEntry` key 2.
    DeviceBus,
    /// `DeviceEntry` key 3.
    Addr,
    /// `DeviceEntry` key 4.
    Product,
    /// `DeviceEntry` key 5.
    Dialect,
    /// `DeviceEntry` key 6.
    Role,
    /// `DeviceEntry` key 7.
    Parent,
    /// `DeviceEntry` key 8.
    Options,
    /// A key of the options map.
    Option(DeviceOption),
}

impl BusesAndDevicesKey {
    pub(crate) const fn number(self) -> i64 {
        match self {
            Self::Buses | Self::Bus | Self::Dev => 1,
            Self::Devices | Self::Rate | Self::DeviceBus => 2,
            Self::DataBits | Self::Addr => 3,
            Self::Parity | Self::Product => 4,
            Self::StopBits | Self::Dialect => 5,
            Self::Role => 6,
            Self::Parent => 7,
            Self::Options => 8,
            Self::Option(option) => option as i64,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Buses => "buses and devices buses",
            Self::Devices => "buses and devices devices",
            Self::Bus => "bus entry bus",
            Self::Rate => "bus entry rate",
            Self::DataBits => "bus entry data_bits",
            Self::Parity => "bus entry parity",
            Self::StopBits => "bus entry stop_bits",
            Self::Dev => "device entry dev",
            Self::DeviceBus => "device entry bus",
            Self::Addr => "device entry addr",
            Self::Product => "device entry product",
            Self::Dialect => "device entry dialect",
            Self::Role => "device entry role",
            Self::Parent => "device entry parent",
            Self::Options => "device entry options",
            Self::Option(DeviceOption::CurrentDirection) => "device option current_direction",
            Self::Option(DeviceOption::PylontechVersion) => "device option pylontech_version",
            Self::Option(DeviceOption::VeDirect3v3) => "device option ve_direct_3v3",
            Self::Option(DeviceOption::PollPeriod) => "device option poll_period",
        }
    }

    const fn key(self) -> SectionKey {
        SectionKey::BusesAndDevices(self)
    }
}

/// What a bus's transport lets a configuration say about it (P-261, P-202).
impl Transport {
    /// Whether a device on it needs an `addr`: the multidrop and network
    /// transports, where two devices share one wire, and 1-Wire, where a
    /// probe's ROM code is the only thing telling it from the next one.
    #[must_use]
    pub const fn addressed(self) -> bool {
        match self {
            Self::Rs485 | Self::Can | Self::Ip | Self::Onewire => true,
            Self::VeDirect | Self::LocalIo | Self::Internal => false,
        }
    }

    /// Whether a `rate` means anything on it.
    #[must_use]
    pub const fn has_rate(self) -> bool {
        match self {
            Self::Rs485 | Self::Can | Self::VeDirect => true,
            Self::LocalIo | Self::Ip | Self::Onewire | Self::Internal => false,
        }
    }

    /// Whether it is a serial line, the only kind with data bits, parity and
    /// stop bits to set.
    #[must_use]
    pub const fn is_serial_line(self) -> bool {
        match self {
            Self::Rs485 | Self::VeDirect => true,
            Self::Can | Self::LocalIo | Self::Ip | Self::Onewire | Self::Internal => false,
        }
    }
}

/// The controller's id for a device. Never 0, which is the controller itself,
/// and never given twice (P-262).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DevId(NonZeroU16);

impl DevId {
    /// Stands in for an id that was refused, in a body that is refused with it.
    const PLACEHOLDER: Self = Self(NonZeroU16::MAX);

    /// Refused at 0.
    pub const fn new(dev: u16) -> Result<Self, ConfigError> {
        match NonZeroU16::new(dev) {
            Some(dev) => Ok(Self(dev)),
            None => Err(ConfigError::OutOfSchema(BusesAndDevicesKey::Dev.key())),
        }
    }

    /// The id as it travels.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Hands out device ids, each once, in ascending order.
///
/// The controller keeps the next id with the section and shares this with
/// run-time adoption, because a sub-device's `dev` comes out of the same space.
/// Once `0xFFFF` has been given there is nothing left, and adding a device is
/// refused rather than wrapped round to an id somebody's history is filed
/// under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DevAllocator(Option<DevId>);

impl DevAllocator {
    /// A controller that has never given an id.
    pub const FIRST: Self = Self(Some(DevId(NonZeroU16::MIN)));

    /// Resume from the next id the controller stored, or `None` once every id
    /// has been given.
    #[must_use]
    pub const fn resume(next: Option<DevId>) -> Self {
        Self(next)
    }

    /// The id the next device will get, to store beside the section.
    #[must_use]
    pub const fn next(self) -> Option<DevId> {
        self.0
    }

    /// Give out the next id.
    pub fn allocate(&mut self) -> Result<DevId, ConfigError> {
        let given = self.0.ok_or(ConfigError::DevsExhausted)?;
        self.0 = given.0.checked_add(1).map(DevId);
        Ok(given)
    }
}

/// Data bits on a serial line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DataBits {
    /// Seven.
    Seven,
    /// Eight.
    Eight,
}

impl DataBits {
    const fn from_wire(bits: u8) -> Option<Self> {
        match bits {
            7 => Some(Self::Seven),
            8 => Some(Self::Eight),
            _ => None,
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::Seven => 7,
            Self::Eight => 8,
        }
    }
}

/// Stop bits on a serial line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StopBits {
    /// One.
    One,
    /// Two.
    Two,
}

impl StopBits {
    const fn from_wire(bits: u8) -> Option<Self> {
        match bits {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            _ => None,
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

/// The settings of one bus the board has (P-261). Every `None` is what the
/// devices' dialects require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BusEntry {
    /// Key 1, `BusRow` key 1 in the inventory.
    pub bus: u8,
    /// Key 2, bit/s.
    pub rate: Option<NonZeroU32>,
    /// Key 3.
    pub data_bits: Option<DataBits>,
    /// Key 4.
    pub parity: Option<Parity>,
    /// Key 5.
    pub stop_bits: Option<StopBits>,
}

impl BusEntry {
    fn pairs(self) -> usize {
        1 + usize::from(self.rate.is_some())
            + usize::from(self.data_bits.is_some())
            + usize::from(self.parity.is_some())
            + usize::from(self.stop_bits.is_some())
    }

    fn encode(self, cbor: &mut CborWriter<'_>) -> Result<(), ConfigError> {
        cbor.map(self.pairs())?;
        cbor.key(BusesAndDevicesKey::Bus.number())?;
        cbor.u64(u64::from(self.bus))?;
        if let Some(rate) = self.rate {
            cbor.key(BusesAndDevicesKey::Rate.number())?;
            cbor.u64(u64::from(rate.get()))?;
        }
        if let Some(bits) = self.data_bits {
            cbor.key(BusesAndDevicesKey::DataBits.number())?;
            cbor.u64(u64::from(bits.wire()))?;
        }
        if let Some(parity) = self.parity {
            cbor.key(BusesAndDevicesKey::Parity.number())?;
            cbor.u64(u64::from(parity as u8))?;
        }
        if let Some(bits) = self.stop_bits {
            cbor.key(BusesAndDevicesKey::StopBits.number())?;
            cbor.u64(u64::from(bits.wire()))?;
        }
        Ok(())
    }

    fn decode(cbor: &mut CborReader<'_>, invalid: &mut Invalid) -> Result<Self, ConfigError> {
        let pairs = cbor.map()?;
        let mut bus = None;
        let mut rate = None;
        let mut data_bits = None;
        let mut parity = None;
        let mut stop_bits = None;
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(&mut bus, BusesAndDevicesKey::Bus, cbor.u8()?)?,
                2 => once(&mut rate, BusesAndDevicesKey::Rate, cbor.u32()?)?,
                3 => once(&mut data_bits, BusesAndDevicesKey::DataBits, cbor.u8()?)?,
                4 => {
                    let value = Parity::try_from(cbor.u8()?).map_err(|()| {
                        ConfigError::UnknownValue(BusesAndDevicesKey::Parity.key())
                    })?;
                    once(&mut parity, BusesAndDevicesKey::Parity, value)?;
                }
                5 => once(&mut stop_bits, BusesAndDevicesKey::StopBits, cbor.u8()?)?,
                _ => cbor.skip()?,
            }
        }
        let bus = bus.ok_or(ConfigError::Missing(BusesAndDevicesKey::Bus.key()))?;
        if rate.is_none() && data_bits.is_none() && parity.is_none() && stop_bits.is_none() {
            return Err(ConfigError::NothingSet(BusesAndDevicesKey::Bus.key()));
        }
        Ok(Self {
            bus,
            rate: rate
                .and_then(|rate| invalid.unless(NonZeroU32::new(rate), BusesAndDevicesKey::Rate)),
            data_bits: data_bits.and_then(|bits| {
                invalid.unless(DataBits::from_wire(bits), BusesAndDevicesKey::DataBits)
            }),
            parity,
            stop_bits: stop_bits.and_then(|bits| {
                invalid.unless(StopBits::from_wire(bits), BusesAndDevicesKey::StopBits)
            }),
        })
    }

    /// P-261 against the bus's transport.
    fn check(self, transport: Transport) -> Result<(), ConfigError> {
        if self.rate.is_none()
            && self.data_bits.is_none()
            && self.parity.is_none()
            && self.stop_bits.is_none()
        {
            return Err(ConfigError::NothingSet(BusesAndDevicesKey::Bus.key()));
        }
        let refuse = |key: BusesAndDevicesKey| ConfigError::NotOnTransport {
            bus: self.bus,
            key: key.key(),
        };
        if self.rate.is_some() && !transport.has_rate() {
            return Err(refuse(BusesAndDevicesKey::Rate));
        }
        if !transport.is_serial_line() {
            if self.data_bits.is_some() {
                return Err(refuse(BusesAndDevicesKey::DataBits));
            }
            if self.parity.is_some() {
                return Err(refuse(BusesAndDevicesKey::Parity));
            }
            if self.stop_bits.is_some() {
                return Err(refuse(BusesAndDevicesKey::StopBits));
            }
        }
        Ok(())
    }
}

/// A bus address, 1 to [`MAX_ADDR`] bytes, as the bus defines one (P-202).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Addr<'a>(&'a [u8]);

impl<'a> Addr<'a> {
    /// Refused empty or longer than [`MAX_ADDR`].
    pub const fn new(bytes: &'a [u8]) -> Result<Self, ConfigError> {
        if bytes.is_empty() || bytes.len() > MAX_ADDR {
            return Err(ConfigError::Length {
                key: BusesAndDevicesKey::Addr.key(),
                len: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// The address as it travels.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

/// Which way the battery current a device reports counts positive. The
/// registry's third sign, magnitude only, is not a direction and is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CurrentDirection {
    /// Positive is into the battery, charging.
    PositiveIsIn,
    /// Positive is out of the battery.
    PositiveIsOut,
}

impl CurrentDirection {
    const fn direction(self) -> Direction {
        match self {
            Self::PositiveIsIn => Direction::PositiveIsIn,
            Self::PositiveIsOut => Direction::PositiveIsOut,
        }
    }
}

/// One device's options (P-264). Every `None` is an option nobody set, which a
/// driver never fills in with a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceOptions {
    /// Option 1.
    pub current_direction: Option<CurrentDirection>,
    /// Option 2.
    pub pylontech_version: Option<PylontechVersion>,
    /// Option 3: the product's VE.Direct port runs at 3.3 V.
    pub ve_direct_3v3: Option<bool>,
    /// Option 4, milliseconds between polls.
    pub poll_period_ms: Option<u32>,
}

impl DeviceOptions {
    /// No option set; the entry carries no key 8.
    pub const NONE: Self = Self {
        current_direction: None,
        pylontech_version: None,
        ve_direct_3v3: None,
        poll_period_ms: None,
    };

    /// The options this carries, so a dialect can be asked about each.
    fn set(&self) -> [Option<DeviceOption>; 4] {
        [
            self.current_direction
                .map(|_| DeviceOption::CurrentDirection),
            self.pylontech_version
                .map(|_| DeviceOption::PylontechVersion),
            self.ve_direct_3v3.map(|_| DeviceOption::VeDirect3v3),
            self.poll_period_ms.map(|_| DeviceOption::PollPeriod),
        ]
    }

    fn pairs(&self) -> usize {
        self.set().iter().flatten().count()
    }

    fn encode(&self, cbor: &mut CborWriter<'_>) -> Result<(), ConfigError> {
        cbor.map(self.pairs())?;
        if let Some(direction) = self.current_direction {
            cbor.key(DeviceOption::CurrentDirection as i64)?;
            cbor.u64(u64::from(direction.direction() as u8))?;
        }
        if let Some(version) = self.pylontech_version {
            cbor.key(DeviceOption::PylontechVersion as i64)?;
            cbor.u64(u64::from(version as u8))?;
        }
        if let Some(low) = self.ve_direct_3v3 {
            cbor.key(DeviceOption::VeDirect3v3 as i64)?;
            cbor.bool(low)?;
        }
        if let Some(period) = self.poll_period_ms {
            cbor.key(DeviceOption::PollPeriod as i64)?;
            cbor.u64(u64::from(period))?;
        }
        Ok(())
    }

    /// An option key nobody allocated is not skipped: skipping it is a setting
    /// the client sent and the controller never used (P-264).
    fn decode(cbor: &mut CborReader<'_>, invalid: &mut Invalid) -> Result<Self, ConfigError> {
        let pairs = cbor.map()?;
        if pairs == 0 {
            return Err(ConfigError::NothingSet(BusesAndDevicesKey::Options.key()));
        }
        let mut options = Self::NONE;
        let mut direction = None;
        for _ in 0..pairs {
            let number = cbor.key()?;
            let Some(option) = u16::try_from(number)
                .ok()
                .and_then(|n| DeviceOption::try_from(n).ok())
            else {
                invalid.note(ConfigError::UnknownOption(number));
                cbor.skip()?;
                continue;
            };
            let key = BusesAndDevicesKey::Option(option);
            match option {
                DeviceOption::CurrentDirection => {
                    let value = Direction::try_from(cbor.u8()?)
                        .map_err(|()| ConfigError::UnknownValue(key.key()))?;
                    once(&mut direction, key, value)?;
                }
                DeviceOption::PylontechVersion => {
                    let value = PylontechVersion::try_from(cbor.u8()?)
                        .map_err(|()| ConfigError::UnknownValue(key.key()))?;
                    once(&mut options.pylontech_version, key, value)?;
                }
                DeviceOption::VeDirect3v3 => once(&mut options.ve_direct_3v3, key, cbor.bool()?)?,
                DeviceOption::PollPeriod => once(&mut options.poll_period_ms, key, cbor.u32()?)?,
            }
        }
        options.current_direction = direction.and_then(|direction| match direction {
            Direction::PositiveIsIn => Some(CurrentDirection::PositiveIsIn),
            Direction::PositiveIsOut => Some(CurrentDirection::PositiveIsOut),
            Direction::MagnitudeOnly => {
                invalid.note(ConfigError::OutOfSchema(
                    BusesAndDevicesKey::Option(DeviceOption::CurrentDirection).key(),
                ));
                None
            }
        });
        Ok(options)
    }

    /// P-264 against the device's dialect.
    fn check(&self, rule: &DialectRule<'_>) -> Result<(), ConfigError> {
        for option in self.set().into_iter().flatten() {
            if !rule.options.contains(&option) {
                return Err(ConfigError::OptionNotInDialect {
                    option,
                    dialect: rule.dialect.0,
                });
            }
        }
        match self.poll_period_ms {
            Some(period) if period < rule.min_poll_ms => Err(ConfigError::PollTooShort {
                dialect: rule.dialect.0,
                min: rule.min_poll_ms,
            }),
            Some(_) | None => Ok(()),
        }
    }
}

/// Which id a device entry carries: optional in a write, required in an answer.
/// Sealed, because those are the only two shapes the section has.
pub trait DevSlot: Copy + sealed::Sealed {
    /// Whether this is the controller's answer, whose entries ascend (P-262).
    const ANSWER: bool;

    /// The id, when there is one.
    fn dev(self) -> Option<DevId>;

    #[doc(hidden)]
    fn from_decoded(dev: Option<DevId>) -> Result<Self, ConfigError>;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for Option<super::DevId> {}
    impl Sealed for super::DevId {}
}

impl DevSlot for Option<DevId> {
    const ANSWER: bool = false;

    fn dev(self) -> Option<DevId> {
        self
    }

    fn from_decoded(dev: Option<DevId>) -> Result<Self, ConfigError> {
        Ok(dev)
    }
}

impl DevSlot for DevId {
    const ANSWER: bool = true;

    fn dev(self) -> Option<DevId> {
        Some(self)
    }

    fn from_decoded(dev: Option<DevId>) -> Result<Self, ConfigError> {
        dev.ok_or(ConfigError::Missing(BusesAndDevicesKey::Dev.key()))
    }
}

/// One configured device. `D` is `Option<DevId>` in a write and `DevId` in the
/// controller's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceEntry<'a, D> {
    /// Key 1 (P-262).
    pub dev: D,
    /// Key 2.
    pub bus: u8,
    /// Key 3, present exactly on an addressed transport (P-202).
    pub addr: Option<Addr<'a>>,
    /// Key 4.
    pub product: Product,
    /// Key 5.
    pub dialect: Dialect,
    /// Key 6.
    pub role: DeviceRole,
    /// Key 7, another entry's `dev`.
    pub parent: Option<DevId>,
    /// Key 8; [`DeviceOptions::NONE`] leaves the key out.
    pub options: DeviceOptions,
}

impl<'a, D: DevSlot> DeviceEntry<'a, D> {
    fn pairs(&self) -> usize {
        4 + usize::from(self.dev.dev().is_some())
            + usize::from(self.addr.is_some())
            + usize::from(self.parent.is_some())
            + usize::from(self.options != DeviceOptions::NONE)
    }

    fn encode(&self, cbor: &mut CborWriter<'_>) -> Result<(), ConfigError> {
        cbor.map(self.pairs())?;
        if let Some(dev) = self.dev.dev() {
            cbor.key(BusesAndDevicesKey::Dev.number())?;
            cbor.u64(u64::from(dev.get()))?;
        }
        cbor.key(BusesAndDevicesKey::DeviceBus.number())?;
        cbor.u64(u64::from(self.bus))?;
        if let Some(addr) = self.addr {
            cbor.key(BusesAndDevicesKey::Addr.number())?;
            cbor.bytes(addr.as_bytes())?;
        }
        cbor.key(BusesAndDevicesKey::Product.number())?;
        cbor.u64(u64::from(self.product.0))?;
        cbor.key(BusesAndDevicesKey::Dialect.number())?;
        cbor.u64(u64::from(self.dialect.0))?;
        cbor.key(BusesAndDevicesKey::Role.number())?;
        cbor.u64(u64::from(self.role.0))?;
        if let Some(parent) = self.parent {
            cbor.key(BusesAndDevicesKey::Parent.number())?;
            cbor.u64(u64::from(parent.get()))?;
        }
        if self.options != DeviceOptions::NONE {
            cbor.key(BusesAndDevicesKey::Options.number())?;
            self.options.encode(cbor)?;
        }
        Ok(())
    }

    fn decode(cbor: &mut CborReader<'a>, invalid: &mut Invalid) -> Result<Self, ConfigError> {
        let pairs = cbor.map()?;
        let mut dev = None;
        let mut bus = None;
        let mut addr = None;
        let mut product = None;
        let mut dialect = None;
        let mut role = None;
        let mut parent = None;
        let mut options = None;
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(&mut dev, BusesAndDevicesKey::Dev, cbor.u16()?)?,
                2 => once(&mut bus, BusesAndDevicesKey::DeviceBus, cbor.u8()?)?,
                3 => once(&mut addr, BusesAndDevicesKey::Addr, cbor.bytes()?)?,
                4 => once(&mut product, BusesAndDevicesKey::Product, cbor.u16()?)?,
                5 => once(&mut dialect, BusesAndDevicesKey::Dialect, cbor.u16()?)?,
                6 => once(&mut role, BusesAndDevicesKey::Role, cbor.u16()?)?,
                7 => once(&mut parent, BusesAndDevicesKey::Parent, cbor.u16()?)?,
                8 => {
                    let read = DeviceOptions::decode(cbor, invalid)?;
                    once(&mut options, BusesAndDevicesKey::Options, read)?;
                }
                _ => cbor.skip()?,
            }
        }
        let required = |slot: Option<u16>, key: BusesAndDevicesKey| {
            slot.ok_or(ConfigError::Missing(key.key()))
        };
        let product = Product(required(product, BusesAndDevicesKey::Product)?);
        let dialect = Dialect(required(dialect, BusesAndDevicesKey::Dialect)?);
        let role = DeviceRole(required(role, BusesAndDevicesKey::Role)?);
        let bus = bus.ok_or(ConfigError::Missing(BusesAndDevicesKey::DeviceBus.key()))?;
        // A `dev` of 0 is held as a stand-in and the body refused invalid,
        // rather than read as an entry that adds a device.
        let dev = match dev {
            None => D::from_decoded(None)?,
            Some(raw) => {
                let dev = invalid.unless_ok(DevId::new(raw));
                D::from_decoded(Some(dev.unwrap_or(DevId::PLACEHOLDER)))?
            }
        };
        Ok(Self {
            dev,
            bus,
            addr: addr.and_then(|bytes| invalid.unless_ok(Addr::new(bytes))),
            product,
            dialect,
            role,
            parent: parent.and_then(|parent| {
                invalid.unless_ok(
                    DevId::new(parent)
                        .map_err(|_| ConfigError::OutOfSchema(BusesAndDevicesKey::Parent.key())),
                )
            }),
            options: options.unwrap_or(DeviceOptions::NONE),
        })
    }
}

/// A bus the board has, as its inventory lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BoardBus {
    /// `BusRow` key 1.
    pub bus: u8,
    /// `BusRow` key 2.
    pub transport: Transport,
}

/// What the controller's driver for one dialect accepts: the transports it runs
/// over, the options it reads, and how often it may poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DialectRule<'r> {
    /// The dialect.
    pub dialect: Dialect,
    /// The transports it can be carried over.
    pub transports: &'r [Transport],
    /// The option keys it defines; any other is refused (P-264).
    pub options: &'r [DeviceOption],
    /// The shortest `poll_period` it accepts, in milliseconds.
    pub min_poll_ms: u32,
}

/// Everything a body is checked against that the body does not carry: the
/// board's buses, the dialect table, and the caps `Hello 0x81` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SiteRules<'r> {
    /// The buses the inventory lists, bus 0 included.
    pub buses: &'r [BoardBus],
    /// One rule per dialect the controller drives. A dialect with no rule is
    /// one it cannot drive at all.
    pub dialects: &'r [DialectRule<'r>],
    /// `max_devices`, `HelloReport` key 21.
    pub max_devices: usize,
    /// `max_topology_depth`, `HelloReport` key 29: how many devices one parent
    /// chain may hold, the device at its end included.
    pub max_topology_depth: usize,
}

impl SiteRules<'_> {
    fn transport(&self, bus: u8) -> Option<Transport> {
        self.buses
            .iter()
            .find(|board| board.bus == bus)
            .map(|board| board.transport)
    }

    /// The rule for a dialect over a transport. A table may give one dialect
    /// a row per transport, each with its own options.
    fn dialect(&self, dialect: Dialect, transport: Transport) -> Option<&DialectRule<'_>> {
        self.dialects
            .iter()
            .find(|rule| rule.dialect == dialect && rule.transports.contains(&transport))
    }
}

/// `0x0003 buses and devices`. `D` says which direction it travels in; use
/// [`BusesAndDevicesWrite`] or [`BusesAndDevicesRead`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BusesAndDevices<'a, D> {
    buses: [Option<BusEntry>; MAX_CONFIG_BUSES],
    devices: [Option<DeviceEntry<'a, D>>; MAX_CONFIG_DEVICES],
}

/// The section as `SetConfig` writes it: a device with no `dev` is one to add.
pub type BusesAndDevicesWrite<'a> = BusesAndDevices<'a, Option<DevId>>;

/// The section as `Config` answers with it: every device has its `dev`.
///
/// A device with no id cannot be put in one, so an answer that lists a device
/// the controller never gave an id to does not compile:
///
/// ```compile_fail
/// use km43::{BusesAndDevicesRead, DeviceEntry, DeviceOptions, DeviceRole, Dialect, Product};
/// let mut answer = BusesAndDevicesRead::EMPTY;
/// let _ = answer.push_device(DeviceEntry {
///     dev: None,
///     bus: 1,
///     addr: None,
///     product: Product::PZEM_017,
///     dialect: Dialect::PZEM_DC,
///     role: DeviceRole::ENERGY_METER,
///     parent: None,
///     options: DeviceOptions::NONE,
/// });
/// ```
/// ```
/// use km43::{BusesAndDevicesRead, DevId, DeviceEntry, DeviceOptions, DeviceRole, Dialect, Product};
/// let mut answer = BusesAndDevicesRead::EMPTY;
/// let dev = DevId::new(1).expect("a nonzero id");
/// let pushed = answer.push_device(DeviceEntry {
///     dev,
///     bus: 1,
///     addr: None,
///     product: Product::PZEM_017,
///     dialect: Dialect::PZEM_DC,
///     role: DeviceRole::ENERGY_METER,
///     parent: None,
///     options: DeviceOptions::NONE,
/// });
/// assert!(pushed.is_ok());
/// ```
pub type BusesAndDevicesRead<'a> = BusesAndDevices<'a, DevId>;

/// A write the controller accepted: what it now holds, and the allocator to
/// store beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Accepted<'a> {
    /// The section to store and to answer `GetConfig` with.
    pub section: BusesAndDevicesRead<'a>,
    /// The allocator after the added devices took their ids.
    pub allocator: DevAllocator,
}

impl<D: DevSlot> Default for BusesAndDevices<'_, D> {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl<'a, D: DevSlot> BusesAndDevices<'a, D> {
    /// Nothing configured: both lists present and empty.
    pub const EMPTY: Self = Self {
        buses: [None; MAX_CONFIG_BUSES],
        devices: [None; MAX_CONFIG_DEVICES],
    };

    /// Add a bus entry, refused once [`MAX_CONFIG_BUSES`] are held.
    pub fn push_bus(&mut self, entry: BusEntry) -> Result<(), ConfigError> {
        let slot = self
            .buses
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ConfigError::TooMany(BusesAndDevicesKey::Buses.key()))?;
        *slot = Some(entry);
        Ok(())
    }

    /// Add a device entry, refused once [`MAX_CONFIG_DEVICES`] are held.
    pub fn push_device(&mut self, entry: DeviceEntry<'a, D>) -> Result<(), ConfigError> {
        let slot = self
            .devices
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ConfigError::TooMany(BusesAndDevicesKey::Devices.key()))?;
        *slot = Some(entry);
        Ok(())
    }

    /// The bus entries, in the order they travel.
    pub fn buses(&self) -> impl Iterator<Item = &BusEntry> {
        self.buses.iter().flatten()
    }

    /// The device entries, in the order they travel.
    pub fn devices(&self) -> impl Iterator<Item = &DeviceEntry<'a, D>> {
        self.devices.iter().flatten()
    }

    /// Encode the body. An answer whose entries do not ascend is refused rather
    /// than sent to a client that would refuse it (P-262).
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ConfigError> {
        self.ascending()?;
        let mut cbor = CborWriter::new(dst);
        cbor.map(2)?;
        cbor.key(BusesAndDevicesKey::Buses.number())?;
        cbor.array(self.buses().count())?;
        for bus in self.buses() {
            bus.encode(&mut cbor)?;
        }
        cbor.key(BusesAndDevicesKey::Devices.number())?;
        cbor.array(self.devices().count())?;
        for device in self.devices() {
            device.encode(&mut cbor)?;
        }
        Ok(cbor.finish()?)
    }

    /// Read a body, its whole structure before any value is judged: a body
    /// that is both malformed and out of schema is error 1 (P-101).
    ///
    /// Entries past [`MAX_CONFIG_BUSES`] or [`MAX_CONFIG_DEVICES`] are read to
    /// the end and then refused as invalid, never dropped (P-265).
    pub fn decode(body: &'a [u8]) -> Result<Self, ConfigError> {
        let mut invalid = Invalid::default();
        let mut section = Self::EMPTY;
        let mut cbor = CborReader::new(body);
        let pairs = cbor.map()?;
        let mut buses = None;
        let mut devices = None;
        for _ in 0..pairs {
            match cbor.key()? {
                1 => {
                    once(&mut buses, BusesAndDevicesKey::Buses, ())?;
                    for _ in 0..cbor.array()? {
                        let entry = BusEntry::decode(&mut cbor, &mut invalid)?;
                        if section.push_bus(entry).is_err() {
                            invalid.note(ConfigError::TooMany(BusesAndDevicesKey::Buses.key()));
                        }
                    }
                }
                2 => {
                    once(&mut devices, BusesAndDevicesKey::Devices, ())?;
                    for _ in 0..cbor.array()? {
                        let entry = DeviceEntry::decode(&mut cbor, &mut invalid)?;
                        if section.push_device(entry).is_err() {
                            invalid.note(ConfigError::TooMany(BusesAndDevicesKey::Devices.key()));
                        }
                    }
                }
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        buses.ok_or(ConfigError::Missing(BusesAndDevicesKey::Buses.key()))?;
        devices.ok_or(ConfigError::Missing(BusesAndDevicesKey::Devices.key()))?;
        invalid.result()?;
        section.ascending()?;
        Ok(section)
    }

    /// An answer lists buses by `bus` and devices by `dev`, each strictly
    /// ascending (P-262). A write is in whatever order the client chose.
    fn ascending(&self) -> Result<(), ConfigError> {
        if !D::ANSWER {
            return Ok(());
        }
        let buses = self.buses().zip(self.buses().skip(1));
        if buses.into_iter().any(|(a, b)| a.bus >= b.bus) {
            return Err(ConfigError::OutOfOrder(BusesAndDevicesKey::Bus.key()));
        }
        let devices = self.devices().zip(self.devices().skip(1));
        if devices.into_iter().any(|(a, b)| a.dev.dev() >= b.dev.dev()) {
            return Err(ConfigError::OutOfOrder(BusesAndDevicesKey::Dev.key()));
        }
        Ok(())
    }

    /// Check the body against what it does not carry: the board's buses, the
    /// dialect table and the reported caps (P-261, P-264, P-265).
    pub fn check(&self, rules: &SiteRules<'_>) -> Result<(), ConfigError> {
        self.check_buses(rules)?;
        let count = self.devices().count();
        if count > rules.max_devices || count > MAX_CONFIG_DEVICES {
            return Err(ConfigError::TooMany(BusesAndDevicesKey::Devices.key()));
        }
        for (index, device) in self.devices().enumerate() {
            let transport = rules
                .transport(device.bus)
                .ok_or(ConfigError::UnknownBus(device.bus))?;
            self.check_addr(index, device, transport)?;
            let rule =
                rules
                    .dialect(device.dialect, transport)
                    .ok_or(ConfigError::DialectNotCarried {
                        dialect: device.dialect.0,
                        bus: device.bus,
                    })?;
            device.options.check(rule)?;
            if let Some(dev) = device.dev.dev()
                && self
                    .devices()
                    .skip(index + 1)
                    .any(|other| other.dev.dev() == Some(dev))
            {
                return Err(ConfigError::DevTwice(dev.get()));
            }
        }
        for device in self.devices() {
            self.check_chain(device, rules.max_topology_depth)?;
        }
        Ok(())
    }

    fn check_buses(&self, rules: &SiteRules<'_>) -> Result<(), ConfigError> {
        for (index, entry) in self.buses().enumerate() {
            let transport = rules
                .transport(entry.bus)
                .ok_or(ConfigError::UnknownBus(entry.bus))?;
            if self
                .buses()
                .skip(index + 1)
                .any(|other| other.bus == entry.bus)
            {
                return Err(ConfigError::BusTwice(entry.bus));
            }
            entry.check(transport)?;
        }
        Ok(())
    }

    /// P-202: an address exactly where the transport addresses, and never the
    /// same one twice on a bus.
    fn check_addr(
        &self,
        index: usize,
        device: &DeviceEntry<'a, D>,
        transport: Transport,
    ) -> Result<(), ConfigError> {
        match (device.addr, transport.addressed()) {
            (None, true) => Err(ConfigError::AddrRequired(device.bus)),
            (Some(_), false) => Err(ConfigError::AddrNotAddressed(device.bus)),
            (None, false) => Ok(()),
            (Some(addr), true) => {
                let repeated = self.devices().skip(index + 1).any(|other| {
                    other.bus == device.bus && other.addr.map(Addr::as_bytes) == Some(addr.0)
                });
                if repeated {
                    Err(ConfigError::AddrTwice(device.bus))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// The parent chain above one device: every link names a listed `dev`, it
    /// never comes back round, and it holds no more devices than the reported
    /// depth (P-187, P-265).
    fn check_chain(&self, device: &DeviceEntry<'a, D>, depth: usize) -> Result<(), ConfigError> {
        let start = device.dev.dev();
        // Every dev the walk has passed, so a loop is named where it closes
        // even when the device being checked only hangs off it.
        let mut seen: [Option<DevId>; MAX_CONFIG_DEVICES] = [None; MAX_CONFIG_DEVICES];
        let mut held = 1_usize;
        let mut next = device.parent;
        for count in 0..MAX_CONFIG_DEVICES {
            let Some(parent) = next else {
                return if held > depth {
                    Err(ConfigError::TooDeep(start.map_or(0, DevId::get)))
                } else {
                    Ok(())
                };
            };
            let passed = seen
                .get(..count)
                .is_some_and(|passed| passed.contains(&Some(parent)));
            if start == Some(parent) || passed {
                return Err(ConfigError::ParentLoop(parent.get()));
            }
            if let Some(slot) = seen.get_mut(count) {
                *slot = Some(parent);
            }
            let above = self
                .devices()
                .find(|other| other.dev.dev() == Some(parent))
                .ok_or(ConfigError::ParentNotListed(parent.get()))?;
            held = held.saturating_add(1);
            next = above.parent;
        }
        // Sixteen distinct parents and still going: a seventeenth would have
        // to repeat one, so the chain has come round.
        Err(ConfigError::ParentLoop(start.map_or(0, DevId::get)))
    }
}

impl<'a> BusesAndDevicesWrite<'a> {
    /// Accept a write against what the section holds: check it, refuse an
    /// edit of a device the section does not hold or one that changes its
    /// product or dialect, and give each added device the next id, in the order
    /// the entries arrived (P-262).
    ///
    /// Nothing is handed out unless the whole write is accepted, so a refused
    /// write never spends an id.
    pub fn accept(
        &self,
        rules: &SiteRules<'_>,
        held: &BusesAndDevicesRead<'_>,
        allocator: DevAllocator,
    ) -> Result<Accepted<'a>, ConfigError> {
        self.check(rules)?;
        // Ids go out ascending, so a next id at or below any id the section
        // holds was given before: the allocator was resumed from a stale
        // record. Checked before the write is read, because a write that only
        // removes the highest dev would erase the evidence. Refusing is the
        // only answer that files no history under the wrong device.
        if let Some(next) = allocator.next()
            && held.devices().any(|was| was.dev >= next)
        {
            return Err(ConfigError::AllocatorBehind(next.get()));
        }
        let mut allocator = allocator;
        let mut section = BusesAndDevicesRead::EMPTY;
        for entry in self.buses() {
            section.push_bus(*entry)?;
        }
        for device in self.devices() {
            let dev = if let Some(dev) = device.dev {
                let was = held
                    .devices()
                    .find(|was| was.dev == dev)
                    .ok_or(ConfigError::UnknownDev(dev.get()))?;
                if was.product != device.product || was.dialect != device.dialect {
                    return Err(ConfigError::DeviceChanged(dev.get()));
                }
                dev
            } else {
                allocator.allocate()?
            };
            section.push_device(DeviceEntry {
                dev,
                bus: device.bus,
                addr: device.addr,
                product: device.product,
                dialect: device.dialect,
                role: device.role,
                parent: device.parent,
                options: device.options,
            })?;
        }
        section.sort();
        Ok(Accepted { section, allocator })
    }
}

impl BusesAndDevicesRead<'_> {
    /// Put buses in `bus` order and devices in `dev` order, so the answer
    /// ascends however the write was ordered (P-262). Only the filled slots
    /// are sorted: the empty ones stay at the end, where `push_*` looks.
    fn sort(&mut self) {
        let buses = self.buses().count();
        if let Some(filled) = self.buses.get_mut(..buses) {
            filled.sort_unstable_by_key(|slot| slot.map(|entry| entry.bus));
        }
        let devices = self.devices().count();
        if let Some(filled) = self.devices.get_mut(..devices) {
            filled.sort_unstable_by_key(|slot| slot.map(|device| device.dev));
        }
    }
}

/// The first value-level refusal met while the structure is still being read.
/// Held back so that a malformed body is still answered error 1 (P-101).
#[derive(Default)]
struct Invalid(Option<ConfigError>);

impl Invalid {
    fn note(&mut self, why: ConfigError) {
        if self.0.is_none() {
            self.0 = Some(why);
        }
    }

    fn unless<T>(&mut self, value: Option<T>, key: BusesAndDevicesKey) -> Option<T> {
        if value.is_none() {
            self.note(ConfigError::OutOfSchema(key.key()));
        }
        value
    }

    fn unless_ok<T>(&mut self, value: Result<T, ConfigError>) -> Option<T> {
        match value {
            Ok(value) => Some(value),
            Err(why) => {
                self.note(why);
                None
            }
        }
    }

    fn result(self) -> Result<(), ConfigError> {
        self.0.map_or(Ok(()), Err)
    }
}

fn once<T>(slot: &mut Option<T>, key: BusesAndDevicesKey, value: T) -> Result<(), ConfigError> {
    if slot.is_some() {
        return Err(ConfigError::Duplicate(key.key()));
    }
    *slot = Some(value);
    Ok(())
}

impl fmt::Display for BusesAndDevicesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (key {})", self.name(), self.number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SectionRefusal;
    use crate::generated::ErrorCode;
    use crate::generated::SetConfig;
    use crate::limits::{MAX_DEVICES, MAX_TOPOLOGY_DEPTH};
    use crate::render::Rendering;

    /// Eight address bytes for each of sixteen devices, the widest an `addr`
    /// can be.
    const WIDE_ADDRS: [[u8; MAX_ADDR]; 16] = [
        [0; MAX_ADDR],
        [1; MAX_ADDR],
        [2; MAX_ADDR],
        [3; MAX_ADDR],
        [4; MAX_ADDR],
        [5; MAX_ADDR],
        [6; MAX_ADDR],
        [7; MAX_ADDR],
        [8; MAX_ADDR],
        [9; MAX_ADDR],
        [10; MAX_ADDR],
        [11; MAX_ADDR],
        [12; MAX_ADDR],
        [13; MAX_ADDR],
        [14; MAX_ADDR],
        [15; MAX_ADDR],
    ];

    /// One-byte addresses, one more than a body may list devices.
    const ONE_BYTE: [[u8; 1]; MAX_CONFIG_DEVICES + 1] = [
        [1],
        [2],
        [3],
        [4],
        [5],
        [6],
        [7],
        [8],
        [9],
        [10],
        [11],
        [12],
        [13],
        [14],
        [15],
        [16],
        [17],
    ];

    /// Pylontech CAN has no dialect number yet. A vendor-range dialect stands
    /// in for it, which is also the proof that an option can be bound to a
    /// dialect the registry has not allocated without the wire changing.
    const PYLONTECH_STAND_IN: Dialect = Dialect(0xF0A0);

    const BOARD: &[BoardBus] = &[
        BoardBus {
            bus: 0,
            transport: Transport::LocalIo,
        },
        BoardBus {
            bus: 1,
            transport: Transport::Rs485,
        },
        BoardBus {
            bus: 2,
            transport: Transport::Can,
        },
        BoardBus {
            bus: 3,
            transport: Transport::VeDirect,
        },
        BoardBus {
            bus: 4,
            transport: Transport::Ip,
        },
    ];

    const DIALECTS: &[DialectRule<'static>] = &[
        DialectRule {
            dialect: Dialect::PZEM_DC,
            transports: &[Transport::Rs485],
            options: &[DeviceOption::PollPeriod],
            min_poll_ms: 500,
        },
        DialectRule {
            dialect: Dialect::EPEVER_B,
            transports: &[Transport::Rs485],
            options: &[DeviceOption::CurrentDirection, DeviceOption::PollPeriod],
            min_poll_ms: 1000,
        },
        DialectRule {
            dialect: Dialect::VICTRON_MPPT_RS_HEX,
            transports: &[Transport::VeDirect],
            options: &[DeviceOption::VeDirect3v3, DeviceOption::CurrentDirection],
            min_poll_ms: 1000,
        },
        DialectRule {
            dialect: Dialect::EG4_LIFEPOWER4_SERIAL,
            transports: &[Transport::Rs485],
            options: &[DeviceOption::CurrentDirection],
            min_poll_ms: 1000,
        },
        DialectRule {
            dialect: PYLONTECH_STAND_IN,
            transports: &[Transport::Can],
            options: &[
                DeviceOption::CurrentDirection,
                DeviceOption::PylontechVersion,
                DeviceOption::PollPeriod,
            ],
            min_poll_ms: 1000,
        },
    ];

    const fn rules() -> SiteRules<'static> {
        SiteRules {
            buses: BOARD,
            dialects: DIALECTS,
            max_devices: MAX_DEVICES,
            max_topology_depth: MAX_TOPOLOGY_DEPTH,
        }
    }

    fn dev(n: u16) -> DevId {
        DevId::new(n).expect("a nonzero id")
    }

    fn addr(bytes: &[u8]) -> Addr<'_> {
        Addr::new(bytes).expect("an address")
    }

    fn serial_bus() -> BusEntry {
        BusEntry {
            bus: 1,
            rate: NonZeroU32::new(9600),
            data_bits: Some(DataBits::Eight),
            parity: Some(Parity::None),
            stop_bits: Some(StopBits::Two),
        }
    }

    fn meter<D>(dev: D, at: &[u8]) -> DeviceEntry<'_, D> {
        DeviceEntry {
            dev,
            bus: 1,
            addr: Some(addr(at)),
            product: Product::PZEM_017,
            dialect: Dialect::PZEM_DC,
            role: DeviceRole::ENERGY_METER,
            parent: None,
            options: DeviceOptions {
                poll_period_ms: Some(1000),
                ..DeviceOptions::NONE
            },
        }
    }

    fn charger<D>(dev: D) -> DeviceEntry<'static, D> {
        DeviceEntry {
            dev,
            bus: 1,
            addr: Some(addr(&[0x02])),
            product: Product::EPEVER_TRACER_B,
            dialect: Dialect::EPEVER_B,
            role: DeviceRole::SOLAR_CHARGER,
            parent: None,
            options: DeviceOptions {
                current_direction: Some(CurrentDirection::PositiveIsIn),
                poll_period_ms: Some(2000),
                ..DeviceOptions::NONE
            },
        }
    }

    fn mppt<D>(dev: D) -> DeviceEntry<'static, D> {
        DeviceEntry {
            dev,
            bus: 3,
            addr: None,
            product: Product::VICTRON_MPPT_RS,
            dialect: Dialect::VICTRON_MPPT_RS_HEX,
            role: DeviceRole::SOLAR_CHARGER,
            parent: None,
            options: DeviceOptions {
                ve_direct_3v3: Some(true),
                ..DeviceOptions::NONE
            },
        }
    }

    fn pack<D>(dev: D, at: &'static [u8], parent: Option<DevId>) -> DeviceEntry<'static, D> {
        DeviceEntry {
            dev,
            bus: 1,
            addr: Some(addr(at)),
            product: Product::EG4_LIFEPOWER4,
            dialect: Dialect::EG4_LIFEPOWER4_SERIAL,
            role: DeviceRole::BMS,
            parent,
            options: DeviceOptions::NONE,
        }
    }

    fn write_of(devices: &[DeviceEntry<'static, Option<DevId>>]) -> BusesAndDevicesWrite<'static> {
        let mut section = BusesAndDevicesWrite::EMPTY;
        section.push_bus(serial_bus()).expect("room for a bus");
        for device in devices {
            section.push_device(*device).expect("room for a device");
        }
        section
    }

    /// Three devices added to a site nobody has configured.
    fn site() -> BusesAndDevicesWrite<'static> {
        write_of(&[meter(None, &[0x01]), charger(None), mppt(None)])
    }

    /// The section after `site()` was accepted: devs 1 to 3, next id 4.
    fn held() -> Accepted<'static> {
        site()
            .accept(&rules(), &BusesAndDevicesRead::EMPTY, DevAllocator::FIRST)
            .expect("the site is valid")
    }

    struct Encoded {
        bytes: [u8; MAX_BUSES_AND_DEVICES_BYTES + 64],
        len: usize,
    }

    impl Encoded {
        fn of<D: DevSlot>(section: &BusesAndDevices<'_, D>) -> Self {
            let mut bytes = [0; MAX_BUSES_AND_DEVICES_BYTES + 64];
            let len = section.encode(&mut bytes).expect("the body encodes");
            Self { bytes, len }
        }

        fn body(&self) -> &[u8] {
            self.bytes
                .get(..self.len)
                .expect("the length came from the writer")
        }
    }

    #[track_caller]
    fn is_invalid<T: fmt::Debug>(result: Result<T, ConfigError>) -> ConfigError {
        let why = result.expect_err("the body is refused");
        assert_eq!(
            why.answer(),
            SectionRefusal::Outcome(SetConfig::Invalid),
            "{why} is answered outcome 3"
        );
        why
    }

    #[track_caller]
    fn is_malformed<T: fmt::Debug>(result: Result<T, ConfigError>) -> ConfigError {
        let why = result.expect_err("the body is refused");
        assert_eq!(
            why.answer(),
            SectionRefusal::Error(ErrorCode::MalformedFrame),
            "{why} is answered error 1"
        );
        why
    }

    /// A body built by hand, for the shapes the encoder will not produce.
    fn body(
        build: impl FnOnce(&mut CborWriter<'_>) -> Result<(), crate::cbor::CborError>,
    ) -> Encoded {
        let mut bytes = [0; MAX_BUSES_AND_DEVICES_BYTES + 64];
        let mut cbor = CborWriter::new(&mut bytes);
        build(&mut cbor).expect("the fixture encodes");
        let len = cbor.finish().expect("the fixture is complete");
        Encoded { bytes, len }
    }

    /// `{1: [], 2: [entry]}` with one device entry written by hand.
    fn one_device(
        entry: impl FnOnce(&mut CborWriter<'_>) -> Result<(), crate::cbor::CborError>,
    ) -> Encoded {
        body(|cbor| {
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.array(0)?;
            cbor.key(2)?;
            cbor.array(1)?;
            entry(cbor)
        })
    }

    #[test]
    fn a_site_round_trips_as_written_and_as_answered() {
        let write = site();
        let encoded = Encoded::of(&write);
        assert_eq!(BusesAndDevicesWrite::decode(encoded.body()), Ok(write));

        let answer = held().section;
        let encoded = Encoded::of(&answer);
        assert_eq!(BusesAndDevicesRead::decode(encoded.body()), Ok(answer));
    }

    #[test]
    fn nothing_configured_is_two_empty_lists_and_round_trips() {
        let empty = Encoded::of(&BusesAndDevicesRead::EMPTY);
        assert_eq!(empty.body(), &[0xA2, 0x01, 0x80, 0x02, 0x80]);
        assert_eq!(
            BusesAndDevicesRead::decode(empty.body()),
            Ok(BusesAndDevicesRead::EMPTY)
        );
    }

    /// Every combination of bus settings and every combination of options, so
    /// a key that only goes wrong beside another is walked too.
    #[test]
    fn every_bus_setting_and_every_option_round_trips() {
        for mask in 1_u8..16 {
            let bit = |n: u8| mask & (1 << n) != 0;
            let entry = BusEntry {
                bus: 1,
                rate: bit(0).then_some(NonZeroU32::MAX),
                data_bits: bit(1).then_some(DataBits::Seven),
                parity: bit(2).then_some(Parity::Odd),
                stop_bits: bit(3).then_some(StopBits::One),
            };
            let mut section = BusesAndDevicesWrite::EMPTY;
            section.push_bus(entry).expect("room");
            let options = DeviceOptions {
                current_direction: bit(0).then_some(CurrentDirection::PositiveIsOut),
                pylontech_version: bit(1).then_some(PylontechVersion::V13),
                ve_direct_3v3: bit(2).then_some(false),
                poll_period_ms: bit(3).then_some(u32::MAX),
            };
            section
                .push_device(DeviceEntry {
                    options,
                    ..meter(Some(dev(u16::MAX)), &[0xFF; MAX_ADDR])
                })
                .expect("room");
            let encoded = Encoded::of(&section);
            assert_eq!(
                BusesAndDevicesWrite::decode(encoded.body()),
                Ok(section),
                "mask {mask:#06b}"
            );
        }
    }

    /// The limits derivation costs every key at its widest. Building that body
    /// here and measuring it is what stops the arithmetic in `PROTOCOL.md`
    /// from being a count somebody did once.
    #[test]
    fn the_widest_body_is_the_one_the_limits_derivation_costs() {
        let mut widest = BusesAndDevicesRead::EMPTY;
        for bus in 24..32 {
            widest
                .push_bus(BusEntry {
                    bus,
                    rate: NonZeroU32::new(115_200),
                    data_bits: Some(DataBits::Eight),
                    parity: Some(Parity::Odd),
                    stop_bits: Some(StopBits::Two),
                })
                .expect("room for eight buses");
        }
        for i in 0..16 {
            widest
                .push_device(DeviceEntry {
                    dev: dev(0xFF00 + i),
                    bus: 24,
                    addr: None,
                    product: Product(0xF001),
                    dialect: Dialect(0xF002),
                    role: DeviceRole(0xF003),
                    parent: Some(dev(0xFF00 + (i + 1) % 16)),
                    options: DeviceOptions {
                        current_direction: Some(CurrentDirection::PositiveIsOut),
                        pylontech_version: Some(PylontechVersion::V13),
                        ve_direct_3v3: Some(true),
                        poll_period_ms: Some(100_000),
                    },
                })
                .expect("room for sixteen devices");
        }
        for (slot, bytes) in widest.devices.iter_mut().zip(WIDE_ADDRS.iter()) {
            if let Some(device) = slot {
                device.addr = Some(addr(bytes));
            }
        }
        let encoded = Encoded::of(&widest);
        assert_eq!(encoded.len, MAX_BUSES_AND_DEVICES_BYTES);
        assert_eq!(BusesAndDevicesRead::decode(encoded.body()), Ok(widest));
    }

    /// A receiver handed any prefix of a body must refuse it rather than read
    /// past what it was given.
    #[test]
    fn every_truncation_of_a_body_is_refused() {
        let encoded = Encoded::of(&held().section);
        for len in 0..encoded.len {
            let prefix = encoded.bytes.get(..len).expect("a prefix");
            assert!(
                BusesAndDevicesRead::decode(prefix).is_err(),
                "a {len}-byte prefix decoded"
            );
        }
    }

    /// Every single-bit flip of a real body, through both shapes. Whatever
    /// comes back, nothing panics.
    #[test]
    fn a_flipped_bit_anywhere_never_panics() {
        let encoded = Encoded::of(&held().section);
        for at in 0..encoded.len {
            for bit in 0..8 {
                let mut bytes = encoded.bytes;
                if let Some(byte) = bytes.get_mut(at) {
                    *byte ^= 1 << bit;
                }
                let body = bytes.get(..encoded.len).expect("the body");
                let _ = BusesAndDevicesRead::decode(body);
                let _ = BusesAndDevicesWrite::decode(body);
            }
        }
    }

    #[test]
    fn a_body_without_either_list_is_error_1() {
        let only_buses = body(|cbor| {
            cbor.map(1)?;
            cbor.key(1)?;
            cbor.array(0)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(only_buses.body())),
            ConfigError::Missing(BusesAndDevicesKey::Devices.key())
        );
        let only_devices = body(|cbor| {
            cbor.map(1)?;
            cbor.key(2)?;
            cbor.array(0)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(only_devices.body())),
            ConfigError::Missing(BusesAndDevicesKey::Buses.key())
        );
    }

    #[test]
    fn a_device_entry_missing_a_required_key_or_carrying_one_twice_is_error_1() {
        let no_dialect = one_device(|cbor| {
            cbor.map(3)?;
            cbor.key(2)?;
            cbor.u64(3)?;
            cbor.key(4)?;
            cbor.u64(5)?;
            cbor.key(6)?;
            cbor.u64(1)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(no_dialect.body())),
            ConfigError::Missing(BusesAndDevicesKey::Dialect.key())
        );
        // Written by hand because the writer refuses a repeated key: the
        // entry carries `bus` twice.
        let twice = [
            0xA2, 0x01, 0x80, 0x02, 0x81, 0xA5, 0x02, 0x01, 0x04, 0x03, 0x05, 0x02, 0x06, 0x05,
            0x02, 0x01,
        ];
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(&twice)),
            ConfigError::Duplicate(BusesAndDevicesKey::DeviceBus.key())
        );
    }

    /// Error 1 is decided before any value is judged. A body with a rate of 0
    /// and, later, a device missing its product is malformed, not invalid:
    /// telling the client its values were wrong sends it to fix a value when
    /// its encoder is what is broken.
    #[test]
    fn p_101_structure_is_judged_before_values() {
        let both = body(|cbor| {
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.array(1)?;
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.u64(1)?;
            cbor.key(2)?;
            cbor.u64(0)?;
            cbor.key(2)?;
            cbor.array(1)?;
            cbor.map(3)?;
            cbor.key(2)?;
            cbor.u64(3)?;
            cbor.key(5)?;
            cbor.u64(4)?;
            cbor.key(6)?;
            cbor.u64(1)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(both.body())),
            ConfigError::Missing(BusesAndDevicesKey::Product.key())
        );
    }

    #[test]
    fn an_unallocated_parity_or_protocol_revision_is_error_1() {
        let parity = body(|cbor| {
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.array(1)?;
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.u64(1)?;
            cbor.key(4)?;
            cbor.u64(9)?;
            cbor.key(2)?;
            cbor.array(0)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(parity.body())),
            ConfigError::UnknownValue(BusesAndDevicesKey::Parity.key())
        );
        let version = one_device(|cbor| {
            cbor.map(5)?;
            cbor.key(2)?;
            cbor.u64(2)?;
            cbor.key(4)?;
            cbor.u64(1)?;
            cbor.key(5)?;
            cbor.u64(0xF0A0)?;
            cbor.key(6)?;
            cbor.u64(4)?;
            cbor.key(8)?;
            cbor.map(1)?;
            cbor.key(2)?;
            cbor.u64(3)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(version.body())),
            ConfigError::UnknownValue(
                BusesAndDevicesKey::Option(DeviceOption::PylontechVersion).key()
            )
        );
    }

    #[test]
    fn p_261_an_entry_or_options_map_that_sets_nothing_is_error_1() {
        let bare_bus = body(|cbor| {
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.array(1)?;
            cbor.map(1)?;
            cbor.key(1)?;
            cbor.u64(1)?;
            cbor.key(2)?;
            cbor.array(0)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(bare_bus.body())),
            ConfigError::NothingSet(BusesAndDevicesKey::Bus.key())
        );
        let bare_options = one_device(|cbor| {
            cbor.map(6)?;
            cbor.key(2)?;
            cbor.u64(1)?;
            cbor.key(3)?;
            cbor.bytes(&[1])?;
            cbor.key(4)?;
            cbor.u64(3)?;
            cbor.key(5)?;
            cbor.u64(2)?;
            cbor.key(6)?;
            cbor.u64(5)?;
            cbor.key(8)?;
            cbor.map(0)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(bare_options.body())),
            ConfigError::NothingSet(BusesAndDevicesKey::Options.key())
        );
    }

    #[test]
    fn p_261_a_bus_the_board_does_not_have_is_refused_invalid() {
        let mut section = write_of(&[]);
        section
            .push_bus(BusEntry {
                bus: 7,
                ..serial_bus()
            })
            .expect("room");
        assert_eq!(
            is_invalid(section.check(&rules())),
            ConfigError::UnknownBus(7)
        );
    }

    #[test]
    fn p_261_a_bus_configured_twice_is_refused_invalid() {
        let mut section = write_of(&[]);
        section.push_bus(serial_bus()).expect("room");
        assert_eq!(
            is_invalid(section.check(&rules())),
            ConfigError::BusTwice(1)
        );
    }

    #[test]
    fn p_261_a_setting_the_transport_does_not_have_is_refused_invalid() {
        let cases = [
            (4, BusesAndDevicesKey::Rate, serial_bus()),
            (
                2,
                BusesAndDevicesKey::DataBits,
                BusEntry {
                    rate: None,
                    ..serial_bus()
                },
            ),
            (
                2,
                BusesAndDevicesKey::Parity,
                BusEntry {
                    rate: None,
                    data_bits: None,
                    ..serial_bus()
                },
            ),
            (
                2,
                BusesAndDevicesKey::StopBits,
                BusEntry {
                    rate: None,
                    data_bits: None,
                    parity: None,
                    ..serial_bus()
                },
            ),
        ];
        for (bus, key, entry) in cases {
            let mut section = BusesAndDevicesWrite::EMPTY;
            section.push_bus(BusEntry { bus, ..entry }).expect("room");
            assert_eq!(
                is_invalid(section.check(&rules())),
                ConfigError::NotOnTransport {
                    bus,
                    key: key.key()
                }
            );
        }
        // A rate alone is what a CAN bus has, and it is accepted.
        let mut can = BusesAndDevicesWrite::EMPTY;
        can.push_bus(BusEntry {
            bus: 2,
            rate: NonZeroU32::new(500_000),
            data_bits: None,
            parity: None,
            stop_bits: None,
        })
        .expect("room");
        assert_eq!(can.check(&rules()), Ok(()));
    }

    #[test]
    fn p_261_a_rate_of_zero_or_framing_no_uart_has_is_refused_invalid() {
        for (key, value) in [(2, 0), (3, 9), (3, 6), (5, 3), (5, 0)] {
            let encoded = body(|cbor| {
                cbor.map(2)?;
                cbor.key(1)?;
                cbor.array(1)?;
                cbor.map(2)?;
                cbor.key(1)?;
                cbor.u64(1)?;
                cbor.key(key)?;
                cbor.u64(value)?;
                cbor.key(2)?;
                cbor.array(0)
            });
            let why = is_invalid(BusesAndDevicesWrite::decode(encoded.body()));
            assert!(
                matches!(why, ConfigError::OutOfSchema(_)),
                "key {key} = {value}: {why}"
            );
        }
    }

    #[test]
    fn p_262_added_devices_get_the_next_ids_in_the_order_they_arrived() {
        let accepted = held();
        let devs: [Option<u16>; 3] = {
            let mut devs = [None; 3];
            for (slot, device) in devs.iter_mut().zip(accepted.section.devices()) {
                *slot = Some(device.dev.get());
            }
            devs
        };
        assert_eq!(devs, [Some(1), Some(2), Some(3)]);
        assert_eq!(accepted.section.devices().count(), 3);
        assert_eq!(accepted.allocator.next(), Some(dev(4)));
        let first = accepted.section.devices().next().expect("a device");
        assert_eq!(first.product, Product::PZEM_017);
    }

    /// A charger moved to another address is the same charger, so its history
    /// goes on under the same `dev`.
    #[test]
    fn p_262_a_device_moved_to_another_address_keeps_its_dev() {
        let before = held();
        let moved = write_of(&[meter(Some(dev(1)), &[0x05]), charger(Some(dev(2)))]);
        let after = moved
            .accept(&rules(), &before.section, before.allocator)
            .expect("a move is an edit");
        let meter = after.section.devices().next().expect("the meter");
        assert_eq!(meter.dev, dev(1));
        assert_eq!(meter.addr, Some(addr(&[0x05])));
        assert_eq!(after.allocator, before.allocator, "a move spends no id");
    }

    /// The MPPT at dev 3 is removed, and the next device added gets 4: a
    /// history filed under 3 is never joined to a different device.
    #[test]
    fn p_262_a_removed_devices_id_is_never_given_again() {
        let before = held();
        let without = write_of(&[meter(Some(dev(1)), &[0x01]), charger(Some(dev(2)))]);
        let removed = without
            .accept(&rules(), &before.section, before.allocator)
            .expect("a removal");
        let again = write_of(&[
            meter(Some(dev(1)), &[0x01]),
            charger(Some(dev(2))),
            mppt(None),
        ]);
        let readded = again
            .accept(&rules(), &removed.section, removed.allocator)
            .expect("an addition");
        let last = readded.section.devices().last().expect("the mppt");
        assert_eq!(last.dev, dev(4));
    }

    #[test]
    fn p_262_a_client_cannot_edit_a_dev_the_section_does_not_hold() {
        let before = held();
        let invented = write_of(&[meter(Some(dev(9)), &[0x01])]);
        assert_eq!(
            is_invalid(invented.accept(&rules(), &before.section, before.allocator)),
            ConfigError::UnknownDev(9)
        );
    }

    /// Changing what the device is under the same id would put a battery's
    /// history on a meter's line.
    #[test]
    fn p_262_a_new_product_or_dialect_under_an_old_dev_is_refused_invalid() {
        let before = held();
        let product = write_of(&[DeviceEntry {
            product: Product::PZEM_003,
            ..meter(Some(dev(1)), &[0x01])
        }]);
        assert_eq!(
            is_invalid(product.accept(&rules(), &before.section, before.allocator)),
            ConfigError::DeviceChanged(1)
        );
        let dialect = write_of(&[DeviceEntry {
            dialect: Dialect::EG4_LIFEPOWER4_SERIAL,
            options: DeviceOptions::NONE,
            ..meter(Some(dev(1)), &[0x01])
        }]);
        assert_eq!(
            is_invalid(dialect.accept(&rules(), &before.section, before.allocator)),
            ConfigError::DeviceChanged(1)
        );
        // The same product added fresh is a new device with a new id.
        let fresh = write_of(&[DeviceEntry {
            product: Product::PZEM_003,
            ..meter(None, &[0x01])
        }]);
        let accepted = fresh
            .accept(&rules(), &before.section, before.allocator)
            .expect("remove plus add");
        assert_eq!(
            accepted.section.devices().next().map(|device| device.dev),
            Some(dev(4))
        );
    }

    #[test]
    fn p_262_one_dev_on_two_entries_or_a_dev_of_zero_is_refused_invalid() {
        let twice = write_of(&[meter(Some(dev(1)), &[0x01]), meter(Some(dev(1)), &[0x03])]);
        assert_eq!(is_invalid(twice.check(&rules())), ConfigError::DevTwice(1));
        let zero = one_device(|cbor| {
            cbor.map(6)?;
            cbor.key(1)?;
            cbor.u64(0)?;
            cbor.key(2)?;
            cbor.u64(1)?;
            cbor.key(3)?;
            cbor.bytes(&[1])?;
            cbor.key(4)?;
            cbor.u64(3)?;
            cbor.key(5)?;
            cbor.u64(2)?;
            cbor.key(6)?;
            cbor.u64(5)
        });
        assert_eq!(
            is_invalid(BusesAndDevicesWrite::decode(zero.body())),
            ConfigError::OutOfSchema(BusesAndDevicesKey::Dev.key())
        );
    }

    /// A refused write must not spend ids, or a client retrying a typo burns
    /// through the space.
    #[test]
    fn p_262_a_refused_write_spends_no_id_and_the_last_id_is_the_last() {
        let bad = write_of(&[meter(None, &[0x01]), meter(None, &[0x01])]);
        let mut allocator = DevAllocator::FIRST;
        is_invalid(bad.accept(&rules(), &BusesAndDevicesRead::EMPTY, allocator));
        assert_eq!(allocator.next(), Some(dev(1)));

        allocator = DevAllocator::resume(Some(dev(u16::MAX)));
        assert_eq!(allocator.allocate(), Ok(dev(u16::MAX)));
        assert_eq!(allocator.next(), None);
        assert_eq!(is_invalid(allocator.allocate()), ConfigError::DevsExhausted);
        let one = write_of(&[meter(None, &[0x01])]);
        assert_eq!(
            is_invalid(one.accept(&rules(), &BusesAndDevicesRead::EMPTY, allocator)),
            ConfigError::DevsExhausted
        );
    }

    /// An allocator resumed below an id already held would give it out again.
    #[test]
    fn p_262_an_allocator_behind_the_ids_held_is_refused_rather_than_reused() {
        let before = held();
        let behind = DevAllocator::resume(Some(dev(2)));
        let one_more = write_of(&[
            meter(Some(dev(1)), &[0x01]),
            charger(Some(dev(2))),
            mppt(Some(dev(3))),
            pack(None, &[0x09], None),
        ]);
        assert_eq!(
            is_invalid(one_more.accept(&rules(), &before.section, behind)),
            ConfigError::AllocatorBehind(2)
        );
        // Dev 2 was removed, so it is not held, and it was still given once:
        // an allocator resumed at 2 would give it to a new device.
        let without_two = write_of(&[meter(Some(dev(1)), &[0x01]), mppt(Some(dev(3)))]);
        let removed = without_two
            .accept(&rules(), &before.section, before.allocator)
            .expect("a removal");
        let add = write_of(&[
            meter(Some(dev(1)), &[0x01]),
            mppt(Some(dev(3))),
            pack(None, &[0x09], None),
        ]);
        assert_eq!(
            is_invalid(add.accept(&rules(), &removed.section, behind)),
            ConfigError::AllocatorBehind(2)
        );
    }

    #[test]
    fn p_262_an_answer_ascends_and_a_client_refuses_one_that_does_not() {
        let mut out_of_order = BusesAndDevicesRead::EMPTY;
        out_of_order.push_device(charger(dev(2))).expect("room");
        out_of_order
            .push_device(meter(dev(1), &[0x01]))
            .expect("room");
        let mut dst = [0; 256];
        assert_eq!(
            is_malformed(out_of_order.encode(&mut dst)),
            ConfigError::OutOfOrder(BusesAndDevicesKey::Dev.key())
        );
        let write = write_of(&[charger(Some(dev(2))), meter(Some(dev(1)), &[0x01])]);
        let encoded = Encoded::of(&write);
        assert_eq!(
            is_malformed(BusesAndDevicesRead::decode(encoded.body())),
            ConfigError::OutOfOrder(BusesAndDevicesKey::Dev.key())
        );
        // Accepting that same write puts the answer in order.
        let before = held();
        let accepted = write
            .accept(&rules(), &before.section, before.allocator)
            .expect("valid");
        let encoded = Encoded::of(&accepted.section);
        assert!(BusesAndDevicesRead::decode(encoded.body()).is_ok());
    }

    /// A client that appends a bus to the end of its list writes the buses
    /// out of order. The write is valid; the answer built from it must still
    /// ascend, or the controller holds a section it cannot answer with.
    #[test]
    fn p_262_an_accepted_write_answers_in_order_whatever_order_it_arrived_in() {
        let mut write = BusesAndDevicesWrite::EMPTY;
        for bus in [3, 1, 2] {
            write
                .push_bus(BusEntry {
                    bus,
                    rate: NonZeroU32::new(9600),
                    data_bits: None,
                    parity: None,
                    stop_bits: None,
                })
                .expect("room");
        }
        write.push_device(mppt(None)).expect("room");
        write.push_device(meter(None, &[0x01])).expect("room");
        let accepted = write
            .accept(&rules(), &BusesAndDevicesRead::EMPTY, DevAllocator::FIRST)
            .expect("valid");
        let encoded = Encoded::of(&accepted.section);
        let answer = BusesAndDevicesRead::decode(encoded.body()).expect("the answer ascends");
        let buses: [Option<u8>; 3] = {
            let mut buses = [None; 3];
            for (slot, entry) in buses.iter_mut().zip(answer.buses()) {
                *slot = Some(entry.bus);
            }
            buses
        };
        assert_eq!(buses, [Some(1), Some(2), Some(3)]);
        // Devices keep the order they were given ids in, which is the order
        // they arrived.
        let first = answer.devices().next().expect("a device");
        assert_eq!(
            (first.dev, first.product),
            (dev(1), Product::VICTRON_MPPT_RS)
        );

        let mut backwards = BusesAndDevicesRead::EMPTY;
        backwards
            .push_bus(BusEntry {
                bus: 2,
                ..serial_bus()
            })
            .expect("room");
        backwards.push_bus(serial_bus()).expect("room");
        let mut dst = [0; 64];
        assert_eq!(
            is_malformed(backwards.encode(&mut dst)),
            ConfigError::OutOfOrder(BusesAndDevicesKey::Bus.key())
        );
    }

    /// A table may give one dialect a row per transport. The row that
    /// matches the bus is the one whose options apply.
    #[test]
    fn p_265_a_dialect_with_a_row_per_transport_is_checked_against_its_bus() {
        const TWO_ROWS: &[DialectRule<'static>] = &[
            DialectRule {
                dialect: Dialect::EG4_LIFEPOWER4_SERIAL,
                transports: &[Transport::Can],
                options: &[],
                min_poll_ms: 1000,
            },
            DialectRule {
                dialect: Dialect::EG4_LIFEPOWER4_SERIAL,
                transports: &[Transport::Rs485],
                options: &[DeviceOption::CurrentDirection],
                min_poll_ms: 1000,
            },
        ];
        let rules = SiteRules {
            dialects: TWO_ROWS,
            ..rules()
        };
        let on_rs485 = write_of(&[DeviceEntry {
            options: DeviceOptions {
                current_direction: Some(CurrentDirection::PositiveIsOut),
                ..DeviceOptions::NONE
            },
            ..pack(None, &[0x01], None)
        }]);
        assert_eq!(on_rs485.check(&rules), Ok(()));
    }

    /// A stale allocator is caught before the write is looked at: a write
    /// that only removes the highest dev would otherwise erase the evidence
    /// that the allocator's next id was given before.
    #[test]
    fn p_262_a_stale_allocator_is_refused_even_by_a_write_that_adds_nothing() {
        let before = held();
        let behind = DevAllocator::resume(Some(dev(2)));
        let removal = write_of(&[meter(Some(dev(1)), &[0x01])]);
        assert_eq!(
            is_invalid(removal.accept(&rules(), &before.section, behind)),
            ConfigError::AllocatorBehind(2)
        );
    }

    /// A body built in memory is held to the same shape the decoder
    /// requires, so `accept` never stores what a reader refuses.
    #[test]
    fn p_261_a_bus_entry_that_sets_nothing_is_refused_by_check_as_by_decode() {
        let mut bare = BusesAndDevicesWrite::EMPTY;
        bare.push_bus(BusEntry {
            bus: 1,
            rate: None,
            data_bits: None,
            parity: None,
            stop_bits: None,
        })
        .expect("room");
        assert_eq!(
            is_malformed(bare.check(&rules())),
            ConfigError::NothingSet(BusesAndDevicesKey::Bus.key())
        );
        is_malformed(bare.accept(&rules(), &BusesAndDevicesRead::EMPTY, DevAllocator::FIRST));
    }

    #[test]
    fn p_262_a_config_answer_without_a_dev_is_error_1() {
        let encoded = Encoded::of(&site());
        assert_eq!(
            is_malformed(BusesAndDevicesRead::decode(encoded.body())),
            ConfigError::Missing(BusesAndDevicesKey::Dev.key())
        );
    }

    /// The section has nowhere to put a signal or a component id. A client
    /// that sends one under a key this build does not know has it skipped
    /// (P-013) and never stored, so nothing it chose can reach the inventory.
    #[test]
    fn p_263_a_signal_id_a_client_sends_is_never_stored() {
        let with_signals = one_device(|cbor| {
            cbor.map(6)?;
            cbor.key(2)?;
            cbor.u64(1)?;
            cbor.key(3)?;
            cbor.bytes(&[1])?;
            cbor.key(4)?;
            cbor.u64(3)?;
            cbor.key(5)?;
            cbor.u64(2)?;
            cbor.key(6)?;
            cbor.u64(5)?;
            cbor.key(9)?;
            cbor.array(2)?;
            cbor.u64(41)?;
            cbor.u64(42)
        });
        let write =
            BusesAndDevicesWrite::decode(with_signals.body()).expect("an unknown key is skipped");
        let accepted = write
            .accept(&rules(), &BusesAndDevicesRead::EMPTY, DevAllocator::FIRST)
            .expect("valid");
        let answer = Encoded::of(&accepted.section);
        let without = one_device(|cbor| {
            cbor.map(6)?;
            cbor.key(1)?;
            cbor.u64(1)?;
            cbor.key(2)?;
            cbor.u64(1)?;
            cbor.key(3)?;
            cbor.bytes(&[1])?;
            cbor.key(4)?;
            cbor.u64(3)?;
            cbor.key(5)?;
            cbor.u64(2)?;
            cbor.key(6)?;
            cbor.u64(5)
        });
        assert_eq!(answer.body(), without.body());
    }

    #[test]
    fn p_264_an_option_key_nobody_allocated_is_refused_not_skipped() {
        let unknown = one_device(|cbor| {
            cbor.map(6)?;
            cbor.key(2)?;
            cbor.u64(1)?;
            cbor.key(3)?;
            cbor.bytes(&[1])?;
            cbor.key(4)?;
            cbor.u64(3)?;
            cbor.key(5)?;
            cbor.u64(2)?;
            cbor.key(6)?;
            cbor.u64(5)?;
            cbor.key(8)?;
            cbor.map(1)?;
            cbor.key(9)?;
            cbor.u64(1)
        });
        assert_eq!(
            is_invalid(BusesAndDevicesWrite::decode(unknown.body())),
            ConfigError::UnknownOption(9)
        );
    }

    /// Still structure first: an unknown option before a missing product is a
    /// malformed body.
    #[test]
    fn p_264_an_unknown_option_in_a_malformed_body_is_still_error_1() {
        let both = one_device(|cbor| {
            cbor.map(4)?;
            cbor.key(2)?;
            cbor.u64(1)?;
            cbor.key(5)?;
            cbor.u64(2)?;
            cbor.key(6)?;
            cbor.u64(5)?;
            cbor.key(8)?;
            cbor.map(1)?;
            cbor.key(9)?;
            cbor.u64(1)
        });
        assert_eq!(
            is_malformed(BusesAndDevicesWrite::decode(both.body())),
            ConfigError::Missing(BusesAndDevicesKey::Product.key())
        );
    }

    #[test]
    fn p_264_an_option_the_dialect_does_not_define_is_refused_invalid() {
        let version_on_a_meter = write_of(&[DeviceEntry {
            options: DeviceOptions {
                pylontech_version: Some(PylontechVersion::V12),
                ..DeviceOptions::NONE
            },
            ..meter(None, &[0x01])
        }]);
        assert_eq!(
            is_invalid(version_on_a_meter.check(&rules())),
            ConfigError::OptionNotInDialect {
                option: DeviceOption::PylontechVersion,
                dialect: Dialect::PZEM_DC.0,
            }
        );
        // The stand-in Pylontech dialect defines it.
        let mut pylontech = BusesAndDevicesWrite::EMPTY;
        pylontech
            .push_device(DeviceEntry {
                bus: 2,
                addr: Some(addr(&[0x01])),
                dialect: PYLONTECH_STAND_IN,
                options: DeviceOptions {
                    pylontech_version: Some(PylontechVersion::V12),
                    current_direction: Some(CurrentDirection::PositiveIsIn),
                    ..DeviceOptions::NONE
                },
                ..pack(None, &[0x01], None)
            })
            .expect("room");
        assert_eq!(pylontech.check(&rules()), Ok(()));
    }

    #[test]
    fn p_264_a_poll_period_below_the_dialects_minimum_is_refused_invalid() {
        let at = |period| {
            write_of(&[DeviceEntry {
                options: DeviceOptions {
                    poll_period_ms: Some(period),
                    ..DeviceOptions::NONE
                },
                ..meter(None, &[0x01])
            }])
        };
        assert_eq!(at(500).check(&rules()), Ok(()));
        assert_eq!(
            is_invalid(at(499).check(&rules())),
            ConfigError::PollTooShort {
                dialect: Dialect::PZEM_DC.0,
                min: 500,
            }
        );
    }

    /// Magnitude only is a value the registry allocates, so it is not error 1;
    /// it is not a direction a current can count in, so it is invalid.
    #[test]
    fn p_264_a_current_direction_of_magnitude_only_is_refused_invalid() {
        let magnitude = one_device(|cbor| {
            cbor.map(6)?;
            cbor.key(2)?;
            cbor.u64(1)?;
            cbor.key(3)?;
            cbor.bytes(&[2])?;
            cbor.key(4)?;
            cbor.u64(4)?;
            cbor.key(5)?;
            cbor.u64(3)?;
            cbor.key(6)?;
            cbor.u64(1)?;
            cbor.key(8)?;
            cbor.map(1)?;
            cbor.key(1)?;
            cbor.u64(3)
        });
        assert_eq!(
            is_invalid(BusesAndDevicesWrite::decode(magnitude.body())),
            ConfigError::OutOfSchema(
                BusesAndDevicesKey::Option(DeviceOption::CurrentDirection).key()
            )
        );
    }

    #[test]
    fn p_265_a_device_on_a_bus_the_board_does_not_have_is_refused_invalid() {
        let nowhere = write_of(&[DeviceEntry {
            bus: 9,
            ..meter(None, &[0x01])
        }]);
        assert_eq!(
            is_invalid(nowhere.check(&rules())),
            ConfigError::UnknownBus(9)
        );
    }

    #[test]
    fn p_265_an_address_left_out_carried_or_repeated_against_p_202_is_refused_invalid() {
        let missing = write_of(&[DeviceEntry {
            addr: None,
            ..meter(None, &[0x01])
        }]);
        assert_eq!(
            is_invalid(missing.check(&rules())),
            ConfigError::AddrRequired(1)
        );
        let on_ve_direct = write_of(&[DeviceEntry {
            addr: Some(addr(&[0x01])),
            ..mppt(None)
        }]);
        assert_eq!(
            is_invalid(on_ve_direct.check(&rules())),
            ConfigError::AddrNotAddressed(3)
        );
        let twice = write_of(&[meter(None, &[0x01]), pack(None, &[0x01], None)]);
        assert_eq!(is_invalid(twice.check(&rules())), ConfigError::AddrTwice(1));
        // The same address on two different buses is two devices.
        let apart = write_of(&[
            meter(None, &[0x01]),
            DeviceEntry {
                bus: 2,
                dialect: PYLONTECH_STAND_IN,
                ..pack(None, &[0x01], None)
            },
        ]);
        assert_eq!(apart.check(&rules()), Ok(()));
        is_invalid(Addr::new(&[]));
        is_invalid(Addr::new(&[0; MAX_ADDR + 1]));
    }

    /// A DS18B20 written with no ROM code was accepted while `addressed`
    /// left 1-Wire out of P-202's list, and three probes on one bus became
    /// three rows nobody could tell apart.
    #[test]
    fn p_265_a_onewire_probe_without_its_rom_code_is_refused_invalid() {
        const ROM: &[u8] = &[0x28, 0xFF, 0x4C, 0x21, 0x93, 0x16, 0x04, 0xA7];
        const ONEWIRE_BOARD: &[BoardBus] = &[
            BoardBus {
                bus: 1,
                transport: Transport::Rs485,
            },
            BoardBus {
                bus: 5,
                transport: Transport::Onewire,
            },
        ];
        const PROBES: &[DialectRule<'static>] = &[DialectRule {
            dialect: Dialect::DS18B20,
            transports: &[Transport::Onewire],
            options: &[],
            min_poll_ms: 1000,
        }];
        let rules = SiteRules {
            buses: ONEWIRE_BOARD,
            dialects: PROBES,
            ..rules()
        };
        let probe = |addr| DeviceEntry {
            dev: None,
            bus: 5,
            addr,
            product: Product::DS18B20,
            dialect: Dialect::DS18B20,
            role: DeviceRole::TEMPERATURE_SENSOR,
            parent: None,
            options: DeviceOptions::NONE,
        };
        assert_eq!(
            is_invalid(write_of(&[probe(None)]).check(&rules)),
            ConfigError::AddrRequired(5)
        );
        assert_eq!(write_of(&[probe(Some(addr(ROM)))]).check(&rules), Ok(()));
    }

    #[test]
    fn p_265_a_dialect_the_bus_cannot_carry_or_the_controller_does_not_drive_is_refused_invalid() {
        let on_can = write_of(&[DeviceEntry {
            bus: 2,
            ..meter(None, &[0x01])
        }]);
        assert_eq!(
            is_invalid(on_can.check(&rules())),
            ConfigError::DialectNotCarried {
                dialect: Dialect::PZEM_DC.0,
                bus: 2,
            }
        );
        let undriven = write_of(&[DeviceEntry {
            dialect: Dialect::MORNINGSTAR_SUNSAVER_DUO,
            options: DeviceOptions::NONE,
            ..meter(None, &[0x01])
        }]);
        assert_eq!(
            is_invalid(undriven.check(&rules())),
            ConfigError::DialectNotCarried {
                dialect: Dialect::MORNINGSTAR_SUNSAVER_DUO.0,
                bus: 1,
            }
        );
    }

    #[test]
    fn p_265_a_parent_that_is_not_listed_loops_or_runs_too_deep_is_refused_invalid() {
        let unlisted = write_of(&[pack(Some(dev(2)), &[0x01], Some(dev(7)))]);
        assert_eq!(
            is_invalid(unlisted.check(&rules())),
            ConfigError::ParentNotListed(7)
        );
        let itself = write_of(&[pack(Some(dev(2)), &[0x01], Some(dev(2)))]);
        assert_eq!(
            is_invalid(itself.check(&rules())),
            ConfigError::ParentLoop(2)
        );
        let round = write_of(&[
            pack(Some(dev(2)), &[0x01], Some(dev(3))),
            pack(Some(dev(3)), &[0x02], Some(dev(2))),
        ]);
        assert_eq!(
            is_invalid(round.check(&rules())),
            ConfigError::ParentLoop(2)
        );
        // Dev 1 hangs off a loop it is not part of: the refusal names the dev
        // where the chain came back, 2, not the device the walk started at.
        let beside = write_of(&[
            pack(Some(dev(1)), &[0x01], Some(dev(2))),
            pack(Some(dev(2)), &[0x02], Some(dev(3))),
            pack(Some(dev(3)), &[0x03], Some(dev(2))),
        ]);
        assert_eq!(
            is_invalid(beside.check(&rules())),
            ConfigError::ParentLoop(2)
        );

        let chain = |len: u16| {
            let mut section = BusesAndDevicesWrite::EMPTY;
            for (i, at) in (1..=len).zip(ONE_BYTE.iter()) {
                let parent = (i > 1).then(|| dev(i - 1));
                section
                    .push_device(pack(Some(dev(i)), at, parent))
                    .expect("room");
            }
            section
        };
        let depth = u16::try_from(MAX_TOPOLOGY_DEPTH).expect("a small depth");
        assert_eq!(chain(depth).check(&rules()), Ok(()));
        assert_eq!(
            is_invalid(chain(depth + 1).check(&rules())),
            ConfigError::TooDeep(depth + 1)
        );
    }

    /// Both caps, at the limit and one over: the section's own, and a smaller
    /// one a controller reports.
    #[test]
    fn p_265_more_devices_than_either_cap_is_refused_invalid() {
        let full = |count: usize| {
            let mut section = write_of(&[]);
            for at in ONE_BYTE.iter().take(count) {
                section.push_device(meter(None, at)).expect("room");
            }
            section
        };
        assert_eq!(full(MAX_CONFIG_DEVICES).check(&rules()), Ok(()));
        let mut over = full(MAX_CONFIG_DEVICES);
        assert_eq!(
            is_invalid(over.push_device(meter(None, &[0x7F]))),
            ConfigError::TooMany(BusesAndDevicesKey::Devices.key())
        );

        // Seventeen on the wire decode to the end and are refused invalid.
        let seventeen = body(|cbor| {
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.array(0)?;
            cbor.key(2)?;
            cbor.array(MAX_CONFIG_DEVICES + 1)?;
            for at in &ONE_BYTE {
                cbor.map(6)?;
                cbor.key(2)?;
                cbor.u64(1)?;
                cbor.key(3)?;
                cbor.bytes(at)?;
                cbor.key(4)?;
                cbor.u64(3)?;
                cbor.key(5)?;
                cbor.u64(2)?;
                cbor.key(6)?;
                cbor.u64(5)?;
                cbor.key(8)?;
                cbor.map(0)?;
            }
            Ok(())
        });
        // Every entry above carries an empty options map, which is error 1:
        // the count is invalid, the shape is not, and shape wins.
        is_malformed(BusesAndDevicesWrite::decode(seventeen.body()));
        let seventeen = body(|cbor| {
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.array(0)?;
            cbor.key(2)?;
            cbor.array(MAX_CONFIG_DEVICES + 1)?;
            for at in &ONE_BYTE {
                cbor.map(5)?;
                cbor.key(2)?;
                cbor.u64(1)?;
                cbor.key(3)?;
                cbor.bytes(at)?;
                cbor.key(4)?;
                cbor.u64(3)?;
                cbor.key(5)?;
                cbor.u64(2)?;
                cbor.key(6)?;
                cbor.u64(5)?;
            }
            Ok(())
        });
        assert_eq!(
            is_invalid(BusesAndDevicesWrite::decode(seventeen.body())),
            ConfigError::TooMany(BusesAndDevicesKey::Devices.key())
        );

        let reported = SiteRules {
            max_devices: 3,
            ..rules()
        };
        assert_eq!(full(3).check(&reported), Ok(()));
        assert_eq!(
            is_invalid(full(4).check(&reported)),
            ConfigError::TooMany(BusesAndDevicesKey::Devices.key())
        );
    }

    #[test]
    fn more_bus_entries_than_the_section_holds_are_refused_invalid() {
        let nine = body(|cbor| {
            cbor.map(2)?;
            cbor.key(1)?;
            cbor.array(MAX_CONFIG_BUSES + 1)?;
            for bus in 0..=MAX_CONFIG_BUSES {
                cbor.map(2)?;
                cbor.key(1)?;
                cbor.u64(u64::try_from(bus).expect("a small bus"))?;
                cbor.key(2)?;
                cbor.u64(9600)?;
            }
            cbor.key(2)?;
            cbor.array(0)
        });
        assert_eq!(
            is_invalid(BusesAndDevicesWrite::decode(nine.body())),
            ConfigError::TooMany(BusesAndDevicesKey::Buses.key())
        );
    }

    /// The TypeScript reader holds keys to the same signed 64-bit range; these
    /// are the bodies its test uses, so the two bindings answer them alike.
    #[test]
    fn a_map_key_outside_the_signed_64_bit_range_is_error_1() {
        let unknown_max: [u8; 14] = [
            0xA3, 0x01, 0x80, 0x02, 0x80, 0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let mut skipped = [0; 15];
        skipped
            .get_mut(..14)
            .expect("room")
            .copy_from_slice(&unknown_max);
        assert!(
            BusesAndDevicesWrite::decode(&skipped).is_ok(),
            "i64::MAX is a key"
        );
        for head in [0x1B, 0x3B] {
            let body = [
                0xA3, 0x01, 0x80, 0x02, 0x80, head, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x00,
            ];
            is_malformed(BusesAndDevicesWrite::decode(&body));
        }
        let option = [
            0xA2, 0x01, 0x80, 0x02, 0x81, 0xA5, 0x02, 0x01, 0x04, 0x03, 0x05, 0x02, 0x06, 0x05,
            0x08, 0xA1, 0x1B, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x00,
        ];
        is_malformed(BusesAndDevicesWrite::decode(&option));
    }

    #[test]
    fn every_key_names_itself_and_its_number() {
        let shown = Rendering::<64>::displayed(&SectionKey::BusesAndDevices(
            BusesAndDevicesKey::Option(DeviceOption::PollPeriod),
        ));
        assert_eq!(shown.bytes(), b"device option poll_period (key 4)");
    }

    #[test]
    fn refusals_render_each_a_sentence_of_its_own() {
        let key = |key: BusesAndDevicesKey| key.key();
        let errors = [
            ConfigError::NothingSet(key(BusesAndDevicesKey::Bus)),
            ConfigError::NothingSet(key(BusesAndDevicesKey::Options)),
            ConfigError::UnknownValue(key(BusesAndDevicesKey::Parity)),
            ConfigError::OutOfOrder(key(BusesAndDevicesKey::Dev)),
            ConfigError::OutOfSchema(key(BusesAndDevicesKey::Rate)),
            ConfigError::TooMany(key(BusesAndDevicesKey::Devices)),
            ConfigError::UnknownOption(9),
            ConfigError::UnknownBus(7),
            ConfigError::BusTwice(1),
            ConfigError::NotOnTransport {
                bus: 4,
                key: key(BusesAndDevicesKey::Rate),
            },
            ConfigError::AddrRequired(1),
            ConfigError::AddrNotAddressed(3),
            ConfigError::AddrTwice(1),
            ConfigError::DialectNotCarried { dialect: 2, bus: 2 },
            ConfigError::OptionNotInDialect {
                option: DeviceOption::PylontechVersion,
                dialect: 2,
            },
            ConfigError::PollTooShort {
                dialect: 2,
                min: 500,
            },
            ConfigError::UnknownDev(9),
            ConfigError::DevTwice(1),
            ConfigError::DeviceChanged(1),
            ConfigError::DevsExhausted,
            ConfigError::ParentNotListed(7),
            ConfigError::ParentLoop(2),
            ConfigError::TooDeep(5),
            ConfigError::AllocatorBehind(2),
        ];
        Rendering::<100>::each_says_something_of_its_own(&errors);
    }
}
