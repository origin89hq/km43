//! The section bodies `Config 0x86` answers with and `SetConfig 0x07` writes:
//! identity and site, the network, and the one key every behaviour shares.
//!
//! The network section is the only one with two shapes. [`NetworkWrite`] is
//! what a client sends and carries the passphrase; [`NetworkRead`] is what the
//! controller answers with and has no field to put one in (P-106). A passphrase
//! the read type cannot hold is a passphrase no controller built on this crate
//! can hand to a relay.
//!
//! Every body decodes structure first and values second: a key missing,
//! repeated or of the wrong type is error 1 (P-015), and a value outside the
//! schema is `SetConfigAck` outcome 3 (P-101), so [`ConfigError::answer`]
//! returns one or the other.
//!
//! cites: P-013, P-015, P-101, P-103, P-106, P-107

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::generated::{BehaviourKey, ErrorCode, SetConfig};
use crate::limits::{MAX_LABEL, MAX_LINK_TEXT};
use crate::linklocal::{COUNTRY_BYTES, PSK_LONGEST, PSK_SHORTEST};

/// An SSID, which IEEE 802.11 caps at 32 bytes.
pub const MAX_SSID: usize = 32;

/// A hostname, capped where `NetConfig` caps it.
pub const MAX_HOSTNAME: usize = 32;

// A section the controller accepted has to be a `NetConfig` the comms
// processor cannot refuse for its shape (L-130).
const_assert!(MAX_SSID <= MAX_LINK_TEXT);
const_assert!(MAX_HOSTNAME <= MAX_LINK_TEXT);

/// `site_name` at `MAX_LABEL`: the map head, a key, a two-byte text head and 32.
pub const MAX_IDENTITY_BYTES: usize = 36;

/// `{1: shadow}`, the whole behaviour body this crate knows so far.
pub const MAX_BEHAVIOUR_BYTES: usize = 3;

/// Every key at its widest: a 32-byte `ssid`, a 63-byte `psk`, `country` and
/// a 32-byte `hostname`.
pub const MAX_NETWORK_WRITE_BYTES: usize = 141;

/// The read shape at its widest: `ssid`, `psk_set`, `country`, `hostname`.
pub const MAX_NETWORK_READ_BYTES: usize = 77;

/// A key of one of the section bodies here, so a refusal can say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SectionKey {
    /// Identity and site, key 1.
    SiteName,
    /// Every behaviour section, the key the registry allocates (P-103).
    Shadow,
    /// Network, key 1.
    Ssid,
    /// Network, key 2, `SetConfig` only.
    Psk,
    /// Network, key 3, `Config` only.
    PskSet,
    /// Network, key 4.
    Country,
    /// Network, key 5.
    Hostname,
}

impl SectionKey {
    const fn number(self) -> i64 {
        match self {
            Self::SiteName | Self::Ssid => 1,
            Self::Shadow => BehaviourKey::Shadow as i64,
            Self::Psk => 2,
            Self::PskSet => 3,
            Self::Country => 4,
            Self::Hostname => 5,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::SiteName => "identity site_name",
            Self::Shadow => "behaviour shadow",
            Self::Ssid => "network ssid",
            Self::Psk => "network psk",
            Self::PskSet => "network psk_set",
            Self::Country => "network country",
            Self::Hostname => "network hostname",
        }
    }

    /// The network key this number is, in either shape.
    const fn network(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Ssid),
            2 => Some(Self::Psk),
            3 => Some(Self::PskSet),
            4 => Some(Self::Country),
            5 => Some(Self::Hostname),
            _ => None,
        }
    }
}

impl fmt::Display for SectionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (key {})", self.name(), self.number())
    }
}

/// What a person calls the site, 1 to [`MAX_LABEL`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SiteName<'a>(&'a str);

impl<'a> SiteName<'a> {
    /// Refused outside its bounds, never trimmed to fit.
    pub const fn new(text: &'a str) -> Result<Self, ConfigError> {
        match within(SectionKey::SiteName, text, 1, MAX_LABEL) {
            Ok(()) => Ok(Self(text)),
            Err(why) => Err(why),
        }
    }

    /// The name as it was written.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// The network to join, 1 to [`MAX_SSID`] bytes. Compared byte for byte:
/// `Cabin` and `cabin` are two access points (P-107).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Ssid<'a>(&'a str);

impl<'a> Ssid<'a> {
    /// Refused outside its bounds. An empty SSID is not *no network*; that is
    /// the key being absent.
    pub const fn new(text: &'a str) -> Result<Self, ConfigError> {
        match within(SectionKey::Ssid, text, 1, MAX_SSID) {
            Ok(()) => Ok(Self(text)),
            Err(why) => Err(why),
        }
    }

    /// The SSID as it was written.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// A WPA passphrase, 8 to 63 bytes (L-131). Written, pushed to the radio, and
/// never returned in a `Config` (P-106).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Passphrase<'a>(&'a str);

impl<'a> Passphrase<'a> {
    /// Refused outside WPA's bounds, which are the only ones a radio can use.
    pub const fn new(text: &'a str) -> Result<Self, ConfigError> {
        match within(SectionKey::Psk, text, PSK_SHORTEST, PSK_LONGEST) {
            Ok(()) => Ok(Self(text)),
            Err(why) => Err(why),
        }
    }

    /// The passphrase, for the one place it goes: `NetChange::Set`.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// Written by hand because a derived `Debug` prints the passphrase into
/// whatever log the section passes through. The length is enough to debug a
/// refusal.
impl fmt::Debug for Passphrase<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Passphrase({} bytes)", self.0.len())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Passphrase<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Passphrase({=usize} bytes)", self.0.len());
    }
}

/// ISO 3166-1 alpha-2 as two capital letters (L-134). `ca` is refused rather
/// than upper-cased: the controller does not store a value nobody wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Country<'a>(&'a str);

impl<'a> Country<'a> {
    /// Refused unless exactly two bytes, each `A` to `Z`.
    pub const fn new(text: &'a str) -> Result<Self, ConfigError> {
        if text.len() != COUNTRY_BYTES {
            return Err(ConfigError::Length {
                key: SectionKey::Country,
                len: text.len(),
            });
        }
        match text.as_bytes() {
            [b'A'..=b'Z', b'A'..=b'Z'] => Ok(Self(text)),
            _ => Err(ConfigError::CountryNotCapitals),
        }
    }

    /// The two letters.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// What the comms processor calls itself on the network: 1 to
/// [`MAX_HOSTNAME`] bytes of letters, digits and hyphens, no hyphen at either
/// end, which is a name DHCP and mDNS will both carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Hostname<'a>(&'a str);

impl<'a> Hostname<'a> {
    /// Refused outside its bounds or its alphabet.
    pub fn new(text: &'a str) -> Result<Self, ConfigError> {
        within(SectionKey::Hostname, text, 1, MAX_HOSTNAME)?;
        let bytes = text.as_bytes();
        let alphabet = bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
        if !alphabet || bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return Err(ConfigError::NotAHostname);
        }
        Ok(Self(text))
    }

    /// The hostname as it was written.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

const fn within(
    key: SectionKey,
    text: &str,
    shortest: usize,
    longest: usize,
) -> Result<(), ConfigError> {
    if text.len() < shortest || text.len() > longest {
        return Err(ConfigError::Length {
            key,
            len: text.len(),
        });
    }
    Ok(())
}

/// `0x0001 identity and site`, the same in `Config` and `SetConfig`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct IdentitySection<'a> {
    /// Key 1.
    pub site_name: SiteName<'a>,
}

impl<'a> IdentitySection<'a> {
    /// Encode the body. The caller puts it under key 3 of the message.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ConfigError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(1)?;
        cbor.key(SectionKey::SiteName.number())?;
        cbor.text(self.site_name.as_str())?;
        Ok(cbor.finish()?)
    }

    /// Read a body, structure first and the name's bounds after.
    pub fn decode(body: &'a [u8]) -> Result<Self, ConfigError> {
        let mut cbor = CborReader::new(body);
        let pairs = cbor.map()?;
        let mut site_name = None;
        for _ in 0..pairs {
            match cbor.key()? {
                1 => once(&mut site_name, SectionKey::SiteName, cbor.text()?)?,
                _ => cbor.skip()?,
            }
        }
        cbor.finish()?;
        Ok(Self {
            site_name: SiteName::new(required(site_name, SectionKey::SiteName)?)?,
        })
    }
}

/// What every behaviour section, `0x0010` to `0x0013`, carries under one key.
///
/// Only `shadow` so far. The decoder skips every other key (P-013), so it reads
/// a behaviour body whose own parameters land after this build did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BehaviourSection {
    /// Whether the behaviour decides and actuates nothing (P-103). Required:
    /// a body without it is refused, never presumed live or shadowed.
    pub shadow: bool,
}

impl BehaviourSection {
    /// Encode the shared keys.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, ConfigError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(1)?;
        cbor.key(SectionKey::Shadow.number())?;
        cbor.bool(self.shadow)?;
        Ok(cbor.finish()?)
    }

    /// Read the shared keys out of any behaviour section's body.
    pub fn decode(body: &[u8]) -> Result<Self, ConfigError> {
        let mut cbor = CborReader::new(body);
        let pairs = cbor.map()?;
        let mut shadow = None;
        for _ in 0..pairs {
            let number = cbor.key()?;
            if number == SectionKey::Shadow.number() {
                once(&mut shadow, SectionKey::Shadow, cbor.bool()?)?;
            } else {
                cbor.skip()?;
            }
        }
        cbor.finish()?;
        Ok(Self {
            shadow: required(shadow, SectionKey::Shadow)?,
        })
    }
}

/// The network a `SetConfig` asks the controller to join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct JoinWrite<'a> {
    /// Key 1.
    pub ssid: Ssid<'a>,
    /// Key 2. `None` asks to keep the held passphrase, which P-107 allows only
    /// for the network it was given for.
    pub psk: Option<Passphrase<'a>>,
}

/// `0x0020 network` as `SetConfig` writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkWrite<'a> {
    /// Keys 1 and 2; `None` is *no network*, pushed as `op = clear`.
    pub join: Option<JoinWrite<'a>>,
    /// Key 4.
    pub country: Country<'a>,
    /// Key 5.
    pub hostname: Hostname<'a>,
}

/// What a network write does to the passphrase the controller holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PassphraseChange<'a> {
    /// Store this one.
    Set(Passphrase<'a>),
    /// Keep the held one; the `ssid` is the one it was given for.
    Keep,
    /// No network, so no passphrase either.
    Clear,
}

impl<'a> NetworkWrite<'a> {
    /// Encode the body a client signs as key 3 of the operation.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ConfigError> {
        let pairs = match self.join {
            None => 2,
            Some(JoinWrite { psk: None, .. }) => 3,
            Some(JoinWrite { psk: Some(_), .. }) => 4,
        };
        let mut cbor = CborWriter::new(dst);
        cbor.map(pairs)?;
        if let Some(join) = self.join {
            cbor.key(SectionKey::Ssid.number())?;
            cbor.text(join.ssid.as_str())?;
            if let Some(psk) = join.psk {
                cbor.key(SectionKey::Psk.number())?;
                cbor.text(psk.as_str())?;
            }
        }
        cbor.key(SectionKey::Country.number())?;
        cbor.text(self.country.as_str())?;
        cbor.key(SectionKey::Hostname.number())?;
        cbor.text(self.hostname.as_str())?;
        Ok(cbor.finish()?)
    }

    /// Read a `SetConfig` body. `psk_set` here is refused (P-101): it is the
    /// controller's answer, and a client echoing it back is a client that read
    /// a `Config` and did not look at what it was sending.
    pub fn decode(body: &'a [u8]) -> Result<Self, ConfigError> {
        let mut cbor = CborReader::new(body);
        let pairs = cbor.map()?;
        let mut text = NetworkText::default();
        let mut psk_set = None;
        for _ in 0..pairs {
            match SectionKey::network(cbor.key()?) {
                Some(key @ SectionKey::Ssid) => once(&mut text.ssid, key, cbor.text()?)?,
                Some(key @ SectionKey::Psk) => once(&mut text.psk, key, cbor.text()?)?,
                Some(key @ SectionKey::PskSet) => once(&mut psk_set, key, cbor.bool()?)?,
                Some(key @ SectionKey::Country) => once(&mut text.country, key, cbor.text()?)?,
                Some(key @ SectionKey::Hostname) => once(&mut text.hostname, key, cbor.text()?)?,
                Some(SectionKey::SiteName | SectionKey::Shadow) | None => cbor.skip()?,
            }
        }
        cbor.finish()?;
        let (country, hostname) = text.common()?;
        if psk_set.is_some() {
            return Err(ConfigError::ConfigOnly(SectionKey::PskSet));
        }
        let join = match (text.ssid, text.psk) {
            (None, None) => None,
            (None, Some(_)) => return Err(ConfigError::PassphraseWithoutNetwork),
            (Some(ssid), psk) => Some(JoinWrite {
                ssid: Ssid::new(ssid)?,
                psk: match psk {
                    Some(psk) => Some(Passphrase::new(psk)?),
                    None => None,
                },
            }),
        };
        Ok(Self {
            join,
            country,
            hostname,
        })
    }

    /// What this write does to the passphrase, given the SSID the controller
    /// holds one for (P-107). A write that names a network and brings no
    /// passphrase keeps the held one only for that exact network.
    pub fn passphrase(
        &self,
        held_for: Option<Ssid<'_>>,
    ) -> Result<PassphraseChange<'a>, ConfigError> {
        match (self.join, held_for) {
            (None, _) => Ok(PassphraseChange::Clear),
            (Some(JoinWrite { psk: Some(psk), .. }), _) => Ok(PassphraseChange::Set(psk)),
            (Some(JoinWrite { psk: None, .. }), None) => Err(ConfigError::NoPassphraseHeld),
            (Some(JoinWrite { ssid, psk: None }), Some(held)) => {
                if ssid.as_str().as_bytes() == held.as_str().as_bytes() {
                    Ok(PassphraseChange::Keep)
                } else {
                    Err(ConfigError::PassphraseForAnotherNetwork)
                }
            }
        }
    }
}

/// The network a `Config` says the controller holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct JoinRead<'a> {
    /// Key 1.
    pub ssid: Ssid<'a>,
    /// Key 3: whether a passphrase is held for it. There is no field for the
    /// passphrase itself, and that is the point of this type (P-106).
    pub psk_set: bool,
}

/// `0x0020 network` as `Config` answers with it.
///
/// ```compile_fail
/// use km43::NetworkRead;
/// fn leak<'a>(read: &NetworkRead<'a>) -> Option<&'a str> {
///     read.join.map(|join| join.psk.as_str())
/// }
/// ```
/// ```
/// use km43::NetworkRead;
/// fn shown(read: &NetworkRead<'_>) -> Option<bool> {
///     read.join.map(|join| join.psk_set)
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkRead<'a> {
    /// Keys 1 and 3; `None` is *no network held*.
    pub join: Option<JoinRead<'a>>,
    /// Key 4.
    pub country: Country<'a>,
    /// Key 5.
    pub hostname: Hostname<'a>,
}

impl<'a> NetworkRead<'a> {
    /// Encode the body the controller answers `GetConfig` with.
    pub fn encode(&self, dst: &mut [u8]) -> Result<usize, ConfigError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(if self.join.is_some() { 4 } else { 2 })?;
        if let Some(join) = self.join {
            cbor.key(SectionKey::Ssid.number())?;
            cbor.text(join.ssid.as_str())?;
            cbor.key(SectionKey::PskSet.number())?;
            cbor.bool(join.psk_set)?;
        }
        cbor.key(SectionKey::Country.number())?;
        cbor.text(self.country.as_str())?;
        cbor.key(SectionKey::Hostname.number())?;
        cbor.text(self.hostname.as_str())?;
        Ok(cbor.finish()?)
    }

    /// Read a `Config` body. A body carrying the passphrase is refused whatever
    /// type it arrived as (P-106): the controller that sent it is leaking, and a
    /// client that read past it would be one more place it was stored.
    pub fn decode(body: &'a [u8]) -> Result<Self, ConfigError> {
        let mut cbor = CborReader::new(body);
        let pairs = cbor.map()?;
        let mut text = NetworkText::default();
        let mut psk_set = None;
        let mut psk = None;
        for _ in 0..pairs {
            match SectionKey::network(cbor.key()?) {
                Some(key @ SectionKey::Ssid) => once(&mut text.ssid, key, cbor.text()?)?,
                Some(key @ SectionKey::Psk) => {
                    once(&mut psk, key, ())?;
                    cbor.skip()?;
                }
                Some(key @ SectionKey::PskSet) => once(&mut psk_set, key, cbor.bool()?)?,
                Some(key @ SectionKey::Country) => once(&mut text.country, key, cbor.text()?)?,
                Some(key @ SectionKey::Hostname) => once(&mut text.hostname, key, cbor.text()?)?,
                Some(SectionKey::SiteName | SectionKey::Shadow) | None => cbor.skip()?,
            }
        }
        cbor.finish()?;
        if psk.is_some() {
            return Err(ConfigError::SecretInConfig(SectionKey::Psk));
        }
        let join = match (text.ssid, psk_set) {
            (None, None) => None,
            (None, Some(_)) => return Err(ConfigError::PassphraseWithoutNetwork),
            (Some(_), None) => return Err(ConfigError::Missing(SectionKey::PskSet)),
            (Some(ssid), Some(psk_set)) => Some(JoinRead {
                ssid: Ssid::new(ssid)?,
                psk_set,
            }),
        };
        let (country, hostname) = text.common()?;
        Ok(Self {
            join,
            country,
            hostname,
        })
    }
}

/// The network's text keys as they arrived, before any is validated, so a
/// repeated key anywhere in the map is refused before a value is judged.
#[derive(Default)]
struct NetworkText<'a> {
    ssid: Option<&'a str>,
    psk: Option<&'a str>,
    country: Option<&'a str>,
    hostname: Option<&'a str>,
}

impl<'a> NetworkText<'a> {
    /// The two keys both shapes require.
    fn common(&self) -> Result<(Country<'a>, Hostname<'a>), ConfigError> {
        let country = required(self.country, SectionKey::Country)?;
        let hostname = required(self.hostname, SectionKey::Hostname)?;
        Ok((Country::new(country)?, Hostname::new(hostname)?))
    }
}

fn once<T>(slot: &mut Option<T>, key: SectionKey, value: T) -> Result<(), ConfigError> {
    if slot.is_some() {
        return Err(ConfigError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

fn required<T>(slot: Option<T>, key: SectionKey) -> Result<T, ConfigError> {
    slot.ok_or(ConfigError::Missing(key))
}

/// How a refused section body is answered: error 1 for a body that is not the
/// schema's shape, outcome 3 for one whose values the schema forbids (P-101).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SectionRefusal {
    /// An `Error 0xFF` with this code.
    Error(ErrorCode),
    /// A `SetConfigAck` with this outcome.
    Outcome(SetConfig),
}

/// Why a section body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConfigError {
    /// A required key never arrived (P-015).
    Missing(SectionKey),
    /// The same key twice (P-015).
    Duplicate(SectionKey),
    /// The CBOR underneath was refused.
    Cbor(CborError),
    /// Text outside its key's byte bounds (P-101).
    Length {
        /// Which key.
        key: SectionKey,
        /// The bytes it had.
        len: usize,
    },
    /// Two bytes, not both `A` to `Z` (P-101).
    CountryNotCapitals,
    /// A character outside letters, digits and hyphens, or a hyphen at an end.
    NotAHostname,
    /// A passphrase, or its presence, with no `ssid` it is for.
    PassphraseWithoutNetwork,
    /// A key only `Config` carries, sent in a `SetConfig` (P-101).
    ConfigOnly(SectionKey),
    /// A `Config` body carrying a secret field (P-106).
    SecretInConfig(SectionKey),
    /// No passphrase in the write and none held to keep (P-107).
    NoPassphraseHeld,
    /// No passphrase in the write, and the one held is for another SSID (P-107).
    PassphraseForAnotherNetwork,
}

impl From<CborError> for ConfigError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl ConfigError {
    /// What the controller answers a `SetConfig` carrying this body with. A
    /// client refusing a `Config` body treats every one of these as error 1.
    #[must_use]
    pub const fn answer(self) -> SectionRefusal {
        match self {
            Self::Missing(_) | Self::Duplicate(_) | Self::Cbor(_) | Self::SecretInConfig(_) => {
                SectionRefusal::Error(ErrorCode::MalformedFrame)
            }
            Self::Length { .. }
            | Self::CountryNotCapitals
            | Self::NotAHostname
            | Self::PassphraseWithoutNetwork
            | Self::ConfigOnly(_)
            | Self::NoPassphraseHeld
            | Self::PassphraseForAnotherNetwork => SectionRefusal::Outcome(SetConfig::Invalid),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "section body carries no {key}"),
            Self::Duplicate(key) => write!(f, "section body carries {key} twice"),
            Self::Cbor(why) => write!(f, "{why}"),
            Self::Length { key, len } => write!(f, "{key} is {len} bytes, outside its bounds"),
            Self::CountryNotCapitals => f.write_str("network country is not two capital letters"),
            Self::NotAHostname => {
                f.write_str("network hostname is not letters, digits and inner hyphens")
            }
            Self::PassphraseWithoutNetwork => f.write_str("a passphrase with no ssid to join"),
            Self::ConfigOnly(key) => write!(f, "{key} is the controller's to send, not a write"),
            Self::SecretInConfig(key) => write!(f, "Config carries secret {key}"),
            Self::NoPassphraseHeld => f.write_str("no passphrase written and none held to keep"),
            Self::PassphraseForAnotherNetwork => {
                f.write_str("the held passphrase is for another ssid")
            }
        }
    }
}

impl core::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{LinkEnvelope, LinkHeader, ReqId, SessionId};
    use crate::generated::LinkMessageType;
    use crate::linklocal::NetChange;
    use crate::render::Rendering;

    /// 63 bytes of text to slice every length out of, so a round trip can walk
    /// each field from its shortest to its longest.
    const LETTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789a";

    fn letters(len: usize) -> &'static str {
        LETTERS.get(..len).expect("the fixture is 63 bytes")
    }

    fn country() -> Country<'static> {
        Country::new("CA").expect("a country")
    }

    fn hostname(len: usize) -> Hostname<'static> {
        Hostname::new(letters(len)).expect("letters are a hostname")
    }

    fn cabin() -> NetworkWrite<'static> {
        NetworkWrite {
            join: Some(JoinWrite {
                ssid: Ssid::new("cabin").expect("an ssid"),
                psk: Some(Passphrase::new("correct horse").expect("a passphrase")),
            }),
            country: country(),
            hostname: Hostname::new("origin89").expect("a hostname"),
        }
    }

    fn widest_write() -> NetworkWrite<'static> {
        NetworkWrite {
            join: Some(JoinWrite {
                ssid: Ssid::new(letters(MAX_SSID)).expect("an ssid"),
                psk: Some(Passphrase::new(letters(PSK_LONGEST)).expect("a passphrase")),
            }),
            country: country(),
            hostname: hostname(MAX_HOSTNAME),
        }
    }

    fn widest_read() -> NetworkRead<'static> {
        NetworkRead {
            join: Some(JoinRead {
                ssid: Ssid::new(letters(MAX_SSID)).expect("an ssid"),
                psk_set: true,
            }),
            country: country(),
            hostname: hostname(MAX_HOSTNAME),
        }
    }

    fn widest_identity() -> IdentitySection<'static> {
        IdentitySection {
            site_name: SiteName::new(letters(MAX_LABEL)).expect("a name"),
        }
    }

    /// One section's encoder, so the four can be walked as a list.
    type Encoder = dyn Fn(&mut [u8]) -> Result<usize, ConfigError>;

    /// Whether one section's decoder refuses these bytes.
    type Refuses = dyn Fn(&[u8]) -> bool;

    /// A body encoded into room to spare, so a test can append to it.
    struct Encoded {
        bytes: [u8; MAX_NETWORK_WRITE_BYTES + 8],
        len: usize,
    }

    impl Encoded {
        fn of(encode: impl FnOnce(&mut [u8]) -> Result<usize, ConfigError>) -> Self {
            let mut bytes = [0; MAX_NETWORK_WRITE_BYTES + 8];
            let len = encode(&mut bytes).expect("fits the declared cap");
            Self { bytes, len }
        }

        fn body(&self) -> &[u8] {
            self.bytes.get(..self.len).expect("within the buffer")
        }
    }

    /// Each cap is what a firmware sizes a stack buffer from. The widest body
    /// the types admit fills it exactly, and one byte less is refused rather
    /// than written short.
    #[test]
    fn the_widest_bodies_fill_their_caps_exactly_and_one_byte_less_refuses() {
        let cases: [(usize, &Encoder); 4] = [
            (MAX_IDENTITY_BYTES, &|dst| widest_identity().encode(dst)),
            (MAX_BEHAVIOUR_BYTES, &|dst| {
                BehaviourSection { shadow: false }.encode(dst)
            }),
            (MAX_NETWORK_WRITE_BYTES, &|dst| widest_write().encode(dst)),
            (MAX_NETWORK_READ_BYTES, &|dst| widest_read().encode(dst)),
        ];
        for (cap, encode) in cases {
            let encoded = Encoded::of(encode);
            assert_eq!(encoded.len, cap);
            for short in 0..cap {
                let mut dst = [0; MAX_NETWORK_WRITE_BYTES];
                let room = dst.get_mut(..short).expect("shorter than the cap");
                assert!(encode(room).is_err(), "cap {cap} accepted {short}");
            }
        }
    }

    /// Every length of every text field, from shortest to longest, comes back
    /// as it went. An off-by-one at the CBOR text head's 23/24 boundary is
    /// exactly the length only one field would ever hit.
    #[test]
    fn every_field_round_trips_at_every_length_it_may_take() {
        for len in 1..=MAX_LABEL {
            let identity = IdentitySection {
                site_name: SiteName::new(letters(len)).expect("in bounds"),
            };
            let encoded = Encoded::of(|dst| identity.encode(dst));
            assert_eq!(IdentitySection::decode(encoded.body()), Ok(identity));
        }
        for shadow in [false, true] {
            let behaviour = BehaviourSection { shadow };
            let encoded = Encoded::of(|dst| behaviour.encode(dst));
            assert_eq!(BehaviourSection::decode(encoded.body()), Ok(behaviour));
        }
        for len in 1..=MAX_SSID {
            for psk in [None, Some(PSK_SHORTEST), Some(PSK_LONGEST)] {
                let write = NetworkWrite {
                    join: Some(JoinWrite {
                        ssid: Ssid::new(letters(len)).expect("in bounds"),
                        psk: psk.map(|n| Passphrase::new(letters(n)).expect("in bounds")),
                    }),
                    ..cabin()
                };
                let encoded = Encoded::of(|dst| write.encode(dst));
                assert_eq!(NetworkWrite::decode(encoded.body()), Ok(write));
            }
        }
        for len in PSK_SHORTEST..=PSK_LONGEST {
            let write = NetworkWrite {
                join: Some(JoinWrite {
                    ssid: Ssid::new("cabin").expect("an ssid"),
                    psk: Some(Passphrase::new(letters(len)).expect("in bounds")),
                }),
                ..cabin()
            };
            let encoded = Encoded::of(|dst| write.encode(dst));
            assert_eq!(NetworkWrite::decode(encoded.body()), Ok(write));
        }
        for len in 1..=MAX_HOSTNAME {
            let write = NetworkWrite {
                hostname: hostname(len),
                ..cabin()
            };
            let encoded = Encoded::of(|dst| write.encode(dst));
            assert_eq!(NetworkWrite::decode(encoded.body()), Ok(write));

            for join in [None, Some(true), Some(false)] {
                let read = NetworkRead {
                    join: join.map(|psk_set| JoinRead {
                        ssid: Ssid::new(letters(len)).expect("in bounds"),
                        psk_set,
                    }),
                    country: Country::new("ZW").expect("a country"),
                    hostname: hostname(len),
                };
                let encoded = Encoded::of(|dst| read.encode(dst));
                assert_eq!(NetworkRead::decode(encoded.body()), Ok(read));
            }
        }
        let clear = NetworkWrite {
            join: None,
            ..cabin()
        };
        let encoded = Encoded::of(|dst| clear.encode(dst));
        assert_eq!(NetworkWrite::decode(encoded.body()), Ok(clear));
    }

    /// A resynchronising receiver hands a decoder whatever it has. Every cut of
    /// every widest body is refused, and a byte past the end is refused rather
    /// than ignored.
    #[test]
    fn every_truncation_and_a_trailing_byte_is_refused() {
        let identity = Encoded::of(|dst| widest_identity().encode(dst));
        let behaviour = Encoded::of(|dst| BehaviourSection { shadow: true }.encode(dst));
        let write = Encoded::of(|dst| widest_write().encode(dst));
        let read = Encoded::of(|dst| widest_read().encode(dst));
        let decoders: [(&Encoded, &Refuses); 4] = [
            (&identity, &|b| IdentitySection::decode(b).is_err()),
            (&behaviour, &|b| BehaviourSection::decode(b).is_err()),
            (&write, &|b| NetworkWrite::decode(b).is_err()),
            (&read, &|b| NetworkRead::decode(b).is_err()),
        ];
        for (encoded, refused) in decoders {
            for cut in 0..encoded.len {
                assert!(refused(&encoded.bytes[..cut]), "accepted a cut at {cut}");
            }
            assert!(refused(&encoded.bytes[..=encoded.len]), "a trailing byte");
        }
    }

    /// Everything P-101 names as a value the schema forbids is refused with
    /// outcome 3 and never stored, and nothing is trimmed or case-folded into a
    /// value that would have been accepted.
    #[test]
    fn p_101_each_value_outside_a_section_schema_is_refused_invalid() {
        let too_long_label = letters(MAX_LABEL + 1);
        let refused = [
            (SiteName::new("").err(), SectionKey::SiteName, 0),
            (
                SiteName::new(too_long_label).err(),
                SectionKey::SiteName,
                33,
            ),
            (Ssid::new("").err(), SectionKey::Ssid, 0),
            (Ssid::new(letters(MAX_SSID + 1)).err(), SectionKey::Ssid, 33),
            (Passphrase::new(letters(7)).err(), SectionKey::Psk, 7),
            (Passphrase::new("").err(), SectionKey::Psk, 0),
            (Country::new("CAN").err(), SectionKey::Country, 3),
            (Country::new("C").err(), SectionKey::Country, 1),
            (Hostname::new("").err(), SectionKey::Hostname, 0),
            (Hostname::new(letters(33)).err(), SectionKey::Hostname, 33),
        ];
        for (got, key, len) in refused {
            assert_eq!(got, Some(ConfigError::Length { key, len }), "{key}");
        }
        let long_psk = [b'x'; PSK_LONGEST + 1];
        let long_psk = core::str::from_utf8(&long_psk).expect("ascii");
        assert_eq!(
            Passphrase::new(long_psk).err(),
            Some(ConfigError::Length {
                key: SectionKey::Psk,
                len: 64
            })
        );
        for lower in ["ca", "Ca", "cA", "C1", "1A", "É"] {
            assert!(Country::new(lower).is_err(), "{lower}");
        }
        assert_eq!(Country::new("ca"), Err(ConfigError::CountryNotCapitals));
        for bad in [
            "-cabin", "cabin-", "-", "ca bin", "ca_bin", "cabin.", "cabañ",
        ] {
            assert_eq!(Hostname::new(bad), Err(ConfigError::NotAHostname), "{bad}");
        }
        assert!(Hostname::new("a").is_ok());
        assert!(Hostname::new("cabin-89").is_ok());

        // The same refusals reached through the decoder a controller runs on a
        // `SetConfig`, each answered with outcome 3.
        for (body, want) in [
            (
                &[0xa1, 1, 0x60][..],
                ConfigError::Length {
                    key: SectionKey::SiteName,
                    len: 0,
                },
            ),
            (
                &[0xa2, 4, 0x62, b'c', b'a', 5, 0x61, b'o'],
                ConfigError::CountryNotCapitals,
            ),
            (
                &[0xa2, 4, 0x62, b'C', b'A', 5, 0x61, b'-'],
                ConfigError::NotAHostname,
            ),
            (
                &[
                    0xa3, 2, 0x68, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', 4, 0x62, b'C',
                    b'A', 5, 0x61, b'o',
                ],
                ConfigError::PassphraseWithoutNetwork,
            ),
            (
                &[
                    0xa4, 1, 0x61, b'c', 3, 0xf5, 4, 0x62, b'C', b'A', 5, 0x61, b'o',
                ],
                ConfigError::ConfigOnly(SectionKey::PskSet),
            ),
            (
                &[
                    0xa4, 1, 0x61, b'c', 2, 0x61, b'p', 4, 0x62, b'C', b'A', 5, 0x61, b'o',
                ],
                ConfigError::Length {
                    key: SectionKey::Psk,
                    len: 1,
                },
            ),
        ] {
            let got = if body.get(1) == Some(&1) && body.first() == Some(&0xa1) {
                IdentitySection::decode(body).err()
            } else {
                NetworkWrite::decode(body).err()
            };
            assert_eq!(got, Some(want), "{body:02x?}");
            assert_eq!(want.answer(), SectionRefusal::Outcome(SetConfig::Invalid));
        }
    }

    /// A body that is not the schema's shape is error 1 like any other body
    /// (P-015), and the structure is judged before any value: a repeated key
    /// after a bad value is still the repeat that answers.
    #[test]
    fn p_101_a_body_of_the_wrong_shape_is_error_1_not_an_outcome() {
        for (got, want) in [
            (
                IdentitySection::decode(&[0xa0]),
                ConfigError::Missing(SectionKey::SiteName),
            ),
            (
                IdentitySection::decode(&[0xa2, 1, 0x60, 1, 0x61, b'x']),
                ConfigError::Duplicate(SectionKey::SiteName),
            ),
            (
                IdentitySection::decode(&[0xa1, 1, 0x01]),
                ConfigError::Cbor(CborError::WrongType),
            ),
        ] {
            assert_eq!(got, Err(want));
            assert_eq!(
                want.answer(),
                SectionRefusal::Error(ErrorCode::MalformedFrame)
            );
        }
        for (body, want) in [
            (
                &[0xa1, 5, 0x61, b'o'][..],
                ConfigError::Missing(SectionKey::Country),
            ),
            (
                &[0xa1, 4, 0x62, b'C', b'A'],
                ConfigError::Missing(SectionKey::Hostname),
            ),
            (
                &[0xa3, 4, 0x62, b'c', b'a', 5, 0x61, b'o', 5, 0x61, b'o'],
                ConfigError::Duplicate(SectionKey::Hostname),
            ),
            (
                &[0xa3, 1, 0x60, 1, 0x60, 4, 0x62, b'C', b'A'],
                ConfigError::Duplicate(SectionKey::Ssid),
            ),
            (&[0xa1, 4, 0x02], ConfigError::Cbor(CborError::WrongType)),
        ] {
            assert_eq!(NetworkWrite::decode(body), Err(want), "{body:02x?}");
            assert_eq!(NetworkRead::decode(body), Err(want), "{body:02x?}");
        }
    }

    /// The `shadow` key is the registry's number, the same in every behaviour
    /// section, and a behaviour body without it is refused rather than read as
    /// live or as shadowed. Either guess is wrong at some site: *live* turns a
    /// body a newer client trimmed into actuation, *shadowed* makes an audit
    /// report nothing happening where something is.
    #[test]
    fn p_103_shadow_is_one_registry_key_and_never_defaulted() {
        assert_eq!(BehaviourKey::Shadow as u16, 1);
        assert_eq!(SectionKey::Shadow.number(), 1);
        let on = Encoded::of(|dst| BehaviourSection { shadow: true }.encode(dst));
        assert_eq!(on.body(), &[0xa1, 1, 0xf5]);
        let off = Encoded::of(|dst| BehaviourSection { shadow: false }.encode(dst));
        assert_eq!(off.body(), &[0xa1, 1, 0xf4]);

        assert_eq!(
            BehaviourSection::decode(&[0xa0]),
            Err(ConfigError::Missing(SectionKey::Shadow))
        );
        assert_eq!(
            BehaviourSection::decode(&[0xa1, 2, 0xf5]),
            Err(ConfigError::Missing(SectionKey::Shadow)),
            "another key's true is not shadow"
        );
        assert_eq!(
            BehaviourSection::decode(&[0xa1, 1, 0x01]),
            Err(ConfigError::Cbor(CborError::WrongType)),
            "1 is not true"
        );
        assert_eq!(
            BehaviourSection::decode(&[0xa2, 1, 0xf5, 1, 0xf4]),
            Err(ConfigError::Duplicate(SectionKey::Shadow))
        );
        // The parameters each behaviour will carry, whatever they turn out to
        // be, do not stop this build reading the one key they share.
        assert_eq!(
            BehaviourSection::decode(&[0xa3, 2, 0x19, 0x30, 0x39, 1, 0xf5, 3, 0x81, 0]),
            Ok(BehaviourSection { shadow: true })
        );
    }

    /// The read shape has nowhere to put a passphrase, so what the controller
    /// encodes from it never carries key 2; a client refuses a body that does,
    /// whatever type the leak arrived as.
    #[test]
    fn p_106_a_config_body_cannot_carry_the_passphrase_and_one_that_does_is_refused() {
        let encoded = Encoded::of(|dst| widest_read().encode(dst));
        let mut cbor = CborReader::new(encoded.body());
        let mut keys = [0; 4];
        for slot in keys.iter_mut().take(cbor.map().expect("a map")) {
            *slot = cbor.key().expect("a key");
            cbor.skip().expect("a value");
        }
        assert_eq!(
            keys,
            [1, 3, 4, 5],
            "key 2 is never written in a Config body"
        );

        // A controller that leaks, in any type it might leak as.
        for body in [
            &[
                0xa5, 1, 0x61, b'c', 2, 0x68, b'h', b'u', b'n', b't', b'e', b'r', b'2', b'2', 3,
                0xf5, 4, 0x62, b'C', b'A', 5, 0x61, b'o',
            ][..],
            &[
                0xa5, 1, 0x61, b'c', 2, 0x61, b'*', 3, 0xf5, 4, 0x62, b'C', b'A', 5, 0x61, b'o',
            ],
            &[
                0xa5, 1, 0x61, b'c', 2, 0x41, 0, 3, 0xf5, 4, 0x62, b'C', b'A', 5, 0x61, b'o',
            ],
            &[0xa3, 2, 0x00, 4, 0x62, b'C', b'A', 5, 0x61, b'o'],
        ] {
            assert_eq!(
                NetworkRead::decode(body),
                Err(ConfigError::SecretInConfig(SectionKey::Psk)),
                "{body:02x?}"
            );
        }
        assert_eq!(
            ConfigError::SecretInConfig(SectionKey::Psk).answer(),
            SectionRefusal::Error(ErrorCode::MalformedFrame)
        );

        // Presence is its own key, present exactly when there is a network.
        assert_eq!(
            NetworkRead::decode(&[0xa3, 3, 0xf5, 4, 0x62, b'C', b'A', 5, 0x61, b'o']),
            Err(ConfigError::PassphraseWithoutNetwork)
        );
        assert_eq!(
            NetworkRead::decode(&[0xa3, 1, 0x61, b'c', 4, 0x62, b'C', b'A', 5, 0x61, b'o']),
            Err(ConfigError::Missing(SectionKey::PskSet))
        );

        // And a passphrase does not leak through `{:?}` on its way to a log.
        let debugged = Rendering::<256>::debugged(&cabin());
        assert!(
            !debugged.bytes().windows(13).any(|w| w == b"correct horse"),
            "Debug printed the passphrase"
        );
        let debugged = Rendering::<32>::debugged(&Passphrase::new("correct horse").expect("ok"));
        assert_eq!(debugged.bytes(), b"Passphrase(13 bytes)");
    }

    /// Keeping the held passphrase is for the network it was given for and no
    /// other. `Cabin` is not `cabin`, and a trailing space is another network.
    #[test]
    fn p_107_a_write_without_a_passphrase_keeps_one_only_for_the_same_ssid() {
        let keep = NetworkWrite {
            join: Some(JoinWrite {
                ssid: Ssid::new("cabin").expect("an ssid"),
                psk: None,
            }),
            ..cabin()
        };
        let held = |text| Some(Ssid::new(text).expect("an ssid"));
        assert_eq!(keep.passphrase(held("cabin")), Ok(PassphraseChange::Keep));
        for other in ["Cabin", "cabin ", "cabin2", "cabi"] {
            assert_eq!(
                keep.passphrase(held(other)),
                Err(ConfigError::PassphraseForAnotherNetwork),
                "{other}"
            );
        }
        assert_eq!(keep.passphrase(None), Err(ConfigError::NoPassphraseHeld));

        let set = cabin();
        let given = Passphrase::new("correct horse").expect("ok");
        assert_eq!(set.passphrase(None), Ok(PassphraseChange::Set(given)));
        assert_eq!(
            set.passphrase(held("elsewhere")),
            Ok(PassphraseChange::Set(given))
        );

        let clear = NetworkWrite {
            join: None,
            ..cabin()
        };
        assert_eq!(clear.passphrase(held("cabin")), Ok(PassphraseChange::Clear));
        assert_eq!(clear.passphrase(None), Ok(PassphraseChange::Clear));

        for refused in [
            ConfigError::NoPassphraseHeld,
            ConfigError::PassphraseForAnotherNetwork,
        ] {
            assert_eq!(
                refused.answer(),
                SectionRefusal::Outcome(SetConfig::Invalid)
            );
        }
    }

    /// A v2 sender adds a key; a v1 reader skips it (P-013) wherever it lands.
    #[test]
    fn p_013_unknown_keys_are_skipped_in_every_section_body() {
        let tail = [0x18, 99, 0x81, 0];
        let mut identity = Encoded::of(|dst| widest_identity().encode(dst));
        identity.bytes[0] += 1;
        identity.bytes[identity.len..identity.len + 4].copy_from_slice(&tail);
        identity.len += 4;
        assert_eq!(
            IdentitySection::decode(identity.body()),
            Ok(widest_identity())
        );

        let mut write = Encoded::of(|dst| cabin().encode(dst));
        write.bytes[0] += 1;
        write.bytes[write.len..write.len + 4].copy_from_slice(&tail);
        write.len += 4;
        assert_eq!(NetworkWrite::decode(write.body()), Ok(cabin()));

        let mut read = Encoded::of(|dst| widest_read().encode(dst));
        read.bytes[0] += 1;
        read.bytes[read.len..read.len + 4].copy_from_slice(&tail);
        read.len += 4;
        assert_eq!(NetworkRead::decode(read.body()), Ok(widest_read()));
    }

    /// The section is the master copy of what `NetConfig` pushes (L-130), and a
    /// value the controller accepted here has to be one the link accepts, or the
    /// radio refuses the network with `rejected_invalid` after the client was
    /// told the write succeeded.
    #[test]
    fn a_network_section_at_its_bounds_is_a_netconfig_the_link_accepts() {
        for write in [widest_write(), cabin()] {
            let Some(JoinWrite {
                ssid,
                psk: Some(psk),
            }) = write.join
            else {
                panic!("both fixtures carry a passphrase");
            };
            let change = NetChange::Set {
                version: 1,
                ssid: ssid.as_str(),
                psk: psk.as_str(),
                country: write.country.as_str(),
                hostname: write.hostname.as_str(),
            };
            let mut dst = [0; 256];
            let header = LinkHeader {
                kind: LinkMessageType::NetConfig,
                session: SessionId::None,
                req_id: ReqId(1),
            };
            let len = change.write(header, &mut dst).expect("the link accepts it");
            let envelope = LinkEnvelope::decode(&dst[..len]).expect("an envelope");
            assert_eq!(NetChange::decode(envelope), Ok(change));
        }
    }

    #[test]
    fn refusals_render_each_a_sentence_of_its_own() {
        let errors = [
            ConfigError::Missing(SectionKey::SiteName),
            ConfigError::Missing(SectionKey::Shadow),
            ConfigError::Missing(SectionKey::PskSet),
            ConfigError::Duplicate(SectionKey::Ssid),
            ConfigError::Cbor(CborError::WrongType),
            ConfigError::Length {
                key: SectionKey::Psk,
                len: 7,
            },
            ConfigError::Length {
                key: SectionKey::Hostname,
                len: 7,
            },
            ConfigError::CountryNotCapitals,
            ConfigError::NotAHostname,
            ConfigError::PassphraseWithoutNetwork,
            ConfigError::ConfigOnly(SectionKey::PskSet),
            ConfigError::SecretInConfig(SectionKey::Psk),
            ConfigError::NoPassphraseHeld,
            ConfigError::PassphraseForAnotherNetwork,
        ];
        Rendering::<100>::each_says_something_of_its_own(&errors);
    }
}
