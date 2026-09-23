//! `GetConfig 0x06` / `Config 0x86` and `SetConfig 0x07` / `SetConfigAck 0x87`
//! — reading a configuration section and writing one.
//!
//! The section body travels as its own bytes, exactly as they arrived, and is
//! read by the section's type in `config.rs` once the message around it has
//! decoded. [`SetConfigOperation`] is key 3 of a signed body: the MAC covers
//! these bytes as they arrived, so the controller hands [`SetConfigOperation::body`]
//! to the section decoder and never a re-encoding.
//!
//! A section nobody has written is `version` 0 with no body at all (P-108), and
//! [`ConfigAnswer::new`] refuses to build either half of that without the
//! other.
//!
//! cites: P-013, P-015, P-100, P-101, P-108

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::config::MAX_NETWORK_WRITE_BYTES;
use crate::envelope::Refusal;
use crate::generated::{ConfigSection, ErrorCode, SetConfig};
use crate::limits::MAX_OPERATION;

/// `GetConfig 0x06`: the map head, a key and a `u16` section.
pub const MAX_GET_CONFIG_BYTES: usize = 5;

/// `SetConfigAck 0x87` at its widest: the map head, three keys, a `u16`
/// section, a `u32` version and a one-byte outcome.
pub const MAX_SET_CONFIG_ACK_BYTES: usize = 13;

/// Everything in a `Config` or `SetConfig` operation ahead of the section's
/// body: the map head, a `u16` section, a `u32` version and key 3. A caller
/// sizes its buffer as this plus the section's own cap.
pub const CONFIG_HEADER_BYTES: usize = 12;

// The widest section this crate knows fits a signed operation.
const_assert!(CONFIG_HEADER_BYTES + MAX_NETWORK_WRITE_BYTES <= MAX_OPERATION);

/// A key of one of the four configuration messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConfigMessageKey {
    /// Key 1 of all four.
    Section,
    /// Key 2 of `Config` and `SetConfigAck`.
    Version,
    /// Key 2 of the `SetConfig` operation.
    ExpectedVersion,
    /// Key 3 of `Config` and the `SetConfig` operation.
    Body,
    /// Key 3 of `SetConfigAck`.
    Outcome,
}

impl ConfigMessageKey {
    const fn number(self) -> i64 {
        match self {
            Self::Section => 1,
            Self::Version | Self::ExpectedVersion => 2,
            Self::Body | Self::Outcome => 3,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Section => "section",
            Self::Version => "version",
            Self::ExpectedVersion => "expected_version",
            Self::Body => "body",
            Self::Outcome => "outcome",
        }
    }
}

impl fmt::Display for ConfigMessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (key {})", self.name(), self.number())
    }
}

/// `GetConfig 0x06`: which section a client wants to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GetConfigRequest {
    /// Key 1.
    pub section: ConfigSection,
}

impl GetConfigRequest {
    /// Encode the request body. The caller wraps it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, ConfigMessageError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(1)?;
        section(&mut cbor, self.section)?;
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered. A section
    /// the registry does not allocate is error 6 (P-101).
    pub fn decode(payload: &[u8]) -> Result<Self, ConfigMessageError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        let mut found = None;
        for _ in 0..pairs {
            match body.key()? {
                1 => once(
                    &mut found,
                    ConfigMessageKey::Section,
                    read_section(&mut body)?,
                )?,
                _ => body.skip()?,
            }
        }
        body.finish()?;
        Ok(Self {
            section: required(found, ConfigMessageKey::Section)?,
        })
    }
}

/// `Config 0x86`: a section's version and, once it has been written, its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConfigAnswer<'a> {
    section: ConfigSection,
    version: u32,
    body: Option<&'a [u8]>,
}

impl<'a> ConfigAnswer<'a> {
    /// `body` is `None` exactly when `version` is 0 (P-108), and is one CBOR
    /// map when present.
    pub fn new(
        section: ConfigSection,
        version: u32,
        body: Option<&'a [u8]>,
    ) -> Result<Self, ConfigMessageError> {
        match (version, body) {
            (0, None) => {}
            (0, Some(_)) => return Err(ConfigMessageError::UnwrittenWithBody),
            (_, None) => return Err(ConfigMessageError::WrittenWithoutBody),
            (_, Some(body)) => a_map(body)?,
        }
        Ok(Self {
            section,
            version,
            body,
        })
    }

    /// Key 1.
    #[must_use]
    pub const fn section(self) -> ConfigSection {
        self.section
    }

    /// Key 2.
    #[must_use]
    pub const fn version(self) -> u32 {
        self.version
    }

    /// Key 3, for the section's own decoder. `None` means never written.
    #[must_use]
    pub const fn body(self) -> Option<&'a [u8]> {
        self.body
    }

    /// Encode the answer. The caller wraps and MACs it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, ConfigMessageError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(if self.body.is_some() { 3 } else { 2 })?;
        section(&mut cbor, self.section)?;
        cbor.key(ConfigMessageKey::Version.number())?;
        cbor.u64(u64::from(self.version))?;
        if let Some(body) = self.body {
            cbor.key(ConfigMessageKey::Body.number())?;
            cbor.raw(body)?;
        }
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &'a [u8]) -> Result<Self, ConfigMessageError> {
        let mut read = CborReader::new(payload);
        let pairs = read.map()?;
        let (mut found, mut version, mut body) = (None, None, None);
        for _ in 0..pairs {
            match read.key()? {
                1 => once(
                    &mut found,
                    ConfigMessageKey::Section,
                    read_section(&mut read)?,
                )?,
                2 => once(&mut version, ConfigMessageKey::Version, read.u32()?)?,
                3 => once(&mut body, ConfigMessageKey::Body, read.raw()?)?,
                _ => read.skip()?,
            }
        }
        read.finish()?;
        Self::new(
            required(found, ConfigMessageKey::Section)?,
            required(version, ConfigMessageKey::Version)?,
            body,
        )
    }
}

/// The `SetConfig 0x07` operation: a whole section body, written against the
/// version the client last read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SetConfigOperation<'a> {
    /// Key 1.
    pub section: ConfigSection,
    /// Key 2, 0 for a section never written (P-108).
    pub expected_version: u32,
    /// Key 3: one CBOR map, its bytes exactly as they arrived.
    pub body: &'a [u8],
}

impl<'a> SetConfigOperation<'a> {
    /// Encode the operation body. The caller signs these bytes as key 3.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, ConfigMessageError> {
        a_map(self.body)?;
        let mut cbor = CborWriter::new(dst);
        cbor.map(3)?;
        section(&mut cbor, self.section)?;
        cbor.key(ConfigMessageKey::ExpectedVersion.number())?;
        cbor.u64(u64::from(self.expected_version))?;
        cbor.key(ConfigMessageKey::Body.number())?;
        cbor.raw(self.body)?;
        Ok(cbor.finish()?)
    }

    /// Read the operation out of a signed body whose tag has already verified.
    pub fn decode(operation: &'a [u8]) -> Result<Self, ConfigMessageError> {
        let mut read = CborReader::new(operation);
        let pairs = read.map()?;
        let (mut found, mut expected, mut body) = (None, None, None);
        for _ in 0..pairs {
            match read.key()? {
                1 => once(
                    &mut found,
                    ConfigMessageKey::Section,
                    read_section(&mut read)?,
                )?,
                2 => once(
                    &mut expected,
                    ConfigMessageKey::ExpectedVersion,
                    read.u32()?,
                )?,
                3 => {
                    let raw = read.raw()?;
                    a_map(raw)?;
                    once(&mut body, ConfigMessageKey::Body, raw)?;
                }
                _ => read.skip()?,
            }
        }
        read.finish()?;
        Ok(Self {
            section: required(found, ConfigMessageKey::Section)?,
            expected_version: required(expected, ConfigMessageKey::ExpectedVersion)?,
            body: required(body, ConfigMessageKey::Body)?,
        })
    }

    /// Whether this write was composed against the version the section holds
    /// now (P-100). A mismatch is `stale_version`: somebody else wrote first,
    /// and storing this one would undo their write without either of them
    /// seeing it happen.
    pub const fn check_version(self, current: u32) -> Result<(), SetConfig> {
        if self.expected_version == current {
            Ok(())
        } else {
            Err(SetConfig::StaleVersion)
        }
    }
}

/// The body's length, never the body: a network write carries the passphrase,
/// and a derived `Debug` prints it as decimals no text search finds (P-106).
impl fmt::Debug for SetConfigOperation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetConfigOperation")
            .field("section", &self.section)
            .field("expected_version", &self.expected_version)
            .field("body", &format_args!("{} bytes", self.body.len()))
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SetConfigOperation<'_> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "SetConfigOperation {{ section: {}, expected_version: {=u32}, body: {=usize} bytes }}",
            self.section,
            self.expected_version,
            self.body.len()
        );
    }
}

/// `SetConfigAck 0x87`: what became of a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SetConfigAck {
    /// Key 1.
    pub section: ConfigSection,
    /// Key 2.
    pub version: u32,
    /// Key 3.
    pub outcome: SetConfig,
}

impl SetConfigAck {
    /// Encode the ack body. The caller wraps and MACs it.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, ConfigMessageError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(3)?;
        section(&mut cbor, self.section)?;
        cbor.key(ConfigMessageKey::Version.number())?;
        cbor.u64(u64::from(self.version))?;
        cbor.key(ConfigMessageKey::Outcome.number())?;
        cbor.u64(self.outcome as u64)?;
        Ok(cbor.finish()?)
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    pub fn decode(payload: &[u8]) -> Result<Self, ConfigMessageError> {
        let mut read = CborReader::new(payload);
        let pairs = read.map()?;
        let (mut found, mut version, mut outcome) = (None, None, None);
        for _ in 0..pairs {
            match read.key()? {
                1 => once(
                    &mut found,
                    ConfigMessageKey::Section,
                    read_section(&mut read)?,
                )?,
                2 => once(&mut version, ConfigMessageKey::Version, read.u32()?)?,
                3 => {
                    let number = read.u8()?;
                    let value = SetConfig::try_from(number)
                        .map_err(|()| ConfigMessageError::UnknownOutcome(number))?;
                    once(&mut outcome, ConfigMessageKey::Outcome, value)?;
                }
                _ => read.skip()?,
            }
        }
        read.finish()?;
        Ok(Self {
            section: required(found, ConfigMessageKey::Section)?,
            version: required(version, ConfigMessageKey::Version)?,
            outcome: required(outcome, ConfigMessageKey::Outcome)?,
        })
    }
}

fn section(cbor: &mut CborWriter<'_>, section: ConfigSection) -> Result<(), CborError> {
    cbor.key(ConfigMessageKey::Section.number())?;
    cbor.u64(section as u64)
}

fn read_section(read: &mut CborReader<'_>) -> Result<ConfigSection, ConfigMessageError> {
    let number = read.u16()?;
    ConfigSection::try_from(number).map_err(|()| ConfigMessageError::UnknownSection(number))
}

/// A section body is one map, whatever the section. A key it carries twice is
/// refused by the walk that reads it (P-015).
fn a_map(body: &[u8]) -> Result<(), ConfigMessageError> {
    let mut probe = CborReader::new(body);
    probe.map().map_err(|_| ConfigMessageError::BodyNotAMap)?;
    Ok(())
}

fn once<T>(
    slot: &mut Option<T>,
    key: ConfigMessageKey,
    value: T,
) -> Result<(), ConfigMessageError> {
    if slot.is_some() {
        return Err(ConfigMessageError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

fn required<T>(slot: Option<T>, key: ConfigMessageKey) -> Result<T, ConfigMessageError> {
    slot.ok_or(ConfigMessageError::Missing(key))
}

/// Why a configuration message was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConfigMessageError {
    /// A required key never arrived (P-015).
    Missing(ConfigMessageKey),
    /// The same key twice (P-015).
    Duplicate(ConfigMessageKey),
    /// A section the registry does not allocate (P-101).
    UnknownSection(u16),
    /// A `SetConfig` outcome the registry does not allocate.
    UnknownOutcome(u8),
    /// Key 3 is not a map.
    BodyNotAMap,
    /// Version 0 with a body: a section never written that claims contents.
    UnwrittenWithBody,
    /// A written version with no body (P-108).
    WrittenWithoutBody,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl From<CborError> for ConfigMessageError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl ConfigMessageError {
    /// What to answer. A section nobody allocated is error 6, because it never
    /// reaches a handler (P-101); everything else is a message whose meaning
    /// cannot be read, error 1.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::UnknownSection(_) => Refusal::Client(ErrorCode::UnknownSection),
            Self::Missing(_)
            | Self::Duplicate(_)
            | Self::UnknownOutcome(_)
            | Self::BodyNotAMap
            | Self::UnwrittenWithBody
            | Self::WrittenWithoutBody
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
        }
    }
}

impl fmt::Display for ConfigMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "config message carries no {key}"),
            Self::Duplicate(key) => write!(f, "config message carries {key} twice"),
            Self::UnknownSection(number) => write!(f, "unallocated config section {number:#06x}"),
            Self::UnknownOutcome(number) => write!(f, "unallocated SetConfigAck outcome {number}"),
            Self::BodyNotAMap => f.write_str("config section body is not a map"),
            Self::UnwrittenWithBody => f.write_str("Config version 0 carries a body"),
            Self::WrittenWithoutBody => f.write_str("Config written version carries no body"),
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for ConfigMessageError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Country, Hostname, JoinWrite, NetworkWrite, Passphrase, Ssid};
    use crate::render::Rendering;

    const SECTIONS: [ConfigSection; 9] = [
        ConfigSection::IdentityAndSite,
        ConfigSection::Channels,
        ConfigSection::BusesAndDevices,
        ConfigSection::GeneratorBehaviour,
        ConfigSection::FrostBehaviour,
        ConfigSection::ScheduleBehaviour,
        ConfigSection::LoadShedBehaviour,
        ConfigSection::Network,
        ConfigSection::Cloud,
    ];

    const OUTCOMES: [SetConfig; 6] = [
        SetConfig::Accepted,
        SetConfig::StaleVersion,
        SetConfig::Invalid,
        SetConfig::Unauthorised,
        SetConfig::ExceedsCap,
        SetConfig::Staged,
    ];

    /// `{1: "x"}`, a section body as small as one gets.
    const BODY: &[u8] = &[0xa1, 1, 0x61, b'x'];

    struct Encoded {
        bytes: [u8; 64],
        len: usize,
    }

    impl Encoded {
        fn of(encode: impl FnOnce(&mut [u8]) -> Result<usize, ConfigMessageError>) -> Self {
            let mut bytes = [0; 64];
            let len = encode(&mut bytes).expect("fits");
            Self { bytes, len }
        }

        fn body(&self) -> &[u8] {
            self.bytes.get(..self.len).expect("within the buffer")
        }
    }

    /// Every section, both ends of every version width, every outcome: each
    /// message comes back as it went.
    #[test]
    fn every_message_round_trips_over_every_section_version_and_outcome() {
        for section in SECTIONS {
            let get = GetConfigRequest { section };
            let encoded = Encoded::of(|dst| get.encode(dst));
            assert_eq!(GetConfigRequest::decode(encoded.body()), Ok(get));

            for version in [1, 23, 24, 0xFFFF, 0x1_0000, u32::MAX] {
                let answer = ConfigAnswer::new(section, version, Some(BODY)).expect("valid");
                let encoded = Encoded::of(|dst| answer.encode(dst));
                assert_eq!(ConfigAnswer::decode(encoded.body()), Ok(answer));
                let section_len = len_u32(section as u32);
                assert_eq!(
                    encoded.len,
                    1 + (1 + section_len) + (1 + len_u32(version)) + 1 + BODY.len()
                );

                let write = SetConfigOperation {
                    section,
                    expected_version: version,
                    body: BODY,
                };
                let encoded = Encoded::of(|dst| write.encode(dst));
                assert_eq!(SetConfigOperation::decode(encoded.body()), Ok(write));

                for outcome in OUTCOMES {
                    let ack = SetConfigAck {
                        section,
                        version,
                        outcome,
                    };
                    let encoded = Encoded::of(|dst| ack.encode(dst));
                    assert_eq!(SetConfigAck::decode(encoded.body()), Ok(ack));
                }
            }
        }
    }

    /// The CBOR bytes a `u32` takes, head included.
    fn len_u32(value: u32) -> usize {
        match value {
            0..=23 => 1,
            24..=0xFF => 2,
            0x100..=0xFFFF => 3,
            _ => 5,
        }
    }

    /// The caps are what a firmware sizes buffers from, and they hold a
    /// section at full `u16` width. The widest section allocated today, `0x0021`,
    /// takes one byte less, so the widest message today is one byte under each
    /// cap; a section allocated above `0x00FF` fills it. One byte less than a
    /// message's length is refused rather than written short.
    #[test]
    fn the_widest_messages_sit_one_byte_under_their_caps_and_a_short_buffer_refuses() {
        let get = GetConfigRequest {
            section: ConfigSection::Cloud,
        };
        let ack = SetConfigAck {
            section: ConfigSection::Cloud,
            version: u32::MAX,
            outcome: SetConfig::Staged,
        };
        let write = SetConfigOperation {
            section: ConfigSection::Cloud,
            expected_version: u32::MAX,
            body: BODY,
        };
        let cases: [(usize, &Encoder<'_>); 3] = [
            (MAX_GET_CONFIG_BYTES, &|dst| get.encode(dst)),
            (MAX_SET_CONFIG_ACK_BYTES, &|dst| ack.encode(dst)),
            (CONFIG_HEADER_BYTES + BODY.len(), &|dst| write.encode(dst)),
        ];
        for (cap, encode) in cases {
            let encoded = Encoded::of(encode);
            assert_eq!(encoded.len + 1, cap);
            for short in 0..encoded.len {
                let mut dst = [0; 64];
                let room = dst.get_mut(..short).expect("shorter than the cap");
                assert!(encode(room).is_err(), "cap {cap} accepted {short}");
            }
        }
    }

    type Encoder<'a> = dyn Fn(&mut [u8]) -> Result<usize, ConfigMessageError> + 'a;

    /// Whether one message's decoder refuses these bytes.
    type Refuses = dyn Fn(&[u8]) -> bool;

    /// Every cut of every message is refused, and a byte past the end too.
    #[test]
    fn every_truncation_and_a_trailing_byte_is_refused() {
        let answer = ConfigAnswer::new(ConfigSection::Network, 7, Some(BODY)).expect("valid");
        let unwritten = ConfigAnswer::new(ConfigSection::Network, 0, None).expect("valid");
        let messages = [
            Encoded::of(|dst| {
                GetConfigRequest {
                    section: ConfigSection::Network,
                }
                .encode(dst)
            }),
            Encoded::of(|dst| answer.encode(dst)),
            Encoded::of(|dst| unwritten.encode(dst)),
            Encoded::of(|dst| {
                SetConfigOperation {
                    section: ConfigSection::Network,
                    expected_version: 7,
                    body: BODY,
                }
                .encode(dst)
            }),
            Encoded::of(|dst| {
                SetConfigAck {
                    section: ConfigSection::Network,
                    version: 8,
                    outcome: SetConfig::Accepted,
                }
                .encode(dst)
            }),
        ];
        let decoders: [&Refuses; 5] = [
            &|b| GetConfigRequest::decode(b).is_err(),
            &|b| ConfigAnswer::decode(b).is_err(),
            &|b| ConfigAnswer::decode(b).is_err(),
            &|b| SetConfigOperation::decode(b).is_err(),
            &|b| SetConfigAck::decode(b).is_err(),
        ];
        for (encoded, refused) in messages.iter().zip(decoders) {
            for cut in 0..encoded.len {
                assert!(refused(&encoded.bytes[..cut]), "accepted a cut at {cut}");
            }
            assert!(refused(&encoded.bytes[..=encoded.len]), "a trailing byte");
        }
    }

    /// A write composed against any version but the current one is
    /// `stale_version`, including a first write racing one that landed.
    #[test]
    fn p_100_a_write_against_any_other_version_is_stale() {
        let write = |expected_version| SetConfigOperation {
            section: ConfigSection::Network,
            expected_version,
            body: BODY,
        };
        assert_eq!(write(4).check_version(4), Ok(()));
        assert_eq!(write(0).check_version(0), Ok(()));
        for (expected, current) in [(3, 4), (5, 4), (0, 1), (u32::MAX, 0), (4, u32::MAX)] {
            assert_eq!(
                write(expected).check_version(current),
                Err(SetConfig::StaleVersion),
                "{expected} against {current}"
            );
        }
        assert_eq!(SetConfig::StaleVersion as u8, 2);
    }

    /// A section nobody allocated never reaches a handler, so it is error 6
    /// wherever it appears; one the registry allocates, reserved or live,
    /// decodes and reaches the handler that answers for it.
    #[test]
    fn p_101_an_unallocated_section_is_error_6_in_every_message() {
        // Zero, the gap below the behaviours, and the gap above the network,
        // each in the one-byte form a small number takes.
        for number in [0u8, 4, 0x14] {
            assert_eq!(
                GetConfigRequest::decode(&[0xa1, 1, number]),
                Err(ConfigMessageError::UnknownSection(u16::from(number)))
            );
        }
        // The rest in the two-byte form, in every message.
        for number in [0x18u8, 0x22, 0x30, 0xff] {
            let get = [0xa1, 1, 0x18, number];
            assert_eq!(
                GetConfigRequest::decode(&get),
                Err(ConfigMessageError::UnknownSection(u16::from(number)))
            );
            let answer = [0xa2, 1, 0x18, number, 2, 0];
            assert_eq!(
                ConfigAnswer::decode(&answer),
                Err(ConfigMessageError::UnknownSection(u16::from(number)))
            );
            let write = [0xa3, 1, 0x18, number, 2, 0, 3, 0xa0];
            assert_eq!(
                SetConfigOperation::decode(&write),
                Err(ConfigMessageError::UnknownSection(u16::from(number)))
            );
            let ack = [0xa3, 1, 0x18, number, 2, 0, 3, 1];
            assert_eq!(
                SetConfigAck::decode(&ack),
                Err(ConfigMessageError::UnknownSection(u16::from(number)))
            );
        }
        assert_eq!(
            ConfigMessageError::UnknownSection(4).refusal(),
            Refusal::Client(ErrorCode::UnknownSection)
        );
        assert_eq!(
            GetConfigRequest::decode(&[0xa1, 1, 0x19, 0x01, 0x00]),
            Err(ConfigMessageError::UnknownSection(0x100))
        );
        assert_eq!(
            GetConfigRequest::decode(&[0xa1, 1, 0x11]),
            Ok(GetConfigRequest {
                section: ConfigSection::FrostBehaviour
            })
        );
    }

    /// *Never written* is version 0 and no body, and neither half without the
    /// other: a body at version 0 is contents nobody wrote, and a written
    /// version with no body is a configuration the client cannot see.
    #[test]
    fn p_108_version_0_and_an_absent_body_come_together_or_not_at_all() {
        let unwritten = ConfigAnswer::new(ConfigSection::IdentityAndSite, 0, None).expect("valid");
        assert_eq!(unwritten.body(), None);
        let encoded = Encoded::of(|dst| unwritten.encode(dst));
        assert_eq!(
            encoded.body(),
            &[0xa2, 1, 1, 2, 0],
            "key 3 is absent, not empty"
        );
        assert_eq!(ConfigAnswer::decode(encoded.body()), Ok(unwritten));

        assert_eq!(
            ConfigAnswer::new(ConfigSection::IdentityAndSite, 0, Some(BODY)),
            Err(ConfigMessageError::UnwrittenWithBody)
        );
        assert_eq!(
            ConfigAnswer::new(ConfigSection::IdentityAndSite, 1, None),
            Err(ConfigMessageError::WrittenWithoutBody)
        );
        assert_eq!(
            ConfigAnswer::decode(&[0xa3, 1, 1, 2, 0, 3, 0xa0]),
            Err(ConfigMessageError::UnwrittenWithBody),
            "an empty map is still a body"
        );
        assert_eq!(
            ConfigAnswer::decode(&[0xa2, 1, 1, 2, 1]),
            Err(ConfigMessageError::WrittenWithoutBody)
        );
        for error in [
            ConfigMessageError::UnwrittenWithBody,
            ConfigMessageError::WrittenWithoutBody,
        ] {
            assert_eq!(error.refusal(), Refusal::Client(ErrorCode::MalformedFrame));
        }
    }

    #[test]
    fn p_015_missing_repeated_and_misshapen_keys_are_refused() {
        use ConfigMessageError::{BodyNotAMap, Duplicate, Missing, UnknownOutcome};
        use ConfigMessageKey::{Body, ExpectedVersion, Outcome, Section, Version};
        assert_eq!(GetConfigRequest::decode(&[0xa0]), Err(Missing(Section)));
        assert_eq!(
            GetConfigRequest::decode(&[0xa2, 1, 1, 1, 1]),
            Err(Duplicate(Section))
        );
        assert_eq!(ConfigAnswer::decode(&[0xa1, 1, 1]), Err(Missing(Version)));
        assert_eq!(
            ConfigAnswer::decode(&[0xa3, 1, 1, 2, 1, 2, 1]),
            Err(Duplicate(Version))
        );
        assert_eq!(
            ConfigAnswer::decode(&[0xa3, 1, 1, 2, 1, 3, 0x01]),
            Err(BodyNotAMap)
        );
        assert_eq!(
            SetConfigOperation::decode(&[0xa2, 1, 1, 2, 0]),
            Err(Missing(Body))
        );
        assert_eq!(
            SetConfigOperation::decode(&[0xa2, 1, 1, 3, 0xa0]),
            Err(Missing(ExpectedVersion))
        );
        assert_eq!(
            SetConfigOperation::decode(&[0xa3, 1, 1, 2, 0, 3, 0x80]),
            Err(BodyNotAMap)
        );
        assert_eq!(
            SetConfigOperation::decode(&[0xa4, 1, 1, 2, 0, 3, 0xa0, 3, 0xa0]),
            Err(Duplicate(Body))
        );
        assert_eq!(
            SetConfigOperation {
                section: ConfigSection::Network,
                expected_version: 0,
                body: &[0x01],
            }
            .encode(&mut [0; 16]),
            Err(BodyNotAMap)
        );
        assert_eq!(
            SetConfigAck::decode(&[0xa2, 1, 1, 2, 0]),
            Err(Missing(Outcome))
        );
        for number in [0u8, 6, 7, 8, 10] {
            assert_eq!(
                SetConfigAck::decode(&[0xa3, 1, 1, 2, 0, 3, number]),
                Err(UnknownOutcome(number))
            );
        }
    }

    /// A v2 sender adds a key; a v1 reader skips it (P-013).
    #[test]
    fn p_013_unknown_keys_are_skipped_in_every_message() {
        assert_eq!(
            GetConfigRequest::decode(&[0xa2, 9, 0x81, 0, 1, 0x18, 0x20]),
            Ok(GetConfigRequest {
                section: ConfigSection::Network
            })
        );
        assert_eq!(
            ConfigAnswer::decode(&[0xa3, 1, 1, 2, 0, 9, 0xf5]),
            ConfigAnswer::new(ConfigSection::IdentityAndSite, 0, None)
        );
        assert_eq!(
            SetConfigOperation::decode(&[0xa4, 9, 0, 1, 1, 2, 0, 3, 0xa0]),
            Ok(SetConfigOperation {
                section: ConfigSection::IdentityAndSite,
                expected_version: 0,
                body: &[0xa0],
            })
        );
        assert_eq!(
            SetConfigAck::decode(&[0xa4, 1, 1, 2, 0, 3, 3, 9, 0x60]),
            Ok(SetConfigAck {
                section: ConfigSection::IdentityAndSite,
                version: 0,
                outcome: SetConfig::Invalid,
            })
        );
    }

    /// A network write whose passphrase is `PSK`, encoded as a client signs it.
    fn network_body(dst: &mut [u8]) -> &[u8] {
        let write = NetworkWrite {
            join: Some(JoinWrite {
                ssid: Ssid::new("cabin").expect("an ssid"),
                psk: Some(Passphrase::new(PSK).expect("a passphrase")),
            }),
            country: Country::new("CA").expect("a country"),
            hostname: Hostname::new("origin89").expect("a hostname"),
        };
        let len = write.encode(dst).expect("the write fits");
        dst.get(..len).expect("the length came from the encoder")
    }

    const PSK: &str = "correct horse battery";

    /// The body of a network write is the passphrase in CBOR, and a derived
    /// `Debug` prints it as a list of decimals no text search finds. One
    /// `debug!(?write)` on the controller puts the site's Wi-Fi credential in a
    /// log that P-106 kept it out of on the read side.
    #[test]
    fn p_106_a_set_config_operation_never_prints_its_body() {
        let mut body = [0; MAX_NETWORK_WRITE_BYTES];
        let write = SetConfigOperation {
            section: ConfigSection::Network,
            expected_version: 3,
            body: network_body(&mut body),
        };
        assert_eq!(Rendering::<512>::leak(&write, PSK), None);
    }

    #[test]
    fn refusals_render_each_a_sentence_of_its_own() {
        let errors = [
            ConfigMessageError::Missing(ConfigMessageKey::Section),
            ConfigMessageError::Missing(ConfigMessageKey::ExpectedVersion),
            ConfigMessageError::Duplicate(ConfigMessageKey::Body),
            ConfigMessageError::Duplicate(ConfigMessageKey::Outcome),
            ConfigMessageError::Duplicate(ConfigMessageKey::Version),
            ConfigMessageError::UnknownSection(4),
            ConfigMessageError::UnknownOutcome(0),
            ConfigMessageError::BodyNotAMap,
            ConfigMessageError::UnwrittenWithBody,
            ConfigMessageError::WrittenWithoutBody,
            ConfigMessageError::Cbor(CborError::WrongType),
        ];
        Rendering::<80>::each_says_something_of_its_own(&errors);
    }
}
