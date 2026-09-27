//! Whose network a comms cache holds, which a version alone cannot say.
//!
//! Two caches can report the version the controller holds and still carry
//! credentials it never wrote: a board out of another unit, and a board that
//! was unplugged while this controller repaired its own section and counted
//! back up from 1. The origin token drawn when the section is created (L-138)
//! is what tells them apart, and [`NetStamp`] is the pair both chips compare.

use core::num::NonZeroU32;

use crate::generated::NetConfig;
use crate::linklocal::{LinkError, LinkUp, NetChange, NetVerdict};

/// The width of the origin token `NetConfig` key 7 and `LinkUp` key 9 carry.
pub const NET_ORIGIN_BYTES: usize = 8;

/// The token the controller draws from P-237 when it creates its network
/// section from version 0, and keeps through every later write of it (L-138).
///
/// Not a secret: it names a configuration and grants nothing, so it may be
/// printed where a passphrase must not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetOrigin([u8; NET_ORIGIN_BYTES]);

impl NetOrigin {
    /// Wrap eight bytes drawn from the random bit generator.
    #[must_use]
    pub const fn new(bytes: [u8; NET_ORIGIN_BYTES]) -> Self {
        Self(bytes)
    }

    /// The bytes as they travel.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; NET_ORIGIN_BYTES] {
        &self.0
    }
}

impl TryFrom<&[u8]> for NetOrigin {
    type Error = LinkError;

    /// Refuses any other length rather than padding: a token cut or padded to
    /// fit is one no section was ever created with.
    fn try_from(bytes: &[u8]) -> Result<Self, LinkError> {
        <[u8; NET_ORIGIN_BYTES]>::try_from(bytes)
            .map(Self)
            .map_err(|_| LinkError::OriginNotEight(bytes.len()))
    }
}

/// Whether a failed NVS write left the record as it was (L-137).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NvsWrite {
    /// The record, version and token together, is in flash.
    Durable,
    /// The write or erase did not complete; flash still holds what it held.
    Failed,
}

/// The version and origin token of a written network section, or its absence.
///
/// On the controller this is the master (L-130); on the comms processor it is
/// what NVS holds, never what RAM holds, because after a failed write the two
/// differ and only the flash survives the next reboot (L-132, L-137).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetStamp {
    /// Never written or unreadable on the controller (P-108); an empty cache or
    /// a durably stored unwritten clear on the comms processor (L-132).
    Unwritten,
    /// A written section. A clear keeps the section, so it is one of these.
    Written {
        /// The section's version, never 0 once written.
        version: NonZeroU32,
        /// The token drawn when the section was created (L-138).
        origin: NetOrigin,
    },
}

impl NetStamp {
    /// What a change leaves in the cache once it is durably stored.
    ///
    /// # Errors
    /// A `Set` or `Clear` at version 0, which no decoder hands out.
    pub fn of(change: &NetChange<'_>) -> Result<Self, LinkError> {
        let (version, origin) = match change {
            NetChange::ClearUnwritten => return Ok(Self::Unwritten),
            NetChange::Set {
                version, origin, ..
            }
            | NetChange::Clear {
                version, origin, ..
            } => (*version, *origin),
        };
        let version = NonZeroU32::new(version).ok_or(LinkError::ZeroNetworkVersion)?;
        Ok(Self::Written { version, origin })
    }

    /// `LinkUp` key 7 and `NetConfigAck` key 2: 0 for no written network.
    #[must_use]
    pub const fn net_version(self) -> u32 {
        match self {
            Self::Unwritten => 0,
            Self::Written { version, .. } => version.get(),
        }
    }

    /// `LinkUp` key 9, absent exactly when the version is 0 (L-132).
    #[must_use]
    pub const fn net_origin(self) -> Option<NetOrigin> {
        match self {
            Self::Unwritten => None,
            Self::Written { origin, .. } => Some(origin),
        }
    }

    /// Whether the controller holding this master must push `NetConfig` after
    /// the comms processor's `LinkUp` (L-133).
    ///
    /// A written master compares version and token, and a cache with no token
    /// is a different one. An unwritten master has no token and compares the
    /// version alone. A `LinkUp` with no `net_version` matches nothing.
    #[must_use]
    pub fn needs_push(self, cache: &LinkUp<'_>) -> bool {
        match self {
            Self::Unwritten => cache.net_version != Some(0),
            Self::Written { version, origin } => {
                cache.net_version != Some(version.get()) || cache.net_origin != Some(origin)
            }
        }
    }

    /// What the comms processor holds and answers after trying to store
    /// `change` (L-132, L-137).
    ///
    /// A failed write keeps this stamp and reports it, so the next `LinkUp`
    /// shows the controller the version and token flash still holds.
    ///
    /// # Errors
    /// A `Set` or `Clear` at version 0, which no decoder hands out.
    pub fn settle(
        self,
        change: &NetChange<'_>,
        write: NvsWrite,
    ) -> Result<(Self, NetVerdict), LinkError> {
        let (held, outcome) = match write {
            NvsWrite::Durable => (Self::of(change)?, NetConfig::Stored),
            NvsWrite::Failed => (self, NetConfig::NvsWriteFailed),
        };
        Ok((
            held,
            NetVerdict {
                outcome,
                version: held.net_version(),
            },
        ))
    }
}
