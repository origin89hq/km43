//! The one id space three messages share, and the zero none of them allocates.
//!
//! `dev`, `cmp`, `sig` and `cid` are all `u16`s that start at 1, for one reason
//! stated once here rather than in each message: 0 is spent as the end-of-paging
//! sentinel in `Inventory` key 4, `Readings` key 6 and `Concerns` key 4, and as
//! *from the beginning* in the requests that feed them.
//!
//! No `cites:` header. P-200 is the rule, and it is proved where the refusal
//! reaches a message — `readings.rs` and `concerns.rs` both have a test named
//! after it. A header here would claim the rule for a file with no test in it,
//! which is what P-143's entry in `traceability.toml` was written about.

use core::fmt;

/// A non-zero id: a `dev`, a `cmp`, a `sig` or a `cid`.
///
/// A driver that hands out `sig = 0` makes `next = 0` unreadable — a client
/// cannot tell *resume at signal 0* from *the selection is complete*, so it
/// either stops a page early and renders a dashboard missing the well-pump
/// circuit, or loops on page one for ever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id(u16);

impl Id {
    /// Refuses 0, which is the sentinel and never an id.
    pub const fn new(value: u16) -> Result<Self, IdError> {
        if value == 0 {
            return Err(IdError::Zero);
        }
        Ok(Self(value))
    }

    #[must_use]
    /// The number, never 0.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Why an id was refused. One variant, and each message restates it in its own
/// vocabulary rather than carrying this type into its error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// 0 handed to a space that reserves it as the paging sentinel.
    Zero,
}

impl fmt::Display for IdError {
    fn fmt(&self, w: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => w.write_str("0 is the end-of-paging sentinel and never an id"),
        }
    }
}
