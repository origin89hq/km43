//! The wire: framing, the envelope, and the numbers both implementations agree on.
//!
//! `no_std` and **no `alloc`**, which is the proof rather than the claim: with no
//! allocator crate in scope there is no `Vec` and no `Box` to reach for, so
//! "nothing here allocates" is enforced by the compiler on every build rather
//! than by a rule somebody remembers. Nothing here names a peripheral either —
//! a caller hands it bytes.
//!
//! The `defmt` feature, off by default: it derives `defmt::Format` on the
//! identifiers, counters, enums, verdicts and errors, so a consumer logging on
//! the target can derive it on a row that holds a [`ClientId`] instead of
//! writing the impl by hand. Never on a key or a tag, which have no `Debug`
//! for the same reason.
//!
//! The `vectors` feature exposes the canonical published JSON as `VECTORS_JSON`
//! for consumer tests. It adds no parser or allocator dependency.

#![no_std]
#![deny(unsafe_code)]

macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    };
}

mod admission;
mod ble;
mod boot;
mod cbor;
mod changes;
mod cobs;
mod command;
mod concerns;
mod config;
mod config_messages;
mod controller_record;
mod crc;
mod empty;
mod envelope;
mod error;
mod event;
mod frame;
mod generated;
mod handshake;
mod ident;
mod inventory;
mod kdf;
mod limits;
mod linklocal;
mod mac;
mod pairing;
mod pairing_window;
mod reading;
mod readings;
mod readlog;
#[cfg(test)]
mod render;
mod requirement;
mod requirements;
mod routing;
mod signed;
mod subscribe;
mod time;
mod wrapper;

pub use admission::*;
pub use ble::*;
pub use boot::*;
pub use cbor::*;
pub use changes::*;
pub use cobs::*;
pub use command::*;
pub use concerns::*;
pub use config::*;
pub use config_messages::*;
pub use controller_record::*;
pub use crc::*;
pub use empty::*;
pub use envelope::*;
pub use error::*;
pub use event::*;
pub use frame::*;
pub use generated::*;
pub use handshake::*;
pub use ident::*;
pub use inventory::*;
pub use kdf::*;
pub use limits::*;
pub use linklocal::*;
pub use mac::*;
pub use pairing::*;
pub use pairing_window::*;
pub use reading::*;
pub use readings::*;
pub use readlog::*;
pub use requirement::*;
pub use requirements::*;
pub use routing::*;
pub use signed::*;
pub use subscribe::*;
pub use time::*;
pub use wrapper::*;

/// Published protocol vectors, including BLE traces, pinned to this crate version.
/// Enable `vectors` in a dev-dependency and read this JSON in consumer tests;
/// the crate provides the text without parsing it or allocating.
#[cfg(feature = "vectors")]
pub const VECTORS_JSON: &str = include_str!("../vectors.json");
