//! What a controller must already hold before a type can be answered.
//!
//! Three messages create a session and every other request needs one, and until
//! this was written that fact lived only in the registry's `auth_request`
//! column — a string nothing in the crate read. P-143 turns on it: a request
//! that needs a session and arrives before any `Hello` is error 4, and one on a
//! session the controller does not hold is error 9.
//!
//! A hand-written match rather than something generated, for the reason the four
//! new message types demonstrated when they landed: adding one made `empty.rs`,
//! `signed.rs` and `wrapper.rs` non-exhaustive, and answering each compiler
//! error is a decision somebody takes about the new message. Generating this
//! from `auth_request` would delete that review. What stops the two drifting is
//! a test that reads `protocol.toml` and compares them, which is an outside
//! opinion rather than one more copy.
//!
//! cites: P-143

use crate::generated::MessageType;

/// What a type needs before a controller can answer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Admits {
    /// The exchange that creates a session. No session is needed and none is
    /// looked for — `Discover` has no key to look one up with, `Hello` is what
    /// makes one, and `Pair` and `Enrol` run the pairing handshake under the
    /// label's pre-shared key.
    WithoutSession,
    /// A session must be bound on the connection this arrived on, and the
    /// envelope's `session_id` must be the one that connection holds.
    OnlyWithSession,
    /// Not something a client sends inbound: every response, and the two kinds
    /// that only ever travel outward.
    NotARequest,
}

impl MessageType {
    /// What this type needs before it can be answered.
    ///
    /// Exhaustive on purpose. A new message type breaks this, which is the
    /// compiler asking whether the thing being added is part of the handshake
    /// or something a session has to exist for — and that is a question worth
    /// being made to answer rather than one a default arm settles quietly.
    #[must_use]
    pub const fn admits(self) -> Admits {
        match self {
            Self::Discover | Self::Hello | Self::Pair | Self::Enrol => Admits::WithoutSession,
            Self::Subscribe
            | Self::ReadLog
            | Self::GetConfig
            | Self::SetConfig
            | Self::Command
            | Self::Firmware
            | Self::Time
            | Self::Goodbye
            | Self::Inventory
            | Self::Readings
            | Self::Concerns
            | Self::History
            | Self::WifiScan
            | Self::WifiStatus => Admits::OnlyWithSession,
            Self::DiscoverResponse
            | Self::HelloResponse
            | Self::SubscribeResponse
            | Self::EventResponse
            | Self::ReadLogResponse
            | Self::GetConfigResponse
            | Self::SetConfigResponse
            | Self::CommandResponse
            | Self::FirmwareResponse
            | Self::TimeResponse
            | Self::PairResponse
            | Self::EnrolResponse
            | Self::GoodbyeResponse
            | Self::InventoryResponse
            | Self::ReadingsResponse
            | Self::ConcernsResponse
            | Self::HistoryResponse
            | Self::WifiScanResponse
            | Self::WifiStatusResponse
            | Self::ErrorResponse => Admits::NotARequest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Admits, MessageType};

    /// **The three that make a session are the three that cannot need one.**
    ///
    /// `Discover` has no key to look a session up with, `Hello` is what creates
    /// one, and `Pair` runs on a key derived from the printed secret. Require a
    /// session for any of them and a client that has just been unboxed can never
    /// get one — the handshake refuses itself, and the failure is a unit that
    /// looks dead on the bench.
    #[test]
    fn the_handshake_cannot_require_what_the_handshake_creates() {
        for kind in [MessageType::Discover, MessageType::Hello, MessageType::Pair] {
            assert_eq!(
                kind.admits(),
                Admits::WithoutSession,
                "{kind:?} would need the session it exists to produce"
            );
        }
    }

    /// Everything that reads or writes the site needs one, including the two
    /// that look like housekeeping.
    ///
    /// `Goodbye` is the one worth naming: it *ends* a session, so the tempting
    /// reading is that it does not need one. It does — a `Goodbye` with no
    /// session is a client telling the controller to forget a binding that is
    /// not there, and answering it as though it worked tells that client it has
    /// been released when nothing was.
    #[test]
    fn every_request_that_touches_the_site_needs_a_session() {
        for kind in [
            MessageType::Inventory,
            MessageType::Readings,
            MessageType::Concerns,
            MessageType::History,
            MessageType::Subscribe,
            MessageType::ReadLog,
            MessageType::GetConfig,
            MessageType::SetConfig,
            MessageType::Command,
            MessageType::Firmware,
            MessageType::Time,
            MessageType::Goodbye,
        ] {
            assert_eq!(kind.admits(), Admits::OnlyWithSession, "{kind:?}");
        }
    }

    /// A response arriving inbound is not a request, and this says so rather
    /// than classifying it as one that needs a session.
    ///
    /// The distinction matters because *needs a session* has a refusal attached
    /// and this does not: P-143 names error 4 and error 9, and error 2 is for a
    /// type the document does not allocate. A response type is allocated and
    /// simply travels the other way, so no rule covers it and nothing here
    /// invents one.
    #[test]
    fn a_response_arriving_inbound_is_not_a_request_that_needs_a_session() {
        for kind in [
            MessageType::ReadingsResponse,
            MessageType::EventResponse,
            MessageType::ErrorResponse,
            MessageType::HelloResponse,
        ] {
            assert_eq!(kind.admits(), Admits::NotARequest, "{kind:?}");
        }
    }
}
