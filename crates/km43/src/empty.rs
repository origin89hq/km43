//! `a0` — the body two messages wear, and the one byte that keeps it from
//! being nothing at all.
//!
//! `Goodbye 0x0C` says the client is done and `Goodbye 0x8C` agrees. Neither
//! has a field, so both are the same one byte on the wire and the same type
//! here. `Snapshot 0x02` wore it first and is retired.
//!
//! P-011 makes a body a CBOR map, so *empty inner body* is the empty map and
//! not a payload of no bytes. A wrapper carries both equally happily — key 1 is
//! a `bstr` either way — and a receiver reads them differently: one is a map
//! with no keys, the other has no map to read at all. `Snapshot 0x02` was
//! written first and carried its own copy of this; `Goodbye` would have been
//! the second, which is when it stopped being a message's business and became a
//! shape.
//!
//! cites: P-011, P-013

use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::Refusal;
use crate::generated::{ErrorCode, MessageType};

/// A body with no keys.
///
/// Encoding one is [`EmptyBody::encode`]; the caller wraps and MACs the byte it
/// writes, exactly as it would a body that said something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyBody;

impl EmptyBody {
    /// The two messages whose inner body has no keys, so a caller cannot
    /// reach for this on a message that owes fields.
    ///
    /// `Goodbye`'s two directions are both here: P-076 gives the response no
    /// work to report, because clearing a binding either happened or the frame
    /// never arrived.
    const fn wears_one(kind: MessageType) -> bool {
        match kind {
            MessageType::Goodbye | MessageType::GoodbyeResponse => true,
            // Written out rather than `matches!`, which is a `_` arm wearing a
            // macro: a twenty-seventh type would land in neither list and this
            // file would compile, while `Direction::of` and `signs` — the two
            // gates that do the same job — refuse to.
            MessageType::Discover
            | MessageType::DiscoverResponse
            | MessageType::Hello
            | MessageType::HelloResponse
            | MessageType::Inventory
            | MessageType::InventoryResponse
            | MessageType::Readings
            | MessageType::ReadingsResponse
            | MessageType::Concerns
            | MessageType::ConcernsResponse
            | MessageType::History
            | MessageType::HistoryResponse
            | MessageType::Subscribe
            | MessageType::SubscribeResponse
            | MessageType::EventResponse
            | MessageType::ReadLog
            | MessageType::ReadLogResponse
            | MessageType::GetConfig
            | MessageType::GetConfigResponse
            | MessageType::SetConfig
            | MessageType::SetConfigResponse
            | MessageType::Command
            | MessageType::CommandResponse
            | MessageType::Firmware
            | MessageType::FirmwareResponse
            | MessageType::Time
            | MessageType::TimeResponse
            | MessageType::Pair
            | MessageType::PairResponse
            | MessageType::ErrorResponse => false,
        }
    }

    /// Encode the empty map — one byte, and a map rather than nothing so a later
    /// version has somewhere to put a key.
    pub fn encode(self, kind: MessageType, dst: &mut [u8]) -> Result<usize, EmptyBodyError> {
        if !Self::wears_one(kind) {
            return Err(EmptyBodyError::NotAnEmptyInnerBody(kind));
        }
        let mut cbor = CborWriter::new(dst);
        cbor.map(0).map_err(|_| EmptyBodyError::TooLargeToWrite)?;
        cbor.finish().map_err(|_| EmptyBodyError::TooLargeToWrite)
    }

    /// Read one. Every key is skipped rather than refused (P-013): a v2 client
    /// that asks for two channels, or says goodbye with a reason, must reach a
    /// v1 controller as the request it is and not as error 1.
    ///
    /// P-015's duplicate-key refusal has nothing to catch here, and that is the
    /// crate's reading everywhere rather than this body's: `Slot` refuses a
    /// repeat of a key it *knows*, and this body knows none. The harm P-015
    /// names — two libraries reading different bytes out of one authenticated
    /// message — needs a key whose value is read, and here no value is.
    pub fn decode(kind: MessageType, payload: &[u8]) -> Result<Self, EmptyBodyError> {
        if !Self::wears_one(kind) {
            return Err(EmptyBodyError::NotAnEmptyInnerBody(kind));
        }
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        for _ in 0..pairs {
            body.key()?;
            body.skip()?;
        }
        body.finish()?;
        Ok(Self)
    }
}

/// Why an empty body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyBodyError {
    /// A `type` that does not carry an empty *inner* body. Refused rather than
    /// written as `a0`, which would put a `Readings 0x8E` on the wire saying
    /// nothing at all.
    ///
    /// *Inner* is the word that matters. `Discover 0x00` is `(empty map)` too,
    /// and it is not here: P-054 leaves it unauthenticated, so it has no wrapper
    /// and no inner body to be the empty one. Saying "has fields" of `0x00`
    /// would be a refusal contradicting the page that defines it.
    NotAnEmptyInnerBody(MessageType),
    /// The byte did not fit the buffer it was being written into. Ours, not the
    /// peer's.
    TooLargeToWrite,
    /// The CBOR underneath was refused — a body that is not a map, or bytes
    /// after it.
    Cbor(CborError),
}

impl From<CborError> for EmptyBodyError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl EmptyBodyError {
    /// What to answer.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::TooLargeToWrite => Refusal::Client(ErrorCode::PayloadTooLarge),
            Self::NotAnEmptyInnerBody(_) | Self::Cbor(_) => {
                Refusal::Client(ErrorCode::MalformedFrame)
            }
        }
    }
}

impl fmt::Display for EmptyBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnEmptyInnerBody(kind) => write!(
                f,
                "message type {:#04x} does not carry an empty inner body",
                *kind as u8
            ),
            Self::TooLargeToWrite => {
                f.write_str("the empty body does not fit the buffer it is written into")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for EmptyBodyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    /// The two that wear it, and the thirty that do not.
    ///
    /// `Discover 0x00` is `(empty map)` in the document too and is deliberately
    /// among the thirty: P-054 leaves it unauthenticated, so it has no wrapper
    /// and therefore no *inner* body. The guard is a written-out match for the
    /// same reason this list is exhaustive — a thirty-third type has to be
    /// placed rather than silently omitted. The eight inventory, readings,
    /// concerns and history types were routed by the guard and named by this
    /// list by nobody, which is how a list comes to prove less than it says.
    #[test]
    fn only_the_two_inner_bodies_with_no_fields_are_written_as_the_empty_map() {
        let mut dst = [0u8; 8];
        for kind in [MessageType::Goodbye, MessageType::GoodbyeResponse] {
            assert_eq!(EmptyBody.encode(kind, &mut dst), Ok(1), "{kind:?}");
            assert_eq!(EmptyBody::decode(kind, &[0xa0]), Ok(EmptyBody), "{kind:?}");
        }

        for kind in [
            MessageType::Discover,
            MessageType::DiscoverResponse,
            MessageType::Hello,
            MessageType::HelloResponse,
            MessageType::Inventory,
            MessageType::InventoryResponse,
            MessageType::Readings,
            MessageType::ReadingsResponse,
            MessageType::Concerns,
            MessageType::ConcernsResponse,
            MessageType::History,
            MessageType::HistoryResponse,
            MessageType::Subscribe,
            MessageType::SubscribeResponse,
            MessageType::EventResponse,
            MessageType::ReadLog,
            MessageType::ReadLogResponse,
            MessageType::GetConfig,
            MessageType::GetConfigResponse,
            MessageType::SetConfig,
            MessageType::SetConfigResponse,
            MessageType::Command,
            MessageType::CommandResponse,
            MessageType::Firmware,
            MessageType::FirmwareResponse,
            MessageType::Time,
            MessageType::TimeResponse,
            MessageType::Pair,
            MessageType::PairResponse,
            MessageType::ErrorResponse,
        ] {
            assert_eq!(
                EmptyBody.encode(kind, &mut dst),
                Err(EmptyBodyError::NotAnEmptyInnerBody(kind)),
                "{kind:?} encoded as the empty map"
            );
            assert_eq!(
                EmptyBody::decode(kind, &[0xa0]),
                Err(EmptyBodyError::NotAnEmptyInnerBody(kind)),
                "{kind:?} decoded as the empty map"
            );
        }
    }

    /// The one byte that is the whole message. A payload of no bytes is still a
    /// legal payload — `wrapper.rs` has a test saying so — it just has no map in
    /// it, which is what makes the difference this body's.
    #[test]
    fn an_empty_body_is_the_empty_map_and_not_an_empty_payload() {
        let mut dst = [0u8; 8];
        let len = EmptyBody
            .encode(MessageType::Goodbye, &mut dst)
            .expect("it encodes");
        assert_eq!(dst.get(..len), Some(&[0xa0][..]));

        assert_eq!(
            EmptyBody::decode(MessageType::Goodbye, &[]),
            Err(EmptyBodyError::Cbor(CborError::EndOfInput)),
            "no bytes at all is not the empty map"
        );
    }

    /// P-013. A v2 client that says goodbye with a reason, or asks a snapshot
    /// for two channels, must reach a v1 controller as the request it is — the
    /// alternative is an app that cannot close a session at a controller nobody
    /// has driven out to update.
    #[test]
    fn a_key_this_version_does_not_know_is_skipped() {
        // `{9: 99}` and `{1: [1, 2], 9: true}`
        for body in [
            &[0xa1, 0x09, 0x18, 0x63][..],
            &[0xa2, 0x01, 0x82, 0x01, 0x02, 0x09, 0xf5][..],
        ] {
            assert_eq!(
                EmptyBody::decode(MessageType::Goodbye, body),
                Ok(EmptyBody),
                "a newer peer's key was refused"
            );
        }
    }

    /// A byte after the map is a second message, or a body somebody edited.
    /// `finish()` catches it, and deleting the call leaves the rest of this
    /// module green.
    #[test]
    fn a_byte_appended_after_the_empty_body_is_refused() {
        assert_eq!(
            EmptyBody::decode(MessageType::Goodbye, &[0xa0, 0x00]),
            Err(EmptyBodyError::Cbor(CborError::TrailingBytes))
        );
    }

    /// A body that is not a map at all — an array, a byte string, an integer.
    /// P-011 makes every body a map, so each of these is error 1 rather than a
    /// body with no keys.
    #[test]
    fn a_body_that_is_not_a_map_is_refused_rather_than_read_as_empty() {
        for body in [&[0x80][..], &[0x40][..], &[0x00][..], &[0xf5][..]] {
            assert_eq!(
                EmptyBody::decode(MessageType::Goodbye, body),
                Err(EmptyBodyError::Cbor(CborError::WrongType)),
                "{body:?} read as an empty body"
            );
        }
    }

    /// A destination too small is refused rather than written short.
    #[test]
    fn a_destination_too_small_is_refused_rather_than_written_short() {
        let mut nothing = [0u8; 0];
        assert_eq!(
            EmptyBody.encode(MessageType::Goodbye, &mut nothing),
            Err(EmptyBodyError::TooLargeToWrite)
        );
    }

    /// Every refusal is answered with the code its condition names.
    #[test]
    fn every_refusal_is_answered_with_the_code_its_condition_names() {
        assert_eq!(EmptyBodyError::TooLargeToWrite.refusal().code(), 5);
        assert_eq!(
            EmptyBodyError::NotAnEmptyInnerBody(MessageType::Hello)
                .refusal()
                .code(),
            1
        );
        assert_eq!(
            EmptyBodyError::Cbor(CborError::WrongType).refusal().code(),
            1
        );
    }

    /// Every refusal renders as its own sentence.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [EmptyBodyError; 3] = [
            EmptyBodyError::NotAnEmptyInnerBody(MessageType::Hello),
            EmptyBodyError::TooLargeToWrite,
            EmptyBodyError::Cbor(CborError::WrongType),
        ];
        Rendering::<80>::each_says_something_of_its_own(&EVERY);
    }

    /// The whole of `Goodbye`, both directions, through the wrapper that
    /// authenticates it — because the body says nothing, and everything this
    /// message *is* lives in the type and the label around it.
    ///
    /// P-052 puts `0x0C` under `km43/v1/wrq` and `0x8C` under `km43/v1/rsp`.
    /// The request tagged as its own answer must not verify: that is a frame a
    /// relay gets for free, and on a message with no body it is the only thing
    /// there is to get wrong.
    #[test]
    fn a_goodbye_verifies_as_itself_and_not_as_its_own_answer() {
        use crate::envelope::{Envelope, Header, ReqId, SessionId};
        use crate::mac::SessionKey;
        use crate::wrapper::{Tagged, Wrapper};

        let key = SessionKey::new([0x5a; 32]);
        let mut body = [0u8; 8];
        let len = EmptyBody
            .encode(MessageType::Goodbye, &mut body)
            .expect("the body encodes");
        let payload = body.get(..len).expect("the writer's own length");

        for kind in [MessageType::Goodbye, MessageType::GoodbyeResponse] {
            let header = Header {
                kind,
                session: SessionId::from(3),
                req_id: ReqId(17),
            };
            let mut frame = [0u8; 64];
            let wrote = Tagged::over(header, payload, &key)
                .expect("P-052 wraps both directions")
                .write(&mut frame)
                .expect("the frame fits");

            let envelope =
                Envelope::decode(frame.get(..wrote).expect("the length")).expect("it decodes");
            let verified = Wrapper::decode(envelope)
                .expect("the wrapper decodes")
                .verify(&key)
                .expect("the tag checks out");
            assert_eq!(
                EmptyBody::decode(kind, verified.payload()),
                Ok(EmptyBody),
                "{kind:?}"
            );
        }

        // The request's own payload and tag, lifted into the response envelope.
        let request = Header {
            kind: MessageType::Goodbye,
            session: SessionId::from(3),
            req_id: ReqId(17),
        };
        let answer = Header {
            kind: MessageType::GoodbyeResponse,
            ..request
        };
        let asked = Tagged::over(request, payload, &key).expect("a request tags");
        let answered = Tagged::over(answer, payload, &key).expect("a response tags");
        assert_ne!(
            asked.mac().as_bytes(),
            answered.mac().as_bytes(),
            "the two directions of a message whose body is identical must not share a tag"
        );

        // The request's own tag, lifted into the response envelope — the frame a
        // relay gets for free when the two bodies are the same two bytes.
        let mut frame = [0u8; 64];
        let wrote = answered.write(&mut frame).expect("the frame fits");
        let mac_at = wrote.checked_sub(16).expect("the tag is the tail");
        frame
            .get_mut(mac_at..wrote)
            .expect("the tag's own bytes")
            .copy_from_slice(asked.mac().as_bytes());

        let envelope =
            Envelope::decode(frame.get(..wrote).expect("the length")).expect("it decodes");
        assert!(
            Wrapper::decode(envelope)
                .expect("the wrapper still decodes")
                .verify(&key)
                .is_err(),
            "a Goodbye request was accepted as its own answer"
        );
    }
}
