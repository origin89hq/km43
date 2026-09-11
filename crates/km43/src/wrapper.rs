//! `{1: payload, 2: mac}` — the body every wrapper-authenticated message wears,
//! and the type that makes P-051's ordering impossible to get wrong.
//!
//! P-051 says verify the MAC **before** decoding `payload`. Written as a rule an
//! implementer obeys it on the path they were thinking about and not on the one
//! they were not, and no happy-path test ever notices. Written as a type it does
//! not compile: [`Wrapper<Unverified>`] has no accessor for the payload at all,
//! [`Wrapper::verify`] is the only thing that produces a [`Wrapper<Verified>`],
//! and only that one gives the bytes up. The doc-tests on [`Wrapper`] are what
//! say so out loud, and each is paired with a twin that must still compile so
//! neither can pass for an unrelated reason.
//!
//! P-013's skip-unknown-keys is switched off here and only here (P-050). A key 3
//! added to this map later would be meaningful and structurally *outside* the
//! MAC, which is the classic shape of the bug — the field lands on the wrong
//! side of the authentication and every older decoder skips politely past it.
//! Exactly keys 1 and 2, and a key that arrives twice is refused before either
//! copy is used (P-015): that is the duplicate check `cbor.rs` deliberately
//! leaves to whoever knows which numbers it recognises.
//!
//! cites: P-015, P-023, P-050, P-051, P-052, P-110

use core::fmt;
use core::marker::PhantomData;

use crate::cbor::CborError;
use crate::envelope::{Envelope, Header, Refusal, ReqId};
use crate::generated::{ErrorCode, MessageType};
use crate::mac::{MacError, SessionKey, Tag, Wrapped};

/// One of the two keys P-050's map is allowed to carry, by name rather than by
/// number. Named `WrapperKey` and not `Key` because this crate is full of keys
/// and none of the others are integers on a wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperKey {
    /// Key 1, the inner body — and the only thing the MAC covers.
    Payload,
    /// Key 2, the sixteen bytes of [`Tag`].
    Mac,
}

impl WrapperKey {
    /// The two numbers this map is allowed to carry, and `None` for every other
    /// integer — including the negative ones, which are a legal CBOR key and not
    /// a legal wrapper key.
    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Payload),
            2 => Some(Self::Mac),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Payload => 1,
            Self::Mac => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Payload => "payload",
            Self::Mac => "mac",
        }
    }
}

impl fmt::Display for WrapperKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (key {})", self.name(), self.number())
    }
}

/// The two states, and no third: a state nobody can implement is a state nobody
/// can verify a message into.
pub trait WrapperState: sealed::Sealed {}

/// Sealing, so `WrapperState` names exactly the two types below.
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Unverified {}
    impl Sealed for super::Verified {}
}

/// A wrapper whose tag has not been checked. It has no payload accessor, which
/// is the whole of P-051 written as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unverified;

/// A wrapper whose tag checked out under a key the receiver holds. Reachable
/// only through [`Wrapper::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified;

impl WrapperState for Unverified {}
impl WrapperState for Verified {}

/// Which of P-052's three labels a message is authenticated under.
///
/// Read off the `type` rather than passed in. A read-only request and the
/// response to it carry identical fields and are separated by the label alone,
/// so a caller allowed to choose is a caller who can let a captured request
/// re-enter the session as its own answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
    Event,
}

impl Direction {
    /// P-052's table. The nine types that are not in it are refused rather than
    /// guessed at: `Hello` and `Pair` prove themselves from inside their bodies
    /// (P-057), the four signed requests carry a counter the wrapper has no room
    /// for (P-053), and `Discover` has no key at all (P-054).
    fn of(header: Header) -> Result<Self, WrapperError> {
        match header.kind {
            MessageType::Inventory
            | MessageType::Readings
            | MessageType::Concerns
            | MessageType::History
            | MessageType::Subscribe
            | MessageType::ReadLog
            | MessageType::GetConfig
            | MessageType::Goodbye => Ok(Self::Request),
            MessageType::HelloResponse
            | MessageType::InventoryResponse
            | MessageType::ReadingsResponse
            | MessageType::ConcernsResponse
            | MessageType::HistoryResponse
            | MessageType::SubscribeResponse
            | MessageType::ReadLogResponse
            | MessageType::GetConfigResponse
            | MessageType::SetConfigResponse
            | MessageType::CommandResponse
            | MessageType::FirmwareResponse
            | MessageType::TimeResponse
            | MessageType::GoodbyeResponse
            | MessageType::ErrorResponse => Ok(Self::Response),
            // The `evt` preimage puts four zero bytes where a `req_id` goes
            // (P-023), so the envelope's own `req_id` is the one field of an
            // event the MAC does not cover. Left unchecked, the comms processor
            // can stamp any number it likes onto an event and the tag still
            // verifies — which is exactly what P-047 spends four bytes to stop
            // on every other message.
            MessageType::EventResponse => {
                if header.req_id == ReqId(0) {
                    Ok(Self::Event)
                } else {
                    Err(WrapperError::EventCarriesReqId(header.req_id))
                }
            }
            MessageType::Discover
            | MessageType::DiscoverResponse
            | MessageType::Hello
            | MessageType::Pair
            | MessageType::PairResponse
            | MessageType::SetConfig
            | MessageType::Command
            | MessageType::Firmware
            | MessageType::Time => Err(WrapperError::NotWrapped(header.kind)),
        }
    }

    fn tag(self, key: &SessionKey, fields: &Wrapped<'_>) -> Tag {
        match self {
            Self::Request => key.wrapper_request(fields),
            Self::Response => key.response(fields),
            Self::Event => key.event(fields.session, fields.payload),
        }
    }
}

/// What has arrived so far.
///
/// `None` means the key has not been seen, never an empty payload: an empty
/// `bstr` is a legal body and a wrapper carrying none is a different message.
struct Slots<'a> {
    payload: Option<&'a [u8]>,
    mac: Option<&'a [u8]>,
}

impl<'a> Slots<'a> {
    const fn new() -> Self {
        Self {
            payload: None,
            mac: None,
        }
    }

    /// Fill one slot, refusing a key that has already arrived (P-015). RFC 8949
    /// §5.6 leaves a repeated key to the decoder, and two libraries picking
    /// differently read different bytes out of one authenticated message.
    fn fill(&mut self, key: WrapperKey, value: &'a [u8]) -> Result<(), WrapperError> {
        let slot = match key {
            WrapperKey::Payload => &mut self.payload,
            WrapperKey::Mac => &mut self.mac,
        };
        if slot.is_some() {
            return Err(WrapperError::Duplicate(key));
        }
        *slot = Some(value);
        Ok(())
    }

    fn complete(self) -> Result<(&'a [u8], &'a [u8]), WrapperError> {
        Ok((
            self.payload
                .ok_or(WrapperError::Missing(WrapperKey::Payload))?,
            self.mac.ok_or(WrapperError::Missing(WrapperKey::Mac))?,
        ))
    }
}

/// P-050's authenticated body, in one of two states.
///
/// `Wrapper<Unverified>` cannot reach the payload; [`Wrapper::verify`] is the
/// only constructor of `Wrapper<Verified>`, which can. Each pair below differs
/// by a single token, so the half that must fail cannot be failing for some
/// unrelated reason:
///
/// ```
/// use km43::{Verified, Wrapper};
/// fn read(wrapper: Wrapper<'_, Verified>) -> &[u8] { wrapper.payload() }
/// ```
/// ```compile_fail
/// use km43::{Unverified, Wrapper};
/// fn read(wrapper: Wrapper<'_, Unverified>) -> &[u8] { wrapper.payload() }
/// ```
/// ```
/// use km43::{Verified, Wrapper};
/// fn seen(wrapper: Wrapper<'_, Verified>) -> Wrapper<'_, Verified> { wrapper }
/// ```
/// ```compile_fail
/// use km43::{Unverified, Verified, Wrapper};
/// fn seen(wrapper: Wrapper<'_, Unverified>) -> Wrapper<'_, Verified> { wrapper }
/// ```
pub struct Wrapper<'a, S: WrapperState> {
    header: Header,
    direction: Direction,
    payload: &'a [u8],
    mac: &'a [u8],
    state: PhantomData<S>,
}

/// Written out rather than derived, because a derive prints every private field
/// and that is a payload accessor spelled `{:?}`.
///
/// `mac.rs` refuses `Debug` on the three key types for the same reason. One
/// `tracing::debug!(?wrapper)` in a tool, or one `write!` to a sink in firmware,
/// and attacker-chosen bytes no key has authenticated are in a log a person
/// reads — recoverable from the rendered text, out of a wrapper nobody verified.
impl<S: WrapperState> fmt::Debug for Wrapper<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Wrapper {{ header: {:?}, direction: {:?}, payload: {} bytes }}",
            self.header,
            self.direction,
            self.payload.len()
        )
    }
}

impl<S: WrapperState> Wrapper<'_, S> {
    /// The envelope's three scalars, which are inside the preimage (P-046,
    /// P-047) — so on a verified wrapper these are the ones that were signed.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }
}

impl<'a> Wrapper<'a, Unverified> {
    /// Take the wrapper out of an envelope's body, refusing anything that is not
    /// exactly keys 1 and 2.
    ///
    /// Nothing is interpreted here: both values are borrowed as they arrived
    /// (P-048), and the payload stays unreachable until [`Wrapper::verify`].
    pub fn decode(envelope: Envelope<'a>) -> Result<Self, WrapperError> {
        let header = envelope.header();
        // Before a key is read, so a message this wrapper does not authenticate
        // is refused rather than half-parsed under a label somebody guessed.
        let direction = Direction::of(header)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut slots = Slots::new();
        for _ in 0..pairs {
            let number = body.key().map_err(WrapperError::Cbor)?;
            let key = WrapperKey::of(number).ok_or(WrapperError::UnknownKey(number))?;
            let value = body.bytes().map_err(WrapperError::Cbor)?;
            slots.fill(key, value)?;
        }
        body.finish().map_err(WrapperError::Cbor)?;
        let (payload, mac) = slots.complete()?;
        Ok(Self {
            header,
            direction,
            payload,
            mac,
            state: PhantomData,
        })
    }

    /// Check the tag, and hand back the only wrapper that will give up its
    /// payload. A failure discards the message (P-051) — it is never a body
    /// worth a second look under another key.
    pub fn verify(self, key: &SessionKey) -> Result<Wrapper<'a, Verified>, WrapperError> {
        let expected = self.direction.tag(
            key,
            &Wrapped {
                kind: self.header.kind,
                session: self.header.session,
                req_id: self.header.req_id,
                payload: self.payload,
            },
        );
        expected.verify(self.mac).map_err(WrapperError::Mac)?;
        Ok(Wrapper {
            header: self.header,
            direction: self.direction,
            payload: self.payload,
            mac: self.mac,
            state: PhantomData,
        })
    }
}

impl<'a> Wrapper<'a, Verified> {
    /// The inner body, exactly as it arrived (P-048) and only now that the tag
    /// over it has been checked.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// The sending half: an inner body and the tag over exactly those bytes.
///
/// [`Tagged::over`] is the only constructor, and it computes the tag from the
/// same `header` and `payload` that [`Tagged::write`] then puts on the wire.
/// That is P-048 as a type rather than as a rule — a caller who could tag one
/// encoding and send another would authenticate a body it never sent, and it is
/// the same argument [`crate::HelloInner::prove`] makes one message over.
///
/// It also puts P-052's table on the send side, where nothing enforced it
/// before: every wrapper on this wire was assembled by hand.
pub struct Tagged<'a> {
    header: Header,
    payload: &'a [u8],
    mac: Tag,
}

impl<'a> Tagged<'a> {
    /// Tag `payload` under the label this `header`'s type requires (P-052).
    ///
    /// The label is read off the type rather than passed in, so a captured
    /// request cannot be re-sent as its own answer, and a type the wrapper does
    /// not authenticate is refused here rather than tagged under a guess.
    pub fn over(header: Header, payload: &'a [u8], key: &SessionKey) -> Result<Self, WrapperError> {
        let direction = Direction::of(header)?;
        let mac = direction.tag(
            key,
            &Wrapped {
                kind: header.kind,
                session: header.session,
                req_id: header.req_id,
                payload,
            },
        );
        Ok(Self {
            header,
            payload,
            mac,
        })
    }

    /// The tag, for a caller assembling a frame some other way. Checking one is
    /// [`Wrapper::verify`].
    #[must_use]
    pub const fn mac(&self) -> &Tag {
        &self.mac
    }

    /// Write the whole envelope — the three scalars and `{1: payload, 2: mac}` —
    /// and hand back its length.
    ///
    /// The header is the one the tag was computed over, so the `session_id` and
    /// `req_id` P-046 and P-047 spend six bytes protecting cannot be filled in
    /// twice and differ.
    pub fn write(&self, dst: &mut [u8]) -> Result<usize, WrapperError> {
        let mut cbor = self
            .header
            .write(2, dst)
            .map_err(|_| WrapperError::TooLargeToWrite)?;
        let mut put = |key: WrapperKey, value: &[u8]| {
            cbor.key(key.number())
                .and_then(|()| cbor.bytes(value))
                .map_err(|_| WrapperError::TooLargeToWrite)
        };
        put(WrapperKey::Payload, self.payload)?;
        put(WrapperKey::Mac, self.mac.as_bytes())?;
        cbor.finish().map_err(|_| WrapperError::TooLargeToWrite)
    }
}

/// Lengths, never the payload — the argument the `Debug` on [`Wrapper`] makes,
/// and it applies to a body on its way out as much as to one that arrived.
impl fmt::Debug for Tagged<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tagged {{ header: {:?}, payload: {} bytes }}",
            self.header,
            self.payload.len()
        )
    }
}

/// Why a wrapper was refused. Two of these are error 10, one is error 5, and the
/// rest are error 1 — a distinction a client acts on: error 1 says the frame was
/// garbled and error 10 says the key was wrong, and a client told the first
/// about the second retries the same frame until it gives up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperError {
    /// A key that is neither 1 nor 2 (P-050), refused rather than skipped —
    /// P-013 does not reach inside this map.
    UnknownKey(i64),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(WrapperKey),
    /// A key that never arrived. A missing MAC is a discard, never a message
    /// with a key missing (P-051).
    Missing(WrapperKey),
    /// A `type` P-052 does not wrap. Refused rather than verified under a
    /// guessed label, which would authenticate a `Hello` as a `Readings`.
    NotWrapped(MessageType),
    /// An unsolicited `Event` carrying a `req_id` where P-023 requires zero. The
    /// `evt` preimage covers a literal `0x00000000`, so a number here is a field
    /// outside the MAC that anything on the path can choose.
    EventCarriesReqId(ReqId),
    /// The tag did not check out, or was not sixteen bytes wide.
    Mac(MacError),
    /// The frame did not fit the buffer it was being written into. Ours, not
    /// the peer's: the only way [`Tagged::write`] fails. It is error 5 and not
    /// error 1 because the frame was never garbled — it was too big, which is
    /// the refusal `limits.rs` names wherever a body outgrows a payload.
    TooLargeToWrite,
    /// The CBOR underneath was refused. A body that is not a map arrives at the
    /// envelope; a value that is not a byte string arrives here.
    Cbor(CborError),
}

impl WrapperError {
    /// What to answer, and P-051 pins the pair that matters: a wrapper that
    /// failed its MAC and a wrapper that carried none are both error 10.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(WrapperKey::Mac) | Self::Mac(_) => Refusal::Client(ErrorCode::BadMAC),
            Self::Missing(WrapperKey::Payload)
            | Self::UnknownKey(_)
            | Self::Duplicate(_)
            | Self::NotWrapped(_)
            | Self::EventCarriesReqId(_)
            | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
            Self::TooLargeToWrite => Refusal::Client(ErrorCode::PayloadTooLarge),
        }
    }
}

impl fmt::Display for WrapperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(number) => {
                write!(f, "wrapper key {number} is neither payload nor mac")
            }
            Self::Duplicate(key) => write!(f, "wrapper carries {key} twice"),
            Self::Missing(key) => write!(f, "wrapper carries no {key}"),
            Self::NotWrapped(kind) => {
                write!(
                    f,
                    "message type {:#04x} is not authenticated by the wrapper",
                    *kind as u8
                )
            }
            Self::EventCarriesReqId(req_id) => {
                write!(f, "an unsolicited event carries req_id {}", req_id.0)
            }
            Self::Mac(why) => write!(f, "{why}"),
            Self::TooLargeToWrite => {
                f.write_str("the frame does not fit the buffer it is written into")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for WrapperError {}

const_assert!(
    size_of::<WrapperError>() == 16,
    "a Result carrying one of these comes back from every decode and every verify on a part with 144 KB of RAM, so the width is paid on the frames that pass and not only on the ones that fail. Sixteen is the width of the MacError already inside it: the eight variants and their fields ride in bit patterns that error was not using, and cost nothing until one of them stops fitting"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::SessionId;
    use crate::render::Rendering;

    /// Wider than any fixture here, and narrow enough that a length bug shows
    /// as a panic in the builder rather than as a passing test.
    const SCRATCH: usize = 96;

    /// Two keys that are not each other. What a key *is* belongs to the
    /// derivation and to `mac.rs`; here it only has to be thirty-two bytes.
    const OURS: [u8; 32] = [0x5a; 32];
    const THEIRS: [u8; 32] = [0xa5; 32];

    /// A `ReadLog` body, `{1: 1216, 2: 64}` — a real inner body rather than
    /// filler, because the payload is opaque to this layer and a fixture that
    /// looked like filler would hide it if it ever stopped being.
    const PAYLOAD: [u8; 8] = [0xa2, 0x01, 0x19, 0x04, 0xc0, 0x02, 0x18, 0x40];

    /// A different body of the same width, so a fixture that swaps them cannot
    /// pass by changing a length somewhere.
    const OTHER_PAYLOAD: [u8; 8] = [0xa2, 0x01, 0x19, 0x04, 0xc1, 0x02, 0x18, 0x40];

    /// Which label a fixture is MAC'd under, chosen by the test rather than by
    /// [`Direction`].
    ///
    /// The mapping from `type` to label is the thing under test, so a fixture
    /// that asked `Direction` for it would be checking the code against itself
    /// and would stay green if every label in P-052's table moved one row.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Under {
        Request,
        Response,
        Event,
    }

    /// The key one end of a fixture holds, and the tags it computes.
    struct Peer(SessionKey);

    impl Peer {
        fn new(bytes: [u8; 32]) -> Self {
            Self(SessionKey::new(bytes))
        }

        fn key(&self) -> &SessionKey {
            &self.0
        }

        fn tag(&self, under: Under, header: Header, payload: &[u8]) -> Tag {
            let fields = Wrapped {
                kind: header.kind,
                session: header.session,
                req_id: header.req_id,
                payload,
            };
            match under {
                Under::Request => self.0.wrapper_request(&fields),
                Under::Response => self.0.response(&fields),
                Under::Event => self.0.event(header.session, payload),
            }
        }

        /// A whole frame: the envelope, the two keys, and a tag computed under
        /// the label the caller named.
        fn wrap(&self, under: Under, header: Header, payload: &[u8]) -> Wire {
            Wire::envelope(header, 2)
                .bstr(1, payload)
                .bstr(2, self.tag(under, header, payload).as_bytes())
        }
    }

    /// One frame's bytes, assembled by hand.
    ///
    /// Not through `CborWriter`: it refuses a duplicate key and a key that does
    /// not ascend, which is exactly what half of these fixtures have to send.
    #[derive(Clone, Copy)]
    struct Wire {
        bytes: [u8; SCRATCH],
        len: usize,
    }

    impl Wire {
        /// `[type, session_id, req_id, {` with the type in long form and the two
        /// scalars inline, which is why every fixture keeps them under 24.
        fn envelope(header: Header, pairs: usize) -> Self {
            let session = u8::try_from(u16::from(header.session)).expect("a one-byte session");
            let req_id = u8::try_from(header.req_id.0).expect("a one-byte req_id");
            let pairs = u8::try_from(pairs).expect("a map of fewer than twenty-four pairs");
            assert!(session < 24 && req_id < 24 && pairs < 24, "one-byte CBOR");
            let mut wire = Self {
                bytes: [0; SCRATCH],
                len: 0,
            };
            wire.push(&[0x84, 0x18, header.kind as u8, session, req_id, 0xa0 | pairs]);
            wire
        }

        fn push(&mut self, data: &[u8]) {
            for &byte in data {
                let slot = self
                    .bytes
                    .get_mut(self.len)
                    .expect("the fixture fits the scratch");
                *slot = byte;
                self.len = self.len.saturating_add(1);
            }
        }

        /// A key carrying a byte string, which is what both legal keys carry.
        fn bstr(mut self, key: u8, value: &[u8]) -> Self {
            let len = u8::try_from(value.len()).expect("a string under twenty-four bytes");
            assert!(len < 24, "the fixture strings are all short form");
            self.push(&[key, 0x40 | len]);
            self.push(value);
            self
        }

        /// A key carrying something that is not a byte string.
        fn small(mut self, key: u8, value: u8) -> Self {
            assert!(value < 24, "the fixture integers are all inline");
            self.push(&[key, value]);
            self
        }

        fn appended(mut self, byte: u8) -> Self {
            self.push(&[byte]);
            self
        }

        fn flipped(mut self, at: usize, bit: u8) -> Self {
            let slot = self.bytes.get_mut(at).expect("at is inside the frame");
            *slot ^= 1 << bit;
            self
        }

        fn cut_to(mut self, len: usize) -> Self {
            assert!(len <= self.len, "a cut is a prefix");
            self.len = len;
            self
        }

        fn bytes(&self) -> &[u8] {
            self.bytes
                .get(..self.len)
                .expect("the length came from the builder")
        }

        fn decoded(&self) -> Result<Wrapper<'_, Unverified>, WrapperError> {
            let envelope = Envelope::decode(self.bytes()).expect("the fixture's envelope decodes");
            Wrapper::decode(envelope)
        }

        fn verified(&self, key: &SessionKey) -> Result<Wrapper<'_, Verified>, WrapperError> {
            self.decoded()?.verify(key)
        }

        /// Whether these bytes reach a payload at all, with every refusal along
        /// the way — envelope, wrapper, MAC — collapsed to `None`.
        fn reaches_payload(&self, key: &SessionKey) -> Option<&[u8]> {
            let envelope = Envelope::decode(self.bytes()).ok()?;
            Some(Wrapper::decode(envelope).ok()?.verify(key).ok()?.payload())
        }
    }

    fn header(kind: MessageType, req_id: u32) -> Header {
        Header {
            kind,
            session: SessionId::from(3),
            req_id: ReqId(req_id),
        }
    }

    fn request() -> Header {
        header(MessageType::ReadLog, 17)
    }

    fn response() -> Header {
        header(MessageType::ReadLogResponse, 17)
    }

    /// The path this module exists for, in all three directions: a payload goes
    /// out under a key, comes back, and is reachable only on the far side of the
    /// tag over it.
    #[test]
    fn a_wrapper_gives_up_its_payload_once_the_tag_over_it_has_been_checked() {
        let peer = Peer::new(OURS);
        for (under, header) in [
            (Under::Request, request()),
            (Under::Response, response()),
            (Under::Event, header(MessageType::EventResponse, 0)),
        ] {
            let wire = peer.wrap(under, header, &PAYLOAD);
            let verified = wire
                .verified(peer.key())
                .expect("a wrapper this key MAC'd verifies under it");
            assert_eq!(verified.payload(), &PAYLOAD[..], "{under:?}");
            assert_eq!(verified.header(), header, "{under:?}");
        }
    }

    /// **P-017 — authentication does not depend on P-016.**
    ///
    /// The MAC covers the byte string that arrived and is verified exactly as
    /// received, never over a re-encoding. So a payload whose keys descend —
    /// which P-016 forbids — still **verifies**, and is refused a layer later by
    /// the decoder that reads it.
    ///
    /// The two rules answering separately is the whole point. If verification
    /// re-encoded a body to check it, then two implementations that ordered keys
    /// differently would compute different tags over the same message and
    /// neither could talk to the other; and a body that survived the trip
    /// unchanged could be declared inauthentic on a formatting difference. P-016
    /// is for debuggability and byte-stability. Where they disagree, the MAC
    /// wins.
    #[test]
    fn p_017_a_body_whose_keys_descend_still_verifies_and_is_refused_by_the_decoder() {
        // `{2: 64, 1: 1216}` — the same two pairs as `PAYLOAD` in the order
        // P-016 forbids, and the same width, so nothing here turns on a length.
        const DESCENDING: [u8; 8] = [0xa2, 0x02, 0x18, 0x40, 0x01, 0x19, 0x04, 0xc0];
        assert_eq!(DESCENDING.len(), PAYLOAD.len());

        let peer = Peer::new(OURS);
        let wire = peer.wrap(Under::Request, request(), &DESCENDING);
        let verified = wire
            .verified(peer.key())
            .expect("the MAC is over the bytes that arrived, whatever order they are in");
        assert_eq!(
            verified.payload(),
            &DESCENDING[..],
            "the payload came back re-encoded rather than as received"
        );

        // **The reader takes it, and that is not a gap.** P-016 binds
        // *encoders* — "Encoders MUST emit ... sorted map keys" — so a decoder
        // that refused this would be enforcing a rule written for the other
        // end, and would turn a peer's formatting mistake into a frame this
        // controller cannot read even though it authenticated.
        let mut body = crate::cbor::CborReader::new(verified.payload());
        assert_eq!(body.map(), Ok(2));
        assert_eq!(body.key(), Ok(2));
        assert_eq!(body.u16(), Ok(64));
        assert_eq!(
            body.key(),
            Ok(1),
            "the reader enforced a rule about encoders"
        );

        // Where P-016 *is* enforced is the encoder, which is what the rule
        // says and the half that keeps this project's own bytes stable.
        let mut out = [0u8; SCRATCH];
        let mut writer = crate::cbor::CborWriter::new(&mut out);
        assert_eq!(writer.map(2), Ok(()));
        assert_eq!(writer.key(2), Ok(()));
        assert_eq!(writer.u64(64), Ok(()));
        assert_eq!(
            writer.key(1),
            Err(crate::cbor::CborError::KeysNotAscending),
            "this encoder emitted a descending key, which P-016 forbids"
        );
    }

    /// The type-state says an unverified wrapper has no accessor for the
    /// payload. A derived `Debug` is one, and it took two reviewers running
    /// `format!` to notice, because the four doc-tests above assert the property
    /// by *type* and a formatter is not a type.
    #[test]
    fn an_unverified_wrapper_does_not_hand_its_payload_to_a_formatter() {
        let peer = Peer::new(OURS);
        let wire = peer.wrap(Under::Request, request(), &PAYLOAD);
        let ours = Rendering::<240>::debugged(&wire.decoded().expect("the fixture decodes"));

        // A different payload of the same length. If one byte of it reached the
        // rendering, the two differ — and comparing renderings rather than
        // hunting for digits avoids the false positive that `17` in a payload
        // looks exactly like the `req_id` beside it.
        let mut other = PAYLOAD;
        for (slot, byte) in other.iter_mut().zip(0u8..) {
            *slot = byte.wrapping_add(0x5A);
        }
        let elsewhere = peer.wrap(Under::Request, request(), &other);
        let theirs = Rendering::<240>::debugged(&elsewhere.decoded().expect("the fixture decodes"));

        assert_eq!(
            ours.bytes(),
            theirs.bytes(),
            "two payloads rendered differently, so the rendering carries payload"
        );
        let text = core::str::from_utf8(ours.bytes()).expect("a rendering is UTF-8");
        assert!(
            text.contains("bytes"),
            "the length is not the secret and a reader needs it: {text}"
        );
    }

    /// Every single-bit change anywhere in the frame — envelope, keys, lengths,
    /// payload, tag — is refused. Nothing reaches a payload the sender did not
    /// send, whichever byte the link corrupted.
    #[test]
    fn no_single_bit_change_anywhere_in_a_frame_reaches_a_verified_payload() {
        let peer = Peer::new(OURS);
        let wire = peer.wrap(Under::Request, request(), &PAYLOAD);
        assert_eq!(
            wire.reaches_payload(peer.key()),
            Some(&PAYLOAD[..]),
            "the fixture must pass, or every flip below proves nothing"
        );

        for at in 0..wire.len {
            for bit in 0..8u8 {
                assert_eq!(
                    wire.flipped(at, bit).reaches_payload(peer.key()),
                    None,
                    "byte {at} bit {bit} of a frame reached a payload"
                );
            }
        }
    }

    /// P-051: a body arriving without a MAC is discarded, never read as a
    /// message with a key missing. Skipping it the way P-013 skips an unknown
    /// key is how an unauthenticated `Command` becomes a generator start.
    #[test]
    fn a_wrapper_with_no_mac_is_discarded_rather_than_read_as_a_key_that_is_absent() {
        let wire = Wire::envelope(request(), 1).bstr(1, &PAYLOAD);
        assert_eq!(
            wire.decoded().err(),
            Some(WrapperError::Missing(WrapperKey::Mac))
        );

        let empty = Wire::envelope(request(), 0);
        assert_eq!(
            empty.decoded().err(),
            Some(WrapperError::Missing(WrapperKey::Payload)),
            "an empty map is not a message with an empty body"
        );

        let mac_only = Wire::envelope(request(), 1).bstr(2, &[0u8; Tag::LEN]);
        assert_eq!(
            mac_only.decoded().err(),
            Some(WrapperError::Missing(WrapperKey::Payload))
        );
    }

    /// P-015: the same key twice is refused before either copy is used, even
    /// when one reading of the map would authenticate. RFC 8949 §5.6 leaves the
    /// resolution to the decoder — first wins, last wins — and two ends picking
    /// differently read different bytes out of one authenticated frame.
    #[test]
    fn a_wrapper_that_carries_a_key_twice_is_refused_before_either_copy_is_used() {
        let peer = Peer::new(OURS);
        let header = request();

        let twice = Wire::envelope(header, 2)
            .bstr(1, &PAYLOAD)
            .bstr(1, &OTHER_PAYLOAD);
        assert_eq!(
            twice.decoded().err(),
            Some(WrapperError::Duplicate(WrapperKey::Payload))
        );

        let two_macs = Wire::envelope(header, 2)
            .bstr(2, &[0u8; Tag::LEN])
            .bstr(2, &[1u8; Tag::LEN]);
        assert_eq!(
            two_macs.decoded().err(),
            Some(WrapperError::Duplicate(WrapperKey::Mac))
        );

        // The dangerous one: a perfectly good wrapper with a second payload
        // appended. Last-wins reads the body the MAC does not cover; first-wins
        // reads the body it does, and neither end can tell which the other did.
        let tag = peer.tag(Under::Request, header, &PAYLOAD);
        let appended = Wire::envelope(header, 3)
            .bstr(1, &PAYLOAD)
            .bstr(2, tag.as_bytes())
            .bstr(1, &OTHER_PAYLOAD);
        assert_eq!(
            appended.decoded().err(),
            Some(WrapperError::Duplicate(WrapperKey::Payload))
        );
        assert_eq!(
            appended.reaches_payload(peer.key()),
            None,
            "a duplicated key must not authenticate under either reading"
        );
    }

    /// P-050 switches P-013 off for this one map. A key added here in a later
    /// version is meaningful and outside the MAC, so a decoder that skipped it
    /// politely would carry a field nobody signed — which is the classic shape
    /// of the bug, invisible because skip-unknown-keys is right everywhere else.
    #[test]
    fn a_key_this_version_does_not_know_is_refused_rather_than_skipped() {
        let peer = Peer::new(OURS);
        let header = request();
        let tag = peer.tag(Under::Request, header, &PAYLOAD);

        let extra = Wire::envelope(header, 3)
            .bstr(1, &PAYLOAD)
            .bstr(2, tag.as_bytes())
            .small(0x03, 1);
        assert_eq!(extra.decoded().err(), Some(WrapperError::UnknownKey(3)));
        assert_eq!(
            extra.reaches_payload(peer.key()),
            None,
            "the MAC over key 1 is perfect, and the frame still must not pass"
        );

        let zero = Wire::envelope(header, 3)
            .small(0x00, 1)
            .bstr(1, &PAYLOAD)
            .bstr(2, tag.as_bytes());
        assert_eq!(zero.decoded().err(), Some(WrapperError::UnknownKey(0)));

        // -1, which is a legal CBOR key and not a legal wrapper key.
        let negative = Wire::envelope(header, 3)
            .small(0x20, 1)
            .bstr(1, &PAYLOAD)
            .bstr(2, tag.as_bytes());
        assert_eq!(negative.decoded().err(), Some(WrapperError::UnknownKey(-1)));
    }

    /// P-016 says encoders sort their keys and P-017 says authentication must
    /// not depend on it. A decoder that refused key 2 before key 1 would be
    /// adding a rule the document does not have, and would drop a frame it can
    /// authenticate perfectly well.
    #[test]
    fn a_wrapper_whose_two_keys_arrived_out_of_order_still_authenticates() {
        let peer = Peer::new(OURS);
        let header = request();
        let tag = peer.tag(Under::Request, header, &PAYLOAD);
        let reversed = Wire::envelope(header, 2)
            .bstr(2, tag.as_bytes())
            .bstr(1, &PAYLOAD);
        assert_eq!(reversed.reaches_payload(peer.key()), Some(&PAYLOAD[..]));
    }

    /// A tag of exactly the right shape computed under somebody else's key.
    /// Nothing about the frame is wrong except the sixteen bytes, which is what
    /// the whole wrapper is for.
    #[test]
    fn a_wrapper_verified_under_the_wrong_key_is_refused() {
        let ours = Peer::new(OURS);
        let theirs = Peer::new(THEIRS);
        let wire = theirs.wrap(Under::Request, request(), &PAYLOAD);
        assert_eq!(
            wire.verified(ours.key()).err(),
            Some(WrapperError::Mac(MacError::Mismatch))
        );
        assert_eq!(WrapperError::Mac(MacError::Mismatch).refusal().code(), 10);
    }

    /// P-052's table, written out from the document rather than read off
    /// `Direction`, and checked end to end: every type verifies under the label
    /// its row names, and under neither of the other two.
    ///
    /// Share a label between a request and its response and a captured
    /// read-only request re-enters the session as its own answer, MAC and all.
    #[test]
    fn each_message_type_verifies_only_under_the_label_p_052_names_for_it() {
        const TABLE: [(MessageType, Option<Under>); 24] = [
            (MessageType::Subscribe, Some(Under::Request)),
            (MessageType::ReadLog, Some(Under::Request)),
            (MessageType::GetConfig, Some(Under::Request)),
            (MessageType::Goodbye, Some(Under::Request)),
            (MessageType::HelloResponse, Some(Under::Response)),
            (MessageType::SubscribeResponse, Some(Under::Response)),
            (MessageType::ReadLogResponse, Some(Under::Response)),
            (MessageType::GetConfigResponse, Some(Under::Response)),
            (MessageType::SetConfigResponse, Some(Under::Response)),
            (MessageType::CommandResponse, Some(Under::Response)),
            (MessageType::FirmwareResponse, Some(Under::Response)),
            (MessageType::TimeResponse, Some(Under::Response)),
            (MessageType::GoodbyeResponse, Some(Under::Response)),
            (MessageType::ErrorResponse, Some(Under::Response)),
            (MessageType::EventResponse, Some(Under::Event)),
            (MessageType::Discover, None),
            (MessageType::DiscoverResponse, None),
            (MessageType::Hello, None),
            (MessageType::Pair, None),
            (MessageType::PairResponse, None),
            (MessageType::SetConfig, None),
            (MessageType::Command, None),
            (MessageType::Firmware, None),
            (MessageType::Time, None),
        ];
        const EVERY: [Under; 3] = [Under::Request, Under::Response, Under::Event];

        let peer = Peer::new(OURS);
        for (kind, wrapped) in TABLE {
            // Zero throughout: P-023 requires it of an event, and every other
            // type is happy with it, so one header serves the whole table.
            let head = header(kind, 0);
            for under in EVERY {
                let wire = peer.wrap(under, head, &PAYLOAD);
                let reached = wire.reaches_payload(peer.key());
                if wrapped == Some(under) {
                    assert_eq!(
                        reached,
                        Some(&PAYLOAD[..]),
                        "{kind:?} must verify under {under:?}"
                    );
                } else {
                    assert_eq!(reached, None, "{kind:?} must not verify under {under:?}");
                }
            }
            if wrapped.is_none() {
                assert_eq!(
                    peer.wrap(Under::Request, head, &PAYLOAD).decoded().err(),
                    Some(WrapperError::NotWrapped(kind)),
                    "{kind:?} is not P-052's wrapper and must say so"
                );
            }
        }
    }

    /// P-023 fixes an event's `req_id` at zero and the `evt` preimage covers
    /// four zero bytes, so the envelope's own `req_id` is the one field of an
    /// event the MAC does not cover. Unchecked, anything on the path can stamp a
    /// number into it and the tag still verifies.
    #[test]
    fn an_event_carrying_a_req_id_is_refused_rather_than_verified_over_a_zero() {
        let peer = Peer::new(OURS);
        let stamped = header(MessageType::EventResponse, 7);
        let wire = peer.wrap(Under::Event, stamped, &PAYLOAD);
        assert_eq!(
            wire.decoded().err(),
            Some(WrapperError::EventCarriesReqId(ReqId(7))),
            "the tag over this frame is correct, which is exactly the problem"
        );

        let unsolicited = header(MessageType::EventResponse, 0);
        assert_eq!(
            peer.wrap(Under::Event, unsolicited, &PAYLOAD)
                .reaches_payload(peer.key()),
            Some(&PAYLOAD[..])
        );
    }

    /// A tag of the wrong width is refused on its width, never padded out or
    /// trimmed to fit: a twelve-byte tag zero-padded to sixteen verifies against
    /// a forgery whose last four bytes were never guessed.
    #[test]
    fn a_mac_that_is_not_sixteen_bytes_is_refused_on_its_width() {
        let peer = Peer::new(OURS);
        let header = request();
        let tag = peer.tag(Under::Request, header, &PAYLOAD);
        let bytes = tag.as_bytes();

        for short in [0usize, 1, 8, 15] {
            let truncated = bytes.get(..short).expect("short is inside the tag");
            let wire = Wire::envelope(header, 2)
                .bstr(1, &PAYLOAD)
                .bstr(2, truncated);
            assert_eq!(
                wire.verified(peer.key()).err(),
                Some(WrapperError::Mac(MacError::WrongLength(short))),
                "a {short}-byte tag"
            );
        }

        let long = [0u8; Tag::LEN + 1];
        let wire = Wire::envelope(header, 2).bstr(1, &PAYLOAD).bstr(2, &long);
        assert_eq!(
            wire.verified(peer.key()).err(),
            Some(WrapperError::Mac(MacError::WrongLength(Tag::LEN + 1)))
        );
    }

    /// An empty payload is a body of zero length, not the absence of one. A
    /// decoder that read `None` and `Some(&[])` as the same thing would accept a
    /// wrapper with no key 1 as a message with an empty body.
    #[test]
    fn an_empty_payload_is_a_body_of_no_bytes_and_not_a_missing_one() {
        let peer = Peer::new(OURS);
        let header = request();
        let empty: [u8; 0] = [];
        let wire = peer.wrap(Under::Request, header, &empty);
        let verified = wire.verified(peer.key()).expect("an empty body verifies");
        assert_eq!(verified.payload(), &empty[..]);

        // The same frame with a tag over a body that is not empty.
        let tag = peer.tag(Under::Request, header, &PAYLOAD);
        let mismatched = Wire::envelope(header, 2)
            .bstr(1, &empty)
            .bstr(2, tag.as_bytes());
        assert_eq!(
            mismatched.verified(peer.key()).err(),
            Some(WrapperError::Mac(MacError::Mismatch))
        );
    }

    /// Both keys carry byte strings. A `payload` that arrived as a text string
    /// or an integer is a sender that has gone wrong, and a decoder that
    /// coerced it would hash something the sender never wrote.
    #[test]
    fn a_wrapper_value_that_is_not_a_byte_string_is_refused() {
        let peer = Peer::new(OURS);
        let header = request();
        let tag = peer.tag(Under::Request, header, &PAYLOAD);

        let integer = Wire::envelope(header, 2)
            .small(0x01, 12)
            .bstr(2, tag.as_bytes());
        assert_eq!(
            integer.decoded().err(),
            Some(WrapperError::Cbor(CborError::WrongType))
        );

        // 0x62 0x68 0x69 is the text string "hi".
        let mut text = Wire::envelope(header, 2).bstr(1, &PAYLOAD);
        text = text.appended(0x02).appended(0x62).appended(0x68);
        text = text.appended(0x69);
        assert_eq!(
            text.decoded().err(),
            Some(WrapperError::Cbor(CborError::WrongType))
        );
    }

    /// A byte appended after a wrapper that is otherwise perfect. That byte is a
    /// field one implementation reads inside a frame both of them
    /// authenticated, which is the disagreement P-051's ordering exists to make
    /// impossible.
    #[test]
    fn a_byte_appended_after_the_wrapper_is_refused() {
        let peer = Peer::new(OURS);
        let wire = peer.wrap(Under::Request, request(), &PAYLOAD);
        assert_eq!(
            wire.appended(0x00).decoded().err(),
            Some(WrapperError::Cbor(CborError::TrailingBytes))
        );
    }

    /// Every prefix of a valid frame. A frame cut short by a link that dropped
    /// carrier must never read as a shorter wrapper — least of all as one whose
    /// MAC is the bytes that happened to survive.
    #[test]
    fn every_truncation_of_a_wrapper_is_refused() {
        let peer = Peer::new(OURS);
        let wire = peer.wrap(Under::Request, request(), &PAYLOAD);
        for cut in 0..wire.len {
            assert_eq!(
                wire.cut_to(cut).reaches_payload(peer.key()),
                None,
                "a frame cut at {cut} of {} bytes reached a payload",
                wire.len
            );
        }
        assert_eq!(wire.reaches_payload(peer.key()), Some(&PAYLOAD[..]));
    }

    /// P-051 pins error 10 to the MAC and P-050 pins error 1 to the shape. A
    /// client told "malformed frame" about a key that was wrong retries the same
    /// bytes until it gives up; one told "bad MAC" reconnects and re-derives.
    #[test]
    fn a_missing_mac_is_answered_with_ten_and_a_stray_key_with_one() {
        assert_eq!(WrapperError::Missing(WrapperKey::Mac).refusal().code(), 10);
        assert_eq!(WrapperError::Mac(MacError::Mismatch).refusal().code(), 10);
        assert_eq!(
            WrapperError::Mac(MacError::WrongLength(12))
                .refusal()
                .code(),
            10
        );

        assert_eq!(
            WrapperError::Missing(WrapperKey::Payload).refusal().code(),
            1
        );
        assert_eq!(WrapperError::UnknownKey(3).refusal().code(), 1);
        assert_eq!(
            WrapperError::Duplicate(WrapperKey::Payload)
                .refusal()
                .code(),
            1
        );
        assert_eq!(
            WrapperError::NotWrapped(MessageType::Hello)
                .refusal()
                .code(),
            1
        );
        assert_eq!(
            WrapperError::EventCarriesReqId(ReqId(1)).refusal().code(),
            1
        );
        assert_eq!(WrapperError::Cbor(CborError::WrongType).refusal().code(), 1);
        assert_eq!(WrapperError::TooLargeToWrite.refusal().code(), 5);
    }

    /// Every refusal renders as its own sentence. The pair somebody will be
    /// telling apart in a bench log is "no mac arrived" and "the mac did not
    /// match", and two that share a line send them to the wrong half.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [WrapperError; 10] = [
            WrapperError::TooLargeToWrite,
            WrapperError::UnknownKey(3),
            WrapperError::Duplicate(WrapperKey::Payload),
            WrapperError::Duplicate(WrapperKey::Mac),
            WrapperError::Missing(WrapperKey::Payload),
            WrapperError::Missing(WrapperKey::Mac),
            WrapperError::NotWrapped(MessageType::Hello),
            WrapperError::EventCarriesReqId(ReqId(7)),
            WrapperError::Mac(MacError::Mismatch),
            WrapperError::Cbor(CborError::WrongType),
        ];
        Rendering::<80>::each_says_something_of_its_own(&EVERY);
    }

    /// What a sender writes and what a receiver reads, in all three directions.
    /// Every wrapper on this wire was assembled by hand until this existed, and a
    /// frame built by hand is a frame built differently at each call site.
    #[test]
    fn a_body_a_sender_tagged_verifies_at_the_receiver_that_reads_it() {
        let peer = Peer::new(OURS);
        for header in [request(), response(), header(MessageType::EventResponse, 0)] {
            let mut dst = [0u8; SCRATCH];
            let tagged = Tagged::over(header, &PAYLOAD, peer.key()).expect("the type is wrapped");
            let len = tagged.write(&mut dst).expect("the frame fits the scratch");
            let bytes = dst.get(..len).expect("the writer's own length");

            let envelope = Envelope::decode(bytes).expect("a written envelope decodes");
            let verified = Wrapper::decode(envelope)
                .expect("a written wrapper decodes")
                .verify(peer.key())
                .expect("the tag it was written with checks out");
            assert_eq!(verified.payload(), &PAYLOAD[..], "{header:?}");
            assert_eq!(verified.header(), header, "{header:?}");
        }
    }

    /// The tag, against one this module did not compute. A round trip through
    /// the crate's own decoder cannot catch an encoder and a verifier that are
    /// wrong the same way, and `Peer` reaches P-052's labels by hand.
    #[test]
    fn a_written_tag_is_the_one_the_label_p_052_names_produces() {
        let peer = Peer::new(OURS);
        for (under, header) in [
            (Under::Request, request()),
            (Under::Response, response()),
            (Under::Event, header(MessageType::EventResponse, 0)),
        ] {
            let tagged = Tagged::over(header, &PAYLOAD, peer.key()).expect("the type is wrapped");
            assert_eq!(
                tagged.mac().as_bytes(),
                peer.tag(under, header, &PAYLOAD).as_bytes(),
                "{under:?}"
            );
        }
    }

    /// One whole frame spelled out, because P-016 says an encoder owes shortest
    /// form and only the bytes can say whether it paid.
    ///
    /// `Wire` cannot be the witness here. It writes the `type` in long form on
    /// purpose — a decoder must accept one (P-017), which is what half the
    /// fixtures above are for — so comparing against it would assert that the
    /// encoder is as loose as the decoder is required to be.
    #[test]
    fn a_written_frame_is_in_the_shortest_form_p_016_requires() {
        let peer = Peer::new(OURS);
        let tagged = Tagged::over(response(), &PAYLOAD, peer.key()).expect("a response tags");
        let mut dst = [0u8; SCRATCH];
        let len = tagged.write(&mut dst).expect("the frame fits the scratch");

        let mut want = [0u8; SCRATCH];
        let mut at = 0usize;
        for chunk in [
            // `[ 0x85, 3, 17,` — one byte over the inline ceiling, so the type
            // is `0x18 0x85` and the two scalars are not.
            &[0x84, 0x18, 0x85, 0x03, 0x11][..],
            // `{ 1: bstr(8)`
            &[0xa2, 0x01, 0x48][..],
            &PAYLOAD[..],
            // `2: bstr(16) }`
            &[0x02, 0x50][..],
            tagged.mac().as_bytes(),
        ] {
            for &byte in chunk {
                let slot = want.get_mut(at).expect("the expectation fits the scratch");
                *slot = byte;
                at = at.saturating_add(1);
            }
        }

        assert_eq!(dst.get(..len), want.get(..at));
    }

    /// A request whose type is inline — the case the frame above cannot show,
    /// because `0x85` needs a prefix byte and `0x05` does not. An encoder that
    /// wrote every type in long form would pass that test and fail this one.
    #[test]
    fn a_type_below_the_inline_ceiling_is_written_without_a_prefix_byte() {
        let peer = Peer::new(OURS);
        let mut dst = [0u8; SCRATCH];
        let len = Tagged::over(request(), &PAYLOAD, peer.key())
            .expect("a request tags")
            .write(&mut dst)
            .expect("the frame fits the scratch");
        assert_eq!(
            dst.get(..5),
            Some(&[0x84, 0x05, 0x03, 0x11, 0xa2][..]),
            "ReadLog is 0x05 and fits inline"
        );
        assert!(len > 5);
    }

    /// P-052's two labels on the sending side. A request and its answer carry
    /// identical fields, so if the label came from the caller rather than from
    /// the `type`, a captured request could be replayed as its own response and
    /// the tag would still check out.
    #[test]
    fn a_captured_request_cannot_be_returned_as_its_own_answer() {
        let peer = Peer::new(OURS);
        let asked = Tagged::over(request(), &PAYLOAD, peer.key()).expect("a request tags");
        let answered = Tagged::over(response(), &PAYLOAD, peer.key()).expect("a response tags");
        assert_ne!(
            asked.mac().as_bytes(),
            answered.mac().as_bytes(),
            "one label for both directions"
        );

        // The request's own payload and tag, lifted into a response envelope —
        // which is the frame a relay in the middle can build for free.
        let replayed = Wire::envelope(response(), 2)
            .bstr(1, &PAYLOAD)
            .bstr(2, asked.mac().as_bytes());
        assert!(matches!(
            replayed.verified(peer.key()),
            Err(WrapperError::Mac(MacError::Mismatch))
        ));
    }

    /// The nine types P-052 does not wrap, refused before a tag exists rather
    /// than tagged under a label somebody guessed. `Hello` and `Pair` prove
    /// themselves from inside their bodies (P-057), the four signed requests
    /// carry a counter (P-053), and `Discover` has no key at all (P-054).
    #[test]
    fn a_message_the_wrapper_does_not_authenticate_cannot_be_tagged_by_it() {
        let peer = Peer::new(OURS);
        for kind in [
            MessageType::Discover,
            MessageType::DiscoverResponse,
            MessageType::Hello,
            MessageType::Pair,
            MessageType::PairResponse,
            MessageType::SetConfig,
            MessageType::Command,
            MessageType::Firmware,
            MessageType::Time,
        ] {
            assert_eq!(
                Tagged::over(header(kind, 17), &PAYLOAD, peer.key()).map(|_| ()),
                Err(WrapperError::NotWrapped(kind)),
                "{kind:?}"
            );
        }
    }

    /// P-023's four zero bytes, enforced where the frame is built. The `evt`
    /// preimage covers a literal `0x00000000`, so a sender that stamped a
    /// `req_id` on an event would put a field on the wire that its own tag does
    /// not cover — the thing P-047 spends four bytes to stop everywhere else.
    #[test]
    fn an_event_cannot_be_tagged_while_it_carries_a_req_id() {
        let peer = Peer::new(OURS);
        for req_id in [1u32, 17, u32::MAX] {
            assert_eq!(
                Tagged::over(
                    header(MessageType::EventResponse, req_id),
                    &PAYLOAD,
                    peer.key()
                )
                .map(|_| ()),
                Err(WrapperError::EventCarriesReqId(ReqId(req_id)))
            );
        }
    }

    /// Every length short of the whole frame, because a writer that stops when
    /// it runs out and reports the bytes it managed is a sender that puts half a
    /// frame on a link and a tag over a body nobody will see.
    #[test]
    fn a_destination_too_small_is_refused_rather_than_written_short() {
        let peer = Peer::new(OURS);
        let tagged = Tagged::over(response(), &PAYLOAD, peer.key()).expect("a response tags");

        let mut full = [0u8; SCRATCH];
        let len = tagged.write(&mut full).expect("the frame fits the scratch");

        for short in 0..len {
            let mut dst = [0u8; SCRATCH];
            let room = dst.get_mut(..short).expect("a prefix of the scratch");
            assert!(
                tagged.write(room).is_err(),
                "wrote a frame of {len} into {short} bytes"
            );
        }
        let mut exact = [0u8; SCRATCH];
        let room = exact.get_mut(..len).expect("a prefix of the scratch");
        assert_eq!(tagged.write(room), Ok(len), "the exact width must fit");
    }

    /// A body on the way out says as little as one on the way in. The `Debug` on
    /// `Wrapper` was written out for this reason and a derive here would undo it
    /// on the sending side, where the payload is one this end chose and the log
    /// is the one a person reads at a bench.
    #[test]
    fn an_outgoing_body_does_not_hand_its_payload_to_a_formatter() {
        let peer = Peer::new(OURS);
        let ours = Rendering::<240>::debugged(
            &Tagged::over(request(), &PAYLOAD, peer.key()).expect("a request tags"),
        );
        let theirs = Rendering::<240>::debugged(
            &Tagged::over(request(), &OTHER_PAYLOAD, peer.key()).expect("a request tags"),
        );
        assert_eq!(
            ours.bytes(),
            theirs.bytes(),
            "two payloads rendered differently, so the rendering carries payload"
        );
    }
}
