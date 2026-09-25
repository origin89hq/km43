//! `[type, session_id, req_id, body]` — the four elements every message wears.
//!
//! The array length is the extension point (P-028), so the refusal has to happen
//! before any element is read: a five-element envelope is a message whose meaning
//! is not knowable, and reading its first four is acting on a message whose fifth
//! may be the one that changes what the other four mean. [`FourElements`] is what
//! makes that structural rather than remembered — nothing here can look at
//! element 0 without holding one, and the only way to hold one is past the check.
//!
//! Two of the refusals are deliberately not error 1. A `type` this version does
//! not allocate is error 2 (P-143) — the frame parsed perfectly, it simply says
//! nothing — and a link-local `type` on a client-facing transport is error 257
//! (P-020), which is a routing bug in the comms processor rather than a client
//! sending nonsense. They want different investigations, so they are different
//! variants and different codes.
//!
//! **P-022 is not cited here.** This file reads `req_id` off the wire as the
//! `u32` the rule says it is, and that sentence is a statement of the field
//! rather than one of its MUSTs. The ones that make it true bind a controller
//! holding per-session state — the highest accepted and the last
//! `MAX_INFLIGHT` — and there is no controller-side session in this crate to
//! hold it. The window, and the silence P-022 requires when it refuses, belong
//! to the controller.
//!
//! cites: P-010, P-020, P-021, P-028, L-002, L-180
//!
//! P-143 was on that list and is not a rule this file implements. It says which
//! refusal a session-requiring request gets — error 4 before any `Hello`, error 9
//! on a session the controller does not hold — and that is a decision a request
//! dispatcher makes, which does not exist yet. Nothing in the tree performs
//! either refusal and no test asserts one, so the header was standing over
//! nothing while the matrix read the rule as covered.

use core::fmt;
use core::num::NonZeroU16;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::generated::{ErrorCode, LinkErrorCode, LinkMessageType, MessageType};

/// P-028's number. It is named because it is the extension point rather than a
/// length: a fifth element is how this protocol grows, and the check is what
/// stops a v1 decoder acting on a shape it was never told about.
const ELEMENTS: usize = 4;

/// The `type` byte before it is anything else.
///
/// P-020's response bit and the link-local range are properties of the byte, not
/// of the message, so they are decided here once rather than at each caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Opcode(u8);

impl Opcode {
    /// P-020: the high bit set means *response to a request*.
    const RESPONSE: u8 = 0x80;

    /// The link-local requests carved out of the request space (LINK.md L-002).
    /// Their responses are `0xE0`–`0xFE`, which is this range with
    /// [`Opcode::RESPONSE`] set.
    const LINK_LOCAL_FIRST: u8 = 0x60;
    const LINK_LOCAL_LAST: u8 = 0x7E;

    const fn of(kind: MessageType) -> Self {
        Self(kind as u8)
    }

    const fn byte(self) -> u8 {
        self.0
    }

    const fn is_response(self) -> bool {
        self.0 & Self::RESPONSE != 0
    }

    /// Both link-local ranges are one range once the response bit is cleared,
    /// which is why there is no second list here to keep in step with LINK.md.
    const fn is_link_local(self) -> bool {
        let request = self.0 & !Self::RESPONSE;
        request >= Self::LINK_LOCAL_FIRST && request <= Self::LINK_LOCAL_LAST
    }

    /// The message this byte names on a client-facing transport. The link-local
    /// check comes first because P-143 says that case is error 257 and says in
    /// as many words that it is *not* error 2.
    fn client_type(self) -> Result<MessageType, EnvelopeError> {
        if self.is_link_local() {
            return Err(EnvelopeError::LinkLocalType(self.0));
        }
        MessageType::try_from(self.0).map_err(|()| EnvelopeError::UnknownType(self.0))
    }
}

const_assert!(
    Opcode::LINK_LOCAL_LAST | Opcode::RESPONSE != 0xFF,
    "the link-local range has to stop below 0x7F, whose response opcode is 0xFF and already spoken for by Error — a request whose response is somebody else's is a trap for whoever allocates last (P-020)"
);

/// A session, or the absence of one.
///
/// Zero is not session zero: P-021 has a client with no session send 0 and the
/// comms processor overwrite it with the connection handle, so a 0 that reaches
/// the controller is a comms-processor bug rather than a client to serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionId {
    /// The client had no session to name (P-021).
    None,
    /// The connection handle the comms processor stamped in, and after `Hello`
    /// the session itself. Never zero, which is what makes the two decidable.
    Assigned(NonZeroU16),
}

impl From<u16> for SessionId {
    fn from(raw: u16) -> Self {
        NonZeroU16::new(raw).map_or(Self::None, Self::Assigned)
    }
}

impl From<SessionId> for u16 {
    fn from(id: SessionId) -> Self {
        match id {
            SessionId::None => 0,
            SessionId::Assigned(raw) => raw.get(),
        }
    }
}

/// P-022's request counter, strictly increasing within a session.
///
/// Zero is a value here rather than an absence: an unsolicited `Event` sends 0
/// (P-023), and so does an error about a frame whose envelope never parsed
/// (P-025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReqId(pub u32);

/// Everything an envelope carries except the body — what a sender fills in and
/// what a receiver dispatches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header {
    /// Which message this is, and — through its high bit — whether it answers
    /// one (P-020).
    pub kind: MessageType,
    /// The connection handle, or the absence of one before `Hello` (P-021).
    pub session: SessionId,
    /// P-022's counter, echoed by whatever answers this frame (P-027).
    pub req_id: ReqId,
}

impl Header {
    /// P-020, read off the opcode rather than off the name: `Event 0x04` is the
    /// one message that arrives without having been asked for, and its generated
    /// name says `Response`.
    #[must_use]
    pub const fn is_response(self) -> bool {
        Opcode::of(self.kind).is_response()
    }

    /// Write the array header, the three scalars and a body map of `keys` pairs,
    /// and hand back the writer standing at the body's first key. The caller
    /// writes the pairs and calls `finish` on it for the encoded length.
    pub fn write(self, keys: usize, dst: &mut [u8]) -> Result<CborWriter<'_>, EnvelopeError> {
        Self::write_scalars(Opcode::of(self.kind), self.session, self.req_id, keys, dst)
    }

    /// The four elements, whichever opcode space the caller is in.
    ///
    /// Shared with [`LinkHeader::write`] because L-010 says a link-local frame
    /// uses this envelope **unchanged**. A second copy is how two formats drift
    /// while both look right.
    fn write_scalars(
        opcode: Opcode,
        session: SessionId,
        req_id: ReqId,
        keys: usize,
        dst: &mut [u8],
    ) -> Result<CborWriter<'_>, EnvelopeError> {
        let mut cbor = CborWriter::new(dst);
        cbor.array(ELEMENTS).map_err(EnvelopeError::Cbor)?;
        cbor.u64(u64::from(opcode.byte()))
            .map_err(EnvelopeError::Cbor)?;
        cbor.u64(u64::from(u16::from(session)))
            .map_err(EnvelopeError::Cbor)?;
        cbor.u64(u64::from(req_id.0)).map_err(EnvelopeError::Cbor)?;
        cbor.map(keys).map_err(EnvelopeError::Cbor)?;
        Ok(cbor)
    }
}

/// A reader standing at element 0 of an envelope whose array header said exactly
/// four.
///
/// This is P-028 made structural. There is no constructor but [`FourElements::open`],
/// which refuses before it hands the reader on, so an accessor added here later
/// still cannot read element 0 of a five-element envelope.
struct FourElements<'a>(CborReader<'a>);

impl<'a> FourElements<'a> {
    fn open(bytes: &'a [u8]) -> Result<Self, EnvelopeError> {
        let mut cbor = CborReader::new(bytes);
        let elements = cbor.array().map_err(EnvelopeError::Cbor)?;
        if elements != ELEMENTS {
            return Err(EnvelopeError::WrongLength);
        }
        Ok(Self(cbor))
    }

    /// The three scalars and the body map, whichever space the opcode is in.
    ///
    /// Shared by both transports on purpose: L-010 says a link-local frame uses
    /// the client protocol's envelope, framing and size limits **unchanged**, and
    /// a second copy of this is how the two formats come to differ while both
    /// look right.
    fn scalars(
        mut cbor: CborReader<'a>,
    ) -> Result<(u8, SessionId, ReqId, usize, CborReader<'a>), EnvelopeError> {
        let opcode = cbor.u8().map_err(EnvelopeError::Cbor)?;
        let session = SessionId::from(cbor.u16().map_err(EnvelopeError::Cbor)?);
        let req_id = ReqId(cbor.u32().map_err(EnvelopeError::Cbor)?);
        let keys = cbor.map().map_err(EnvelopeError::Cbor)?;
        Ok((opcode, session, req_id, keys, cbor))
    }

    fn read_link(self) -> Result<LinkEnvelope<'a>, EnvelopeError> {
        let Self(cbor) = self;
        let (opcode, session, req_id, keys, body) = Self::scalars(cbor)?;
        Ok(LinkEnvelope {
            opcode,
            session,
            req_id,
            keys,
            body,
        })
    }

    fn read(self) -> Result<Envelope<'a>, EnvelopeError> {
        let Self(mut cbor) = self;
        let kind = Opcode(cbor.u8().map_err(EnvelopeError::Cbor)?).client_type()?;
        let session = SessionId::from(cbor.u16().map_err(EnvelopeError::Cbor)?);
        let req_id = ReqId(cbor.u32().map_err(EnvelopeError::Cbor)?);
        let keys = cbor.map().map_err(EnvelopeError::Cbor)?;
        Ok(Envelope {
            header: Header {
                kind,
                session,
                req_id,
            },
            keys,
            body: cbor,
        })
    }
}

/// A decoded envelope and the reader left standing inside its body map.
///
/// The body is not interpreted here: which keys a message carries, and what a
/// repeated one means (P-015), is the body decoder's, and only it knows which
/// numbers it recognises.
#[derive(Debug)]
pub struct Envelope<'a> {
    header: Header,
    keys: usize,
    body: CborReader<'a>,
}

impl<'a> Envelope<'a> {
    /// Decode one client-facing envelope out of bytes that may be anything.
    ///
    /// A `session_id` of 0 is carried as [`SessionId::None`] rather than refused
    /// — P-021 makes that a comms-processor bug, and this layer is not where the
    /// controller decides what to do about one.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, EnvelopeError> {
        FourElements::open(bytes)?.read()
    }

    /// The three scalars, which is what a receiver dispatches and routes on.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// How many key-value pairs the body map promised.
    #[must_use]
    pub const fn keys(&self) -> usize {
        self.keys
    }

    /// The reader, positioned at the body's first key. Read the pairs off it and
    /// call `finish`, which is what refuses a frame with bytes left over.
    #[must_use]
    pub fn into_body(self) -> CborReader<'a> {
        self.body
    }
}

/// The three scalars of a link-local frame.
///
/// The same shape as [`Header`] with the other opcode space, and deliberately a
/// second type rather than a `kind` that could hold either. The two spaces being
/// disjoint is what makes L-020's *no MAC, no shared key* structural: a link
/// message cannot reach `Wrapper` or `Tagged` because it cannot be built into a
/// `Header` at all. One shared enum would delete that guarantee to save a struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LinkHeader {
    /// Which link message this is, and — through its high bit — whether it
    /// answers one.
    pub kind: LinkMessageType,
    /// The connection a message is about, or [`SessionId::None`] for the ones
    /// about the cable itself.
    pub session: SessionId,
    /// Echoed by whatever answers this frame, the same as P-027 one wire over.
    pub req_id: ReqId,
}

impl LinkHeader {
    /// Open a link-local envelope and hand back the writer standing in its body.
    ///
    /// # Errors
    /// `dst` will not hold the envelope.
    pub fn write(self, keys: usize, dst: &mut [u8]) -> Result<CborWriter<'_>, EnvelopeError> {
        Header::write_scalars(
            Opcode(self.kind as u8),
            self.session,
            self.req_id,
            keys,
            dst,
        )
    }
}

/// A decoded link-local envelope and the reader left standing inside its body.
///
/// **The opcode stays a raw byte here.** Typing it is
/// [`arriving`](crate::linklocal::arriving)'s, which refuses one this build does
/// not know, one from the wrong side, and one carrying a session it should not —
/// in that order, because a receiver that reported the session first would send
/// the peer to look at the wrong field. Decoding this envelope into a typed kind
/// would make that decision twice and let the two disagree.
#[derive(Debug)]
pub struct LinkEnvelope<'a> {
    opcode: u8,
    session: SessionId,
    req_id: ReqId,
    keys: usize,
    body: CborReader<'a>,
}

impl<'a> LinkEnvelope<'a> {
    /// Decode one envelope arriving on the link between the two chips.
    ///
    /// The same four-element array, the same guard and the same size limits as
    /// the client path — L-010 says *unchanged*, and this shares the code rather
    /// than restating it.
    ///
    /// # Errors
    /// Not four elements, a client `type`, a `type` this version does not
    /// allocate, or CBOR that will not read.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, EnvelopeError> {
        FourElements::open(bytes)?.read_link()
    }

    /// The raw `type` byte, to hand to
    /// [`arriving`](crate::linklocal::arriving).
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        self.opcode
    }

    /// The connection this is about, or [`SessionId::None`] for the messages
    /// about the cable itself.
    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Echoed by whatever answers this frame.
    #[must_use]
    pub const fn req_id(&self) -> ReqId {
        self.req_id
    }

    /// How many key-value pairs the body map promised.
    #[must_use]
    pub const fn keys(&self) -> usize {
        self.keys
    }

    /// The reader, positioned at the body's first key.
    #[must_use]
    pub fn into_body(self) -> CborReader<'a> {
        self.body
    }
}

/// The code a refusal is answered with, in whichever space it belongs to.
///
/// Widening one to hold the other would make a routing bug in the comms
/// processor look like the client's own request failing, and the two want
/// different retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Refusal {
    /// A code the client is entitled to and can act on.
    Client(ErrorCode),
    /// A code about the two firmwares, which reaches the client only because
    /// L-180 says the three routing faults must (257 is one of them).
    LinkLocal(LinkErrorCode),
}

impl Refusal {
    /// The number that goes into an `Error 0xFF`.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Client(code) => code as u16,
            Self::LinkLocal(code) => code as u16,
        }
    }
}

/// Why an envelope was refused. Each variant is a different answer on the wire,
/// which is why an envelope that is the wrong shape and one that names a message
/// nobody allocated are not the same refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EnvelopeError {
    /// The array length was not exactly four (P-028), refused before any element
    /// was read.
    WrongLength,
    /// A `type` this version does not allocate (P-143). Error 2 rather than
    /// error 1: the frame parsed perfectly, it just says nothing.
    UnknownType(u8),
    /// A link-local `type` on a client-facing transport (P-020, L-002). Error
    /// 257, and a question for whoever wrote the comms processor.
    LinkLocalType(u8),
    /// The CBOR underneath was refused. An envelope that is not an array at all
    /// (P-010), and a body that is not a map, both arrive here as
    /// [`CborError::WrongType`].
    Cbor(CborError),
}

impl EnvelopeError {
    /// What to answer, and in which space.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::WrongLength | Self::Cbor(_) => Refusal::Client(ErrorCode::MalformedFrame),
            Self::UnknownType(_) => Refusal::Client(ErrorCode::UnknownMessageType),
            Self::LinkLocalType(_) => Refusal::LinkLocal(LinkErrorCode::LinkTypeOnClientTransport),
        }
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => f.write_str("envelope array length is not exactly four"),
            Self::UnknownType(opcode) => write!(f, "message type {opcode:#04x} is not allocated"),
            Self::LinkLocalType(opcode) => {
                write!(
                    f,
                    "link-local message type {opcode:#04x} on a client transport"
                )
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for EnvelopeError {}

const_assert!(
    size_of::<EnvelopeError>() == 2,
    "one of these is held per refused frame on a part with 144 KB of RAM; the opcode it carries is the byte a bench log wants and it is the only thing paid for beyond the tag"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Wide enough for any envelope written below, and short enough that a
    /// destination-too-small bug would show rather than hide.
    const SCRATCH: usize = 64;

    /// `[0x81, 0x0102, 0xFFFFFFFF, {1: 12}]` — the four elements at close to
    /// their widest, written out by hand so the tests below compare against
    /// bytes rather than against this crate's own encoder.
    const HELLO_RESPONSE: [u8; 14] = [
        0x84, // array(4)
        0x18, 0x81, // type 0x81
        0x19, 0x01, 0x02, // session_id 0x0102
        0x1a, 0xff, 0xff, 0xff, 0xff, // req_id 0xFFFFFFFF
        0xa1, 0x01, 0x0c, // body {1: 12}
    ];

    /// An envelope carrying `opcode` and an empty body, in long form so that
    /// every one of the 256 values is the same six bytes. A reader that accepts
    /// a long-form integer is doing what P-017 asks of it.
    fn with_type(opcode: u8) -> [u8; 6] {
        [0x84, 0x18, opcode, 0x00, 0x00, 0xa0]
    }

    /// The refusal, or `None` if the bytes decoded. An [`Envelope`] holds a
    /// reader and is not comparable, and the refusal is what these are about.
    fn refused(bytes: &[u8]) -> Option<EnvelopeError> {
        Envelope::decode(bytes).err()
    }

    fn header(kind: MessageType) -> Header {
        Header {
            kind,
            session: SessionId::None,
            req_id: ReqId(0),
        }
    }

    /// Renders a refusal into a fixed buffer, since there is no `String` here.
    fn render(error: EnvelopeError, into: &mut [u8]) -> usize {
        use core::fmt::Write as _;

        struct Sink<'a> {
            into: &'a mut [u8],
            written: usize,
        }

        impl fmt::Write for Sink<'_> {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                for &byte in text.as_bytes() {
                    let slot = self.into.get_mut(self.written).ok_or(fmt::Error)?;
                    *slot = byte;
                    self.written = self.written.saturating_add(1);
                }
                Ok(())
            }
        }

        let mut sink = Sink { into, written: 0 };
        write!(sink, "{error}").expect("every refusal fits eighty bytes");
        sink.written
    }

    fn said<'a>(rendered: &'a [[u8; 80]], lengths: &[usize], index: usize) -> &'a [u8] {
        let whole = rendered.get(index).expect("the index came from the list");
        let len = *lengths.get(index).expect("the index came from the list");
        whole.get(..len).expect("the length came from the render")
    }

    /// The shape everything on this wire is wrapped in, in both directions and
    /// against fixed bytes. An encoder and a decoder that agree with each other
    /// and not with the document is the mistake this crate has already made
    /// once, so the vector is written by hand rather than by the writer.
    #[test]
    fn a_four_element_envelope_round_trips_through_the_bytes_the_document_shows() {
        let mut buf = [0u8; SCRATCH];
        let sent = Header {
            kind: MessageType::HelloResponse,
            session: SessionId::from(0x0102),
            req_id: ReqId(0xFFFF_FFFF),
        };
        let mut writer = sent.write(1, &mut buf).expect("the envelope is written");
        writer.key(1).expect("the body's only key");
        writer.u64(12).expect("its value");
        let len = writer.finish().expect("the body was complete");
        assert_eq!(
            buf.get(..len).expect("the writer's own length"),
            &HELLO_RESPONSE[..],
            "the encoder and the hand-written envelope have parted company"
        );

        let envelope = Envelope::decode(&HELLO_RESPONSE).expect("the envelope decodes");
        assert_eq!(envelope.header(), sent);
        assert_eq!(envelope.keys(), 1);
        assert!(sent.is_response());

        let mut body = envelope.into_body();
        assert_eq!(body.key(), Ok(1));
        assert_eq!(body.u64(), Ok(12));
        body.finish().expect("the envelope ends exactly there");
    }

    /// P-028, and the requirement is the *ordering*: refuse before reading an
    /// element. Every fixture below has a five-element header over a first
    /// element that would produce its own distinct refusal if anything read it —
    /// a float, a tag, a text string, an out-of-range integer, a link-local
    /// type, an unallocated type. All six must come back as the same refusal.
    ///
    /// Without the ordering, one implementation reads the first four elements
    /// and acts on a message whose fifth it cannot see, and the fifth may be the
    /// one that changes what the other four mean.
    #[test]
    fn a_five_element_envelope_is_refused_before_element_zero_is_read() {
        // Four perfectly good elements and a fifth. Read the first four and
        // this succeeds, which is the failure P-028 is about.
        let appended: [u8; 15] = [
            0x85, 0x18, 0x81, 0x19, 0x01, 0x02, 0x1a, 0xff, 0xff, 0xff, 0xff, 0xa1, 0x01, 0x0c,
            0x00,
        ];
        assert_eq!(
            refused(&appended),
            Some(EnvelopeError::WrongLength),
            "a v1 decoder must not read the four elements it recognises"
        );

        // Each of these poisons element 0 with something that refuses loudly and
        // differently. The refusal that comes back names the length every time,
        // which is only possible if nothing looked at element 0.
        let poisoned: [(&[u8], &str); 6] = [
            (
                &[0x85, 0xf9, 0x00, 0x00, 0x00, 0x00, 0x00],
                "a float would be FloatNotAllowed",
            ),
            (
                &[0x85, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00],
                "a tag would be TagNotAllowed",
            ),
            (
                &[0x85, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00],
                "a text string would be WrongType",
            ),
            (
                &[0x85, 0x19, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
                "a type of 0x100 would be IntegerOutOfRange",
            ),
            (
                &[0x85, 0x18, 0x60, 0x00, 0x00, 0x00, 0x00],
                "a link-local type would be LinkLocalType",
            ),
            (
                &[0x85, 0x18, 0x0d, 0x00, 0x00, 0x00, 0x00],
                "an unallocated type would be UnknownType",
            ),
        ];
        for (bytes, otherwise) in poisoned {
            assert_eq!(
                refused(bytes),
                Some(EnvelopeError::WrongLength),
                "element 0 was read: {otherwise}"
            );
        }
    }

    /// The other side of P-028, and the one an over-eager decoder gets wrong by
    /// reading what is there and defaulting the rest. A three-element envelope
    /// has no `body`, and a body defaulted to empty is a `Command` with no
    /// command in it.
    #[test]
    fn a_three_element_envelope_is_refused_before_element_zero_is_read() {
        let short: [u8; 11] = [
            0x83, 0x18, 0x81, 0x19, 0x01, 0x02, 0x1a, 0xff, 0xff, 0xff, 0xff,
        ];
        assert_eq!(refused(&short), Some(EnvelopeError::WrongLength));

        // Poisoned the same way: a float first would be FloatNotAllowed if the
        // element were read before the length was checked.
        let poisoned: [u8; 6] = [0x83, 0xf9, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            refused(&poisoned),
            Some(EnvelopeError::WrongLength),
            "element 0 was read: a float would be FloatNotAllowed"
        );
    }

    /// An empty array is a well-formed CBOR item and an envelope with nothing in
    /// it. A decoder that treated a missing `type` as 0 would dispatch it as
    /// `Discover` — every field absent, and absence read as a value.
    #[test]
    fn an_empty_envelope_array_is_not_a_discover_with_every_field_zero() {
        assert_eq!(refused(&[0x80]), Some(EnvelopeError::WrongLength));
    }

    /// P-010 says envelopes are arrays. A map of four is the near miss: four
    /// somethings, the right count, and a decoder that only counted would read a
    /// key as a `type`.
    #[test]
    fn an_envelope_that_is_not_an_array_is_refused_however_close_it_looks() {
        let map_of_four: [u8; 9] = [0xa4, 0x01, 0x01, 0x02, 0x02, 0x03, 0x03, 0x04, 0x04];
        assert_eq!(
            refused(&map_of_four),
            Some(EnvelopeError::Cbor(CborError::WrongType))
        );
        assert_eq!(
            refused(&[0x00]),
            Some(EnvelopeError::Cbor(CborError::WrongType))
        );
        assert_eq!(
            refused(&[0x64, 0x49, 0x45, 0x54, 0x46]),
            Some(EnvelopeError::Cbor(CborError::WrongType))
        );
        assert_eq!(
            refused(&[]),
            Some(EnvelopeError::Cbor(CborError::EndOfInput))
        );
    }

    /// Each field at the edge of its own width. A `type` of 0x100 truncated to a
    /// byte is 0x00, which is `Discover` — so a decoder that narrowed instead of
    /// refusing would dispatch a message nobody sent.
    #[test]
    fn a_field_wider_than_its_width_is_refused_rather_than_narrowed() {
        // type: 0xFF is the widest allocated one and it decodes.
        let widest_type: [u8; 6] = [0x84, 0x18, 0xff, 0x00, 0x00, 0xa0];
        let envelope = Envelope::decode(&widest_type).expect("0xFF is Error");
        assert_eq!(envelope.header().kind, MessageType::ErrorResponse);
        // 0x100 is one past a byte, and its low byte is Discover.
        let too_wide: [u8; 7] = [0x84, 0x19, 0x01, 0x00, 0x00, 0x00, 0xa0];
        assert_eq!(
            refused(&too_wide),
            Some(EnvelopeError::Cbor(CborError::IntegerOutOfRange))
        );

        // session_id: 0xFFFF decodes, 0x10000 does not.
        let widest_session: [u8; 7] = [0x84, 0x00, 0x19, 0xff, 0xff, 0x00, 0xa0];
        let envelope = Envelope::decode(&widest_session).expect("0xFFFF is a handle");
        assert_eq!(u16::from(envelope.header().session), 0xFFFF);
        let too_wide: [u8; 9] = [0x84, 0x00, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0];
        assert_eq!(
            refused(&too_wide),
            Some(EnvelopeError::Cbor(CborError::IntegerOutOfRange))
        );

        // req_id: 0xFFFFFFFF decodes — P-022 spends two extra bytes per frame on
        // exactly this range, so a decoder that stopped at a u16 would refuse
        // every request a client made after its first sixty-five thousand.
        let widest_req: [u8; 9] = [0x84, 0x00, 0x00, 0x1a, 0xff, 0xff, 0xff, 0xff, 0xa0];
        let envelope = Envelope::decode(&widest_req).expect("0xFFFFFFFF is a req_id");
        assert_eq!(envelope.header().req_id, ReqId(0xFFFF_FFFF));
        let too_wide: [u8; 13] = [
            0x84, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa0,
        ];
        assert_eq!(
            refused(&too_wide),
            Some(EnvelopeError::Cbor(CborError::IntegerOutOfRange))
        );
    }

    /// A negative anything in an envelope is a sender that has gone wrong, and a
    /// decoder that took the two's-complement byte would read `-1` as `Error`.
    #[test]
    fn a_negative_envelope_field_is_out_of_range_rather_than_wrapped() {
        for at in 1usize..=3 {
            let mut bytes: [u8; 5] = [0x84, 0x00, 0x00, 0x00, 0xa0];
            let slot = bytes.get_mut(at).expect("the three scalars are 1..=3");
            *slot = 0x20; // -1
            assert_eq!(
                refused(&bytes),
                Some(EnvelopeError::Cbor(CborError::IntegerOutOfRange)),
                "element {at} carrying -1"
            );
        }
    }

    /// P-021: zero is the absence of a session, not a session anybody is in. A
    /// decoder that carried it as a number would let eight pre-session clients
    /// share one session, and the first `Hello` to arrive would answer all of
    /// them.
    #[test]
    fn a_session_id_of_zero_is_the_absence_of_a_session_not_session_zero() {
        let no_session: [u8; 5] = [0x84, 0x00, 0x00, 0x00, 0xa0];
        let envelope = Envelope::decode(&no_session).expect("a pre-session Discover");
        assert_eq!(envelope.header().session, SessionId::None);

        let handle: [u8; 5] = [0x84, 0x00, 0x01, 0x00, 0xa0];
        let envelope = Envelope::decode(&handle).expect("a stamped handle");
        let SessionId::Assigned(id) = envelope.header().session else {
            panic!("a handle of 1 must not read as the absence of a session");
        };
        assert_eq!(id.get(), 1);

        // And the two survive the trip back out, so a controller echoing a
        // pre-session request under P-026 cannot turn a 0 into a 1.
        assert_eq!(u16::from(SessionId::None), 0);
        for raw in [1u16, 2, 0x7FFF, 0xFFFF] {
            assert_eq!(u16::from(SessionId::from(raw)), raw, "session_id {raw}");
        }
    }

    /// L-002 and P-020. A link-local `type` reaching a client transport means
    /// the comms processor forwarded something it was told to drop, and P-143
    /// says in as many words that this is not error 2 — a routing bug in our own
    /// firmware and a client sending nonsense want different investigations.
    #[test]
    fn a_link_local_type_on_a_client_transport_is_error_257_and_not_error_2() {
        for opcode in [0x60u8, 0x61, 0x6f, 0x7e, 0xe0, 0xe1, 0xef, 0xfe] {
            let bytes = with_type(opcode);
            assert_eq!(
                refused(&bytes),
                Some(EnvelopeError::LinkLocalType(opcode)),
                "type {opcode:#04x}"
            );
            assert_eq!(
                EnvelopeError::LinkLocalType(opcode).refusal(),
                Refusal::LinkLocal(LinkErrorCode::LinkTypeOnClientTransport)
            );
            assert_eq!(
                EnvelopeError::LinkLocalType(opcode).refusal().code(),
                257,
                "the document names 257"
            );
        }
    }

    /// P-143: a `type` nobody allocated is error 2 and bare, not error 1 and not
    /// silence. The frame parsed perfectly — it simply says nothing — and a
    /// client that hears nothing waits out its own timeout with an empty screen.
    #[test]
    fn an_unallocated_type_is_error_2_rather_than_dropped_or_called_malformed() {
        for opcode in [0x15u8, 0x16, 0x1f, 0x5f, 0x7f, 0x95, 0xdf] {
            let bytes = with_type(opcode);
            assert_eq!(
                refused(&bytes),
                Some(EnvelopeError::UnknownType(opcode)),
                "type {opcode:#04x}"
            );
            assert_eq!(
                EnvelopeError::UnknownType(opcode).refusal(),
                Refusal::Client(ErrorCode::UnknownMessageType)
            );
            assert_eq!(EnvelopeError::UnknownType(opcode).refusal().code(), 2);
        }
        // And the refusals that are error 1, so the three codes are pinned to
        // the three conditions rather than to whichever one was written last.
        assert_eq!(EnvelopeError::WrongLength.refusal().code(), 1);
        assert_eq!(
            EnvelopeError::Cbor(CborError::WrongType).refusal().code(),
            1
        );
    }

    /// Every byte, because the link-local range is a hole punched in the
    /// allocated space and the two lists live in different files. An opcode that
    /// were both would be refused as a comms-processor bug while a client sat
    /// waiting for an answer it was entitled to.
    #[test]
    fn no_allocated_opcode_hides_inside_the_link_local_range() {
        for opcode in 0u8..=0xFF {
            let link_local = (0x60..=0x7E).contains(&opcode) || (0xE0..=0xFE).contains(&opcode);
            let bytes = with_type(opcode);
            match Envelope::decode(&bytes) {
                Ok(envelope) => {
                    assert!(
                        !link_local,
                        "{opcode:#04x} is allocated and link-local at once"
                    );
                    assert_eq!(
                        envelope.header().is_response(),
                        opcode & 0x80 != 0,
                        "{opcode:#04x}: the response bit is read off the byte"
                    );
                }
                Err(EnvelopeError::LinkLocalType(got)) => {
                    assert!(link_local, "{opcode:#04x} is not in the link-local range");
                    assert_eq!(got, opcode);
                }
                Err(EnvelopeError::UnknownType(got)) => {
                    assert!(!link_local, "{opcode:#04x} is link-local, not unallocated");
                    assert_eq!(got, opcode);
                }
                Err(EnvelopeError::WrongLength | EnvelopeError::Cbor(_)) => {
                    panic!("{opcode:#04x}: the fixture is a well-formed four-element envelope")
                }
            }
        }
    }

    /// `Event` has no request, so the generator named its only opcode
    /// `EventResponse` — and 0x04 has no high bit. A decoder that read the name
    /// instead of the bit would call every event a response, and a client
    /// obeying P-024 drops a response matching no outstanding request: every
    /// alarm from the site, dropped, silently.
    #[test]
    fn the_unsolicited_event_is_not_a_response_despite_its_generated_name() {
        assert!(!header(MessageType::EventResponse).is_response());
        assert!(!header(MessageType::Hello).is_response());
        assert!(!header(MessageType::Command).is_response());
        assert!(header(MessageType::HelloResponse).is_response());
        assert!(header(MessageType::CommandResponse).is_response());
        assert!(header(MessageType::ErrorResponse).is_response());
    }

    /// P-010 says the fourth element is a map, and P-011 says a body's keys are
    /// integers. An array there would read its first element as a key and turn
    /// a body into whatever the first value happened to be.
    #[test]
    fn a_body_that_is_not_a_map_is_refused() {
        let array_body: [u8; 5] = [0x84, 0x00, 0x00, 0x00, 0x80];
        assert_eq!(
            refused(&array_body),
            Some(EnvelopeError::Cbor(CborError::WrongType))
        );
        let integer_body: [u8; 5] = [0x84, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            refused(&integer_body),
            Some(EnvelopeError::Cbor(CborError::WrongType))
        );
    }

    /// Every prefix of a valid envelope. A frame cut short by a link that
    /// dropped carrier must never read as a shorter valid envelope — at every
    /// single cut point, including the ones inside a multi-byte integer.
    #[test]
    fn every_truncation_of_an_envelope_is_refused() {
        for cut in 0..HELLO_RESPONSE.len() {
            let prefix = HELLO_RESPONSE.get(..cut).expect("cut is below the length");
            assert!(
                Envelope::decode(prefix).is_err(),
                "an envelope cut at {cut} of {} bytes must be refused",
                HELLO_RESPONSE.len()
            );
        }
        assert!(Envelope::decode(&HELLO_RESPONSE).is_ok());
    }

    /// The eleven bytes every derivation in `limits.rs` spends on an envelope.
    /// If the encoder ever costs twelve, `MAX_CHANNELS` and `MAX_LOG_PAGE_BYTES`
    /// are both a byte optimistic and the frame that does not fit is built at a
    /// fully configured site rather than on a bench.
    #[test]
    fn the_widest_envelope_is_the_eleven_bytes_the_limits_arithmetic_spends() {
        let mut buf = [0u8; SCRATCH];
        let widest = Header {
            kind: MessageType::ErrorResponse,
            session: SessionId::from(0xFFFF),
            req_id: ReqId(u32::MAX),
        };
        let writer = widest.write(0, &mut buf).expect("an empty body");
        let len = writer.finish().expect("nothing was left open");
        assert_eq!(
            len, 12,
            "eleven bytes of envelope and one for an empty body map"
        );
    }

    /// The composition this module exists for: the envelope hands the body
    /// decoder a reader that is already inside the map, with the nesting
    /// accounted for, so P-013's skip works and `finish` still refuses trailing
    /// bytes. A reader handed back out of position would lose the outer array
    /// and accept a frame with something appended.
    #[test]
    fn the_body_reader_comes_back_inside_the_map_with_the_array_still_counted() {
        let mut buf = [0u8; SCRATCH];
        let sent = Header {
            kind: MessageType::Readings,
            session: SessionId::from(7),
            req_id: ReqId(9),
        };
        let mut writer = sent.write(3, &mut buf).expect("the envelope is written");
        writer.key(1).expect("a key this version knows");
        writer.u64(7).expect("its value");
        writer.key(9).expect("a key from a newer sender");
        writer.array(2).expect("and it is a whole nested body");
        writer.u64(1).expect("one");
        writer.bool(true).expect("two");
        writer.key(11).expect("a key this version knows again");
        writer.u64(42).expect("its value");
        let len = writer.finish().expect("nothing was left open");

        let message = buf.get(..len).expect("the writer's own length");
        let envelope = Envelope::decode(message).expect("the envelope decodes");
        assert_eq!(envelope.header(), sent);
        assert_eq!(envelope.keys(), 3);

        let mut body = envelope.into_body();
        assert_eq!(body.key(), Ok(1));
        assert_eq!(body.u64(), Ok(7));
        assert_eq!(body.key(), Ok(9));
        body.skip().expect("an unknown key's value is skipped");
        assert_eq!(body.key(), Ok(11));
        assert_eq!(body.u64(), Ok(42));
        body.finish().expect("the envelope ends exactly there");

        // One byte appended, and the same read has to refuse it: that byte is a
        // field one implementation sees inside a frame both authenticated.
        let mut longer = [0u8; SCRATCH];
        for (slot, &byte) in longer.iter_mut().zip(message.iter()) {
            *slot = byte;
        }
        let appended = longer
            .get(..len.saturating_add(1))
            .expect("the scratch is wider");
        let envelope = Envelope::decode(appended).expect("the envelope still decodes");
        let mut body = envelope.into_body();
        for _ in 0..3 {
            body.key().expect("a key");
            body.skip().expect("its value");
        }
        assert_eq!(body.finish(), Err(CborError::TrailingBytes));
    }

    /// Every refusal renders as its own sentence. Two that share a line is a
    /// bench log naming the wrong cause, and the two here that are one byte
    /// apart on the wire — an unallocated type and a link-local one — are
    /// exactly the pair somebody will be trying to tell apart.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [EnvelopeError; 5] = [
            EnvelopeError::WrongLength,
            EnvelopeError::UnknownType(0x60),
            EnvelopeError::LinkLocalType(0x60),
            EnvelopeError::Cbor(CborError::WrongType),
            EnvelopeError::Cbor(CborError::EndOfInput),
        ];
        let mut rendered = [[0u8; 80]; EVERY.len()];
        let mut lengths = [0usize; EVERY.len()];
        for (index, error) in EVERY.iter().enumerate() {
            let slot = rendered
                .get_mut(index)
                .expect("the buffer is as long as the list");
            let written = render(*error, slot);
            assert!(written > 0, "{error:?} renders as nothing");
            let length = lengths
                .get_mut(index)
                .expect("the buffer is as long as the list");
            *length = written;
        }
        for first in 0..EVERY.len() {
            for second in first.saturating_add(1)..EVERY.len() {
                assert_ne!(
                    said(&rendered, &lengths, first),
                    said(&rendered, &lengths, second),
                    "refusals {first} and {second} render the same sentence"
                );
            }
        }
    }

    /// The writer refuses a destination it cannot finish rather than leaving
    /// half an envelope in a caller's buffer, which is a frame that still parses
    /// at the far end as a shorter message carrying other fields.
    #[test]
    fn an_envelope_that_will_not_fit_is_refused_rather_than_truncated() {
        let sent = Header {
            kind: MessageType::HelloResponse,
            session: SessionId::from(0x0102),
            req_id: ReqId(0xFFFF_FFFF),
        };
        for short in 0..11 {
            let mut buf = [0u8; SCRATCH];
            let dst = buf.get_mut(..short).expect("short is below the scratch");
            assert_eq!(
                sent.write(0, dst).err(),
                Some(EnvelopeError::Cbor(CborError::DestinationTooSmall)),
                "an {short}-byte destination for an eleven-byte envelope"
            );
        }
    }
}
