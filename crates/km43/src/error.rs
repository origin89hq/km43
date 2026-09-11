//! `Error 0xFF` — a refusal, and the two shapes it comes in.
//!
//! Which shape a sender uses is P-142 and nothing else: wrapped when it holds a
//! session for that `session_id`, bare when it does not. A receiver does **not**
//! decide by looking at the body — letting the body choose is letting the comms
//! processor strip the MAC off a refusal to hide it.
//!
//! The registry's MAC'd column is the other half and it is the *receiver's*
//! check: the list of codes a receiver refuses to read out of a bare body. Read
//! as an instruction to the sender it is a rule that cannot be obeyed, because
//! the conditions with genuinely no session are exactly the ones with no key to
//! honour it with. So a bare error carrying error 6, 7 or 11 is discarded here
//! rather than acted on, and everything else arrives as a [`Hint`].
//!
//! cites: P-140, P-142
use core::fmt;

use crate::cbor::{CborError, CborReader, CborWriter};
use crate::envelope::{Envelope, Header, Refusal};
use crate::generated::{ErrorCode, Incoming, MessageType};

/// The two keys of an `Error 0xFF` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKey {
    /// Key 1.
    Code,
    /// Key 2, at most [`crate::MAX_STRING`] bytes.
    Detail,
}

impl ErrorKey {
    const COUNT: usize = 2;

    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Code),
            2 => Some(Self::Detail),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Code => 1,
            Self::Detail => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Detail => "detail",
        }
    }
}

impl fmt::Display for ErrorKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error 0xFF {} (key {})", self.name(), self.number())
    }
}

/// The body itself, before anything has decided what it is worth.
///
/// `code` is an [`Incoming`], which keeps the client space and the link-local
/// space apart: a routing fault in the comms processor must not read as this
/// client's own request failing, and the two want different retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorBody<'a> {
    /// Key 1.
    pub code: Incoming,
    /// Key 2 — a sentence for a person, never something to branch on.
    pub detail: &'a str,
}

impl<'a> ErrorBody<'a> {
    /// Encode the two keys. The caller decides the shape under P-142; this is
    /// the body that goes bare, or inside the wrapper.
    pub fn encode(self, dst: &mut [u8]) -> Result<usize, ErrorBodyError> {
        let mut cbor = CborWriter::new(dst);
        cbor.map(ErrorKey::COUNT)?;
        cbor.key(ErrorKey::Code.number())?;
        cbor.u64(u64::from(wire(self.code)))?;
        cbor.key(ErrorKey::Detail.number())?;
        cbor.text(self.detail)?;
        Ok(cbor.finish()?)
    }

    /// Write the whole **bare** `Error 0xFF` envelope and hand back its length.
    ///
    /// The bare form puts these two keys straight into the envelope's map;
    /// [`Self::encode`] writes the standalone map that goes *inside* a wrapper.
    /// Which one a sender uses is P-142 and nothing else — wrapped when it holds
    /// a session for that `session_id`, bare when it does not — so both shapes
    /// live here rather than being assembled at each call site.
    ///
    /// # Errors
    /// The header does not name `Error`, or the body will not fit `dst`.
    pub fn write(self, header: Header, dst: &mut [u8]) -> Result<usize, ErrorBodyError> {
        if header.kind != MessageType::ErrorResponse {
            return Err(ErrorBodyError::WrongMessage(header.kind));
        }
        let mut cbor = header
            .write(ErrorKey::COUNT, dst)
            .map_err(|_| ErrorBodyError::Cbor(CborError::DestinationTooSmall))?;
        cbor.key(ErrorKey::Code.number())?;
        cbor.u64(u64::from(wire(self.code)))?;
        cbor.key(ErrorKey::Detail.number())?;
        cbor.text(self.detail)?;
        Ok(cbor.finish()?)
    }

    /// Read one out of a **bare** envelope, applying the receiver's rule.
    ///
    /// The counterpart of [`Self::write`]: the two keys are the envelope's own,
    /// so there is no payload to hand to [`Self::bare`].
    ///
    /// # Errors
    /// The envelope does not name `Error`, will not decode, or carries a code
    /// the registry marks MAC'd — which P-051 discards rather than acts on.
    pub fn from_envelope(envelope: Envelope<'a>) -> Result<Hint<'a>, ErrorBodyError> {
        let kind = envelope.header().kind;
        if kind != MessageType::ErrorResponse {
            return Err(ErrorBodyError::WrongMessage(kind));
        }
        let pairs = envelope.keys();
        let found = Self::read(envelope.into_body(), pairs)?;
        if let Incoming::Client(code) = found.code
            && code.needs_a_mac()
        {
            return Err(ErrorBodyError::BareCodeNeedsAMac(code));
        }
        Ok(Hint(found))
    }

    /// Read one out of a payload a wrapper MAC has already covered.
    ///
    /// The MAC'd column does not apply here: it is the rule for a *bare* body,
    /// and this one arrived under a key.
    pub fn authenticated(payload: &'a [u8]) -> Result<Self, ErrorBodyError> {
        Self::decode(payload)
    }

    /// Read one out of a **bare** body, applying the receiver's rule.
    ///
    /// A code the registry marks MAC'd is discarded rather than acted on
    /// (P-051): those are the refusals a controller only ever sends with a key
    /// in hand, so one arriving without a tag is one the comms processor wrote.
    /// Everything else comes back as a [`Hint`] — never a fact about the site.
    pub fn bare(payload: &'a [u8]) -> Result<Hint<'a>, ErrorBodyError> {
        let body = Self::decode(payload)?;
        if let Incoming::Client(code) = body.code
            && code.needs_a_mac()
        {
            return Err(ErrorBodyError::BareCodeNeedsAMac(code));
        }
        Ok(Hint(body))
    }

    fn decode(payload: &'a [u8]) -> Result<Self, ErrorBodyError> {
        let mut body = CborReader::new(payload);
        let pairs = body.map()?;
        Self::read(body, pairs)
    }

    /// The two keys, from a reader already standing at them.
    ///
    /// Shared because the bare envelope and the wrapped payload differ only in
    /// who opened the map — and a second copy of this loop is how the two shapes
    /// come to disagree about which keys are required.
    fn read(mut body: CborReader<'a>, pairs: usize) -> Result<Self, ErrorBodyError> {
        let mut code = None;
        let mut detail = None;
        for _ in 0..pairs {
            let number = body.key()?;
            match ErrorKey::of(number) {
                Some(key @ ErrorKey::Code) => once(&mut code, key, body.u16()?)?,
                Some(key @ ErrorKey::Detail) => once(&mut detail, key, body.text()?)?,
                None => body.skip()?,
            }
        }
        body.finish()?;
        let detail = detail.ok_or(ErrorBodyError::Missing(ErrorKey::Detail))?;
        Ok(Self {
            code: Incoming::from(code.ok_or(ErrorBodyError::Missing(ErrorKey::Code))?),
            detail,
        })
    }
}

/// An error nobody authenticated.
///
/// P-140 is P-055 for this message: a client MAY retry or reconnect on one of
/// these and MUST conclude nothing else. In particular it MUST NOT conclude that
/// its earlier writes did not land — the two sides can disagree about whether a
/// session is live, and a bare error 9 where a wrapper was expected is exactly
/// that disagreement rather than news about the site.
///
/// The wrapper is a separate type so the difference survives being passed to a
/// function: an [`ErrorBody`] came out of something authenticated, and a `Hint`
/// did not.
///
/// ```compile_fail
/// use km43::{ErrorBody, Hint};
/// fn take(hint: Hint<'_>) -> ErrorBody<'_> { hint }
/// ```
/// ```
/// use km43::Hint;
/// fn take(hint: Hint<'_>) -> Hint<'_> { hint }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hint<'a>(ErrorBody<'a>);

impl<'a> Hint<'a> {
    /// What the sender said. Enough to decide between retrying and
    /// reconnecting, which is all P-140 licenses.
    #[must_use]
    pub const fn code(self) -> Incoming {
        self.0.code
    }

    /// The sentence, for a log a person reads. Never something to branch on —
    /// nobody authenticated it.
    #[must_use]
    pub const fn detail(self) -> &'a str {
        self.0.detail
    }
}

/// The number a code goes out as, from whichever space it belongs to.
///
/// Genuinely free: it takes a code and belongs to no state.
const fn wire(code: Incoming) -> u16 {
    match code {
        Incoming::Client(code) => code as u16,
        Incoming::LinkLocal(code) => code as u16,
        Incoming::Unknown(raw) => raw,
    }
}

fn once<T>(slot: &mut Option<T>, key: ErrorKey, value: T) -> Result<(), ErrorBodyError> {
    if slot.is_some() {
        return Err(ErrorBodyError::Duplicate(key));
    }
    *slot = Some(value);
    Ok(())
}

/// Why an `Error` body was refused. Refusing one is never answered with another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorBodyError {
    /// A required key never arrived (P-015).
    Missing(ErrorKey),
    /// The same key twice (P-015), refused before either copy is used.
    Duplicate(ErrorKey),
    /// A bare body carrying a code the registry marks MAC'd — discarded rather
    /// than acted on, because the controller only ever sends this one with a key
    /// in hand.
    BareCodeNeedsAMac(ErrorCode),
    /// The CBOR underneath was refused.
    Cbor(CborError),
    /// An envelope whose `type` is not `Error`.
    WrongMessage(MessageType),
}

impl From<CborError> for ErrorBodyError {
    fn from(why: CborError) -> Self {
        Self::Cbor(why)
    }
}

impl ErrorBodyError {
    /// What to answer — and the answer is nothing.
    ///
    /// An `Error` answering an `Error` is the amplifier P-031 refuses to build
    /// one flipped bit at a time. The code is here because every refusal in this
    /// crate carries one and a variant that is not error 1 has to say so; what a
    /// caller does with it is drop the frame.
    #[must_use]
    pub const fn refusal(self) -> Refusal {
        match self {
            Self::Missing(_) | Self::Duplicate(_) | Self::BareCodeNeedsAMac(_) | Self::Cbor(_) => {
                Refusal::Client(ErrorCode::MalformedFrame)
            }
            // Error 2 rather than error 1: the bytes were well formed, they
            // simply were not this message. Saying `malformed` sends somebody
            // looking at an encoder that is fine.
            Self::WrongMessage(_) => Refusal::Client(ErrorCode::UnknownMessageType),
        }
    }
}

impl fmt::Display for ErrorBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(key) => write!(f, "error carries no {key}"),
            Self::Duplicate(key) => write!(f, "error carries {key} twice"),
            Self::BareCodeNeedsAMac(code) => write!(
                f,
                "error {} arrived bare and a receiver only reads it under a MAC",
                *code as u16
            ),
            Self::Cbor(why) => write!(f, "{why}"),
            Self::WrongMessage(kind) => {
                write!(f, "an envelope naming {kind:?} is not an error")
            }
        }
    }
}

impl core::error::Error for ErrorBodyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ReqId, SessionId};
    use crate::generated::LinkErrorCode;
    use crate::limits::MAX_STRING;
    use crate::render::Rendering;

    const SCRATCH: usize = 128;

    fn encoded(body: ErrorBody<'_>) -> ([u8; SCRATCH], usize) {
        let mut dst = [0u8; SCRATCH];
        let len = body.encode(&mut dst).expect("the fixture encodes");
        (dst, len)
    }

    /// The list and the numbers live in three places apiece.
    #[test]
    fn every_key_number_maps_back_to_the_key_that_claims_it() {
        for n in 1..=ErrorKey::COUNT {
            let number = i64::try_from(n).expect("small");
            assert_eq!(ErrorKey::of(number).expect("a key").number(), number);
        }
        assert!(ErrorKey::of(0).is_none());
        assert!(ErrorKey::of(-1).is_none());
        assert!(ErrorKey::of(3).is_none());
    }

    /// A refusal arrives saying what the sender said.
    #[test]
    fn a_refusal_arrives_saying_what_the_sender_said() {
        let sent = ErrorBody {
            code: Incoming::Client(ErrorCode::HelloRequiredFirst),
            detail: "no session on this connection",
        };
        let (dst, len) = encoded(sent);
        let read =
            ErrorBody::authenticated(dst.get(..len).expect("the length")).expect("it decodes");
        assert_eq!(read, sent);
    }

    /// The registry's MAC'd column is the **receiver's** rule, and this is it.
    ///
    /// Codes 6, 7 and 11 are the ones a controller only ever sends with a key in
    /// hand, so one arriving bare is one the comms processor wrote. Discarded
    /// rather than acted on — a forged error 7 `busy` that a client believes is
    /// a client that stops asking.
    #[test]
    fn a_bare_error_envelope_round_trips_through_the_shape_the_spec_names() {
        let header = Header {
            kind: MessageType::ErrorResponse,
            session: SessionId::None,
            req_id: ReqId(7),
        };
        let mut dst = [0u8; 256];
        let len = ErrorBody {
            code: Incoming::Client(ErrorCode::UnknownClient),
            detail: "no enrolment at that slot",
        }
        .write(header, &mut dst)
        .expect("the bare form encodes");

        let envelope = Envelope::decode(dst.get(..len).expect("the frame")).expect("an envelope");
        assert_eq!(
            envelope.header().req_id,
            ReqId(7),
            "it answered another request"
        );
        let hint = ErrorBody::from_envelope(envelope).expect("a hint");
        assert_eq!(hint.code(), Incoming::Client(ErrorCode::UnknownClient));
        assert_eq!(hint.detail(), "no enrolment at that slot");
    }

    /// The receiver's rule applies to the envelope form too. It would be easy to
    /// add a second door into this body and leave P-051 on the first one.
    #[test]
    fn a_bare_error_envelope_carrying_a_macd_code_is_discarded_too() {
        let header = Header {
            kind: MessageType::ErrorResponse,
            session: SessionId::None,
            req_id: ReqId(1),
        };
        let mut dst = [0u8; 256];
        let len = ErrorBody {
            code: Incoming::Client(ErrorCode::BusyRetry),
            detail: "forged",
        }
        .write(header, &mut dst)
        .expect("it encodes");
        let envelope = Envelope::decode(dst.get(..len).expect("the frame")).expect("an envelope");
        assert_eq!(
            ErrorBody::from_envelope(envelope).map(|_| ()),
            Err(ErrorBodyError::BareCodeNeedsAMac(ErrorCode::BusyRetry))
        );
    }

    /// An envelope naming another message is refused rather than read as one.
    #[test]
    fn an_envelope_that_is_not_an_error_is_not_read_as_one() {
        let mut dst = [0u8; 256];
        let cbor = Header {
            kind: MessageType::Discover,
            session: SessionId::None,
            req_id: ReqId(1),
        }
        .write(0, &mut dst)
        .expect("it opens");
        let len = cbor.finish().expect("it closes");
        let envelope = Envelope::decode(dst.get(..len).expect("the frame")).expect("an envelope");
        assert_eq!(
            ErrorBody::from_envelope(envelope).map(|_| ()),
            Err(ErrorBodyError::WrongMessage(MessageType::Discover))
        );
    }

    #[test]
    fn p_142_a_bare_error_carrying_a_macd_code_is_discarded_rather_than_read() {
        for code in [
            ErrorCode::UnknownSection,
            ErrorCode::BusyRetry,
            ErrorCode::CounterNotFresh,
        ] {
            assert!(
                code.needs_a_mac(),
                "{code:?} is marked MAC'd in the registry"
            );
            let (dst, len) = encoded(ErrorBody {
                code: Incoming::Client(code),
                detail: "forged",
            });
            assert_eq!(
                ErrorBody::bare(dst.get(..len).expect("the length")).map(|_| ()),
                Err(ErrorBodyError::BareCodeNeedsAMac(code)),
                "{code:?} was read out of a bare body"
            );
            // The same bytes under a MAC are read, because that is the other
            // half of the same column.
            assert!(ErrorBody::authenticated(dst.get(..len).expect("the length")).is_ok());
        }
    }

    /// **A condition that has an outcome has no error code left to send.** Two
    /// answers to one refusal is one implementer emitting the error while
    /// another implements the outcome as dead code, and the client that meets
    /// both cannot tell which of them means what.
    ///
    /// Codes 13 and 15 are the two this was already applied to. Error 6 is the
    /// third and it was missed, because the duplication was inside one code's
    /// meaning rather than between two codes: the registry called it *unknown
    /// channel or section*, and an unknown channel reaches a handler, where
    /// P-101 answers it `SetConfigAck` outcome 3. No message a client can send
    /// names a channel at all — `channel` appears once in this protocol, on a
    /// `Value` the controller sends — so the channel half was a second answer to
    /// a condition that has an outcome, wearing the name of one that does not.
    #[test]
    fn p_141_a_condition_with_an_outcome_has_no_error_code_left_to_send() {
        // Withdrawn: `pairing window closed` and `snapshot exceeds channel cap`.
        for retired in [13u16, 15] {
            assert!(
                ErrorCode::try_from(retired).is_err(),
                "error {retired} is live again, so the outcome that replaced it \
                 is now dead code in somebody's implementation"
            );
        }
        // The outcomes that replaced them, under their own numbers.
        assert_eq!(crate::generated::Pair::WindowClosed as u8, 2);
        assert_eq!(crate::generated::SetConfig::ExceedsCap as u8, 5);
        // And the two P-100 and P-101 name, for the same reason.
        assert_eq!(crate::generated::SetConfig::StaleVersion as u8, 2);
        assert_eq!(crate::generated::SetConfig::Invalid as u8, 3);

        // Error 6 survives, naming only the condition that never reaches a
        // handler. The variant name is the assertion: reinstate the channel half
        // in `protocol.toml` and this stops compiling.
        assert_eq!(ErrorCode::UnknownSection as u16, 6);

        // Code 10 stays live: it still answers a wrapper MAC and a signed
        // request. What it must not answer is a `Pair`, which is P-051's rule.
        assert!(ErrorCode::try_from(10).is_ok());
    }

    /// And the codes that are not marked, which are the ones with genuinely no
    /// session to key a MAC with. Refusing these would refuse every refusal that
    /// matters at the start of a connection.
    #[test]
    fn p_142_a_bare_error_with_no_session_behind_it_is_read_as_a_hint() {
        for code in [
            ErrorCode::MalformedFrame,
            ErrorCode::UnknownMessageType,
            ErrorCode::ProtocolMajorMismatch,
            ErrorCode::HelloRequiredFirst,
            ErrorCode::PayloadTooLarge,
            ErrorCode::SessionTableFull,
            ErrorCode::SessionExpired,
            ErrorCode::BadMAC,
            ErrorCode::UnknownClient,
            ErrorCode::StaleChallengeReconnectAndRetry,
        ] {
            assert!(!code.needs_a_mac(), "{code:?}");
            let (dst, len) = encoded(ErrorBody {
                code: Incoming::Client(code),
                detail: "why",
            });
            let hint = ErrorBody::bare(dst.get(..len).expect("the length"))
                .unwrap_or_else(|e| panic!("{code:?} refused: {e}"));
            assert_eq!(hint.code(), Incoming::Client(code));
            assert_eq!(hint.detail(), "why");
        }
    }

    /// A routing fault in the comms processor must not read as this client's own
    /// request failing — the two want different retries, and that is why the
    /// code comes back as an `Incoming` rather than a number.
    #[test]
    fn a_link_local_code_stays_in_the_space_it_came_from() {
        let (dst, len) = encoded(ErrorBody {
            code: Incoming::LinkLocal(LinkErrorCode::UnknownHandle),
            detail: "no such handle",
        });
        let hint = ErrorBody::bare(dst.get(..len).expect("the length")).expect("a hint");
        assert_eq!(
            hint.code(),
            Incoming::LinkLocal(LinkErrorCode::UnknownHandle)
        );

        // And a number in neither space is carried rather than guessed at.
        let (dst, len) = encoded(ErrorBody {
            code: Incoming::Unknown(9_999),
            detail: "from a newer controller",
        });
        let hint = ErrorBody::bare(dst.get(..len).expect("the length")).expect("a hint");
        assert_eq!(hint.code(), Incoming::Unknown(9_999));
    }

    /// P-140. The signature half of this lives on [`Hint`] itself, because a
    /// doc test written here is inside `#[cfg(test)]` and rustdoc never
    /// collects it — it looked like a check for as long as it existed and was
    /// never once run.
    #[test]
    fn an_unauthenticated_refusal_is_a_different_type_from_one_under_a_mac() {
        let (dst, len) = encoded(ErrorBody {
            code: Incoming::Client(ErrorCode::SessionExpired),
            detail: "reconnect",
        });
        let bytes = dst.get(..len).expect("the length");
        let hint = ErrorBody::bare(bytes).expect("a hint");
        let authenticated = ErrorBody::authenticated(bytes).expect("a body");
        assert_eq!(hint.code(), authenticated.code);
        assert_eq!(hint.detail(), authenticated.detail);
    }

    /// A detail past the cap is refused rather than truncated into a different
    /// sentence — on both ends, because the far one is where a hostile peer
    /// sends it.
    ///
    /// The bound belongs to `cbor.rs` and this module does not keep a second
    /// copy of it. It had one, on both paths, and the decode-side half was
    /// unreachable: `CborReader::head` refuses a long text before a body
    /// decoder ever sees the string. Two formulas for one bound is the defect
    /// `limits.rs` was written about; a named variant restating a check the
    /// codec already makes is the same thing with a nicer sentence.
    #[test]
    fn a_detail_past_the_cap_is_refused_at_both_ends() {
        let long = [b'x'; MAX_STRING + 1];
        let long = core::str::from_utf8(&long).expect("ascii");
        let mut dst = [0u8; SCRATCH];
        assert_eq!(
            ErrorBody {
                code: Incoming::Client(ErrorCode::MalformedFrame),
                detail: long,
            }
            .encode(&mut dst),
            Err(ErrorBodyError::Cbor(CborError::StringTooLong))
        );

        // And on the way in: `{1: 1, 2: <65 bytes>}`, which is what a hostile
        // peer sends and the only end that is not ours.
        let mut body = [b'x'; MAX_STRING + 7];
        body[0] = 0xa2;
        body[1] = 0x01;
        body[2] = 0x01;
        body[3] = 0x02;
        body[4] = 0x78;
        body[5] = u8::try_from(MAX_STRING + 1).expect("under 256");
        assert_eq!(
            ErrorBody::authenticated(&body),
            Err(ErrorBodyError::Cbor(CborError::StringTooLong))
        );

        // At the cap it is a sentence, not a refusal.
        let at_the_cap = [b'x'; MAX_STRING];
        let at_the_cap = core::str::from_utf8(&at_the_cap).expect("ascii");
        assert!(
            ErrorBody {
                code: Incoming::Client(ErrorCode::MalformedFrame),
                detail: at_the_cap,
            }
            .encode(&mut dst)
            .is_ok()
        );
    }

    /// P-013 and P-015 on this body too.
    #[test]
    fn a_newer_peers_key_is_skipped_and_a_repeated_one_is_refused() {
        // `{1: 1, 2: "x", 9: true}`
        let read = ErrorBody::authenticated(&[0xa3, 0x01, 0x01, 0x02, 0x61, 0x78, 0x09, 0xf5])
            .expect("a newer peer's key is skipped");
        assert_eq!(read.code, Incoming::Client(ErrorCode::MalformedFrame));

        assert_eq!(
            ErrorBody::authenticated(&[0xa3, 0x01, 0x01, 0x01, 0x02, 0x02, 0x61, 0x78]),
            Err(ErrorBodyError::Duplicate(ErrorKey::Code))
        );
    }

    /// A required key that never arrived says which one.
    #[test]
    fn a_body_missing_a_required_key_says_which_one() {
        assert_eq!(
            ErrorBody::authenticated(&[0xa1, 0x02, 0x61, 0x78]),
            Err(ErrorBodyError::Missing(ErrorKey::Code))
        );
        assert_eq!(
            ErrorBody::authenticated(&[0xa1, 0x01, 0x01]),
            Err(ErrorBodyError::Missing(ErrorKey::Detail))
        );
    }

    /// Every truncation, and a byte appended after.
    #[test]
    fn a_frame_cut_short_or_run_on_is_refused() {
        let (dst, len) = encoded(ErrorBody {
            code: Incoming::Client(ErrorCode::BadMAC),
            detail: "tag",
        });
        for cut in 0..len {
            assert!(
                ErrorBody::authenticated(dst.get(..cut).expect("a prefix")).is_err(),
                "decoded {cut} of {len}"
            );
        }
        let mut run_on = dst;
        let slot = run_on.get_mut(len).expect("the scratch is wider");
        *slot = 0x00;
        assert_eq!(
            ErrorBody::authenticated(run_on.get(..=len).expect("one more")),
            Err(ErrorBodyError::Cbor(CborError::TrailingBytes))
        );
    }

    /// Every refusal renders as its own sentence and answers error 1 — and what
    /// a caller does with it is drop the frame, because an `Error` answering an
    /// `Error` is the amplifier P-031 refuses to build.
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [ErrorBodyError; 4] = [
            ErrorBodyError::Missing(ErrorKey::Code),
            ErrorBodyError::Duplicate(ErrorKey::Detail),
            ErrorBodyError::BareCodeNeedsAMac(ErrorCode::BusyRetry),
            ErrorBodyError::Cbor(CborError::WrongType),
        ];
        Rendering::<112>::each_says_something_of_its_own(&EVERY);
        for why in EVERY {
            assert_eq!(why.refusal().code(), 1, "{why}");
        }
    }
}
