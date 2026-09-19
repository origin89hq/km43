//! The 16-byte tag every authenticated message carries, and the seven preimages
//! it is computed over.
//!
//! Two rules here are structural rather than remembered. A preimage cannot be
//! started without its label, because `Preimage::under` is the only constructor
//! and it takes a [`Domain`] — P-043 is there so a value computed for one
//! purpose can never verify for another, and a bare `&str` at a call site is how
//! a label gains a hyphen on one side of the link and nobody sees it. And a key
//! cannot sign a preimage belonging to another key: [`PairKey`] has the two
//! pairing proofs and nothing else, which is P-054 written as a type after two
//! requirements one page apart said opposite things about which key signs
//! `Pair`.
//!
//! [`Tag`] deliberately has no `PartialEq`, so `==` on a tag does not compile.
//! A comparison that stops at the first differing byte is a forgery oracle one
//! byte at a time, and [`Tag::verify`] goes through `subtle` instead. Note what
//! that does *not* buy: [`Tag::as_bytes`] hands out an array, arrays are
//! `PartialEq`, and `tag.as_bytes() == received` compiles cleanly. `as_bytes` is
//! for putting a tag on the wire; checking one is `verify` and only `verify`.
//!
//! Nothing here encodes anything. `operation` and `payload` arrive as bytes and
//! are fed as bytes (P-048): a verifier that re-encoded before hashing would be
//! authenticating a message the sender never sent.
//!
//! cites: P-040, P-041, P-043, P-046, P-047, P-048, P-054, P-069

use core::fmt;

use hmac::{KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// Holds the `subtle` import down.
///
/// Swapping `ct_eq` for `==` in [`Tag::verify`] passes every test in this crate,
/// because a timing property is not observable from a test process. The only
/// thing that noticed was `unused import`, and that signal evaporates the moment
/// a second `ct_eq` lands in the file. This makes it deliberate: remove the
/// constant-time comparison and the import is still used, so the lint stays
/// quiet — but this line names the function, so deleting `subtle` is a build
/// error rather than a quiet loss.
const _: fn(&[u8], &[u8]) -> subtle::Choice = <[u8] as subtle::ConstantTimeEq>::ct_eq;

use crate::envelope::{ReqId, SessionId};
use crate::generated::{ClientKind, MessageType, Pair};

type HmacSha256 = hmac::Hmac<Sha256>;

/// Every key on this wire is an HKDF output asked for `L = 32`.
const KEY_BYTES: usize = 32;

/// SHA-256's digest, and the width RFC 4231 publishes.
const DIGEST_BYTES: usize = 32;

/// SHA-256's block, which is the width RFC 2104 pads a key to.
const BLOCK_BYTES: usize = 64;

/// P-041's leftmost sixteen: a 128-bit authentication tag.
const TAG_BYTES: usize = 16;

/// P-038's `device_id`, as the 16 bytes and never their hex rendering.
const DEVICE_ID_BYTES: usize = 16;

/// A `challenge`, a `next_challenge` and a `client_nonce` are all `bstr16`.
const NONCE_BYTES: usize = 16;

const_assert!(
    TAG_BYTES <= DIGEST_BYTES,
    "the tag is taken by zipping a fixed array against the digest, so a tag wider than the digest would come back with a tail of zeros and nothing on either side would say so"
);

/// The seven labels a MAC preimage begins with (P-043).
///
/// The three HKDF `info` labels of the same table are deliberately not here.
/// P-043 says in as many words that an implementer who reads that table as nine
/// MAC preimages derives keys that are wrong on both sides and identical to
/// nobody, so a variant here is a preimage prefix and never a KDF argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Domain {
    /// A signed request — one that carries a counter.
    SignedRequest,
    /// A wrapper-authenticated request: read-only, with no counter to sign.
    WrapperRequest,
    /// A response.
    Response,
    /// An unsolicited `Event`.
    Event,
    /// The client's proof during pairing.
    PairProof,
    /// The controller's answer to it.
    PairAck,
    /// The client's proof during `Hello`.
    HelloProof,
}

impl Domain {
    /// P-043's ASCII, with no trailing NUL. Private because the only thing
    /// entitled to prepend one is `Preimage::under`.
    const fn as_str(self) -> &'static str {
        match self {
            Self::SignedRequest => "km43/v1/req",
            Self::WrapperRequest => "km43/v1/wrq",
            Self::Response => "km43/v1/rsp",
            Self::Event => "km43/v1/evt",
            Self::PairProof => "km43/v1/pair-proof",
            Self::PairAck => "km43/v1/pair-ack",
            Self::HelloProof => "km43/v1/hello-proof",
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A 128-bit authentication tag: the leftmost 16 bytes of HMAC-SHA256 (P-041).
///
/// There is no `PartialEq` and that is the point — [`Tag::verify`] is the only
/// comparison, and it is constant time.
#[derive(Debug, Clone, Copy)]
pub struct Tag([u8; TAG_BYTES]);

impl Tag {
    /// P-041's sixteen. On the type because a body decoder reading a `bstr`
    /// needs it, and a second free constant in the crate root would be a second
    /// name for one number.
    pub const LEN: usize = TAG_BYTES;

    /// The bytes as they go on the wire — never for checking a tag against
    /// another, which is [`Tag::verify`]. Comparing these with `==` is the
    /// timing leak the missing `PartialEq` was meant to prevent.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TAG_BYTES] {
        &self.0
    }

    /// Whether `candidate` is this tag, compared in constant time.
    ///
    /// Do not simplify this to `==` or to a loop that breaks early. A comparison
    /// that stops at the first wrong byte tells whoever holds the link how many
    /// leading bytes of a guess were right, and sixteen bytes surrendered one at
    /// a time is a few thousand tries rather than 2^128.
    pub fn verify(&self, candidate: &[u8]) -> Result<(), MacError> {
        // The length is not a secret: it is a CBOR byte-string header the comms
        // processor has already read off the wire. Refusing on it before the
        // comparison leaks nothing, and it is what keeps `ct_eq` fed two equal
        // widths rather than letting it answer on the lengths alone.
        if candidate.len() != TAG_BYTES {
            return Err(MacError::WrongLength(candidate.len()));
        }
        // Pinned below, because swapping this for `==` passes every test in the
        // crate — a timing property is not observable from a test process.
        if bool::from(self.0.as_slice().ct_eq(candidate)) {
            Ok(())
        } else {
            Err(MacError::Mismatch)
        }
    }
}

/// Why a tag was refused. Both stop the message: P-051 answers a failed MAC with
/// error 10 and does not decode the body it covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MacError {
    /// A tag that is not exactly [`Tag::LEN`] bytes, carrying what arrived so a
    /// bench log can say how far off the peer was. Refused rather than padded
    /// out or trimmed to fit — a twelve-byte tag zero-padded to sixteen is a
    /// 96-bit tag nobody agreed to, and a peer that pads is a peer that accepts
    /// one.
    WrongLength(usize),
    /// The tag did not match the one these fields compute.
    Mismatch,
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(f, "authentication tag is {len} bytes, not {TAG_BYTES}")
            }
            Self::Mismatch => f.write_str("authentication tag does not match"),
        }
    }
}

impl core::error::Error for MacError {}

/// The pairing key of P-088, derived from the printed secret and the
/// `device_id`.
///
/// It signs the two pairing proofs and nothing else: the comms processor watches
/// every pairing exchange, and P-088 exists because keying a proof with the
/// master secret hands it an oracle under the one secret the device depends on.
///
/// No `Debug`, here or on the two keys below. A key with one is a key in a bench
/// log the day somebody adds `?key` to a span, and a compile error is a better
/// answer than a redaction somebody can undo.
pub struct PairKey([u8; KEY_BYTES]);

impl PairKey {
    /// The 32 bytes HKDF produced under `km43/v1/pair-key`.
    #[must_use]
    pub(crate) const fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// The client's proof during pairing.
    ///
    /// The `label` a person reads is inside it (P-069), which is what makes
    /// P-078's byte-exact reclaim sound: left outside, the comms processor
    /// rewrites the name in flight and the controller stores and authenticates
    /// the rewrite.
    #[must_use]
    pub fn proof(&self, fields: &PairProof<'_>) -> Tag {
        Preimage::under(&self.0, Domain::PairProof)
            .bytes(fields.device_id)
            .bytes(fields.challenge)
            .bytes(fields.client_nonce)
            .u8(fields.client_kind as u8)
            .bytes(fields.label.as_bytes())
            .tag()
    }

    /// The controller's answer, which is the message that fixes a client's
    /// identity.
    ///
    /// `client_nonce` is in it for that reason (P-069): without it every input
    /// is chosen by the controller or fixed by the device, so an ack recorded
    /// from an earlier enrolment verifies again on a later attempt.
    #[must_use]
    pub fn ack(&self, fields: &PairAck<'_>) -> Tag {
        Preimage::under(&self.0, Domain::PairAck)
            .bytes(fields.device_id)
            .bytes(fields.challenge)
            .bytes(fields.client_nonce)
            .u8(fields.outcome as u8)
            .u32(fields.client_id)
            .u32(fields.epoch)
            .bytes(fields.next_challenge)
            .tag()
    }
}

/// A client's long-term key, derived per `epoch` and per `client_id`.
pub struct ClientKey([u8; KEY_BYTES]);

impl ClientKey {
    /// The 32 bytes HKDF produced under `km43/v1/client-key`.
    #[must_use]
    pub(crate) const fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// The client's proof during `Hello` — the one message whose key is named by
    /// a field inside the body it authenticates (P-057).
    #[must_use]
    pub fn hello_proof(&self, fields: &HelloProof<'_>) -> Tag {
        Preimage::under(&self.0, Domain::HelloProof)
            .bytes(fields.challenge)
            .bytes(fields.client_nonce)
            .u32(fields.client_id)
            .bytes(fields.payload)
            .tag()
    }
}

/// The key one session's traffic is authenticated under, in both directions.
pub struct SessionKey([u8; KEY_BYTES]);

impl SessionKey {
    /// The 32 bytes HKDF produced under `km43/v1/session-key`.
    #[must_use]
    pub(crate) const fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// A request carrying a counter.
    ///
    /// `client_id` and `counter` are in this preimage and the read-only one
    /// below has neither, which is why they are two labels rather than one with
    /// fields a sender can leave out.
    #[must_use]
    pub fn signed_request(&self, fields: &SignedRequest<'_>) -> Tag {
        Preimage::under(&self.0, Domain::SignedRequest)
            .u8(fields.kind as u8)
            .u16(u16::from(fields.session))
            .u32(fields.req_id.0)
            .u32(fields.client_id)
            .u64(fields.counter)
            .bytes(fields.operation)
            .tag()
    }

    /// A read-only request, authenticated by the wrapper.
    #[must_use]
    pub fn wrapper_request(&self, fields: &Wrapped<'_>) -> Tag {
        Preimage::under(&self.0, Domain::WrapperRequest)
            .u8(fields.kind as u8)
            .u16(u16::from(fields.session))
            .u32(fields.req_id.0)
            .bytes(fields.payload)
            .tag()
    }

    /// The answer to one. Same four fields as the request and a different label,
    /// which is the whole of P-052 and the reason these are two methods rather
    /// than one with a direction somebody can pass the wrong way round.
    #[must_use]
    pub fn response(&self, fields: &Wrapped<'_>) -> Tag {
        Preimage::under(&self.0, Domain::Response)
            .u8(fields.kind as u8)
            .u16(u16::from(fields.session))
            .u32(fields.req_id.0)
            .bytes(fields.payload)
            .tag()
    }

    /// An unsolicited `Event`, which answers no request.
    ///
    /// The four zero bytes where a `req_id` would sit are a literal rather than
    /// a parameter: a caller allowed to pass one could compute this tag for a
    /// message that did answer something. The type is fixed for the same reason
    /// P-046 puts it in the preimage at all.
    #[must_use]
    pub fn event(&self, session: SessionId, payload: &[u8]) -> Tag {
        Preimage::under(&self.0, Domain::Event)
            .u8(MessageType::EventResponse as u8)
            .u16(u16::from(session))
            .u32(0)
            .bytes(payload)
            .tag()
    }
}

/// What the pairing proof covers.
#[derive(Debug, Clone, Copy)]
pub struct PairProof<'a> {
    /// The 16 bytes of P-038, not the 32 characters they print as.
    pub device_id: &'a [u8; DEVICE_ID_BYTES],
    /// The challenge this connection was issued, spent on presentation.
    pub challenge: &'a [u8; NONCE_BYTES],
    /// Fresh per attempt, from the client's CSPRNG (P-069).
    pub client_nonce: &'a [u8; NONCE_BYTES],
    /// What kind of thing is pairing, which the capability mask is fixed from.
    pub client_kind: ClientKind,
    /// The UTF-8 bytes a person reads in the client list, with no CBOR header
    /// and no length prefix. It is last because it is the one variable-width
    /// field in any preimage in this protocol, and `MAX_STRING` bounds it.
    pub label: &'a str,
}

/// What the controller's pairing answer covers.
#[derive(Debug, Clone, Copy)]
pub struct PairAck<'a> {
    /// The 16 bytes of P-038.
    pub device_id: &'a [u8; DEVICE_ID_BYTES],
    /// The challenge that was presented — the same one the proof covered.
    pub challenge: &'a [u8; NONCE_BYTES],
    /// The nonce the client chose — the same one the proof covered.
    pub client_nonce: &'a [u8; NONCE_BYTES],
    /// What the controller decided.
    pub outcome: Pair,
    /// Zero on every outcome but `Enrolled` and `Reclaimed`. A `u32` rather than
    /// an `Option`, because a verifier has to reproduce the zero that arrived —
    /// a type that could not express one could not check the ack that refused a
    /// client, which is the ack a refused client most needs to trust.
    pub client_id: u32,
    /// The counter a factory reset increments, so a client whose key no longer
    /// derives is told why rather than seeing an unexplainable bad proof.
    pub epoch: u32,
    /// The challenge this connection holds now the presented one is spent. It is
    /// inside the MAC because the next `Hello` proof is computed against it.
    pub next_challenge: &'a [u8; NONCE_BYTES],
}

/// What the `Hello` proof covers.
#[derive(Debug, Clone, Copy)]
pub struct HelloProof<'a> {
    /// The challenge the controller minted for this connection.
    pub challenge: &'a [u8; NONCE_BYTES],
    /// Fresh per attempt; it and the challenge are what `session_key` is salted
    /// with.
    pub client_nonce: &'a [u8; NONCE_BYTES],
    /// Which enrolment is proving itself, and so which `client_key` to check
    /// under.
    pub client_id: u32,
    /// The inner body exactly as it arrived (P-048).
    pub payload: &'a [u8],
}

/// What a signed request covers.
#[derive(Debug, Clone, Copy)]
pub struct SignedRequest<'a> {
    /// P-046: inside the preimage, so a signed `SetConfig` cannot be replayed as
    /// a signed `Command`.
    pub kind: MessageType,
    /// The connection handle the comms processor stamped in.
    pub session: SessionId,
    /// P-047: `(session_id, req_id)` is what the untrusted comms processor
    /// correlates on, so it is signed at both ends.
    pub req_id: ReqId,
    /// Which enrolment is acting, which is what selects the counter row.
    pub client_id: u32,
    /// Strictly increasing per `client_id`, which is what makes a captured frame
    /// unusable a second time.
    pub counter: u64,
    /// The signed blob exactly as it arrived (P-048), never re-encoded.
    pub operation: &'a [u8],
}

/// What a wrapper-authenticated request or response covers.
///
/// One type for both directions on purpose: the fields really are the same and
/// the label is the only thing separating them, so holding them together is what
/// makes [`SessionKey::wrapper_request`] and [`SessionKey::response`] the place
/// the direction is decided.
#[derive(Debug, Clone, Copy)]
pub struct Wrapped<'a> {
    /// P-046, and on a response it is what stops one answer standing in for
    /// another.
    pub kind: MessageType,
    /// The connection handle, which the envelope carries too and must match.
    pub session: SessionId,
    /// P-047, echoed by whatever answers this frame.
    pub req_id: ReqId,
    /// The inner body exactly as it arrived (P-048).
    pub payload: &'a [u8],
}

/// One preimage under construction: keyed, with its label already fed.
///
/// `under` is the only constructor and it takes a [`Domain`], so P-043 is not a
/// rule anybody has to remember — there is no way to reach a field writer
/// without a label having gone in first.
struct Preimage(Hmac256);

impl Preimage {
    fn under(key: &[u8; KEY_BYTES], domain: Domain) -> Self {
        Self(Hmac256::keyed(key).feed(domain.as_str().as_bytes()))
    }

    /// Big-endian and fixed width because P-040 says so, and because there is no
    /// other method here: two implementations that agree on the algorithm and
    /// not on the byte order produce tags neither of them can explain.
    fn u8(self, value: u8) -> Self {
        Self(self.0.feed(&[value]))
    }

    fn u16(self, value: u16) -> Self {
        Self(self.0.feed(&value.to_be_bytes()))
    }

    fn u32(self, value: u32) -> Self {
        Self(self.0.feed(&value.to_be_bytes()))
    }

    fn u64(self, value: u64) -> Self {
        Self(self.0.feed(&value.to_be_bytes()))
    }

    /// Bytes that came off the wire, fed as they came off it (P-048).
    fn bytes(self, value: &[u8]) -> Self {
        Self(self.0.feed(value))
    }

    fn tag(self) -> Tag {
        self.0.tag()
    }
}

/// HMAC-SHA256 over a key of any length, with no fallible constructor in the
/// way.
struct Hmac256(HmacSha256);

impl Hmac256 {
    fn keyed(key: &[u8]) -> Self {
        Self(HmacSha256::new(&block_key(key).into()))
    }

    fn feed(mut self, data: &[u8]) -> Self {
        self.0.update(data);
        self
    }

    /// The full digest, which is the width RFC 4231 publishes and so the only
    /// way to check this against the world rather than against ourselves.
    fn full(self) -> [u8; DIGEST_BYTES] {
        self.0.finalize().into_bytes().into()
    }

    /// P-041's truncation: the **leftmost** sixteen bytes, which is a vector and
    /// not a property. Take them from the wrong end and every self-test in this
    /// file still passes while nothing this controller signs verifies anywhere
    /// else.
    fn tag(self) -> Tag {
        let digest = self.full();
        let mut out = [0u8; TAG_BYTES];
        for (slot, &byte) in out.iter_mut().zip(&digest) {
            *slot = byte;
        }
        Tag(out)
    }
}

/// RFC 2104's `K0`: a key longer than the block is hashed first, a shorter one
/// is zero-padded to the block.
///
/// Written out rather than left to `Mac::new_from_slice`, which hands back a
/// `Result` whose error arm an HMAC has no way to take. An error nothing can
/// produce is worse than no error at all, because every caller of every MAC in
/// this crate would then have to carry it.
fn block_key(key: &[u8]) -> [u8; BLOCK_BYTES] {
    let mut block = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        for (slot, &byte) in block.iter_mut().zip(Sha256::digest(key).iter()) {
            *slot = byte;
        }
    } else {
        for (slot, &byte) in block.iter_mut().zip(key) {
            *slot = byte;
        }
    }
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Rendering;

    /// Fixtures go in as the hexadecimal the documents publish. Retyping
    /// `0x8a, 0xee, …` by hand is how a digit moves house without anybody
    /// noticing, and this is a `const fn` so a fixture of the wrong width fails
    /// the build rather than a test.
    const fn hex<const N: usize>(text: &str) -> [u8; N] {
        let src = text.as_bytes();
        assert!(src.len() == N * 2, "hex fixture is not the width it claims");
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            out[i] = (nibble(src[i * 2]) << 4) | nibble(src[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex fixture is not lowercase hexadecimal"),
        }
    }

    const PAIR_KEY: [u8; KEY_BYTES] =
        hex("d2b669d733ae985424f2930404f5b5976fc52776deaf02a853f14d43c0b73007");
    const CLIENT_KEY: [u8; KEY_BYTES] =
        hex("eadf9347ac95af6e8d164d90883965d670a003c52785f1052fba086b05a1a853");
    const SESSION_KEY: [u8; KEY_BYTES] =
        hex("ba9ddffe57f11ccceeb5699cbaa5e1c196b719e9e867d97b05dd3b855d0f7601");

    const DEVICE_ID: [u8; DEVICE_ID_BYTES] = hex("4f524947494e38392044454d4f203031");
    const CHALLENGE: [u8; NONCE_BYTES] = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    const NEXT_CHALLENGE: [u8; NONCE_BYTES] = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
    const CLIENT_NONCE: [u8; NONCE_BYTES] = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    const CLIENT_ID: u32 = 7;
    const SESSION: u16 = 3;
    const REQ_ID: u32 = 17;
    const COUNTER: u64 = 66;
    const LABEL: &str = "kitchen phone";
    const EPOCH: u32 = 1;

    const HELLO_BODY: [u8; 40] =
        hex("a5010102000307046d6f38392d636c6920302e312e300550b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    const OPERATION: [u8; 14] = hex("a301182a0219010103a101190384");
    const READ_LOG_BODY: [u8; 8] = hex("a2011904c0021840");
    const COMMAND_ACK_BODY: [u8; 26] = hex("a301182a0201037267656e657261746f72207374617274696e67");
    const EVENT_BODY: [u8; 25] = hex("a4011904d2021b0000018f1e2a3b400319020104a201030201");

    fn pair_proof_fields() -> PairProof<'static> {
        PairProof {
            device_id: &DEVICE_ID,
            challenge: &CHALLENGE,
            client_nonce: &CLIENT_NONCE,
            client_kind: ClientKind::App,
            label: LABEL,
        }
    }

    fn pair_ack_fields() -> PairAck<'static> {
        PairAck {
            device_id: &DEVICE_ID,
            challenge: &CHALLENGE,
            client_nonce: &CLIENT_NONCE,
            outcome: Pair::Enrolled,
            client_id: CLIENT_ID,
            epoch: EPOCH,
            next_challenge: &NEXT_CHALLENGE,
        }
    }

    fn hello_proof_fields() -> HelloProof<'static> {
        HelloProof {
            challenge: &CHALLENGE,
            client_nonce: &CLIENT_NONCE,
            client_id: CLIENT_ID,
            payload: &HELLO_BODY,
        }
    }

    fn signed_request_fields() -> SignedRequest<'static> {
        SignedRequest {
            kind: MessageType::Command,
            session: SessionId::from(SESSION),
            req_id: ReqId(REQ_ID),
            client_id: CLIENT_ID,
            counter: COUNTER,
            operation: &OPERATION,
        }
    }

    fn read_log_fields() -> Wrapped<'static> {
        Wrapped {
            kind: MessageType::ReadLog,
            session: SessionId::from(SESSION),
            req_id: ReqId(REQ_ID),
            payload: &READ_LOG_BODY,
        }
    }

    fn command_ack_fields() -> Wrapped<'static> {
        Wrapped {
            kind: MessageType::CommandResponse,
            session: SessionId::from(SESSION),
            req_id: ReqId(REQ_ID),
            payload: &COMMAND_ACK_BODY,
        }
    }

    /// The seven MACs of `docs/protocol/vectors/v1.json`: what these methods
    /// compute, beside what the file publishes.
    fn published() -> [([u8; Tag::LEN], [u8; Tag::LEN]); 7] {
        let pair = PairKey::new(PAIR_KEY);
        let client = ClientKey::new(CLIENT_KEY);
        let session = SessionKey::new(SESSION_KEY);
        [
            (
                *pair.proof(&pair_proof_fields()).as_bytes(),
                hex("22171c0449d848381e6d99ed7c92d1bd"),
            ),
            (
                *pair.ack(&pair_ack_fields()).as_bytes(),
                hex("4a7937d934b87b750a254a05289f030b"),
            ),
            (
                *client.hello_proof(&hello_proof_fields()).as_bytes(),
                hex("8418a3ffb064b88022622123ce6a4f01"),
            ),
            (
                *session.signed_request(&signed_request_fields()).as_bytes(),
                hex("078cc3c1d821bc16a1d6ab81e11ec30d"),
            ),
            (
                *session.wrapper_request(&read_log_fields()).as_bytes(),
                hex("dc50348012c95f28990c26c4f0f84cb5"),
            ),
            (
                *session.response(&command_ack_fields()).as_bytes(),
                hex("879f149683b569b80d2b190a955eccba"),
            ),
            (
                *session
                    .event(SessionId::from(SESSION), &EVENT_BODY)
                    .as_bytes(),
                hex("98b7711ad5f1162b6eb7d2dc41d863ef"),
            ),
        ]
    }

    /// RFC 4231's seven cases, at full width.
    ///
    /// Every other test in this file compares this crate against this crate. If
    /// the HMAC underneath were wrong — a swapped pad constant, a key hashed
    /// where it should be padded — all of them would still be green and nothing
    /// this controller signed would verify anywhere in the world.
    #[test]
    fn the_hmac_underneath_is_the_one_rfc_4231_publishes() {
        const CASES: [(&[u8], &[u8], [u8; DIGEST_BYTES]); 7] = [
            (
                &[0x0b; 20],
                b"Hi There",
                hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
            ),
            (
                &hex::<25>("0102030405060708090a0b0c0d0e0f10111213141516171819"),
                &[0xcd; 50],
                hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
            ),
            (
                &[0x0c; 20],
                b"Test With Truncation",
                hex("a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5"),
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
            ),
            (
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                hex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
            ),
        ];

        for (index, (key, data, want)) in CASES.iter().enumerate() {
            assert_eq!(
                Hmac256::keyed(key).feed(data).full(),
                *want,
                "RFC 4231 case {} does not agree with this crate",
                index.saturating_add(1)
            );
        }
    }

    /// Case 5 is the one RFC 4231 itself also publishes truncated to 128 bits,
    /// so it is the vector for P-041's *leftmost*.
    ///
    /// Truncating from the right passes every round trip in this file and makes
    /// every frame this controller signs unverifiable to any conforming peer —
    /// invisible until two implementations meet, which is on a wall four hours
    /// from a road.
    #[test]
    fn the_tag_is_the_leftmost_sixteen_bytes_and_not_the_rightmost() {
        let tag = Hmac256::keyed(&[0x0c; 20])
            .feed(b"Test With Truncation")
            .tag();
        assert_eq!(
            *tag.as_bytes(),
            hex::<16>("a3b6167473100ee06e0c796c2955552b"),
            "RFC 4231's own 128-bit truncation of case 5"
        );

        let full = Hmac256::keyed(&[0x0c; 20])
            .feed(b"Test With Truncation")
            .full();
        let rightmost = full
            .get(DIGEST_BYTES.saturating_sub(TAG_BYTES)..)
            .expect("half a digest");
        assert_ne!(
            tag.as_bytes().as_slice(),
            rightmost,
            "the two ends of this digest differ, or this test proves nothing"
        );
    }

    /// Every MAC in `v1.json`, byte for byte.
    ///
    /// That file is produced by a tool forbidden from importing this crate. The
    /// reading of it that counts is `tests/vectors.rs`, which drives the public
    /// API; the hex below is a transcription, and would be the second copy
    /// CLAUDE.md warns about if that test did not exist.
    #[test]
    fn every_published_mac_is_reproduced_byte_for_byte() {
        for (index, (computed, published)) in published().iter().enumerate() {
            assert_eq!(computed, published, "vector {index} moved");
        }
    }

    /// The published preimage bytes, fed straight in, give the published tag too.
    ///
    /// Without this a dropped field and a broken primitive look identical from
    /// the test above: both come back as one wrong tag. Here a composition bug
    /// makes these two disagree with each other while a primitive bug makes both
    /// disagree with the vector, which says which half to go and read.
    #[test]
    fn the_fields_these_methods_compose_are_the_published_preimage_bytes() {
        const PREIMAGES: [(&[u8; KEY_BYTES], &[u8]); 7] = [
            (
                &PAIR_KEY,
                &hex::<80>(
                    "6b6d34332f76312f706169722d70726f6f664f524947494e38392044454d4f2030\
                     31a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf01\
                     6b69746368656e2070686f6e65",
                ),
            ),
            (
                &PAIR_KEY,
                &hex::<89>(
                    "6b6d34332f76312f706169722d61636b4f524947494e38392044454d4f2030\
                     31a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0100\
                     00000700000001c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
                ),
            ),
            (
                &CLIENT_KEY,
                &hex::<95>(
                    "6b6d34332f76312f68656c6c6f2d70726f6f66a0a1a2a3a4a5a6a7a8a9aaabacada\
                     eafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00000007a5010102000307046d6f38392d\
                     636c6920302e312e300550b0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
                ),
            ),
            (
                &SESSION_KEY,
                &hex::<44>(
                    "6b6d34332f76312f7265710800030000001100000007000000000000004\
                     2a301182a0219010103a101190384",
                ),
            ),
            (
                &SESSION_KEY,
                &hex::<26>("6b6d34332f76312f77727105000300000011a2011904c0021840"),
            ),
            (
                &SESSION_KEY,
                &hex::<44>(
                    "6b6d34332f76312f72737088000300000011a301182a0201037267656e657261746\
                     f72207374617274696e67",
                ),
            ),
            (
                &SESSION_KEY,
                &hex::<43>(
                    "6b6d34332f76312f65767404000300000000a4011904d2021b0000018f1e2a3b400\
                     319020104a201030201",
                ),
            ),
        ];

        for (index, ((composed, _), (key, preimage))) in
            published().iter().zip(PREIMAGES).enumerate()
        {
            assert_eq!(
                composed,
                Hmac256::keyed(key).feed(preimage).tag().as_bytes(),
                "the fields of vector {index} do not compose the published preimage"
            );
        }
    }

    /// Every label is the ASCII the specification prints, checked against the
    /// bytes at the head of a published preimage rather than against another
    /// copy of the same list.
    ///
    /// A preimage in this repo once gained a label in the spec and not in the
    /// generator, and the check meant to catch it compared descriptions while
    /// the bytes underneath had already diverged.
    #[test]
    fn every_label_is_the_ascii_the_published_preimage_starts_with() {
        const LABELS: [(Domain, &[u8]); 7] = [
            (Domain::SignedRequest, &hex::<11>("6b6d34332f76312f726571")),
            (Domain::WrapperRequest, &hex::<11>("6b6d34332f76312f777271")),
            (Domain::Response, &hex::<11>("6b6d34332f76312f727370")),
            (Domain::Event, &hex::<11>("6b6d34332f76312f657674")),
            (
                Domain::PairProof,
                &hex::<18>("6b6d34332f76312f706169722d70726f6f66"),
            ),
            (
                Domain::PairAck,
                &hex::<16>("6b6d34332f76312f706169722d61636b"),
            ),
            (
                Domain::HelloProof,
                &hex::<19>("6b6d34332f76312f68656c6c6f2d70726f6f66"),
            ),
        ];

        for (domain, ascii) in LABELS {
            assert_eq!(
                domain.as_str().as_bytes(),
                ascii,
                "{domain} is not the label the vectors were computed under"
            );
        }
    }

    /// Two labels over one key and one body are two tags. This is what says
    /// `km43/v1/req` and `km43/v1/wrq` are separate purposes rather than two
    /// spellings of one.
    #[test]
    fn no_two_domains_produce_one_tag_over_the_same_body() {
        const EVERY: [Domain; 7] = [
            Domain::SignedRequest,
            Domain::WrapperRequest,
            Domain::Response,
            Domain::Event,
            Domain::PairProof,
            Domain::PairAck,
            Domain::HelloProof,
        ];

        let mut tags = [[0u8; Tag::LEN]; EVERY.len()];
        for (slot, domain) in tags.iter_mut().zip(EVERY) {
            *slot = *Preimage::under(&SESSION_KEY, domain)
                .bytes(&READ_LOG_BODY)
                .tag()
                .as_bytes();
        }

        for first in 0..EVERY.len() {
            for second in first.saturating_add(1)..EVERY.len() {
                assert_ne!(
                    tags.get(first).expect("the index came from the list"),
                    tags.get(second).expect("the index came from the list"),
                    "{} and {} share a tag over one body",
                    EVERY.get(first).expect("the index came from the list"),
                    EVERY.get(second).expect("the index came from the list"),
                );
            }
        }
    }

    /// The concrete case behind the property above: a read-only request and the
    /// answer to it carry identical fields, and only the label separates them.
    ///
    /// Share a label and a captured request re-enters the session as its own
    /// response, MAC and all.
    #[test]
    fn a_read_only_request_cannot_be_replayed_as_the_response_to_itself() {
        let session = SessionKey::new(SESSION_KEY);
        let fields = read_log_fields();
        assert_ne!(
            session.wrapper_request(&fields).as_bytes(),
            session.response(&fields).as_bytes()
        );
    }

    /// P-046: `type` is inside the preimage, so a signed `SetConfig` cannot be
    /// replayed as a signed `Command` on a controller that would act on it.
    #[test]
    fn a_signed_request_cannot_be_replayed_under_another_message_type() {
        let session = SessionKey::new(SESSION_KEY);
        let mut other = signed_request_fields();
        other.kind = MessageType::SetConfig;
        assert_ne!(
            session.signed_request(&signed_request_fields()).as_bytes(),
            session.signed_request(&other).as_bytes()
        );
    }

    /// P-047: without `req_id` in both preimages the comms processor can move a
    /// validly-MAC'd answer onto a different outstanding request and both ends
    /// still verify. The `session_id` is in there for the other half of the same
    /// pair.
    #[test]
    fn a_response_cannot_be_moved_onto_another_outstanding_request() {
        let session = SessionKey::new(SESSION_KEY);

        let mut elsewhere = command_ack_fields();
        elsewhere.req_id = ReqId(REQ_ID.saturating_add(1));
        assert_ne!(
            session.response(&command_ack_fields()).as_bytes(),
            session.response(&elsewhere).as_bytes()
        );

        let mut other_session = command_ack_fields();
        other_session.session = SessionId::from(SESSION.saturating_add(1));
        assert_ne!(
            session.response(&command_ack_fields()).as_bytes(),
            session.response(&other_session).as_bytes()
        );
    }

    /// P-069: an ack recorded from an earlier enrolment must not verify on a
    /// later attempt. The nonce is the only input the client chooses, so it is
    /// all that stands between a replayed ack and a second phone being told it
    /// is the same `client_id` as the first.
    #[test]
    fn an_ack_from_an_earlier_enrolment_does_not_verify_on_a_later_attempt() {
        let pair = PairKey::new(PAIR_KEY);
        let fresh = [0x5au8; NONCE_BYTES];
        let mut later = pair_ack_fields();
        later.client_nonce = &fresh;
        assert_ne!(
            pair.ack(&pair_ack_fields()).as_bytes(),
            pair.ack(&later).as_bytes()
        );
    }

    /// The proof and the ack of one attempt are not interchangeable either, even
    /// though they share a key and three of their fields.
    #[test]
    fn a_pairing_proof_does_not_verify_as_the_ack_that_answers_it() {
        let pair = PairKey::new(PAIR_KEY);
        assert_ne!(
            pair.proof(&pair_proof_fields()).as_bytes(),
            pair.ack(&pair_ack_fields()).as_bytes()
        );
    }

    /// Every client kind is its own tag. The kind fixes the capability mask at
    /// enrolment, so a phone that could be re-read as a cloud enrolment is the
    /// whole capability model gone.
    #[test]
    fn each_client_kind_pairs_under_a_tag_of_its_own() {
        const KINDS: [ClientKind; 4] = [
            ClientKind::App,
            ClientKind::Browser,
            ClientKind::Cloud,
            ClientKind::Cli,
        ];
        let pair = PairKey::new(PAIR_KEY);

        let mut tags = [[0u8; Tag::LEN]; KINDS.len()];
        for (slot, kind) in tags.iter_mut().zip(KINDS) {
            let mut fields = pair_proof_fields();
            fields.client_kind = kind;
            *slot = *pair.proof(&fields).as_bytes();
        }
        for first in 0..KINDS.len() {
            for second in first.saturating_add(1)..KINDS.len() {
                assert_ne!(
                    tags.get(first).expect("the index came from the list"),
                    tags.get(second).expect("the index came from the list"),
                    "two client kinds share a proof"
                );
            }
        }
    }

    /// One bit anywhere and the tag moves — across a fixed 16-byte field, a
    /// big-endian integer and the variable-width bytes at the tail.
    ///
    /// A field fed at the wrong width, or dropped from the concatenation
    /// altogether, shows up here as a run of flips that change nothing.
    #[test]
    fn a_single_bit_flipped_anywhere_in_a_preimage_changes_the_tag() {
        let baseline = hello_tag(&CHALLENGE, &CLIENT_NONCE, CLIENT_ID, &HELLO_BODY);

        for byte in 0..NONCE_BYTES {
            for bit in 0..8u8 {
                let mut challenge = CHALLENGE;
                *challenge.get_mut(byte).expect("inside the challenge") ^= 1 << bit;
                assert_ne!(
                    hello_tag(&challenge, &CLIENT_NONCE, CLIENT_ID, &HELLO_BODY),
                    baseline,
                    "challenge byte {byte} bit {bit} does not reach the tag"
                );

                let mut nonce = CLIENT_NONCE;
                *nonce.get_mut(byte).expect("inside the nonce") ^= 1 << bit;
                assert_ne!(
                    hello_tag(&CHALLENGE, &nonce, CLIENT_ID, &HELLO_BODY),
                    baseline,
                    "client_nonce byte {byte} bit {bit} does not reach the tag"
                );
            }
        }

        for bit in 0..u32::BITS {
            assert_ne!(
                hello_tag(
                    &CHALLENGE,
                    &CLIENT_NONCE,
                    CLIENT_ID ^ (1u32 << bit),
                    &HELLO_BODY
                ),
                baseline,
                "client_id bit {bit} does not reach the tag"
            );
        }

        for byte in 0..HELLO_BODY.len() {
            for bit in 0..8u8 {
                let mut payload = HELLO_BODY;
                *payload.get_mut(byte).expect("inside the payload") ^= 1 << bit;
                assert_ne!(
                    hello_tag(&CHALLENGE, &CLIENT_NONCE, CLIENT_ID, &payload),
                    baseline,
                    "payload byte {byte} bit {bit} does not reach the tag"
                );
            }
        }
    }

    fn hello_tag(
        challenge: &[u8; NONCE_BYTES],
        nonce: &[u8; NONCE_BYTES],
        client_id: u32,
        payload: &[u8],
    ) -> [u8; Tag::LEN] {
        *ClientKey::new(CLIENT_KEY)
            .hello_proof(&HelloProof {
                challenge,
                client_nonce: nonce,
                client_id,
                payload,
            })
            .as_bytes()
    }

    /// P-048: the MAC covers the literal bytes that arrived.
    ///
    /// `1904c0` and `1a000004c0` are the same CBOR integer and different bytes.
    /// A verifier that decoded and re-encoded before hashing would compute one
    /// tag for both — and so would authenticate a body the sender never sent,
    /// which is the whole of what the MAC was there to rule out.
    #[test]
    fn a_re_encoded_payload_is_not_the_payload_that_arrived() {
        let session = SessionKey::new(SESSION_KEY);
        let long_form: [u8; 10] = hex("a2011a000004c0021840");
        let mut same_meaning = read_log_fields();
        same_meaning.payload = &long_form;

        assert_ne!(
            session.wrapper_request(&read_log_fields()).as_bytes(),
            session.wrapper_request(&same_meaning).as_bytes(),
            "two encodings of one map produced one tag, so something re-encoded"
        );
    }

    /// An empty body is still a preimage with a label in front of it, not an
    /// empty input — and two empty bodies under two labels are still two tags.
    #[test]
    fn an_empty_payload_is_still_a_labelled_preimage() {
        let session = SessionKey::new(SESSION_KEY);
        let mut empty = read_log_fields();
        empty.payload = &[];

        assert_ne!(
            session.wrapper_request(&empty).as_bytes(),
            session.response(&empty).as_bytes()
        );
        assert_ne!(
            session.wrapper_request(&empty).as_bytes(),
            session.wrapper_request(&read_log_fields()).as_bytes()
        );
    }

    /// The tag a key computes verifies against the bytes it produces, which is
    /// the only thing that makes every refusal below mean anything.
    #[test]
    fn the_tag_these_fields_compute_verifies_against_the_bytes_they_produce() {
        let session = SessionKey::new(SESSION_KEY);
        let tag = session.response(&command_ack_fields());
        assert_eq!(tag.verify(tag.as_bytes().as_slice()), Ok(()));
    }

    /// A tag of the wrong width is refused, never padded out or trimmed to fit.
    ///
    /// Pad a twelve-byte tag to sixteen and it verifies against a forgery whose
    /// last four bytes were never guessed; trim a longer one and a peer that
    /// disagrees about the width still gets in.
    #[test]
    fn a_tag_of_the_wrong_width_is_refused_rather_than_padded() {
        let session = SessionKey::new(SESSION_KEY);
        let tag = session.response(&command_ack_fields());
        let bytes = tag.as_bytes();

        for short in 0..TAG_BYTES {
            let truncated = bytes.get(..short).expect("short is inside the tag");
            assert_eq!(
                tag.verify(truncated),
                Err(MacError::WrongLength(short)),
                "a {short}-byte tag was not refused on its width"
            );
        }

        let mut long = [0u8; TAG_BYTES + 1];
        for (slot, &byte) in long.iter_mut().zip(bytes) {
            *slot = byte;
        }
        assert_eq!(tag.verify(&long), Err(MacError::WrongLength(TAG_BYTES + 1)));
        assert_eq!(tag.verify(&[]), Err(MacError::WrongLength(0)));
    }

    /// Every single-bit forgery of a correct tag is refused. A comparison that
    /// stopped early would pass this too and would still be a byte-at-a-time
    /// oracle, which is why the comparison itself goes through `subtle` rather
    /// than being checked by a test.
    #[test]
    fn a_tag_that_is_one_bit_wrong_does_not_verify() {
        let session = SessionKey::new(SESSION_KEY);
        let tag = session.response(&command_ack_fields());

        for byte in 0..TAG_BYTES {
            for bit in 0..8u8 {
                let mut forged = *tag.as_bytes();
                *forged.get_mut(byte).expect("inside the tag") ^= 1 << bit;
                assert_eq!(
                    tag.verify(&forged),
                    Err(MacError::Mismatch),
                    "byte {byte} bit {bit} of a tag was not checked"
                );
            }
        }
    }

    /// A tag computed under another key does not verify. It is sixteen bytes of
    /// exactly the right shape, so nothing but the comparison catches it.
    #[test]
    fn a_tag_computed_under_another_key_does_not_verify() {
        let ours = SessionKey::new(SESSION_KEY);
        let theirs = SessionKey::new(PAIR_KEY);
        let fields = command_ack_fields();
        assert_eq!(
            ours.response(&fields)
                .verify(theirs.response(&fields).as_bytes().as_slice()),
            Err(MacError::Mismatch)
        );
    }

    /// The refusals render as different sentences, because the pair somebody
    /// will be telling apart in a bench log is "the peer disagrees about the
    /// width" and "the peer disagrees about the key".
    #[test]
    fn every_refusal_says_something_of_its_own() {
        const EVERY: [MacError; 3] = [
            MacError::WrongLength(0),
            MacError::WrongLength(32),
            MacError::Mismatch,
        ];
        Rendering::<64>::each_says_something_of_its_own(&EVERY);
    }

    /// A domain renders as the label it prepends, so a bench log naming the
    /// domain a frame failed under is naming the bytes that went into the hash.
    #[test]
    fn a_domain_renders_as_the_label_it_prepends() {
        assert_eq!(
            Rendering::<64>::displayed(&Domain::HelloProof).bytes(),
            b"km43/v1/hello-proof"
        );
    }
}
