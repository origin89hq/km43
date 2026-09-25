//! The sealed body every message wears once a handshake has finished, and the
//! types that make its two rules impossible to get wrong.
//!
//! The receiver's rule: nothing inside is read before the tag verifies.
//! [`Sealed`] has no accessor for the plaintext at all, and [`Sealed::open`] is
//! the only way to an [`Opened`], which has one.
//!
//! The sender's rule: a nonce is used once per key. The counter lives in the
//! sealer and moves on every seal; there is no parameter a caller could pass
//! twice (P-232). A repeated ChaCha20-Poly1305 nonce under one key gives away
//! the XOR of two plaintexts and the one-time Poly1305 key, which is every later
//! message of the session forged. A client's sealer issues `req_id` itself,
//! because a request's nonce *is* its `req_id`.
//!
//! cites: P-022, P-023, P-050, P-051, P-230, P-231, P-232, P-233, P-234

use core::fmt;

use zeroize::Zeroizing;

use crate::cbor::CborError;
use crate::envelope::{Envelope, Header, Refusal, ReqId, SessionId};
use crate::generated::{ErrorCode, MessageType};
use crate::limits::{MAX_INFLIGHT, MAX_REPLAY_WINDOW};
use crate::noise::{KEY_BYTES, NoiseError, TAG_BYTES, open_in_place, seal_in_place};

/// P-234's associated data: the three envelope scalars, fixed width and
/// big-endian (P-040). The comms processor routes on exactly these, so a frame
/// it moves onto another request or another session no longer opens.
const AD_BYTES: usize = 1 + 2 + 4;

/// The one nonce Noise reserves, which a controller session ends before
/// reaching (P-232).
const LAST_NONCE: u64 = u64::MAX;

const_assert!(
    MAX_REPLAY_WINDOW <= u64::BITS as usize && MAX_INFLIGHT < MAX_REPLAY_WINDOW,
    "a window is one bit per nonce in a u64; wider and the shift below silently drops the oldest"
);

/// One of the two keys a sealed body carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SealedKey {
    /// Key 1, the ciphertext with its tag.
    Sealed,
    /// Key 2, the controller's nonce. A request carries none: its `req_id` is.
    Nonce,
}

impl SealedKey {
    const fn of(number: i64) -> Option<Self> {
        match number {
            1 => Some(Self::Sealed),
            2 => Some(Self::Nonce),
            _ => None,
        }
    }

    const fn number(self) -> i64 {
        match self {
            Self::Sealed => 1,
            Self::Nonce => 2,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Nonce => "nonce",
        }
    }
}

impl fmt::Display for SealedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (key {})", self.name(), self.number())
    }
}

/// Which way a sealed message travels, read off its `type`: it decides the
/// body's shape and where the nonce comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// A client's request; the nonce is the `req_id`.
    Request,
    /// A response or an event; the nonce is carried in key 2.
    Controller,
}

impl Direction {
    /// P-052's table. The handshake messages carry their own Noise messages and
    /// `Discover` has no key yet, so each is refused rather than sealed under a
    /// guess. `Error` is sealed only when its sender holds a session, which the
    /// caller decides (P-142).
    const fn of(kind: MessageType) -> Option<Self> {
        match kind {
            MessageType::Subscribe
            | MessageType::ReadLog
            | MessageType::GetConfig
            | MessageType::SetConfig
            | MessageType::Command
            | MessageType::Firmware
            | MessageType::Time
            | MessageType::Goodbye
            | MessageType::Inventory
            | MessageType::Readings
            | MessageType::Concerns
            | MessageType::History
            | MessageType::WifiScan
            | MessageType::WifiStatus => Some(Self::Request),
            MessageType::EnrolResponse
            | MessageType::SubscribeResponse
            | MessageType::EventResponse
            | MessageType::ReadLogResponse
            | MessageType::GetConfigResponse
            | MessageType::SetConfigResponse
            | MessageType::CommandResponse
            | MessageType::FirmwareResponse
            | MessageType::TimeResponse
            | MessageType::GoodbyeResponse
            | MessageType::InventoryResponse
            | MessageType::ReadingsResponse
            | MessageType::ConcernsResponse
            | MessageType::HistoryResponse
            | MessageType::WifiScanResponse
            | MessageType::WifiStatusResponse
            | MessageType::ErrorResponse => Some(Self::Controller),
            MessageType::Discover
            | MessageType::DiscoverResponse
            | MessageType::Hello
            | MessageType::HelloResponse
            | MessageType::Pair
            | MessageType::PairResponse
            | MessageType::Enrol => None,
        }
    }

    /// The type's direction, refusing a type that does not travel sealed and an
    /// event whose `req_id` is not zero (P-023).
    fn check(header: Header) -> Result<Self, SealError> {
        let direction = Self::of(header.kind).ok_or(SealError::NotSealed(header.kind))?;
        if header.kind == MessageType::EventResponse && header.req_id != ReqId(0) {
            return Err(SealError::EventCarriesReqId(header.req_id));
        }
        Ok(direction)
    }
}

fn ad(header: Header) -> [u8; AD_BYTES] {
    let mut out = [0u8; AD_BYTES];
    let session = u16::from(header.session).to_be_bytes();
    let req_id = header.req_id.0.to_be_bytes();
    let fields = [header.kind as u8].into_iter().chain(session).chain(req_id);
    for (slot, byte) in out.iter_mut().zip(fields) {
        *slot = byte;
    }
    out
}

/// The client's side of a session: it seals requests and opens what the
/// controller sends. Built only by [`crate::SessionKeys::for_initiator`].
///
/// No `Debug`, no `Clone`: a copy of a sealer is a second counter over the same
/// key.
pub struct ClientChannel {
    /// Seals requests and issues their `req_id`.
    pub tx: RequestSealer,
    /// Opens responses and events.
    pub rx: Opener,
}

impl ClientChannel {
    pub(crate) fn new(
        send: Zeroizing<[u8; KEY_BYTES]>,
        receive: Zeroizing<[u8; KEY_BYTES]>,
    ) -> Self {
        Self {
            tx: RequestSealer { key: send, next: 1 },
            rx: Opener::new(receive, MAX_REPLAY_WINDOW),
        }
    }
}

/// The controller's side: it seals responses and events and opens requests.
/// Built only by [`crate::SessionKeys::for_responder`].
pub struct ControllerChannel {
    /// Seals responses and events under its own nonce.
    pub tx: ControllerSealer,
    /// Opens requests, refusing a `req_id` P-022's window has already seen.
    pub rx: Opener,
}

impl ControllerChannel {
    pub(crate) fn new(
        send: Zeroizing<[u8; KEY_BYTES]>,
        receive: Zeroizing<[u8; KEY_BYTES]>,
    ) -> Self {
        Self {
            tx: ControllerSealer { key: send, next: 0 },
            // P-022: the highest accepted and the MAX_INFLIGHT below it.
            rx: Opener::new(receive, MAX_INFLIGHT.saturating_add(1)),
        }
    }
}

/// The client's sending direction: a key, and the `req_id` it issues next.
pub struct RequestSealer {
    key: Zeroizing<[u8; KEY_BYTES]>,
    next: u32,
}

impl RequestSealer {
    /// Seal `inner` as a request of `kind` on `session`, under the next
    /// `req_id`, and write the whole envelope into `dst`. The `req_id` comes
    /// back with the length, because the caller matches the response on it
    /// (P-024) and never chose it.
    ///
    /// The `req_id` is spent even if writing fails afterwards: a nonce is spent
    /// the moment it has keyed a keystream, whether or not the frame left.
    pub fn seal(
        &mut self,
        kind: MessageType,
        session: SessionId,
        inner: &[u8],
        dst: &mut [u8],
    ) -> Result<(ReqId, usize), SealError> {
        if Direction::of(kind) != Some(Direction::Request) {
            return Err(SealError::NotSealed(kind));
        }
        let req_id = self.next;
        self.next = req_id.checked_add(1).ok_or(SealError::Exhausted)?;
        let header = Header {
            kind,
            session,
            req_id: ReqId(req_id),
        };
        let len = write(&self.key, header, u64::from(req_id), None, inner, dst)?;
        Ok((header.req_id, len))
    }

    /// The `req_id` the next request will carry.
    #[must_use]
    pub const fn next_req_id(&self) -> ReqId {
        ReqId(self.next)
    }
}

/// The controller's sending direction: a key and the next nonce under it.
pub struct ControllerSealer {
    key: Zeroizing<[u8; KEY_BYTES]>,
    next: u64,
}

impl ControllerSealer {
    /// Seal `inner` under the next nonce and write the whole envelope into
    /// `dst`. `header` echoes the request it answers (P-027), or carries
    /// `req_id` 0 on an event (P-023).
    pub fn seal(
        &mut self,
        header: Header,
        inner: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, SealError> {
        if Direction::check(header)? != Direction::Controller {
            return Err(SealError::NotSealed(header.kind));
        }
        let nonce = self.next;
        if nonce == LAST_NONCE {
            return Err(SealError::Exhausted);
        }
        self.next = nonce.saturating_add(1);
        write(&self.key, header, nonce, Some(nonce), inner, dst)
    }

    /// The nonce the next message will carry.
    #[must_use]
    pub const fn next_nonce(&self) -> u64 {
        self.next
    }
}

/// Write the envelope, reserve the ciphertext in place, and seal it there.
fn write(
    key: &[u8; KEY_BYTES],
    header: Header,
    nonce: u64,
    carried: Option<u64>,
    inner: &[u8],
    dst: &mut [u8],
) -> Result<usize, SealError> {
    let sealed_len = inner
        .len()
        .checked_add(TAG_BYTES)
        .ok_or(SealError::TooLargeToWrite)?;
    let pairs = if carried.is_some() { 2 } else { 1 };
    let mut cbor = header
        .write(pairs, dst)
        .map_err(|_| SealError::TooLargeToWrite)?;
    let range = (|| {
        cbor.key(SealedKey::Sealed.number())?;
        let range = cbor.bytes_to_fill(sealed_len)?;
        if let Some(value) = carried {
            cbor.key(SealedKey::Nonce.number())?;
            cbor.u64(value)?;
        }
        Ok::<_, CborError>(range)
    })()
    .map_err(|_| SealError::TooLargeToWrite)?;
    let len = cbor.finish().map_err(|_| SealError::TooLargeToWrite)?;
    let region = dst.get_mut(range).ok_or(SealError::TooLargeToWrite)?;
    let (body, tag) = region
        .split_at_mut_checked(inner.len())
        .ok_or(SealError::TooLargeToWrite)?;
    body.copy_from_slice(inner);
    seal_in_place(key, nonce, &ad(header), body, tag).map_err(SealError::Open)?;
    Ok(len)
}

/// A receiving direction: a key and the window of nonces already accepted.
pub struct Opener {
    key: Zeroizing<[u8; KEY_BYTES]>,
    window: Window,
}

impl Opener {
    fn new(key: Zeroizing<[u8; KEY_BYTES]>, span: usize) -> Self {
        Self {
            key,
            window: Window::new(span),
        }
    }
}

/// The nonces accepted so far: the highest, and one bit per position below it
/// down to `span - 1` places back. A controller's is P-022's `MAX_INFLIGHT`
/// below the highest; a client's is P-233's `MAX_REPLAY_WINDOW` ending at it.
struct Window {
    highest: Option<u64>,
    /// Bit `n` set means `highest - n` has been accepted.
    seen: u64,
    span: u64,
}

impl Window {
    fn new(span: usize) -> Self {
        Self {
            highest: None,
            seen: 0,
            span: u64::try_from(span).unwrap_or(u64::from(u64::BITS)),
        }
    }

    /// Whether `nonce` may be opened: not older than the window and not already
    /// accepted. Checked before the tag, so a replay costs nothing.
    fn admits(&self, nonce: u64) -> Result<(), SealError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if nonce > highest {
            return Ok(());
        }
        let age = highest.saturating_sub(nonce);
        if age >= self.span {
            return Err(SealError::TooOld(nonce));
        }
        let bit = u32::try_from(age)
            .ok()
            .and_then(|age| 1u64.checked_shl(age))
            .ok_or(SealError::TooOld(nonce))?;
        if self.seen & bit == 0 {
            Ok(())
        } else {
            Err(SealError::Replayed(nonce))
        }
    }

    /// Record `nonce` as accepted. Called only after its tag verified, so a
    /// forged nonce cannot move the window past the honest frames behind it.
    fn accept(&mut self, nonce: u64) {
        match self.highest {
            None => {
                self.highest = Some(nonce);
                self.seen = 1;
            }
            Some(highest) if nonce > highest => {
                let shift = nonce.saturating_sub(highest);
                self.seen = u32::try_from(shift)
                    .ok()
                    .and_then(|shift| self.seen.checked_shl(shift))
                    .unwrap_or(0)
                    | 1;
                self.highest = Some(nonce);
            }
            Some(highest) => {
                let age = highest.saturating_sub(nonce);
                if let Some(bit) = u32::try_from(age)
                    .ok()
                    .and_then(|age| 1u64.checked_shl(age))
                {
                    self.seen |= bit;
                }
            }
        }
    }
}

/// A sealed body as it arrived: routing fields, a nonce, and bytes nobody has
/// authenticated. It has no accessor for the plaintext:
///
/// ```
/// fn read<'d>(opened: km43::Opened<'d>) -> &'d [u8] { opened.inner() }
/// ```
/// ```compile_fail
/// fn read<'a>(sealed: km43::Sealed<'a>) -> &'a [u8] { sealed.inner() }
/// ```
pub struct Sealed<'a> {
    header: Header,
    nonce: u64,
    ciphertext: &'a [u8],
}

impl<'a> Sealed<'a> {
    /// Take the sealed body out of an envelope, refusing anything but exactly
    /// the keys its direction carries (P-231): a key beside the ciphertext would
    /// sit outside the tag.
    pub fn decode(envelope: Envelope<'a>) -> Result<Self, SealError> {
        let header = envelope.header();
        let direction = Direction::check(header)?;
        let pairs = envelope.keys();
        let mut body = envelope.into_body();
        let mut nonce = None;
        let mut sealed = None;
        for _ in 0..pairs {
            let number = body.key().map_err(SealError::Cbor)?;
            let key = SealedKey::of(number).ok_or(SealError::UnknownKey(number))?;
            match key {
                SealedKey::Sealed => {
                    let value = body.bytes().map_err(SealError::Cbor)?;
                    if sealed.replace(value).is_some() {
                        return Err(SealError::Duplicate(key));
                    }
                }
                SealedKey::Nonce => {
                    if direction == Direction::Request {
                        return Err(SealError::UnknownKey(number));
                    }
                    let value = body.u64().map_err(SealError::Cbor)?;
                    if nonce.replace(value).is_some() {
                        return Err(SealError::Duplicate(key));
                    }
                }
            }
        }
        body.finish().map_err(SealError::Cbor)?;
        let nonce = match direction {
            Direction::Request => u64::from(header.req_id.0),
            Direction::Controller => nonce.ok_or(SealError::Missing(SealedKey::Nonce))?,
        };
        Ok(Self {
            header,
            nonce,
            ciphertext: sealed.ok_or(SealError::Missing(SealedKey::Sealed))?,
        })
    }

    /// The routing fields. Unauthenticated until [`Sealed::open`] succeeds, but
    /// they are what picks the session whose key opens it.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// Open under `rx` into `dst`. A nonce already accepted, or older than the
    /// window, is refused before any work; a tag that fails leaves `dst`
    /// cleared and the window where it was.
    pub fn open<'d>(self, rx: &mut Opener, dst: &'d mut [u8]) -> Result<Opened<'d>, SealError> {
        // No honest sender reaches it (P-232), so it is a discard like a
        // replay, never the session-ending refusal a relay could otherwise
        // trigger without a valid frame (P-233).
        if self.nonce == LAST_NONCE {
            return Err(SealError::Reserved);
        }
        rx.window.admits(self.nonce)?;
        let body_len = self
            .ciphertext
            .len()
            .checked_sub(TAG_BYTES)
            .ok_or(SealError::Open(NoiseError::Truncated))?;
        let (ciphertext, tag) = self
            .ciphertext
            .split_at_checked(body_len)
            .ok_or(SealError::Open(NoiseError::Truncated))?;
        let out = dst
            .get_mut(..body_len)
            .ok_or(SealError::DestinationTooSmall)?;
        out.copy_from_slice(ciphertext);
        if let Err(why) = open_in_place(&rx.key, self.nonce, &ad(self.header), out, tag) {
            out.fill(0);
            return Err(SealError::Open(why));
        }
        rx.window.accept(self.nonce);
        Ok(Opened {
            header: self.header,
            inner: out,
        })
    }
}

/// Lengths and routing only, for the reason the plaintext accessor is missing.
impl fmt::Debug for Sealed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sealed {{ header: {:?}, nonce: {}, sealed: {} bytes }}",
            self.header,
            self.nonce,
            self.ciphertext.len()
        )
    }
}

/// A body whose tag verified: the envelope scalars it was bound to, and the
/// plaintext.
pub struct Opened<'d> {
    header: Header,
    inner: &'d [u8],
}

/// Lengths, never the plaintext: a `SetConfig` body carries the site's Wi-Fi
/// passphrase, and a derived `Debug` is a log line away from printing it.
impl fmt::Debug for Opened<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Opened {{ header: {:?}, inner: {} bytes }}",
            self.header,
            self.inner.len()
        )
    }
}

impl<'d> Opened<'d> {
    /// The scalars the tag covered.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// The inner body, now authenticated.
    #[must_use]
    pub const fn inner(&self) -> &'d [u8] {
        self.inner
    }
}

/// Why a sealed body was refused or could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SealError {
    /// A key that is not one its direction carries (P-231).
    UnknownKey(i64),
    /// The same key twice (P-015).
    Duplicate(SealedKey),
    /// A key that never arrived.
    Missing(SealedKey),
    /// A type that does not travel sealed, or not in this direction.
    NotSealed(MessageType),
    /// An event with a non-zero `req_id` (P-023).
    EventCarriesReqId(ReqId),
    /// A nonce this receiver has already accepted. Not answered and not
    /// counted (P-022, P-233).
    Replayed(u64),
    /// A nonce older than the window. Not answered and not counted.
    TooOld(u64),
    /// The nonce Noise reserves, which no honest sender uses. Not answered and
    /// not counted (P-233).
    Reserved,
    /// The tag did not verify, or the body was too short to carry one.
    Open(NoiseError),
    /// The session reached the last nonce or `req_id` it may use (P-232).
    Exhausted,
    /// The plaintext does not fit the buffer handed in. Ours, not the peer's.
    DestinationTooSmall,
    /// The frame did not fit the buffer it was being written into.
    TooLargeToWrite,
    /// The CBOR underneath was refused.
    Cbor(CborError),
}

impl SealError {
    /// What to answer. `None` for the refusals P-022 and P-233 answer with
    /// silence: a replay verifies nothing new, and answering it would mint a
    /// second response to a request already answered.
    #[must_use]
    pub const fn refusal(self) -> Option<Refusal> {
        match self {
            Self::Missing(SealedKey::Sealed) | Self::Open(_) => {
                Some(Refusal::Client(ErrorCode::AuthenticationFailed))
            }
            Self::Missing(SealedKey::Nonce)
            | Self::UnknownKey(_)
            | Self::Duplicate(_)
            | Self::NotSealed(_)
            | Self::EventCarriesReqId(_)
            | Self::Cbor(_) => Some(Refusal::Client(ErrorCode::MalformedFrame)),
            Self::TooLargeToWrite | Self::DestinationTooSmall => {
                Some(Refusal::Client(ErrorCode::PayloadTooLarge))
            }
            Self::Exhausted => Some(Refusal::Client(ErrorCode::SessionExpired)),
            Self::Replayed(_) | Self::TooOld(_) | Self::Reserved => None,
        }
    }

    /// Whether this counts against `MAX_AUTH_FAILURES` (P-051): a tag that
    /// failed, and nothing else. A replay verified once already.
    #[must_use]
    pub const fn counts(self) -> bool {
        match self {
            Self::Missing(SealedKey::Sealed) | Self::Open(_) => true,
            Self::Missing(SealedKey::Nonce)
            | Self::UnknownKey(_)
            | Self::Duplicate(_)
            | Self::NotSealed(_)
            | Self::EventCarriesReqId(_)
            | Self::Replayed(_)
            | Self::TooOld(_)
            | Self::Reserved
            | Self::Exhausted
            | Self::DestinationTooSmall
            | Self::TooLargeToWrite
            | Self::Cbor(_) => false,
        }
    }
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(number) => write!(f, "sealed body key {number} is not one it carries"),
            Self::Duplicate(key) => write!(f, "sealed body carries {key} twice"),
            Self::Missing(key) => write!(f, "sealed body carries no {key}"),
            Self::NotSealed(kind) => write!(
                f,
                "message type {:#04x} does not travel sealed this way",
                *kind as u8
            ),
            Self::EventCarriesReqId(req_id) => {
                write!(f, "an unsolicited event carries req_id {}", req_id.0)
            }
            Self::Replayed(nonce) => write!(f, "nonce {nonce} was already accepted"),
            Self::TooOld(nonce) => write!(f, "nonce {nonce} is older than the replay window"),
            Self::Reserved => f.write_str("the nonce Noise reserves arrived"),
            Self::Open(why) => write!(f, "{why}"),
            Self::Exhausted => f.write_str("the session reached the last nonce it may use"),
            Self::DestinationTooSmall => f.write_str("the plaintext does not fit the buffer"),
            Self::TooLargeToWrite => {
                f.write_str("the frame does not fit the buffer it is written into")
            }
            Self::Cbor(why) => write!(f, "{why}"),
        }
    }
}

impl core::error::Error for SealError {}

/// Both ends of one session from fixed keys, for tests that need a channel
/// without running a handshake first.
#[cfg(test)]
pub(crate) fn channels(
    client_to_controller: [u8; KEY_BYTES],
    controller_to_client: [u8; KEY_BYTES],
) -> (ClientChannel, ControllerChannel) {
    (
        ClientChannel::new(
            Zeroizing::new(client_to_controller),
            Zeroizing::new(controller_to_client),
        ),
        ControllerChannel::new(
            Zeroizing::new(controller_to_client),
            Zeroizing::new(client_to_controller),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::CborWriter;

    const INNER: &[u8] = &[0xA1, 0x01, 0x18, 0x2A];

    fn pair() -> (ClientChannel, ControllerChannel) {
        channels([0x11; KEY_BYTES], [0x22; KEY_BYTES])
    }

    fn header(kind: MessageType, req_id: u32) -> Header {
        Header {
            kind,
            session: SessionId::from(3),
            req_id: ReqId(req_id),
        }
    }

    fn open<'d>(frame: &[u8], rx: &mut Opener, dst: &'d mut [u8]) -> Result<Opened<'d>, SealError> {
        let envelope = Envelope::decode(frame).map_err(|_| SealError::TooLargeToWrite)?;
        Sealed::decode(envelope)?.open(rx, dst)
    }

    /// A request goes out under the `req_id` the sealer picked and comes back
    /// out whole at the controller; a response comes back at the client.
    #[test]
    fn p_231_a_request_and_its_answer_open_at_the_other_end() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        let (req_id, len) = client
            .tx
            .seal(MessageType::ReadLog, SessionId::from(3), INNER, &mut frame)
            .expect("seals");
        let mut plain = [0u8; 16];
        let opened = open(&frame[..len], &mut controller.rx, &mut plain).expect("opens");
        assert_eq!(opened.inner(), INNER);
        assert_eq!(opened.header().req_id, req_id);

        let len = controller
            .tx
            .seal(
                header(MessageType::ReadLogResponse, req_id.0),
                INNER,
                &mut frame,
            )
            .expect("seals");
        let opened = open(&frame[..len], &mut client.rx, &mut plain).expect("opens");
        assert_eq!(opened.inner(), INNER);
    }

    /// The sealer issues `req_id` from 1 and never twice, and the caller has no
    /// way to choose one: a `req_id` sealed twice is a nonce used twice.
    #[test]
    fn p_232_the_client_issues_each_req_id_once_starting_at_one() {
        let (mut client, _) = pair();
        let mut frame = [0u8; 64];
        for want in 1..=40u32 {
            let (req_id, _) = client
                .tx
                .seal(
                    MessageType::Goodbye,
                    SessionId::from(3),
                    &[0xA0],
                    &mut frame,
                )
                .expect("seals");
            assert_eq!(req_id, ReqId(want));
        }
        assert_eq!(client.tx.next_req_id(), ReqId(41));
    }

    /// The controller's nonce starts at 0, rises by one per message whatever the
    /// kind, and is carried in key 2.
    #[test]
    fn p_232_the_controller_carries_a_nonce_that_rises_by_one_per_message() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        let mut plain = [0u8; 16];
        for (i, kind) in [
            MessageType::GoodbyeResponse,
            MessageType::EventResponse,
            MessageType::ErrorResponse,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(controller.tx.next_nonce(), u64::try_from(i).expect("small"));
            let req_id = if kind == MessageType::EventResponse {
                0
            } else {
                5
            };
            let len = controller
                .tx
                .seal(header(kind, req_id), &[0xA0], &mut frame)
                .expect("seals");
            let sealed = Sealed::decode(Envelope::decode(&frame[..len]).expect("decodes"))
                .expect("a sealed body");
            assert_eq!(sealed.nonce, u64::try_from(i).expect("small"));
            sealed.open(&mut client.rx, &mut plain).expect("opens");
        }
    }

    /// A session ends rather than wrapping: the last `req_id` a `u32` holds is
    /// refused, and so is the nonce Noise reserves.
    #[test]
    fn p_232_a_session_ends_before_a_nonce_could_repeat() {
        let (mut client, mut controller) = pair();
        client.tx.next = u32::MAX;
        let mut frame = [0u8; 64];
        assert_eq!(
            client
                .tx
                .seal(
                    MessageType::Goodbye,
                    SessionId::from(3),
                    &[0xA0],
                    &mut frame
                )
                .err(),
            Some(SealError::Exhausted)
        );
        controller.tx.next = LAST_NONCE;
        assert_eq!(
            controller
                .tx
                .seal(header(MessageType::GoodbyeResponse, 1), &[0xA0], &mut frame)
                .err(),
            Some(SealError::Exhausted)
        );
    }

    /// P-022, the controller's side: a request whose `req_id` it already took is
    /// refused before the tag is checked, and so is one older than the reorder
    /// window, and neither is answered or counted.
    #[test]
    fn p_022_a_request_whose_req_id_it_already_took_is_refused() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        let mut plain = [0u8; 16];
        let (_, len) = client
            .tx
            .seal(MessageType::ReadLog, SessionId::from(3), INNER, &mut frame)
            .expect("seals");
        let replay = frame;
        open(&frame[..len], &mut controller.rx, &mut plain).expect("the first opens");
        let refused = open(&replay[..len], &mut controller.rx, &mut plain).err();
        assert_eq!(refused, Some(SealError::Replayed(1)));
    }

    #[test]
    fn p_022_a_request_older_than_the_reorder_window_is_refused() {
        let (mut client, mut controller) = pair();
        let mut first = [0u8; 64];
        let mut plain = [0u8; 16];
        let (_, first_len) = client
            .tx
            .seal(MessageType::ReadLog, SessionId::from(3), INNER, &mut first)
            .expect("seals");
        let mut frame = [0u8; 64];
        let mut last = 0;
        for _ in 0..MAX_INFLIGHT.saturating_add(1) {
            let (_, len) = client
                .tx
                .seal(MessageType::ReadLog, SessionId::from(3), INNER, &mut frame)
                .expect("seals");
            last = len;
        }
        open(&frame[..last], &mut controller.rx, &mut plain).expect("the newest opens");
        assert_eq!(
            open(&first[..first_len], &mut controller.rx, &mut plain).err(),
            Some(SealError::TooOld(1)),
            "a frame banked in the morning and delivered at midnight"
        );
    }

    /// Frames reordered inside the window all open: a client may have four in
    /// flight on a bad radio, and they may land in any order.
    #[test]
    fn p_022_requests_reordered_inside_the_window_all_open() {
        let (mut client, mut controller) = pair();
        let mut frames = [[0u8; 64]; 4];
        let mut lens = [0usize; 4];
        for (frame, len) in frames.iter_mut().zip(lens.iter_mut()) {
            *len = client
                .tx
                .seal(MessageType::ReadLog, SessionId::from(3), INNER, frame)
                .expect("seals")
                .1;
        }
        let mut plain = [0u8; 16];
        for i in [3usize, 0, 2, 1] {
            open(&frames[i][..lens[i]], &mut controller.rx, &mut plain)
                .unwrap_or_else(|e| panic!("frame {i} was refused: {e}"));
        }
    }

    /// Silence is the answer to a replay: no refusal is minted for it and it
    /// does not count against `MAX_AUTH_FAILURES`, or a relay could shed a
    /// client with that client's own frames.
    #[test]
    fn p_022_a_refused_replay_is_unanswered_and_uncounted() {
        for why in [SealError::Replayed(7), SealError::TooOld(7)] {
            assert_eq!(why.refusal(), None, "{why}");
            assert!(!why.counts(), "{why}");
        }
        assert!(SealError::Open(NoiseError::Decrypt).counts());
    }

    /// P-233, the client's side: a controller nonce it already accepted is
    /// refused, and one older than `MAX_REPLAY_WINDOW` is too.
    #[test]
    fn p_233_a_controller_nonce_already_accepted_or_too_old_is_refused() {
        let (mut client, mut controller) = pair();
        let mut frames = [[0u8; 64]; 70];
        let mut lens = [0usize; 70];
        for (frame, len) in frames.iter_mut().zip(lens.iter_mut()) {
            *len = controller
                .tx
                .seal(header(MessageType::EventResponse, 0), &[0xA0], frame)
                .expect("seals");
        }
        let mut plain = [0u8; 4];
        open(&frames[0][..lens[0]], &mut client.rx, &mut plain).expect("first opens");
        assert_eq!(
            open(&frames[0][..lens[0]], &mut client.rx, &mut plain).err(),
            Some(SealError::Replayed(0))
        );
        open(&frames[69][..lens[69]], &mut client.rx, &mut plain).expect("the newest opens");
        assert_eq!(
            open(&frames[1][..lens[1]], &mut client.rx, &mut plain).err(),
            Some(SealError::TooOld(1)),
            "68 behind the newest is outside a window of 64"
        );
        open(&frames[6][..lens[6]], &mut client.rx, &mut plain)
            .expect("63 behind the newest is inside the window");
    }

    /// A forged frame with a high nonce does not move the window: if it did,
    /// every honest frame behind it would be refused as too old without the
    /// forger ever producing a valid tag.
    #[test]
    fn p_233_a_forged_nonce_does_not_move_the_window() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        let len = controller
            .tx
            .seal(header(MessageType::EventResponse, 0), &[0xA0], &mut frame)
            .expect("seals");
        let mut forged = [0u8; 64];
        let mut cbor = header(MessageType::EventResponse, 0)
            .write(2, &mut forged)
            .expect("fits");
        cbor.key(1).expect("key");
        cbor.bytes(&[0; 17]).expect("bytes");
        cbor.key(2).expect("key");
        cbor.u64(1_000).expect("nonce");
        let forged_len = cbor.finish().expect("done");
        let mut plain = [0u8; 4];
        assert!(matches!(
            open(&forged[..forged_len], &mut client.rx, &mut plain),
            Err(SealError::Open(_))
        ));
        open(&frame[..len], &mut client.rx, &mut plain).expect("nonce 0 still opens");
    }

    /// The associated data is `(type, session_id, req_id)`: a sealed request
    /// moved to another type, session or request does not open (P-046, P-047).
    #[test]
    fn p_234_a_frame_moved_to_another_type_session_or_request_does_not_open() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        let len = controller
            .tx
            .seal(header(MessageType::CommandResponse, 9), INNER, &mut frame)
            .expect("seals");
        let sealed =
            Sealed::decode(Envelope::decode(&frame[..len]).expect("decodes")).expect("sealed");
        let ciphertext = sealed.ciphertext;
        for moved in [
            header(MessageType::SetConfigResponse, 9),
            Header {
                session: SessionId::from(4),
                ..header(MessageType::CommandResponse, 9)
            },
            header(MessageType::CommandResponse, 10),
        ] {
            let mut out = [0u8; 64];
            let mut cbor = moved.write(2, &mut out).expect("fits");
            cbor.key(1).expect("key");
            cbor.bytes(ciphertext).expect("bytes");
            cbor.key(2).expect("key");
            cbor.u64(0).expect("nonce");
            let n = cbor.finish().expect("done");
            let mut plain = [0u8; 16];
            assert!(
                matches!(
                    open(&out[..n], &mut client.rx, &mut plain),
                    Err(SealError::Open(_))
                ),
                "{moved:?} opened"
            );
        }
    }

    /// P-046, one direction over: a sealed `SetConfig` is not a sealed
    /// `Command`, whatever its bytes.
    #[test]
    fn p_046_a_sealed_setconfig_does_not_open_as_a_command() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        let (_, len) = client
            .tx
            .seal(
                MessageType::SetConfig,
                SessionId::from(3),
                INNER,
                &mut frame,
            )
            .expect("seals");
        // The type is the envelope's second byte.
        frame[1] = MessageType::Command as u8;
        let mut plain = [0u8; 16];
        assert!(matches!(
            open(&frame[..len], &mut controller.rx, &mut plain),
            Err(SealError::Open(_))
        ));
    }

    /// P-047: a response's associated data carries its `req_id`, so a genuine
    /// answer attached to another outstanding request does not open.
    #[test]
    fn p_047_an_answer_moved_to_another_request_does_not_open() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        let len = controller
            .tx
            .seal(header(MessageType::ReadingsResponse, 12), INNER, &mut frame)
            .expect("seals");
        // `req_id` 12 is the envelope's fourth item, one byte after the type's
        // two and the session's one.
        assert_eq!(frame[4], 12);
        frame[4] = 13;
        let mut plain = [0u8; 16];
        assert!(matches!(
            open(&frame[..len], &mut client.rx, &mut plain),
            Err(SealError::Open(_))
        ));
    }

    /// Each direction has its own key (P-230): a client's request played back to
    /// the client as if the controller had said it does not open.
    #[test]
    fn p_230_a_request_reflected_back_at_the_client_does_not_open() {
        let (mut client, _) = pair();
        let mut frame = [0u8; 64];
        let (_, len) = client
            .tx
            .seal(
                MessageType::Goodbye,
                SessionId::from(3),
                &[0xA0],
                &mut frame,
            )
            .expect("seals");
        let sealed =
            Sealed::decode(Envelope::decode(&frame[..len]).expect("decodes")).expect("sealed");
        let mut out = [0u8; 64];
        let mut cbor = header(MessageType::GoodbyeResponse, 1)
            .write(2, &mut out)
            .expect("fits");
        cbor.key(1).expect("key");
        cbor.bytes(sealed.ciphertext).expect("bytes");
        cbor.key(2).expect("key");
        cbor.u64(1).expect("nonce");
        let n = cbor.finish().expect("done");
        let mut plain = [0u8; 4];
        assert!(matches!(
            open(&out[..n], &mut client.rx, &mut plain),
            Err(SealError::Open(_))
        ));
    }

    /// P-023: an event carrying a `req_id` is refused before anything else, at
    /// both ends.
    #[test]
    fn p_023_an_event_with_a_req_id_is_refused_before_it_is_opened() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        assert_eq!(
            controller
                .tx
                .seal(header(MessageType::EventResponse, 5), &[0xA0], &mut frame)
                .err(),
            Some(SealError::EventCarriesReqId(ReqId(5)))
        );
        let mut cbor = header(MessageType::EventResponse, 5)
            .write(2, &mut frame)
            .expect("fits");
        cbor.key(1).expect("key");
        cbor.bytes(&[0; 17]).expect("bytes");
        cbor.key(2).expect("key");
        cbor.u64(0).expect("nonce");
        let len = cbor.finish().expect("done");
        let mut plain = [0u8; 4];
        assert_eq!(
            open(&frame[..len], &mut client.rx, &mut plain).err(),
            Some(SealError::EventCarriesReqId(ReqId(5)))
        );
    }

    /// Exactly the keys a direction carries (P-231, P-050): a nonce on a request,
    /// a third key, a key twice and a missing one are all refused.
    #[test]
    fn p_231_a_body_with_any_other_key_set_is_refused() {
        type Case = (MessageType, &'static [(i64, bool)], SealError);
        let cases: [Case; 5] = [
            (
                MessageType::ReadLog,
                &[(1, true), (2, false)],
                SealError::UnknownKey(2),
            ),
            (
                MessageType::ReadLogResponse,
                &[(1, true), (2, false), (3, false)],
                SealError::UnknownKey(3),
            ),
            (
                MessageType::ReadLogResponse,
                &[(1, true)],
                SealError::Missing(SealedKey::Nonce),
            ),
            (
                MessageType::ReadLog,
                &[],
                SealError::Missing(SealedKey::Sealed),
            ),
            (
                MessageType::ReadLogResponse,
                &[(2, false)],
                SealError::Missing(SealedKey::Sealed),
            ),
        ];
        for (kind, keys, want) in cases {
            let mut frame = [0u8; 64];
            let mut cbor = header(kind, 1).write(keys.len(), &mut frame).expect("fits");
            for &(key, bytes) in keys {
                cbor.key(key).expect("key");
                if bytes {
                    cbor.bytes(&[0; 17]).expect("bytes");
                } else {
                    cbor.u64(0).expect("u64");
                }
            }
            let len = cbor.finish().expect("done");
            let got = Sealed::decode(Envelope::decode(&frame[..len]).expect("decodes")).err();
            assert_eq!(got, Some(want), "{kind:?} {keys:?}");
        }
    }

    /// P-052: `Discover` and the handshake messages are refused rather than
    /// sealed under a guess, and every other type travels sealed.
    #[test]
    fn p_052_only_the_listed_types_travel_sealed() {
        for kind in [
            MessageType::Discover,
            MessageType::DiscoverResponse,
            MessageType::Hello,
            MessageType::HelloResponse,
            MessageType::Pair,
            MessageType::PairResponse,
            MessageType::Enrol,
        ] {
            assert_eq!(Direction::of(kind), None, "{kind:?}");
        }
        assert_eq!(
            Direction::of(MessageType::EnrolResponse),
            Some(Direction::Controller)
        );
        assert_eq!(Direction::of(MessageType::Time), Some(Direction::Request));
    }

    /// A client cannot seal a response and a controller cannot seal a request:
    /// the sealer's direction is its role's.
    #[test]
    fn each_sealer_refuses_the_other_directions_types() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        assert_eq!(
            client
                .tx
                .seal(
                    MessageType::ReadLogResponse,
                    SessionId::from(3),
                    &[0xA0],
                    &mut frame
                )
                .err(),
            Some(SealError::NotSealed(MessageType::ReadLogResponse))
        );
        assert_eq!(
            controller
                .tx
                .seal(header(MessageType::ReadLog, 1), &[0xA0], &mut frame)
                .err(),
            Some(SealError::NotSealed(MessageType::ReadLog))
        );
    }

    /// P-017: the tag covers the bytes as sealed. An inner body in a
    /// non-canonical encoding — a map head a byte wider than it needs — opens as
    /// exactly those bytes; nothing re-encodes before checking.
    #[test]
    fn p_017_a_non_canonical_inner_body_opens_as_the_bytes_it_was() {
        let (mut client, mut controller) = pair();
        let loose = [0xB8, 0x00];
        let mut frame = [0u8; 64];
        let (_, len) = client
            .tx
            .seal(MessageType::Goodbye, SessionId::from(3), &loose, &mut frame)
            .expect("seals");
        let mut plain = [0u8; 4];
        let opened = open(&frame[..len], &mut controller.rx, &mut plain).expect("opens");
        assert_eq!(opened.inner(), loose);
    }

    /// A tag that fails leaves nothing behind in the buffer it was opened into,
    /// and counts (P-051).
    #[test]
    fn p_051_a_failed_tag_clears_the_plaintext_and_counts() {
        let (mut client, mut controller) = pair();
        let mut frame = [0u8; 64];
        let (_, len) = client
            .tx
            .seal(MessageType::ReadLog, SessionId::from(3), INNER, &mut frame)
            .expect("seals");
        frame[len - 1] ^= 1;
        let mut plain = [0x55u8; 16];
        let why = open(&frame[..len], &mut controller.rx, &mut plain).expect_err("refused");
        assert!(why.counts());
        assert_eq!(
            why.refusal(),
            Some(Refusal::Client(ErrorCode::AuthenticationFailed))
        );
        assert!(plain[..INNER.len()].iter().all(|&b| b == 0));
    }

    /// Every single-bit flip in a sealed frame is refused, whichever field it
    /// lands in, and none of them panics.
    #[test]
    fn every_flipped_bit_of_a_sealed_frame_is_refused() {
        let (_, mut controller) = pair();
        let (mut client, _) = pair();
        let mut frame = [0u8; 64];
        let len = controller
            .tx
            .seal(header(MessageType::ReadLogResponse, 7), INNER, &mut frame)
            .expect("seals");
        for byte in 0..len {
            for bit in 0..8 {
                let mut flipped = frame;
                flipped[byte] ^= 1 << bit;
                let (mut fresh, _) = pair();
                let mut plain = [0u8; 16];
                let opened = open(&flipped[..len], &mut fresh.rx, &mut plain);
                assert!(opened.is_err(), "bit {bit} of byte {byte} opened");
            }
        }
        let mut plain = [0u8; 16];
        open(&frame[..len], &mut client.rx, &mut plain).expect("the original still opens");
    }

    /// Every truncation of a sealed frame is refused without a panic.
    #[test]
    fn every_truncation_of_a_sealed_frame_is_refused() {
        let (mut client, _) = pair();
        let mut frame = [0u8; 64];
        let (_, len) = client
            .tx
            .seal(MessageType::ReadLog, SessionId::from(3), INNER, &mut frame)
            .expect("seals");
        for cut in 0..len {
            let (_, mut controller) = pair();
            let mut plain = [0u8; 16];
            assert!(
                open(&frame[..cut], &mut controller.rx, &mut plain).is_err(),
                "a frame cut to {cut} bytes opened"
            );
        }
    }

    /// A buffer too small for the frame or for the plaintext is refused, never
    /// written short, and the nonce it would have used is spent anyway.
    #[test]
    fn a_buffer_too_small_is_refused_and_the_nonce_is_still_spent() {
        let (mut client, mut controller) = pair();
        let mut tiny = [0u8; 8];
        assert_eq!(
            client
                .tx
                .seal(MessageType::ReadLog, SessionId::from(3), INNER, &mut tiny)
                .err(),
            Some(SealError::TooLargeToWrite)
        );
        assert_eq!(client.tx.next_req_id(), ReqId(2));
        let mut frame = [0u8; 64];
        let (_, len) = client
            .tx
            .seal(MessageType::ReadLog, SessionId::from(3), INNER, &mut frame)
            .expect("seals");
        let mut plain = [0u8; 2];
        assert_eq!(
            open(&frame[..len], &mut controller.rx, &mut plain).err(),
            Some(SealError::DestinationTooSmall)
        );
    }

    /// The writer the sealer uses reserves the ciphertext's bytes in place: the
    /// range it hands back is exactly where the bytes sit.
    #[test]
    fn the_reserved_ciphertext_is_where_the_writer_says() {
        let mut out = [0xFFu8; 16];
        let mut cbor = CborWriter::new(&mut out);
        let range = cbor.bytes_to_fill(5).expect("fits");
        let len = cbor.finish().expect("one item");
        assert_eq!(range, 1..6);
        assert_eq!(len, 6);
        assert_eq!(out[0], 0x45);
        assert_eq!(&out[1..6], &[0; 5]);
    }

    /// P-233: the reserved nonce is discarded, unanswered and uncounted, so a
    /// relay cannot end a session with a frame it made up.
    #[test]
    fn p_233_the_reserved_nonce_is_discarded_not_answered() {
        let (mut client, _) = pair();
        let mut frame = [0u8; 64];
        let mut cbor = header(MessageType::EventResponse, 0)
            .write(2, &mut frame)
            .expect("fits");
        cbor.key(1).expect("key");
        cbor.bytes(&[0; 17]).expect("bytes");
        cbor.key(2).expect("key");
        cbor.u64(u64::MAX).expect("nonce");
        let len = cbor.finish().expect("done");
        let mut plain = [0u8; 4];
        let why = open(&frame[..len], &mut client.rx, &mut plain).expect_err("discarded");
        assert_eq!(why, SealError::Reserved);
        assert_eq!(why.refusal(), None);
        assert!(!why.counts());
    }
}
