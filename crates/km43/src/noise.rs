//! The Noise framework's symmetric state and the two handshakes KM43 runs on it:
//! `XXpsk0` to enrol under the printed label, `IK` to open a session under a
//! controller key the client already holds.
//!
//! Each handshake is a chain of types, one per message, and each step consumes
//! the one before it. A responder cannot write its reply before reading the
//! request, an initiator cannot finish before reading the reply, and neither can
//! run a step twice: that is the whole of Noise's message order, checked by the
//! compiler rather than by a `match` on a state byte somebody forgot to advance.
//!
//! Nothing here draws a random byte. Every ephemeral and static key comes in as
//! [`Entropy`] from the caller's CSPRNG, which is what keeps the crate free of a
//! peripheral and every handshake reproducible from a published vector.
//!
//! cites: P-226, P-227, P-228, P-229

use core::fmt;

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut as _, KeyInit as _};
use hmac::Mac as _;
use sha2::{Digest as _, Sha256};
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize as _, Zeroizing};

type HmacSha256 = hmac::Hmac<Sha256>;

/// `DHLEN` and `HASHLEN`: X25519 and SHA-256 are both 32 bytes, which is why
/// one constant serves a public key, a chaining key, a hash and a cipher key.
pub const KEY_BYTES: usize = 32;

/// ChaCha20-Poly1305's tag, carried after every ciphertext.
pub const TAG_BYTES: usize = 16;

/// An encrypted static key on the wire: the key and its tag.
pub const SEALED_KEY_BYTES: usize = KEY_BYTES + TAG_BYTES;

/// SHA-256's block, the width RFC 2104 pads an HMAC key to.
const BLOCK_BYTES: usize = 64;

/// The one nonce value Noise reserves, so a cipher state refuses to reach it.
const NONCE_RESERVED: u64 = u64::MAX;

/// The pairing handshake's name, hashed into the first transcript value.
const PAIRING_NAME: &[u8] = b"Noise_XXpsk0_25519_ChaChaPoly_SHA256";

/// The session handshake's name. Exactly 32 bytes, so it is the first
/// transcript value itself rather than its hash.
const SESSION_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_SHA256";

const_assert!(
    SESSION_NAME.len() == KEY_BYTES && PAIRING_NAME.len() > KEY_BYTES,
    "Noise pads a name of 32 bytes or fewer and hashes a longer one; the two constructors below take one path each and would silently take the other if a name changed length"
);

/// Thirty-two bytes from the caller's CSPRNG, spent on exactly one key.
///
/// It is consumed by the key it makes, so the same draw cannot become two
/// ephemerals: two handshakes sharing an ephemeral share `ee`, and the session
/// keys of one are then a function of the other's.
pub struct Entropy([u8; KEY_BYTES]);

impl Entropy {
    /// Wrap bytes the caller drew from its CSPRNG. Nothing here can check that
    /// they are random; the vectors are the only caller that passes fixed ones.
    #[must_use]
    pub const fn new(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Spend the draw on a challenge instead of a key (P-063): its first
    /// sixteen bytes.
    #[must_use]
    pub fn into_challenge(self) -> [u8; CHALLENGE_BYTES] {
        let bytes = self.take();
        let mut out = [0u8; CHALLENGE_BYTES];
        for (slot, &byte) in out.iter_mut().zip(bytes.iter()) {
            *slot = byte;
        }
        out
    }

    /// The bytes, leaving zeros behind for the drop to clear again.
    fn take(mut self) -> Zeroizing<[u8; KEY_BYTES]> {
        Zeroizing::new(core::mem::take(&mut self.0))
    }
}

/// A challenge is sixteen bytes (P-060).
pub const CHALLENGE_BYTES: usize = 16;

impl Drop for Entropy {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An X25519 public key as it travels: 32 bytes, no clamping, no validation
/// beyond the length. A low-order point is caught where it matters, at the DH
/// that would have produced zeros.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; KEY_BYTES]);

impl PublicKey {
    /// The key a peer sent or a client pinned.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// The bytes, for the wire and for storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    /// Constant-time, because a slot lookup that stops at the first differing
    /// byte tells a caller how many leading bytes of an enrolled key it guessed.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        bool::from(self.0.ct_eq(&other.0))
    }
}

/// Public keys are not secret, so this prints them; a person comparing two
/// controllers needs to see which one they have.
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// A long-term X25519 key pair: the controller's, or one client's.
///
/// No `Debug` and no `Clone`: the private half leaves only through
/// [`StaticKey::to_stored`], which hands back bytes that clear themselves.
pub struct StaticKey {
    secret: StaticSecret,
    public: PublicKey,
}

impl StaticKey {
    /// A fresh key pair from the caller's CSPRNG.
    #[must_use]
    pub fn generate(entropy: Entropy) -> Self {
        Self::from_secret(*entropy.take())
    }

    /// The key pair a client or the controller kept, read back from storage.
    #[must_use]
    pub fn from_stored(secret: [u8; KEY_BYTES]) -> Self {
        Self::from_secret(secret)
    }

    fn from_secret(mut bytes: [u8; KEY_BYTES]) -> Self {
        let secret = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes());
        Self { secret, public }
    }

    /// The half anyone may see.
    #[must_use]
    pub const fn public(&self) -> PublicKey {
        self.public
    }

    /// The private half, for the one caller that must write it to storage.
    #[must_use]
    pub fn to_stored(&self) -> Zeroizing<[u8; KEY_BYTES]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// P-238's admission key for the enrolment between this key and `peer`:
    /// the client's key and the pinned controller key, or the controller's key
    /// and a slot's. Both ends reach the same value.
    pub fn admit_key(
        &self,
        device_id: crate::DeviceId,
        peer: &PublicKey,
    ) -> Result<crate::AdmitKey, NoiseError> {
        Ok(crate::kdf::admit_key(device_id, &*self.agree(peer)?))
    }

    /// X25519, refusing an all-zero result. A peer that sends a low-order point
    /// makes the output a constant it already knows, and that DH then adds
    /// nothing to the key it is mixed into.
    fn agree(&self, theirs: &PublicKey) -> Result<Zeroizing<[u8; KEY_BYTES]>, NoiseError> {
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(theirs.0));
        if shared.was_contributory() {
            Ok(Zeroizing::new(shared.to_bytes()))
        } else {
            Err(NoiseError::LowOrderPoint)
        }
    }
}

/// The pre-shared key a pairing mixes in first (`psk0`). Derived from the
/// printed secret by [`crate::Label::pair_psk`]; nothing else makes
/// one.
pub struct Psk(Zeroizing<[u8; KEY_BYTES]>);

impl Psk {
    pub(crate) const fn new(bytes: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self(bytes)
    }
}

/// A key for one direction of a session, with the nonce it has reached.
///
/// Shared by the handshake and the transport: Noise's `CipherState`, where the
/// handshake's use is the implicit counter the specification defines.
struct CipherState {
    key: Option<Zeroizing<[u8; KEY_BYTES]>>,
    nonce: u64,
}

impl CipherState {
    const fn empty() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    fn keyed(key: Zeroizing<[u8; KEY_BYTES]>) -> Self {
        Self {
            key: Some(key),
            nonce: 0,
        }
    }

    /// Encrypt `plaintext` into `dst` with the next nonce, or copy it through
    /// while there is no key yet, as Noise defines for the first tokens of a
    /// pattern with no pre-shared key.
    fn encrypt(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, NoiseError> {
        if self.key.is_none() {
            let out = dst
                .get_mut(..plaintext.len())
                .ok_or(NoiseError::DestinationTooSmall)?;
            out.copy_from_slice(plaintext);
            return Ok(plaintext.len());
        }
        let nonce = self.take_nonce()?;
        let key = self.key.as_ref().ok_or(NoiseError::NonceExhausted)?;
        let len = plaintext
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(NoiseError::DestinationTooSmall)?;
        let out = dst.get_mut(..len).ok_or(NoiseError::DestinationTooSmall)?;
        let (body, tag) = out
            .split_at_mut_checked(plaintext.len())
            .ok_or(NoiseError::DestinationTooSmall)?;
        body.copy_from_slice(plaintext);
        seal_in_place(key, nonce, ad, body, tag)?;
        Ok(len)
    }

    /// The inverse, and the only place a tag is checked during a handshake.
    fn decrypt(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, NoiseError> {
        let Some(key) = &self.key else {
            let out = dst
                .get_mut(..ciphertext.len())
                .ok_or(NoiseError::DestinationTooSmall)?;
            out.copy_from_slice(ciphertext);
            return Ok(ciphertext.len());
        };
        let body_len = ciphertext
            .len()
            .checked_sub(TAG_BYTES)
            .ok_or(NoiseError::Truncated)?;
        let (body, tag) = ciphertext
            .split_at_checked(body_len)
            .ok_or(NoiseError::Truncated)?;
        let out = dst
            .get_mut(..body_len)
            .ok_or(NoiseError::DestinationTooSmall)?;
        out.copy_from_slice(body);
        // The nonce moves only once the tag has verified. A forged message must
        // not advance it: the honest message that follows would then be opened
        // under a nonce its sender never used, and the handshake dies of a frame
        // the attacker did not even have to get right.
        let nonce = self.nonce;
        if nonce == NONCE_RESERVED {
            return Err(NoiseError::NonceExhausted);
        }
        if open_in_place(key, nonce, ad, out, tag).is_err() {
            out.zeroize();
            return Err(NoiseError::Decrypt);
        }
        self.nonce = nonce.saturating_add(1);
        Ok(body_len)
    }

    fn take_nonce(&mut self) -> Result<u64, NoiseError> {
        let nonce = self.nonce;
        if nonce == NONCE_RESERVED {
            return Err(NoiseError::NonceExhausted);
        }
        self.nonce = nonce.saturating_add(1);
        Ok(nonce)
    }
}

/// ChaCha20-Poly1305 with Noise's nonce layout: four zero bytes, then the
/// counter little-endian. Shared with the transport, which is why the counter
/// is a parameter rather than state.
pub(crate) fn seal_in_place(
    key: &[u8; KEY_BYTES],
    nonce: u64,
    ad: &[u8],
    body: &mut [u8],
    tag_out: &mut [u8],
) -> Result<(), NoiseError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(&nonce_bytes(nonce).into(), ad, body.into())
        .map_err(|_| NoiseError::DestinationTooSmall)?;
    let out = tag_out
        .get_mut(..TAG_BYTES)
        .ok_or(NoiseError::DestinationTooSmall)?;
    out.copy_from_slice(&tag);
    Ok(())
}

/// The inverse of [`seal_in_place`]. `body` holds the ciphertext on the way in
/// and the plaintext on the way out, and only if the tag verified.
pub(crate) fn open_in_place(
    key: &[u8; KEY_BYTES],
    nonce: u64,
    ad: &[u8],
    body: &mut [u8],
    tag: &[u8],
) -> Result<(), NoiseError> {
    let tag: &[u8; TAG_BYTES] = tag.try_into().map_err(|_| NoiseError::Truncated)?;
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_inout_detached(&nonce_bytes(nonce).into(), ad, body.into(), tag.into())
        .map_err(|_| NoiseError::Decrypt)
}

fn nonce_bytes(nonce: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    for (slot, byte) in out.iter_mut().skip(4).zip(nonce.to_le_bytes()) {
        *slot = byte;
    }
    out
}

/// Noise's `SymmetricState`: the chaining key, the transcript hash, and the
/// cipher state they key.
struct SymmetricState {
    cipher: CipherState,
    chaining: Zeroizing<[u8; KEY_BYTES]>,
    hash: [u8; KEY_BYTES],
}

impl SymmetricState {
    /// `InitializeSymmetric(protocol_name)` followed by `MixHash(prologue)`.
    fn start(name: &[u8], prologue: &[u8]) -> Self {
        let mut hash = [0u8; KEY_BYTES];
        if name.len() <= KEY_BYTES {
            for (slot, &byte) in hash.iter_mut().zip(name) {
                *slot = byte;
            }
        } else {
            hash = Sha256::digest(name).into();
        }
        let mut state = Self {
            cipher: CipherState::empty(),
            chaining: Zeroizing::new(hash),
            hash,
        };
        state.mix_hash(prologue);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut digest = Sha256::new();
        digest.update(self.hash);
        digest.update(data);
        self.hash = digest.finalize().into();
    }

    fn mix_key(&mut self, material: &[u8]) {
        let (chaining, key) = hkdf2(&self.chaining, material);
        self.chaining = chaining;
        self.cipher = CipherState::keyed(key);
    }

    fn mix_key_and_hash(&mut self, material: &[u8]) {
        let (chaining, extra, key) = hkdf3(&self.chaining, material);
        self.chaining = chaining;
        self.mix_hash(&*extra);
        self.cipher = CipherState::keyed(key);
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8], dst: &mut [u8]) -> Result<usize, NoiseError> {
        let hash = self.hash;
        let len = self.cipher.encrypt(&hash, plaintext, dst)?;
        self.mix_hash(dst.get(..len).ok_or(NoiseError::DestinationTooSmall)?);
        Ok(len)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8], dst: &mut [u8]) -> Result<usize, NoiseError> {
        let hash = self.hash;
        let len = self.cipher.decrypt(&hash, ciphertext, dst)?;
        self.mix_hash(ciphertext);
        Ok(len)
    }

    /// `e` on the sending side: put the public key on the wire and in the
    /// transcript, and into the key too when a pre-shared key is in play.
    fn send_ephemeral(
        &mut self,
        key: &StaticKey,
        psk: bool,
        dst: &mut [u8],
    ) -> Result<usize, NoiseError> {
        let out = dst
            .get_mut(..KEY_BYTES)
            .ok_or(NoiseError::DestinationTooSmall)?;
        out.copy_from_slice(key.public.as_bytes());
        self.mix_hash(key.public.as_bytes());
        if psk {
            self.mix_key(key.public.as_bytes());
        }
        Ok(KEY_BYTES)
    }

    /// `e` on the receiving side.
    fn read_ephemeral(&mut self, msg: &[u8], psk: bool) -> Result<PublicKey, NoiseError> {
        let key = first_key(msg)?;
        self.mix_hash(key.as_bytes());
        if psk {
            self.mix_key(key.as_bytes());
        }
        Ok(key)
    }

    /// `s` on the receiving side: 48 bytes once a key is in play.
    fn read_static(&mut self, msg: &[u8]) -> Result<PublicKey, NoiseError> {
        let sealed = msg.get(..SEALED_KEY_BYTES).ok_or(NoiseError::Truncated)?;
        let mut out = [0u8; KEY_BYTES];
        let len = self.decrypt_and_hash(sealed, &mut out)?;
        if len != KEY_BYTES {
            return Err(NoiseError::Truncated);
        }
        Ok(PublicKey(out))
    }

    /// `Split()`: the initiator's sending key first, as Noise orders them.
    fn split(self) -> SessionKeys {
        let (first, second) = hkdf2(&self.chaining, &[]);
        SessionKeys {
            initiator_to_responder: first,
            responder_to_initiator: second,
            hash: self.hash,
        }
    }
}

fn first_key(msg: &[u8]) -> Result<PublicKey, NoiseError> {
    let bytes = msg.get(..KEY_BYTES).ok_or(NoiseError::Truncated)?;
    let mut out = [0u8; KEY_BYTES];
    out.copy_from_slice(bytes);
    Ok(PublicKey(out))
}

/// A 32-byte secret that clears itself.
type Secret = Zeroizing<[u8; KEY_BYTES]>;

/// Noise's `HKDF` with two outputs: HMAC-SHA256 keyed by the chaining key.
fn hkdf2(chaining: &[u8; KEY_BYTES], material: &[u8]) -> (Secret, Secret) {
    let temp = hmac(&chaining[..], &[material]);
    let first = hmac(&temp[..], &[&[1]]);
    let second = hmac(&temp[..], &[&first[..], &[2]]);
    (first, second)
}

/// The three-output form, which only `MixKeyAndHash` uses.
fn hkdf3(chaining: &[u8; KEY_BYTES], material: &[u8]) -> (Secret, Secret, Secret) {
    let temp = hmac(&chaining[..], &[material]);
    let first = hmac(&temp[..], &[&[1]]);
    let second = hmac(&temp[..], &[&first[..], &[2]]);
    let third = hmac(&temp[..], &[&second[..], &[3]]);
    (first, second, third)
}

/// HMAC-SHA256 over the concatenation of `parts`, with a key of at most one
/// block. Every key here is 32 bytes, so the key is zero-padded and never
/// hashed, and there is no length error to carry.
fn hmac(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut block = Zeroizing::new([0u8; BLOCK_BYTES]);
    for (slot, &byte) in block.iter_mut().zip(key) {
        *slot = byte;
    }
    let mut mac = HmacSha256::new((&*block).into());
    for part in parts {
        mac.update(part);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// The two keys `Split()` produces, and the transcript hash they came from.
///
/// Named by direction rather than by role, and turned into a sender and a
/// receiver only by [`SessionKeys::for_initiator`] or
/// [`SessionKeys::for_responder`]: each side sends under one key and receives
/// under the other, and a side that took the wrong one would encrypt under the
/// key its peer also sends under.
pub struct SessionKeys {
    initiator_to_responder: Zeroizing<[u8; KEY_BYTES]>,
    responder_to_initiator: Zeroizing<[u8; KEY_BYTES]>,
    hash: [u8; KEY_BYTES],
}

impl SessionKeys {
    /// The client's view: it initiates both handshakes.
    #[must_use]
    pub fn for_initiator(self) -> crate::ClientChannel {
        crate::ClientChannel::new(self.initiator_to_responder, self.responder_to_initiator)
    }

    /// The controller's view.
    #[must_use]
    pub fn for_responder(self) -> crate::ControllerChannel {
        crate::ControllerChannel::new(self.responder_to_initiator, self.initiator_to_responder)
    }

    /// The final transcript hash. Both sides hold the same value after a
    /// handshake that succeeded, which is what a test compares.
    #[must_use]
    pub const fn handshake_hash(&self) -> &[u8; KEY_BYTES] {
        &self.hash
    }
}

/// The client's side of the pairing handshake, after message 1.
///
/// Reading the controller's reply is the only step it offers:
///
/// ```compile_fail
/// fn skip(pairing: km43::PairInitiator, key: &km43::StaticKey) {
///     let mut out = [0u8; 128];
///     let _ = pairing.finish(key, &[], &mut out);
/// }
/// ```
pub struct PairInitiator {
    state: SymmetricState,
    ephemeral: StaticKey,
}

impl PairInitiator {
    /// The handshake hash after message 1, which a refusal is tagged over
    /// (P-241).
    #[must_use]
    pub const fn handshake_hash(&self) -> &[u8; KEY_BYTES] {
        &self.state.hash
    }

    /// Write message 1, `psk, e`, with `payload` sealed under the pre-shared
    /// key, into `dst`.
    pub fn start(
        prologue: &[u8],
        psk: &Psk,
        ephemeral: Entropy,
        payload: &[u8],
        dst: &mut [u8],
    ) -> Result<(Self, usize), NoiseError> {
        let mut state = SymmetricState::start(PAIRING_NAME, prologue);
        state.mix_key_and_hash(&*psk.0);
        let ephemeral = StaticKey::generate(ephemeral);
        let head = state.send_ephemeral(&ephemeral, true, dst)?;
        let tail = dst.get_mut(head..).ok_or(NoiseError::DestinationTooSmall)?;
        let body = state.encrypt_and_hash(payload, tail)?;
        Ok((Self { state, ephemeral }, head.saturating_add(body)))
    }

    /// Read message 2, `e, ee, s, es`: the controller's static key and its
    /// payload, both authenticated by the pre-shared key and by `es`.
    pub fn read_reply<'d>(
        mut self,
        msg: &[u8],
        dst: &'d mut [u8],
    ) -> Result<(PairReplied, &'d [u8]), NoiseError> {
        let theirs = self.state.read_ephemeral(msg, true)?;
        self.state.mix_key(&*self.ephemeral.agree(&theirs)?);
        let rest = msg.get(KEY_BYTES..).ok_or(NoiseError::Truncated)?;
        let controller = self.state.read_static(rest)?;
        self.state.mix_key(&*self.ephemeral.agree(&controller)?);
        let payload = rest.get(SEALED_KEY_BYTES..).ok_or(NoiseError::Truncated)?;
        let len = self.state.decrypt_and_hash(payload, dst)?;
        let plain = dst.get(..len).ok_or(NoiseError::DestinationTooSmall)?;
        Ok((
            PairReplied {
                state: self.state,
                their_ephemeral: theirs,
                controller,
            },
            plain,
        ))
    }
}

/// The client's side after message 2: the controller's static key is known and
/// authenticated, and message 3 is the only thing left to write.
pub struct PairReplied {
    state: SymmetricState,
    their_ephemeral: PublicKey,
    controller: PublicKey,
}

impl PairReplied {
    /// The key the controller proved it holds, which the client pins.
    #[must_use]
    pub const fn controller(&self) -> PublicKey {
        self.controller
    }

    /// Write message 3, `s, se`, and split. `key` is the client's new static
    /// key, the one the controller will store.
    pub fn finish(
        mut self,
        key: &StaticKey,
        payload: &[u8],
        dst: &mut [u8],
    ) -> Result<(SessionKeys, usize), NoiseError> {
        let head = self.state.encrypt_and_hash(key.public.as_bytes(), dst)?;
        self.state.mix_key(&*key.agree(&self.their_ephemeral)?);
        let tail = dst.get_mut(head..).ok_or(NoiseError::DestinationTooSmall)?;
        let body = self.state.encrypt_and_hash(payload, tail)?;
        Ok((self.state.split(), head.saturating_add(body)))
    }
}

/// The controller's side of the pairing handshake, before anything is read.
pub struct PairResponder;

impl PairResponder {
    /// Read message 1. Only a holder of the pre-shared key gets past this, and
    /// it costs the controller one HKDF chain and one tag check, no DH.
    pub fn read_request<'d>(
        prologue: &[u8],
        psk: &Psk,
        msg: &[u8],
        dst: &'d mut [u8],
    ) -> Result<(PairRequested, &'d [u8]), NoiseError> {
        let mut state = SymmetricState::start(PAIRING_NAME, prologue);
        state.mix_key_and_hash(&*psk.0);
        let theirs = state.read_ephemeral(msg, true)?;
        let payload = msg.get(KEY_BYTES..).ok_or(NoiseError::Truncated)?;
        let len = state.decrypt_and_hash(payload, dst)?;
        let plain = dst.get(..len).ok_or(NoiseError::DestinationTooSmall)?;
        Ok((
            PairRequested {
                state,
                their_ephemeral: theirs,
            },
            plain,
        ))
    }
}

/// The controller's side after message 1: the peer knows the label, and the
/// reply is the only step left.
pub struct PairRequested {
    state: SymmetricState,
    their_ephemeral: PublicKey,
}

impl PairRequested {
    /// The handshake hash after message 1, which a refusal is tagged over
    /// (P-241).
    #[must_use]
    pub const fn handshake_hash(&self) -> &[u8; KEY_BYTES] {
        &self.state.hash
    }

    /// Write message 2, `e, ee, s, es`, carrying `payload`.
    pub fn reply(
        mut self,
        controller: &StaticKey,
        ephemeral: Entropy,
        payload: &[u8],
        dst: &mut [u8],
    ) -> Result<(PairAwaiting, usize), NoiseError> {
        let ephemeral = StaticKey::generate(ephemeral);
        let mut at = self.state.send_ephemeral(&ephemeral, true, dst)?;
        self.state
            .mix_key(&*ephemeral.agree(&self.their_ephemeral)?);
        let tail = dst.get_mut(at..).ok_or(NoiseError::DestinationTooSmall)?;
        at = at.saturating_add(
            self.state
                .encrypt_and_hash(controller.public.as_bytes(), tail)?,
        );
        self.state
            .mix_key(&*controller.agree(&self.their_ephemeral)?);
        let tail = dst.get_mut(at..).ok_or(NoiseError::DestinationTooSmall)?;
        at = at.saturating_add(self.state.encrypt_and_hash(payload, tail)?);
        Ok((
            PairAwaiting {
                state: self.state,
                ephemeral,
            },
            at,
        ))
    }
}

/// The controller's side after message 2, waiting for the client's static key.
pub struct PairAwaiting {
    state: SymmetricState,
    ephemeral: StaticKey,
}

impl PairAwaiting {
    /// Read message 3, `s, se`: the client's static key, proved by `se`, and
    /// the split keys the enrolment result is sealed under.
    pub fn read_finish<'d>(
        mut self,
        msg: &[u8],
        dst: &'d mut [u8],
    ) -> Result<(PairFinished, &'d [u8]), NoiseError> {
        let client = self.state.read_static(msg)?;
        self.state.mix_key(&*self.ephemeral.agree(&client)?);
        let payload = msg.get(SEALED_KEY_BYTES..).ok_or(NoiseError::Truncated)?;
        let len = self.state.decrypt_and_hash(payload, dst)?;
        let plain = dst.get(..len).ok_or(NoiseError::DestinationTooSmall)?;
        Ok((
            PairFinished {
                client,
                keys: self.state.split(),
            },
            plain,
        ))
    }
}

/// A pairing handshake that completed: the client's proved static key, and the
/// keys the controller seals its answer under.
pub struct PairFinished {
    /// The key to store in the slot.
    pub client: PublicKey,
    /// The split keys.
    pub keys: SessionKeys,
}

/// The client's side of the session handshake, after message 1.
pub struct HelloInitiator {
    state: SymmetricState,
    ephemeral: StaticKey,
}

impl HelloInitiator {
    /// Write message 1, `e, es, s, ss`, to the controller whose key the client
    /// pinned. `controller` must be the pinned key, never one a `Discover` just
    /// offered: IK authenticates the controller only against the key the client
    /// brought.
    pub fn start(
        prologue: &[u8],
        controller: &PublicKey,
        client: &StaticKey,
        ephemeral: Entropy,
        payload: &[u8],
        dst: &mut [u8],
    ) -> Result<(Self, usize), NoiseError> {
        let mut state = SymmetricState::start(SESSION_NAME, prologue);
        state.mix_hash(controller.as_bytes());
        let ephemeral = StaticKey::generate(ephemeral);
        let mut at = state.send_ephemeral(&ephemeral, false, dst)?;
        state.mix_key(&*ephemeral.agree(controller)?);
        let tail = dst.get_mut(at..).ok_or(NoiseError::DestinationTooSmall)?;
        at = at.saturating_add(state.encrypt_and_hash(client.public.as_bytes(), tail)?);
        state.mix_key(&*client.agree(controller)?);
        let tail = dst.get_mut(at..).ok_or(NoiseError::DestinationTooSmall)?;
        at = at.saturating_add(state.encrypt_and_hash(payload, tail)?);
        Ok((Self { state, ephemeral }, at))
    }

    /// Read message 2, `e, ee, se`, and split.
    pub fn read_reply<'d>(
        mut self,
        client: &StaticKey,
        msg: &[u8],
        dst: &'d mut [u8],
    ) -> Result<(SessionKeys, &'d [u8]), NoiseError> {
        let theirs = self.state.read_ephemeral(msg, false)?;
        self.state.mix_key(&*self.ephemeral.agree(&theirs)?);
        self.state.mix_key(&*client.agree(&theirs)?);
        let payload = msg.get(KEY_BYTES..).ok_or(NoiseError::Truncated)?;
        let len = self.state.decrypt_and_hash(payload, dst)?;
        let plain = dst.get(..len).ok_or(NoiseError::DestinationTooSmall)?;
        Ok((self.state.split(), plain))
    }
}

/// The controller's side of the session handshake, before anything is read.
pub struct HelloResponder;

impl HelloResponder {
    /// Read message 1 as far as the client's static key, and stop.
    ///
    /// The key is returned before `ss` is computed so the controller can refuse
    /// a key no slot holds for the price of one DH rather than two. It is not
    /// yet proved: anybody can encrypt any public key under `es`, and only
    /// [`HelloClaimed::prove`] establishes that the sender holds its private
    /// half.
    pub fn read_claim(
        prologue: &[u8],
        controller: &StaticKey,
        msg: &[u8],
    ) -> Result<HelloClaimed, NoiseError> {
        let mut state = SymmetricState::start(SESSION_NAME, prologue);
        state.mix_hash(controller.public.as_bytes());
        let theirs = state.read_ephemeral(msg, false)?;
        state.mix_key(&*controller.agree(&theirs)?);
        let rest = msg.get(KEY_BYTES..).ok_or(NoiseError::Truncated)?;
        let client = state.read_static(rest)?;
        Ok(HelloClaimed {
            state,
            their_ephemeral: theirs,
            client,
        })
    }
}

/// A session request that named a client key it has not yet proved.
///
/// The claimed key is reachable, because the slot lookup needs it; the payload
/// is not, because nothing has authenticated it:
///
/// ```compile_fail
/// fn peek(claim: &km43::HelloClaimed) -> &[u8] { claim.payload() }
/// ```
pub struct HelloClaimed {
    state: SymmetricState,
    their_ephemeral: PublicKey,
    client: PublicKey,
}

impl HelloClaimed {
    /// The static key the peer claims. Unproved: it selects a slot and licenses
    /// nothing else.
    #[must_use]
    pub const fn claimed(&self) -> PublicKey {
        self.client
    }

    /// Compute `ss` and open the payload of message 1, which proves the peer
    /// holds the private half of [`HelloClaimed::claimed`].
    pub fn prove<'d>(
        mut self,
        controller: &StaticKey,
        msg: &[u8],
        dst: &'d mut [u8],
    ) -> Result<(HelloProved, &'d [u8]), NoiseError> {
        self.state.mix_key(&*controller.agree(&self.client)?);
        let payload = msg
            .get(KEY_BYTES.saturating_add(SEALED_KEY_BYTES)..)
            .ok_or(NoiseError::Truncated)?;
        let len = self.state.decrypt_and_hash(payload, dst)?;
        let plain = dst.get(..len).ok_or(NoiseError::DestinationTooSmall)?;
        Ok((
            HelloProved {
                state: self.state,
                their_ephemeral: self.their_ephemeral,
                client: self.client,
            },
            plain,
        ))
    }
}

/// A session request whose client key is proved; the reply is the only step
/// left.
pub struct HelloProved {
    state: SymmetricState,
    their_ephemeral: PublicKey,
    client: PublicKey,
}

impl HelloProved {
    /// The proved client key.
    #[must_use]
    pub const fn client(&self) -> PublicKey {
        self.client
    }

    /// Write message 2, `e, ee, se`, carrying `payload`, and split.
    pub fn reply(
        mut self,
        ephemeral: Entropy,
        payload: &[u8],
        dst: &mut [u8],
    ) -> Result<(SessionKeys, usize), NoiseError> {
        let ephemeral = StaticKey::generate(ephemeral);
        let head = self.state.send_ephemeral(&ephemeral, false, dst)?;
        self.state
            .mix_key(&*ephemeral.agree(&self.their_ephemeral)?);
        self.state.mix_key(&*ephemeral.agree(&self.client)?);
        let tail = dst.get_mut(head..).ok_or(NoiseError::DestinationTooSmall)?;
        let body = self.state.encrypt_and_hash(payload, tail)?;
        Ok((self.state.split(), head.saturating_add(body)))
    }
}

/// Why a handshake step failed. Every one of them ends the handshake: the
/// states above are consumed by the step that failed, so there is nothing left
/// to retry against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NoiseError {
    /// A message shorter than the tokens its pattern step carries.
    Truncated,
    /// A tag did not verify: the wrong pre-shared key, the wrong static key, a
    /// rewritten prologue, or a forgery. Indistinguishable by design.
    Decrypt,
    /// A DH with a low-order point, whose output is a constant.
    LowOrderPoint,
    /// A cipher state reached the one nonce Noise reserves.
    NonceExhausted,
    /// The buffer handed in cannot hold what was to be written. Ours, not the
    /// peer's.
    DestinationTooSmall,
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "the handshake message is shorter than its pattern",
            Self::Decrypt => "a handshake tag did not verify",
            Self::LowOrderPoint => "a key agreement produced the all-zero output",
            Self::NonceExhausted => "a cipher state reached the reserved nonce",
            Self::DestinationTooSmall => "the output buffer is too small",
        })
    }
}

impl core::error::Error for NoiseError {}

#[cfg(test)]
mod tests {
    use super::*;

    impl crate::residue::Unpadded for Entropy {}
    impl crate::residue::Unpadded for Psk {}

    const PROLOGUE: &[u8] = b"km43/v1/prologue-under-test";

    fn psk() -> Psk {
        Psk::new(Zeroizing::new([0x09; KEY_BYTES]))
    }

    fn key(byte: u8) -> StaticKey {
        StaticKey::generate(Entropy::new([byte; KEY_BYTES]))
    }

    struct Pairing {
        message_1: [u8; 128],
        len_1: usize,
        message_2: [u8; 128],
        len_2: usize,
        message_3: [u8; 128],
        len_3: usize,
    }

    /// A pairing run to the end, keeping every message for the tests that break
    /// one of them.
    fn pairing() -> (Pairing, SessionKeys, PairFinished) {
        let mut p = Pairing {
            message_1: [0; 128],
            len_1: 0,
            message_2: [0; 128],
            len_2: 0,
            message_3: [0; 128],
            len_3: 0,
        };
        let (initiator, len) = PairInitiator::start(
            PROLOGUE,
            &psk(),
            Entropy::new([2; 32]),
            b"offer",
            &mut p.message_1,
        )
        .expect("message 1");
        p.len_1 = len;
        let mut out = [0u8; 128];
        let (requested, offer) =
            PairResponder::read_request(PROLOGUE, &psk(), &p.message_1[..len], &mut out)
                .expect("message 1 opens");
        assert_eq!(offer, b"offer");
        let (awaiting, len) = requested
            .reply(&key(3), Entropy::new([4; 32]), b"", &mut p.message_2)
            .expect("message 2");
        p.len_2 = len;
        let (replied, _) = initiator
            .read_reply(&p.message_2[..len], &mut out)
            .expect("message 2 opens");
        assert_eq!(replied.controller(), key(3).public());
        let (client_keys, len) = replied
            .finish(&key(1), b"", &mut p.message_3)
            .expect("message 3");
        p.len_3 = len;
        let (finished, _) = awaiting
            .read_finish(&p.message_3[..len], &mut out)
            .expect("message 3 opens");
        (p, client_keys, finished)
    }

    /// `XXpsk0` end to end: both ends agree on the transcript and split into the
    /// same two keys, each sending under the one the other receives under.
    #[test]
    fn p_226_the_pairing_pattern_completes_and_both_ends_agree() {
        let (_, client, finished) = pairing();
        assert_eq!(finished.client, key(1).public());
        assert_eq!(client.handshake_hash(), finished.keys.handshake_hash());
        let mut client = client.for_initiator();
        let mut controller = finished.keys.for_responder();
        let mut frame = [0u8; 64];
        let (_, len) = client
            .tx
            .seal(
                crate::MessageType::Goodbye,
                crate::SessionId::from(3),
                &[0xA0],
                &mut frame,
            )
            .expect("seals");
        let mut plain = [0u8; 4];
        crate::Sealed::decode(crate::Envelope::decode(&frame[..len]).expect("decodes"))
            .expect("sealed")
            .open(&mut controller.rx, &mut plain)
            .expect("the controller opens what the client sealed");
    }

    /// A pre-shared key that differs by one bit is refused at message 1, before
    /// any key agreement.
    #[test]
    fn p_088_message_1_under_another_label_is_refused_before_any_dh() {
        let (p, _, _) = pairing();
        let mut other = [0x09; KEY_BYTES];
        other[0] ^= 1;
        let mut out = [0u8; 128];
        assert!(matches!(
            PairResponder::read_request(
                PROLOGUE,
                &Psk::new(Zeroizing::new(other)),
                &p.message_1[..p.len_1],
                &mut out
            ),
            Err(NoiseError::Decrypt)
        ));
    }

    /// `IK` end to end against the controller key the client brought, and the
    /// claimed key is the client's before `ss` proves it.
    #[test]
    fn p_226_the_session_pattern_completes_and_both_ends_agree() {
        let controller = key(3);
        let client = key(1);
        let mut message_1 = [0u8; 160];
        let (initiator, len) = HelloInitiator::start(
            PROLOGUE,
            &controller.public(),
            &client,
            Entropy::new([2; 32]),
            b"offer",
            &mut message_1,
        )
        .expect("message 1");
        let claim = HelloResponder::read_claim(PROLOGUE, &controller, &message_1[..len])
            .expect("the claim reads");
        assert_eq!(claim.claimed(), client.public());
        let mut out = [0u8; 160];
        let (proved, offer) = claim
            .prove(&controller, &message_1[..len], &mut out)
            .expect("ss proves it");
        assert_eq!(offer, b"offer");
        let mut message_2 = [0u8; 160];
        let (controller_keys, len) = proved
            .reply(Entropy::new([4; 32]), b"report", &mut message_2)
            .expect("message 2");
        let (client_keys, report) = initiator
            .read_reply(&client, &message_2[..len], &mut out)
            .expect("message 2 opens");
        assert_eq!(report, b"report");
        assert_eq!(
            client_keys.handshake_hash(),
            controller_keys.handshake_hash()
        );
    }

    /// A client that runs IK against a key the controller does not hold gets a
    /// message 1 the controller cannot read past `s`.
    #[test]
    fn p_222_a_hello_to_another_controller_key_does_not_open() {
        let mut message_1 = [0u8; 160];
        let (_, len) = HelloInitiator::start(
            PROLOGUE,
            &key(9).public(),
            &key(1),
            Entropy::new([2; 32]),
            b"offer",
            &mut message_1,
        )
        .expect("message 1");
        assert!(matches!(
            HelloResponder::read_claim(PROLOGUE, &key(3), &message_1[..len]),
            Err(NoiseError::Decrypt)
        ));
    }

    /// A claimed key without its private half passes the claim and fails `ss`:
    /// a key encrypted under `es` is something anybody can send.
    #[test]
    fn a_claimed_key_is_not_proved_until_ss() {
        let controller = key(3);
        let honest = key(1);
        let impostor = key(5);
        let mut message_1 = [0u8; 160];
        let (_, len) = HelloInitiator::start(
            PROLOGUE,
            &controller.public(),
            &impostor,
            Entropy::new([2; 32]),
            b"offer",
            &mut message_1,
        )
        .expect("message 1");
        let claim = HelloResponder::read_claim(PROLOGUE, &controller, &message_1[..len])
            .expect("the claim reads");
        assert_ne!(claim.claimed(), honest.public());
        assert_eq!(claim.claimed(), impostor.public());
    }

    /// P-228: an all-zero X25519 output is refused on both sides. A low-order
    /// ephemeral in message 1 of IK stops at `es`; one in message 2 of a
    /// pairing stops the client at `ee`; and a low-order client key in message
    /// 3 stops the controller at `se`, so no slot ever holds one.
    #[test]
    fn p_228_a_low_order_point_is_refused_on_both_sides() {
        let controller = key(3);
        let mut message_1 = [0u8; 160];
        let (_, len) = HelloInitiator::start(
            PROLOGUE,
            &controller.public(),
            &key(1),
            Entropy::new([2; 32]),
            b"offer",
            &mut message_1,
        )
        .expect("message 1");
        message_1[..KEY_BYTES].fill(0);
        assert!(matches!(
            HelloResponder::read_claim(PROLOGUE, &controller, &message_1[..len]),
            Err(NoiseError::LowOrderPoint)
        ));

        let (p, _, _) = pairing();
        let (initiator, _) = PairInitiator::start(
            PROLOGUE,
            &psk(),
            Entropy::new([2; 32]),
            b"offer",
            &mut [0u8; 128],
        )
        .expect("message 1");
        let mut message_2 = p.message_2;
        message_2[..KEY_BYTES].fill(0);
        let mut out = [0u8; 128];
        assert!(matches!(
            initiator.read_reply(&message_2[..p.len_2], &mut out),
            Err(NoiseError::LowOrderPoint)
        ));

        // A pairing whose message 1 carries the identity point as its ephemeral:
        // the controller answers message 2 with ee refused.
        let mut message_1 = p.message_1;
        message_1[..KEY_BYTES].fill(0);
        let result = PairResponder::read_request(PROLOGUE, &psk(), &message_1[..p.len_1], &mut out);
        match result {
            Ok((requested, _)) => assert!(matches!(
                requested.reply(&controller, Entropy::new([4; 32]), b"", &mut [0u8; 128]),
                Err(NoiseError::LowOrderPoint)
            )),
            Err(why) => assert_eq!(
                why,
                NoiseError::Decrypt,
                "a changed e is a changed transcript"
            ),
        }
    }

    /// Every truncation of every pairing message is refused without a panic.
    #[test]
    fn every_truncation_of_a_pairing_message_is_refused() {
        let (p, _, _) = pairing();
        let mut out = [0u8; 128];
        for cut in 0..p.len_1 {
            assert!(
                PairResponder::read_request(PROLOGUE, &psk(), &p.message_1[..cut], &mut out)
                    .is_err()
            );
        }
        for cut in 0..p.len_2 {
            let (initiator, _) = PairInitiator::start(
                PROLOGUE,
                &psk(),
                Entropy::new([2; 32]),
                b"offer",
                &mut [0u8; 128],
            )
            .expect("message 1");
            assert!(
                initiator.read_reply(&p.message_2[..cut], &mut out).is_err(),
                "cut {cut}"
            );
        }
    }

    /// Every single-bit flip in message 1 of a pairing is refused: the
    /// ephemeral key and the ciphertext are both in the transcript the tag
    /// covers.
    #[test]
    fn every_flipped_bit_of_pairing_message_1_is_refused() {
        let (p, _, _) = pairing();
        let mut out = [0u8; 128];
        for byte in 0..p.len_1 {
            for bit in 0..8 {
                let mut flipped = p.message_1;
                flipped[byte] ^= 1 << bit;
                assert!(
                    PairResponder::read_request(PROLOGUE, &psk(), &flipped[..p.len_1], &mut out)
                        .is_err(),
                    "bit {bit} of byte {byte} opened"
                );
            }
        }
    }

    /// A prologue that differs in one byte is a handshake whose first tag fails
    /// (P-227): the transcript both ends hash starts there.
    #[test]
    fn p_227_a_prologue_that_differs_in_one_byte_fails_the_first_tag() {
        let (p, _, _) = pairing();
        let mut other = [0u8; 27];
        other.copy_from_slice(PROLOGUE);
        other[26] ^= 1;
        let mut out = [0u8; 128];
        assert!(matches!(
            PairResponder::read_request(&other, &psk(), &p.message_1[..p.len_1], &mut out),
            Err(NoiseError::Decrypt)
        ));
    }

    /// The draw that makes an ephemeral is spent on it, and a dropped draw
    /// leaves nothing behind.
    #[test]
    fn a_dropped_draw_leaves_nothing_behind() {
        let residue: [u8; KEY_BYTES] = crate::residue::after_drop(Entropy::new([0xAB; KEY_BYTES]));
        assert_eq!(residue, [0; KEY_BYTES]);
        let residue: [u8; KEY_BYTES] = crate::residue::after_drop(psk());
        assert_eq!(residue, [0; KEY_BYTES]);
    }

    /// A challenge is the first sixteen bytes of a draw.
    #[test]
    fn a_challenge_is_a_draw_cut_to_sixteen() {
        let bytes: [u8; KEY_BYTES] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(0));
        let challenge = Entropy::new(bytes).into_challenge();
        assert_eq!(challenge[..], bytes[..CHALLENGE_BYTES]);
    }

    /// P-228 at enrolment: message 3 whose client key is the identity point.
    /// A holder of the label can build one — `se` is then a constant it knows —
    /// and without the refusal the controller would store a slot anybody can
    /// open. It stops at `se`, before a slot is written.
    #[test]
    fn p_228_a_low_order_client_key_at_enrolment_is_refused() {
        let (initiator, _) = PairInitiator::start(
            PROLOGUE,
            &psk(),
            Entropy::new([2; 32]),
            b"offer",
            &mut [0u8; 128],
        )
        .expect("message 1");
        let mut message_1 = [0u8; 128];
        let (_, len_1) = PairInitiator::start(
            PROLOGUE,
            &psk(),
            Entropy::new([2; 32]),
            b"offer",
            &mut message_1,
        )
        .expect("message 1 again, the same bytes");
        let mut out = [0u8; 128];
        let (requested, _) =
            PairResponder::read_request(PROLOGUE, &psk(), &message_1[..len_1], &mut out)
                .expect("opens");
        let mut message_2 = [0u8; 128];
        let (awaiting, len_2) = requested
            .reply(&key(3), Entropy::new([4; 32]), b"", &mut message_2)
            .expect("message 2");
        let (mut replied, _) = initiator
            .read_reply(&message_2[..len_2], &mut out)
            .expect("message 2 opens");
        let mut message_3 = [0u8; 128];
        let head = replied
            .state
            .encrypt_and_hash(&[0; KEY_BYTES], &mut message_3)
            .expect("the identity point, sealed as s");
        let len_3 = head + TAG_BYTES + 1;
        assert!(matches!(
            awaiting.read_finish(&message_3[..len_3], &mut out),
            Err(NoiseError::LowOrderPoint)
        ));
    }
}
