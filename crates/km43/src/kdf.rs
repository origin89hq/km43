//! Where the three keys come from, so nothing above this file is trusted with
//! thirty-two bytes it made up.
//!
//! Every derivation here is HKDF-SHA256 with `salt`, `IKM` and `info` passed
//! **separately** (P-042). The draft this replaces wrote `HKDF(a | b | c)`,
//! which assigns none of the three and still produces a perfectly good key —
//! one no other implementation can reproduce. So the two extract arguments are
//! two newtypes rather than two `&[u8]` in a row, and the `info` is built by a
//! chain that cannot be started without a [`Derivation`].
//!
//! The ladder is the other half. A [`PrintedSecret`] is not a `ClientKey` and a
//! `ClientKey` is not a `SessionKey`: the only route to a session key runs
//! through an [`Enrolment`], and the only route to an enrolment runs through
//! the printed secret and P-085's `epoch`. P-088 is the same argument one step
//! further down — the printed secret is never itself an HMAC key, because the
//! comms processor watches every pairing exchange and a master secret that
//! cannot be rotated must not be handed to it as an oracle.
//!
//! cites: P-040, P-042, P-043, P-044, P-085, P-086, P-088

use core::fmt;
use core::num::NonZeroU32;

use hkdf::HkdfExtract;
use sha2::Sha256;

use crate::envelope::SessionId;
use crate::mac::{ClientKey, PairKey, SessionKey};

/// P-044's entropy, decoded from the QR code's 64 characters.
const PRINTED_SECRET_BYTES: usize = 32;

/// P-038's `device_id`, as the 16 bytes and never their hex rendering.
const DEVICE_ID_BYTES: usize = 16;

/// A `challenge` and a `client_nonce` are both `bstr16`.
const NONCE_BYTES: usize = 16;

/// The session salt: the challenge and the nonce, joined with no separator.
const SESSION_SALT_BYTES: usize = 32;

/// SHA-256's digest, which is HKDF's `HashLen`.
const DIGEST_BYTES: usize = 32;

/// RFC 5869's `L`, which every derivation in this protocol asks for.
const DERIVED_KEY_BYTES: usize = 32;

/// RFC 5869 §2.3's counter byte. `T(1)` is the only block [`Expand::key`]
/// computes, which is what the assertion below holds down.
const FIRST_BLOCK: u8 = 1;

const_assert!(
    DERIVED_KEY_BYTES == DIGEST_BYTES,
    "the expand here stops at T(1); asking for a wider key needs T(2), and the array conversion that would then fail to compile says nothing about which line to go and write"
);
const_assert!(
    SESSION_SALT_BYTES == NONCE_BYTES * 2,
    "the session salt is the two nonces joined with no separator (P-040) — one byte wider and its tail is a zero the peer never agreed to, on a key both ends have to reach independently"
);

/// The three HKDF `info` labels of P-043's table.
///
/// A sibling of `mac.rs`'s `Domain` rather than three more of its variants, and
/// deliberately: P-043 says an implementer who reads that table as nine MAC
/// preimages derives keys that are wrong on both sides and identical to nobody.
/// One enum spanning both kinds is that mistake made reachable —
/// `Preimage::under(key, Domain::PairKey)` would compile — and two enums are
/// what makes it a type error instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Derivation {
    /// The pairing key, derived from the printed secret (P-088).
    PairKey,
    /// A client's long-term key, per `epoch` and per `client_id`.
    ClientKey,
    /// The key one session's traffic is authenticated under.
    SessionKey,
    /// The seed a controller mints challenges from (P-063).
    ///
    /// **Controller-local: no client ever derives this one.** It is here anyway
    /// because it descends from the same device secret as the other three, and
    /// a label of its own is what stops a challenge and a key colliding — a
    /// challenge is published in every `Discover`, so a construction that let it
    /// share a derivation with `pair_key` would be handing that key out.
    Challenge,
}

impl Derivation {
    /// P-043's ASCII, with no trailing NUL. Private because the only thing
    /// entitled to put one at the head of an `info` is [`Prk::expand`].
    const fn as_str(self) -> &'static str {
        match self {
            Self::PairKey => "km43/v1/pair-key",
            Self::ClientKey => "km43/v1/client-key",
            Self::SessionKey => "km43/v1/session-key",
            Self::Challenge => "km43/v1/challenge",
        }
    }
}

impl fmt::Display for Derivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// P-044's 32 bytes of entropy — the decoded QR payload, never the printed
/// text, and never an HMAC key (P-088).
///
/// No `Debug`, for the reason the keys in `mac.rs` have none: the one secret on
/// this device that can never be rotated should not be one `?secret` away from
/// a bench log.
pub struct PrintedSecret([u8; PRINTED_SECRET_BYTES]);

impl PrintedSecret {
    /// The decoded 32 bytes of P-044, not the 64 characters they print as.
    #[must_use]
    pub const fn new(bytes: [u8; PRINTED_SECRET_BYTES]) -> Self {
        Self(bytes)
    }
}

/// P-038's sixteen bytes, as bytes and never their hex rendering.
///
/// A type rather than a `&[u8; 16]` because it is the `salt` of both
/// device-level derivations, and at that call site a bare array is one swap
/// away from being the IKM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceId([u8; DEVICE_ID_BYTES]);

impl DeviceId {
    /// The 16 bytes of P-038, not the 32 characters the QR code prints.
    #[must_use]
    pub const fn new(bytes: [u8; DEVICE_ID_BYTES]) -> Self {
        Self(bytes)
    }
}

/// P-085's factory-reset counter — the only thing on this device that can
/// invalidate key material.
///
/// Zero is not an epoch: it starts at 1 and only ever climbs, so a zero is FRAM
/// nobody wrote, and deriving under it mints keys the first successful write
/// invalidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Epoch(NonZeroU32);

impl Epoch {
    /// What a unit leaves the factory holding (P-085).
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// The counter as it was read back out of FRAM, or nothing if that read
    /// gave a zero.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(epoch) => Some(Self(epoch)),
            None => None,
        }
    }

    /// The counter as it goes into a `PairAck` or a `Discover` answer (P-087),
    /// so a client whose key no longer derives is told why.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// P-086's slot index in the client table, counting from 1.
///
/// Zero is what a `PairAck` carries when nobody was enrolled, so it names no
/// slot and there is no key at it. Refusing it here is what stops a refused
/// pairing from deriving anything at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientId(NonZeroU32);

impl ClientId {
    /// The slot P-086 allocated, or nothing if the caller passed the zero that
    /// means *no client*.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    /// The number as it goes into a `PairAck` or a `Hello` body.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Where this client's row sits in a table that holds one per slot.
    ///
    /// P-086 counts slots from one, so every such table subtracts one — and
    /// this is stated here, once, beside the `NonZeroU32` that makes it sound.
    /// Two tables doing the arithmetic separately are two tables that can
    /// address different rows for the same client, and the counter store and
    /// the capability mask are documented as sharing a FRAM row.
    ///
    /// The table it indexes is what bounds it: a slot past the end reads as
    /// `None` from the `get` that uses this, and that is the only bound there
    /// should be. `None` here is a `client_id` too large for this machine's
    /// `usize`, which is not a case any target of this firmware has.
    #[must_use]
    pub fn slot(self) -> Option<usize> {
        usize::try_from(self.0.get().saturating_sub(1)).ok()
    }
}

/// The two nonces a session key is salted with, in the order the salt joins
/// them.
///
/// Named fields rather than two arrays in a row: swapped, both ends still
/// derive a key, it is simply not the same key, and the symptom is every frame
/// failing its MAC with nothing pointing at this line.
#[derive(Debug, Clone, Copy)]
pub struct Handshake {
    /// The challenge the controller minted for this connection.
    pub challenge: [u8; NONCE_BYTES],
    /// Fresh per attempt, from the client's CSPRNG.
    pub client_nonce: [u8; NONCE_BYTES],
}

impl Handshake {
    /// `challenge | client_nonce`, with no separator (P-040).
    fn salt(&self) -> [u8; SESSION_SALT_BYTES] {
        let mut salt = [0u8; SESSION_SALT_BYTES];
        let joined = self.challenge.iter().chain(&self.client_nonce);
        for (slot, &byte) in salt.iter_mut().zip(joined) {
            *slot = byte;
        }
        salt
    }
}

/// The two things one unit is born with: the `device_id` etched into it and the
/// `printed_secret` on its label, which are exactly what P-049's QR code
/// carries.
///
/// They are held together because every key on the device descends from this
/// pair and from nothing else, and because they are the `salt` and the `IKM` of
/// both device-level derivations — one struct is one place for them to be the
/// right way round.
pub struct DeviceSecret {
    device_id: DeviceId,
    printed_secret: PrintedSecret,
}

impl DeviceSecret {
    /// The pair a controller reads out of its own store, or a client decodes
    /// from the QR code it has just scanned.
    #[must_use]
    pub const fn new(device_id: DeviceId, printed_secret: PrintedSecret) -> Self {
        Self {
            device_id,
            printed_secret,
        }
    }

    /// The key both pairing proofs are computed under (P-088).
    ///
    /// The comms processor observes every pairing exchange, so a proof MAC'd
    /// under `printed_secret` would hand the one component this protocol calls
    /// hostile an oracle under the secret the whole device rests on.
    #[must_use]
    pub fn pair_key(&self) -> PairKey {
        PairKey::new(self.prk().expand(Derivation::PairKey).key())
    }

    /// The challenge for `counter`, minted without any physical entropy.
    ///
    /// **This part has no RNG peripheral**, so P-063's CSPRNG has to be built.
    /// It is a PRF in counter mode: unpredictable to anybody who does not hold
    /// the printed secret, which is everybody the threat model cares about, and
    /// distinct for every `counter`.
    ///
    /// So the whole of its security rests on `counter` **never repeating for one
    /// device**. A repeat re-mints a challenge, and a challenge that comes round
    /// again is one a recorded `Hello` or `Pair` proof verifies against a second
    /// time. That is why the counter has to outlive a reset, and why this takes
    /// it as an argument rather than holding it: the thing that has to persist
    /// belongs to whoever owns the storage.
    #[must_use]
    pub fn challenge(&self, counter: u64) -> [u8; NONCE_BYTES] {
        let key = self.prk().expand(Derivation::Challenge).u64(counter).key();
        let mut out = [0u8; NONCE_BYTES];
        for (slot, byte) in out.iter_mut().zip(key.iter()) {
            *slot = *byte;
        }
        out
    }

    /// One client's long-term secret, at one slot and one epoch.
    ///
    /// Both coordinates go into the `info` because both have to (P-085, P-086).
    /// Drop `epoch` and a factory reset re-mints the key a stolen phone already
    /// holds; drop `client_id` and every client on the unit shares one key.
    #[must_use]
    pub fn enrolment(&self, epoch: Epoch, client_id: ClientId) -> Enrolment {
        Enrolment {
            client_id,
            key: self
                .prk()
                .expand(Derivation::ClientKey)
                .u32(epoch.get())
                .u32(client_id.get())
                .key(),
        }
    }

    /// Both device-level derivations extract under the same salt and IKM, which
    /// is what leaves P-043's label as the only thing separating them.
    fn prk(&self) -> Prk {
        Prk::of(Salt(&self.device_id.0), Ikm(&self.printed_secret.0))
    }
}

/// One enrolled client's long-term secret and the slot it was derived at.
///
/// The `client_id` rides along because the `Hello` proof names it inside the
/// body it authenticates (P-057): taken from the enrolment that holds the key,
/// the field and the key cannot end up naming two different clients.
pub struct Enrolment {
    client_id: ClientId,
    key: [u8; DERIVED_KEY_BYTES],
}

impl Enrolment {
    /// Which slot this is, for the `client_id` a `Hello` body carries.
    #[must_use]
    pub const fn client_id(&self) -> ClientId {
        self.client_id
    }

    /// The long-term key, handed to the MAC layer.
    #[must_use]
    pub const fn client_key(&self) -> ClientKey {
        ClientKey::new(self.key)
    }

    /// The key this session's traffic is authenticated under, in both
    /// directions.
    ///
    /// Salted with both nonces, so neither end fixes the key alone: a
    /// controller whose challenge repeats and a client that replays its nonce
    /// each still land on a fresh key unless the other end repeated too.
    #[must_use]
    pub fn session_key(&self, handshake: &Handshake, session: SessionId) -> SessionKey {
        let salt = handshake.salt();
        SessionKey::new(
            Prk::of(Salt(&salt), Ikm(&self.key))
                .expand(Derivation::SessionKey)
                .u16(u16::from(session))
                .key(),
        )
    }
}

/// RFC 5869's `salt`, named so it cannot be passed as the IKM.
#[derive(Clone, Copy)]
struct Salt<'a>(&'a [u8]);

/// RFC 5869's `IKM`, named for the same reason.
#[derive(Clone, Copy)]
struct Ikm<'a>(&'a [u8]);

/// The pseudorandom key of RFC 5869 §2.2 — `HMAC(salt, IKM)` — and the one
/// place the two arguments meet.
struct Prk([u8; DIGEST_BYTES]);

impl Prk {
    fn of(salt: Salt<'_>, ikm: Ikm<'_>) -> Self {
        let mut extract = HkdfExtract::<Sha256>::new(Some(salt.0));
        extract.input_ikm(ikm.0);
        Self(extract.finalize().0.into())
    }

    /// Opens an `info` with P-043's label, which is the only way a derivation
    /// here begins.
    fn expand(&self, derivation: Derivation) -> Expand {
        Expand::under(self, derivation.as_str().as_bytes())
    }
}

/// One `info` under construction, over a PRK that is already fixed.
///
/// `under` puts its first argument at the head of the `info` and [`Prk::expand`]
/// is its only caller outside the tests, so there is no reaching an integer
/// writer without a label having gone in ahead of it.
struct Expand(HkdfExtract<Sha256>);

impl Expand {
    fn under(prk: &Prk, label: &[u8]) -> Self {
        let mut extract = HkdfExtract::<Sha256>::new(Some(&prk.0));
        extract.input_ikm(label);
        Self(extract)
    }

    /// Big-endian and fixed width because P-040 says so, and because there is
    /// no other method here: two implementations that agree on the algorithm
    /// and not on the byte order derive keys neither of them can explain.
    fn u16(mut self, value: u16) -> Self {
        self.0.input_ikm(&value.to_be_bytes());
        self
    }

    fn u32(mut self, value: u32) -> Self {
        self.0.input_ikm(&value.to_be_bytes());
        self
    }

    fn u64(mut self, value: u64) -> Self {
        self.0.input_ikm(&value.to_be_bytes());
        self
    }

    /// RFC 5869 §2.3 at `L` = `HashLen`, which is `T(1) = HMAC(PRK, info |
    /// 0x01)` and nothing more.
    ///
    /// Going through extract rather than `Hkdf::expand` is what removes a
    /// `Result` whose only arm is `L > 255 × HashLen` — unreachable against a
    /// fixed 32-byte array, and an error nothing can produce would have to be
    /// carried by every caller of every derivation, which is the argument
    /// `mac.rs` makes about `Mac::new_from_slice`. Extract *is* that HMAC; its
    /// key is simply spelled `salt`.
    fn key(mut self) -> [u8; DERIVED_KEY_BYTES] {
        self.0.input_ikm(&[FIRST_BLOCK]);
        self.0.finalize().0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A repeated counter re-mints a challenge, and that is the whole risk.**
    ///
    /// A challenge that comes round again is one a recorded `Hello` or `Pair`
    /// proof verifies against a second time. Nothing in this function can stop
    /// that — only a counter that outlives a reset can — so the test that
    /// matters is that the counter is genuinely what separates them.
    #[test]
    fn a_challenge_is_a_function_of_the_counter_and_nothing_else() {
        let device = DeviceSecret::new(DeviceId::new([0xAB; 16]), PrintedSecret::new([0xCD; 32]));
        assert_eq!(
            device.challenge(7),
            device.challenge(7),
            "the same counter has to give the same challenge, or nothing can reason about repeats"
        );
        // No allocator here or on the target, so the fixture is a fixed array
        // for the same reason the firmware's buffers are.
        let mut seen = [[0u8; NONCE_BYTES]; 64];
        for counter in 0..64usize {
            let minted = device.challenge(counter as u64);
            let earlier = seen.get(..counter).expect("the filled prefix");
            assert!(
                !earlier.contains(&minted),
                "counter {counter} re-minted a challenge an earlier one had already produced"
            );
            if let Some(slot) = seen.get_mut(counter) {
                *slot = minted;
            }
        }
    }

    /// Two units do not share a challenge sequence. They would if the
    /// derivation forgot the device secret and leaned on the counter alone,
    /// which is exactly the shape a tick-based stand-in has.
    #[test]
    fn two_devices_do_not_mint_the_same_challenges() {
        let one = DeviceSecret::new(DeviceId::new([0x01; 16]), PrintedSecret::new([0xCD; 32]));
        let two = DeviceSecret::new(DeviceId::new([0x02; 16]), PrintedSecret::new([0xCD; 32]));
        let secret = DeviceSecret::new(DeviceId::new([0x01; 16]), PrintedSecret::new([0xEE; 32]));
        for counter in 0..8u64 {
            assert_ne!(one.challenge(counter), two.challenge(counter), "device_id");
            assert_ne!(one.challenge(counter), secret.challenge(counter), "secret");
        }
    }

    // **There is no test that a challenge differs from a key**, and the reason
    // is the better guarantee: `PairKey` and `ClientKey` do not surrender their
    // bytes, so the comparison cannot be written. What keeps them apart is
    // `Derivation::Challenge`'s own label — the same mechanism, checked by the
    // compiler enumerating the four rather than by a test comparing two.
    use core::fmt::Write as _;

    use crate::envelope::ReqId;
    use crate::generated::{ClientKind, MessageType};
    use crate::mac::{HelloProof, PairProof, Tag, Wrapped};

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

    const PRINTED_SECRET: [u8; PRINTED_SECRET_BYTES] =
        hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const DEVICE_ID: [u8; DEVICE_ID_BYTES] = hex("4f524947494e38392044454d4f203031");
    const CHALLENGE: [u8; NONCE_BYTES] = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    const CLIENT_NONCE: [u8; NONCE_BYTES] = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    const CLIENT_ID: u32 = 7;
    const SESSION: u16 = 3;
    const REQ_ID: u32 = 17;
    const LABEL: &str = "kitchen phone";

    const HELLO_BODY: [u8; 40] =
        hex("a5010102000307046d6f38392d636c6920302e312e300550b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    const COMMAND_ACK_BODY: [u8; 26] = hex("a301182a0201037267656e657261746f72207374617274696e67");

    /// The `inputs` block of `docs/protocol/vectors/v1.json`, as the pair every
    /// key on this unit descends from.
    fn device() -> DeviceSecret {
        DeviceSecret::new(DeviceId::new(DEVICE_ID), PrintedSecret::new(PRINTED_SECRET))
    }

    fn enrolment() -> Enrolment {
        device().enrolment(
            Epoch::new(1).expect("epoch 1 is what the vectors were derived at"),
            ClientId::new(CLIENT_ID).expect("client_id 7 is a slot"),
        )
    }

    fn handshake() -> Handshake {
        Handshake {
            challenge: CHALLENGE,
            client_nonce: CLIENT_NONCE,
        }
    }

    /// Every key type here seals its bytes on purpose — a key with an accessor
    /// is a key in a bench log — so the only way to ask whether two derivations
    /// agree is to have each sign one fixed body and compare the tags.
    fn pair_signs(key: &PairKey) -> [u8; Tag::LEN] {
        *key.proof(&PairProof {
            device_id: &DEVICE_ID,
            challenge: &CHALLENGE,
            client_nonce: &CLIENT_NONCE,
            client_kind: ClientKind::App,
            label: LABEL,
        })
        .as_bytes()
    }

    fn client_signs(enrolment: &Enrolment) -> [u8; Tag::LEN] {
        *enrolment
            .client_key()
            .hello_proof(&HelloProof {
                challenge: &CHALLENGE,
                client_nonce: &CLIENT_NONCE,
                client_id: enrolment.client_id().get(),
                payload: &HELLO_BODY,
            })
            .as_bytes()
    }

    fn session_signs(key: &SessionKey) -> [u8; Tag::LEN] {
        *key.response(&Wrapped {
            kind: MessageType::CommandResponse,
            session: SessionId::from(SESSION),
            req_id: ReqId(REQ_ID),
            payload: &COMMAND_ACK_BODY,
        })
        .as_bytes()
    }

    /// RFC 5869's Appendix A, which is the only thing in this file that is an
    /// opinion from outside this repository about extract and expand.
    ///
    /// The published `OKM` runs longer than the 32 bytes this protocol asks for
    /// — 42, 82 and 42 — and that costs nothing: expand emits
    /// `T(1) | T(2) | …` and truncates, so a published `OKM` *begins* with the
    /// `L = 32` answer. Comparing that prefix is comparing against the RFC.
    /// Case 3 is the one that earns its place: an empty salt and an empty info
    /// are where an implementation that quietly swapped two arguments still
    /// looks right.
    #[test]
    fn extract_and_expand_are_the_ones_rfc_5869_publishes() {
        const CASES: [RfcCase; 3] = [
            RfcCase {
                ikm: &[0x0b; 22],
                salt: &hex::<13>("000102030405060708090a0b0c"),
                info: &hex::<10>("f0f1f2f3f4f5f6f7f8f9"),
                prk: hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
                okm: hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"),
            },
            RfcCase {
                ikm: &hex::<80>(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222\
                     32425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546\
                     4748494a4b4c4d4e4f",
                ),
                salt: &hex::<80>(
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828\
                     38485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6\
                     a7a8a9aaabacadaeaf",
                ),
                info: &hex::<80>(
                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d\
                     3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6\
                     f7f8f9fafbfcfdfeff",
                ),
                prk: hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
                okm: hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"),
            },
            RfcCase {
                ikm: &[0x0b; 22],
                salt: &[],
                info: &[],
                prk: hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
                okm: hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"),
            },
        ];

        for (index, case) in CASES.iter().enumerate() {
            case.agrees(index.saturating_add(1));
        }
    }

    /// One case of RFC 5869's Appendix A: the three arguments it names, and the
    /// two answers it publishes for them.
    struct RfcCase {
        ikm: &'static [u8],
        salt: &'static [u8],
        info: &'static [u8],
        prk: [u8; DIGEST_BYTES],
        okm: [u8; DERIVED_KEY_BYTES],
    }

    impl RfcCase {
        fn agrees(&self, case: usize) {
            let prk = Prk::of(Salt(self.salt), Ikm(self.ikm));
            assert_eq!(prk.0, self.prk, "RFC 5869 case {case} extracts differently");
            assert_eq!(
                Expand::under(&prk, self.info).key(),
                self.okm,
                "RFC 5869 case {case} expands differently"
            );
        }
    }

    /// The `derived_keys` block of `docs/protocol/vectors/v1.json`, fed the
    /// salt, the IKM and the `info` exactly as that file publishes them.
    ///
    /// **The hex below is retyped, not read**, so this is not the outside opinion
    /// an earlier version of this comment claimed — change a nibble in the file
    /// and every test here stays green. What actually pins the three
    /// derivations to that artefact is `tests/vectors.rs`, which drives the
    /// ladder and checks all seven published tags: a wrong key gives a wrong
    /// tag, so all three are covered there transitively.
    ///
    /// This stays because it splits the diagnosis. Feeding the published `info`
    /// as bytes says the primitive agrees; the test below says our own assembly
    /// of that `info` agrees. One test covering both comes back as a single
    /// wrong key and says nothing about which half to go and read.
    #[test]
    fn every_published_key_is_reproduced_byte_for_byte() {
        const CASES: [PublishedKey; 3] = [
            PublishedKey {
                derivation: Derivation::PairKey,
                salt: &DEVICE_ID,
                ikm: &PRINTED_SECRET,
                info: &hex::<16>("6b6d34332f76312f706169722d6b6579"),
                out: hex("d2b669d733ae985424f2930404f5b5976fc52776deaf02a853f14d43c0b73007"),
            },
            PublishedKey {
                derivation: Derivation::ClientKey,
                salt: &DEVICE_ID,
                ikm: &PRINTED_SECRET,
                info: &hex::<26>("6b6d34332f76312f636c69656e742d6b65790000000100000007"),
                out: hex("eadf9347ac95af6e8d164d90883965d670a003c52785f1052fba086b05a1a853"),
            },
            PublishedKey {
                derivation: Derivation::SessionKey,
                salt: &hex::<32>(
                    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
                ),
                ikm: &hex::<32>("eadf9347ac95af6e8d164d90883965d670a003c52785f1052fba086b05a1a853"),
                info: &hex::<21>("6b6d34332f76312f73657373696f6e2d6b65790003"),
                out: hex("ba9ddffe57f11ccceeb5699cbaa5e1c196b719e9e867d97b05dd3b855d0f7601"),
            },
        ];

        for case in &CASES {
            case.is_reproduced();
        }
    }

    /// One entry of the `derived_keys` block: the three arguments the file
    /// names, and the 32 bytes it publishes for them.
    struct PublishedKey {
        derivation: Derivation,
        salt: &'static [u8],
        ikm: &'static [u8],
        info: &'static [u8],
        out: [u8; DERIVED_KEY_BYTES],
    }

    impl PublishedKey {
        fn is_reproduced(&self) {
            assert_eq!(
                Expand::under(&Prk::of(Salt(self.salt), Ikm(self.ikm)), self.info).key(),
                self.out,
                "the {} vector moved",
                self.derivation
            );
        }
    }

    /// The keys these methods derive are the keys the published MACs were
    /// signed with.
    ///
    /// This is what closes the loop through three types that seal their bytes,
    /// and it is the only thing that would catch `pair_key` reaching for
    /// `Derivation::ClientKey`, or `enrolment` feeding `client_id` ahead of
    /// `epoch`. Every such slip derives 32 bytes that look exactly as good as
    /// the right ones, and nothing says otherwise until a second implementation
    /// refuses every frame.
    #[test]
    fn each_derived_key_signs_the_tag_the_vectors_publish() {
        assert_eq!(
            pair_signs(&device().pair_key()),
            hex::<16>("22171c0449d848381e6d99ed7c92d1bd"),
            "the derived pair_key does not sign the published pairing proof"
        );
        assert_eq!(
            client_signs(&enrolment()),
            hex::<16>("8418a3ffb064b88022622123ce6a4f01"),
            "the derived client_key does not sign the published Hello proof"
        );
        assert_eq!(
            session_signs(&enrolment().session_key(&handshake(), SessionId::from(SESSION))),
            hex::<16>("879f149683b569b80d2b190a955eccba"),
            "the derived session_key does not sign the published response"
        );
    }

    /// Every label is the ASCII the specification prints, checked against the
    /// head of the `info` the vectors publish rather than against a second copy
    /// of the same list.
    ///
    /// A preimage in this repo once gained a label in the spec and not in the
    /// generator, and the check meant to catch it compared descriptions while
    /// the bytes underneath had already diverged.
    #[test]
    fn every_label_is_the_ascii_the_published_info_starts_with() {
        const LABELS: [(Derivation, &[u8]); 3] = [
            (
                Derivation::PairKey,
                &hex::<16>("6b6d34332f76312f706169722d6b6579"),
            ),
            (
                Derivation::ClientKey,
                &hex::<18>("6b6d34332f76312f636c69656e742d6b6579"),
            ),
            (
                Derivation::SessionKey,
                &hex::<19>("6b6d34332f76312f73657373696f6e2d6b6579"),
            ),
        ];

        for (derivation, ascii) in LABELS {
            assert_eq!(
                derivation.as_str().as_bytes(),
                ascii,
                "{derivation} is not the label the vectors were derived under"
            );
        }
    }

    /// P-042 as a property rather than a sentence: the two extract arguments
    /// are two arguments, not one byte string with a comma written in it.
    ///
    /// Swapping them is the obvious half. The half that actually rules out the
    /// `HKDF(a | b | c)` this replaced is the second: one fixed 48-byte string
    /// cut in two at two different places is two derivations here and *one*
    /// hash over a concatenation, because the concatenation cannot see where
    /// the boundary was. An implementation that agrees with the second
    /// assertion is one that assigned its arguments.
    #[test]
    fn salt_and_ikm_are_two_arguments_and_not_one_concatenation() {
        let named = Prk::of(Salt(&DEVICE_ID), Ikm(&PRINTED_SECRET));
        let swapped = Prk::of(Salt(&PRINTED_SECRET), Ikm(&DEVICE_ID));
        assert_ne!(
            named.expand(Derivation::PairKey).key(),
            swapped.expand(Derivation::PairKey).key(),
            "the two arguments are interchangeable, so neither is assigned"
        );

        let joined: [u8; DEVICE_ID_BYTES + PRINTED_SECRET_BYTES] = hex(
            "4f524947494e38392044454d4f203031000102030405060708090a0b0c0d0e0f10111213141516\
                 1718191a1b1c1d1e1f",
        );
        let early = joined.get(..DEVICE_ID_BYTES).expect("inside the string");
        let late = joined.get(..DIGEST_BYTES).expect("inside the string");
        assert_ne!(
            Prk::of(
                Salt(early),
                Ikm(joined.get(DEVICE_ID_BYTES..).expect("inside the string"))
            )
            .expand(Derivation::PairKey)
            .key(),
            Prk::of(
                Salt(late),
                Ikm(joined.get(DIGEST_BYTES..).expect("inside the string"))
            )
            .expand(Derivation::PairKey)
            .key(),
            "one byte string cut in two places derived one key, so the salt and the IKM were concatenated"
        );
    }

    /// One salt and one IKM under three labels are three keys. That is what
    /// makes `pair-key`, `client-key` and `session-key` separate purposes
    /// rather than three spellings of one, and it is what lets P-088 say the
    /// pairing proofs are keyed by something the session traffic is not.
    #[test]
    fn no_two_derivations_share_a_key_under_one_salt_and_ikm() {
        const EVERY: [Derivation; 3] = [
            Derivation::PairKey,
            Derivation::ClientKey,
            Derivation::SessionKey,
        ];
        let prk = Prk::of(Salt(&DEVICE_ID), Ikm(&PRINTED_SECRET));

        let mut keys = [[0u8; DERIVED_KEY_BYTES]; EVERY.len()];
        for (slot, derivation) in keys.iter_mut().zip(EVERY) {
            *slot = prk.expand(derivation).key();
        }
        for first in 0..EVERY.len() {
            for second in first.saturating_add(1)..EVERY.len() {
                assert_ne!(
                    keys.get(first).expect("the index came from the list"),
                    keys.get(second).expect("the index came from the list"),
                    "{} and {} derive one key",
                    EVERY.get(first).expect("the index came from the list"),
                    EVERY.get(second).expect("the index came from the list"),
                );
            }
        }
    }

    /// P-085: a factory reset must not re-mint the key a stolen phone holds.
    ///
    /// Press the button, reset, pair a new phone, and P-086 hands it slot 1
    /// again. Without `epoch` in the `info` that phone is issued the key the
    /// phone stolen last week already has, and the documented remedy for a
    /// compromised client removes no access at all.
    #[test]
    fn a_new_epoch_does_not_re_mint_the_key_a_stolen_phone_holds() {
        let slot = ClientId::new(1).expect("slot 1 is a slot");
        let before = device().enrolment(Epoch::FIRST, slot);
        let after = device().enrolment(Epoch::new(2).expect("2 is an epoch"), slot);

        assert_ne!(
            client_signs(&before),
            client_signs(&after),
            "one slot at two epochs derives one key, so a factory reset invalidates nothing"
        );
    }

    /// P-086: two slots at one epoch are two clients, and two clients do not
    /// share a key.
    ///
    /// Sharing one would let any enrolled phone sign as any other, and the
    /// capability mask fixed at pairing would stop meaning anything the moment
    /// a second client existed.
    #[test]
    fn two_slots_at_one_epoch_do_not_share_a_key() {
        let first = device().enrolment(Epoch::FIRST, ClientId::new(1).expect("slot 1 is a slot"));
        let second = device().enrolment(Epoch::FIRST, ClientId::new(2).expect("slot 2 is a slot"));

        assert_ne!(client_signs(&first), client_signs(&second));
    }

    /// The other half of the two above, and the half that would go unnoticed:
    /// the same epoch and the same slot derive the same key every time.
    ///
    /// A derivation that mixed in anything not in its arguments — a timer, a
    /// counter, uninitialised memory — passes both tests above and fails the
    /// first time a controller reboots between pairing a phone and answering
    /// it.
    #[test]
    fn one_slot_at_one_epoch_derives_one_key_every_time() {
        let slot = ClientId::new(CLIENT_ID).expect("slot 7 is a slot");
        assert_eq!(
            client_signs(&device().enrolment(Epoch::FIRST, slot)),
            client_signs(&device().enrolment(Epoch::FIRST, slot))
        );
    }

    /// Two connections are two session keys, because the challenge is in the
    /// salt.
    ///
    /// Share one and a frame recorded off an earlier connection verifies on a
    /// later one, which is the whole reason the controller mints a challenge at
    /// all.
    #[test]
    fn two_challenges_do_not_derive_one_session_key() {
        let enrolment = enrolment();
        let session = SessionId::from(SESSION);
        let mut later = handshake();
        later.challenge = [0x5a; NONCE_BYTES];

        assert_ne!(
            session_signs(&enrolment.session_key(&handshake(), session)),
            session_signs(&enrolment.session_key(&later, session))
        );
    }

    /// The client's half of the salt has to reach the key too, or the client
    /// contributes nothing and a controller with a stuck RNG hands every
    /// connection the same key.
    #[test]
    fn two_client_nonces_do_not_derive_one_session_key() {
        let enrolment = enrolment();
        let session = SessionId::from(SESSION);
        let mut other = handshake();
        other.client_nonce = [0x5a; NONCE_BYTES];

        assert_ne!(
            session_signs(&enrolment.session_key(&handshake(), session)),
            session_signs(&enrolment.session_key(&other, session))
        );
    }

    /// `session_id` is in the `info`, so two sessions off one handshake are two
    /// keys. It is the only thing separating them, since the salt and the IKM
    /// are identical.
    #[test]
    fn two_session_ids_over_one_handshake_do_not_derive_one_key() {
        let enrolment = enrolment();
        assert_ne!(
            session_signs(&enrolment.session_key(&handshake(), SessionId::from(SESSION))),
            session_signs(
                &enrolment.session_key(&handshake(), SessionId::from(SESSION.saturating_add(1)))
            )
        );
    }

    /// Two clients on one connection do not share a session key either: the
    /// client key is the IKM, so the whole ladder stays under the enrolment.
    #[test]
    fn two_enrolments_over_one_handshake_do_not_derive_one_session_key() {
        let device = device();
        let first = device.enrolment(Epoch::FIRST, ClientId::new(1).expect("slot 1 is a slot"));
        let second = device.enrolment(Epoch::FIRST, ClientId::new(2).expect("slot 2 is a slot"));
        let session = SessionId::from(SESSION);

        assert_ne!(
            session_signs(&first.session_key(&handshake(), session)),
            session_signs(&second.session_key(&handshake(), session))
        );
    }

    /// The salt is the challenge and *then* the nonce, joined with nothing in
    /// between (P-040).
    ///
    /// Swapped, both ends still derive a key; it is simply not the same key,
    /// and the only symptom is every frame of the session failing its MAC.
    #[test]
    fn the_session_salt_is_the_challenge_and_then_the_nonce() {
        let salt = handshake().salt();
        assert_eq!(
            salt.get(..NONCE_BYTES).expect("the salt holds both nonces"),
            CHALLENGE
        );
        assert_eq!(
            salt.get(NONCE_BYTES..).expect("the salt holds both nonces"),
            CLIENT_NONCE
        );

        let swapped = Handshake {
            challenge: CLIENT_NONCE,
            client_nonce: CHALLENGE,
        };
        assert_ne!(salt, swapped.salt());
    }

    /// Zero is FRAM nobody wrote, not epoch zero. Deriving under it mints keys
    /// at an epoch the first successful write immediately invalidates — every
    /// client on the unit refused, with nothing pointing at the read that
    /// failed.
    #[test]
    fn a_zero_epoch_is_refused_rather_than_derived_under() {
        assert_eq!(Epoch::new(0), None);
        assert_eq!(Epoch::new(1), Some(Epoch::FIRST));
        assert_eq!(
            Epoch::new(u32::MAX)
                .expect("the top of the counter is an epoch")
                .get(),
            u32::MAX,
            "an epoch does not survive the round trip through its own type"
        );
    }

    /// Zero is the `client_id` a `PairAck` carries when nobody was enrolled, so
    /// it names no slot. A key derived at slot zero is a key for a client that
    /// does not exist, and P-086 counts from 1.
    #[test]
    fn a_zero_client_id_names_no_slot() {
        assert_eq!(ClientId::new(0), None);
        assert_eq!(
            ClientId::new(1).expect("slot 1 is a slot").get(),
            1,
            "a slot does not survive the round trip through its own type"
        );
    }

    /// The enrolment carries the slot it was derived at, so the `client_id` a
    /// `Hello` body announces and the key that signs that body cannot name two
    /// different clients.
    #[test]
    fn an_enrolment_reports_the_slot_its_key_was_derived_at() {
        assert_eq!(enrolment().client_id().get(), CLIENT_ID);
    }

    /// A derivation renders as the label it puts at the head of its `info`, so
    /// a bench log naming the derivation is naming the bytes that went in.
    #[test]
    fn a_derivation_renders_as_the_label_it_puts_in_the_info() {
        let mut into = [0u8; 64];
        let mut sink = Sink {
            into: &mut into,
            written: 0,
        };
        write!(sink, "{}", Derivation::SessionKey).expect("a label fits sixty-four bytes");
        let written = sink.written;
        assert_eq!(
            into.get(..written)
                .expect("the length came from the render"),
            b"km43/v1/session-key"
        );
    }

    /// Renders into a fixed buffer, since there is no `String` here.
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
}
