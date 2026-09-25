//! Both handshakes and the sealed transport, computed by code that shares
//! nothing with `km43`.
//!
//! The handshakes run in `snow`, a Noise implementation somebody else wrote, so
//! a published message is the framework's reading of the pattern rather than
//! ours. The transport is sealed here with the ChaCha20-Poly1305 primitive
//! directly, under the keys `snow` split into: the nonce layout and the
//! associated data are the parts KM43 defines, and they are written out below
//! from the specification rather than borrowed.
//!
//! cites: P-226, P-227, P-231, P-232, P-234

use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use snow::params::NoiseParams;

pub const PAIRING_NAME: &str = "Noise_XXpsk0_25519_ChaChaPoly_SHA256";
pub const SESSION_NAME: &str = "Noise_IK_25519_ChaChaPoly_SHA256";

const L_PROLOGUE: &[u8] = b"km43/v1/prologue";

/// The Noise messages are small; this is room for the widest with slack.
const MESSAGE_ROOM: usize = 1024;

/// X25519 of `scalar` with the base point: a public key from its private half.
pub fn public(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// X25519 of `scalar` with `point`.
pub fn agree(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*private, *public)
}

/// What P-227 puts in a prologue, named so no two can be swapped.
pub struct PrologueFields<'a> {
    pub suite: u8,
    pub major: u8,
    pub minor: u8,
    pub device_id: &'a [u8],
    pub epoch: u32,
    pub challenge: &'a [u8],
    pub handle: u16,
}

impl PrologueFields<'_> {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        if self.device_id.len() != 16 || self.challenge.len() != 16 {
            bail!("the prologue's device_id and challenge are sixteen bytes each");
        }
        Ok([
            L_PROLOGUE,
            &[self.suite, self.major, self.minor],
            self.device_id,
            &self.epoch.to_be_bytes(),
            self.challenge,
            &self.handle.to_be_bytes(),
        ]
        .concat())
    }

    pub const READABLE: &'static str = "'km43/v1/prologue' | suite:u8 | protocol_major:u8 | protocol_minor:u8 | device_id[16] | epoch:u32be | challenge[16] | handle:u16be";
}

/// One enrolment, message by message.
pub struct Pairing {
    pub message_1: Vec<u8>,
    /// The handshake hash after message 1, which the refusal tag covers.
    pub h1: Vec<u8>,
    pub message_2: Vec<u8>,
    pub message_3: Vec<u8>,
    pub hash: Vec<u8>,
    pub client_to_controller: [u8; 32],
    pub controller_to_client: [u8; 32],
}

pub struct PairingInputs<'a> {
    pub prologue: &'a [u8],
    pub psk: &'a [u8; 32],
    pub client: &'a [u8; 32],
    pub controller: &'a [u8; 32],
    pub client_ephemeral: &'a [u8; 32],
    pub controller_ephemeral: &'a [u8; 32],
    pub offer: &'a [u8],
    /// The payload of messages 2 and 3, which P-064 says is an empty map.
    pub empty: &'a [u8],
}

/// Run `XXpsk0` between two `snow` states and keep every byte that crossed.
pub fn pair(i: &PairingInputs<'_>) -> Result<Pairing> {
    let params: NoiseParams = PAIRING_NAME.parse().context("the pairing pattern")?;
    let mut client = snow::Builder::new(params.clone())
        .prologue(i.prologue)?
        .psk(0, i.psk)?
        .local_private_key(i.client)?
        .fixed_ephemeral_key_for_testing_only(i.client_ephemeral)
        .build_initiator()?;
    let mut controller = snow::Builder::new(params)
        .prologue(i.prologue)?
        .psk(0, i.psk)?
        .local_private_key(i.controller)?
        .fixed_ephemeral_key_for_testing_only(i.controller_ephemeral)
        .build_responder()?;

    let message_1 = send(&mut client, i.offer)?;
    expect_payload(&mut controller, &message_1, i.offer)?;
    let h1 = controller.get_handshake_hash().to_vec();
    if client.get_handshake_hash() != h1.as_slice() {
        bail!("the two ends of the pairing disagree about h1");
    }
    let message_2 = send(&mut controller, i.empty)?;
    expect_payload(&mut client, &message_2, i.empty)?;
    if client.get_remote_static() != Some(public(i.controller).as_slice()) {
        bail!("message 2 does not carry the controller key");
    }
    let message_3 = send(&mut client, i.empty)?;
    expect_payload(&mut controller, &message_3, i.empty)?;
    if controller.get_remote_static() != Some(public(i.client).as_slice()) {
        bail!("message 3 does not carry the client key");
    }
    let hash = controller.get_handshake_hash().to_vec();
    let (client_to_controller, controller_to_client) = split(&mut client, &mut controller)?;
    Ok(Pairing {
        message_1,
        h1,
        message_2,
        message_3,
        hash,
        client_to_controller,
        controller_to_client,
    })
}

/// One session handshake.
pub struct Session {
    pub message_1: Vec<u8>,
    pub message_2: Vec<u8>,
    pub hash: Vec<u8>,
    pub client_to_controller: [u8; 32],
    pub controller_to_client: [u8; 32],
}

pub struct SessionInputs<'a> {
    pub prologue: &'a [u8],
    pub client: &'a [u8; 32],
    pub controller: &'a [u8; 32],
    pub client_ephemeral: &'a [u8; 32],
    pub controller_ephemeral: &'a [u8; 32],
    pub offer: &'a [u8],
    pub report: &'a [u8],
}

/// Run `IK` with the client holding the controller key it pinned.
pub fn hello(i: &SessionInputs<'_>) -> Result<Session> {
    let params: NoiseParams = SESSION_NAME.parse().context("the session pattern")?;
    let mut client = snow::Builder::new(params.clone())
        .prologue(i.prologue)?
        .local_private_key(i.client)?
        .remote_public_key(&public(i.controller))?
        .fixed_ephemeral_key_for_testing_only(i.client_ephemeral)
        .build_initiator()?;
    let mut controller = snow::Builder::new(params)
        .prologue(i.prologue)?
        .local_private_key(i.controller)?
        .fixed_ephemeral_key_for_testing_only(i.controller_ephemeral)
        .build_responder()?;

    let message_1 = send(&mut client, i.offer)?;
    expect_payload(&mut controller, &message_1, i.offer)?;
    if controller.get_remote_static() != Some(public(i.client).as_slice()) {
        bail!("message 1 does not carry the client key");
    }
    let message_2 = send(&mut controller, i.report)?;
    expect_payload(&mut client, &message_2, i.report)?;
    let hash = controller.get_handshake_hash().to_vec();
    let (client_to_controller, controller_to_client) = split(&mut client, &mut controller)?;
    Ok(Session {
        message_1,
        message_2,
        hash,
        client_to_controller,
        controller_to_client,
    })
}

fn send(state: &mut snow::HandshakeState, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; MESSAGE_ROOM];
    let len = state.write_message(payload, &mut out)?;
    out.truncate(len);
    Ok(out)
}

fn expect_payload(state: &mut snow::HandshakeState, message: &[u8], want: &[u8]) -> Result<()> {
    let mut out = vec![0u8; MESSAGE_ROOM];
    let len = state.read_message(message, &mut out)?;
    if out.get(..len) != Some(want) {
        bail!("a handshake payload did not survive its own round trip");
    }
    Ok(())
}

/// Both ends' `Split()`, which must agree: Noise orders the keys the same way
/// for both roles, initiator's sending key first.
fn split(
    client: &mut snow::HandshakeState,
    controller: &mut snow::HandshakeState,
) -> Result<([u8; 32], [u8; 32])> {
    let ours = client.dangerously_get_raw_split();
    if ours != controller.dangerously_get_raw_split() {
        bail!("the two ends split into different keys");
    }
    Ok(ours)
}

/// P-234's associated data: the three envelope scalars, big-endian.
pub fn ad(kind: u8, session: u16, req_id: u32) -> Vec<u8> {
    [&[kind][..], &session.to_be_bytes(), &req_id.to_be_bytes()].concat()
}

pub const AD_READABLE: &str = "type:u8 | session_id:u16be | req_id:u32be";

/// ChaCha20-Poly1305 with P-232's nonce: four zero bytes, then the nonce
/// little-endian. The tag comes back appended.
pub fn seal(key: &[u8; 32], nonce: u64, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_raw(key, &iv(nonce)?, ad, plaintext)
}

/// The inverse, for the self-check that the sealed bytes open again.
pub fn open(key: &[u8; 32], nonce: u64, ad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let split = sealed
        .len()
        .checked_sub(16)
        .context("a sealed body carries a sixteen-byte tag")?;
    let (body, tag) = sealed.split_at(split);
    let tag: [u8; 16] = tag.try_into().context("the tag is sixteen bytes")?;
    let mut out = body.to_vec();
    ChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(
            &iv(nonce)?.into(),
            ad,
            out.as_mut_slice().into(),
            &tag.into(),
        )
        .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 refused to open"))?;
    Ok(out)
}

/// The same primitive with the whole twelve-byte nonce, which is the form RFC
/// 8439 publishes its vector in.
pub fn seal_raw(key: &[u8; 32], iv: &[u8; 12], ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut out = plaintext.to_vec();
    let tag = ChaCha20Poly1305::new(key.into())
        .encrypt_inout_detached(&(*iv).into(), ad, out.as_mut_slice().into())
        .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 refused to seal"))?;
    out.extend_from_slice(&tag);
    Ok(out)
}

fn iv(nonce: u64) -> Result<[u8; 12]> {
    let mut iv = [0u8; 12];
    iv.get_mut(4..)
        .context("the nonce has twelve bytes")?
        .copy_from_slice(&nonce.to_le_bytes());
    Ok(iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prologue built from a wrong-width field is a transcript nobody else
    /// computes, so it is refused rather than padded.
    #[test]
    fn a_prologue_with_a_short_field_is_refused() {
        let fields = PrologueFields {
            suite: 1,
            major: 1,
            minor: 0,
            device_id: &[0; 15],
            epoch: 1,
            challenge: &[0; 16],
            handle: 3,
        };
        assert!(fields.bytes().is_err());
    }

    /// Fifty-seven bytes, which is what P-238's admission preimage counts on
    /// before the variable-width handshake message.
    #[test]
    fn a_prologue_is_fifty_seven_bytes() {
        let fields = PrologueFields {
            suite: 1,
            major: 1,
            minor: 0,
            device_id: &[0; 16],
            epoch: 1,
            challenge: &[0; 16],
            handle: 3,
        };
        assert_eq!(fields.bytes().expect("fixed widths").len(), 57);
    }

    /// A sealed body opened under the other direction's key, or with the
    /// associated data of another request, fails: the two properties the
    /// transport vectors exist to pin.
    #[test]
    fn a_sealed_body_opens_only_under_its_own_key_and_header() {
        let key = [7u8; 32];
        let sealed = seal(&key, 5, &ad(0x05, 3, 17), b"inner").expect("seals");
        assert_eq!(
            open(&key, 5, &ad(0x05, 3, 17), &sealed).expect("opens"),
            b"inner"
        );
        assert!(open(&[8u8; 32], 5, &ad(0x05, 3, 17), &sealed).is_err());
        assert!(open(&key, 5, &ad(0x05, 3, 18), &sealed).is_err());
        assert!(open(&key, 6, &ad(0x05, 3, 17), &sealed).is_err());
    }
}
