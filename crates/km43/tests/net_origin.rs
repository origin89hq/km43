//! A comms cache at the controller's own version can still hold another
//! network, and the origin token is what says so (L-132, L-133, L-137, L-138).
//!
//! Every exchange here goes through the encoder and the decoder a peer would
//! use, so a token written under the wrong key or dropped on the way fails the
//! same test that checks the decision.
use core::num::NonZeroU32;

use km43::{
    LinkEnvelope, LinkError, LinkField, LinkHeader, LinkMessageType, LinkUp, NET_ORIGIN_BYTES,
    NetChange, NetConfig, NetConfigOp, NetOrigin, NetStamp, NetVerdict, NvsWrite, ReqId, SessionId,
    Side, Version,
};

/// This controller's section, drawn when it was first written.
const HOME: NetOrigin = NetOrigin::new(*b"home-sec");
/// The section this controller drew when it repaired its own record.
const REPAIRED: NetOrigin = NetOrigin::new(*b"repaired");
/// Another unit's section, on a board that came out of it.
const FOREIGN: NetOrigin = NetOrigin::new(*b"next-dor");

fn written(version: u32, origin: NetOrigin) -> NetStamp {
    NetStamp::Written {
        version: NonZeroU32::new(version).expect("a written version is nonzero"),
        origin,
    }
}

fn header(kind: LinkMessageType) -> LinkHeader {
    LinkHeader {
        kind,
        session: SessionId::None,
        req_id: ReqId(1),
    }
}

/// The comms `LinkUp` a module sends for what its flash holds.
fn reporting(net_version: Option<u32>, net_origin: Option<NetOrigin>) -> LinkUp<'static> {
    LinkUp {
        version: Version::V1_0,
        role: Side::Comms,
        fw: "0.2.0+g5e6f7a8b",
        boot_id: 0x5eed_face,
        hw: "controller-a rev A",
        net_version,
        device_id: None,
        net_origin,
    }
}

fn reporting_stamp(held: NetStamp) -> LinkUp<'static> {
    reporting(Some(held.net_version()), held.net_origin())
}

/// What the controller reads off the cable, rather than the struct the module
/// built: the decision has to hold for the bytes.
fn heard<'b>(up: &LinkUp<'_>, bytes: &'b mut [u8; 256]) -> LinkUp<'b> {
    let len = up
        .write(header(LinkMessageType::LinkUp), bytes)
        .expect("the module's LinkUp encodes");
    let frame: &'b [u8] = &bytes[..len];
    LinkUp::decode(LinkEnvelope::decode(frame).expect("an envelope")).expect("the LinkUp reads")
}

fn pushes(master: NetStamp, up: &LinkUp<'_>) -> bool {
    let mut bytes = [0; 256];
    master.needs_push(&heard(up, &mut bytes))
}

fn set(version: u32, origin: NetOrigin) -> NetChange<'static> {
    NetChange::Set {
        version,
        ssid: "cabin",
        psk: "correct horse battery",
        country: "CA",
        hostname: "o89",
        origin,
    }
}

fn clear(version: u32, origin: NetOrigin) -> NetChange<'static> {
    NetChange::Clear {
        version,
        country: "CA",
        hostname: "o89",
        origin,
    }
}

/// The module's answer as the controller reads it off the cable.
fn acknowledged(verdict: NetVerdict) -> NetVerdict {
    let mut bytes = [0; 64];
    let len = verdict
        .write(header(LinkMessageType::NetConfigAck), &mut bytes)
        .expect("the ack encodes");
    NetVerdict::decode(LinkEnvelope::decode(&bytes[..len]).expect("an envelope"))
        .expect("the ack reads")
}

/// The controller's own section in the module: nothing to push, and pushing it
/// anyway on every boot would put the passphrase on the link for nothing.
///
/// cites: L-133
#[test]
fn l_133_the_same_origin_at_an_equal_version_needs_no_push() {
    for version in [1, 7, u32::MAX] {
        let master = written(version, HOME);
        assert!(
            !pushes(master, &reporting_stamp(master)),
            "version {version}"
        );
    }
}

/// A board out of another unit that happens to report this controller's
/// version. Version-only, it keeps the other site's passphrase and joins the
/// other site's network name, and nothing on the link says so.
///
/// cites: L-133
#[test]
fn l_133_pushes_when_the_origin_differs_at_an_equal_version_from_another_controller() {
    for version in [1, 7, u32::MAX] {
        let master = written(version, HOME);
        let swapped_in = reporting(Some(version), Some(FOREIGN));
        assert!(pushes(master, &swapped_in), "version {version}");
    }
}

/// The same controller, twice. A module is unplugged while the section is at
/// version 3, the record is damaged, a client repairs it against
/// `expected_version` 0 and the version restarts at 1, and two more edits bring
/// it back to 3. The module comes back holding the old passphrase at version 3.
/// A `device_id` would match here too; only the token drawn at the repair
/// tells the two version 3s apart.
///
/// cites: L-133, L-138
#[test]
fn l_133_pushes_when_the_origin_differs_at_an_equal_version_after_a_repair() {
    let before = written(3, HOME);
    let unplugged = reporting_stamp(before);
    assert!(!pushes(before, &unplugged), "in step before the damage");

    // P-108: the damaged section reads as version 0, and the controller
    // clears the cache rather than vouch for it.
    assert!(pushes(NetStamp::Unwritten, &unplugged));

    for version in 1..=3 {
        let after = written(version, REPAIRED);
        assert!(
            pushes(after, &unplugged),
            "the module that missed the repair kept its old passphrase at version {version}"
        );
    }

    // Once pushed and stored, the module is the repaired section's.
    let (held, verdict) = before
        .settle(&set(3, REPAIRED), NvsWrite::Durable)
        .expect("a written change");
    assert_eq!(acknowledged(verdict).version, 3);
    assert!(!pushes(written(3, REPAIRED), &reporting_stamp(held)));
}

/// L-133's *different, not newer*, unchanged by the token: a foreign cache
/// below or above this controller's version is pushed whatever its token.
///
/// cites: L-133
#[test]
fn l_133_a_foreign_cache_at_a_lower_or_higher_version_is_pushed() {
    let master = written(7, HOME);
    for version in [1, 6, 8, u32::MAX] {
        for origin in [HOME, FOREIGN] {
            assert!(
                pushes(master, &reporting(Some(version), Some(origin))),
                "version {version}"
            );
        }
    }
}

/// A module at the right version that cannot say whose network it holds is
/// not one the controller vouches for. There is no legacy cache to spare:
/// nothing has shipped without the token.
///
/// cites: L-133
#[test]
fn l_133_a_cache_with_no_origin_token_is_pushed() {
    let master = written(7, HOME);
    assert!(pushes(master, &reporting(Some(7), None)));
    assert!(
        pushes(master, &reporting(None, None)),
        "no net_version at all"
    );
    assert!(
        master.needs_push(&reporting(None, None)),
        "a LinkUp with no version compares as nothing"
    );
}

/// With no section of its own the controller has no token to compare, so the
/// rule stays version-only: an empty module is left alone, and anything
/// written is cleared whatever token it carries.
///
/// cites: L-133
#[test]
fn l_133_an_unwritten_or_unreadable_master_compares_the_version_alone() {
    let master = NetStamp::Unwritten;
    assert!(!pushes(master, &reporting_stamp(NetStamp::Unwritten)));
    assert!(pushes(master, &reporting(Some(5), Some(FOREIGN))));
    assert!(pushes(master, &reporting(Some(5), None)));
    assert!(
        pushes(master, &reporting_stamp(written(3, HOME))),
        "its own, unreadable"
    );
    assert!(master.needs_push(&reporting(None, None)));
}

/// Both clears end the push once they are durable: the unwritten one by
/// reporting 0 and no token, the ordinary one by reporting its own version and
/// the token it was sent with.
///
/// cites: L-132, L-133
#[test]
fn l_132_a_durable_clear_reports_what_it_stored_and_ends_the_push() {
    let foreign = written(5, FOREIGN);
    let (held, verdict) = foreign
        .settle(&NetChange::ClearUnwritten, NvsWrite::Durable)
        .expect("an unwritten clear");
    assert_eq!(held, NetStamp::Unwritten);
    assert_eq!(
        acknowledged(verdict),
        NetVerdict {
            outcome: NetConfig::Stored,
            version: 0
        }
    );
    let up = reporting_stamp(held);
    assert_eq!((up.net_version, up.net_origin), (Some(0), None));
    assert!(!pushes(NetStamp::Unwritten, &up));

    let (held, verdict) = foreign
        .settle(&clear(9, HOME), NvsWrite::Durable)
        .expect("a written clear");
    assert_eq!(held, written(9, HOME));
    assert_eq!(acknowledged(verdict).version, 9);
    assert!(!pushes(written(9, HOME), &reporting_stamp(held)));
}

/// A factory reset keeps the section, so it keeps the token: the clear goes out
/// at the next version with the same origin, and once stored the module is in
/// step without a second push.
///
/// cites: L-135, L-138
#[test]
fn l_135_a_factory_clear_keeps_the_origin_and_settles_the_cache() {
    let before = written(3, HOME);
    let module = reporting_stamp(before);
    let after = written(4, HOME);
    assert!(pushes(after, &module), "the reset moved the version");

    let reset = clear(4, HOME);
    let mut bytes = [0; 128];
    let len = reset
        .write(header(LinkMessageType::NetConfig), &mut bytes)
        .expect("the factory clear encodes");
    let sent = NetChange::decode(LinkEnvelope::decode(&bytes[..len]).expect("an envelope"))
        .expect("the factory clear reads");
    let NetChange::Clear {
        country, origin, ..
    } = sent
    else {
        panic!("a factory clear is a written clear");
    };
    assert_eq!((country, origin), ("CA", HOME));

    let (held, verdict) = before
        .settle(&sent, NvsWrite::Durable)
        .expect("a written clear");
    assert_eq!(acknowledged(verdict).outcome, NetConfig::Stored);
    assert!(!pushes(after, &reporting_stamp(held)));
}

/// A write that did not reach flash leaves the module running on the new
/// network in RAM and the old one in NVS. It has to keep saying so, reboot
/// included, or the controller stops pushing and the next power cycle brings
/// the old passphrase back.
///
/// cites: L-132, L-137
#[test]
fn l_137_an_interrupted_write_keeps_reporting_the_persisted_origin() {
    let master = written(3, REPAIRED);
    let in_flash = written(3, HOME);
    let push = set(3, REPAIRED);

    let (held, verdict) = in_flash
        .settle(&push, NvsWrite::Failed)
        .expect("a written change");
    assert_eq!(held, in_flash, "a failed write moved what flash holds");
    assert_eq!(
        acknowledged(verdict),
        NetVerdict {
            outcome: NetConfig::NvsWriteFailed,
            version: 3
        }
    );

    // The next LinkUp and the one after a reboot both come from flash.
    for boot in 0..2 {
        assert!(pushes(master, &reporting_stamp(held)), "boot {boot}");
    }
    // What the RAM copy would have said is exactly what hides the failure.
    let ram = NetStamp::of(&push).expect("a written change");
    assert!(!pushes(master, &reporting_stamp(ram)));

    let (held, verdict) = held.settle(&push, NvsWrite::Durable).expect("a retry");
    assert_eq!(acknowledged(verdict).outcome, NetConfig::Stored);
    assert!(!pushes(master, &reporting_stamp(held)));
}

/// A failed erase of a foreign cache keeps reporting the foreign version and
/// token until erasure succeeds, so the unwritten clear is retried after every
/// `LinkUp`, reboots included.
///
/// cites: L-132, L-137
#[test]
fn l_137_a_failed_erase_keeps_the_foreign_cache_visible_until_it_is_gone() {
    let foreign = written(5, FOREIGN);
    let (held, verdict) = foreign
        .settle(&NetChange::ClearUnwritten, NvsWrite::Failed)
        .expect("an unwritten clear");
    assert_eq!(held, foreign);
    assert_eq!(
        acknowledged(verdict),
        NetVerdict {
            outcome: NetConfig::NvsWriteFailed,
            version: 5
        }
    );
    let up = reporting_stamp(held);
    assert_eq!((up.net_version, up.net_origin), (Some(5), Some(FOREIGN)));
    for boot in 0..2 {
        assert!(pushes(NetStamp::Unwritten, &up), "boot {boot}");
    }

    let (held, _) = held
        .settle(&NetChange::ClearUnwritten, NvsWrite::Durable)
        .expect("the retried clear");
    assert!(!pushes(NetStamp::Unwritten, &reporting_stamp(held)));
}

/// An acknowledgement names what flash holds, never what was offered: a set
/// that stored reports its version, and one that failed reports the version
/// already there, a clear's and an empty cache's 0 included.
///
/// cites: L-132, L-137
#[test]
fn l_132_an_acknowledgement_reports_only_what_flash_holds() {
    for (before, change, write, outcome, version) in [
        (
            NetStamp::Unwritten,
            set(2, HOME),
            NvsWrite::Durable,
            NetConfig::Stored,
            2,
        ),
        (
            NetStamp::Unwritten,
            set(2, HOME),
            NvsWrite::Failed,
            NetConfig::NvsWriteFailed,
            0,
        ),
        (
            written(4, HOME),
            set(5, HOME),
            NvsWrite::Failed,
            NetConfig::NvsWriteFailed,
            4,
        ),
        (
            written(4, HOME),
            clear(5, HOME),
            NvsWrite::Durable,
            NetConfig::Stored,
            5,
        ),
    ] {
        let (_, verdict) = before.settle(&change, write).expect("a written change");
        assert_eq!(
            acknowledged(verdict),
            NetVerdict { outcome, version },
            "{change:?} over {before:?}"
        );
    }
}

/// The token is stored with the version it arrived with and nothing else: a
/// stored change yields both of its own, and a failed one both of the old.
///
/// cites: L-138
#[test]
fn l_138_the_origin_is_persisted_with_its_version() {
    let old = written(4, FOREIGN);
    for change in [set(9, HOME), clear(9, HOME)] {
        let (held, _) = old.settle(&change, NvsWrite::Durable).expect("a change");
        assert_eq!((held.net_version(), held.net_origin()), (9, Some(HOME)));
        let (held, _) = old.settle(&change, NvsWrite::Failed).expect("a change");
        assert_eq!((held.net_version(), held.net_origin()), (4, Some(FOREIGN)));
    }
    assert_eq!(
        NetStamp::of(&set(0, HOME)),
        Err(LinkError::ZeroNetworkVersion),
        "a written stamp at version 0"
    );
    assert_eq!(
        old.settle(&clear(0, HOME), NvsWrite::Durable),
        Err(LinkError::ZeroNetworkVersion)
    );
}

/// Key 7 on every written `NetConfig`, byte for byte, and a written one
/// without it is refused rather than stored with no origin.
///
/// cites: L-138
#[test]
fn l_138_every_nonzero_net_config_carries_the_origin() {
    for change in [set(1, HOME), clear(u32::MAX, HOME)] {
        let mut bytes = [0; 128];
        let len = change
            .write(header(LinkMessageType::NetConfig), &mut bytes)
            .expect("it encodes");
        let frame = &bytes[..len];
        assert!(
            frame
                .windows(NET_ORIGIN_BYTES)
                .any(|run| run == HOME.bytes()),
            "{change:?} left its origin off the link"
        );
        assert_eq!(
            NetChange::decode(LinkEnvelope::decode(frame).expect("an envelope")),
            Ok(change)
        );
        for end in 0..len {
            if let Ok(envelope) = LinkEnvelope::decode(&frame[..end]) {
                assert!(NetChange::decode(envelope).is_err(), "cut at {end}");
            }
        }
    }

    for op in [NetConfigOp::Set, NetConfigOp::Clear] {
        let mut bytes = [0; 128];
        let set_only = op == NetConfigOp::Set;
        let keys = if set_only { 6 } else { 4 };
        let mut cbor = header(LinkMessageType::NetConfig)
            .write(keys, &mut bytes)
            .expect("a header");
        cbor.key(1).expect("key");
        cbor.u64(u64::from(op as u8)).expect("op");
        cbor.key(2).expect("key");
        cbor.u64(3).expect("version");
        if set_only {
            cbor.key(3).expect("key");
            cbor.text("cabin").expect("ssid");
            cbor.key(4).expect("key");
            cbor.text("correct horse battery").expect("psk");
        }
        cbor.key(5).expect("key");
        cbor.text("CA").expect("country");
        cbor.key(6).expect("key");
        cbor.text("o89").expect("hostname");
        let len = cbor.finish().expect("it closes");
        assert_eq!(
            NetChange::decode(LinkEnvelope::decode(&bytes[..len]).expect("an envelope")),
            Err(LinkError::Missing(LinkField::Origin)),
            "{op:?} without an origin"
        );
    }
}

/// A `NetConfig` with one key beside `op` and `version`, so the refusal can
/// only be about that key.
fn one_extra(op: NetConfigOp, version: u64, key: i64, origin: &[u8]) -> ([u8; 128], usize) {
    let mut bytes = [0; 128];
    let mut cbor = header(LinkMessageType::NetConfig)
        .write(3, &mut bytes)
        .expect("a header");
    cbor.key(1).expect("key");
    cbor.u64(u64::from(op as u8)).expect("op");
    cbor.key(2).expect("key");
    cbor.u64(version).expect("version");
    cbor.key(key).expect("key");
    cbor.bytes(origin).expect("origin");
    let len = cbor.finish().expect("it closes");
    (bytes, len)
}

/// The unwritten clear names no section, so a token on it is refused the way
/// keys 3 to 6 are, and the module's answer is `rejected_invalid` with its
/// cache untouched. A version-zero set was already refused for its version.
///
/// cites: L-133
#[test]
fn l_133_a_version_zero_net_config_carrying_an_origin_is_refused() {
    for (op, expected) in [
        (NetConfigOp::Clear, LinkError::UnwrittenClearCarriedOrigin),
        (NetConfigOp::Set, LinkError::ZeroNetworkVersion),
    ] {
        let (bytes, len) = one_extra(op, 0, 7, HOME.bytes());
        assert_eq!(
            NetChange::decode(LinkEnvelope::decode(&bytes[..len]).expect("an envelope")),
            Err(expected)
        );
    }
    // Without the token the same clear is the ordinary unwritten one, which
    // shows the refusal above is about key 7 and nothing else.
    let mut bytes = [0; 64];
    let len = NetChange::ClearUnwritten
        .write(header(LinkMessageType::NetConfig), &mut bytes)
        .expect("it encodes");
    assert_eq!(
        NetChange::decode(LinkEnvelope::decode(&bytes[..len]).expect("an envelope")),
        Ok(NetChange::ClearUnwritten)
    );
}

/// A token cut or padded to fit is one no section was created with.
///
/// cites: L-138
#[test]
fn l_138_an_origin_of_any_other_width_is_refused() {
    for width in [0, 1, 7, 9, 16] {
        let token = [0x5A; 16];
        let (bytes, len) = one_extra(NetConfigOp::Clear, 3, 7, &token[..width]);
        assert_eq!(
            NetChange::decode(LinkEnvelope::decode(&bytes[..len]).expect("an envelope")),
            Err(LinkError::OriginNotEight(width)),
            "{width} bytes"
        );
        assert_eq!(
            NetOrigin::try_from(&token[..width]),
            Err(LinkError::OriginNotEight(width))
        );
    }
    assert_eq!(NetOrigin::try_from(&HOME.bytes()[..]), Ok(HOME));
}

/// One value after the six shared `LinkUp` keys.
#[derive(Clone, Copy)]
enum Extra<'a> {
    Number(u64),
    Bytes(&'a [u8]),
}

/// A `LinkUp` from `role` with the shared keys and then `keys`, written raw so
/// the decoder can be handed what the encoder refuses to build.
fn raw_link_up(role: Side, keys: &[(i64, Extra<'_>)]) -> ([u8; 256], usize) {
    let shared = reporting(None, None);
    let mut bytes = [0; 256];
    let mut cbor = header(LinkMessageType::LinkUp)
        .write(6 + keys.len(), &mut bytes)
        .expect("a header");
    cbor.key(1).expect("key");
    cbor.u64(u64::from(shared.version.major)).expect("major");
    cbor.key(2).expect("key");
    cbor.u64(u64::from(shared.version.minor)).expect("minor");
    cbor.key(3).expect("key");
    cbor.u64(u64::from(role.number())).expect("role");
    cbor.key(4).expect("key");
    cbor.text(shared.fw).expect("fw");
    cbor.key(5).expect("key");
    cbor.u64(u64::from(shared.boot_id)).expect("boot_id");
    cbor.key(6).expect("key");
    cbor.text(shared.hw).expect("hw");
    for (key, value) in keys {
        cbor.key(*key).expect("key");
        match value {
            Extra::Number(n) => cbor.u64(*n).expect("a number"),
            Extra::Bytes(b) => cbor.bytes(b).expect("bytes"),
        }
    }
    let len = cbor.finish().expect("it closes");
    (bytes, len)
}

fn decoded(raw: &([u8; 256], usize)) -> Result<LinkUp<'_>, LinkError> {
    LinkUp::decode(LinkEnvelope::decode(&raw.0[..raw.1]).expect("an envelope"))
}

/// The token rides beside a written version and comes from the comms processor
/// alone. Each refusal is checked at both ends, so neither side can build what
/// the other must refuse.
///
/// cites: L-132
#[test]
fn l_132_a_net_origin_rides_only_beside_a_written_version() {
    let mut bytes = [0; 256];
    for version in [None, Some(0)] {
        assert_eq!(
            reporting(version, Some(HOME)).write(header(LinkMessageType::LinkUp), &mut bytes),
            Err(LinkError::NetOriginWithoutVersion),
            "{version:?}"
        );
    }
    let origin = Extra::Bytes(HOME.bytes());
    assert_eq!(
        decoded(&raw_link_up(
            Side::Comms,
            &[(7, Extra::Number(0)), (9, origin)]
        ))
        .err(),
        Some(LinkError::NetOriginWithoutVersion)
    );
    assert_eq!(
        decoded(&raw_link_up(Side::Comms, &[(9, origin)])).err(),
        Some(LinkError::NetOriginWithoutVersion)
    );

    let controller = LinkUp {
        role: Side::Controller,
        net_version: None,
        device_id: Some(*b"ORIGIN89 DEMO 01"),
        net_origin: Some(HOME),
        ..reporting(None, None)
    };
    assert_eq!(
        controller.write(header(LinkMessageType::LinkUp), &mut bytes),
        Err(LinkError::NetOriginFromController)
    );
    let device_id = Extra::Bytes(b"ORIGIN89 DEMO 01");
    assert_eq!(
        decoded(&raw_link_up(
            Side::Controller,
            &[(8, device_id), (9, origin)]
        ))
        .err(),
        Some(LinkError::NetOriginFromController)
    );

    assert_eq!(
        decoded(&raw_link_up(
            Side::Comms,
            &[(7, Extra::Number(3)), (9, Extra::Bytes(&[0x5A; 7]))]
        ))
        .err(),
        Some(LinkError::OriginNotEight(7))
    );
    let fine = raw_link_up(Side::Comms, &[(7, Extra::Number(3)), (9, origin)]);
    let up = decoded(&fine).expect("a written cache with its token");
    assert_eq!((up.net_version, up.net_origin), (Some(3), Some(HOME)));
}

/// A comms `LinkUp` carrying a token, cut at every length: never read as a
/// cache with no token, which L-133 would push, or as one with a token it did
/// not send.
///
/// cites: L-132
#[test]
fn l_132_every_truncation_of_a_link_up_with_its_origin_is_refused() {
    let up = reporting(Some(3), Some(HOME));
    let mut bytes = [0; 256];
    let len = up
        .write(header(LinkMessageType::LinkUp), &mut bytes)
        .expect("it encodes");
    for end in 0..len {
        if let Ok(envelope) = LinkEnvelope::decode(&bytes[..end]) {
            assert!(LinkUp::decode(envelope).is_err(), "cut at {end}");
        }
    }
    let envelope = LinkEnvelope::decode(&bytes[..len]).expect("an envelope");
    assert_eq!(LinkUp::decode(envelope), Ok(up));
}
