//! The session classification against the column that allocates it.
//!
//! `admission.rs` is a hand-written match, deliberately, so a new message type
//! breaks it and somebody has to answer whether the thing they are adding is
//! part of the handshake. What that costs is a second place the fact lives:
//! `protocol.toml` already carries `auth_request` per message, and the two can
//! drift with nothing saying so — which is the defect the registry's own note
//! describes, *the registry's column and the rules in the specification once
//! said the same thing in two vocabularies and agreed only by luck*.
//!
//! So this reads the registry and compares. Not a parser — a scan, because a
//! dev-dependency on a TOML crate here is an allocator in the one crate whose
//! no-`alloc` claim is compiler-enforced, and the shape being read is four
//! lines of `key = value`.
//!
//! cites: P-143

use km43::{Admits, MessageType};

const REGISTRY: &str = include_str!("../protocol.toml");

/// One `[[messages]]` table, as the fields this test cares about.
struct Allocated {
    request: Option<u8>,
    auth_request: Option<String>,
    status: String,
}

/// Every `[[messages]]` table, read by scanning rather than parsing.
fn messages() -> Vec<Allocated> {
    let mut out = Vec::new();
    for block in REGISTRY.split("[[messages]]").skip(1) {
        // A table ends where the next one begins, and the next `[[` or `[`
        // heading is what marks it.
        let block = block.split("\n[").next().unwrap_or_default();
        let field = |name: &str| -> Option<String> {
            block.lines().find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key.trim() == name).then(|| value.trim().trim_matches('"').to_owned())
            })
        };
        out.push(Allocated {
            request: field("request")
                .and_then(|v| u8::from_str_radix(v.trim_start_matches("0x"), 16).ok()),
            auth_request: field("auth_request"),
            status: field("status").unwrap_or_default(),
        });
    }
    out
}

/// **The registry's `auth_request` and this crate's match must agree about
/// every message, or one of them is describing a protocol nobody implements.**
///
/// `none` and `handshake` are the two that run before a session exists: no key
/// at all, and a Noise handshake message that authenticates itself. `sealed`
/// and `signed` both require one — the first is sealed under the session's
/// keys, and the second is that plus a counter, which is a session's counter.
///
/// Watched by flipping `Concerns`' `auth_request` to `handshake` in `protocol.toml`:
/// this goes red naming the message, while every other check in the repo stays
/// green, because nothing else reads that column against anything.
#[test]
fn p_143_the_registry_and_this_crate_agree_about_what_needs_a_session() {
    let mut seen = 0;
    for message in messages() {
        // A retired message has no `MessageType` variant to classify — the
        // generator drops it, which is what retirement means here.
        if message.status == "retired" {
            continue;
        }
        let (Some(opcode), Some(auth)) = (message.request, message.auth_request.as_deref()) else {
            continue;
        };
        let kind = MessageType::try_from(opcode)
            .unwrap_or_else(|()| panic!("0x{opcode:02X} is allocated and has no MessageType"));

        let want = match auth {
            "none" | "handshake" => Admits::WithoutSession,
            "sealed" | "signed" => Admits::OnlyWithSession,
            other => panic!("{kind:?} has auth_request {other:?}, which classifies nothing"),
        };
        assert_eq!(
            kind.admits(),
            want,
            "{kind:?} is `{auth}` in protocol.toml and {:?} in admission.rs",
            kind.admits()
        );
        seen += 1;
    }
    assert!(
        seen >= 15,
        "only {seen} request types were compared, so this test has stopped reading the registry"
    );
}

/// Every response opcode the registry allocates classifies as not a request.
///
/// The count is asserted for the same reason: a scan that quietly matched
/// nothing would pass this file and prove nothing, which is how a check reports
/// full coverage over an empty list.
#[test]
fn p_143_every_allocated_response_is_not_a_request() {
    let mut seen = 0;
    for block in REGISTRY.split("[[messages]]").skip(1) {
        let block = block.split("\n[").next().unwrap_or_default();
        let value = |name: &str| -> Option<String> {
            block.lines().find_map(|line| {
                let (key, v) = line.split_once('=')?;
                (key.trim() == name).then(|| v.trim().trim_matches('"').to_owned())
            })
        };
        if value("status").as_deref() == Some("retired") {
            continue;
        }
        let Some(opcode) =
            value("response").and_then(|v| u8::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        else {
            continue;
        };
        let kind = MessageType::try_from(opcode)
            .unwrap_or_else(|()| panic!("0x{opcode:02X} is allocated and has no MessageType"));
        assert_eq!(kind.admits(), Admits::NotARequest, "{kind:?}");
        seen += 1;
    }
    assert!(seen >= 15, "only {seen} responses were compared");
}
