//! The consumer's failing case, made to compile.
//!
//! A `no_std` consumer that logs with `defmt` derives `Format` on a row that
//! holds a `ClientId`, and without the feature the answer is E0277 with
//! nothing to do about it but a hand-written impl per wrapper or
//! `Debug2Format`, which formats on the target and costs flash the controller
//! does not have. This file is that derive, on the types the controller's
//! tables wrap, so a type that quietly loses its `Format` fails here rather
//! than in the firmware's build.
#![cfg(feature = "defmt")]

use km43::{
    ClientCapability, ClientId, ClientKind, Counter, Epoch, ErrorCode, EventKind, LinkError,
    MessageType, Outcome, ReqId, SessionId, SignedError,
};

/// The shape of a client-table row: every field is a `km43` type, and the
/// derive is the whole test.
#[derive(defmt::Format)]
struct Row {
    who: ClientId,
    minted_under: Epoch,
    kind: ClientKind,
    may: ClientCapability,
    last: Counter,
}

/// The shape of a dedup entry and a refusal, which is what the firmware logs
/// when a frame is turned away.
#[derive(defmt::Format)]
enum Because {
    Signed(SignedError),
    Link(LinkError),
    Answered(Outcome, ErrorCode),
    Seen(MessageType, SessionId, ReqId, EventKind),
}

#[test]
fn a_row_of_identifiers_derives_format_without_a_hand_written_impl() {
    let row = Row {
        who: ClientId::new(3).expect("3 is a slot"),
        minted_under: Epoch::FIRST,
        kind: ClientKind::App,
        may: ClientCapability::SEND_COMMAND,
        last: Counter(1),
    };
    // `Format` has no output to assert on the host; the derive compiling is
    // the witness, and moving the value proves the row is built.
    let _ = row;
}

#[test]
fn a_refusal_enum_over_link_and_signed_errors_derives_format() {
    let because = [
        Because::Signed(SignedError::WrongClient {
            bound: ClientId::new(1).expect("1 is a slot"),
            body: ClientId::new(2).expect("2 is a slot"),
        }),
        Because::Link(LinkError::Missing(km43::LinkField::Fw)),
        Because::Answered(Outcome::WindowClosed, ErrorCode::MalformedFrame),
        Because::Seen(
            MessageType::Hello,
            SessionId::None,
            ReqId(0),
            EventKind::SIGNAL_VALIDITY_CHANGED,
        ),
    ];
    assert_eq!(because.len(), 4);
}
