//! The charge stages, from a vendor's stage register to the reading a client
//! draws.
//!
//! A charger's stage is an answer, not a measurement, and the failure worth
//! testing is the confident wrong one: Victron's `CS` 245 is *starting up*, a
//! state with no member here, and a controller that published 245 under `ok`,
//! or a client that picked the nearest stage it holds, would draw a stage over
//! a bank that is doing something else.

use km43::{CborReader, CborWriter, QualityError};
use km43::{
    ChargeStage, Concern, ConcernState, Condition, EnumSpace, Id, Meaning, Part, Sample, Severity,
    SignalQuality, Subject, Validity, VendorCode, VendorNamespace,
};

/// Victron VE.Direct `CS` 245, *starting up*. Named in the owner's decision as
/// a vendor state the normalized set leaves out on purpose.
const VICTRON_STARTING_UP: u32 = 245;

fn id(n: u16) -> Id {
    Id::new(n).expect("a non-zero id")
}

/// The sample a controller publishes for a stage its registry cannot name, and
/// the same sample read back off the wire.
fn unnamed_sample() -> Sample {
    let q = SignalQuality::absent(Validity::UnnamedState).expect("unnamed_state carries nothing");
    let sample = Sample::new(id(31), q, None, None).expect("unnamed_state with no value is legal");
    let mut dst = [0u8; 16];
    let mut cbor = CborWriter::new(&mut dst);
    sample.encode(&mut cbor).expect("one sample encodes");
    let len = cbor.finish().expect("a whole item");
    let mut body = CborReader::new(dst.get(..len).expect("within the buffer"));
    Sample::decode(&mut body).expect("the published sample decodes")
}

/// Every member the registry allocated is one this build names, which is the
/// join by name between `[[open_registries.enum_space]]` "charge stage" and
/// `[[enums.charge_stage]]`. Had the table been written under another name, the
/// space would have come out empty and every charger would read
/// `unnamed_state` at every poll.
#[test]
fn every_charge_stage_is_named_by_its_space() {
    for stage in [
        ChargeStage::Off,
        ChargeStage::Bulk,
        ChargeStage::Absorption,
        ChargeStage::Float,
        ChargeStage::Equalise,
        ChargeStage::Storage,
        ChargeStage::Fault,
    ] {
        let value = i32::from(stage as u8);
        assert!(EnumSpace::CHARGE_STAGE.names(value), "{stage:?}");
        assert_eq!(
            Meaning::of(Some(value), Some(EnumSpace::CHARGE_STAGE)),
            Meaning::Named(value)
        );
    }
    assert_eq!(
        EnumSpace::CHARGE_STAGE.members().map(<[i32]>::len),
        Some(7),
        "a member the space names and the enum does not, or the reverse"
    );
}

/// The sample P-164 asks for, for a vendor stage with no member: 245 is not a
/// charge stage the registry names, an `unnamed_state` sample reads back with
/// no value, and one that tried to carry 245 anyway is refused before it is
/// encoded.
///
/// This checks the shapes the crate gives a controller, not the controller's
/// choice to use them. Deciding to publish `unnamed_state` and raise the
/// concern is the dialect's, in origin89, and P-164 stays uncovered here until
/// something in this tree makes that decision.
#[test]
fn a_vendor_stage_with_no_member_has_no_value_slot_on_the_wire() {
    let raw = i32::try_from(VICTRON_STARTING_UP).expect("fits");
    assert!(!EnumSpace::CHARGE_STAGE.names(raw));
    assert!(ChargeStage::try_from(u8::try_from(raw).expect("fits a u8")).is_err());

    let read = unnamed_sample();
    assert_eq!(read.q.validity_of(), Validity::UnnamedState);
    assert_eq!(
        read.value(),
        None,
        "an unnamed stage came back with a number"
    );

    let q = SignalQuality::absent(Validity::UnnamedState).expect("legal");
    assert_eq!(
        Sample::new(id(31), q, Some(raw), None).unwrap_err(),
        QualityError::NoValueToCarry(Validity::UnnamedState),
        "unnamed_state was handed the vendor's code as its value"
    );
}

/// The vendor's code is not lost: a concern carrying it, with the namespace
/// that says whose 245 it is, survives the trip to the client unchanged.
#[test]
fn a_vendor_stage_concern_keeps_its_raw_code_and_namespace_on_the_wire() {
    let concern = Concern {
        cid: id(14),
        subject: Subject::Part(Part::device(id(5))),
        cond: Condition::UNNAMED_STATE,
        sev: Severity::Warning,
        state: ConcernState::Active,
        age: 60,
        since: None,
        code: Some(VendorCode {
            raw: VICTRON_STARTING_UP,
            vns: VendorNamespace::VICTRON,
        }),
        seq: 812,
    };
    let mut dst = [0u8; 64];
    let mut cbor = CborWriter::new(&mut dst);
    concern.encode(&mut cbor).expect("the row encodes");
    let len = cbor.finish().expect("a whole item");

    let read = Concern::decode(dst.get(..len).expect("within the buffer")).expect("decodes");
    assert_eq!(read.cond, Condition::UNNAMED_STATE);
    assert_eq!(
        read.code,
        Some(VendorCode {
            raw: VICTRON_STARTING_UP,
            vns: VendorNamespace::VICTRON,
        }),
        "the vendor's own code or its namespace was lost on the way"
    );
}

/// **P-125** — a client older than the controller that answered it meets a
/// stage its build has no member for. It surfaces that reading as
/// unrecognised and keeps the integer for a bench log; it never draws the
/// nearest stage, and never a bare number.
#[test]
fn p_125_a_charge_stage_this_build_cannot_name_is_unrecognised_with_its_value_kept() {
    let space = Some(EnumSpace::CHARGE_STAGE);
    for unknown in [0, 8, 245] {
        let meaning = Meaning::of(Some(unknown), space);
        assert_eq!(meaning, Meaning::Unrecognised(unknown));
        assert_eq!(meaning.raw(), Some(unknown));
    }
    assert_eq!(
        Meaning::of(Some(4), space),
        Meaning::Named(4),
        "the boundary between named and unrecognised moved"
    );
    // A reading published `unnamed_state` has nothing to interpret at all.
    assert_eq!(
        Meaning::of(unnamed_sample().value(), space),
        Meaning::Nothing
    );
}
