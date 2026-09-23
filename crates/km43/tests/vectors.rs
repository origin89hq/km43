//! The crate against the published vectors, which is the one comparison the
//! rest of the suite cannot make.
//!
//! `docs/protocol/vectors/v1.json` is produced by `xtask`, which
//! `cargo xtask check` forbids from depending on this crate — so the two are
//! independent implementations of the same spec. That independence was already
//! enforced and the *agreement* was checked by nobody: the generator could move
//! the artefact and every test in the crate would stay green.
//!
//! cites: P-011, P-013, P-016, P-001, P-038

use km43::{
    Attempt, BOOT_MAX_BYTES, Boot, BootCause, CONCERN_MAX_BYTES, Caps, CborReader, CborWriter,
    ClientId, ClientKind, Closed, CmdList, Concern, ConcernChanged, ConcernRaised, ConcernRows,
    ConcernState, ConcernsBody, ConcernsHeader, ConcernsOutcome, ConcernsPage, Condition, Counter,
    DeviceId, DeviceSecret, Discovery, ElementAt, Enrolment, Envelope, Epoch, ErrorBody,
    ErrorBodyError, ErrorCode, Event, EventKind, Handshake, Header, HelloClaim, HelloInner,
    HelloReport, Id, Incoming, InventoryHeader, InventoryOutcome, LogEntry, LogPage, LogSeq,
    MAX_DISCOVER_BODY, MAX_FRAME, MAX_HELLO_INNER, MAX_HELLO_REPORT, MAX_LOG_PAGE_BYTES,
    MAX_PAIR_ACK_BODY, MAX_PAIR_BODY, MAX_PAYLOAD, MAX_SERIES_LEN, MessageType, Outcome, Page,
    Pair, PairAck, PairAckClaim, PairClaim, PairProof, PairRequest, PairResponse, PanicSite, Part,
    PresenceChanged, PrintedSecret, Provenance, ReadConcerns, ReadInventory, ReadLog, ReadSignals,
    ReadingsBody, ReadingsHeader, ReadingsOutcome, ReadingsPage, ReqId, Row, RowKind, RowSlots,
    SAMPLE_MAX_BYTES, SERIES_MAX_BYTES, Sample, Sel, Series, Session, SessionId, SessionKey,
    Severity, SignalQuality, Signed, SignedClaim, SignedKey, StateSeq, Subject, Tagged,
    TopologyChangeReason, TopologyChanged, Validity, ValidityChanged, Value, VendorCode,
    VendorNamespace, Version, Wrapped, Wrapper,
};

const VECTORS: &str = include_str!("../../../docs/protocol/vectors/v1.json");

/// The hex blobs under a given key, without a JSON parser.
///
/// A dev-dependency on `serde_json` is the obvious route and it drags an
/// allocator into the one crate whose no-`alloc` claim is compiler-enforced.
/// The blobs are hex under known keys, so finding them is a scan.
fn blobs(key: &str) -> Vec<Vec<u8>> {
    let needle = format!("\"{key}\": \"");
    VECTORS
        .match_indices(&needle)
        .filter_map(|(at, _)| {
            let from = at.checked_add(needle.len())?;
            let rest = VECTORS.get(from..)?;
            let end = rest.find('"')?;
            let hex = rest.get(..end)?;
            if hex.is_empty() || hex.len() % 2 != 0 {
                return None;
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(hex.get(i..i.checked_add(2)?)?, 16).ok())
                .collect()
        })
        .collect()
}

/// Every CBOR body the generator published must parse here, whole, with nothing
/// left over. A body this reader cannot walk is one the two implementations
/// disagree about, and the disagreement would otherwise wait for a bench.
#[test]
fn every_published_body_is_one_this_reader_walks_to_the_end() {
    let mut seen = 0;
    for key in [
        "inner_body_cbor",
        "operation_cbor",
        "full_body_cbor",
        "body_cbor",
    ] {
        for bytes in blobs(key) {
            let mut reader = CborReader::new(&bytes);
            reader.skip().unwrap_or_else(|e| panic!("{key}: {e}"));
            reader
                .finish()
                .unwrap_or_else(|e| panic!("{key}: trailing bytes: {e}"));
            seen += 1;
        }
    }
    assert_eq!(seen, 36, "the vector file grew or shrank a body");
}

/// The envelope the generator publishes must decode here to the same four
/// fields. It is the only place the envelope meets bytes it did not build.
#[test]
fn the_published_envelope_decodes_to_the_fields_the_generator_wrote() {
    let found = blobs("envelope_cbor");
    let bytes = found.first().expect("one envelope vector");
    let envelope = Envelope::decode(bytes).expect("the published envelope decodes");
    let header = envelope.header();
    assert_eq!(header.req_id, ReqId(17));
    let three = SessionId::from(3);
    assert_eq!(header.session, three, "the handle the generator stamped in");
}

/// The published MAC tags, recomputed by this crate.
///
/// The crate's own MAC tests compare one tag against another and never against
/// the file — the hex literals `mac.rs` once carried were a restatement rather
/// than an outside opinion, green while the generator truncated from the
/// right. Change the generator that way, regenerate, and this is the test that
/// goes red.
#[test]
fn every_published_tag_is_one_this_crate_recomputes() {
    let key = session_key();

    let tags = blobs("out16");
    assert_eq!(tags.len(), 8, "the vector file grew or shrank a MAC");
    let bodies = blobs("inner_body_cbor");

    // The tags, by index in the order the file writes them: pair_proof 0,
    // pair_ack 1, hello_proof 2, signed_request 3, wrapper_request 4,
    // response 5, event 6, error_response 7. The last is recomputed by name
    // in `the_published_wrapped_error_is_one_this_crate_signs_and_refuses_to_read_bare`,
    // beside the receiver's rule it exists to pin.
    //
    // This comment counted from one and said wrapper_request was "the fourth
    // MAC". It is the fifth; the fourth is signed_request, the one nothing
    // recomputed. `response` and `event` were right, so the sentence was not a
    // consistent off-by-one — it was the missing tag showing up as a wrong
    // ordinal in the one place a reader would have looked for it.
    let cases = [
        (4_usize, 1_usize, MessageType::ReadLog, 17_u32),
        (5, 2, MessageType::CommandResponse, 17),
    ];
    for (tag_at, body_at, kind, req_id) in cases {
        let payload = bodies.get(body_at).expect("an inner body");
        let want = tags.get(tag_at).expect("a published tag");
        let fields = Wrapped {
            kind,
            session: SessionId::from(3),
            req_id: ReqId(req_id),
            payload,
        };
        let tag = if tag_at == 4 {
            key.wrapper_request(&fields)
        } else {
            key.response(&fields)
        };
        tag.verify(want)
            .unwrap_or_else(|e| panic!("published tag {tag_at} is not what we compute: {e}"));
    }

    let event_body = bodies.get(3).expect("the event body");
    let want = tags.get(6).expect("the event tag");
    key.event(SessionId::from(3), event_body)
        .verify(want)
        .expect("the published event tag is not what we compute");
}

/// A fixed-width input, read out of the vector file.
fn fixed<const N: usize>(key: &str) -> [u8; N] {
    let found = blobs(key);
    let bytes = found
        .first()
        .unwrap_or_else(|| panic!("{key} is published"));
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is not {N} bytes"))
}

/// The device the `inputs` block describes: the printed secret and the
/// `device_id` every key in the file hangs off.
fn device() -> DeviceSecret {
    DeviceSecret::new(
        DeviceId::new(fixed("device_id")),
        PrintedSecret::new(fixed("printed_secret")),
    )
}

/// Epoch 1, slot 7 — the enrolment the published `client_key` was derived for.
fn enrolment() -> Enrolment {
    device().enrolment(
        Epoch::new(1).expect("the published epoch"),
        ClientId::new(7).expect("the published slot"),
    )
}

/// The two nonces that salt the session key, one from each end.
fn handshake() -> Handshake {
    Handshake {
        challenge: fixed("challenge"),
        client_nonce: fixed("client_nonce"),
    }
}

/// The session key, derived the way a controller derives it, from the inputs the
/// vector file publishes.
///
/// It used to read `derived_keys[1].out` — the answer — straight out of the file
/// it is checking, which pinned the tags and left the whole derivation ladder
/// unpinned. Coming through `DeviceSecret` means dropping `epoch` from the
/// client-key info, or swapping HKDF's salt and IKM, moves these tags.
fn session_key() -> SessionKey {
    enrolment().session_key(&handshake(), SessionId::from(3))
}

/// The three MACs the wrapper path does not reach: both pairing tags and the
/// `Hello` proof.
///
/// This paragraph said *four*, and *tags 0 to 3*, over a test that recomputes
/// 0, 1 and 2. The fourth it was counting is the signed request's, which the
/// test below now drives — and until that one existed the comment was
/// describing coverage the file did not have, which is the shape of mistake
/// this whole file exists to catch in the vectors.
#[test]
fn the_pairing_and_hello_tags_are_ones_this_crate_recomputes_too() {
    let tags = blobs("out16");
    let device_id: [u8; 16] = fixed("device_id");
    let challenge: [u8; 16] = fixed("challenge");
    let client_nonce: [u8; 16] = fixed("client_nonce");
    let next_challenge: [u8; 16] = fixed("next_challenge");

    let pair = device().pair_key();

    pair.proof(&PairProof {
        device_id: &device_id,
        challenge: &challenge,
        client_nonce: &client_nonce,
        client_kind: ClientKind::App,
        label: "kitchen phone",
    })
    .verify(tags.first().expect("the pair proof tag"))
    .expect("the published pair proof is not what we compute");

    pair.ack(&PairAck {
        device_id: &device_id,
        challenge: &challenge,
        client_nonce: &client_nonce,
        outcome: Pair::Enrolled,
        client_id: 7,
        epoch: 1,
        next_challenge: &next_challenge,
    })
    .verify(tags.get(1).expect("the pair ack tag"))
    .expect("the published pair ack is not what we compute");

    // The payload comes from this crate's encoder, not from the file. Feeding
    // the published body in and checking only the tag leaves the encoder — the
    // key numbers, the widths, the map order of the one body a proof is
    // computed over — pinned by nothing outside the crate.
    let bodies = blobs("inner_body_cbor");
    let mut scratch = [0u8; MAX_HELLO_INNER];
    let request = HelloInner {
        version: Version::V1_0,
        client_id: ClientId::new(7).expect("the published slot"),
        client_version: "o89-cli 0.1.0",
        client_nonce,
    }
    .prove(&enrolment().client_key(), &challenge, &mut scratch)
    .expect("the published inner body encodes");

    let published = bodies.first().expect("the hello body");
    assert_eq!(
        request.payload(),
        published.as_slice(),
        "this encoder and the published inner body have parted company"
    );
    request
        .proof()
        .verify(tags.get(2).expect("the hello proof tag"))
        .expect("the published hello proof is not what we compute");

    // And the other direction over the same bytes. The frame written here
    // carries the payload just asserted equal to the published body, so
    // decoding it back through the claim is decoding the published bytes: the
    // fields come out as the generator wrote them, and the encoder and the
    // decoder are not simply wrong together.
    let header = Header {
        kind: MessageType::Hello,
        session: SessionId::from(3),
        req_id: ReqId(17),
    };
    let mut frame = [0u8; MAX_PAYLOAD];
    let len = request
        .write(header, &mut frame)
        .expect("the published hello fits a payload");
    let envelope = Envelope::decode(frame.get(..len).expect("the writer's own length"))
        .expect("the frame this crate wrote decodes");
    let accepted = HelloClaim::decode(envelope)
        .expect("the frame names a Hello")
        .verify(&enrolment().client_key(), &challenge, Version::V1_0)
        .expect("the published proof verifies over the published body");
    assert_eq!(
        accepted.inner,
        HelloInner {
            version: Version::V1_0,
            client_id: ClientId::new(7).expect("the published slot"),
            client_version: "o89-cli 0.1.0",
            client_nonce,
        },
        "the published inner body does not decode to the fields the generator wrote"
    );
}

/// The bodies under `bodies`, in the order the file writes them: the
/// `Discover 0x80`, the `Hello 0x81`, the `Inventory 0x8D`, the
/// `Readings 0x8E`, the `Concerns 0x8F`, the six event bodies — the two
/// concern records `0x0501` and `0x0502`, then `0x0102`, `0x0901` and `0x0902`,
/// then the boot record `0x0601`, followed by nine controller-record examples —
/// and the five read by name rather than by position: `Pair 0x0B`,
/// `Pair 0x8B`, the bare `Error 0xFF`, `ReadLog 0x05` and `LogPage 0x85`.
///
/// Asserted rather than assumed, so a file that lost one does not hand the
/// wrong bytes to whichever test still finds something at index 0. The count
/// going red when a body lands is the point — it is what made somebody read
/// this comment, which had gone on naming `Snapshot 0x82` for several commits
/// after that message was retired.
fn published_bodies() -> Vec<Vec<u8>> {
    let found = blobs("body_cbor");
    assert_eq!(found.len(), 25, "the vector file grew or shrank a body");
    found
}

/// What a `Discover 0x80` wears in front of its body, spelled out rather than
/// asked of the encoder that is on trial here: `array(4)`, type `0x80`, the
/// published `session_id` of 3 and the published `req_id` of 17.
///
/// The generator publishes the body alone, so this head is this test's own
/// choice. Comparing it separately means a `Discovery::write` that put a field
/// in the wrong place fails at the head or at the body, and says which.
const DISCOVER_HEAD: [u8; 5] = [0x84, 0x18, 0x80, 0x03, 0x11];

/// The `Discover 0x80` body this crate writes, against the one the generator
/// published.
///
/// Nothing outside the crate pinned it before. `Discover` is the one message
/// with no MAC (P-054), so a key number, a `bool` written as `0xF5`/`0xF4`, or
/// the epoch P-087 put at key 8 could all move here and every MAC test in this
/// file would stay green — the tags are computed over other bodies entirely.
#[test]
fn the_published_discover_body_is_the_one_this_encoder_writes() {
    let bodies = published_bodies();
    let want = bodies.first().expect("the Discover 0x80 body");

    let mut buf = [0u8; DISCOVER_HEAD.len() + MAX_DISCOVER_BODY];
    let len = Discovery {
        version: Version::V1_0,
        device_id: fixed("device_id"),
        model: "Origin89 CTRL-1 (G0B1)",
        provisioned: false,
        pairing_open: true,
        challenge: fixed("challenge"),
        epoch: Epoch::new(1).expect("the published epoch"),
    }
    .write(
        Header {
            kind: MessageType::DiscoverResponse,
            session: SessionId::from(3),
            req_id: ReqId(17),
        },
        &mut buf,
    )
    .expect("the published Discover 0x80 encodes");
    let written = buf.get(..len).expect("the length came from the writer");

    assert_eq!(
        written.get(..DISCOVER_HEAD.len()),
        Some(DISCOVER_HEAD.as_slice()),
        "the envelope this crate writes is not [0x80, 3, 17, …]"
    );
    assert_eq!(
        written.get(DISCOVER_HEAD.len()..),
        Some(want.as_slice()),
        "this encoder and the published Discover 0x80 body have parted company"
    );
}

/// The published `Discover 0x80`, read back by the decoder that will meet one on
/// a wire.
///
/// The encoder test above would stay green if both sides of this crate had
/// agreed on a wrong key number, because it only ever compares what the crate
/// wrote. This one starts from bytes the crate did not produce.
#[test]
fn the_published_discover_body_reads_back_to_the_fields_the_generator_wrote() {
    let bodies = published_bodies();
    let want = bodies.first().expect("the Discover 0x80 body");

    let mut frame = [0u8; DISCOVER_HEAD.len() + MAX_DISCOVER_BODY];
    let len = DISCOVER_HEAD.len().saturating_add(want.len());
    frame
        .get_mut(..DISCOVER_HEAD.len())
        .expect("room for the head")
        .copy_from_slice(&DISCOVER_HEAD);
    frame
        .get_mut(DISCOVER_HEAD.len()..len)
        .expect("room for the published body")
        .copy_from_slice(want);

    let envelope =
        Envelope::decode(frame.get(..len).expect("the frame we just built")).expect("it decodes");
    let read = Discovery::decode(envelope).expect("the published Discover 0x80 decodes");

    assert_eq!(read.version, Version::V1_0, "the two version bytes moved");
    assert_eq!(read.device_id, fixed("device_id"), "key 3 moved");
    assert_eq!(read.model, "Origin89 CTRL-1 (G0B1)", "key 4 moved");
    assert!(!read.provisioned, "key 5 is published false");
    assert!(read.pairing_open, "key 6 is published true");
    assert_eq!(read.challenge, fixed("challenge"), "key 7 moved");
    assert_eq!(read.epoch.get(), 1, "P-087's epoch moved");
}

/// A text the `inputs` block publishes, read out of the file rather than
/// retyped, so the firmware strings can change shape without this file
/// quietly asserting the old ones.
fn input_text(key: &str) -> &'static str {
    strings_of(object("inputs"), key)
        .first()
        .copied()
        .unwrap_or_else(|| panic!("`inputs` publishes no `{key}`"))
}

/// The seventeen fields the `inputs` block describes, typed.
///
/// The caps come from `Caps::THIS_CONTROLLER` rather than from six literals:
/// P-005 says the controller reports the numbers it enforces, so a `limits.rs`
/// that raised `MAX_INFLIGHT` without the generator hearing about it is a client
/// being promised a cap nobody keeps, and this is where the two part company.
fn published_report() -> HelloReport<'static> {
    HelloReport {
        topology: km43::Topology::THIS_CONTROLLER,
        version: Version::V1_0,
        session: SessionId::from(3),
        fw_controller: input_text("fw_controller"),
        fw_comms: input_text("fw_comms"),
        capabilities: 0xf7,
        log_oldest_seq: LogSeq(1),
        log_newest_seq: LogSeq(256),
        state_seq: StateSeq(255),
        time_known: true,
        counter: 65,
        caps: Caps::THIS_CONTROLLER,
    }
}

/// The `Hello 0x81` body this crate writes, against the one the generator
/// published.
///
/// Seventeen keys, four of them `u64` and two texts of 23 and 24 bytes, either
/// side of the length where a string head grows: every one is a chance for the
/// two implementations to have picked a different CBOR head width, and none of
/// them is covered by a MAC in this file.
#[test]
fn the_published_hello_0x81_body_is_the_one_this_encoder_writes() {
    let bodies = published_bodies();
    let want = bodies.get(1).expect("the Hello 0x81 body");

    let mut buf = [0u8; MAX_HELLO_REPORT];
    let len = published_report()
        .encode(&mut buf)
        .expect("the published Hello 0x81 encodes");

    assert_eq!(
        buf.get(..len),
        Some(want.as_slice()),
        "this encoder and the published Hello 0x81 body have parted company"
    );
}

/// The published `Hello 0x81`, read back the only way a client can reach one:
/// through [`Session::open`], which derives the key off the envelope and checks
/// the wrapper MAC before the body is legible at all (P-072).
///
/// So this pins more than the seventeen keys. The wrapper the body travels
/// under carries a tag under the `rsp` label the vector file names, and a
/// `session_id` in key 3 that did not match the envelope's would be refused
/// rather than believed.
#[test]
fn the_published_hello_0x81_body_reads_back_to_the_fields_the_generator_wrote() {
    let bodies = published_bodies();
    let want = bodies.get(1).expect("the Hello 0x81 body");

    let header = Header {
        kind: MessageType::HelloResponse,
        session: SessionId::from(3),
        req_id: ReqId(17),
    };
    let tag = session_key().response(&Wrapped {
        kind: header.kind,
        session: header.session,
        req_id: header.req_id,
        payload: want,
    });

    // Keys 1 and 2 written as the numbers P-050 fixes them at, not as the
    // crate's own constants — a wrapper that renumbered itself would otherwise
    // renumber this test with it.
    let mut frame = [0u8; MAX_PAYLOAD];
    let mut cbor = header.write(2, &mut frame).expect("the wrapper map opens");
    cbor.key(1).expect("the payload key");
    cbor.bytes(want).expect("the published body fits");
    cbor.key(2).expect("the mac key");
    cbor.bytes(tag.as_bytes()).expect("the tag fits");
    let len = cbor.finish().expect("the wrapper closes");

    let envelope =
        Envelope::decode(frame.get(..len).expect("the frame we just built")).expect("it decodes");
    let session = Session::open(envelope, &enrolment(), &handshake(), Version::V1_0)
        .expect("the published Hello 0x81 opens a session");
    let read = session.report();

    assert_eq!(session.version(), Version::V1_0, "P-073 agreed on 1.0");
    assert_eq!(read.session, SessionId::from(3), "key 3 moved");
    assert_eq!(
        read.fw_controller,
        input_text("fw_controller"),
        "key 4 moved"
    );
    assert_eq!(read.fw_comms, input_text("fw_comms"), "key 5 moved");
    assert_eq!(read.capabilities, 0xf7, "key 6 moved");
    assert_eq!(read.log_oldest_seq, LogSeq(1), "key 7 moved");
    assert_eq!(read.log_newest_seq, LogSeq(256), "key 8 moved");
    // 255 sitting beside 256 is the trap P-074 names: two sequence spaces that
    // look alike in a hex dump. A decoder that read key 9 into a `LogSeq` would
    // not fail here, so the types are what stand behind it — this assert is the
    // reminder that the compiler is doing the work.
    assert_eq!(read.state_seq, StateSeq(255), "key 9 moved");
    assert!(read.time_known, "key 10 is published true");
    assert_eq!(
        read.counter, 65,
        "key 11 is the last counter accepted, one below the signed request's 66"
    );
    assert_eq!(read.caps, Caps::THIS_CONTROLLER, "keys 12 to 17 moved");
    assert_eq!(
        *read,
        published_report(),
        "a field the asserts above do not name has moved"
    );
}

/// The four bytes a signed `Command 0x08` wears in front of its body: `array(4)`,
/// the type inline because `0x08` is below the CBOR ceiling, then the published
/// `session_id` of 3 and `req_id` of 17.
const SIGNED_HEAD: [u8; 4] = [0x84, 0x08, 0x03, 0x11];

/// The published signed request, both ways: the bytes this crate writes, and the
/// tag it recomputes from the bytes the generator published.
///
/// `macs.signed_request.out16` was the one tag in the file that nothing checked.
/// It was counted — `tags.len() == 7` — and never verified, so its only witness
/// was a hex literal transcribed into `mac.rs`, the module that computes it. Set
/// it to sixteen zero bytes and the whole suite stayed green.
#[test]
fn the_published_signed_request_is_the_one_this_crate_signs_and_reads() {
    let tags = blobs("out16");
    let want_tag = tags.get(3).expect("the signed request tag");
    let operations = blobs("operation_cbor");
    let operation = operations.first().expect("the published operation");
    // `full_body_cbor` is published by five of the eight MACs — the three
    // pairing/hello tags carry no body — so in file order it is
    // signed_request 0, wrapper_request 1, response 2, event 3,
    // error_response 4. Not the same index as `out16`, which all eight carry.
    let bodies = blobs("full_body_cbor");
    let want_body = bodies.first().expect("the signed request full body");

    let header = Header {
        kind: MessageType::Command,
        session: SessionId::from(3),
        req_id: ReqId(17),
    };
    let client = ClientId::new(7).expect("the published enrolment");

    // Written: the envelope head this test spells out, then the published body.
    let signed = Signed::over(header, client, Counter(66), operation, &session_key())
        .expect("the published signed request signs");
    signed
        .mac()
        .verify(want_tag)
        .expect("the published signed request tag is not what we compute");

    let mut frame = [0u8; MAX_PAYLOAD];
    let len = signed.write(&mut frame).expect("it fits a payload");
    let written = frame.get(..len).expect("the writer's own length");
    assert_eq!(
        written.get(..SIGNED_HEAD.len()),
        Some(SIGNED_HEAD.as_slice()),
        "the envelope this crate writes is not [0x08, 3, 17, …]"
    );
    assert_eq!(
        written.get(SIGNED_HEAD.len()..),
        Some(want_body.as_slice()),
        "this encoder and the published signed body have parted company"
    );

    // Read: from the published bytes, through both of P-080's checks, to the
    // operation — which is reachable nowhere else.
    let mut arrived = [0u8; MAX_PAYLOAD];
    let end = SIGNED_HEAD.len().saturating_add(want_body.len());
    arrived
        .get_mut(..SIGNED_HEAD.len())
        .expect("room for the head")
        .copy_from_slice(&SIGNED_HEAD);
    arrived
        .get_mut(SIGNED_HEAD.len()..end)
        .expect("room for the published body")
        .copy_from_slice(want_body);

    let envelope =
        Envelope::decode(arrived.get(..end).expect("the frame we just built")).expect("it decodes");
    let fresh = SignedClaim::decode(envelope)
        .expect("the published signed body decodes")
        .verify(&session_key(), client)
        .expect("the published tag does not check out")
        .fresh(Counter(65))
        .expect("66 is ahead of the 65 Hello 0x81 key 11 publishes");

    assert_eq!(fresh.counter(), Counter(66), "key 2 moved");
    assert_eq!(fresh.operation(), operation.as_slice(), "key 3 moved");

    // The field names, against the published `preimage_readable` rather than a
    // second copy of them in the module that prints them. `SignedKey::name` is
    // reachable only through `Display`, and nothing compared that text to
    // anything: transposing `client_id` and `counter` there left every test
    // green while a bench log named the wrong field.
    let readable = readable("preimage_readable");
    let fields: Vec<&str> = readable.split('|').map(str::trim).collect();
    // The label and the three envelope scalars come first; the body's own
    // fields follow in key order, which is what makes this a check on the names
    // rather than on their spelling.
    let body_fields = fields.get(4..).expect("the preimage names the body fields");
    for (key, field) in [
        SignedKey::ClientId,
        SignedKey::Counter,
        SignedKey::Operation,
    ]
    .into_iter()
    .zip(body_fields)
    {
        let name = field.split(':').next().expect("a field name").trim();
        assert!(
            key.to_string().contains(name),
            "key {key} does not carry the published name {name}"
        );
    }
}

/// The first prose value under `key`, for the published strings that are English
/// rather than hex.
fn readable(key: &str) -> String {
    let needle = format!("\"{key}\": \"");
    let at = VECTORS
        .find("\"signed_request\"")
        .expect("the signed request is published");
    let rest = VECTORS.get(at..).expect("the tail of the file");
    let from = rest.find(&needle).expect("it carries the key") + needle.len();
    let tail = rest.get(from..).expect("the tail of the value");
    let end = tail.find('"').expect("the value is closed");
    tail.get(..end).expect("the value").to_owned()
}

/// A published integer, for the values that are numbers rather than hex.
fn number(key: &str) -> usize {
    let needle = format!("\"{key}\": ");
    let at = VECTORS.find(&needle).expect("the key is published") + needle.len();
    let tail = VECTORS.get(at..).expect("the tail of the file");
    let end = tail
        .find(|c: char| !c.is_ascii_digit())
        .expect("the number is followed by something");
    tail.get(..end)
        .expect("the digits")
        .parse()
        .expect("a decimal integer")
}

/// The frame cap a receiver allocates, against the one the generator publishes.
///
/// Two derivations of one number, and nothing compared them. The crate reserves
/// `floor(n / 254) + 1` code bytes (`cobs::max_encoded_len`); the generator
/// publishes `ceil(n / 254)`. Those agree everywhere except at an exact multiple
/// of 254 — where the generator is one *lower*. At today's `MAX_PAYLOAD` the
/// COBS input is 1026 and both say 1032, so the disagreement is invisible.
///
/// The failure is a `MAX_PAYLOAD` that lands on a block boundary: 1014 makes the
/// input 1016, the generator publishes a cap of 1021, a receiver allocates 1022,
/// and an implementation built from the published number drops the largest legal
/// frame at a site. That is P-002's own subject, arriving through the artefact.
#[test]
fn the_frame_cap_a_receiver_allocates_is_the_one_the_vectors_publish() {
    assert_eq!(number("max_payload"), MAX_PAYLOAD, "the payload cap moved");
    assert_eq!(
        number("cobs_input"),
        MAX_PAYLOAD + 2,
        "the CRC that goes into COBS beside the envelope moved"
    );
    assert_eq!(
        number("max_frame_including_delimiter"),
        MAX_FRAME,
        "the generator and the crate disagree about how big a frame can get — \
         at a multiple of 254 they differ by one, and the crate is the larger"
    );
}

/// One named array block, so a key that appears in two blocks is never read out
/// of the wrong one.
fn block(name: &str) -> &'static str {
    let needle = format!("\"{name}\": [");
    let at = VECTORS
        .find(&needle)
        .unwrap_or_else(|| panic!("v1.json has no `{name}` block"));
    let from = at + needle.len();
    let rest = VECTORS
        .get(from..)
        .expect("the block starts inside the file");
    let end = rest.find(']').expect("the block closes");
    rest.get(..end).expect("the block is a slice")
}

/// Every string under `key` in `hay`, in file order, **including empty ones** —
/// which `blobs` drops, and the empty input is the case a COBS encoder gets
/// wrong.
fn strings_of(hay: &'static str, key: &str) -> Vec<&'static str> {
    let needle = format!("\"{key}\": \"");
    hay.match_indices(&needle)
        .filter_map(|(at, _)| {
            let from = at.checked_add(needle.len())?;
            let rest = hay.get(from..)?;
            let end = rest.find('"')?;
            rest.get(..end)
        })
        .collect()
}

/// One named object block, for the same reason [`block`] exists.
fn object(name: &str) -> &'static str {
    let needle = format!("\"{name}\": {{");
    let at = VECTORS
        .find(&needle)
        .unwrap_or_else(|| panic!("v1.json has no `{name}` object"));
    let from = at + needle.len();
    let rest = VECTORS
        .get(from..)
        .expect("the object starts inside the file");
    // Brace-matched, because `envelope_readable` carries a `{...}` of its own
    // and stopping at the first close cuts the block in half — which is how
    // this scan first read the frame block as three keys instead of seven.
    let mut depth = 0usize;
    for (i, c) in rest.char_indices() {
        match c {
            '{' => depth += 1,
            '}' if depth == 0 => return rest.get(..i).expect("the object is a slice"),
            '}' => depth -= 1,
            _ => {}
        }
    }
    panic!("the `{name}` object never closes")
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "odd-length hex in the vectors: {hex:?}"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(hex.get(i..i + 2).expect("a hex pair"), 16)
                .unwrap_or_else(|e| panic!("{hex:?}: {e}"))
        })
        .collect()
}

/// **The CRC check value and the rest of the published table.** The framing
/// layer round-tripped against itself and the four cases the generator
/// publishes were read by nothing — change a nibble in `v1.json` and every test
/// in this crate stayed green while the controller and the published bytes
/// disagreed about the checksum on every frame.
#[test]
fn p_001_every_published_crc16_is_the_one_this_crate_computes() {
    let inputs = strings_of(block("crc16"), "input");
    let want = strings_of(block("crc16"), "crc");
    assert_eq!(inputs.len(), want.len(), "a crc16 case lost half of itself");
    assert_eq!(inputs.len(), 4, "the crc16 table grew or shrank");

    for (input, crc) in inputs.iter().zip(&want) {
        let expected = u16::from_str_radix(crc.trim_start_matches("0x"), 16)
            .unwrap_or_else(|e| panic!("{crc:?}: {e}"));
        assert_eq!(
            km43::crc16(&unhex(input)),
            expected,
            "crc16 of {input:?}: the published table and this crate disagree"
        );
    }
}

/// **The COBS paper's own examples, read out of the file that publishes them.**
/// Seven cases including the empty input and the 254-byte block boundary, which
/// is the length an encoder gets wrong and no round trip notices.
#[test]
fn p_001_every_published_cobs_encoding_is_the_one_this_crate_produces() {
    let inputs = strings_of(block("cobs"), "input");
    let want = strings_of(block("cobs"), "encoded");
    assert_eq!(inputs.len(), want.len(), "a cobs case lost half of itself");
    assert_eq!(inputs.len(), 7, "the cobs table grew or shrank");

    for (input, encoded) in inputs.iter().zip(&want) {
        let src = unhex(input);
        let published = unhex(encoded);

        let mut dst = [0u8; MAX_FRAME];
        let len = km43::encode(&src, &mut dst).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!(
            dst.get(..len).expect("the encoded length"),
            published.as_slice(),
            "cobs of {input:?}: the published bytes and this crate disagree"
        );

        // And the other direction, over the published bytes rather than our own.
        let mut back = [0u8; MAX_FRAME];
        let back_len =
            km43::decode(&published, &mut back).unwrap_or_else(|e| panic!("{encoded:?}: {e}"));
        assert_eq!(
            back.get(..back_len).expect("the decoded length"),
            src.as_slice(),
            "the published encoding of {input:?} does not decode back to it"
        );
    }
}

/// **The one whole frame the corpus publishes, byte for byte.** The CRC covers
/// the envelope exactly, the COBS runs over envelope-plus-CRC, and the frame
/// ends with the delimiter — three claims that were prose in `v1.json` and
/// nothing else.
#[test]
fn p_001_the_published_frame_is_the_one_this_crate_writes() {
    let frame = object("frame");
    let envelope = unhex(
        strings_of(frame, "envelope_cbor")
            .first()
            .copied()
            .expect("the frame block publishes its envelope"),
    );
    let published = unhex(
        strings_of(frame, "encoded_with_delimiter")
            .first()
            .copied()
            .expect("the frame block publishes its wire bytes"),
    );

    // The CRC the file publishes, over the region the file says it covers.
    let crc = strings_of(frame, "crc16_ccitt_false")
        .first()
        .map(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).expect("a hex crc"))
        .expect("the frame block publishes its crc");
    assert_eq!(
        km43::crc16(&envelope),
        crc,
        "the crc this crate computes over the published envelope is not the published one"
    );

    let mut dst = [0u8; MAX_FRAME];
    let len = km43::FrameWriter::default()
        .write(&envelope, &mut dst)
        .expect("the published envelope fits a frame");
    assert_eq!(
        dst.get(..len).expect("the frame length"),
        published.as_slice(),
        "the frame this crate writes is not the one the corpus publishes"
    );

    // The length is published too, and it is the one number a reader checks by
    // eye against a logic-analyser capture.
    let stated: usize = number("encoded_len");
    assert_eq!(
        len, stated,
        "the published frame length is not its own length"
    );
}

/// **The ten link frames' wire bytes, read.** `every_published_link_frame_is_one_
/// this_crate_decodes` starts from `envelope_cbor`, so a wrong `crc16_ccitt_false`
/// or a mis-framed `encoded_with_delimiter` in the `link_local` block was
/// invisible: the gate accepts any quoted key inside a block as *read*, and the
/// client `frame` block's test brace-matches its own object only.
#[test]
fn every_published_link_frame_is_the_one_this_crate_frames_and_checksums() {
    let link = object("link_local");
    let envelopes = strings_of(link, "envelope_cbor");
    let frames = strings_of(link, "encoded_with_delimiter");
    let crcs = strings_of(link, "crc16_ccitt_false");
    assert_eq!(envelopes.len(), 10, "the link block changed shape");
    assert_eq!(frames.len(), envelopes.len());
    assert_eq!(crcs.len(), envelopes.len());

    for ((envelope, frame), crc) in envelopes.iter().zip(&frames).zip(&crcs) {
        let envelope = unhex(envelope);
        let published = unhex(frame);
        let crc = u16::from_str_radix(crc.trim_start_matches("0x"), 16).expect("a hex crc");
        assert_eq!(
            km43::crc16(&envelope),
            crc,
            "the crc this crate computes over a published link envelope is not the published one"
        );
        let mut dst = [0u8; MAX_FRAME];
        let len = km43::FrameWriter::default()
            .write(&envelope, &mut dst)
            .expect("a published link envelope fits a frame");
        assert_eq!(
            dst.get(..len).expect("the frame length"),
            published.as_slice(),
            "the frame this crate writes for a link envelope is not the one the corpus publishes"
        );
    }
}

/// **The QR payload, counted.** P-049 fixes it at an exact character count, and
/// the count is what a client validates a scan against before it derives
/// anything — so an off-by-one there rejects every real label.
///
/// The arithmetic in the specification said 105 for a long time after the
/// protocol was renamed: the leading literal used to be `clamp`, which is five
/// characters, and `km43` is four. The generator has published 104 throughout
/// and nothing compared the two.
#[test]
fn p_049_the_published_qr_payload_is_the_length_the_specification_counts() {
    const PREFIX: &str = "km43:1:";
    const DEVICE_ID_CHARS: usize = 32;
    const SECRET_CHARS: usize = 64;
    // 4 + 1 + 1 + 1 + 32 + 1 + 64, said as its parts so a change to any of them
    // moves this rather than a number somebody has to recompute.
    const COUNTED: usize = PREFIX.len() + DEVICE_ID_CHARS + 1 + SECRET_CHARS;

    let qr = object("qr");
    let payload = strings_of(qr, "payload")
        .first()
        .copied()
        .expect("the qr block publishes its payload");

    assert_eq!(COUNTED, 104, "the parts do not add up to the count");
    assert_eq!(
        payload.chars().count(),
        COUNTED,
        "the published payload is not the length the specification counts"
    );
    assert_eq!(
        number("len"),
        COUNTED,
        "the published length is not its own"
    );

    assert!(payload.starts_with(PREFIX), "{payload:?}");
    assert_eq!(
        payload.matches(':').count(),
        3,
        "a colon appeared or vanished"
    );
    assert!(
        !payload.contains(char::is_whitespace),
        "no whitespace, no trailing newline, nothing else"
    );

    let mut fields = payload.split(':').skip(2);
    let device_id = fields.next().expect("a device_id field");
    let secret = fields.next().expect("a printed_secret field");
    assert_eq!(device_id.len(), DEVICE_ID_CHARS);
    assert_eq!(secret.len(), SECRET_CHARS);
    for (what, field) in [("device_id", device_id), ("printed_secret", secret)] {
        assert!(
            field
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "{what} is not lowercase hexadecimal: {field:?}"
        );
    }
}

/// **P-038: the `device_id` is those sixteen bytes, in lowercase hex, with no
/// separators.** A client takes the MQTT topic straight off the label, so a
/// rendering that disagreed with the bytes would send every Discover to a topic
/// nobody is listening on.
#[test]
fn p_038_the_device_id_on_the_label_renders_the_bytes_the_corpus_publishes() {
    let published = blobs("device_id")
        .into_iter()
        .next()
        .expect("the inputs block publishes a device_id");
    assert_eq!(published.len(), 16, "a device_id is sixteen bytes");

    let on_the_label = strings_of(object("qr"), "payload")
        .first()
        .copied()
        .and_then(|p| p.split(':').nth(2))
        .expect("the qr payload carries a device_id field");

    let mut rendered = String::new();
    for byte in &published {
        use core::fmt::Write as _;
        let _ = write!(rendered, "{byte:02x}");
    }
    assert_eq!(
        on_the_label, rendered,
        "the label and the bytes disagree about which controller this is"
    );
    assert!(
        !on_the_label.contains('-') && !on_the_label.contains(':'),
        "no separators"
    );
    assert_eq!(on_the_label, on_the_label.to_ascii_lowercase());
}

/// One hex blob, found by the key that names it rather than by a JSON parser.
///
/// The same scan `blobs` uses, narrowed to a single named entry: the inventory
/// rows nest one level down, and a parser here would drag an allocator into the
/// one crate whose no-`alloc` claim is compiler-enforced.
fn blob_under(entry: &str, key: &str) -> Vec<u8> {
    let at = VECTORS
        .find(&format!("\"{entry}\""))
        .unwrap_or_else(|| panic!("the vector file has no {entry}"));
    let rest = VECTORS.get(at..).unwrap_or_default();
    let needle = format!("\"{key}\": \"");
    let from = rest
        .find(&needle)
        .unwrap_or_else(|| panic!("{entry} has no {key}"))
        + needle.len();
    let tail = rest.get(from..).unwrap_or_default();
    let end = tail
        .find('"')
        .unwrap_or_else(|| panic!("{entry}.{key} is unterminated"));
    unhex(tail.get(..end).unwrap_or_default())
}

/// One published row against what this encoder writes for it.
///
/// Split out because the lint describing the fix is the lint that fired: five
/// fixtures and one assertion is a hundred and twelve lines, and the assertion
/// is the part worth reading.
/// The largest number a closed space allocates, asked of the space.
///
/// The published bytes carry `xtask`'s hand-written opinion of the same number —
/// 7 for a transport, 9 for a signal domain — and this is the registry's. A
/// tenth signal domain moves this one, leaves that one, and turns the comparison
/// red saying the vectors need regenerating. Hardcoding it here would make both
/// sides one opinion typed twice.
fn member(space: Closed) -> Value<'static> {
    Value::U8(space.widest())
}

fn published_row_matches(name: &str, kind: RowKind, values: &[Value<'_>]) {
    let published = blob_under(name, "row_cbor");
    let row = Row::new(kind, values).unwrap_or_else(|e| panic!("{name}: {e}"));
    let mut page = Page::new(kind);
    assert!(
        page.push(&row, 1).unwrap_or_else(|e| panic!("{name}: {e}")),
        "{name} must fit an empty page"
    );
    assert_eq!(
        page.encoded_rows(),
        published.as_slice(),
        "{name}: this encoder and the published row have parted company"
    );
}

/// **The published rows are the ones this encoder writes.**
///
/// `vectors/v1.json` is built by `xtask`, which may not depend on this crate, so
/// these bytes are a second opinion and not a copy of one. The row-width table
/// in TOPOLOGY-DESIGN.md is a third, derived by hand. All three agree here or
/// one of them is wrong.
///
/// Move `vectors/v1.json` and this goes red. That is the point: four modules in
/// this repo have carried a hex string retyped into the file it was meant to
/// check, each wearing the artefact's name in its own doc comment.
#[test]
fn the_published_inventory_rows_are_the_ones_this_encoder_writes() {
    let label = "01234567890123456789012345678901";
    let ident = "012345678901234567890123";
    let addr: &[u8] = &[0xFF; 8];
    let cmds = CmdList::new(&[u16::MAX; 4]).expect("a full cmds array");
    let (u16m, u8m, u32m, i32m) = (
        Value::U16(u16::MAX),
        Value::U8(u8::MAX),
        Value::U32(u32::MAX),
        Value::I32(i32::MIN),
    );

    published_row_matches(
        "bus_widest",
        RowKind::Bus,
        &[u8m, member(Closed::Transport), Value::Text(label), u32m],
    );
    published_row_matches(
        "device_widest",
        RowKind::Device,
        &[
            u16m,
            u8m,
            Value::Bytes(addr),
            u16m,
            u16m,
            u16m,
            u16m,
            Value::Text(ident),
            Value::Text(ident),
            Value::Text(ident),
            Value::Text(label),
            u32m,
            Value::U16List(cmds),
        ],
    );
    published_row_matches(
        "component_widest",
        RowKind::Component,
        &[
            u16m,
            u16m,
            u16m,
            u16m,
            u16m,
            u16m,
            Value::Text(label),
            Value::U16List(cmds),
            u32m,
        ],
    );
    // Four keys pinned by something other than their type, and every one of them
    // was `u8::MAX` or `u16::MAX` here until the check that forbids it existed.
    // `shape` 2 and `vtype` 4 because `n` and `esp` are legal only under exactly
    // those; `n` at MAX_SERIES_LEN and `ebase` sixteen below the top, because a
    // longer series has elements no `Concern` can name and a higher base
    // promises labels past `u16` (P-206). The widest row the types permit is a
    // row the field list forbids, and it was what this vector carried.
    published_row_matches(
        "signal_widest",
        RowKind::Signal,
        &[
            u16m,
            u16m,
            u16m,
            u16m,
            Value::U8(2),
            Value::U8(4),
            member(Closed::Domain),
            u16m,
            member(Closed::Direction),
            Value::U8(16),
            u16m,
            Value::U16(u16::MAX - 15),
            u16m,
            u8m,
            u8m,
            u16m,
            member(Closed::Bucket),
            Value::Text(label),
        ],
    );
    published_row_matches(
        "param_widest",
        RowKind::Param,
        &[
            u16m,
            u16m,
            u16m,
            u16m,
            i32m,
            Value::U8(4),
            member(Closed::Domain),
            u16m,
            member(Closed::Direction),
            u16m,
            i32m,
            i32m,
            u16m,
            u8m,
            u8m,
            u16m,
            Value::Text(label),
        ],
    );
}

/// The other end of every row, and the one the page ceiling rests on.
///
/// If `bus_required_keys_only` stops being five bytes,
/// `INVENTORY_PAGE_ROWS_CEILING` is dividing the page cap by the wrong number.
#[test]
fn the_published_narrowest_row_is_what_the_page_ceiling_divides_by() {
    let published = blob_under("bus_required_keys_only", "row_cbor");
    let values = [Value::U8(1), Value::U8(1), Value::Absent, Value::Absent];
    let row = Row::new(RowKind::Bus, &values).expect("required keys only is legal");
    let mut page = Page::new(RowKind::Bus);
    assert!(page.push(&row, 1).expect("encodes"));
    assert_eq!(page.encoded_rows(), published.as_slice());
    assert_eq!(page.len(), 5, "the divisor the ceiling uses");
}

/// The published `Inventory 0x8D`, read back by the decoder that will meet one
/// on a wire — starting from bytes this crate did not produce.
#[test]
fn the_published_inventory_body_reads_back_to_what_the_generator_wrote() {
    let body = blob_under("inventory_0x8D", "body_cbor");
    let got = InventoryHeader::decode(&body).expect("the published body decodes");
    assert_eq!(got.rev, 41);
    assert_eq!(got.what, 1, "buses");
    assert_eq!(got.outcome, InventoryOutcome::Ok);
    assert_eq!(got.rows, 3);
    assert_eq!(got.total, 3);
    assert_eq!(
        got.next, 0,
        "the walk completed, which is what lets key 7 ride"
    );
    assert_eq!(got.digest, Some([1, 2, 3, 4, 5, 6, 7, 8]));

    let request = blob_under("inventory_0x8D", "request_body_cbor");
    let read = ReadInventory::decode(&request).expect("the published request decodes");
    assert_eq!(read.rev, 41);
    assert_eq!(read.what, 2);
    assert_eq!(read.from, 0);
    assert_eq!(read.dev, Some(7));
}

/// The published widest `Sample` and `Series`, against what this encoder writes
/// for them.
///
/// The two numbers are the ones `SAMPLE_MAX_BYTES` and `SERIES_MAX_BYTES` claim
/// and the two page ceilings divide the byte budget by. They are derived by hand
/// in TOPOLOGY-DESIGN.md, written as constants in `limits.rs`, and produced here
/// by a generator that has never seen this crate — so if any one of the three
/// moves, this is where they stop agreeing.
#[test]
fn the_widest_reading_the_generator_publishes_is_the_one_this_crate_budgets_for() {
    let q = SignalQuality::carrying(Validity::Stale, Provenance::Measured).expect("stale carries");

    let sample = Sample::new(
        Id::new(u16::MAX).expect("a signal id"),
        q,
        Some(i32::MIN),
        Some(u32::MAX),
    )
    .expect("the widest one");
    let mut dst = [0u8; 64];
    let mut cbor = CborWriter::new(&mut dst);
    sample.encode(&mut cbor).expect("encodes");
    let len = cbor.finish().expect("finishes");
    assert_eq!(
        dst.get(..len),
        Some(blob_under("sample_widest", "row_cbor").as_slice())
    );
    assert_eq!(len, SAMPLE_MAX_BYTES, "the divisor SAMPLE_CEILING uses");

    let all = [q; MAX_SERIES_LEN];
    let values = [i32::MIN; MAX_SERIES_LEN];
    let series = Series::new(
        Id::new(u16::MAX).expect("a signal id"),
        &all,
        &values,
        Some(u32::MAX),
    )
    .expect("the widest one");
    let mut dst = [0u8; 256];
    let mut scratch = [0u8; MAX_SERIES_LEN];
    let mut cbor = CborWriter::new(&mut dst);
    series.encode(&mut cbor, &mut scratch).expect("encodes");
    let len = cbor.finish().expect("finishes");
    assert_eq!(
        dst.get(..len),
        Some(blob_under("series_widest", "row_cbor").as_slice())
    );
    assert_eq!(len, SERIES_MAX_BYTES, "the divisor SERIES_CEILING uses");
}

/// The published `Readings 0x8E`, built again from the public API and compared
/// byte for byte, then read back by the decoder that will meet one on a wire.
///
/// The series in it is the case the whole `q`-byte design exists for: three
/// cells, the middle one with an open sense wire. Its byte says `5 sensor_fault`
/// and it contributes **no integer at all**, so key 3 holds two numbers for
/// three elements — and the two that are readable stay on their own sides of
/// the gap rather than shifting up by one.
#[test]
fn the_published_readings_body_is_the_one_this_encoder_writes() {
    let ok = SignalQuality::carrying(Validity::Ok, Provenance::Measured).expect("ok carries");
    let open = SignalQuality::absent(Validity::SensorFault).expect("a fault carries nothing");

    let mut page = ReadingsPage::new();
    let sample =
        Sample::new(Id::new(9).expect("a signal id"), ok, Some(1_250), None).expect("12.50 V");
    assert!(page.push_sample(&sample).expect("encodes"));

    let q = [ok, open, ok];
    let values = [3_312, 3_309];
    let series = Series::new(Id::new(21).expect("a signal id"), &q, &values, None)
        .expect("two readable of three");
    assert!(page.push_series(&series).expect("encodes"));

    let body = ReadingsBody {
        seq: 4_211,
        rev: 41,
        at: Some(1_767_225_600),
        outcome: ReadingsOutcome::Ok,
        total: 2,
        page: Some(&page),
    };
    let mut dst = [0u8; 512];
    let len = body.encode(&mut dst).expect("the body encodes");
    let published = blob_under("readings_0x8E", "body_cbor");
    assert_eq!(dst.get(..len), Some(published.as_slice()));

    let got = ReadingsHeader::decode(&published).expect("the published body decodes");
    assert_eq!(got.seq, 4_211);
    assert_eq!(got.rev, 41);
    assert_eq!(got.at, Some(1_767_225_600));
    assert_eq!(got.outcome, ReadingsOutcome::Ok);
    assert_eq!(got.samples, 1);
    assert_eq!(got.series, 1);
    assert_eq!(got.total, 2);
    assert_eq!(got.next, 0, "the selection completed");
}

/// The published `ReadSignals 0x0E`, decoded by the crate that will answer one.
///
/// Two selectors of different kinds, because a `Sel` that named two things at
/// once or none at all is error 1, and a request carrying one of each is the
/// shape that proves the union is a union rather than a concatenation.
#[test]
fn the_published_readsignals_request_is_the_one_this_crate_reads() {
    let request = blob_under("readings_0x8E", "request_body_cbor");
    let got = ReadSignals::decode(&request).expect("the published request decodes");
    assert_eq!(got.rev, 41);
    assert_eq!(got.from, 0);
    assert!(!got.is_everything());

    let want = [
        Sel::Dev(Id::new(7).expect("a device")),
        Sel::Sig(Id::new(21).expect("a signal")),
    ];
    assert_eq!(got.selectors().count(), want.len());
    for (got, want) in got.selectors().zip(want) {
        assert_eq!(got, want);
    }

    let mut dst = [0u8; 64];
    let len = got.encode(&mut dst).expect("and re-encodes");
    assert_eq!(dst.get(..len), Some(request.as_slice()));
}

/// **Flip one `q` byte and the two cells that are readable shift by one.**
///
/// The published series has three cells and the middle one's sense wire is
/// open: byte `0x50` `sensor_fault`, and no integer for it anywhere in the
/// message. Change that byte to `0x11 ok` and the bytes still parse, still
/// MAC-verify, and still look like a healthy three-cell string — except key 3
/// now holds two integers for three elements that all claim to carry one. A
/// receiver that trusts the array's length renders cell 2 at cell 3's voltage
/// and cell 3 at nothing.
///
/// `Series::new` holds the counting rule for anything this crate builds, and a
/// controller somewhere else does not have this crate. This is the rule on the
/// side that renders.
#[test]
fn p_197_a_q_byte_flipped_to_ok_without_a_number_is_refused() {
    let published = blob_under("readings_0x8E", "body_cbor");
    // The series map, lifted out by the crate's own item walker rather than by
    // counting bytes backwards from the q string — an offset guessed here is a
    // second opinion about the encoding, which is the thing this file exists to
    // avoid having.
    let starts = published
        .windows(3)
        .position(|w| w == [0xA3, 0x01, 0x15])
        .expect("the series map at sig 21");
    let tail = published.get(starts..).expect("the rest of the body");
    let series = CborReader::new(tail)
        .raw()
        .expect("one whole item")
        .to_vec();

    let (sig, elements) = Series::check(&series).expect("the published series checks out");
    assert_eq!(sig, 21);
    assert_eq!(elements, 3);

    let at = series
        .windows(3)
        .position(|w| w == [0x11, 0x50, 0x11])
        .expect("the published q bytes");
    let mut flipped = series.clone();
    *flipped
        .get_mut(at.saturating_add(1))
        .expect("the middle cell's byte") = 0x11;
    assert!(
        Series::check(&flipped).is_err(),
        "three elements all claiming a number, and two numbers, was accepted"
    );
}

/// **The published `Concerns 0x8F`, rebuilt byte for byte by this crate.**
///
/// The generator has never seen this crate, so this is the one comparison that
/// can catch an encoder and a spec that drifted apart — a round trip inside the
/// crate agrees with itself no matter what either says. Three rows, each
/// carrying a rule that is easy to write and hard to notice being wrong.
#[test]
fn the_published_concerns_body_is_the_one_this_crate_writes() {
    let dev = |n| Id::new(n).expect("a device");
    let cmp = |d, n| Part::component(dev(d), Id::new(n).expect("a component"));

    // cid 9 — pack 2's cell 23, which is element 7 of a signal whose `ebase`
    // is 17. Both numbers are correct and they are different.
    let cell = Concern {
        cid: dev(9),
        subject: Subject::Element(
            cmp(3, 57),
            dev(204),
            ElementAt::new(7).expect("a position inside the series"),
        ),
        cond: Condition::OVER_VOLTAGE,
        sev: Severity::Protection,
        state: ConcernState::Active,
        age: 21_600,
        since: Some(1_767_204_000),
        code: None,
        seq: 4_198,
    };
    // cid 11 — the charger as a whole, at `cmp = 0`, reporting a state this
    // build cannot name and carrying whose code it is.
    let unnamed = Concern {
        cid: dev(11),
        subject: Subject::Part(Part::device(dev(5))),
        cond: Condition::UNNAMED_STATE,
        sev: Severity::Warning,
        state: ConcernState::ActiveAcked,
        age: 900,
        since: None,
        code: Some(VendorCode {
            raw: 0x0021,
            vns: VendorNamespace::EPEVER,
        }),
        seq: 4_203,
    };
    // cid 12 — a protection that ended at dawn and has not been released. It is
    // still a row the walk returns, and `total` counts it.
    let over = Concern {
        cid: dev(12),
        subject: Subject::Signal(cmp(3, 58), dev(211)),
        cond: Condition::UNDER_TEMPERATURE,
        sev: Severity::Protection,
        state: ConcernState::Cleared,
        age: 43_200,
        since: None,
        code: None,
        seq: 4_180,
    };

    let mut page = ConcernsPage::new();
    for row in [&cell, &unnamed, &over] {
        assert!(page.push(row).expect("encodes"), "the page refused a row");
    }
    let body = ConcernsBody {
        rev: 41,
        seq: 4_211,
        total: 3,
        refused: 2,
        outcome: ConcernsOutcome::Ok,
        page: Some(&page),
    };
    let mut dst = [0u8; MAX_PAYLOAD];
    let len = body.encode(&mut dst).expect("the body encodes");
    let published = blob_under("concerns_0x8F", "body_cbor");
    assert_eq!(
        dst.get(..len),
        Some(published.as_slice()),
        "this encoder and the generator disagree about the bytes of a concerns page"
    );
    assert_eq!(len, published.len(), "the published length is not its own");

    // And back the other way, from bytes this crate did not produce.
    let got = ConcernsHeader::decode(&published).expect("the published body decodes");
    assert_eq!(got.rev, 41);
    assert_eq!(got.seq, 4_211, "the pin a walk is held against");
    assert_eq!(got.rows, 3);
    assert_eq!(got.total, 3, "the cleared row was left out of total");
    assert_eq!(got.refused, 2);
    assert_eq!(got.next, 0, "the walk completed");
    assert_eq!(got.outcome, ConcernsOutcome::Ok);

    let mut walked = 0usize;
    for (row, want) in ConcernRows::of(&published)
        .expect("the rows")
        .zip([cell, unnamed, over])
    {
        assert_eq!(row.expect("a published row decodes"), want);
        walked += 1;
    }
    assert_eq!(walked, 3, "the walk did not return every published row");
}

/// **The two ends of the `Concern` row budget, from a third opinion.**
///
/// 63 is the divisor `MAX_CONCERN_PAGE_ROWS` was derived with, and 37 is the
/// number behind the claim that the byte cap would admit 22 rows where the row
/// cap admits 12 — which is what makes the row arm the one that binds. Both are
/// worked out by hand in TOPOLOGY-DESIGN.md, written as constants in
/// `limits.rs`, and produced here by a generator that has never seen this
/// crate. If any one of the three moves, this is where they stop agreeing.
#[test]
fn the_widest_concern_the_generator_publishes_is_the_one_this_crate_budgets_for() {
    let all = Id::new(u16::MAX).expect("an id");
    let widest = Concern {
        cid: all,
        subject: Subject::Element(
            Part::component(all, all),
            all,
            ElementAt::new(u8::try_from(MAX_SERIES_LEN).expect("a small length"))
                .expect("the last position of the longest series"),
        ),
        cond: Condition(u16::MAX),
        sev: Severity::Protection,
        state: ConcernState::Cleared,
        age: u32::MAX,
        since: Some(u64::MAX),
        code: Some(VendorCode {
            raw: u32::MAX,
            vns: VendorNamespace(u16::MAX),
        }),
        seq: u64::MAX,
    };
    // **Narrowest is fewest keys, not smallest numbers.** The required keys stay
    // at their widest, because 37 is the divisor behind *the byte cap would
    // admit 22 rows* — and a figure derived from small ids would claim a bigger
    // number than a real page can rely on. Written as `Part::device` first,
    // which is `cmp = 0` and two bytes narrower, and the published vector is
    // what said so.
    let narrowest = Concern {
        subject: Subject::Part(Part::component(all, all)),
        since: None,
        code: None,
        ..widest
    };

    for (concern, key, want) in [
        (widest, "concern_widest", CONCERN_MAX_BYTES),
        (narrowest, "concern_required_keys_only", 37),
    ] {
        let mut dst = [0u8; CONCERN_MAX_BYTES];
        let mut cbor = CborWriter::new(&mut dst);
        concern.encode(&mut cbor).expect("encodes");
        let len = cbor.finish().expect("finishes");
        assert_eq!(
            dst.get(..len),
            Some(blob_under(key, "row_cbor").as_slice()),
            "{key}: this encoder and the generator disagree about a row's bytes"
        );
        assert_eq!(len, want, "{key} is no longer the width the page cap uses");
    }
}

/// The published `ReadConcerns 0x0F`, decoded by the crate that will answer one.
///
/// `from = 0` is the one place a zero is legal in this message, because it is a
/// cursor and not an id — and it is the value every walk starts at.
#[test]
fn the_published_readconcerns_request_is_the_one_this_crate_reads() {
    let request = blob_under("concerns_0x8F", "request_body_cbor");
    let got = ReadConcerns::decode(&request).expect("the published request decodes");
    assert_eq!(got.rev, 41);
    assert_eq!(got.from, 0, "a walk starts from the beginning");

    let mut dst = [0u8; 32];
    let len = got.encode(&mut dst).expect("and re-encodes");
    assert_eq!(dst.get(..len), Some(request.as_slice()));
}

/// **The published `0x0501` carries the row a page carries, byte for byte.**
///
/// The generator writes the raise and the page from the same `Concern`, and this
/// crate encodes both through the same code. If either side ever grew a second
/// shape for a raised concern, these bytes would stop being a subset of those.
#[test]
fn the_published_concern_raise_carries_the_row_the_page_carries() {
    let published = blob_under("concernraised_0x0501", "body_cbor");
    let raised = ConcernRaised::decode(&published).expect("the published raise decodes");
    assert_eq!(raised.rev, 41);
    assert_eq!(raised.concern.cid.get(), 9, "pack 2's cell 23");
    assert_eq!(raised.concern.age, 21_600, "six hours of protection");

    // Re-encoded here it must be the same bytes the generator wrote.
    let mut dst = [0u8; 128];
    let len = raised.encode(&mut dst).expect("and re-encodes");
    assert_eq!(dst.get(..len), Some(published.as_slice()));

    // And the row inside it is the row the page publishes, not a second shape.
    let page = blob_under("concerns_0x8F", "body_cbor");
    let first = ConcernRows::of(&page)
        .expect("the page rows")
        .next()
        .expect("a first row")
        .expect("it decodes");
    assert_eq!(
        raised.concern, first,
        "the raise and the page disagree about the same concern"
    );
}

/// **The published concern says element 7 and the published row says cell 23.**
///
/// This is P-206 driven end to end from committed bytes rather than from prose.
/// The concern page carries a *position* — `elem` 7 of signal 204 — and nothing
/// in it can turn that into the number painted on the rack. The `SignalRow` can:
/// it says the series starts at `ebase` 17, so element 7 is cell 23.
///
/// Both numbers parse, both MAC-verify, and the difference between them is
/// somebody driving four hours and pulling a cell out of the other pack. Move
/// either artefact and this goes red — which is the whole reason the row was
/// added to the vectors: the two halves of the rule were published in two files
/// and joined only by a sentence.
#[test]
fn p_206_the_published_element_position_reads_as_the_cell_the_published_row_labels() {
    let page = blob_under("concerns_0x8F", "body_cbor");
    let cell = ConcernRows::of(&page)
        .expect("the page rows")
        .next()
        .expect("a first row")
        .expect("it decodes");
    let Subject::Element(part, sig, at) = cell.subject else {
        panic!("the published first concern names an element of a series");
    };
    assert_eq!(sig.get(), 204, "the signal the descriptor below describes");
    assert_eq!(at.get(), 7, "a position, 1-based, and not a label");

    let row_bytes = blob_under("signal_series", "row_cbor");
    let mut slots = RowSlots::new();
    let row = slots
        .decode(RowKind::Signal, &row_bytes)
        .expect("the published descriptor decodes");
    assert_eq!(
        row.get(1),
        Some(Value::U16(204)),
        "the row describes the signal the concern names"
    );
    assert_eq!(
        row.get(2),
        Some(Value::U16(part.dev().get())),
        "and it is on the device the concern names"
    );

    let labels = row.labels().expect("a series row describes a series");
    assert_eq!(labels.base(), 17, "pack 2 starts at the cell painted 17");
    assert_eq!(
        labels.label_of(at).expect("element 7 of sixteen"),
        23,
        "element 7 of a series based at 17 is cell 23, and rendering 7 is the other pack"
    );

    // The other half of the same rule, on the row that omits `ebase`: nothing on
    // the wire means *unlabelled*, so a reader that reads absence as 0 numbers
    // every cell one below what a person counting them would say.
    let scalar = blob_under("signal_required_keys_only", "row_cbor");
    let mut spare = RowSlots::new();
    assert_eq!(
        spare
            .decode(RowKind::Signal, &scalar)
            .expect("the published scalar row decodes")
            .labels(),
        None,
        "a scalar has no elements to label"
    );
}

/// The published `0x0502`, and the state it moved **from**.
///
/// `prev` is the field a hole in `seq` is read against (P-096): a client holding
/// `active` that meets a change from `latched_cleared` knows it lost a record,
/// rather than rendering a lifecycle that skipped a state.
#[test]
fn the_published_concern_change_says_which_state_it_moved_from() {
    let published = blob_under("concernchanged_0x0502", "body_cbor");
    let changed = ConcernChanged::decode(&published).expect("the published change decodes");
    assert_eq!(changed.rev, 41);
    assert_eq!(changed.cid.get(), 12);
    assert_eq!(changed.dev.get(), 3);
    assert_eq!(changed.cond, Condition::UNDER_TEMPERATURE);
    assert_eq!(
        changed.state,
        ConcernState::Cleared,
        "state 5 is the row leaving the table, which is the only way one does"
    );
    assert_eq!(changed.prev, ConcernState::LatchedCleared);

    let mut dst = [0u8; 64];
    let len = changed.encode(&mut dst).expect("and re-encodes");
    assert_eq!(dst.get(..len), Some(published.as_slice()));
}

/// The three published change records, driven through the decoders that will
/// meet them.
///
/// The validity sweep is the one worth reading: three signals behind one pair,
/// in one event, each carrying the `q` the client was last **told** rather than
/// the last one observed — which is what a client compares against what it
/// holds.
#[test]
fn the_published_change_records_are_the_ones_this_crate_reads() {
    let published = blob_under("validitychanged_0x0102", "body_cbor");
    let (rev, entries) = ValidityChanged::decode(&published).expect("the sweep decodes");
    assert_eq!(rev, 41);
    let mut sigs = Vec::new();
    for entry in entries {
        let entry = entry.expect("an entry");
        assert_eq!(entry.q.byte(), 0x70, "absent, with no provenance to claim");
        assert_eq!(entry.prev.byte(), 0x11, "the ok/measured the client holds");
        sigs.push(entry.sig.get());
    }
    assert_eq!(
        sigs,
        vec![9, 21, 204],
        "one pair took three signals with it"
    );

    let published = blob_under("topologychanged_0x0901", "body_cbor");
    let moved = TopologyChanged::decode(&published).expect("the topology change decodes");
    assert_eq!(moved.rev, 42);
    assert_eq!(moved.reason, TopologyChangeReason::SubDeviceAdopted);
    assert_eq!((moved.added, moved.removed), (17, 0));
    let mut dst = [0u8; 64];
    let len = moved.encode(&mut dst).expect("and re-encodes");
    assert_eq!(dst.get(..len), Some(published.as_slice()));

    let published = blob_under("boot_0x0601", "body_cbor");
    let boot = Boot::decode(&published).expect("the panic boot decodes");
    assert_eq!(
        boot.cause,
        BootCause::Panic(PanicSite {
            file: 0x9E37_79B9,
            line: 212
        })
    );
    assert!(
        !boot.backup_valid,
        "the cell that kept the calendar was dead"
    );
    assert!(boot.rtc_crystal && !boot.rail_cycled);
    let mut dst = [0u8; BOOT_MAX_BYTES];
    let len = boot.encode(&mut dst).expect("and re-encodes");
    assert_eq!(dst.get(..len), Some(published.as_slice()));

    let published = blob_under("presencechanged_0x0902", "body_cbor");
    let (rev, entries) = PresenceChanged::decode(&published).expect("the presence sweep decodes");
    assert_eq!(rev, 41, "presence does not move rev (P-155)");
    let seen: Vec<_> = entries
        .map(|e| e.expect("an entry"))
        .map(|e| (e.dev.get(), e.presence, e.prev))
        .collect();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, 3);
    assert_ne!(seen[0].1, seen[0].2, "an entry that went nowhere");
}

/// **Every published link-local frame, decoded by this crate.**
///
/// The link has two *different* codebases on its ends — this crate on the
/// STM32, an esp-hal firmware on the ESP32 — and until the generator published
/// these, the only thing checking either encoding was the other one. Two
/// implementations that agree with each other and with nothing else is how a
/// wire format drifts from what it is documented to be.
///
/// Move a key number in `xtask/src/vectors.rs`, regenerate, and this goes red.
/// That is the test: the artefact is the witness, and it is read here rather
/// than transcribed.
///
/// cites: L-010, L-070, L-132, L-152, L-170
#[test]
fn every_published_link_frame_is_one_this_crate_decodes() {
    use km43::{
        ClientConnected, ClientUp, ClientUpAck, ClockOffer, DownloadReason, DownloadRequest,
        DownloadVerdict, EnterDownload, Intake, LinkEnvelope, LinkMessageType, NetConfig,
        NetVerdict, Side, TimeOffer, TimeVerdict, arriving,
    };

    let frames = link_envelopes();
    assert_eq!(
        frames.len(),
        10,
        "the published link section changed shape; this test walks it by count \
         so a vector that stops being published cannot go unnoticed"
    );

    let mut seen = 0;
    for bytes in &frames {
        let envelope = LinkEnvelope::decode(bytes).expect("a published link envelope decodes");
        // The receiving side is whichever one does not send it, which is what
        // `arriving` decides — checked here rather than assumed, because a
        // vector published under the wrong opcode would otherwise round-trip
        // happily against a decoder that never asked.
        let at = receiving(envelope.opcode());
        let Intake::Act(kind) = arriving(envelope.opcode(), at, envelope.session()) else {
            panic!(
                "a published frame was refused admission at {at:?}: {:#04x}",
                envelope.opcode()
            );
        };

        match kind {
            // **`session_id` is 0 on every one of them** (L-010). The link
            // carries no session because it carries no client; a frame with one
            // is refused above, and this is where that would show.
            LinkMessageType::LinkUp => {
                let up = km43::LinkUp::decode(envelope).expect("the published LinkUp reads");
                assert_eq!(up.role, Side::Comms);
                assert_eq!(up.boot_id, 0x5eed_face, "the boot_id the generator wrote");
                // L-031 makes this `fw` the `fw_comms` the controller reports,
                // so the corpus has to publish one text in both places. Two
                // different ones would teach a second implementation that a
                // controller reports something other than what it was sent.
                assert_eq!(
                    up.fw,
                    input_text("fw_comms"),
                    "the published comms LinkUp and the published Hello disagree about fw_comms"
                );
                assert_eq!(
                    up.net_version,
                    Some(0),
                    "a board holding nothing reports 0, and 0 is a value"
                );
                seen += 1;
            }
            LinkMessageType::ClientConnected => {
                let client = ClientUp::decode(envelope).expect("the published ClientUp reads");
                assert_eq!(client.conn, 7);
                assert_eq!(client.peer, "192.168.4.2");
                seen += 1;
            }
            LinkMessageType::ClientConnectedAck => {
                let ack = ClientUpAck::decode(envelope).expect("the published ack reads");
                assert_eq!(ack.outcome, ClientConnected::Accepted);
                seen += 1;
            }
            LinkMessageType::TimeOffer => {
                let offer = ClockOffer::decode(envelope).expect("the published offer reads");
                assert_eq!(offer.unix_ms, 1_786_802_653_000);
                assert_eq!(offer.server, "0.pool.ntp.org");
                seen += 1;
            }
            // The refusal, not the acceptance. An implementation that only ever
            // encodes `accepted` has never exercised the arm the rate limit
            // produces, and that is the one L-151 turns on.
            LinkMessageType::TimeOfferAck => {
                let verdict = TimeVerdict::decode(envelope).expect("the published verdict reads");
                assert_eq!(verdict.outcome, TimeOffer::RefusedRateLimited);
                seen += 1;
            }
            LinkMessageType::NetConfigAck => {
                let verdict = NetVerdict::decode(envelope).expect("the published ack reads");
                assert_eq!(verdict.outcome, NetConfig::Stored);
                assert_eq!(
                    verdict.version, 0,
                    "L-132's honest answer from a board never given a network, \
                     and the one that gets it provisioned"
                );
                seen += 1;
            }
            kind @ (LinkMessageType::CommsRelease | LinkMessageType::CommsReleaseAck) => {
                a_published_release_frame_reads(kind, envelope);
                seen += 1;
            }
            LinkMessageType::EnterDownload => {
                let request =
                    DownloadRequest::decode(envelope).expect("the published request reads");
                assert_eq!(request.reason, DownloadReason::Bench);
                seen += 1;
            }
            // The refusal, not the acceptance: the frame a controller that
            // knocked late has to read (L-191).
            LinkMessageType::EnterDownloadAck => {
                let verdict =
                    DownloadVerdict::decode(envelope).expect("the published verdict reads");
                assert_eq!(verdict.outcome, EnterDownload::RefusedOutsideWindow);
                seen += 1;
            }
            other => panic!("a published link frame this test does not cover: {other:?}"),
        }
    }
    assert_eq!(seen, frames.len(), "a published frame was walked past");
}

/// The comms firmware release pair, read out of the published link section.
/// Apart from the walk above only because the digest is recomputed here, which
/// is the check that makes the release vector worth publishing (L-170).
fn a_published_release_frame_reads(kind: km43::LinkMessageType, envelope: km43::LinkEnvelope<'_>) {
    use km43::{CommsRelease, CommsReleaseOp, LinkMessageType, ReleaseRequest, ReleaseVerdict};
    use sha2::{Digest, Sha256};

    match kind {
        // The digest is a real SHA-256 over a fixed run of bytes, checked
        // by recomputing it here rather than by reading 32 bytes back: a
        // generator that published any 32 bytes would pass the decoder and
        // prove nothing about the field a release turns on (L-170).
        LinkMessageType::CommsRelease => {
            let request = ReleaseRequest::decode(envelope).expect("the published authorise reads");
            let image = b"km43 comms release vector image";
            assert_eq!(request.op, CommsReleaseOp::Authorise);
            assert_eq!(request.version, "0.2.0+g1a2b3c4d");
            assert_eq!(
                request.image_len,
                u32::try_from(image.len()).expect("it fits")
            );
            assert_eq!(
                request.digest,
                <[u8; 32]>::from(Sha256::digest(image)),
                "the published digest is not the SHA-256 of the image it names"
            );
        }
        // The refusal, not the acceptance, and `version` still names the
        // old image: what it will boot next is not what it was sent.
        LinkMessageType::CommsReleaseAck => {
            let verdict = ReleaseVerdict::decode(envelope).expect("the published ack reads");
            assert_eq!(verdict.outcome, CommsRelease::RefusedDigestMismatch);
            assert_eq!(verdict.version, "0.1.0+g9f8e7d6c");
            assert_eq!(verdict.bytes_have, 524_288);
        }
        other => panic!("{other:?} is not a release frame"),
    }
}

/// Which side receives each published frame, written out rather than derived.
///
/// A second opinion about the direction table rather than a restatement of it.
/// An acknowledgement comes back to whoever **started** the exchange, which is
/// the half that was wrong in the crate until these vectors existed: `NetConfig`
/// is the controller's, so its ack lands on the controller, while
/// `ClientConnected` and `TimeOffer` are the comms processor's and theirs land
/// on the ESP32.
fn receiving(opcode: u8) -> km43::Side {
    use km43::Side::{Comms, Controller};

    const AT: [(u8, km43::Side); 10] = [
        (0x60, Controller), // LinkUp, either way; the STM32 receives this one
        (0x62, Controller), // ClientConnected, comms → controller
        (0x66, Controller), // TimeOffer, comms → controller
        (0xe2, Comms),      // ClientConnectedAck, back to the comms processor
        (0xe6, Comms),      // TimeOfferAck, back to the comms processor
        (0xe5, Controller), // NetConfigAck, back to the controller
        (0x67, Comms),      // CommsRelease, controller → comms
        (0xe7, Controller), // CommsReleaseAck, back to the controller
        (0x68, Comms),      // EnterDownload, controller → comms
        (0xe8, Controller), // EnterDownloadAck, back to the controller
    ];

    AT.into_iter()
        .find_map(|(code, side)| (code == opcode).then_some(side))
        .unwrap_or_else(|| panic!("a published link frame carries opcode {opcode:#04x}"))
}

/// The link envelopes, which are the `envelope_cbor` blobs after the client
/// one.
///
/// The client `frame` section is published first and shares the key name, so
/// the split is by position — asserted rather than assumed: the first must be
/// the client envelope, whose opcode is `Ack 0x88`.
fn link_envelopes() -> Vec<Vec<u8>> {
    let found = blobs("envelope_cbor");
    let first = found
        .first()
        .expect("the client envelope is published first");
    assert_eq!(
        first.get(1).copied(),
        Some(0x18),
        "the client envelope no longer leads the file, so this split is reading \
         the wrong blobs"
    );
    found.into_iter().skip(1).collect()
}

/// The attempt both pairing vectors are computed over: the published device,
/// the challenge `Discover 0x80` carried, and the client's nonce.
fn published_attempt() -> Attempt {
    Attempt {
        device_id: fixed("device_id"),
        challenge: fixed("challenge"),
        client_nonce: fixed("client_nonce"),
    }
}

/// The published `Pair 0x0B`, both ways: the envelope this crate writes for
/// the same fields and attempt, and the fields it reads back out of the
/// published bytes once the proof checks out.
///
/// Only the tag was published before, and a tag pins the preimage, not the
/// body. `label` at key 3 and `proof` at key 2 would have left every MAC in
/// the file green while a controller and a phone built from two readings of
/// the document refused each other at the panel.
#[test]
fn the_published_pair_request_is_the_one_this_crate_proves_and_reads() {
    let whole = blob_under("pair_0x0B", "whole_envelope_cbor");
    let body = blob_under("pair_0x0B", "body_cbor");
    let pair = device().pair_key();
    let header = Header {
        kind: MessageType::Pair,
        session: SessionId::from(0),
        req_id: ReqId(17),
    };

    let mut frame = [0u8; MAX_PAYLOAD];
    let len = PairRequest {
        client_kind: ClientKind::App,
        label: "kitchen phone",
    }
    .write(&pair, &published_attempt(), header, &mut frame)
    .expect("the published Pair 0x0B writes");
    assert_eq!(
        frame.get(..len),
        Some(whole.as_slice()),
        "this encoder and the published Pair 0x0B have parted company"
    );
    assert!(
        whole.ends_with(&body),
        "the published body is not the one inside the published envelope"
    );
    assert!(
        body.len() <= MAX_PAIR_BODY,
        "a client sizing its buffer at MAX_PAIR_BODY refuses the published body"
    );

    let envelope = Envelope::decode(&whole).expect("the published Pair 0x0B is an envelope");
    assert_eq!(envelope.header(), header, "the three scalars moved");
    let claim = PairClaim::decode(envelope).expect("the published Pair 0x0B decodes");
    let attempt = claim.attempt(fixed("device_id"), fixed("challenge"));
    assert_eq!(
        attempt,
        published_attempt(),
        "key 4 is not the published client_nonce"
    );
    let fields = claim
        .verify(&pair, &attempt)
        .expect("the published proof checks out over the fields that arrived");
    assert_eq!(fields.client_kind, ClientKind::App, "key 1 moved");
    assert_eq!(fields.label, "kitchen phone", "key 2 moved");
}

/// The published `Pair 0x8B`, both ways, and the one field it does not carry.
///
/// `epoch` is under the MAC and not in the body (P-087). A client that read it
/// from anywhere but `Discover 0x80` gets a tag that never checks out, and the
/// last assertion is that failure: the same published bytes, a different
/// epoch, refused.
#[test]
fn the_published_pair_ack_is_the_one_this_crate_macs_and_reads() {
    let whole = blob_under("pair_0x8B", "whole_envelope_cbor");
    let body = blob_under("pair_0x8B", "body_cbor");
    let pair = device().pair_key();
    let epoch = Epoch::new(1).expect("the published epoch");
    let header = Header {
        kind: MessageType::PairResponse,
        session: SessionId::from(3),
        req_id: ReqId(17),
    };
    let answer = PairResponse {
        outcome: Outcome::Enrolled(ClientId::new(7).expect("the published slot")),
        epoch,
        next_challenge: fixed("next_challenge"),
    };

    let mut frame = [0u8; MAX_PAYLOAD];
    let len = answer
        .write(&pair, &published_attempt(), header, &mut frame)
        .expect("the published Pair 0x8B writes");
    assert_eq!(
        frame.get(..len),
        Some(whole.as_slice()),
        "this encoder and the published Pair 0x8B have parted company"
    );
    assert!(
        whole.ends_with(&body),
        "the published body is not the one inside the published envelope"
    );
    assert!(
        body.len() <= MAX_PAIR_ACK_BODY,
        "the published ack is wider than the crate budgets for"
    );

    let read = PairAckClaim::decode(Envelope::decode(&whole).expect("an envelope"))
        .expect("the published Pair 0x8B decodes")
        .verify(&pair, &published_attempt(), epoch)
        .expect("the published MAC checks out");
    assert_eq!(read, answer, "a key of the published ack moved");
    assert_eq!(
        read.outcome.slot(),
        ClientId::new(7),
        "keys 1 and 2 read as a different enrolment"
    );

    let other = Epoch::new(2).expect("a later epoch");
    assert!(
        PairAckClaim::decode(Envelope::decode(&whole).expect("an envelope"))
            .expect("it decodes")
            .verify(&pair, &published_attempt(), other)
            .is_err(),
        "the ack verified under an epoch it was not computed over"
    );
}

/// The published bare `Error 0xFF`, both ways.
///
/// The bare shape puts the two keys straight into the envelope's map, so the
/// crate writes it whole; the standalone map is what a wrapper carries, and
/// both are compared. Code 4 is one the registry lets a receiver read bare,
/// so it arrives as a hint rather than being discarded.
#[test]
fn the_published_bare_error_is_the_one_this_crate_writes_and_reads() {
    let whole = blob_under("error_0xFF", "whole_envelope_cbor");
    let body = blob_under("error_0xFF", "body_cbor");
    let header = Header {
        kind: MessageType::ErrorResponse,
        session: SessionId::from(3),
        req_id: ReqId(17),
    };
    let sent = ErrorBody {
        code: Incoming::Client(ErrorCode::HelloRequiredFirst),
        detail: "no session on this connection",
    };

    let mut frame = [0u8; MAX_PAYLOAD];
    let len = sent
        .write(header, &mut frame)
        .expect("the published bare Error writes");
    assert_eq!(
        frame.get(..len),
        Some(whole.as_slice()),
        "this encoder and the published bare Error 0xFF have parted company"
    );
    let mut map = [0u8; MAX_PAYLOAD];
    let len = sent.encode(&mut map).expect("the two keys encode");
    assert_eq!(
        map.get(..len),
        Some(body.as_slice()),
        "the standalone Error 0xFF map is not the published one"
    );

    let hint = ErrorBody::from_envelope(Envelope::decode(&whole).expect("an envelope"))
        .expect("code 4 is readable bare");
    assert_eq!(hint.code(), sent.code, "key 1 moved");
    assert_eq!(hint.detail(), sent.detail, "key 2 moved");
    let hint = ErrorBody::bare(&body).expect("the published map reads bare");
    assert_eq!(hint.code(), sent.code, "key 1 moved in the standalone map");
}

/// The published wrapped `Error 0xFF`: the tag this crate computes, the
/// wrapper it writes, the body it reads once the tag checks out — and the
/// receiver's rule the vector exists to pin.
///
/// Code 7 is marked MAC'd in the registry, so the same two keys read out of a
/// bare body are discarded (P-051, P-142). A decoder that let the body decide
/// its own shape would read them, and the comms processor could then strip
/// the MAC off a refusal to forge one.
#[test]
fn the_published_wrapped_error_is_one_this_crate_signs_and_refuses_to_read_bare() {
    let inner = blob_under("error_response", "inner_body_cbor");
    let full = blob_under("error_response", "full_body_cbor");
    let tag = blob_under("error_response", "out16");
    let key = session_key();
    let header = Header {
        kind: MessageType::ErrorResponse,
        session: SessionId::from(3),
        req_id: ReqId(17),
    };
    let sent = ErrorBody {
        code: Incoming::Client(ErrorCode::BusyRetry),
        detail: "four requests already in flight",
    };

    let mut map = [0u8; MAX_PAYLOAD];
    let len = sent.encode(&mut map).expect("the two keys encode");
    let payload = map.get(..len).expect("the encoder's own length");
    assert_eq!(
        payload,
        inner.as_slice(),
        "this encoder and the published wrapped Error 0xFF body have parted company"
    );

    let tagged = Tagged::over(header, payload, &key).expect("Error 0xFF is wrapped under rsp");
    tagged
        .mac()
        .verify(&tag)
        .expect("the published wrapped Error tag is not what we compute");
    let mut frame = [0u8; MAX_PAYLOAD];
    let len = tagged.write(&mut frame).expect("it fits a payload");
    let written = frame.get(..len).expect("the writer's own length");
    assert!(
        written.ends_with(&full),
        "the wrapper this crate writes is not the published one"
    );

    let read = Wrapper::decode(Envelope::decode(written).expect("an envelope"))
        .expect("a wrapper")
        .verify(&key)
        .expect("the published tag checks out");
    let body = ErrorBody::authenticated(read.payload()).expect("the wrapped body decodes");
    assert_eq!(body, sent, "a key of the wrapped Error moved");

    assert_eq!(
        ErrorBody::bare(&inner),
        Err(ErrorBodyError::BareCodeNeedsAMac(ErrorCode::BusyRetry)),
        "a MAC'd code was read out of a bare body"
    );
}

/// The published `ReadLog 0x05`, both ways — and the first test that calls
/// `ReadLog::encode` at all.
///
/// The body inside `macs.wrapper_request` is the same request, and the tag
/// test above reads it by position; this ties the two, so the request a tag
/// was computed over and the one published on its own cannot drift apart.
#[test]
fn the_published_readlog_request_is_the_one_this_crate_writes_and_reads() {
    let body = blob_under("readlog_0x05", "body_cbor");
    let got = ReadLog::decode(&body).expect("the published ReadLog decodes");
    assert_eq!(got.from_seq, LogSeq(1216), "key 1 moved");
    assert_eq!(got.max_entries, 64, "key 2 moved");

    let asked = ReadLog {
        from_seq: LogSeq(1216),
        max_entries: 64,
    };
    let mut dst = [0u8; 16];
    let len = asked.encode(&mut dst).expect("the request encodes");
    assert_eq!(
        dst.get(..len),
        Some(body.as_slice()),
        "this encoder and the published ReadLog 0x05 have parted company"
    );
    // Every destination short of the published length is refused rather than
    // written partway, which is the truncation a fixed buffer invites.
    for short in 0..body.len() {
        let mut dst = [0u8; 16];
        let room = dst.get_mut(..short).expect("under sixteen");
        assert!(
            asked.encode(room).is_err(),
            "a ReadLog wrote into {short} bytes"
        );
    }

    assert_eq!(
        blob_under("wrapper_request", "inner_body_cbor"),
        body,
        "macs.wrapper_request wraps a different ReadLog from the one published"
    );
}

/// The published `LogPage 0x85`, both ways.
///
/// Its first record has no `at`: a boot written before the clock was ever set.
/// A decoder that defaults an absent key 2 to zero reads a record from 1970,
/// and an encoder that writes one puts it there. Its body is a boot body the
/// `0x0601` codec reads, not filler. The second record carries
/// the time, kind and body of `macs.event`, read out of that vector rather
/// than restated here.
#[test]
fn the_published_logpage_is_the_one_this_crate_writes_and_reads() {
    let body = blob_under("logpage_0x85", "body_cbor");
    let published_event = blob_under("event", "inner_body_cbor");
    let event = Event::decode(&published_event).expect("the published event decodes");

    let cold = Boot {
        cause: BootCause::Power,
        backup_valid: false,
        rtc_crystal: true,
        rail_cycled: true,
    };
    let mut boot_body = [0u8; BOOT_MAX_BYTES];
    let len = cold.encode(&mut boot_body).expect("the boot body encodes");
    let cold_body = boot_body.get(..len).expect("the writer's own length");

    let mut page = LogPage::new(LogSeq(1216), LogSeq(1), false);
    page.push(
        LogEntry::new(LogSeq(1216), None, EventKind::BOOT, cold_body).expect("a boot record"),
    )
    .expect("room for it");
    page.push(
        LogEntry::new(LogSeq(1217), event.at, event.kind, event.body())
            .expect("the published event as a record"),
    )
    .expect("room for it");
    assert_eq!(
        page.next_seq(),
        LogSeq(1218),
        "P-029: the cursor is one past the highest seq, not at it"
    );

    let mut dst = [0u8; MAX_LOG_PAGE_BYTES];
    let len = page.encode(&mut dst).expect("the page encodes");
    assert_eq!(
        dst.get(..len),
        Some(body.as_slice()),
        "this encoder and the published LogPage 0x85 have parted company"
    );

    let read = LogPage::decode(&body).expect("the published LogPage decodes");
    let [boot, state] = read.entries() else {
        panic!("the published page carries two records")
    };
    assert_eq!(boot.seq, LogSeq(1216), "the first record's key 1 moved");
    assert_eq!(
        boot.at, None,
        "a record with no clock read back with a time"
    );
    assert_eq!(boot.kind, EventKind::BOOT, "the first record's key 3 moved");
    assert_eq!(boot.body(), cold_body, "the boot record's body moved");
    assert_eq!(
        Boot::decode(boot.body()),
        Ok(cold),
        "a boot record in a page is one the boot codec reads"
    );
    assert_eq!(state.seq, LogSeq(1217), "the second record's key 1 moved");
    assert_eq!(state.at, event.at, "the second record's key 2 moved");
    assert_eq!(
        state.kind,
        EventKind::GENERATOR_STATE_CHANGED,
        "the second record's key 3 moved"
    );
    assert_eq!(
        state.body(),
        event.body(),
        "the second record's key 4 moved"
    );
    assert_eq!(read.next_seq(), LogSeq(1218), "key 2 moved");
    assert_eq!(read.oldest_seq, LogSeq(1), "key 3 moved");
    assert!(!read.complete, "key 4 is published false");
    assert_eq!(
        read, page,
        "a field the asserts above do not name has moved"
    );
}

/// Read every controller record from the committed witness, then compare both
/// its interpretation and its encoding. The generator does not depend on km43.
#[test]
fn p_215_published_controller_records_pin_each_body_schema() {
    use core::num::NonZeroU32;
    use km43::{CONTROLLER_RECORD_MAX_BYTES, ControllerRecord, TimeSource};
    let cases = [
        (
            "timeset_0x0604",
            ControllerRecord::TimeSet {
                old: Some(1_700_000_005_000),
                new: 1_700_000_000_000,
                source: TimeSource::Client,
            },
        ),
        (
            "time_set_unknown_0x0604",
            ControllerRecord::TimeSet {
                old: None,
                new: 1_700_000_000_000,
                source: TimeSource::NtpViaComms,
            },
        ),
        (
            "recordfailedcrc_0x0702",
            ControllerRecord::RecordFailedCrc {
                count: NonZeroU32::new(2).expect("positive"),
            },
        ),
        ("commslinklost_0x0801", ControllerRecord::CommsLinkLost),
        (
            "commspowercycled_0x0802",
            ControllerRecord::CommsPowerCycled {
                count: NonZeroU32::new(3).expect("positive"),
            },
        ),
        (
            "commsunrecoverable_0x0803",
            ControllerRecord::CommsUnrecoverable { rail_on: false },
        ),
        (
            "comms_unrecoverable_on_0x0803",
            ControllerRecord::CommsUnrecoverable { rail_on: true },
        ),
        (
            "sessionsshedforbackpressure_0x0804",
            ControllerRecord::SessionsShed {
                count: NonZeroU32::MIN,
            },
        ),
        (
            "commsbootnoise_0x0805",
            ControllerRecord::CommsBootNoise { count: 1140 },
        ),
    ];
    for (name, want) in cases {
        let published = blob_under(name, "body_cbor");
        assert_eq!(
            ControllerRecord::decode(want.kind(), &published),
            Ok(want),
            "{name}"
        );
        let mut dst = [0; CONTROLLER_RECORD_MAX_BYTES];
        let len = want.encode(&mut dst).expect("fits");
        assert_eq!(dst.get(..len), Some(published.as_slice()), "{name}");
    }
}
