//! Generates the protocol test vectors.
//!
//! Every primitive is checked against its RFC's published vectors before any of
//! ours is published, and nothing here may come from `km43` — vectors
//! produced by the code they check agree with its bugs.
//!
//! cites: P-005, P-006, P-087

use anyhow::{Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json, map::Map};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

fn t16(d: [u8; 32]) -> Vec<u8> {
    d[..16].to_vec()
}

/// RFC 5869 HKDF-SHA256, with salt, IKM and info as named arguments.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = vec![0u8; len];
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .expect("length is well under 255 * 32");
    okm
}

/// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, xorout 0x0000.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Encodes by runs, which is what gets the 254-byte boundary right.
///
/// Code `0xFF` means 254 bytes and no implicit zero; any other code `c` means
/// `c - 1` bytes then a zero. So a run of exactly 254 followed by a zero needs
/// both groups — drop the second and the trailing zero is lost, which a round
/// trip cannot see because the decoder loses it too.
fn cobs_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 254 + 2);
    let runs: Vec<&[u8]> = data.split(|&b| b == 0).collect();
    let last = runs.len() - 1;
    for (idx, run) in runs.iter().enumerate() {
        let mut rest: &[u8] = run;
        let mut emitted_full_block = false;
        while rest.len() >= 254 {
            out.push(0xFF);
            out.extend_from_slice(&rest[..254]);
            rest = &rest[254..];
            emitted_full_block = true;
        }
        if idx == last && emitted_full_block && rest.is_empty() {
            continue; // the 0xFF group already ended the data
        }
        out.push(u8::try_from(rest.len() + 1).expect("rest is under 254"));
        out.extend_from_slice(rest);
    }
    out
}

fn cobs_decode(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let code = data[i];
        if code == 0 {
            bail!("zero code byte inside a COBS frame");
        }
        i += 1;
        let end = i + usize::from(code) - 1;
        if end > data.len() {
            bail!("COBS block runs past the end of the frame");
        }
        out.extend_from_slice(&data[i..end]);
        i = end;
        if code != 0xFF && i < data.len() {
            out.push(0);
        }
    }
    Ok(out)
}

/// The CBOR shapes this protocol uses, encoded per RFC 8949 §4.2.
///
/// There is no float variant and there never will be: P-018 keeps floating
/// point off the wire, so every measurement arrives as `I` with a scale.
enum Cb {
    U(u64),
    I(i64),
    B(Vec<u8>),
    T(String),
    A(Vec<Cb>),
    M(BTreeMap<u64, Cb>),
    Bool(bool),
}

fn head(major: u8, val: u64) -> Vec<u8> {
    let m = major << 5;
    match val {
        0..=23 => vec![m | u8::try_from(val).expect("under 24")],
        24..=0xFF => vec![m | 0x18, u8::try_from(val).expect("under 256")],
        0x100..=0xFFFF => {
            let mut v = vec![m | 0x19];
            v.extend_from_slice(&u16::try_from(val).expect("under 65536").to_be_bytes());
            v
        }
        0x1_0000..=0xFFFF_FFFF => {
            let mut v = vec![m | 0x1A];
            v.extend_from_slice(&u32::try_from(val).expect("under 2^32").to_be_bytes());
            v
        }
        _ => {
            let mut v = vec![m | 0x1B];
            v.extend_from_slice(&val.to_be_bytes());
            v
        }
    }
}

fn cbor(c: &Cb) -> Vec<u8> {
    match c {
        Cb::U(v) => head(0, *v),
        // Nothing carries a sign bit. Major 0 counts up from 0 and major 1
        // counts down from -1, so a negative goes out as -1 - n and -1 is one
        // byte, same as 0. The subtraction cannot wrap: v is negative here, so
        // its magnitude is at least 1.
        Cb::I(v) => {
            if *v < 0 {
                head(1, v.unsigned_abs().saturating_sub(1))
            } else {
                head(0, v.unsigned_abs())
            }
        }
        // A simple value is major 7 with the value as the argument, which is
        // why `false` and `true` are one byte and not a tagged anything.
        Cb::Bool(b) => head(7, if *b { 21 } else { 20 }),
        Cb::B(b) => {
            let mut o = head(2, b.len() as u64);
            o.extend_from_slice(b);
            o
        }
        Cb::T(s) => {
            let mut o = head(3, s.len() as u64);
            o.extend_from_slice(s.as_bytes());
            o
        }
        Cb::A(items) => {
            let mut o = head(4, items.len() as u64);
            for i in items {
                o.extend(cbor(i));
            }
            o
        }
        Cb::M(m) => {
            let mut o = head(5, m.len() as u64);
            for (k, v) in m {
                o.extend(head(0, *k));
                o.extend(cbor(v));
            }
            o
        }
    }
}

macro_rules! cmap {
    ($($k:expr => $v:expr),* $(,)?) => {{
        let mut m = BTreeMap::new();
        $(m.insert($k as u64, $v);)*
        Cb::M(m)
    }};
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

/// Accumulates the primitive checks so one failure does not hide the rest.
struct SelfCheck {
    failures: Vec<String>,
}

impl SelfCheck {
    fn new() -> Self {
        println!("Validating primitives against published vectors:");
        Self {
            failures: Vec::new(),
        }
    }

    fn expect(&mut self, name: &str, got: &str, want: &str) {
        if got == want {
            println!("  [ok] {name}");
        } else {
            println!("  [FAIL] {name}");
            self.failures.push(format!("{name}: got {got} want {want}"));
        }
    }

    fn kdf_and_mac(&mut self) {
        // RFC 5869 A.1 and A.3
        self.expect(
            "HKDF-SHA256 RFC 5869 A.1",
            &hex(&hkdf(
                &(0u8..=12).collect::<Vec<u8>>(),
                &[0x0b; 22],
                &hex_to_bytes("f0f1f2f3f4f5f6f7f8f9"),
                42,
            )),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
        self.expect(
            "HKDF-SHA256 RFC 5869 A.3 zero salt/info",
            &hex(&hkdf(&[], &[0x0b; 22], &[], 42)),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
        // RFC 4231 case 2
        self.expect(
            "HMAC-SHA256 RFC 4231 case 2",
            &hex(&hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
        self.expect(
            "CRC-16/CCITT-FALSE check value",
            &format!("{:#06x}", crc16(b"123456789")),
            "0x29b1",
        );
    }

    fn cobs(&mut self) -> Result<()> {
        // Cheshire & Baker's own examples. Cases 6-9 are the 254-byte boundary.
        let r = |a: u16, b: u16| -> Vec<u8> { (a..b).map(|v| u8::try_from(v).unwrap()).collect() };
        let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
            ("case 1", vec![0x00], vec![0x01, 0x01]),
            ("case 2", vec![0x00, 0x00], vec![0x01, 0x01, 0x01]),
            (
                "case 3",
                vec![0x11, 0x22, 0x00, 0x33],
                vec![0x03, 0x11, 0x22, 0x02, 0x33],
            ),
            // A zero at both ends of a one-byte run: three blocks, two of them
            // empty. Absent until somebody checked this table against the paper
            // row by row rather than trusting the comment above it.
            (
                "case 3b",
                vec![0x00, 0x11, 0x00],
                vec![0x01, 0x02, 0x11, 0x01],
            ),
            (
                "case 4",
                vec![0x11, 0x22, 0x33, 0x44],
                vec![0x05, 0x11, 0x22, 0x33, 0x44],
            ),
            (
                "case 5",
                vec![0x11, 0x00, 0x00, 0x00],
                vec![0x02, 0x11, 0x01, 0x01, 0x01],
            ),
            (
                "case 6 (254 B, exactly one block)",
                r(1, 255),
                [vec![0xFF], r(1, 255)].concat(),
            ),
            (
                "case 7 (leading zero, 255 B)",
                r(0, 255),
                [vec![0x01, 0xFF], r(1, 255)].concat(),
            ),
            (
                "case 8 (255 B, overflows a block)",
                r(1, 256),
                [vec![0xFF], r(1, 255), vec![0x02, 0xFF]].concat(),
            ),
            (
                "case 9 (trailing zero, 255 B)",
                [r(2, 256), vec![0]].concat(),
                [vec![0xFF], r(2, 256), vec![0x01, 0x01]].concat(),
            ),
            (
                "case 10 (zero one byte short of a block, 255 B)",
                [r(3, 256), vec![0, 1]].concat(),
                [vec![0xFE], r(3, 256), vec![0x02, 0x01]].concat(),
            ),
        ];
        for (name, raw, enc) in &cases {
            self.expect(&format!("COBS {name}"), &hex(&cobs_encode(raw)), &hex(enc));
            self.expect(
                &format!("COBS {name} decode"),
                &hex(&cobs_decode(enc)?),
                &hex(raw),
            );
        }

        // Round trip over every length that matters, four fill patterns.
        let mut rt_ok = true;
        for n in (0usize..300).chain([1024, 1026]) {
            for filler in [0x00u8, 0x41, 0xFF] {
                let d = vec![filler; n];
                if cobs_decode(&cobs_encode(&d))? != d {
                    rt_ok = false;
                }
            }
            let d: Vec<u8> = (0..n)
                .map(|i| u8::try_from((i * 7 + 1) % 256).unwrap())
                .collect();
            if cobs_decode(&cobs_encode(&d))? != d {
                rt_ok = false;
            }
        }
        self.expect(
            "COBS round trip, 0..299 + 1024/1026, four patterns",
            &rt_ok.to_string(),
            "true",
        );
        Ok(())
    }

    fn cbor(&mut self) {
        self.cbor_unsigned_widths();
        self.cbor_negative_widths();
        self.cbor_string_widths();
        self.cbor_maps_and_arrays();
        self.cbor_flags();
    }

    /// Major type 0 at every width the head can take.
    ///
    /// A head that grows one value too late or one too early still round trips
    /// against itself, so only an outside answer catches it — most of these
    /// rows are RFC 8949 Appendix A, and the rest are the same boundaries.
    fn cbor_unsigned_widths(&mut self) {
        for (name, v, want) in [
            ("CBOR uint 0", Cb::U(0), "00"),
            ("CBOR uint 1", Cb::U(1), "01"),
            ("CBOR uint 10", Cb::U(10), "0a"),
            ("CBOR uint 23, last head with no argument", Cb::U(23), "17"),
            ("CBOR uint 24, argument becomes one byte", Cb::U(24), "1818"),
            ("CBOR uint 25", Cb::U(25), "1819"),
            ("CBOR uint 100", Cb::U(100), "1864"),
            ("CBOR uint 255, last one-byte argument", Cb::U(255), "18ff"),
            ("CBOR uint 256, argument becomes two", Cb::U(256), "190100"),
            ("CBOR uint 1000", Cb::U(1000), "1903e8"),
            (
                "CBOR uint 65535, last two-byte argument",
                Cb::U(65535),
                "19ffff",
            ),
            (
                "CBOR uint 65536, argument becomes four",
                Cb::U(65536),
                "1a00010000",
            ),
            ("CBOR uint 1000000", Cb::U(1_000_000), "1a000f4240"),
            (
                "CBOR uint 4294967295, last four-byte argument",
                Cb::U(4_294_967_295),
                "1affffffff",
            ),
            (
                "CBOR uint 4294967296, argument becomes eight",
                Cb::U(4_294_967_296),
                "1b0000000100000000",
            ),
            (
                "CBOR uint 1000000000000",
                Cb::U(1_000_000_000_000),
                "1b000000e8d4a51000",
            ),
            ("CBOR uint u64::MAX", Cb::U(u64::MAX), "1bffffffffffffffff"),
        ] {
            self.expect(name, &hex(&cbor(&v)), want);
        }
    }

    /// Major type 1, which is on the wire the first time a bank discharges.
    ///
    /// P-089 puts a signed `i32` in `Value` key 3, and major 1 stores `-1 - n`
    /// rather than a sign, so -1 is one byte and -25 needs two while -24 does
    /// not. An encoder written from memory is off by one here.
    fn cbor_negative_widths(&mut self) {
        for (name, v, want) in [
            ("CBOR nint -1", Cb::I(-1), "20"),
            ("CBOR nint -5", Cb::I(-5), "24"),
            ("CBOR nint -10", Cb::I(-10), "29"),
            (
                "CBOR nint -24, last head with no argument",
                Cb::I(-24),
                "37",
            ),
            (
                "CBOR nint -25, argument becomes one byte",
                Cb::I(-25),
                "3818",
            ),
            ("CBOR nint -100", Cb::I(-100), "3863"),
            (
                "CBOR nint -256, last one-byte argument",
                Cb::I(-256),
                "38ff",
            ),
            (
                "CBOR nint -257, argument becomes two",
                Cb::I(-257),
                "390100",
            ),
            ("CBOR nint -1000", Cb::I(-1000), "3903e7"),
            (
                "CBOR nint -65536, last two-byte argument",
                Cb::I(-65536),
                "39ffff",
            ),
            (
                "CBOR nint -65537, argument becomes four",
                Cb::I(-65537),
                "3a00010000",
            ),
            (
                "CBOR nint i32::MIN, the widest a Value key 3 goes",
                Cb::I(-2_147_483_648),
                "3a7fffffff",
            ),
            (
                "CBOR nint -4294967296, last four-byte argument",
                Cb::I(-4_294_967_296),
                "3affffffff",
            ),
            (
                "CBOR nint -4294967297, argument becomes eight",
                Cb::I(-4_294_967_297),
                "3b0000000100000000",
            ),
            (
                "CBOR int 0 through the signed path stays major 0",
                Cb::I(0),
                "00",
            ),
            (
                "CBOR int i32::MAX through the signed path stays major 0",
                Cb::I(2_147_483_647),
                "1a7fffffff",
            ),
        ] {
            self.expect(name, &hex(&cbor(&v)), want);
        }
    }

    /// Byte and text strings share the head, so they share the boundary.
    ///
    /// A 16-byte MAC sits under it and a 32-byte tag over it, and an encoder
    /// that writes a one-byte head for 24 makes the next field start a byte
    /// early — the map after it decodes as garbage rather than as an error.
    fn cbor_string_widths(&mut self) {
        for (name, v, want) in [
            ("CBOR bstr empty", Cb::B(Vec::new()), "40"),
            ("CBOR bstr of one zero byte", Cb::B(vec![0]), "4100"),
            ("CBOR bstr 01020304", Cb::B(vec![1, 2, 3, 4]), "4401020304"),
            (
                "CBOR bstr 23 bytes, last head with no argument",
                Cb::B((0u8..23).collect()),
                "57000102030405060708090a0b0c0d0e0f10111213141516",
            ),
            (
                "CBOR bstr 24 bytes, length becomes its own byte",
                Cb::B((0u8..24).collect()),
                "5818000102030405060708090a0b0c0d0e0f1011121314151617",
            ),
            ("CBOR tstr empty", Cb::T(String::new()), "60"),
            ("CBOR tstr \"a\"", Cb::T("a".into()), "6161"),
            ("CBOR tstr \"IETF\"", Cb::T("IETF".into()), "6449455446"),
            (
                "CBOR tstr 23 chars, last head with no argument",
                Cb::T("abcdefghijklmnopqrstuvw".into()),
                "776162636465666768696a6b6c6d6e6f7071727374757677",
            ),
            (
                "CBOR tstr 24 chars, length becomes its own byte",
                Cb::T("abcdefghijklmnopqrstuvwx".into()),
                "78186162636465666768696a6b6c6d6e6f707172737475767778",
            ),
            // A label is UTF-8 and somebody will name a room with an accent in
            // it. The length is bytes, not characters, and the two differ by
            // one here — count characters and the reader is left a byte short
            // in the middle of a MAC.
            (
                "CBOR tstr \"café\", 4 characters but 5 bytes",
                Cb::T("café".into()),
                "65636166c3a9",
            ),
            (
                "CBOR tstr 23 characters that are 24 bytes",
                Cb::T("abcdefghijklmnopqrstuvé".into()),
                "78186162636465666768696a6b6c6d6e6f70717273747576c3a9",
            ),
        ] {
            self.expect(name, &hex(&cbor(&v)), want);
        }
    }

    /// Containers, and the ordering P-016 requires of them.
    ///
    /// Map keys go out ascending whatever order the source built them in;
    /// nothing pinned that until this row, and two encoders that disagree
    /// produce two different byte strings for one body with nothing to point
    /// at but a hex dump.
    fn cbor_maps_and_arrays(&mut self) {
        for (name, v, want) in [
            ("CBOR array empty", Cb::A(Vec::new()), "80"),
            (
                "CBOR array [1,2,3]",
                Cb::A(vec![Cb::U(1), Cb::U(2), Cb::U(3)]),
                "83010203",
            ),
            (
                "CBOR array [1,[2,3],[4,5]]",
                Cb::A(vec![
                    Cb::U(1),
                    Cb::A(vec![Cb::U(2), Cb::U(3)]),
                    Cb::A(vec![Cb::U(4), Cb::U(5)]),
                ]),
                "8301820203820405",
            ),
            (
                "CBOR array of 25, length becomes its own byte",
                Cb::A((1u64..=25).map(Cb::U).collect()),
                "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            ),
            ("CBOR map empty", Cb::M(BTreeMap::new()), "a0"),
            (
                "CBOR map {1:2,3:4}",
                cmap! {1 => Cb::U(2), 3 => Cb::U(4)},
                "a201020304",
            ),
            (
                "CBOR map built 24,1,256,23 goes out ascending",
                cmap! {24 => Cb::U(1), 1 => Cb::U(2), 256 => Cb::U(3), 23 => Cb::U(4)},
                "a40102170418180119010003",
            ),
            (
                "CBOR map of 24 keys, length becomes its own byte",
                Cb::M((1u64..=24).map(|k| (k, Cb::U(0))).collect()),
                "b8180100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700181800",
            ),
            (
                "CBOR map nested one level",
                cmap! {1 => cmap!{2 => Cb::U(3)}},
                "a101a10203",
            ),
            // The shape a Snapshot has: a body map, a values array, a Value map
            // per channel, one of them reading below zero.
            (
                "CBOR map, array of maps, three levels deep",
                cmap! {
                    1 => Cb::A(vec![
                        cmap!{1 => Cb::U(1), 2 => Cb::I(-5)},
                        cmap!{1 => Cb::U(2), 2 => Cb::I(0)},
                    ]),
                    2 => Cb::B(vec![0xDE, 0xAD]),
                },
                "a20182a201010224a2010202000242dead",
            ),
        ] {
            self.expect(name, &hex(&cbor(&v)), want);
        }
    }

    /// The four booleans on the wire — `provisioned`, `pairing_open`, `gap`,
    /// `complete` — are major 7 simple values, one byte each and never a
    /// number. An encoder that writes them as 0 and 1 is a decoder's error 1.
    fn cbor_flags(&mut self) {
        for (name, v, want) in [
            ("CBOR false", Cb::Bool(false), "f4"),
            ("CBOR true", Cb::Bool(true), "f5"),
            (
                "CBOR Discover-shaped {5:true, 6:false}",
                cmap! {5 => Cb::Bool(true), 6 => Cb::Bool(false)},
                "a205f506f4",
            ),
        ] {
            self.expect(name, &hex(&cbor(&v)), want);
        }
    }

    /// The two bodies that had no outside opinion at all.
    ///
    /// Seventeen key numbers, six capacity widths and the ascending order they
    /// go out in were asserted only against the encoder that wrote them: a
    /// `max_channels` of 32 emitted as one byte, or key 15 emitted as 16, round
    /// trips against itself and reads correctly in a hex dump. Every byte below
    /// was derived by hand from the field lists in `docs/PROTOCOL.md`.
    fn pre_session_bodies(&mut self, b: &Builder) {
        const DISCOVER: &str = concat!(
            "a8",   // map, 8 keys
            "0101", // 1: protocol_major = 1
            "0200", // 2: protocol_minor = 0
            "0350",
            "4f524947494e38392044454d4f203031", // 3: device_id, bstr16
            "0476",
            "4f726967696e3839204354524c2d3120284730423129", // 4: model, tstr 22
            "05f4",                                         // 5: provisioned = false
            "06f5",                                         // 6: pairing_open = true
            "0750",
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", // 7: challenge, bstr16
            "0801",                             // 8: epoch = 1
        );
        const HELLO: &str = concat!(
            "b81d", // map, 29 keys — past 23, so the header grows its own byte
            "0101", // 1: protocol_major = 1
            "0200", // 2: protocol_minor = 0
            "0303", // 3: session_id = 3
            // 4: fw_controller, tstr 22
            "0476",
            "6f38392d73746d333220302e312e302b316132623363",
            // 5: fw_comms, tstr 24 -- one longer, and the length becomes its own
            // byte. Get this wrong and key 6 starts a byte early, so the rest of
            // the map decodes as plausible numbers rather than as an error.
            "057818",
            "6573703332633620302e322e302d756e7665726966696564",
            "0618f7",               // 6: capabilities, bits 0-2 and 4-7
            "0701",                 // 7: log_oldest_seq = 1
            "08190100",             // 8: log_newest_seq = 256, argument becomes two bytes
            "0918ff",               // 9: state_seq = 255, last one-byte argument
            "0af5",                 // 10: time_known = true
            "0b1841",               // 11: counter = 65
            "0c08",                 // 12: max_sessions = 8
            "0d1820",               // 13: max_channels = 32, over 23 so the head grows
            "0e08",                 // 14: max_clients = 8
            "0f10",                 // 15: max_event_queue = 16
            "1004",                 // 16: max_inflight = 4
            "111820",               // 17: max_cmd_dedup = 32
            "1200",                 // 18: rev = 0, a controller with no topology yet
            "13480000000000000000", // 19: topo_digest, bstr8 of zero
            "1408",                 // 20: max_buses = 8
            "151818",               // 21: max_devices = 24
            "1618a0",               // 22: max_components = 160
            "17190180",             // 23: max_signals = 384, argument becomes two bytes
            // Key 24 is where a map key stops fitting one byte. `1818` is the
            // key, not a value — this is the only body in the protocol whose
            // numbering crosses that boundary, and reading it as one byte puts
            // every field after it one short.
            "1818190200", // 24: max_series_elements = 512
            "18191860",   // 25: max_params = 96
            "181a1830",   // 26: max_concerns = 48
            "181b0c",     // 27: max_selectors = 12
            "181c1818",   // 28: max_history_signals = 24
            "181d04",     // 29: max_topology_depth = 4
        );

        self.expect("Discover 0x80 body", &hex(&b.discover_body()), DISCOVER);
        self.expect("Hello 0x81 inner body", &hex(&b.hello_body()), HELLO);
    }

    fn finish(self) -> Result<()> {
        if self.failures.is_empty() {
            println!("\nAll primitives agree with their published vectors.\n");
            return Ok(());
        }
        eprintln!("\nPRIMITIVE VALIDATION FAILED:");
        for x in &self.failures {
            eprintln!("  {x}");
        }
        bail!(
            "{} primitive check(s) failed — the vectors would encode the bug",
            self.failures.len()
        )
    }
}

fn self_check(b: &Builder) -> Result<()> {
    let mut c = SelfCheck::new();
    c.kdf_and_mac();
    c.cobs()?;
    c.cbor();
    c.pre_session_bodies(b);
    c.finish()
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex literal"))
        .collect()
}

const L_CLIENT_KEY: &[u8] = b"km43/v1/client-key";
const L_SESSION_KEY: &[u8] = b"km43/v1/session-key";
const L_PAIR_KEY: &[u8] = b"km43/v1/pair-key";
const L_PAIR_PROOF: &[u8] = b"km43/v1/pair-proof";
const L_PAIR_ACK: &[u8] = b"km43/v1/pair-ack";
const L_HELLO_PROOF: &[u8] = b"km43/v1/hello-proof";
const L_REQ: &[u8] = b"km43/v1/req";
const L_WRQ: &[u8] = b"km43/v1/wrq";
const L_RSP: &[u8] = b"km43/v1/rsp";
const L_EVT: &[u8] = b"km43/v1/evt";

const MAX_PAYLOAD: usize = 1024;

/// The version every body in this file carries. `Hello 0x01` announces it and
/// `Discover 0x80` and `Hello 0x81` answer with it, so one pair of numbers held
/// in one place is what stops a vector set from negotiating with itself.
const PROTOCOL_MAJOR: u64 = 1;
const PROTOCOL_MINOR: u64 = 0;

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_owned(), v);
    }
    Value::Object(m)
}

/// What kind of client is enrolling. One byte on the wire, inside the pairing
/// proof, so the comms processor cannot rewrite it.
#[derive(Clone, Copy)]
enum ClientKind {
    App = 1,
}

/// How the controller answered a pairing attempt.
#[derive(Clone, Copy)]
enum PairOutcome {
    Enrolled = 1,
}

/// The message types the vectors exercise.
#[derive(Clone, Copy)]
enum Msg {
    Event = 0x04,
    ReadLog = 0x05,
    Command = 0x08,
    Discover = 0x80,
    // `Hello` is the 0x81 *response*; the request 0x01 has no vector here.
    Hello = 0x81,
    Ack = 0x88,
}

/// The link-local message types the vectors exercise.
///
/// A second enum rather than more arms on [`Msg`]: they are two ranges with two
/// audiences, and the link-local half is the one the ESP32 firmware has to
/// agree with. Mixing them would let a client vector be published under a link
/// name by a typo nothing catches.
#[derive(Clone, Copy)]
enum Link {
    Up = 0x60,
    ClientConnected = 0x62,
    ClientConnectedAck = 0xe2,
    TimeOffer = 0x66,
    TimeOfferAck = 0xe6,
    NetConfigAck = 0xe5,
    CommsRelease = 0x67,
    CommsReleaseAck = 0xe7,
}

/// One published link frame before it is framed: the envelope's three header
/// fields, the body, and the body in words for whoever reads the file without a
/// CBOR decoder.
struct LinkCase {
    name: &'static str,
    kind: Link,
    session: u16,
    req_id: u32,
    body: Cb,
    readable: String,
}

/// The six capacities this controller reports in `Hello 0x81` keys 12 to 17.
///
/// They are what *this* device enforces, not what the protocol permits (P-005),
/// and `max_channels` is only ever reported downward from 32 (P-006) — report
/// more and a fully configured site builds a snapshot the controller then
/// refuses with error 5, which no client can do anything about.
struct ReportedLimits {
    sessions: u8,
    channels: u8,
    clients: u8,
    event_queue: u16,
    inflight: u8,
    cmd_dedup: u16,
}

/// What the controller says about itself in the two pre-session bodies.
///
/// Nothing in here is a measurement and nothing in here is secret: `fw_comms`
/// in particular is the comms processor's own claim about the comms processor,
/// which is why the spec forbids reading it as evidence that any image is
/// installed.
struct SelfReport {
    model: &'static str,
    provisioned: bool,
    pairing_open: bool,
    fw_controller: &'static str,
    fw_comms: &'static str,
    capabilities: u32,
    log_oldest_seq: u64,
    log_newest_seq: u64,
    state_seq: u64,
    time_known: bool,
    limits: ReportedLimits,
}

impl SelfReport {
    /// A fresh unit with somebody holding the button, chosen so the widths
    /// differ: `fw_controller` is 23 bytes and `fw_comms` is 24, which is the
    /// byte where a CBOR string head gains its own length byte.
    const fn new() -> Self {
        Self {
            model: "Origin89 CTRL-1 (G0B1)",
            provisioned: false,
            pairing_open: true,
            fw_controller: "o89-stm32 0.1.0+1a2b3c",
            fw_comms: "esp32c6 0.2.0-unverified",
            // Bits 0, 1, 2, 4, 5, 6 and 7 set; bit 3 clear because there is no
            // bootloader to push an image to yet.
            capabilities: 0xF7,
            log_oldest_seq: 1,
            log_newest_seq: 256,
            state_seq: 255,
            time_known: true,
            limits: ReportedLimits {
                sessions: 8,
                channels: 32,
                clients: 8,
                event_queue: 16,
                inflight: 4,
                cmd_dedup: 32,
            },
        }
    }

    fn inputs(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("model", json!(self.model)),
            ("provisioned", json!(self.provisioned)),
            ("pairing_open", json!(self.pairing_open)),
            ("fw_controller", json!(self.fw_controller)),
            ("fw_comms", json!(self.fw_comms)),
            ("capabilities", json!(self.capabilities)),
            ("log_oldest_seq", json!(self.log_oldest_seq)),
            ("log_newest_seq", json!(self.log_newest_seq)),
            ("state_seq", json!(self.state_seq)),
            ("time_known", json!(self.time_known)),
            (
                "reported_limits",
                obj(vec![
                    ("max_sessions", json!(self.limits.sessions)),
                    ("max_channels", json!(self.limits.channels)),
                    ("max_clients", json!(self.limits.clients)),
                    ("max_event_queue", json!(self.limits.event_queue)),
                    ("max_inflight", json!(self.limits.inflight)),
                    ("max_cmd_dedup", json!(self.limits.cmd_dedup)),
                ]),
            ),
        ]
    }
}

/// Everything the vectors are computed from.
///
/// The inputs are obviously fake so nobody mistakes one for a real device
/// secret in a log, and the keys are derived once here rather than at each use.
pub struct Builder {
    printed_secret: Vec<u8>,
    device_id: Vec<u8>,
    challenge: Vec<u8>,
    next_challenge: Vec<u8>,
    client_nonce: Vec<u8>,
    client_id: u32,
    session_id: u16,
    req_id: u32,
    counter: u64,
    label: &'static str,
    epoch: u32,
    report: SelfReport,

    pair_key: Vec<u8>,
    client_key: Vec<u8>,
    session_key: Vec<u8>,
    client_key_info: Vec<u8>,
    session_key_info: Vec<u8>,
    session_salt: Vec<u8>,
}

/// A response body and its MAC, kept so the frame vector wraps the same bytes.
struct Response {
    inner: Vec<u8>,
    mac: Vec<u8>,
}

impl Builder {
    fn new() -> Self {
        let printed_secret: Vec<u8> = (0u8..32).collect();
        let device_id = b"ORIGIN89 DEMO 01".to_vec();
        let challenge = hex_to_bytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let client_nonce = hex_to_bytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        let client_id: u32 = 7;
        let session_id: u16 = 3;

        // Bumped on every factory reset, and the only input to a client key
        // anybody can change: the device id is etched and the printed secret is
        // on a label nobody can reprint into a unit already on a wall.
        let epoch: u32 = 1;

        let client_key_info =
            [L_CLIENT_KEY, &epoch.to_be_bytes(), &client_id.to_be_bytes()].concat();
        let session_salt = [challenge.clone(), client_nonce.clone()].concat();
        let session_key_info = [L_SESSION_KEY, &session_id.to_be_bytes()[..]].concat();
        let client_key = hkdf(&device_id, &printed_secret, &client_key_info, 32);

        Self {
            pair_key: hkdf(&device_id, &printed_secret, L_PAIR_KEY, 32),
            session_key: hkdf(&session_salt, &client_key, &session_key_info, 32),
            client_key,
            client_key_info,
            session_key_info,
            session_salt,
            printed_secret,
            device_id,
            challenge,
            next_challenge: hex_to_bytes("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
            client_nonce,
            client_id,
            session_id,
            req_id: 0x11,
            counter: 0x42,
            label: "kitchen phone",
            epoch,
            report: SelfReport::new(),
        }
    }

    /// The client's pairing proof. `label` goes last because it is the only
    /// variable-width field: nothing follows it, so no length prefix is needed.
    fn pair_proof(&self) -> (&'static str, Value) {
        let preimage = [
            L_PAIR_PROOF,
            &self.device_id,
            &self.challenge,
            &self.client_nonce,
            &[ClientKind::App as u8],
            self.label.as_bytes(),
        ]
        .concat();
        (
            "pair_proof",
            MacVector::new(DerivedKey::Pair, preimage, "'km43/v1/pair-proof' | device_id[16] | challenge[16] | client_nonce[16] | client_kind:u8 | label (UTF-8, no NUL, last)").finish(&self.pair_key),
        )
    }

    /// The controller's answer, which fixes the client's identity and carries
    /// the challenge for the handshake that follows.
    fn pair_ack(&self) -> (&'static str, Value) {
        let preimage = [
            L_PAIR_ACK,
            &self.device_id,
            &self.challenge,
            &self.client_nonce,
            &[PairOutcome::Enrolled as u8],
            &self.client_id.to_be_bytes(),
            &self.epoch.to_be_bytes(),
            &self.next_challenge,
        ]
        .concat();
        (
            "pair_ack_mac",
            MacVector::new(DerivedKey::Pair, preimage, "'km43/v1/pair-ack' | device_id[16] | challenge[16] | client_nonce[16] | outcome:u8 | client_id:u32be | epoch:u32be | next_challenge[16]").finish(&self.pair_key),
        )
    }

    fn hello_proof(&self) -> (&'static str, Value) {
        let inner = cbor(&cmap! {
            1 => Cb::U(PROTOCOL_MAJOR), 2 => Cb::U(PROTOCOL_MINOR),
            3 => Cb::U(u64::from(self.client_id)),
            4 => Cb::T("o89-cli 0.1.0".into()), 5 => Cb::B(self.client_nonce.clone()),
        });
        let preimage = [
            L_HELLO_PROOF,
            &self.challenge,
            &self.client_nonce,
            &self.client_id.to_be_bytes(),
            &inner,
        ]
        .concat();
        (
            "hello_proof",
            MacVector::new(DerivedKey::Client, preimage, "'km43/v1/hello-proof' | challenge[16] | client_nonce[16] | client_id:u32be | payload")
                .with("inner_body_cbor", hex(&inner))
                .finish(&self.client_key),
        )
    }

    /// `Discover 0x80`, the only thing an unauthenticated peer is given.
    ///
    /// The challenge is the one the `Pair` and `Hello` proofs below are computed
    /// against, so this is the Discover at the top of the enrolment flow:
    /// nothing enrolled yet and somebody holding the button.
    fn discover_body(&self) -> Vec<u8> {
        cbor(&cmap! {
            1 => Cb::U(PROTOCOL_MAJOR),
            2 => Cb::U(PROTOCOL_MINOR),
            3 => Cb::B(self.device_id.clone()),
            4 => Cb::T(self.report.model.into()),
            5 => Cb::Bool(self.report.provisioned),
            6 => Cb::Bool(self.report.pairing_open),
            7 => Cb::B(self.challenge.clone()),
            8 => Cb::U(u64::from(self.epoch)),
        })
    }

    /// `Hello 0x81`'s inner body — what key 1 of the wrapper carries.
    ///
    /// Key 11 is one below the counter the signed request uses, because it is
    /// the highest value already *accepted*: publish the two as equal and the
    /// request beside it is a replay.
    fn hello_body(&self) -> Vec<u8> {
        let r = &self.report;
        cbor(&cmap! {
            1 => Cb::U(PROTOCOL_MAJOR),
            2 => Cb::U(PROTOCOL_MINOR),
            3 => Cb::U(u64::from(self.session_id)),
            4 => Cb::T(r.fw_controller.into()),
            5 => Cb::T(r.fw_comms.into()),
            6 => Cb::U(u64::from(r.capabilities)),
            7 => Cb::U(r.log_oldest_seq),
            8 => Cb::U(r.log_newest_seq),
            9 => Cb::U(r.state_seq),
            10 => Cb::Bool(r.time_known),
            11 => Cb::U(self.counter.saturating_sub(1)),
            12 => Cb::U(u64::from(r.limits.sessions)),
            13 => Cb::U(u64::from(r.limits.channels)),
            14 => Cb::U(u64::from(r.limits.clients)),
            15 => Cb::U(u64::from(r.limits.event_queue)),
            16 => Cb::U(u64::from(r.limits.inflight)),
            17 => Cb::U(u64::from(r.limits.cmd_dedup)),
            // Keys 18 to 29: the topology plane. `rev` is 0 and the digest is
            // eight zero bytes because this fixture reports a controller that
            // has no topology yet — the digest's own vector is the inventory
            // entry's, computed over rows rather than asserted here.
            18 => Cb::U(0),
            19 => Cb::B(vec![0; 8]),
            20 => Cb::U(8),
            21 => Cb::U(24),
            22 => Cb::U(160),
            23 => Cb::U(384),
            24 => Cb::U(512),
            25 => Cb::U(96),
            26 => Cb::U(48),
            27 => Cb::U(12),
            28 => Cb::U(24),
            29 => Cb::U(4),
        })
    }

    /// The three bodies that carry no MAC of their own.
    /// A `MAX_LABEL` label and a `MAX_IDENT` identifier, written out rather than
    /// generated, because a vector built by a loop is a vector that agrees with
    /// whatever the loop believed.
    fn widest_label() -> String {
        "01234567890123456789012345678901".to_owned()
    }

    fn widest_ident() -> String {
        "012345678901234567890123".to_owned()
    }

    /// One descriptor row of each kind, every optional key present and every
    /// field at the top of the width it may **legally** carry.
    ///
    /// Nothing here is a plausible descriptor. It is a **size**: the number that
    /// matters is each row's length beside the row-width table the design
    /// derives by hand. Built from this file's own CBOR writer, which has never
    /// seen `km43` — a vector produced by the code it checks agrees with
    /// that code's bugs.
    ///
    /// **The values below are written out rather than read from the registry,
    /// and that is the point.** `9` for a signal domain is this file saying what
    /// the space holds; `km43` derives the same number by asking the
    /// generated enum. Two opinions that have to meet, which is the whole reason
    /// this generator does not depend on that crate.
    fn inventory_widest_rows() -> Vec<(&'static str, Cb)> {
        let u16max = u64::from(u16::MAX);
        let u8max = u64::from(u8::MAX);
        let u32max = u64::from(u32::MAX);
        let cmds = || Cb::A((0..4).map(|_| Cb::U(u16max)).collect());

        vec![
            (
                "bus",
                cmap! {
                    // `transport` is a closed space of seven, so its widest is
                    // 7 and not `u8::MAX` — a port on an eighth kind of bus is
                    // a row nothing can be told to talk over.
                    1 => Cb::U(u8max), 2 => Cb::U(7),
                    3 => Cb::T(Self::widest_label()), 4 => Cb::U(u32max),
                },
            ),
            (
                "device",
                cmap! {
                    1 => Cb::U(u16max), 2 => Cb::U(u8max), 3 => Cb::B(vec![0xFF; 8]),
                    4 => Cb::U(u16max), 5 => Cb::U(u16max), 6 => Cb::U(u16max),
                    7 => Cb::U(u16max),
                    8 => Cb::T(Self::widest_ident()), 9 => Cb::T(Self::widest_ident()),
                    10 => Cb::T(Self::widest_ident()), 11 => Cb::T(Self::widest_label()),
                    12 => Cb::U(u32max), 13 => cmds(),
                },
            ),
            (
                "component",
                cmap! {
                    1 => Cb::U(u16max), 2 => Cb::U(u16max), 3 => Cb::U(u16max),
                    4 => Cb::U(u16max), 5 => Cb::U(u16max), 6 => Cb::U(u16max),
                    7 => Cb::T(Self::widest_label()), 8 => cmds(), 9 => Cb::U(u32max),
                },
            ),
            (
                "signal",
                cmap! {
                    1 => Cb::U(u16max), 2 => Cb::U(u16max), 3 => Cb::U(u16max),
                    // Four of these are pinned by something other than their
                    // type, and every one of them used to be `u8::MAX` or
                    // `u16::MAX` here — a row the field list forbids, published
                    // as a width. `shape` 2 and `vtype` 4 because `n` and `esp`
                    // are legal only under exactly those. `n` at MAX_SERIES_LEN
                    // because a longer series has elements no `Concern` can
                    // name, and `ebase` at the top that still leaves sixteen
                    // labels below `u16::MAX`, because a higher one promises
                    // cells that do not exist (P-206).
                    4 => Cb::U(u16max), 5 => Cb::U(2), 6 => Cb::U(4),
                    // `domain` is nine, `dir` is three and `hist` is three:
                    // closed spaces, no vendor range, so a number outside one
                    // is error 1 rather than a value to skip.
                    7 => Cb::U(9), 8 => Cb::U(u16max), 9 => Cb::U(3),
                    10 => Cb::U(16), 11 => Cb::U(u16max), 12 => Cb::U(u16max - 15),
                    13 => Cb::U(u16max), 14 => Cb::U(u8max), 15 => Cb::U(u8max),
                    16 => Cb::U(u16max), 17 => Cb::U(3),
                    18 => Cb::T(Self::widest_label()),
                },
            ),
            (
                "param",
                cmap! {
                    1 => Cb::U(u16max), 2 => Cb::U(u16max), 3 => Cb::U(u16max),
                    4 => Cb::U(u16max), 5 => Cb::I(i64::from(i32::MIN)),
                    // `vtype` 4 for the reason the signal row's is, so key 10
                    // `esp` is a key this row may legally carry.
                    6 => Cb::U(4), 7 => Cb::U(9), 8 => Cb::U(u16max),
                    9 => Cb::U(3), 10 => Cb::U(u16max),
                    11 => Cb::I(i64::from(i32::MIN)), 12 => Cb::I(i64::from(i32::MIN)),
                    13 => Cb::U(u16max), 14 => Cb::U(u8max), 15 => Cb::U(u8max),
                    16 => Cb::U(u16max), 17 => Cb::T(Self::widest_label()),
                },
            ),
        ]
    }

    /// The descriptor the concern page needs and nothing else publishes.
    ///
    /// `concerns_0x8F` reports element **7** of signal 204, and that is a
    /// position — the cell it names is 23. Without this row the two numbers only
    /// meet in a sentence in `rows_readable`, which is prose, and prose is what
    /// P-206 exists because somebody implemented from.
    ///
    /// Sixteen cells of a 32-cell string, on the second half-string component,
    /// so `ebase` is 17 and element 0 is the cell painted 17.
    fn inventory_labelled_series() -> (&'static str, Cb) {
        (
            "signal_series",
            cmap! {
                1 => Cb::U(204),    // sig — the one the concern page names
                2 => Cb::U(3),      // dev
                3 => Cb::U(57),     // cmp — the second half-string
                4 => Cb::U(0x0101), // kind: DC voltage
                5 => Cb::U(2),      // shape: series
                6 => Cb::U(1),      // vtype: gauge
                7 => Cb::U(1),      // domain: live
                10 => Cb::U(16),    // n
                12 => Cb::U(17),    // ebase — element 0 is cell 17
            },
        )
    }

    /// The other end of every row: required keys only, and every value small.
    ///
    /// The `BusRow` here is the narrowest legal descriptor row in the protocol,
    /// and it is what `INVENTORY_PAGE_ROWS_CEILING` divides the page cap by — so
    /// if this vector's length moves, that ceiling is wrong. Cheapest and not
    /// required-keys-at-widest: the ceiling asks how many rows could ever
    /// arrive, which is the opposite question from a width.
    fn inventory_narrowest_rows() -> Vec<(&'static str, Cb)> {
        vec![
            ("bus", cmap! { 1 => Cb::U(1), 2 => Cb::U(1) }),
            (
                "device",
                cmap! {
                    1 => Cb::U(1), 2 => Cb::U(1), 4 => Cb::U(1),
                    5 => Cb::U(1), 6 => Cb::U(1), 12 => Cb::U(41),
                },
            ),
            (
                "component",
                cmap! { 1 => Cb::U(1), 2 => Cb::U(1), 4 => Cb::U(1), 9 => Cb::U(41) },
            ),
            (
                "signal",
                cmap! {
                    1 => Cb::U(1), 2 => Cb::U(1), 3 => Cb::U(0), 4 => Cb::U(0x0101),
                    5 => Cb::U(1), 6 => Cb::U(1), 7 => Cb::U(1),
                },
            ),
            (
                "param",
                cmap! {
                    1 => Cb::U(1), 2 => Cb::U(1), 3 => Cb::U(0),
                    4 => Cb::U(0x0101), 6 => Cb::U(1), 7 => Cb::U(1),
                },
            ),
        ]
    }

    fn inventory_entry() -> (&'static str, Value) {
        let request = cbor(&cmap! {
            1 => Cb::U(41), 2 => Cb::U(2), 3 => Cb::U(0), 4 => Cb::U(7),
        });
        let bus = || {
            Self::inventory_narrowest_rows()
                .into_iter()
                .find(|(n, _)| *n == "bus")
                .map(|(_, r)| r)
                .expect("the bus row is in the list")
        };
        let page = cbor(&cmap! {
            1 => Cb::U(41), 2 => Cb::U(1),
            3 => Cb::A(vec![bus(), bus(), bus()]),
            4 => Cb::U(0), 5 => Cb::U(3), 6 => Cb::U(1),
            7 => Cb::B(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        });

        let mut fields = vec![
            ("type", json!(0x8Du8)),
            (
                "authentication",
                json!(
                    "this is the inner body; on the wire it is key 1 of the wrapper, whose key 2 is a MAC under session_key with the label 'km43/v1/rsp'"
                ),
            ),
            ("request_body_cbor", json!(hex(&request))),
            (
                "request_readable",
                json!("ReadInventory 0x0D {1:rev=41, 2:what=2 devices, 3:from=0, 4:dev=7}"),
            ),
            (
                "rows_readable",
                json!(
                    "one row of each kind at the widest its declared types permit, and one of each carrying required keys only. Neither is a plausible descriptor — each is a size, checked against the row-width table TOPOLOGY-DESIGN.md derives by hand. signal_series is the exception and is a real row: it is the descriptor concerns_0x8F's element 7 has to be read against to come out as cell 23 (P-206)"
                ),
            ),
            ("body_cbor", json!(hex(&page))),
            ("body_len", json!(page.len())),
            (
                "body_readable",
                json!("{1:rev, 2:what, 3:rows, 4:next, 5:total, 6:outcome, 7:digest}"),
            ),
            (
                "values_readable",
                json!(
                    "rev 41, what 1 buses, three bus rows, next 0 so the walk is complete, total 3, outcome 1 ok, and the digest. Key 7 rides this page and only this shape of page: P-145 lets a whole-topology digest travel when key 4 is 0 and the outcome is 1, and nowhere else"
                ),
            ),
        ];
        for (name, row) in Self::inventory_widest_rows() {
            let bytes = cbor(&row);
            fields.push((
                Box::leak(format!("{name}_widest").into_boxed_str()),
                json!({ "row_cbor": hex(&bytes), "row_len": bytes.len() }),
            ));
        }
        for (name, row) in Self::inventory_narrowest_rows() {
            let bytes = cbor(&row);
            fields.push((
                Box::leak(format!("{name}_required_keys_only").into_boxed_str()),
                json!({ "row_cbor": hex(&bytes), "row_len": bytes.len() }),
            ));
        }
        let (name, row) = Self::inventory_labelled_series();
        let bytes = cbor(&row);
        fields.push((
            name,
            json!({ "row_cbor": hex(&bytes), "row_len": bytes.len() }),
        ));
        ("inventory_0x8D", obj(fields))
    }

    /// A `Sample` and a `Series` at the top of the widths their declared types
    /// permit.
    ///
    /// Neither is a plausible reading — a series of sixteen elements all at
    /// `i32::MIN` and all stale is nothing a meter produces. Each is a **size**:
    /// 20 and 111 are what `SAMPLE_MAX_BYTES` and `SERIES_MAX_BYTES` claim, and
    /// the page ceilings divide the byte budget by exactly those.
    fn readings_widest_rows() -> Vec<(&'static str, Cb)> {
        let u16max = u64::from(u16::MAX);
        let u32max = u64::from(u32::MAX);
        // `2 stale` with provenance `1 measured`: the only validity that carries
        // both a value and an age, which is what makes it the widest.
        let stale = 0x21_u64;

        vec![
            (
                "sample",
                cmap! {
                    1 => Cb::U(u16max), 2 => Cb::I(i64::from(i32::MIN)),
                    3 => Cb::U(stale), 4 => Cb::U(u32max),
                },
            ),
            (
                "series",
                cmap! {
                    1 => Cb::U(u16max),
                    2 => Cb::B(vec![0x21; 16]),
                    3 => Cb::A((0..16).map(|_| Cb::I(i64::from(i32::MIN))).collect()),
                    4 => Cb::U(u32max),
                },
            ),
        ]
    }

    fn readings_entry() -> (&'static str, Value) {
        let request = cbor(&cmap! {
            1 => Cb::U(41),
            2 => Cb::A(vec![cmap! { 1 => Cb::U(7) }, cmap! { 3 => Cb::U(21) }]),
            3 => Cb::U(0),
        });

        // One scalar and one series, in ascending `sig` — which is the order
        // P-198 fixes and the only one a page may be a prefix of. `sig` 21 is
        // the series, so the two kinds are not in `sig` blocks: a page splits
        // them into key 4 and key 5 while the selection stays one order.
        let sample = cmap! { 1 => Cb::U(9), 3 => Cb::U(0x11), 2 => Cb::I(1_250) };
        let series = cmap! {
            1 => Cb::U(21),
            2 => Cb::B(vec![0x11, 0x50, 0x11]),
            3 => Cb::A(vec![Cb::I(3_312), Cb::I(3_309)]),
        };
        let page = cbor(&cmap! {
            1 => Cb::U(4_211), 2 => Cb::U(41), 3 => Cb::U(1_767_225_600),
            4 => Cb::A(vec![sample]),
            5 => Cb::A(vec![series]),
            6 => Cb::U(0), 7 => Cb::U(2), 8 => Cb::U(1),
        });

        let mut fields = vec![
            ("type", json!(0x8Eu8)),
            (
                "authentication",
                json!(
                    "this is the inner body; on the wire it is key 1 of the wrapper, whose key 2 is a MAC under session_key with the label 'km43/v1/rsp'"
                ),
            ),
            ("request_body_cbor", json!(hex(&request))),
            (
                "request_readable",
                json!(
                    "ReadSignals 0x0E {1:rev=41, 2:sel=[{1:dev=7}, {3:sig=21}], 3:from=0} — a device and one signal, which resolve to a set union ordered by sig ascending"
                ),
            ),
            ("body_cbor", json!(hex(&page))),
            ("body_len", json!(page.len())),
            (
                "body_readable",
                json!("{1:seq, 2:rev, 3:at, 4:s, 5:v, 6:next, 7:total, 8:outcome}"),
            ),
            (
                "values_readable",
                json!(
                    "seq 4211, rev 41, one scalar at sig 9 reading 12.50 V, and a three-element series at sig 21 whose middle cell has an open sense wire: its q byte is 0x50 sensor_fault, it carries no integer at all, and the two that are readable sit either side of the gap. next 0 so the selection is complete, total 2, outcome 1 ok"
                ),
            ),
        ];
        for (name, row) in Self::readings_widest_rows() {
            let bytes = cbor(&row);
            fields.push((
                Box::leak(format!("{name}_widest").into_boxed_str()),
                json!({ "row_cbor": hex(&bytes), "row_len": bytes.len() }),
            ));
        }
        ("readings_0x8E", obj(fields))
    }

    /// The two ends of the `Concern` row budget, as an outside opinion.
    ///
    /// 63 is what `MAX_CONCERN_PAGE_ROWS` divides the byte cap by, and 37 is the
    /// number behind the design's claim that the byte cap would admit 22 rows
    /// where the row cap admits 12 — which is why the row arm is the one that
    /// binds. Both are derived by hand in TOPOLOGY-DESIGN.md and written as
    /// constants in `limits.rs`, and this is the third opinion.
    fn concern_rows() -> Vec<(&'static str, Cb)> {
        let u16max = u64::from(u16::MAX);
        let u32max = u64::from(u32::MAX);

        vec![
            (
                "concern_widest",
                cmap! {
                    1 => Cb::U(u16max), 2 => Cb::U(u16max), 3 => Cb::U(u16max),
                    4 => Cb::U(u16max), 5 => Cb::U(16), 6 => Cb::U(u16max),
                    7 => Cb::U(4), 8 => Cb::U(5), 9 => Cb::U(u32max),
                    10 => Cb::U(u64::MAX), 11 => Cb::U(u32max), 12 => Cb::U(u16max),
                    13 => Cb::U(u64::MAX),
                },
            ),
            // Narrowest is **fewest keys**, not smallest numbers: no `sig`, no
            // `elem`, no `since`, no vendor code, and every required key still
            // at its widest. A 37 derived from small ids would claim more rows
            // fit than a real page can rely on.
            (
                "concern_required_keys_only",
                cmap! {
                    1 => Cb::U(u16max), 2 => Cb::U(u16max), 3 => Cb::U(u16max),
                    6 => Cb::U(u16max), 7 => Cb::U(4), 8 => Cb::U(5),
                    9 => Cb::U(u32max), 13 => Cb::U(u64::MAX),
                },
            ),
        ]
    }

    fn concerns_entry() -> (&'static str, Value) {
        let request = cbor(&cmap! { 1 => Cb::U(41), 2 => Cb::U(0) });

        // Pack 2's cell 23, which is element 7 of a half-string signal whose
        // `ebase` is 17. Both numbers are correct and they are different, which
        // is the whole of P-206.
        let cell = cmap! {
            1 => Cb::U(9), 2 => Cb::U(3), 3 => Cb::U(57), 4 => Cb::U(204),
            5 => Cb::U(7), 6 => Cb::U(0x0001), 7 => Cb::U(4), 8 => Cb::U(1),
            9 => Cb::U(21_600), 10 => Cb::U(1_767_204_000), 13 => Cb::U(4_198),
        };
        // The charger as a whole — `cmp = 0` — reporting a state this build
        // cannot name, carrying the vendor's own code and whose code it is.
        let unnamed = cmap! {
            1 => Cb::U(11), 2 => Cb::U(5), 3 => Cb::U(0), 6 => Cb::U(0x000d),
            7 => Cb::U(2), 8 => Cb::U(2), 9 => Cb::U(900),
            11 => Cb::U(0x0021), 12 => Cb::U(0x0002), 13 => Cb::U(4_203),
        };
        // A low-temperature protection that ended at dawn and has not been
        // released yet. It is still a row the walk returns, and `total` counts
        // it — a client that never receives it never learns the condition ended.
        let over = cmap! {
            1 => Cb::U(12), 2 => Cb::U(3), 3 => Cb::U(58), 4 => Cb::U(211),
            6 => Cb::U(0x0004), 7 => Cb::U(4), 8 => Cb::U(5),
            9 => Cb::U(43_200), 13 => Cb::U(4_180),
        };
        let page = cbor(&cmap! {
            1 => Cb::U(41), 2 => Cb::U(4_211),
            3 => Cb::A(vec![cell, unnamed, over]),
            4 => Cb::U(0), 5 => Cb::U(3), 6 => Cb::U(2), 7 => Cb::U(1),
        });

        let mut fields = vec![
            ("type", json!(0x8Fu8)),
            (
                "authentication",
                json!(
                    "this is the inner body; on the wire it is key 1 of the wrapper, whose key 2 is a MAC under session_key with the label 'km43/v1/rsp'"
                ),
            ),
            ("request_body_cbor", json!(hex(&request))),
            (
                "request_readable",
                json!(
                    "ReadConcerns 0x0F {1:rev=41, 2:from=0} — from the beginning, which is the one place 0 is legal because it is a cursor and not an id"
                ),
            ),
            ("body_cbor", json!(hex(&page))),
            ("body_len", json!(page.len())),
            (
                "body_readable",
                json!("{1:rev, 2:seq, 3:c, 4:next, 5:total, 6:refused, 7:outcome}"),
            ),
            (
                "values_readable",
                json!(
                    "rev 41, seq 4211 as the pin a walk is held against, and three rows in cid ascending. cid 9 is pack 2's cell 23 over voltage — dev 3, cmp 57, sig 204, elem 7, and the label a client renders is that signal's ebase of 17 plus 7 minus 1. cid 11 is the charger as a whole at cmp 0, reporting a state this build cannot name, carrying the vendor's own 0x0021 and the namespace that reads it. cid 12 is a low-temperature protection that ended at dawn and has not been released, so it is state 5 cleared and still a row the walk returns. next 0 so the walk is complete, total 3 with the cleared row counted, refused 2 since boot, outcome 1 ok"
                ),
            ),
        ];
        for (name, row) in Self::concern_rows() {
            let bytes = cbor(&row);
            fields.push((
                name,
                json!({ "row_cbor": hex(&bytes), "row_len": bytes.len() }),
            ));
        }
        ("concerns_0x8F", obj(fields))
    }

    /// The two records a concern writes, `0x0501` and `0x0502`.
    ///
    /// The raise carries the same `Concern` a page carries — the cell-23 row
    /// from the page above, byte for byte — because a second shape meaning
    /// nearly the same thing is two decoders to keep in step. The change is the
    /// row leaving the table at dawn, and it carries the state it moved **from**
    /// so a client that lost a record to a hole in `seq` can tell that from a
    /// controller that skipped a state.
    fn concern_events() -> Vec<(&'static str, Value)> {
        let cell = cmap! {
            1 => Cb::U(9), 2 => Cb::U(3), 3 => Cb::U(57), 4 => Cb::U(204),
            5 => Cb::U(7), 6 => Cb::U(0x0001), 7 => Cb::U(4), 8 => Cb::U(1),
            9 => Cb::U(21_600), 10 => Cb::U(1_767_204_000), 13 => Cb::U(4_198),
        };
        let raised = cbor(&cmap! { 1 => Cb::U(41), 2 => cell });
        let changed = cbor(&cmap! {
            1 => Cb::U(41), 2 => Cb::U(12), 3 => Cb::U(3), 4 => Cb::U(0x0004),
            5 => Cb::U(5), 6 => Cb::U(3),
        });

        vec![
            (
                "concernraised_0x0501",
                obj(vec![
                    ("kind", json!(0x0501u16)),
                    ("class", json!("A")),
                    (
                        "authentication",
                        json!(
                            "an event body; on the wire it is Event 0x04 key 4, inside a wrapper MAC'd under session_key with the label 'km43/v1/evt'"
                        ),
                    ),
                    ("body_cbor", json!(hex(&raised))),
                    ("body_len", json!(raised.len())),
                    ("body_readable", json!("{1:rev, 2:c}")),
                    (
                        "values_readable",
                        json!(
                            "rev 41, and the row exactly as a Concerns 0x8F page carries it: cid 9, pack 2's cell 23 over voltage at elem 7 against an ebase of 17, protection, active, six hours old"
                        ),
                    ),
                ]),
            ),
            (
                "concernchanged_0x0502",
                obj(vec![
                    ("kind", json!(0x0502u16)),
                    ("class", json!("A")),
                    (
                        "authentication",
                        json!(
                            "an event body; on the wire it is Event 0x04 key 4, inside a wrapper MAC'd under session_key with the label 'km43/v1/evt'"
                        ),
                    ),
                    ("body_cbor", json!(hex(&changed))),
                    ("body_len", json!(changed.len())),
                    (
                        "body_readable",
                        json!("{1:rev, 2:cid, 3:dev, 4:cond, 5:state, 6:prev}"),
                    ),
                    (
                        "values_readable",
                        json!(
                            "rev 41, concern 12 on device 3 — the pack's under-temperature protection — moving to state 5 cleared from state 3 latched_cleared. State 5 is the row leaving the table, which is the only way one does (P-180), and prev is what tells a client whether it missed a transition"
                        ),
                    ),
                ]),
            ),
        ]
    }

    /// The three remaining change records, `0x0102`, `0x0901` and `0x0902`.
    ///
    /// The validity sweep is the failure the array exists for, at three signals
    /// rather than 384: one RS-485 pair going quiet takes everything behind it
    /// with it, and one event per signal would close every session.
    fn change_events() -> Vec<(&'static str, Value)> {
        // `0x11` is ok/measured — what the client was last told — and `0x70` is
        // absent with no provenance, because there is no number to have a source.
        let entry = |sig: u64| cmap! { 1 => Cb::U(sig), 2 => Cb::U(0x70), 3 => Cb::U(0x11) };
        let validity = cbor(&cmap! {
            1 => Cb::U(41),
            2 => Cb::A(vec![entry(9), entry(21), entry(204)]),
        });
        let topology = cbor(&cmap! {
            1 => Cb::U(42), 2 => Cb::U(3), 3 => Cb::U(17), 4 => Cb::U(0),
        });
        let presence = cbor(&cmap! {
            1 => Cb::U(41),
            2 => Cb::A(vec![
                cmap! { 1 => Cb::U(3), 2 => Cb::U(3), 3 => Cb::U(1) },
                cmap! { 1 => Cb::U(5), 2 => Cb::U(2), 3 => Cb::U(1) },
            ]),
        });

        let auth = "an event body; on the wire it is Event 0x04 key 4, inside a wrapper MAC'd under session_key with the label 'km43/v1/evt'";
        vec![
            (
                "validitychanged_0x0102",
                obj(vec![
                    ("kind", json!(0x0102u16)),
                    ("class", json!("A")),
                    ("authentication", json!(auth)),
                    ("body_cbor", json!(hex(&validity))),
                    ("body_len", json!(validity.len())),
                    ("body_readable", json!("{1:rev, 2:e}")),
                    (
                        "values_readable",
                        json!(
                            "rev 41, and three signals behind one RS-485 pair going quiet at once: each moves to q 0x70, validity 7 absent with provenance 0 because there is no number to have a source, from the q 0x11 ok/measured the client was last told. One event and not three, which is what stops 384 of them closing every session"
                        ),
                    ),
                ]),
            ),
            (
                "topologychanged_0x0901",
                obj(vec![
                    ("kind", json!(0x0901u16)),
                    ("class", json!("A")),
                    ("authentication", json!(auth)),
                    ("body_cbor", json!(hex(&topology))),
                    ("body_len", json!(topology.len())),
                    (
                        "body_readable",
                        json!("{1:rev, 2:reason, 3:added, 4:removed}"),
                    ),
                    (
                        "values_readable",
                        json!(
                            "the revision moved to 42 because a sub-device was adopted — reason 3 — bringing 17 descriptor rows and removing none. The reason is what tells a person the difference between somebody writing configuration and a module appearing in a bay, which is the same two numbers and a different afternoon"
                        ),
                    ),
                ]),
            ),
            (
                "presencechanged_0x0902",
                obj(vec![
                    ("kind", json!(0x0902u16)),
                    ("class", json!("A")),
                    ("authentication", json!(auth)),
                    ("body_cbor", json!(hex(&presence))),
                    ("body_len", json!(presence.len())),
                    ("body_readable", json!("{1:rev, 2:e}")),
                    (
                        "values_readable",
                        json!(
                            "rev 41, device 3 gone from 1 online to 3 offline and device 5 from 1 online to 2 degraded. Presence does not move rev (P-155), which is why this event carries the current one rather than a new one"
                        ),
                    ),
                ]),
            ),
        ]
    }

    /// Link-local frames, whole and framed.
    ///
    /// **The reason this belongs in the published file at all**: the ESP32
    /// firmware and the controller both encode these, and until now the only
    /// thing checking them was each other. Two implementations that agree with
    /// each other and with nothing else is precisely how a wire format drifts
    /// from what it is documented to be — and this link has two *different*
    /// codebases on its two ends, which is the case an outside opinion is for.
    ///
    /// Built here from the byte level, with no dependency on `km43`.
    /// `cargo xtask check` refuses that edge, and it is the whole point: a
    /// generator that imports the thing it checks publishes the implementation's
    /// opinion of itself.
    fn link() -> Result<Value> {
        let mut out = Vec::new();
        for LinkCase {
            name,
            kind,
            session,
            req_id,
            body,
            readable,
        } in Self::link_cases()?
        {
            let envelope = cbor(&Cb::A(vec![
                Cb::U(kind as u64),
                Cb::U(u64::from(session)),
                Cb::U(u64::from(req_id)),
                body,
            ]));
            let crc = crc16(&envelope);
            let framed = [envelope.clone(), crc.to_le_bytes().to_vec()].concat();
            let mut encoded = cobs_encode(&framed);
            encoded.push(0);
            // The same round trip the client frame takes, because a vector that
            // has not been decoded is a vector nobody has checked.
            if cobs_decode(&encoded[..encoded.len() - 1])? != framed {
                bail!("the {name} vector does not survive its own round trip");
            }
            out.push((
                name,
                obj(vec![
                    ("type", json!(kind as u8)),
                    (
                        "authentication",
                        json!(
                            "none; this link is a cable inside one enclosure and carries no MAC (L-010)"
                        ),
                    ),
                    ("session_id", json!(session)),
                    ("req_id", json!(req_id)),
                    ("body_readable", json!(readable)),
                    ("envelope_cbor", json!(hex(&envelope))),
                    ("crc16_ccitt_false", json!(format!("{crc:#06x}"))),
                    ("encoded_with_delimiter", json!(hex(&encoded))),
                    ("encoded_len", json!(encoded.len())),
                ]),
            ));
        }
        Ok(obj(out))
    }

    /// The link bodies, one per published frame.
    fn link_cases() -> Result<Vec<LinkCase>> {
        /// What the published `CommsRelease` authorises: not a firmware, but a
        /// fixed run of bytes whose SHA-256 anybody can recompute. The text is
        /// quoted in `body_readable` so an outside implementation can.
        const IMAGE: &str = "km43 comms release vector image";
        Ok(vec![
            LinkCase {
                name: "link_up_0x60",
                kind: Link::Up,
                session: 0,
                req_id: 1,
                body: cmap! {
                    1 => Cb::U(1),
                    2 => Cb::U(0),
                    3 => Cb::U(2),
                    4 => Cb::T("o89-esp32 0.1.0".into()),
                    5 => Cb::U(0x5eed_face),
                    6 => Cb::T("esp32c6-devkitc-1".into()),
                    7 => Cb::U(0),
                },
                readable: "{1:protocol_major=1, 2:protocol_minor=0, 3:role=comms, 4:fw, 5:boot_id, 6:hw, 7:net_version=0}"
                    .into(),
            },
            LinkCase {
                name: "client_connected_0x62",
                kind: Link::ClientConnected,
                session: 0,
                req_id: 2,
                body: cmap! {1 => Cb::U(7), 2 => Cb::U(2), 3 => Cb::T("192.168.4.2".into())},
                readable: "{1:conn=7, 2:transport=wifi_local, 3:peer}".into(),
            },
            LinkCase {
                name: "client_connected_ack_0xe2",
                kind: Link::ClientConnectedAck,
                session: 0,
                req_id: 2,
                body: cmap! {1 => Cb::U(1)},
                readable: "{1:outcome=accepted}".into(),
            },
            LinkCase {
                name: "time_offer_0x66",
                kind: Link::TimeOffer,
                session: 0,
                req_id: 3,
                body: cmap! {
                    1 => Cb::U(1_786_802_653_000),
                    2 => Cb::U(1),
                    3 => Cb::U(40),
                    4 => Cb::T("0.pool.ntp.org".into()),
                },
                readable: "{1:unix_ms, 2:source=ntp, 3:accuracy_ms=40, 4:server}".into(),
            },
            // **The refusal, not the acceptance.** An implementation that only
            // ever encodes `accepted` has never exercised the arm that matters,
            // and this is the one the rate limit produces.
            LinkCase {
                name: "time_offer_ack_0xe6",
                kind: Link::TimeOfferAck,
                session: 0,
                req_id: 3,
                body: cmap! {1 => Cb::U(5)},
                readable: "{1:outcome=refused_rate_limited}".into(),
            },
            // Version 0 from a board holding nothing, which is L-132's honest
            // answer and the one that gets it provisioned.
            LinkCase {
                name: "net_config_ack_0xe5",
                kind: Link::NetConfigAck,
                session: 0,
                req_id: 4,
                body: cmap! {1 => Cb::U(1), 2 => Cb::U(0)},
                readable: "{1:outcome=stored, 2:version=0}".into(),
            },
            // An `authorise` over a real SHA-256 rather than a pattern of
            // bytes, so the published digest is one a firmware could have
            // computed from the image named in `body_readable`.
            LinkCase {
                name: "comms_release_0x67",
                kind: Link::CommsRelease,
                session: 0,
                req_id: 5,
                body: cmap! {
                    1 => Cb::U(1),
                    2 => Cb::T("0.2.0+g1a2b3c4d".into()),
                    3 => Cb::U(u64::try_from(IMAGE.len())?),
                    4 => Cb::B(Sha256::digest(IMAGE.as_bytes()).to_vec()),
                },
                readable: format!(
                    "{{1:op=authorise, 2:version, 3:image_len={}, 4:digest=sha256 of the ASCII text \"{IMAGE}\"}}",
                    IMAGE.len()
                ),
            },
            // **The refusal, not the acceptance.** A digest mismatch is the
            // outcome L-171 exists for, and `version` names what it will boot
            // next, which after a refusal is still the old image.
            LinkCase {
                name: "comms_release_ack_0xe7",
                kind: Link::CommsReleaseAck,
                session: 0,
                req_id: 5,
                body: cmap! {
                    1 => Cb::U(4),
                    2 => Cb::T("0.1.0+g9f8e7d6c".into()),
                    3 => Cb::U(524_288),
                },
                readable: "{1:outcome=refused_digest_mismatch, 2:version, 3:bytes_have=524288}"
                    .into(),
            },
        ])
    }

    fn bodies(&self) -> Value {
        obj(vec![
            self.discover_entry(),
            self.hello_entry(),
            Self::inventory_entry(),
            Self::readings_entry(),
            Self::concerns_entry(),
        ]
        .into_iter()
        .chain(Self::concern_events())
        .chain(Self::change_events())
        .collect::<Vec<_>>())
    }

    fn discover_entry(&self) -> (&'static str, Value) {
        let discover = self.discover_body();
        (
            "discover_0x80",
            obj(vec![
                ("type", json!(Msg::Discover as u8)),
                (
                    "authentication",
                    json!("none; no key exists yet, so there is no MAC to publish"),
                ),
                (
                    "body_readable",
                    json!(
                        "{1:protocol_major=1, 2:protocol_minor=0, 3:device_id, 4:model, 5:provisioned=false, 6:pairing_open=true, 7:challenge, 8:epoch=1}"
                    ),
                ),
                ("body_cbor", json!(hex(&discover))),
                ("body_len", json!(discover.len())),
            ]),
        )
    }

    fn hello_entry(&self) -> (&'static str, Value) {
        let hello = self.hello_body();
        (
            "hello_0x81",
            obj(vec![
                ("type", json!(Msg::Hello as u8)),
                (
                    "authentication",
                    json!(
                        "this is the inner body; on the wire it is key 1 of the wrapper, whose key 2 is a MAC under session_key with the label 'km43/v1/rsp'"
                    ),
                ),
                (
                    "body_readable",
                    json!(
                        "{1:protocol_major=1, 2:protocol_minor=0, 3:session_id=3, 4:fw_controller, 5:fw_comms, 6:capabilities=0xf7, 7:log_oldest_seq=1, 8:log_newest_seq=256, 9:state_seq=255, 10:time_known=true, 11:counter=65, 12:max_sessions=8, 13:max_channels=32, 14:max_clients=8, 15:max_event_queue=16, 16:max_inflight=4, 17:max_cmd_dedup=32, 18:rev=0, 19:topo_digest, 20:max_buses=8, 21:max_devices=24, 22:max_components=160, 23:max_signals=384, 24:max_series_elements=512, 25:max_params=96, 26:max_concerns=48, 27:max_selectors=12, 28:max_history_signals=24, 29:max_topology_depth=4}"
                    ),
                ),
                (
                    "capabilities_readable",
                    json!(
                        "bit 0 log readable, 1 config writable, 2 commands accepted, 4 clock settable, 5 counted state of charge, 6 AC metering, 7 a behaviour is in shadow mode; bit 3 firmware update is clear"
                    ),
                ),
                (
                    "counter_readable",
                    json!(
                        "the highest counter already accepted from client_id 7, which is why the signed_request vector's 0x42 is the next value that is not a replay"
                    ),
                ),
                (
                    "sequence_spaces",
                    json!(
                        "keys 7 and 8 are log positions and key 9 is the state store's own counter; the two spaces must never be compared, and 255 sitting beside 256 here is what that trap looks like"
                    ),
                ),
                ("body_cbor", json!(hex(&hello))),
                ("body_len", json!(hello.len())),
            ]),
        )
    }

    fn signed_request(&self) -> (&'static str, Value) {
        let operation = cbor(&cmap! {
            1 => Cb::U(0x2A), 2 => Cb::U(0x0101), 3 => cmap!{1 => Cb::U(900)},
        });
        let preimage = [
            L_REQ,
            &[Msg::Command as u8],
            &self.session_id.to_be_bytes(),
            &self.req_id.to_be_bytes(),
            &self.client_id.to_be_bytes(),
            &self.counter.to_be_bytes(),
            &operation,
        ]
        .concat();
        let mac = t16(hmac(&self.session_key, &preimage));
        let body = cbor(&cmap! {
            1 => Cb::U(u64::from(self.client_id)), 2 => Cb::U(self.counter),
            3 => Cb::B(operation.clone()), 4 => Cb::B(mac.clone()),
        });
        (
            "signed_request",
            MacVector::new(DerivedKey::Session, preimage, "'km43/v1/req' | type:u8 | session_id:u16be | req_id:u32be | client_id:u32be | counter:u64be | operation")
                .with("type", Msg::Command as u8)
                .with("operation_cbor", hex(&operation))
                .body(hex(&body))
                .finish(&self.session_key),
        )
    }

    /// Read-only requests carry no counter, so they need their own label.
    fn wrapper_request(&self) -> (&'static str, Value) {
        let inner = cbor(&cmap! {1 => Cb::U(0x04C0), 2 => Cb::U(64)});
        let preimage = [
            L_WRQ,
            &[Msg::ReadLog as u8],
            &self.session_id.to_be_bytes(),
            &self.req_id.to_be_bytes(),
            &inner,
        ]
        .concat();
        let mac = t16(hmac(&self.session_key, &preimage));
        (
            "wrapper_request",
            MacVector::new(
                DerivedKey::Session,
                preimage,
                "'km43/v1/wrq' | type:u8 | session_id:u16be | req_id:u32be | payload",
            )
            .with("type", Msg::ReadLog as u8)
            .with("inner_body_cbor", hex(&inner))
            .body(wrapped(&inner, &mac))
            .finish(&self.session_key),
        )
    }

    fn response(&self) -> ((&'static str, Value), Response) {
        let inner = cbor(&cmap! {
            1 => Cb::U(0x2A), 2 => Cb::U(1), 3 => Cb::T("generator starting".into()),
        });
        let preimage = [
            L_RSP,
            &[Msg::Ack as u8],
            &self.session_id.to_be_bytes(),
            &self.req_id.to_be_bytes(),
            &inner,
        ]
        .concat();
        let mac = t16(hmac(&self.session_key, &preimage));
        let entry = MacVector::new(
            DerivedKey::Session,
            preimage,
            "'km43/v1/rsp' | type:u8 | session_id:u16be | req_id:u32be | payload",
        )
        .with("type", Msg::Ack as u8)
        .with("inner_body_cbor", hex(&inner))
        .body(wrapped(&inner, &mac))
        .finish(&self.session_key);
        (("response", entry), Response { inner, mac })
    }

    fn event(&self) -> (&'static str, Value) {
        let inner = cbor(&cmap! {
            1 => Cb::U(0x04D2), 2 => Cb::U(0x0000_018F_1E2A_3B40), 3 => Cb::U(0x0201),
            4 => cmap!{1 => Cb::U(3), 2 => Cb::U(1)},
        });
        let preimage = [
            L_EVT,
            &[Msg::Event as u8],
            &self.session_id.to_be_bytes(),
            &0u32.to_be_bytes(),
            &inner,
        ]
        .concat();
        let mac = t16(hmac(&self.session_key, &preimage));
        (
            "event",
            MacVector::new(
                DerivedKey::Session,
                preimage,
                "'km43/v1/evt' | type:u8 | session_id:u16be | 0x00000000 | payload",
            )
            .with("type", Msg::Event as u8)
            .with("inner_body_cbor", hex(&inner))
            .body(wrapped(&inner, &mac))
            .finish(&self.session_key),
        )
    }

    /// One complete frame, envelope through delimiter.
    fn frame(&self, rsp: &Response) -> Result<Value> {
        let envelope = cbor(&Cb::A(vec![
            Cb::U(Msg::Ack as u64),
            Cb::U(u64::from(self.session_id)),
            Cb::U(u64::from(self.req_id)),
            cmap! {1 => Cb::B(rsp.inner.clone()), 2 => Cb::B(rsp.mac.clone())},
        ]));
        let crc = crc16(&envelope);
        let framed = [envelope.clone(), crc.to_le_bytes().to_vec()].concat();
        let mut encoded = cobs_encode(&framed);
        encoded.push(0);
        if cobs_decode(&encoded[..encoded.len() - 1])? != framed {
            bail!("the frame vector does not survive its own round trip");
        }
        Ok(obj(vec![
            ("envelope_cbor", json!(hex(&envelope))),
            (
                "envelope_readable",
                json!("[type:0x88, session_id:3, req_id:17, {1:payload, 2:mac}]"),
            ),
            ("crc16_ccitt_false", json!(format!("{crc:#06x}"))),
            (
                "crc_covers",
                json!("the CBOR envelope bytes exactly, from first byte to last"),
            ),
            ("pre_cobs", json!(hex(&framed))),
            ("encoded_with_delimiter", json!(hex(&encoded))),
            ("encoded_len", json!(encoded.len())),
        ]))
    }

    /// The label, which is the one artefact fixed at print time.
    ///
    /// Its length is normative, so a scanner's cheapest first check is a
    /// compare against a number that was written by hand and went stale the
    /// day the protocol was renamed.
    fn qr(&self) -> Value {
        let payload = format!(
            "km43:1:{}:{}",
            hex(&self.device_id),
            hex(&self.printed_secret)
        );
        obj(vec![
            ("len", json!(payload.len())),
            ("payload", json!(payload)),
        ])
    }

    fn inputs(&self) -> Value {
        let mut pairs = vec![
            ("printed_secret", json!(hex(&self.printed_secret))),
            ("device_id", json!(hex(&self.device_id))),
            ("challenge", json!(hex(&self.challenge))),
            ("next_challenge", json!(hex(&self.next_challenge))),
            ("client_nonce", json!(hex(&self.client_nonce))),
            ("client_id", json!(self.client_id)),
            ("session_id", json!(self.session_id)),
            ("req_id", json!(self.req_id)),
            ("counter", json!(self.counter)),
            ("label", json!(self.label)),
            ("epoch", json!(self.epoch)),
            ("protocol_major", json!(PROTOCOL_MAJOR)),
            ("protocol_minor", json!(PROTOCOL_MINOR)),
        ];
        pairs.extend(self.report.inputs());
        obj(pairs)
    }

    fn derived_keys(&self) -> Value {
        obj(vec![
            (
                "client_key",
                key_entry(
                    &self.device_id,
                    &self.printed_secret,
                    &self.client_key_info,
                    "'km43/v1/client-key' | epoch:u32be | client_id:u32be",
                    &self.client_key,
                ),
            ),
            (
                "session_key",
                key_entry(
                    &self.session_salt,
                    &self.client_key,
                    &self.session_key_info,
                    "'km43/v1/session-key' | session_id:u16be",
                    &self.session_key,
                ),
            ),
            (
                "pair_key",
                key_entry(
                    &self.device_id,
                    &self.printed_secret,
                    L_PAIR_KEY,
                    "'km43/v1/pair-key'",
                    &self.pair_key,
                ),
            ),
        ])
    }

    fn document(&self) -> Result<Value> {
        let (response, rsp) = self.response();
        let macs = vec![
            self.pair_proof(),
            self.pair_ack(),
            self.hello_proof(),
            self.signed_request(),
            self.wrapper_request(),
            response,
            self.event(),
        ];
        let (crc_v, cobs_v) = edge_cases()?;
        let cobs_input = MAX_PAYLOAD + 2;
        let overhead = cobs_input.div_ceil(254);

        Ok(obj(vec![
            (
                "note",
                json!(
                    "Generated by xtask. Every primitive is validated against its RFC's published vectors before these are computed. Regenerate with `cargo xtask vectors`, never hand-edit."
                ),
            ),
            ("conventions", conventions()),
            ("inputs", self.inputs()),
            ("qr", self.qr()),
            (
                "limits",
                obj(vec![
                    ("max_payload", json!(MAX_PAYLOAD)),
                    ("cobs_input", json!(cobs_input)),
                    ("max_cobs_overhead", json!(overhead)),
                    (
                        "max_frame_including_delimiter",
                        json!(cobs_input + overhead + 1),
                    ),
                ]),
            ),
            ("derived_keys", self.derived_keys()),
            ("macs", obj(macs)),
            ("bodies", self.bodies()),
            ("crc16", Value::Array(crc_v)),
            ("cobs", Value::Array(cobs_v)),
            ("frame", self.frame(&rsp)?),
            ("link_local", Self::link()?),
        ]))
    }
}

fn conventions() -> Value {
    obj(vec![
        (
            "integers",
            json!("big-endian, fixed width, no padding, no length prefix"),
        ),
        (
            "concatenation",
            json!("the | operator joins fixed-width fields with no separator"),
        ),
        (
            "hmac",
            json!("HMAC-SHA256, truncated to the LEFTMOST 16 bytes where 16 is specified"),
        ),
        (
            "hkdf",
            json!("HKDF-SHA256 (RFC 5869) with salt, IKM and info as named arguments"),
        ),
        ("cbor", json!("RFC 8949 section 4.2 deterministic encoding")),
    ])
}

/// Which derived key a MAC is computed under.
///
/// A `&'static str` here meant `MacVector::new(DerivedKey::Pair, ..).finish(&session_key)`
/// compiled and published a vector whose name and bytes disagreed — the one
/// mistake this file cannot catch, because it is the file everything else is
/// checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DerivedKey {
    Pair,
    Client,
    Session,
}

impl std::fmt::Display for DerivedKey {
    fn fmt(&self, w: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        w.write_str(match self {
            Self::Pair => "pair_key",
            Self::Client => "client_key",
            Self::Session => "session_key",
        })
    }
}

/// Builds one MAC vector.
///
/// The fields go out in a fixed order that a reader compares down the file, so
/// this collects them rather than taking six positional arguments of which two
/// are `Option`.
struct MacVector {
    key: DerivedKey,
    preimage: Vec<u8>,
    readable: &'static str,
    extra: Vec<(&'static str, Value)>,
    body: Option<String>,
}

impl MacVector {
    fn new(key: DerivedKey, preimage: Vec<u8>, readable: &'static str) -> Self {
        Self {
            key,
            preimage,
            readable,
            extra: Vec::new(),
            body: None,
        }
    }

    /// A field shown before the preimage, such as the encoded inner body.
    fn with(mut self, name: &'static str, value: impl Into<Value>) -> Self {
        self.extra.push((name, value.into()));
        self
    }

    /// The whole encoded message, where the vector shows one.
    fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Computes the MAC under `key_bytes` and renders the entry.
    fn finish(self, key_bytes: &[u8]) -> Value {
        let mut pairs = vec![("key", json!(self.key.to_string()))];
        pairs.extend(self.extra);
        pairs.push(("preimage", json!(hex(&self.preimage))));
        pairs.push(("preimage_readable", json!(self.readable)));
        pairs.push(("out16", json!(hex(&t16(hmac(key_bytes, &self.preimage))))));
        if let Some(b) = self.body {
            pairs.push(("full_body_cbor", json!(b)));
        }
        obj(pairs)
    }
}

fn key_entry(salt: &[u8], ikm: &[u8], info: &[u8], readable: &str, out: &[u8]) -> Value {
    obj(vec![
        ("salt", json!(hex(salt))),
        ("ikm", json!(hex(ikm))),
        ("info", json!(hex(info))),
        ("info_readable", json!(readable)),
        ("L", json!(32)),
        ("out", json!(hex(out))),
    ])
}

fn wrapped(inner: &[u8], mac: &[u8]) -> String {
    hex(&cbor(
        &cmap! {1 => Cb::B(inner.to_vec()), 2 => Cb::B(mac.to_vec())},
    ))
}

/// The inputs that break a careless encoder.
fn edge_cases() -> Result<(Vec<Value>, Vec<Value>)> {
    let mut crc_v = Vec::new();
    let mut cobs_v = Vec::new();
    for (lbl, data) in [
        ("empty", Vec::new()),
        ("single zero", vec![0u8]),
        ("no zeros", b"origin89".to_vec()),
        ("embedded zero", hex_to_bytes("11223300445566")),
    ] {
        crc_v.push(
            json!({"label": lbl, "input": hex(&data), "crc": format!("{:#06x}", crc16(&data))}),
        );
        cobs_v
            .push(json!({"label": lbl, "input": hex(&data), "encoded": hex(&cobs_encode(&data))}));
    }

    let b254: Vec<u8> = (1u16..255)
        .map(|v| u8::try_from(v).expect("under 255"))
        .collect();
    let mut b255 = b254.clone();
    b255.push(0x41);
    let mut b254z = b254.clone();
    b254z.push(0x00);
    for (lbl, d) in [
        ("254 non-zero bytes (block boundary)", &b254),
        ("255 non-zero bytes (boundary + 1)", &b255),
        // The one a round trip cannot catch — see cobs_encode.
        (
            "254 non-zero bytes then a zero (the silent-loss case)",
            &b254z,
        ),
    ] {
        cobs_v.push(json!({"label": lbl, "input": hex(d), "encoded": hex(&cobs_encode(d))}));
    }
    if cobs_decode(&cobs_encode(&b254z))? != b254z {
        bail!("the silent-loss case does not round trip");
    }
    Ok((crc_v, cobs_v))
}

pub fn build() -> Result<String> {
    let b = Builder::new();
    self_check(&b)?;
    println!("client_key   = {}", hex(&b.client_key));
    println!("session_key  = {}", hex(&b.session_key));
    println!("pair_key     = {}", hex(&b.pair_key));
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&b.document()?)?
    ))
}

#[cfg(test)]
mod tests {
    use super::{Builder, Cb, PROTOCOL_MAJOR, SelfReport, cbor, hex};

    /// A capacity dropped from the body leaves a client using the number it was
    /// compiled with, at a controller that enforces a different one — which is
    /// quiet rather than loud, and reads as *the site is busy* all afternoon.
    #[test]
    fn a_hello_that_omits_a_reported_capacity_sends_a_client_back_to_its_guess() {
        let body = Builder::new().hello_body();
        // Twenty-nine pairs is past twenty-three, so the map header is two
        // bytes: `b8 1d` and not a single `bN`.
        assert_eq!(
            body.get(..2),
            Some(&[0xB8, 0x1D][..]),
            "the Hello map must carry all twenty-nine keys"
        );
        // Key 29 and its value are the last three bytes — the key itself is two
        // of them, because a map key past 23 stops fitting one. A truncated tail
        // shows up here rather than in a hex dump nobody reads.
        assert_eq!(
            body.get(body.len().saturating_sub(3)..),
            Some(&[0x18, 0x1D, 0x04][..])
        );
    }

    /// A `Discover` without key 8 sends a client off to derive a client key
    /// under an epoch the controller has already left behind, and the only
    /// symptom is a proof that will not verify.
    #[test]
    fn a_discover_without_the_epoch_leaves_a_client_deriving_under_a_dead_one() {
        let b = Builder::new();
        let body = b.discover_body();
        assert_eq!(body.first().copied(), Some(0xA8));
        let epoch = u8::try_from(b.epoch).expect("the fixture epoch fits in a byte");
        assert_eq!(
            body.get(body.len().saturating_sub(2)..),
            Some(&[0x08, epoch][..])
        );
    }

    /// Reported above 32, a fully configured site builds a snapshot larger than
    /// `MAX_PAYLOAD` and the controller refuses its own frame with error 5.
    /// There is no paging to fall back on and nothing a client can do.
    #[test]
    fn max_channels_reported_above_thirty_two_is_a_frame_the_controller_refuses_itself() {
        assert!(SelfReport::new().limits.channels <= 32);
    }

    /// Publishing key 11 equal to the counter the signed request carries makes
    /// that request a replay, and a client reading the two together would send
    /// a value it has already been told was accepted.
    #[test]
    fn a_reported_counter_at_the_next_request_makes_that_request_a_replay() {
        let b = Builder::new();
        let reported = b.counter.saturating_sub(1);
        assert!(reported < b.counter);
        assert_eq!(hex(&cbor(&Cb::U(reported))), "1841");
    }

    /// Both bodies announce the same version the `Hello 0x01` proof covers. Two
    /// numbers in two places is a vector set negotiating a downgrade with
    /// itself, and the proof is what would have caught it on the wire.
    #[test]
    fn the_two_bodies_and_the_hello_proof_cannot_announce_different_versions() {
        let b = Builder::new();
        let major = u8::try_from(PROTOCOL_MAJOR).expect("the fixture major fits in a byte");
        assert_eq!(b.discover_body().get(..3), Some(&[0xA8, 0x01, major][..]));
        assert_eq!(
            b.hello_body().get(..4),
            Some(&[0xB8, 0x1D, 0x01, major][..])
        );
    }
}
