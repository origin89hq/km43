//! `0x0003 buses and devices` against the published vectors.
//!
//! The generator writes these bodies from its own numbers and never reads this
//! crate, so decoding them here and writing them back byte for byte is the
//! comparison with a second reading of the document. The unit tests beside
//! the codec only ever meet bytes the codec produced.
//!
//! cites: P-101, P-262, P-265

use km43::{
    BoardBus, BusesAndDevicesRead, BusesAndDevicesWrite, ConfigError, ConfigSection, DevAllocator,
    DevId, DeviceOption, DeviceRole, Dialect, DialectRule, MAX_BUSES_AND_DEVICES_BYTES,
    MAX_DEVICES, MAX_TOPOLOGY_DEPTH, Product, SectionRefusal, SetConfig, SiteRules, Transport,
};

const VECTORS: &str = include_str!("../vectors.json");

/// The board the published site runs on: an RS-485 pair, a CAN bus and a
/// VE.Direct port.
const BOARD: &[BoardBus] = &[
    BoardBus {
        bus: 1,
        transport: Transport::Rs485,
    },
    BoardBus {
        bus: 2,
        transport: Transport::Can,
    },
    BoardBus {
        bus: 3,
        transport: Transport::VeDirect,
    },
];

/// The dialects the published site's devices speak, with the options each
/// reads.
const DIALECTS: &[DialectRule<'static>] = &[
    DialectRule {
        dialect: Dialect::PZEM_DC,
        transports: &[Transport::Rs485],
        options: &[DeviceOption::PollPeriod],
        min_poll_ms: 500,
    },
    DialectRule {
        dialect: Dialect::EPEVER_B,
        transports: &[Transport::Rs485],
        options: &[DeviceOption::CurrentDirection, DeviceOption::PollPeriod],
        min_poll_ms: 1000,
    },
    DialectRule {
        dialect: Dialect::VICTRON_MPPT_RS_HEX,
        transports: &[Transport::VeDirect],
        options: &[DeviceOption::VeDirect3v3],
        min_poll_ms: 1000,
    },
];

const RULES: SiteRules<'static> = SiteRules {
    buses: BOARD,
    dialects: DIALECTS,
    max_devices: MAX_DEVICES,
    max_topology_depth: MAX_TOPOLOGY_DEPTH,
};

fn body(name: &str) -> Vec<u8> {
    let entry = object(name);
    let needle = "\"body_cbor\": \"";
    let from = entry.find(needle).expect("the entry has a body") + needle.len();
    let tail = entry.get(from..).expect("the hex");
    let hex = tail
        .get(..tail.find('"').expect("terminated"))
        .expect("the hex");
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2).expect("two digits"), 16).expect("hex"))
        .collect()
}

/// The vector file from the named entry onward. Each lookup takes the first
/// match after the name, and every key it looks for is one each entry has.
fn object(name: &str) -> &'static str {
    let at = VECTORS
        .find(&format!("\"{name}\": {{"))
        .unwrap_or_else(|| panic!("the vector file has no {name}"));
    VECTORS.get(at..).expect("the entry")
}

fn dev(n: u16) -> DevId {
    DevId::new(n).expect("a nonzero id")
}

fn reencoded<D: km43::DevSlot>(section: &km43::BusesAndDevices<'_, D>) -> Vec<u8> {
    let mut dst = [0; MAX_BUSES_AND_DEVICES_BYTES];
    let len = section.encode(&mut dst).expect("the body encodes");
    dst.get(..len)
        .expect("the length came from the writer")
        .to_vec()
}

#[test]
fn p_101_the_published_bodies_decode_and_reencode_byte_for_byte() {
    for name in [
        "busesanddevices_0x0003",
        "buses_and_devices_empty_0x0003",
        "buses_and_devices_widest_0x0003",
    ] {
        let published = body(name);
        let read = BusesAndDevicesRead::decode(&published).expect("a valid answer");
        assert_eq!(reencoded(&read), published, "{name}");
    }
    for name in [
        "buses_and_devices_write_0x0003",
        "buses_and_devices_empty_0x0003",
    ] {
        let published = body(name);
        let write = BusesAndDevicesWrite::decode(&published).expect("a valid write");
        assert_eq!(reencoded(&write), published, "{name}");
    }
}

/// The published site says what its description says: two buses configured,
/// three devices, and the Tracer's current counted into the battery.
#[test]
fn the_published_site_reads_back_to_the_fields_the_generator_wrote() {
    let published = body("busesanddevices_0x0003");
    let site = BusesAndDevicesRead::decode(&published).expect("a valid answer");
    assert_eq!(site.check(&RULES), Ok(()));

    let buses: Vec<(u8, Option<u32>)> = site
        .buses()
        .map(|bus| (bus.bus, bus.rate.map(core::num::NonZeroU32::get)))
        .collect();
    assert_eq!(buses, [(1, Some(9600)), (2, Some(500_000))]);

    let devices: Vec<(u16, Product, Dialect, DeviceRole)> = site
        .devices()
        .map(|device| {
            (
                device.dev.get(),
                device.product,
                device.dialect,
                device.role,
            )
        })
        .collect();
    assert_eq!(
        devices,
        [
            (
                1,
                Product::PZEM_017,
                Dialect::PZEM_DC,
                DeviceRole::ENERGY_METER
            ),
            (
                2,
                Product::EPEVER_TRACER_B,
                Dialect::EPEVER_B,
                DeviceRole::SOLAR_CHARGER
            ),
            (
                4,
                Product::VICTRON_MPPT_RS,
                Dialect::VICTRON_MPPT_RS_HEX,
                DeviceRole::SOLAR_CHARGER
            ),
        ]
    );
    let charger = site.devices().nth(1).expect("the charger");
    assert_eq!(
        charger.options.current_direction,
        Some(km43::CurrentDirection::PositiveIsIn)
    );
    let mppt = site.devices().nth(2).expect("the mppt");
    assert_eq!(mppt.addr, None);
    assert_eq!(mppt.options.ve_direct_3v3, Some(true));
}

/// The published write, accepted against the published answer: the moved meter
/// keeps dev 1, the MPPT at dev 4 is gone, and the new PZEM-003 gets dev 5 —
/// not 3, which was given once already, and not 4, which was just freed.
#[test]
fn p_262_the_published_write_edits_the_published_site() {
    let held = body("busesanddevices_0x0003");
    let held = BusesAndDevicesRead::decode(&held).expect("a valid answer");
    let write = body("buses_and_devices_write_0x0003");
    let write = BusesAndDevicesWrite::decode(&write).expect("a valid write");

    let accepted = write
        .accept(&RULES, &held, DevAllocator::resume(Some(dev(5))))
        .expect("the write is valid");
    let devices: Vec<(u16, Option<Vec<u8>>, Product)> = accepted
        .section
        .devices()
        .map(|device| {
            (
                device.dev.get(),
                device.addr.map(|addr| addr.as_bytes().to_vec()),
                device.product,
            )
        })
        .collect();
    assert_eq!(
        devices,
        [
            (1, Some(vec![0x05]), Product::PZEM_017),
            (2, Some(vec![0x02]), Product::EPEVER_TRACER_B),
            (5, Some(vec![0x06]), Product::PZEM_003),
        ]
    );
    assert_eq!(accepted.allocator.next(), Some(dev(6)));
}

/// The widest body the derivation costs is the one published, it fits both
/// the write and the answer, and it is refused: every device names a parent,
/// so the chain closes on itself.
#[test]
fn p_265_the_published_widest_body_is_the_derived_cap_and_is_refused_as_a_loop() {
    let published = body("buses_and_devices_widest_0x0003");
    assert_eq!(published.len(), MAX_BUSES_AND_DEVICES_BYTES);
    let widest = BusesAndDevicesRead::decode(&published).expect("the widest body decodes");
    assert_eq!(widest.devices().count(), km43::MAX_CONFIG_DEVICES);
    assert_eq!(widest.buses().count(), km43::MAX_CONFIG_BUSES);

    let board: Vec<BoardBus> = (24..32)
        .map(|bus| BoardBus {
            bus,
            transport: Transport::Rs485,
        })
        .collect();
    let dialects = [DialectRule {
        dialect: Dialect(0xF002),
        transports: &[Transport::Rs485],
        options: &[
            DeviceOption::CurrentDirection,
            DeviceOption::PylontechVersion,
            DeviceOption::VeDirect3v3,
            DeviceOption::PollPeriod,
        ],
        min_poll_ms: 1000,
    }];
    let rules = SiteRules {
        buses: &board,
        dialects: &dialects,
        max_devices: MAX_DEVICES,
        max_topology_depth: MAX_TOPOLOGY_DEPTH,
    };
    let why = widest.check(&rules).expect_err("a closed chain");
    assert!(matches!(why, ConfigError::ParentLoop(_)), "{why}");
    assert_eq!(why.answer(), SectionRefusal::Outcome(SetConfig::Invalid));
}

/// The nested types are published alone so their keys are held to the
/// document. Each is put back inside a body here to be read.
#[test]
fn the_published_nested_entries_read_back_inside_a_body() {
    let mut bus_body = vec![0xA2, 0x01, 0x81];
    bus_body.extend(body("busentry"));
    bus_body.extend([0x02, 0x80]);
    let buses = BusesAndDevicesWrite::decode(&bus_body).expect("the bus entry decodes");
    let bus = buses.buses().next().expect("one bus");
    assert_eq!(bus.bus, 1);
    assert_eq!(bus.parity, Some(km43::Parity::None));
    assert_eq!(bus.stop_bits, Some(km43::StopBits::Two));

    let mut device_body = vec![0xA2, 0x01, 0x80, 0x02, 0x81];
    device_body.extend(body("deviceentry"));
    let devices = BusesAndDevicesRead::decode(&device_body).expect("the device entry decodes");
    let device = devices.devices().next().expect("one device");
    assert_eq!(device.dev, dev(6));
    assert_eq!(device.parent, Some(dev(5)));
    assert_eq!(device.product, Product::EG4_LIFEPOWER4);
    assert_eq!(device.options.poll_period_ms, Some(1000));

    // The options map alone, under key 8 of a minimal entry.
    let mut options_body = vec![
        0xA2, 0x01, 0x80, 0x02, 0x81, 0xA5, 0x02, 0x01, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x08,
    ];
    options_body.extend(body("deviceoptions"));
    let options = BusesAndDevicesWrite::decode(&options_body).expect("the options decode");
    let options = options.devices().next().expect("one device").options;
    assert_eq!(options.pylontech_version, Some(km43::PylontechVersion::V13));
    assert_eq!(options.ve_direct_3v3, Some(true));
    assert_eq!(options.poll_period_ms, Some(500));
}

/// The generator writes the section number from its own list, so nothing but
/// this ties it to the registry.
#[test]
fn the_published_bodies_carry_the_registry_section_number() {
    for name in [
        "busesanddevices_0x0003",
        "buses_and_devices_write_0x0003",
        "buses_and_devices_empty_0x0003",
        "buses_and_devices_widest_0x0003",
        "busentry",
        "deviceentry",
        "deviceoptions",
    ] {
        let entry = object(name);
        let needle = "\"section\": ";
        let from = entry.find(needle).expect("the entry names its section") + needle.len();
        let tail = entry.get(from..).expect("the number");
        let digits = tail
            .get(
                ..tail
                    .find(|c: char| !c.is_ascii_digit())
                    .expect("terminated"),
            )
            .expect("the digits");
        assert_eq!(
            digits.parse::<u16>().expect("a section number"),
            ConfigSection::BusesAndDevices as u16,
            "{name}"
        );
    }
}
