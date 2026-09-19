//! The generated helpers against the registry they were generated from.
//!
//! `generated.rs` is written by `cargo xtask registry`, and the gate compares
//! the file to what the generator would write today. What it cannot see is a
//! generator that was changed on purpose and now folds a table wrongly: a
//! `granted` that drops the cloud row, a `METRIC_UNITS` sorted by name so the
//! bisect misses, a `TryFrom` that keeps a retired number or hands two names
//! each other's. Each of those would regenerate cleanly and ship. So these
//! read `protocol.toml` with the same scan `admission.rs` uses and ask the
//! bindings the question a consumer will, never retyping a number: the file
//! is the only opinion.

use km43::{
    BootReason, Bucket, CapabilityBit, ClientCapability, ClientConnected, ClientDisconnected,
    ClientKind, CloseConnection, CloseReason, Command, CommandKind, CommsRelease, CommsReleaseOp,
    ConcernState, Concerns, ConfigSection, ControlOwner, Direction, DisconnectReason, ErrorCode,
    EventKind, Firmware, GeneratorSelector, GeneratorState, History, HistorySource,
    HistoryStopReason, Inventory, InventoryKind, LinkDirection, LinkErrorCode, LinkMessageType,
    LinkTransport, MessageType, MetricKind, NetConfig, NetConfigOp, Pair, Presence, Provenance,
    Quality, Readings, SetConfig, Severity, Shape, SignalDomain, Time, TimeOffer, TimeSource,
    TopologyChangeReason, Transport, Unit, Validity, Vtype,
};
use std::collections::BTreeSet;

const REGISTRY: &str = include_str!("../protocol.toml");

/// One `[[table]]` block, as the `key = value` lines under it.
struct Table {
    name: String,
    fields: Vec<(String, String)>,
}

impl Table {
    /// A field's value with its quotes stripped, or `None` when the block has
    /// no such line.
    fn field(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().trim_matches('"'))
    }

    /// A field that is a number, written in hex or decimal.
    fn number(&self, key: &str) -> Option<u16> {
        parse_number(self.field(key)?)
    }

    /// A `["a", "b"]` field as its words.
    fn list(&self, key: &str) -> Vec<String> {
        self.field(key)
            .map(|v| {
                v.trim_matches(|c| c == '[' || c == ']')
                    .split(',')
                    .map(|w| w.trim().trim_matches('"').to_owned())
                    .filter(|w| !w.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A `status` line, or `None` when the row carries none.
    fn status(&self) -> Option<&str> {
        self.field("status")
    }
}

fn parse_number(v: &str) -> Option<u16> {
    v.strip_prefix("0x")
        .map_or_else(|| v.parse().ok(), |hex| u16::from_str_radix(hex, 16).ok())
}

/// Every block in the registry, by scanning rather than parsing: a heading
/// line opens a block and every `key = value` line until the next heading
/// belongs to it. Not a TOML crate, for the reason `admission.rs` gives.
fn tables() -> Vec<Table> {
    let mut out: Vec<Table> = Vec::new();
    for line in REGISTRY.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            out.push(Table {
                name: line.trim_matches(|c| c == '[' || c == ']').to_owned(),
                fields: Vec::new(),
            });
            continue;
        }
        if let (Some(last), Some((key, value))) = (out.last_mut(), line.split_once('=')) {
            last.fields
                .push((key.trim().to_owned(), value.trim().to_owned()));
        }
    }
    out
}

/// The blocks under one heading, and there must be some: a scan that matched
/// nothing would pass every assertion below over an empty list.
fn blocks(name: &str) -> Vec<Table> {
    let found: Vec<_> = tables().into_iter().filter(|t| t.name == name).collect();
    assert!(
        !found.is_empty(),
        "no [[{name}]] block was read out of protocol.toml"
    );
    found
}

/// Whether a status means the generator drops the number.
fn is_gone(status: Option<&str>) -> bool {
    matches!(status, Some("withdrawn" | "retired"))
}

/// Every event, with whether the registry says class A. A retired event is
/// gone from the bindings and so must answer `None`, which is how a controller
/// avoids ranking a record nobody writes any more.
#[test]
fn is_class_a_answers_the_registry_s_class_column_for_every_event() {
    let mut classified = 0;
    for event in blocks("events") {
        let kind = EventKind(event.number("kind").expect("an event has a kind"));
        let class = event.field("class").expect("an event has a class");
        if is_gone(event.status()) {
            assert_eq!(
                kind.is_class_a(),
                None,
                "{kind:?} is {:?} in the registry and the bindings still classify it",
                event.status()
            );
            continue;
        }
        assert_eq!(
            kind.is_class_a(),
            Some(class == "A"),
            "{kind:?} is class {class} in the registry"
        );
        classified += 1;
    }
    assert!(classified >= 10, "only {classified} events were compared");
}

/// A kind the registry never allocated is `None`, not `false`: a controller
/// that shed an unknown record as droppable sheds the ones a newer firmware
/// added because they mattered. Every free kind, because a stray row at
/// `0xffff` answers for a kind nobody defined and a check of the smallest
/// free one never looks there.
#[test]
fn is_class_a_says_nothing_about_any_kind_the_registry_never_allocated() {
    for free in every_free(blocks("events").iter().filter_map(|e| e.number("kind"))) {
        assert_eq!(
            EventKind(free).is_class_a(),
            None,
            "event kind {free:#06x} is not in the registry and the bindings classify it"
        );
    }
}

/// Every metric answers the unit and decade the registry gives it. Bisected
/// on a table the generator sorts, so a table emitted in file order would
/// miss every kind after the first one out of place.
#[test]
fn unit_and_scale_answers_the_registry_s_unit_and_decade_for_every_metric() {
    let mut compared = 0;
    for metric in blocks("metrics") {
        if is_gone(metric.status()) {
            continue;
        }
        let kind = MetricKind(metric.number("kind").expect("a metric has a kind"));
        let unit = metric.field("unit").expect("a metric has a unit");
        let scale: i8 = metric
            .field("scale")
            .expect("a metric has a scale")
            .parse()
            .expect("a scale is a small signed integer");
        assert_eq!(
            kind.unit_and_scale(),
            Some((unit, scale)),
            "{kind:?} is read in {unit} at 10^{scale} in the registry"
        );
        compared += 1;
    }
    assert!(compared >= 20, "only {compared} metrics were compared");
}

/// A kind with no row is `None`, never a default unit: a value rendered in
/// the wrong unit is a number a person acts on. Every free kind, for the
/// reason the event check above gives.
#[test]
fn unit_and_scale_has_no_answer_for_any_kind_the_registry_never_allocated() {
    for free in every_free(blocks("metrics").iter().filter_map(|m| m.number("kind"))) {
        assert_eq!(
            MetricKind(free).unit_and_scale(),
            None,
            "metric kind {free:#06x} is not in the registry and the bindings give it a unit"
        );
    }
}

/// The live capability rows: bit and the kinds each is granted to.
fn capability_rows() -> Vec<(u16, Vec<String>)> {
    let rows: Vec<_> = blocks("client_capability")
        .iter()
        .filter(|c| c.status() == Some("live"))
        .filter_map(|c| Some((c.number("bit")?, c.list("granted_to"))))
        .collect();
    assert!(
        rows.len() >= 3,
        "only {} capability bits were read",
        rows.len()
    );
    rows
}

/// Every client kind, as its wire value and its registry name. The variant
/// the value decodes to must carry that name, or the grant checks below would
/// compare `cloud`'s column against whichever variant took its number.
fn client_kinds() -> Vec<(ClientKind, String)> {
    blocks("enums.client_kind")
        .iter()
        .filter(|k| !is_gone(k.status()))
        .map(|k| {
            let value = u8::try_from(k.number("value").expect("a kind has a value"))
                .expect("a client kind is a byte");
            let kind = ClientKind::try_from(value)
                .unwrap_or_else(|()| panic!("client kind {value} is allocated and has no variant"));
            let name = k.field("name").expect("a kind has a name").to_owned();
            assert_eq!(
                format!("{kind:?}"),
                generated_name(&name),
                "client kind {value} is {name} in the registry"
            );
            (kind, name)
        })
        .collect()
}

/// `granted` is the `granted_to` column folded per kind, and the cloud row is
/// the one that differs: a generator that gave every kind the same mask is a
/// cloud client the document says cannot push firmware, pushing firmware.
#[test]
fn granted_folds_the_registry_s_granted_to_column_for_every_client_kind() {
    let rows = capability_rows();
    let mut masks = Vec::new();
    for (kind, name) in client_kinds() {
        let mask = rows
            .iter()
            .filter(|(_, kinds)| kinds.contains(&name))
            .fold(0u16, |mask, (bit, _)| mask | (1 << bit));
        assert_eq!(
            ClientCapability::granted(kind),
            ClientCapability(mask),
            "{kind:?} is granted {mask:#07b} by the registry"
        );
        masks.push(mask);
    }
    assert!(
        masks.iter().any(|m| masks.iter().any(|n| n != m)),
        "every kind has the same mask, so the fold is not reading the column"
    );
}

/// `allows` answers each bit the way the registry grants it, kind by kind,
/// and the multi-bit case both ways: the whole granted mask is allowed, and a
/// mask carrying one bit the kind lacks is refused with it.
#[test]
fn allows_agrees_with_the_registry_bit_by_bit_and_refuses_a_mask_with_one_bit_too_many() {
    let rows = capability_rows();
    let mut refused_one = false;
    for (kind, name) in client_kinds() {
        let granted = ClientCapability::granted(kind);
        assert!(
            granted.allows(granted),
            "{kind:?} does not allow its own mask"
        );
        for (bit, kinds) in &rows {
            let one = ClientCapability(1 << bit);
            assert_eq!(
                granted.allows(one),
                kinds.contains(&name),
                "{kind:?} and bit {bit} disagree with the registry"
            );
            if !kinds.contains(&name) {
                assert!(
                    !granted.allows(ClientCapability(granted.0 | one.0)),
                    "{kind:?} allows a mask carrying bit {bit}, which it was never granted"
                );
                refused_one = true;
            }
        }
    }
    assert!(
        refused_one,
        "no kind lacks any bit, so the refusal was never exercised"
    );
}

/// An unallocated bit is granted to nobody: a capability nobody has defined
/// is not one a client can hold. Both ends of the range and everything
/// between, since a mask with bit 9 set passes a check of bit 5.
#[test]
fn no_client_kind_is_granted_any_bit_the_registry_has_not_allocated() {
    let (first, last) = blocks("client_capability")
        .iter()
        .find_map(|c| {
            let (first, last) = c.field("range")?.split_once('–')?;
            Some((parse_number(first.trim())?, parse_number(last.trim())?))
        })
        .expect("the capability table names its unallocated range by both ends");
    assert!(
        first <= last,
        "the unallocated range {first}–{last} is empty"
    );
    for (kind, _) in client_kinds() {
        for bit in first..=last {
            let one = 1u16
                .checked_shl(u32::from(bit))
                .unwrap_or_else(|| panic!("bit {bit} does not fit a u16 mask"));
            assert!(
                !ClientCapability::granted(kind).allows(ClientCapability(one)),
                "{kind:?} holds bit {bit}, which the registry leaves unallocated"
            );
        }
    }
}

/// Every number no row of a table carries, gone rows included since those
/// are checked on their own, so a refusal covers the whole space the file
/// says is free rather than the one number somebody thought to try.
fn every_free(allocated: impl Iterator<Item = u16>) -> impl Iterator<Item = u16> {
    let taken: BTreeSet<u16> = allocated.collect();
    (0..=u16::MAX).filter(move |n| !taken.contains(n))
}

/// The side the registry's `direction` column names, spelled out here rather
/// than borrowed from xtask so the two can disagree. A value this match has
/// never seen fails rather than falling through to a guess.
fn registry_direction(column: &str) -> LinkDirection {
    match column {
        "either" => LinkDirection::Either,
        "comms-to-controller" => LinkDirection::CommsToController,
        "controller-to-comms" => LinkDirection::ControllerToComms,
        other => panic!("link direction {other:?} is not one this test knows"),
    }
}

/// Every link-local request and its acknowledgement answer the side the
/// registry's `direction` column gives the row. L-001 refuses a message from
/// the wrong side, and its test takes the expectation from `direction()`
/// itself, so a generator that put `NetConfig` on the comms side would have a
/// controller refusing its own configuration with every test green.
#[test]
fn link_direction_answers_the_registry_s_direction_column_for_every_request_and_ack() {
    let mut sides = BTreeSet::new();
    for row in blocks("link_messages") {
        if is_gone(row.status()) {
            continue;
        }
        let column = row
            .field("direction")
            .expect("a link message has a direction");
        let expected = registry_direction(column);
        for key in ["request", "response"] {
            let number = row
                .number(key)
                .and_then(|n| u8::try_from(n).ok())
                .unwrap_or_else(|| panic!("a link message has a one-byte {key}"));
            let message = LinkMessageType::try_from(number)
                .unwrap_or_else(|()| panic!("link opcode {number:#04x} has no variant"));
            assert_eq!(
                message.direction(),
                expected,
                "{message:?} ({number:#04x}) is sent {column} in the registry"
            );
        }
        sides.insert(column.to_owned());
    }
    assert_eq!(
        sides.len(),
        3,
        "the rows named only {sides:?}, so not every side was compared"
    );
}

/// The identifier the generator gives a registry name, written out again here
/// rather than borrowed from xtask so the two can disagree: the part before any
/// parenthetical, split on everything that is not an ASCII letter or digit,
/// each word's first letter raised and the rest left alone, so `Bad MAC` is
/// `BadMAC` and `Busy — retry` is `BusyRetry`.
fn generated_name(name: &str) -> String {
    name.split('(')
        .next()
        .unwrap_or(name)
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            c.next().map_or_else(String::new, |f| {
                f.to_ascii_uppercase().to_string() + c.as_str()
            })
        })
        .collect()
}

/// One allocated number of a closed set, and the variant the generator names
/// it, or `None` when the generator drops the row.
struct Allocated {
    number: u16,
    variant: Option<String>,
}

/// The numbers a `[[messages]]`-shaped table allocates under `request` and
/// `response`, emitted unless the row is gone. A request is named for the row
/// and its response for the row plus `response_suffix`, which is `Response`
/// for a client message and `Ack` for a link-local one.
fn message_numbers(table: &str, response_suffix: &str) -> Vec<Allocated> {
    blocks(table)
        .iter()
        .flat_map(|m| {
            let base = (!is_gone(m.status()))
                .then(|| generated_name(m.field("name").expect("a message has a name")));
            [("request", ""), ("response", response_suffix)]
                .into_iter()
                .filter_map(|(key, suffix)| {
                    Some(Allocated {
                        number: m.number(key)?,
                        variant: base.as_ref().map(|b| format!("{b}{suffix}")),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The numbers under one `key` of a table, emitted under `rule` and named from
/// the `named_by` column. That column is `name` everywhere but `[[errors]]`,
/// whose variants are named for their `meaning`.
fn numbers(
    table: &str,
    key: &str,
    named_by: &str,
    rule: fn(Option<&str>) -> bool,
) -> Vec<Allocated> {
    blocks(table)
        .iter()
        .filter_map(|row| {
            Some(Allocated {
                number: row.number(key)?,
                variant: rule(row.status()).then(|| {
                    generated_name(row.field(named_by).unwrap_or_else(|| {
                        panic!("a {table} row numbered by {key} has no {named_by}")
                    }))
                }),
            })
        })
        .collect()
}

/// An error code is emitted only while live: a reserved code has no meaning
/// yet, and a variant for it is a refusal a receiver could act on.
fn live_only(status: Option<&str>) -> bool {
    status == Some("live")
}

/// An outcome or enum member is emitted unless retired or withdrawn, and a
/// row with no status line is live.
fn unless_gone(status: Option<&str>) -> bool {
    !is_gone(status)
}

/// A `codes.*` row is emitted only when it carries a status and that status
/// is not gone; a range row has neither a number nor a status.
fn with_status_unless_gone(status: Option<&str>) -> bool {
    status.is_some_and(|s| !is_gone(Some(s)))
}

/// Every allocated number of a closed set decodes through its `TryFrom` to the
/// variant named for its registry row, every gone number is refused, and so is
/// every other number the type can carry. A generator that dropped a live
/// row, kept a retired one, or emitted a discriminant off by one is caught by
/// whichever of the three it broke. The name is what catches two rows whose
/// numbers were swapped: each number still decodes to a variant carrying it,
/// so the round trip passes while every caller that writes `Hello` sends the
/// opcode of something else.
macro_rules! closed_set {
    ($test:ident, $ty:ty, $repr:ty, $rows:expr) => {
        #[test]
        fn $test() {
            let rows: Vec<Allocated> = $rows;
            assert!(
                rows.iter().any(|r| r.variant.is_some()),
                "{} has no emitted row, so nothing here was compared",
                stringify!($ty)
            );
            for row in &rows {
                let number = <$repr>::try_from(row.number).unwrap_or_else(|_| {
                    panic!("{} does not fit a {}", row.number, stringify!($repr))
                });
                let got = <$ty>::try_from(number);
                if let Some(expected) = &row.variant {
                    let variant = got.unwrap_or_else(|()| {
                        panic!(
                            "{} {number:#x} is allocated and has no variant",
                            stringify!($ty)
                        )
                    });
                    assert_eq!(
                        variant as $repr,
                        number,
                        "{} {number:#x} decodes to a variant numbered otherwise",
                        stringify!($ty)
                    );
                    assert_eq!(
                        format!("{variant:?}"),
                        *expected,
                        "{} {number:#x} is {expected} in the registry",
                        stringify!($ty)
                    );
                } else {
                    assert!(
                        got.is_err(),
                        "{} {number:#x} is gone from the registry and still decodes",
                        stringify!($ty)
                    );
                }
            }
            // Every number the type can carry, not only the first free one: a
            // stray arm at 0xfe passes a check that looks at 0x00.
            let taken: std::collections::BTreeSet<u16> = rows.iter().map(|r| r.number).collect();
            for free in <$repr>::MIN..=<$repr>::MAX {
                if taken.contains(&u16::from(free)) {
                    continue;
                }
                assert!(
                    <$ty>::try_from(free).is_err(),
                    "{} accepts {free:#x}, which the registry never allocated",
                    stringify!($ty)
                );
            }
        }
    };
}

closed_set!(
    message_type_carries_every_allocated_opcode_and_refuses_the_rest,
    MessageType,
    u8,
    message_numbers("messages", "Response")
);
closed_set!(
    link_message_type_carries_every_allocated_opcode_and_refuses_the_rest,
    LinkMessageType,
    u8,
    message_numbers("link_messages", "Ack")
);
closed_set!(
    error_code_carries_every_live_code_and_refuses_the_withdrawn,
    ErrorCode,
    u16,
    numbers("errors", "code", "meaning", live_only)
);
closed_set!(
    link_error_code_carries_every_live_code_and_refuses_the_rest,
    LinkErrorCode,
    u16,
    numbers("link_errors", "code", "name", live_only)
);

closed_set!(
    command_outcome_matches_the_registry,
    Command,
    u8,
    numbers("outcomes.command", "value", "name", unless_gone)
);
closed_set!(
    concerns_outcome_matches_the_registry,
    Concerns,
    u8,
    numbers("outcomes.concerns", "value", "name", unless_gone)
);
closed_set!(
    firmware_outcome_matches_the_registry,
    Firmware,
    u8,
    numbers("outcomes.firmware", "value", "name", unless_gone)
);
closed_set!(
    history_outcome_matches_the_registry,
    History,
    u8,
    numbers("outcomes.history", "value", "name", unless_gone)
);
closed_set!(
    inventory_outcome_matches_the_registry,
    Inventory,
    u8,
    numbers("outcomes.inventory", "value", "name", unless_gone)
);
closed_set!(
    pair_outcome_matches_the_registry,
    Pair,
    u8,
    numbers("outcomes.pair", "value", "name", unless_gone)
);
closed_set!(
    readings_outcome_matches_the_registry,
    Readings,
    u8,
    numbers("outcomes.readings", "value", "name", unless_gone)
);
closed_set!(
    set_config_outcome_matches_the_registry,
    SetConfig,
    u8,
    numbers("outcomes.set_config", "value", "name", unless_gone)
);
closed_set!(
    time_outcome_matches_the_registry,
    Time,
    u8,
    numbers("outcomes.time", "value", "name", unless_gone)
);

closed_set!(
    boot_reason_matches_the_registry,
    BootReason,
    u8,
    numbers("enums.boot_reason", "value", "name", unless_gone)
);
closed_set!(
    bucket_matches_the_registry,
    Bucket,
    u8,
    numbers("enums.bucket", "value", "name", unless_gone)
);
closed_set!(
    client_kind_matches_the_registry,
    ClientKind,
    u8,
    numbers("enums.client_kind", "value", "name", unless_gone)
);
closed_set!(
    concern_state_matches_the_registry,
    ConcernState,
    u8,
    numbers("enums.concern_state", "value", "name", unless_gone)
);
closed_set!(
    control_owner_matches_the_registry,
    ControlOwner,
    u8,
    numbers("enums.control_owner", "value", "name", unless_gone)
);
closed_set!(
    direction_matches_the_registry,
    Direction,
    u8,
    numbers("enums.direction", "value", "name", unless_gone)
);
closed_set!(
    generator_selector_matches_the_registry,
    GeneratorSelector,
    u8,
    numbers("enums.generator_selector", "value", "name", unless_gone)
);
closed_set!(
    generator_state_matches_the_registry,
    GeneratorState,
    u8,
    numbers("enums.generator_state", "value", "name", unless_gone)
);
closed_set!(
    history_source_matches_the_registry,
    HistorySource,
    u8,
    numbers("enums.history_source", "value", "name", unless_gone)
);
closed_set!(
    history_stop_reason_matches_the_registry,
    HistoryStopReason,
    u8,
    numbers("enums.history_stop_reason", "value", "name", unless_gone)
);
closed_set!(
    inventory_kind_matches_the_registry,
    InventoryKind,
    u8,
    numbers("enums.inventory_kind", "value", "name", unless_gone)
);
closed_set!(
    presence_matches_the_registry,
    Presence,
    u8,
    numbers("enums.presence", "value", "name", unless_gone)
);
closed_set!(
    provenance_matches_the_registry,
    Provenance,
    u8,
    numbers("enums.provenance", "value", "name", unless_gone)
);
closed_set!(
    quality_matches_the_registry,
    Quality,
    u8,
    numbers("enums.quality", "value", "name", unless_gone)
);
closed_set!(
    severity_matches_the_registry,
    Severity,
    u8,
    numbers("enums.severity", "value", "name", unless_gone)
);
closed_set!(
    shape_matches_the_registry,
    Shape,
    u8,
    numbers("enums.shape", "value", "name", unless_gone)
);
closed_set!(
    signal_domain_matches_the_registry,
    SignalDomain,
    u8,
    numbers("enums.signal_domain", "value", "name", unless_gone)
);
closed_set!(
    time_source_matches_the_registry,
    TimeSource,
    u8,
    numbers("enums.time_source", "value", "name", unless_gone)
);
closed_set!(
    topology_change_reason_matches_the_registry,
    TopologyChangeReason,
    u8,
    numbers("enums.topology_change_reason", "value", "name", unless_gone)
);
closed_set!(
    transport_matches_the_registry,
    Transport,
    u8,
    numbers("enums.transport", "value", "name", unless_gone)
);
closed_set!(
    unit_matches_the_registry,
    Unit,
    u8,
    numbers("enums.unit", "value", "name", unless_gone)
);
closed_set!(
    validity_matches_the_registry,
    Validity,
    u8,
    numbers("enums.validity", "value", "name", unless_gone)
);
closed_set!(
    vtype_matches_the_registry,
    Vtype,
    u8,
    numbers("enums.vtype", "value", "name", unless_gone)
);

closed_set!(
    capability_bit_matches_the_registry,
    CapabilityBit,
    u16,
    numbers(
        "codes.capability_bit",
        "number",
        "name",
        with_status_unless_gone
    )
);
closed_set!(
    command_kind_matches_the_registry,
    CommandKind,
    u16,
    numbers(
        "codes.command_kind",
        "number",
        "name",
        with_status_unless_gone
    )
);
closed_set!(
    config_section_matches_the_registry,
    ConfigSection,
    u16,
    numbers(
        "codes.config_section",
        "number",
        "name",
        with_status_unless_gone
    )
);

closed_set!(
    client_connected_outcome_matches_the_registry,
    ClientConnected,
    u8,
    numbers(
        "link_outcomes.client_connected",
        "value",
        "name",
        unless_gone
    )
);
closed_set!(
    client_disconnected_outcome_matches_the_registry,
    ClientDisconnected,
    u8,
    numbers(
        "link_outcomes.client_disconnected",
        "value",
        "name",
        unless_gone
    )
);
closed_set!(
    close_connection_outcome_matches_the_registry,
    CloseConnection,
    u8,
    numbers(
        "link_outcomes.close_connection",
        "value",
        "name",
        unless_gone
    )
);
closed_set!(
    comms_release_outcome_matches_the_registry,
    CommsRelease,
    u8,
    numbers("link_outcomes.comms_release", "value", "name", unless_gone)
);
closed_set!(
    net_config_outcome_matches_the_registry,
    NetConfig,
    u8,
    numbers("link_outcomes.net_config", "value", "name", unless_gone)
);
closed_set!(
    time_offer_outcome_matches_the_registry,
    TimeOffer,
    u8,
    numbers("link_outcomes.time_offer", "value", "name", unless_gone)
);
closed_set!(
    close_reason_matches_the_registry,
    CloseReason,
    u8,
    numbers("link_enums.close_reason", "value", "name", unless_gone)
);
closed_set!(
    comms_release_op_matches_the_registry,
    CommsReleaseOp,
    u8,
    numbers("link_enums.comms_release_op", "value", "name", unless_gone)
);
closed_set!(
    disconnect_reason_matches_the_registry,
    DisconnectReason,
    u8,
    numbers("link_enums.disconnect_reason", "value", "name", unless_gone)
);
closed_set!(
    link_transport_matches_the_registry,
    LinkTransport,
    u8,
    numbers("link_enums.link_transport", "value", "name", unless_gone)
);
closed_set!(
    net_config_op_matches_the_registry,
    NetConfigOp,
    u8,
    numbers("link_enums.net_config_op", "value", "name", unless_gone)
);
