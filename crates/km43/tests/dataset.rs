//! The dataset crosswalk, read back through the generated bindings.
//!
//! The registry says which metric at which place carries which word of the
//! public equipment dataset. These read the answer the way a consumer will: a
//! kind and a place in, a word or nothing out.

use km43::{
    ComponentRole, DATASET_ABSENT, DATASET_METRICS, MeasurementPoint, MetricKind, SignalDomain,
};

#[test]
fn a_bank_voltage_is_the_dataset_battery_voltage() {
    assert_eq!(
        MetricKind::DC_VOLTAGE.dataset_name(
            SignalDomain::Live,
            Some(ComponentRole::BATTERY_BANK),
            None
        ),
        Some("battery-voltage")
    );
}

#[test]
fn the_same_kind_at_a_tracker_is_pv_voltage() {
    assert_eq!(
        MetricKind::DC_VOLTAGE.dataset_name(
            SignalDomain::Live,
            Some(ComponentRole::MPPT_TRACKER),
            None
        ),
        Some("pv-voltage")
    );
}

#[test]
fn a_cell_temperature_is_the_battery_s_and_a_heater_s_is_plain() {
    assert_eq!(
        MetricKind::TEMPERATURE.dataset_name(
            SignalDomain::Live,
            Some(ComponentRole::CELL),
            Some(MeasurementPoint::CELL)
        ),
        Some("battery-temperature"),
        "the specific row wins over the plain one"
    );
    assert_eq!(
        MetricKind::TEMPERATURE.dataset_name(SignalDomain::Live, Some(ComponentRole::HEATER), None),
        Some("temperature")
    );
}

#[test]
fn a_kind_with_no_word_and_a_place_no_row_names_answer_none() {
    assert_eq!(
        MetricKind::LOG_RING_UTILISATION.dataset_name(SignalDomain::Live, None, None),
        None
    );
    assert_eq!(
        MetricKind::DC_VOLTAGE.dataset_name(SignalDomain::Live, Some(ComponentRole::HEATER), None),
        None,
        "a heater's DC voltage is a reading with no dataset word, not a battery's"
    );
}

#[test]
fn a_word_the_protocol_cannot_carry_says_why() {
    let (_, why) = DATASET_ABSENT
        .iter()
        .find(|(word, _)| *word == "charge-stage")
        .expect("charge-stage is listed as absent");
    assert!(!why.is_empty());
    assert!(
        DATASET_METRICS.iter().all(|m| m.name != "charge-stage"),
        "a word is carried or absent, never both"
    );
}

#[test]
fn rows_are_most_specific_first() {
    let specificity = |m: &km43::DatasetMetric| {
        usize::from(m.role.is_some()) * 2 + usize::from(m.point.is_some())
    };
    let order: Vec<usize> = DATASET_METRICS.iter().map(specificity).collect();
    let mut sorted = order.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(
        order, sorted,
        "a lookup takes the first match, so specific rows must lead"
    );
}

#[test]
fn a_counter_s_word_depends_on_its_window() {
    assert_eq!(
        MetricKind::AC_ENERGY.dataset_name(SignalDomain::Lifetime, None, None),
        Some("ac-energy-total")
    );
    assert_eq!(
        MetricKind::AC_ENERGY.dataset_name(SignalDomain::Today, None, None),
        Some("ac-energy-today")
    );
    assert_eq!(
        MetricKind::AC_ENERGY.dataset_name(SignalDomain::Yesterday, None, None),
        None,
        "yesterday's energy is a period counter with no dataset word"
    );
    assert_eq!(
        MetricKind::AC_ENERGY.dataset_name(SignalDomain::Live, None, None),
        None,
        "a counter is never the live reading"
    );
}

#[test]
fn a_limit_is_not_the_live_reading() {
    assert_eq!(
        MetricKind::DC_CURRENT.dataset_name(
            SignalDomain::Live,
            Some(ComponentRole::BATTERY_BANK),
            None
        ),
        Some("battery-current")
    );
    assert_eq!(
        MetricKind::DC_CURRENT.dataset_name(
            SignalDomain::LimitUpper,
            Some(ComponentRole::BATTERY_BANK),
            None
        ),
        None,
        "a charge-current ceiling is a limit, not the current"
    );
}
