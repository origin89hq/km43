//! The dataset crosswalk, read back through the generated bindings.
//!
//! The registry says which metric at which place carries which word of the
//! public equipment dataset. These read the answer the way a consumer will: a
//! kind and a place in, a word or nothing out.

use km43::{
    ComponentRole, DATASET_ABSENT, DATASET_METRICS, Direction, MeasurementPoint, MetricKind,
    SignalDomain,
};

#[test]
fn a_bank_voltage_is_the_dataset_battery_voltage() {
    assert_eq!(
        MetricKind::DC_VOLTAGE.dataset_name(
            SignalDomain::Live,
            Some(ComponentRole::BATTERY_BANK),
            None,
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
            None,
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
            Some(MeasurementPoint::CELL),
            None
        ),
        Some("battery-temperature"),
        "the specific row wins over the plain one"
    );
    assert_eq!(
        MetricKind::TEMPERATURE.dataset_name(
            SignalDomain::Live,
            Some(ComponentRole::HEATER),
            None,
            None
        ),
        Some("temperature")
    );
}

#[test]
fn a_kind_with_no_word_and_a_place_no_row_names_answer_none() {
    assert_eq!(
        MetricKind::LOG_RING_UTILISATION.dataset_name(SignalDomain::Live, None, None, None),
        None
    );
    assert_eq!(
        MetricKind::DC_VOLTAGE.dataset_name(
            SignalDomain::Live,
            Some(ComponentRole::HEATER),
            None,
            None
        ),
        None,
        "a heater's DC voltage is a reading with no dataset word, not a battery's"
    );
}

#[test]
fn a_word_the_protocol_cannot_carry_says_why() {
    let (_, why) = DATASET_ABSENT
        .iter()
        .find(|(word, _)| *word == "cycle-count")
        .expect("cycle-count is listed as absent");
    assert!(!why.is_empty());
    for (word, _) in DATASET_ABSENT {
        assert!(
            DATASET_METRICS.iter().all(|m| m.name != *word),
            "{word} is carried and absent; a word is one or the other"
        );
    }
}

/// A dialect reading a charger's stage register publishes it under the charge
/// stage kind, and the dataset calls that `charge-stage`. The word was listed
/// absent until the space had members; a crosswalk that still said so would
/// leave every charger's stage without a column.
#[test]
fn a_live_charge_stage_is_the_dataset_charge_stage() {
    assert_eq!(
        MetricKind::CHARGE_STAGE.dataset_name(SignalDomain::Live, None, None, None),
        Some("charge-stage")
    );
    assert!(
        DATASET_ABSENT
            .iter()
            .all(|(word, _)| *word != "charge-stage"),
        "charge-stage is carried now and must not also be explained away"
    );
}

/// The stage is what the charger says now. A stage from yesterday is not a
/// charge stage anybody can act on, so no other domain is given the word.
#[test]
fn a_charge_stage_in_any_other_domain_has_no_word() {
    for domain in [
        SignalDomain::Lifetime,
        SignalDomain::SinceReset,
        SignalDomain::Today,
        SignalDomain::Yesterday,
    ] {
        assert_eq!(
            MetricKind::CHARGE_STAGE.dataset_name(domain, None, None, None),
            None,
            "{domain:?}"
        );
    }
}

#[test]
fn rows_are_most_specific_first() {
    let specificity = |m: &km43::DatasetMetric| {
        usize::from(m.role.is_some()) * 4
            + usize::from(m.point.is_some()) * 2
            + usize::from(m.dir.is_some())
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
        MetricKind::AC_ENERGY.dataset_name(SignalDomain::Lifetime, None, None, None),
        Some("ac-energy-total")
    );
    assert_eq!(
        MetricKind::AC_ENERGY.dataset_name(SignalDomain::Today, None, None, None),
        Some("ac-energy-today")
    );
    assert_eq!(
        MetricKind::AC_ENERGY.dataset_name(SignalDomain::Yesterday, None, None, None),
        None,
        "yesterday's energy is a period counter with no dataset word"
    );
    assert_eq!(
        MetricKind::AC_ENERGY.dataset_name(SignalDomain::Live, None, None, None),
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
            None,
            None
        ),
        Some("battery-current")
    );
    assert_eq!(
        MetricKind::DC_CURRENT.dataset_name(
            SignalDomain::LimitUpper,
            Some(ComponentRole::BATTERY_BANK),
            None,
            None
        ),
        None,
        "a charge-current ceiling is a limit, not the current"
    );
}

#[test]
fn uptime_is_counted_since_a_reset() {
    assert_eq!(
        MetricKind::UPTIME_SINCE_BOOT.dataset_name(SignalDomain::SinceReset, None, None, None),
        Some("uptime")
    );
    assert_eq!(
        MetricKind::UPTIME_SINCE_BOOT.dataset_name(SignalDomain::Live, None, None, None),
        None,
        "an uptime is a counter since boot, not an instantaneous reading"
    );
}

#[test]
fn a_tracker_s_yield_is_pv_energy_over_its_window() {
    let tracker = Some(ComponentRole::MPPT_TRACKER);
    let out = Some(Direction::PositiveIsOut);
    assert_eq!(
        MetricKind::DC_ENERGY.dataset_name(SignalDomain::Lifetime, tracker, None, out),
        Some("pv-energy-total")
    );
    assert_eq!(
        MetricKind::DC_ENERGY.dataset_name(SignalDomain::Today, tracker, None, out),
        Some("pv-energy-today")
    );
    assert_eq!(
        MetricKind::DC_ENERGY.dataset_name(
            SignalDomain::Today,
            Some(ComponentRole::PV_ARRAY),
            None,
            out
        ),
        Some("pv-energy-today"),
        "the array's own yield is the same word as its tracker's"
    );
    assert_eq!(
        MetricKind::DC_ENERGY.dataset_name(SignalDomain::Yesterday, tracker, None, out),
        None,
        "yesterday's yield is a period counter with no dataset word"
    );
    assert_eq!(
        MetricKind::DC_ENERGY.dataset_name(SignalDomain::Lifetime, tracker, None, None),
        None,
        "a DC counter that names no direction is not one the crosswalk can name"
    );
}

/// A shunt counts the bank's charge both ways, as two signals of one kind.
/// Only the one counting out is what the dataset calls consumed; a lookup that
/// ignored the direction would put the charged amp-hours under that word.
#[test]
fn only_the_charge_leaving_the_bank_is_consumed_amp_hours() {
    let bank = Some(ComponentRole::BATTERY_BANK);
    assert_eq!(
        MetricKind::DC_CHARGE.dataset_name(
            SignalDomain::SinceReset,
            bank,
            None,
            Some(Direction::PositiveIsOut)
        ),
        Some("consumed-amp-hours")
    );
    assert_eq!(
        MetricKind::DC_CHARGE.dataset_name(
            SignalDomain::SinceReset,
            bank,
            None,
            Some(Direction::PositiveIsIn)
        ),
        None,
        "charged amp-hours are not consumed ones"
    );
    assert_eq!(
        MetricKind::DC_CHARGE.dataset_name(
            SignalDomain::Lifetime,
            bank,
            None,
            Some(Direction::PositiveIsOut)
        ),
        None,
        "a lifetime total drawn is not the count since the shunt last synchronised"
    );
    assert_eq!(
        MetricKind::DC_CHARGE.dataset_name(
            SignalDomain::SinceReset,
            Some(ComponentRole::LOAD_OUTPUT),
            None,
            Some(Direction::PositiveIsOut)
        ),
        None,
        "a load's amp-hours are not the bank's"
    );
}

#[test]
fn the_dc_counters_are_carried_and_no_longer_listed_absent() {
    for word in ["pv-energy-today", "pv-energy-total", "consumed-amp-hours"] {
        assert!(
            DATASET_METRICS.iter().any(|m| m.name == word),
            "{word} is carried"
        );
        assert!(
            DATASET_ABSENT.iter().all(|(absent, _)| *absent != word),
            "{word} is carried and still listed absent"
        );
    }
}
