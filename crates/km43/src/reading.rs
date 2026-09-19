//! What one value on the wire *means* to whoever received it.
//!
//! A `Sample` carries an integer and a `q` byte, and neither says whether the
//! integer is a measurement or a member of some set. The signal's descriptor
//! says: `vtype` makes it an enum and `esp` names which enum. This is the one
//! place that question is answered, so a client and a bench log cannot answer it
//! differently.
//!
//! **The rule is a refusal** (P-125). A member this build cannot name is
//! surfaced as itself and never mapped onto the nearest one that *is* named,
//! never rendered as a bare number, and never replaced with a fallback. A
//! charger ships firmware with charge stage 9; a client that picks the closest
//! stage it knows draws *float* over a pack that is doing something else, and
//! draws it confidently.
//!
//! This is the receiving half. The sending half is P-164, in the controller's
//! `q` byte: a controller that cannot name a state publishes
//! `validity 8 unnamed_state` and no value at all. The two are different
//! directions and neither substitutes for the other — a controller can only
//! refuse what *it* cannot name, and a client two versions older has a shorter
//! list.
//!
//! What used to be here was the controller's value model — `Reading`, keyed by
//! channel and metric kind, with `Meaning` matching three metric kinds written
//! out by hand. The store publishes `Sample` now and the hardcoded list is
//! exactly what `esp` was allocated to delete.

use crate::generated::EnumSpace;

/// What a value is, once the signal's descriptor has been consulted.
///
/// Built from `Option<EnumSpace>` rather than from a `vtype`, because for *this*
/// question a gauge and a counter are the same thing: a number. What matters is
/// whether the integer was drawn from a set, and which set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Meaning {
    /// A scaled integer. Its unit and scale are the metric kind's.
    Measurement(i32),
    /// A member of the signal's set, and this build can name it. The caller
    /// decodes it against that space's own type.
    Named(i32),
    /// A member of the signal's set that this build cannot name.
    ///
    /// The integer rides along because a bench log needs to tell state 6 from
    /// state 7, and a person reading one is not a screen rendering it. What it
    /// must never become is a fallback, a nearest match, or a number with a unit
    /// on it.
    Unrecognised(i32),
    /// No value. The `q` byte said so, and there is nothing to interpret.
    Nothing,
}

impl Meaning {
    /// Interpret one value against the set its signal draws from.
    ///
    /// `space` is `None` for a gauge or a counter — [`crate::Vtype`] says which
    /// of the two, and neither changes what the number *is*. Pass a signal's
    /// `esp`, which is REQUIRED exactly when its `vtype` is enum or flags.
    ///
    /// A space this build knows nothing about — a vendor one under P-019, or one
    /// allocated in a registry newer than this build — names nothing, so every
    /// value in it is [`Self::Unrecognised`]. That is the same answer for the
    /// same reason: surfaced, and never guessed at.
    #[must_use]
    pub fn of(value: Option<i32>, space: Option<EnumSpace>) -> Self {
        let Some(value) = value else {
            return Self::Nothing;
        };
        match space {
            None => Self::Measurement(value),
            Some(space) if space.names(value) => Self::Named(value),
            Some(_) => Self::Unrecognised(value),
        }
    }

    /// The integer, whatever it turned out to mean, or `None` where there was
    /// no value at all.
    ///
    /// For a bench log and for nothing that draws: [`Self::Unrecognised`] hands
    /// its number over here too, which is the whole point of keeping it.
    #[must_use]
    pub const fn raw(self) -> Option<i32> {
        match self {
            Self::Measurement(value) | Self::Named(value) | Self::Unrecognised(value) => {
                Some(value)
            }
            Self::Nothing => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Meaning;
    use crate::generated::EnumSpace;

    /// **P-125** — a state this build cannot name is `Unrecognised`, never the
    /// nearest one it knows and never a measurement.
    ///
    /// The failure is a client rendering *generator state 7* as *running*
    /// because 7 is not in its table and 3 is the closest thing. An engine
    /// somebody believes is running is worse than one they know they cannot
    /// see. The integer rides along so a bench log can tell state 6 from 7.
    ///
    /// This is the receiving half of the rule the controller enforces as
    /// `unnamed_state`. It is a separate test because it is a separate
    /// direction: a controller refuses what it cannot name, and a client two
    /// versions older has a shorter list than the controller that answered it.
    #[test]
    fn p_125_an_unnamed_state_is_never_rendered_as_the_nearest_one_this_build_knows() {
        let space = Some(EnumSpace::GENERATOR_STATE);

        // 3 is `running`, by the registry's own table.
        assert_eq!(Meaning::of(Some(3), space), Meaning::Named(3));

        // 9 is not a state this build has, and there is no arm that turns it
        // into one — nor into a number a unit could be hung on.
        assert_eq!(Meaning::of(Some(9), space), Meaning::Unrecognised(9));
        assert_ne!(Meaning::of(Some(9), space), Meaning::Measurement(9));

        // And it keeps its integer, which is what a bench log needs.
        assert_eq!(Meaning::of(Some(9), space).raw(), Some(9));
    }

    /// **P-019** — a value drawn from a set in the vendor range is surfaced,
    /// never rejected and never drawn as something else.
    ///
    /// Somebody hangs a meter this build has never heard of next to the frost
    /// probe, and it publishes states out of its own namespace. Refusing the
    /// value would blank a reading because one space was new; rendering it would
    /// put a number with no meaning on a card. It is `Unrecognised`, carrying
    /// its integer, which is the same answer P-125 gives for the same reason.
    ///
    /// A space allocated in a registry newer than this build answers identically
    /// — this build cannot name anything in either, and pretending to tell them
    /// apart would be a claim it has no basis for.
    #[test]
    fn p_019_a_value_from_a_vendor_set_is_surfaced_rather_than_rejected_or_drawn() {
        let vendor = Some(EnumSpace(0xF001));
        assert_eq!(
            Meaning::of(Some(4_200), vendor),
            Meaning::Unrecognised(4_200)
        );
        assert_eq!(Meaning::of(Some(4_200), vendor).raw(), Some(4_200));

        // The same integer with no space at all is a measurement, which is what
        // makes the boundary a boundary rather than a comment.
        assert_eq!(
            Meaning::of(Some(4_200), None),
            Meaning::Measurement(4_200),
            "a plain gauge was read as a state"
        );
    }

    /// No value is not a value of zero, and it is not an unrecognised state
    /// either — there is nothing to recognise.
    ///
    /// The `q` byte is what decides this, and it decides it for every validity
    /// that carries no number: a dead probe, a signal nobody has polled, a
    /// reading the source said was out of range. All of them arrive here as
    /// `None` and none of them may leave with an integer.
    #[test]
    fn a_reading_with_no_value_is_nothing_rather_than_zero() {
        for space in [
            None,
            Some(EnumSpace::GENERATOR_STATE),
            Some(EnumSpace(0xF001)),
        ] {
            assert_eq!(Meaning::of(None, space), Meaning::Nothing);
            assert_eq!(Meaning::of(None, space).raw(), None);
        }
    }
}
