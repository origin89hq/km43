//! A counter that went backwards restarted. It did not break.
//!
//! A PV yield returns to zero at midnight and a meter's total does after a power
//! cut. Refusing either as `out_of_range` drops a real day of energy, and
//! publishing it as `ok` hands a chart a cliff it reads as energy going back into
//! the panels. `reset` publishes the number and says a new run starts at it, so
//! whatever joins readings into a line starts a new one.
//!
//! The judgement needs the previous total, which a single reading does not
//! carry. That is why this is a type the publisher holds per signal and not a
//! check a decoder could make.
//!
//! cites: P-259

use crate::generated::Validity;

/// The last total one counter signal published, which is what the next one is
/// judged against.
///
/// One per counter signal, held by whoever publishes it. It starts empty, so
/// the first total after a boot is `ok`: a restart the controller did not see
/// is not one it can claim, and a client comparing its own history still can.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CounterRun {
    last: Option<i32>,
}

impl CounterRun {
    /// A run with nothing published yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// The validity to publish `total` at. Changes nothing.
    ///
    /// Below the last published total is `reset`, with the number. A negative
    /// total is `out_of_range` with none: a counter counts up from zero, so a
    /// negative one is a decode fault.
    #[must_use]
    pub const fn judge(&self, total: i32) -> Validity {
        if total < 0 {
            return Validity::OutOfRange;
        }
        match self.last {
            Some(last) if total < last => Validity::Reset,
            Some(_) | None => Validity::Ok,
        }
    }

    /// Record `total` as published, once the sample carrying it is on the
    /// wire and not before.
    ///
    /// Apart from [`Self::judge`] because a full page leaves a sample for the
    /// next one: recorded at judgement, the reset that missed the page would be
    /// the last total, and the same zero on the next page would go out as `ok`.
    /// A negative total is never published with a value, so it is ignored
    /// rather than kept as a floor the next honest reading reads as a rise from.
    pub fn published(&mut self, total: i32) {
        if total >= 0 {
            self.last = Some(total);
        }
    }

    /// The last total published, or `None` before the first.
    #[must_use]
    pub const fn last(&self) -> Option<i32> {
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::{CborReader, CborWriter};
    use crate::generated::Provenance;
    use crate::ident::Id;
    use crate::readings::{Sample, SignalQuality};

    /// Feed a run a sequence of totals, each published, and collect what each
    /// was published at.
    fn judged<const N: usize>(totals: [i32; N]) -> [Validity; N] {
        let mut run = CounterRun::new();
        totals.map(|total| {
            let validity = run.judge(total);
            run.published(total);
            validity
        })
    }

    /// The day's yield went back to zero at midnight. Refused, the morning's
    /// first reading is lost; published as `ok`, a chart draws the whole of
    /// yesterday flowing back into the array.
    #[test]
    fn p_259_a_counter_that_moved_backwards_is_marked_reset_and_keeps_its_value() {
        assert_eq!(
            judged([5_000, 5_200, 0, 30]),
            [Validity::Ok, Validity::Ok, Validity::Reset, Validity::Ok],
            "the drop is the reset, and the run after it carries on as ok"
        );

        let q = SignalQuality::carrying(Validity::Reset, Provenance::Counted)
            .expect("a reset carries the number it restarted at");
        let sample = Sample::new(Id::new(7).expect("a sig"), q, Some(0), None)
            .expect("a reset sample with its value");
        let mut buf = [0u8; 32];
        let mut w = CborWriter::new(&mut buf);
        sample.encode(&mut w).expect("encodes");
        let len = w.finish().expect("the map is closed");
        let mut r = CborReader::new(buf.get(..len).expect("within the buffer"));
        let back = Sample::decode(&mut r).expect("decodes");
        assert_eq!(back.q.validity_of(), Validity::Reset);
        assert_eq!(
            back.value(),
            Some(0),
            "the restart value reaches the client"
        );
    }

    /// A counter that held still or rose is the same run.
    #[test]
    fn a_counter_that_holds_or_rises_is_ok() {
        assert_eq!(
            judged([10, 10, 11, i32::MAX]),
            [Validity::Ok; 4],
            "equal is not backwards"
        );
    }

    /// Nothing has been published after a boot, so there is nothing to be
    /// below: a first total of zero is not evidence of a restart.
    #[test]
    fn the_first_total_after_a_boot_is_ok_whatever_it_is() {
        assert_eq!(judged([0]), [Validity::Ok]);
        assert_eq!(CounterRun::new().last(), None);
    }

    /// A 32-bit meter wrapping at its top is a restart as far as a run is
    /// concerned: the total went down and a line across it would be a lie.
    #[test]
    fn a_wrap_at_the_top_is_a_reset() {
        assert_eq!(judged([i32::MAX, 0]), [Validity::Ok, Validity::Reset]);
    }

    /// A negative total is a decode fault on a quantity that only counts up. It
    /// is refused, and it must not become the floor: remembered, the honest 900
    /// after it would read as a rise from -5 and the true restart from 1 000
    /// would go unmarked.
    #[test]
    fn a_negative_total_is_out_of_range_and_does_not_become_the_floor() {
        let mut run = CounterRun::new();
        run.published(1_000);
        assert_eq!(run.judge(-5), Validity::OutOfRange);
        run.published(-5);
        assert_eq!(run.last(), Some(1_000));
        assert_eq!(run.judge(900), Validity::Reset);
    }

    /// The reset did not fit on this page, so it goes out on the next one. It
    /// has to go out as a reset there too: judged and recorded at once, the
    /// zero that never left would be the last total, the same zero a page later
    /// would be `ok`, and a client would see 200 fall to 0 with nothing marked.
    #[test]
    fn a_reset_left_off_a_full_page_is_still_a_reset_on_the_next() {
        let mut run = CounterRun::new();
        run.published(200);
        assert_eq!(
            run.judge(0),
            Validity::Reset,
            "judged, and the page was full"
        );
        assert_eq!(
            run.judge(0),
            Validity::Reset,
            "judged again for the next page"
        );
        run.published(0);
        assert_eq!(run.judge(10), Validity::Ok);
    }
}
