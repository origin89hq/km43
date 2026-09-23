//! Turning a refusal into bytes a test can compare, which is what a crate with
//! no allocator has instead of `format!`.
//!
//! Test-only, and one copy on purpose. `mac.rs` and `wrapper.rs` each grew
//! their own sink, their own render and their own read-back, alike to the byte
//! except for the width of the buffer. Both stand behind the same claim — that
//! no two refusals arrive as one sentence — and a claim checked in two places
//! is one that can quietly go wrong in either while both stay green, which is
//! the shape every check in this repo that turned out to be comparing nothing
//! had in common.

use core::fmt;
use core::fmt::Write as _;

/// A `core::fmt` sink over a fixed buffer. Running past the end is an error and
/// not a truncation, so a buffer too narrow for its sentences fails at the
/// `write!` rather than clipping two of them to a common prefix and reporting
/// that they match.
struct Sink<'a> {
    into: &'a mut [u8],
    written: usize,
}

impl fmt::Write for Sink<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for &byte in text.as_bytes() {
            let slot = self.into.get_mut(self.written).ok_or(fmt::Error)?;
            *slot = byte;
            self.written = self.written.saturating_add(1);
        }
        Ok(())
    }
}

/// The form a secret reached a rendering in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leak {
    /// Its own characters.
    AsText,
    /// Its bytes as decimals, which is how a derived `Debug` prints `&[u8]`.
    AsNumbers,
}

/// One rendered value: `WIDTH` bytes of room and the length actually written.
///
/// `WIDTH` is the caller's promise about the longest sentence its values
/// produce, and it is named at the call site rather than baked in here so two
/// tests with different vocabularies cannot end up sharing one number that
/// suits neither.
#[derive(Clone, Copy)]
pub(crate) struct Rendering<const WIDTH: usize> {
    text: [u8; WIDTH],
    len: usize,
}

impl<const WIDTH: usize> Rendering<WIDTH> {
    /// The sentence a person reads in a bench log.
    pub(crate) fn displayed(value: &impl fmt::Display) -> Self {
        Self::of(format_args!("{value}"))
    }

    /// The `Debug` rendering, which is where a leak hides: a derived `Debug`
    /// prints every private field, and that is a payload accessor spelled
    /// `{:?}`.
    pub(crate) fn debugged(value: &impl fmt::Debug) -> Self {
        Self::of(format_args!("{value:?}"))
    }

    /// How `value`'s `Debug` shows `secret`, if it does: as text, or as the
    /// decimal list a derived `Debug` prints for `&[u8]`. Checking the text
    /// alone passes a passphrase that went to the log as `[99, 111, 114, …]`.
    pub(crate) fn leak(value: &impl fmt::Debug, secret: &str) -> Option<Leak> {
        let rendered = Self::debugged(value);
        if rendered.shows(secret.as_bytes()) {
            return Some(Leak::AsText);
        }
        let listed = Self::debugged(&secret.as_bytes());
        let numbers = listed
            .bytes()
            .strip_prefix(b"[")
            .and_then(|inner| inner.strip_suffix(b"]"))
            .expect("a byte slice debugs as a bracketed list");
        rendered.shows(numbers).then_some(Leak::AsNumbers)
    }

    fn shows(&self, needle: &[u8]) -> bool {
        !needle.is_empty() && self.bytes().windows(needle.len()).any(|w| w == needle)
    }

    /// The bytes that were written, and none of the room that was not.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.text
            .get(..self.len)
            .expect("the length came from the render")
    }

    /// No two of `values` render as one sentence, and none renders as nothing.
    ///
    /// Each pair is rendered afresh rather than held side by side, so one list
    /// of any length needs one buffer's worth of stack and no allocator.
    pub(crate) fn each_says_something_of_its_own<T: fmt::Display + fmt::Debug>(values: &[T]) {
        for (first, one) in values.iter().enumerate() {
            let rendered = Self::displayed(one);
            assert!(!rendered.bytes().is_empty(), "{one:?} renders as nothing");
            for (second, other) in values.iter().enumerate().skip(first.saturating_add(1)) {
                assert_ne!(
                    rendered.bytes(),
                    Self::displayed(other).bytes(),
                    "refusals {first} and {second} render the same sentence"
                );
            }
        }
    }

    fn of(args: fmt::Arguments<'_>) -> Self {
        let mut text = [0u8; WIDTH];
        let mut sink = Sink {
            into: &mut text,
            written: 0,
        };
        sink.write_fmt(args)
            .expect("the rendering fits the width the test asked for");
        let len = sink.written;
        Self { text, len }
    }
}

#[cfg(test)]
mod tests {
    use super::Rendering;

    /// The one behaviour this file promises and nothing observed: a buffer too
    /// narrow fails at the render rather than clipping.
    ///
    /// Silently truncating instead leaves every test in the crate green, and the
    /// check it would quietly break is the one that says two refusals do not
    /// share a message — two sentences clipped to a common prefix compare equal
    /// and report exactly the agreement they were written to refuse.
    #[test]
    #[should_panic = "the rendering fits the width the test asked for"]
    fn a_sentence_wider_than_its_buffer_is_refused_rather_than_clipped() {
        let _ = Rendering::<8>::displayed(&"a sentence considerably wider than eight bytes");
    }
}
