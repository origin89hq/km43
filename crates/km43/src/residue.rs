//! What a key leaves in the memory it was dropped from, which safe Rust cannot
//! look at: the value is gone before anything can read it.
//!
//! Test-only. Without it the `Drop` impls that clear key bytes can be deleted
//! and every test still passes, because derivation and tagging work the same
//! either way.

#![expect(
    unsafe_code,
    reason = "reading a value's bytes after its destructor ran is the only witness that the destructor cleared them; the reads are confined to `Unpadded` types, whose every byte is initialised"
)]

use core::mem::{MaybeUninit, size_of};

/// A type with no padding, so reading its bytes as `u8` never reads an
/// uninitialised one. Each implementation sits beside the tests that use it,
/// with a size assertion that fails the build if padding ever appears.
pub(crate) trait Unpadded {}

/// Runs `value`'s destructor in place and returns the bytes it left behind.
pub(crate) fn after_drop<T: Unpadded, const N: usize>(value: T) -> [u8; N] {
    const { assert!(size_of::<T>() == N, "N must be the whole of T") };
    let mut slot = MaybeUninit::new(value);
    // SAFETY: `slot` holds the initialised `T` it was built from, this drops it
    // exactly once, and nothing reads it as a `T` afterwards.
    unsafe { slot.assume_init_drop() };
    // SAFETY: `N` is `size_of::<T>()`, so the read stays inside `slot`. `T` is
    // `Unpadded`, so every byte was initialised, and running a destructor does
    // not de-initialise the memory it ran on.
    unsafe { slot.as_ptr().cast::<[u8; N]>().read() }
}
