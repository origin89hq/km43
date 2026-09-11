//! Refuses to build against constants that no longer match the registry.
//!
//! It does not generate anything. `cargo xtask registry` does that, and the
//! generated files are committed so that changing a protocol number shows up in
//! review as a diff — which is the entire point of allocating numbers in one
//! file. What this catches is the gap in between: somebody edits
//! `protocol.toml`, builds, and the firmware quietly keeps the old opcode
//! because nothing told them to regenerate. That mistake is free to make and
//! expensive to find, because the two implementations then disagree about a
//! number and nothing says so until a frame is refused on a bench.
//!
//! FNV-1a, computed here rather than pulled from a crate: a build script for a
//! firmware crate should not drag a hashing dependency into every
//! cross-compile, and the question is only whether the file changed.

use std::path::Path;

/// Kept in step with `Bindings::DIGEST_MARKER` in xtask.
const MARKER: &str = "// registry-digest: ";

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry = dir.join("protocol.toml");
    let generated = dir.join("src/generated.rs");

    println!("cargo:rerun-if-changed={}", registry.display());
    println!("cargo:rerun-if-changed={}", generated.display());

    let (Ok(source), Ok(bindings)) = (
        std::fs::read_to_string(&registry),
        std::fs::read_to_string(&generated),
    ) else {
        // A missing file is the build system's problem to report, not ours; a
        // panic here would bury the real error under a confusing one.
        return;
    };

    let Some(recorded) = bindings
        .lines()
        .find_map(|l| l.strip_prefix(MARKER))
        .map(str::trim)
    else {
        println!(
            "cargo:warning=src/generated.rs carries no registry digest; run `cargo xtask registry`"
        );
        return;
    };

    let actual = digest(&source);
    if recorded != actual {
        println!(
            "cargo:warning=protocol.toml has changed since src/generated.rs was written \
             ({recorded} on file, {actual} now) — run `cargo xtask registry`"
        );
        std::process::exit(1);
    }
}

/// Carriage returns are stripped so a checkout with different line endings does
/// not read as a different registry.
fn digest(source: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in source.bytes().filter(|&b| b != b'\r') {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}
