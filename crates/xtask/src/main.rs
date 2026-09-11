//! Build tooling for the Origin89 protocol specification.
//!
//! Four artefacts have to agree with each other and eventually with two
//! implementations: the prose spec, the registry, the test vectors, and the
//! code. That is six ways to drift, and today nothing forces any of them to
//! move together — a formula changed and the vectors did not, and it was caught
//! by somebody reading both files rather than by a check.
//!
//! This crate is that check.

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]

mod bindings;
mod bodies;
mod check;
mod codegen;
mod diagram;
mod preimage;
mod registry;
mod rows;
mod traceability;
mod vectors;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Keep the protocol spec, registry, vectors and code in sync"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Regenerate REGISTRY.md, MAP.md and both bindings from protocol.toml.
    Registry,
    /// Regenerate the test vectors.
    Vectors,
    /// Every consistency check. This is the one CI runs.
    Check {
        /// Report what is wrong without failing, for use while editing.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Registry => {
            let root = check::repo_root()?;
            codegen::Codegen::load(&root)?.write(&root)?;
            diagram::Diagram::load(&root)?.write(&root)?;
            bindings::Bindings::load(&root)?.write(&root)
        }
        Cmd::Vectors => {
            let out = vectors::build()?;
            let path = check::repo_root()?.join("docs/protocol/vectors/v1.json");
            std::fs::write(&path, out)?;
            println!("\nwrote {}", path.display());
            Ok(())
        }
        Cmd::Check { dry_run } => check::run(dry_run),
    }
}
