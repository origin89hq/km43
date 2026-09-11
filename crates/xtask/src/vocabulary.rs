//! Moves the dataset vocabulary pin, and never the build.
//!
//! The crosswalk in `protocol.toml` names words of the public equipment
//! dataset, and `cargo xtask check` reads them from a copy pinned beside the
//! registry. The copy is not fetched by the gate: a gate that reaches the
//! network fails when the network does and cannot be reproduced later, and a
//! registry that once passed would fail again the day the dataset renamed a
//! word, with no commit here to say so. This fetches instead, on request, shows
//! which words arrived or left, and moves the pin only with `--accept`, so a
//! change in the dataset reaches the registry as a reviewable diff.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::Digest as _;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::registry::Registry;

/// What the dataset's index says about one published file.
#[derive(Deserialize)]
struct Manifest {
    files: std::collections::BTreeMap<String, FileMeta>,
}

#[derive(Deserialize)]
struct FileMeta {
    sha256: String,
}

#[derive(Deserialize)]
struct Vocabulary {
    metrics: Vec<String>,
}

/// Fetch, compare, and with `accept` move the pin.
pub fn run(root: &Path, accept: bool) -> Result<()> {
    let reg = Registry::load(root)?;
    let dataset = reg
        .dataset
        .as_ref()
        .context("no [dataset] table pins a vocabulary")?;
    let manifest_url = manifest_url(&dataset.vocabulary_url)?;

    let manifest: Manifest = serde_json::from_slice(&fetch(&manifest_url)?)
        .with_context(|| format!("{manifest_url} is not the dataset's index"))?;
    let bytes = fetch(&dataset.vocabulary_url)?;
    let digest = hex(&sha2::Sha256::digest(&bytes));
    let listed = manifest
        .files
        .get("vocabulary.json")
        .map(|f| f.sha256.as_str())
        .context("the index lists no vocabulary.json")?;
    if listed != digest {
        bail!(
            "{} is sha256 {digest} and the index says {listed}; the dataset is mid-publish or \
             the file is not what its index describes. Try again, and do not accept this",
            dataset.vocabulary_url
        );
    }

    let dir = Path::new(Registry::PATH)
        .parent()
        .context("the registry path has no directory")?;
    let pinned_path = root.join(dir).join(&dataset.vocabulary_file);
    // What identifies the bytes: where they were fetched and what the index said of
    // them. No date, which would make the line depend on the day somebody ran this.
    let provenance = |digest: &str| {
        format!(
            "fetched from {}, listed by the index as sha256 {digest}",
            dataset.vocabulary_url
        )
    };
    if digest == dataset.vocabulary_sha256 {
        println!("the pin is current: {digest}");
        // An earlier `--accept` that moved the registry and then failed to write the
        // copy leaves the pin ahead of the file; this is where that is put right.
        let copy_matches =
            std::fs::read(&pinned_path).is_ok_and(|b| hex(&sha2::Sha256::digest(&b)) == digest);
        if !copy_matches {
            if accept {
                replace(&pinned_path, &bytes)?;
                println!("the pinned copy was behind the pin and is written again");
            } else {
                println!("the pinned copy does not match the pin; `--accept` writes it again");
            }
        }
        // The bytes were pinned before this fetch confirmed them against the index, as
        // the first pin was; `--accept` records that they have been now.
        if accept && !dataset.vocabulary_provenance.starts_with("fetched from ") {
            let toml_path = root.join(Registry::PATH);
            let source = std::fs::read_to_string(&toml_path)?;
            replace(
                &toml_path,
                move_pin(&source, &digest, &provenance(&digest))?.as_bytes(),
            )?;
            println!("provenance now records the fetch");
        }
        return Ok(());
    }

    let pinned: Vocabulary = serde_json::from_slice(&std::fs::read(&pinned_path)?)
        .context("the pinned copy is not a vocabulary")?;
    let published: Vocabulary =
        serde_json::from_slice(&bytes).context("the published file is not a vocabulary")?;
    let (added, removed) = words_moved(&pinned.metrics, &published.metrics);
    println!(
        "the published vocabulary is sha256 {digest}; the pin says {}",
        dataset.vocabulary_sha256
    );
    println!(
        "  {} metric words before, {} after: {} added, {} removed",
        pinned.metrics.len(),
        published.metrics.len(),
        added.len(),
        removed.len()
    );
    for w in &added {
        println!("    + {w}");
    }
    for w in &removed {
        println!("    - {w} (a crosswalk row naming it will fail the check)");
    }
    if !accept {
        println!("\nLook at the change, then accept it with:\n  cargo xtask vocabulary --accept");
        return Ok(());
    }

    // The registry edit is prepared before either file is written: a `protocol.toml`
    // that `move_pin` cannot rewrite must leave the pinned copy as it was, not pair
    // new bytes with the old hash and fail the gate.
    let toml_path = root.join(Registry::PATH);
    let source = std::fs::read_to_string(&toml_path)?;
    let moved = move_pin(&source, &digest, &provenance(&digest))?;
    // Two files cannot change as one, so each is replaced whole, the registry
    // first: a failure between the two leaves the pin ahead of the copy, which
    // the gate reports and a second `--accept` repairs, never a copy with no
    // pin that names it.
    replace(&toml_path, moved.as_bytes())?;
    replace(&pinned_path, &bytes)?;
    println!(
        "\npin moved to {digest}; run `just registry` and `just check`, and read the crosswalk \
         diff before committing"
    );
    Ok(())
}

/// Replace a file whole: written beside it, then renamed over it, so a failure
/// mid-write leaves the old file and not a torn one.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} over {}", tmp.display(), path.display()))
}

/// The index beside the published file: `/v1/vocabulary.json` is listed by `/manifest.json`.
fn manifest_url(vocabulary_url: &str) -> Result<String> {
    vocabulary_url
        .strip_suffix("/v1/vocabulary.json")
        .map(|origin| format!("{origin}/manifest.json"))
        .with_context(|| format!("{vocabulary_url} is not a `/v1/vocabulary.json` URL"))
}

/// Words in `after` that `before` lacks, and the other way round.
fn words_moved(before: &[String], after: &[String]) -> (Vec<String>, Vec<String>) {
    let b: BTreeSet<&str> = before.iter().map(String::as_str).collect();
    let a: BTreeSet<&str> = after.iter().map(String::as_str).collect();
    (
        a.difference(&b).map(|w| (*w).to_owned()).collect(),
        b.difference(&a).map(|w| (*w).to_owned()).collect(),
    )
}

/// `protocol.toml` with the pin's hash and provenance replaced, and nothing else
/// touched. Both keys must be present exactly once, or nothing is written.
fn move_pin(source: &str, sha256: &str, provenance: &str) -> Result<String> {
    let mut hash_lines = 0;
    let mut provenance_lines = 0;
    let out: Vec<String> = source
        .lines()
        .map(|line| {
            if line.starts_with("vocabulary_sha256 = ") {
                hash_lines += 1;
                format!("vocabulary_sha256 = {sha256:?}")
            } else if line.starts_with("vocabulary_provenance = ") {
                provenance_lines += 1;
                format!("vocabulary_provenance = {provenance:?}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    if hash_lines != 1 || provenance_lines != 1 {
        bail!(
            "expected one `vocabulary_sha256` and one `vocabulary_provenance` line, found {hash_lines} \
             and {provenance_lines}; move the pin by hand"
        );
    }
    let mut text = out.join("\n");
    if source.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// `curl`, because the one thing this needs from the network is bytes, and a
/// generator that must stay independent of `km43` should not grow an HTTP
/// stack for a maintenance command.
fn fetch(url: &str) -> Result<Vec<u8>> {
    let out = Command::new("curl")
        .args(["-fsSL", "--max-time", "30", url])
        .output()
        .with_context(|| format!("running curl for {url}"))?;
    if !out.status.success() {
        bail!(
            "fetching {url}: curl exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::{manifest_url, move_pin, words_moved};

    #[test]
    fn the_index_sits_beside_the_published_file() {
        assert_eq!(
            manifest_url("https://data.origin89.com/v1/vocabulary.json").expect("a v1 URL"),
            "https://data.origin89.com/manifest.json"
        );
        assert!(manifest_url("https://elsewhere.example/vocab.json").is_err());
    }

    #[test]
    fn a_move_says_which_words_came_and_went() {
        let before = ["a".to_owned(), "b".to_owned()];
        let after = ["b".to_owned(), "c".to_owned()];
        assert_eq!(
            words_moved(&before, &after),
            (vec!["c".to_owned()], vec!["a".to_owned()])
        );
        assert_eq!(words_moved(&before, &before), (vec![], vec![]));
    }

    /// The pin moves in two lines and the rest of the file is untouched; a file
    /// that does not carry both lines exactly once is left alone.
    #[test]
    fn moving_the_pin_rewrites_two_lines_and_nothing_else() {
        let source = "[dataset]\nvocabulary_url = \"u\"\nvocabulary_sha256 = \"old\"\nvocabulary_provenance = \"built\"\n\n[[dataset_metrics]]\nname = \"x\"\n";
        let moved = move_pin(source, "new", "fetched today").expect("both lines present");
        assert_eq!(
            moved,
            "[dataset]\nvocabulary_url = \"u\"\nvocabulary_sha256 = \"new\"\nvocabulary_provenance = \"fetched today\"\n\n[[dataset_metrics]]\nname = \"x\"\n"
        );
        assert!(move_pin("[dataset]\nvocabulary_url = \"u\"\n", "new", "p").is_err());
        assert!(
            move_pin(
                "vocabulary_sha256 = \"a\"\nvocabulary_sha256 = \"b\"\nvocabulary_provenance = \"p\"\n",
                "new",
                "p"
            )
            .is_err(),
            "two hash lines is a file somebody has to look at"
        );
    }
}
