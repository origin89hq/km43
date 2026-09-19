//! The consistency checks. Each one exists because something got past a human.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A check that failed, with enough detail to fix it without re-deriving it.
struct Failure {
    check: &'static str,
    detail: String,
}

/// The checkout every check reads, found once.
///
/// It was nineteen free functions taking the same `&Path` and deriving from it
/// separately — three of them re-reading `docs/PROTOCOL.md`, three more
/// re-loading the registry. That is the shape the house rule names: functions
/// that all take the same first argument are a struct asking to exist, and what
/// it buys is that the root is found once and every check after that relies on
/// it instead of being handed a path it has to trust.
struct Checks {
    root: PathBuf,
}

pub fn run(dry_run: bool) -> Result<()> {
    let checks = Checks { root: repo_root()? };
    let mut failures = Vec::new();

    for result in [
        checks.vectors_are_regenerated(),
        checks.vectors_generator_is_independent(),
        checks.preimages_match_the_spec(),
        checks.bodies_match_the_spec(),
        checks.published_rows_match_the_spec(),
        checks.registry_version_matches_the_spec(),
        checks.every_live_number_is_reachable(),
        checks.every_live_enum_space_names_its_members(),
        checks.no_retired_message_keeps_a_normative_section(),
        checks.every_message_declares_its_auth(),
        checks.every_number_a_document_names_is_called_by_a_name_it_has(),
        checks.no_response_carries_key_material(),
        checks.no_link_code_is_written_as_a_literal(),
        checks.bindings_are_regenerated(),
        checks.no_doc_test_is_hidden_in_a_test_module(),
        checks.every_published_vector_is_read(),
        checks.every_no_std_crate_builds_for_the_target(),
        checks.every_link_lands(),
        checks.no_number_is_allocated_twice(),
        checks.every_requirement_is_cited(),
        checks.dataset_crosswalk_is_sound(),
    ] {
        match result {
            Ok(()) => {}
            Err(f) => failures.push(f),
        }
    }

    if failures.is_empty() {
        println!("all checks pass");
        return Ok(());
    }

    for f in &failures {
        eprintln!("\nFAIL  {}\n{}", f.check, indent(&f.detail));
    }
    if dry_run {
        eprintln!(
            "\n{} check(s) failed; --dry-run, not failing the build",
            failures.len()
        );
        return Ok(());
    }
    bail!("{} check(s) failed", failures.len())
}

impl Checks {
    /// `docs/PROTOCOL.md`, read from the root this was constructed with.
    ///
    /// Three checks opened it by name and one of them spelled the path a fourth
    /// time; a check reading a document that exists but is the wrong one passes
    /// in silence, which is the failure a shared accessor makes unreachable.
    fn spec(&self) -> Result<String> {
        let path = self.root.join("docs/PROTOCOL.md");
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))
    }

    /// The registry, parsed. Loaded per check rather than held, because a check
    /// that fails to parse it should say so as its own failure rather than stop
    /// the other eighteen from running.
    fn registry(&self) -> Result<crate::registry::Registry> {
        crate::registry::Registry::load(&self.root)
    }

    /// The vectors on disk must be exactly what the generator produces.
    ///
    /// A pairing preimage once gained a field and the vectors were never
    /// re-run, so two implementations could both pass every vector and still
    /// fail to pair.
    fn vectors_are_regenerated(&self) -> Result<(), Failure> {
        let path = self.root.join("docs/protocol/vectors/v1.json");
        let fail = |detail: String| Failure {
            check: "vectors are regenerated",
            detail,
        };

        let want = crate::vectors::build().map_err(|e| {
            fail(format!(
                "the generator refused to run — its own RFC self-checks failed, so any vectors it \
                 produced would encode the bug rather than catch it:\n{e}"
            ))
        })?;
        let have = std::fs::read_to_string(&path)
            .map_err(|e| fail(format!("reading {}: {e}", path.display())))?;

        if have == want {
            return Ok(());
        }
        let first = have
            .lines()
            .zip(want.lines())
            .enumerate()
            .find(|(_, (h, w))| h != w)
            .map_or_else(
                || {
                    format!(
                        "same prefix, different length ({} vs {} bytes)",
                        have.len(),
                        want.len()
                    )
                },
                |(n, (h, w))| {
                    format!(
                        "first difference at line {}:\n  on disk   {}\n  generated {}",
                        n + 1,
                        h.trim(),
                        w.trim()
                    )
                },
            );
        Err(fail(format!(
            "{path} is not what the generator produces. Either a formula changed and the vectors \
             were not regenerated, or the file was edited by hand. Run `cargo xtask vectors` and \
             commit the result in the SAME commit as the formula change — a vector that disagrees \
             with the spec is worse than no vector, because both implementations can pass it and \
             still not interoperate.\n\n{first}",
            path = path.display()
        )))
    }

    /// The vectors must not be produced by the code they check.
    ///
    /// Depend on `km43` here and the vectors become a round-trip test, which
    /// cannot catch an encoder and a decoder that are wrong the same way.
    fn vectors_generator_is_independent(&self) -> Result<(), Failure> {
        const FORBIDDEN: &str = "km43";
        let manifest = self.root.join("crates/xtask/Cargo.toml");
        let text = std::fs::read_to_string(&manifest).map_err(|e| Failure {
            check: "vectors generator is independent",
            detail: format!("could not read {}: {e}", manifest.display()),
        })?;

        // Only the dependency sections matter — the doc comment above names the
        // crate on purpose and must not trip its own check.
        let declares_it = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .any(|l| l.contains(FORBIDDEN));

        if declares_it {
            Err(Failure {
                check: "vectors generator is independent",
                detail: format!(
                    "xtask declares a dependency on {FORBIDDEN}. The vectors are the independent \
                     witness km43 is tested against; sharing its code makes them agree with \
                     its bugs. Use audited third-party primitives instead."
                ),
            })
        } else {
            Ok(())
        }
    }

    /// P-012, checked where the numbers are. See [`no_number_is_allocated_twice`].
    fn no_number_is_allocated_twice(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "no number is allocated twice",
            detail,
        };
        let registry = self.registry().map_err(|e| fail(format!("{e:#}")))?;
        no_number_is_allocated_twice(&registry).map_err(fail)
    }

    /// Every link a document makes must land. See [`every_link_lands`].
    fn every_link_lands(&self) -> Result<(), Failure> {
        every_link_lands(&self.root).map_err(|detail| Failure {
            check: "every link lands",
            detail,
        })
    }

    /// The generator's preimages must be the ones PROTOCOL.md specifies.
    ///
    /// The vectors gate above only proves the JSON matches the generator. Both can
    /// be self-consistent and both wrong, which is what happened when a pairing
    /// preimage gained a field in the spec and nowhere else.
    fn preimages_match_the_spec(&self) -> Result<(), Failure> {
        use crate::preimage::{DescribedBytes, Preimages};
        let fail = |detail: String| Failure {
            check: "preimages match the spec",
            detail,
        };

        let spec = Preimages::from_spec(&self.root).map_err(|e| fail(e.to_string()))?;
        let vectors = Preimages::from_vectors(&self.root).map_err(|e| fail(e.to_string()))?;
        let mut wrong = spec.disagreements(&vectors);
        wrong.extend(
            DescribedBytes::load(&self.root)
                .map_err(|e| fail(e.to_string()))?
                .disagreements(),
        );

        if wrong.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "the generator and the specification disagree about what a MAC covers. Whichever \
                 is right, an implementation built from the other one cannot interoperate:\n\n{}",
                wrong.join("\n")
            )))
        }
    }

    /// The published bodies must carry the fields PROTOCOL.md lists, under the
    /// numbers it gives them.
    ///
    /// Two implementations agreeing byte for byte says they read the document the
    /// same way. It does not say the document still says that — a reviewer
    /// renumbered a key in PROTOCOL.md and every check here stayed green.
    fn bodies_match_the_spec(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "published bodies match the spec",
            detail,
        };
        let spec = crate::bodies::Bodies::from_spec(&self.root).map_err(|e| fail(e.to_string()))?;
        let ours =
            crate::bodies::Bodies::from_vectors(&self.root).map_err(|e| fail(e.to_string()))?;
        let wrong = ours.disagreements(&spec);
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "a body and its definition have parted company:\n\n{}",
                wrong.join("\n")
            )))
        }
    }

    /// The same question one level down, for the types a message embeds.
    ///
    /// `bodies_match_the_spec` never asked it. A descriptor row is published as a
    /// `row_cbor` blob with no `body_readable`, which that check skips, and its
    /// parser drops a nested type's key list on the floor — so both sides were
    /// blind at once and sixty-one row keys went unread while it printed a pass.
    fn published_rows_match_the_spec(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "published rows match the spec",
            detail,
        };
        let spec = crate::rows::Spec::read(&self.root).map_err(|e| fail(format!("{e:#}")))?;
        let ours = crate::rows::Published::read(&self.root).map_err(|e| fail(format!("{e:#}")))?;
        let wrong = ours.disagreements(&spec);
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "a published row and its definition have parted company:\n\n{}",
                wrong.join("\n")
            )))
        }
    }

    /// protocol.toml and PROTOCOL.md must claim the same protocol version.
    ///
    /// They are the two files a version bump has to touch, and nothing else would
    /// notice if only one of them moved.
    fn registry_version_matches_the_spec(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "registry and spec agree on the version",
            detail,
        };
        let reg = self.registry().map_err(|e| fail(e.to_string()))?;
        let spec = self.spec().map_err(|e| fail(e.to_string()))?;
        // The docs website adds YAML frontmatter before the Markdown title. The
        // version still lives in the first H1, which is what both GitHub and the
        // published page present as the document's title.
        let title = spec
            .lines()
            .find(|line| line.starts_with("# "))
            .unwrap_or_default();
        let want = format!("v{}", reg.meta.protocol);
        if title.contains(&want) {
            Ok(())
        } else {
            Err(fail(format!(
                "protocol.toml says protocol {} but PROTOCOL.md's title is {title:?}",
                reg.meta.protocol
            )))
        }
    }

    /// A message the registry calls retired keeps no section telling somebody how to
    /// send it.
    ///
    /// The two halves of a retirement are the registry entry and the prose, and only
    /// the first one is mechanical. `Snapshot` was marked retired in `protocol.toml`,
    /// deleted from the tree, and went on having a full normative section in
    /// `PROTOCOL.md` — keys, wire tables, five requirements — for several commits
    /// afterwards. Every check passed the whole time, because nothing compared the
    /// registry's opinion to the specification's.
    ///
    /// What that costs is an implementer building a message the controller will
    /// answer with error 1, from the document that is supposed to be authoritative.
    /// The registry is where a retirement is recorded; this is what makes the
    /// document agree with it.
    ///
    /// A heading is the test rather than a mention: prose *about* a retired message
    /// is how a specification explains what happened to a number, and deleting that
    /// would be the opposite of the point.
    fn no_retired_message_keeps_a_normative_section(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "no retired message keeps a normative section",
            detail,
        };
        let reg = self.registry().map_err(|e| fail(e.to_string()))?;
        let spec = self.spec().map_err(|e| fail(e.to_string()))?;

        let mut wrong = Vec::new();
        for message in &reg.messages {
            if message.status != crate::registry::Status::Retired {
                continue;
            }
            // The house form for a message section, as every live one is written:
            // `### Hello — `0x01` / `0x81``. Matching the name after `### ` is what
            // tells a section from a sentence mentioning the message.
            let heading = format!("### {}", message.name);
            if spec.contains(&heading) {
                wrong.push(format!(
                    "`{}` is retired in protocol.toml and `{heading}` is still a section of \
                     PROTOCOL.md. An implementer reads the specification, builds the message, and \
                     gets error 1 from a controller that no longer has it",
                    message.name
                ));
            }
        }

        if wrong.is_empty() {
            Ok(())
        } else {
            Err(fail(wrong.join("\n      ")))
        }
    }

    /// A live enum space must name what is in it.
    ///
    /// `esp` says which set an enum-shaped value is drawn from, and the only thing
    /// that makes that worth carrying is a list of what the set contains. The join
    /// is **by name** — `enum_space` "generator state" against `[[enums.generator_state]]`
    /// — which is two lists that have to agree with nothing making them.
    ///
    /// The failure is quiet and looks like broken hardware. A space allocated live
    /// with no members hands the controller a constant it can put in a descriptor
    /// row and not one value it can ever name, so every reading of that signal is
    /// `validity 8 unnamed_state` and P-164 raises a concern for each one. Somebody
    /// drives out to a cabinet that reads as a rack of failed instruments, and the
    /// cause is a registry entry that was half written.
    ///
    /// Reserved spaces are skipped, and that is the whole point of the status:
    /// `charge stage` and `balancing` are allocated with no members on purpose,
    /// because the design has not settled what is in them. This check is what makes
    /// promoting one to `live` require settling it.
    fn every_live_enum_space_names_its_members(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "every live enum space names its members",
            detail,
        };
        let reg = self.registry().map_err(|e| fail(e.to_string()))?;
        let spaces = reg
            .open_registries
            .get("enum_space")
            .ok_or_else(|| fail("no `[[open_registries.enum_space]]` table at all".to_owned()))?;

        let mut wrong = Vec::new();
        for space in spaces {
            // A row spanning the vendor range allocates no single number and has no
            // status, which is what tells it from an allocation.
            if space.status != Some(crate::registry::Status::Live) {
                continue;
            }
            let table = space.name.replace(' ', "_");
            if !reg.enums.contains_key(&table) {
                wrong.push(format!(
                    "enum space `{}` is live and no `[[enums.{table}]]` names its members. A \
                     descriptor may draw a value from it and nothing can ever name one, so every \
                     reading is validity 8 unnamed_state",
                    space.name
                ));
            }
        }

        if wrong.is_empty() {
            Ok(())
        } else {
            Err(fail(wrong.join("\n      ")))
        }
    }

    /// Every word of the dataset's vocabulary is carried or explained, every live
    /// metric reaches a word or is declared the controller's own, and the pinned
    /// vocabulary is the one the pin names.
    ///
    /// The failure is a support list that lies by omission: a dataset word with
    /// no row reads as "Origin89 cannot read this" when nobody decided, and a live
    /// metric with no row is a reading a consumer cannot name, so it never reaches
    /// the rating that limits it.
    fn dataset_crosswalk_is_sound(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "dataset crosswalk is sound",
            detail,
        };
        let reg = self.registry().map_err(|e| fail(e.to_string()))?;
        let words = reg
            .vocabulary(&self.root)
            .map_err(|e| fail(format!("{e:#}")))?;
        let wrong = crosswalk_findings(&reg, &words);
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(fail(wrong.join("\n      ")))
        }
    }

    /// A number the registry calls live must be one some rule can produce.
    ///
    /// Test vectors cannot catch this: a vector is only computed for a condition
    /// somebody decided to compute, so a code nothing triggers has no vector and its
    /// absence looks exactly like a code that is simply not exercised.
    fn every_live_number_is_reachable(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "every live number is reachable",
            detail,
        };
        let reg = self.registry().map_err(|e| fail(e.to_string()))?;
        let mut docs = self.spec().map_err(|e| fail(e.to_string()))?;
        // REGISTRY.md is deliberately absent: it is generated from the registry, so
        // a number citing its own allocation proves nothing. The wire and the link
        // are where rules live. The controller's design document is not swept
        // either, and on purpose: a number only a behaviour over there produces is
        // a number this specification has not said who emits.
        let link = "docs/protocol/LINK.md";
        docs.push_str(
            &std::fs::read_to_string(self.root.join(link))
                .map_err(|e| fail(format!("reading {link}: {e}")))?,
        );

        let orphans = reg.unreachable(&docs);
        if orphans.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "these are allocated and nothing emits them. Either write the rule that produces \
                 one, or mark it withdrawn — live means a reader can expect to see it:\n\n{}",
                orphans.join("\n")
            )))
        }
    }

    /// A document that gives a number must call it by a name the registry gives it.
    ///
    /// The registry is where a rename happens and the prose is where it does not
    /// follow. `0x0501` was `alarm raised`; the topology design renamed it to
    /// `concern raised` and `protocol.toml` took the new name, while **four MUSTs in
    /// `PROTOCOL.md` went on saying the old one** for several commits with every
    /// gate green. An implementer reads the settled document, builds the record and
    /// sends a kind by a name nothing allocates.
    ///
    /// Stated as *somewhere in the same document*, which is deliberately weak. The
    /// strong version — the name beside each mention — cannot be written without
    /// deciding what counts as beside, and it would fire on `0x0101 DC voltage`,
    /// which is a legitimate mention of a metric kind that is also an event kind.
    /// The weak version has no false positives on this corpus and still goes red the
    /// moment a document knows a number and not its name, which is the whole of the
    /// failure above.
    fn every_number_a_document_names_is_called_by_a_name_it_has(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "every number a document names is called by a name it has",
            detail,
        };
        let reg = self.registry().map_err(|e| fail(e.to_string()))?;
        let names = reg.names_by_number().map_err(|e| fail(e.to_string()))?;

        let mut unnamed = Vec::new();
        for path in ["docs/PROTOCOL.md", "docs/protocol/LINK.md"] {
            let text = std::fs::read_to_string(self.root.join(path))
                .map_err(|e| fail(format!("reading {path}: {e}")))?;
            for (number, allowed) in &names {
                // Both spellings, because a document writes `0x8F` in a table and
                // `0x8f` nowhere, and nothing enforces which.
                let upper = format!("0x{number:04X}");
                let lower = format!("0x{number:04x}");
                if !text.contains(&upper) && !text.contains(&lower) {
                    continue;
                }
                if allowed.iter().any(|name| text.contains(name)) {
                    continue;
                }
                let calls: Vec<&str> = allowed.iter().map(String::as_str).collect();
                unnamed.push(format!(
                    "{path} gives {upper} and never calls it {}",
                    calls.join(" or ")
                ));
            }
        }

        if unnamed.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "a number with no name in the document that uses it is a number somebody \
                 implements from the wrong table:\n\n{}",
                unnamed.join("\n")
            )))
        }
    }

    /// Every direction a message has must say how it is authenticated.
    ///
    /// The registry's column and the rules in the specification once said the same
    /// thing in two vocabularies and agreed only by luck. They cannot disagree now —
    /// the labels are an enum — but a direction with no label at all is still a
    /// message nobody has decided about.
    fn every_message_declares_its_auth(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "every message declares its auth",
            detail,
        };
        let reg = self.registry().map_err(|e| fail(e.to_string()))?;

        let missing: Vec<String> = reg
            .messages
            .iter()
            .flat_map(|m| {
                [
                    (m.request.is_some() && m.auth_request.is_none())
                        .then(|| format!("{} has a request opcode and no auth_request", m.name)),
                    (m.response.is_some() && m.auth_response.is_none())
                        .then(|| format!("{} has a response opcode and no auth_response", m.name)),
                ]
            })
            .flatten()
            .collect();

        if missing.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "a direction with no rule is a message somebody will authenticate by guessing:\n\n{}",
                missing.join("\n")
            )))
        }
    }

    /// No response may carry a field derived from key material.
    ///
    /// An early draft returned the client's long-term key in the pairing response,
    /// over the link, through the one component that must never hold one. The frame
    /// was well formed and a vector for it would have been perfectly reproducible —
    /// which is why this reads the bytes rather than the description.
    fn no_response_carries_key_material(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "no response carries key material",
            detail,
        };
        let text = std::fs::read_to_string(self.root.join("docs/protocol/vectors/v1.json"))
            .map_err(|e| fail(format!("reading v1.json: {e}")))?;
        let doc: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| fail(e.to_string()))?;

        let mut secrets = Vec::new();
        if let Some(keys) = doc
            .get("derived_keys")
            .and_then(serde_json::Value::as_object)
        {
            for (name, k) in keys {
                if let Some(hex) = k.get("out").and_then(serde_json::Value::as_str) {
                    secrets.push((name.clone(), hex.to_owned()));
                }
            }
        }
        if let Some(s) = doc
            .get("inputs")
            .and_then(|i| i.get("printed_secret"))
            .and_then(serde_json::Value::as_str)
        {
            secrets.push(("printed_secret".to_owned(), s.to_owned()));
        }

        let mut leaks = Vec::new();
        if let Some(macs) = doc.get("macs").and_then(serde_json::Value::as_object) {
            for (name, entry) in macs {
                for field in ["full_body_cbor", "inner_body_cbor", "operation_cbor"] {
                    let Some(body) = entry.get(field).and_then(serde_json::Value::as_str) else {
                        continue;
                    };
                    for (secret, hex) in &secrets {
                        if body.contains(hex.as_str()) {
                            leaks.push(format!("{name}.{field} contains {secret}"));
                        }
                    }
                }
            }
        }

        if leaks.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "a key on the wire is a key the comms processor has, for the life of the device:\n\n{}",
                leaks.join("\n")
            )))
        }
    }

    /// The generated bindings must be what the registry produces.
    fn bindings_are_regenerated(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "bindings are regenerated",
            detail,
        };
        let b = crate::bindings::Bindings::load(&self.root).map_err(|e| fail(e.to_string()))?;
        let mut stale = b.stale(&self.root);
        if crate::diagram::Diagram::load(&self.root)
            .map_err(|e| fail(e.to_string()))?
            .stale(&self.root)
        {
            stale.push("docs/protocol/MAP.md".to_owned());
        }
        if crate::codegen::Codegen::load(&self.root)
            .map_err(|e| fail(e.to_string()))?
            .stale(&self.root)
            .map_err(|e| fail(e.to_string()))?
        {
            stale.push(crate::codegen::Codegen::PATH.to_owned());
        }
        if stale.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "run `cargo xtask registry` and commit the result in the same commit as the \
                 registry change:\n\n{}",
                stale.join("\n")
            )))
        }
    }

    /// No crate writes a link-local error code as a literal.
    ///
    /// `LinkErrorCode` is generated from the registry, so a `Refused::code()`
    /// that reads it goes red or stops compiling when a number moves. A
    /// `pub const VERSION_MISMATCH_CODE: u16 = 261` beside it does neither, and
    /// the only thing standing behind that pair was a test asserting they
    /// differed from each other — an agreement between two lines of one file.
    /// Found twice, in `linkup.rs` and `inflight.rs`, the second one so
    /// unattached that no line of code read it at all.
    ///
    /// **It sweeps 257 to 511 and cannot see 256.** That is `wrong side`, and it
    /// is also the size of half the buffers in this workspace, so by value alone
    /// a retyped 256 is indistinguishable from a page. The client codes are 1 to
    /// 14 and collide with every width and count there is, so they are out of
    /// reach the same way. This catches the range where a literal can only be
    /// one thing.
    fn no_link_code_is_written_as_a_literal(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "no link code is written as a literal",
            detail,
        };
        let reg = self.registry().map_err(|e| fail(e.to_string()))?;
        // The link errors' own table, not `names_by_number` — that sweep walks
        // events, metrics and the enum spaces, and `[[link_errors]]` is none of
        // those. Written against it, this check could not fire: every literal
        // came back *nothing the registry allocates*, including the 262 it was
        // written for. It said so only when somebody put the defect back.
        let names: std::collections::BTreeMap<u32, &str> = reg
            .link_errors
            .iter()
            .map(|e| (u32::from(e.code), e.name.as_str()))
            .collect();

        let mut sources = Vec::new();
        collect_rs(&self.root.join("crates"), &mut sources)
            .map_err(|e| fail(format!("walking crates: {e:#}")))?;

        let mut retyped = Vec::new();
        for path in sources {
            if path.ends_with("generated.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|e| fail(format!("reading {}: {e}", path.display())))?;
            for (at, line) in text.lines().enumerate() {
                let Some((declaration, value)) = line.trim().split_once(" = ") else {
                    continue;
                };
                if !declaration.starts_with("const ") && !declaration.starts_with("pub const ") {
                    continue;
                }
                let Ok(number) = value
                    .trim_end_matches(';')
                    .trim()
                    .replace('_', "")
                    .parse::<u32>()
                else {
                    continue;
                };
                if !(257..=511).contains(&number) {
                    continue;
                }
                // Allocated, not merely inside the range. `MAX_SIGNALS` is 384
                // and a couple of test buffers are 300, and none of those is a
                // number the registry has ever handed out.
                let Some(called) = names.get(&number) else {
                    continue;
                };
                retyped.push(format!(
                    "{}:{} declares {number}, which the registry calls {called}",
                    path.display(),
                    at + 1
                ));
            }
        }

        if retyped.is_empty() {
            Ok(())
        } else {
            Err(fail(format!(
                "a wire number typed into a crate is a second copy of something the registry \
                 already generates, and the copy is the one that goes stale. Take it off \
                 `LinkErrorCode` instead — a rename then stops this compiling, which a literal \
                 can never do.\n\n{}",
                retyped.join("\n")
            )))
        }
    }

    /// Every numbered requirement must have something that can fail behind it, or a
    /// written reason why nothing can.
    ///
    /// The count of the ones with neither is recorded in `traceability.toml` and
    /// this refuses to let it rise — and refuses to let it sit above the truth,
    /// because a ratchet nobody tightens rusts open. It is a ratchet rather than a
    /// floor of zero for one reason: on the day it was written the workspace had no
    /// tests at all, and a check that is red on its first run is a check somebody
    /// switches off before its second.
    fn every_requirement_is_cited(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "every requirement is cited",
            detail,
        };
        let t = crate::traceability::Traceability::load(&self.root)
            .map_err(|e| fail(format!("{e:#}")))?;
        println!("{}", t.summary());
        t.verdict().map_err(fail)
    }

    /// P-001 says *every* vector, and four blocks were read by nothing.
    ///
    /// The CRC-16 table, the COBS table and the whole published frame sat in
    /// `v1.json` while `tests/vectors.rs` read four other keys — so a nibble could
    /// move in any of them with the suite green. Publishing a vector and reading it
    /// are separate acts and only one of them was ever checked.
    ///
    /// Coarse on purpose: it asks whether the test file names each block as a
    /// quoted key, not whether it checks it well. A block nobody has typed the name of is certainly
    /// unread; the rest is what review is for.
    fn every_published_vector_is_read(&self) -> Result<(), Failure> {
        const READER: &str = "crates/km43/tests/vectors.rs";
        let fail = |detail: String| Failure {
            check: "every published vector is read",
            detail,
        };
        let vectors = std::fs::read_to_string(self.root.join("docs/protocol/vectors/v1.json"))
            .map_err(|e| fail(e.to_string()))?;
        let reader =
            std::fs::read_to_string(self.root.join(READER)).map_err(|e| fail(e.to_string()))?;

        // A block is read when the test file scans it — names it, or a key inside
        // it, as a quoted string — or when the file argues in prose why it does not
        // need to, which is a backticked mention. `derived_keys` is the second
        // kind: the three derivations are pinned transitively by the seven MAC
        // tags, because a wrong key gives a wrong tag, and that argument is written
        // down where somebody reading the file will meet it.
        //
        // Quoted rather than a bare substring, because a bare one is satisfied by
        // the key turning up inside a test's own name — which is how `qr` looked
        // read while a nibble could move in it untouched.
        let named = |key: &str| {
            reader.contains(&format!("\"{key}\"")) || reader.contains(&format!("`{key}"))
        };
        let mut unread = Vec::new();
        let mut block: Option<(String, bool)> = None;
        for line in vectors.lines() {
            let key = |indent: &str| {
                line.strip_prefix(indent)
                    .filter(|rest| rest.starts_with('"'))
                    .and_then(|rest| rest.get(1..)?.split('"').next())
                    .map(str::to_owned)
            };
            if let Some(top) = key("  ") {
                if let Some((name, seen)) = block.take()
                    && !seen
                {
                    unread.push(name);
                }
                // Prose about the file rather than a vector in it.
                if !matches!(top.as_str(), "note" | "conventions") {
                    let seen = named(&top);
                    block = Some((top, seen));
                }
            } else if let Some((_, seen)) = block.as_mut()
                && let Some(inner) = key("    ").or_else(|| key("      "))
            {
                *seen = *seen || named(&inner);
            }
        }
        if let Some((name, false)) = block {
            unread.push(name);
        }

        if unread.is_empty() {
            return Ok(());
        }
        Err(fail(format!(
            "these blocks are published in v1.json and {READER} names nothing in them, so a byte \
             could move anywhere inside them with the suite green:\n{}\n\nP-001 is *every* vector.",
            unread.join("\n")
        )))
    }

    /// A doc test inside a `#[cfg(test)]` module is never collected.
    ///
    /// `rustdoc` strips those modules before it looks for code fences, so the block
    /// is not compiled, not run, and not capable of failing — it is a check that
    /// reads as one and has never been anything. Two `compile_fail` blocks lived
    /// like that in this crate, and one of them was the signature that keeps an
    /// unauthenticated refusal from being laundered into an authenticated one.
    ///
    /// The fix is always the same: move the block onto the public item it is about,
    /// where the prose usually already makes the claim.
    fn no_doc_test_is_hidden_in_a_test_module(&self) -> Result<(), Failure> {
        let fail = |detail: String| Failure {
            check: "no doc test is hidden in a test module",
            detail,
        };
        let mut hidden = Vec::new();
        let mut files = Vec::new();
        collect_rs(&self.root, &mut files).map_err(|e| fail(format!("{e:#}")))?;
        files.sort();
        for path in files {
            let text = std::fs::read_to_string(&path).map_err(|e| fail(e.to_string()))?;
            let shown = path
                .strip_prefix(&self.root)
                .unwrap_or(&path)
                .display()
                .to_string();
            for (at, line) in fenced_doc_lines(&text) {
                if in_a_test_module(&text, at) {
                    hidden.push(format!("{shown}:{line}"));
                }
            }
        }
        if hidden.is_empty() {
            return Ok(());
        }
        Err(fail(format!(
            "these doc tests are inside `#[cfg(test)]`, so rustdoc never collects them \
             and they have never run:\n{}\n\nMove each block onto the public item it is \
             about. `cargo test -p <crate> --doc -- --list` is what counts them.",
            hidden.join("\n")
        )))
    }

    /// Everything declared `no_std` must compile for both parts.
    ///
    /// **The claim this repo makes is that the host and the target cannot disagree**
    /// — no allocator on either, so a fixture cannot be built from something the
    /// firmware does not have. Nothing checked it. `cargo test` and `cargo clippy`
    /// both build for the host, where `std` is present, `usize` is 64 bits and
    /// every enum is laid out differently.
    ///
    /// It has already cost one build. `handshake.rs` asserted the size of an error
    /// type against a literal measured on this laptop; on the target the number is
    /// smaller, and the whole firmware failed to compile on a constant the gate had
    /// been green about for as long as it existed.
    ///
    /// Two targets, because two parts speak this protocol: the controller's
    /// Cortex-M0+ and the comms processor's RISC-V. The second was installed by
    /// `rust-toolchain.toml` and, until this loop, built by nothing.
    ///
    /// The crate list is **read from the tree**, not written down here: a list of
    /// names is checked against nothing, so a new `no_std` crate would be added,
    /// never cross-compiled, and look covered. Only the libraries are built —
    /// `#[cfg(test)]` code needs `std` and never ships.
    fn every_no_std_crate_builds_for_the_target(&self) -> Result<(), Failure> {
        const CHECK: &str = "every no_std crate builds for the target";
        const TARGETS: [&str; 2] = ["thumbv6m-none-eabi", "riscv32imac-unknown-none-elf"];
        // Twice per target: once as a consumer that asked for nothing, once
        // with every feature on. The features exist for the target and nowhere
        // else — `defmt` is a logger for a part with no console — so a host
        // build with them on says nothing about the derive that matters.
        const FEATURE_SETS: [&[&str]; 2] = [&[], &["--all-features"]];
        let fail = |detail: String| Failure {
            check: CHECK,
            detail,
        };

        let mut crates = Vec::new();
        let dir = self.root.join("crates");
        let entries =
            std::fs::read_dir(&dir).map_err(|e| fail(format!("reading {}: {e}", dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| fail(format!("reading {}: {e}", dir.display())))?;
            let lib = entry.path().join("src/lib.rs");
            let Ok(text) = std::fs::read_to_string(&lib) else {
                continue;
            };
            if text.lines().any(|line| line.trim() == "#![no_std]") {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                crates.push(name);
            }
        }
        crates.sort();
        if crates.is_empty() {
            return Err(fail(
                "no crate in crates/ declares #![no_std], which cannot be right — this repo's \
                 whole argument is that its logic runs on a Cortex-M0+ with no allocator."
                    .to_owned(),
            ));
        }

        for target in TARGETS {
            for features in FEATURE_SETS {
                let mut cargo =
                    Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()));
                cargo
                    .current_dir(&self.root)
                    .args(["check", "--locked", "--target", target])
                    .args(features);
                for name in &crates {
                    cargo.args(["-p", name]);
                }
                let out = cargo.output().map_err(|e| {
                    fail(format!(
                        "running cargo check --target {target} {}: {e}",
                        features.join(" ")
                    ))
                })?;
                if !out.status.success() {
                    let why = String::from_utf8_lossy(&out.stderr);
                    return Err(fail(format!(
                        "the no_std crates ({}) do not all build for {target} with `{}`. A \
                         green host build says nothing about this: there `std` is present, \
                         `usize` is 64 bits and the enum layouts differ. If the target is not \
                         installed, `rustup target add {target}`.\n\n{}",
                        crates.join(", "),
                        features.join(" "),
                        why.trim()
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Byte offset and 1-based line of every doc code fence that opens a block.
fn fenced_doc_lines(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut open = false;
    for (n, line) in text.lines().enumerate() {
        let doc = line
            .trim_start()
            .strip_prefix("///")
            .or_else(|| line.trim_start().strip_prefix("//!"));
        if let Some(rest) = doc
            && rest.trim_start().starts_with("```")
        {
            if !open {
                out.push((at, n.saturating_add(1)));
            }
            open = !open;
        }
        at = at.saturating_add(line.len()).saturating_add(1);
    }
    out
}

/// Whether `at` falls inside a module the compiler only builds under `cfg(test)`.
///
/// Brace-counted from each `#[cfg(test)]` rather than matched by indentation,
/// because a nested module is exactly the case an indentation rule gets wrong.
fn in_a_test_module(text: &str, at: usize) -> bool {
    for (start, _) in text.match_indices("#[cfg(test)]") {
        if start >= at {
            break;
        }
        let Some(rest) = text.get(start..) else {
            continue;
        };
        let Some(open) = rest.find('{') else { continue };
        let mut depth = 0usize;
        for (i, c) in rest.char_indices().skip(open) {
            match c {
                '{' => depth = depth.saturating_add(1),
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        if at > start && at < start.saturating_add(i) {
                            return true;
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

/// Every `.rs` file in the tree.
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    const SKIP: [&str; 4] = ["target", ".git", "node_modules", ".claude"];
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();
        if SKIP.contains(&name) {
            continue;
        }
        if path.is_dir() {
            collect_rs(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

pub fn repo_root() -> Result<PathBuf> {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("running git rev-parse")?;
    if !out.status.success() {
        bail!("not inside a git repository");
    }
    Ok(PathBuf::from(String::from_utf8(out.stdout)?.trim()))
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("      {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every relative link a document or a doc comment makes must resolve.
///
/// **A file that says something about the tree, and is wrong, is worse than a
/// file that says nothing.** Somebody follows the pointer, finds nothing, and
/// concludes the thing is not tracked rather than that the note went stale.
///
/// This was written after `firmwares/o89-stm32/src/main.rs` spent six commits
/// claiming that "README.md carries what each addition costs" against a README
/// that did not exist. Nothing caught it, because nothing had ever read a link
/// and asked whether it landed.
///
/// Only relative targets are checked. An `http` link is somebody else's uptime,
/// and an anchor without a path is a heading this cannot resolve without
/// parsing markdown — both are skipped rather than guessed at.
fn every_link_lands(root: &Path) -> Result<(), String> {
    let mut broken = Vec::new();
    for file in walk(root)? {
        // Not text. A binary fixture is not making a claim about anything.
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let from = file.parent().unwrap_or(root);
        let rust = file.extension().and_then(|e| e.to_str()) == Some("rs");
        for target in links(&text, rust) {
            if !from.join(&target).exists() {
                let shown = file.strip_prefix(root).unwrap_or(&file);
                broken.push(format!("{} -> {target}", shown.display()));
            }
        }
    }
    if broken.is_empty() {
        return Ok(());
    }
    broken.sort();
    broken.dedup();
    Err(format!(
        "{} link(s) point at something that is not there. A pointer that does \
         not land reads as *this is not tracked* rather than as *this note is \
         stale*, which is how a stale claim survives being read:\n  {}",
        broken.len(),
        broken.join("\n  ")
    ))
}

/// The relative paths a file points at.
///
/// In Rust only `///` and `//!` lines are read, because those are the claims. A
/// path inside a string literal is code doing its job, and reading those was the
/// first version of this check reporting a format specifier as a broken link.
///
/// Skipped: anything absolute, which in this tree is a published site URL rather
/// than a file; anything with `::`, which is an intra-doc link to a Rust item;
/// and anything with whitespace or braces, which is not a path.
fn links(text: &str, rust: bool) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        if rust && !(line.starts_with("///") || line.starts_with("//!")) {
            continue;
        }
        for part in line.split("](").skip(1) {
            let Some((target, _)) = part.split_once(')') else {
                continue;
            };
            let target = target.split('#').next().unwrap_or(target);
            if target.is_empty()
                || target.starts_with('/')
                || target.starts_with("http")
                || target.starts_with("mailto:")
                || target.contains("::")
                || target.contains(char::is_whitespace)
                || target.contains('{')
                || target.contains('"')
            {
                continue;
            }
            found.push(target.to_owned());
        }
    }
    found
}

/// Every `.md` and `.rs` under the tree, skipping what is not ours.
fn walk(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if matches!(path.extension().and_then(|e| e.to_str()), Some("md" | "rs")) {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// **P-012** — a retired number is never reused.
///
/// The rule's second sentence is what makes the first checkable: retired
/// numbers *stay recorded*, so reusing one shows up as the same number
/// allocated twice in one space. That is what this looks for, in every space the
/// registry numbers.
///
/// The failure it prevents does not announce itself. Two implementations built
/// a year apart both read the registry, disagree about what one number means,
/// and every frame carrying it decodes cleanly into the wrong thing — a metric
/// read as another metric, an outcome acted on as a different outcome. There is
/// no MAC failure and no decode error, because nothing is malformed.
/// What is wrong with the crosswalk against the dataset's words, as sentences.
///
/// Empty means sound. Kept apart from the check so a test can hand it a
/// registry with one row removed and read the sentence it produces.
pub fn crosswalk_findings(registry: &crate::registry::Registry, words: &[String]) -> Vec<String> {
    use crate::registry::Status;
    use std::collections::BTreeSet;

    let mut wrong = Vec::new();
    let known: BTreeSet<&str> = words.iter().map(String::as_str).collect();
    let crosswalk = &registry.crosswalk;

    let mut named: BTreeSet<&str> = BTreeSet::new();
    for c in &crosswalk.carried {
        named.insert(&c.name);
        if !known.contains(c.name.as_str()) {
            wrong.push(format!(
                "`{}` is carried as a dataset word and the pinned vocabulary has no such word",
                c.name
            ));
        }
    }
    for (name, _) in &crosswalk.absent {
        if crosswalk.carried.iter().any(|c| &c.name == name) {
            wrong.push(format!("`{name}` is listed as absent and also carried"));
        }
        named.insert(name);
        if !known.contains(name.as_str()) {
            wrong.push(format!(
                "`{name}` is listed as absent and the pinned vocabulary has no such word"
            ));
        }
    }
    for word in words {
        if !named.contains(word.as_str()) {
            wrong.push(format!(
                "dataset word `{word}` has no row: carry it, or say why the protocol cannot"
            ));
        }
    }

    let internal: BTreeSet<&str> = registry
        .dataset
        .as_ref()
        .map(|d| d.internal.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let carried: BTreeSet<u16> = crosswalk.carried.iter().map(|c| c.kind).collect();
    for m in registry.metrics.iter().filter(|m| m.status == Status::Live) {
        match (
            carried.contains(&m.kind),
            internal.contains(m.name.as_str()),
        ) {
            (false, false) => wrong.push(format!(
                "live metric `{}` ({:#06x}) reaches no dataset word and is not declared internal",
                m.name, m.kind
            )),
            (true, true) => wrong.push(format!(
                "`{}` is declared internal and also carried as a dataset word",
                m.name
            )),
            (true, false) | (false, true) => {}
        }
    }
    for name in &internal {
        if !registry
            .metrics
            .iter()
            .any(|m| m.name == *name && m.status == Status::Live)
        {
            wrong.push(format!(
                "dataset.internal names `{name}`, which is not a live metric; a declaration \
                 outlives the metric it excuses"
            ));
        }
    }
    wrong
}

pub fn no_number_is_allocated_twice(registry: &crate::registry::Registry) -> Result<(), String> {
    let mut clashes = Vec::new();

    let mut check = |space: &str, numbers: Vec<(u64, String)>| {
        let mut seen: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
        for (number, name) in numbers {
            if let Some(first) = seen.get(&number) {
                clashes.push(format!("{space} {number:#x}: {first} and {name}"));
            } else {
                seen.insert(number, name);
            }
        }
    };

    check(
        "error",
        registry
            .errors
            .iter()
            .map(|e| (u64::from(e.code), e.meaning.clone()))
            .collect(),
    );
    check(
        "metric",
        registry
            .metrics
            .iter()
            .map(|m| (u64::from(m.kind), m.name.clone()))
            .collect(),
    );
    check(
        "event",
        registry
            .events
            .iter()
            .map(|e| (u64::from(e.kind), e.name.clone()))
            .collect(),
    );
    for (space, outcomes) in &registry.outcomes {
        check(
            space,
            outcomes
                .iter()
                .map(|o| (u64::from(o.value), o.name.clone()))
                .collect(),
        );
    }
    for (space, outcomes) in &registry.enums {
        check(
            space,
            outcomes
                .iter()
                .map(|o| (u64::from(o.value), o.name.clone()))
                .collect(),
        );
    }
    for (space, codes) in &registry.codes {
        // A row naming a `range` rather than a number is a span reserved for
        // somebody else, and two of those overlapping is a different rule.
        check(
            space,
            codes
                .iter()
                .filter_map(|c| c.number.map(|n| (u64::from(n), c.name.clone())))
                .collect(),
        );
    }

    // Opcodes live in one space across every message, request and response
    // alike: an opcode is a byte on the wire before anything knows which
    // direction it was going.
    let mut opcodes = Vec::new();
    for message in &registry.messages {
        if let Some(op) = message.request {
            opcodes.push((u64::from(op.0), format!("{} request", message.name)));
        }
        if let Some(op) = message.response {
            opcodes.push((u64::from(op.0), format!("{} response", message.name)));
        }
    }
    check("opcode", opcodes);

    if clashes.is_empty() {
        return Ok(());
    }
    clashes.sort();
    Err(format!(
        "{} number(s) allocated twice. A retired number that comes back means \
         two implementations decode the same frame into different things, with \
         no MAC failure and no decode error to show for it:\n  {}",
        clashes.len(),
        clashes.join("\n  ")
    ))
}

#[cfg(test)]
mod crosswalk {
    use super::{crosswalk_findings, repo_root};
    use crate::registry::Registry;

    fn loaded() -> (Registry, Vec<String>) {
        let root = repo_root().expect("a repo to read the registry from");
        let reg = Registry::load(&root).expect("the registry parses");
        let words = reg.vocabulary(&root).expect("the pinned vocabulary reads");
        (reg, words)
    }

    #[test]
    fn the_registry_as_committed_is_sound() {
        let (reg, words) = loaded();
        assert_eq!(crosswalk_findings(&reg, &words), Vec::<String>::new());
    }

    /// The failure this exists for: a word nobody decided about reads, in a
    /// support list, as "Origin89 cannot read this".
    #[test]
    fn a_dataset_word_no_row_accounts_for_is_named() {
        let (mut reg, words) = loaded();
        reg.crosswalk.carried.retain(|c| c.name != "tank-level");
        let said = crosswalk_findings(&reg, &words).join("\n");
        assert!(said.contains("`tank-level` has no row"), "{said}");
    }

    #[test]
    fn a_word_outside_the_pinned_vocabulary_is_refused() {
        let (mut reg, words) = loaded();
        // A row the registry already resolved, renamed: the fixture holds no wire
        // number of its own.
        let mut renamed = reg
            .crosswalk
            .carried
            .first()
            .cloned()
            .expect("a carried row");
        renamed.name = "cabin-mood".to_owned();
        reg.crosswalk.carried.push(renamed);
        let said = crosswalk_findings(&reg, &words).join("\n");
        assert!(
            said.contains("`cabin-mood` is carried") && said.contains("no such word"),
            "{said}"
        );
    }

    /// A metric retired after it was declared internal: the declaration is stale
    /// and must say so rather than keep the check green.
    #[test]
    fn a_retired_metric_cannot_stay_declared_internal() {
        let (mut reg, words) = loaded();
        let gone = reg
            .metrics
            .iter_mut()
            .find(|m| m.name == "log ring utilisation")
            .expect("the log ring metric");
        gone.status = crate::registry::Status::Retired;
        let said = crosswalk_findings(&reg, &words).join("\n");
        assert!(said.contains("not a live metric"), "{said}");
    }

    #[test]
    fn a_live_metric_with_no_word_must_be_declared_internal() {
        let (mut reg, words) = loaded();
        let dataset = reg.dataset.as_mut().expect("a pin");
        dataset.internal.retain(|m| m != "log ring utilisation");
        let said = crosswalk_findings(&reg, &words).join("\n");
        assert!(
            said.contains("`log ring utilisation`") && said.contains("not declared internal"),
            "{said}"
        );

        let (mut reg, words) = loaded();
        reg.dataset
            .as_mut()
            .expect("a pin")
            .internal
            .push("uptime since boot".to_owned());
        let said = crosswalk_findings(&reg, &words).join("\n");
        assert!(
            said.contains("declared internal and also carried"),
            "{said}"
        );
    }
}
