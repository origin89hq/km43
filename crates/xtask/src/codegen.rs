//! Renders the tables in `REGISTRY.md` from `protocol.toml`.
//!
//! Only the tables. The prose around them is written by hand and stays in the
//! markdown, because a data file carrying kilobytes of documentation is a
//! document with an awkward syntax.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::path::Path;

use crate::registry::{Auth, Code, Outcome, Registry, Status};

/// One table, and the heading it lives under.
struct Section {
    heading: String,
    table: String,
}

impl Section {
    /// Swaps the run of `|` lines that follows the heading, leaving the writing
    /// around it alone.
    fn splice(&self, doc: &str) -> Result<String> {
        let at = doc
            .find(&self.heading)
            .with_context(|| format!("REGISTRY.md has no {:?} section", self.heading))?;
        let section = doc
            .get(at..)
            .context("section is not on a character boundary")?;
        let (before_table, table) = section
            .split_once("\n|")
            .with_context(|| format!("{:?} has no table", self.heading))?;
        let suffix = table.split_once("\n\n").map(|(_, rest)| rest);
        let prefix = doc
            .get(..at)
            .context("section is not on a character boundary")?;
        Ok(format!(
            "{prefix}{before_table}\n{}{}{}",
            self.table.trim_end(),
            if suffix.is_some() { "\n\n" } else { "" },
            suffix.unwrap_or("")
        ))
    }
}

pub struct Codegen {
    registry: Registry,
}

impl Codegen {
    pub fn load(root: &Path) -> Result<Self> {
        Ok(Self {
            registry: Registry::load(root)?,
        })
    }

    pub const PATH: &'static str = "docs/protocol/REGISTRY.md";

    pub fn write(&self, root: &Path) -> Result<()> {
        let (current, next) = self.rendered(root)?;
        if next == current {
            println!("REGISTRY.md already matches protocol.toml");
            return Ok(());
        }
        std::fs::write(root.join(Self::PATH), next)?;
        println!("wrote {}", root.join(Self::PATH).display());
        Ok(())
    }

    /// Whether the tables on disk still say what the registry says.
    ///
    /// Nothing checked this, and the tables are where a reader looks a number up:
    /// `5 panic` could be hand-edited to `6 panic` and the whole gate stayed
    /// green, because only the two generated source files and MAP.md were
    /// compared. The registry's own document was the one artefact allowed to
    /// disagree with the registry.
    pub fn stale(&self, root: &Path) -> Result<bool> {
        let (current, next) = self.rendered(root)?;
        Ok(current != next)
    }

    /// The document as it is, and as the registry says it should read.
    fn rendered(&self, root: &Path) -> Result<(String, String)> {
        let current = std::fs::read_to_string(root.join(Self::PATH))?;

        let sections = self.sections();
        let unclaimed = Self::unclaimed(&current, &sections);
        if !unclaimed.is_empty() {
            anyhow::bail!(
                "REGISTRY.md has tables no section generates: {}\n\
                 A hand-kept table is silent forever — allocate it in {} instead.",
                unclaimed.join(", "),
                Registry::PATH
            );
        }

        let mut next = current.clone();
        for section in &sections {
            next = section.splice(&next)?;
        }
        Ok((current, next))
    }

    /// Headings in the document that carry a table but that nothing generates.
    ///
    /// The tooling was asymmetric in the unsafe direction: a section whose data
    /// disappears fails loudly at `splice`, and a table nobody ever claimed sat
    /// there being hand-edited with no way to notice. That is how the client
    /// capability mask — the newest authorisation material in the protocol —
    /// stayed outside the file every other number lives in.
    fn unclaimed(doc: &str, sections: &[Section]) -> Vec<String> {
        let mut out = Vec::new();
        let mut lines = doc.lines().peekable();
        while let Some(line) = lines.next() {
            if !line.starts_with("## ") && !line.starts_with("### ") {
                continue;
            }
            // A heading owns the table that follows it before the next heading.
            let has_table = lines
                .clone()
                .take_while(|l| !l.starts_with("## ") && !l.starts_with("### "))
                .any(|l| l.starts_with('|'));
            // Prefix, not equality: a heading carries its width — `## Quality —
            // u8` — and `splice` finds its section the same way.
            if has_table && !sections.iter().any(|s| line.starts_with(&s.heading)) {
                out.push(line.to_owned());
            }
        }
        out
    }

    fn sections(&self) -> Vec<Section> {
        let mut ble = String::from("| Name | Value |\n|---|---|\n");
        for (name, uuid, _) in self.registry.ble.uuids() {
            let _ = writeln!(ble, "| `{name}` | `{uuid}` |");
        }
        for (name, value, _) in self.registry.ble.flags() {
            let _ = writeln!(ble, "| `{name}` | `{value:#04x}` |");
        }
        for limit in self.registry.transport_limits() {
            let _ = writeln!(ble, "| `{}` | `{}` |", limit.name, limit.value);
        }
        let ws = &self.registry.websocket;
        let (port_name, port, _) = ws.port();
        let mut websocket = format!("| Name | Value |\n|---|---|\n| `{port_name}` | `{port}` |\n");
        for (name, text, _) in ws.texts() {
            let _ = writeln!(websocket, "| `{name}` | `{text}` |");
        }
        let mut out = vec![
            Section {
                heading: "## BLE GATT identifiers".to_owned(),
                table: ble,
            },
            Section {
                heading: "## WebSocket discovery".to_owned(),
                table: websocket,
            },
            Section {
                heading: "## Message types".to_owned(),
                table: self.messages(),
            },
            Section {
                heading: "## Error codes".to_owned(),
                table: self.errors(),
            },
        ];
        for (key, o) in &self.registry.outcomes {
            out.push(Section {
                heading: heading_for(key),
                table: Self::outcomes(o),
            });
        }
        for (key, o) in &self.registry.enums {
            out.push(Section {
                heading: heading_for(key),
                table: Self::outcomes(o),
            });
        }
        for (key, c) in &self.registry.codes {
            out.push(Section {
                heading: heading_for(key),
                table: Self::codes(c, Self::first_column(key)),
            });
        }
        for (key, c) in &self.registry.open_registries {
            out.push(Section {
                heading: heading_for(key),
                table: Self::codes(c, Self::first_column(key)),
            });
        }
        let mut seen = Vec::new();
        for m in &self.registry.metrics {
            if seen.contains(&&m.group) {
                continue;
            }
            seen.push(&m.group);
            out.push(Section {
                heading: format!("### {}", m.group),
                table: self.metrics(&m.group),
            });
        }
        out.push(Section {
            heading: "## Event kinds".to_owned(),
            table: self.events(),
        });
        out.push(Section {
            heading: "## Link-local error codes".to_owned(),
            table: self.link_errors(),
        });
        out.push(Section {
            heading: "## Client capability mask".to_owned(),
            table: self.client_capability(),
        });
        out.push(Section {
            heading: "## Dataset metrics".to_owned(),
            table: self.dataset_metrics(),
        });
        out
    }

    /// The crosswalk as a reader looks it up: by the dataset's word, with the
    /// place spelled out and *any* where a row leaves it open.
    fn dataset_metrics(&self) -> String {
        let named = |space: &str, number: Option<u16>| -> String {
            number.map_or_else(
                || "any".to_owned(),
                |n| {
                    self.registry
                        .open_registries
                        .get(space)
                        .and_then(|rows| rows.iter().find(|r| r.number == Some(n)))
                        .map_or_else(|| format!("`0x{n:04X}`"), |r| r.name.clone())
                },
            )
        };
        let domain = |value: u8| -> String {
            self.registry
                .enums
                .get("signal_domain")
                .and_then(|rows| rows.iter().find(|r| r.value == value))
                .map_or_else(|| value.to_string(), |r| r.name.clone())
        };
        let mut t = String::from(
            "| Dataset word | Kind | Role | Point | Domain |\n|---|---|---|---|---|\n",
        );
        for c in &self.registry.crosswalk.carried {
            let kind = self
                .registry
                .metrics
                .iter()
                .find(|m| m.kind == c.kind)
                .map_or_else(String::new, |m| m.name.clone());
            let _ = writeln!(
                t,
                "| `{}` | `0x{:04X}` {kind} | {} | {} | {} |",
                cell(&c.name),
                c.kind,
                named("component_role", c.role),
                named("measurement_point", c.point),
                domain(c.domain)
            );
        }
        for (name, why) in &self.registry.crosswalk.absent {
            let _ = writeln!(
                t,
                "| `{}` | *not carried: {}* | — | — | — |",
                cell(name),
                cell(why)
            );
        }
        t
    }

    fn link_errors(&self) -> String {
        let mut t = String::from("| Code | Meaning | Reaches a client? |\n|---|---|---|\n");
        for e in &self.registry.link_errors {
            let reaches = if e.reaches_client { "**yes**" } else { "no" };
            let _ = writeln!(t, "| {} | {} | {reaches} |", e.code, e.meaning);
        }
        t
    }

    /// One column per role, in the order the registry allocates them, so
    /// adding a role cannot leave a column nobody filled in.
    fn client_capability(&self) -> String {
        let kinds: Vec<&str> = self
            .registry
            .enums
            .get("role")
            .map(|k| k.iter().map(|e| e.name.as_str()).collect())
            .unwrap_or_default();

        let mut t = String::from("| Bit | The client may");
        for k in &kinds {
            let _ = write!(t, " | {k}");
        }
        t.push_str(" |\n|---|---");
        for _ in &kinds {
            t.push_str("|---");
        }
        t.push_str("|\n");

        for c in &self.registry.client_capability {
            let cell = c
                .bit
                .map_or_else(|| c.range.clone().unwrap_or_default(), |b| b.to_string());
            let _ = write!(t, "| {cell} | {}", c.may);
            for k in &kinds {
                let cell = if c.bit.is_none() {
                    "—"
                } else if c.granted_to.iter().any(|g| g == k) {
                    "yes"
                } else {
                    "**no**"
                };
                let _ = write!(t, " | {cell}");
            }
            t.push_str(" |\n");
        }
        t
    }

    fn metrics(&self, group: &str) -> String {
        let mut t =
            String::from("| Kind | Name | Unit | Scale | Status |\n|---|---|---|---|---|\n");
        for e in self.registry.metrics.iter().filter(|m| m.group == group) {
            let scale = if e.scale < 0 {
                format!("−{}", -e.scale)
            } else {
                e.scale.to_string()
            };
            let _ = writeln!(
                t,
                "| `0x{:04X}` | {} | {} | {scale} | {} |",
                e.kind, e.name, e.unit, e.status
            );
        }
        t
    }

    fn events(&self) -> String {
        let mut t = String::from("| Kind | Name | Class | Status |\n|---|---|---|---|\n");
        for e in &self.registry.events {
            let _ = writeln!(
                t,
                "| `0x{:04X}` | {} | {} | {} |",
                e.kind, e.name, e.class, e.status
            );
        }
        t
    }

    /// The first two column headings a space uses.
    fn first_column(key: &str) -> (&'static str, &'static str) {
        match key {
            "capability_bit" => ("Bit", "Meaning"),
            "config_section" => ("Section", "Name"),
            "behaviour_key" => ("Key", "Name"),
            _ => ("Kind", "Name"),
        }
    }

    fn codes(space: &[Code], (first, second): (&str, &str)) -> String {
        let mut t = format!("| {first} | {second} | Status |\n|---|---|---|\n");
        for e in space {
            let cell = e.number.map_or_else(
                || e.range.clone().unwrap_or_default(),
                |n| {
                    if first == "Bit" || first == "Key" {
                        n.to_string()
                    } else {
                        format!("`0x{n:04X}`")
                    }
                },
            );
            let status = e.status.map_or_else(|| "—".to_owned(), |s| s.to_string());
            let _ = writeln!(t, "| {cell} | {} | {status} |", e.name);
        }
        t
    }

    /// Rows are sorted by opcode, so the table cannot drift out of order the way
    /// a hand-maintained one does.
    fn messages(&self) -> String {
        let mut rows: Vec<(u16, String)> = self
            .registry
            .messages
            .iter()
            .map(|e| {
                (
                    e.sort_key(),
                    format!(
                        "| {} | {} | {} | {} | {} | {} | {} |",
                        e.request_cell(),
                        e.response_cell(),
                        e.name,
                        auth(e.auth_request),
                        auth(e.auth_response),
                        e.since,
                        e.status
                    ),
                )
            })
            .collect();
        rows.extend(self.registry.message_ranges.iter().map(|r| {
            (
                r.request_lo.0,
                format!(
                    "| {} | {} | *{}, see [{}]({})* | — | — | {} | live |",
                    r.request_cell(),
                    r.response_cell(),
                    r.name,
                    r.see,
                    r.see,
                    r.since
                ),
            )
        }));
        rows.sort_by_key(|(k, _)| *k);

        let mut t = String::from(
            "| Request | Response | Name | Auth (request) | Auth (response) | Since | Status |\n\
             |---|---|---|---|---|---|---|\n",
        );
        for (_, r) in rows {
            t.push_str(&r);
            t.push('\n');
        }
        t
    }

    fn errors(&self) -> String {
        let mut t = String::from("| Code | Meaning | Sealed? | Status |\n|---|---|---|---|\n");
        for c in &self.registry.errors {
            let sealed = if c.sealed { "yes" } else { "no" };
            let _ = writeln!(
                t,
                "| {} | {} | {sealed} | {} |",
                c.code, c.meaning, c.status
            );
        }
        for r in &self.registry.error_ranges {
            let _ = writeln!(
                t,
                "| {}–{} | *{}, see [{}]({})* | no | live |",
                r.lo, r.hi, r.name, r.see, r.see
            );
        }
        t
    }

    /// The third column is whichever the space actually uses: a meaning where
    /// the values need explaining, a status where they are not all live yet,
    /// neither where the names speak for themselves.
    fn outcomes(o: &[Outcome]) -> String {
        let meaning = o.iter().any(|e| e.meaning.is_some());
        let status = o.iter().any(|e| e.status != Status::Live);

        let mut t = String::from("| Value | Name");
        if meaning {
            t.push_str(" | Meaning");
        }
        if status {
            t.push_str(" | Status");
        }
        t.push_str(" |\n|---|---");
        if meaning {
            t.push_str("|---");
        }
        if status {
            t.push_str("|---");
        }
        t.push_str("|\n");

        for e in o {
            let _ = write!(t, "| {} | {}", e.value, e.name);
            if meaning {
                let _ = write!(t, " | {}", e.meaning.as_deref().unwrap_or(""));
            }
            if status {
                let _ = write!(t, " | {}", e.status);
            }
            t.push_str(" |\n");
        }
        t
    }
}

/// Text as one Markdown table cell: a pipe would end the cell and a newline the
/// row, and a reason is free text somebody wrote in `protocol.toml`.
fn cell(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
}

/// The REGISTRY.md heading a space's generated table is spliced under.
///
/// An unrecognised space names itself in what it returns, so the splice fails with the
/// space in the message rather than with a fallback string every unnamed space shares.
/// The failure is the right one either way — a generated table with nowhere to go must
/// not be dropped — but "no section for `component_role`" is a sentence somebody can act
/// on, and "no section for unknown outcome space" is one they have to bisect for.
pub fn heading_for(key: &str) -> String {
    let known = match key {
        "command" => "## Command outcomes",
        "set_config" => "## SetConfig outcomes",
        "pair" => "## Pair outcomes",
        "time" => "## Time outcomes",
        "firmware" => "## Firmware outcomes",
        "quality" => "## Quality",
        "generator_state" => "## Generator states",
        "generator_selector" => "## Generator selector",
        "boot_reason" => "## Boot reasons",
        "time_source" => "## Time sources",
        "client_kind" => "## Client kinds",
        "role" => "## Roles",
        "invite_decision" => "## Invite decisions",
        "invite" => "## Invite outcomes",
        "approve" => "## Approve outcomes",
        "remove" => "## Remove outcomes",
        "suite" => "## Suites",
        "config_section" => "## Config sections",
        "behaviour_key" => "## Behaviour section keys",
        "command_kind" => "## Command kinds",
        "capability_bit" => "## Capability bits",
        "inventory" => "## Inventory outcomes",
        "readings" => "## Readings outcomes",
        "concerns" => "## Concerns outcomes",
        "history" => "## History outcomes",
        "transport" => "## Bus transports",
        "shape" => "## Signal shapes",
        "vtype" => "## Value types",
        "signal_domain" => "## Signal domains",
        "direction" => "## Sign conventions",
        "validity" => "## Validity",
        "provenance" => "## Provenance",
        "severity" => "## Concern severities",
        "concern_state" => "## Concern states",
        "presence" => "## Device presence",
        "unit" => "## Units",
        "bucket" => "## History buckets",
        "history_source" => "## History sources",
        "history_stop_reason" => "## History stop reasons",
        "topology_change_reason" => "## Topology change reasons",
        "inventory_kind" => "## Inventory row kinds",
        "control_owner" => "## Control owners",
        "component_role" => "## Component roles",
        "device_role" => "## Device roles",
        "product" => "## Products",
        "dialect" => "## Driver dialects",
        "condition" => "## Conditions",
        "enum_space" => "## Enum spaces",
        "measurement_point" => "## Measurement points",
        "vendor_namespace" => "## Vendor namespaces",
        "scan_state" => "## Scan states",
        "scan_refusal" => "## Scan refusals",
        "wifi_security" => "## Wi-Fi security",
        "wifi_band" => "## Wi-Fi bands",
        "wifi_state" => "## Wi-Fi states",
        "wifi_failure" => "## Wi-Fi failures",
        _ => return format!("## no heading is allocated for the `{key}` space"),
    };
    known.to_owned()
}

fn auth(a: Option<Auth>) -> String {
    a.map_or_else(|| "—".to_owned(), |a| format!("`{a}`"))
}

#[cfg(test)]
mod tests {
    use super::Section;

    #[test]
    fn splicing_preserves_utf8_prose_around_the_table() {
        let section = Section {
            heading: "## Café".into(),
            table: "| new |\n".into(),
        };
        assert_eq!(
            section
                .splice("préface\n\n## Café\n\nexplanation\n\n| old |\n| row |\n\nsuffix é\n")
                .expect("existing table"),
            "préface\n\n## Café\n\nexplanation\n\n| new |\n\nsuffix é\n"
        );
    }

    #[test]
    fn splicing_accepts_a_table_at_end_of_file() {
        let section = Section {
            heading: "## End".into(),
            table: "| new |\n".into(),
        };
        for doc in ["## End\n| old |", "## End\n| old |\n"] {
            assert_eq!(section.splice(doc).expect("last table"), "## End\n| new |");
        }
    }

    #[test]
    fn splicing_refuses_a_missing_heading_or_table() {
        let section = Section {
            heading: "## Missing".into(),
            table: "| new |".into(),
        };
        assert!(
            section
                .splice("## Other\n| old |")
                .expect_err("missing heading")
                .to_string()
                .contains("section")
        );
        assert!(
            section
                .splice("## Missing\nprose only")
                .expect_err("missing table")
                .to_string()
                .contains("no table")
        );
    }
}
