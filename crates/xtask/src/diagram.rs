//! Draws the protocol from `protocol.toml`, for the reader rather than the
//! implementer.
//!
//! REGISTRY.md answers *what is number 7*. It cannot answer *what does an
//! exchange look like*, *which key is protecting this message*, or *where does
//! the next number go*, because fourteen sorted tables hide exactly the things
//! that are not in any one row: the order of the handshake, the gap between
//! `0x0C` and the link-local range, the fact that five messages are signed
//! writes and everything else is not.
//!
//! Generated, so it cannot drift into being a picture of a protocol we used to
//! have. That is the whole reason it is here and not drawn by hand.

use anyhow::Result;
use std::fmt::Write as _;
use std::path::Path;

use crate::registry::{Auth, Message, Registry, Status};

/// Where in a connection's life a rule applies.
///
/// Derived from the `Auth` label the registry already carries, so the stages
/// cannot disagree with the auth column — there is no second list to maintain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    /// No key exists yet on either side.
    BeforeAnyKey,
    /// The label and the button.
    Enrolment,
    /// A Noise handshake: pairing messages 1 and 3, or a session's.
    Handshake,
    /// A session is running.
    InSession,
    /// The internal UART, which never reaches a client.
    Link,
}

impl Stage {
    fn of(auth: Auth) -> Self {
        match auth {
            Auth::None => Self::BeforeAnyKey,
            Auth::PairReply | Auth::PairSealed => Self::Enrolment,
            Auth::Handshake => Self::Handshake,
            Auth::Sealed | Auth::Signed | Auth::SealedOrBare => Self::InSession,
            Auth::Link => Self::Link,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::BeforeAnyKey => "Before any key exists",
            Self::Enrolment => "Enrolment — the label, and somebody at the panel",
            Self::Handshake => "Handshake — agreeing keys",
            Self::InSession => "In session",
            Self::Link => "The internal UART",
        }
    }

    fn all() -> [Self; 5] {
        [
            Self::BeforeAnyKey,
            Self::Enrolment,
            Self::Handshake,
            Self::InSession,
            Self::Link,
        ]
    }
}

pub struct Diagram {
    registry: Registry,
}

impl Diagram {
    const PATH: &'static str = "docs/protocol/MAP.md";

    pub fn load(root: &Path) -> Result<Self> {
        Ok(Self {
            registry: Registry::load(root)?,
        })
    }

    /// Whether the committed map still matches the registry.
    pub fn stale(&self, root: &Path) -> bool {
        std::fs::read_to_string(root.join(Self::PATH)).is_ok_and(|c| c != self.document())
    }

    pub fn write(&self, root: &Path) -> Result<()> {
        let path = root.join(Self::PATH);
        let body = self.document();
        if std::fs::read_to_string(&path).is_ok_and(|c| c == body) {
            println!("MAP.md already matches protocol.toml");
            return Ok(());
        }
        std::fs::write(&path, body)?;
        println!("wrote {}", path.display());
        Ok(())
    }

    fn document(&self) -> String {
        let mut o = String::from(
            "---\n\
             title: Protocol map\n\
             description: Generated diagrams of KM43 authentication stages, message families, and allocated code spaces.\n\
             tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 2 }\n\
             ---\n\n\
             # KM43 — the map\n\n\
             <p class=\"o89-doc-kicker\">KM43 / generated overview</p>\n\n\
             <p class=\"o89-doc-deck\">The protocol in three views: how authentication changes through a connection, which numeric ranges remain free, and where a new metric or event kind belongs.</p>\n\n\
             <dl class=\"o89-doc-facts\">\n\
               <div>\n\
                 <dt>Status</dt>\n\
                 <dd>Generated and non-normative</dd>\n\
               </div>\n\
               <div>\n\
                 <dt>Source</dt>\n\
                 <dd><code>protocol.toml</code></dd>\n\
               </div>\n\
               <div>\n\
                 <dt>Shows</dt>\n\
                 <dd>Authentication, allocation, and families</dd>\n\
               </div>\n\
               <div>\n\
                 <dt>Regenerate</dt>\n\
                 <dd><code>cargo xtask registry</code></dd>\n\
               </div>\n\
             </dl>\n\n\
             <nav class=\"o89-doc-links\" aria-label=\"Related KM43 documents\">\n\
               <a href=\"/km43/registry/\">Number registry <span aria-hidden=\"true\">→</span></a>\n\
               <a href=\"/km43/specification/\">Specification <span aria-hidden=\"true\">→</span></a>\n\
               <a href=\"/km43/controller-link/\">Controller link <span aria-hidden=\"true\">→</span></a>\n\
             </nav>\n\n\
             Generated from [`protocol.toml`](../../crates/km43/protocol.toml). \
             The rules themselves remain in [PROTOCOL.md](../PROTOCOL.md) and \
             [LINK.md](LINK.md); where a picture and a requirement disagree, the \
             requirement wins.\n\n",
        );
        o.push_str(&self.exchange());
        o.push_str(&self.spaces());
        o.push_str(&self.families());
        o
    }

    /// Every message, grouped by what authenticates it.
    ///
    /// The grouping is the point: the security model is a property of the auth
    /// column, and read as a column nobody sees that `Discover` is naked or
    /// that exactly four messages are writes.
    fn exchange(&self) -> String {
        let mut o = String::from(
            "## What protects each message\n\n\
             Grouped by the authentication rule the registry gives it, which is also \
             roughly the order a connection meets them. Each node carries its request \
             opcode and rule, then its response opcode and rule.\n\n\
             ```mermaid\nflowchart TD\n",
        );
        for stage in Stage::all() {
            let rows: Vec<&Message> = self
                .registry
                .messages
                .iter()
                .filter(|m| m.status != Status::Withdrawn)
                .filter(|m| m.auth_request.or(m.auth_response).map(Stage::of) == Some(stage))
                .collect();
            if rows.is_empty() {
                continue;
            }
            let _ = writeln!(
                o,
                "  subgraph {}[\"{}\"]",
                ident(stage.title()),
                stage.title()
            );
            for m in rows {
                let side = |op: Option<crate::registry::Opcode>, auth: Option<Auth>| {
                    op.map(|o| {
                        let rule = auth.map_or_else(String::new, |a| format!(" {a}"));
                        format!("{:#04X}{rule}", o.0)
                    })
                };
                // A response-only message has no arrow to draw: `— → 0x04` reads
                // as a missing opcode rather than as one nobody asked for.
                let label = match (
                    side(m.request, m.auth_request),
                    side(m.response, m.auth_response),
                ) {
                    (Some(req), Some(rsp)) => format!("{req} → {rsp}"),
                    (None, Some(rsp)) => format!("unsolicited · {rsp}"),
                    (Some(req), None) => req,
                    (None, None) => String::new(),
                };
                let _ = writeln!(o, "    {}[\"{}<br/>{label}\"]", ident(&m.name), m.name);
            }
            o.push_str("  end\n");
        }

        if !self.registry.link_messages.is_empty() {
            let title = Stage::Link.title();
            let _ = writeln!(o, "  subgraph {}[\"{title}\"]", ident(title));
            for m in &self.registry.link_messages {
                let _ = writeln!(
                    o,
                    "    {}[\"{}<br/>{:#04X} → {:#04X} · {}\"]",
                    ident(&m.name),
                    m.name,
                    m.request.0,
                    m.response.0,
                    m.direction
                );
            }
            o.push_str("  end\n");
        }

        let mut prev: Option<Stage> = None;
        for stage in Stage::all() {
            if stage == Stage::Link {
                continue;
            }
            let present = self.registry.messages.iter().any(|m| {
                m.status != Status::Withdrawn
                    && m.auth_request.or(m.auth_response).map(Stage::of) == Some(stage)
            });
            if !present {
                continue;
            }
            if let Some(p) = prev {
                let _ = writeln!(o, "  {} --> {}", ident(p.title()), ident(stage.title()));
            }
            prev = Some(stage);
        }
        o.push_str("```\n\n");
        o
    }

    /// What is allocated in each number space, and what is left.
    ///
    /// A sorted table of allocated numbers cannot show a hole, and a hole is
    /// the only thing somebody allocating a number needs to see.
    fn spaces(&self) -> String {
        let mut o = String::from(
            "## What is allocated, and what is left\n\n\
             A table of allocated numbers cannot show a gap, and a gap is the only thing \
             somebody allocating the next number needs to see.\n\n```text\n",
        );

        let reqs: Vec<u16> = self
            .registry
            .messages
            .iter()
            .filter_map(|m| m.request.map(|r| r.0))
            .collect();
        let rsps: Vec<u16> = self
            .registry
            .messages
            .iter()
            .filter_map(|m| m.response.map(|r| r.0))
            .collect();
        let link: Vec<u16> = self
            .registry
            .link_messages
            .iter()
            .map(|m| m.request.0)
            .collect();
        let link_rsp: Vec<u16> = self
            .registry
            .link_messages
            .iter()
            .map(|m| m.response.0)
            .collect();

        let errs: Vec<u16> = self.registry.errors.iter().map(|e| e.code).collect();
        let link_errs: Vec<u16> = self.registry.link_errors.iter().map(|e| e.code).collect();

        for space in [
            Space::opcodes("client requests", 0x00, 0x5F, &reqs),
            Space::opcodes("link-local requests", 0x60, 0x7E, &link),
            Space::opcodes("client responses", 0x80, 0xDF, &rsps),
            Space::opcodes("link-local responses", 0xE0, 0xFE, &link_rsp),
            Space::codes("client errors", 1, 32, &errs),
            Space::codes("link-local errors", 256, 287, &link_errs),
        ] {
            space.draw(&mut o);
        }

        o.push_str("```\n\n");
        let _ = writeln!(
            o,
            "The two error spaces run further than shown — a client code is a `u16` and the \
             link-local range ends at 511. The window is where the next one would go.\n\n\
             `0x7F` is absent from the link-local range on purpose: `0x7F` with the high \
             bit set is `0xFF`, which is `Error`.\n"
        );
        o
    }

    /// The high byte of a metric or event kind is its family.
    fn families(&self) -> String {
        let mut o = String::from(
            "## Where a new kind goes\n\n\
             The high byte is the family. A kind allocated in the wrong one is not wrong \
             on the wire and is wrong for everybody reading a log.\n\n\
             ```mermaid\nflowchart LR\n",
        );
        o.push_str("  metrics[\"metric kinds\"]\n  events[\"event kinds\"]\n");
        let mut seen: Vec<u16> = Vec::new();
        for m in &self.registry.metrics {
            let hi = m.kind >> 8;
            if seen.contains(&hi) {
                continue;
            }
            seen.push(hi);
            let n = self
                .registry
                .metrics
                .iter()
                .filter(|x| x.kind >> 8 == hi)
                .count();
            let _ = writeln!(
                o,
                "  metrics --> m{hi}[\"0x{hi:02X}xx · {} · {n} allocated\"]",
                m.group.split('—').next_back().unwrap_or("").trim()
            );
        }
        let mut seen: Vec<u16> = Vec::new();
        for e in &self.registry.events {
            let hi = e.kind >> 8;
            if seen.contains(&hi) {
                continue;
            }
            seen.push(hi);
            let n = self
                .registry
                .events
                .iter()
                .filter(|x| x.kind >> 8 == hi)
                .count();
            let a = self
                .registry
                .events
                .iter()
                .filter(|x| x.kind >> 8 == hi && x.class == crate::registry::EventClass::A)
                .count();
            let _ = writeln!(
                o,
                "  events --> e{hi}[\"0x{hi:02X}xx · {n} allocated · {a} class A\"]"
            );
        }
        o.push_str(
            "```\n\n\
             `0xF000`–`0xFFFF` is vendor and experimental in both spaces and is never \
             allocated here.\n",
        );
        o
    }
}

/// One number space, and which of its numbers are taken.
///
/// A struct because the five things a picture of a space needs — its name, its
/// bounds, what is taken, and how a number in it is written — travel together
/// and are wrong apart: an opcode drawn in decimal and an error code drawn in
/// hex are both unreadable to whoever is looking for the next free one.
struct Space<'a> {
    name: &'a str,
    lo: u16,
    hi: u16,
    taken: &'a [u16],
    hex: bool,
}

impl<'a> Space<'a> {
    fn opcodes(name: &'a str, lo: u16, hi: u16, taken: &'a [u16]) -> Self {
        Self {
            name,
            lo,
            hi,
            taken,
            hex: true,
        }
    }

    /// Error codes are decimal everywhere in the corpus — "error 7", "code 259"
    /// — so they are decimal here.
    fn codes(name: &'a str, lo: u16, hi: u16, taken: &'a [u16]) -> Self {
        Self {
            name,
            lo,
            hi,
            taken,
            hex: false,
        }
    }

    fn label(&self, n: u16) -> String {
        if self.hex {
            format!("{n:#04X}")
        } else {
            format!("{n:>4}")
        }
    }

    /// `#` taken, `.` free, in rows of 32 under the number they start at.
    ///
    /// Rows rather than one long bar, because the question a reader arrives
    /// with is "what is at 0x0B", and counting to the eleventh character of
    /// ninety-six is not an answer.
    fn draw(&self, o: &mut String) {
        let used = (self.lo..=self.hi)
            .filter(|n| self.taken.contains(n))
            .count();
        let free = usize::from(self.hi - self.lo + 1) - used;
        let _ = writeln!(
            o,
            "{} — {} to {}, {used} allocated, {free} free",
            self.name,
            self.label(self.lo),
            self.label(self.hi)
        );

        let mut n = self.lo;
        while n <= self.hi {
            let _ = write!(o, "  {}  ", self.label(n));
            for col in 0..32 {
                let at = n + col;
                if at > self.hi {
                    break;
                }
                if col % 8 == 0 && col != 0 {
                    o.push(' ');
                }
                o.push(if self.taken.contains(&at) { '#' } else { '.' });
            }
            o.push('\n');
            n += 32;
        }
        o.push('\n');
    }
}

/// A mermaid node id: letters and digits, nothing a parser argues with.
fn ident(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
}
