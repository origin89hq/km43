//! Where a refusal is addressed to, and whether it reaches a client at all.
//!
//! A client matches a response to a request by `(session_id, req_id)` and has
//! nothing else to match on. So an `Error` about a request that parsed fine has
//! to echo that request's pair: stamped `0, 0` it arrives as an unmatchable link
//! diagnostic, and the request it was meant to answer sits outstanding until it
//! times out. The echoed values are also what enter the `rsp` MAC preimage —
//! two sides that disagree about which `req_id` went in compute different tags
//! for codes 6, 7 and 11, so a refusal somebody needed to read arrives as a
//! verification failure instead.
//!
//! A frame too malformed to parse an envelope from has no pair to echo, and
//! carries `0, 0`. It is still routed: the comms processor sends it back on the
//! connection it just read the bytes from, which is the one thing it knows. The
//! earlier rule had it swallow this as a link-level diagnostic and route
//! nothing, and a client whose frames are arriving corrupted then hears nothing
//! at all — it waits out its own timeout with an empty screen, and the person
//! holding it says *it just stops working*, which is the one bug report nobody
//! can act on.
//!
//! An error about a **link-local** frame is the opposite case and the only one
//! that goes nowhere near a client. The frame came from the other firmware
//! rather than from a socket, so there is no client behind it, and routing it
//! anyway hands some arbitrary client a diagnostic about a conversation it is
//! not part of with nothing to match it against.
//!
//! P-024 is the other side of this and is **not** cited here. It is a rule for
//! a client — drop a response whose pair matches no outstanding request, never
//! re-match one by inspecting its body — and there is no client in this
//! workspace to hold the outstanding table it needs. What this module supplies
//! is the half P-024 depends on: the `session_id` a pre-session answer carries
//! is the handle the client is told to adopt.

use crate::envelope::{Header, ReqId, SessionId};

/// Which connection the comms processor read a frame from.
///
/// Never zero — zero is the link itself, which is what makes *no connection*
/// and *connection 0* decidable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conn(pub u16);

/// What a refusal is about, which is what decides how it is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum About {
    /// A client frame whose envelope parsed. Its `session_id` and `req_id` are
    /// echoed, and they are what the `rsp` preimage covers.
    AClientFrame {
        /// The frame being refused.
        header: Header,
        /// Where it came from.
        conn: Conn,
    },
    /// A client frame too malformed to parse an envelope from. There is no pair
    /// to echo, so `0, 0` — and the connection is the only thing left to route
    /// by, which the comms processor has because it just read the bytes.
    AFrameThatDidNotParse {
        /// Where it came from.
        conn: Conn,
    },
    /// A pre-session request — `Discover 0x80`, `Pair 0x8B`, and any bare
    /// `Error` answering one. The **connection handle** goes in `session_id`,
    /// because the only demux field on the wire is one the client is told to
    /// zero. That is not a session; a session exists only after `Hello`.
    APreSessionRequest {
        /// The handle that becomes `session_id`.
        conn: Conn,
        /// Echoed like any other request's.
        req_id: ReqId,
    },
    /// A link-local frame. It came from the other firmware.
    ALinkLocalFrame,
}

/// Where a refusal goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Out to this connection.
    ToClient(Conn),
    /// Nowhere near a client. It stays on the UART.
    StaysOnTheLink,
}

/// How a refusal is stamped and where it is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addressed {
    /// What goes in the envelope's `session_id`.
    pub session: SessionId,
    /// What goes in the envelope's `req_id`.
    pub req_id: ReqId,
    /// Where the frame goes.
    pub route: Route,
}

impl About {
    /// Address the refusal.
    ///
    /// The one rule underneath all four arms: echo the pair when there is a
    /// pair to echo, and route to the connection whenever there is a client
    /// behind it.
    #[must_use]
    pub fn addressed(self) -> Addressed {
        match self {
            Self::AClientFrame { header, conn } => Addressed {
                session: header.session,
                req_id: header.req_id,
                route: Route::ToClient(conn),
            },
            Self::AFrameThatDidNotParse { conn } => Addressed {
                session: SessionId::None,
                req_id: ReqId(0),
                route: Route::ToClient(conn),
            },
            Self::APreSessionRequest { conn, req_id } => Addressed {
                session: SessionId::from(conn.0),
                req_id,
                route: Route::ToClient(conn),
            },
            Self::ALinkLocalFrame => Addressed {
                session: SessionId::None,
                req_id: ReqId(0),
                route: Route::StaysOnTheLink,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::MessageType;

    fn asked(session: u16, req_id: u32) -> Header {
        Header {
            kind: MessageType::Readings,
            session: SessionId::from(session),
            req_id: ReqId(req_id),
        }
    }

    /// **A client matches a response to a request by `(session_id, req_id)` and
    /// has nothing else.** An error about a request that parsed fine and went
    /// out stamped `0, 0` reaches the client as an unmatchable link diagnostic,
    /// while the request it was meant to answer sits outstanding until it times
    /// out. The echo is also what the `rsp` preimage covers, so two sides that
    /// disagree about it compute different tags for every code the registry
    /// still marks MAC'd.
    #[test]
    fn p_027_an_error_about_a_frame_that_parsed_echoes_what_the_client_matches_on() {
        let out = About::AClientFrame {
            header: asked(3, 17),
            conn: Conn(3),
        }
        .addressed();
        assert_eq!(out.session, SessionId::from(3));
        assert_eq!(out.req_id, ReqId(17));
        assert_eq!(out.route, Route::ToClient(Conn(3)));
    }

    /// And it echoes whatever the frame carried, rather than anything derived —
    /// including a `req_id` of 0, which is a value here and not an absence.
    #[test]
    fn p_027_the_echo_is_the_frames_own_pair_and_not_a_number_we_chose() {
        for (session, req) in [(1u16, 0u32), (8, 1), (0xFFFF, u32::MAX), (2, 42)] {
            let out = About::AClientFrame {
                header: asked(session, req),
                conn: Conn(1),
            }
            .addressed();
            assert_eq!(
                u16::from(out.session),
                session,
                "session {session} was not echoed"
            );
            assert_eq!(out.req_id, ReqId(req), "req_id {req} was not echoed");
        }
    }

    /// **A frame with no envelope has no pair to echo, and is still routed.**
    /// The `0, 0` error is the only thing on the wire that says *your frames are
    /// arriving corrupted*; swallowed as a link diagnostic it leaves a client
    /// waiting out its own timeout with an empty screen.
    #[test]
    fn p_025_a_frame_too_malformed_to_parse_is_answered_on_the_connection_it_arrived_on() {
        let out = About::AFrameThatDidNotParse { conn: Conn(6) }.addressed();
        assert_eq!(out.session, SessionId::None);
        assert_eq!(out.req_id, ReqId(0));
        assert_eq!(
            out.route,
            Route::ToClient(Conn(6)),
            "the one refusal a client cannot ask about again was not sent to it"
        );
    }

    /// **A pre-session request is answered with the connection handle in
    /// `session_id`.** The only demux field on the wire is one the client is
    /// told to zero, so without the stamp the controller cannot tell which of
    /// eight connections a `Discover` arrived on — and a fresh challenge per
    /// connection is unimplementable, falling back to one device-wide challenge
    /// and the two-client livelock it exists to prevent.
    #[test]
    fn p_026_a_pre_session_answer_carries_the_handle_that_asked() {
        for handle in [1u16, 2, 8, 0xFFFF] {
            let out = About::APreSessionRequest {
                conn: Conn(handle),
                req_id: ReqId(4),
            }
            .addressed();
            assert_eq!(
                u16::from(out.session),
                handle,
                "connection {handle} could not be told apart from the other seven"
            );
            assert_eq!(out.req_id, ReqId(4));
            assert_eq!(out.route, Route::ToClient(Conn(handle)));
        }
    }

    /// **An error about a link-local frame stays on the UART.** The frame came
    /// from the other firmware rather than from a socket, so routing it hands
    /// some arbitrary client a diagnostic about a conversation it is not part of
    /// — with `0, 0` on it, which is nothing to match against.
    #[test]
    fn l_181_an_error_about_the_link_never_reaches_a_client() {
        let out = About::ALinkLocalFrame.addressed();
        assert_eq!(out.session, SessionId::None);
        assert_eq!(out.req_id, ReqId(0));
        assert_eq!(
            out.route,
            Route::StaysOnTheLink,
            "a client was handed a diagnostic about the firmware-to-firmware link"
        );
    }

    /// **Every error about a client's frame is routed to that client**, and only
    /// the link-local one is not. Both halves matter: a refusal that is not
    /// routed is a client waiting out a timeout, and one routed to the wrong
    /// place is a client holding a diagnostic it cannot match.
    #[test]
    fn l_182_the_only_refusal_that_does_not_reach_a_client_is_the_one_with_no_client() {
        let about_a_client = [
            About::AClientFrame {
                header: asked(3, 17),
                conn: Conn(3),
            },
            About::AFrameThatDidNotParse { conn: Conn(3) },
            About::APreSessionRequest {
                conn: Conn(3),
                req_id: ReqId(1),
            },
        ];
        for about in about_a_client {
            assert_eq!(
                about.addressed().route,
                Route::ToClient(Conn(3)),
                "{about:?} was not routed to the client it is about"
            );
        }
        assert_eq!(
            About::ALinkLocalFrame.addressed().route,
            Route::StaysOnTheLink
        );
    }

    /// `0, 0` is carried **only** when the envelope did not parse or there is no
    /// request behind it. A refusal that zeroed a pair it had is the P-027
    /// failure, and one that invented a pair it did not have is a client
    /// matching an error to a request nobody made.
    #[test]
    fn l_182_a_zero_pair_is_carried_only_where_there_was_no_pair_to_carry() {
        let zeroed = |about: About| {
            let out = about.addressed();
            out.session == SessionId::None && out.req_id == ReqId(0)
        };
        assert!(zeroed(About::AFrameThatDidNotParse { conn: Conn(3) }));
        assert!(zeroed(About::ALinkLocalFrame));
        assert!(!zeroed(About::AClientFrame {
            header: asked(3, 17),
            conn: Conn(3),
        }));
        assert!(!zeroed(About::APreSessionRequest {
            conn: Conn(3),
            req_id: ReqId(1),
        }));
    }
}
