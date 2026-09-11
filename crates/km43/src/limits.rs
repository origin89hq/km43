//! The numbers both implementations agree on, and the arithmetic that says why.
//!
//! Most of these are derived rather than chosen, and they are computed here so
//! the derivation cannot rot into a comment: an earlier log page was 1024 bytes
//! inside a 1024-byte payload, and the channel cap was documented as "the
//! largest that fits" by somebody counting by hand when three more did. That
//! second one is why every cap added since sits under a computed ceiling — and
//! why `MAX_CHANNELS`, which lost its ceiling with the message it was derived
//! against, now carries a paragraph saying so. The reasoning is in the Limits
//! section of `docs/PROTOCOL.md`.
//!
//! cites: P-006
//!
//! P-003 was on that list and this file cannot stand behind it. *Refusing is
//! preferred to evicting* is a behaviour, and every test here is about a buffer
//! size — the caps live here and the refusing does not. It is the controller's
//! session module's, which is what P-003's own sentence is about: silently dropping a client's
//! enrolment is how a cabin loses its ability to be told to stop.

// The COBS worst case is defined once, beside the encoder it bounds. Two
// formulas for one bound were here first, and they disagreed by a byte at every
// multiple of 254 — both safe, so nothing went red while they drifted.
use crate::cobs::max_encoded_len;

// A cap with no ceiling over it is a number anybody can raise. These two protect
// something a bigger value quietly breaks, and both survived being raised —
// MAX_DEPTH to 255 — with every test in this crate still green, because nothing
// stood behind them.
const_assert!(
    MAX_DEPTH <= 16,
    "nested containers past this is a recursion budget nobody costed, on a part with no stack guard"
);
const_assert!(
    MAX_STRING <= 255,
    "a string longer than this cannot carry its own length in a byte"
);

/// The encoded envelope a receiver will accept; anything larger gets error 5 and the frame is dropped.
pub const MAX_PAYLOAD: usize = 1024;

/// What a receiver sizes its frame buffer at before a byte arrives; a longer frame is dropped and it resynchronises.
pub const MAX_FRAME: usize = 1032;

/// The signed `operation` blob; a longer one gets error 5, because the body that signs it also has to fit.
pub const MAX_OPERATION: usize = 960;

/// A log page stops at this many bytes and comes back with `complete = false` rather than growing.
pub const MAX_LOG_PAGE_BYTES: usize = 896;

/// A log page stops at this many entries and comes back with `complete = false` rather than growing.
pub const MAX_LOG_PAGE_ENTRIES: usize = 64;

/// A UTF-8 string on the wire; a longer one gets error 1 rather than being truncated into a different string.
pub const MAX_STRING: usize = 64;

/// CBOR nesting; a deeper body gets error 1, which is what stops a hostile message walking off the stack.
pub const MAX_DEPTH: u8 = 8;

/// Bindings this controller holds, reported in `Hello 0x81` key 12; a ninth gets error 8 and the oldest is **not** evicted.
pub const MAX_SESSIONS: usize = 8;

/// Channels a config may name, reported in key 13; more is refused at write time with `SetConfigAck` outcome 5 `exceeds_cap`.
///
/// **The one cap in this file with no ceiling over it**, which is the thing the comment at the top
/// of the file says nobody should leave lying around. It had one: 35, from fitting a worst-case
/// `Snapshot` into `MAX_PAYLOAD`, with three spare so a `Value` could gain a key. That message is
/// retired and took the derivation with it. What bounds a channel list now is the `0x0002 channels`
/// config section, and nothing here derives its width — so 32 is a chosen number again, and raising
/// it breaks nothing in this file, which is exactly why this paragraph is here.
pub const MAX_CHANNELS: usize = 32;

/// Enrolled clients, reported in key 14; pairing a ninth gets outcome 4 `table_full` rather than dropping somebody's enrolment.
pub const MAX_CLIENTS: usize = 8;

/// Events held per session, reported in key 15. Class B is dropped oldest-first and counted; a class A
/// event that cannot be queued closes the connection rather than being lied about.
pub const MAX_EVENT_QUEUE: usize = 16;

/// Requests in flight per session, reported in key 16; the next one gets error 7 `busy`.
pub const MAX_INFLIGHT: usize = 4;

/// Command dedup entries, reported in key 17; a full table gets error 7 `busy`, because evicting one
/// is how a retried command starts the generator a second time.
pub const MAX_CMD_DEDUP: usize = 32;

/// Challenges held at once, one per connection row (P-060).
///
/// A single device-wide challenge livelocks two clients against each other
/// exactly the way a device-wide counter would, so there is one per connection
/// and the table is as wide as the connection table. Full is error 7 `busy` and
/// nothing is evicted — a challenge dropped to make room sends the client that
/// was proving against it to error 14 for no reason it can see.
pub const MAX_CHALLENGES: usize = 8;

/// MAC failures one connection may reach before it is closed (P-051).
///
/// A `u8` and not a `usize` like its neighbours, because this one is not a table
/// width — it is a counter that lives in a connection row eight times over, and
/// eight bytes to count to eight is seven of them spent on a number that cannot
/// reach nine.
///
/// The window it is counted over is a duration rather than a width, so it lives
/// beside the rows that measure it, in the controller's session module; its
/// dedup window sits the same way relative to `MAX_CMD_DEDUP`.
pub const MAX_AUTH_FAILURES: u8 = 8;

/// The CRC-16 that goes into COBS alongside the envelope.
const CRC_BYTES: usize = 2;

/// The zero byte that ends every frame.
const FRAME_DELIMITER_BYTES: usize = 1;

/// `[type, session_id, req_id, body]` and the body's own map header, with `req_id` a `u32` — five
/// CBOR bytes at the top of its range, not three. A `type` past `0x17` costs one more.
pub(crate) const ENVELOPE_BYTES: usize = 11;

/// The signed wrapper's map **contents** and the 16-byte MAC — the map header is not here.
///
/// This was `WRAPPER_BYTES = 23`, which counted the map header that [`ENVELOPE_BYTES`] already
/// carries. The double-count cancelled against a second error — every response `type` is `0x8x`,
/// which is two CBOR bytes rather than the one the envelope assumed — so `11 + 23 = 34` was the
/// right answer for every response and one byte conservative for every request. Two errors that
/// cancel are correct until somebody fixes one of them.
const WRAPPER_CONTENTS_BYTES: usize = 22;

/// A `0x8x` response type is two CBOR bytes; a request type at or below `0x17` is one.
const RESPONSE_TYPE_EXTRA_BYTE: usize = 1;

/// What a response spends before its inner body: 11 + 22 + 1.
const RESPONSE_FRAMING_BYTES: usize =
    ENVELOPE_BYTES + WRAPPER_CONTENTS_BYTES + RESPONSE_TYPE_EXTRA_BYTE;

/// What a request spends before its inner body: 11 + 22. One byte cheaper, because its type fits
/// in one CBOR byte.
const REQUEST_FRAMING_BYTES: usize = ENVELOPE_BYTES + WRAPPER_CONTENTS_BYTES;

/// The inner body budget every topology derivation rests on.
pub const INNER_BODY_BYTES: usize = MAX_PAYLOAD - RESPONSE_FRAMING_BYTES;

/// The signed body around its operation: four key numbers at one byte each, `client_id` at `u32`
/// width, `counter` at `u64` width, the `bstr` head a full-width operation needs, and the 16-byte
/// MAC with its own head. The map header is not here — `ENVELOPE_BYTES` already carries it.
///
/// Written 39 first, from a count that included that map header twice and a comment that
/// enumerated 35. `signed.rs` measures it against the encoder now, which is what this file is for.
pub(crate) const SIGNED_BODY_BYTES: usize = 38;

/// The largest `operation` whose worst-case signed request still fits `MAX_PAYLOAD`.
///
/// `MAX_OPERATION` sits below it on purpose, the way every cap in this file sits below its own
/// ceiling: the signed body is one of the three whose MAC covers fields, so a later key lands
/// inside the preimage and inside these bytes.
pub const MAX_OPERATION_CEILING: usize = MAX_PAYLOAD - SIGNED_BODY_BYTES - ENVELOPE_BYTES;

/// The `Event 0x04` body around key 4: the four key numbers, `seq` and `at` at `u64` width, and
/// `kind` at `u16`. The map header is `ENVELOPE_BYTES`'.
const EVENT_FIXED_BYTES: usize = 25;

/// The event record's own map header. [`EVENT_FIXED_BYTES`] deliberately leaves it out, and under
/// the old constants it was paid for by the byte `ENVELOPE_BYTES` and `WRAPPER_BYTES` double-counted.
/// Named here so the cancellation is a line somebody can read rather than luck.
const EVENT_RECORD_MAP_HEADER_BYTES: usize = 1;

/// The widest `body` an `Event 0x04` can carry — what a payload holds once the envelope, the
/// wrapper and the record's own three fields are paid for.
///
/// An `Event` is `0x04`, which is one CBOR byte, so `RESPONSE_TYPE_EXTRA_BYTE` does not apply
/// here. It still comes to 965: the byte the old pair double-counted is exactly the record's map
/// header, so the answer is unchanged and is now exact rather than lucky.
pub const MAX_EVENT_BODY: usize =
    MAX_PAYLOAD - REQUEST_FRAMING_BYTES - EVENT_RECORD_MAP_HEADER_BYTES - EVENT_FIXED_BYTES;

/// `LogPage` keys 2, 3 and 4.
const LOG_PAGE_HEADER_BYTES: usize = 26;

/// What is left of a payload for log entries once the envelope, the wrapper and the page header are paid for.
const LOG_PAGE_HEADROOM: usize = MAX_PAYLOAD - RESPONSE_FRAMING_BYTES - LOG_PAGE_HEADER_BYTES;

/// Elements in one series signal. A driver declaring a longer series fails to register that
/// signal — the device attaches, the signal does not, and a `Concern` names it. Never truncated.
pub const MAX_SERIES_LEN: usize = 16;

/// A descriptor label, UTF-8. Refused rather than truncated: "pump hous" is a different label and
/// somebody acts on it wrongly.
pub const MAX_LABEL: usize = 32;

/// A firmware or board revision string on the link, UTF-8 (LINK.md `LinkUp` keys 4 and 6).
///
/// Bounded at the field for the reason the pairing label is: `MAX_STRING` is 64 and what stores
/// this is narrower, so a value between the two would decode cleanly and have nowhere to go. The
/// controller reports key 4 onward as `fw_comms` in every client `Hello` (L-031), which is what
/// makes it a value somebody reads rather than a diagnostic.
pub const MAX_LINK_TEXT: usize = 32;

/// A serial, hardware or firmware string on a `DeviceRow`. Same refuse-not-truncate rule.
pub const MAX_IDENT: usize = 24;

/// A bus address, as the bus defines one. Longer cannot be expressed and the driver is refused at
/// registration.
pub const MAX_ADDR: usize = 8;

/// The scratch one descriptor row is encoded into before it is measured, 14 over the widest row
/// the design costs (a `DeviceRow` at 170). A row that would exceed it is refused at registration,
/// where a person can act on it, rather than silently stopping a page.
pub const MAX_ROW_BYTES: usize = 184;

/// Scalar samples in one `Readings 0x8E`. The response stops and `next` names the first
/// unanswered `sig`; not an error.
pub const MAX_SAMPLES: usize = 40;

/// Series signals in one `Readings 0x8E`. Same behaviour when reached.
pub const MAX_SERIES: usize = 7;

/// The byte arm of a `Readings 0x8E`. One spelling of this bound, and it is this one.
pub const MAX_READINGS_BYTES: usize = 880;

/// The row arm of an `Inventory 0x8D` page — what a decoder sizes its row array at.
pub const MAX_INVENTORY_PAGE_ROWS: usize = 48;

/// The byte arm of an `Inventory 0x8D` page. Whichever arm binds first ends the page (P-208).
pub const MAX_INVENTORY_PAGE_BYTES: usize = 880;

/// The row arm of a `Concerns 0x8F` page.
pub const MAX_CONCERN_PAGE_ROWS: usize = 12;

/// The byte arm of a `Concerns 0x8F` page. It is a backstop rather than a binding cap — twelve
/// concerns at their widest are 756 bytes, so the row arm always binds first. It stays because a
/// later key on `Concern` must not turn a legal page into a frame the controller then refuses.
pub const MAX_CONCERN_PAGE_BYTES: usize = 832;

/// Buckets in one `History 0x90`. A request above it is error 1 — a client can check its own number.
pub const MAX_HISTORY_POINTS: usize = 96;

/// Command kinds one component or device may accept. A component needing a fifth is a component
/// that should be a parent and a child.
pub const MAX_COMPONENT_CMDS: usize = 4;

/// Entries in one coalesced `0x0102 signal validity changed`. Entries past it wait for the next
/// tick and are **not** dropped (P-182).
pub const MAX_VALIDITY_SWEEP: usize = 48;

/// Entries in one coalesced `0x0902 device presence changed`. Bounded by the device cap rather
/// than by the body, because every device can change presence at once and one event carries them all.
pub const MAX_PRESENCE_SWEEP: usize = MAX_DEVICES;

/// `0x0501` and `0x0502` together, per tick. Counted together because P-180 makes an `0x0502`
/// mandatory as each concern leaves the table, and thirty-two per-cell concerns clear at dawn in
/// one tick — a cap on raises alone leaves the clears unbounded.
pub const MAX_CONCERN_EVENTS_PER_TICK: usize = 4;

/// How often `rev` may move, on P-004's tick. A sub-device found inside the window is staged and
/// adopted at the next boundary, so the descriptor tables and `rev` move together and atomically.
pub const MIN_REV_INTERVAL_MS: u64 = 30_000;

/// Physical ports, reported in `Hello 0x81` key 20.
pub const MAX_BUSES: usize = 8;

/// Devices, reported in key 21. A sub-device found past the cap is not adopted, `rev` does not
/// move, and a `Concern` names it. Nothing evicted.
pub const MAX_DEVICES: usize = 24;

/// Components, reported in key 22.
pub const MAX_COMPONENTS: usize = 160;

/// Signals, reported in key 23. It was 320 until the six fixtures were costed and came to 276
/// against 256 writable — an installer adding a tank probe and a shunt would have met a refused
/// config write four hours from a road.
pub const MAX_SIGNALS: usize = 384;

/// The shared series-element pool, reported in key 24. Sized for fixture 3 at fourteen packs
/// (504), not for the six fixtures. A series that does not fit the remainder is refused at
/// registration, never shortened (P-172).
pub const MAX_SERIES_ELEMENTS: usize = 512;

/// Parameters, reported in key 25.
pub const MAX_PARAMS: usize = 96;

/// Concerns held at once, reported in key 26. Refused and counted, never evicted.
pub const MAX_CONCERNS: usize = 48;

/// Selectors in one `ReadSignals 0x0E`, reported in key 27. More is error 1.
pub const MAX_SELECTORS: usize = 12;

/// Signals that may carry history, reported in key 28.
pub const MAX_HISTORY_SIGNALS: usize = 24;

/// How deep either `parent` chain may run, reported in key 29. Refused at config write **and** at
/// runtime adoption, because adoption is not a config write and it is the path fixture 6 proves.
pub const MAX_TOPOLOGY_DEPTH: usize = 4;

/// How many of [`MAX_CONCERNS`] may be `info` or `warning`. The remainder is reserved for `fault`
/// and `protection`, so twenty-four cell-imbalance warnings arriving first cannot hide the pack
/// fault that arrives twenty-fifth.
pub const MAX_CONCERNS_BELOW_FAULT: usize = 24;

/// A `Readings 0x8E` before its first sample: map header 1, `seq` 10, `rev` 6, `at` 10, the two
/// array keys and headers 5, `next` 4, `total` 4, `outcome` 2.
pub const READINGS_HEADER_BYTES: usize = 42;

/// An `Inventory 0x8D` before its first row: map header 1, `rev` 6, `what` 2, the rows key and its
/// header 3, `next` 4, `total` 4, `outcome` 2, `digest` 10.
pub const INVENTORY_HEADER_BYTES: usize = 32;

/// A `Concerns 0x8F` before its first row: map header 1, `rev` 6, `seq` 10, the array key and
/// header 2, `next` 4, `total` 4, `refused` 4, `outcome` 2.
pub const CONCERNS_HEADER_BYTES: usize = 33;

/// A `Sample` at its widest: map header 1, `sig` 4, `v` 6 (an `i32` under P-185), `q` 3, `age` 6.
pub const SAMPLE_MAX_BYTES: usize = 20;

/// A `Series` at [`MAX_SERIES_LEN`], every element present and stale: map header 1, `sig` 4,
/// `q` 18, `v` 82, `age` 6.
pub const SERIES_MAX_BYTES: usize = 111;

/// A `Concern` at its widest, with `elem` at two bytes because P-206 makes it a position in
/// `1..MAX_SERIES_LEN` rather than a label that can exceed 23.
pub const CONCERN_MAX_BYTES: usize = 63;

/// The narrowest legal descriptor row: a `BusRow` with neither optional key — map header 1,
/// `bus` 3, `transport` 2.
const NARROWEST_ROW_BYTES: usize = 6;

/// One `VChange` in a coalesced `0x0102`: map header 1, `sig` 4, `q` 3, `prev` 3.
pub const VCHANGE_MAX_BYTES: usize = 11;

/// A coalesced `0x0102` before its first entry: map header 1, `rev` 6, the array key and header 3.
const VALIDITY_SWEEP_HEADER_BYTES: usize = 10;

/// One `PChange` in a coalesced `0x0902`: map header 1, `dev` 4, `presence` 2, `prev` 2.
pub const PCHANGE_MAX_BYTES: usize = 9;

/// A coalesced `0x0902` before its first entry: map header 1, `rev` 6, the array key and header 3.
const PRESENCE_SWEEP_HEADER_BYTES: usize = 10;

/// What a `History 0x90` costs that does not scale with the bucket count.
const HISTORY_FIXED_BYTES: usize = 65;

/// What one history bucket costs, in eighths of a byte: `q` 1, `v` 5, `n` 1, `src` 1 and one
/// `reset` bit. Eighths rather than a float because there is no FPU on the target and this has to
/// be a `const`.
const HISTORY_POINT_EIGHTHS: usize = 65;

/// The most scalar samples the byte budget could carry.
pub const SAMPLE_CEILING: usize = (INNER_BODY_BYTES - READINGS_HEADER_BYTES) / SAMPLE_MAX_BYTES;

/// The most full-width series the byte budget could carry.
pub const SERIES_CEILING: usize = (INNER_BODY_BYTES - READINGS_HEADER_BYTES) / SERIES_MAX_BYTES;

/// The most widest-case concerns one page could carry.
pub const CONCERN_CEILING: usize = (INNER_BODY_BYTES - CONCERNS_HEADER_BYTES) / CONCERN_MAX_BYTES;

/// The most rows the inventory byte cap could ever admit — at the narrowest legal row, which is
/// the only place the row arm binds. The margin under it is large on purpose and not by accident.
pub const INVENTORY_PAGE_ROWS_CEILING: usize = MAX_INVENTORY_PAGE_BYTES / NARROWEST_ROW_BYTES;

/// The most history buckets one body could carry.
pub const POINT_CEILING: usize =
    (INNER_BODY_BYTES - HISTORY_FIXED_BYTES) * 8 / HISTORY_POINT_EIGHTHS;

/// The most validity changes one coalesced event could carry.
pub const SWEEP_CEILING: usize = (MAX_EVENT_BODY - VALIDITY_SWEEP_HEADER_BYTES) / VCHANGE_MAX_BYTES;

/// The class A events one tick can produce **from this design**: one `0x0102`, one `0x0902`,
/// [`MAX_CONCERN_EVENTS_PER_TICK`] concern events, and at most one `0x0901`.
///
/// This is not the whole bound. REGISTRY.md allocates nineteen class A kinds and sixteen of them
/// have no per-tick bound anywhere in this repo — the rest of the budget is theirs, and bounding
/// them is the event-bodies commit's work. A ceiling that counts only the kinds its author was
/// thinking about is the defect this constant exists to stop, so it says which kinds it counts.
pub const CLASS_A_TICK_CEILING: usize = 1 + 1 + MAX_CONCERN_EVENTS_PER_TICK + 1;

const_assert!(
    MAX_LABEL <= MAX_STRING && MAX_IDENT <= MAX_STRING && MAX_LINK_TEXT <= MAX_STRING,
    "a descriptor string longer than MAX_STRING is one the CBOR writer refuses, so the row cap would be a cap the encoder never reaches"
);

const_assert!(
    MAX_SAMPLES <= SAMPLE_CEILING,
    "MAX_SAMPLES above its ceiling is a Readings the controller builds and then refuses with error 5, at a fully configured site"
);

const_assert!(
    MAX_SERIES <= SERIES_CEILING,
    "MAX_SERIES above its ceiling is the same frame one row kind over"
);

const_assert!(
    MAX_READINGS_BYTES <= INNER_BODY_BYTES - READINGS_HEADER_BYTES,
    "the readings byte cap must fit under the inner body once the header is paid for — a page is not a payload"
);

const_assert!(
    MAX_INVENTORY_PAGE_BYTES <= INNER_BODY_BYTES - INVENTORY_HEADER_BYTES,
    "the inventory byte cap must fit under the inner body once the header is paid for"
);

const_assert!(
    MAX_INVENTORY_PAGE_ROWS <= INVENTORY_PAGE_ROWS_CEILING,
    "more rows than the byte cap could admit at the narrowest legal row is a row cap that can never bind"
);

const_assert!(
    MAX_CONCERN_PAGE_ROWS <= CONCERN_CEILING,
    "MAX_CONCERN_PAGE_ROWS above its ceiling is a concerns page built and then refused"
);

const_assert!(
    MAX_CONCERN_PAGE_BYTES <= INNER_BODY_BYTES - CONCERNS_HEADER_BYTES,
    "the concern byte cap must fit under the inner body once the header is paid for"
);

const_assert!(
    MAX_CONCERN_PAGE_ROWS * CONCERN_MAX_BYTES <= MAX_CONCERN_PAGE_BYTES,
    "the row arm must bind before the byte arm here, or the byte cap is doing work the row cap claims"
);

const_assert!(
    MAX_HISTORY_POINTS <= POINT_CEILING,
    "MAX_HISTORY_POINTS above its ceiling is a chart the controller builds and then refuses"
);

const_assert!(
    MAX_VALIDITY_SWEEP <= SWEEP_CEILING,
    "a coalesced 0x0102 above its ceiling is a class A event too large to send, which P-098 turns into a closed session"
);

const_assert!(
    PRESENCE_SWEEP_HEADER_BYTES + MAX_PRESENCE_SWEEP * PCHANGE_MAX_BYTES <= MAX_EVENT_BODY,
    "a coalesced 0x0902 carrying every device must still fit one event body"
);

// Without P-182's coalescing the same column is one event per signal, so the burst a single
// intermittent RS-485 pair produces is many times the whole queue. This is why that rule is a
// bound and not a preference, and it is here rather than in a test because it decides nothing at
// runtime and everything at compile time.
const_assert!(
    MAX_SIGNALS > MAX_EVENT_QUEUE * 8,
    "a per-signal validity sweep would overrun every session's queue many times over, which is the failure the coalescing rule exists to stop"
);

const_assert!(
    CLASS_A_TICK_CEILING <= MAX_EVENT_QUEUE,
    "this design alone must not fill a session's queue in one tick: class A cannot be dropped, so P-098 closes the session, the reconnect replays the burst and closes again, and L-022 puts the controller on the ladder"
);

const_assert!(
    MAX_CONCERNS_BELOW_FAULT < MAX_CONCERNS,
    "with no rows reserved above the band, per-cell warnings fill the table before the pack fault that decides whether charging is safe"
);

const_assert!(
    MAX_SERIES_LEN <= MAX_SERIES_ELEMENTS,
    "one series must fit the pool, or no series can be registered at all"
);

const_assert!(
    MAX_ROW_BYTES <= MAX_INVENTORY_PAGE_BYTES,
    "a row that cannot fit an empty page is a row no page can ever carry"
);

const_assert!(
    RESPONSE_FRAMING_BYTES + READINGS_HEADER_BYTES + MAX_READINGS_BYTES <= MAX_PAYLOAD,
    "the widest Readings must fit a payload"
);

const_assert!(
    RESPONSE_FRAMING_BYTES + INVENTORY_HEADER_BYTES + MAX_INVENTORY_PAGE_BYTES <= MAX_PAYLOAD,
    "the widest Inventory page must fit a payload"
);

const_assert!(
    RESPONSE_FRAMING_BYTES + CONCERNS_HEADER_BYTES + MAX_CONCERN_PAGE_BYTES <= MAX_PAYLOAD,
    "the widest Concerns page must fit a payload"
);

const_assert!(
    RESPONSE_FRAMING_BYTES
        + HISTORY_FIXED_BYTES
        + (MAX_HISTORY_POINTS * HISTORY_POINT_EIGHTHS).div_ceil(8)
        <= MAX_PAYLOAD,
    "the widest History must fit a payload"
);

const _: () = assert!(
    MAX_FRAME >= max_encoded_len(MAX_PAYLOAD + CRC_BYTES) + FRAME_DELIMITER_BYTES,
    "MAX_FRAME must hold a full payload after COBS expands it, or the buffer a receiver sized before the frame arrived is overrun by a legal message"
);

const _: () = assert!(
    MAX_LOG_PAGE_BYTES <= LOG_PAGE_HEADROOM,
    "MAX_LOG_PAGE_BYTES must fit inside MAX_PAYLOAD under the envelope, the wrapper and the page header — a page is not a frame"
);

const _: () = assert!(
    MAX_OPERATION <= MAX_OPERATION_CEILING,
    "MAX_OPERATION above its ceiling is a write the client builds and the controller then refuses with error 5. The check here before it was `MAX_OPERATION < MAX_PAYLOAD`, which is true of any operation leaving one byte for the four keys and the MAC that sign it"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Worst-case wire size of a frame carrying `payload` bytes of envelope.
    fn frame_bytes(payload: usize) -> usize {
        max_encoded_len(payload.saturating_add(CRC_BYTES)).saturating_add(FRAME_DELIMITER_BYTES)
    }

    /// What a `LogPage` of `page` bytes costs once the envelope, the wrapper and the page header
    /// are wrapped around it — the derivation again, not `LOG_PAGE_HEADROOM` read back.
    fn log_page_frame_bytes(page: usize) -> usize {
        ENVELOPE_BYTES
            .saturating_add(WRAPPER_CONTENTS_BYTES)
            .saturating_add(RESPONSE_TYPE_EXTRA_BYTE)
            .saturating_add(LOG_PAGE_HEADER_BYTES)
            .saturating_add(page)
    }

    /// The frame buffer is sized before a byte arrives, so it has to come from the derivation rather
    /// than from a number in a table. If the two ever part company, this is where it shows.
    #[test]
    fn a_full_payload_still_fits_the_frame_buffer_after_cobs_expands_it() {
        assert_eq!(
            frame_bytes(MAX_PAYLOAD),
            MAX_FRAME,
            "the COBS derivation and MAX_FRAME have parted company"
        );
        assert_eq!(MAX_FRAME, 1032, "the document states 1032");
    }

    /// Sizing the receive buffer at `MAX_PAYLOAD` is the tempting mistake: the envelope fits and the
    /// framing around it does not, so the overrun only bites on a full frame at a busy site.
    #[test]
    fn a_buffer_sized_at_the_payload_would_be_overrun_by_the_framing() {
        let framed = frame_bytes(MAX_PAYLOAD);
        let overhead = framed
            .checked_sub(MAX_PAYLOAD)
            .expect("a frame is never smaller than the payload it carries");
        assert_eq!(overhead, 8, "crc 2 + cobs 5 + delimiter 1");
    }

    /// One overhead byte per 254, and the boundary is where an off-by-one hides: 254 costs one byte
    /// and 255 costs two, so a body one byte over a block is the frame that does not fit.
    #[test]
    fn cobs_spends_one_overhead_byte_per_block_of_254() {
        let cases = [
            (0_usize, 1_usize),
            (1, 2),
            (253, 254),
            (254, 256),
            (255, 257),
            (508, 511),
            (509, 512),
            (1026, 1031),
        ];
        for (input, expected) in cases {
            assert_eq!(max_encoded_len(input), expected, "max_encoded_len({input})");
        }
    }

    /// Every length up to a full payload, because the whole point of a worst case is that no single
    /// length beats it. A formula that is right at 1026 and wrong at 762 is not a bound.
    ///
    /// Against the **encoder's real output**, not against a second closed form. The first version
    /// of this compared `n + ceil(n/254)` to `n + n/254 + 1` — two formulas, neither of which had
    /// ever encoded a byte, so it would have passed unchanged if the encoder's overhead doubled.
    #[test]
    fn no_length_below_a_full_payload_beats_the_worst_case() {
        let widest = MAX_PAYLOAD + CRC_BYTES;
        // All non-zero, which is what makes COBS spend a code byte every 254 bytes and is
        // therefore the input the bound is a bound for.
        let worst = [0xA5u8; MAX_PAYLOAD + CRC_BYTES];
        let mut dst = [0u8; MAX_FRAME];
        for n in 0..=widest {
            let src = worst.get(..n).expect("a slice of the fixture");
            let encoded =
                crate::cobs::encode(src, &mut dst).expect("the fixture buffer is a frame");
            let bound = max_encoded_len(n);
            assert!(encoded <= bound, "encoder beat its own bound at n = {n}");
            assert!(
                encoded > n,
                "COBS always costs at least one byte, at n = {n}"
            );
        }
    }

    /// A page is not a frame — it travels inside one, under an envelope, a wrapper and a MAC. An
    /// earlier revision put 1024 bytes of page inside a 1024-byte payload, which cannot happen.
    #[test]
    fn a_log_page_is_not_a_payload() {
        assert_eq!(LOG_PAGE_HEADROOM, 964, "the document derives 964");
        assert!(
            log_page_frame_bytes(MAX_LOG_PAGE_BYTES) <= MAX_PAYLOAD,
            "the page must fit under its own overhead"
        );
        assert!(
            log_page_frame_bytes(MAX_PAYLOAD) > MAX_PAYLOAD,
            "a page the size of a payload is the revision this test remembers"
        );
    }

    /// The page keeps a margin for the same reason the channel cap does: `LogPage` gaining a key
    /// must not turn a page that was legal yesterday into one that cannot be sent.
    #[test]
    fn the_log_page_keeps_a_margin_for_a_page_that_gains_a_key() {
        let margin = LOG_PAGE_HEADROOM
            .checked_sub(MAX_LOG_PAGE_BYTES)
            .expect("the page must sit below its headroom");
        assert_eq!(margin, 68, "896 under a headroom of 964");
    }

    /// An operation is signed, and the signature travels with it. If the operation could fill a
    /// payload there would be nothing left for the body that proves it was not forged.
    ///
    /// The margin is against the body *and* the envelope. Written as
    /// `MAX_PAYLOAD - MAX_OPERATION == 64` first, which is a subtraction rather than a derivation:
    /// it stays true if the body doubles.
    #[test]
    fn an_operation_leaves_room_for_the_body_and_the_envelope_that_sign_it() {
        assert_eq!(
            MAX_OPERATION_CEILING, 975,
            "1024 less 38 of body and 11 of envelope"
        );
        let spent = MAX_OPERATION
            .checked_add(SIGNED_BODY_BYTES)
            .and_then(|n| n.checked_add(ENVELOPE_BYTES))
            .expect("a signed request must not overflow a usize");
        assert_eq!(
            spent, 1009,
            "960 of operation under 38 of body and 11 of envelope"
        );
    }

    /// Fifteen spare bytes is what absorbs the signed body gaining a key. It is one of the three
    /// bodies whose MAC covers fields rather than an encoding, so a later key enters the preimage
    /// and these bytes — and without the margin, adding one turns a legal operation into a frame
    /// the controller refuses with error 5.
    ///
    /// The check here before this was `greedy + SIGNED_BODY_BYTES + ENVELOPE_BYTES > MAX_PAYLOAD`,
    /// where `greedy` had just subtracted `SIGNED_BODY_BYTES` — so it reduced to
    /// `ENVELOPE_BYTES > 0`, and was true for every value of the cap it claimed to guard.
    #[test]
    fn the_operation_cap_keeps_a_margin_for_a_body_that_gains_a_key() {
        let margin = MAX_OPERATION_CEILING
            .checked_sub(MAX_OPERATION)
            .expect("the cap must sit below its ceiling, not above it");
        assert_eq!(margin, 15, "960 under a ceiling of 975");

        let widened = SIGNED_BODY_BYTES.saturating_add(10);
        assert!(
            MAX_OPERATION + widened + ENVELOPE_BYTES <= MAX_PAYLOAD,
            "a body ten bytes wider must still fit at the cap, which is what the margin is for"
        );
    }

    /// A capacity of zero is a controller nobody can talk to, and it would report the zero
    /// cheerfully. The failure is silent on the wire and only visible as a site that never answers.
    ///
    /// **Every `pub const` in this file belongs in the list below.** The first version of this
    /// test named six of the eleven, and `MAX_DEPTH` — whose whole job is stopping a hostile
    /// message walking off the stack — could be raised to 255 with the suite still green. A list
    /// that has to be extended by hand is one somebody forgets to extend, which is the same
    /// failure CLAUDE.md records twice already: a check that ran, reported success, and was
    /// comparing a truncated set.
    #[test]
    fn a_reported_capacity_of_zero_would_lock_every_client_out() {
        // Each constant is checked in its own type, so nothing is cast on the way in — a
        // `u64` narrowed to `usize` is a truncation on the 32-bit part this ships on. The name
        // comes from the same identifier as the value, so an entry cannot name one constant and
        // measure another, which the pair-of-literals form allowed and nothing checked.
        macro_rules! every {
            ($($name:ident),* $(,)?) => {
                $(assert!(
                    $name > 0,
                    concat!(stringify!($name), " must be at least one")
                );)*
            };
        }
        every![
            MAX_PAYLOAD,
            MAX_FRAME,
            MAX_OPERATION,
            MAX_LOG_PAGE_BYTES,
            MAX_LOG_PAGE_ENTRIES,
            MAX_OPERATION_CEILING,
            MAX_EVENT_BODY,
            MAX_STRING,
            MAX_DEPTH,
            MAX_SESSIONS,
            MAX_CHANNELS,
            MAX_CLIENTS,
            MAX_EVENT_QUEUE,
            MAX_INFLIGHT,
            MAX_CMD_DEDUP,
            MAX_CHALLENGES,
            MAX_AUTH_FAILURES,
            ENVELOPE_BYTES,
            SIGNED_BODY_BYTES,
            INNER_BODY_BYTES,
            MAX_SERIES_LEN,
            MAX_LABEL,
            MAX_LINK_TEXT,
            MAX_IDENT,
            MAX_ADDR,
            MAX_ROW_BYTES,
            MAX_SAMPLES,
            MAX_SERIES,
            MAX_READINGS_BYTES,
            MAX_INVENTORY_PAGE_ROWS,
            MAX_INVENTORY_PAGE_BYTES,
            MAX_CONCERN_PAGE_ROWS,
            MAX_CONCERN_PAGE_BYTES,
            MAX_HISTORY_POINTS,
            MAX_COMPONENT_CMDS,
            MAX_VALIDITY_SWEEP,
            MAX_PRESENCE_SWEEP,
            MAX_CONCERN_EVENTS_PER_TICK,
            MIN_REV_INTERVAL_MS,
            MAX_BUSES,
            MAX_DEVICES,
            MAX_COMPONENTS,
            MAX_SIGNALS,
            MAX_SERIES_ELEMENTS,
            MAX_PARAMS,
            MAX_CONCERNS,
            MAX_SELECTORS,
            MAX_HISTORY_SIGNALS,
            MAX_TOPOLOGY_DEPTH,
            MAX_CONCERNS_BELOW_FAULT,
            READINGS_HEADER_BYTES,
            INVENTORY_HEADER_BYTES,
            CONCERNS_HEADER_BYTES,
            SAMPLE_CEILING,
            SERIES_CEILING,
            SAMPLE_MAX_BYTES,
            SERIES_MAX_BYTES,
            CONCERN_MAX_BYTES,
            VCHANGE_MAX_BYTES,
            PCHANGE_MAX_BYTES,
            CONCERN_CEILING,
            INVENTORY_PAGE_ROWS_CEILING,
            POINT_CEILING,
            SWEEP_CEILING,
            CLASS_A_TICK_CEILING,
        ];
    }

    /// The framing split must not move a single existing answer. That is the whole claim of the
    /// commit that made it, and the other tests in this file check it from the far end — this one
    /// checks the three new constants add up to the two they replaced.
    #[test]
    fn the_framing_split_reproduces_the_pair_it_replaced() {
        assert_eq!(RESPONSE_FRAMING_BYTES, 34, "11 + 22 + 1, the old 11 + 23");
        assert_eq!(
            REQUEST_FRAMING_BYTES, 33,
            "a request type is one CBOR byte, so it is a byte cheaper — which the old pair could not say"
        );
        assert_eq!(INNER_BODY_BYTES, 990, "1024 less a response's framing");
        assert_eq!(
            MAX_EVENT_BODY, 965,
            "unchanged, and now exact: an Event 0x04 pays request framing, and the byte the old \
             pair double-counted is the event record's own map header"
        );
    }

    /// Every topology ceiling and the margin the document states under it.
    ///
    /// A margin is the difference between a cap and what carries it, and it is the thing that
    /// absorbs a body gaining a key. Written out here because a margin nobody named is a margin
    /// the next person spends without knowing it was there.
    #[test]
    fn every_topology_cap_sits_under_its_ceiling_by_the_stated_margin() {
        let margins = [
            ("MAX_SAMPLES", SAMPLE_CEILING, MAX_SAMPLES, 47, 7),
            ("MAX_SERIES", SERIES_CEILING, MAX_SERIES, 8, 1),
            (
                "MAX_CONCERN_PAGE_ROWS",
                CONCERN_CEILING,
                MAX_CONCERN_PAGE_ROWS,
                15,
                3,
            ),
            (
                "MAX_HISTORY_POINTS",
                POINT_CEILING,
                MAX_HISTORY_POINTS,
                113,
                17,
            ),
            (
                "MAX_VALIDITY_SWEEP",
                SWEEP_CEILING,
                MAX_VALIDITY_SWEEP,
                86,
                38,
            ),
            (
                "MAX_INVENTORY_PAGE_ROWS",
                INVENTORY_PAGE_ROWS_CEILING,
                MAX_INVENTORY_PAGE_ROWS,
                146,
                98,
            ),
        ];
        for (name, ceiling, cap, want_ceiling, want_margin) in margins {
            assert_eq!(ceiling, want_ceiling, "{name}'s ceiling");
            let margin = ceiling
                .checked_sub(cap)
                .expect("a cap must sit below its ceiling, not above it");
            assert_eq!(margin, want_margin, "{name}'s margin");
        }
    }

    /// The byte caps against their headrooms, and the widest response each one produces.
    ///
    /// `MAX_LOG_PAGE_BYTES` keeps 68 under its 964; these keep the same order of margin for the
    /// same reason, and the numbers are the ones the design document prints.
    #[test]
    fn every_widest_response_fits_a_payload_with_the_headroom_claimed() {
        let widest = [
            (
                "Readings",
                READINGS_HEADER_BYTES,
                MAX_READINGS_BYTES,
                948,
                68,
                956,
            ),
            (
                "Inventory",
                INVENTORY_HEADER_BYTES,
                MAX_INVENTORY_PAGE_BYTES,
                958,
                78,
                946,
            ),
            (
                "Concerns",
                CONCERNS_HEADER_BYTES,
                MAX_CONCERN_PAGE_BYTES,
                957,
                125,
                899,
            ),
        ];
        for (name, header, cap, want_headroom, want_margin, want_widest) in widest {
            let headroom = INNER_BODY_BYTES - header;
            assert_eq!(headroom, want_headroom, "{name} headroom");
            assert_eq!(headroom - cap, want_margin, "{name} margin");
            let response = RESPONSE_FRAMING_BYTES + header + cap;
            assert_eq!(response, want_widest, "{name} widest response");
            assert!(response <= MAX_PAYLOAD, "{name} must fit a payload");
        }

        // History carries no separate byte cap: its bucket count is the only arm.
        let history =
            HISTORY_FIXED_BYTES + (MAX_HISTORY_POINTS * HISTORY_POINT_EIGHTHS).div_ceil(8);
        assert_eq!(history, 845, "the widest History body");
        assert_eq!(
            INNER_BODY_BYTES - history,
            145,
            "History keeps the widest margin of the four"
        );
        assert_eq!(RESPONSE_FRAMING_BYTES + history, 879, "widest History");
    }

    /// A burst this design can produce must not fill a session's queue in one tick.
    ///
    /// The margin of nine is **not** headroom for a later kind — it is what the sixteen existing
    /// class A kinds have to fit in, and none of them is bounded yet. The test says so, because a
    /// number that looks like slack gets spent as slack.
    #[test]
    fn one_tick_of_this_design_cannot_fill_a_session_queue() {
        assert_eq!(
            CLASS_A_TICK_CEILING, 7,
            "0x0102 + 0x0902 + 4 concern + 0x0901"
        );
        let left = MAX_EVENT_QUEUE
            .checked_sub(CLASS_A_TICK_CEILING)
            .expect("this design alone must not exceed the queue");
        assert_eq!(left, 9, "what the sixteen unbounded kinds must fit in");
    }

    /// The list above is the one whose comment says it must never be short. It went short once,
    /// and naming six of eleven let `MAX_DEPTH` be raised to 255 with the whole suite green.
    ///
    /// So it is no longer trusted to a person. This reads the file back and asserts every exported
    /// constant in it is named in the list — which is the difference between a rule somebody
    /// remembers and a rule that goes red. Add a `pub const` and forget the list, and this fails
    /// here, naming the constant that is missing.
    #[test]
    fn every_exported_constant_is_named_in_the_zero_check() {
        let source = include_str!("limits.rs");
        let listed = source
            .split("every![")
            .nth(1)
            .and_then(|rest| rest.split("];").next())
            .expect("the zero-check list is in this file, in the macro form");

        for line in source.lines() {
            let trimmed = line.trim_start();
            let Some(rest) = trimmed
                .strip_prefix("pub const ")
                .or_else(|| trimmed.strip_prefix("pub(crate) const "))
            else {
                continue;
            };
            let name = rest
                .split(':')
                .next()
                .expect("a const declaration names something")
                .trim();

            // Matched with the trailing comma so `MAX_SERIES` cannot be satisfied by
            // `MAX_SERIES_ELEMENTS` sitting in the list — a prefix is not a member.
            let mut found = false;
            for entry in listed.split(',') {
                if entry.trim() == name {
                    found = true;
                    break;
                }
            }
            assert!(
                found,
                "{name} is exported and is not in the zero check — the list this test exists to \
                 stop going short has gone short again"
            );
        }
    }

    /// P-003 refuses rather than evicts, so the dedup table has to be wide enough to hold one entry
    /// per request that can legally be in flight. Narrower, and a busy site evicts an entry a retry
    /// still needs — which is how the same command starts the generator twice.
    #[test]
    fn the_dedup_table_holds_every_request_that_can_be_in_flight_at_once() {
        let live = MAX_SESSIONS
            .checked_mul(MAX_INFLIGHT)
            .expect("the in-flight total must not overflow");
        // Equality rather than `>=`: under `>=`, halving MAX_SESSIONS or MAX_INFLIGHT still
        // satisfies it, so the test stood behind neither of the numbers it is about.
        assert_eq!(
            MAX_CMD_DEDUP, live,
            "{MAX_CMD_DEDUP} dedup entries against {live} in-flight requests"
        );
    }
}
