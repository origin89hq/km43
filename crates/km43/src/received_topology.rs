//! P-202 on the receiving side: an `addr` wherever the bus addresses, and never
//! the same one twice on a bus, judged across every page of one walk.
//!
//! The transport lives on a `BusRow` and the address on a `DeviceRow`, and a
//! client fetches the two tables in whatever order it likes, so no single page
//! can be judged alone. Each page is applied to a copy of what is held and the
//! copy is checked after every row; it replaces what is held only if it
//! passes, so a page that breaks P-202 is refused and leaves nothing behind.
//!
//! A device whose `BusRow` never arrives is outside P-202 and is held
//! unjudged. Its `addr` still counts against the others on that bus number.

use crate::cbor::CborReader;
use crate::generated::Transport;
use crate::inventory::{
    BUS_ROW_BUS_KEY, BUS_ROW_TRANSPORT_KEY, Closed, DEVICE_ROW_ADDR_KEY, DEVICE_ROW_BUS_KEY,
    DEVICE_ROW_DEV_KEY, InventoryError, InventoryHeader, InventoryOutcome, Row, RowKind, RowSlots,
    Value,
};
use crate::limits::{MAX_ADDR, MAX_DEVICES};

/// Every number a `bus` can carry. Held by number rather than up to a cap,
/// because `max_buses` is the peer's to report (P-005) and a `u8` is the most
/// it can say.
const BUS_NUMBERS: usize = 1 << u8::BITS;

/// The device capacity a controller built from this crate needs: its
/// [`MAX_DEVICES`] and its own row at `dev 0`. A client talking to a controller
/// that reports a larger `max_devices` sizes [`ReceivedTopology`] from that.
pub const HELD_DEVICES: usize = MAX_DEVICES + 1;

/// One `addr`, copied out of the page it arrived in so the next page can be
/// compared against it. Zero-filled past `len`, which is what makes the
/// derived `PartialEq` compare two addresses and not two lots of leftovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeldAddr {
    bytes: [u8; MAX_ADDR],
    len: u8,
}

impl HeldAddr {
    fn new(addr: &[u8]) -> Result<Self, InventoryError> {
        let too_long = InventoryError::AddrTooLong(addr.len());
        let mut bytes = [0u8; MAX_ADDR];
        bytes
            .get_mut(..addr.len())
            .ok_or(too_long)?
            .copy_from_slice(addr);
        let len = u8::try_from(addr.len()).map_err(|_| too_long)?;
        Ok(Self { bytes, len })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HeldDevice {
    dev: u16,
    bus: u8,
    addr: Option<HeldAddr>,
}

/// What a client has received of one walk's buses and devices, enough to
/// judge P-202 over all of it.
///
/// `DEVICES` is how many device rows it holds. Size it from the `max_devices`
/// the controller reported in `Hello` plus one for `dev 0`: a walk naming
/// more is refused with [`InventoryError::TooManyDevices`], never trimmed.
///
/// Held per `rev`: a page at another revision starts the walk again, because
/// a row from before the move says nothing about the topology after it. The
/// same `bus` or `dev` arriving twice replaces its own entry, so a page
/// fetched again after a lost response is not two devices at one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedTopology<const DEVICES: usize = HELD_DEVICES> {
    rev: Option<u32>,
    buses: [Option<Transport>; BUS_NUMBERS],
    devices: [Option<HeldDevice>; DEVICES],
}

impl<const DEVICES: usize> Default for ReceivedTopology<DEVICES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEVICES: usize> ReceivedTopology<DEVICES> {
    /// Nothing received yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rev: None,
            buses: [None; BUS_NUMBERS],
            devices: [None; DEVICES],
        }
    }

    /// Take one `Inventory 0x8D` body, refusing it if what it adds to the walk
    /// breaks P-202. On a refusal nothing it carried is held, and the page
    /// that was fine before it still is.
    ///
    /// Every page goes through here, whatever its kind: the header checks run
    /// on all of them, and only bus and device pages change what is held.
    pub fn page(&mut self, payload: &[u8]) -> Result<InventoryHeader, InventoryError> {
        let (header, rows) = InventoryHeader::decode_with_rows(payload)?;
        let Some(kind) = RowKind::from_number(header.what) else {
            return Ok(header);
        };
        let holds = match kind {
            RowKind::Bus | RowKind::Device => matches!(header.outcome, InventoryOutcome::Ok),
            RowKind::Component | RowKind::Signal | RowKind::Param => false,
        };
        if !holds {
            return Ok(header);
        }
        let mut next = if self.rev == Some(header.rev) {
            *self
        } else {
            Self {
                rev: Some(header.rev),
                ..Self::new()
            }
        };
        let mut reader = CborReader::new(rows);
        let mut slots = RowSlots::new();
        for _ in 0..reader.array()? {
            let row = slots.decode(kind, reader.raw()?)?;
            next.hold(&row)?;
            // After every row and not once per page: a `dev` listed twice in
            // one page replaces its own entry, and the row it replaced has to
            // have been judged before it went.
            next.p_202_holds()?;
        }
        reader.finish()?;
        *self = next;
        Ok(header)
    }

    fn hold(&mut self, row: &Row<'_>) -> Result<(), InventoryError> {
        match row.kind() {
            RowKind::Bus => self.hold_bus(row),
            RowKind::Device => self.hold_device(row),
            RowKind::Component | RowKind::Signal | RowKind::Param => Ok(()),
        }
    }

    fn hold_bus(&mut self, row: &Row<'_>) -> Result<(), InventoryError> {
        let bus = u8_at(row, BUS_ROW_BUS_KEY)?;
        let number = u8_at(row, BUS_ROW_TRANSPORT_KEY)?;
        let transport = Transport::try_from(number).map_err(|()| InventoryError::NotAMember {
            kind: RowKind::Bus,
            key: BUS_ROW_TRANSPORT_KEY,
            space: Closed::Transport,
            value: number,
        })?;
        let slot = self
            .buses
            .get_mut(usize::from(bus))
            .ok_or(InventoryError::WrongType {
                kind: RowKind::Bus,
                key: BUS_ROW_BUS_KEY,
            })?;
        *slot = Some(transport);
        Ok(())
    }

    fn hold_device(&mut self, row: &Row<'_>) -> Result<(), InventoryError> {
        let Some(Value::U16(dev)) = row.get(DEVICE_ROW_DEV_KEY) else {
            return Err(InventoryError::WrongType {
                kind: RowKind::Device,
                key: DEVICE_ROW_DEV_KEY,
            });
        };
        let bus = u8_at(row, DEVICE_ROW_BUS_KEY)?;
        let addr = match row.get(DEVICE_ROW_ADDR_KEY) {
            None => None,
            Some(Value::Bytes(addr)) => Some(HeldAddr::new(addr)?),
            Some(
                Value::U8(_)
                | Value::U16(_)
                | Value::U32(_)
                | Value::I32(_)
                | Value::Text(_)
                | Value::U16List(_)
                | Value::Absent,
            ) => {
                return Err(InventoryError::WrongType {
                    kind: RowKind::Device,
                    key: DEVICE_ROW_ADDR_KEY,
                });
            }
        };
        let same = self
            .devices
            .iter()
            .position(|held| held.is_some_and(|held| held.dev == dev));
        let at = same
            .or_else(|| self.devices.iter().position(Option::is_none))
            .ok_or(InventoryError::TooManyDevices(DEVICES))?;
        let slot = self
            .devices
            .get_mut(at)
            .ok_or(InventoryError::TooManyDevices(DEVICES))?;
        *slot = Some(HeldDevice { dev, bus, addr });
        Ok(())
    }

    /// Both halves of P-202 over everything held, because a `BusRow` arriving
    /// late can condemn a device that was accepted pages ago.
    fn p_202_holds(&self) -> Result<(), InventoryError> {
        for (at, device) in self.devices.iter().enumerate() {
            let Some(device) = device else {
                continue;
            };
            let Some(addr) = device.addr else {
                if self.transport(device.bus).is_some_and(Transport::addressed) {
                    return Err(InventoryError::AddrMissing {
                        dev: device.dev,
                        bus: device.bus,
                    });
                }
                continue;
            };
            let later = self.devices.iter().skip(at.saturating_add(1)).flatten();
            if let Some(other) = later
                .filter(|other| other.bus == device.bus)
                .find(|other| other.addr == Some(addr))
            {
                return Err(InventoryError::AddrTwice {
                    bus: device.bus,
                    dev: device.dev,
                    other: other.dev,
                });
            }
        }
        Ok(())
    }

    fn transport(&self, bus: u8) -> Option<Transport> {
        self.buses.get(usize::from(bus)).copied().flatten()
    }
}

fn u8_at(row: &Row<'_>, key: u8) -> Result<u8, InventoryError> {
    match row.get(key) {
        Some(Value::U8(value)) => Ok(value),
        Some(
            Value::U16(_)
            | Value::U32(_)
            | Value::I32(_)
            | Value::Text(_)
            | Value::Bytes(_)
            | Value::U16List(_)
            | Value::Absent,
        )
        | None => Err(InventoryError::WrongType {
            kind: row.kind(),
            key,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{InventoryBody, Page};
    use crate::limits::MAX_INVENTORY_PAGE_BYTES;

    const REV: u32 = 41;
    const ADDRESSED: [Transport; 4] = [
        Transport::Rs485,
        Transport::Can,
        Transport::Ip,
        Transport::Onewire,
    ];
    const UNADDRESSED: [Transport; 3] =
        [Transport::VeDirect, Transport::LocalIo, Transport::Internal];

    fn bus(bus: u8, transport: Transport) -> [Value<'static>; 4] {
        [
            Value::U8(bus),
            Value::U8(transport as u8),
            Value::Absent,
            Value::Absent,
        ]
    }

    fn device(dev: u16, bus: u8, addr: Option<&'static [u8]>) -> [Value<'static>; 13] {
        [
            Value::U16(dev),
            Value::U8(bus),
            addr.map_or(Value::Absent, Value::Bytes),
            Value::U16(1),
            Value::U16(1),
            Value::U16(1),
            Value::Absent,
            Value::Absent,
            Value::Absent,
            Value::Absent,
            Value::Absent,
            Value::U32(1),
            Value::Absent,
        ]
    }

    struct Body {
        bytes: [u8; MAX_INVENTORY_PAGE_BYTES + 64],
        len: usize,
    }

    impl Body {
        fn of<const N: usize>(rev: u32, kind: RowKind, rows: &[[Value<'_>; N]]) -> Self {
            let mut page = Page::new(kind);
            for (id, values) in rows.iter().enumerate() {
                let row = Row::new(kind, values).expect("a legal row");
                let id = u16::try_from(id).expect("a page-sized id");
                assert!(page.push(&row, id).expect("encodes"), "the page has room");
            }
            let body = InventoryBody {
                rev,
                what: kind.number(),
                outcome: InventoryOutcome::Ok,
                total: u16::try_from(rows.len()).expect("a page-sized count"),
                page: Some(&page),
                digest: None,
            };
            let mut bytes = [0u8; MAX_INVENTORY_PAGE_BYTES + 64];
            let len = body.encode(&mut bytes).expect("encodes");
            Self { bytes, len }
        }

        fn buses<const N: usize>(rows: [[Value<'static>; 4]; N]) -> Self {
            Self::of(REV, RowKind::Bus, &rows)
        }

        fn devices<const N: usize>(rows: [[Value<'static>; 13]; N]) -> Self {
            Self::of(REV, RowKind::Device, &rows)
        }

        fn wire(&self) -> &[u8] {
            self.bytes.get(..self.len).expect("encoded")
        }
    }

    fn holding(pages: &[Body]) -> ReceivedTopology {
        let mut topology: ReceivedTopology = ReceivedTopology::new();
        for page in pages {
            topology.page(page.wire()).expect("a page P-202 accepts");
        }
        topology
    }

    /// Two chargers on one RS-485 pair and neither carrying an address are two
    /// rows a client cannot tell apart, and the same on CAN, IP and 1-Wire,
    /// where a probe's ROM code is the only thing that tells it from the next.
    #[test]
    fn p_202_required_exactly_where_rs485_can_ip_and_onewire_address() {
        for transport in ADDRESSED {
            let mut topology = holding(&[Body::buses([bus(1, transport)])]);
            let before = topology;
            assert_eq!(
                topology.page(Body::devices([device(7, 1, None)]).wire()),
                Err(InventoryError::AddrMissing { dev: 7, bus: 1 }),
                "{transport:?}"
            );
            assert_eq!(topology, before, "a refused page holds nothing");
            topology
                .page(Body::devices([device(7, 1, Some(&[0x28, 0x01]))]).wire())
                .expect("the same device with its address");
        }
    }

    /// The other half of *exactly where*: a VE.Direct port has one device on
    /// it, so a row with no address there is a whole description.
    #[test]
    fn p_202_required_exactly_where_the_bus_addresses_and_nowhere_else() {
        for transport in UNADDRESSED {
            let mut topology = holding(&[Body::buses([bus(3, transport)])]);
            let page = Body::devices([device(7, 3, None)]);
            assert_eq!(
                topology.page(page.wire()).map(|header| header.rows),
                Ok(1),
                "{transport:?}"
            );
        }
    }

    /// Which table a client fetches first is its own choice. A device page read
    /// before the bus page cannot be judged when it arrives, so the bus page
    /// that reveals the missing address is the one refused.
    #[test]
    fn p_202_required_exactly_where_judged_when_the_bus_row_arrives_second() {
        let mut topology = holding(&[Body::devices([device(7, 1, None)])]);
        let before = topology;
        assert_eq!(
            topology.page(Body::buses([bus(1, Transport::Rs485)]).wire()),
            Err(InventoryError::AddrMissing { dev: 7, bus: 1 })
        );
        assert_eq!(topology, before, "the device is still held, the bus is not");
        topology
            .page(Body::buses([bus(1, Transport::VeDirect)]).wire())
            .expect("a bus that does not address");
    }

    /// A device whose bus never arrives is outside P-202. Refusing it would
    /// refuse a correct controller for the order a client asked in.
    #[test]
    fn p_202_a_device_whose_bus_never_arrives_is_not_judged() {
        let mut topology: ReceivedTopology = ReceivedTopology::new();
        let page = Body::devices([device(7, 9, None)]);
        assert_eq!(
            topology.page(page.wire()).map(|header| header.rows),
            Ok(1),
            "nothing says bus 9 addresses"
        );
    }

    /// Two devices answering at one address: one of them is answering for both,
    /// and its numbers arrive under two serial numbers.
    #[test]
    fn p_202_one_address_on_one_bus_twice_in_a_page_is_refused() {
        let mut topology = holding(&[Body::buses([bus(1, Transport::Rs485)])]);
        let before = topology;
        assert_eq!(
            topology.page(
                Body::devices([device(7, 1, Some(&[0x02])), device(8, 1, Some(&[0x02]))]).wire()
            ),
            Err(InventoryError::AddrTwice {
                bus: 1,
                dev: 7,
                other: 8
            })
        );
        assert_eq!(topology, before);
    }

    /// Uniqueness is cross-row and so cross-page: the second device page is
    /// refused and the first one stands.
    #[test]
    fn p_202_one_address_on_one_bus_across_two_pages_is_refused_and_the_first_stands() {
        let mut topology = holding(&[
            Body::buses([bus(1, Transport::Onewire)]),
            Body::devices([device(7, 1, Some(&[0x28, 0xAA]))]),
        ]);
        let before = topology;
        assert_eq!(
            topology.page(Body::devices([device(8, 1, Some(&[0x28, 0xAA]))]).wire()),
            Err(InventoryError::AddrTwice {
                bus: 1,
                dev: 7,
                other: 8
            })
        );
        assert_eq!(topology, before);
        topology
            .page(Body::devices([device(8, 1, Some(&[0x28, 0xBB]))]).wire())
            .expect("a second probe with its own ROM code");
    }

    /// Modbus address 1 on each of two RS-485 ports is two devices.
    #[test]
    fn p_202_one_address_on_one_bus_is_not_one_address_on_two_buses() {
        let mut topology = holding(&[Body::buses([
            bus(1, Transport::Rs485),
            bus(2, Transport::Rs485),
        ])]);
        let page = Body::devices([device(7, 1, Some(&[0x01])), device(8, 2, Some(&[0x01]))]);
        assert_eq!(topology.page(page.wire()).map(|header| header.rows), Ok(2));
    }

    /// Two rows sharing a bus number share it whether or not the `BusRow` has
    /// arrived, so the duplicate is caught on the page that shows it.
    #[test]
    fn p_202_one_address_on_one_bus_is_refused_before_the_bus_row_arrives() {
        let mut topology: ReceivedTopology = ReceivedTopology::new();
        assert_eq!(
            topology.page(
                Body::devices([device(7, 4, Some(&[0x05])), device(8, 4, Some(&[0x05]))]).wire()
            ),
            Err(InventoryError::AddrTwice {
                bus: 4,
                dev: 7,
                other: 8
            })
        );
    }

    /// A client that lost a response asks for the same page again. The rows
    /// in it are the devices it already holds, not a second set at the same
    /// addresses.
    #[test]
    fn p_202_one_address_on_one_bus_counts_a_page_fetched_again_as_the_same_devices() {
        let page = Body::devices([device(7, 1, Some(&[0x01])), device(8, 1, Some(&[0x02]))]);
        let mut topology = holding(&[Body::buses([bus(1, Transport::Rs485)]), page]);
        let once = topology;
        let again = Body::devices([device(7, 1, Some(&[0x01])), device(8, 1, Some(&[0x02]))]);
        topology.page(again.wire()).expect("the same page twice");
        assert_eq!(topology, once);
    }

    /// An empty page is a kind with nothing in it, and it takes nothing away.
    #[test]
    fn p_202_an_empty_page_is_accepted_and_changes_nothing() {
        let mut topology = holding(&[
            Body::buses([bus(1, Transport::Rs485)]),
            Body::devices([device(7, 1, Some(&[0x01]))]),
        ]);
        let before = topology;
        let header = topology
            .page(Body::of::<13>(REV, RowKind::Device, &[]).wire())
            .expect("an empty page");
        assert_eq!(header.rows, 0);
        assert_eq!(topology, before);
    }

    /// Past the cap a device is refused rather than dropped: a device evicted
    /// to make room is one whose duplicate nothing would then catch.
    #[test]
    fn p_202_a_walk_past_what_a_receiver_holds_is_refused_rather_than_evicted() {
        let mut full = [device(0, 3, None); HELD_DEVICES];
        for (dev, row) in (0u16..).zip(full.iter_mut()) {
            *row = device(dev, 3, None);
        }
        let mut topology = holding(&[Body::devices(full)]);
        let before = topology;
        let past = u16::try_from(HELD_DEVICES).expect("a dev");
        assert_eq!(
            topology.page(Body::devices([device(past, 3, None)]).wire()),
            Err(InventoryError::TooManyDevices(HELD_DEVICES))
        );
        assert_eq!(topology, before);
        assert_eq!(
            topology
                .page(Body::devices([device(0, 3, None)]).wire())
                .map(|header| header.rows),
            Ok(1),
            "a held device again takes no new slot"
        );

        let mut small = ReceivedTopology::<2>::new();
        let three = Body::devices([device(1, 3, None), device(2, 3, None), device(3, 3, None)]);
        assert_eq!(
            small.page(three.wire()),
            Err(InventoryError::TooManyDevices(2))
        );
        assert_eq!(small, ReceivedTopology::<2>::new());
    }

    /// `max_buses` is the controller's to report, so a bus numbered past this
    /// crate's own eight is judged like any other rather than refused.
    #[test]
    fn p_202_required_exactly_where_on_a_bus_past_this_controllers_own_eight() {
        let mut buses = [bus(0, Transport::LocalIo); 48];
        for (number, row) in (0u8..).zip(buses.iter_mut()) {
            *row = bus(number, Transport::Rs485);
        }
        let mut topology = holding(&[Body::buses(buses), Body::buses([bus(200, Transport::Can)])]);
        assert_eq!(
            topology.page(Body::devices([device(7, 200, None)]).wire()),
            Err(InventoryError::AddrMissing { dev: 7, bus: 200 })
        );
        assert_eq!(
            topology.page(Body::devices([device(7, 47, None)]).wire()),
            Err(InventoryError::AddrMissing { dev: 7, bus: 47 })
        );
    }

    /// A `dev` listed twice in one page replaces its own entry. The first
    /// row broke P-202 and is judged before the second can hide it.
    #[test]
    fn p_202_required_exactly_where_judged_for_a_dev_listed_twice_in_one_page() {
        let mut topology = holding(&[Body::buses([bus(1, Transport::Rs485)])]);
        let before = topology;
        assert_eq!(
            topology.page(Body::devices([device(7, 1, None), device(7, 1, Some(&[0x01]))]).wire()),
            Err(InventoryError::AddrMissing { dev: 7, bus: 1 })
        );
        assert_eq!(topology, before);
    }

    /// A row from before `rev` moved says nothing about the topology after it:
    /// the device that held address 1 may be the one that was replaced.
    #[test]
    fn p_202_a_page_at_a_new_rev_starts_the_walk_again() {
        let mut topology = holding(&[
            Body::buses([bus(1, Transport::Rs485)]),
            Body::devices([device(7, 1, Some(&[0x01]))]),
        ]);
        let moved = Body::of(REV + 1, RowKind::Device, &[device(8, 1, Some(&[0x01]))]);
        assert_eq!(
            topology.page(moved.wire()).map(|header| header.rev),
            Ok(REV + 1),
            "dev 7 was of the old rev"
        );
        let unaddressed = Body::of(REV + 1, RowKind::Device, &[device(9, 1, None)]);
        assert_eq!(
            topology.page(unaddressed.wire()).map(|header| header.rows),
            Ok(1),
            "and so was bus 1's transport"
        );
    }

    #[test]
    fn a_page_of_another_kind_or_one_that_answered_nothing_changes_nothing() {
        let mut topology = holding(&[Body::buses([bus(1, Transport::Rs485)])]);
        let before = topology;
        let component = [
            Value::U16(1),
            Value::U16(7),
            Value::Absent,
            Value::U16(1),
            Value::Absent,
            Value::Absent,
            Value::Absent,
            Value::Absent,
            Value::U32(1),
        ];
        let header = topology
            .page(Body::of(REV + 1, RowKind::Component, &[component]).wire())
            .expect("a component page");
        assert_eq!(header.rows, 1);
        let nothing = InventoryBody {
            rev: REV + 1,
            what: RowKind::Device.number(),
            outcome: InventoryOutcome::OutOfRange,
            total: 0,
            page: None,
            digest: None,
        };
        let mut bytes = [0u8; 32];
        let len = nothing.encode(&mut bytes).expect("encodes");
        topology
            .page(bytes.get(..len).expect("encoded"))
            .expect("an answer with no rows");
        assert_eq!(topology, before);
    }

    #[test]
    fn an_addr_past_max_addr_is_refused_rather_than_cut_to_fit() {
        let mut topology: ReceivedTopology = ReceivedTopology::new();
        assert_eq!(
            topology.page(Body::devices([device(7, 1, Some(&[0xAA; MAX_ADDR + 1]))]).wire()),
            Err(InventoryError::AddrTooLong(MAX_ADDR + 1))
        );
        topology
            .page(Body::devices([device(7, 1, Some(&[0xAA; MAX_ADDR]))]).wire())
            .expect("an address at MAX_ADDR");
    }

    /// A resynchronising receiver hands this arbitrary bytes. Every cut of a
    /// good page is refused, and none of them leaves a row behind.
    #[test]
    fn a_page_cut_short_at_any_byte_is_refused_and_holds_nothing() {
        let page = Body::devices([device(7, 1, Some(&[0x01])), device(8, 1, None)]);
        let wire = page.wire();
        let mut topology = holding(&[Body::buses([bus(1, Transport::VeDirect)])]);
        let before = topology;
        for cut in 0..wire.len() {
            let short = wire.get(..cut).expect("a prefix");
            assert!(topology.page(short).is_err(), "cut at {cut}");
            assert_eq!(topology, before, "cut at {cut}");
        }
        topology.page(wire).expect("the whole page");
    }
}
