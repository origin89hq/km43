//! Bounded BLE value fragmentation, independent of a radio or phone API.
//!
//! Adapters preserve FIFO ordering on one ATT bearer and discard these objects
//! on disconnect. A completed byte string still needs envelope decoding and
//! controller authentication; BLE reception grants no permission.
//!
//! cites: P-036, P-037, P-039

use crate::{
    BLE_INDEX_MASK, BLE_LAST_FLAG, BLE_MAX_MTU, BLE_MAX_VALUE, BLE_MIN_MTU, BLE_TIMEOUT_MS,
    MAX_PAYLOAD,
};

/// A negotiated ATT MTU, distinct from a platform's maximum value length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BleMtu(u16);

impl BleMtu {
    /// Rejects values outside the supported ATT range before sizing a buffer.
    pub fn new(mtu: u16) -> Result<Self, BleError> {
        if !(BLE_MIN_MTU..=BLE_MAX_MTU).contains(&mtu) {
            return Err(BleError::Mtu);
        }
        Ok(Self(mtu))
    }

    /// Includes KM43's two header bytes but excludes the ATT opcode and handle.
    #[must_use]
    pub fn value_len(self) -> usize {
        usize::from(self.0).saturating_sub(3).min(BLE_MAX_VALUE)
    }

    /// Uses the negotiated maximum when the adapter has no smaller value bound.
    #[must_use]
    pub fn value_limit(self) -> BleValueLimit {
        BleValueLimit(self.value_len())
    }

    /// Rejects a selected value length that exceeds this connection's ATT budget.
    pub fn select(self, value_len: usize) -> Result<BleValueLimit, BleError> {
        if value_len > self.value_len() {
            return Err(BleError::ValueLimit);
        }
        BleValueLimit::new(value_len)
    }
}

/// A selected transmit value length, including the two KM43 fragment bytes.
/// It may be smaller than the negotiated ATT budget and is frozen on enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BleValueLimit(usize);

impl BleValueLimit {
    /// Accepts a platform-reported value length without pretending it is an MTU.
    /// When the ATT MTU is also known, use `BleMtu::select` to check that bound.
    pub fn new(value_len: usize) -> Result<Self, BleError> {
        let minimum = usize::from(BLE_MIN_MTU).saturating_sub(3);
        if !(minimum..=BLE_MAX_VALUE).contains(&value_len) {
            return Err(BleError::ValueLimit);
        }
        Ok(Self(value_len))
    }

    /// Includes KM43's header; subtract it only when sizing fragment data.
    #[must_use]
    pub const fn value_len(self) -> usize {
        self.0
    }
}

/// Refusals leave no partially accepted new message in the transmit slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BleError {
    /// ATT MTU is outside the supported range.
    Mtu,
    /// Selected value length is outside GATT or negotiated ATT bounds.
    ValueLimit,
    /// Empty or oversized message, or malformed fragment value.
    Length,
    /// Fragment continuity was lost; the assembly was discarded.
    Sequence,
    /// The single transmit slot is occupied.
    Busy,
    /// The caller's destination cannot hold the next value.
    Buffer,
    /// There is no pending value to acknowledge to the fragmenter.
    Idle,
}

/// One assembly per connection and receiving direction, refusing overflow.
pub struct BleReceiver {
    bytes: [u8; MAX_PAYLOAD],
    len: usize,
    active: Option<(u8, u8, u64)>,
}

impl Default for BleReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl BleReceiver {
    /// Creates an idle receiver with no retained connection state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_PAYLOAD],
            len: 0,
            active: None,
        }
    }

    /// Clears partial bytes on disconnect, controller loss or notification disable.
    pub fn reset(&mut self) {
        self.active = None;
        self.len = 0;
    }

    /// Run from the adapter's monotonic timer even when no values arrive.
    pub fn expire(&mut self, now_ms: u64) {
        if let Some((_, _, last_ms)) = self.active
            && now_ms
                .checked_sub(last_ms)
                .is_none_or(|age| age >= BLE_TIMEOUT_MS)
        {
            self.reset();
        }
    }

    /// Returns only whole messages; rejected fragments clear any partial assembly.
    /// The borrowed bytes must be consumed before the next fragment arrives.
    pub fn receive(
        &mut self,
        value: &[u8],
        mtu: BleMtu,
        now_ms: u64,
    ) -> Result<Option<&[u8]>, BleError> {
        self.expire(now_ms);
        let result = self.append(value, mtu, now_ms);
        match result {
            Ok(true) => Ok(self.bytes.get(..self.len)),
            Ok(false) => Ok(None),
            Err(error) => {
                self.reset();
                Err(error)
            }
        }
    }

    fn append(&mut self, value: &[u8], mtu: BleMtu, now_ms: u64) -> Result<bool, BleError> {
        if value.len() < 3 || value.len() > mtu.value_len() {
            return Err(BleError::Length);
        }
        let (&id, rest) = value.split_first().ok_or(BleError::Length)?;
        let (&flags, data) = rest.split_first().ok_or(BleError::Length)?;
        let index = flags & BLE_INDEX_MASK;
        let last = flags & BLE_LAST_FLAG != 0;
        if let Some((previous, _, _)) = self.active
            && previous != id
        {
            self.reset();
        }
        match self.active {
            Some((_, expected, _)) if expected != index => return Err(BleError::Sequence),
            None if index != 0 => return Err(BleError::Sequence),
            None => self.len = 0,
            Some(_) => {}
        }
        let end = self.len.checked_add(data.len()).ok_or(BleError::Length)?;
        if !last && (index == BLE_INDEX_MASK || end >= MAX_PAYLOAD) {
            return Err(BleError::Length);
        }
        self.bytes
            .get_mut(self.len..end)
            .ok_or(BleError::Length)?
            .copy_from_slice(data);
        self.len = end;
        self.active = if last {
            None
        } else {
            Some((id, index.checked_add(1).ok_or(BleError::Sequence)?, now_ms))
        };
        Ok(last)
    }
}

/// One owned message retained until the stack accepts its final fragment.
/// Call `fragment` again after backpressure and `accepted` only after FIFO admission.
pub struct BleSender {
    bytes: [u8; MAX_PAYLOAD],
    pending: Option<BlePending>,
    next_id: u8,
}

struct BlePending {
    len: usize,
    offset: usize,
    index: u8,
    limit: BleValueLimit,
    offered: Option<usize>,
}

impl Default for BleSender {
    fn default() -> Self {
        Self::new()
    }
}

impl BleSender {
    /// Each connection begins with ID zero; no old queued values may survive it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_PAYLOAD],
            pending: None,
            next_id: 0,
        }
    }

    /// Invalid or busy admission preserves the old message and its ID.
    pub fn enqueue(&mut self, message: &[u8], limit: BleValueLimit) -> Result<(), BleError> {
        if self.pending.is_some() {
            return Err(BleError::Busy);
        }
        if message.is_empty() || message.len() > MAX_PAYLOAD {
            return Err(BleError::Length);
        }
        self.bytes
            .get_mut(..message.len())
            .ok_or(BleError::Length)?
            .copy_from_slice(message);
        self.pending = Some(BlePending {
            len: message.len(),
            offset: 0,
            index: 0,
            limit,
            offered: None,
        });
        Ok(())
    }

    /// Repeated calls return identical bytes until `accepted`; no retry advances an ID.
    pub fn fragment(&mut self, out: &mut [u8]) -> Result<usize, BleError> {
        let pending = self.pending.as_mut().ok_or(BleError::Idle)?;
        let end = pending
            .offset
            .saturating_add(pending.limit.value_len().saturating_sub(2))
            .min(pending.len);
        let data = self
            .bytes
            .get(pending.offset..end)
            .ok_or(BleError::Length)?;
        let size = data.len().checked_add(2).ok_or(BleError::Length)?;
        let value = out.get_mut(..size).ok_or(BleError::Buffer)?;
        let (id, rest) = value.split_first_mut().ok_or(BleError::Buffer)?;
        let (flags, dest) = rest.split_first_mut().ok_or(BleError::Buffer)?;
        *id = self.next_id;
        *flags = pending.index | if end == pending.len { BLE_LAST_FLAG } else { 0 };
        dest.copy_from_slice(data);
        pending.offered = Some(end);
        Ok(size)
    }

    /// Acknowledges local stack admission, never delivery or KM43 authorization.
    pub fn accepted(&mut self) -> Result<(), BleError> {
        let pending = self.pending.as_mut().ok_or(BleError::Idle)?;
        let end = pending.offered.take().ok_or(BleError::Idle)?;
        if end == pending.len {
            self.pending = None;
            self.next_id = self.next_id.checked_add(1).unwrap_or(0);
        } else {
            pending.offset = end;
            pending.index = pending.index.checked_add(1).ok_or(BleError::Sequence)?;
        }
        Ok(())
    }

    /// The adapter must also purge its stack queue before this connection is reused.
    pub fn reset(&mut self) {
        self.pending = None;
        self.next_id = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_037_selected_limit_checks_the_known_mtu_and_value_bounds() {
        let mtu = BleMtu::new(247).expect("negotiated");
        assert_eq!(mtu.value_limit().value_len(), 244);
        for length in [20, 64, 244] {
            assert_eq!(mtu.select(length).expect("fits").value_len(), length);
        }
        for length in [0, 19, 245, usize::MAX] {
            assert_eq!(mtu.select(length), Err(BleError::ValueLimit));
        }
        for length in [20, 512] {
            assert_eq!(
                BleValueLimit::new(length)
                    .expect("platform length")
                    .value_len(),
                length
            );
        }
        for length in [0, 19, 513, usize::MAX] {
            assert_eq!(BleValueLimit::new(length), Err(BleError::ValueLimit));
        }
    }

    #[test]
    fn p_037_platform_limit_stays_fixed_during_backpressure() {
        let mut tx = BleSender::new();
        let small = BleValueLimit::new(20).expect("platform limit without an MTU");
        let large = BleValueLimit::new(64).expect("new platform limit");
        tx.enqueue(&[7; 40], small).expect("queue");
        let mut out = [0; BLE_MAX_VALUE];
        assert_eq!(tx.fragment(&mut out), Ok(20));
        assert_eq!(tx.enqueue(&[8; 40], large), Err(BleError::Busy));
        assert_eq!(tx.fragment(&mut out), Ok(20));
        assert_eq!(&out[..2], &[0, 0]);
        tx.accepted().expect("first value admitted");
        assert_eq!(tx.fragment(&mut out), Ok(20));
        assert_eq!(&out[..2], &[0, 1]);
        tx.accepted().expect("second value admitted");
        assert_eq!(tx.fragment(&mut out), Ok(6));
        assert_eq!(&out[..2], &[0, BLE_LAST_FLAG | 2]);
        tx.accepted().expect("last value admitted");
        tx.enqueue(&[8; 40], large)
            .expect("next message may use a different limit");
        assert_eq!(tx.fragment(&mut out), Ok(42));
        assert_eq!(&out[..2], &[1, BLE_LAST_FLAG]);
    }

    #[test]
    fn p_037_mtu_rejects_outside_range_and_caps_attribute_length() {
        for invalid in [0, 22, 518, u16::MAX] {
            assert_eq!(BleMtu::new(invalid), Err(BleError::Mtu));
        }
        for (mtu, value) in [(23, 20), (247, 244), (515, 512), (517, 512)] {
            assert_eq!(BleMtu::new(mtu).expect("valid").value_len(), value);
        }
    }

    #[test]
    fn p_039_independent_connections_do_not_share_assembly_or_send_state() {
        let mtu = BleMtu::new(BLE_MIN_MTU).expect("minimum");
        let mut first = BleReceiver::new();
        let mut second = BleReceiver::new();
        assert_eq!(first.receive(&[0, 0, 1], mtu, 0), Ok(None));
        assert_eq!(
            second.receive(&[0, BLE_LAST_FLAG, 2], mtu, 0),
            Ok(Some(&[2][..]))
        );
        second.reset();
        assert_eq!(
            first.receive(&[0, BLE_LAST_FLAG | 1, 3], mtu, 1),
            Ok(Some(&[1, 3][..]))
        );
        let mut tx = BleSender::new();
        tx.enqueue(&[1], mtu.value_limit()).expect("queue");
        assert_eq!(tx.enqueue(&[2], mtu.value_limit()), Err(BleError::Busy));
        assert_eq!(
            second.receive(&[0, BLE_LAST_FLAG, 4], mtu, 2),
            Ok(Some(&[4][..]))
        );
    }

    #[test]
    fn p_036_fragment_boundaries_roundtrip_every_supported_message_length() {
        let message = [0xa5; MAX_PAYLOAD];
        for mtu in [23, 185, 247, 517] {
            let mtu = BleMtu::new(mtu).expect("supported MTU");
            for len in 1..=MAX_PAYLOAD {
                let mut tx = BleSender::new();
                let mut rx = BleReceiver::new();
                tx.enqueue(&message[..len], mtu.value_limit())
                    .expect("fits");
                let mut completed = false;
                let mut out = [0; BLE_MAX_VALUE];
                for _ in 0..128 {
                    match tx.fragment(&mut out) {
                        Ok(n) => {
                            let value = rx.receive(&out[..n], mtu, 0).expect("ordered fragment");
                            if let Some(bytes) = value {
                                assert!(!completed);
                                assert_eq!(bytes, &message[..len]);
                                completed = true;
                            }
                            tx.accepted().expect("offered value");
                        }
                        Err(BleError::Idle) => break,
                        Err(error) => panic!("unexpected {error:?}"),
                    }
                }
                assert!(completed, "length {len}");
                assert_eq!(tx.fragment(&mut out), Err(BleError::Idle));
            }
        }
    }
}
