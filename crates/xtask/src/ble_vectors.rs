//! BLE action traces consumed unchanged by transport adapters and host tests.
//! Expectations name the contract outcome rather than running the receiver.

use anyhow::{Context as _, Result};
use serde_json::{Value, json};

use crate::registry::Registry;
use crate::vectors::hex;

struct Trace {
    steps: Vec<Value>,
    mtu: u16,
    now: u64,
}

impl Trace {
    fn step(&mut self, action: &str, input: &[u8], expected: &str, output: &[u8]) {
        self.steps.push(
            json!({"action": action, "mtu": self.mtu, "now_ms": self.now,
            "input": hex(input), "expected": expected, "output": hex(output)}),
        );
    }

    fn reset(&mut self, name: &str) {
        self.now = 0;
        self.step("reset", &[], name, &[]);
    }

    fn receive(&mut self, packet: &[u8], expected: &str, output: &[u8]) {
        self.step("receive", packet, expected, output);
    }

    fn malformed(&mut self, reg: &Registry) -> Result<()> {
        let last = reg.ble.last_flag;
        self.reset("malformed_values");
        for data in [vec![], vec![0], vec![0, last], vec![0; 21]] {
            self.receive(&[0, 0, 1], "pending", &[]);
            self.receive(&data, "length", &[]);
            self.receive(&[0, last | 1, 2], "sequence", &[]);
        }
        self.reset("index_exhaustion");
        for index in 0..=reg.ble.index_mask {
            self.receive(
                &[0, index, 1],
                if index == reg.ble.index_mask {
                    "length"
                } else {
                    "pending"
                },
                &[],
            );
        }
        self.reset("last_index_is_legal_when_final");
        for index in 0..reg.ble.index_mask {
            self.receive(&[0, index, 1], "pending", &[]);
        }
        self.receive(&[0, last | reg.ble.index_mask, 1], "message", &[1; 128]);
        self.reset("payload_overflow");
        let packet = [0u8; 20];
        for index in 0..56u8 {
            let mut p = packet;
            *p.get_mut(1).context("flags")? = index;
            self.receive(&p, "pending", &[]);
        }
        let mut p = packet;
        *p.get_mut(1).context("flags")? = last | 0x38;
        self.receive(&p, "length", &[]);
        Ok(())
    }

    fn transfer(&mut self, data: &[u8], id: u8, reg: &Registry, deliver: bool) -> Result<()> {
        self.step("enqueue", data, "ok", &[]);
        let chunks = data.chunks(
            usize::from(self.mtu)
                .saturating_sub(3)
                .min(512)
                .saturating_sub(2),
        );
        let count = chunks.len();
        for (index, chunk) in chunks.enumerate() {
            let last = index.checked_add(1) == Some(count);
            let flags = u8::try_from(index)? | if last { reg.ble.last_flag } else { 0 };
            let mut packet = vec![id, flags];
            packet.extend_from_slice(chunk);
            self.step("fragment", &[], "ok", &packet);
            self.step("fragment", &[], "ok", &packet); // stack busy: identical retry
            self.step("enqueue", &[0], "busy", &[]);
            if deliver {
                self.receive(
                    &packet,
                    if last { "message" } else { "pending" },
                    if last { data } else { &[] },
                );
            }
            self.step("accepted", &[], "ok", &[]);
        }
        Ok(())
    }
}

pub fn build(envelope: &[u8]) -> Result<Value> {
    let reg = Registry::load(&crate::check::repo_root()?)?;
    let last = reg.ble.last_flag;
    let mut t = Trace {
        steps: Vec::new(),
        mtu: 23,
        now: 0,
    };
    for mtu in [23, 185, 247, 517] {
        t.mtu = mtu;
        t.reset("full_payload_and_backpressure");
        t.transfer(&vec![0x5a; 1024], 0, &reg, true)?;
        t.transfer(envelope, 1, &reg, true)?;
    }
    t.mtu = 23;
    t.reset("missing_fragment");
    t.receive(&[0, 0, 1], "pending", &[]);
    t.receive(&[0, last | 2, 3], "sequence", &[]);
    t.receive(&[0, last | 1, 2], "sequence", &[]);
    t.receive(&[1, last, 4], "message", &[4]);
    for (name, index) in [("duplicate", 0), ("out_of_order", 2)] {
        t.reset(name);
        t.receive(&[0, 0, 1], "pending", &[]);
        t.receive(&[0, index, 2], "sequence", &[]);
        t.receive(&[0, last | 1, 3], "sequence", &[]);
        t.receive(&[1, last, 4], "message", &[4]);
    }
    t.reset("changed_id_zero_restarts_immediately");
    t.receive(&[0, 0, 1], "pending", &[]);
    t.receive(&[1, last, 2], "message", &[2]);
    t.receive(&[2, 0, 1], "pending", &[]);
    t.receive(&[3, last | 1, 2], "sequence", &[]);
    t.receive(&[3, last, 3], "message", &[3]);
    t.reset("timeout_boundary_and_refresh");
    t.receive(&[0, 0, 1], "pending", &[]);
    t.now = 4999;
    t.receive(&[0, 1, 2], "pending", &[]);
    t.now = 9998;
    t.receive(&[0, last | 2, 3], "message", &[1, 2, 3]);
    t.receive(&[1, 0, 1], "pending", &[]);
    t.now = 14998;
    t.receive(&[1, last | 1, 2], "sequence", &[]);
    t.receive(&[1, last, 4], "message", &[4]);
    t.reset("timer_without_traffic");
    t.receive(&[0, 0, 1], "pending", &[]);
    t.now = 5000;
    t.step("expire", &[], "ok", &[]);
    t.receive(&[0, last | 1, 2], "sequence", &[]);
    t.reset("clock_regression_discards");
    t.now = 10;
    t.receive(&[0, 0, 1], "pending", &[]);
    t.now = 9;
    t.receive(&[0, last | 1, 2], "sequence", &[]);
    t.reset("disconnect_discards_both_directions");
    t.receive(&[0, 0, 1], "pending", &[]);
    t.step("enqueue", &[1, 2], "ok", &[]);
    t.step("fragment", &[], "ok", &[0, last, 1, 2]);
    t.step("disconnect", &[], "ok", &[]);
    t.receive(&[0, last | 1, 2], "sequence", &[]);
    t.step("accepted", &[], "idle", &[]);
    t.transfer(&[3], 0, &reg, true)?;
    t.malformed(&reg)?;
    t.reset("transmit_refusals_preserve_id");
    t.step("enqueue", &[], "length", &[]);
    t.step("enqueue", &vec![0; 1025], "length", &[]);
    t.step("fragment", &[], "idle", &[]);
    t.step("accepted", &[], "idle", &[]);
    t.step("enqueue", &[7], "ok", &[]);
    t.step("accepted", &[], "idle", &[]);
    t.step("small_buffer", &[], "buffer", &[]);
    t.step("fragment", &[], "ok", &[0, last, 7]);
    t.step("accepted", &[], "ok", &[]);
    t.reset("ordered_wrap_under_backpressure");
    for id in 0..254 {
        t.transfer(&[id], id, &reg, true)?;
    }
    // Three accepted values stay queued across wrap, then arrive in FIFO order.
    for id in [254, 255, 0] {
        t.transfer(&[id], id, &reg, false)?;
    }
    for id in [254, 255, 0] {
        t.receive(&[id, last, id], "message", &[id]);
    }
    Ok(json!(t.steps))
}
