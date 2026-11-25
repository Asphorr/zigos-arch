//! A wait that spins, for code that cannot sleep: before the scheduler runs,
//! with interrupts off, in the middle of a device's reset sequence.
//!
//! One function, on whichever clock there is:
//!   - the TSC, once apic.init has calibrated it — from then on, for good;
//!   - before that, the PIT's channel 0, which pit.init left counting;
//!   - with neither, writes to port 0x80: about a microsecond apiece on
//!     hardware, more under a hypervisor. Too long rather than too short.
//!
//! A task that can afford to give the CPU up waits by sleeping, or polls
//! under a Deadline (util/deadline.zig); this is for the rest.

const std = @import("std");
const io = @import("../io.zig");
const apic = @import("../irq/apic.zig");
const pit = @import("pit.zig");

/// Spin for at least `n` microseconds.
pub fn us(n: u64) void {
    const per_quantum = apic.tscPerQuantumSane(); // TSC ticks in 10 ms
    if (per_quantum != 0) {
        const ticks = n *| per_quantum / 10_000;
        const start = apic.readTsc();
        while (apic.readTsc() -% start < ticks) std.atomic.spinLoopHint();
        return;
    }
    if (pit.delayUs(n)) return;
    for (0..n) |_| io.outb(0x80, 0);
}

/// Spin for at least `n` milliseconds.
pub fn ms(n: u64) void {
    us(n *| 1_000);
}
