//! The reference clock: what the TSC clock in time.zig is pinned to, and
//! its rate measured against. The best the machine has:
//!
//!   hpet      its own crystal, the period read from the device;
//!   kvmclock  the host's clock as KVM publishes it — read without an exit;
//!   acpi_pm   the ACPI timer port, 3.579545 MHz, on any ACPI machine;
//!   none      the TSC clock keeps the rate it was calibrated at.
//!
//! Chosen once, by init(). A reference only has to count evenly between two
//! readings: where its zero is, and what S3 does to it, is time.zig's to
//! take out.

const std = @import("std");
const acpi_pm = @import("acpi_pm.zig");
const apic = @import("../irq/apic.zig");
const debug = @import("../debug/debug.zig");
const hpet = @import("hpet.zig");
const kvm = @import("../virt/kvm.zig");

pub const Kind = enum { none, hpet, kvmclock, acpi_pm };

var kind: Kind = .none; // (c) set by init

/// After hpet.init, the BSP's kvmclock record and acpi.init.
pub fn init() void {
    kind = if (hpet.isInitialized())
        .hpet
    else if (kvm.clockReady())
        .kvmclock
    else if (acpi_pm.init())
        .acpi_pm
    else
        .none;
    if (kind == .acpi_pm) {
        pm_last = acpi_pm.read();
        pm_last_tsc = apic.readTsc();
    }
    debug.klog("[time] reference clock: {s}\n", .{switch (kind) {
        .hpet => "HPET",
        .kvmclock => "kvmclock (no HPET)",
        .acpi_pm => "ACPI PM timer (no HPET)",
        .none => "none — the TSC runs at its calibrated rate",
    }});
}

pub fn which() Kind {
    return kind;
}

/// After S3, on the BSP alone, before the first reading: the reference
/// counts again. From where is unknown — the caller takes a fresh zero.
/// (kvmclock's record is re-armed with the rest of the CPU's state, and the
/// ACPI timer is the platform's to keep running.) A lock an AP held when
/// the power went is nobody's now.
pub fn afterS3() void {
    switch (kind) {
        .hpet => hpet.afterS3(),
        .acpi_pm => {
            @atomicStore(bool, &pm_lock, false, .release);
            pm_last = acpi_pm.read();
            pm_last_tsc = apic.readTsc();
        },
        .kvmclock, .none => {},
    }
}

/// The longest the reference may go unread and still count right. A counter
/// narrower than 64 bits is summed from read to read: a quarter of its wrap.
pub fn maxGapNs() u64 {
    return switch (kind) {
        .hpet => hpet.maxGapNs(),
        .acpi_pm => (@as(u64, acpi_pm.counterMask()) + 1) / 4 * std.time.ns_per_s / acpi_pm.HZ,
        .kvmclock, .none => std.math.maxInt(u64),
    };
}

/// Nanoseconds on the reference, from a zero of its own. null: there is no
/// reference, or it could not be read this time (a kvmclock record caught
/// mid-update). Interrupts off — the state behind a narrow counter is under
/// a lock a handler on this CPU must not find held. Other than on kvmclock
/// the read is an exit to the VMM under a hypervisor.
pub fn nanos() ?u64 {
    return switch (kind) {
        .none => null,
        .hpet => hpet.readNanos(),
        .kvmclock => kvm.clockNs(0),
        .acpi_pm => pmNanos(),
    };
}

// The ACPI timer is 24 or 32 bits wide: 4.7 s or 20 minutes to a wrap. Its
// ticks are summed here read to read. The clock reads it well within a wrap
// (maxGapNs); should it not, the wraps between two reads are counted from
// the TSC, whose rate is known closely enough to tell how many.
var pm_lock: bool = false;
var pm_last: u32 = 0; // counter at the last read
var pm_last_tsc: u64 = 0; // TSC at the last read
var pm_ticks: u64 = 0; // ticks since init

fn pmNanos() u64 {
    while (@cmpxchgWeak(bool, &pm_lock, false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    defer @atomicStore(bool, &pm_lock, false, .release);
    const now = acpi_pm.read();
    const tsc = apic.readTsc();
    // What the TSC makes of the time since the last read, in timer ticks;
    // 0 while its rate is unknown, and the counter is then taken at its word.
    const per_q = apic.tscPerQuantumSane(); // TSC ticks in 10 ms
    const est: u64 = if (per_q == 0) 0 else @intCast(@min(
        @as(u128, tsc -| pm_last_tsc) * acpi_pm.HZ / (@as(u128, per_q) * 100),
        std.math.maxInt(u64),
    ));
    pm_ticks +%= widenedDelta(pm_last, now, acpi_pm.counterMask(), est);
    pm_last = now;
    pm_last_tsc = tsc;
    return pm_ticks / acpi_pm.HZ * std.time.ns_per_s + pm_ticks % acpi_pm.HZ * std.time.ns_per_s / acpi_pm.HZ;
}

/// How far a counter `mask + 1` wide went from `prev` to `now`, when about
/// `est` ticks should have passed: the low bits are the counter's, the
/// wraps are the estimate's. Exact while the estimate is within half a wrap
/// of the truth.
fn widenedDelta(prev: u32, now: u32, mask: u32, est: u64) u64 {
    const seen: u64 = (now -% prev) & mask;
    if (est <= seen) return seen;
    const wrap: u64 = @as(u64, mask) + 1;
    return seen + (est - seen + wrap / 2) / wrap * wrap;
}

comptime {
    const a = std.debug.assert;
    const m24: u32 = 0xFF_FFFF;
    const w24: u64 = 0x100_0000;
    a(widenedDelta(10, 110, m24, 0) == 100); // no estimate: the counter's word
    a(widenedDelta(10, 110, m24, 103) == 100); // an estimate a little off
    a(widenedDelta(0xFF_FFF0, 0x10, m24, 0x21) == 0x20); // across one wrap, seen
    a(widenedDelta(100, 150, m24, 3 * w24 + 40) == 3 * w24 + 50); // three wraps nobody saw
    a(widenedDelta(100, 150, m24, w24 / 2 + 49) == 50); // short of half a wrap more: none
    a(widenedDelta(100, 150, m24, w24 / 2 + 50) == w24 + 50); // half a wrap more: one
    a(widenedDelta(5, 4, 0xFFFF_FFFF, 0) == 0xFFFF_FFFF);
}
