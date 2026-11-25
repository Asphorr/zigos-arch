// HPET (High Precision Event Timer) — main-counter driver.
//
// A machine-wide counter at a frequency the device states itself: the first
// choice of reference for the kernel clock (refclock.zig) and for the LAPIC
// timer calibration. Not every machine has one — a firmware switch or a
// hypervisor's default can leave it out; `isInitialized` says. Comparators
// (one-shot timers) are not used.
//
// The base is the ACPI HPET table's, or 0xFED00000 where there is no table.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const paging = @import("../mm/paging.zig");
const acpi = @import("../acpi/acpi.zig");

// Architectural default base (physical). Real boards usually keep this
// and ACPI's HPET table reports the same address; on a few exotic
// platforms it differs and we honour the table's value when present.
//
// `hpet_base` stores the kernel-pointer view (physmap VA) — Phase 3
// dropped PML4[0], so dereferencing a raw phys would fault. `init`
// translates ACPI overrides through `physToVirt` before assigning.
const HPET_BASE_PHYS_DEFAULT: usize = 0xFED00000;
const HPET_SIZE: usize = 0x400;
var hpet_base: usize = paging.PHYSMAP_BASE + HPET_BASE_PHYS_DEFAULT;
var hpet_base_phys: usize = HPET_BASE_PHYS_DEFAULT;

// Register offsets (all 64-bit, naturally aligned)
const REG_GENERAL_CAP: usize = 0x000;
const REG_GENERAL_CFG: usize = 0x010;
const REG_MAIN_COUNTER: usize = 0x0F0;

// REG_GENERAL_CAP bit 13: 1 = 64-bit main counter, 0 = 32-bit. 32-bit
// HPETs are pre-2008 chipsets (some VIA EPIA, early Atom, low-end AMD);
// modern Intel/AMD + every emulator we care about ship 64-bit. We still
// handle 32-bit so anyone booting ZigOS on a relic hardware doesn't get
// silent wrong-time bugs — just slightly costlier readNanos.
const CAP_COUNT_SIZE: u64 = 1 << 13;
const CFG_ENABLE: u64 = 1 << 0;

var period_fs: u64 = 0; // counter period in femtoseconds (10^-15 s)
var initialized: bool = false;
var counter_is_64bit: bool = true;

// Software wrap-extension state for the 32-bit-counter case, behind a TAS
// lock: readNanos is called with interrupts off there (refclock.nanos), so
// no handler on the holder's CPU can come for it. On 64-bit hardware this
// state is dead.
var wrap_state_lock: u32 = 0;
var wraps: u32 = 0;
var last_seen32: u32 = 0;

inline fn read64(offset: usize) u64 {
    const ptr: *volatile u64 = @ptrFromInt(hpet_base + offset);
    return ptr.*;
}

inline fn write64(offset: usize, value: u64) void {
    const ptr: *volatile u64 = @ptrFromInt(hpet_base + offset);
    ptr.* = value;
}

pub fn init() void {
    if (acpi.getHpet()) |h| {
        if (h.address.address != 0) {
            const phys: usize = @intCast(h.address.address);
            hpet_base_phys = phys;
            hpet_base = paging.physToVirt(phys);
            if (phys != HPET_BASE_PHYS_DEFAULT) {
                debug.klog("[hpet] ACPI overrides base: phys 0x{x} -> 0x{x}\n", .{ HPET_BASE_PHYS_DEFAULT, phys });
            }
        }
    }
    paging.mapMMIO(hpet_base_phys, HPET_SIZE);

    const cap = read64(REG_GENERAL_CAP);
    period_fs = cap >> 32;
    counter_is_64bit = (cap & CAP_COUNT_SIZE) != 0;

    if (period_fs == 0 or period_fs > 100_000_000) {
        debug.klog("[hpet] Bogus period 0x{X} — disabling\n", .{period_fs});
        return;
    }

    // Reset counter to 0, then enable it.
    write64(REG_GENERAL_CFG, 0);
    write64(REG_MAIN_COUNTER, 0);
    write64(REG_GENERAL_CFG, CFG_ENABLE);

    // Seed the 32-bit wrap-extension state from the just-zeroed counter
    // so the first readNanos doesn't false-positive a wrap.
    if (!counter_is_64bit) {
        last_seen32 = 0;
        wraps = 0;
    }

    initialized = true;
    const freq_hz = 1_000_000_000_000_000 / period_fs;
    debug.klog("[hpet] Initialized: period={d}fs ({d} Hz, {s}-bit counter)\n", .{
        period_fs,
        freq_hz,
        if (counter_is_64bit) "64" else "32",
    });
}

pub fn isInitialized() bool {
    return initialized;
}

/// After S3: the platform may hand the counter back stopped, and at any
/// value. Start it; what it then reads against what it read before the
/// sleep is the caller's to take out (time.restartClock). BSP alone.
pub fn afterS3() void {
    if (!initialized) return;
    write64(REG_GENERAL_CFG, read64(REG_GENERAL_CFG) | CFG_ENABLE);
    // A lock an AP held when the power went is nobody's now.
    @atomicStore(u32, &wrap_state_lock, 0, .release);
    if (!counter_is_64bit) last_seen32 = @truncate(read64(REG_MAIN_COUNTER));
}

/// The longest the counter may go unread and still count right: a quarter
/// of a 32-bit counter's wrap, whose wraps are told by the reads.
pub fn maxGapNs() u64 {
    if (counter_is_64bit) return std.math.maxInt(u64);
    return @truncate((@as(u128, 1) << 30) * period_fs / 1_000_000);
}

/// Nanoseconds since hpet.init(). u64 holds ~584 years at ns precision.
///
/// On 32-bit-counter HPETs the hardware counter wraps every ~5 min worst
/// case. We extend it to 64 bits in software via a TAS-locked
/// (wraps, last_seen32) pair updated on every read — which has to come at
/// least once a wrap; the clock's re-anchoring (time.zig) keeps inside
/// maxGapNs.
pub fn readNanos() u64 {
    if (!initialized) return 0;
    var ctr: u64 = undefined;
    if (counter_is_64bit) {
        ctr = read64(REG_MAIN_COUNTER);
    } else {
        // Read INSIDE the lock so the (read, wrap-detect, last_seen
        // update) sequence is atomic w.r.t. other readers. If we read
        // outside the lock, a CPU whose read landed pre-wrap but who
        // grabbed the lock post-wrap (and post-other-readers updating
        // last_seen32) would see cur32 < last_seen32 and falsely bump
        // wraps. Wrap window is 5 min worst case so this is theoretical,
        // but the lock cost is ~50ns either way — pay it correctly.
        while (@cmpxchgWeak(u32, &wrap_state_lock, 0, 1, .acquire, .monotonic) != null) {
            asm volatile ("pause");
        }
        const cur32: u32 = @truncate(read64(REG_MAIN_COUNTER));
        // Wrap detect: a backwards cur32 means the hardware counter
        // rolled over once.
        if (cur32 < last_seen32) wraps +%= 1;
        last_seen32 = cur32;
        ctr = (@as(u64, wraps) << 32) | @as(u64, cur32);
        @atomicStore(u32, &wrap_state_lock, 0, .release);
    }
    // Femtoseconds per tick to nanoseconds: exact, in 128 bits.
    return @truncate(@as(u128, ctr) * period_fs / 1_000_000);
}
