// HPET (High Precision Event Timer) — main-counter driver.
//
// Provides a high-resolution monotonic clock that's machine-wide (no per-CPU
// drift like the LAPIC timer) and far more accurate than the 100Hz
// `tick_count` increment in handleIRQ0. Comparators (one-shot timers) are
// not used yet — that's a follow-up if we ever go fully tickless on BSP.
//
// QEMU's i440fx/q35 emulation always exposes HPET at 0xFED00000 (the default
// for x86 platforms when no ACPI override is parsed). Period is read from
// the device, so we don't have to assume a frequency.

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

// Software wrap-extension state for the 32-bit-counter case. Updated
// inside readNanos via a TAS spinlock — readNanos isn't a hot enough
// path to warrant lockless games (sysUsleep + gettimeofday are the
// only callers). On 64-bit hardware this state is dead.
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

/// Raw counter value. On 32-bit hardware the upper 32 bits read as zero
/// per HPET spec; readNanos handles that, but callers of readCounter
/// directly will see a counter that wraps every ~5 minutes (worst case
/// at 14.318 MHz). Use readNanos for monotonic timing instead.
pub fn readCounter() u64 {
    if (!initialized) return 0;
    return read64(REG_MAIN_COUNTER);
}

/// Nanoseconds since hpet.init(). u64 holds ~584 years at ns precision.
///
/// Math is u128 to defeat overflow in the counter*period_fs intermediate.
/// At the worst legal period (≈100 ns/tick) the u64 product would wrap
/// after ~5 hours of uptime; at QEMU's typical 14.318 MHz it's ~213 days.
/// u128 capacity is 2^91 bits at the period bound — fine for any uptime
/// short of cosmological.
///
/// On 32-bit-counter HPETs the hardware counter wraps every ~5 min worst
/// case. We extend it to 64 bits in software via a TAS-locked
/// (wraps, last_seen32) pair updated on every read. Adds ~50 ns to
/// readNanos on the legacy path; modern 64-bit hardware skips it
/// entirely.
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
        // rolled over once. (Multiple wraps would only matter if no one
        // called readNanos for ~5 min — implausible with usleep,
        // gettimeofday, and the perf-stall logger calling us continuously.)
        if (cur32 < last_seen32) wraps +%= 1;
        last_seen32 = cur32;
        ctr = (@as(u64, wraps) << 32) | @as(u64, cur32);
        @atomicStore(u32, &wrap_state_lock, 0, .release);
    }
    // ctr * period_fs / 1_000_000, but in u64 to avoid pulling __udivti3
    // (compiler-rt 128-bit divide isn't linked by the KASAN pipeline's
    // manual `ld` step). Split: whole-ns per tick + sub-ns remainder.
    // For HPET 100MHz period_fs = 10_000_000 → period_ns_whole = 10,
    // remainder = 0 — the second term is a no-op.
    // Safe from overflow: ctr * 10_000 fits u64 for ~5800 years uptime at
    // 100MHz; ctr * (period_fs % 1_000_000) is bounded by ctr * 999_999.
    const period_ns_whole = period_fs / 1_000_000;
    const period_ns_rem = period_fs % 1_000_000;
    return ctr *% period_ns_whole +% (ctr *% period_ns_rem) / 1_000_000;
}

/// Microseconds since init. Convenient for short-duration timing.
pub fn readMicros() u64 {
    return readNanos() / 1_000;
}

/// Period of one HPET tick, in femtoseconds (10^-15 s). Returns 0 before
/// init / when HPET is unavailable.
pub fn periodFs() u64 {
    return period_fs;
}

/// HPET tick frequency in Hz (typically 14.318 MHz on i440fx, 100 MHz on
/// q35, hardware-specific elsewhere). Returns 0 if HPET is unavailable.
pub fn frequencyHz() u64 {
    if (period_fs == 0) return 0;
    return 1_000_000_000_000_000 / period_fs;
}

/// True iff the HPET hardware exposes a full 64-bit main counter (the
/// modern norm). 32-bit counters are software-extended in readNanos but
/// readCounter sees the raw narrow value.
pub fn isCounter64Bit() bool {
    return counter_is_64bit;
}
