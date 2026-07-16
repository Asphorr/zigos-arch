// CPU thermal + power telemetry (DTS / RAPL / effective frequency).
//
// Read-only observability over the on-die sensors the rest of the kernel
// has never touched:
//   - Digital Thermal Sensor (DTS): per-core + package temperature, in °C
//     below the CPU's junction-max (Tj_max). IA32_THERM_STATUS (0x19C) /
//     IA32_PACKAGE_THERM_STATUS (0x1B1), Intel SDM Vol 3B §15.8.
//   - Thermal-event *history*: the sticky "log" bits in those same status
//     MSRs latch that a throttle/PROCHOT/critical-temp event happened since
//     the last clear — a free throttle audit with no interrupt wiring.
//   - RAPL energy counters: MSR_PKG_ENERGY_STATUS (0x611) + PP0/core
//     (0x639), sampled over an interval → watts. SDM Vol 3B §15.10.
//   - Effective delivered frequency from the IA32_APERF/IA32_MPERF ratio
//     (0xE8 / 0xE7): shows turbo (>base) or throttle (<base) vs the CPUID
//     base clock. SDM Vol 3B §15.2 "Hardware-Controlled Performance States".
//
// ── Probing, not guessing ───────────────────────────────────────────────
// Every MSR here goes through msr.rdmsrSafe, which recovers from the #GP a
// platform raises for an unimplemented register (see cpu/arch/msr.zig). So
// capability is learned by *attempting* the read: CPUID leaf 6 tells us a
// sensor is architecturally advertised, and a non-faulting read confirms
// the backing MSR actually responds. RAPL — which has no CPUID presence
// bit — is detected purely by a probe read at init. This replaces the old
// "bare-metal only / recognized-silicon only" heuristics: the telemetry now
// lights up on any host that answers the MSRs (real HW, or a hypervisor
// that emulates them) and stays silent, without faulting, where they don't.
//
// Everything here is additive and interrupt-free: no IDT/LVT changes beyond
// the shared safe-MSR fixup. The LVT thermal interrupt (async throttle
// notification) and HWP P-state *control* are the natural follow-ups.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const apic = @import("../../time/apic.zig");
const msr = @import("msr.zig");

// --- MSRs ---
const IA32_THERM_STATUS: u32 = 0x19C;
const IA32_PACKAGE_THERM_STATUS: u32 = 0x1B1;
const MSR_TEMPERATURE_TARGET: u32 = 0x1A2; // Tj_max in bits [23:16]
const IA32_MPERF: u32 = 0xE7;
const IA32_APERF: u32 = 0xE8;
const MSR_RAPL_POWER_UNIT: u32 = 0x606; // energy-status unit in bits [12:8]
const MSR_PKG_ENERGY_STATUS: u32 = 0x611; // 32-bit wrapping energy counter
const MSR_PP0_ENERGY_STATUS: u32 = 0x639; // core-domain energy counter

// --- Detection state (BSP, set once in detect()) ---
pub var supported: bool = false; // at least one sensor/counter available
pub var has_dts: bool = false; // CPUID.06H:EAX[0] + THERM_STATUS responds
pub var has_pkg_therm: bool = false; // CPUID.06H:EAX[6]
pub var has_turbo: bool = false; // CPUID.06H:EAX[1] (informational)
pub var has_hwp: bool = false; // CPUID.06H:EAX[7] (informational — future P-state control)
pub var has_arat: bool = false; // CPUID.06H:EAX[2] (always-running APIC timer)
pub var has_aperf: bool = false; // CPUID.06H:ECX[0] (IA32_APERF/MPERF present)
pub var has_rapl: bool = false; // probed: MSR_RAPL_POWER_UNIT read without #GP
pub var under_hypervisor: bool = false; // CPUID.01H:ECX[31] (informational)

pub var tj_max: u32 = 100; // junction-max °C; default when 0x1A2 unreadable
pub var base_mhz: u32 = 0; // CPUID.16H:EAX base clock (0 if leaf absent)
var energy_nj_per_unit: u64 = 0; // RAPL energy-status unit, in nanojoules

inline fn cpuid(leaf: u32, sub: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf),
          [_] "{ecx}" (sub),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

pub fn detect() void {
    const max_leaf = cpuid(0, 0).eax;
    const fms = cpuid(1, 0);
    under_hypervisor = (fms.ecx & (1 << 31)) != 0;

    if (max_leaf < 6) {
        debug.klog("[thermal] CPUID max leaf {d} < 6 — no thermal/power enum\n", .{max_leaf});
        return;
    }
    const l6 = cpuid(6, 0);
    has_turbo = (l6.eax & (1 << 1)) != 0;
    has_arat = (l6.eax & (1 << 2)) != 0;
    has_pkg_therm = (l6.eax & (1 << 6)) != 0;
    has_hwp = (l6.eax & (1 << 7)) != 0;
    has_aperf = (l6.ecx & (1 << 0)) != 0;

    // DTS: architecturally advertised by CPUID.06H:EAX[0], but confirm the
    // status MSR actually responds (a hypervisor can advertise the bit and
    // still #GP the register).
    if (l6.eax & (1 << 0) != 0) has_dts = msr.msrPresent(IA32_THERM_STATUS);

    // Base clock for the effective-frequency scale (leaf 0x16 EAX, MHz).
    if (max_leaf >= 0x16) base_mhz = cpuid(0x16, 0).eax & 0xFFFF;

    // Tj_max from MSR_TEMPERATURE_TARGET[23:16] (no CPUID gate; probe it).
    // Keep the 100 °C default if absent or out of a sane window.
    if (has_dts) {
        if (msr.rdmsrSafe(MSR_TEMPERATURE_TARGET)) |tt| {
            const t: u32 = @truncate((tt >> 16) & 0xFF);
            if (t >= 50 and t <= 125) tj_max = t;
        }
    }

    // RAPL has no CPUID presence bit — detect it by probing the unit MSR.
    if (msr.rdmsrSafe(MSR_RAPL_POWER_UNIT)) |unit| {
        has_rapl = true;
        const esu: u6 = @truncate((unit >> 8) & 0x1F); // energy-status unit exponent
        energy_nj_per_unit = 1_000_000_000 / (@as(u64, 1) << esu);
    }

    supported = has_dts or has_aperf or has_rapl;

    debug.klog(
        "[thermal] dts={s} pkg={s} aperf={s} rapl={s} hwp={s} turbo={s} Tj_max={d}C base={d}MHz{s}\n",
        .{
            yn(has_dts), yn(has_pkg_therm), yn(has_aperf), yn(has_rapl),
            yn(has_hwp), yn(has_turbo),     tj_max,        base_mhz,
            if (under_hypervisor) " (virtualized)" else "",
        },
    );
}

inline fn yn(b: bool) []const u8 {
    return if (b) "y" else "n";
}

// --- Temperature + throttle-history readout (instantaneous) ---

pub const Throttle = struct {
    // Sticky "log" bits — set once an event occurs, stay set until cleared.
    thermal: bool, // bit 1  — thermal status log (hit the DTS threshold)
    prochot: bool, // bit 3  — PROCHOT# / FORCEPR# asserted
    critical: bool, // bit 5  — out-of-spec / critical temperature
    threshold1: bool, // bit 7  — programmable threshold #1 crossed
    threshold2: bool, // bit 9  — programmable threshold #2 crossed
    power_limit: bool, // bit 11 — RAPL/power-limit throttling
    current_limit: bool, // bit 13 — current-limit throttling
    cross_domain: bool, // bit 15 — cross-domain-limit throttling

    pub fn any(self: Throttle) bool {
        return self.thermal or self.prochot or self.critical or self.threshold1 or
            self.threshold2 or self.power_limit or self.current_limit or self.cross_domain;
    }
};

fn decodeThrottle(status: u64) Throttle {
    return .{
        .thermal = (status & (1 << 1)) != 0,
        .prochot = (status & (1 << 3)) != 0,
        .critical = (status & (1 << 5)) != 0,
        .threshold1 = (status & (1 << 7)) != 0,
        .threshold2 = (status & (1 << 9)) != 0,
        .power_limit = (status & (1 << 11)) != 0,
        .current_limit = (status & (1 << 13)) != 0,
        .cross_domain = (status & (1 << 15)) != 0,
    };
}

pub const Temps = struct {
    core_c: ?i32, // per-(this-)core temperature, °C
    pkg_c: ?i32, // package temperature, °C
    tj_max: u32,
    core_throttle: ?Throttle,
    pkg_throttle: ?Throttle,
};

/// Read the DTS temperatures + throttle-history for the CURRENT core.
/// Fields stay null where the sensor is absent or the MSR faults.
pub fn readTemps() Temps {
    var out = Temps{
        .core_c = null,
        .pkg_c = null,
        .tj_max = tj_max,
        .core_throttle = null,
        .pkg_throttle = null,
    };

    if (has_dts) {
        if (msr.rdmsrSafe(IA32_THERM_STATUS)) |s| {
            // Bit 31 = reading valid; bits [22:16] = °C below Tj_max.
            if (s & (1 << 31) != 0) {
                const below: i32 = @intCast((s >> 16) & 0x7F);
                out.core_c = @as(i32, @intCast(tj_max)) - below;
            }
            out.core_throttle = decodeThrottle(s);
        }
    }
    if (has_pkg_therm) {
        if (msr.rdmsrSafe(IA32_PACKAGE_THERM_STATUS)) |s| {
            const below: i32 = @intCast((s >> 16) & 0x7F);
            out.pkg_c = @as(i32, @intCast(tj_max)) - below;
            out.pkg_throttle = decodeThrottle(s);
        }
    }
    return out;
}

// --- Interval sampling: power (watts) + effective frequency ---

const Sample = struct {
    tsc: u64,
    mperf: u64,
    aperf: u64,
    pkg_energy: u32, // raw RAPL units (wraps at 32 bits)
    pp0_energy: u32,
    valid: bool,
};

var last: ?Sample = null;

/// Cached rates from the most recent `sampleRates` — lets /proc/thermal
/// show the last live power/freq figures a `thermal` command produced,
/// without procfs itself having to spin an interval.
var last_rates: ?Rates = null;

pub const Rates = struct {
    pkg_mw: ?u64, // package power, milliwatts
    pp0_mw: ?u64, // core-domain power, milliwatts
    eff_mhz: ?u32, // effective delivered frequency (needs base_mhz)
    eff_pct: ?u32, // effective / base, percent (turbo > 100)
};

fn readSample() Sample {
    var s = Sample{ .tsc = apic.readTsc(), .mperf = 0, .aperf = 0, .pkg_energy = 0, .pp0_energy = 0, .valid = true };
    if (has_aperf) {
        s.mperf = msr.rdmsrSafe(IA32_MPERF) orelse 0;
        s.aperf = msr.rdmsrSafe(IA32_APERF) orelse 0;
    }
    if (has_rapl) {
        s.pkg_energy = @truncate(msr.rdmsrSafe(MSR_PKG_ENERGY_STATUS) orelse 0);
        s.pp0_energy = @truncate(msr.rdmsrSafe(MSR_PP0_ENERGY_STATUS) orelse 0);
    }
    return s;
}

/// Take the first of a sample pair. Pair with a short delay then
/// `sampleRates` for a power/frequency reading over the interval.
pub fn beginSample() void {
    last = readSample();
}

/// Compute rates over the interval since `beginSample`. Returns null if no
/// prior sample or the interval was degenerate. Refreshes `last` (so
/// back-to-back calls each measure their own window) and caches the result
/// for /proc/thermal.
pub fn sampleRates() ?Rates {
    const prev = last orelse return null;
    const cur = readSample();
    last = cur;

    const dt_tsc = cur.tsc -% prev.tsc;
    const dt_ms = apic.tscToMs(dt_tsc);
    if (dt_ms == 0) return null;

    var r = Rates{ .pkg_mw = null, .pp0_mw = null, .eff_mhz = null, .eff_pct = null };

    if (has_rapl and energy_nj_per_unit != 0) {
        // 32-bit energy counters wrap; the masked delta is correct for any
        // interval whose energy stays under 2^32 units (~260 kJ) — always
        // true for sub-second windows. nJ / ms = µW; /1000 = mW.
        const d_pkg: u64 = cur.pkg_energy -% prev.pkg_energy;
        const d_pp0: u64 = cur.pp0_energy -% prev.pp0_energy;
        r.pkg_mw = (d_pkg * energy_nj_per_unit) / dt_ms / 1000;
        r.pp0_mw = (d_pp0 * energy_nj_per_unit) / dt_ms / 1000;
    }

    if (has_aperf) {
        const d_mperf = cur.mperf -% prev.mperf;
        const d_aperf = cur.aperf -% prev.aperf;
        if (d_mperf != 0) {
            r.eff_pct = @intCast((d_aperf *% 100) / d_mperf);
            if (base_mhz != 0) {
                const eff = (@as(u128, base_mhz) * d_aperf) / d_mperf;
                r.eff_mhz = @intCast(@min(eff, 100_000)); // clamp absurd values
            }
        }
    }

    last_rates = r;
    return r;
}

// --- procfs /proc/thermal ---

pub fn renderProc(buf: []u8) usize {
    var n: usize = 0;
    n += fmt(buf[n..], "supported:   {s}\n", .{yn(supported)});
    n += fmt(buf[n..], "virtualized: {s}\n", .{yn(under_hypervisor)});
    n += fmt(buf[n..], "features:    dts={s} pkg_therm={s} aperf={s} rapl={s} hwp={s} turbo={s} arat={s}\n", .{
        yn(has_dts), yn(has_pkg_therm), yn(has_aperf), yn(has_rapl), yn(has_hwp), yn(has_turbo), yn(has_arat),
    });
    n += fmt(buf[n..], "tj_max_c:    {d}\n", .{tj_max});
    n += fmt(buf[n..], "base_mhz:    {d}\n", .{base_mhz});

    const t = readTemps();
    if (t.core_c) |c| n += fmt(buf[n..], "core_temp_c: {d}\n", .{c});
    if (t.pkg_c) |c| n += fmt(buf[n..], "pkg_temp_c:  {d}\n", .{c});
    if (t.core_throttle) |th| n += fmt(buf[n..], "throttle:    {s}\n", .{throttleSummary(th)});

    if (last_rates) |r| {
        if (r.pkg_mw) |mw| n += fmt(buf[n..], "pkg_power_w: {d}.{d:0>3}\n", .{ mw / 1000, mw % 1000 });
        if (r.pp0_mw) |mw| n += fmt(buf[n..], "core_power_w:{d}.{d:0>3}\n", .{ mw / 1000, mw % 1000 });
        if (r.eff_mhz) |mhz| n += fmt(buf[n..], "eff_mhz:     {d}\n", .{mhz});
        if (r.eff_pct) |pct| n += fmt(buf[n..], "eff_pct:     {d}\n", .{pct});
    } else if (has_rapl or has_aperf) {
        n += fmt(buf[n..], "power/freq:  run `thermal` for a live interval sample\n", .{});
    }
    return n;
}

var throttle_buf: [96]u8 = undefined;
fn throttleSummary(t: Throttle) []const u8 {
    if (!t.any()) return "none";
    var n: usize = 0;
    const parts = [_]struct { on: bool, name: []const u8 }{
        .{ .on = t.thermal, .name = "thermal " },
        .{ .on = t.prochot, .name = "prochot " },
        .{ .on = t.critical, .name = "critical " },
        .{ .on = t.threshold1, .name = "thresh1 " },
        .{ .on = t.threshold2, .name = "thresh2 " },
        .{ .on = t.power_limit, .name = "power-limit " },
        .{ .on = t.current_limit, .name = "current-limit " },
        .{ .on = t.cross_domain, .name = "cross-domain " },
    };
    for (parts) |p| {
        if (!p.on) continue;
        const take = @min(p.name.len, throttle_buf.len - n);
        @memcpy(throttle_buf[n..][0..take], p.name[0..take]);
        n += take;
        if (n >= throttle_buf.len) break;
    }
    return throttle_buf[0..n];
}

fn fmt(buf: []u8, comptime f: []const u8, args: anytype) usize {
    const out = std.fmt.bufPrint(buf, f, args) catch buf;
    return out.len;
}
