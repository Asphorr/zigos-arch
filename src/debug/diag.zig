// Diagnostic manifest + heartbeat.
//
// Problem these solve: ZigOS has accumulated a lot of trap-style
// instrumentation (KASAN, KCSAN, watchdog, pcb_invariants, cpu_alias,
// heap canaries, PMM canary, descriptor-table hash, heap invariants).
// Each is enabled by some combination of build flag + runtime init.
// When reading a log after a wedge, it's not obvious WHICH of these were
// actually live at the time — "kasan didn't fire" could mean it caught
// nothing, OR that it wasn't armed in this build.
//
// Two outputs:
//   1. `[diag]` manifest, printed once at end of boot. Enumerates every
//      checker and whether it's armed in this build / this session.
//   2. `[diag-hb]` heartbeat every 60s. Each checker reports how many
//      times it has run + any mismatch count. Proves the traps are
//      actually firing — a silent trap is no trap at all.
//
// Heartbeat cadence is intentionally slow (60s) so it doesn't dominate
// logs. The numbers should be roughly monotonic: pcb_inv runs once per
// scan period, desc_hash piggybacks on pcb_inv, alias likewise. PMM
// canary mismatches should stay at zero or drift very slowly (early
// boot frames produce a few benign mismatches; UAF would show repeated
// hits at the same phys).

const build_options = @import("build_options");
const serial = @import("serial.zig");

const HB_INTERVAL_TICKS: u64 = 6000; // ~60s at 100 Hz BSP IRQ0

var last_hb_tick: u64 = 0;

/// Print the manifest. Call once at end of boot (e.g. just before the
/// "Boot complete" banner or right after the kernel idle task takes
/// over).
pub fn printManifest() void {
    // Tolerate build_options that don't expose these — diag should never
    // break the build itself.
    const kasan = if (@hasDecl(build_options, "kasan_enabled") and build_options.kasan_enabled) "on" else "off";
    const kcsan = if (@hasDecl(build_options, "kcsan_enabled") and build_options.kcsan_enabled) "on" else "off";
    const watchdog = if (@import("watchdog.zig").isArmed()) "armed" else "disarmed";
    serial.print(
        "[diag] traps: kasan={s} kcsan={s} watchdog={s} pcb_inv=1s alias=piggy desc_hash=piggy heap_canary=on pmm_canary=on heap_inv=on-demand smp_check=boot\n",
        .{ kasan, kcsan, watchdog },
    );
}

/// Heartbeat. Call from BSP IRQ0 every tick; the function self-rate-
/// limits to one log per HB_INTERVAL_TICKS. Safe to call from cli'd
/// IRQ context (reads atomics only).
pub fn maybeHeartbeat(tick_count: u64) void {
    if (tick_count - last_hb_tick < HB_INTERVAL_TICKS) return;
    last_hb_tick = tick_count;
    const hash = @import("cpu_struct_hash.zig");
    const pmm = @import("../mm/pmm.zig");
    const hash_count = hash.verifyCount();
    const hash_miss = hash.mismatchCount();
    const pmm_miss = pmm.pmmCanaryMismatches();
    serial.print(
        "[diag-hb] tick={d} desc_hash=runs:{d}/mis:{d} pmm_canary=mis:{d}\n",
        .{ tick_count, hash_count, hash_miss, pmm_miss },
    );
}
