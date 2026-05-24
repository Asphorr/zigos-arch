// Post-init integrity hashing of CPU descriptor tables: GDT, IDT, all TSSs.
//
// Each of these is set up once during boot, then must never change. A wild
// write into GDT/IDT/TSS surfaces eventually as #GP / #PF / triple-fault in
// some unrelated code path — by which point the original cause is long
// gone. Hashing them after init and re-verifying on a 1Hz scan tells us
// EXACTLY WHEN something scribbles on them.
//
// Cost: ~5 KB to hash per verify (4 KB IDT + 56 B GDT + N × 104 B TSSs).
// FNV-1a over byte streams = microseconds. Called from pcb_invariants 1Hz
// scan so it's effectively free.
//
// Caveats:
//   - TSS.RSP0 is updated on every user→kernel transition (setTssRsp0).
//     We hash the TSS EXCLUDING the rsp0 field; it's the rest that should
//     stay frozen.
//   - The IDT entries[] is technically also where ww_entries/dyn_handlers
//     and other late-bound state lives, but those are SEPARATE state — the
//     IDT entries themselves are fixed after init.

const std = @import("std");
const gdt = @import("../cpu/gdt.zig");
const idt = @import("../cpu/idt.zig");
const smp = @import("../cpu/smp.zig");
const serial = @import("serial.zig");

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

inline fn fnv1a(seed: u64, bytes: []const u8) u64 {
    var h = seed;
    for (bytes) |b| {
        h ^= b;
        h *%= FNV_PRIME;
    }
    return h;
}

var initialized: bool = false;
var baseline_gdt: u64 = 0;
var baseline_idt: u64 = 0;
var baseline_tss: [smp.MAX_CPUS]u64 = [_]u64{0} ** smp.MAX_CPUS;
var verify_count: u64 = 0;
var mismatch_count: u64 = 0;

// TSS layout (gdt.Tss64, 104 bytes):
//   offset  0..4   reserved
//   offset  4..12  rsp0   <- mutates on every user→kernel
//   offset 12..104 rest   <- should be frozen
// We hash the rest, skipping rsp0.
const TSS_HASH_SKIP_LO: usize = 4;
const TSS_HASH_SKIP_HI: usize = 12;

fn hashTssSkippingRsp0(tss_bytes: []const u8) u64 {
    var h = FNV_OFFSET;
    h = fnv1a(h, tss_bytes[0..TSS_HASH_SKIP_LO]);
    h = fnv1a(h, tss_bytes[TSS_HASH_SKIP_HI..]);
    return h;
}

/// Snapshot the current GDT/IDT/TSS state as the baseline. Call exactly
/// once, after smp.init() has finished bringing up all APs and each AP
/// has installed its own GDT/IDT/TSS via `lgdt`/`lidt`/`ltr`.
pub fn captureBaseline() void {
    baseline_gdt = fnv1a(FNV_OFFSET, gdt.entriesBytes());
    baseline_idt = fnv1a(FNV_OFFSET, idt.entriesBytes());
    for (0..smp.MAX_CPUS) |i| {
        if (!@atomicLoad(bool, &smp.cpus[i].alive, .acquire)) {
            baseline_tss[i] = 0;
            continue;
        }
        const tss_ptr: [*]const u8 = @ptrCast(&smp.cpus[i].tss);
        const tss_bytes = tss_ptr[0..@sizeOf(@TypeOf(smp.cpus[i].tss))];
        baseline_tss[i] = hashTssSkippingRsp0(tss_bytes);
    }
    initialized = true;
    var alive_cpus: u32 = 0;
    for (0..smp.MAX_CPUS) |i| if (@atomicLoad(bool, &smp.cpus[i].alive, .acquire)) {
        alive_cpus += 1;
    };
    serial.print("[desc-hash] baseline captured: gdt=0x{X:0>16} idt=0x{X:0>16} ({d} TSSs)\n", .{ baseline_gdt, baseline_idt, alive_cpus });
}

/// Re-hash and compare against baseline. Returns true if all clean.
/// Logs detailed mismatch info on first detection (so subsequent
/// 1Hz scan calls don't spam).
pub fn verify() bool {
    if (!initialized) return true;
    verify_count +%= 1;
    var ok = true;
    const got_gdt = fnv1a(FNV_OFFSET, gdt.entriesBytes());
    if (got_gdt != baseline_gdt) {
        ok = false;
        if (mismatch_count == 0) {
            serial.print("[desc-hash] !!! GDT MUTATED !!! baseline=0x{X:0>16} now=0x{X:0>16}\n", .{ baseline_gdt, got_gdt });
        }
    }
    const got_idt = fnv1a(FNV_OFFSET, idt.entriesBytes());
    if (got_idt != baseline_idt) {
        ok = false;
        if (mismatch_count == 0) {
            serial.print("[desc-hash] !!! IDT MUTATED !!! baseline=0x{X:0>16} now=0x{X:0>16}\n", .{ baseline_idt, got_idt });
        }
    }
    for (0..smp.MAX_CPUS) |i| {
        if (!@atomicLoad(bool, &smp.cpus[i].alive, .acquire)) continue;
        if (baseline_tss[i] == 0) continue;
        const tss_ptr: [*]const u8 = @ptrCast(&smp.cpus[i].tss);
        const tss_bytes = tss_ptr[0..@sizeOf(@TypeOf(smp.cpus[i].tss))];
        const got = hashTssSkippingRsp0(tss_bytes);
        if (got != baseline_tss[i]) {
            ok = false;
            if (mismatch_count == 0) {
                serial.print("[desc-hash] !!! TSS[cpu{d}] MUTATED !!! baseline=0x{X:0>16} now=0x{X:0>16}\n", .{ i, baseline_tss[i], got });
            }
        }
    }
    if (!ok) mismatch_count +%= 1;
    return ok;
}

pub fn verifyCount() u64 {
    return @atomicLoad(u64, &verify_count, .monotonic);
}
pub fn mismatchCount() u64 {
    return @atomicLoad(u64, &mismatch_count, .monotonic);
}
pub fn isInitialized() bool {
    return initialized;
}
