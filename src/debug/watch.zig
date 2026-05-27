//! DR0-DR3 hardware watchpoint manager.
//!
//! x86_64 has 4 debug-address registers (DR0-DR3) and one control register
//! (DR7). When CPU writes/reads/executes the linear address in DRn, hardware
//! raises #DB (vector 1) and latches a sticky bit B0..B3 in DR6.
//!
//! Registers are PER-CPU, so a watch armed on BSP does NOT fire for AP
//! activity. The public `arm*` and `disarm` functions automatically
//! broadcast via IPI (`broadcastSync`) so all alive CPUs apply the new
//! `entries[]` to their DR registers within microseconds — by the time
//! the caller returns past the arm/disarm, every CPU is in sync.
//!
//! DR7 layout (only fields we use):
//!   bit 0   L0  / bit 1   G0   — slot 0 enable (local / global)
//!   bit 2   L1  / bit 3   G1   — slot 1
//!   bit 4   L2  / bit 5   G2   — slot 2
//!   bit 6   L3  / bit 7   G3   — slot 3
//!   bit 8   LE                  — legacy local-exact (recommended)
//!   bit 9   GE                  — legacy global-exact
//!   bit 10                      — reserved, must be 1
//!   bits 16-17 R/W0  / 18-19 LEN0
//!   bits 20-21 R/W1  / 22-23 LEN1
//!   bits 24-25 R/W2  / 26-27 LEN2
//!   bits 28-29 R/W3  / 30-31 LEN3
//!
//! R/W: 00=exec, 01=write, 10=I/O (CR4.DE), 11=read+write.
//! LEN: 00=1B, 01=2B, 10=8B, 11=4B.  (Yes, 8B and 4B are swapped.)
//! Address must be naturally aligned to LEN.

const std = @import("std");
const apic = @import("../time/apic.zig");
const smp = @import("../cpu/smp.zig");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");

pub const Kind = enum(u2) {
    exec = 0b00,
    write = 0b01,
    rw = 0b11,
};

pub const Len = enum(u2) {
    one = 0b00,
    two = 0b01,
    eight = 0b10,
    four = 0b11,
};

pub const Policy = enum {
    /// Dump full state, disable all watches, panic.
    panic_dump,
    /// Print one-line `[watch hit]` and continue. Useful for tracing.
    log_continue,
    /// Don't print; just clear DR6 and continue. Useful when you only care
    /// about the hit count via `entries[N].hits`.
    silent,
};

pub const WatchEntry = struct {
    armed: bool = false,
    addr: u64 = 0,
    kind: Kind = .write,
    len: Len = .eight,
    policy: Policy = .panic_dump,
    label: []const u8 = "",
    /// Whitelist suppresses hits whose RIP is inside `whitelist_sym` and
    /// within `whitelist_max_offset` bytes of its start. Empty disables.
    whitelist_sym: []const u8 = "",
    whitelist_max_offset: u32 = 0,
    /// Total hit count, including whitelisted suppressions.
    hits: u32 = 0,
    /// Value-based filter: only fire if the value at addr (post-write) is
    /// STRICTLY LESS than this. 0 disables (always fire). Used to filter
    /// out legitimate large RIP/CS writes and only surface wild small
    /// values like 0x3 / 0x40 / 0x37F.
    value_threshold: u64 = 0,
    /// CS-slot filter: when true, fire only if the value at addr is
    /// NOT 0x08 (kernel CS) AND NOT 0x23 (user CS). Used for watching
    /// the CS slot of an iretq frame — legit writes always set 0x08 or
    /// 0x23, so any other value is corruption. Catches the
    /// shifted-iretq-frame-write race where the corrupt write looks
    /// "value-plausible" but the CS slot ends up with 0x0 / wild values.
    cs_slot_check: bool = false,
    /// Non-canonical-address filter: when true, fire if the post-write
    /// value at addr is in x86_64's non-canonical range
    /// [0x00008000_00000000, 0xFFFF7FFF_FFFFFFFF]. Combined with
    /// value_threshold, catches BOTH small wild RIPs (0x3, 0x40) AND
    /// large garbage values (0xAAAAAAAAAAAAAAAA, 0x4141..., etc.) —
    /// every value that physically cannot be a real RIP.
    noncanon_check: bool = false,
    /// Skip-value filter: when non-zero, suppresses the hit if the
    /// post-write value at addr EQUALS this. Used to skip Zig's
    /// undefined-init pattern (0xAAAAAAAAAAAAAAAA) on the deep-kstack
    /// watch — these come from `var X: [N]u8 = undefined` stack-locals
    /// in fs code, NOT from the wild writer we're hunting (which zeros).
    skip_value: u64 = 0,
    /// Optional predicate: if non-null, called with the writer RIP AND the
    /// watched address, suppresses the hit when it returns true. Both args
    /// are needed because some watch types must validate not just "who
    /// wrote" but "what was written at this specific address". Example:
    /// kernel_esp watch — switchTo is a legit writer but ONLY if it stored
    /// a value belonging to the PCB it wrote into; a cross-slot value is
    /// the bug we're hunting. The predicate is called inside the #DB
    /// handler so it must be re-entrant-safe and fast (no locks, no I/O).
    whitelist_fn: ?*const fn (rip: u64, addr: u64) bool = null,
    /// kesp+48 mirror-compare: when `mirror_pid_plus1 != 0`, suppresses the
    /// hit if the post-write value at addr EQUALS
    /// `save_trace.last_save_plus48[mirror_pid_plus1 - 1]`. Use case: hunt
    /// the silent corrupter that overwrites a parked task's saved RA — every
    /// legit switchTo save updates both the slot and the mirror to the same
    /// value, so any post-write value that differs from the mirror is the
    /// bug. mirror_pid_plus1 is the pid + 1 (0 = disabled) so the default
    /// zero is "off".
    mirror_pid_plus1: u8 = 0,
    /// "Armed only while pid is parked" gate. When non-zero, the watch is
    /// only effectively armed in `computeDr7` if procs[gate_pid_parked - 1]
    /// is fully parked (state != .running AND no CPU is mid-scheduling-out
    /// of it). Used to scope DR fires to the diagnostically-interesting
    /// window (silent corruption while task is sleeping) and skip the
    /// noise / cost of #DB on every legit switchTo save. The arm/disarm
    /// is recomputed lazily in computeDr7 → applyLocal on each timer
    /// tick + on every explicit applyLocal call from save_trace_record
    /// (so the disarm-during-scheduling-out window updates the local
    /// CPU's DR7 immediately, before switchTo writes kernel_esp).
    /// 0 = disabled (always armed when .armed=true). Stored as pid+1 so
    /// the default zero is "off".
    gate_pid_parked_plus1: u8 = 0,
};

/// Canonical state. The actual DR registers on each CPU are kept in sync via
/// `applyLocal()` (called locally on arm/disarm and by the IPI handler on
/// remote CPUs).
pub var entries: [4]WatchEntry = [_]WatchEntry{.{}} ** 4;

inline fn writeDr0(addr: u64) void {
    asm volatile ("mov %[a], %%dr0"
        :
        : [a] "r" (addr),
    );
}
inline fn writeDr1(addr: u64) void {
    asm volatile ("mov %[a], %%dr1"
        :
        : [a] "r" (addr),
    );
}
inline fn writeDr2(addr: u64) void {
    asm volatile ("mov %[a], %%dr2"
        :
        : [a] "r" (addr),
    );
}
inline fn writeDr3(addr: u64) void {
    asm volatile ("mov %[a], %%dr3"
        :
        : [a] "r" (addr),
    );
}
inline fn writeDr7(val: u64) void {
    asm volatile ("mov %[v], %%dr7"
        :
        : [v] "r" (val),
    );
}
pub inline fn readDr6() u64 {
    return asm volatile ("mov %%dr6, %[r]"
        : [r] "=r" (-> u64),
    );
}
inline fn writeDr6(val: u64) void {
    asm volatile ("mov %[v], %%dr6"
        :
        : [v] "r" (val),
    );
}

/// Returns true if pid is "fully parked" — not running on any CPU AND no
/// CPU is mid-scheduling-out of it. The scheduling-out window matters
/// because the outgoing pid's state byte gets flipped to .sleeping/.ready
/// BEFORE switchTo's `movq %rsp,(%rdi)` saves its kernel_esp; if the gate
/// said "parked" then, that legit save would fire #DB and waste an
/// exception cycle on a known-good writer. save_trace_record clears
/// scheduling_out_pid right after the save, at which point we genuinely
/// want subsequent writes to the same slot to fire.
inline fn isPidFullyParked(pid: u8) bool {
    const process = @import("../proc/process.zig");
    const smp_mod = @import("../cpu/smp.zig");
    if (pid >= process.MAX_PROCS) return false;
    if (@atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire) ==
        @intFromEnum(process.State.running)) return false;
    for (&smp_mod.cpus, 0..) |*c, i| {
        if (i != 0 and !c.alive) continue;
        if (c.scheduling_out_pid == @as(u16, pid)) return false;
    }
    return true;
}

/// True iff `e` should contribute its enable bits to DR7 right now.
/// Wraps the static `.armed` flag with the dynamic
/// `gate_pid_parked_plus1` gate so a watch can opt into "only fire while
/// the watched pid is parked" semantics without rewriting the suppression
/// logic in onDebugException.
inline fn entryEffectivelyArmed(e: WatchEntry) bool {
    if (!e.armed) return false;
    if (e.gate_pid_parked_plus1 != 0) {
        return isPidFullyParked(e.gate_pid_parked_plus1 - 1);
    }
    return true;
}

/// Compute DR7 from `entries[]`. Bit 10 is reserved-must-be-1.
fn computeDr7() u64 {
    var dr7: u64 = (1 << 10);
    for (entries, 0..) |e, i| {
        if (entryEffectivelyArmed(e)) {
            const shift_en: u6 = @intCast(2 * i + 1);
            const shift_rw: u6 = @intCast(16 + 4 * i);
            const shift_len: u6 = @intCast(18 + 4 * i);
            dr7 |= @as(u64, 1) << shift_en; // Gn (global) — survives ctx-switch
            dr7 |= (1 << 8) | (1 << 9); // LE / GE
            dr7 |= @as(u64, @intFromEnum(e.kind)) << shift_rw;
            dr7 |= @as(u64, @intFromEnum(e.len)) << shift_len;
        }
    }
    return dr7;
}

// Per-CPU cache of the last-applied (DR7, addr0..3) tuple. Used by
// applyLocal to skip the 5 mov-to-DR writes (each serializing on x86,
// ~hundreds of cycles under nested-virt) when the effective state hasn't
// changed since the last application on this CPU. The save_trace_record
// path fires applyLocal on EVERY context switch — without this cache,
// 2,800 schedules/sec × 5 DR writes = ~14K mov-to-DR/sec on cpu0.
//
// Initial sentinel 0xFFFFFFFFFFFFFFFF forces a first-time write since
// DR7 is initialized to 0x400 (bit 10 reserved-set) on boot, which we
// won't otherwise match.
var last_applied_dr7: [smp.MAX_CPUS]u64 = [_]u64{0xFFFF_FFFF_FFFF_FFFF} ** smp.MAX_CPUS;
var last_applied_addrs: [smp.MAX_CPUS][4]u64 =
    [_][4]u64{[_]u64{0xFFFF_FFFF_FFFF_FFFF} ** 4} ** smp.MAX_CPUS;

/// Push the current `entries[]` to the local CPU's DR registers. Idempotent.
/// Per-CPU cached — when neither the effective DR7 (which depends on the
/// scheduling-out gate state of any kesp-gated watch) nor any of the four
/// watched addresses have changed since the last apply on this CPU, the
/// function is a 5-compare branch and 0 writes. Caller correctness is
/// preserved because computeDr7() re-evaluates entryEffectivelyArmed every
/// call — the gate state IS part of the cache key.
pub fn applyLocal() void {
    const cpu_id = smp.myCpu().cpu_id;
    const new_dr7 = computeDr7();
    const a0 = entries[0].addr;
    const a1 = entries[1].addr;
    const a2 = entries[2].addr;
    const a3 = entries[3].addr;
    if (cpu_id < smp.MAX_CPUS) {
        if (last_applied_dr7[cpu_id] == new_dr7
            and last_applied_addrs[cpu_id][0] == a0
            and last_applied_addrs[cpu_id][1] == a1
            and last_applied_addrs[cpu_id][2] == a2
            and last_applied_addrs[cpu_id][3] == a3)
        {
            return;
        }
    }
    writeDr0(a0);
    writeDr1(a1);
    writeDr2(a2);
    writeDr3(a3);
    writeDr7(new_dr7);
    if (cpu_id < smp.MAX_CPUS) {
        last_applied_dr7[cpu_id] = new_dr7;
        last_applied_addrs[cpu_id][0] = a0;
        last_applied_addrs[cpu_id][1] = a1;
        last_applied_addrs[cpu_id][2] = a2;
        last_applied_addrs[cpu_id][3] = a3;
    }
}

// ---- IPI-based cross-CPU sync (task #231) -------------------------------
// DR0-DR3 are per-CPU. The original design relied on each CPU calling
// applyLocal() on its next timer IRQ — up to 10ms delay before DRs sync.
// That's too slow for catching transient cross-CPU writers (the iretq-frame
// corruption hunt: writer fires inside an IRQ handler that lasts ~100µs,
// so by the time other CPUs' applyLocal() runs, the writer is long gone).
//
// Fix: arm/disarm broadcast an IPI to every other alive CPU. The IPI handler
// runs applyLocal() on the receiving CPU within microseconds. Now DR
// registers sync globally before the calling kernel function continues
// past arm/disarm.
//
// Vector is allocated dynamically at boot via idt.allocDynVector() and
// registered with idt.registerIrq(); kernel main calls watch.initIpi()
// after smp.init() so all alive CPUs have a working LAPIC.

var ipi_vector: ?u8 = null;

fn ipiHandler() callconv(.c) void {
    // Receiving CPU: re-apply entries[] to local DR registers.
    applyLocal();
}

/// Allocate + register the dynamic IRQ vector for DR sync. Must be called
/// AFTER smp.init() (which sets cpu.alive[]) but BEFORE the first arm()
/// that needs cross-CPU semantics. Falls back to lazy applyLocal() (the
/// original 10ms timer-tick path) if no dyn vectors are free.
pub fn initIpi() void {
    const idt = @import("../cpu/idt.zig");
    const v = idt.allocDynVector() orelse {
        serial.print("[watch] no dyn vector free — falling back to lazy DR sync\n", .{});
        return;
    };
    idt.registerIrq(v, ipiHandler);
    ipi_vector = v;
    serial.print("[watch] IPI vector 0x{X} registered for DR sync\n", .{v});
}

/// Broadcast "re-apply DR" IPI to every alive CPU except self. Called
/// after entries[] is updated locally so all CPUs converge before the
/// caller proceeds. No-op if initIpi() hasn't run yet (boot-time arms
/// from BSP fall back to local-only — fine because APs aren't running yet).
pub fn broadcastSync() void {
    const v = ipi_vector orelse return;
    const my_id = apic.getLapicId();
    for (&smp.cpus) |*cpu| {
        if (!cpu.alive) continue;
        if (cpu.lapic_id == my_id) continue;
        apic.sendIPI(cpu.lapic_id, v);
    }
}

pub fn arm(slot: u2, addr: u64, kind: Kind, len: Len, policy: Policy, label: []const u8) void {
    entries[slot] = .{
        .armed = true,
        .addr = addr,
        .kind = kind,
        .len = len,
        .policy = policy,
        .label = label,
    };
    applyLocal();
    broadcastSync();
}

pub fn armWithWhitelist(
    slot: u2,
    addr: u64,
    kind: Kind,
    len: Len,
    policy: Policy,
    label: []const u8,
    sym: []const u8,
    max_off: u32,
) void {
    entries[slot] = .{
        .armed = true,
        .addr = addr,
        .kind = kind,
        .len = len,
        .policy = policy,
        .label = label,
        .whitelist_sym = sym,
        .whitelist_max_offset = max_off,
    };
    applyLocal();
    broadcastSync();
}

/// Watch `addr` for writes; only fire when the post-write value at addr
/// is < `value_threshold`. Use case: detect wild small RIPs being written
/// to an iretq frame slot while ignoring all the legitimate large RIPs
/// the CPU pushes on every IRQ entry.
pub fn armValueThreshold(
    slot: u2,
    addr: u64,
    len: Len,
    policy: Policy,
    label: []const u8,
    value_threshold: u64,
) void {
    entries[slot] = .{
        .armed = true,
        .addr = addr,
        .kind = .write,
        .len = len,
        .policy = policy,
        .label = label,
        .value_threshold = value_threshold,
    };
    applyLocal();
    broadcastSync();
}

/// Watch `addr` for writes; suppress hits where the post-write value
/// EQUALS `skip_value`. Used to catch RA-flip corruption on a parked
/// task's saved RIP slot — the one legit value (callq's pushed RA)
/// is the just-observed `*addr` at arm time; anything else is the bug.
pub fn armSkipValue(
    slot: u2,
    addr: u64,
    len: Len,
    policy: Policy,
    label: []const u8,
    skip_value: u64,
) void {
    entries[slot] = .{
        .armed = true,
        .addr = addr,
        .kind = .write,
        .len = len,
        .policy = policy,
        .label = label,
        .skip_value = skip_value,
    };
    applyLocal();
    broadcastSync();
}

/// Watch the CS slot of an iretq frame. Fires only when the written
/// value is NOT a valid CS (neither 0x08 nor 0x23). Catches both wild
/// scrambled writes AND the shifted-frame-write race where the post-
/// write value looks plausible by magnitude but is wrong by structure.
pub fn armCsSlot(slot: u2, addr: u64, label: []const u8) void {
    entries[slot] = .{
        .armed = true,
        .addr = addr,
        .kind = .write,
        .len = .eight,
        .policy = .panic_dump,
        .label = label,
        .cs_slot_check = true,
    };
    applyLocal();
    broadcastSync();
}

pub fn disarm(slot: u2) void {
    entries[slot].armed = false;
    applyLocal();
    broadcastSync();
}

pub fn disarmAll() void {
    for (&entries) |*e| e.armed = false;
    writeDr7(0);
    writeDr6(0);
}

/// Called from idt.zig handleException for int_no==1. `rsp` is the saved-
/// frame pointer (same layout as crash dump), `saved_rip` is the writer RIP.
/// Returns true iff a watchpoint actually triggered (and so the caller
/// should skip the rest of the #DB path).
pub fn onDebugException(rsp: u64, saved_rip: u64) bool {
    const dr6 = readDr6();
    var any_hit = false;
    for (&entries, 0..) |*e, i| {
        const bit_idx: u6 = @intCast(i);
        if ((dr6 >> bit_idx) & 1 == 0) continue;
        any_hit = true;
        e.hits +%= 1;

        // Whitelist: known-legitimate writers don't crash the system.
        // Two paths:
        //   - whitelist_sym (single-symbol fast path): name + offset match
        //   - whitelist_fn (predicate, for multi-writer cases like kernel_esp
        //     which has 5 legit writers — too many for the single-sym field)
        const suppressed = blk: {
            if (e.whitelist_sym.len > 0) {
                if (symbols.resolveKernel(saved_rip)) |r| {
                    if (std.mem.eql(u8, r.name, e.whitelist_sym) and
                        r.offset <= e.whitelist_max_offset) break :blk true;
                }
            }
            if (e.whitelist_fn) |fp| {
                if (fp(saved_rip, e.addr)) break :blk true;
            }
            break :blk false;
        };
        if (suppressed) continue;

        // Value-based suppression: read the watched address. If it's >=
        // value_threshold (and threshold is non-zero), the just-written
        // value isn't "wild small" — silently skip. Catches the case of
        // watching an iretq RIP slot where every IRQ entry writes a big
        // legit RIP, but a wild write of 0x3 / 0x40 should still fire.
        if (e.value_threshold != 0) {
            const p: *const u64 = @ptrFromInt(@as(usize, @intCast(e.addr)));
            const v = p.*;
            if (v >= e.value_threshold) continue;
        }
        if (e.skip_value != 0) {
            const p: *const u64 = @ptrFromInt(@as(usize, @intCast(e.addr)));
            const v = p.*;
            if (v == e.skip_value) continue;
        }
        // kesp+48 mirror-compare: legit switchTo saves update both the slot
        // and save_trace's last_save_plus48 mirror to the same value. Any
        // post-write value that DIFFERS from the mirror is the silent
        // corrupter we're hunting (the writer RIP captured in `saved_rip`
        // names the culprit).
        //
        // Two additional guards: (a) suppress if pid is currently running/scheduling-out
        // on ANY cpu — when the task is live, RSP moves below kesp+48 and
        // new function calls (e.g., IRQ-time verifyEndCanary's push rbp)
        // legitimately reuse the slot; (b) suppress if the watched address
        // != current pcb.kernel_esp + 48 — the watch is on a stale (old)
        // kesp slot that was abandoned when the task reparked at a different
        // depth, so writes there are normal stack churn.
        if (e.mirror_pid_plus1 != 0) {
            const pid: u8 = e.mirror_pid_plus1 - 1;
            const save_trace = @import("save_trace.zig");
            const process = @import("../proc/process.zig");
            if (save_trace.isPidRunningOrSchedulingOut(pid)) continue;
            const kesp_now = @atomicLoad(usize, &process.procs[pid].kernel_esp, .acquire);
            if (kesp_now +% 48 != e.addr) continue;
            const p: *const u64 = @ptrFromInt(@as(usize, @intCast(e.addr)));
            const v = p.*;
            const mirror = save_trace.last_save_plus48[pid];
            if (v == mirror) continue;
        }
        // CS-slot filter: legit iretq frames always have CS=0x08 or 0x23.
        // Any other value is corruption (including 0x0 from shifted-frame
        // races, or 0x800005-style scrambled values).
        if (e.cs_slot_check) {
            const p: *const u64 = @ptrFromInt(@as(usize, @intCast(e.addr)));
            const v = p.*;
            if (v == 0x08 or v == 0x23) continue;
        }

        switch (e.policy) {
            .silent => {},
            .log_continue => printHit(@intCast(i), e, rsp, saved_rip, false),
            .panic_dump => {
                // Disable all watches FIRST so the dump path's own writes
                // don't recurse into #DB. (kdbg.crashAutopsy hits a lot of
                // memory.)
                writeDr7(0);
                writeDr6(0);
                // Enter panic critical section — serializes against other
                // CPUs' concurrent panics so output isn't byte-interleaved.
                @import("kdbg.zig").enterCritical();
                printHit(@intCast(i), e, rsp, saved_rip, true);
                @import("kdbg.zig").crashAutopsy(.{
                    .kernel_rsp = rsp,
                });
                @panic("watchpoint hit (panic_dump)");
            },
        }
    }
    if (any_hit) writeDr6(0); // clear sticky B0..B3
    return any_hit;
}

fn printHit(slot: u8, e: *const WatchEntry, rsp: u64, saved_rip: u64, full: bool) void {
    const cpu_id = smp.myCpu().cpu_id;
    // Read the watched address's current value. For data write traps this
    // is the value the writer just stored; for exec traps it's the bytes
    // the CPU was about to fetch.
    const cur_val: u64 = blk: {
        if (e.addr == 0) break :blk 0;
        const p: *const u64 = @ptrFromInt(@as(usize, @intCast(e.addr)));
        break :blk p.*;
    };
    const addrinfo = @import("addrinfo.zig");
    serial.print("\n!!! WATCH HIT slot={d} cpu={d} '{s}' addr=0x{X:0>16} val=0x{X:0>16} hits={d} !!!\n", .{
        slot, cpu_id, e.label, e.addr, cur_val, e.hits,
    });
    serial.print("  addr -> {s}\n", .{addrinfo.describe(@intCast(e.addr))});
    serial.print("  val  -> {s}\n", .{addrinfo.describe(@intCast(cur_val))});
    serial.print("  RIP=0x{X:0>16} -> {s}\n", .{ saved_rip, addrinfo.describe(saved_rip) });
    if (!full) return;

    // Stack layout matches idt.zig's handleException (see comment there):
    //   [0]  r15  [1]  r14  [2]  r13  [3]  r12
    //   [4]  r11  [5]  r10  [6]  r9   [7]  r8
    //   [8]  rdi  [9]  rsi  [10] rbp  [11] rbx
    //   [12] rdx  [13] rcx  [14] rax
    //   [15] int_no  [16] error_code
    //   [17] rip  [18] cs  [19] rflags  [20] rsp  [21] ss
    const stack: [*]const u64 = @ptrFromInt(rsp);
    serial.print("  RAX=0x{X:0>16} RBX=0x{X:0>16} RCX=0x{X:0>16} RDX=0x{X:0>16}\n", .{ stack[14], stack[11], stack[13], stack[12] });
    serial.print("  RSI=0x{X:0>16} RDI=0x{X:0>16} R8 =0x{X:0>16} R9 =0x{X:0>16}\n", .{ stack[9], stack[8], stack[7], stack[6] });
    serial.print("  R10=0x{X:0>16} R11=0x{X:0>16} R12=0x{X:0>16} R13=0x{X:0>16}\n", .{ stack[5], stack[4], stack[3], stack[2] });
    serial.print("  R14=0x{X:0>16} R15=0x{X:0>16}\n", .{ stack[1], stack[0] });
    serial.print("  RBP=0x{X:0>16} RSP=0x{X:0>16} RFLAGS=0x{X:0>16}\n", .{ stack[10], stack[20], stack[19] });
    serial.print("  CS =0x{X:0>4}             SS =0x{X:0>4}\n", .{ stack[18], stack[21] });

    // Code bytes at writer RIP. Cap at the next page so we don't fault on
    // an unmapped following page.
    if (saved_rip != 0) {
        const rip_page_end = (saved_rip & ~@as(u64, 0xFFF)) + 0x1000;
        const safe_len: u64 = @min(16, rip_page_end - saved_rip);
        const code: [*]const u8 = @ptrFromInt(saved_rip);
        serial.print("  Code:", .{});
        for (0..@intCast(safe_len)) |i| serial.print(" {X:0>2}", .{code[i]});
        serial.print("\n", .{});
        serial.print("  Insn: ", .{});
        @import("disasm.zig").printOne(code[0..@intCast(safe_len)]);
        serial.print("\n", .{});
    }

    // Kernel RBP backtrace. Restrict to canonical kernel range; user code
    // hitting this would be CS==0x23 (and we'd usually want a different
    // walker), but we don't bail because watch hits in user mode are still
    // informative.
    const saved_rbp = stack[10];
    // Kernel rbp is either the legacy boot stack (low phys, only alive
    // pre-enterFirstTask) or a high-half kstack (kstack_pool in kernel
    // BSS, or heap-allocated via the physmap). Anything else is junk —
    // bail before deref.
    const saved_in_low = saved_rbp >= 0x100000 and saved_rbp < 0x4000000;
    const saved_in_high = saved_rbp >= 0xFFFF_8000_0000_0000;
    if (saved_in_low or saved_in_high) {
        serial.print("  Backtrace (rbp):\n", .{});
        var rbp: u64 = saved_rbp;
        var depth: u32 = 0;
        while (depth < 16) : (depth += 1) {
            if (rbp == 0) break;
            const ok_low = rbp >= 0x100000 and rbp < 0x4000000;
            const ok_high = rbp >= 0xFFFF_8000_0000_0000;
            if (!ok_low and !ok_high) break;
            // Reject non-canonical pointers (the gap between low and high half).
            if (rbp >= 0x0000_8000_0000_0000 and rbp < 0xFFFF_8000_0000_0000) break;
            if ((rbp & 7) != 0) break; // misaligned — corrupt rbp
            const frame: [*]const u64 = @ptrFromInt(rbp);
            const ret_addr = frame[1];
            if (ret_addr == 0) break;
            serial.print("    [{d}] 0x{X:0>16}", .{ depth, ret_addr });
            if (symbols.resolveKernel(ret_addr)) |r| {
                serial.print("  {s}+0x{X}", .{ r.name, r.offset });
            }
            serial.print("\n", .{});
            const next = frame[0];
            if (next <= rbp) break;
            rbp = next;
        }
    }
}

// ----------- C.1: kernel_esp watchdog on user PIDs ----------------------
//
// The wild-RIP smoking gun (sched-ring autopsy) showed shell's saved
// kernel_esp = 0x317978 — INSIDE cat's kstack slot — i.e. cross-stack
// aliasing. The new per-PID setTssRsp0 validator confirmed kernel_stack_top
// is never corrupted, so the wild writer targets `procs[i].kernel_esp`
// instead.
//
// Coverage strategy: pin DR0-DR3 to user PIDs 3-6 (shell + 3 typical
// children — covers `cat | wc` since shell=3, cat=4, wc=5). That's the
// observed bug cluster; idle/desktop PIDs 0-2 aren't affected because
// they don't get cross-CPU-dispatched in the bug pattern.
//
// The whitelist predicate (isLegitKernelEspWriter) checks BOTH:
//   - Writer is a legit kernel_esp updater (switchTo + 4 create variants)
//   - The just-stored value is inside THIS PCB's own kstack slot (or its
//     registered heap kstack)
// Both conditions must hold. switchTo storing a CROSS-SLOT value (the bug)
// fails condition 2 → panic_dump with full RIP + backtrace.
//
// One-time arm at first call (driven from handleIRQ0 every KESP_REROTATE_TICKS
// for re-arm safety in case some other path called disarmAll). No IPI
// broadcast — handleIRQ0's lazy applyLocal propagates to other CPUs within
// one timer tick (~10ms), avoiding the IPI heisendetector that masked the
// race with the per-IRQ arm/disarm design.

// 50 = every ~500ms at 100Hz. Was briefly 1 during the 2026-05-17 netstat
// hunt to catch a fast-window kesp+48 corruption; restored after the
// IST=1 structural fix landed (per-tick arming combined with the rest of
// the diagnostic stack was costing ~1ms per IRQ0 and starving the
// compositor). Bump back to 1 only while actively re-hunting that class.
pub const KESP_REROTATE_TICKS: u32 = 50;
// Pid 2 = desktop, pid 3 = shell. Dropped 4 and 5 from the field-watch list
// to free DR slots 2 and 3 for the NEW kesp+48 MEMORY watches added below
// (netstat-desktop bug 2026-05-17: save_trace proves kernel_esp field is
// NOT being corrupted — it's the kstack memory at *(kesp+48) that gets
// zeroed between save and dispatch. The field watch wouldn't catch that;
// a memory watch on the saved-RIP slot will).
// Pid 2 = desktop, pid 3 = shell. Field watch on procs[].kernel_esp
// (slot 0,1) stays armed — catches switchTo writing a cross-PCB value.
//
// 2026-05-17: KESP_PLUS48 (memory watch on kstack at kesp+48) is
// disabled. For a *running* task, its previous saved-kesp+48 address
// gets organically rewritten by ordinary stack push/pop activity
// (caught schedule's own `pushfq` writing RFLAGS=0x6 → false positive
// crash). pcb_invariants.checkPcb catches the SLEEPING/READY case via
// the same saved-RIP-text-range check, so this watch was redundant.
pub const KESP_WATCHED_PIDS = [_]u8{ 2, 3 };
// Silent-RA-flip hunt (2026-05-25): pid=2 desktop + pid=3 shell both saw
// kesp+48 stomped from a real schedule RA to 0x80340317 (another
// schedule-shaped address). Arm save_trace mirror-compare on these slots;
// any write whose post-value differs from save_trace.last_save_plus48[pid]
// fires with the writer RIP. Empty means "off".
//
// TEMPORARILY DISABLED 2026-05-25: enabling { 2, 3 } here regressed boot
// against f813bec — splash drags ~10× longer to render under host SMI
// load. Combined with the per-switch arm in save_trace_record (now also
// off via hwbp_save_arm_enabled=false) and the per-tick rotation, going
// from 2 → 4 active DR slots seems to compound badly with the slow
// scheduler / nested-virt environment. Need to investigate WHY before
// re-enabling — the structural diagnostic value of these is real, but
// running them while the cause is unknown blocks all other work.
pub const KESP_PLUS48_WATCHED_PIDS = [_]u8{};

// 2026-05-19 attempt: re-enabled the deep canary on pid 2 at
// `top - 0x1000` to hunt the AAAA / 0x0 kesp+48 corruption. Boot
// showed the corruption hit pid 3 (not pid 2), and at `kesp+48`
// (= top - 0xF38) not at top - 0x1000. Also the observed value flip
// is one canonical kernel RA → another canonical kernel RA (e.g.
// schedule's callq RA flipped to schedule:2363's RA — cross-CPU
// stack aliasing signature) so the deep canary's filter wouldn't
// fire anyway. Replaced by save_trace-driven HWBP with dynamic
// skip_value (= just-observed legit RA) on both pid 2 and pid 3
// kesp+48. See save_trace.zig.
pub const KSTACK_DEEP_WATCHED_PIDS = [_]u8{};
// 0x1000 (4KB deep). Syscall entry uses ~640B immediately (15 GPRs + 520B
// FXSAVE), and nested call frames can stack more on top — 0x100 from top
// was too shallow (FXSAVE write tripped it). 0x1000 is well below any
// realistic kernel call chain depth but above the kstack bottom (16KB
// total), leaving plenty of margin.
pub const KSTACK_DEEP_OFFSET_FROM_TOP: usize = 0x1000;

/// Whitelist for the deep-kstack watch. Two whitelisted categories:
///
/// 1. IRQ/syscall/exception entry stubs — always push 15 GPRs + 512B
///    FXSAVE = ~650B on the preempted task's kstack. When caller's
///    RSP is already deep, the entry's FXSAVE lands on our watched
///    address — legitimate, not the wild writer.
///
/// 2. Any writer whose RSP at the moment of write is INSIDE the same
///    kstack as the watched address. This catches the "stack-local
///    buffer + memcpy/memset into it" pattern (ext2 readInodeBytes
///    + readBlock copy disk data into a stack `[4096]u8`, fat32 etc.).
///    A wild cross-stack writer (e.g. destroyCurrent's bulk @memset
///    on netstat exit) would have its RSP on a DIFFERENT kstack
///    (netstat's), so the filter doesn't suppress those.
///
/// True wild writers (cross-PCB bulk-wipe, dangling pointer writes
/// from arbitrary kernel code) fail both checks and fire.
fn isLegitDeepKstackWriter(rip: u64, addr: u64) bool {
    const r = symbols.resolveKernel(rip) orelse return false;
    // Category 1: entry stubs.
    if (std.mem.eql(u8, r.name, "cpu.idt.isr_irq0")) return true;
    if (std.mem.eql(u8, r.name, "isr_common_exc")) return true;
    if (std.mem.eql(u8, r.name, "handleException")) return true;
    if (std.mem.eql(u8, r.name, "handleIRQ0")) return true;
    if (std.mem.eql(u8, r.name, "handleDynIrq")) return true;
    if (std.mem.startsWith(u8, r.name, "cpu.syscall.entry.CpuEntry(")) return true;
    if (std.mem.startsWith(u8, r.name, "cpu.idt.DynIrqStub(")) return true;

    // Category 2: writer's RSP is in the same kstack as the watched
    // address (= "this task is writing to its own stack-local buffer").
    const process = @import("../proc/process.zig");
    const config = @import("../config.zig");
    const writer_rsp = asm volatile ("movq %%rsp, %[ret]"
        : [ret] "=r" (-> u64),
    );
    // Find the watched kstack: addr is in kstack_pool, which pid owns it?
    const pool_base = @intFromPtr(&process.kstack_pool[0]);
    const pool_total = config.MAX_PROCS * config.KSTACK_SLOT_SIZE;
    if (addr >= pool_base and addr < pool_base + pool_total) {
        const slot_off = addr - pool_base;
        const slot_idx = slot_off / config.KSTACK_SLOT_SIZE;
        const slot_base = pool_base + slot_idx * config.KSTACK_SLOT_SIZE;
        const slot_end = slot_base + config.KSTACK_SLOT_SIZE;
        // Writer RSP in same slot = same-kstack legit writer.
        if (writer_rsp >= slot_base and writer_rsp < slot_end) return true;
    }
    return false;
}
// Kernel VA base — any value written at *(kesp+48) below this is wild
// (legit values are kernel .text RAs which all sit above KERNEL_VIRT_BASE).
const KERNEL_VIRT_BASE: u64 = 0xFFFFFFFF80000000;

/// Predicate: is this kesp+48 write a legitimate `call switchTo` push?
///
/// Every legit kesp+48 write comes from the `call switchTo` instruction
/// inside `proc.sched.schedule` (that call pushes the return address onto
/// the parked task's kstack, landing at kesp+48 after switchTo's 6 register
/// pushes). save_trace_record runs AFTER switchTo's body, so there is a
/// brief window where (post-write value at kesp+48) != (mirror) — the
/// mirror-compare alone would false-positive on every save. Whitelist the
/// writer RIP if it's inside schedule.
///
/// Anything OUTSIDE schedule writing to a parked task's kesp+48 is the
/// silent corrupter we're hunting.
pub fn isLegitKesp48Writer(rip: u64, _: u64) bool {
    const r = symbols.resolveKernel(rip) orelse return false;
    return std.mem.eql(u8, r.name, "proc.sched.schedule") or
        std.mem.eql(u8, r.name, "proc.sched_asm.switchTo");
}

/// Predicate: is this kernel_esp write legitimate?
///
/// Two conditions both must hold:
///   1. Writer is in one of the 5 legit-writer functions:
///        - proc.sched_asm.switchTo: `movq %%rsp, (%%rdi)` save
///        - proc.process.{create,cloneCurrent,createKernelIdle,createKernelTask}:
///          each writes `procs[i].kernel_esp = stack_top - FRAME_BYTES` at init
///   2. The just-written value belongs to THIS PCB's own kstack slot (or its
///      registered heap kstack for kernel tasks).
///
/// Why both: the wild-RIP smoking gun is exactly switchTo (a "legit" writer)
/// saving an RSP that's INSIDE A DIFFERENT PCB's kstack — i.e. the runtime
/// got onto the wrong kstack, then preempted, and switchTo saved the cross-
/// slot value. Suppressing all switchTo writes hides this; we want to fire
/// when switchTo's stored value is cross-slot.
fn isLegitKernelEspWriter(rip: u64, addr: u64) bool {
    const process = @import("../proc/process.zig");
    const config = @import("../config.zig");

    // Step 1: identify the writer first. Any write from outside the known
    // legit functions is wild regardless of value/PCB-state.
    const r = symbols.resolveKernel(rip) orelse return false;
    // After commit ??? these moved from proc.process.* to proc.lifecycle.*.
    // Re-exports in process.zig don't change the symbol the linker assigns to
    // the function BODY — that stays in lifecycle.zig — so the resolver
    // returns "proc.lifecycle.X" for any RIP inside one of these now. Accept
    // both prefixes so the whitelist survives the split.
    const is_create =
        std.mem.eql(u8, r.name, "proc.lifecycle.create") or
        std.mem.eql(u8, r.name, "proc.lifecycle.cloneCurrent") or
        std.mem.eql(u8, r.name, "proc.lifecycle.createKernelIdle") or
        std.mem.eql(u8, r.name, "proc.lifecycle.createKernelTask") or
        std.mem.eql(u8, r.name, "proc.lifecycle.forkCurrent") or
        std.mem.eql(u8, r.name, "proc.process.create") or
        std.mem.eql(u8, r.name, "proc.process.cloneCurrent") or
        std.mem.eql(u8, r.name, "proc.process.createKernelIdle") or
        std.mem.eql(u8, r.name, "proc.process.createKernelTask") or
        std.mem.eql(u8, r.name, "proc.process.forkCurrent");
    const is_switch = std.mem.eql(u8, r.name, "proc.sched_asm.switchTo");
    // memcpy/memset called from resetPcbExceptState during create — the
    // bulk PCB zero. Whitelisted unconditionally; the explicit caller-side
    // store immediately after IS what we want the watch to validate.
    const is_bulk_copy =
        std.mem.eql(u8, r.name, "memcpy") or
        std.mem.eql(u8, r.name, "memset");
    if (!is_create and !is_switch and !is_bulk_copy) return false;

    // Create-path AND bulk-copy writes can happen BEFORE expected_kstack_tops
    // is set (resetPcbExceptState memsets the whole PCB to zero before the
    // explicit kernel_esp/expected_kstack_tops assignment). Accept these
    // unconditionally; the explicit store that follows IS the writer we
    // want to actually validate, and that store is in the create whitelist.
    if (is_create or is_bulk_copy) return true;

    // switchTo path: value must be inside this PCB's own kstack. This is
    // the cross-stack-aliasing detector — switchTo storing a value that
    // belongs to a DIFFERENT PCB's kstack is the wild-RIP root cause.
    const pcb0 = @intFromPtr(&process.procs[0]);
    const kesp_off = @intFromPtr(&process.procs[0].kernel_esp) - pcb0;
    const procs_base = pcb0 + kesp_off;
    if (addr < procs_base) return false;
    const pcb_size = @sizeOf(process.PCB);
    const off = addr - procs_base;
    if (off % pcb_size != 0) return false;
    const pid = off / pcb_size;
    if (pid >= config.MAX_PROCS) return false;

    const expected_top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
    if (expected_top == 0) return false; // switchTo on uninit slot = wild

    // Heap kstacks (desktop's 64KB) need a wider window; conservatively
    // accept anything within 4×KSTACK_SIZE below expected_top. Bounds
    // check prevents the subtract from wrapping if KESP_WATCHED_PIDS ever
    // grows to cover a low-VA stack — today every watched PID is on a
    // kstack_pool slot in high-half so the if() is dead, but cheap insurance.
    const window: usize = config.KSTACK_SIZE * 4;
    if (expected_top < window) return false;
    const allow_lo = expected_top - window;
    const v = @as(*const u64, @ptrFromInt(addr)).*;
    if (v >= allow_lo and v < expected_top) return true;

    // ALSO accept: value is inside some CPU's per-CPU isr_stack range. With
    // IRQ0 + dyn IRQs on TSS.IST=1, the CPU's IRQ-time RSP lives in
    // cpu.isr_stack[]. If the task was preempted mid-IRQ-handler, switchTo's
    // save writes that IST1 RSP into the PCB. Later switchTo resumes from
    // that IST1 address — works because the iretq frame on IST1 still has
    // the task's original kstack RSP. Without this whitelist branch, every
    // such legit save would trip the watch.
    for (0..smp.MAX_CPUS) |i| {
        const cpu = &smp.cpus[i];
        if (i > 0 and !cpu.alive) continue;
        const isr_lo = @intFromPtr(&cpu.isr_stack);
        const isr_hi = isr_lo + cpu.isr_stack.len;
        if (v >= isr_lo and v < isr_hi) return true;
    }
    return false;
}

/// Pin DR0-DR3 to KESP_WATCHED_PIDS' kernel_esp slots + KESP_PLUS48_WATCHED_PIDS'
/// memory at *(kesp+48). Idempotent — safe to re-arm every tick. Doesn't
/// broadcast IPI; relies on handleIRQ0's lazy applyLocal sync (~10ms) on
/// each CPU. The arm itself is BSP-only.
///
/// Slot layout:
///   slot 0..KESP_WATCHED_PIDS.len-1   : kernel_esp FIELD watch (cross-stack alias detector)
///   slot KESP_WATCHED_PIDS.len..      : kesp+48 MEMORY watch (saved-RIP zeroing detector)
pub fn rotateKernelEspWatches() void {
    // KASAN renames bulk-copy intrinsics (memcpy/memset → __anon_*) so the
    // isLegitKernelEspWriter exact-match whitelist falsely flags the legit
    // PCB zero-init from proc.lifecycle.create as a wild writer. KASAN
    // covers the same corruption class with finer-grained reporting, so
    // disable this hw-watchpoint when KASAN is on rather than relax the
    // whitelist into something too permissive.
    if (@hasDecl(@import("build_options"), "kasan_enabled") and
        @import("build_options").kasan_enabled) return;
    const process = @import("../proc/process.zig");
    var any_change = false;
    for (KESP_WATCHED_PIDS, 0..) |pid, i| {
        const e = &entries[i];
        const want_addr = @intFromPtr(&process.procs[pid].kernel_esp);
        // Skip re-write if already armed at the right address — saves the
        // applyLocal churn on the steady state.
        if (e.armed and e.addr == want_addr and e.whitelist_fn != null and
            e.gate_pid_parked_plus1 == pid + 1) continue;
        e.* = .{
            .armed = true,
            .addr = want_addr,
            .kind = .write,
            .len = .eight,
            .policy = .panic_dump,
            .label = "kesp",
            .whitelist_fn = &isLegitKernelEspWriter,
            // Gate: only fire while pid is fully parked. While the pid is
            // running, every switchTo legitimately rewrites this field —
            // arming through that wastes ~3000 cycles per dispatch on a
            // suppression path. The gate cuts those out entirely; we still
            // catch cross-stack-alias writes that land OUTSIDE legit
            // switchTo because those happen with the pid parked (the
            // attacker pid races against the watched pid's PCB slot).
            .gate_pid_parked_plus1 = pid + 1,
        };
        any_change = true;
    }
    // Memory watch on *(kesp+48) for the netstat-desktop saved-RIP corruption
    // hunt. value_threshold = KERNEL_VIRT_BASE means: fire iff post-write
    // value < KERNEL_VIRT_BASE. Legit writes are `call`-push of a kernel RA
    // (above KERNEL_VIRT_BASE → suppressed). Wild writes like memset(0),
    // user-mode garbage, or stale-pointer junk land below → fire with
    // writer's RIP in the autopsy.
    const base_slot: u2 = @intCast(KESP_WATCHED_PIDS.len);
    for (KESP_PLUS48_WATCHED_PIDS, 0..) |pid, j| {
        const slot: u2 = base_slot + @as(u2, @intCast(j));
        const e = &entries[slot];
        const kesp = @atomicLoad(usize, &process.procs[pid].kernel_esp, .acquire);
        // Bounds-check: kesp must be inside the pid's kstack body OR we
        // skip arming (would otherwise fire on legit unrelated writes).
        const top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
        const want_addr: u64 = blk: {
            if (top == 0) break :blk 0;
            const body_lo = top -| @import("../config.zig").KSTACK_SIZE;
            const cand = kesp +% 48;
            if (cand < body_lo or cand + 8 > top) break :blk 0;
            break :blk cand;
        };
        if (want_addr == 0) {
            if (e.armed) {
                e.armed = false;
                any_change = true;
            }
            continue;
        }
        if (e.armed and e.addr == want_addr and e.mirror_pid_plus1 == pid + 1 and
            e.gate_pid_parked_plus1 == pid + 1) continue;
        e.* = .{
            .armed = true,
            .addr = want_addr,
            .kind = .write,
            .len = .eight,
            .policy = .panic_dump,
            .label = "kesp+48",
            .mirror_pid_plus1 = pid + 1,
            .whitelist_fn = &isLegitKesp48Writer,
            // Same gate as the kesp FIELD watch above: while pid is
            // running, kesp+48 is meaningless — the saved-RIP slot has
            // already been popped off and live stack churn writes there.
            // The corruption we hunt only matters once the pid is fully
            // parked and the slot is supposed to hold the next dispatch's
            // RA.
            .gate_pid_parked_plus1 = pid + 1,
        };
        any_change = true;
    }
    // Deep-kstack watch — slot KESP_WATCHED_PIDS.len + KESP_PLUS48_WATCHED_PIDS.len
    // and onwards. Arms one address per watched pid at `kstack_top - OFFSET`.
    // No value threshold: ANY write to this address is interesting (no legit
    // writer should reach this deep into a live task's kstack).
    //
    // Skipped at comptime when KSTACK_DEEP_WATCHED_PIDS is empty so the u2
    // slot index can't overflow when KESP_WATCHED_PIDS + KESP_PLUS48_WATCHED_PIDS
    // already fill all four DR slots.
    if (comptime KSTACK_DEEP_WATCHED_PIDS.len > 0) {
    const deep_base: u2 = @intCast(KESP_WATCHED_PIDS.len + KESP_PLUS48_WATCHED_PIDS.len);
    for (KSTACK_DEEP_WATCHED_PIDS, 0..) |pid, k| {
        const slot: u2 = deep_base + @as(u2, @intCast(k));
        const e = &entries[slot];
        const top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
        const want_addr: u64 = if (top == 0) 0 else top - KSTACK_DEEP_OFFSET_FROM_TOP;
        if (want_addr == 0) {
            if (e.armed) {
                e.armed = false;
                any_change = true;
            }
            continue;
        }
        if (e.armed and e.addr == want_addr and e.whitelist_fn != null) continue;
        e.* = .{
            .armed = true,
            .addr = want_addr,
            .kind = .write,
            .len = .eight,
            .policy = .panic_dump,
            .label = "kstack_deep",
            .value_threshold = 0, // fire on ANY value
            .whitelist_fn = &isLegitDeepKstackWriter,
            // skip_value intentionally 0 (no skip). The AAAA pattern
            // IS the bug we're hunting for pid 2 (2026-05-19) — older
            // "Zig undefined-init noise" rationale doesn't apply here
            // because the depth + isLegitDeepKstackWriter filter
            // already gates same-stack writers.
        };
        any_change = true;
    }
    }
    if (any_change) applyLocal();
    // No broadcastSync — handleIRQ0's per-tick applyLocal on each CPU
    // picks up the new entries[] within ~10ms. IPI broadcast is the
    // observed heisenberg trigger (see iretq_canary commentary).
}

/// Diagnostic: dump current entries[] state.
pub fn dumpState() void {
    serial.print("[watch] DR6=0x{X:0>16} DR7=0x{X:0>16}\n", .{ readDr6(), computeDr7() });
    for (&entries, 0..) |*e, i| {
        if (e.armed) {
            serial.print("  slot{d}: addr=0x{X:0>16} kind={s} len={s} policy={s} hits={d} '{s}'\n", .{
                i, e.addr, @tagName(e.kind), @tagName(e.len), @tagName(e.policy), e.hits, e.label,
            });
        }
    }
}
