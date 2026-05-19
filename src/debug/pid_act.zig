// Per-PID activity ring buffer.
//
// Existing diagnostics are per-CPU (save_trace, pid_trace, breadcrumb) which
// is great for "what was each CPU doing at the crash" but terrible for
// "what just happened to pid X". Cross-correlating 4 per-CPU rings to
// reconstruct one pid's recent history is slow and error-prone.
//
// This module records the lifecycle events of EACH PID into its own small
// ring. To autopsy pid 4: dump pid_act.ring[4]. One block, one direction
// (time-ordered), all CPUs.
//
// Event kinds are intentionally narrow — only the events that distinguish
// FP-from-real-race for our recent bug classes. Currently:
//   - SETSTATE     state byte transition (via setState() — bracketed)
//   - PICK_CAS     pickNext's direct .ready→.running CAS (NOT in setState)
//   - SETCURPID    cpu.current_pid changed to/from this pid
//   - RQ_ENTER     pid added to a cpu's runqueue
//   - RQ_LEAVE     pid removed from a cpu's runqueue
//
// The "state==.running but no cpu owns" race becomes obvious here: you see
// a PICK_CAS without a following SETCURPID, or the inverse, or them in the
// wrong order. The current rq-audit reverse-direction FP is similarly
// visible: PICK_CAS at tsc=A, RQ_LEAVE at tsc=B>A, audit reads in (A,B).
//
// Cost: rdtsc + 4 stores per event, no atomics on the hot path (each pid's
// ring has a single logical writer at a time because state transitions are
// CAS-serialized through setState; PICK_CAS at line 2318 has a brief race
// window only on simultaneous candidate-pickers, accepted-as-best-effort).
//
// Size: 16 entries × MAX_PROCS=32 pids × 24 bytes = 12 KB BSS. Static.

const std = @import("std");
const config = @import("../config.zig");
const smp = @import("../cpu/smp.zig");
const serial = @import("serial.zig");
const process = @import("../proc/process.zig");

pub const RING_SIZE: usize = 16;

pub const Kind = enum(u8) {
    none = 0,
    setstate = 1, // payload_a = old_state, payload_b = new_state
    pick_cas = 2, // payload_a = (none), payload_b = (none)
    setcurpid_in = 3, // cpu.current_pid set TO this pid; payload_a = prev_pid_on_cpu (0xFF=null)
    setcurpid_out = 4, // cpu.current_pid moved AWAY from this pid; payload_a = next_pid_on_cpu (0xFF=null)
    rq_enter = 5, // payload_a = priority (0=bg/1=normal/2=interactive)
    rq_leave = 6,
};

pub const Entry = extern struct {
    tsc: u64 = 0,
    /// Caller @returnAddress at stamp site. Symbolizes to schedule()/setState/etc.
    caller_ra: u64 = 0,
    cpu_id: u8 = 0xFF,
    kind: Kind = .none,
    payload_a: u8 = 0xFF,
    payload_b: u8 = 0xFF,
    _pad: [4]u8 = .{ 0, 0, 0, 0 },
};

const Ring = struct {
    entries: [RING_SIZE]Entry = [_]Entry{.{}} ** RING_SIZE,
    head: u32 = 0,
};

var rings: [config.MAX_PROCS]Ring align(64) = [_]Ring{.{}} ** config.MAX_PROCS;

inline fn rdtsc() u64 {
    return asm volatile (
        \\ rdtsc
        \\ shlq $32, %%rdx
        \\ orq %%rdx, %%rax
        : [r] "={rax}" (-> u64),
        :: .{ .rdx = true });
}

/// Record an event for `pid`. Cheap (~30ns). Safe in IRQ context.
/// `payload_a` / `payload_b` are kind-specific — see Kind doc above.
///
/// Caller-provided `caller_ra` so this can be invoked from inline `@call`
/// sites without losing the original stamp point. Pass `@returnAddress()`
/// at the stamp call.
pub fn record(pid: usize, kind: Kind, payload_a: u8, payload_b: u8, caller_ra: u64) void {
    if (pid >= config.MAX_PROCS) return;
    const cpu_id = blk: {
        const c = smp.myCpu();
        if (c.cpu_id < smp.MAX_CPUS) break :blk c.cpu_id;
        break :blk @as(u8, 0xFE);
    };
    const ring = &rings[pid];
    const slot: usize = ring.head % RING_SIZE;
    ring.head +%= 1;
    ring.entries[slot] = .{
        .tsc = rdtsc(),
        .caller_ra = caller_ra,
        .cpu_id = cpu_id,
        .kind = kind,
        .payload_a = payload_a,
        .payload_b = payload_b,
    };
}

/// Reset a pid's ring. Call from process create/recycle paths so a reused
/// slot starts clean (otherwise the autopsy mixes prior life with new).
pub fn resetPid(pid: usize) void {
    if (pid >= config.MAX_PROCS) return;
    rings[pid] = .{};
}

fn kindName(k: Kind) []const u8 {
    return switch (k) {
        .none => "NONE",
        .setstate => "SETSTATE",
        .pick_cas => "PICK_CAS",
        .setcurpid_in => "SETCURPID_IN",
        .setcurpid_out => "SETCURPID_OUT",
        .rq_enter => "RQ_ENTER",
        .rq_leave => "RQ_LEAVE",
    };
}

fn stateName(s: u8) []const u8 {
    return switch (s) {
        0 => "unused",
        1 => "loading",
        2 => "ready",
        3 => "running",
        4 => "sleeping",
        5 => "zombie",
        else => "?",
    };
}

fn prioName(p: u8) []const u8 {
    return switch (p) {
        0 => "bg",
        1 => "nrm",
        2 => "int",
        else => "?",
    };
}

/// Dump a single pid's ring, oldest-first. Called from pcb_invariants /
/// panic-path autopsy for the failing pid.
pub fn dump(pid: usize) void {
    if (pid >= config.MAX_PROCS) {
        serial.print("[pid-act] pid={d} out of range\n", .{pid});
        return;
    }
    const symbols = @import("symbols.zig");
    const r = &rings[pid];
    const total = r.head;
    const count: usize = @min(@as(usize, total), RING_SIZE);
    const name = blk: {
        const p = &process.procs[pid];
        if (p.name_len == 0) break :blk "(unnamed)";
        break :blk p.name[0..@min(p.name_len, p.name.len)];
    };
    if (count == 0) {
        serial.print("\n[pid-act pid={d} ({s})] (no events recorded)\n", .{ pid, name });
        return;
    }
    serial.print("\n[pid-act pid={d} ({s})] last {d} events (oldest first):\n", .{ pid, name, count });
    var k: usize = 0;
    while (k < count) : (k += 1) {
        const slot: usize = (r.head -% @as(u32, @intCast(count - k))) % RING_SIZE;
        const e = r.entries[slot];
        serial.print(
            "  [{d:0>2}] tsc=0x{X:0>12} cpu{d}  {s:<14}",
            .{ slot, e.tsc, e.cpu_id, kindName(e.kind) },
        );
        switch (e.kind) {
            .setstate => serial.print(
                "  {s} -> {s}",
                .{ stateName(e.payload_a), stateName(e.payload_b) },
            ),
            .pick_cas => serial.print("  .ready -> .running (CAS)", .{}),
            .setcurpid_in => {
                if (e.payload_a == 0xFF) {
                    serial.print("  cpu{d}.current_pid: (none) -> pid", .{e.cpu_id});
                } else {
                    serial.print("  cpu{d}.current_pid: pid{d} -> pid", .{ e.cpu_id, e.payload_a });
                }
            },
            .setcurpid_out => {
                if (e.payload_a == 0xFF) {
                    serial.print("  cpu{d}.current_pid: pid -> (none)", .{e.cpu_id});
                } else {
                    serial.print("  cpu{d}.current_pid: pid -> pid{d}", .{ e.cpu_id, e.payload_a });
                }
            },
            .rq_enter, .rq_leave => serial.print("  cpu{d}.rq.{s}", .{ e.cpu_id, prioName(e.payload_a) }),
            .none => {},
        }
        if (symbols.resolveKernel(e.caller_ra)) |sym| {
            serial.print("  via {s}+0x{X}\n", .{ sym.name, sym.offset });
        } else {
            serial.print("  via 0x{X:0>16}\n", .{e.caller_ra});
        }
    }
}

/// Dump every alive pid's ring. Used by general autopsy paths.
pub fn dumpAll() void {
    var p: usize = 0;
    while (p < config.MAX_PROCS) : (p += 1) {
        if (process.procs[p].state == .unused) continue;
        if (rings[p].head == 0) continue;
        dump(p);
    }
}
