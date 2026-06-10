//! bpf/kernel — zBPF's kernel-side glue: hooks, helpers, and the map.
//!
//! M2 wires the first observation point: a BPF program runs on EVERY syscall
//! entry and bills it to the calling pid in a per-pid map, surfaced at
//! /proc/bpf. The program itself is the M2 demo — it is NOT hand-rolled
//! kernel code doing the counting; the counting logic executes inside the
//! sandboxed interpreter, reading the hook's context struct and calling a
//! registered helper, exactly the shape userspace-loaded programs will have
//! once the verifier (M3) gates the load path.
//!
//! Safety story (why this is allowed near the syscall path at all):
//!   * the interpreter bounds-checks every memory access against the
//!     program stack + the read-only ctx region — a buggy program cannot
//!     touch kernel memory (vm.zig's checkMem chokepoint);
//!   * fuel-bounded — cannot hang the syscall path;
//!   * any program Error just increments err_count and the syscall proceeds
//!     — observation must never break the observed;
//!   * the helper validates its own args (the program controls them).
//!
//! Cost: the builtin program is 6 instructions ≈ a few hundred cycles per
//! syscall, run OUTSIDE the perf.enter window so the carefully-tuned
//! [perf] sys# table doesn't absorb interpreter overhead. The `enabled`
//! flag (default ON — the demo should work out of the box) short-circuits
//! to one atomic load + branch when off.
//!
//! Concurrency: the Vm lives on the caller's kernel stack (~600 B at the
//! TOP of doSyscall, depth-1 — far from the deep FS/ELF paths the
//! kstack-lean rule protects; a per-CPU BSS Vm would be UNSAFE here, since
//! an IRQ-driven reschedule mid-run lets another task on the same CPU
//! re-enter the hook and corrupt the first run's state). The map uses
//! atomic adds — two CPUs in syscalls concurrently both land counts.

const std = @import("std");
const insn = @import("insn.zig");
const vm = @import("vm.zig");
const process = @import("../proc/process.zig");

/// Hook context handed to syscall-entry programs, read-only. Field order is
/// ABI for the programs below — extend by APPENDING (programs address it by
/// byte offset, like every real eBPF ctx struct).
pub const SyscallCtx = extern struct {
    nr: u64, // syscall number
    pid: u64, // calling pid (0xFFFFFFFF if pre-task, filtered before run)
};

// === the map: per-pid syscall counts ===

var counts: [process.MAX_PROCS]u64 = [_]u64{0} ** process.MAX_PROCS;
var total: u64 = 0;

// === hook bookkeeping ===

pub var enabled: bool = true;
var run_count: u64 = 0;
var err_count: u64 = 0;
var last_err: ?vm.Error = null;

/// Fuel for hook programs. The builtin needs 6; 256 leaves headroom for
/// experimentation while still bounding a runaway at sub-microsecond scale.
const HOOK_FUEL: u64 = 256;

// === helpers (the program-callable kernel surface) ===
// Table indexed by the CALL immediate. Id 0 is deliberately unregistered —
// a zero-initialized/garbage CALL must fail, not silently hit a real helper.

fn helperCountPid(pid: u64, _: u64, _: u64, _: u64, _: u64) u64 {
    // The program controls this argument — validate like any user input.
    if (pid >= process.MAX_PROCS) return 1;
    _ = @atomicRmw(u64, &counts[@intCast(pid)], .Add, 1, .monotonic);
    _ = @atomicRmw(u64, &total, .Add, 1, .monotonic);
    return 0;
}

const HELPERS = [_]?vm.HelperFn{
    null, // 0: reserved
    helperCountPid, // 1: count(pid) -> 0 ok, 1 rejected
};

// === the builtin program ===
// Assembled at comptime from the same builders the harness uses — the ISA
// is dogfooded, not bypassed. Logic:
//
//     r2 = ctx->nr        ; touch the first field too (exercises offset 0)
//     r1 = ctx->pid       ; load the pid (clobbers ctx ptr — done with it)
//     call count(r1)
//     r0 = 0
//     exit
const BUILTIN_PROG = [_]insn.Insn{
    insn.ldx(.dw, 2, 1, 0), // r2 = ctx->nr
    insn.ldx(.dw, 1, 1, 8), // r1 = ctx->pid
    insn.call(1),
    insn.mov64Imm(0, 0),
    insn.exit(),
};

// === the hook ===

/// Called from doSyscall on every syscall entry. Must be cheap when
/// disabled and must NEVER propagate a failure into the syscall path.
pub fn onSyscallEnter(sys_num: u32) void {
    if (!@atomicLoad(bool, &enabled, .acquire)) return;

    const pid = process.getCurrentPid();
    if (pid == 0xFFFFFFFF) return; // pre-enterFirstTask: nothing to bill

    var ctx = SyscallCtx{ .nr = sys_num, .pid = pid };
    const env = vm.Env{
        .regions = &[_]vm.Region{
            .{ .base = @intFromPtr(&ctx), .len = @sizeOf(SyscallCtx), .writable = false },
        },
        .helpers = &HELPERS,
    };

    var machine = vm.Vm{};
    if (machine.runEnv(&BUILTIN_PROG, @intFromPtr(&ctx), HOOK_FUEL, env)) |_| {
        run_count +%= 1;
    } else |e| {
        // Observation must never break the observed: record and move on.
        err_count +%= 1;
        last_err = e;
    }
}

// === /proc/bpf ===

/// Render hook + map state. Same contract as procfs's other renderers:
/// fresh from live state, into the caller's buffer, returns length.
pub fn renderProc(buf: []u8) usize {
    var n: usize = 0;
    n += fmt(buf[n..], "zbpf: syscall-entry hook (builtin counter, {d} insns)\n", .{BUILTIN_PROG.len});
    n += fmt(buf[n..], "enabled: {}\nruns:    {d}\nerrors:  {d}", .{ @atomicLoad(bool, &enabled, .acquire), run_count, err_count });
    if (last_err) |e| {
        n += fmt(buf[n..], " (last: {s})", .{@errorName(e)});
    }
    n += fmt(buf[n..], "\ntotal:   {d}\n\n{s:<4} {s:<16} {s}\n", .{ @atomicLoad(u64, &total, .monotonic), "pid", "name", "syscalls" });
    var pid: usize = 0;
    while (pid < process.MAX_PROCS) : (pid += 1) {
        const c = @atomicLoad(u64, &counts[pid], .monotonic);
        if (c == 0) continue;
        // Name from the PCB; a recycled/exited pid keeps its last name,
        // which is the useful label for "who burned these".
        const name_z = &process.procs[pid].name;
        const name_len = std.mem.indexOfScalar(u8, name_z, 0) orelse name_z.len;
        n += fmt(buf[n..], "{d:<4} {s:<16} {d}\n", .{ pid, name_z[0..name_len], c });
    }
    return n;
}

fn fmt(buf: []u8, comptime f: []const u8, args: anytype) usize {
    const out = std.fmt.bufPrint(buf, f, args) catch buf;
    return out.len;
}
