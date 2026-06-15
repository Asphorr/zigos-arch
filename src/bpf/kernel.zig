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
const verifier = @import("verifier.zig");
const jit = @import("jit.zig");
const process = @import("../proc/process.zig");
const spinlock = @import("../proc/spinlock.zig");
const serial = @import("../debug/serial.zig");
const common = @import("../cpu/syscall/common.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");

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

// === verifier contract (M3a) ===
// The STATIC mirror of the run-time Env above: the program's ctx is a read-only
// SyscallCtx, and helper id 1 reads one argument (the pid). verify() uses this
// to prove a loaded program can only ever touch this region and call these
// helpers — before it is allowed anywhere near the syscall path. Helper id 0
// stays unregistered here too, so the two views agree on what a valid CALL is.
const VERIFIER_HELPERS = [_]?verifier.HelperSig{
    null, // 0: reserved — must stay unregistered
    .{ .n_args = 1 }, // 1: count(pid)
};
const BUILTIN_CFG = verifier.Config{
    .ctx_len = @sizeOf(SyscallCtx),
    .ctx_writable = false,
    .helpers = &VERIFIER_HELPERS,
};

/// Serializes verify()'s module-static analysis scratch (see verifier.zig's
/// NOT-REENTRANT note). Today only init() takes it, once, at boot — but it is
/// the chokepoint a future sys_bpf load path shares. Leaf lock, never from IRQ.
var verify_lock: spinlock.SpinLock = .{};

/// Set true once the builtin passes verification at init(); surfaced on
/// /proc/bpf. If the builtin ever FAILS to verify, the hook is force-disabled —
/// an unverified program must never run on the syscall path.
pub var builtin_verified: bool = false;

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

// === load-time verification (M3a) ===

/// Verify a program through the serialized verifier — the gated entry point a
/// future sys_bpf load path shares with init().
fn verifyProgram(prog: []const insn.Insn, cfg: verifier.Config) verifier.VerifyError!void {
    verify_lock.acquire();
    defer verify_lock.release();
    return verifier.verify(prog, cfg);
}

/// Verify the builtin at boot — called from kmain before the first syscall can
/// fire. Proves the dogfood in the live FREESTANDING kernel (not just under the
/// off-target harness) and refuses to run it if it somehow fails to verify, so
/// the program on the syscall path is always one the verifier has approved.
pub fn init() void {
    if (verifyProgram(&BUILTIN_PROG, BUILTIN_CFG)) |_| {
        builtin_verified = true;
        serial.print("[zbpf] verifier: builtin verified OK ({d} insns)\n", .{BUILTIN_PROG.len});
    } else |e| {
        builtin_verified = false;
        enabled = false;
        serial.print("[zbpf] verifier: builtin FAILED ({s}) — syscall hook DISABLED\n", .{@errorName(e)});
    }
    jitInit();
}

// === userspace loading: sys_bpf (verify-and-run) ===
//
// The whole point of the verifier: let an UNTRUSTED program — handed in from
// userspace — be cleared to run in ring 0. cmd 0 verifies a program and, if it
// passes, runs it ONCE in the sandbox against a copied-in context, returning r0
// and any context writes. The program can only ever touch its own 512-byte
// stack and the ctx buffer the kernel owns; it is fuel-bounded; and it was
// proven (no OOB, no bad jump, bounded loops) before a single instruction ran.
// v1 exposes NO helpers — the ctx in/out is the only I/O channel — so any CALL
// is rejected at verification.

const MAX_USER_CTX: u32 = 1024;
const USER_BPF_FUEL: u64 = 4096; // the verifier proved <= MAX_DEPTH (1024) concrete steps

/// The userspace ABI struct: a pointer to one of these is passed as the syscall
/// `attr`. Layout is shared verbatim with app/zbpf.zig — extend by APPENDING.
pub const BpfAttr = extern struct {
    ret: u64 = 0, // OUT: r0 from the run (valid only when the call returns 0)
    prog: u32 = 0, // user ptr to `prog_cnt` 8-byte instructions
    prog_cnt: u32 = 0,
    ctx: u32 = 0, // user ptr to the context buffer (0 if none)
    ctx_len: u32 = 0, // <= MAX_USER_CTX
    ctx_writable: u32 = 0, // 0/1 — may the program write its context?
    flags: u32 = 0, // reserved, must be 0
};

// Kernel staging buffers, serialized by verify_lock: the program and ctx are
// copied here so the verifier/interpreter never dereference user VA and a
// concurrent thread can't mutate the program between verify and run.
var ub_prog: [insn.MAX_INSNS]insn.Insn = undefined;
var ub_ctx: [MAX_USER_CTX]u8 align(8) = undefined;
const USER_HELPERS = [_]?verifier.HelperSig{}; // v1: no helpers for userspace programs

pub var user_loads: u64 = 0;
pub var user_rejects: u64 = 0;

// === JIT: native execution of verified programs (interpreter fallback) ===
//
// jit.zig lowers a verified program to x86-64; running that instead of
// interpreting is byte-identical (proven off-target over ~700k differential
// runs) and skips per-instruction decode/dispatch. The code buffer is dedicated
// PMM frames reached through the physmap, which is EXECUTABLE: boot.asm maps the
// physmap 1 GB pages P|RW|PS|G (0x183, no NX), so physToVirt() memory is RWX —
// no page-table work needed here. (If the physmap ever gains NX, this is the one
// spot that needs a paging.makeExecutable.)
//
// Safety model: the JIT runs with NO runtime fuel or bounds checks — it trusts
// the verifier's proofs (every memory access in range, loops bounded), exactly
// as a production JIT trusts its verifier. The interpreter remains the fallback
// and keeps all of its own runtime checks. Any program the JIT can't lower yet
// (helper CALL, atomics) or that overflows the buffer simply runs on the
// interpreter — a miss is never a failure. The whole path is serialized by
// verify_lock, which also guards jit.zig's module-static codegen scratch and the
// single shared code buffer below.
const JIT_CODE_FRAMES: u32 = 16; // 64 KB — comfortably past the worst-case expansion of a ~1000-insn program
const JIT_CODE_SIZE: usize = JIT_CODE_FRAMES * 4096;
var jit_code: ?[]u8 = null; // executable code buffer (physmap VA); null if PMM couldn't spare the run
// The native run's eBPF stack. Static (not on the lean syscall kstack), zeroed
// per run, and verify_lock-serialized — same single-owner discipline as ub_ctx.
var jit_stack: [insn.STACK_SIZE]u8 align(16) = undefined;
pub var jit_enabled: bool = true; // runtime kill-switch — force the interpreter path if ever needed
pub var jit_runs: u64 = 0; // programs executed as native code
pub var jit_misses: u64 = 0; // programs that fell back to the interpreter

/// One-time JIT code-buffer allocation. Optional: on failure the JIT stays off
/// and every program runs on the interpreter.
fn jitInit() void {
    if (pmm.allocContiguous(JIT_CODE_FRAMES)) |phys| {
        jit_code = @as([*]u8, @ptrFromInt(paging.physToVirt(phys)))[0..JIT_CODE_SIZE];
        serial.print("[zbpf] jit: {d} KB code buffer @ phys 0x{X} (physmap-exec)\n", .{ JIT_CODE_SIZE / 1024, phys });
    } else {
        serial.print("[zbpf] jit: no code buffer — interpreter only\n", .{});
    }
}

/// Run a VERIFIED program and return r0: native via the JIT when it can lower
/// the whole program and there are no helpers (CALL isn't emitted yet), else the
/// interpreter. The CALLER MUST hold verify_lock — the JIT shares the global
/// codegen scratch and the single code buffer. The native run gets a fresh,
/// zeroed 512-byte eBPF stack and `ctx_ptr` as r1; its raw accesses land in
/// exactly the stack + the ctx region the verifier already bounded.
fn runVerified(prog: []const insn.Insn, ctx_ptr: u64, fuel: u64, env: vm.Env) vm.Error!u64 {
    if (jit_enabled and jit_code != null and env.helpers.len == 0) {
        if (jit.compile(prog, jit_code.?)) |_| {
            const f: jit.CompiledFn = @ptrFromInt(@intFromPtr(jit_code.?.ptr));
            // Zero the eBPF stack per run (vm.zig does the same): no read-before-
            // write proof, so a stale slot must not leak kernel bytes to userspace.
            @memset(&jit_stack, 0);
            const r0 = f(ctx_ptr, @intFromPtr(&jit_stack));
            jit_runs +%= 1;
            return r0;
        } else |_| {
            // Unsupported opcode / buffer overflow / malformed — interpret instead.
        }
    }
    var machine = vm.Vm{};
    const res = try machine.runEnv(prog, ctx_ptr, fuel, env);
    jit_misses +%= 1;
    return res.r0;
}

/// sys_bpf(cmd, attr_ptr, attr_len). Returns 0 on a completed run (result in
/// attr.ret), EINVAL on bad args or a verifier rejection, EFAULT on a bad user
/// pointer.
pub fn sysBpf(cmd: u32, attr_ptr: u32, attr_len: u32) u32 {
    if (cmd != 0) return common.E_INVAL; // only verify-and-run for now
    if (attr_len != @sizeOf(BpfAttr)) return common.E_INVAL;
    if (!common.validateUserPtrWriteAligned(attr_ptr, @sizeOf(BpfAttr), 8)) return common.E_FAULT;

    var attr: BpfAttr = undefined;
    @memcpy(std.mem.asBytes(&attr), @as([*]const u8, @ptrFromInt(attr_ptr))[0..@sizeOf(BpfAttr)]);

    if (attr.prog_cnt == 0 or attr.prog_cnt > insn.MAX_INSNS) return common.E_INVAL;
    if (attr.ctx_len > MAX_USER_CTX) return common.E_INVAL;
    if (attr.flags != 0) return common.E_INVAL;

    const prog_bytes = @as(usize, attr.prog_cnt) * @sizeOf(insn.Insn);
    if (!common.validateUserPtr(attr.prog, prog_bytes)) return common.E_FAULT;
    if (attr.ctx_len > 0) {
        const ok = if (attr.ctx_writable != 0)
            common.validateUserPtrWrite(attr.ctx, attr.ctx_len)
        else
            common.validateUserPtr(attr.ctx, attr.ctx_len);
        if (!ok) return common.E_FAULT;
    }

    verify_lock.acquire();
    defer verify_lock.release();

    @memcpy(std.mem.sliceAsBytes(ub_prog[0..attr.prog_cnt]), @as([*]const u8, @ptrFromInt(attr.prog))[0..prog_bytes]);
    if (attr.ctx_len > 0)
        @memcpy(ub_ctx[0..attr.ctx_len], @as([*]const u8, @ptrFromInt(attr.ctx))[0..attr.ctx_len]);

    const prog = ub_prog[0..attr.prog_cnt];
    const cfg = verifier.Config{
        .ctx_len = attr.ctx_len,
        .ctx_writable = attr.ctx_writable != 0,
        .helpers = &USER_HELPERS,
    };

    user_loads +%= 1;
    verifier.verify(prog, cfg) catch {
        user_rejects +%= 1;
        return common.E_INVAL; // the verifier refused the program
    };

    // Verified — run it once. The ctx region points at our kernel copy, so the
    // program's reach is exactly its stack + these `ctx_len` bytes.
    const regions = [_]vm.Region{.{ .base = @intFromPtr(&ub_ctx), .len = attr.ctx_len, .writable = attr.ctx_writable != 0 }};
    const env = vm.Env{
        .regions = if (attr.ctx_len > 0) regions[0..1] else regions[0..0],
        .helpers = &[_]?vm.HelperFn{},
    };
    // Native via the JIT when possible (no helpers on this path), else the
    // interpreter. Either way ctx mutations go straight into ub_ctx through r1,
    // so the copy-back below is unchanged.
    const r0 = runVerified(prog, @intFromPtr(&ub_ctx), USER_BPF_FUEL, env) catch {
        return common.E_FAULT; // unreachable for a verified program — defence in depth
    };

    attr.ret = r0;
    @memcpy(@as([*]u8, @ptrFromInt(attr_ptr))[0..@sizeOf(BpfAttr)], std.mem.asBytes(&attr));
    if (attr.ctx_len > 0 and attr.ctx_writable != 0)
        @memcpy(@as([*]u8, @ptrFromInt(attr.ctx))[0..attr.ctx_len], ub_ctx[0..attr.ctx_len]);

    return 0;
}

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
    n += fmt(buf[n..], "verifier: builtin {s} (structural + ranges + bounded loops)\n", .{if (builtin_verified) "VERIFIED" else "UNVERIFIED"});
    n += fmt(buf[n..], "sys_bpf:  {d} user loads, {d} rejected by verifier\n", .{ user_loads, user_rejects });
    n += fmt(buf[n..], "jit:      {s}, {d} native runs, {d} interpreter fallbacks\n", .{ if (jit_code != null and jit_enabled) "on" else "off", jit_runs, jit_misses });
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
