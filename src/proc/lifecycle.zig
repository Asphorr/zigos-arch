//! Process lifecycle: PCB slot alloc, process/thread create + clone + fork,
//! per-CPU kernel idle + kernel-task spawn, kill / destroy / reap teardown,
//! reparent-on-orphan, stale-zombie sweep. Split out of process.zig (#810).
//!
//! Owns:
//!   * allocSlot + resetPcbExceptState — the .unused→.loading CAS plus the
//!     verbatim field reset that the four constructors (create,
//!     createKernelIdle, createKernelTask, cloneCurrent) share.
//!   * create / cloneCurrent / cloneLinuxThread / forkCurrent — user-process /
//!     thread / Linux thread / fork PCB constructors. Each builds a synthetic
//!     kstack frame so the next dispatch lands in the right ring-3 RIP/RSP.
//!   * kernelIdle + createKernelIdle / createIdleProcess / createKernelTask
//!     — kernel-mode PCBs (one idle per CPU, plus desktop and friends).
//!   * setInflightSlot / clearInflightSlot / reclaimInflightSlot and the
//!     setInflightFrame / clearInflightFrame / reclaimInflightFrame mirror —
//!     in-flight swap bookkeeping, so a thread killed while parked in
//!     blockOn(.nvme_io) leaks neither its NVMe slot (evict direction) nor
//!     its freshly allocated frame (swap-in direction).
//!   * tearDownTask + the kill / destroy / reap surface
//!     (killProcessWithStatus, killProcess, destroyCurrentWithStatus,
//!     destroyCurrent, reapZombie, findZombieChild, reparentChildren,
//!     maybeReapZombies, reapStaleZombies).
//!   * freeElfBuf — internal helper that drops the per-process ELF buffer.
//!   * claimTeardown / countThreadsInGroup — the "am I the last thread of
//!     the tgid" decision (and therefore whether to free shared resources
//!     like the page directory + GUI window + ELF buf). claimTeardown is
//!     the lock-serialized form tearDownTask uses.
//!
//! Re-exported from process.zig so external callers keep using process.X
//! paths unchanged.

const std = @import("std");

const vga = @import("../driver.zig").vga;
const gdt = @import("../cpu/arch/gdt.zig");
const debug = @import("../debug/debug.zig");
const vmm = @import("../mm/vmm.zig");
const pcid_mod = @import("../cpu/mmu/pcid.zig");
const heap = @import("../mm/heap.zig");
const pmm = @import("../mm/pmm.zig");
const swap = @import("../mm/swap.zig");
const Phys = @import("../util/addr.zig").Phys;
const symbols = @import("../debug/symbols.zig");
const smp = @import("../cpu/smp.zig");
const memmap = @import("../mm/memmap.zig");
const config = @import("../config.zig");
const pid_set = @import("../util/pid_set.zig");
const signals = @import("signals.zig");
const frames = @import("frames.zig");
const file_mod = @import("../fs/file.zig");
const pid_nr = @import("pid_nr.zig");
const dspec = frames.dispatch; // NOT `fd` — this file is full of file-descriptor captures

const process = @import("process.zig");
// Pull-on-idle work stealing: an idle CPU steals one queued task from the
// busiest peer (via migrate()) instead of waiting up to a full load-balance
// interval for the BSP's periodic push. The migrate() PCID gen-bump
// (pcid.invalidateForMigration) makes the cross-CPU move TLB-safe. Confirmed
// not to cause the schedstress cpu0 hang — that wedges with this off too
// (a pre-existing scheduler livelock under a sysYield storm).
const STEAL_ON_IDLE = true;
const PCB = process.PCB;
const State = process.State;
const Priority = process.Priority;
const WaitKind = process.WaitKind;
const MAX_PROCS = process.MAX_PROCS;

const KSTACK_SIZE = config.KSTACK_SIZE;
const KSTACK_GUARD_SIZE = config.KSTACK_GUARD_SIZE;
const KSTACK_SLOT_SIZE = config.KSTACK_SLOT_SIZE;
const MAX_FDS = config.MAX_FDS;

/// Atomically claim an unused PCB slot, transitioning state .unused → .loading
/// in a single CAS so two CPUs can't pick the same slot. Returns the slot
/// index (with state already set to .loading) or null if the table is full.
///
/// Why this matters: the previous check-then-write pattern
///   `if (procs[i].state == .unused) { procs[i] = .{}; ... }`
/// has a window between the load and the struct write where another CPU's
/// check also sees .unused, both pick the same slot, both write to the same
/// kstack — observed corruption: one create() zeroed PID 4's GPR area
/// (`for (0..15) frame[k] = 0`) while pid 4 was still running on cpu0,
/// triggering the iretq-canary fire.
///
/// After this function returns, the caller MUST reset PCB fields without
/// touching `state` (use `resetPcbExceptState` below) — `procs[i] = .{}`
/// would set state back to .unused briefly, re-opening the race.
fn allocSlot() ?usize {
    for (0..MAX_PROCS) |i| {
        // A task that tore itself down frees its slot before its final
        // schedule() leaves the kstack; until that switch clears on_cpu, a
        // new occupant would build its first frame on a stack still in use.
        // Nothing sets on_cpu on an .unused slot, so the check cannot go
        // stale before the CAS.
        if (@atomicLoad(bool, &process.procs[i].on_cpu, .acquire)) continue;
        const state_ptr: *u8 = @as(*u8, @ptrCast(&process.procs[i].state));
        if (@cmpxchgStrong(
            u8,
            state_ptr,
            @intFromEnum(State.unused),
            @intFromEnum(State.loading),
            .acquire,
            .monotonic,
        ) == null) {
            // releaseSlot left the stack marked freed. Here, not where the
            // task is made ready: by then another CPU may be running it.
            @import("../debug/kasan.zig").markPcbAlive(@intFromPtr(&process.kstack_pool[i]) + KSTACK_GUARD_SIZE, KSTACK_SIZE);
            return i;
        }
    }
    return null;
}

/// Reset every PCB field to its default EXCEPT `state` (which the caller has
/// already set to .loading via allocSlot's CAS). Equivalent to
/// `procs[i] = .{}` minus the state-byte write — necessary because that write
/// would briefly restore state to .unused and re-open the slot to other CPUs.
/// FP state a forked or cloned task starts with: its parent's at the
/// syscall. User code may keep values in XMM registers across a syscall,
/// and the child returns from the same one.
var inherited_fpu: [MAX_PROCS][512]u8 align(16) = undefined;

/// Give task `child`, whose first-dispatch frame starts at `sw_base`, the
/// FP state the caller's syscall saved: retToUserStub loads the image its
/// switch frame's rbx names (0 there: fp.init_template).
fn inheritFpu(child: usize, frame: *const signals.SyscallFrame, sw_base: [*]u64) void {
    @memcpy(&inherited_fpu[child], frame.userFpu());
    sw_base[dspec.switch_frame.index(.rbx)] = @intFromPtr(&inherited_fpu[child]);
    @import("../cpu/arch/fp.zig").inheritExtended(child);
}

/// Fields a reused slot keeps: `state` (allocSlot's CAS owns it) and
/// `as_lock` (a /proc reader of the slot's last process may still hold or
/// await it; the lock belongs to the slot).
const KEPT_SPANS = blk: {
    var spans: [2][2]usize = undefined;
    for (.{ "state", "as_lock" }, 0..) |name, i| {
        const off = @offsetOf(PCB, name);
        spans[i] = .{ off, off + @sizeOf(@FieldType(PCB, name)) };
    }
    if (spans[0][0] > spans[1][0]) std.mem.swap([2]usize, &spans[0], &spans[1]);
    break :blk spans;
};

fn resetPcbExceptState(pcb: *PCB) void {
    const fresh: PCB = .{};
    const dst: [*]u8 = @ptrCast(pcb);
    const src: [*]const u8 = @ptrCast(&fresh);
    var from: usize = 0;
    inline for (KEPT_SPANS) |s| {
        @memcpy(dst[from..s[0]], src[from..s[0]]);
        from = s[1];
    }
    @memcpy(dst[from..@sizeOf(PCB)], src[from..@sizeOf(PCB)]);
    // Accounting fields default to 0 from the fresh literal above; the one
    // we want non-zero is start_tick. Stamping it here covers all four
    // constructors (create, createKernelTask, createKernelIdle,
    // cloneCurrent) — they all call resetPcbExceptState exactly once per
    // PCB lifecycle, right after allocSlot. Other accounting counters
    // start at 0 by design.
    pcb.acct_start_tick = process.tick_count;
    // Clear save_trace's "has been preempted" flag so a re-used PID slot
    // starts as "not yet saved" — the new task won't have a valid
    // *(kesp+48) until switchTo runs at least once.
    const pid = (@intFromPtr(pcb) - @intFromPtr(&process.procs[0])) / @sizeOf(PCB);
    if (pid < MAX_PROCS) {
        @import("../debug/save_trace.zig").resetPid(@intCast(pid));
        @import("../debug/pid_act.zig").resetPid(pid);
        @import("../debug/yield_loop.zig").resetPid(pid);
        @import("../cpu/arch/fp.zig").resetExtended(pid);
        // A new number for the slot's new occupant. It leads a group and a
        // session of its own until a parent's are copied in (fork, clone,
        // sysExec).
        pcb.pid_nr = pid_nr.assign(pid);
        pcb.pgid = pcb.pid_nr;
        pcb.sid = pcb.pid_nr;
    }
}

/// Create a process with a fake interrupt frame on its kernel stack.
/// entry: Ring 3 RIP, user_stack: Ring 3 RSP.
/// Returns process index or null if table full.
pub fn create(entry: usize, user_stack: usize) ?usize {
    const i = allocSlot() orelse return null;
    resetPcbExceptState(&process.procs[i]); // state stays .loading from allocSlot's CAS

    // Stack region is the upper 16KB of slot i; bottom 4KB is the
    // unmapped guard page installed at boot by initKstackGuards.
    const slot_base = @intFromPtr(&process.kstack_pool[i]);
    const stack_top = slot_base + KSTACK_SLOT_SIZE;

    // Kernel stack image at first dispatch: the dispatch contract —
    // switch-frame zeros + planted retToUserStub + GPR slots + iretq
    // words. The geometry (counts, offsets, pop orders, 16-alignment)
    // lives ONCE in frames.dispatch, the same value sched_asm.zig
    // derives its push/pop text from; this function only fills values.
    //
    // After the first iretq the task is in user mode. On its next
    // preempt/yield, isr_irq0/syscall stub saves new state on this
    // SAME kstack at the top, then schedule() pushes its own
    // switchTo frame (callee-saves) deeper on the kstack.
    const frame: [*]u64 = @ptrFromInt(stack_top - dspec.pt_regs_bytes);
    frame[dspec.iretq.ss.at()] = 0x1B;
    // SysV ABI invariant: function entry RSP must be (16-aligned minus 8) —
    // see the matching block in cloneCurrent. _start almost always survives
    // because it's a small leaf that calls main via `call` (which itself
    // realigns), so the bug stays latent for sysExec but bites sysClone
    // where the entry is an arbitrary user function. Fix both for symmetry.
    frame[dspec.iretq.rsp.at()] = (user_stack & ~@as(usize, 0xF)) - 8;
    frame[dspec.iretq.rflags.at()] = 0x202;
    frame[dspec.iretq.cs.at()] = 0x23;
    frame[dspec.iretq.rip.at()] = entry;
    for (0..dspec.gprs.count) |k| frame[k] = 0;

    const sched_asm = @import("sched_asm.zig");
    const sw_base: [*]u64 = @ptrFromInt(stack_top - dspec.total_bytes);
    for (0..dspec.switch_frame.count) |k| sw_base[k] = 0;
    sw_base[dspec.ret_slot] = @intFromPtr(&sched_asm.retToUserStub);

    process.procs[i].kernel_esp = stack_top - dspec.total_bytes;
    process.procs[i].kernel_stack_top = stack_top;
    process.plantStackCanary(i); // P4: plant base canary BEFORE publishing the slot runnable
    @atomicStore(usize, &process.expected_kstack_tops[i], stack_top, .release);
    // state already .loading from allocSlot's CAS — no further write needed.
    process.procs[i].tgid = @intCast(i);
    // Session and group are its own (resetPcbExceptState). sysExec copies
    // the parent's in before scheduling, so spawned children land in the
    // parent's session and group, as after fork+exec.
    @import("../debug/kdbg.zig").procEvent(.create, @intCast(i), 0, 0);
    return i;
}

/// Number of *live* PCBs sharing `tgid`. (tearDownTask itself now uses
/// claimTeardown — the lock-serialized, self-excluding form — for the
/// last-thread decision; this plain count remains for diagnostics/future
/// callers.) "Live" means actually running or runnable: .ready, .running,
/// .sleeping, .switching_out. Excluded:
///   - .unused: slot is free, no thread.
///   - .loading: slot was claimed by process.create but never finished
///     init (typical cause: a CPU panicked mid-clone, leaving the worker
///     stranded). Counting these as "live" makes a stuck .loading worker
///     prevent the lead's last_in_group cleanup forever — symptom we hit
///     in the threadbrot close-button log: stranded PID 5 .loading after
///     a cpu1 panic blocked PID 4's GUI window teardown on close.
///   - .zombie: thread already exited; per-thread cleanup ran. The slot
///     is awaiting parent's waitpid reap and shouldn't keep the group
///     "alive" from the lead's perspective.
pub fn countThreadsInGroup(tgid: u8) u8 {
    var n: u8 = 0;
    for (0..MAX_PROCS) |i| {
        const s = process.procs[i].state;
        if (s == .unused or s == .loading or s == .zombie) continue;
        if (process.procs[i].tgid == tgid) n += 1;
    }
    return n;
}

/// Spawn a new thread that shares the parent's address space. The new
/// thread enters user mode at `entry` with `stack_top` as its RSP and
/// `arg` in RDI; `fs_base` becomes its IA32_FS_BASE for thread-local
/// storage (0 = inherit / no TLS). Returns the child pid (which doubles
/// as its tid) or null if the process table is full.
///
/// What's shared: page_directory (same CR3 pointer + phys) and the PCID —
/// every shootdown of the AS names the lead's PCID, so a thread tagged with
/// another one would keep stale entries past munmap/fork/swap. regions,
/// fd_table, sigactions, cwd, etc. all live on the lead thread; cloned
/// threads access them through `leader(pcb)`.
///
/// What's fresh: kernel stack (kstack_pool slot), kernel_esp (set up
/// with a synthetic iretq frame so first dispatch lands in the user
/// entry). Thread-local fields (signal_mask, pending_signals,
/// in_signal_handler, ticks_used, perf_gap_cyc) are reset; the parent's
/// values are NOT inherited.
pub fn cloneCurrent(entry: usize, stack_top: usize, arg: usize, fs_base: u64) ?usize {
    const parent = process.currentPCB() orelse return null;
    const parent_lead = process.leader(parent);

    const i = allocSlot() orelse return null;
    resetPcbExceptState(&process.procs[i]); // state stays .loading from allocSlot's CAS

    joinGroup(&process.procs[i], parent, parent_lead);
    if (groupExiting(&process.procs[i])) {
        process.setState(i, .unused);
        return null;
    }
    // Its own table: the lead's files as they are now, each with a
    // reference this thread's teardown drops.
    file_mod.copyTable(&process.procs[i], parent_lead);
    process.procs[i].fs_base = fs_base;

    // Kernel stack image: same dispatch contract as create() but with
    // caller-chosen RIP/RSP/RDI. Geometry from frames.dispatch.
    const slot_base = @intFromPtr(&process.kstack_pool[i]);
    const kstack_top = slot_base + KSTACK_SLOT_SIZE;

    const frame: [*]u64 = @ptrFromInt(kstack_top - dspec.pt_regs_bytes);
    frame[dspec.iretq.ss.at()] = 0x1B;
    // SysV ABI invariant: at function entry RSP must be (16-aligned minus 8).
    // A normal `call` pushes 8-byte RA before transferring control, so the
    // callee sees RSP at (16k - 8). iretq performs no such push, so we
    // pre-adjust user RSP so `entry`'s prologue sees the alignment a normal
    // `call` would produce. Without this, ANY XMM-spill in `entry`'s
    // prologue (movaps/movdqa — emitted by Zig under register pressure,
    // notably anything calling std.fmt.bufPrint) GPFs immediately on
    // misaligned access. threadtest/threadbrot survive only because their
    // worker bodies don't trigger XMM pressure; richer thread bodies crash.
    frame[dspec.iretq.rsp.at()] = (stack_top & ~@as(usize, 0xF)) - 8;
    frame[dspec.iretq.rflags.at()] = 0x202;
    frame[dspec.iretq.cs.at()] = 0x23;
    frame[dspec.iretq.rip.at()] = entry;
    for (0..dspec.gprs.count) |k| frame[k] = 0;
    // First arg rides in RDI. The slot index is DERIVED from the pop
    // order (this was the hand-counted "frame[8] = arg").
    frame[dspec.gprs.index(.rdi)] = arg;

    const sched_asm = @import("sched_asm.zig");
    const sw_base: [*]u64 = @ptrFromInt(kstack_top - dspec.total_bytes);
    for (0..dspec.switch_frame.count) |k| sw_base[k] = 0;
    sw_base[dspec.ret_slot] = @intFromPtr(&sched_asm.retToUserStub);

    process.procs[i].kernel_esp = kstack_top - dspec.total_bytes;
    process.procs[i].kernel_stack_top = kstack_top;
    process.plantStackCanary(i); // P4: plant base canary BEFORE publishing the slot runnable
    @atomicStore(usize, &process.expected_kstack_tops[i], kstack_top, .release);
    // Atomic transition .loading → .ready. Callers of cloneCurrent expect
    // the new PCB to be schedulable immediately (no separate "ready" step
    // like sysExec does after page-table setup). assignInitialCpu first
    // so setState's rqEnter lands on the right per-CPU runqueue.
    process.assignInitialCpu(i);
    process.setState(i, .ready);
    return i;
}

/// What a new thread takes from its group: the tgid, process group and
/// session (a thread is not a process of its own: setpgid/setsid on it act
/// on the lead), the address space with its PCID, and copies of the
/// process-level state native thread code reads off its own PCB. The fd
/// table is the caller's to set: a native thread gets a copy of the lead's,
/// a Linux thread an empty one (the Linux layer goes to the lead's table,
/// which is how Linux threads share one).
fn joinGroup(child: *PCB, parent: *const PCB, parent_lead: *const PCB) void {
    child.tgid = parent_lead.tgid;
    child.pgid = parent_lead.pgid;
    child.sid = parent_lead.sid;
    child.page_directory = parent_lead.page_directory;
    child.page_dir_phys = parent_lead.page_dir_phys;
    child.pcid = parent_lead.pcid;
    child.sigactions = parent_lead.sigactions;
    child.cwd = parent_lead.cwd;
    child.cwd_len = parent_lead.cwd_len;
    child.name = parent_lead.name;
    child.name_len = parent_lead.name_len;
    child.priority = parent.priority;
    child.parent_pid = parent_lead.tgid;
}

/// True when the new thread `child`'s group is being killed: the caller
/// drops the slot. The killer stores group_exiting, then makes one pass
/// over the slots; the tgid joinGroup stored is fenced ahead of the flag
/// read, so either that pass sees this thread or this sees the flag.
fn groupExiting(child: *const PCB) bool {
    asm volatile ("mfence" ::: .{ .memory = true });
    return @atomicLoad(bool, &process.procs[child.tgid].group_exiting, .seq_cst);
}

/// What a Linux clone(CLONE_THREAD) sets up beyond the caller's registers.
pub const LinuxThreadSpec = struct {
    /// The thread's user stack pointer; 0 keeps the caller's.
    stack: usize,
    fs_base: u64,
    /// CLONE_CHILD_CLEARTID word, 0 for none.
    clear_tid: usize,
    /// CLONE_PARENT_SETTID / CLONE_CHILD_SETTID words, 0 for none. The
    /// caller validates them (u32, writable); the tid is stored in them
    /// before the thread can run.
    parent_tid: usize,
    child_tid: usize,
};

/// clone() for a Linux thread: a task in the caller's group, as with
/// cloneCurrent, that returns from the caller's syscall with every register
/// the caller had (musl's __clone keeps the start routine in r9) except
/// RAX = 0 and RSP = spec.stack. Returns the tid: the task's number.
pub fn cloneLinuxThread(frame: *const signals.SyscallFrame, spec: LinuxThreadSpec) ?u32 {
    const parent = process.currentPCB() orelse return null;
    const parent_lead = process.leader(parent);

    const i = allocSlot() orelse return null;
    resetPcbExceptState(&process.procs[i]); // state stays .loading from allocSlot's CAS

    joinGroup(&process.procs[i], parent, parent_lead);
    if (groupExiting(&process.procs[i])) {
        process.setState(i, .unused);
        return null;
    }
    // The Linux layer uses the lead's fd table and cwd. Without copies of
    // its own, a path that reached for this thread's would fail rather than
    // act on fds and a cwd as they were at clone time.
    process.procs[i].fd_table = [_]process.FdSlot{.{}} ** MAX_FDS;
    process.procs[i].cwd_len = 0;
    process.procs[i].personality = .linux;
    process.procs[i].fs_base = spec.fs_base;
    process.procs[i].clear_child_tid = spec.clear_tid;
    process.procs[i].signal_mask = parent.signal_mask;

    // Kernel stack image: forkCurrent's, on the new stack.
    const slot_base = @intFromPtr(&process.kstack_pool[i]);
    const kstack_top = slot_base + KSTACK_SLOT_SIZE;
    const f: [*]u64 = @ptrFromInt(kstack_top - dspec.pt_regs_bytes);
    f[dspec.iretq.ss.at()] = 0x1B;
    f[dspec.iretq.rsp.at()] = if (spec.stack != 0) spec.stack else frame.user_rsp;
    f[dspec.iretq.rflags.at()] = frame.r11;
    f[dspec.iretq.cs.at()] = 0x23;
    f[dspec.iretq.rip.at()] = frame.rcx;
    inline for (dspec.gprs.regs, 0..) |r, k| {
        f[k] = switch (r) {
            .rax => 0,
            else => @field(frame, @tagName(r)),
        };
    }

    const sched_asm = @import("sched_asm.zig");
    const sw_base: [*]u64 = @ptrFromInt(kstack_top - dspec.total_bytes);
    for (0..dspec.switch_frame.count) |k| sw_base[k] = 0;
    sw_base[dspec.ret_slot] = @intFromPtr(&sched_asm.retToUserStub);
    inheritFpu(i, frame, sw_base);

    process.procs[i].kernel_esp = kstack_top - dspec.total_bytes;
    process.procs[i].kernel_stack_top = kstack_top;
    process.plantStackCanary(i); // P4: plant base canary BEFORE publishing the slot runnable
    @atomicStore(usize, &process.expected_kstack_tops[i], kstack_top, .release);

    // musl's thread start reads its tid from here (mutex owner ids), so it
    // is in place before the thread is.
    const tid: u32 = process.procs[i].pid_nr;
    if (spec.parent_tid != 0) @atomicStore(u32, @as(*u32, @ptrFromInt(spec.parent_tid)), tid, .release);
    if (spec.child_tid != 0) @atomicStore(u32, @as(*u32, @ptrFromInt(spec.child_tid)), tid, .release);

    process.assignInitialCpu(i);
    process.setState(i, .ready);
    @import("../debug/kdbg.zig").procEvent(.create, @intCast(i), parent_lead.tgid, 0);
    return tid;
}

/// What a fork is asked for beyond the copy (Linux clone's fork shapes).
pub const ForkSpec = struct {
    /// Where the child's number (pid_nr.zig) goes.
    child_nr: ?*u32 = null,
    /// The child's user stack pointer; 0 keeps the caller's.
    stack: usize = 0,
    /// CLONE_CHILD_SETTID: a u32 in the CHILD's memory that gets its tid.
    set_tid: usize = 0,
    /// CLONE_CHILD_CLEARTID word, 0 for none.
    clear_tid: usize = 0,
};

/// Store `tid` at `va` in the address space of new process `child`, which
/// has not run yet. The page is the child's copy: the parent's keeps what
/// it had. False if the page can't be had (not mapped, no memory).
fn pokeChildTid(child: *PCB, va: usize, tid: u32) bool {
    if (va & 3 != 0 or !memmap.userDataRangeOk(va, 4)) return false;
    child.as_lock.acquireRead();
    defer child.as_lock.releaseRead();
    if (!process.ensureUserRangeWritableFor(child, va, 4)) return false;
    const pml4 = child.page_directory orelse return false;
    const frame_phys = vmm.resolveUserPhys(pml4, va) orelse return false;
    const word: *align(1) u32 = @ptrFromInt(frame_phys.toVirt().raw() + (va & 0xFFF));
    word.* = tid;
    return true;
}

/// Spawn a child via fork(). Clones the parent's address space (COW shared),
/// copies fd_table / sigactions / cwd / regions / argv, and synthesizes
/// a kstack iretq frame so the child resumes at the parent's syscall-return
/// RIP/RSP with RAX=0. Parent's caller (sysFork) returns the child PID.
///
/// `frame` is the parent's saved syscall frame (passed through doSyscall) —
/// we read RIP/RFLAGS/RSP/all GPRs from there to seed child's iretq frame.
/// Returns the child's slot.
pub fn forkCurrent(frame: *signals.SyscallFrame, spec: ForkSpec) ?usize {
    const child_nr = spec.child_nr;
    const child_stack = spec.stack;
    const parent = process.currentPCB() orelse return null;
    // A Linux process's children are the process's, whichever thread forked
    // (any of them may wait4 for them).
    const parent_pid_u8: u8 = if (parent.personality == .linux) parent.tgid else @intCast(smp.currentPid() orelse return null);
    // Process-level state (address space, regions, fd table, argv…)
    // lives on the LEAD thread. fork() from a cloned worker used to copy the
    // WORKER's own fields — empty regions, default brk/mmap_top — so
    // the child faulted on its first instruction. Read through the lead.
    const parent_lead_src = process.leader(parent);
    const parent_pml4 = parent_lead_src.page_directory orelse return null;

    // AS-stability lock on PARENT — cloneAddressSpace walks every PTE,
    // mutating R/W bits for COW. Concurrent sysMunmap / io_uring worker
    // memcpy on the parent's AS would race the walk. Released after the
    // child PML4 is built; the new child PCB gets its own as_lock (default
    // unowned). See PCB.as_lock.
    parent_lead_src.as_lock.acquire();
    defer parent_lead_src.as_lock.release();

    const i = allocSlot() orelse return null;
    resetPcbExceptState(&process.procs[i]); // state stays .loading from allocSlot's CAS

    // Per-AS state — fork has its own AS, so the regions are a copy (not
    // aliased through tgid like clone's).
    process.procs[i].regions = parent_lead_src.regions.clone() catch {
        debug.klog("[fork] no memory for the child's {d} regions\n", .{parent_lead_src.regions.len});
        process.setState(i, .unused);
        return null;
    };

    // Clone parent's address space. On OOM partway through, the child PML4 is
    // partially built; tear it down via destroyAddressSpace, which drops every
    // refcount we bumped and frees every page-table page we allocated.
    var child_pml4_phys: Phys = Phys.of(0);
    const child_pml4 = vmm.cloneAddressSpace(parent_pml4, parent_lead_src.pcid, &child_pml4_phys) orelse {
        if (child_pml4_phys.raw() != 0) {
            const pml4_ptr: [*]align(4096) u64 = @ptrFromInt(child_pml4_phys.toVirt().raw());
            vmm.destroyAddressSpace(@alignCast(pml4_ptr), child_pml4_phys);
        }
        process.procs[i].regions.deinit();
        process.setState(i, .unused);
        return null;
    };
    process.procs[i].page_directory = child_pml4;
    process.procs[i].page_dir_phys = child_pml4_phys.raw();
    process.procs[i].pcid = pcid_mod.alloc();

    // brk/mmap state is inherited as values too. All of it lives on the
    // lead (see parent_lead_src above).
    process.procs[i].heap_start = parent_lead_src.heap_start;
    process.procs[i].brk_base = parent_lead_src.brk_base;
    process.procs[i].user_brk = parent_lead_src.user_brk;
    process.procs[i].mmap_top = parent_lead_src.mmap_top;
    process.procs[i].stack_base = parent_lead_src.stack_base;
    process.procs[i].arg_start = parent_lead_src.arg_start;
    process.procs[i].arg_end = parent_lead_src.arg_end;
    process.procs[i].env_end = parent_lead_src.env_end;
    process.procs[i].auxv_start = parent_lead_src.auxv_start;
    process.procs[i].auxv_end = parent_lead_src.auxv_end;

    // Shared-anon regions: bump refcount per inherited LazyRegion. The
    // PT-level COW path covers private anon (each AS gets a fresh frame on
    // first write); shared-anon stays POSIX-SHARED — child sees parent's
    // writes byte-for-byte and vice versa. The PTE entries already point at
    // the same frames (cloneAddressSpace strips writable for COW, but the
    // fault handler re-checks shm_id BEFORE handleCowFault, so writes on a
    // shared-anon page take the shm-map path, not the COW path).
    //
    // Kernel buffers behind `source` (a private file mmap's copy, the ELF
    // image) are not remapped by COW: the child's copied regions read the
    // parent's buffers, so each gains an owner and the last one frees it.
    {
        const shm = @import("../mm/shm.zig");
        for (process.procs[i].regions.slice()) |r| {
            if (r.shm_id != shm.SHM_INVALID) _ = shm.acquire(r.shm_id);
            r.holdBacking();
            if (r.buf_owned) {
                if (r.source) |src| pmm.shareContiguous(kbufPhys(src));
            }
        }
    }
    if (parent_lead_src.elf_buf) |buf| pmm.shareContiguous(kbufPhys(buf));
    process.procs[i].elf_buf = parent_lead_src.elf_buf;
    process.procs[i].elf_buf_pages = parent_lead_src.elf_buf_pages;

    // FD table: the parent's files, shared — the child's descriptors refer
    // to the same open files, offsets and all, each with one more
    // reference. fd_table is process-level → lead's.
    file_mod.copyTable(&process.procs[i], parent_lead_src);

    // Inherit cwd, name, sigactions, argv (process-level → lead) and
    // priority, fs_base (per-thread → the calling thread).
    process.procs[i].cwd = parent_lead_src.cwd;
    process.procs[i].cwd_len = parent_lead_src.cwd_len;
    process.procs[i].umask = parent_lead_src.umask;
    process.procs[i].oom_score_adj = @atomicLoad(i16, &parent_lead_src.oom_score_adj, .monotonic);
    process.procs[i].name = parent_lead_src.name;
    process.procs[i].name_len = parent_lead_src.name_len;
    process.procs[i].sigactions = parent_lead_src.sigactions;
    process.procs[i].argv = parent_lead_src.argv;
    process.procs[i].arg_lens = parent_lead_src.arg_lens;
    process.procs[i].argc = parent_lead_src.argc;
    process.procs[i].exe_path = parent_lead_src.exe_path;
    process.procs[i].exe_path_len = parent_lead_src.exe_path_len;
    process.procs[i].priority = parent.priority;
    process.procs[i].fs_base = parent.fs_base;
    // A Linux process's forked children are Linux too — inherit the ABI
    // personality so the child's syscalls route to the same translation layer.
    process.procs[i].personality = parent_lead_src.personality;

    process.procs[i].parent_pid = parent_pid_u8;
    process.procs[i].tgid = @intCast(i); // lead thread of the new process group
    // POSIX fork() preserves the parent's pgid and sid — only setsid /
    // setpgid mutate them. A daemon's classic double-fork relies on
    // this: the middle child calls setsid AFTER it's been forked off,
    // and the grandchild then naturally inherits the new sid here.
    process.procs[i].pgid = parent_lead_src.pgid;
    process.procs[i].sid = parent_lead_src.sid;
    // The forking thread's mask and alternate stack are the child's; what
    // was pending for the parent is not.
    process.procs[i].signal_mask = parent.signal_mask;
    process.procs[i].alt_stack = parent.alt_stack;
    // glibc's fork has the child's tid stored in the child's own thread
    // block, and that word cleared when it exits.
    if (spec.set_tid != 0) _ = pokeChildTid(&process.procs[i], spec.set_tid, process.procs[i].pid_nr);
    process.procs[i].clear_child_tid = spec.clear_tid;

    // Build child's kstack image — the same dispatch contract as
    // create()/cloneCurrent(), values seeded from parent's saved syscall
    // frame so the child resumes at the parent's syscall-return point
    // with RAX=0.
    const slot_base = @intFromPtr(&process.kstack_pool[i]);
    const kstack_top = slot_base + KSTACK_SLOT_SIZE;

    const f: [*]u64 = @ptrFromInt(kstack_top - dspec.pt_regs_bytes);
    // Iretq frame (top of pt_regs).
    f[dspec.iretq.ss.at()] = 0x1B; // user SS
    f[dspec.iretq.rsp.at()] = if (child_stack != 0) child_stack else frame.user_rsp;
    f[dspec.iretq.rflags.at()] = frame.r11; // syscall stashes RFLAGS in R11
    f[dspec.iretq.cs.at()] = 0x23; // user CS
    f[dspec.iretq.rip.at()] = frame.rcx; // syscall stashes user RIP in RCX
    // GPR slots: copy BY NAME along the pop order — this loop replaces
    // the hand-transposed f[0]=r15 … f[14]=rax table, so the slot of
    // each register is derived, not counted by eye. Special cases: RAX
    // is fork()'s return value for the child (0); R11/RCX slots carry
    // the parent's raw values exactly as before (R11's GPR slot is
    // overwritten by iretq's RFLAGS load anyway).
    inline for (dspec.gprs.regs, 0..) |r, k| {
        f[k] = switch (r) {
            .rax => 0, // fork() → 0 in the child
            else => @field(frame, @tagName(r)),
        };
    }

    const sched_asm = @import("sched_asm.zig");
    const sw_base: [*]u64 = @ptrFromInt(kstack_top - dspec.total_bytes);
    for (0..dspec.switch_frame.count) |k| sw_base[k] = 0;
    sw_base[dspec.ret_slot] = @intFromPtr(&sched_asm.retToUserStub);
    inheritFpu(i, frame, sw_base);

    process.procs[i].kernel_esp = kstack_top - dspec.total_bytes;
    process.procs[i].kernel_stack_top = kstack_top;
    process.plantStackCanary(i); // P4: plant base canary BEFORE publishing the slot runnable
    @atomicStore(usize, &process.expected_kstack_tops[i], kstack_top, .release);
    // Read before the child can run: once it has exited and been reaped,
    // the slot may hold another task's number.
    if (child_nr) |nr| nr.* = process.procs[i].pid_nr;
    process.assignInitialCpu(i);
    process.setState(i, .ready);
    @import("../debug/kdbg.zig").procEvent(.create, @intCast(i), parent_pid_u8, 0);
    return i;
}

/// Per-CPU kernel-mode idle task (task #235). Runs CS=0x08, no user space,
/// no syscall_entry. Loop: `sti; hlt; schedule()` when the wake queued work.
///
/// The post-hlt `schedule()` call is critical: handleIRQ0 SKIPS calling
/// schedule when the IRQ fires from kernel mode (see idt.zig's `if
/// (from_user or was_soft_yield)`). Without us yielding voluntarily, the
/// IRQ that woke us would just iretq back to our own loop and we'd hlt
/// forever, ignoring any newly-ready task. The explicit schedule() call
/// gives any waker (desktop, a now-runnable user task) a chance to be
/// dispatched.
///
/// First dispatch lands at this function via switchTo's `ret` from the
/// synthetic frame planted by createKernelIdle. Subsequent IRQs preempt
/// us inline (kernel-mode IRQs don't switch stacks); we resume after hlt
/// and yield, repeat.
fn kernelIdle() callconv(.c) noreturn {
    const mwait = @import("../cpu/arch/mwait.zig");
    while (true) {
        // Pre-suspend AP quiesce (S3 CP2b-2c) safe point. This is the lock-clean
        // top of the idle loop — the previous schedule() released sched_lock and we
        // hold nothing. If the BSP has requested a quiesce, an AP acks and parks
        // here in cli; hlt until S3 powers it down (or INIT/SIPI re-onlines it). No
        // effect on the BSP or in normal operation (the gate is a single bool load).
        smp.parkForQuiesceIfRequested();
        // Drain any pending async app load (file-read offload). Used to be
        // serviced by apEntry's scheduler-context loop, but per-CPU idle
        // (task #235) made that loop dead code on APs. Idle is the right
        // home: it runs whenever the CPU has nothing else to do, and the
        // CAS pending->loading inside apProcessLoadQueue prevents two
        // idles from racing on the same request.
        smp.apProcessLoadQueue();
        // Pull-on-idle work stealing. We're the idle task → this CPU has no
        // local runnable work. If a peer is backed up, steal one of its queued
        // tasks and dispatch it NOW instead of sleeping — work reaches a free
        // core in µs rather than waiting up to a full load-balance interval
        // (~50 ticks) for the BSP's periodic one-task push. Lock-clean here;
        // tryStealWork goes through migrate() (two-rq-lock safe, current_pid
        // guarded). On a steal, schedule() runs it; the loop re-checks for more
        // before ever sleeping. No steal → fall through to the normal sleep.
        if (STEAL_ON_IDLE and process.tryStealWork()) {
            @import("../cpu/idt/irq0.zig").shortenAfterIdleWake();
            process.schedule();
            continue;
        }
        // A task became runnable HERE with no IPI to break the sleep below
        // (apProcessLoadQueue readying a pid assigned to this CPU, a same-
        // CPU wake): run it now, off the tickless stretch, instead of
        // hlt-ing over it for up to 10 quanta. Spin-proof: if schedule()
        // dispatched nothing (a queued pid the picker skips for a reason
        // rqHasDispatchable doesn't model), fall through and sleep on the
        // one-quantum arm the shorten left — never re-check in a loop.
        if (@import("../cpu/idt/irq0.zig").localRqHasWork()) {
            const seq = @import("../cpu/idt/irq0.zig").dispatchSeq();
            @import("../cpu/idt/irq0.zig").shortenAfterIdleWake();
            process.schedule();
            if (@import("../cpu/idt/irq0.zig").dispatchSeq() != seq) continue;
        } else if (@import("sched.zig").pollIdle()) {
            // Work arrived while we spun instead of halting.
            const seq = @import("../cpu/idt/irq0.zig").dispatchSeq();
            @import("../cpu/idt/irq0.zig").shortenAfterIdleWake();
            process.schedule();
            if (@import("../cpu/idt/irq0.zig").dispatchSeq() != seq) continue;
        }
        if (mwait.mwait_supported) {
            // sti + monitor + mwait. MWAIT(EAX=C1 hint, ECX[0]=1) wakes on
            // either a write to the monitored line or an interrupt — IRQs
            // break it just like HLT, with the added bonus of letting the
            // CPU drop into C1/C1E. The monitored word is per-CPU; the
            // compositor's wake.requestWake() bumps the BSP's word so a
            // producer on any CPU pops this mwait without an IPI.
            //
            // Order matters: arm MONITOR, THEN check the parked desktop,
            // THEN mwait. A requestWake that lands after the check writes
            // the already-armed line, so the MWAIT returns immediately —
            // no check→sleep window. (Pre-fix this loop slept straight
            // over wakes posted while this CPU was busy: the desktop's
            // wake check only ran AFTER an IRQ broke mwait, which is why
            // a freshly-launched terminal or a terminal app's output sat
            // invisible until the next mouse/keyboard IRQ.)
            const cpu = smp.myCpu();
            mwait.monitorArm(&cpu.idle_monitor_word);
            if (@import("../ui/desktop.zig").wakeIfDueFromIdle()) {
                @import("../cpu/idt/irq0.zig").shortenAfterIdleWake();
                process.schedule();
                continue;
            }
            asm volatile ("sti");
            mwait.mwaitEnter();
        } else {
            // No MONITOR/MWAIT (common under KVM): the pre-sleep check
            // still closes the busy→idle lost-wake path; a wake that
            // races past it is caught by the next timer fire (the BSP
            // stretch is capped by earliest_wake_tick, ≤100 ms).
            if (@import("../ui/desktop.zig").wakeIfDueFromIdle()) {
                @import("../cpu/idt/irq0.zig").shortenAfterIdleWake();
                process.schedule();
                continue;
            }
            asm volatile ("sti; hlt");
        }
        // Parked-desktop instant wake: input IRQs land on the BSP and
        // break its hlt — hand the event to the desktop NOW, at the idle
        // loop's first pass after the IRQ. µs-class input
        // latency instead of waiting for the next tick. No-op off-BSP
        // or when the desktop isn't parked/due. Runs BEFORE the tickless
        // hook below so a woken desktop counts as work on this CPU.
        _ = @import("../ui/desktop.zig").wakeIfDueFromIdle();
        // Tickless idle: if the one-shot is stretched and this wake put
        // work on our queue (or the BSP was kicked for a sooner deadline),
        // restore the 10 ms cadence BEFORE scheduling it — otherwise it
        // runs up to the full stretch with no preemption and (on BSP) no
        // wallclock advance. Queue empty → the stretch stands, whether the
        // timer or an inline-handled device IRQ woke us.
        @import("../cpu/idt/irq0.zig").shortenAfterIdleWake();
        // Queue empty: schedule() would only pick idle again (~12k cycles a
        // wake). The loop top re-checks before the next sleep.
        if (@import("../cpu/idt/irq0.zig").localRqHasWork()) process.schedule();
    }
}

/// Create a kernel-mode idle PCB for `cpu_id`. Returns the new PID.
pub fn createKernelIdle(cpu_id: u8) ?usize {
    const i = allocSlot() orelse {
        debug.klog("[proc] Failed to create kernel idle for cpu{d}\n", .{cpu_id});
        return null;
    };
    resetPcbExceptState(&process.procs[i]); // state stays .loading from allocSlot's CAS
    const slot_base = @intFromPtr(&process.kstack_pool[i]);
    const stack_top = slot_base + KSTACK_SLOT_SIZE;

    // Kthread frame: switch-frame zeros + entry address + poison ret
    // slot — geometry from the dispatch contract (dspec.kthread_*).
    const sw_base: [*]u64 = @ptrFromInt(stack_top - dspec.kthread_bytes);
    for (0..dspec.switch_frame.count) |k| sw_base[k] = 0;
    sw_base[dspec.ret_slot] = @intFromPtr(&kernelIdle);
    sw_base[dspec.kthread_ret_pad] = 0;

    process.procs[i].kernel_esp = stack_top - dspec.kthread_bytes;
    process.procs[i].kernel_stack_top = stack_top;
    process.plantStackCanary(i); // P4: plant base canary BEFORE publishing the slot runnable
    @atomicStore(usize, &process.expected_kstack_tops[i], stack_top, .release);
    process.procs[i].is_idle = true;
    process.procs[i].idle_cpu = cpu_id;
    process.procs[i].priority = .background;
    process.procs[i].page_dir_phys = 0;
    process.procs[i].last_cpu = cpu_id;
    process.procs[i].tgid = @intCast(i);
    process.procs[i].cwd[0] = '/';
    process.procs[i].cwd_len = 1;
    process.procs[i].name[0] = 'i';
    process.procs[i].name[1] = 'd';
    process.procs[i].name[2] = 'l';
    process.procs[i].name[3] = 'e';
    process.procs[i].name[4] = '0' + @as(u8, cpu_id);
    process.procs[i].name_len = 5;

    // Idle PCBs are NEVER enqueued in the rq (pickNext falls back to
    // cpu.idle_pid directly), so the assigned_cpu assignment is purely
    // bookkeeping. setState→.ready won't actually rqEnter (rqEnter
    // skips is_idle). Keep both calls anyway so the state-write path
    // is uniform across all create*() helpers.
    process.assignInitialCpu(i);
    process.setState(i, .ready);
    debug.klog("[proc] Idle PID={d} for cpu{d}, kstack_top=0x{X:0>16}\n", .{ i, cpu_id, stack_top });
    return i;
}

/// Re-plant a fresh synthetic switch frame on an EXISTING idle PCB so its CPU can
/// be re-dispatched cleanly after an S3 resume (CP2b-2b). The idle task is a
/// stateless `while (true)` loop, so restarting it from `kernelIdle` with a clean
/// stack is correct — and necessary: the CPU's live registers were lost when S3
/// powered it down, so the PCB's saved `kernel_esp` is stale and must NOT be fed
/// to `enterFirstTaskAp` as-is. Mirrors the frame-planting in `createKernelIdle`
/// but REUSES the slot (no `allocSlot`) so a PCB isn't leaked every resume. Runs
/// on the re-onlined AP, after the BSP has already observed its `alive` flag, so
/// no other CPU is touching this slot.
pub fn resetKernelIdleForResume(idle_pid: usize) void {
    const i = idle_pid;
    const slot_base = @intFromPtr(&process.kstack_pool[i]);
    const stack_top = slot_base + KSTACK_SLOT_SIZE;

    const sw_base: [*]u64 = @ptrFromInt(stack_top - dspec.kthread_bytes);
    for (0..dspec.switch_frame.count) |k| sw_base[k] = 0;
    sw_base[dspec.ret_slot] = @intFromPtr(&kernelIdle);
    sw_base[dspec.kthread_ret_pad] = 0;

    process.procs[i].kernel_esp = stack_top - dspec.kthread_bytes;
    process.procs[i].kernel_stack_top = stack_top;
    // Stale dispatch-claim from before the suspend (this idle was current
    // on the AP at power-off; the clear in switchTo's asm never ran).
    // enterFirstTaskAp re-sets it at the re-dispatch.
    @atomicStore(bool, &process.procs[i].on_cpu, false, .release);
    process.plantStackCanary(i); // re-plant base canary before re-publishing runnable
    @atomicStore(usize, &process.expected_kstack_tops[i], stack_top, .release);

    // It may still be marked .running (was current on the AP at suspend); route to
    // .ready so enterFirstTaskAp's setState(.running) is a clean transition.
    // rqEnter skips is_idle, so this never enqueues.
    process.setState(i, .ready);
}

/// Compatibility shim — old call site in main.zig. Creates the BSP's
/// kernel-mode idle and stashes it in `cpus[0].idle_pid`. Per-CPU idle
/// is the only idle book-keeping we need; pickNext filters via the
/// `is_idle` flag.
pub fn createIdleProcess() void {
    const pid = createKernelIdle(0) orelse return;
    smp.cpus[0].idle_pid = pid;
}

/// Create a generic kernel-mode task PCB. Like createKernelIdle but with
/// custom entry point, name, and priority. Used to bootstrap the desktop
/// (BSP-pinned, interactive priority) and any future kernel threads.
///
/// `entry` must be `fn() callconv(.c) noreturn` — never returns. The
/// switchTo asm `ret`s to it directly; there's no iretq frame and no user
/// mode. Function runs in CS=0x08, RSP=this PCB's kstack.
///
/// `kstack_bytes` is the stack the task needs; every task runs on its pool
/// slot (KSTACK_SIZE with a guard page below). A request past KSTACK_SIZE
/// fails: a heap-allocated stack had no guard page (an overflow silently
/// shredded neighbouring heap blocks) and was never freed.
pub fn createKernelTask(
    entry_fn_addr: usize,
    name: []const u8,
    cpu_id: u8,
    prio: Priority,
    kstack_bytes: usize,
) ?usize {
    if (kstack_bytes > KSTACK_SIZE) {
        debug.klog("[proc] createKernelTask '{s}': kstack {d} bytes > KSTACK_SIZE {d} — refused\n", .{ name, kstack_bytes, KSTACK_SIZE });
        return null;
    }
    const i = allocSlot() orelse return null;
    resetPcbExceptState(&process.procs[i]); // state stays .loading from allocSlot's CAS

    const stack_top: usize = @intFromPtr(&process.kstack_pool[i]) + KSTACK_SLOT_SIZE;

    const sw_base: [*]u64 = @ptrFromInt(stack_top - dspec.kthread_bytes);
    for (0..dspec.switch_frame.count) |k| sw_base[k] = 0;
    sw_base[dspec.ret_slot] = entry_fn_addr;
    sw_base[dspec.kthread_ret_pad] = 0;

    process.procs[i].kernel_esp = stack_top - dspec.kthread_bytes;
    process.procs[i].kernel_stack_top = stack_top;
    process.plantStackCanary(i); // P4: plant base canary BEFORE publishing the slot runnable
    @atomicStore(usize, &process.expected_kstack_tops[i], stack_top, .release);
    process.procs[i].is_idle = false;
    process.procs[i].pinned_cpu = cpu_id;
    process.procs[i].priority = prio;
    process.procs[i].page_dir_phys = 0;
    process.procs[i].last_cpu = cpu_id;
    process.procs[i].tgid = @intCast(i);
    // Boot session — the desktop kernel task leads its own session and
    // group (resetPcbExceptState); what it sysExec's inherits them.
    process.procs[i].cwd[0] = '/';
    process.procs[i].cwd_len = 1;
    const copy_len = @min(name.len, process.procs[i].name.len);
    for (0..copy_len) |k| process.procs[i].name[k] = name[k];
    process.procs[i].name_len = @intCast(copy_len);

    // pinned_cpu was set above so assignInitialCpu copies it into
    // assigned_cpu (kernel tasks always pinned, never round-robined).
    process.assignInitialCpu(i);
    process.setState(i, .ready);
    debug.klog("[proc] Kernel task PID={d} '{s}' on cpu{d} (pinned), kstack_top=0x{X:0>16} ({d} KB)\n", .{ i, name[0..copy_len], cpu_id, stack_top, kstack_bytes / 1024 });
    return i;
}

/// Publish the swap slot the calling thread has in-flight (between
/// evictFrame's phase-1 and phase-3 CAS) so process teardown can free the
/// slot if the thread is killed while parked in blockOn(.nvme_io). Called
/// by swap.evictFrame; counterpart `clearInflightSlot` runs at phase-3 /
/// rollback. Atomic so killProcess can observe it from another CPU.
pub fn setInflightSlot(slot: u32) void {
    const cur = smp.currentPid() orelse return;
    @atomicStore(u32, &process.procs[cur].swap_inflight_slot, slot, .release);
}

pub fn clearInflightSlot() void {
    const cur = smp.currentPid() orelse return;
    @atomicStore(u32, &process.procs[cur].swap_inflight_slot, 0xFFFFFFFF, .release);
}

/// Release any in-flight swap slot owned by `pid` so it isn't leaked when
/// the thread is torn down. Called from kill / destroy paths just before
/// freeing the PCB. Idempotent — the exchange makes exactly one caller the
/// owner, so a racing clearInflightSlot can't produce a double free.
pub fn reclaimInflightSlot(pid: usize) void {
    if (pid >= MAX_PROCS) return;
    // Exchange, not load-then-store: whoever reads a real slot out of the
    // channel owns it, and everyone else reads NO_SLOT. Two callers can no
    // longer both see the same slot and both free it.
    const cur = @atomicRmw(u32, &process.procs[pid].swap_inflight_slot, .Xchg, 0xFFFFFFFF, .acq_rel);
    if (cur == 0xFFFFFFFF) return;
    swap.freeSlot(cur);
}

/// Publish the frame `swapInFrame` is reading into, across the blocking
/// readPage. Counterpart of setInflightSlot for the swap-IN direction; see the
/// `swap_inflight_frame` comment in process.zig for why the leak it prevents
/// is self-amplifying.
pub fn setInflightFrame(frame: Phys) void {
    const cur = smp.currentPid() orelse return;
    @atomicStore(usize, &process.procs[cur].swap_inflight_frame, frame.raw(), .release);
}

pub fn clearInflightFrame() void {
    const cur = smp.currentPid() orelse return;
    @atomicStore(usize, &process.procs[cur].swap_inflight_frame, 0, .release);
}

/// Release any in-flight swap-in frame owned by `pid`. Same exchange-owns-it
/// discipline as reclaimInflightSlot.
///
/// Caveat, inherited rather than introduced: the NVMe read that was filling
/// this frame may still be in flight, so the frame can be handed back to the
/// PMM while a DMA write is pending against it. That is the same exposure the
/// existing writePage/CID reclaims already accept (a late CQE lands in reapCq's
/// orphan branch) — fixing it properly means teaching the NVMe layer to hold a
/// reference on the target buffer, which is a separate job. Leaking every such
/// frame instead is strictly worse: it is unbounded and it compounds.
pub fn reclaimInflightFrame(pid: usize) void {
    if (pid >= MAX_PROCS) return;
    const cur = @atomicRmw(usize, &process.procs[pid].swap_inflight_frame, .Xchg, 0, .acq_rel);
    if (cur == 0) return;
    pmm.freeFrame(Phys.of(cur));
}

/// Give back every file a dying task's own table holds, so a pipe sees its
/// end close and the last sharer of a file releases it. A lead's table goes
/// with the last thread of its group (Linux threads work on it to the end);
/// a native thread's copy with the thread.
fn dropFds(pid: usize) void {
    file_mod.dropAll(&process.procs[pid]);
}

/// Tasks in a Linux wait4, entered before the task first looks for a zombie
/// child. A child of their process becoming reapable wakes them by pid (any
/// thread of a process may wait for its children), so a wake between the
/// look and the park is kept (wake_pending).
var child_waiters: pid_set.AtomicPidSet = .{};

pub fn childWaitEnter(pid: usize) void {
    child_waiters.enter(pid);
}

pub fn childWaitLeave(pid: usize) void {
    child_waiters.leave(pid);
}

/// The pids in wait4 now, as bits (diagnostics).
pub fn childWaiterMask() [pid_set.WORDS]u64 {
    return child_waiters.snapshot();
}

/// A child of process `parent` became reapable, stopped or continued: wake
/// its wait4 sleepers. Interrupt context is fine.
pub fn wakeChildWaiters(parent: u8) void {
    if (parent >= MAX_PROCS) return;
    const group = process.procs[parent].tgid;
    // The set's locked RMW orders the zombie state store before the read.
    var it = child_waiters.members();
    while (it.next()) |w| {
        if (process.procs[w].tgid == group) process.wake(@intCast(w));
    }
}

/// True if any other process is currently blocked in waitpid waiting for this
/// dying process. waitpid wakes when its child becomes a zombie, so a parent
/// in waitpid(child_pid) or waitpid(any) needs the kid kept around as a zombie
/// rather than freed outright.
fn parentIsWaiting(child_pid: u8) bool {
    const parent = process.procs[child_pid].parent_pid;
    if (parent == 0 or parent >= MAX_PROCS) return false;
    if (process.procs[parent].state == .unused) return false;
    if (process.procs[parent].wait_kind != .waitpid) return false;
    const target = process.procs[parent].wait_target;
    return target == 0xFFFFFFFF or target == child_pid;
}

/// Kill a process by PID. Status code is recorded for the parent's waitpid.
/// Threading semantics mirror destroyCurrentWithStatus — only the last
/// thread in the tgid does the heavy process-level teardown.
/// External vs self-exit teardown. Threaded through `tearDownTask` to
/// adjust two unique steps: self-exit needs to switch CR3 to kernel
/// before destroying its own page tables, and to steer the CPU's
/// TSS rsp0 to its idle kstack before the dying slot becomes free.
const TerminateOp = enum { kill, destroy };

const SpinLock = @import("spinlock.zig").SpinLock;
var teardown_count_lock: SpinLock = .{};

/// Atomically decide whether `pid`'s teardown is the one that must free the
/// group-shared resources (page directory, GUI window, ELF buf, lazy
/// regions): true iff NO other live, unclaimed member of `tgid` remains.
///
/// Replaces the old `countThreadsInGroup(tgid) <= 1`, which was wrong twice:
///   * Kill path: the victim is already .zombie (killProcessWithStatus flips
///     state BEFORE tearDownTask), so it never counted itself — killing the
///     second-to-last member counted ONE survivor, passed `<= 1`, and freed
///     the page directory the survivor was still running on. killThreadGroup
///     walked straight into this on every multi-thread group kill.
///   * Concurrency: two members dying on different CPUs could both count the
///     other as live (nobody frees → AS leaked) or — kill+destroy interleave
///     — both reach `<= 1` (double destroyAddressSpace). The mark below is
///     serialized by the lock, so exactly the LAST claimant sees zero
///     survivors.
///
/// The mark doubles as schedule()'s re-entry gate (see PCB.teardown_marked).
/// Lock hold is a bounded 64-slot scan with no sleeps; SpinLock's preempt
/// pin keeps the holder from being preempted mid-count.
fn claimTeardown(pid: usize, tgid: u8) bool {
    teardown_count_lock.acquire();
    defer teardown_count_lock.release();
    @atomicStore(bool, &process.procs[pid].teardown_marked, true, .release);
    for (0..MAX_PROCS) |k| {
        if (k == pid) continue;
        const p = &process.procs[k];
        const s = p.state;
        // .loading excluded like countThreadsInGroup: a slot stranded
        // mid-construction (CPU panicked in clone) must not pin the
        // group's cleanup forever.
        if (s == .unused or s == .loading or s == .zombie) continue;
        if (@atomicLoad(bool, &p.teardown_marked, .acquire)) continue;
        if (p.tgid == tgid) return false;
    }
    return true;
}

/// Rate-limit the per-teardown diagnostics. A thread-churn workload
/// (schedstress spawns+reaps ~100 threads/s) makes the three klogs per
/// teardown — `[proc] destroyed` + the `[pmm-diag]` pre/post pair — a ~280
/// line/s flood of near-constant data. That doesn't wedge anymore (serial
/// load-sheds), but the ksoftirqd drain of it (slow nested-virt `outb`
/// VM-exits) still starves the compositor on cpu0 → "works but the UI is
/// frozen" (2026-06-20). Throttle to a few per ~100ms; the per-pid lifecycle
/// is still captured unconditionally in the kdbg autopsy ring
/// (procEvent(.kill/.destroy) below), so no forensic signal is lost. The
/// suppressed count is folded into the next emitted block as `hidden=N`.
const TEARDOWN_DIAG_GAP_TICKS: u64 = 10; // ~100 ms at 10 ms/tick → ≤ ~10 blocks/s
var teardown_diag_last_tick: u64 = 0; // (a) tick of the last emitted block
var teardown_diag_suppressed: u32 = 0; // (a) teardowns hidden since then

/// Common teardown for both external kill and self-destroy. Caller
/// is responsible for the entry/exit dance unique to each:
///
///   * `kill`: flip state→.zombie BEFORE calling here (the killer owns the
///     pid via the exit_requested claim; a .running victim is evicted via
///     killProcessWithStatus's case-2 IPI loop instead of being torn down
///     remotely).
///   * `destroy`: call `schedule()` + halt AFTER this returns (the
///     dying CPU is still on the dying kstack until it reschedules).
fn tearDownTask(pid: usize, status: u32, op: TerminateOp, persist_shared_dirty: bool) void {
    const my_tgid: u8 = process.procs[pid].tgid;
    // The lead as it is now: once this thread is gone its slot may be
    // reaped and taken by another.
    const lead_nr = process.procs[my_tgid].pid_nr;
    // Self-destroy: leave the AS for kernel tables BEFORE the claim. Once
    // marked, this thread no longer keeps the AS alive — a sibling dying on
    // another CPU can be the last claimant and free the page tables (PML4
    // included) while this CPU would still be walking them. Nothing below
    // touches user memory. External kill runs on the killer's own CR3 (the
    // victim's is not active anywhere), so no switch there.
    if (op == .destroy) {
        pcid_mod.loadCr3(@import("../mm/paging.zig").getKernelPageDirPhys(), 0, smp.myCpu().cpu_id);
    }
    const last_in_group = claimTeardown(pid, my_tgid);
    // Throttle the teardown diagnostics (see TEARDOWN_DIAG_GAP_TICKS). One
    // decision gates the [proc] line + both [pmm-diag] lines below, so the
    // pre/post pair stays consistent (both emit or both suppress). tick_count
    // is BSP-advanced, so the gate always reopens — forward progress is
    // guaranteed even under a churn storm.
    const now_tick = process.tick_count;
    const log_teardown = (now_tick -% @atomicLoad(u64, &teardown_diag_last_tick, .monotonic)) >= TEARDOWN_DIAG_GAP_TICKS;
    const pmm_diag = @import("../mm/pmm.zig");
    if (log_teardown) {
        @atomicStore(u64, &teardown_diag_last_tick, now_tick, .monotonic);
        const hidden = @atomicRmw(u32, &teardown_diag_suppressed, .Xchg, 0, .monotonic);
        debug.klog("[proc] {s} {d} {s} (status=0x{X}) hidden={d}\n", .{
            if (last_in_group) "Process" else "Thread",
            pid,
            if (op == .kill) "killed" else "destroyed",
            status,
            hidden,
        });
        // PMM diagnostic: free frames immediately before this proc's pages
        // get reclaimed. Pair with the post-teardown [pmm-diag] line below to
        // see whether teardown returned everything to PMM.
        debug.klog("[pmm-diag] pre-teardown free={d}/{d}\n", .{ pmm_diag.freeFrameCount(), pmm_diag.managedFrameCount() });
    } else {
        _ = @atomicRmw(u32, &teardown_diag_suppressed, .Add, 1, .monotonic);
    }

    // Force-release any registered Mutex held by the dying pid. Done
    // BEFORE the cleanup steps below because some of them
    // (virtio_gpu.ctxDestroy → the queue's large buffer) would
    // recursively try to acquire a lock the dying pid still owns,
    // deadlocking the entire GPU pipeline. Each released lock logs a
    // [lock-dump] line so the autopsy shows what was stranded.
    //
    // First the GPU command slots of a thread killed while waiting on one,
    // which nobody would ever free: before its locks go, so the large
    // buffer's next user finds slot 0 freed (or given up, while the device
    // still holds it).
    @import("../driver.zig").virtio_gpu.releaseTask(@intCast(pid));
    @import("spinlock.zig").releaseMutexesOwnedBy(@intCast(pid));

    // If this thread was parked in blockOn(.nvme_io) inside swap.evictFrame's
    // writePage, wake() against a .zombie is a no-op and the in-flight swap
    // slot would leak. Reclaim it before the AS teardown frees the in-flight
    // frame via teardownNonPresent. (Reviewer-caught 2026-05-23.)
    reclaimInflightSlot(pid);

    // Mirror for the swap-IN direction: a thread killed while parked in
    // blockOn(.nvme_io) inside swapInFrame's readPage holds a freshly
    // allocated frame that no PTE and no other field names (the PTE still
    // reads SWAPPED, so the AS teardown below frees the slot and never the
    // frame). Without this the 4 KiB is gone for the uptime of the machine.
    reclaimInflightFrame(pid);

    // Same hazard for the FS read path: a thread killed while parked in
    // nvme.readSectorsPipelined's wave-wait holds up to PIPELINE_DEPTH NVMe
    // CID slots (.wake = .pid). wake() against the .zombie is a no-op, so
    // without an explicit reclaim those slots stay active forever and starve
    // the ring. Safe post-kill: a late CQE hits reapCq's orphan branch.
    @import("../driver.zig").nvme.reclaimWaitersForPid(@intCast(pid));

    // The per-mount ext2 block-cache lock (sleeping) can likewise be held by a
    // thread killed while blocked on NVMe I/O inside readBlock/writeBlock. Left
    // stranded, the whole filesystem deadlocks (every later ext2 op sleeps on
    // the dead owner forever). Release it here, mirroring the NVMe reclaim above.
    // (2026-06-04 SMP ext2 on-disk-corruption fix.)
    @import("../fs/ext2/block.zig").releaseLockIfHeld(@intCast(pid));

    // The group's address-space lock, likewise: a thread killed while it held
    // the read side (a fault parked on swap-in or a page-cache fill) or waited
    // for the lock would wedge every other thread of the group at its next
    // fault or mmap.
    if (process.procs[my_tgid].as_lock.dropPid(pid)) {
        debug.klog("[proc] pid={d} died holding or awaiting the as_lock of pid {d}; released\n", .{ pid, my_tgid });
    }
    const foreign = process.procs[pid].foreign_as_lock;
    if (foreign != process.NO_FOREIGN_LOCK and foreign < MAX_PROCS and process.procs[foreign].as_lock.dropPid(pid)) {
        debug.klog("[proc] pid={d} died holding or awaiting the as_lock of pid {d}; released\n", .{ pid, foreign });
    }

    // io_uring instances owned by this pid: free the slot-table entries.
    // The underlying ring memory is freed by the LazyRegion shm.release in
    // the per-AS cleanup below; this just recycles the kernel bookkeeping.
    @import("../ipc/iouring.zig").releaseAllForPid(@intCast(pid));

    // fdpoll waiters tied to this pid — drop them before iouring shutdown
    // completes, since the OP_POLL pending slots reference them by index
    // and the worker may already have recycled the Instance slot above.
    @import("../ipc/fdpoll.zig").releaseAllForPid(@intCast(pid));
    // Killed inside poll, waitEvent, wait4 or a pipe: its bits would wake
    // the slot's next task.
    @import("../ipc/fdpoll.zig").sleeperLeave(pid);
    @import("../ui/desktop/event_wait.zig").leave(pid);
    childWaitLeave(pid);
    @import("pipe.zig").leave(pid);

    // A native thread's own copy of the table (a Linux thread's is empty).
    if (pid != my_tgid) dropFds(pid);

    // Resources reachable in any address space (GUI window state, GPU
    // contexts, debug symbols all live in heap / driver structures, not
    // user memory). Safe to free before the CR3 switch below.
    //
    // All three live on the LEAD PCB (loadAndStart / GUI / GPU attach to the
    // exec'd process, which is its own lead) — index by my_tgid, not pid:
    // when the last dier is a WORKER (lead exited earlier and sits pinned as
    // a zombie), indexing by pid freed the worker's (empty) fields and
    // leaked the lead's window/ctx/symbols.
    //
    // A GUI window goes with the task that made it (ui/gui_window.zig).
    if (!last_in_group) @import("../ui/gui_window.zig").taskEnded(@intCast(pid));
    if (last_in_group) {
        const lead_res = &process.procs[my_tgid];
        const desktop = @import("../ui/desktop.zig");
        // Every window of the group, one a member ending beside us has yet
        // to take included. Its framebuffer and GPU slot are released
        // further down, once the address space is gone.
        _ = desktop.destroyGuiWindow(.{ .group = my_tgid });
        const virtio_gpu = @import("../driver.zig").virtio_gpu;
        if (lead_res.gpu_has_ctx) {
            if (!virtio_gpu.ctxDestroy(lead_res.gpu_ctx_id)) {
                debug.klog("[proc] GPU ctx {d} destroy failed for pid {d}\n", .{ lead_res.gpu_ctx_id, my_tgid });
            }
            lead_res.gpu_has_ctx = false;
            lead_res.gpu_ctx_id = 0;
        }
        if (lead_res.sym_table) |st| {
            symbols.freeSymTable(st);
            lead_res.sym_table = null;
        }
    }

    if (last_in_group) {
        const lead = &process.procs[my_tgid];
        // A member that claimed earlier may not have released its io_uring
        // instances yet; their workers copy on these tables, under the read
        // side — so before the write side below, which would wait for them.
        if (lead.page_directory != null) @import("../ipc/iouring.zig").releaseAllForGroup(my_tgid);
        // Readers from another group (/proc) hold the read side while they
        // walk these tables and regions: they finish first.
        lead.as_lock.acquire();
        defer lead.as_lock.release();
        if (lead.page_directory) |pd| {
            vmm.destroyAddressSpace(pd, Phys.of(lead.page_dir_phys));
            lead.page_directory = null;
            lead.page_dir_phys = 0;
            if (lead.pcid != 0) {
                pcid_mod.free(lead.pcid);
                lead.pcid = 0;
            }
        }
        dropFds(my_tgid);
        @import("../fs/locks.zig").processGone(lead.pid_nr);
        freeElfBuf(lead);
        const shm = @import("../mm/shm.zig");
        const page_cache = @import("../mm/page_cache.zig");
        for (lead.regions.slice()) |r| {
            // Shared-anon: drop this AS's refcount. The shm registry frees
            // its frames at refcount==0, so peers keep working until they
            // also exit / munmap.
            if (r.shm_id != shm.SHM_INVALID) shm.release(r.shm_id);
            // MAP_SHARED file region: destroyAddressSpace above already dropped
            // this AS's PTEs, so any of its pages now mapped by no one else sit
            // at refcount==1 (cache-only) with their dirty bit still set.
            //
            //   * Any end but one for memory (an exit, a signal, a kill): LEAVE
            //     them dirty. pgflushd — guaranteed running, since a cache_shared
            //     region can only exist if ext2 init'd, which is what spawns it
            //     — writes them back within ≤1 interval, then its refcount-gated
            //     clear makes them evictable. So a process that ends WITHOUT
            //     msync still durably persists its final window of writes.
            //   * Ended for its memory (lead.oom_ended, the OOM policy): clear
            //     the dirty bit WITHOUT writeback. That path reaches here under
            //     memory pressure and must free these pages NOW, not wait for
            //     the daemon; dropping the unflushed writes is the right trade
            //     when the alternative is staying out of memory. (Else they
            //     would linger dirty-and-unevictable — chooseSlot skips dirty.)
            //
            // Either way, pages another AS still maps (refcount>1) are untouched:
            // clearDirtyRangeCacheOnly is refcount-gated, and the surviving peer
            // keeps them dirty (pgflushd re-flushes while it lives). Safe against
            // an inode being freed+reused inside the widened dirty window: ext2
            // freeInode → page_cache.invalidateFile drops EVERY entry (dirty
            // included), so a stale page can't be written to a reused inum.
            if (r.cache_inode != 0 and r.cache_shared and !persist_shared_dirty and !@atomicLoad(bool, &lead.exits_clean, .acquire) and
                @atomicLoad(bool, &lead.oom_ended, .acquire))
            {
                _ = page_cache.clearDirtyRangeCacheOnly(page_cache.ext2FileId(r.cache_inode), r.cache_off, r.end - r.start);
            }
            // The mapping's hold on its inode, last: until here the inode
            // could not go to another file. One this frees waits for
            // pgflushd (ext2.freeQueued): teardown does no I/O.
            r.dropBacking();
            if (!r.buf_owned) continue;
            const src = r.source orelse continue;
            pmm.releaseContiguous(kbufPhys(src), r.buf_pages);
        }
        lead.regions.deinit();
        lead.heap_start = 0;
    }

    // The group's memory in the GPU's host-memory window: the blobs it
    // mapped (sysGpuMapBlob; they outlive sysGpuCtxDestroy, so not under
    // gpu_has_ctx) and its windows' GPU compositor slots. Those pages go to
    // another process next, so only now, with the address space that mapped
    // them destroyed: until then a kernel copy made for the group (an
    // io_uring worker's) could still land in them.
    if (last_in_group) {
        const virtio_gpu = @import("../driver.zig").virtio_gpu;
        virtio_gpu.releaseOwnedBlobs(virtio_gpu.BlobOwner.process(my_tgid));
        @import("../ui/gpu_compositor.zig").releaseWindowImagesOf(my_tgid);
    }

    // Per-thread: drop the borrowed page directory pointer so a future
    // zombie reap doesn't double-free, and stamp exit_status for waitpid.
    // EXCEPT for a lead about to be pinned (workers still live): the last
    // worker's group cleanup frees the address space THROUGH this PCB —
    // nulling it here would skip that destroyAddressSpace and leak the
    // whole AS. The cleanup itself nulls the fields after the free.
    if (pid != my_tgid or last_in_group) {
        process.procs[pid].page_directory = null;
        process.procs[pid].page_dir_phys = 0;
        process.procs[pid].pcid = 0;
    }
    process.procs[pid].exit_status = status;
    // The process's CPU time keeps what this thread used.
    if (pid != my_tgid) @import("sched.zig").foldCpuTicks(pid, my_tgid);

    // Self-destroy: steer this CPU's TSS rsp0 to its own idle kstack
    // BEFORE the slot becomes free / reusable. Without this, there's a
    // window between `cpu.current_pid = null` below and the next
    // schedule() (which would call setTssRsp0) where rsp0 still points
    // at the dying task's kstack. If another CPU recycles that PCB slot
    // (or kstack) in that window, both CPUs end up sharing one kstack
    // for IRQ entry — exactly the cross-stack aliasing class B.3
    // catches and the suspected root of task #267 (KASAN UAF on freed
    // kstack). Stress test (boot_mode=3) reliably reproduced this on
    // iter ~2 before the steer-to-idle was added.
    if (op == .destroy) {
        const cpu = smp.myCpu();
        if (cpu.idle_pid) |idle| {
            gdt.setTssRsp0(idle, process.procs[idle].kernel_stack_top);
        }
        // Outbound TOCTOU bracket: cpu.current_pid is about to be cleared,
        // but procs[pid].state stays .running until the setState
        // (.zombie/.unused) below. A cross-CPU pcb_invariants scan in this
        // window would false-fire "state==.running but no owner". Mirror
        // of dispatching_in_pid for the outbound direction; cleared after
        // the setState lands further down.
        cpu.dispatching_out_pid = @intCast(pid);
        // The final schedule() clears this slot's on_cpu once off the
        // kstack; allocSlot waits for that.
        @import("sched.zig").noteDying(pid);
        @import("../debug/pid_trace.zig").setCurrentPid(cpu, null);
    }

    // Decide zombie vs immediate free. Parent alive AND lead thread →
    // keep as zombie so the parent's waitpid can read exit_status.
    // No parent / parent gone / worker thread → free immediately so the
    // slot can be reused. Workers (non-lead threads) are joined via the
    // user-space TCB futex, never via waitpid, so they auto-reap
    // regardless of parent state.
    const parent = process.procs[pid].parent_pid;
    const parent_there = hasParent(pid);
    // A zombie is for a parent that reads exit statuses: not for one that
    // set SIGCHLD aside.
    const parent_alive = parent_there and !signals.discardsChildren(&process.procs[parent]);
    const is_worker_thread = pid != my_tgid;
    // A LEAD that dies before its workers must stay pinned as a zombie even
    // with no parent to reap it: every worker derefs procs[tgid] via
    // leader() on each page fault / mmap / brk, and the last worker's
    // teardown frees the group resources THROUGH this PCB. Letting the slot
    // go .unused (or be waitpid-reaped early — findZombieChild's guard)
    // while workers live means the slot gets reused and the workers read a
    // stranger's PCB — and the last worker then destroys the new occupant's
    // address space. Linux pins group leaders the same way.
    const must_pin_as_lead = !is_worker_thread and !last_in_group;

    // Reparent children before changing state — otherwise a child's
    // parent_pid could point at a slot that gets reused by a future
    // create() and the child would think a stranger is its parent.
    // Children are the process's (parent_pid = the lead): they move when
    // the group empties, whichever member is the last. Until then a worker
    // may wait4 them, and the lead's slot is still the group's.
    if (last_in_group) {
        hangUpOrphanedGroups(my_tgid);
        reparentChildren(my_tgid);
    }

    if ((parent_alive and !is_worker_thread) or must_pin_as_lead) {
        process.procs[pid].death_tick = process.tick_count;
        // Before the state: whoever finds the zombie finds this too. (The
        // kill path made it a zombie before the teardown; setState's lock
        // is the fence that puts the flag ahead of what is read below.)
        @atomicStore(bool, &process.procs[pid].exit_done, true, .release);
        process.setState(pid, .zombie);
        if (parent_alive) {
            if (parentIsWaiting(@intCast(pid))) process.wake(parent);
            wakeChildWaiters(parent);
            // SIGCHLD is default-ignored, so this is a no-op for shells
            // that don't care; shells with a SIGCHLD handler can do
            // non-blocking reaping. Sent regardless of waitpid state per POSIX.
            // Not for a lead that stays pinned: its process lives on, and
            // the last thread out sends the one that counts.
            if (!must_pin_as_lead) notifyParentOfExit(parent, pid);
        }
        // Nobody will wait for it: the parent keeps no zombies, or ended
        // since the look at it above — it raised `orphan` and looked for a
        // zombie, this looks at `orphan` after becoming one, and one of
        // the two frees it. Refused while workers still pin a lead.
        if (!parent_alive or @atomicLoad(bool, &process.procs[pid].orphan, .seq_cst)) {
            dropZombie(@intCast(pid), process.procs[pid].pid_nr);
        }
    } else {
        // A parent that keeps no zombies may be in wait4 all the same: it
        // looks again and finds this child gone. Read before the slot goes.
        const tell = parent_there and !is_worker_thread;
        const waiting = tell and parentIsWaiting(@intCast(pid));
        freeSlot(pid);
        if (tell) {
            if (waiting) process.wake(parent);
            wakeChildWaiters(parent);
        }
    }

    // After an execve from a thread the program's main thread is a worker:
    // how the last one ends is how the process ends, as the lead's end is
    // for any other process. A group that exits or is killed as a whole
    // has its status on the lead already.
    if (is_worker_thread and last_in_group and process.procs[my_tgid].pid_nr == lead_nr and
        @atomicLoad(bool, &process.procs[my_tgid].main_is_worker, .acquire) and
        !@atomicLoad(bool, &process.procs[my_tgid].group_exiting, .seq_cst))
    {
        process.procs[my_tgid].exit_status = status;
    }

    // A worker that outlived its lead: the lead sits pinned as a zombie
    // until no member is left, and this one is gone now. The lead's parent
    // looks again (its wait4 saw this worker alive — findZombieChild's
    // guard — and went back to sleep), or with nobody to wait for it the
    // lead is freed here: by whichever member is done last, refused while
    // another lives. A lead that turns zombie after this look finds this
    // worker gone and does the same itself.
    if (is_worker_thread and process.procs[my_tgid].state == .zombie and process.procs[my_tgid].pid_nr == lead_nr) {
        const lp = process.procs[my_tgid].parent_pid;
        if (hasParent(my_tgid) and !signals.discardsChildren(&process.procs[lp])) {
            if (parentIsWaiting(my_tgid)) process.wake(lp);
            wakeChildWaiters(lp);
            if (last_in_group) notifyParentOfExit(lp, my_tgid);
        } else {
            dropZombie(my_tgid, lead_nr);
        }
    }

    // Release the outbound TOCTOU bracket — pid's state is no longer
    // .running so pcb_invariants' running-but-no-owner check is no
    // longer fooled. Only applies to op == .destroy; the kill path
    // never claimed it (the victim's CPU runs the .destroy branch
    // instead per killProcessWithStatus's IPI protocol).
    if (op == .destroy) {
        smp.myCpu().dispatching_out_pid = 0xFFFF;
    }

    @import("../debug/kdbg.zig").procEvent(
        if (op == .kill) .kill else .destroy,
        @intCast(pid),
        parent,
        status,
    );

    // Post-teardown PMM count. Diff against [pmm-diag] pre-teardown
    // above to see how many frames this exit returned to the pool. A
    // process holding 1 MB of user pages should give back ~256 frames;
    // anything less is a leak in the destroy path. Gated on the same throttle
    // decision as the pre-teardown line so the pair stays matched.
    if (log_teardown) {
        debug.klog("[pmm-diag] post-teardown free={d}/{d} (pid={d})\n", .{ pmm_diag.freeFrameCount(), pmm_diag.managedFrameCount(), pid });
    }
}

/// External kill (Phase 3 protocol).
///
/// Atomic ownership claim via exit_requested xchg means at most one
/// killer ever runs the teardown for a given pid; concurrent killers
/// just wait for the winning one to finish.
///
/// Per-state dispatch:
///   * .running on this CPU: escalate to destroyCurrentWithStatus.
///   * .running on other CPU: IPI + spin until state leaves .running.
///     Target CPU's schedule() observes exit_requested at its entry
///     and runs destroyCurrentWithStatus on its own kstack — the
///     teardown happens there. Killer just observes the resulting
///     .zombie/.unused state and returns.
///   * .ready / .sleeping: killer owns pid (exit_requested gate in
///     pickNext keeps any racing CPU from dispatching it), so killer
///     sets state=.zombie via setState (rqLeave fires) and runs
///     tearDownTask directly.
///   * .loading: wait (bounded) for the constructor to finish, then
///     handle as above — tearing down a mid-construction PCB races the
///     constructing CPU's writes.
///
/// The schedule()-side save bypass (prev_save→NONE_PID when prev's
/// state is .zombie/.unused) means switchTo never lands an asm save in
/// a doomed PCB slot, regardless of whose CPU is doing the teardown.
/// That replaces the old save_in_flight_prev bracketing.
pub fn killProcessWithStatus(pid: u8, status: u32) void {
    if (pid >= MAX_PROCS) return;
    {
        const init_state = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire);
        if (init_state == @intFromEnum(State.unused) or
            init_state == @intFromEnum(State.zombie)) return;
    }

    // The first killer's status stands, as on Linux, however long the task
    // takes to end; it is there before exit_requested says to read it.
    process.offerKillStatus(&process.procs[pid], status);

    // Atomic ownership claim — only one killer runs teardown per pid.
    // .Xchg returns the previous value; if it was already true another
    // killer is in flight, so we just wait for terminal state and bail.
    const prev_req = @atomicRmw(bool, &process.procs[pid].exit_requested, .Xchg, true, .acq_rel);
    if (prev_req) {
        var spin: u32 = 0;
        while (spin < 10_000_000) : (spin += 1) {
            const s = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire);
            if (s == @intFromEnum(State.zombie) or s == @intFromEnum(State.unused)) return;
            // Finishing a no-kill section or its own teardown: it dies on
            // its own, and may need this CPU to.
            if (!process.doomed(pid)) return;
            asm volatile ("pause" ::: .{ .memory = true });
        }
        debug.klog("[kill] WARN: pid={d} concurrent-killer wait timed out\n", .{pid});
        return;
    }

    // The claim may be ours and the status an earlier killer's.
    const first_status = process.killStatus(&process.procs[pid]);

    // Case 1: self-kill (current CPU is running pid). Escalate to the
    // self-destroy path, which steers TSS rsp0 to idle and never returns.
    if (smp.currentPid()) |cur| {
        if (cur == pid) {
            destroyCurrentWithStatus(first_status);
            unreachable;
        }
    }

    const apic = @import("../irq/apic.zig");
    const my_lapic = apic.getLapicId();
    var ipi_attempts: u32 = 0;
    var loading_waits: u32 = 0;

    while (true) {
        // Inside a no-kill section (an ext2 operation) it is still
        // dispatched, finishes the operation and dies at its next
        // schedule(). Read before the state: once it reads doomed, a task
        // off-CPU is never dispatched again, and one on-CPU dies at its next
        // schedule(). The one gap — running when read, then into a section
        // and asleep before the state read — case 3 closes with nokill_seq.
        const seq = @atomicLoad(u32, &process.procs[pid].nokill_seq, .acquire);
        if (!process.doomed(pid)) {
            endWaitOfKilled(pid);
            return;
        }
        const snap = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire);
        if (snap == @intFromEnum(State.zombie) or snap == @intFromEnum(State.unused)) return;

        if (snap == @intFromEnum(State.loading)) {
            // Mid-construction: cloneCurrent/create on another CPU is still
            // writing this PCB + kstack. Tearing it down NOW races the
            // constructor — it would keep initializing a freed slot and its
            // final setState(.ready) would revive it (reachable via ^C →
            // killThreadGroup landing on a clone child mid-pthread_create:
            // tgid is set early in the constructor). Wait for construction
            // to finish; our exit_requested claim already blocks pickNext
            // from ever dispatching it, so the next loop round kills the
            // then-.ready pid cleanly on this CPU.
            loading_waits += 1;
            if (loading_waits > 64) {
                // Stranded .loading (constructor's CPU panicked mid-clone).
                // Pre-existing leak shape — leave the slot rather than
                // corrupt it; countThreadsInGroup/claimTeardown both
                // already exclude .loading so it can't pin a group.
                debug.klog("[kill] WARN: pid={d} stuck .loading, giving up\n", .{pid});
                return;
            }
            var lspin: u32 = 0;
            while (lspin < 1_000_000) : (lspin += 1) {
                const s2 = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire);
                if (s2 != @intFromEnum(State.loading)) break;
                asm volatile ("pause" ::: .{ .memory = true });
            }
            continue;
        }

        if (stillOnCpu(pid, snap)) {
            // Case 2: another CPU is running pid. IPI to wake it into
            // schedule(); schedule's exit_requested check at top runs
            // destroyCurrentWithStatus on the target CPU.
            var target_lapic: ?u32 = null;
            for (&smp.cpus) |*c| {
                if (!c.alive) continue;
                if (c.lapic_id == my_lapic) continue;
                if (smp.peekCurrentPid(c.cpu_id)) |cp| {
                    if (cp == pid) {
                        target_lapic = c.lapic_id;
                        break;
                    }
                }
            }
            if (target_lapic) |tl| {
                if (process.kickVector()) |v| apic.sendIPI(tl, v);
            }
            ipi_attempts += 1;
            if (ipi_attempts > 16) {
                debug.klog("[kill] WARN: gave up evicting pid={d} after 16 IPI rounds\n", .{pid});
                return;
            }
            var spin: u32 = 0;
            while (spin < 1_000_000) : (spin += 1) {
                const s = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire);
                // Into a call or a no-kill section meanwhile: not ours.
                if (!stillOnCpu(pid, s) or !process.doomed(pid)) break;
                asm volatile ("pause" ::: .{ .memory = true });
            }
            continue;
        }

        // Case 3: .ready / .sleeping (.loading is parked above until the
        // constructor finishes). Killer owns pid via
        // exit_requested xchg + pickNext skip → no CPU will dispatch it.
        // Safe to setState + tearDown directly. (parent reaping AFTER
        // tearDown is naturally serialized via the wake() inside tearDown
        // — parent was blocked in waitpid until tearDown wakes it.)
        //
        // Off-CPU now. If it went into a no-kill section since the first
        // look, it isn't ours. The claim is a CAS from the state seen: it
        // fails if a CPU that read exit_requested before we set it picked
        // the task meanwhile.
        if (!process.doomed(pid) or @atomicLoad(u32, &process.procs[pid].nokill_seq, .acquire) != seq) continue;
        if (!@import("sched.zig").setStateFrom(pid, @enumFromInt(snap), .zombie)) continue;
        // External kill (user kill / Ctrl-C / fatal signal): clear unflushed
        // shared dirty pages, same as today. A killed process makes no msync
        // guarantee; persisting its final window is deferred (the graceful
        // self-exit path opts in via destroyCurrentGraceful).
        //
        // A kill of this task now waits for the teardown: ending here would
        // leave the victim half gone, its locks held by nobody.
        process.noKillEnter();
        tearDownTask(pid, first_status, .kill, false);
        process.noKillLeave();
        return;
    }
}

/// A killed task that is not torn down from outside. Inside a Linux call
/// it ends as the call returns: a wait it sleeps in ends now, and a
/// job-control stop no longer holds it. In a no-kill section or its own
/// teardown it needs nothing.
fn endWaitOfKilled(pid: u8) void {
    const p = &process.procs[pid];
    if (!@atomicLoad(bool, &p.in_call, .acquire)) return;
    @atomicStore(bool, &p.job_stopped, false, .seq_cst);
    process.wake(pid);
    process.kickReschedule(pid);
}

/// Wake again the killed tasks that are still inside a Linux call: a wake
/// that came before the call's wait began is not lost for good, and a call
/// that does not end is named. From the timer, once a second.
pub fn nudgeKilled() void {
    for (&process.procs, 0..) |*p, i| {
        if (!@atomicLoad(bool, &p.exit_requested, .acquire) or !@atomicLoad(bool, &p.in_call, .acquire)) {
            p.kill_nudges = 0;
            continue;
        }
        if (p.state == .unused or p.state == .zombie or p.state == .loading) continue;
        p.kill_nudges +|= 1;
        if (p.kill_nudges == 5) {
            debug.klog("[kill] pid={d} '{s}' is killed and still inside a call after 5 s\n", .{ i, std.mem.sliceTo(&p.name, 0) });
            process.dumpSyscallRing(@intCast(i));
        }
        endWaitOfKilled(@intCast(i));
    }
}

/// pid (in state `state`) still executes on its CPU: .running, or .sleeping /
/// .ready while that CPU hasn't switched away yet — between a blocker's
/// setState(.sleeping) and its yield, or a preempted task before its context
/// is saved. Torn down from here, it could roll back to .running past the
/// teardown and return to user mode on a freed address space.
fn stillOnCpu(pid: u8, state: u8) bool {
    if (state == @intFromEnum(State.running)) return true;
    if (state != @intFromEnum(State.sleeping) and state != @intFromEnum(State.ready)) return false;
    return @atomicLoad(bool, &process.procs[pid].on_cpu, .acquire);
}

/// Tear down a process its constructor still holds in .loading, after a
/// loader step failed. Only the constructor may: killers wait for .loading
/// to end (killProcess would wait on itself) and pickNext never dispatches
/// it. With no parent yet, the slot goes straight back to .unused.
pub fn abortLoading(pid: u8) void {
    std.debug.assert(process.procs[pid].state == .loading);
    process.setState(pid, .zombie);
    tearDownTask(pid, 0, .kill, false);
}

/// Kill a process by PID (status defaults to 0 — for callers that don't care
/// or aren't routing through sysKill). Most internal callers (desktop
/// close-button, cli `kill` command) use this.
pub fn killProcess(pid: u8) void {
    killProcessWithStatus(pid, 0);
}

/// POSIX exit_group semantics for multi-threaded processes. When a fatal
/// default-action signal (term/core) fires on one thread, the WHOLE thread
/// group must die — otherwise cloned peers keep running with the leader's
/// address space and hold all the memory the leader thought it freed.
/// (Without this, ^C on mtswap kills only the leader; pid 5 / pid 6 peers
/// keep evicting until OOM. See [[ctrlc-mtswap-wedge]].)
///
/// Walks every PCB whose `tgid` matches and kills it via the existing
/// killProcessWithStatus path — peers first, self last. The self-kill
/// (destroyCurrentWithStatus inside killProcessWithStatus's case-1) never
/// returns. Idempotent re: peers racing into this from concurrent fatal
/// signals: killProcessWithStatus's exit_requested xchg collapses duplicates.
/// ctx: irq-ok — from IRQ0 (a signal's default action) the group is the
/// caller's own: no peer is last_in_group while the caller lives, so the
/// Mutex-taking teardown runs in its self-destroy, past hardirqReset().
pub fn killThreadGroup(tgid: u8, status: u32) void {
    const my_pid_opt = smp.currentPid();

    // A lead whose thread went first sits pinned while the group lives (a
    // main thread that exited, an execve from another thread): the status
    // its parent reads is how the group ends.
    if (tgid < MAX_PROCS and process.procs[tgid].state == .zombie and groupHasOtherLive(tgid)) {
        process.procs[tgid].exit_status = status;
    }
    // Phase 1: kill every peer OTHER than the current thread. Defer self so
    // tearDownTask on peers (which reads procs[tgid].regions etc) can
    // finish before we tear our own kstack out from under this call.
    if (tgid < MAX_PROCS) @atomicStore(bool, &process.procs[tgid].group_exiting, true, .seq_cst);
    killPeers(tgid, my_pid_opt, status);

    // Phase 2: if current is in the group, self-destroy. Mirrors the case-1
    // self-escalation inside killProcessWithStatus — destroyCurrentWithStatus
    // never returns.
    if (my_pid_opt) |cur| {
        const cur_pcb = &process.procs[cur];
        if (cur_pcb.tgid == tgid) {
            const s = cur_pcb.state;
            if (s != .unused and s != .zombie) {
                // An earlier killer's status stands.
                process.offerKillStatus(cur_pcb, status);
                destroyCurrentWithStatus(process.killStatus(cur_pcb));
                unreachable;
            }
        }
    }
}

/// Kill every live member of `tgid` but `except`.
fn killPeers(tgid: u8, except: ?usize, status: u32) void {
    var i: u8 = 0;
    while (i < MAX_PROCS) : (i += 1) {
        const p = &process.procs[i];
        const s = p.state;
        if (s == .unused or s == .zombie) continue;
        if (p.tgid != tgid) continue;
        if (except) |cur| if (cur == i) continue;
        killProcessWithStatus(i, status);
    }
}

/// Kill every other thread of the caller's group and wait until they are
/// gone (a killed thread inside a no-kill section finishes it first). For
/// execve, which then drops the address space they ran on: it waits for
/// as long as that takes, as Linux's de_thread does.
///
/// The caller need not be the lead: the lead is then one of the threads
/// that go, and its slot stays pinned with the process's state, as when a
/// main thread exits before the others.
pub fn killOtherThreads() void {
    const me = smp.currentPid() orelse return;
    const tgid = process.procs[me].tgid;
    // Holds off clones from the threads while they die.
    @atomicStore(bool, &process.procs[tgid].group_exiting, true, .seq_cst);
    killPeers(tgid, me, 0);
    var waited_s: u32 = 0;
    while (groupHasLiveBeside(tgid, me)) {
        var d = @import("../util/deadline.zig").Deadline.ms(5000, "execve: other threads");
        while (groupHasLiveBeside(tgid, me) and d.live()) @import("sched_asm.zig").softYield();
        if (groupHasLiveBeside(tgid, me)) {
            waited_s += 5;
            debug.klog("[exec] pid={d}: threads of the group still alive after {d} s\n", .{ me, waited_s });
        }
    }
    @atomicStore(bool, &process.procs[tgid].group_exiting, false, .seq_cst);
}

/// The caller's is the one execve its process commits now: false while
/// another thread's is. Two at once would each wait for the other to die.
pub fn execBegin() bool {
    const me = smp.currentPid() orelse return false;
    const lead = process.leader(&process.procs[me]);
    return @cmpxchgStrong(bool, &lead.execing, false, true, .acq_rel, .acquire) == null;
}

/// The execve execBegin let in is over, taken or failed.
pub fn execEnd() void {
    const me = smp.currentPid() orelse return;
    @atomicStore(bool, &process.leader(&process.procs[me]).execing, false, .release);
}

/// True while group `tgid` has a live member other than `me`.
fn groupHasLiveBeside(tgid: u8, me: usize) bool {
    for (0..MAX_PROCS) |k| {
        if (k == me) continue;
        const s = process.procs[k].state;
        if (s == .unused or s == .loading or s == .zombie) continue;
        if (process.procs[k].tgid == tgid) return true;
    }
    return false;
}

/// The per-process image fields execve trades between the caller and the
/// slot its new image was built in.
const IMAGE_FIELDS = .{
    "page_directory", "page_dir_phys", "pcid",      "regions",       "heap_start",
    "user_brk",       "brk_base",      "mmap_top",  "stack_base",    "elf_buf",
    "elf_buf_pages",  "text_inum",     "sym_table", "swap_clock_va", "arg_start",
    "arg_end",        "env_end",       "auxv_start", "auxv_end",
};

fn swapImages(p: *PCB, t: *PCB) void {
    p.as_lock.acquire();
    defer p.as_lock.release();
    // Nobody else reaches `t`: held in .loading, never dispatched.
    t.as_lock.acquire();
    defer t.as_lock.release();
    inline for (IMAGE_FIELDS) |f| std.mem.swap(@TypeOf(@field(p, f)), &@field(p, f), &@field(t, f));
}

/// execve's commit, past which there is no going back: the caller, alone
/// in its group (killOtherThreads), takes the address space and image
/// built in `img` (elf_loader.loadForExec, held in .loading); `img` takes
/// the process's old ones and is torn down with them, as an exiting process
/// would be (MAP_SHARED dirty pages stay for pgflushd). Identity, fds,
/// parent and children stay the process's.
///
/// The process's state is on its lead's slot, also when the caller is
/// another thread and the lead's thread is gone (killOtherThreads): the new
/// program then runs in the caller's slot, under the process's pid and the
/// caller's tid.
pub fn takeExecImage(img: usize) void {
    const me = smp.currentPid() orelse return;
    const p = &process.procs[me];
    const lead = process.leader(p);
    const t = &process.procs[img];
    swapImages(lead, t);
    // A thread runs on its own copies of the lead's three.
    p.page_directory = lead.page_directory;
    p.page_dir_phys = lead.page_dir_phys;
    p.pcid = lead.pcid;
    if (p != lead) @atomicStore(bool, &lead.main_is_worker, true, .release);
    // Onto the new tables before the old ones go.
    pcid_mod.loadCr3(p.page_dir_phys, p.pcid, smp.myCpu().cpu_id);

    // Handlers were code of the old image: they go back to the default.
    // What is ignored stays ignored, and the mask and pending signals are
    // the process's still. On the lead's slot and the caller's alike.
    for ([_]*PCB{ lead, p }) |q| {
        q.name = t.name;
        q.name_len = t.name_len;
        q.argv = t.argv;
        q.arg_lens = t.arg_lens;
        q.argc = t.argc;
        q.exe_path = t.exe_path;
        q.exe_path_len = t.exe_path_len;
        q.personality = t.personality;
        for (&q.sigactions) |*d| {
            d.* = if (d.handler == signals.SIG_IGN) .{ .handler = signals.SIG_IGN } else .{};
        }
    }
    p.clear_child_tid = 0;
    p.in_signal_handler = false;
    p.alt_stack = .{};

    process.setState(img, .zombie);
    tearDownTask(img, 0, .kill, true);
}

/// Linux exit_group(): the caller's whole group exits with `status`, the
/// other threads killed first as in killThreadGroup, the caller last through
/// the graceful self-exit (a voluntary exit persists shared dirty pages).
pub fn exitThreadGroup(exit_code: u32) void {
    const cur = smp.currentPid() orelse return;
    const tgid = process.procs[cur].tgid;
    // Killed before it got here: the group ends with that status, not this.
    const me = &process.procs[cur];
    const status = if (@atomicLoad(bool, &me.exit_requested, .acquire)) process.killStatus(me) else exit_code;
    // A lead that exited first stays pinned until the group empties; the
    // status its parent reads is the group's.
    if (cur != tgid and process.procs[tgid].state == .zombie) process.procs[tgid].exit_status = status;
    @atomicStore(bool, &process.procs[tgid].group_exiting, true, .seq_cst);
    // A thread inside a call outlives the caller: the last one out ends
    // the group as the caller would have.
    @atomicStore(bool, &process.procs[tgid].exits_clean, true, .release);
    killPeers(tgid, cur, status);
    destroyCurrentGraceful(status);
}

// =============================================================================
// Reaper infrastructure (process accounting / cleanup)
// =============================================================================
//
// Two cleanup mechanisms layered on top of the existing destroy paths:
//
// 1. `reparentChildren(dead_pid)` — when a parent process dies, walk its
//    children and reset their `parent_pid` to PID 1 (init / desktop). The
//    existing auto-reap path keeps working (a child whose parent is .unused
//    still auto-reaps on exit), but the explicit reparent makes the intent
//    visible and gives `init` a chance to actually waitpid them later.
//
// 2. `reapStaleZombies(max_age_ticks)` — periodic sweep called from the
//    desktop main loop. Catches zombies whose parent is alive but never
//    called waitpid (sloppy parent code, parent crashed mid-waitpid, etc).
//    After max_age_ticks the slot is forcibly reclaimed so the PCB table
//    doesn't fill up with zombies after a long uptime.
//
// PID 1 / init: slot 1 is a kernel task that never waits (BSP idle is
// PID 0). An orphan shows it as its parent (getppid) and carries `orphan`:
// it is freed as it ends, and one that was a zombie already is freed when
// its parent ends.

/// SIGCHLD for process `parent`: its child in slot `child` has ended, with
/// an exit code or by a signal.
fn notifyParentOfExit(parent: u8, child: usize) void {
    const st = process.procs[child].exit_status;
    const by_signal = st > 0xFF;
    _ = signals.sendProcess(parent, signals.SIGCHLD, .{
        .code = if (by_signal) signals.CLD_KILLED else signals.CLD_EXITED,
        .pid = process.procs[child].pid_nr,
        .value = if (!by_signal) st else if (st & signals.KILLED_BY != 0) st & 0x7F else signals.SIGKILL,
    });
}

const INIT_PID: u8 = 1; // desktop, by convention

/// The process in slot `dying` ends. A process group that is left with no
/// member whose parent is in another group of its session is orphaned: no
/// shell is there to continue its stopped members. POSIX has every member
/// of a group this end orphans, one of them stopped, sent SIGHUP and then
/// SIGCONT. The groups it can orphan are its own and its children's.
/// Before the children are given a new parent.
fn hangUpOrphanedGroups(dying: u8) void {
    const d = &process.procs[dying];
    @atomicStore(bool, &d.leaving, true, .seq_cst);
    // Only a group it held until now: its own through its parent, a
    // child's through itself.
    if (hasParent(dying)) {
        const pt = &process.procs[d.parent_pid];
        if (pt.state != .loading and pt.tgid < MAX_PROCS) {
            const pp = process.leader(pt);
            if (pp.pgid != d.pgid and pp.sid == d.sid) hangUpIfOrphaned(d.pgid, dying);
        }
    }
    for (&process.procs, 0..) |*c, i| {
        if (i == dying or c.state == .unused or c.state == .loading) continue;
        if (c.tgid != i or c.parent_pid != dying) continue;
        if (c.pgid == d.pgid or c.sid != d.sid) continue;
        hangUpIfOrphaned(c.pgid, dying);
    }
}

/// The process in slot `i`, alive: its lead, or threads its ended lead left.
fn liveProcess(i: usize) bool {
    const p = &process.procs[i];
    if (p.state == .unused or p.state == .loading or p.tgid != i) return false;
    return p.state != .zombie or groupHasOtherLive(@intCast(i));
}

/// True if the task in `slot` is a lead whose thread has ended while other
/// threads of its process live (a main thread that exited first, an execve
/// from another thread): the process is there, under this slot's number.
pub fn pinnedLead(slot: usize) bool {
    if (slot >= MAX_PROCS) return false;
    const p = &process.procs[slot];
    return p.state == .zombie and p.tgid == slot and groupHasOtherLive(@intCast(slot));
}

/// Hang up process group `pgid` if, `dying` not counted as a member or as a
/// parent, it is orphaned and has a stopped member.
fn hangUpIfOrphaned(pgid: u32, dying: u8) void {
    if (pgid == 0) return;
    var stopped = false;
    for (&process.procs, 0..) |*t, i| {
        if (t.state == .unused or t.state == .loading or t.state == .zombie) continue;
        if (t.tgid == dying or t.tgid >= MAX_PROCS) continue;
        const lead = &process.procs[t.tgid];
        if (lead.pgid != pgid) continue;
        // One that is ending too is no member any more.
        if (@atomicLoad(bool, &lead.leaving, .seq_cst)) continue;
        if (@atomicLoad(bool, &t.job_stopped, .seq_cst)) stopped = true;
        if (t.tgid != i and lead.state != .zombie) continue; // the lead answers for the process
        // A parent in another group of the session holds the group.
        const par = lead.parent_pid;
        if (par == dying or par == 0 or par == INIT_PID or par >= MAX_PROCS) continue;
        if (@atomicLoad(bool, &lead.orphan, .seq_cst)) continue;
        const pt = &process.procs[par];
        if (pt.state == .unused or pt.state == .loading or pt.tgid >= MAX_PROCS) continue;
        // The parent's group and session are its lead's (a native task's
        // parent may be a thread, whose copies go stale).
        const pp = process.leader(pt);
        // Nor does a parent that is ending hold the group.
        if (@atomicLoad(bool, &pp.leaving, .seq_cst)) continue;
        if (pp.pgid != pgid and pp.sid == lead.sid) return;
    }
    if (!stopped) return;
    for (0..MAX_PROCS) |i| {
        if (i == dying or !liveProcess(i) or process.procs[i].pgid != pgid) continue;
        if (@atomicLoad(bool, &process.procs[i].leaving, .seq_cst)) continue;
        _ = signals.sendProcess(@intCast(i), signals.SIGHUP, .{});
        _ = signals.sendProcess(@intCast(i), signals.SIGCONT, .{});
    }
}

/// Walk every PCB and reparent any whose parent_pid == dead_pid to INIT_PID.
/// Called from the destroy paths just before flipping state to .zombie or
/// .unused — order matters because we want children to see the new parent
/// BEFORE their old parent's slot gets reused.
pub fn reparentChildren(dead_pid: u8) void {
    var i: u8 = 0;
    while (i < MAX_PROCS) : (i += 1) {
        if (i == dead_pid) continue;
        const p = &process.procs[i];
        var nr: u32 = 0;
        {
            // Under the lock slots are freed under: the child looked at is
            // the one that gets the new parent.
            const flags = reap_lock.acquireIrqSave();
            defer reap_lock.releaseIrqRestore(flags);
            // A slot being set up is not the dying process's: it forks no
            // more. Its own threads are not its children.
            if (p.state == .unused or p.state == .loading) continue;
            if (p.parent_pid != dead_pid or p.tgid == dead_pid) continue;
            nr = p.pid_nr;
            p.parent_pid = INIT_PID;
            // Nobody waits for it now. `orphan` goes up before the look at
            // its state; the child looks at `orphan` after it becomes a
            // zombie.
            @atomicStore(bool, &p.orphan, true, .seq_cst);
        }
        if (p.state == .zombie) _ = reapZombieOf(i, nr);
    }
}

/// Free the zombie numbered `nr` in slot `pid`, which no parent will wait
/// for. A parent that keeps no zombies may be in wait4 all the same: it
/// looks again and finds the child gone.
fn dropZombie(pid: u8, nr: u32) void {
    const parent = process.procs[pid].parent_pid;
    const tell = hasParent(pid);
    const waiting = tell and parentIsWaiting(pid);
    if (!reapZombieOf(pid, nr)) return;
    if (tell) {
        if (waiting) process.wake(parent);
        wakeChildWaiters(parent);
    }
}

/// True when the process in slot `pid` has a parent that may wait for it: a
/// live one, the child not left behind by it.
fn hasParent(pid: usize) bool {
    const p = &process.procs[pid];
    if (@atomicLoad(bool, &p.orphan, .seq_cst)) return false;
    const parent = p.parent_pid;
    return parent != 0 and parent < MAX_PROCS and process.procs[parent].state != .unused;
}

/// Convenience wrapper for callers that don't want to track timing.
/// Called every desktop loop iteration; runs an actual sweep at most
/// once every REAP_INTERVAL_TICKS (≈30 s @ 100 Hz). Cheap on the no-op
/// path — one tick comparison and an early return.
const STALE_ZOMBIE_TICKS: u64 = 3000; // 30 s @ 100 Hz
const REAP_INTERVAL_TICKS: u64 = 500; // 5 s
var last_reap_tick: u64 = 0;
pub fn maybeReapZombies() void {
    const now = process.tick_count;
    if (now -% last_reap_tick < REAP_INTERVAL_TICKS) return;
    last_reap_tick = now;
    _ = reapStaleZombies(STALE_ZOMBIE_TICKS);
}

/// Force-reap zombies whose parent is alive but hasn't called waitpid in
/// `max_age_ticks` (≈10 ms per tick @ 100 Hz LAPIC timer). Default callers
/// pass 30 seconds = 3000 ticks. A waitpid-pending parent always reaps
/// instantly via the wake() in killProcessWithStatus, so by the time we
/// reach this sweep the parent is genuinely uninterested.
///
/// Returns the number of slots reclaimed — purely informational, fed to
/// klog at low volume so a sudden zombie-pile-up is visible without
/// flooding the log on the common no-op case.
pub fn reapStaleZombies(max_age_ticks: u64) u32 {
    var reaped: u32 = 0;
    var i: u8 = 0;
    while (i < MAX_PROCS) : (i += 1) {
        // The occupant looked at: a slot freed and taken again meanwhile is
        // not the one the checks below were made for.
        const nr = process.procs[i].pid_nr;
        if (process.procs[i].state != .zombie) continue;
        // Parent might be waiting; if so, leave it for the normal path.
        // (parentIsWaiting is the same predicate killProcessWithStatus uses.)
        if (parentIsWaiting(i)) continue;
        // Pinned lead — live workers still deref this PCB via leader().
        if (groupHasOtherLive(i)) continue;
        // A Linux parent may wait4 whenever it likes, and reads ECHILD for
        // a child taken from it as a bug (Zig's std: unreachable).
        const parent = process.procs[i].parent_pid;
        if (parent != 0 and parent < MAX_PROCS and process.procs[parent].state != .unused and
            process.procs[parent].personality == .linux) continue;
        // Age from the DEATH stamp, not acct_start_tick: aging from creation
        // gave any process older than the threshold a zero-second grace
        // window between exit and force-reap, racing the parent's waitpid
        // out of its exit status.
        const age = process.tick_count -% process.procs[i].death_tick;
        if (age < max_age_ticks) continue;
        if (reapZombieOf(i, nr)) reaped += 1;
    }
    if (reaped > 0) {
        debug.klog("[reaper] reaped {d} stale zombie(s)\n", .{reaped});
    }
    return reaped;
}

/// Mark current process as exited. Called by sys_exit (#3, status=0) and
/// sysExit (#48, user-supplied status). Switches CR3 to kernel before tearing
/// down per-process page tables. Either marks the slot zombie (parent alive,
/// will reap via waitpid) or fully frees it (no parent / parent already gone).
///
/// Threading: if this thread is one of several in its group (sysClone
/// members), only the thread-local cleanup runs — the shared page
/// directory, fd_table, sym_table, GPU ctx, GUI window, ELF buf, and
/// regions stay alive on the lead PCB until the LAST thread exits.
/// Self-exit. Calls the shared teardown (which switches CR3 to kernel,
/// frees the address space, steers TSS rsp0 to idle, clears
/// cpu.current_pid), then reschedules + halts. We MUST reschedule
/// before returning: the dying task is no longer current but the CPU
/// is still on its kstack. If the caller hlts (kernel-task self-destroy
/// pattern, see test/stress_kstack.zig:workerExit) or returns through a
/// path that doesn't reschedule, the next IRQ in ring 0 lands on the
/// dying kstack (the CPU only loads rsp0 on a privilege transition),
/// and handleIRQ0 runs on memory that's about to be reclaimed.
pub fn destroyCurrentWithStatus(status: u32) void {
    destroyCurrentImpl(status, false);
}

/// Graceful self-exit. Identical to destroyCurrentWithStatus EXCEPT it leaves a
/// MAP_SHARED region's unflushed dirty cache pages in place so pgflushd persists
/// them (Slice 3d-2b: a process that exits without msync still durably writes
/// back its final window). Wired ONLY to the voluntary exit syscalls
/// (sys_exit / exit_status) — the OOM, fatal-fault, and external-kill paths keep
/// the default (clear-without-writeback) so they free memory immediately.
pub fn destroyCurrentGraceful(status: u32) void {
    destroyCurrentImpl(status, true);
}

// ctx: irq-ok — a fatal signal can end the task from IRQ0's return path;
// hardirqReset() below drops that handler frame and the rest runs as the
// dying task, which may sleep on a Mutex (destroyGuiWindow).
fn destroyCurrentImpl(status: u32, persist_shared_dirty: bool) void {
    // Interrupts stay off to the final schedule(): a handler landing here
    // would run on a PCB, kstack and address space mid-teardown. Syscall
    // bodies run IF=1, so the exit paths can arrive with it on.
    asm volatile ("cli" ::: .{ .memory = true });
    @import("spinlock.zig").hardirqReset();
    const cur = smp.currentPid() orelse return;

    tearDownTask(cur, status, .destroy, persist_shared_dirty);

    // For user sys_exit, the syscall handler ALSO calls schedule afterwards
    // — that's now a redundant no-op (cheap). For kernel-task callers, this
    // schedule is the difference between a clean dispatch into the next
    // task and a hang on the next IRQ.
    process.schedule();
    // schedule() never returns when current_pid was null going in (dead-
    // letter eats the outgoing rsp), but the type system doesn't know that.
    while (true) asm volatile ("cli; hlt");
}

/// Mark current process as unused (called by sys_exit with no status — exit code
/// 0). Forced/status-0 self-destroy used by the OOM, fatal-fault, io_uring
/// worker, and deferred-self-destroy paths — clears dirty shared pages (does NOT
/// persist; the graceful exit syscalls call destroyCurrentGraceful instead).
pub fn destroyCurrent() void {
    destroyCurrentWithStatus(0);
}

/// Free a zombie slot after the parent has read its exit status. Called from
/// sysWaitpid. Safe to call only when procs[pid].state == .zombie — the heavy
/// teardown (page tables, fd_table, ELF buf, etc.) was already done at exit
/// time, so this is just a state flip.
pub fn reapZombie(pid: u8) void {
    if (pid >= MAX_PROCS) return;
    _ = reapZombieOf(pid, process.procs[pid].pid_nr);
}

/// A slot that held a process is freed under this, one at a time. A zombie
/// is given up by its parent's wait, by the parent or a worker ending, by
/// itself with nobody to wait for it, or by the sweep.
var reap_lock: SpinLock = .{};

/// True once the process in slot `pid` is a zombie whose teardown is over:
/// its exit status stands and it may be reaped.
pub fn hasEnded(pid: usize) bool {
    return process.procs[pid].state == .zombie and @atomicLoad(bool, &process.procs[pid].exit_done, .acquire);
}

/// reapZombie for the occupant numbered `nr`: a slot freed and taken again
/// since the caller looked is left alone, and so is a killed task its
/// killer is still tearing down. True if this call freed it.
pub fn reapZombieOf(pid: u8, nr: u32) bool {
    const flags = reap_lock.acquireIrqSave();
    defer reap_lock.releaseIrqRestore(flags);
    if (!hasEnded(pid) or process.procs[pid].pid_nr != nr) return false;
    // Pinned lead (exited before its workers): the slot must survive until
    // the last worker's teardown — workers deref procs[tgid] via leader()
    // on every fault, and the group cleanup runs through this PCB.
    if (groupHasOtherLive(pid)) return false;
    releaseSlot(pid);
    return true;
}

/// The task in slot `pid` is over with nothing left to read: the slot is
/// free for another.
fn freeSlot(pid: usize) void {
    const flags = reap_lock.acquireIrqSave();
    defer reap_lock.releaseIrqRestore(flags);
    releaseSlot(pid);
}

fn releaseSlot(pid: usize) void {
    process.setState(pid, .unused);
    @atomicStore(usize, &process.expected_kstack_tops[pid], 0, .release);
    @import("../debug/kasan.zig").markPcbDead(@intFromPtr(&process.kstack_pool[pid]) + KSTACK_GUARD_SIZE, KSTACK_SIZE);
}

/// True if any live thread OTHER than `tgid` itself still belongs to the
/// group — i.e. the zombie lead must stay pinned (not reapable). Excludes
/// .loading like countThreadsInGroup (a slot stranded mid-construction must
/// not pin the lead forever) but does NOT exclude teardown_marked members:
/// a marked worker is still mid-teardown and reads the lead PCB for the
/// group cleanup, so the lead must outlive it.
fn groupHasOtherLive(tgid: u8) bool {
    for (0..MAX_PROCS) |k| {
        if (k == tgid) continue;
        const s = process.procs[k].state;
        if (s == .unused or s == .loading or s == .zombie) continue;
        if (process.procs[k].tgid == tgid) return true;
    }
    return false;
}

/// Find the lowest-pid zombie child of `parent`. Returns null if none.
/// `target_pid == 0xFFFFFFFF` means "any child"; otherwise wait for exactly
/// that pid.
pub fn findZombieChild(parent: u8, target_pid: u32) ?u8 {
    for (0..MAX_PROCS) |i| {
        // Not one its killer is still tearing down: no exit status yet.
        if (!hasEnded(i)) continue;
        if (process.procs[i].parent_pid != parent) continue;
        if (target_pid != 0xFFFFFFFF and i != @as(usize, @intCast(target_pid))) continue;
        // Pinned lead — the process isn't fully dead until its workers exit
        // (POSIX: waitpid returns when the whole process is gone). The last
        // worker's teardown re-wakes the parent once the group empties.
        if (groupHasOtherLive(@intCast(i))) continue;
        return @intCast(i);
    }
    return null;
}

/// Drop this PCB's ownership of the ELF buffer. A fork child shares the
/// parent's buffer (forkCurrent), so the pages go back to the PMM only when
/// the last owner lets go.
fn freeElfBuf(pcb: *PCB) void {
    if (pcb.elf_buf) |buf| {
        pmm.releaseContiguous(kbufPhys(buf), pcb.elf_buf_pages);
        pcb.elf_buf = null;
        pcb.elf_buf_pages = 0;
    }
}

/// Phys head of a PMM buffer the kernel reaches through the physmap
/// (elf_buf, a file mmap's `source`).
fn kbufPhys(buf: [*]const u8) Phys {
    const paging = @import("../mm/paging.zig");
    return Phys.of(paging.virtToPhys(@intFromPtr(buf)).?);
}
