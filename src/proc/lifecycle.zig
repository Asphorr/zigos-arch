//! Process lifecycle: PCB slot alloc, process/thread create + clone + fork,
//! per-CPU kernel idle + kernel-task spawn, kill / destroy / reap teardown,
//! reparent-on-orphan, stale-zombie sweep. Split out of process.zig (#810).
//!
//! Owns:
//!   * allocSlot + resetPcbExceptState — the .unused→.loading CAS plus the
//!     verbatim field reset that the four constructors (create,
//!     createKernelIdle, createKernelTask, cloneCurrent) share.
//!   * create / cloneCurrent / forkCurrent — user-process / thread / fork
//!     PCB constructors. Each builds a synthetic kstack frame so the next
//!     dispatch lands in the right ring-3 RIP/RSP.
//!   * kernelIdle + createKernelIdle / createIdleProcess / createKernelTask
//!     — kernel-mode PCBs (one idle per CPU, plus desktop and friends).
//!   * waitForPidOffCpu — pre-teardown synchronization that IPIs peer CPUs
//!     off the dying pid before its kstack/PT pages get reclaimed.
//!   * setInflightSlot / clearInflightSlot / reclaimInflightSlot — swap-
//!     evict in-flight slot bookkeeping (so a thread killed mid-swap doesn't
//!     leak its NVMe slot).
//!   * tearDownTask + the kill / destroy / reap surface
//!     (killProcessWithStatus, killProcess, destroyCurrentWithStatus,
//!     destroyCurrent, reapZombie, findZombieChild, reparentChildren,
//!     maybeReapZombies, reapStaleZombies).
//!   * freeElfBuf — internal helper that drops the per-process ELF buffer.
//!   * countThreadsInGroup — used by tearDownTask to decide whether this is
//!     the last thread of the tgid (and therefore whether to free shared
//!     resources like the page directory + GUI window + ELF buf).
//!
//! Re-exported from process.zig so external callers keep using process.X
//! paths unchanged.

const std = @import("std");

const vga = @import("../ui/vga.zig");
const gdt = @import("../cpu/gdt.zig");
const debug = @import("../debug/debug.zig");
const vmm = @import("../mm/vmm.zig");
const pcid_mod = @import("../cpu/pcid.zig");
const heap = @import("../mm/heap.zig");
const pmm = @import("../mm/pmm.zig");
const swap = @import("../mm/swap.zig");
const symbols = @import("../debug/symbols.zig");
const smp = @import("../cpu/smp.zig");
const memmap = @import("../mm/memmap.zig");
const config = @import("../config.zig");
const signals = @import("signals.zig");

const process = @import("process.zig");
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
        const state_ptr: *u8 = @as(*u8, @ptrCast(&process.procs[i].state));
        if (@cmpxchgStrong(
            u8,
            state_ptr,
            @intFromEnum(State.unused),
            @intFromEnum(State.loading),
            .acquire,
            .monotonic,
        ) == null) {
            return i;
        }
    }
    return null;
}

/// Reset every PCB field to its default EXCEPT `state` (which the caller has
/// already set to .loading via allocSlot's CAS). Equivalent to
/// `procs[i] = .{}` minus the state-byte write — necessary because that write
/// would briefly restore state to .unused and re-open the slot to other CPUs.
fn resetPcbExceptState(pcb: *PCB) void {
    const fresh: PCB = .{};
    const state_off = comptime @offsetOf(PCB, "state");
    const dst: [*]u8 = @ptrCast(pcb);
    const src: [*]const u8 = @ptrCast(&fresh);
    @memcpy(dst[0..state_off], src[0..state_off]);
    @memcpy(dst[state_off + 1 .. @sizeOf(PCB)], src[state_off + 1 .. @sizeOf(PCB)]);
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

    // Kernel stack image at first dispatch (low → high address):
    //   [stack_top - 216 .. stack_top - 168) = 6 zero callee-saves   (48 B)
    //   [stack_top - 168 .. stack_top - 160) = retToUserStub address  (8 B)
    //   [stack_top - 160 .. stack_top -  40) = R15..RAX              (120 B)
    //   [stack_top -  40 .. stack_top)       = RIP CS RFLAGS RSP SS  (40 B)
    //
    // After the first iretq the task is in user mode. On its next
    // preempt/yield, isr_irq0/syscall stub saves new state on this
    // SAME kstack at the top, then schedule() pushes its own
    // switchTo frame (callee-saves) deeper on the kstack.
    const PT_REGS_QWORDS: usize = 20; // 15 GPRs + 5 iretq qwords
    const PT_REGS_BYTES = PT_REGS_QWORDS * 8; // 160
    const SWITCH_FRAME_BYTES: usize = 56; // 6 callee-saves + ret addr
    const TOTAL_BYTES = PT_REGS_BYTES + SWITCH_FRAME_BYTES; // 216

    comptime {
        if ((TOTAL_BYTES - SWITCH_FRAME_BYTES) % 16 != 0) @compileError("retToUserStub entry RSP must be 16-aligned");
    }

    const frame: [*]u64 = @ptrFromInt(stack_top - PT_REGS_QWORDS * 8);
    frame[19] = 0x1B;
    frame[18] = user_stack;
    frame[17] = 0x202;
    frame[16] = 0x23;
    frame[15] = entry;
    for (0..15) |k| frame[k] = 0;

    const sched_asm = @import("sched_asm.zig");
    const sw_base: [*]u64 = @ptrFromInt(stack_top - TOTAL_BYTES);
    for (0..6) |k| sw_base[k] = 0;
    sw_base[6] = @intFromPtr(&sched_asm.retToUserStub);

    process.procs[i].kernel_esp = stack_top - TOTAL_BYTES;
    process.procs[i].kernel_stack_top = stack_top;
    @atomicStore(usize, &process.expected_kstack_tops[i], stack_top, .release);
    // state already .loading from allocSlot's CAS — no further write needed.
    process.procs[i].tgid = @intCast(i);
    // Default session/group = self. sysExec overrides these from the
    // parent before scheduling so spawned children land in the parent's
    // session+group (POSIX-equivalent of fork+exec preserving sid/pgid).
    process.procs[i].pgid = @intCast(i);
    process.procs[i].sid = @intCast(i);
    @import("../debug/kdbg.zig").procEvent(.create, @intCast(i), 0, 0);
    @import("../debug/kasan.zig").markPcbAlive(slot_base + KSTACK_GUARD_SIZE, KSTACK_SIZE);
    return i;
}

/// Number of *live* PCBs sharing `tgid`. Used at exit/kill to decide
/// whether to keep or free the shared page directory + GUI window + ELF
/// buf. "Live" means actually running or runnable: .ready, .running,
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
/// What's shared: page_directory (same CR3 pointer + phys). lazy_regions,
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

    // Inherit thread-group + address space from the lead thread.
    process.procs[i].tgid = parent_lead.tgid;
    // Threads share the leader's process group + session — they're not
    // separate processes. setpgid/setsid on a thread mutates the whole
    // group's leader (matches Linux pthread semantics).
    process.procs[i].pgid = parent_lead.pgid;
    process.procs[i].sid = parent_lead.sid;
    process.procs[i].page_directory = parent_lead.page_directory;
    process.procs[i].page_dir_phys = parent_lead.page_dir_phys;

    // Copy per-thread defaults that need to mirror the parent for
    // sane scheduling. fd_table is COPIED for now (Linux would
    // share via CLONE_FILES; we punt). sigactions copied likewise.
    process.procs[i].fd_table = parent_lead.fd_table;
    process.procs[i].sigactions = parent_lead.sigactions;
    process.procs[i].cwd = parent_lead.cwd;
    process.procs[i].cwd_len = parent_lead.cwd_len;
    process.procs[i].name = parent_lead.name;
    process.procs[i].name_len = parent_lead.name_len;
    process.procs[i].priority = parent.priority;
    process.procs[i].parent_pid = @intCast(parent_lead.tgid);
    process.procs[i].fs_base = fs_base;

    // Kernel stack image: same layout as create() but with caller-
    // chosen RIP/RSP/RDI. See create()'s comment for the full layout.
    const slot_base = @intFromPtr(&process.kstack_pool[i]);
    const kstack_top = slot_base + KSTACK_SLOT_SIZE;
    const PT_REGS_QWORDS: usize = 20;
    const PT_REGS_BYTES = PT_REGS_QWORDS * 8; // 160
    const SWITCH_FRAME_BYTES: usize = 56;
    const TOTAL_BYTES = PT_REGS_BYTES + SWITCH_FRAME_BYTES; // 216

    const frame: [*]u64 = @ptrFromInt(kstack_top - PT_REGS_QWORDS * 8);
    frame[19] = 0x1B;
    frame[18] = stack_top;
    frame[17] = 0x202;
    frame[16] = 0x23;
    frame[15] = entry;
    for (0..15) |k| frame[k] = 0;
    frame[8] = arg;

    const sched_asm = @import("sched_asm.zig");
    const sw_base: [*]u64 = @ptrFromInt(kstack_top - TOTAL_BYTES);
    for (0..6) |k| sw_base[k] = 0;
    sw_base[6] = @intFromPtr(&sched_asm.retToUserStub);

    process.procs[i].kernel_esp = kstack_top - TOTAL_BYTES;
    process.procs[i].kernel_stack_top = kstack_top;
    @atomicStore(usize, &process.expected_kstack_tops[i], kstack_top, .release);
    // Atomic transition .loading → .ready. Callers of cloneCurrent expect
    // the new PCB to be schedulable immediately (no separate "ready" step
    // like sysExec does after page-table setup). assignInitialCpu first
    // so setState's rqEnter lands on the right per-CPU runqueue.
    process.assignInitialCpu(i);
    process.setState(i, .ready);
    @import("../debug/kasan.zig").markPcbAlive(slot_base + KSTACK_GUARD_SIZE, KSTACK_SIZE);
    return i;
}

/// Spawn a child via fork(). Clones the parent's address space (COW shared),
/// copies fd_table / sigactions / cwd / lazy_regions / argv, and synthesizes
/// a kstack iretq frame so the child resumes at the parent's syscall-return
/// RIP/RSP with RAX=0. Parent's caller (sysFork) returns the child PID.
///
/// `frame` is the parent's saved syscall frame (passed through doSyscall) —
/// we read RIP/RFLAGS/RSP/all GPRs from there to seed child's iretq frame.
pub fn forkCurrent(frame: *signals.SyscallFrame) ?usize {
    const parent = process.currentPCB() orelse return null;
    const parent_pid_u8: u8 = @intCast(smp.myCpu().current_pid orelse return null);
    const parent_pml4 = parent.page_directory orelse return null;

    const i = allocSlot() orelse return null;
    resetPcbExceptState(&process.procs[i]); // state stays .loading from allocSlot's CAS

    // Clone parent's address space. On OOM partway through, the child PML4 is
    // partially built; tear it down via destroyAddressSpace, which drops every
    // refcount we bumped and frees every page-table page we allocated.
    var child_pml4_phys: usize = 0;
    const child_pml4 = vmm.cloneAddressSpace(parent_pml4, &child_pml4_phys) orelse {
        if (child_pml4_phys != 0) {
            const paging = @import("../mm/paging.zig");
            const pml4_ptr: [*]align(4096) u64 = @ptrFromInt(paging.physToVirt(child_pml4_phys));
            vmm.destroyAddressSpace(@alignCast(pml4_ptr), child_pml4_phys);
        }
        process.setState(i, .unused);
        return null;
    };
    process.procs[i].page_directory = child_pml4;
    process.procs[i].page_dir_phys = child_pml4_phys;
    process.procs[i].pcid = pcid_mod.alloc();

    // Per-AS state — fork has its own AS so lazy regions and brk/mmap state
    // are inherited as values (not aliased through tgid like clone does).
    process.procs[i].lazy_regions = parent.lazy_regions;
    process.procs[i].lazy_count = parent.lazy_count;
    process.procs[i].heap_lazy_idx = parent.heap_lazy_idx;
    process.procs[i].user_brk = parent.user_brk;
    process.procs[i].mmap_top = parent.mmap_top;
    process.procs[i].stack_base = parent.stack_base;

    // Shared-anon regions: bump refcount per inherited LazyRegion. The
    // PT-level COW path covers private anon (each AS gets a fresh frame on
    // first write); shared-anon stays POSIX-SHARED — child sees parent's
    // writes byte-for-byte and vice versa. The PTE entries already point at
    // the same frames (cloneAddressSpace strips writable for COW, but the
    // fault handler re-checks shm_id BEFORE handleCowFault, so writes on a
    // shared-anon page take the shm-map path, not the COW path).
    {
        const shm = @import("../mm/shm.zig");
        var ri: u8 = 0;
        while (ri < process.procs[i].lazy_count) : (ri += 1) {
            const sid = process.procs[i].lazy_regions[ri].shm_id;
            if (sid != shm.SHM_INVALID) _ = shm.acquire(sid);
        }
    }
    // ELF buf is the parent's source-of-truth for demand paging; child shares
    // a *reference* to it (lazy_regions point at parent's buf). Don't free
    // it twice on exit — child sets its own elf_buf to null so destroyCurrent
    // skips freeing on this PCB. Parent owns the lifetime; if parent exits
    // first, the buffer outlives via ELF-page refcounts (each lazy fault-in
    // copies bytes through the kernel buffer; once all child faults are
    // resolved, the buffer is no longer needed). For correctness today we
    // accept that child's lazy_regions[].source pointers may dangle if
    // parent execs / exits before child finishes faulting in. Practical fix
    // requires elf_buf refcounting — deferred.
    process.procs[i].elf_buf = null;
    process.procs[i].elf_buf_pages = 0;

    // FD table — copy entries verbatim, then bump pipe-side refcounts so the
    // parent closing its end doesn't drop the last reference while child
    // still holds the inherited fd.
    process.procs[i].fd_table = parent.fd_table;
    {
        const pipe = @import("pipe.zig");
        for (process.procs[i].fd_table) |fd| {
            if (!fd.in_use) continue;
            if (fd.fs_type == .pipe) {
                if (fd.flags == 0) pipe.addReader(fd.pipe_id) else pipe.addWriter(fd.pipe_id);
            }
        }
    }

    // Inherit cwd, name, sigactions, argv, priority, fs_base.
    process.procs[i].cwd = parent.cwd;
    process.procs[i].cwd_len = parent.cwd_len;
    process.procs[i].name = parent.name;
    process.procs[i].name_len = parent.name_len;
    process.procs[i].sigactions = parent.sigactions;
    process.procs[i].argv = parent.argv;
    process.procs[i].arg_lens = parent.arg_lens;
    process.procs[i].argc = parent.argc;
    process.procs[i].priority = parent.priority;
    process.procs[i].fs_base = parent.fs_base;

    process.procs[i].parent_pid = parent_pid_u8;
    process.procs[i].tgid = @intCast(i); // lead thread of the new process group
    // POSIX fork() preserves the parent's pgid and sid — only setsid /
    // setpgid mutate them. A daemon's classic double-fork relies on
    // this: the middle child calls setsid AFTER it's been forked off,
    // and the grandchild then naturally inherits the new sid here.
    process.procs[i].pgid = parent.pgid;
    process.procs[i].sid = parent.sid;

    // Build child's kstack image — same shape as create()/cloneCurrent(), but
    // values seeded from parent's saved syscall frame so child resumes at the
    // parent's syscall-return point with RAX=0. retToUserStub pops 15 GPRs in
    // order R15..RAX (frame[0..15]) then iretqs through frame[15..20].
    const slot_base = @intFromPtr(&process.kstack_pool[i]);
    const kstack_top = slot_base + KSTACK_SLOT_SIZE;
    const PT_REGS_QWORDS: usize = 20;
    const PT_REGS_BYTES = PT_REGS_QWORDS * 8;
    const SWITCH_FRAME_BYTES: usize = 56;
    const TOTAL_BYTES = PT_REGS_BYTES + SWITCH_FRAME_BYTES;

    const f: [*]u64 = @ptrFromInt(kstack_top - PT_REGS_BYTES);
    // Iretq frame (top of pt_regs): SS, RSP, RFLAGS, CS, RIP.
    f[19] = 0x1B;            // user SS
    f[18] = frame.user_rsp;  // user RSP
    f[17] = frame.r11;       // RFLAGS — saved by syscall in R11
    f[16] = 0x23;             // user CS
    f[15] = frame.rcx;        // user RIP — saved by syscall in RCX
    // GPRs (retToUserStub pops in this order): R15..RAX.
    f[0]  = frame.r15;
    f[1]  = frame.r14;
    f[2]  = frame.r13;
    f[3]  = frame.r12;
    f[4]  = frame.r11;        // R11 GPR slot — overwritten anyway by iretq's RFLAGS load
    f[5]  = frame.r10;
    f[6]  = frame.r9;
    f[7]  = frame.r8;
    f[8]  = frame.rdi;
    f[9]  = frame.rsi;
    f[10] = frame.rbp;
    f[11] = frame.rbx;
    f[12] = frame.rdx;
    f[13] = frame.rcx;        // RCX GPR slot
    f[14] = 0;                // RAX = fork() return value for child

    const sched_asm = @import("sched_asm.zig");
    const sw_base: [*]u64 = @ptrFromInt(kstack_top - TOTAL_BYTES);
    for (0..6) |k| sw_base[k] = 0;
    sw_base[6] = @intFromPtr(&sched_asm.retToUserStub);

    process.procs[i].kernel_esp = kstack_top - TOTAL_BYTES;
    process.procs[i].kernel_stack_top = kstack_top;
    @atomicStore(usize, &process.expected_kstack_tops[i], kstack_top, .release);
    process.assignInitialCpu(i);
    process.setState(i, .ready);
    @import("../debug/kdbg.zig").procEvent(.create, @intCast(i), parent_pid_u8, 0);
    @import("../debug/kasan.zig").markPcbAlive(slot_base + KSTACK_GUARD_SIZE, KSTACK_SIZE);
    return i;
}

/// Per-CPU kernel-mode idle task (task #235). Runs CS=0x08, no user space,
/// no syscall_entry. Loop: `sti; hlt; schedule()`.
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
    const mwait = @import("../cpu/mwait.zig");
    while (true) {
        // Drain any pending async app load (file-read offload). Used to be
        // serviced by apEntry's scheduler-context loop, but per-CPU idle
        // (task #235) made that loop dead code on APs. Idle is the right
        // home: it runs whenever the CPU has nothing else to do, and the
        // CAS pending->loading inside apProcessLoadQueue prevents two
        // idles from racing on the same request.
        smp.apProcessLoadQueue();
        if (mwait.mwait_supported) {
            // sti + monitor + mwait. MWAIT(EAX=C1 hint, ECX[0]=1) wakes on
            // either a write to the monitored line or an interrupt — IRQs
            // break it just like HLT, with the added bonus of letting the
            // CPU drop into C1/C1E. The monitored word is per-CPU; future
            // wake-from-kernel paths can bump it to wake without an IPI.
            const cpu = smp.myCpu();
            asm volatile ("sti");
            mwait.idleWait(&cpu.idle_monitor_word);
        } else {
            asm volatile ("sti; hlt");
        }
        process.schedule();
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

    const FRAME_BYTES: usize = 64;
    const sw_base: [*]u64 = @ptrFromInt(stack_top - FRAME_BYTES);
    for (0..6) |k| sw_base[k] = 0;
    sw_base[6] = @intFromPtr(&kernelIdle);
    sw_base[7] = 0;

    process.procs[i].kernel_esp = stack_top - FRAME_BYTES;
    process.procs[i].kernel_stack_top = stack_top;
    @atomicStore(usize, &process.expected_kstack_tops[i], stack_top, .release);
    process.procs[i].is_idle = true;
    process.procs[i].idle_cpu = cpu_id;
    process.procs[i].priority = .background;
    process.procs[i].page_dir_phys = 0;
    process.procs[i].last_cpu = cpu_id;
    process.procs[i].tgid = @intCast(i);
    process.procs[i].pgid = @intCast(i);
    process.procs[i].sid = @intCast(i);
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
/// `kstack_bytes` lets the caller request a larger kstack than the pool
/// default (16 KB). Desktop needs at least 32 KB because its init+render
/// path (virtio_gpu init, font rasterization) was sized for the 32 KB
/// boot stack. Heap-allocated; no guard page at the bottom (the heap
/// allocator surrounds it with redzones if KASAN is on).
pub fn createKernelTask(
    entry_fn_addr: usize,
    name: []const u8,
    cpu_id: u8,
    prio: Priority,
    kstack_bytes: usize,
) ?usize {
    const i = allocSlot() orelse return null;
    resetPcbExceptState(&process.procs[i]); // state stays .loading from allocSlot's CAS

    const stack_top: usize = blk: {
        if (kstack_bytes <= KSTACK_SIZE) {
            const slot_base = @intFromPtr(&process.kstack_pool[i]);
            break :blk slot_base + KSTACK_SLOT_SIZE;
        }
        const buf = heap.kmallocAligned(kstack_bytes, 4096) orelse {
            debug.klog("[proc] createKernelTask: heap alloc {d} bytes failed\n", .{kstack_bytes});
            // Release the slot back to .unused. State was .loading from
            // allocSlot's CAS, never reached .ready, so no rq enter happened.
            process.setState(i, .unused);
            return null;
        };
        const top = @intFromPtr(buf) + kstack_bytes;
        // Heap kstack tops are recorded via expected_kstack_tops below at
        // the same time as the per-pid witness — `isValidKstackTopShape`
        // scans that array for tops outside the kstack pool.
        break :blk top;
    };

    const FRAME_BYTES: usize = 64;
    const sw_base: [*]u64 = @ptrFromInt(stack_top - FRAME_BYTES);
    for (0..6) |k| sw_base[k] = 0;
    sw_base[6] = entry_fn_addr;
    sw_base[7] = 0;

    process.procs[i].kernel_esp = stack_top - FRAME_BYTES;
    process.procs[i].kernel_stack_top = stack_top;
    @atomicStore(usize, &process.expected_kstack_tops[i], stack_top, .release);
    process.procs[i].is_idle = false;
    process.procs[i].pinned_cpu = cpu_id;
    process.procs[i].priority = prio;
    process.procs[i].page_dir_phys = 0;
    process.procs[i].last_cpu = cpu_id;
    process.procs[i].tgid = @intCast(i);
    // Boot session — desktop kernel-task is the de-facto session leader,
    // so its sid+pgid mirror its own pid. Any child it sysExec's will
    // inherit these (see sysExec's parent→child copy).
    process.procs[i].pgid = @intCast(i);
    process.procs[i].sid = @intCast(i);
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

/// Block until no CPU has `cpu.current_pid == pid`. Used by killProcess
/// before tearing down a process's address space and PCB.
///
/// Phase 3 simplification: the save_in_flight_prev bracket is no longer
/// load-bearing because schedule() now redirects switchTo's save target
/// to dead_letter when prev's state is .zombie/.unused (set by the
/// killer before this wait). So a save into the doomed PCB never lands
/// in the to-be-recycled slot — we just need to confirm cpu has actually
/// switched off pid (current_pid != pid).
fn waitForPidOffCpu(pid: u8) void {
    const apic = @import("../time/apic.zig");
    const my_lapic = apic.getLapicId();

    var attempts: u32 = 0;
    while (attempts < 8) : (attempts += 1) {
        var found_cid: ?u8 = null;
        var found_lapic: u32 = 0;
        for (&smp.cpus) |*cpu| {
            if (!cpu.alive) continue;
            if (cpu.lapic_id == my_lapic) continue; // self can't be on the dying pid (we're killing it)
            const on_cpu = if (cpu.current_pid) |cur| cur == pid else false;
            if (on_cpu) {
                found_cid = cpu.cpu_id;
                found_lapic = cpu.lapic_id;
                break;
            }
        }
        const cid = found_cid orelse return; // pid is not on any other CPU

        // Kick the target CPU into schedule(). schedule() at the top
        // checks exit_requested[cur] and routes through
        // destroyCurrentWithStatus, so the target tears itself down on
        // its own kstack (no remote teardown race). Without the IPI
        // vector (early boot), natural preemption (~10ms) does the same.
        if (process.kickVector()) |v| apic.sendIPI(found_lapic, v);

        // Spin-wait until current_pid changes. No save_in_flight check
        // needed — schedule() bypasses the save into the doomed PCB.
        var spin: u32 = 0;
        while (spin < 2_000_000) : (spin += 1) {
            const cur_now = smp.cpus[cid].current_pid;
            if (cur_now == null or cur_now.? != pid) break;
            asm volatile ("pause" ::: .{ .memory = true });
        }
        if (spin >= 2_000_000) {
            debug.klog("[kill] WARN: cpu{d} stuck on pid={d} after IPI (attempt {d})\n", .{ cid, pid, attempts });
            // Don't return — retry. Most likely cause: IRQs masked on
            // target during a long critical section, will release soon.
        }
    }
    debug.klog("[kill] WARN: gave up evicting pid={d} after 8 attempts\n", .{pid});
}

/// Publish the swap slot the calling thread has in-flight (between
/// evictFrame's phase-1 and phase-3 CAS) so process teardown can free the
/// slot if the thread is killed while parked in blockOn(.nvme_io). Called
/// by swap.evictFrame; counterpart `clearInflightSlot` runs at phase-3 /
/// rollback. Atomic so killProcess can observe it from another CPU.
pub fn setInflightSlot(slot: u32) void {
    const cur = smp.myCpu().current_pid orelse return;
    @atomicStore(u32, &process.procs[cur].swap_inflight_slot, slot, .release);
}

pub fn clearInflightSlot() void {
    const cur = smp.myCpu().current_pid orelse return;
    @atomicStore(u32, &process.procs[cur].swap_inflight_slot, 0xFFFFFFFF, .release);
}

/// Release any in-flight swap slot owned by `pid` so it isn't leaked when
/// the thread is torn down. Called from kill / destroy paths just before
/// freeing the PCB. Idempotent — clears the field after freeing.
pub fn reclaimInflightSlot(pid: usize) void {
    if (pid >= MAX_PROCS) return;
    const cur = @atomicLoad(u32, &process.procs[pid].swap_inflight_slot, .acquire);
    if (cur == 0xFFFFFFFF) return;
    @atomicStore(u32, &process.procs[pid].swap_inflight_slot, 0xFFFFFFFF, .release);
    swap.freeSlot(cur);
}

/// Walk a dying process's fd_table and close any pipe fds so the pipe pool's
/// reader/writer counts stay correct. Called from killProcessWithStatus and
/// destroyCurrentWithStatus before the slot is freed.
fn closePipeFds(pid: u8) void {
    const pipe = @import("pipe.zig");
    for (0..MAX_FDS) |fd| {
        const desc = &process.procs[pid].fd_table[fd];
        if (!desc.in_use or desc.fs_type != .pipe) continue;
        if (desc.flags == 0) {
            pipe.closeReader(desc.pipe_id);
        } else {
            pipe.closeWriter(desc.pipe_id);
        }
        desc.in_use = false;
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

/// Common teardown for both external kill and self-destroy. Caller
/// is responsible for the entry/exit dance unique to each:
///
///   * `kill`: flip state→.zombie + waitForPidOffCpu BEFORE calling here
///     (so no other CPU still references the dying PCB).
///   * `destroy`: call `schedule()` + halt AFTER this returns (the
///     dying CPU is still on the dying kstack until it reschedules).
fn tearDownTask(pid: usize, status: u32, op: TerminateOp) void {
    const kp = @import("../debug/kstack_protect.zig");
    kp.checkpoint("tdt:entry");
    const my_tgid: u8 = process.procs[pid].tgid;
    const last_in_group = countThreadsInGroup(my_tgid) <= 1;
    debug.klog("[proc] {s} {d} {s} (status=0x{X})\n", .{
        if (last_in_group) "Process" else "Thread",
        pid,
        if (op == .kill) "killed" else "destroyed",
        status,
    });
    // PMM diagnostic: free frames immediately before this proc's pages
    // get reclaimed. Pair with the [pmm-diag] line on the next sysExec
    // to see whether teardown returned everything to PMM.
    const pmm_diag = @import("../mm/pmm.zig");
    debug.klog("[pmm-diag] pre-teardown free={d}/{d}\n", .{ pmm_diag.freeFrameCount(), pmm_diag.managedFrameCount() });

    // Force-release any registered Mutex held by the dying pid. Done
    // BEFORE the cleanup steps below because some of them
    // (virtio_gpu.ctxDestroy → sendCmd → ctrl_lock.acquire) would
    // recursively try to acquire a lock the dying pid still owns,
    // deadlocking the entire GPU pipeline. Each released lock logs a
    // [lock-dump] line so the autopsy shows what was stranded.
    @import("spinlock.zig").releaseMutexesOwnedBy(@intCast(pid));
    kp.checkpoint("tdt:post-mutexRelease");

    // If this thread was parked in blockOn(.nvme_io) inside swap.evictFrame's
    // writePage, wake() against a .zombie is a no-op and the in-flight swap
    // slot would leak. Reclaim it before the AS teardown frees the in-flight
    // frame via teardownNonPresent. (Reviewer-caught 2026-05-23.)
    reclaimInflightSlot(pid);

    // Resources reachable in any address space (GUI window state, GPU
    // contexts, debug symbols all live in heap / driver structures, not
    // user memory). Safe to free before the CR3 switch below.
    if (last_in_group) {
        const desktop = @import("../ui/desktop.zig");
        desktop.destroyGuiWindow(@intCast(pid));
        kp.checkpoint("tdt:post-destroyGuiWindow");
        if (process.procs[pid].gpu_has_ctx) {
            const virtio_gpu = @import("../driver/virtio_gpu.zig");
            if (!virtio_gpu.ctxDestroy(process.procs[pid].gpu_ctx_id)) {
                debug.klog("[proc] GPU ctx {d} destroy failed for pid {d}\n", .{ process.procs[pid].gpu_ctx_id, pid });
            }
            process.procs[pid].gpu_has_ctx = false;
            process.procs[pid].gpu_ctx_id = 0;
            kp.checkpoint("tdt:post-ctxDestroy");
        }
        if (process.procs[pid].sym_table) |st| {
            symbols.freeSymTable(st);
            process.procs[pid].sym_table = null;
            kp.checkpoint("tdt:post-freeSymTable");
        }
    }

    // Self-destroy: switch to kernel CR3 BEFORE freeing the victim's PT
    // pages — otherwise destroyAddressSpace would free the very CR3 the
    // CPU is walking. External kill is on the killer's own CR3 (the
    // victim's was never active here), so no switch needed.
    if (op == .destroy) {
        pcid_mod.loadCr3(@import("../mm/paging.zig").getKernelPageDirPhys(), 0, smp.myCpu().cpu_id);
        kp.checkpoint("tdt:post-switchAS");
    }

    if (last_in_group) {
        const lead = &process.procs[my_tgid];
        if (lead.page_directory) |pd| {
            vmm.destroyAddressSpace(pd, lead.page_dir_phys);
            lead.page_directory = null;
            lead.page_dir_phys = 0;
            if (lead.pcid != 0) {
                pcid_mod.free(lead.pcid);
                lead.pcid = 0;
            }
            kp.checkpoint("tdt:post-destroyAS");
        }
        closePipeFds(my_tgid);
        kp.checkpoint("tdt:post-closePipes");
        freeElfBuf(lead);
        kp.checkpoint("tdt:post-freeElfBuf");
        const paging = @import("../mm/paging.zig");
        const shm = @import("../mm/shm.zig");
        for (lead.lazy_regions[0..lead.lazy_count]) |r| {
            // Shared-anon: drop this AS's refcount. The shm registry frees
            // its frames at refcount==0, so peers keep working until they
            // also exit / munmap.
            if (r.shm_id != shm.SHM_INVALID) shm.release(r.shm_id);
            if (!r.buf_owned) continue;
            const src = r.source orelse continue;
            // r.source points at a PMM-allocated buffer reached through
            // the kernel physmap. Translate VA → phys before handing to
            // PMM (which lives in phys space).
            const base: usize = paging.virtToPhys(@intFromPtr(src)).?;
            pmm.freeContiguous(base, r.buf_pages);
        }
        lead.lazy_count = 0;
        lead.heap_lazy_idx = -1;
        kp.checkpoint("tdt:post-lazyRegions");
    }

    // Per-thread: drop borrowed page directory pointer so a future zombie
    // reap doesn't double-free, and stamp exit_status for waitpid.
    process.procs[pid].page_directory = null;
    process.procs[pid].page_dir_phys = 0;
    process.procs[pid].exit_status = status;

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
        @import("../debug/pid_trace.zig").setCurrentPid(cpu, null);
        kp.checkpoint("tdt:post-steerToIdle");
    }

    // Decide zombie vs immediate free. Parent alive AND lead thread →
    // keep as zombie so the parent's waitpid can read exit_status.
    // No parent / parent gone / worker thread → free immediately so the
    // slot can be reused. Workers (non-lead threads) are joined via the
    // user-space TCB futex, never via waitpid, so they auto-reap
    // regardless of parent state.
    const parent = process.procs[pid].parent_pid;
    const parent_alive = parent < MAX_PROCS and process.procs[parent].state != .unused and parent != 0;
    const is_worker_thread = pid != my_tgid;

    // Reparent children before changing state — otherwise a child's
    // parent_pid could point at a slot that gets reused by a future
    // create() and the child would think a stranger is its parent.
    // Worker threads share a tgid; only the lead process owns children.
    if (!is_worker_thread) {
        reparentChildren(@intCast(pid));
    }

    if (parent_alive and !is_worker_thread) {
        // setState rqLeave's pid if it was somehow .ready (shouldn't be —
        // tearDownTask is preceded by waitForPidOffCpu in the kill path
        // and by self-yield in the destroy path — but defensive).
        process.setState(pid, .zombie);
        if (parentIsWaiting(@intCast(pid))) process.wake(parent);
        // SIGCHLD is default-ignored, so this is a no-op for shells
        // that don't care; shells with a SIGCHLD handler can do
        // non-blocking reaping. Sent regardless of waitpid state per POSIX.
        _ = signals.send(parent, signals.SIGCHLD);
        kp.checkpoint("tdt:post-zombie+SIGCHLD");
    } else {
        process.setState(pid, .unused);
        @atomicStore(usize, &process.expected_kstack_tops[pid], 0, .release);
        @import("../debug/kasan.zig").markPcbDead(@intFromPtr(&process.kstack_pool[pid]) + KSTACK_GUARD_SIZE, KSTACK_SIZE);
        kp.checkpoint("tdt:post-markPcbDead");
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
    // anything less is a leak in the destroy path.
    debug.klog("[pmm-diag] post-teardown free={d}/{d} (pid={d})\n", .{ pmm_diag.freeFrameCount(), pmm_diag.managedFrameCount(), pid });
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
///   * .ready / .sleeping / .loading: killer owns pid (exit_requested
///     gate in pickNext keeps any racing CPU from dispatching it), so
///     killer sets state=.zombie via setState (rqLeave fires) and runs
///     tearDownTask directly.
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

    process.procs[pid].exit_status = status;

    // Atomic ownership claim — only one killer runs teardown per pid.
    // .Xchg returns the previous value; if it was already true another
    // killer is in flight, so we just wait for terminal state and bail.
    const prev_req = @atomicRmw(bool, &process.procs[pid].exit_requested, .Xchg, true, .acq_rel);
    if (prev_req) {
        var spin: u32 = 0;
        while (spin < 10_000_000) : (spin += 1) {
            const s = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire);
            if (s == @intFromEnum(State.zombie) or s == @intFromEnum(State.unused)) return;
            asm volatile ("pause" ::: .{ .memory = true });
        }
        debug.klog("[kill] WARN: pid={d} concurrent-killer wait timed out\n", .{pid});
        return;
    }

    // Case 1: self-kill (current CPU is running pid). Escalate to the
    // self-destroy path, which steers TSS rsp0 to idle and never returns.
    const my_cpu = smp.myCpu();
    if (my_cpu.current_pid) |cur| {
        if (cur == pid) {
            destroyCurrentWithStatus(status);
            unreachable;
        }
    }

    const apic = @import("../time/apic.zig");
    const my_lapic = apic.getLapicId();
    var ipi_attempts: u32 = 0;

    while (true) {
        const snap = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire);
        if (snap == @intFromEnum(State.zombie) or snap == @intFromEnum(State.unused)) return;

        if (snap == @intFromEnum(State.running)) {
            // Case 2: another CPU is running pid. IPI to wake it into
            // schedule(); schedule's exit_requested check at top runs
            // destroyCurrentWithStatus on the target CPU.
            var target_lapic: ?u32 = null;
            for (&smp.cpus) |*c| {
                if (!c.alive) continue;
                if (c.lapic_id == my_lapic) continue;
                if (c.current_pid) |cp| {
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
                if (s != @intFromEnum(State.running)) break;
                asm volatile ("pause" ::: .{ .memory = true });
            }
            continue;
        }

        // Case 3: .ready / .sleeping / .loading. Killer owns pid via
        // exit_requested xchg + pickNext skip → no CPU will dispatch it.
        // Safe to setState + tearDown directly. (parent reaping AFTER
        // tearDown is naturally serialized via the wake() inside tearDown
        // — parent was blocked in waitpid until tearDown wakes it.)
        process.setState(pid, .zombie);
        tearDownTask(pid, status, .kill);
        return;
    }
}

/// Kill a process by PID (status defaults to 0 — for callers that don't care
/// or aren't routing through sysKill). Most internal callers (elf_loader,
/// desktop close-button, cli `kill` command) use this.
pub fn killProcess(pid: u8) void {
    killProcessWithStatus(pid, 0);
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
// PID 1 / init: the `desktop` kernel task runs at PID 1 by convention
// (BSP idle is PID 0). Reparenting points orphans at desktop, which never
// calls waitpid — so the auto-reap-on-orphan path triggers naturally on
// the next exit, freeing the slot. Worth-it tradeoff: simpler code,
// slight delay in slot reclamation.

const INIT_PID: u8 = 1; // desktop, by convention

/// Walk every PCB and reparent any whose parent_pid == dead_pid to INIT_PID.
/// Called from the destroy paths just before flipping state to .zombie or
/// .unused — order matters because we want children to see the new parent
/// BEFORE their old parent's slot gets reused.
pub fn reparentChildren(dead_pid: u8) void {
    var i: u8 = 0;
    while (i < MAX_PROCS) : (i += 1) {
        if (i == dead_pid) continue;
        if (process.procs[i].state == .unused) continue;
        if (process.procs[i].parent_pid == dead_pid) {
            process.procs[i].parent_pid = INIT_PID;
        }
    }
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
        if (process.procs[i].state != .zombie) continue;
        // Parent might be waiting; if so, leave it for the normal path.
        // (parentIsWaiting is the same predicate killProcessWithStatus uses.)
        if (parentIsWaiting(i)) continue;
        const age = process.tick_count -% process.procs[i].acct_start_tick;
        if (age < max_age_ticks) continue;
        // Force-reap: same teardown as the .unused branch in killProcessWithStatus.
        // setState handles the rq book-keeping (zombie isn't runnable so the
        // rq should already be empty for this pid; defensive).
        process.setState(i, .unused);
        @atomicStore(usize, &process.expected_kstack_tops[i], 0, .release);
        @import("../debug/kasan.zig").markPcbDead(@intFromPtr(&process.kstack_pool[i]) + KSTACK_GUARD_SIZE, KSTACK_SIZE);
        reaped += 1;
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
/// lazy_regions stay alive on the lead PCB until the LAST thread exits.
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
    const cur = smp.myCpu().current_pid orelse return;

    // Protect the kstacks of PROTECTED_PIDS (currently desktop=2, shell=3)
    // for the duration of the destroy critical section. Any wild write
    // into those kstacks during teardown #PFs on the writing CPU with
    // the writer's RIP captured in the saved frame. Note: tasks currently
    // running on another CPU are SKIPPED (would brick that CPU on next
    // push); the running-victim wild-writer case is hunted via the
    // `checkpoint` bisection logger instead.
    const kstack_protect = @import("../debug/kstack_protect.zig");
    kstack_protect.checkpoint("dcws:entry");
    kstack_protect.protectAll();
    kstack_protect.checkpoint("dcws:post-protect");

    tearDownTask(cur, status, .destroy);

    kstack_protect.checkpoint("dcws:post-teardown");
    kstack_protect.unprotectAll();
    kstack_protect.checkpoint("dcws:post-unprotect");

    // For user sys_exit, the syscall handler ALSO calls schedule afterwards
    // — that's now a redundant no-op (cheap). For kernel-task callers, this
    // schedule is the difference between a clean dispatch into the next
    // task and a hang on the next IRQ.
    process.schedule();
    // schedule() never returns when current_pid was null going in (dead-
    // letter eats the outgoing rsp), but the type system doesn't know that.
    while (true) asm volatile ("cli; hlt");
}

/// Mark current process as unused (called by sys_exit with no status — exit code 0).
pub fn destroyCurrent() void {
    destroyCurrentWithStatus(0);
}

/// Free a zombie slot after the parent has read its exit status. Called from
/// sysWaitpid. Safe to call only when procs[pid].state == .zombie — the heavy
/// teardown (page tables, fd_table, ELF buf, etc.) was already done at exit
/// time, so this is just a state flip.
pub fn reapZombie(pid: u8) void {
    if (pid >= MAX_PROCS) return;
    if (process.procs[pid].state != .zombie) return;
    const kp = @import("../debug/kstack_protect.zig");
    kp.checkpoint("reap:entry");
    process.setState(pid, .unused);
    @atomicStore(usize, &process.expected_kstack_tops[pid], 0, .release);
    @import("../debug/kasan.zig").markPcbDead(@intFromPtr(&process.kstack_pool[pid]) + KSTACK_GUARD_SIZE, KSTACK_SIZE);
    kp.checkpoint("reap:exit");
}

/// Find the lowest-pid zombie child of `parent`. Returns null if none.
/// `target_pid == 0xFFFFFFFF` means "any child"; otherwise wait for exactly
/// that pid.
pub fn findZombieChild(parent: u8, target_pid: u32) ?u8 {
    for (0..MAX_PROCS) |i| {
        if (process.procs[i].state != .zombie) continue;
        if (process.procs[i].parent_pid != parent) continue;
        if (target_pid != 0xFFFFFFFF and i != @as(usize, @intCast(target_pid))) continue;
        return @intCast(i);
    }
    return null;
}

/// Free the per-process ELF buffer (PMM-allocated contiguous frames).
fn freeElfBuf(pcb: *PCB) void {
    if (pcb.elf_buf) |buf| {
        // pcb.elf_buf is a kernel-side physmap VA (set from vfs.loadFileFresh's
        // physToVirt result). PMM speaks phys, translate.
        const paging = @import("../mm/paging.zig");
        const base: usize = paging.virtToPhys(@intFromPtr(buf)).?;
        pmm.freeContiguous(base, pcb.elf_buf_pages);
        pcb.elf_buf = null;
        pcb.elf_buf_pages = 0;
    }
}
