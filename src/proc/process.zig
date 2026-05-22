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
const runqueue = @import("runqueue.zig");
const SpinLock = @import("spinlock.zig").SpinLock;
const std = @import("std");

pub const MAX_PROCS = config.MAX_PROCS;
const KSTACK_SIZE = config.KSTACK_SIZE;

/// Targeted scheduler-trace gate. When non-zero, every setState CAS,
/// rqEnter, rqLeave, and pickNext CAS for this pid prints a one-line
/// klog with caller RA + CPU. Set to 0 to disable. Used 2026-05-20 to
/// root out the "state=.running but no cpu.current_pid points here"
/// pcb-invariant panic on Q1 — the trace klog widened the picker
/// CAS→bracket window enough to make the latent race fire reliably,
/// pinpointing that `cpu.dispatching_in_pid = cand` happened AFTER
/// rather than BEFORE the state CAS in pickNext. Bracket order fixed
/// 2026-05-20; trace left in place (gated to 0) for next regression.
const TRACE_PID: u8 = 0;
const KSTACK_GUARD_SIZE = config.KSTACK_GUARD_SIZE;
const KSTACK_SLOT_SIZE = config.KSTACK_SLOT_SIZE;
const MAX_FDS = config.MAX_FDS;

/// Default cwd byte array for new PCBs. Set to "/" — the ext2 root mount,
/// where user binaries live under `/bin/` (post Phase-2 migration). The
/// shell's PATH-style lookup is `/bin/<name>`; relative paths from "/" cwd
/// resolve through resolvePath via the mount-table catch-all. Tarfs is
/// still mounted at "/tar/" as a migration fallback so old absolute paths
/// don't hard-fail. vfs.resolvePath reads `pcb.cwd[0..pcb.cwd_len]`
/// literally, so the bytes must actually spell "/" — a zero-init default
/// would silently break every relative-path open with a path-not-found
/// bounce.
const INIT_CWD_PATH: []const u8 = "/";
const INIT_CWD: [256]u8 = blk: {
    var c = [_]u8{0} ** 256;
    for (INIT_CWD_PATH, 0..) |b, i| c[i] = b;
    break :blk c;
};

// Per-process kernel stack pool. Each slot is `[guard 4KB | stack 16KB ↑]`,
// 4KB-aligned so paging.installGuardPage can mark slot[0..4096] not-present.
// Static (BSS) so the addresses are stable from boot — guards must be planted
// before any user process exists (createAddressSpace copies kernel PD entries
// by value; later splits would leave older processes with stale huge-page
// entries). Pool slot i ↔ procs[i].
pub var kstack_pool: [MAX_PROCS][KSTACK_SLOT_SIZE]u8 align(4096) =
    [_][KSTACK_SLOT_SIZE]u8{[_]u8{0} ** KSTACK_SLOT_SIZE} ** MAX_PROCS;

/// Per-task scratch slot for held-across-yield I/O buffers (one disk
/// block = 4KB). Replaces `var X: [4096]u8 align(N) = undefined` patterns
/// in fs/* and elsewhere that were:
///   (a) eating ~4KB of kstack frame per call (close to KSTACK overflow
///       on deep paths), and
///   (b) being initialized to 0xAA by Zig ReleaseSafe undefined-fill,
///       tripping our deep-kstack watchpoint with false positives.
///
/// Per-task (not per-CPU) so callers can safely hold the buffer across
/// blocking I/O — preemption is a non-issue because each task owns its
/// own slot. Limited to ONE outstanding borrow per task; deep nesting
/// inside ext2/fat32 path-walks needs caller-passed buffers.
///
/// Cost: 4KB × MAX_PROCS = 128KB BSS at MAX_PROCS=32. Trivial.
pub var io_scratch_pool: [MAX_PROCS][4096]u8 align(4096) =
    [_][4096]u8{[_]u8{0} ** 4096} ** MAX_PROCS;

/// Boot-time fallback. Returned by currentIoScratch when no current_pid
/// is set (e.g. fs init runs from kmain before SMP/pid bring-up). Boot
/// is single-threaded at this point so no concurrency exposure.
var boot_io_scratch: [4096]u8 align(4096) = [_]u8{0} ** 4096;

/// Return the current task's I/O scratch slot, or a boot-time fallback
/// when no current_pid is set (early kmain fs init). Callers MUST NOT
/// nest borrows on the same task — see io_scratch_pool docs.
pub fn currentIoScratch() *[4096]u8 {
    if (smp.myCpu().current_pid) |pid| return &io_scratch_pool[pid];
    return &boot_io_scratch;
}

pub const State = enum(u8) {
    unused, // slot is free and may be claimed by process.create
    loading, // process.create has claimed the slot but the loader hasn't
    // finished initializing it (page_directory, lazy_regions,
    // pcb fields). pickNext MUST NOT pick a loading PCB — without
    // this gap, an AP racing process.create's `state=.ready` set
    // dispatches a half-initialized PCB with page_dir_phys=0, runs
    // it on the kernel CR3, and the user code page is mapped USER
    // (boot.asm identity map) so no PF fires and the process loops
    // forever in a zero page. loader transitions loading→ready.
    ready,
    running,
    sleeping,
    zombie,
    // (Removed: .switching_out. The "another CPU is mid-save on this
    // PCB" condition is now signaled by `cpu.save_in_flight_prev`,
    // checked atomically in pickNext for every candidate. Demotion
    // .running → .ready happens directly in schedule()'s Zig, before
    // the gate is published; switchTo asm clears the gate after the
    // rsp save commits, re-opening the PCB to pickers.)
};

pub const Priority = enum(u8) {
    background = 0,
    normal = 1,
    interactive = 2,
};

pub const FsType = enum(u8) { console = 0, fat32 = 1, tarfs = 2, pipe = 3, devfs = 4, procfs = 5, ext2 = 6 };

/// Generic blocking primitive used by waitpid + pipe read/write. The scheduler
/// treats a PCB with wait_kind != .none as not runnable. Exactly one waiter
/// per resource is allowed (parent-on-child for waitpid; one read/write side
/// per pipe end for pipes), so the PCB itself is the wait queue — no separate
/// queue structure needed.
pub const WaitKind = enum(u8) {
    none,
    waitpid, // wait_target = child pid, or 0xFFFFFFFF = any child
    pipe_read, // wait_target = pipe id
    pipe_write, // wait_target = pipe id
    futex, // wait_target = exact 4-byte-aligned user VA of the futex word (NOT page-aligned — two futexes in one page must stay distinct); FUTEX_WAKE matches on the exact VA
    gpu_io, // wait_target = ignored; virtio-gpu IRQ wakes all .gpu_io waiters (only one exists at a time, ctrl_lock-serialized)
    mutex, // wait_target = low-32 of &Mutex.owner_pid; Mutex.release walks procs and wakes matching waiters
    nvme_io, // wait_target = (ctrl_idx << 16) | cid — NVMe MSI-X handler reaps CQ + wakes by exact (ctrl,cid) match
};

pub const FileDesc = struct {
    in_use: bool = false,
    inode: u32 = 0,
    offset: u32 = 0,
    flags: u8 = 0,
    fs_type: FsType = .console,
    fat_cluster: u32 = 0, // cached FAT32 cluster for O(1) sequential reads
    fat_cluster_off: u32 = 0, // byte offset that fat_cluster corresponds to
    // Cluster of the parent directory holding this file's dirent — set on
    // open/create and used by reads/writes/closes to update the entry's
    // file_size in the right directory. 0 means "use fat32.root_cluster"
    // (back-compat default for older fds and the root-dir case).
    fat_dir_cluster: u32 = 0,
    pipe_id: u8 = 0xFF, // valid only when fs_type == .pipe
};

pub const PCB = struct {
    state: State = .unused,
    kernel_esp: usize = 0,
    kernel_stack_top: usize = 0,
    // VMM fields
    page_directory: ?[*]align(4096) u64 = null,
    page_dir_phys: usize = 0,
    user_brk: usize = memmap.USER_BRK_INITIAL, // sbrk start; sits above kernel heap (see memmap.zig)
    // mmap allocator (sysMmap). VAs grow downward from USER_SPACE_END so they
    // don't collide with the upward-growing user_brk; collision is rejected
    // explicitly in sysMmap. munmap currently leaks VA range — we don't reclaim
    // unmapped VA into a free list (pages are freed, just the address space
    // isn't compacted). v2 problem; bump-allocator works fine for short-lived
    // apps and the few hundred MB of user space is plenty for now.
    mmap_top: usize = MMAP_TOP_INIT,
    // File descriptor table
    fd_table: [MAX_FDS]FileDesc = initFdTable(),
    // Sleep support
    wake_tick: u64 = 0,
    // Race-free wake handshake. wake() sets this BEFORE clearing wait_kind /
    // setStating .ready, so a blockOn that just set wait_kind but hasn't yet
    // setState(.sleeping) can detect the race after setState and roll back.
    // Without this, the wake() can land between blockOn's wait_kind store and
    // its setState — wake clears wait_kind and sees state==.running (no-op),
    // then blockOn's setState sleeps the task with no waker. Reproduced as
    // "shell stops accepting input after a few keystrokes" / "calc clicks
    // dead" — both apps eventually call blockOn (via pipe.read or sysSleep)
    // and lose a wake to this race. Atomic for cross-CPU visibility.
    wake_pending: bool = false,
    // Process name (for window titles / icon matching)
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    // Real argv vector. argv[0] is the program name without `.elf`; argv[1..
    // argc] are user-supplied args parsed out of the exec string by splitting
    // on spaces. Replaces the old single-string `exec_arg`/`exec_arg_len`,
    // which couldn't represent multi-arg invocations like `cat foo bar`.
    // syscall 25 (getExecArg) is preserved as a backward-compat shim by
    // joining argv[1..] with spaces in the kernel.
    argv: [config.MAX_ARGS][config.MAX_ARG_LEN]u8 =
        [_][config.MAX_ARG_LEN]u8{[_]u8{0} ** config.MAX_ARG_LEN} ** config.MAX_ARGS,
    arg_lens: [config.MAX_ARGS]u8 = [_]u8{0} ** config.MAX_ARGS,
    argc: u8 = 0,
    // Scheduler — track consecutive ticks for fairness
    ticks_used: u32 = 0,
    priority: Priority = .normal,
    last_cpu: u8 = 0, // CPU this process last ran on (for affinity)
    // GPU 3D context
    gpu_ctx_id: u32 = 0,
    gpu_has_ctx: bool = false,
    // Debug symbols (loaded from ELF section headers)
    sym_table: ?*symbols.SymTable = null,
    // Current working directory. The default is "/tar/" (the user-binary
    // mount) — see INIT_CWD comment above for why the bytes need to actually
    // spell that path rather than relying on a zero default.
    cwd: [256]u8 = INIT_CWD,
    cwd_len: u8 = INIT_CWD_PATH.len,
    // Lazy regions: VA ranges whose pages get allocated on first access via the
    // page-fault handler. Used for: 64KB user stack (avoids upfront cost),
    // sbrk heap (grows on demand), and demand-paged ELF segments.
    lazy_regions: [MAX_LAZY_REGIONS]LazyRegion = [_]LazyRegion{.{}} ** MAX_LAZY_REGIONS,
    lazy_count: u8 = 0,
    // Index of the lazy region tracking the heap (sbrk). -1 = no heap region
    // has been registered yet. Allows sysSbrk to extend in place across calls.
    heap_lazy_idx: i8 = -1,
    // Swap clock cursor (a user VA): reclaimViaSwap resumes its cold-page
    // eviction scan from here so it doesn't rescan already-evicted pages on
    // every fault (turns an O(n^2) linear-scan workload into O(n)).
    swap_clock_va: usize = 0,
    // Per-process kernel-side ELF buffer (PMM-allocated contiguous frames).
    // Lazy regions for PT_LOAD segments reference this; freed on process destroy.
    elf_buf: ?[*]u8 = null,
    elf_buf_pages: u32 = 0,
    // Bottom of the user stack (lazy region start). Set by elf_loader. The
    // page-fault handler treats faults in [stack_base - GUARD_SIZE, stack_base)
    // as stack overflow rather than a generic segfault.
    stack_base: usize = 0,
    // Cycles spent descheduled inside the current syscall — bumped by blocking
    // primitives (yield/sleep) and subtracted by doSyscall so the syscall
    // counter reflects CPU time, not wall time.
    perf_gap_cyc: u64 = 0,
    // --- Process tree + exit/wait (Task #73) ---
    // 0 means "no parent" (kernel-spawned, e.g. desktop). When this process
    // exits, killProcess/destroyCurrent looks for procs[parent_pid] with a
    // matching wait_kind == .waitpid and wakes it.
    parent_pid: u8 = 0,
    // Exit status reported via sysWaitpid. Valid only when state == .zombie.
    exit_status: u32 = 0,
    // Generic blocking primitive (used by waitpid + pipe.read/write).
    // Scheduler skips PCBs with wait_kind != .none.
    wait_kind: WaitKind = .none,
    wait_target: u32 = 0,
    // --- POSIX signals (src/signals.zig) ---
    // Pending bitmap — bit N = signal N is pending. Cleared when delivered.
    // u32 caps us at NSIG=32 which matches POSIX 1..31; widening to u64 +
    // rt-signals is a future tunable in config.zig.
    pending_signals: u32 = 0,
    // Currently blocked signals (sigprocmask). Signals marked pending while
    // blocked stay pending until unblocked, then deliver in numeric order.
    signal_mask: u32 = 0,
    // Per-signal disposition. Default = all SIG_DFL with empty mask/flags;
    // signals.zig consults default_actions[] to decide what SIG_DFL means
    // for each signal (term, core, ignore, stop, cont).
    sigactions: [config.NSIG]signals.SigAction = [_]signals.SigAction{.{}} ** config.NSIG,
    // Mask snapshot taken when entering a handler — restored by sigreturn.
    saved_signal_mask: u32 = 0,
    // True between handler entry and sigreturn. Suppresses re-entry from
    // syscall/IRQ delivery paths (a handler that itself does syscalls would
    // otherwise stack signal frames recursively).
    in_signal_handler: bool = false,
    // Tick at which a pending SIGALRM should be delivered, or 0 for none.
    // Compared against tick_count in process.deliverDueAlarms each timer.
    alarm_tick: u64 = 0,

    // --- Threads (sysClone) ---------------------------------------------
    // Thread group ID = pid of the lead thread that started the process.
    // Threads spawned via sysClone copy the parent's tgid; lead-thread
    // PCBs have tgid == self_pid. Per-process state — lazy_regions for
    // shared mmap, fd_table, etc. — is owned by `procs[tgid]`. The page
    // fault handler reads `procs[pcb.tgid].lazy_regions` so all threads
    // see the same mmap'd address space.
    //
    // 0xFF means "not assigned yet"; create() and clone() fill it in.
    tgid: u8 = 0xFF,

    // --- Sessions / process groups (POSIX setsid / setpgid) -------------
    // Process group ID = pid of the group leader. Default fill-in (by
    // process.create) is self_pid (own group). fork() and sysExec()
    // inherit parent's pgid; setpgid() moves into a different group;
    // setsid() makes the caller a group AND session leader (pgid = sid =
    // self_pid). Used for kill(-PID) → "signal whole group", for shell
    // job control's foreground-group concept, and for daemons that detach
    // from the parent shell's session via setsid.
    pgid: u8 = 0,
    // Session ID = pid of the session leader. Boot session is whatever sid
    // the desktop kernel-task ends up with (it's never set explicitly, so
    // its children inherit the create()-default of self_pid). User
    // sessions are created by setsid(): caller's sid becomes its own pid,
    // and it's no longer in any other process group. Daemons run their
    // own session so closing the parent shell's session leader doesn't
    // SIGHUP them.
    sid: u8 = 0,

    // Per-thread TLS base (written to IA32_FS_BASE on dispatch). 0 = no
    // TLS / inherit. Set by sysSetTls.
    fs_base: u64 = 0,
    // Userspace tid pointer — when this thread exits, futex-wake any
    // thread joining on this address. 0 = no join address.
    clear_child_tid: u32 = 0,
    // Per-thread snapshot of `per_cpu_user_rsp[cpu]`. The syscall entry
    // stub stashes the user RSP into the per-CPU slot; if this thread is
    // preempted mid-syscall and another thread on the same CPU enters its
    // own syscall, the per-CPU slot is overwritten. Schedule saves the
    // slot here on switch-out and restores from here on switch-in so each
    // thread's sysret pops the right user RSP.
    user_rsp_save: u64 = 0,

    // PCID for this address space (CR4.PCIDE). 0 = no tagging (kernel
    // tasks or PCID feature unavailable). User PCBs get a non-zero PCID
    // from `pcid.alloc` when their page_dir_phys is assigned and free it
    // on destroyAddressSpace. The schedule path uses pcid + the per-CPU
    // generation tracker to set CR3 bit 63 (preserve-TLB) on reloads.
    pcid: u16 = 0,

    // iretq-frame snapshot tripwire (task #230). Captured by
    // debug.iretq_canary.capture() at IRQ/exception entry; checked at
    // every `iretq_canary.check(@src())` call. Travels with the task
    // across CPU migrations because it's per-PCB (not per-CPU). See
    // src/debug/iretq_canary.zig for the design rationale.
    iretq_snap: @import("../debug/iretq_canary.zig").Snap = .{},

    // --- Per-CPU kernel idle (task #235) -----------------------------------
    // True for kernel-mode idle PCBs (one per CPU, created at SMP boot).
    // These run a simple `sti; hlt; jmp` loop in CS=0x08 — no user space,
    // no syscall_entry, no iretq path. They exist so every CPU ALWAYS has
    // a current task: when no user task is ready, schedule() dispatches
    // the cpu's own idle. This eliminates the "scheduler context with stale
    // per_cpu_asm" failure mode that powered the iretq-aliasing bug class.
    is_idle: bool = false,
    // Which CPU owns this idle PCB. pickNext only picks an idle PCB when
    // cpu.cpu_id == idle_cpu — prevents two CPUs from racing onto the
    // same idle kstack (the bug we observed before per-CPU idle existed).
    idle_cpu: u8 = 0xFF,
    // CPU pin for non-idle kernel tasks (desktop). Only this CPU picks
    // them. 0xFF = unpinned (normal user task — schedulable anywhere).
    // Without this, an AP can pick the desktop kernel task (its priority
    // is higher than user tasks), causing two CPUs to run desktop on
    // its single kstack and trip BSP-only assertions. Set by
    // createKernelTask from its `cpu_id` arg.
    pinned_cpu: u8 = 0xFF,

    // --- Phase 1 runqueue parallel-tracking (scheduler rewrite) -----------
    // Which CPU's `runqueue` this PCB is enqueued on when state == .ready.
    // Set ONCE at create() via `assignInitialCpu` (round-robin for plain
    // user tasks; copies idle_cpu / pinned_cpu when those are set). Phase
    // 4's load balancer will mutate this under both rq.lock acquisitions.
    // 0xFF = not yet assigned (between allocSlot and the post-init assign).
    assigned_cpu: u8 = 0xFF,
    // Cross-CPU exit signal. The killer sets this true atomically + IPIs
    // the assigned_cpu; that CPU's schedule() observes the flag on its
    // own current task and tears self down on its own kstack — closing
    // the kill-vs-save race without the dead-letter machinery. Phase 1
    // only stores the field; the consumer lands in Phase 2's cutover.
    exit_requested: bool = false,

    // --- CFS-style vruntime (scheduler rewrite, post-Phase 7) -------------
    // Accumulated CPU "fair-share" time in ticks. Bumped by accountRunningTick
    // each tick this PCB is currently running, scaled by the inverse of its
    // weight so that lower-nice (higher-priority) tasks accumulate vruntime
    // slower → get picked more often within their band. Pickers select the
    // lowest vruntime within each priority band.
    vruntime: u64 = 0,
    // Tick at which the current run-slice began (set by schedule() when
    // this PCB transitions to .running). On the next preempt or
    // checkPreempt firing, `tick_count - slice_start_tick` is the slice
    // length used for ideal_runtime gating.
    slice_start_tick: u64 = 0,
    // Linux-style nice value, range -20..19 (defaults to 0). Lower = more
    // CPU share, higher = less. Maps to a weight via NICE_WEIGHTS; vruntime
    // increment per tick = NICE_0_WEIGHT / weight[20+nice]. So nice=-20
    // (weight 88761) consumes vruntime ~12× slower than nice=0 (weight
    // 1024); nice=19 (weight 15) consumes ~68× faster. Within a priority
    // band, this lets userspace fine-tune CPU share without changing the
    // band. setpriority(#47) still picks the BAND; sysSetNice (#101) picks
    // the WEIGHT within the band.
    nice: i8 = 0,

    // --- Accounting (process accounting infra) ----------------------------
    // Counters maintained by scheduler / page-fault handler / syscall
    // dispatch / vmm.mapUserPage. Read by sysProcessList for sysmon. All
    // monotonically-increasing except `acct_current_rss` which goes both
    // ways. None of these participate in correctness — purely diagnostic.
    /// Total scheduler ticks ever consumed by this PCB. One tick = one
    /// timer-IRQ interval (LAPIC tick). Add `acct_cpu_ticks * tick_ms`
    /// to get wall-clock CPU time.
    acct_cpu_ticks: u64 = 0,
    /// Page faults serviced for this PCB (user-mode). Includes lazy
    /// region fault-ins, NOT supervisor-mode kernel faults.
    acct_pf_count: u32 = 0,
    /// Total syscalls dispatched to this PCB since creation.
    acct_syscall_count: u64 = 0,
    /// Peak resident set size in pages — high-water mark of
    /// acct_current_rss. Useful for sizing decisions and OOM heuristics.
    acct_peak_rss: u32 = 0,
    /// Currently-mapped user pages (R/W and lazy faulted alike).
    /// Bumped by vmm.mapUserPage; decremented when pages are unmapped /
    /// when the process is destroyed.
    acct_current_rss: u32 = 0,
    /// Tick at which this PCB entered its first non-unused state.
    /// `tick_count - acct_start_tick` = process uptime in ticks.
    acct_start_tick: u64 = 0,

    // --- Diagnostic syscall ring ---------------------------------------
    // 8-entry circular buffer of the most recent syscall numbers (high
    // bit set on the entry written *most recently* — used as the head
    // marker so dump order is unambiguous without a separate index).
    // Cost: 16 bytes per PCB. Dumped on panic / watchdog wedge /
    // sysExitStatus to answer "what was this PID doing when it died /
    // hung?" — a class of question the existing acct_syscall_count
    // total can't answer because it's just a counter.
    syscall_ring: [8]u16 = [_]u16{0} ** 8,
    syscall_ring_head: u8 = 0,
};

pub const SYSCALL_RING_LEN: u8 = 8;

/// Record `sys_num` into this PCB's ring. Called from the syscall
/// dispatch entry point (after PID resolution). Cheap — single store +
/// modular increment; safe to call with IRQs enabled because the PCB
/// is touched only by its assigned CPU.
pub fn recordSyscall(pcb: *PCB, sys_num: u16) void {
    pcb.syscall_ring[pcb.syscall_ring_head] = sys_num;
    pcb.syscall_ring_head = (pcb.syscall_ring_head + 1) % SYSCALL_RING_LEN;
}

/// Print this PCB's recent syscall ring, newest first.
pub fn dumpSyscallRing(pid: u8) void {
    if (pid >= MAX_PROCS) return;
    const pcb = &procs[pid];
    debug.klog("[syscall-ring pid={d}] last {d} (newest first):", .{ pid, SYSCALL_RING_LEN });
    var i: u8 = 0;
    while (i < SYSCALL_RING_LEN) : (i += 1) {
        const idx = (pcb.syscall_ring_head + SYSCALL_RING_LEN - 1 - i) % SYSCALL_RING_LEN;
        const num = pcb.syscall_ring[idx];
        if (num == 0 and i > 0) break;
        debug.klog(" #{d}", .{num});
    }
    debug.klog("\n", .{});
}

/// Read-through helper: returns the lead thread's PCB for fields that
/// are conceptually per-process. Single-threaded processes have
/// `pcb.tgid == self_pid` so `leader(pcb) == pcb` and no behavior change.
pub inline fn leader(pcb: *PCB) *PCB {
    return &procs[pcb.tgid];
}

pub const MAX_LAZY_REGIONS: u8 = config.MAX_LAZY_REGIONS;

/// Initial value for `PCB.mmap_top`. memmap.USER_SPACE_END is u64; we narrow
/// to usize once at the comptime boundary so the field default stays clean.
pub const MMAP_TOP_INIT: usize = @intCast(memmap.USER_SPACE_END);

// Linux-style prot bits — stored on each LazyRegion and consulted by
// `handleUserPageFault` to derive the PTE flags. PROT_READ has no PTE
// representation (pages are readable when PRESENT), so it's effectively
// informational; the work happens in PROT_WRITE / PROT_EXEC.
pub const PROT_READ: u8 = 1;
pub const PROT_WRITE: u8 = 2;
pub const PROT_EXEC: u8 = 4;
pub const PROT_RW: u8 = PROT_READ | PROT_WRITE;
pub const PROT_RWX: u8 = PROT_READ | PROT_WRITE | PROT_EXEC;

pub const LazyRegion = struct {
    start: usize = 0,
    end: usize = 0, // exclusive
    flags: u8 = 0, // reserved for future use (RO/exec/etc.)
    // Optional source for demand-paged ELF segments. If non-null, on first
    // touch the kernel copies the intersection of the new page's VA range with
    // [src_va_base, src_va_base + src_size) from `source`. Bytes outside that
    // intersection stay zero (the freshly mapped page is already zero-filled).
    source: ?[*]const u8 = null,
    src_va_base: usize = 0,
    src_size: usize = 0,
    src_offset: usize = 0,
    // True iff `source` was PMM-allocated by sysMmap (file-backed mmap) and
    // belongs to this region. munmap and destroyCurrent free `buf_pages`
    // contiguous frames starting at `source` when this is set. ELF segments
    // share `pcb.elf_buf` and DON'T set this — that buffer is freed once via
    // freeElfBuf instead.
    buf_owned: bool = false,
    buf_pages: u16 = 0,
    // Page-protection bits (PROT_READ | PROT_WRITE | PROT_EXEC). Default RWX
    // matches the pre-PROT-enforcement behavior so legacy callers (sbrk, ELF
    // segments, lazy stack) keep working without per-call updates. mmap and
    // mprotect explicitly set tighter prots (PROT_RW = no exec; PROT_READ
    // alone = RO + NX; etc.) and the page-fault handler honors them.
    prot: u8 = PROT_RWX,
};

fn initFdTable() [MAX_FDS]FileDesc {
    var table: [MAX_FDS]FileDesc = [_]FileDesc{.{}} ** MAX_FDS;
    // Pre-open stdin(0), stdout(1), stderr(2)
    table[0] = .{ .in_use = true, .inode = 0, .offset = 0, .flags = 0, .fs_type = .console }; // stdin
    table[1] = .{ .in_use = true, .inode = 0, .offset = 0, .flags = 1, .fs_type = .console }; // stdout
    table[2] = .{ .in_use = true, .inode = 0, .offset = 0, .flags = 1, .fs_type = .console }; // stderr
    return table;
}

pub var procs: [MAX_PROCS]PCB = [_]PCB{.{}} ** MAX_PROCS;

// Tick counter incremented by IRQ0
pub var tick_count: u64 = 0;

/// Plant the unmapped guard page at the bottom of every kstack pool slot.
/// Must run after pmm/paging are up and BEFORE the first user process is
/// created (see comment on kstack_pool for the chicken-and-egg with
/// vmm.createAddressSpace). Idempotent.
///
/// UEFI path is currently skipped: the firmware's 1GB huge pages need a
/// 1GB→2MB→4KB triple-split, and PMM-allocated PT pages end up at addresses
/// (0x1C40000+) that get corrupted by something between install and use,
/// triple-faulting the kernel on a "not-present" instruction-fetch from a
/// kernel .text page that the split *did* map. Multiboot only needs a
/// 2MB→4KB split and works fine. Disabling on UEFI keeps stack overflow
/// detection on Multiboot while UEFI is investigated separately.
pub fn initKstackGuards() void {
    if (@import("../boot/boot_info.zig").is_uefi) {
        debug.klog("[proc] kstack guards disabled on UEFI (see comment)\n", .{});
        return;
    }
    for (0..MAX_PROCS) |i| {
        const slot_base = @intFromPtr(&kstack_pool[i]);
        if (!@import("../mm/paging.zig").installGuardPage(slot_base)) {
            debug.klog("[proc] guard page install failed for slot {d} @ 0x{X}\n", .{ i, slot_base });
        }
    }
}

/// True if `top` is a plausible kernel_stack_top value — it points at the
/// HIGH edge of one of kstack_pool's slots, or matches the recorded top of
/// some heap-allocated kstack (kernel tasks like desktop with non-default
/// sizes — see createKernelTask). Used by gdt.setTssRsp0 to catch a
/// corrupted PCB.kernel_stack_top BEFORE it leaks into TSS.RSP0 (which
/// both the IDT-gate AND the syscall-entry path read).
pub fn isValidKstackTopShape(top: usize) bool {
    const base = @intFromPtr(&kstack_pool[0]);
    const end = base + MAX_PROCS * KSTACK_SLOT_SIZE;
    if (top > base and top <= end) {
        return ((top - base) % KSTACK_SLOT_SIZE) == 0;
    }
    // Heap-backed kstacks: scan the per-PID witnesses set at create() time.
    // Same array `isValidKstackTop` consults for the per-PID exact match —
    // a heap kstack is just any expected_kstack_tops entry that doesn't sit
    // in the pool's address range (already handled by the early return).
    for (expected_kstack_tops) |t| {
        if (t != 0 and t == top) return true;
    }
    return false;
}

/// Per-PID expected kernel_stack_top — set ONCE at create() and immutable
/// for the life of the slot. Lives in a separate static array (not in PCB)
/// so a wild writer that scribbles inside procs[i] can't simultaneously
/// corrupt the witness. setTssRsp0 cross-checks PCB.kernel_stack_top
/// against expected_kstack_tops[pid] — mismatch = corruption, panic
/// pointing at the bad slot rather than letting the wild value leak into
/// TSS.RSP0 and crash deep inside doSyscall. Defends against:
///   - cross-PCB writes (e.g. desktop's heap kstack value leaking into
///     procs[3] — the smoking gun for the wild-RIP bug we've been chasing)
///   - wild stores into procs[].kernel_stack_top from anywhere
///   - stale PCB residue after slot recycle
pub var expected_kstack_tops: [MAX_PROCS]usize = [_]usize{0} ** MAX_PROCS;

/// True iff `top` matches the expected kernel_stack_top recorded at create
/// time for `pid`. Tightened from isValidKstackTopShape (which only
/// checks "is this any plausible top") to a per-PID exact match —
/// catches cross-PCB leaks that the shape check would silently accept.
pub fn isValidKstackTop(pid: usize, top: usize) bool {
    if (pid >= MAX_PROCS) return false;
    const expected = @atomicLoad(usize, &expected_kstack_tops[pid], .acquire);
    if (expected == 0) return false; // slot never initialized
    return top == expected;
}

/// True if `addr` falls inside any kstack pool guard region (bottom 4KB of a
/// slot). Used by the page-fault handler to flag stack overflow definitively.
pub fn addrInKstackGuard(addr: usize) ?u8 {
    const base = @intFromPtr(&kstack_pool[0]);
    const total = MAX_PROCS * KSTACK_SLOT_SIZE;
    if (addr < base or addr >= base + total) return null;
    const off = addr - base;
    const slot = off / KSTACK_SLOT_SIZE;
    const within = off % KSTACK_SLOT_SIZE;
    if (within >= KSTACK_GUARD_SIZE) return null;
    return @intCast(slot);
}

// =============================================================================
// Phase 1: per-CPU runqueue parallel-tracking
// =============================================================================
//
// Centralized state-transition path. Every PCB state change SHOULD route
// through `setState` — it maintains the per-CPU runqueue's view of "which
// pids are .ready and assigned here" alongside the legacy state byte.
//
// The two CAS sites that can't go through setState (allocSlot's
// .unused→.loading CAS and schedule()'s pickNext-claim .ready→.running CAS)
// instead call the explicit one-side helpers (`rqOnLeaveReady` after they
// flip a pid out of .ready). Phase 1 is shadow-only — `pickNext` still
// scans procs[] — so the rq is purely audit material until Phase 2.

/// Phase 4 load-balancer thresholds. BALANCE_INTERVAL_TICKS gates how
/// often loadBalance() runs (BSP timer IRQ); BALANCE_THRESHOLD is the
/// minimum (busiest_load - idlest_load) delta that triggers a single-task
/// migration. 50 ticks × 10 ms = ~500 ms cadence; threshold 2 prevents
/// migration ping-pong when load differs by 1.
const BALANCE_INTERVAL_TICKS: u64 = 50;
const BALANCE_THRESHOLD: u16 = 2;

/// CFS-style scheduling tunables. Units are timer ticks (10 ms each at
/// our 100 Hz LAPIC cadence). See pickNext / checkPreempt / setState
/// (sleeper-bonus path) / migrate for usage.
///
/// SCHED_LATENCY: target wall time for ALL runnable tasks in a band to
///   each get one slice. With 6 ticks (60 ms) and N runnable tasks,
///   ideal_runtime = max(MIN_GRANULARITY, SCHED_LATENCY/N).
/// MIN_GRANULARITY: floor on a slice. Without this, two tasks with
///   near-equal vruntime would ping-pong every tick.
/// SLEEPER_CREDIT: when a task wakes from .sleeping, it's bumped to
///   `max(vruntime, min_vruntime - SLEEPER_CREDIT)` so it runs soon
///   without strip-mining tasks that have been waiting at the floor.
///   Half SCHED_LATENCY is the standard CFS heuristic.
const SCHED_LATENCY: u64 = 6;
const MIN_GRANULARITY: u64 = 1;
const SLEEPER_CREDIT: u64 = 3;

/// Linux-style nice → weight table (kernel/sched/core.c sched_prio_to_weight[]).
/// Indexed by `nice + 20` (so range -20..19 maps to indices 0..39).
/// The ratio between adjacent nice levels is ~1.25 (so each nice level changes
/// CPU share by ~25%), and nice=0 has weight NICE_0_WEIGHT (1024 on Linux —
/// our canonical "1 unit of vruntime per tick" baseline).
const NICE_0_WEIGHT: u64 = 1024;
const NICE_WEIGHTS = [40]u64{
    // nice -20..-11
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
    // nice -10..-1
     9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
    // nice 0..9
     1024,   820,   655,   526,   423,   335,   272,   215,   172,   137,
    // nice 10..19
      110,    87,    70,    56,    45,    36,    29,    23,    18,    15,
};

/// Map a nice value (-20..19, clamped) to its weight. Out-of-range nice is
/// clamped to the nearest endpoint.
inline fn niceToWeight(nice: i8) u64 {
    const clamped: i8 = if (nice < -20) -20 else if (nice > 19) 19 else nice;
    const idx: usize = @intCast(@as(i32, clamped) + 20);
    return NICE_WEIGHTS[idx];
}

/// Cursor kept around for diagnostic continuity; load-balancer-driven
/// assignInitialCpu picks min effective load now, no round-robin needed.
var next_assignment_cpu: u8 = 0;

/// schedule()-call counter used to throttle `rqAudit` to every 64th call.
/// u32 wrap is harmless — only the low bits matter for the cadence test.
var sched_audit_counter: u32 = 0;

/// Effective scheduling load on a cpu — the runnable count plus 1 if a
/// non-idle task is currently dispatched. This counts the running task
/// as load (a CPU with one .ready and one .running has effective load 2,
/// not 1) so we don't preferentially place new tasks on a cpu that's
/// already pinned saturating something — desktop on cpu0 with empty rq
/// has effective load 1, not 0.
fn effectiveLoad(cpu_idx: usize) u16 {
    if (cpu_idx >= smp.MAX_CPUS) return std.math.maxInt(u16);
    if (!smp.cpus[cpu_idx].alive) return std.math.maxInt(u16);
    var load: u16 = smp.cpus[cpu_idx].runqueue.nr_runnable;
    if (smp.cpus[cpu_idx].current_pid) |cur| {
        if (cur < MAX_PROCS and !procs[cur].is_idle) load +%= 1;
    }
    return load;
}

/// Assign a freshly-created PCB to a CPU's runqueue. Called once per
/// PCB lifecycle, after the kstack/page-tables are set up but BEFORE
/// the first state→.ready transition (so the rqEnter triggered by
/// setState lands on the right rq).
///
/// Idempotent — repeated calls inside a single PCB lifetime no-op.
/// resetPcbExceptState resets `assigned_cpu` to 0xFF on slot recycle,
/// so the next create() lands a fresh assignment.
///
/// Phase 4: picks the cpu with the lowest effective load (vs the prior
/// "skip cpu0" hack). Combined with pickNext's exclude_prev fairness
/// and the periodic load balancer, this lets cpu0 share work with
/// desktop instead of being permanently dedicated.
pub fn assignInitialCpu(pid: usize) void {
    const pcb = &procs[pid];
    if (pcb.assigned_cpu != 0xFF) return;
    if (pcb.is_idle) {
        pcb.assigned_cpu = pcb.idle_cpu;
        return;
    }
    if (pcb.pinned_cpu != 0xFF) {
        pcb.assigned_cpu = pcb.pinned_cpu;
        return;
    }
    var best_cpu: u8 = 0;
    var best_load: u16 = std.math.maxInt(u16);
    var i: u8 = 0;
    while (i < smp.MAX_CPUS) : (i += 1) {
        if (!smp.cpus[i].alive) continue;
        const load = effectiveLoad(i);
        if (load < best_load) {
            best_load = load;
            best_cpu = i;
        }
    }
    pcb.assigned_cpu = best_cpu;
    next_assignment_cpu +%= 1; // diag-only cursor
}

/// Phase 4: move pid from its current assigned_cpu's runqueue to
/// new_cpu's. Atomic across both rq locks (acquired in cpu_id order to
/// avoid deadlock with concurrent migrate calls). Skips pinned/idle/
/// dead/already-there pids.
///
/// If pid is .ready (in the source rq), it's removed and pushed to the
/// target rq's matching priority queue. For other states (.running,
/// .sleeping, .loading), only assigned_cpu is updated — the next
/// state→.ready transition will rqEnter on the new cpu.
///
/// Returns true on a state-affecting move, false otherwise.
pub fn migrate(pid: u8, new_cpu: u8) bool {
    if (pid >= MAX_PROCS) return false;
    if (new_cpu >= smp.MAX_CPUS) return false;
    if (!smp.cpus[new_cpu].alive) return false;

    const pcb = &procs[pid];
    if (pcb.is_idle) return false;
    // Pinned tasks can only migrate TO their pin destination — load
    // balancer respects pinning, but sysSetAffinity sets pinned_cpu first
    // and then calls migrate() to move the task to its pin.
    if (pcb.pinned_cpu != 0xFF and pcb.pinned_cpu != new_cpu) return false;
    const old_cpu = pcb.assigned_cpu;
    if (old_cpu == new_cpu) return false;
    if (old_cpu == 0xFF or old_cpu >= smp.MAX_CPUS) return false;

    const lo: u8 = @min(old_cpu, new_cpu);
    const hi: u8 = @max(old_cpu, new_cpu);
    const lo_lock = &smp.cpus[lo].runqueue.lock;
    const hi_lock = &smp.cpus[hi].runqueue.lock;
    const f = lo_lock.acquireIrqSave();
    hi_lock.acquire();
    defer {
        hi_lock.release();
        lo_lock.releaseIrqRestore(f);
    }

    // Re-check under both locks — pid may have moved/died since our
    // pre-lock snapshot.
    if (pcb.assigned_cpu != old_cpu) return false;
    if (pcb.is_idle) return false;
    const state_byte = @atomicLoad(u8, @as(*const u8, @ptrCast(&pcb.state)), .acquire);
    if (state_byte == @intFromEnum(State.unused) or
        state_byte == @intFromEnum(State.zombie)) return false;

    // Cross-CPU dispatch race fix (task #713). Refuse migration if any CPU
    // still has `pid` as `current_pid` — that CPU may be mid-schedule,
    // having demoted prev to .ready (visible to us NOW), but not yet
    // updated prev's kernel_esp via switchTo's save. Picking prev up here
    // and dispatching elsewhere would resume from a stale kernel_esp →
    // stack corruption. Caller (loadBalance) retries next tick.
    for (0..smp.MAX_CPUS) |i| {
        if (i > 0 and !smp.cpus[i].alive) continue;
        if (smp.cpus[i].current_pid) |cur| {
            if (cur == pid) return false;
        }
    }

    const old_rq = &smp.cpus[old_cpu].runqueue;
    const new_rq = &smp.cpus[new_cpu].runqueue;

    var removed = false;
    if (old_rq.interactive.remove(pid)) {
        old_rq.nr_runnable -%= 1;
        removed = true;
    } else if (old_rq.normal.remove(pid)) {
        old_rq.nr_runnable -%= 1;
        removed = true;
    } else if (old_rq.background.remove(pid)) {
        old_rq.nr_runnable -%= 1;
        removed = true;
    }
    if (removed) {
        // CFS vruntime translation: preserve the task's "fairness debt"
        // (lag above the source floor) and re-anchor on the destination
        // floor. Linux place_entity-style. Saturating subtract: if
        // vruntime < old_floor (e.g., a task that fell behind while
        // sleeping), treat lag as 0 — the task is effectively at the
        // floor anyway. Without saturation, wrapping `-%` underflows
        // to ~u64-max and the task gets stuck never being picked
        // (vruntime > everyone else's, picker always passes it over).
        const band: usize = @intFromEnum(pcb.priority);
        const old_floor = old_rq.min_vruntime[band];
        const new_floor = new_rq.min_vruntime[band];
        const lag: u64 = if (pcb.vruntime > old_floor) pcb.vruntime - old_floor else 0;
        pcb.vruntime = new_floor +% lag;

        const target_q = switch (pcb.priority) {
            .interactive => &new_rq.interactive,
            .normal => &new_rq.normal,
            .background => &new_rq.background,
        };
        target_q.pushBack(pid);
        new_rq.nr_runnable +%= 1;
    }

    // Migration accounting (exposed via /proc/sched). Bump under both
    // rq locks so /proc/sched readers see a coherent in/out pair.
    smp.cpus[old_cpu].migrations_out +%= 1;
    smp.cpus[new_cpu].migrations_in +%= 1;

    pcb.assigned_cpu = new_cpu;
    return true;
}

/// Phase 7: pin/unpin a pid to a specific CPU.
///   cpu_id == 0xFF → unpin (load balancer regains discretion)
///   cpu_id < MAX_CPUS → pin to that cpu, migrate if needed
///
/// Behavior by current state of pid:
///   .ready: migrate() moves it to target cpu's rq immediately.
///   .running on different cpu: update assigned_cpu, IPI old cpu — its
///     next schedule's prev demote will rqEnter on the new assigned_cpu.
///   .sleeping / .loading: just update fields — when pid next becomes
///     .ready, rqEnter sees the new assigned_cpu and lands on it.
///
/// Returns false on invalid args (bad pid, bad cpu, idle PCB). Caller
/// (sysSetAffinity) is responsible for permission checks.
pub fn setAffinity(pid: u8, cpu_id: u8) bool {
    if (pid >= MAX_PROCS) return false;
    if (cpu_id != 0xFF) {
        if (cpu_id >= smp.MAX_CPUS) return false;
        if (!smp.cpus[cpu_id].alive) return false;
    }
    const pcb = &procs[pid];
    if (pcb.is_idle) return false; // idles can't be re-pinned

    pcb.pinned_cpu = cpu_id;
    if (cpu_id == 0xFF) {
        // Unpinning — leave assigned_cpu as is. Load balancer will
        // rebalance opportunistically if there's a load delta.
        return true;
    }
    pcb.assigned_cpu = cpu_id;

    const state_byte = @atomicLoad(u8, @as(*const u8, @ptrCast(&pcb.state)), .acquire);
    if (state_byte == @intFromEnum(State.ready)) {
        _ = migrate(pid, cpu_id);
    } else if (state_byte == @intFromEnum(State.running)) {
        // pid is dispatched somewhere — find that CPU and IPI it so its
        // schedule runs sooner. The prev demote in schedule will see the
        // updated assigned_cpu via setState→rqEnter.
        for (&smp.cpus) |*c| {
            if (!c.alive) continue;
            if (c.cpu_id == cpu_id) continue;
            if (c.current_pid) |cur| {
                if (cur == pid) {
                    if (kill_kick_vector) |v| {
                        const apic = @import("../time/apic.zig");
                        apic.sendIPI(c.lapic_id, v);
                    }
                    break;
                }
            }
        }
    }
    return true;
}

/// Phase 7 companion: read a pid's current affinity.
///   Returns pid's `pinned_cpu`: 0..MAX_CPUS-1 = pinned to that CPU,
///   0xFF = unpinned (load balancer has discretion).
/// Returns 0xFF for invalid pid (treat as unpinned).
pub fn getAffinity(pid: u8) u8 {
    if (pid >= MAX_PROCS) return 0xFF;
    return procs[pid].pinned_cpu;
}

/// Phase 4 BSP-driven periodic load balancer. Picks the busiest and
/// idlest cpus by effective load, migrates one task from busiest to
/// idlest if delta >= BALANCE_THRESHOLD. Single migration per call —
/// gradual convergence avoids migration storms.
///
/// Migration source preference: lowest priority queue (least
/// disruption to interactive/normal tasks); within a queue, TAIL
/// (least recently dispatched, less hot in cache).
///
/// Called from handleIRQ0 BSP block every BALANCE_INTERVAL_TICKS.
pub fn loadBalance() void {
    if (!smp.isBSP()) return;

    var busiest_cpu: u8 = 0xFF;
    var busiest_load: u16 = 0;
    var idlest_cpu: u8 = 0xFF;
    var idlest_load: u16 = std.math.maxInt(u16);

    var i: u8 = 0;
    while (i < smp.MAX_CPUS) : (i += 1) {
        if (!smp.cpus[i].alive) continue;
        const load = effectiveLoad(i);
        if (load > busiest_load) {
            busiest_load = load;
            busiest_cpu = i;
        }
        if (load < idlest_load) {
            idlest_load = load;
            idlest_cpu = i;
        }
    }
    if (busiest_cpu == 0xFF or idlest_cpu == 0xFF) return;
    if (busiest_cpu == idlest_cpu) return;
    if (busiest_load < idlest_load + BALANCE_THRESHOLD) return;

    // Pick a migration candidate: lowest-priority queue, tail-end.
    const busy_rq = &smp.cpus[busiest_cpu].runqueue;
    var pick: ?u8 = null;
    {
        const f = busy_rq.lock.acquireIrqSave();
        defer busy_rq.lock.releaseIrqRestore(f);
        const queues = [_]*const runqueue.PriQueue{
            &busy_rq.background, &busy_rq.normal, &busy_rq.interactive,
        };
        outer: for (queues) |q| {
            if (q.count == 0) continue;
            var idx: i32 = @as(i32, @intCast(q.count)) - 1;
            while (idx >= 0) : (idx -= 1) {
                const candidate = q.pids[@intCast(idx)];
                if (candidate >= MAX_PROCS) continue;
                const pcb = &procs[candidate];
                if (pcb.is_idle) continue;
                if (pcb.pinned_cpu != 0xFF) continue;
                pick = candidate;
                break :outer;
            }
        }
    }

    if (pick) |p| {
        _ = migrate(p, idlest_cpu);
    }
}

/// Map a `Priority` enum value to the matching PriQueue inside an Rq.
/// Tiny wrapper so runqueue.zig stays free of process.Priority.
inline fn rqQueueFor(rq: *runqueue.Rq, prio: Priority) *runqueue.PriQueue {
    return switch (prio) {
        .interactive => &rq.interactive,
        .normal => &rq.normal,
        .background => &rq.background,
    };
}

/// Add a pid to its assigned CPU's runqueue. Caller must have already
/// transitioned the pid into a runnable state. Idle PCBs are never
/// enqueued — they're picked via the dedicated `cpu.idle_pid` slot,
/// not via the rq scan. Same for unassigned (assigned_cpu == 0xFF)
/// PCBs that haven't been through `assignInitialCpu` yet.
///
/// Idempotent across ALL queues — same reasoning as rqLeave's full
/// scan: an out-of-band priority bump after enqueue could leave the
/// pid in the OLD priority queue, and a subsequent rqEnter that only
/// checked the current priority would double-enqueue (incrementing
/// nr_runnable without being able to find the pid for removal later).
///
/// CFS sleeper bonus: callers passing `from_sleep=true` (setState's
/// .sleeping → .ready transition) get vruntime bumped to
/// `max(vruntime, min_vruntime[band] - SLEEPER_CREDIT)`. Newly-created
/// tasks (first rqEnter, vruntime == 0) are seeded to min_vruntime[band]
/// + 1 so they don't immediately monopolize their band.
fn rqEnter(pid: usize, from_sleep: bool) void {
    const pcb = &procs[pid];
    // Targeted scheduler-invariant trace: dump on every rq mutation for
    // TRACE_PID (Q1's expected pid). Find which transition leaves pid
    // stuck "state=sleeping + in_rq=true" by reading the linear sequence
    // of setState/rqEnter/rqLeave events that crossed the bad state.
    // Remove after the wedge is rooted out.
    if (TRACE_PID != 0 and pid == TRACE_PID) {
        const ra = @returnAddress();
        debug.klog("[trace pid={d} cpu={d}] rqEnter from_sleep={any} state_before={d} assigned_cpu={d} ra=0x{X}\n", .{
            pid, smp.myCpu().cpu_id, from_sleep, @intFromEnum(pcb.state), pcb.assigned_cpu, ra,
        });
    }
    if (pcb.is_idle) return;
    if (pcb.assigned_cpu == 0xFF) return;
    if (pcb.assigned_cpu >= smp.MAX_CPUS) return;
    const rq = &smp.cpus[pcb.assigned_cpu].runqueue;
    const f = rq.lock.acquireIrqSave();
    defer rq.lock.releaseIrqRestore(f);
    const pid_u8: u8 = @intCast(pid);
    if (rq.interactive.contains(pid_u8)) {
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqEnter SKIP — already in interactive\n", .{ pid, smp.myCpu().cpu_id });
        return; // already enqueued — idempotent
    }
    if (rq.normal.contains(pid_u8)) {
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqEnter SKIP — already in normal\n", .{ pid, smp.myCpu().cpu_id });
        return;
    }
    if (rq.background.contains(pid_u8)) {
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqEnter SKIP — already in background\n", .{ pid, smp.myCpu().cpu_id });
        return;
    }

    // CFS placement under the rq's own lock so a concurrent picker on the
    // same rq can't race against the vruntime adjustment.
    const band: usize = @intFromEnum(pcb.priority);
    const floor = rq.min_vruntime[band];
    if (pcb.vruntime == 0) {
        // Fresh PCB — seed at min + 1 so it doesn't outrank everyone in
        // its band immediately. The +1 keeps strict ordering with any
        // task currently sitting AT min.
        pcb.vruntime = floor +% 1;
    } else if (from_sleep) {
        // Sleeper bonus: bump near floor so the woken task gets to run
        // soon, but cap at its own historical vruntime so a long-running
        // task that briefly slept doesn't get a free reset. Saturating
        // subtract: if floor < SLEEPER_CREDIT (e.g., a band that hasn't
        // been touched yet — interactive on cpu1 before any task ran
        // there), credited stays at 0. Wrapping `-%` would underflow to
        // ~u64-max and immediately set vruntime to that, starving the
        // task forever (picker always sees it as worst-vruntime). This
        // bug surfaced as "editor stops accepting input after a few
        // chars" once the editor migrated to cpu1 and tried to wake
        // there.
        const credited: u64 = if (floor > SLEEPER_CREDIT) floor - SLEEPER_CREDIT else 0;
        if (pcb.vruntime < credited) pcb.vruntime = credited;
    }
    // Demote-to-ready (state .running → .ready in schedule()) leaves
    // vruntime as-is; the task already accumulated its slice via
    // checkPreempt/schedule's slice-end accounting.

    rqQueueFor(rq, pcb.priority).pushBack(pid_u8);
    rq.nr_runnable +%= 1;
    @import("../debug/pid_act.zig").record(
        pid, .rq_enter, @intFromEnum(pcb.priority), 0xFF, @returnAddress(),
    );
    if (TRACE_PID != 0 and pid == TRACE_PID) {
        debug.klog("[trace pid={d} cpu={d}] rqEnter DONE — pushed to band={d} nr_runnable={d}\n", .{
            pid, smp.myCpu().cpu_id, @intFromEnum(pcb.priority), rq.nr_runnable,
        });
    }
}

/// Remove a pid from its assigned CPU's runqueue. Idempotent — if the
/// pid isn't there (already dispatched, or never was), this is a no-op.
///
/// Scans ALL THREE priority queues, not just the one matching the PCB's
/// current priority. Reason: several callsites mutate `pcb.priority`
/// directly after the PCB has been enqueued (smp.pollAppLoad bumps
/// background→interactive; sysExec / desktop.foreground likewise). If
/// rqLeave only consulted the current priority, it would miss the pid
/// in the OLD priority's queue and leave a phantom entry — the audit
/// drift class first reproduced as `pid=3 state=4 assigned_cpu=1
/// in_rq=true` (process slept after a priority bump). Three queues of
/// MAX_PROCS=32 entries each is trivial to scan.
fn rqLeave(pid: usize) void {
    const pcb = &procs[pid];
    if (TRACE_PID != 0 and pid == TRACE_PID) {
        const ra2 = @returnAddress();
        debug.klog("[trace pid={d} cpu={d}] rqLeave ENTRY state={d} assigned_cpu={d} ra=0x{X}\n", .{
            pid, smp.myCpu().cpu_id, @intFromEnum(pcb.state), pcb.assigned_cpu, ra2,
        });
    }
    if (pcb.is_idle) return;
    if (pcb.assigned_cpu == 0xFF) return;
    if (pcb.assigned_cpu >= smp.MAX_CPUS) return;
    const rq = &smp.cpus[pcb.assigned_cpu].runqueue;
    const f = rq.lock.acquireIrqSave();
    defer rq.lock.releaseIrqRestore(f);
    const pid_u8: u8 = @intCast(pid);
    const ra = @returnAddress();
    const pid_act = @import("../debug/pid_act.zig");
    if (rq.interactive.remove(pid_u8)) {
        rq.nr_runnable -%= 1;
        pid_act.record(pid, .rq_leave, @intFromEnum(Priority.interactive), 0xFF, ra);
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqLeave REMOVED from interactive nr_runnable={d}\n", .{ pid, smp.myCpu().cpu_id, rq.nr_runnable });
        return;
    }
    if (rq.normal.remove(pid_u8)) {
        rq.nr_runnable -%= 1;
        pid_act.record(pid, .rq_leave, @intFromEnum(Priority.normal), 0xFF, ra);
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqLeave REMOVED from normal nr_runnable={d}\n", .{ pid, smp.myCpu().cpu_id, rq.nr_runnable });
        return;
    }
    if (rq.background.remove(pid_u8)) {
        rq.nr_runnable -%= 1;
        pid_act.record(pid, .rq_leave, @intFromEnum(Priority.background), 0xFF, ra);
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqLeave REMOVED from background nr_runnable={d}\n", .{ pid, smp.myCpu().cpu_id, rq.nr_runnable });
        return;
    }
    if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqLeave NO-OP — not in any queue\n", .{ pid, smp.myCpu().cpu_id });
}

/// Centralized state setter. ALL non-CAS state writes go through here so
/// rq membership stays in sync with the state byte. Skip-and-return when
/// new == old (no-op). Order matters: leave the rq BEFORE the state-byte
/// store on a runnable→non-runnable transition (so a concurrent picker
/// that sees us still .ready can also still find us in the rq); enter
/// the rq AFTER the state-byte store on the reverse (so an audit between
/// the two never sees "in rq but not .ready").
///
/// Phase 6: after rqEnter, fire a preempt IPI to the assigned CPU when
/// appropriate (target is idle or running a lower-priority task). Keeps
/// IPC wake latency at ~μs instead of waiting up to a 10 ms timer tick.
/// Per-pid bracket counter for the rq audit. Incremented at the top of
/// setState (BEFORE the state CAS); decremented at the bottom (AFTER the
/// rq op). Audit skips pids whose counter is non-zero, structurally
/// eliminating the "CAS landed but rqEnter hasn't" transient FP. Counter
/// (not bool) because the same pid can hit setState concurrently from
/// multiple CPUs — the CAS loop reconciles state, but each caller's
/// bracket must independently increment/decrement.
pub var setstate_in_flight: [MAX_PROCS]u8 = [_]u8{0} ** MAX_PROCS;

/// Per-pid setState serializing lock. Held across the CAS + rq op so a
/// concurrent setState on the SAME pid (e.g., cpu1's nvme IRQ wake doing
/// .sleeping→.ready while cpu0's preempt does .running→.ready) cannot
/// interleave the state byte write with the rq insert/remove. Without
/// this, a wake's `CAS .sleeping→.ready then rqEnter` could overlap with
/// a picker's `CAS .ready→.running then rqLeave`: picker's rqLeave finds
/// pid not yet in rq (no-op), wake's rqEnter then inserts pid AFTER
/// picker already dispatched it — pid ends up .running AND in rq. On the
/// next .running→.sleeping transition, was_ready=false skips rqLeave and
/// pid stays in rq as .sleeping forever; picker keeps fishing it out,
/// transitioning .sleeping→.running via CAS, dispatching, blockOn-yields
/// immediately — tight schedule-park loop, system wedges.
/// Caught 2026-05-19: audit reported `pid=2 state=3 in_rq=true want=false`
/// right before all four pids stalled on (.nvme_io, target=0x10000).
var setstate_locks: [MAX_PROCS]SpinLock = [_]SpinLock{.{}} ** MAX_PROCS;

pub fn setState(pid: usize, new_state: State) void {
    if (pid >= MAX_PROCS) return;
    const lock_flags = setstate_locks[pid].acquireIrqSave();
    defer setstate_locks[pid].releaseIrqRestore(lock_flags);
    _ = @atomicRmw(u8, &setstate_in_flight[pid], .Add, 1, .acquire);
    defer _ = @atomicRmw(u8, &setstate_in_flight[pid], .Sub, 1, .release);
    const pcb = &procs[pid];
    const state_ptr: *u8 = @as(*u8, @ptrCast(&pcb.state));

    // Atomically claim the state transition via CAS. Without this, two
    // concurrent setState calls (e.g., cpu0's wakeExpired doing
    // .sleeping→.ready while cpu1's killProcess does .running→.zombie)
    // could both pass the load-then-decide check based on the same
    // pre-transition state, then race in the rq op block: rqLeave runs
    // before rqEnter, finds no entry to remove, doesn't decrement, then
    // rqEnter adds and increments → permanent nr_runnable / queue
    // drift, and the pid gets stuck in .ready but invisible to the
    // picker (or vice versa).
    //
    // The CAS loop ensures exactly one setState call wins each transition
    // for a given old→new pair. Concurrent calls either find their
    // expected-old already changed and return (no-op) or retry. After
    // the CAS succeeds, only THIS caller does the rq ops for THIS
    // specific old→new transition.
    var old_byte: u8 = @atomicLoad(u8, state_ptr, .acquire);
    const new_byte: u8 = @intFromEnum(new_state);
    while (true) {
        if (old_byte == new_byte) {
            if (TRACE_PID != 0 and pid == TRACE_PID) {
                debug.klog("[trace pid={d} cpu={d}] setState NOOP old=={d} new=={d} ra=0x{X}\n", .{
                    pid, smp.myCpu().cpu_id, old_byte, new_byte, @returnAddress(),
                });
            }
            return; // already in this state
        }
        const cas = @cmpxchgStrong(u8, state_ptr, old_byte, new_byte, .acq_rel, .acquire);
        if (cas == null) break; // we own this transition
        old_byte = cas.?;        // someone else changed state — retry with their value
    }
    const old_state: State = @enumFromInt(old_byte);
    if (TRACE_PID != 0 and pid == TRACE_PID) {
        debug.klog("[trace pid={d} cpu={d}] setState CAS-OK {d}->{d} ra=0x{X}\n", .{
            pid, smp.myCpu().cpu_id, old_byte, new_byte, @returnAddress(),
        });
    }
    // Per-PID activity ring stamp. Logged AFTER the CAS succeeded so the
    // ring entry corresponds to a real transition (no-op early-returns
    // above leave no trace, by design).
    @import("../debug/pid_act.zig").record(
        pid, .setstate, old_byte, new_byte, @returnAddress(),
    );
    const was_ready = (old_state == .ready);
    const is_ready = (new_state == .ready);
    // Only .sleeping→.ready gets the CFS sleeper bonus. Demote
    // .running→.ready (preempt) keeps vruntime as-accumulated;
    // .loading→.ready (fresh task) gets the seed-to-min path inside
    // rqEnter (vruntime == 0 sentinel).
    const from_sleep = (old_state == .sleeping);

    // CFS: leaving .running for ANY reason (.ready preempt, .sleeping
    // block, .zombie exit) is a slice-end. Flush accumulated ticks
    // into vruntime now so the next picker sees a fair value.
    if (old_state == .running and new_state != .running) {
        accountRunningTick(pid, false);
    }

    if (was_ready and !is_ready) rqLeave(pid);
    if (!was_ready and is_ready) {
        rqEnter(pid, from_sleep);
        maybePreemptOnWake(pid);
    }
}

/// CFS: bump current.vruntime by ticks consumed since slice start, and
/// raise the per-band min_vruntime floor so a future sleeper bonus or
/// migration translation reflects this CPU's actual progress. Called
/// from schedule() at every preempt/yield point AND from checkPreempt()
/// once per timer tick.
///
/// `commit_slice_start` resets slice_start_tick to tick_count so the
/// next call accounts only the new sub-slice. Schedule passes false
/// when it's about to setState the task off-CPU (the slice is fully
/// flushed, no need to commit a fresh start); checkPreempt passes true
/// because the task continues running.
fn accountRunningTick(pid: usize, commit_slice_start: bool) void {
    const pcb = &procs[pid];
    if (pcb.is_idle) return;
    const now = tick_count;
    const start = pcb.slice_start_tick;
    if (now <= start) {
        if (commit_slice_start) pcb.slice_start_tick = now;
        return;
    }
    const delta = now - start;
    // TRIAGE: nice scaling temporarily disabled — just bump vruntime by
    // delta to isolate whether the multiply/divide was the problem.
    // const weight = niceToWeight(pcb.nice);
    // const weighted_delta = (delta * NICE_0_WEIGHT) / weight;
    pcb.vruntime +%= delta;
    if (commit_slice_start) pcb.slice_start_tick = now;

    // Bump per-band min_vruntime floor on this rq if the running task
    // pushed past it. (Other tasks on the rq advance their own vruntime
    // when they run; the floor monotonically follows the slowest one.)
    if (pcb.assigned_cpu < smp.MAX_CPUS) {
        const rq = &smp.cpus[pcb.assigned_cpu].runqueue;
        const band: usize = @intFromEnum(pcb.priority);
        // Floor = min over (running's vruntime, smallest queued vruntime).
        // Running pushes the floor up; queued tasks are at-or-above.
        const cur_floor = rq.min_vruntime[band];
        if (pcb.vruntime > cur_floor) {
            // Don't take rq.lock here — the floor is advisory (off-by-one
            // doesn't break correctness, only the precision of sleeper
            // bonuses). Atomic store keeps the read side coherent.
            @atomicStore(u64, &rq.min_vruntime[band], pcb.vruntime, .release);
        }
    }
}

/// CFS per-tick vruntime maintenance — called from handleIRQ0 on every
/// real (non-soft-yield) timer firing. Bumps the running task's vruntime
/// by ticks consumed since slice start and pushes the per-band
/// min_vruntime floor up. The actual preempt decision is *not* made
/// here — handleIRQ0's natural per-tick `from_user` schedule path
/// already preempts at every quantum, and pickNext now picks min-vruntime
/// within each band. So all checkPreempt needs to do is keep vruntime
/// accurate so pickNext's selection is fair.
///
/// (Previous draft set `cpu.pending_soft_yield = true` to force a
/// kernel-mode preempt; that breaks the next tick's `was_soft_yield`
/// inference and was scrapped. Kernel tasks like desktop run to their
/// natural yield points, which is correct behavior.)
pub fn checkPreempt() void {
    const cpu = smp.myCpu();
    const cur = cpu.current_pid orelse return;
    if (cur >= MAX_PROCS) return;
    const pcb = &procs[cur];
    if (pcb.is_idle) return;
    if (pcb.state != .running) return;
    accountRunningTick(cur, true);
}

/// Phase 6: fire a resched IPI to the woken pid's assigned CPU when:
///   - target is a different CPU than caller (same-cpu wakes get handled
///     by the local schedule loop on the next preempt, no IPI needed),
///   - AND target is currently running its idle PCB OR a strictly lower-
///     priority task.
///
/// Reuses kill_kick_vector — the handler is just `schedule()`, which on
/// the receiver checks exit_requested + demotes prev + pickNext, doing
/// exactly what a preempt-on-wake needs. (Naming: the vector handles
/// "any reason to reschedule NOW" — kill, wake, or future events.)
fn maybePreemptOnWake(pid: usize) void {
    const pcb = &procs[pid];
    if (pcb.is_idle) return;
    const target_cpu_id = pcb.assigned_cpu;
    if (target_cpu_id == 0xFF) return;
    if (target_cpu_id >= smp.MAX_CPUS) return;

    const my_cpu = smp.myCpu();
    if (target_cpu_id == my_cpu.cpu_id) return; // same-cpu, local schedule will pick

    const target_cpu = &smp.cpus[target_cpu_id];
    if (!target_cpu.alive) return;

    const should_preempt = blk: {
        const target_cur = target_cpu.current_pid orelse break :blk true;
        if (target_cur >= MAX_PROCS) break :blk false;
        if (procs[target_cur].is_idle) break :blk true;
        break :blk @intFromEnum(pcb.priority) > @intFromEnum(procs[target_cur].priority);
    };
    if (!should_preempt) return;

    if (kill_kick_vector) |v| {
        const apic = @import("../time/apic.zig");
        apic.sendIPI(target_cpu.lapic_id, v);
    }
}

/// Two CAS sites (allocSlot's .unused→.loading and schedule()'s pickNext
/// claim .ready→.running) flip the state byte directly without going
/// through setState — they need atomicity that wraps both the read and
/// the write. Once the CAS succeeds they call this to keep the rq in
/// sync with the .ready→non-ready half of the transition.
fn rqOnLeaveReady(pid: usize) void {
    rqLeave(pid);
}

/// Per-tick audit. Two checks:
///   (1) Per-CPU rq internal consistency: `totalCount == nr_runnable`.
///       Both fields update under the rq.lock so no FP class applies; any
///       mismatch is a real bookkeeping bug.
///   (2) Per-pid cross-check: state==.ready ⟺ pid is in its assigned_cpu's
///       rq. This one is FP-prone — setState's state CAS happens BEFORE
///       rqEnter (deliberate ordering documented at setState — chosen to
///       avoid the *reverse* "in rq but not .ready" class). The per-pid
///       `setstate_in_flight[pid]` bracket counter is set BEFORE the CAS
///       and cleared AFTER the rq op; the cross-check skips bracketed
///       pids, structurally eliminating the FP. (Caught 2026-05-19 once
///       the pcb-invariant FP was suppressed and the rq drift became
///       visible — earlier "retry across N samples" approach reported
///       persistent drift but couldn't distinguish a real bug from a
///       slow-window transient.)
pub fn rqAudit() void {
    var i: usize = 0;
    while (i < smp.MAX_CPUS) : (i += 1) {
        if (!smp.cpus[i].alive) continue;
        const rq_count = smp.cpus[i].runqueue.totalCount();
        const rq_nr = smp.cpus[i].runqueue.nr_runnable;
        if (rq_count != rq_nr) {
            debug.klog("[rq-audit] cpu{d} totalCount={d} != nr_runnable={d}\n", .{ i, rq_count, rq_nr });
            rqAuditFull();
            return;
        }
    }
    rqAuditFull();
}

/// Slow walk that names the drifting pid(s). Skips any pid whose
/// `setstate_in_flight` counter is non-zero — that pid is mid-setState
/// on another CPU and the state-byte ↔ rq-membership cross-check would
/// fire spuriously inside the CAS-to-rqEnter window. The bracket is set
/// at the top of setState and cleared at the bottom; on no-CPU-in-flight
/// the cross-check is structurally consistent.
fn rqAuditFull() void {
    var p: usize = 0;
    while (p < MAX_PROCS) : (p += 1) {
        if (procs[p].is_idle) continue;
        if (@atomicLoad(u8, &setstate_in_flight[p], .acquire) > 0) continue;
        const s = @atomicLoad(u8, @as(*const u8, @ptrCast(&procs[p].state)), .acquire);
        const want_in_rq = (s == @intFromEnum(State.ready));
        const cpu_idx = procs[p].assigned_cpu;
        const in_rq = if (cpu_idx == 0xFF or cpu_idx >= smp.MAX_CPUS) false else
            smp.cpus[cpu_idx].runqueue.contains(@intCast(p));
        if (want_in_rq == in_rq) continue;
        // Re-check bracket after the in_rq load: a setState may have started
        // between our skip-check and the in_rq read. If now in-flight, skip.
        if (@atomicLoad(u8, &setstate_in_flight[p], .acquire) > 0) continue;
        debug.klog(
            "[rq-audit] pid={d} state={d} assigned_cpu={d} in_rq={any} want={any}\n",
            .{ p, s, cpu_idx, in_rq, want_in_rq },
        );
    }
}

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
        const state_ptr: *u8 = @as(*u8, @ptrCast(&procs[i].state));
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
    pcb.acct_start_tick = tick_count;
    // Clear save_trace's "has been preempted" flag so a re-used PID slot
    // starts as "not yet saved" — the new task won't have a valid
    // *(kesp+48) until switchTo runs at least once.
    const pid = (@intFromPtr(pcb) - @intFromPtr(&procs[0])) / @sizeOf(PCB);
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
    resetPcbExceptState(&procs[i]); // state stays .loading from allocSlot's CAS

    // Stack region is the upper 16KB of slot i; bottom 4KB is the
    // unmapped guard page installed at boot by initKstackGuards.
    const slot_base = @intFromPtr(&kstack_pool[i]);
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

    procs[i].kernel_esp = stack_top - TOTAL_BYTES;
    procs[i].kernel_stack_top = stack_top;
    @atomicStore(usize, &expected_kstack_tops[i], stack_top, .release);
    // state already .loading from allocSlot's CAS — no further write needed.
    procs[i].tgid = @intCast(i);
    // Default session/group = self. sysExec overrides these from the
    // parent before scheduling so spawned children land in the parent's
    // session+group (POSIX-equivalent of fork+exec preserving sid/pgid).
    procs[i].pgid = @intCast(i);
    procs[i].sid = @intCast(i);
    @import("../debug/kdbg.zig").procEvent(.create, @intCast(i), 0, 0);
    @import("../debug/kasan.zig").markPcbAlive(slot_base + KSTACK_GUARD_SIZE, KSTACK_SIZE);
    return i;
}

const ProcessInfo = struct { kernel_esp: usize, kernel_stack_top: usize };

pub fn getProcessInfo(pid: usize) ProcessInfo {
    return .{ .kernel_esp = procs[pid].kernel_esp, .kernel_stack_top = procs[pid].kernel_stack_top };
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
        const s = procs[i].state;
        if (s == .unused or s == .loading or s == .zombie) continue;
        if (procs[i].tgid == tgid) n += 1;
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
    const parent = currentPCB() orelse return null;
    const parent_lead = leader(parent);

    const i = allocSlot() orelse return null;
    resetPcbExceptState(&procs[i]); // state stays .loading from allocSlot's CAS

    // Inherit thread-group + address space from the lead thread.
    procs[i].tgid = parent_lead.tgid;
    // Threads share the leader's process group + session — they're not
    // separate processes. setpgid/setsid on a thread mutates the whole
    // group's leader (matches Linux pthread semantics).
    procs[i].pgid = parent_lead.pgid;
    procs[i].sid = parent_lead.sid;
    procs[i].page_directory = parent_lead.page_directory;
    procs[i].page_dir_phys = parent_lead.page_dir_phys;

    // Copy per-thread defaults that need to mirror the parent for
    // sane scheduling. fd_table is COPIED for now (Linux would
    // share via CLONE_FILES; we punt). sigactions copied likewise.
    procs[i].fd_table = parent_lead.fd_table;
    procs[i].sigactions = parent_lead.sigactions;
    procs[i].cwd = parent_lead.cwd;
    procs[i].cwd_len = parent_lead.cwd_len;
    procs[i].name = parent_lead.name;
    procs[i].name_len = parent_lead.name_len;
    procs[i].priority = parent.priority;
    procs[i].parent_pid = @intCast(parent_lead.tgid);
    procs[i].fs_base = fs_base;

    // Kernel stack image: same layout as create() but with caller-
    // chosen RIP/RSP/RDI. See create()'s comment for the full layout.
    const slot_base = @intFromPtr(&kstack_pool[i]);
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

    procs[i].kernel_esp = kstack_top - TOTAL_BYTES;
    procs[i].kernel_stack_top = kstack_top;
    @atomicStore(usize, &expected_kstack_tops[i], kstack_top, .release);
    // Atomic transition .loading → .ready. Callers of cloneCurrent expect
    // the new PCB to be schedulable immediately (no separate "ready" step
    // like sysExec does after page-table setup). assignInitialCpu first
    // so setState's rqEnter lands on the right per-CPU runqueue.
    assignInitialCpu(i);
    setState(i, .ready);
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
    const parent = currentPCB() orelse return null;
    const parent_pid_u8: u8 = @intCast(smp.myCpu().current_pid orelse return null);
    const parent_pml4 = parent.page_directory orelse return null;

    const i = allocSlot() orelse return null;
    resetPcbExceptState(&procs[i]); // state stays .loading from allocSlot's CAS

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
        setState(i, .unused);
        return null;
    };
    procs[i].page_directory = child_pml4;
    procs[i].page_dir_phys = child_pml4_phys;
    procs[i].pcid = pcid_mod.alloc();

    // Per-AS state — fork has its own AS so lazy regions and brk/mmap state
    // are inherited as values (not aliased through tgid like clone does).
    procs[i].lazy_regions = parent.lazy_regions;
    procs[i].lazy_count = parent.lazy_count;
    procs[i].heap_lazy_idx = parent.heap_lazy_idx;
    procs[i].user_brk = parent.user_brk;
    procs[i].mmap_top = parent.mmap_top;
    procs[i].stack_base = parent.stack_base;
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
    procs[i].elf_buf = null;
    procs[i].elf_buf_pages = 0;

    // FD table — copy entries verbatim, then bump pipe-side refcounts so the
    // parent closing its end doesn't drop the last reference while child
    // still holds the inherited fd.
    procs[i].fd_table = parent.fd_table;
    {
        const pipe = @import("pipe.zig");
        for (procs[i].fd_table) |fd| {
            if (!fd.in_use) continue;
            if (fd.fs_type == .pipe) {
                if (fd.flags == 0) pipe.addReader(fd.pipe_id) else pipe.addWriter(fd.pipe_id);
            }
        }
    }

    // Inherit cwd, name, sigactions, argv, priority, fs_base.
    procs[i].cwd = parent.cwd;
    procs[i].cwd_len = parent.cwd_len;
    procs[i].name = parent.name;
    procs[i].name_len = parent.name_len;
    procs[i].sigactions = parent.sigactions;
    procs[i].argv = parent.argv;
    procs[i].arg_lens = parent.arg_lens;
    procs[i].argc = parent.argc;
    procs[i].priority = parent.priority;
    procs[i].fs_base = parent.fs_base;

    procs[i].parent_pid = parent_pid_u8;
    procs[i].tgid = @intCast(i); // lead thread of the new process group
    // POSIX fork() preserves the parent's pgid and sid — only setsid /
    // setpgid mutate them. A daemon's classic double-fork relies on
    // this: the middle child calls setsid AFTER it's been forked off,
    // and the grandchild then naturally inherits the new sid here.
    procs[i].pgid = parent.pgid;
    procs[i].sid = parent.sid;

    // Build child's kstack image — same shape as create()/cloneCurrent(), but
    // values seeded from parent's saved syscall frame so child resumes at the
    // parent's syscall-return point with RAX=0. retToUserStub pops 15 GPRs in
    // order R15..RAX (frame[0..15]) then iretqs through frame[15..20].
    const slot_base = @intFromPtr(&kstack_pool[i]);
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

    procs[i].kernel_esp = kstack_top - TOTAL_BYTES;
    procs[i].kernel_stack_top = kstack_top;
    @atomicStore(usize, &expected_kstack_tops[i], kstack_top, .release);
    assignInitialCpu(i);
    setState(i, .ready);
    @import("../debug/kdbg.zig").procEvent(.create, @intCast(i), parent_pid_u8, 0);
    @import("../debug/kasan.zig").markPcbAlive(slot_base + KSTACK_GUARD_SIZE, KSTACK_SIZE);
    return i;
}

/// Get mutable pointer to PCB for current process (per-CPU). Returns null
/// when no task is dispatched on this CPU (only true pre-`enterFirstTask`).
pub fn currentPCB() ?*PCB {
    if (smp.myCpu().current_pid) |cur| return &procs[cur];
    return null;
}

/// Get mutable pointer to PCB by pid.
pub fn getPCB(pid: usize) *PCB {
    return &procs[pid];
}

/// Read the raw u8 state byte for a pid. Used by stack-alias detector and
/// other off-process diagnostics that don't want to import the State enum.
pub fn getStateRaw(pid: usize) u8 {
    if (pid >= MAX_PROCS) return 0xFF;
    return @atomicLoad(u8, @as(*const u8, @ptrCast(&procs[pid].state)), .acquire);
}

/// Mark process as running and set it as current (for initial launch).
/// Routes through setState so the rq stays in sync (rqLeave fires if pid
/// was previously enqueued at .ready). Defensively calls assignInitialCpu
/// in case the caller (legacy elf_loader.loadAndExecute path) reaches us
/// before any other create-time helper has assigned a CPU.
pub fn setCurrent(pid: usize) void {
    assignInitialCpu(pid);
    // Inbound-dispatch bracket — same window as schedule()'s PICK_CAS
    // path: state becomes .running here, but cpu.current_pid only
    // claims it on the next line. Without the bracket a cross-CPU
    // pcb_invariants scan landing in between would false-fire
    // "state==.running but no owner". setCurrentPid clears the bracket.
    const cpu = smp.myCpu();
    cpu.dispatching_in_pid = @intCast(pid);
    setState(pid, .running);
    @import("../debug/pid_trace.zig").setCurrentPid(cpu, pid);
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
        schedule();
    }
}

/// Create a kernel-mode idle PCB for `cpu_id`. Returns the new PID.
pub fn createKernelIdle(cpu_id: u8) ?usize {
    const i = allocSlot() orelse {
        debug.klog("[proc] Failed to create kernel idle for cpu{d}\n", .{cpu_id});
        return null;
    };
    resetPcbExceptState(&procs[i]); // state stays .loading from allocSlot's CAS
    const slot_base = @intFromPtr(&kstack_pool[i]);
    const stack_top = slot_base + KSTACK_SLOT_SIZE;

    const FRAME_BYTES: usize = 64;
    const sw_base: [*]u64 = @ptrFromInt(stack_top - FRAME_BYTES);
    for (0..6) |k| sw_base[k] = 0;
    sw_base[6] = @intFromPtr(&kernelIdle);
    sw_base[7] = 0;

    procs[i].kernel_esp = stack_top - FRAME_BYTES;
    procs[i].kernel_stack_top = stack_top;
    @atomicStore(usize, &expected_kstack_tops[i], stack_top, .release);
    procs[i].is_idle = true;
    procs[i].idle_cpu = cpu_id;
    procs[i].priority = .background;
    procs[i].page_dir_phys = 0;
    procs[i].last_cpu = cpu_id;
    procs[i].tgid = @intCast(i);
    procs[i].pgid = @intCast(i);
    procs[i].sid = @intCast(i);
    procs[i].cwd[0] = '/';
    procs[i].cwd_len = 1;
    procs[i].name[0] = 'i';
    procs[i].name[1] = 'd';
    procs[i].name[2] = 'l';
    procs[i].name[3] = 'e';
    procs[i].name[4] = '0' + @as(u8, cpu_id);
    procs[i].name_len = 5;

    // Idle PCBs are NEVER enqueued in the rq (pickNext falls back to
    // cpu.idle_pid directly), so the assigned_cpu assignment is purely
    // bookkeeping. setState→.ready won't actually rqEnter (rqEnter
    // skips is_idle). Keep both calls anyway so the state-write path
    // is uniform across all create*() helpers.
    assignInitialCpu(i);
    setState(i, .ready);
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
    resetPcbExceptState(&procs[i]); // state stays .loading from allocSlot's CAS

    const stack_top: usize = blk: {
        if (kstack_bytes <= KSTACK_SIZE) {
            const slot_base = @intFromPtr(&kstack_pool[i]);
            break :blk slot_base + KSTACK_SLOT_SIZE;
        }
        const buf = heap.kmallocAligned(kstack_bytes, 4096) orelse {
            debug.klog("[proc] createKernelTask: heap alloc {d} bytes failed\n", .{kstack_bytes});
            // Release the slot back to .unused. State was .loading from
            // allocSlot's CAS, never reached .ready, so no rq enter happened.
            setState(i, .unused);
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

    procs[i].kernel_esp = stack_top - FRAME_BYTES;
    procs[i].kernel_stack_top = stack_top;
    @atomicStore(usize, &expected_kstack_tops[i], stack_top, .release);
    procs[i].is_idle = false;
    procs[i].pinned_cpu = cpu_id;
    procs[i].priority = prio;
    procs[i].page_dir_phys = 0;
    procs[i].last_cpu = cpu_id;
    procs[i].tgid = @intCast(i);
    // Boot session — desktop kernel-task is the de-facto session leader,
    // so its sid+pgid mirror its own pid. Any child it sysExec's will
    // inherit these (see sysExec's parent→child copy).
    procs[i].pgid = @intCast(i);
    procs[i].sid = @intCast(i);
    procs[i].cwd[0] = '/';
    procs[i].cwd_len = 1;
    const copy_len = @min(name.len, procs[i].name.len);
    for (0..copy_len) |k| procs[i].name[k] = name[k];
    procs[i].name_len = @intCast(copy_len);

    // pinned_cpu was set above so assignInitialCpu copies it into
    // assigned_cpu (kernel tasks always pinned, never round-robined).
    assignInitialCpu(i);
    setState(i, .ready);
    debug.klog("[proc] Kernel task PID={d} '{s}' on cpu{d} (pinned), kstack_top=0x{X:0>16} ({d} KB)\n", .{ i, name[0..copy_len], cpu_id, stack_top, kstack_bytes / 1024 });
    return i;
}

/// Bootstrap the BSP's first dispatch. Creates the BSP idle + desktop
/// kernel task, then switches THIS context (kmain's bootstrap stack) into
/// the desktop task. kmain's stack is abandoned — we never come back. From
/// this point on, every CPU always has a real PCB as current; `schedule()`
/// no longer needs the legacy "scheduler context" path.
pub fn enterFirstTask(desktop_entry: usize) noreturn {
    // Disable IRQs across the BSP cutover. `cpu.current_pid = desktop_pid`
    // below makes the B.3 stack-alias detector expect desktop's kstack,
    // but RSP only swaps over to it inside `switchToCall`. A timer IRQ
    // landing in the gap saw kmain's boot-stack RSP under desktop's
    // expected slot and panicked. switchToCall uses `ret` (not iretq)
    // so EFLAGS isn't restored — desktop.taskEntry must `sti` after the
    // PML4[0] drop. Mirror in enterFirstTaskAp.
    asm volatile ("cli");

    // BSP idle (legacy `idle_pid` global also set).
    createIdleProcess();
    // Desktop needs a 64 KB kstack — its init+render path was sized for
    // the 32 KB boot stack and overflows the 16 KB pool slot.
    const desktop_pid = createKernelTask(desktop_entry, "desktop", 0, .interactive, 64 * 1024) orelse {
        @panic("enterFirstTask: failed to create desktop kernel task");
    };
    const cpu = smp.myCpu();
    // Mark desktop as running on this cpu BEFORE we switch — gdt.setTssRsp0
    // and the schedule machinery expect cpu.current_pid to track reality.
    // setState (.ready→.running) also rqLeave's the desktop pid so it
    // doesn't sit on the rq while it's actively dispatched.
    @import("../debug/pid_trace.zig").setCurrentPid(cpu, desktop_pid);
    setState(desktop_pid, .running);
    procs[desktop_pid].last_cpu = 0;
    gdt.setTssRsp0(desktop_pid, procs[desktop_pid].kernel_stack_top);

    // First dispatch — kmain's stack is abandoned. Pass null prev_save
    // so switchTo asm skips the save entirely (no PCB to write into).
    @import("sched_asm.zig").switchToCall(null, procs[desktop_pid].kernel_esp);
    unreachable;
}

/// AP-side counterpart to enterFirstTask. The caller (smp.apEntry) has
/// already called createKernelIdle and stashed the new pid into
/// cpus[my_id].idle_pid. We dispatch into that idle PCB so the AP runs
/// as a real kernel task from the very first instant — no apEntry-loop
/// "scheduler context" sitting on the trampoline stack. After this call
/// the AP trampoline's stack is abandoned (same fate as kmain's stack
/// after enterFirstTask).
pub fn enterFirstTaskAp(ap_idle_pid: usize) noreturn {
    // Same race as enterFirstTask — see comment there. kernelIdle's
    // `sti; hlt` re-enables IRQs on its first loop iteration, so no
    // explicit sti is needed downstream.
    asm volatile ("cli");

    const cpu = smp.myCpu();
    @import("../debug/pid_trace.zig").setCurrentPid(cpu, ap_idle_pid);
    // Idle PCB — rqLeave is a no-op (idles never enter the rq), but route
    // through setState anyway for path uniformity.
    setState(ap_idle_pid, .running);
    procs[ap_idle_pid].last_cpu = cpu.cpu_id;
    gdt.setTssRsp0(ap_idle_pid, procs[ap_idle_pid].kernel_stack_top);

    // First dispatch — trampoline stack is abandoned. Same null-prev_save
    // rationale as enterFirstTask: no PCB to write into.
    @import("sched_asm.zig").switchToCall(null, procs[ap_idle_pid].kernel_esp);
    unreachable;
}

/// Linear scan of a single priority queue picking the pid with the
/// smallest `vruntime`, skipping any that are doomed (exit_requested),
/// blocked (wait_kind != .none), or match `exclude_pid`. Returns null
/// if the queue has no eligible pid.
///
/// Ties broken by FIFO position (smaller index = earlier-enqueued).
/// O(N) where N <= MAX_PROCS = 32 per queue — fine without an rb-tree.
fn pickMinVruntime(q: *const runqueue.PriQueue, exclude_pid: ?u8) ?u8 {
    var best: ?u8 = null;
    var best_vr: u64 = std.math.maxInt(u64);
    var i: u8 = 0;
    while (i < q.count) : (i += 1) {
        const pid: u8 = q.pids[i];
        if (pid >= MAX_PROCS) continue;
        if (exclude_pid) |xp| if (pid == xp) continue;
        if (@atomicLoad(bool, &procs[pid].exit_requested, .acquire)) continue;
        if (procs[pid].wait_kind != .none) continue;
        const vr = procs[pid].vruntime;
        if (best == null or vr < best_vr) {
            best = pid;
            best_vr = vr;
        }
    }
    return best;
}

/// Pick the next runnable PCB from THIS CPU's per-CPU runqueue, in
/// priority-band order (interactive → normal → background). Within each
/// non-empty band, the pid with the smallest `vruntime` wins (CFS-style
/// fairness within a band) — no longer FIFO.
///
/// Phase 4's `exclude_pid` semantics are preserved: when set, Phase A
/// prefers any other runnable pid across ALL bands; only if no
/// alternative exists does Phase B fall back to a band containing
/// exclude_pid. Schedule passes `cpu.current_pid` here, so a task that
/// just finished its quantum doesn't immediately re-pick itself when
/// there's any other runnable work — even at lower priority.
///
/// Filters:
///   - `exit_requested`: pid is being killed; skip so pickNext can't
///     dispatch a doomed pid between kill signal and target's destroy.
///   - `wait_kind != .none`: defensive belt-and-suspenders. setState
///     removes blocked pids from the rq, so this shouldn't trip; if it
///     does, the audit at 1/64 already caught the drift and we'd rather
///     skip than dispatch into a wait.
///
/// CPU affinity is structural: a pid is in rq[pid.assigned_cpu] only.
/// No two-pass affinity scan; no idle filter (idles aren't enqueued).
pub fn pickNext(exclude_pid: ?u8) ?usize {
    smp.verifyEndCanary();
    @import("../debug/iretq_canary.zig").check(@src());

    const cpu = smp.myCpu();
    const rq = &cpu.runqueue;
    const queues = [_]*const runqueue.PriQueue{
        &rq.interactive,
        &rq.normal,
        &rq.background,
    };

    // Phase A: prefer the lowest-vruntime pid in each band, walking
    // bands highest-priority-first. Excludes exclude_pid in this pass.
    if (exclude_pid) |_| {
        for (queues) |q| {
            if (pickMinVruntime(q, exclude_pid)) |pid| return pid;
        }
    }

    // Phase B: no other candidate — accept exclude_pid (or scan when no
    // exclusion was specified).
    for (queues) |q| {
        if (pickMinVruntime(q, null)) |pid| return pid;
    }

    // Fallback: this CPU's own idle PCB.
    if (cpu.idle_pid) |idle| {
        if (procs[idle].idle_cpu == cpu.cpu_id) return idle;
    }
    return null;
}

// =============================================================================
// Kill-kick IPI: synchronous "evict pid from any CPU" primitive
// =============================================================================
//
// killProcessWithStatus tears down a process's address space, ELF buf, and
// PCB synchronously on the killer's CPU. If the victim pid is currently
// running on ANOTHER CPU (.running on cpu1 while cpu0 issues the kill), two
// races fire:
//
//   1. cpu1's next schedule() does `movq %rsp, &procs[pid].kernel_esp` (the
//      switchTo save) AFTER cpu0 zeroed expected_kstack_tops[pid]. The kesp
//      watch's whitelist requires expected != 0 → panic on a benign-looking
//      switchTo. Reproduced via test/stress_kill_race.zig (boot_mode=6).
//
//   2. cpu0's vmm.destroyAddressSpace frees PT pages while cpu1 is still
//      walking them on the dying CR3. Latent — TLB usually masks it but
//      a freed PT page reused for something else corrupts cpu1's view.
//
// Fix: before teardown, IPI any CPU running pid to force a context switch
// off it. The IPI handler just calls schedule() — landing in any IRQ +
// schedule's natural pickNext is enough to swap pid out (it's about to
// flip to .zombie/.unused, so even if pickNext sees it as .ready briefly,
// the wait loop re-IPIs). After the wait, no CPU is on pid's CR3 or
// kstack, and teardown is exclusive.
//
// Pairs with the schedule() defense-in-depth in prev_save selection:
// `expected_kstack_tops[cur] == 0` redirects to dead-letter rather than
// writing to a corpse PCB. That guard catches anything this IPI sync misses.
var kill_kick_vector: ?u8 = null;

/// Per-CPU kill-kick (and any wake-IPI reusing this vector) receive count.
/// Read by debug CLI to compare against virtio_gpu_wake_ipis_sent — if
/// sent grows but receive doesn't grow on cpu1, IPI delivery is broken
/// under the current hypervisor. If both grow but cube still hangs, the
/// broken link is later in the schedule()/iretq path.
pub var kick_handler_runs: [smp.MAX_CPUS]u64 = blk: {
    var x: [smp.MAX_CPUS]u64 = undefined;
    for (&x) |*c| c.* = 0;
    break :blk x;
};
fn killKickHandler() callconv(.c) void {
    const cpu = smp.myCpu();
    if (cpu.cpu_id < smp.MAX_CPUS) kick_handler_runs[cpu.cpu_id] +%= 1;
    // Receiving CPU: force a reschedule. The currently-running task may be
    // the kill target — schedule() will demote it through the normal path
    // and pick anything else (idle if nothing's ready). After this, the
    // victim CPU's `current_pid` no longer points at the dying pid, which
    // is what waitForPidOffCpu's polling loop is waiting for.
    //
    // Shape D: do NOT call schedule() directly here. This handler dispatches
    // through DynIrqStub, whose body now runs on the per-CPU isr_stack — a
    // direct schedule()/switchTo would save an isr_stack RSP into the
    // preempted task's kernel_esp (the IST=1-class corruption). Defer via the
    // per-CPU flag instead; DynIrqStub's epilogue (check_and_preempt_dynirq)
    // runs schedule() on the task kstack, in the same interrupt return, with
    // the correct RSP. Matches the nvme/virtio deferred-preempt discipline.
    cpu.dynirq_preempt_pending = true;
}

/// Allocate + register the dynamic IRQ vector for kill-kick. Must be called
/// AFTER smp.init() (so cpu.alive[] is populated). Falls back to "no IPI"
/// if vectors are exhausted; callers degrade to natural-preemption timing.
pub fn initKillKickIpi() void {
    const idt = @import("../cpu/idt.zig");
    const v = idt.allocDynVector() orelse {
        debug.klog("[kill] no dyn vector free — kill-kick disabled (degrades to natural preempt)\n", .{});
        return;
    };
    idt.registerIrq(v, killKickHandler);
    kill_kick_vector = v;
    debug.klog("[kill] IPI vector 0x{X} registered for kill-kick\n", .{v});
}

/// Expose the kill-kick vector to non-process callers (e.g. drivers
/// wanting to wake other CPUs from `sti; hlt`). Returns null before
/// `initKillKickIpi()` has run.
pub fn kickVector() ?u8 {
    return kill_kick_vector;
}

// =============================================================================
// Wake-only IPI vector — distinct from kill-kick because the latter calls
// schedule() which demotes the receiver's current task. For "wake the CPU
// out of hlt so it re-checks an in-memory flag" (e.g. virtio-gpu completion
// while a syscall waits in sti+hlt) we need the OPPOSITE: do not preempt
// the woken task; let iretq restore its hlt+1 RIP and let the wait loop
// re-poll. A no-op handler does exactly that.
// =============================================================================

var wake_ipi_vector: ?u8 = null;
pub var wake_handler_runs: [smp.MAX_CPUS]u64 = blk: {
    var x: [smp.MAX_CPUS]u64 = undefined;
    for (&x) |*c| c.* = 0;
    break :blk x;
};
fn wakeOnlyHandler() callconv(.c) void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id < smp.MAX_CPUS) wake_handler_runs[cpu_id] +%= 1;
    // Intentionally empty — the IRQ delivery itself is the work. By NOT
    // calling schedule(), we don't demote the receiver's current task.
    // iretq pops the original kernel frame; if the receiver was in hlt,
    // execution resumes at hlt+1 and any wait loop above re-checks its
    // condition.
}

pub fn initWakeIpi() void {
    const idt = @import("../cpu/idt.zig");
    const v = idt.allocDynVector() orelse {
        debug.klog("[wake] no dyn vector free — wake-IPI disabled\n", .{});
        return;
    };
    idt.registerIrq(v, wakeOnlyHandler);
    wake_ipi_vector = v;
    debug.klog("[wake] IPI vector 0x{X} registered for wake-only\n", .{v});
}

pub fn wakeVector() ?u8 {
    return wake_ipi_vector;
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
        if (kill_kick_vector) |v| apic.sendIPI(found_lapic, v);

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

/// Linux-style scheduler. Called as a regular function from anywhere that
/// wants to yield (handleIRQ0 on preemption, sysSleep / sysYield / pipe
/// block, sysExit, desktop.run main loop). Does not take or return an RSP
/// — context switching happens via `switchTo` (kernel→kernel `ret`).
///
/// Behavior: cpu.current_pid is always non-null (BSP runs desktop or its
/// idle, APs run their per-CPU idle). schedule picks the next ready task,
/// falling back to this CPU's idle PCB if no user/kernel task is ready;
/// when next == current, it short-circuits and returns immediately.
///
/// Locking: each CPU holds its own `sched_lock`; the .ready→.running CAS
/// keeps two CPUs from claiming the same PID. We MUST release the lock
/// before calling switchTo (otherwise we'd hold it across the switch and
/// deadlock the next dispatch).
pub fn schedule() void {
    // CpuLocal end-canary check (task #229). Wild writes into cpus[N]
    // would corrupt sched_lock that we're about to read; trip here with
    // the writer's call path on the stack instead of letting the bad
    // state cause a downstream #UD.
    smp.verifyEndCanary();
    // iretq-frame tripwire (task #230). schedule() runs from inside
    // every IRQ-driven preemption and every soft-yield syscall — if the
    // outgoing task's iretq frame got scribbled before we got here, we
    // catch it with schedule on the call stack.
    @import("../debug/iretq_canary.zig").check(@src());

    // Per-CPU schedule counter (exposed via /proc/sched). Done before
    // the audit / exit_requested branches so callers that bail early
    // still count toward "this cpu reached schedule()".
    smp.myCpu().schedule_count +%= 1;

    // Breadcrumb: schedule_enter, ctx = caller's current_pid (whichever
    // task is about to be replaced). Picked here rather than later so we
    // capture even early-bail paths.
    {
        const cur_now: u64 = if (smp.myCpu().current_pid) |p| @intCast(p) else 0xFF;
        @import("../debug/breadcrumb.zig").stamp(.schedule_enter, cur_now);
    }

    // Phase 1 rq audit (drift detector). Run every 64th schedule call so
    // it stays off the hot path — the audit itself is cheap (sum of
    // nr_runnable across CPUs vs count of .ready PCBs) but the kdbg log
    // on mismatch is verbose. Running it BEFORE the schedule body gives
    // us the cleanest snapshot of any drift introduced by an external
    // (cross-CPU) state write between the previous schedule and now.
    sched_audit_counter +%= 1;
    if (sched_audit_counter & 0x3F == 0) rqAudit();

    // Phase 3: cross-CPU kill via exit_requested. If the current task on
    // this CPU has been marked for exit by another CPU's killProcess,
    // tear ourselves down ON OUR OWN KSTACK rather than letting the killer
    // race against an in-flight switchTo asm save. destroyCurrentWithStatus
    // calls schedule() recursively at the end, so this check MUST run
    // BEFORE acquiring sched_lock — otherwise the recursive schedule's
    // acquireIrqSave deadlocks on the (non-recursive) ticket lock.
    //
    // Note: cur could be the idle PCB or a kernel task. Idles never receive
    // exit_requested (no one kills them); kernel tasks shouldn't either.
    // Defensive: only honor for non-idle PCBs.
    {
        const cpu_now = smp.myCpu();
        if (cpu_now.current_pid) |cur_pid| {
            if (!procs[cur_pid].is_idle and
                @atomicLoad(bool, &procs[cur_pid].exit_requested, .acquire))
            {
                destroyCurrentWithStatus(procs[cur_pid].exit_status);
                unreachable;
            }
        }
    }

    const t = @import("../debug/perf.zig").enter();
    defer @import("../debug/perf.zig").leave(.schedule, t);
    const cpu = smp.myCpu();
    const paging = @import("../mm/paging.zig");

    // Acquire scheduler lock + disable interrupts for the bookkeeping
    // section. We MUST release before calling switchTo (the lock can't be
    // held across the kernel-to-kernel switch).
    const flags = cpu.sched_lock.acquireIrqSave();

    // Compute prev_save: the slot switchTo will write the prev RSP into,
    // or null to skip the save entirely. null when prev is .zombie/.unused
    // (PCB about to be reused by process.create — saving would scribble the
    // new init value) or when there's no current task at all (first dispatch
    // path / mid-destroy where current_pid was just cleared).
    //
    // Phase 5 collapsed the prior NONE_PID + dead_letter + save_in_flight_prev
    // tower into this single null. switchTo asm `testq rdi, rdi; jz skip`
    // handles the no-save case directly.
    const prev_save: ?*u64 = blk: {
        if (cpu.current_pid) |cur| {
            const cur_state_byte = @atomicLoad(u8, @as(*const u8, @ptrCast(&procs[cur].state)), .acquire);
            if (cur_state_byte == @intFromEnum(State.zombie) or
                cur_state_byte == @intFromEnum(State.unused))
            {
                break :blk null; // doomed — skip save
            }
            break :blk &procs[cur].kernel_esp;
        }
        break :blk null;
    };

    // Demote prev .running → .ready directly. Per-CPU rq dispatch (Phase 2)
    // means no other CPU can pick prev — only this cpu reads its own rq.
    // setState routes through rqEnter so prev appears in this cpu's rq
    // and gets dispatched fairly with anything else here. Sleeping /
    // zombie states are left alone — only .running needs the demote.
    //
    // CFS: setState's .running→non-running path flushes vruntime via
    // accountRunningTick — schedule doesn't need to do it directly.
    //
    // Transient-window bracket: between setState(.ready) and switchTo's
    // save below, prev.state==.ready but prev.kernel_esp is still STALE
    // (from the previous save) and prev is busily writing to its kstack
    // (often AAAA from Zig undefined-init). pcb_invariants and
    // kstack_protect.tickMonitor read this field on every cpu and skip
    // the saved-RIP check for any pid that matches — without it they
    // false-fire on the transient stack residue (caught 2026-05-19).
    // Cleared inside save_trace_record once switchTo's `movq %rsp,(%rdi)`
    // lands.
    var demoted_running_to_ready = false;
    if (cpu.current_pid) |cur| {
        if (procs[cur].state == .running) {
            cpu.scheduling_out_pid = @intCast(cur);
            setState(cur, .ready);
            demoted_running_to_ready = true;
            @import("../debug/kdbg.zig").schedEvent(.preempt, @intCast(cur), @intFromEnum(State.running), @intFromEnum(State.ready), 0);
        }
    }

    // Pick a candidate and try to claim it via atomic CAS. Loop because two
    // CPUs could pick the same candidate; the loser retries with a fresh pick.
    // EXCEPTION: own-cpu idle (is_idle=true && idle_cpu==my_cpu) skips the
    // CAS — only this cpu ever dispatches its own idle, so no race possible
    // and the idle's state may be anything (.ready, .running). pickNext's
    // own gate-check (skip pids matching any cpu.save_in_flight_prev) keeps
    // prev out of the candidate set during the in-flight save.
    // Pass cur as exclude_pid so pickNext's Phase A prefers any other
    // runnable candidate first — relaxes strict priority just enough that
    // a cpu running an interactive task (e.g. desktop on cpu0) gives
    // its .normal-priority queueing a turn instead of immediately re-
    // dispatching itself. Falls back to cur if no alternative exists.
    const exclude: ?u8 = if (cpu.current_pid) |c| @intCast(c) else null;
    const next_opt: ?usize = blk: while (true) {
        const cand = pickNext(exclude) orelse break :blk null;
        const ready_val = @intFromEnum(State.ready);
        const running_val = @intFromEnum(State.running);
        const state_ptr: *u8 = @ptrCast(&procs[cand].state);
        if (procs[cand].is_idle and procs[cand].idle_cpu == cpu.cpu_id) {
            // Idle never enters the rq, so rqOnLeaveReady is a no-op,
            // but route through setState for path uniformity (and so a
            // future Phase 2 idle-in-rq variant just works).
            // Same dispatching_in_pid bracket as the CAS-success branch
            // below — even for idle, setState(.running) precedes the
            // setCurrentPid in the caller, so the running-but-no-owner
            // window exists.
            cpu.dispatching_in_pid = @intCast(cand);
            setState(cand, .running);
            @import("../debug/kdbg.zig").schedEvent(.dispatch, @intCast(cand), ready_val, running_val, 0);
            break :blk cand;
        }
        // Per-pid setState lock: serialize this direct CAS+rqLeave with
        // any concurrent setState on cand (e.g., a cross-CPU wake doing
        // .sleeping→.ready+rqEnter). Without it, picker's rqLeave can
        // run BEFORE wake's rqEnter (no entry to remove → no-op),
        // wake's rqEnter then inserts cand AFTER we already dispatched
        // it — cand ends up .running AND in rq, and any subsequent
        // .running→.sleeping skips rqLeave (was_ready=false), pinning
        // cand in rq as .sleeping forever. Caught 2026-05-19 by audit.
        const ss_flags = setstate_locks[cand].acquireIrqSave();
        // dispatching_in_pid bracket: declare intent to flip cand to
        // .running BEFORE the CAS, so any cross-CPU pcb_invariants scan
        // that observes state==.running sees a non-empty bracket and
        // skips. Setting AFTER the CAS leaves a window where state is
        // already .running but the bracket is still 0xFFFF — caught
        // 2026-05-20 by Q1 stress + a debug klog that widened the
        // window enough for cpu1's per-tick scan to land inside it,
        // panicking with "state==.running but no cpu.current_pid points
        // here." x86 TSO orders the prior store before the subsequent
        // locked CAS, so the reader will see the bracket if it sees
        // the post-CAS state.
        cpu.dispatching_in_pid = @intCast(cand);
        const prev = @cmpxchgStrong(u8, state_ptr, ready_val, running_val, .seq_cst, .seq_cst);
        if (TRACE_PID != 0 and cand == TRACE_PID) {
            debug.klog("[trace pid={d} cpu={d}] pickNext CAS .ready->.running result={any}\n", .{
                cand, cpu.cpu_id, prev,
            });
        }
        if (prev == null) {
            // CAS atomically claimed cand — sync the rq view (cand was
            // .ready, now .running, so it must leave its assigned_cpu's
            // rq). Holding setstate_locks[cand] across CAS + rqLeave
            // closes the dispatch / wake race documented above.
            // Per-PID activity ring: this is the OTHER state-byte writer
            // (not via setState). Without this stamp, the autopsy ring
            // would show ready→running mysteriously without a SETSTATE.
            @import("../debug/pid_act.zig").record(
                cand, .pick_cas, 0xFF, 0xFF, @returnAddress(),
            );
            rqOnLeaveReady(cand);
            // CFS: stamp slice_start so the next checkPreempt / schedule
            // measures only this run-slice. Sets even for idle path
            // above (skipped) — but accountRunningTick guards on is_idle.
            procs[cand].slice_start_tick = tick_count;
            @import("../debug/kdbg.zig").schedEvent(.dispatch, @intCast(cand), ready_val, running_val, 0);
            setstate_locks[cand].releaseIrqRestore(ss_flags);
            break :blk cand;
        }
        // CAS failed — another CPU claimed cand first. Clear the bracket
        // so a subsequent pcb_invariants scan doesn't ghost-skip cand on
        // an unrelated future running state.
        cpu.dispatching_in_pid = 0xFFFF;
        setstate_locks[cand].releaseIrqRestore(ss_flags);
        // CAS failed — another CPU got it first. Try again.
    };

    if (next_opt) |next| {
        // Self-switch guard (task #235). When pickNext falls back to own
        // idle and idle is already current, `next == current_pid`. Skip
        // the actual switchTo (no point), but undo the demote.
        if (cpu.current_pid) |cur| {
            if (cur == next) {
                if (demoted_running_to_ready) {
                    // setState(.running) reverses the demote AND rqLeave's
                    // cur (it was rqEnter'd by the demote's setState).
                    setState(cur, .running);
                }
                // Clear the transient bracket — no switchTo will run so
                // save_trace_record won't fire, leaving the field stale
                // would suppress real pcb-invariant hits on cur until the
                // NEXT schedule call.
                cpu.scheduling_out_pid = 0xFFFF;
                cpu.sched_lock.releaseIrqRestore(flags);
                return;
            }
        }

        // -------- Switch to a user task --------
        // Belt-and-suspenders: if the incoming task is in PROTECTED_PIDS
        // and a destroy-window happened to mark its kstack RO, unprotect
        // it before switchTo writes any saved-state into the kstack.
        // Idempotent (no shootdown issued if no PTE actually changed).
        @import("../debug/kstack_protect.zig").unprotectPidIfProtected(next);
        // KCSAN-lite: just before we use procs[next].kernel_esp, watch
        // it for ~µs. If another CPU writes during this window, the race
        // is in switchTo's rsp-save vs another CPU's dispatch path.
        @import("../debug/kcsan.zig").checkU64("next.kernel_esp@dispatch", &procs[next].kernel_esp);
        // Hardware watchpoint on this task's iretq CS slot — DISABLED.
        // The "value must be 0x08 or 0x23" filter assumed only IRQ
        // machinery writes that slot, but syscall_entry's GPR pushes
        // legitimately reuse the same memory (RBX lands where CS would
        // be) and frequently write 0 there. We were drowning in false
        // positives that masked any real corruption. KCSAN's resample
        // protocol (src/debug/kcsan.zig) is the replacement.
        // const watch = @import("../debug/watch.zig");
        // const cs_slot_addr = procs[next].kernel_stack_top -% 32;
        // watch.armCsSlot(1, cs_slot_addr, "iretq_CS");
        procs[next].last_cpu = cpu.cpu_id;
        gdt.setTssRsp0(next, procs[next].kernel_stack_top);
        if (procs[next].page_dir_phys != 0) {
            pcid_mod.loadCr3(procs[next].page_dir_phys, procs[next].pcid, cpu.cpu_id);
        } else {
            pcid_mod.loadCr3(paging.getKernelPageDirPhys(), 0, cpu.cpu_id);
        }
        writeFsBase(procs[next].fs_base);

        // First-occurrence-per-(CPU,PID) trace — confirms which CPU
        // eventually dispatches each PID. Helps catch "PID never
        // scheduled" bugs.
        {
            const trace_dbg = struct {
                var seen: [@import("../cpu/smp.zig").MAX_CPUS][MAX_PROCS]bool =
                    [_][MAX_PROCS]bool{[_]bool{false} ** MAX_PROCS} ** @import("../cpu/smp.zig").MAX_CPUS;
            };
            if (cpu.cpu_id < @import("../cpu/smp.zig").MAX_CPUS and !trace_dbg.seen[cpu.cpu_id][next]) {
                trace_dbg.seen[cpu.cpu_id][next] = true;
                debug.klog("[sched] cpu{d} -> PID={d}\n", .{ cpu.cpu_id, next });
            }
        }

        // prev_save was determined at the top of schedule() — it's the
        // `?*u64` slot switchTo writes into, or null to skip the save.
        const next_kesp = procs[next].kernel_esp;

        // Pre-dispatch saved-RIP guard. switchTo's `ret` will pop the
        // qword at [next_kesp + 48] (after 6 callee-save pops) as the
        // resume RIP. If it's 0, the dispatch lands at RIP=0 → faults
        // on instruction-fetch with no useful backtrace. Catch it here
        // with full diagnostics instead. Repro: `netstat` from shell
        // (2026-05-17) leads to desktop's saved-RIP slot being 0
        // post-pid-3-teardown.
        //
        // Skip the check if next_kesp + 48 isn't in the task's own
        // kstack range — defensive: a wild next_kesp would itself be
        // caught by the kesp watchdog (DR0-DR3), and reading random
        // memory here could itself fault.
        {
            const kstop = procs[next].kernel_stack_top;
            const rip_slot = next_kesp +% 48;
            if (rip_slot + 8 <= kstop and rip_slot >= kstop -% (4 * @import("../config.zig").KSTACK_SIZE)) {
                const saved_rip = @as(*const u64, @ptrFromInt(rip_slot)).*;
                // Plausibility: saved RIP from switchTo's ret must be in
                // kernel .text — either inside the image proper, OR the
                // retToUserStub address used for first-dispatch of new
                // tasks. Anything else (0, user VA, garbage) means kesp is
                // pointing at corrupt/stale data and we'd crash post-ret.
                const k_lo = memmap.KERNEL_VIRT_BASE;
                const k_hi = memmap.kernelEnd();
                const rip_in_text = saved_rip >= k_lo and saved_rip < k_hi;
                if (!rip_in_text) {
                    const cause: []const u8 = if (saved_rip == 0) "RIP=0" else "RIP outside kernel .text";
                    debug.klog("[sched-rip-guard] about to dispatch pid={d} ({s}) with wild saved RIP=0x{X:0>16} ({s})\n", .{
                        next, procs[next].name[0..procs[next].name_len], saved_rip, cause,
                    });
                    debug.klog("[sched-rip-guard]   kernel_esp     = 0x{X:0>16}\n", .{next_kesp});
                    debug.klog("[sched-rip-guard]   kstack_top     = 0x{X:0>16}\n", .{kstop});
                    debug.klog("[sched-rip-guard]   expected_top   = 0x{X:0>16}\n", .{
                        @atomicLoad(usize, &expected_kstack_tops[next], .acquire),
                    });
                    debug.klog("[sched-rip-guard]   state          = {s}\n", .{@tagName(procs[next].state)});
                    const cur_pid: i32 = if (cpu.current_pid) |c| @intCast(c) else -1;
                    debug.klog("[sched-rip-guard]   from_pid       = {d}\n", .{cur_pid});
                    // Per-pid save mirror diagnostic (wild-RIP=0 hunt 2026-05-17):
                    // compare PCB.kernel_esp to what switchTo last saved, and the
                    // current memory at kesp+48 to what was saved there. Reveals
                    // whether the bug is "kesp value changed" or "kesp+48
                    // memory got overwritten after save".
                    const st = @import("../debug/save_trace.zig");
                    const saved_kesp = st.last_save_kesp[next];
                    const saved_plus48_then = st.last_save_plus48[next];
                    const saved_tsc = st.last_save_tsc[next];
                    const now_tsc: u64 = asm volatile (
                        "rdtsc\n\tshlq $32, %%rdx\n\torq %%rdx, %%rax"
                        : [r] "={rax}" (-> u64),
                        :: .{ .rdx = true });
                    debug.klog("[sched-rip-guard]   ---- save-mirror diagnostic ----\n", .{});
                    debug.klog("[sched-rip-guard]   last_save kesp    = 0x{X:0>16}\n", .{saved_kesp});
                    debug.klog("[sched-rip-guard]   last_save +48     = 0x{X:0>16}\n", .{saved_plus48_then});
                    debug.klog("[sched-rip-guard]   last_save tsc     = 0x{X:0>12}  (now=0x{X:0>12}, delta={d} cycles)\n", .{
                        saved_tsc, now_tsc, now_tsc -% saved_tsc,
                    });
                    if (saved_kesp != next_kesp) {
                        debug.klog("[sched-rip-guard]   *** PCB.kernel_esp DIFFERS from last save (changed by non-switchTo writer) ***\n", .{});
                    } else if (saved_plus48_then != saved_rip) {
                        debug.klog("[sched-rip-guard]   *** kesp+48 OVERWRITTEN since save: was=0x{X:0>16} now=0x{X:0>16} ***\n", .{
                            saved_plus48_then, saved_rip,
                        });
                    } else {
                        debug.klog("[sched-rip-guard]   *** save mirror MATCHES current — bug was present AT save time ***\n", .{});
                    }
                    debug.klog("[sched-rip-guard]   --------------------------------\n", .{});
                    // Dump 16 qwords at kernel_esp to see what the
                    // restore frame actually contains.
                    var i: usize = 0;
                    while (i < 16) : (i += 1) {
                        const a = next_kesp +% (i * 8);
                        if (a + 8 > kstop) break;
                        const v = @as(*const u64, @ptrFromInt(a)).*;
                        debug.klog("[sched-rip-guard]   +0x{X:0>2}: 0x{X:0>16}\n", .{ i * 8, v });
                    }
                    // Scan the full kstack body to tell "task never ran"
                    // (all zero) vs "task ran but kesp now points at unused
                    // zeros" (top region has data, bottom is zero).
                    const ktop_qwords: usize = (kstop - (kstop -% (4 * @import("../config.zig").KSTACK_SIZE))) / 8;
                    var nonzero_count: usize = 0;
                    var first_nonzero_off: usize = 0xFFFFFFFFFFFFFFFF;
                    var last_nonzero_off: usize = 0;
                    var q: usize = 0;
                    const scan_qwords: usize = if (ktop_qwords < 8192) ktop_qwords else 8192;
                    while (q < scan_qwords) : (q += 1) {
                        const a = kstop -% (8 * (q + 1));
                        const v = @as(*const u64, @ptrFromInt(a)).*;
                        if (v != 0) {
                            nonzero_count += 1;
                            const off = kstop - a;
                            if (off < first_nonzero_off) first_nonzero_off = off;
                            if (off > last_nonzero_off) last_nonzero_off = off;
                        }
                    }
                    debug.klog("[sched-rip-guard]   kstack scan: nonzero={d}/{d} qwords  first_nz_off=0x{X}  last_nz_off=0x{X}\n", .{
                        nonzero_count, scan_qwords, first_nonzero_off, last_nonzero_off,
                    });
                    // Dump 8 qwords near the top of kstack — the area a
                    // freshly-created task would have written to (sw_base
                    // entry, iretq frame).
                    debug.klog("[sched-rip-guard]   top-region dump (kstack_top-256 .. kstack_top):\n", .{});
                    var j: usize = 0;
                    while (j < 32) : (j += 1) {
                        const a = kstop -% (8 * (32 - j));
                        const v = @as(*const u64, @ptrFromInt(a)).*;
                        if (v != 0) {
                            debug.klog("[sched-rip-guard]     -0x{X:0>3}: 0x{X:0>16}\n", .{ (32 - j) * 8, v });
                        }
                    }
                    @import("../debug/kdbg.zig").nmi_halt_after_snapshot = true;
                    // Save-trace dump — shows the recent kesp saves that
                    // led to this dispatch. The bad save is typically
                    // a few entries back on `from_pid`'s CPU with a
                    // BAD-RIP verdict. Dump BEFORE @panic so we get it
                    // even if the panic path itself hiccups.
                    @import("../debug/save_trace.zig").dumpAll();
                    // Revert the pickNext .ready→.running CAS so the PCB
                    // invariant scanner (which checks state==.running ⟺
                    // some cpu owns it) doesn't false-positive on the
                    // mid-dispatch state. We're panicking, so leaving it
                    // .ready is harmless — nothing will dispatch.
                    @atomicStore(u8, @as(*u8, @ptrCast(&procs[next].state)),
                        @intFromEnum(State.ready), .release);
                    // Release sched_lock BEFORE panicking. Otherwise the
                    // panic-handler's autopsy walks (load balancer state,
                    // rq dumps) re-acquire and self-deadlock on the same
                    // CPU. Stale state in the running task is fine — we're
                    // panicking, not resuming.
                    cpu.sched_lock.release();
                    @panic("dispatch with wild saved RIP (not in kernel .text)");
                }
            }
        }
        // Phase 3 retired the pre-load `next_kesp ∈ next's kstack range`
        // panic block. It defended cross-stack aliasing — a class that
        // required two CPUs to dispatch the same pid in different schedules
        // and stomp on each other's kernel_esp slot. Per-CPU rq (Phase 2)
        // makes this structurally impossible: only the assigned_cpu touches
        // a pid's kernel_esp, and only inside its own (single-threaded
        // wrt itself) schedule call. KASAN/iretq_canary/stack_alias
        // tripwires still catch wild writes from anywhere else.
        const from_pid_a: u8 = if (cpu.current_pid) |c| @intCast(c) else 0xFE; // 0xFE = dying task
        @import("../debug/pid_trace.zig").setCurrentPid(cpu, next);

        // Race fix (B.3 caught this): release the lock WITHOUT restoring IRQ
        // state. We must keep IRQs masked across switchToCall — otherwise an
        // IRQ landing in the gap between `cpu.current_pid = next` and the
        // actual rsp swap re-enters schedule() with current_pid=next but RSP
        // still on prev's stack, and saves prev's RSP into procs[next].
        // kernel_esp. That's the wild-RIP cross-stack-aliasing root cause.
        // After switchToCall returns (in the resumed context), restore the
        // ORIGINAL caller's IRQ state — `flags` lives on this schedule call's
        // own kernel stack, which is preserved across the switch.
        cpu.sched_lock.release();
        @import("../debug/kdbg.zig").schedEvent(.switch_in, from_pid_a, 0, 0, @intCast(next));
        // Breadcrumb: stamp the actual switch — ctx = next_kesp's low 48b
        // so the autopsy shows which kstack address we're about to load.
        @import("../debug/breadcrumb.zig").stamp(.switch_to, next_kesp);
        // hwbp disarm: pid 2/3's kesp+48 is watched while parked
        // (armed by save_trace_record with skip_value = legit RA).
        // Disarm before dispatch — first callq after switchTo's retq
        // legitimately writes a DIFFERENT RA to that exact slot.
        if (next == 2) @import("../debug/watch.zig").disarm(2);
        if (next == 3) @import("../debug/watch.zig").disarm(3);
        @import("sched_asm.zig").switchToCall(prev_save, next_kesp);
        // When we get here, this caller has been re-scheduled.
        @import("../debug/kdbg.zig").schedEvent(.switch_out, from_pid_a, 0, 0, @intCast(next));
        if ((flags & 0x200) != 0) asm volatile ("sti");
        return;
    }

    // pickNext returned null. Post-boot this is unreachable — every CPU has
    // an idle PCB created before its first dispatch (BSP via enterFirstTask,
    // APs via createKernelIdle in apEntry). The only window is a fault
    // arriving after sched bring-up but before idle creation; in that case,
    // releasing the lock and returning lets the caller (likely a panic path)
    // continue. Roll back the demote; otherwise prev would stay .ready
    // (pickable on next iteration).
    if (demoted_running_to_ready) {
        if (cpu.current_pid) |cur| {
            // setState(.running) reverses both the byte AND the rqEnter
            // that the demote's setState triggered.
            setState(cur, .running);
        }
        // Mirror the self-switch path: clear the transient bracket since
        // no switchTo will run on this branch either.
        cpu.scheduling_out_pid = 0xFFFF;
    }
    cpu.sched_lock.releaseIrqRestore(flags);
}

/// Write IA32_FS_BASE for the current CPU. Called from schedule() on
/// dispatch so each thread keeps its own TLS pointer. Cheap (a single
/// wrmsr); safe to call with value 0 (means "no TLS configured").
inline fn writeFsBase(val: u64) void {
    const IA32_FS_BASE: u32 = 0xC0000100;
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (IA32_FS_BASE),
          [lo] "{eax}" (@as(u32, @truncate(val))),
          [hi] "{edx}" (@as(u32, @truncate(val >> 32))));
}

/// Wake sleeping processes whose `sleep()` deadline has expired. Only
/// considers processes with wait_kind == .none (those blocked via
/// `sysSleep`) — futex/pipe/waitpid sleepers leave wait_kind set and
/// must be woken by their respective explicit wake paths. Without the
/// guard, every `.sleeping` PCB with the default wake_tick=0 would
/// race to .ready on the very next tick, breaking blocking syscalls.
pub fn wakeExpired() void {
    for (0..MAX_PROCS) |i| {
        // .gpu_io waiters set both wait_kind AND wake_tick as a safety
        // net: the primary waker is virtio_gpu's MSI-X IRQ walking the
        // PCB table, but QEMU CVE-2024-3446 occasionally drops the
        // notify. wake_tick guarantees the waiter re-runs and re-polls
        // usedIdx after a bounded delay even if no IRQ arrives. We
        // handle .gpu_io here (not in the .none branch) so the wake
        // clears wait_kind back to .none on the same path as the IRQ
        // wake — keeping a single "waiter resumed" code path.
        if (procs[i].state == .sleeping
            and procs[i].wait_kind == .gpu_io
            and procs[i].wake_tick != 0
            and tick_count >= procs[i].wake_tick)
        {
            procs[i].wake_tick = 0;
            procs[i].wait_kind = .none;
            procs[i].wait_target = 0;
            setState(i, .ready);
            continue;
        }
        if (procs[i].state == .sleeping
            and procs[i].wait_kind == .none
            and procs[i].wake_tick != 0
            and tick_count >= procs[i].wake_tick)
        {
            // ORDER MATTERS: clear wake_tick BEFORE setState. setState
            // routes through rqEnter — once the pid is in the rq, an AP
            // (or this CPU on its next schedule()) can pick it, dispatch
            // it, run it, and call sysSleep AGAIN (fresh wake_tick) all
            // before our `wake_tick = 0` line if it came after setState.
            // That clobbers the fresh wake_tick to 0 → orphan sleep on
            // the NEXT block. Reproduced as "shell freezes after a few
            // keystrokes" — shell wakes from sysSleep, runs briefly,
            // calls pipe.read → blockOn, then wakeExpired's stale
            // wake_tick=0 store hits AFTER the new sleep. Clearing
            // wake_tick first means the worst-case race re-wakes us on
            // the next tick (we'd be sleeping with wake_tick=0 briefly,
            // skipped by wakeExpired guard, but the fresh sysSleep would
            // overwrite it before any harm).
            procs[i].wake_tick = 0;
            setState(i, .ready);
        } else if (procs[i].state == .sleeping
            and tick_count -% wake_dbg_last_log >= 200)
        {
            // DBG: this PCB is sleeping but wakeExpired isn't waking it.
            // Three cases — all suspect:
            //   (a) wait_kind=.none AND wake_tick=0  : orphan sleep — no
            //       waker registered. Likely a wake-races-blockOn race
            //       where wake() ran before blockOn() set wait_kind, so
            //       wake cleared wait_kind=.none then state was set to
            //       .sleeping with no further waker.
            //   (b) wait_kind=.none AND wake_tick>now : sleep still pending
            //       (legitimate). Logged for completeness.
            //   (c) wait_kind!=.none (pipe/futex/waitpid/etc) AND no wake
            //       observed for >200 ticks : the explicit-waker path
            //       (pipe.write→process.wake / futex_wake / etc) didn't
            //       fire OR raced against blockOn the same way as (a).
            if (procs[i].wait_kind == .none) {
                if (procs[i].wake_tick == 0) {
                    debug.klog("[wake-skip] pid={d} state=sleeping wait=none wake_tick=0 (orphan sleep)\n", .{i});
                    wake_dbg_last_log = tick_count;
                } else if (tick_count < procs[i].wake_tick) {
                    debug.klog("[wake-skip] pid={d} state=sleeping wait=none wake_tick={d} now={d} delta_future={d}\n", .{
                        i, procs[i].wake_tick, tick_count, procs[i].wake_tick - tick_count,
                    });
                    wake_dbg_last_log = tick_count;
                }
            } else {
                // wait_kind != .none — explicit waker should fire. Log so
                // we can correlate against pipe/futex/waitpid event flow.
                debug.klog("[wake-skip] pid={d} state=sleeping wait_kind={d} wait_target=0x{x} (explicit waker not firing)\n", .{
                    i, @intFromEnum(procs[i].wait_kind), procs[i].wait_target,
                });
                wake_dbg_last_log = tick_count;
                // Stuck-waiter detector: one-shot full state dump after the
                // pid has been parked on the same resource for ≥STUCK_TICKS.
                // Single permanent park is the bug pattern that `observe()`
                // can't catch — there are no repeated yields to compare.
                @import("../debug/yield_loop.zig").checkStuck(
                    i, procs[i].wait_kind, procs[i].wait_target,
                );
            }
        }
    }
}

var wake_dbg_last_log: u64 = 0;

/// Deliver SIGALRM to any process whose `alarm()` deadline has come due.
/// Called from the BSP timer IRQ alongside wakeExpired. Per-process — each
/// PCB has at most one alarm pending; setting a new alarm cancels the old.
pub fn deliverDueAlarms() void {
    for (0..MAX_PROCS) |i| {
        const at = procs[i].alarm_tick;
        if (at != 0 and tick_count >= at) {
            procs[i].alarm_tick = 0;
            _ = signals.send(@intCast(i), signals.SIGALRM);
        }
    }
}

/// Clear a process's wait flag so the scheduler considers it runnable again.
/// Block the current process for `ms` milliseconds, releasing CPU 0 (or
/// whichever CPU we're running on) to other runnable work. Same mechanism
/// as sysSleep (syscall 12), but callable from kernel context — used by
/// long-running syscall handlers (e.g. net.resolve, net.httpGet) that would
/// otherwise busy-spin and freeze the desktop because the BSP is locked out
/// of running anything else.
///
/// Why this lives here rather than in syscall.zig: it's process-state
/// manipulation (wake_tick + state + the rescheduling dance), and net.zig
/// can't import syscall.zig without a cycle.
pub fn kernelSleepMs(ms: u32) void {
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &procs[cur];
    const ticks = (ms + 9) / 10; // 100 Hz timer, round up
    pcb.wake_tick = tick_count + ticks;
    setState(cur, .sleeping);
    smp.myCpu().pending_soft_yield = true;
    @import("sched_asm.zig").softYield();
}

/// Park the current process on `kind`/`target` until `wake()` flips it back
/// to .ready. Sets state=.sleeping atomically with the wait fields — required
/// because the int $0x20 yield path only reschedules when the current PID is
/// no longer .running (see idt.zig:yielded_from_kernel). On resume, wait_kind
/// and wait_target are auto-cleared.
///
/// Caller responsibilities:
///   - Record any per-resource wait bookkeeping (e.g. pipe.blocked_reader_pid,
///     perf_gap_cyc start) BEFORE calling — once we yield, the waker may race
///     in immediately.
///   - Re-check the underlying condition on resume. Wakes can be spurious
///     (signal delivery, parent destroy, EINTR-style cancel).
///
/// Returns when woken; does NOT loop.
/// Result of `blockOnInterruptible`. `.woke` means the wait completed
/// normally (caller's condition is presumed satisfied, or at least worth
/// re-checking). `.signalled` means a non-blocked signal arrived while we
/// were parked (or was already pending on entry); the caller must unwind
/// and return -EINTR rather than continuing the blocking operation —
/// otherwise the signal would only deliver after the syscall finishes,
/// which can be never for `accept`/`read` shapes.
pub const BlockResult = enum { woke, signalled };

inline fn hasPendingDeliverable(pcb: *const PCB) bool {
    const pending = @atomicLoad(u32, &pcb.pending_signals, .acquire);
    return (pending & ~pcb.signal_mask) != 0;
}

/// Like `blockOn`, but bails out (without parking, or while parked) when a
/// non-blocked signal is pending. Callers of the form
///
///     while (!cond) switch (process.blockOnInterruptible(.kind, t)) {
///         .woke => {},
///         .signalled => return E_INTR,
///     }
///
/// get correct EINTR semantics: any syscall they're in is interrupted
/// instead of resumed after handler delivery. Drivers doing kernel-internal
/// waits (NVMe completion, GPU command IRQ) should keep using `blockOn` —
/// interrupting them mid-DMA would leak hardware state.
pub fn blockOnInterruptible(kind: WaitKind, target: u32) BlockResult {
    const cur = smp.myCpu().current_pid orelse return .woke;
    const pcb = &procs[cur];
    // Signal already pending — don't even park. The deliver path on this
    // syscall's return will pick it up.
    if (hasPendingDeliverable(pcb)) return .signalled;
    blockOn(kind, target);
    if (hasPendingDeliverable(pcb)) return .signalled;
    return .woke;
}

pub fn blockOn(kind: WaitKind, target: u32) void {
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &procs[cur];
    // Captured for the yield-loop detector call below — taken here so the
    // trip dump names the high-level yield site (e.g.
    // nvme.waitCompletionAsync, pipe.read), not blockOn itself.
    const caller_ra = @returnAddress();
    // Wake-pending handshake. Atomically test-and-clear: if wake_pending
    // was ALREADY true on entry, a wake() ran between the caller's
    // condition check and our entry here — the wake event has been
    // delivered to us and the caller's next loop iteration will observe
    // its condition is satisfied. Return immediately without parking.
    //
    // The old `@atomicStore(false)` here was buggy: it unconditionally
    // stomped on a prior wake() that had set wake_pending=true,
    // causing permanent park. Caught 2026-05-19 by yield-loop:stuck:
    // desktop pid 2 stuck on nvme1 cid=0 with the waiter showing
    // completed=true while pid 2 was parked .sleeping. The fix
    // generalizes — every `while (!cond) blockOn(...)` pattern (pipe.read,
    // futex_wait, sysWaitpid, etc.) had the same race window.
    if (@atomicRmw(bool, &pcb.wake_pending, .Xchg, false, .acq_rel)) {
        return;
    }
    pcb.wait_kind = kind;
    pcb.wait_target = target;
    setState(cur, .sleeping);
    // Race check: did a wake() land between our test-and-clear above
    // and the setState? If so, roll back to .running and return — the
    // caller's condition is satisfied and yielding would lose the wake.
    if (@atomicLoad(bool, &pcb.wake_pending, .acquire)) {
        pcb.wait_kind = .none;
        pcb.wait_target = 0;
        setState(cur, .running);
        return;
    }
    // Yield-loop detector: trips if this pid keeps actually parking with
    // identical (kind, target, caller_ra) in a tight window — fingerprint
    // of a wake-then-resleep loop on a non-progressing resource. Called
    // here (after both wake_pending early-returns) so only REAL yields
    // count; the fast-path returns from a satisfied caller condition
    // would otherwise produce false-positive trips.
    @import("../debug/yield_loop.zig").observe(cur, kind, target, caller_ra);
    smp.myCpu().pending_soft_yield = true;
    @import("sched_asm.zig").softYield();
    pcb.wait_kind = .none;
    pcb.wait_target = 0;
}


/// Result of blockOnFutex: woke normally, interrupted by a deliverable signal,
/// or the futex word changed during enrollment (caller returns EAGAIN).
pub const FutexResult = enum { woke, signalled, again };

/// Futex compare-and-sleep — mirrors blockOnMutex's register-then-recheck so a
/// racing FUTEX_WAKE can't be lost. `word` is the validated user *uaddr. We
/// enroll as a .futex waiter FIRST, then re-read *word and re-check wake_pending.
/// The old order ("read *uaddr THEN blockOn") dropped a wake that fired in the
/// gap — futex was the only waiter kind whose waker never set wake_pending, so
/// blockOn's re-check was structurally blind to it. setState(.sleeping)'s
/// internal atomic fences our enroll ahead of the *word re-read on x86 (same
/// assumption blockOnMutex relies on). Interruptible: .signalled on a pending
/// deliverable signal so a SIGINT/SIGTERM handler isn't stuck in the wait.
pub fn blockOnFutex(target: u32, word: *const volatile u32, val: u32) FutexResult {
    const cur = smp.myCpu().current_pid orelse return .woke;
    const pcb = &procs[cur];
    if (hasPendingDeliverable(pcb)) return .signalled;

    @atomicStore(bool, &pcb.wake_pending, false, .release);
    pcb.wait_kind = .futex;
    pcb.wait_target = target;
    setState(cur, .sleeping);

    // Race A: the waker stored a new *uaddr before we enrolled. (Futex contract:
    // the waker changes *uaddr, THEN calls FUTEX_WAKE.) Seeing the new value
    // means the wake is already in flight / done — don't park.
    if (word.* != val) {
        pcb.wait_kind = .none;
        pcb.wait_target = 0;
        setState(cur, .running);
        return .again;
    }
    // Race B: a FUTEX_WAKE landed during enrollment — wake() set wake_pending.
    if (@atomicLoad(bool, &pcb.wake_pending, .acquire)) {
        pcb.wait_kind = .none;
        pcb.wait_target = 0;
        setState(cur, .running);
        return .woke;
    }

    smp.myCpu().pending_soft_yield = true;
    @import("sched_asm.zig").softYield();
    pcb.wait_kind = .none;
    pcb.wait_target = 0;
    if (hasPendingDeliverable(pcb)) return .signalled;
    return .woke;
}

/// Called by pipe.write when waking a blocked reader, by pipe.read when waking
/// a blocked writer, and by killProcess/destroyCurrent when waking a parent
/// blocked in waitpid.
pub fn wake(pid: u8) void {
    if (pid >= MAX_PROCS) return;
    // Set wake_pending BEFORE clearing wait_kind / setStating .ready so a
    // racing blockOn (running on the target's own CPU between its wait_kind
    // store and its setState) can detect us via the re-check after setState.
    // Without this, the wake is silently lost and the task sleeps forever.
    @atomicStore(bool, &procs[pid].wake_pending, true, .release);
    procs[pid].wait_kind = .none;
    procs[pid].wait_target = 0;
    // pipe.read / pipe.write park themselves with state=.sleeping so the
    // int $0x20 yield actually reschedules (idt's yielded_from_kernel check
    // requires state != .running). Flip back to .ready here so the next
    // scheduler tick can pick us up. Don't touch .running or .zombie — wake
    // is meant to be a no-op for processes that aren't parked. setState
    // also rqEnter's pid on its assigned_cpu's runqueue.
    if (procs[pid].state == .sleeping) setState(pid, .ready);
}

/// Compare-and-sleep primitive for Mutex.acquire. Enrolls the current
/// PCB as a .mutex waiter on `target_id` (= low-32 of the mutex's
/// owner_pid address), then re-reads `*owner_pid_ptr` atomically. If
/// the mutex became free between the caller's failed CAS-try and now,
/// returns without sleeping — the caller's next CAS-try will claim it.
/// Otherwise, sleeps until released. The dual race guard (re-check of
/// owner + wake_pending) closes the wake-during-enrollment window that
/// would otherwise lose a wakeup.
pub fn blockOnMutex(target_id: u32, owner_pid_ptr: *const u16) void {
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &procs[cur];
    @atomicStore(bool, &pcb.wake_pending, false, .release);
    pcb.wait_kind = .mutex;
    pcb.wait_target = target_id;
    setState(cur, .sleeping);
    // Race A: mutex got released between our caller's CAS-fail and our
    // enrollment. Don't sleep; caller will retry the CAS.
    if (@atomicLoad(u16, owner_pid_ptr, .acquire) == 0xFFFF) {
        pcb.wait_kind = .none;
        pcb.wait_target = 0;
        setState(cur, .running);
        return;
    }
    // Race B: a wake() landed between our wake_pending=false and now.
    if (@atomicLoad(bool, &pcb.wake_pending, .acquire)) {
        pcb.wait_kind = .none;
        pcb.wait_target = 0;
        setState(cur, .running);
        return;
    }
    smp.myCpu().pending_soft_yield = true;
    @import("sched_asm.zig").softYield();
    pcb.wait_kind = .none;
    pcb.wait_target = 0;
}

/// Wake every PCB sleeping on a Mutex with this target_id. Thundering-
/// herd wake: all waiters retry CAS in parallel, one wins, losers
/// re-blockOnMutex. Acceptable for low-contention locks (virtio-gpu
/// submit serializes one ~50ms wait at a time, contention is rare).
pub fn wakeMutexWaiters(target_id: u32) void {
    for (0..MAX_PROCS) |i| {
        const t = &procs[i];
        if (t.state != .sleeping) continue;
        if (t.wait_kind != .mutex) continue;
        if (t.wait_target != target_id) continue;
        wake(@intCast(i));
    }
}

/// Walk a dying process's fd_table and close any pipe fds so the pipe pool's
/// reader/writer counts stay correct. Called from killProcessWithStatus and
/// destroyCurrentWithStatus before the slot is freed.
fn closePipeFds(pid: u8) void {
    const pipe = @import("pipe.zig");
    for (0..MAX_FDS) |fd| {
        const desc = &procs[pid].fd_table[fd];
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
    const parent = procs[child_pid].parent_pid;
    if (parent == 0 or parent >= MAX_PROCS) return false;
    if (procs[parent].state == .unused) return false;
    if (procs[parent].wait_kind != .waitpid) return false;
    const target = procs[parent].wait_target;
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
    const my_tgid: u8 = procs[pid].tgid;
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

    // Resources reachable in any address space (GUI window state, GPU
    // contexts, debug symbols all live in heap / driver structures, not
    // user memory). Safe to free before the CR3 switch below.
    if (last_in_group) {
        const desktop = @import("../ui/desktop.zig");
        desktop.destroyGuiWindow(@intCast(pid));
        kp.checkpoint("tdt:post-destroyGuiWindow");
        if (procs[pid].gpu_has_ctx) {
            const virtio_gpu = @import("../driver/virtio_gpu.zig");
            if (!virtio_gpu.ctxDestroy(procs[pid].gpu_ctx_id)) {
                debug.klog("[proc] GPU ctx {d} destroy failed for pid {d}\n", .{ procs[pid].gpu_ctx_id, pid });
            }
            procs[pid].gpu_has_ctx = false;
            procs[pid].gpu_ctx_id = 0;
            kp.checkpoint("tdt:post-ctxDestroy");
        }
        if (procs[pid].sym_table) |st| {
            symbols.freeSymTable(st);
            procs[pid].sym_table = null;
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
        const lead = &procs[my_tgid];
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
        for (lead.lazy_regions[0..lead.lazy_count]) |r| {
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
    procs[pid].page_directory = null;
    procs[pid].page_dir_phys = 0;
    procs[pid].exit_status = status;

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
            gdt.setTssRsp0(idle, procs[idle].kernel_stack_top);
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
    const parent = procs[pid].parent_pid;
    const parent_alive = parent < MAX_PROCS and procs[parent].state != .unused and parent != 0;
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
        setState(pid, .zombie);
        if (parentIsWaiting(@intCast(pid))) wake(parent);
        // SIGCHLD is default-ignored, so this is a no-op for shells
        // that don't care; shells with a SIGCHLD handler can do
        // non-blocking reaping. Sent regardless of waitpid state per POSIX.
        _ = signals.send(parent, signals.SIGCHLD);
        kp.checkpoint("tdt:post-zombie+SIGCHLD");
    } else {
        setState(pid, .unused);
        @atomicStore(usize, &expected_kstack_tops[pid], 0, .release);
        @import("../debug/kasan.zig").markPcbDead(@intFromPtr(&kstack_pool[pid]) + KSTACK_GUARD_SIZE, KSTACK_SIZE);
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
        const init_state = @atomicLoad(u8, @as(*const u8, @ptrCast(&procs[pid].state)), .acquire);
        if (init_state == @intFromEnum(State.unused) or
            init_state == @intFromEnum(State.zombie)) return;
    }

    procs[pid].exit_status = status;

    // Atomic ownership claim — only one killer runs teardown per pid.
    // .Xchg returns the previous value; if it was already true another
    // killer is in flight, so we just wait for terminal state and bail.
    const prev_req = @atomicRmw(bool, &procs[pid].exit_requested, .Xchg, true, .acq_rel);
    if (prev_req) {
        var spin: u32 = 0;
        while (spin < 10_000_000) : (spin += 1) {
            const s = @atomicLoad(u8, @as(*const u8, @ptrCast(&procs[pid].state)), .acquire);
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
        const snap = @atomicLoad(u8, @as(*const u8, @ptrCast(&procs[pid].state)), .acquire);
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
                if (kill_kick_vector) |v| apic.sendIPI(tl, v);
            }
            ipi_attempts += 1;
            if (ipi_attempts > 16) {
                debug.klog("[kill] WARN: gave up evicting pid={d} after 16 IPI rounds\n", .{pid});
                return;
            }
            var spin: u32 = 0;
            while (spin < 1_000_000) : (spin += 1) {
                const s = @atomicLoad(u8, @as(*const u8, @ptrCast(&procs[pid].state)), .acquire);
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
        setState(pid, .zombie);
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
        if (procs[i].state == .unused) continue;
        if (procs[i].parent_pid == dead_pid) {
            procs[i].parent_pid = INIT_PID;
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
    const now = tick_count;
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
        if (procs[i].state != .zombie) continue;
        // Parent might be waiting; if so, leave it for the normal path.
        // (parentIsWaiting is the same predicate killProcessWithStatus uses.)
        if (parentIsWaiting(i)) continue;
        const age = tick_count -% procs[i].acct_start_tick;
        if (age < max_age_ticks) continue;
        // Force-reap: same teardown as the .unused branch in killProcessWithStatus.
        // setState handles the rq book-keeping (zombie isn't runnable so the
        // rq should already be empty for this pid; defensive).
        setState(i, .unused);
        @atomicStore(usize, &expected_kstack_tops[i], 0, .release);
        @import("../debug/kasan.zig").markPcbDead(@intFromPtr(&kstack_pool[i]) + KSTACK_GUARD_SIZE, KSTACK_SIZE);
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
    schedule();
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
    if (procs[pid].state != .zombie) return;
    const kp = @import("../debug/kstack_protect.zig");
    kp.checkpoint("reap:entry");
    setState(pid, .unused);
    @atomicStore(usize, &expected_kstack_tops[pid], 0, .release);
    @import("../debug/kasan.zig").markPcbDead(@intFromPtr(&kstack_pool[pid]) + KSTACK_GUARD_SIZE, KSTACK_SIZE);
    kp.checkpoint("reap:exit");
}

/// Find the lowest-pid zombie child of `parent`. Returns null if none.
/// `target_pid == 0xFFFFFFFF` means "any child"; otherwise wait for exactly
/// that pid.
pub fn findZombieChild(parent: u8, target_pid: u32) ?u8 {
    for (0..MAX_PROCS) |i| {
        if (procs[i].state != .zombie) continue;
        if (procs[i].parent_pid != parent) continue;
        if (target_pid != 0xFFFFFFFF and i != @as(usize, @intCast(target_pid))) continue;
        return @intCast(i);
    }
    return null;
}

/// Print process table for the `ps` command.
pub fn printProcesses() void {
    vga.print("PID  STATE\n", .{});
    vga.print("---  -----\n", .{});
    for (0..MAX_PROCS) |i| {
        const state_str: []const u8 = switch (procs[i].state) {
            .unused => continue,
            .ready => "ready",
            .running => "running",
            .sleeping => "sleeping",
        };
        vga.print("  {d}  {s}\n", .{ i, state_str });
    }
}

/// Get current process PID (per-CPU). Returns 0xFFFFFFFF when no task is
/// dispatched on this CPU (only true pre-`enterFirstTask`).
pub fn getCurrentPid() u32 {
    if (smp.myCpu().current_pid) |cur| return @intCast(cur);
    return 0xFFFFFFFF;
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

/// Register a lazy region — pages in [start, end) get allocated on first
/// touch via the page-fault handler. Returns false if the table is full or
/// the bounds are invalid. Pages still allocate-and-zero on miss; this just
/// avoids paying for them upfront.
pub fn addLazyRegion(pid: usize, start: usize, end: usize, flags: u8) bool {
    if (end <= start) return false;
    const pcb = &procs[pid];
    if (pcb.lazy_count >= MAX_LAZY_REGIONS) return false;
    pcb.lazy_regions[pcb.lazy_count] = .{ .start = start, .end = end, .flags = flags };
    pcb.lazy_count += 1;
    return true;
}

/// Register a lazy region backed by a kernel buffer (used for demand-paged
/// ELF segments). On first touch of any page in [start, end), the page-fault
/// handler allocates+zeros a frame, then copies bytes from
/// `source[src_offset + (page_va - src_va_base)]` for the intersection of the
/// page with [src_va_base, src_va_base + src_size). Bytes outside that
/// intersection (BSS, segment alignment padding) stay zero.
pub fn addLazyRegionWithSource(
    pid: usize,
    start: usize,
    end: usize,
    flags: u8,
    source: [*]const u8,
    src_va_base: usize,
    src_size: usize,
    src_offset: usize,
) bool {
    if (end <= start) return false;
    const pcb = &procs[pid];
    if (pcb.lazy_count >= MAX_LAZY_REGIONS) return false;
    pcb.lazy_regions[pcb.lazy_count] = .{
        .start = start,
        .end = end,
        .flags = flags,
        .source = source,
        .src_va_base = src_va_base,
        .src_size = src_size,
        .src_offset = src_offset,
    };
    pcb.lazy_count += 1;
    return true;
}

/// Walk PML4→PT for `va` and return a writable pointer to its 4 KB PTE,
/// or null if the path is missing or the address is covered by a huge page.
/// Used by the COW handler to mutate the PTE in place after copying.
fn findUserPte(pml4: [*]align(4096) u64, va: usize) ?*u64 {
    const paging = @import("../mm/paging.zig");
    const PRESENT_F: u64 = 1;
    const PAGE_SIZE_F: u64 = 1 << 7;
    const MASK: u64 = 0x000FFFFFFFFFF000;

    if (pml4[(va >> 39) & 0x1FF] & PRESENT_F == 0) return null;
    const pdpt: [*]u64 = @ptrFromInt(paging.physToVirt(pml4[(va >> 39) & 0x1FF] & MASK));
    const pdpte = pdpt[(va >> 30) & 0x1FF];
    if (pdpte & PRESENT_F == 0 or pdpte & PAGE_SIZE_F != 0) return null;
    const pd: [*]u64 = @ptrFromInt(paging.physToVirt(pdpte & MASK));
    const pde = pd[(va >> 21) & 0x1FF];
    if (pde & PRESENT_F == 0 or pde & PAGE_SIZE_F != 0) return null;
    const pt: [*]u64 = @ptrFromInt(paging.physToVirt(pde & MASK));
    return &pt[(va >> 12) & 0x1FF];
}

/// Copy-on-write fault path. Triggered when a user write hits a present PTE
/// that has the COW software bit set (cloneAddressSpace marks both parent and
/// child PTEs this way). Allocates a private frame for the faulting AS,
/// copies the shared frame's contents in, swaps the PTE to point at the new
/// frame R/W, and drops one refcount on the shared frame. If we were the only
/// owner (refcount==1), skip the copy and just promote in place.
fn handleCowFault(pml4: [*]align(4096) u64, cr2: usize) bool {
    const paging = @import("../mm/paging.zig");
    const va_aligned = cr2 & ~@as(usize, 0xFFF);
    const pte_p = findUserPte(pml4, va_aligned) orelse return false;
    const pte = pte_p.*;
    if (pte & paging.COW == 0) return false;

    const old_phys = pte & paging.PAGE_MASK;

    // Sole-owner promote-in-place. Refcount may race against another CPU's
    // releaseFrame on the same shared frame, but the only outcome of being
    // wrong here is taking the slow path unnecessarily — never incorrect.
    if (pmm.frameRefCount(old_phys) == 1) {
        pte_p.* = (pte & ~paging.COW) | paging.READ_WRITE;
        asm volatile ("invlpg (%[addr])"
            :
            : [addr] "r" (va_aligned),
            : .{ .memory = true }
        );
        return true;
    }

    // Multiple owners — alloc a private copy. Use the user-reserve-
    // aware allocator: a runaway COW fault storm during memory pressure
    // shouldn't be allowed to deplete the kernel's emergency pool.
    const new_phys = pmm.allocFrameUser() orelse return false;
    const src: [*]const u8 = @ptrFromInt(paging.physToVirt(old_phys));
    const dst: [*]u8 = @ptrFromInt(paging.physToVirt(new_phys));
    @memcpy(dst[0..0x1000], src[0..0x1000]);

    // Replace phys field, clear COW, restore R/W. Other flag bits (USER, NX,
    // accessed/dirty) are inherited from the COW PTE.
    pte_p.* = (pte & ~paging.PAGE_MASK & ~paging.COW) | new_phys | paging.READ_WRITE;

    pmm.releaseFrame(old_phys);

    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (va_aligned),
        : .{ .memory = true }
    );
    return true;
}

/// Ensure every page overlapping [va, va+len) in the CURRENT process's user
/// address space is present AND writable, performing the same lazy fault-in +
/// copy-on-write break the ring-3 #PF path does — but proactively, WITHOUT
/// taking a fault. Returns false if any page can't be made writable (no lazy
/// region covers it, or OOM).
///
/// WHY this exists: signal delivery writes the handler frame DIRECTLY to the
/// user stack inside a SMAP `stac` bracket. This kernel's #PF handler only
/// services ring-3 faults (idt.zig gates lazy/COW on `saved_cs & 3`), so a
/// kernel-mode (stac'd) write to a not-yet-faulted-in or still-COW stack page
/// would hit the kernel-fault autopsy and PANIC instead of paging in. The
/// realistic triggers are a freshly fork()'d process whose stack is still COW,
/// and a frame that spans into a lower stack page not yet lazily mapped.
/// Pre-resolving the frame's pages here removes the fault entirely.
///
/// Mirrors handleUserPageFault's COW (handleCowFault) + lazy (allocAndMapUserPage)
/// dispatch, but keyed on the live PTE state rather than a fault error code.
/// Adds an explicit invlpg after a fresh map: mapUserPage only flushes on the
/// remap path (the fault path relies on the faulting instruction's re-walk,
/// which a proactive caller doesn't have).
pub fn ensureUserRangeWritable(va: usize, len: usize) bool {
    if (len == 0) return true;
    const cur = smp.myCpu().current_pid orelse return false;
    const pcb = &procs[cur];
    const pd = pcb.page_directory orelse return false;
    const lead = leader(pcb);

    var p = va & ~@as(usize, 0xFFF);
    const end_excl = va +% len;
    while (p < end_excl) : (p += 0x1000) {
        if (vmm.resolveUserPhys(pd, p) != null) {
            // Present — break COW if needed. handleCowFault breaks + invlpg's a
            // COW page, and is a safe no-op on a non-COW page.
            _ = handleCowFault(pd, p);
            // A present page that is STILL read-only (e.g. an app that
            // mprotect'd its own stack region read-only) can't take our write —
            // fail delivery so the caller kills it (≈ SIGSEGV) rather than
            // panic on the kernel-mode #PF this kernel's ring-3-only handler
            // won't service.
            const paging = @import("../mm/paging.zig");
            const pte_ptr = findUserPte(pd, p) orelse return false;
            if (pte_ptr.* & paging.READ_WRITE == 0) return false;
        } else {
            // Not present — lazy fault-in via the owning region.
            var mapped = false;
            var i: u8 = 0;
            while (i < lead.lazy_count) : (i += 1) {
                const r = lead.lazy_regions[i];
                if (p < r.start or p >= r.end) continue;
                _ = vmm.allocAndMapUserPage(pd, p, vmm.protToMapFlags(r.prot)) catch return false;
                asm volatile ("invlpg (%[addr])"
                    :
                    : [addr] "r" (p),
                    : .{ .memory = true });
                mapped = true;
                break;
            }
            if (!mapped) return false; // no lazy region covers this page
        }
    }
    return true;
}

/// Resolve a faulting user address against the current process's lazy
/// regions. If the address is inside a registered region, allocate+map a
/// fresh zero page, flush TLB, and return true. The caller (PF handler) can
/// then sysret without killing the process.
/// Free up to `want` physical frames by evicting cold, present, non-COW pages
/// of `lead`'s lazy regions out to swap (Phase 2: intra-process only). A
/// per-lead clock cursor (`swap_clock_va`) resumes the scan where it left off
/// so a linear >RAM workload stays O(n), and ITER_CAP bounds per-call work.
/// Skips `skip_va` (the page currently being faulted in). Returns frames freed;
/// no-op if swap is unavailable.
fn reclaimViaSwap(pml4: [*]align(4096) u64, lead: *PCB, skip_va: usize, pcid: u16, want: usize) usize {
    if (!swap.available or lead.lazy_count == 0) return 0;
    const paging = @import("../mm/paging.zig");
    var freed: usize = 0;
    var iters: usize = 0;
    const ITER_CAP: usize = 16384; // bounds total work (pages examined + gap hops)
    var va = lead.swap_clock_va;
    while (freed < want and iters < ITER_CAP) : (iters += 1) {
        // Is va inside a (non-empty) lazy region? Phase 3: we evict ANY private
        // user page — anonymous OR file-backed. File-backed pages used to be
        // skipped because (a) they're clean and re-faultable from `source`, and
        // (b) a swapped (not-present) PTE made kernel-side pointer validation
        // (validateUserPtr) return E_FAULT. (b) is now fixed — trySwapInPage
        // pages a swapped entry back in on the kernel user-access path too — so
        // eviction is transparent to syscalls and the restriction is lifted.
        // (Later optimization: DISCARD clean file-backed pages rather than
        // writing them to swap; they re-read from `source` for free.)
        var in_region = false;
        var k: u8 = 0;
        while (k < lead.lazy_count) : (k += 1) {
            const r = lead.lazy_regions[k];
            if (r.end > r.start and va >= r.start and va < r.end) {
                in_region = true;
                break;
            }
        }
        if (!in_region) {
            // Jump to the next region start above va, else wrap to the lowest.
            var next_start: usize = 0;
            var found = false;
            var lo: usize = 0;
            var any = false;
            var j: u8 = 0;
            while (j < lead.lazy_count) : (j += 1) {
                const r = lead.lazy_regions[j];
                if (r.end <= r.start) continue;
                if (!any or r.start < lo) {
                    lo = r.start;
                    any = true;
                }
                if (r.start > va and (!found or r.start < next_start)) {
                    next_start = r.start;
                    found = true;
                }
            }
            if (!any) break; // no non-empty regions
            va = if (found) next_start else lo;
            continue;
        }
        if (va != skip_va) {
            if (vmm.userPtePtr(pml4, va)) |pte_ptr| {
                const pte = pte_ptr.*;
                if ((pte & paging.PRESENT) != 0 and (pte & paging.COW) == 0) {
                    if (swap.evictFrame(pte_ptr, va, pcid)) freed += 1;
                }
            }
        }
        va += 0x1000;
    }
    lead.swap_clock_va = va;
    return freed;
}

/// Outcome of attempting a swap-in for one page.
///   not_swapped — PTE wasn't a swapped entry; caller proceeds normally.
///   paged_in    — page is now resident.
///   oom         — it WAS swapped but no frame could be obtained even after
///                 reclaim (genuine exhaustion); caller should fail/kill.
const SwapInOutcome = enum { not_swapped, paged_in, oom };

/// If `va`'s leaf PTE encodes a swapped page, page it back in — reclaiming cold
/// frames first if memory is tight. Shared by the page-fault handler AND the
/// kernel-side pointer prefault (validateUserPtr -> prefaultUserRange) so a
/// swapped-out user buffer handed to a syscall is paged in rather than failing
/// validation with E_FAULT. This is what makes evicting ANY user page (not just
/// Phase 2's anon-only subset) safe: the kernel can always fault it back in.
fn trySwapInPage(pd: [*]align(4096) u64, lead: *PCB, va: usize, prot: u8, pcid: u16) SwapInOutcome {
    if (!swap.available) return .not_swapped;
    const sp = vmm.userPtePtr(pd, va) orelse return .not_swapped;
    if (!swap.pteIsSwapped(sp.*)) return .not_swapped;
    // Make sure a frame is free for the read-in; evict cold pages of this
    // process if memory is exhausted. skip_va = va so reclaim never re-targets
    // the very page we're about to swap in.
    if (pmm.freeFrameCount() < 64) _ = reclaimViaSwap(pd, lead, va, pcid, 64);
    if (swap.swapInFrame(sp, va, vmm.protToMapFlags(prot), pcid)) return .paged_in;
    return .oom;
}

pub fn handleUserPageFault(cr2: usize, error_code: u64) bool {
    // Must be user-mode access (U=1, bit 2). Both non-present (P=0) and
    // protection violations (P=1) are valid lazy-fault triggers — the
    // latter happens because createAddressSpace strips USER from inherited
    // kernel-identity pages, so user access hits "present but no USER" PT
    // entries until we replace them with a fresh USER-bit mapping below.
    if ((error_code & 4) == 0) return false;
    const cur = smp.myCpu().current_pid orelse return false;
    const pcb = &procs[cur];
    // Accounting: count every user-mode page fault (handled or not) so the
    // counter reflects the load this PCB puts on the fault path. If we
    // counted only successful lazy fault-ins, "app keeps page-faulting on
    // an unmapped address" wouldn't show up.
    pcb.acct_pf_count +%= 1;
    const pd = pcb.page_directory orelse return false;

    // COW path: write fault on a present user page (P=1, W=1, U=1). Walk the
    // PT and dispatch handleCowFault if the PTE has the COW software bit set.
    // Lazy-region faults are P=0 (non-present); COW faults are P=1 and W=1.
    if ((error_code & 0x3) == 0x3) {
        if (handleCowFault(pd, cr2)) {
            @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, true);
            return true;
        }
    }
    // Lazy regions live on the lead thread (per-process resource). For
    // single-threaded processes this aliases pcb itself; for cloned
    // threads we read the parent's regions so mmap'd VAs are visible.
    const lead = leader(pcb);

    var i: u8 = 0;
    while (i < lead.lazy_count) : (i += 1) {
        const r = lead.lazy_regions[i];
        if (cr2 < r.start or cr2 >= r.end) continue;
        const va_aligned = cr2 & ~@as(usize, 0xFFF);

        // Swap-in: if this VA was evicted to swap, page it back in instead of
        // fresh-allocating a zero page (which would discard its contents and
        // leak the swap slot). The lazy region still exists; only the physical
        // frame was reclaimed. swap_failed => genuine OOM swapping in; skip the
        // fresh-alloc and fall through to the OOM-kill.
        var swap_failed = false;
        switch (trySwapInPage(pd, lead, va_aligned, r.prot, lead.pcid)) {
            .paged_in => {
                @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, true);
                return true;
            },
            .oom => {
                debug.klog("[swap] swap-in FAILED pid={d} va=0x{X} — out of memory, killing\n", .{ cur, va_aligned });
                swap_failed = true;
            },
            .not_swapped => {},
        }

        // Gap #1+#5 (2026-05-20): allocAndMapUserPage now returns a named
        // MapError instead of null. Oom is the only retry-worthy variant
        // (caches might free under pressure); BadVA / KernelHeap mean the
        // lazy region's start..end is malformed — no amount of reclaim
        // helps, fall straight through to OOM-kill (with a distinct log
        // line so the autopsy knows it wasn't memory pressure).
        var frame_opt: ?usize = null;
        if (!swap_failed) {
            if (vmm.allocAndMapUserPage(pd, va_aligned, vmm.protToMapFlags(r.prot))) |f| {
                frame_opt = f;
            } else |e1| {
                if (e1 == error.Oom) {
                    // Memory pressure response: ask registered modules to
                    // shed reclaimable caches (GUI back-buffers etc.), then
                    // retry the alloc ONCE.
                    if (pmm.tryReclaim(1) > 0) {
                        if (vmm.allocAndMapUserPage(pd, va_aligned, vmm.protToMapFlags(r.prot))) |f2| {
                            frame_opt = f2;
                        } else |_| {}
                    }
                    // Still nothing? Evict a BATCH of cold pages of this
                    // process out to swap and retry — THIS is what lets a
                    // process allocate and run past physical RAM instead of
                    // being OOM-killed. The batch must be big enough to climb
                    // back above the reserve-aware user-alloc floor (evicting
                    // just a handful leaves free below the reserve and the
                    // retry alloc still fails).
                    if (frame_opt == null and reclaimViaSwap(pd, lead, va_aligned, lead.pcid, 64) > 0) {
                        if (vmm.allocAndMapUserPage(pd, va_aligned, vmm.protToMapFlags(r.prot))) |f3| {
                            frame_opt = f3;
                        } else |_| {}
                    }
                } else {
                    debug.klog("[vmm] lazy fault REJECTED virt=0x{X} {s} — region[{d}] (0x{X}..0x{X}) prot=0x{X}\n", .{
                        va_aligned, @errorName(e1), i, r.start, r.end, r.prot,
                    });
                }
            }
        }
        const frame = frame_opt orelse {
            @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, false);
            // OOM kill path. The region IS valid (cr2 fell in r.start..r.end);
            // we just don't have a physical frame left. That's not a bug in
            // the user app — it's resource exhaustion — and the right
            // response is to SIGKILL THIS process and let the rest of the
            // system keep running, NOT to run the full crashSummary
            // (register dump, backtrace, dumpAll, fat32 writeCrashLog). The
            // heavy dump is fine for a programmer-error fault but here it's
            // both useless (we know why: OOM) and risky — fat32 writes
            // re-enter the allocator under the same pressure, and the long
            // print stream stalls the compositor on the BSP for hundreds of
            // ms. Take the lightweight route instead and the system stays
            // responsive even with photo / paint / etc. running into their
            // memory caps.
            debug.klog("[oom] killing PID={d} '{s}' — region[{d}] (0x{X}..0x{X}) needed page at cr2=0x{X}, pmm free={d}/{d}\n", .{
                cur,
                pcb.name[0..@min(pcb.name_len, pcb.name.len)],
                i,
                r.start,
                r.end,
                cr2,
                pmm.freeFrameCount(),
                pmm.managedFrameCount(),
            });
            // Memory autopsy: enumerate every lazy region so we can see
            // WHICH range consumed the frames before OOM hit. Without
            // this the OOM line names only the fault site, not the leak
            // site. Added 2026-05-20 during Q1 memory-budget audit.
            debug.klog("[oom]   lazy_count={d} user_brk=0x{X} heap_lazy_idx={d}\n", .{
                lead.lazy_count, lead.user_brk, lead.heap_lazy_idx,
            });
            var ri: u8 = 0;
            while (ri < lead.lazy_count) : (ri += 1) {
                const rr = lead.lazy_regions[ri];
                const size_kb: usize = (rr.end - rr.start) / 1024;
                const tag: []const u8 = if (rr.source != null)
                    "FILE-BACKED"
                else if (lead.heap_lazy_idx >= 0 and ri == @as(u8, @intCast(lead.heap_lazy_idx)))
                    "SBRK-HEAP"
                else
                    "ANON";
                debug.klog("[oom]   region[{d}] 0x{X:0>9}..0x{X:0>9} size={d}KB prot=0x{X} {s}\n", .{
                    ri, rr.start, rr.end, size_kb, rr.prot, tag,
                });
            }
            // Dump the kdbg pmm_alloc + pmm_free rings — they name which
            // call sites have been (de)allocating frames most recently.
            // For the Q1 audit (2026-05-20): lazy regions sum to 17 MB
            // but PMM dropped ~200 MB; the ring tells us who took the
            // other 183 MB.
            @import("../debug/kdbg.zig").dumpPmmAllocRing();
            dumpSyscallRing(@intCast(cur));
            // Desktop notification so the user sees WHY the app vanished
            // without having to scroll serial.log.
            const desktop = @import("../ui/desktop.zig");
            if (desktop.active) desktop.showNotification("App killed: out of memory");
            // tearDown + schedule. schedule() never returns when we just
            // marked current_pid null (dead-letter eats the outgoing rsp);
            // the `unreachable` below is for the type system.
            destroyCurrent();
            schedule();
            unreachable;
        };
        @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, true);
        // For ELF demand paging: copy the intersection of this page with the
        // segment's file-backed range from the kernel buffer. Untouched bytes
        // (alignment padding, BSS) stay zero from allocAndMapUserPage.
        if (r.source) |src| {
            const page_end = va_aligned + 0x1000;
            const src_va_end = r.src_va_base + r.src_size;
            const copy_start = @max(va_aligned, r.src_va_base);
            const copy_end = @min(page_end, src_va_end);
            if (copy_end > copy_start) {
                const dest_offset = copy_start - va_aligned;
                const src_byte_offset = r.src_offset + (copy_start - r.src_va_base);
                const len = copy_end - copy_start;
                const dest: [*]u8 = @ptrFromInt(@import("../mm/paging.zig").physToVirt(frame + dest_offset));
                @memcpy(dest[0..len], src[src_byte_offset .. src_byte_offset + len]);
            }
        }
        // Invalidate TLB on this CPU. Other CPUs don't share user PDs.
        asm volatile ("invlpg (%[addr])"
            :
            : [addr] "r" (va_aligned),
            : .{ .memory = true }
        );
        // Diagnostic: log first fault-in per (PID, 4KB page) so we see every
        // unique page a process touches, not just the first per region. Lets
        // us spot "process keeps faulting same page" loops vs "process moved
        // on to different pages and got stuck mid-execution." The seen-array
        // is bounded; once full we silently stop logging to avoid flooding.
        const dbg = struct {
            const MAX_LOG_PAGES = 64;
            var pages: [MAX_PROCS][MAX_LOG_PAGES]usize =
                [_][MAX_LOG_PAGES]usize{[_]usize{0} ** MAX_LOG_PAGES} ** MAX_PROCS;
            var counts: [MAX_PROCS]u8 = [_]u8{0} ** MAX_PROCS;
        };
        if (cur < MAX_PROCS) {
            // Defensive clamp: cnt is loaded from BSS and SHOULD always be
            // <= MAX_LOG_PAGES (the increment below is gated). If it's
            // larger, something corrupted the array — log and reset rather
            // than tripping a slice OOB panic that masks the real bug.
            const raw_cnt = dbg.counts[cur];
            if (raw_cnt > dbg.MAX_LOG_PAGES) {
                @import("../debug/serial.zig").print("[corrupt] dbg.counts[{d}]={d} > {d} — reset (BSS scribbled?)\n", .{ cur, raw_cnt, dbg.MAX_LOG_PAGES });
                dbg.counts[cur] = 0;
            }
            const cnt = @min(raw_cnt, dbg.MAX_LOG_PAGES);
            var already_seen = false;
            for (dbg.pages[cur][0..cnt]) |seen_va| {
                if (seen_va == va_aligned) {
                    already_seen = true;
                    break;
                }
            }
            if (!already_seen and cnt < dbg.MAX_LOG_PAGES) {
                dbg.pages[cur][cnt] = va_aligned;
                dbg.counts[cur] = cnt + 1;
                debug.klog("[pf] PID={d} lazy fault-in 0x{X} region={d}\n", .{ cur, va_aligned, i });
            }
        }
        // Accounting: this fault successfully populated a fresh user page,
        // so the process's resident set grew by one. Track peak too —
        // useful for OOM heuristics + sysmon's "max ever used" column.
        // Charge against the LEAD thread because lazy regions are shared.
        lead.acct_current_rss +%= 1;
        if (lead.acct_current_rss > lead.acct_peak_rss) {
            lead.acct_peak_rss = lead.acct_current_rss;
        }
        return true;
    }
    // No region matched. Diagnostic: dump lazy region table so we can see
    // whether the fault address is past the heap end, in an unexpected
    // gap between regions, or in territory we never mapped. Throttled
    // per-pid (one dump per crashing PCB) so a wild pointer in a loop
    // doesn't drown serial.
    const dbg2 = struct {
        var dumped: [MAX_PROCS]bool = [_]bool{false} ** MAX_PROCS;
    };
    if (cur < MAX_PROCS and !dbg2.dumped[cur]) {
        dbg2.dumped[cur] = true;
        debug.klog("[pf-miss] PID={d} cr2=0x{X} err=0x{X} — no lazy region matches; user_brk=0x{X}, heap_idx={d}, count={d}\n", .{
            cur, cr2, error_code, lead.user_brk, lead.heap_lazy_idx, lead.lazy_count,
        });
        var j: u8 = 0;
        while (j < lead.lazy_count) : (j += 1) {
            const r = lead.lazy_regions[j];
            debug.klog("[pf-miss]   region[{d}] start=0x{X} end=0x{X} prot=0x{X}\n", .{
                j, r.start, r.end, r.prot,
            });
        }
    }
    return false;
}

/// Force-fault-in any lazy region pages in [addr, addr+len). Used by syscalls
/// before reading user memory — without this, kernel-mode reads bypass the
/// USER bit check and return whatever's in the inherited 2MB identity map
/// (i.e. random kernel data) instead of the app's lazy-loaded data.
pub fn prefaultUserRange(addr: usize, len: usize) void {
    if (len == 0) return;
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &procs[cur];
    const pd = pcb.page_directory orelse return;
    const lead = leader(pcb);

    var page = addr & ~@as(usize, 0xFFF);
    const end = addr + len;
    while (page < end) : (page += 0x1000) {
        // Walk the regions for this page; if it's lazy, ensure its real PTE
        // is installed (which overrides the inherited 2MB mapping).
        var i: u8 = 0;
        while (i < lead.lazy_count) : (i += 1) {
            const r = lead.lazy_regions[i];
            if (page < r.start or page >= r.end) continue;

            // If a real 4K PTE is already installed (has USER bit), nothing
            // to do. Otherwise allocate + map + (optionally) copy from src.
            if (pageHasRealMapping(pd, page)) break;

            // If the page was evicted to swap, page it back in rather than
            // mapping a fresh zero page over the swapped PTE (which would lose
            // its contents AND leak the slot). This is the kernel-side swap-in
            // that lets validateUserPtr accept a pointer into a swapped buffer.
            // NOTE: prefault covers the WHOLE syscall (ptr,len) range, so a
            // syscall handed a large fully-swapped buffer swaps every page in
            // here (evict<->swap-in thrash if it exceeds RAM). Fine for normal
            // syscall buffers; a per-call swap-in cap is the fix if it bites.
            switch (trySwapInPage(pd, lead, page, r.prot, lead.pcid)) {
                .paged_in => break, // resident now (swapInFrame flushed this CPU)
                .oom => break, // leave unmapped — allCurrentUserPagesMapped() then fails -> clean E_FAULT
                .not_swapped => {}, // never-faulted page: fall through to fresh alloc + src copy
            }

            const frame = vmm.allocAndMapUserPage(pd, page, vmm.protToMapFlags(r.prot)) catch return;
            if (r.source) |src| {
                const page_end = page + 0x1000;
                const src_va_end = r.src_va_base + r.src_size;
                const copy_start = @max(page, r.src_va_base);
                const copy_end = @min(page_end, src_va_end);
                if (copy_end > copy_start) {
                    const dest_offset = copy_start - page;
                    const src_byte_offset = r.src_offset + (copy_start - r.src_va_base);
                    const clen = copy_end - copy_start;
                    const dest: [*]u8 = @ptrFromInt(@import("../mm/paging.zig").physToVirt(frame + dest_offset));
                    @memcpy(dest[0..clen], src[src_byte_offset .. src_byte_offset + clen]);
                }
            }
            asm volatile ("invlpg (%[addr])"
                :
                : [addr] "r" (page),
                : .{ .memory = true }
            );
            break;
        }
    }
}

/// Walk PML4→PDPT→PD→PT and report whether `va` resolves through a 4K PTE
/// with the USER bit set (i.e. an honest per-process mapping). Returns false
/// if the address falls through an inherited 2MB / 1GB page or isn't mapped.
///
/// Phase 3: each PTE address is a *physical* frame number — dereferencing it
/// directly used to work via the legacy PML4[0] low identity. After the
/// drop, every walk hop must go through the kernel physmap.
/// True if every 4 KB page in [addr, addr+len) of the current process's
/// address space has a present USER PTE (or sits under an inherited 1GB/2MB
/// page). Use after `prefaultUserRange` to confirm a user pointer is safe
/// to dereference from kernel context — prefault only maps pages registered
/// in lazy_regions, leaving pointers to scratch user VAs unmapped, and the
/// kernel's bare `@memcpy` then page-faults. validateUserPtr in syscall.zig
/// chains prefault → this helper to refuse the call cleanly.
pub fn allCurrentUserPagesMapped(addr: usize, len: usize) bool {
    if (len == 0) return true;
    const cur = smp.myCpu().current_pid orelse return false;
    const pcb = &procs[cur];
    const pd = pcb.page_directory orelse return false;

    var page = addr & ~@as(usize, 0xFFF);
    const end = addr + len;
    while (page < end) : (page += 0x1000) {
        if (!pageHasRealMapping(pd, page)) return false;
    }
    return true;
}

fn pageHasRealMapping(pml4: [*]align(4096) u64, va: usize) bool {
    const PRESENT: u64 = 1;
    const USER: u64 = 1 << 2;
    const PAGE_SIZE_FLAG: u64 = 1 << 7;
    const MASK: u64 = 0x000FFFFFFFFFF000;
    const paging = @import("../mm/paging.zig");

    const pml4_idx = (va >> 39) & 0x1FF;
    const e1 = pml4[pml4_idx];
    if (e1 & PRESENT == 0) return false;
    const pdpt: [*]const u64 = @ptrFromInt(paging.physToVirt(e1 & MASK));

    const pdpt_idx = (va >> 30) & 0x1FF;
    const e2 = pdpt[pdpt_idx];
    if (e2 & PRESENT == 0) return false;
    if (e2 & PAGE_SIZE_FLAG != 0) return false; // 1GB page — inherited
    const pd: [*]const u64 = @ptrFromInt(paging.physToVirt(e2 & MASK));

    const pd_idx = (va >> 21) & 0x1FF;
    const e3 = pd[pd_idx];
    if (e3 & PRESENT == 0) return false;
    if (e3 & PAGE_SIZE_FLAG != 0) return false; // 2MB page — inherited
    const pt: [*]const u64 = @ptrFromInt(paging.physToVirt(e3 & MASK));

    const pt_idx = (va >> 12) & 0x1FF;
    const e4 = pt[pt_idx];
    return (e4 & PRESENT != 0) and (e4 & USER != 0);
}

pub fn setName(pid: u8, name: []const u8) void {
    const len = @min(name.len, 16);
    @memcpy(procs[pid].name[0..len], name[0..len]);
    procs[pid].name_len = @intCast(len);
}

pub fn getName(pid: u8) []const u8 {
    return procs[pid].name[0..procs[pid].name_len];
}
