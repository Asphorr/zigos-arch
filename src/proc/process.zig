//! Process types + shared state. After the 2026-05-23 split (#810) this
//! file holds:
//!
//!   * The exhaustive enums + structs (State, Priority, FsType, WaitKind,
//!     FileDesc, PCB, LazyRegion, ProcessInfo) and the PROT_* / MAX_*
//!     constants — single source of truth that the per-domain files
//!     (fault.zig, lifecycle.zig, sched.zig) import via `process.X`.
//!
//!   * The BSS arrays: `procs` (the PCB table), `kstack_pool`,
//!     `io_scratch_pool`, `expected_kstack_tops`, the standalone
//!     `tick_count`, plus the `kick_handler_runs` / `wake_handler_runs`
//!     IPI counters (the latter two stay here as `pub var` because
//!     cli.zig + virtio_gpu.zig read them as `process.X[idx]` and Zig's
//!     `pub const X = mod.X` re-export pattern would copy a var's value
//!     at comptime, not re-expose the mutable storage).
//!
//!   * Accessor functions that don't fit cleanly elsewhere
//!     (currentPCB, getPCB, getStateRaw, getProcessInfo, setCurrent,
//!     recordSyscall / dumpSyscallRing, currentIoScratch, leader,
//!     setName / getName, getCurrentPid, printProcesses).
//!
//!   * Kernel-stack guard infrastructure (initKstackGuards,
//!     isValidKstackTopShape, isValidKstackTop, addrInKstackGuard).
//!
//!   * Re-export blocks for the symbols that LIVE in
//!     fault.zig / lifecycle.zig / sched.zig but external callers
//!     (drivers, syscall handlers, etc.) keep reaching through the
//!     `process.X` surface for source-stability.

const vga = @import("../ui/vga.zig");
const debug = @import("../debug/debug.zig");
const smp = @import("../cpu/smp.zig");
const memmap = @import("../mm/memmap.zig");
const config = @import("../config.zig");
const signals = @import("signals.zig");
const symbols = @import("../debug/symbols.zig");

pub const MAX_PROCS = config.MAX_PROCS;
const KSTACK_SIZE = config.KSTACK_SIZE;
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

// Per-process kernel stack pool. Each slot is `[guard 4KB | stack 64KB ↑]`,
// 4KB-aligned so paging.installGuardPage can mark slot[0..4096] not-present.
// PMM-BACKED (was static BSS): one contiguous block allocated at boot in
// initKstackGuards and accessed through the physmap, so slot i sits at
// `base + i*KSTACK_SLOT_SIZE` exactly as the old array did — every consumer's
// `&kstack_pool[i]` math is byte-identical. Moved out of BSS so MAX_PROCS no
// longer bloats the kernel image past KERNEL_HEAP_BASE (68KB/proc was the
// dominant term). Shared across address spaces via the physmap's PML4[256]
// entry — which createAddressSpace copies — so the guards we punch before the
// first user process are inherited. Pool slot i ↔ procs[i]. `undefined` until
// initKstackGuards; nothing touches a kstack before then (first task creation
// is well after, see main.zig init order).
pub var kstack_pool: *align(4096) [MAX_PROCS][KSTACK_SLOT_SIZE]u8 = undefined;

/// Total bytes the kstack pool spans. Use this instead of
/// `@sizeOf(@TypeOf(kstack_pool))` — that now yields a pointer's 8 bytes.
pub const KSTACK_POOL_BYTES: usize = MAX_PROCS * KSTACK_SLOT_SIZE;

/// Physical base of the kstack pool block (set in initKstackGuards). The pool
/// lives in the physmap now, NOT at KERNEL_VIRT_BASE — code that needs the
/// pool's phys range (e.g. the iommu DMA tripwire) MUST use this, not the old
/// `VA − KERNEL_VIRT_BASE` trick.
pub var kstack_pool_phys_base: usize = 0;

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

pub const FsType = enum(u8) { console = 0, fat32 = 1, tarfs = 2, pipe = 3, devfs = 4, procfs = 5, ext2 = 6, tcp_sock = 7, tcp_listener = 8 };

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
    swap_evict, // wait_target = low-32 of &leaf_pte. Set by handleUserPageFault when it hits a SWAP_INFLIGHT PTE; evictFrame's commit/abort phase wakes matching waiters
    iouring_work, // wait_target = io_uring instance index. Worker task idles here; both io_uring_enter (fresh SQEs) and the NVMe IRQ callback (in-flight completion) wake the matching worker.
    iouring_cq, // wait_target = io_uring instance index. io_uring_enter parks here when caller asked for min_complete > 0; worker wakes it after writing each CQE.
    softirq, // wait_target = cpu_id. This CPU's ksoftirqd parks here when its softirq_pending mask is empty; softirq.raise wakes it by pid (target is informational only).
    desktop, // wait_target = 0. The desktop task parks here when wake.isDue() + all input checks are idle; woken by the BSP idle loop (instant, input path), the IRQ0 due-check (≤10ms backstop), or wakeExpired at its self-wake deadline.
};

// Per-fd table entry. All fields are owner-pid only — fd_table lives on
// the PCB and is only touched on syscall paths running as that PID.
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

/// ABI personality of a process — selects which translation the `syscall`
/// instruction routes to. `.native` is zigos's own ABI (3×u32 args, native
/// numbers, u32 return); `.linux` is an unmodified Linux x86-64 binary (6×u64
/// args read from the saved frame, Linux numbers, u64 return — see
/// syscall/linux.zig). Set by the Linux ELF load path; inherited across fork.
pub const Personality = enum(u8) { native, linux };

pub const PCB = struct {
    // Access-tag legend (see docs/STYLE.md): (p:lock) protected by lock,
    // (a) atomic, (c) const-after-init. Fields without a tag are
    // owner-pid / owner-CPU only.
    state: State = .unused, // (a) mutate via sched.setState — setstate_locks[pid] serializes
    kernel_esp: usize = 0, // (p:rq.lock) switchTo saves on switch-out
    kernel_stack_top: usize = 0, // (c) assigned at allocKstack
    // VMM fields
    page_directory: ?[*]align(4096) u64 = null, // (c) createAddressSpace, RO after
    page_dir_phys: usize = 0, // (c) createAddressSpace, RO after
    user_brk: usize = memmap.USER_BRK_INITIAL, // sbrk start; sits above kernel heap (see memmap.zig)
    // mmap allocator (sysMmap). VAs grow downward from USER_SPACE_END so they
    // don't collide with the upward-growing user_brk; collision is rejected
    // explicitly in sysMmap. munmap currently leaks VA range — we don't reclaim
    // unmapped VA into a free list (pages are freed, just the address space
    // isn't compacted). v2 problem; bump-allocator works fine for short-lived
    // apps and the few hundred MB of user space is plenty for now.
    mmap_top: usize = MMAP_TOP_INIT, // (p:as_lock)
    // File descriptor table — owner-pid only
    fd_table: [MAX_FDS]FileDesc = initFdTable(),
    // ext2 inode this process's executable image was loaded from (0 = none /
    // not loaded from a regular file). Set by elf_loader.loadAndStart. Read by
    // isTextBusy to implement ETXTBSY: a write/truncate of a file whose inum
    // matches a live process's text_inum is refused, so a process can't pull
    // the rug from under its own (or another's) loader. (2026-06-04)
    text_inum: u32 = 0, // (c) set once at load
    // Sleep support
    wake_tick: u64 = 0, // (a) sysSleep + sched wakeExpired + virtio_gpu IRQ; cross-CPU readable
    // Hi-res sleep deadline, ABSOLUTE TSC ticks (0 = none). Set by sysUsleep,
    // woken by sched.wakeHiresExpired from the timer ISR — the precise-usleep
    // path (#1006) that replaced the ~19.3B-cycle HPET busy-wait. Kept distinct
    // from wake_tick (10 ms-granular) so the two wakers never fight: wakeExpired
    // owns wake_tick, wakeHiresExpired owns this; a sleeper sets exactly one.
    hires_wake_tsc: u64 = 0, // (a) cross-CPU readable
    // Race-free wake handshake. wake() sets this BEFORE clearing wait_kind /
    // setStating .ready, so a blockOn that just set wait_kind but hasn't yet
    // setState(.sleeping) can detect the race after setState and roll back.
    // Without this, the wake() can land between blockOn's wait_kind store and
    // its setState — wake clears wait_kind and sees state==.running (no-op),
    // then blockOn's setState sleeps the task with no waker. Reproduced as
    // "shell stops accepting input after a few keystrokes" / "calc clicks
    // dead" — both apps eventually call blockOn (via pipe.read or sysSleep)
    // and lose a wake to this race. Atomic for cross-CPU visibility.
    wake_pending: bool = false, // (a) wake-handshake; cross-CPU
    // Swap slot owned by an evictFrame call currently in progress on this PCB
    // (between phase-1 CAS and phase-3 CAS). 0xFFFFFFFF = no in-flight slot.
    // Lets process teardown free the slot if this thread is killed while
    // parked in blockOn(.nvme_io) inside writePage — without this, wake() is
    // a no-op on .zombie and the slot would leak. evictFrame stores at phase-1
    // success, clears at phase-3 / writePage-fail. Atomic so killProcess can
    // read it safely from another CPU.
    swap_inflight_slot: u32 = 0xFFFFFFFF, // (a) cross-CPU readable by killProcess
    // Process name (for window titles / icon matching)
    name: [16]u8 = [_]u8{0} ** 16, // (c) set at create/exec
    name_len: u8 = 0, // (c)
    // Real argv vector. argv[0] is the program name without `.elf`; argv[1..
    // argc] are user-supplied args parsed out of the exec string by splitting
    // on spaces. Replaces the old single-string `exec_arg`/`exec_arg_len`,
    // which couldn't represent multi-arg invocations like `cat foo bar`.
    // syscall 25 (getExecArg) is preserved as a backward-compat shim by
    // joining argv[1..] with spaces in the kernel.
    argv: [config.MAX_ARGS][config.MAX_ARG_LEN]u8 = // (c) set at exec
        [_][config.MAX_ARG_LEN]u8{[_]u8{0} ** config.MAX_ARG_LEN} ** config.MAX_ARGS,
    arg_lens: [config.MAX_ARGS]u8 = [_]u8{0} ** config.MAX_ARGS, // (c)
    argc: u8 = 0, // (c)
    // Scheduler — track consecutive ticks for fairness
    /// (p:rq.lock | owning-cpu-cli) Bumped from IRQ0 on the CPU currently
    /// running this PCB (cli-held throughout). Reset/inspected from
    /// schedule() under rq.lock. The two writers never overlap because
    /// IRQ0 cli on the owning CPU blocks the migration that schedule()
    /// would do to take the PCB elsewhere.
    ticks_used: u32 = 0,
    priority: Priority = .normal, // (p:rq.lock)
    last_cpu: u8 = 0, // (p:rq.lock) CPU this process last ran on (affinity)
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
    lazy_regions: [MAX_LAZY_REGIONS]LazyRegion = [_]LazyRegion{.{}} ** MAX_LAZY_REGIONS, // (p:as_lock)
    lazy_count: u8 = 0, // (p:as_lock)
    /// Address-space stability lock (leader-owned, non-leader threads access via
    /// `leader(pcb).as_lock`). Acquired by:
    ///   - AS-mutating syscalls: sysSbrk, sysMmap, sysMmapSharedAnon, sysMunmap,
    ///     sysMprotect (mutate lazy_regions / page directory).
    ///   - Kernel paths that read/write user memory from a NON-current pid:
    ///     io_uring worker's handleCompletion + executeSyncAsWorker.
    /// Serializes the (walk → memcpy) sequence against concurrent munmap/mprotect
    /// on another CPU, which would otherwise let the kernel write to a page after
    /// the owner's TLB shootdown freed its backing frame. Closes the HIGH classes
    /// reviewer flagged 2026-05-24 (concurrent munmap + COW write-fault).
    /// Mutex semantics + sleep-aware → safe to hold across vfs.read/write.
    as_lock: @import("spinlock.zig").Mutex = .{},
    // Index of the lazy region tracking the heap (sbrk). -1 = no heap region
    // has been registered yet. Allows sysSbrk to extend in place across calls.
    heap_lazy_idx: i8 = -1, // (p:as_lock)
    // Swap clock cursor (a user VA): reclaimViaSwap resumes its cold-page
    // eviction scan from here so it doesn't rescan already-evicted pages on
    // every fault (turns an O(n^2) linear-scan workload into O(n)).
    swap_clock_va: usize = 0,
    // Per-process kernel-side ELF buffer (PMM-allocated contiguous frames).
    // Lazy regions for PT_LOAD segments reference this; freed on process destroy.
    elf_buf: ?[*]u8 = null, // (c) set at exec
    elf_buf_pages: u32 = 0, // (c)
    // Shared refcount for elf_buf (see elf_rc.zig). fork() hands the parent's
    // buffer to the child — the child's lazy_regions[].source point into it —
    // so the PMM pages must live until the LAST referrer frees them, not the
    // original owner. null = un-refcounted single owner (buffer dropped at
    // load, or rc pool exhausted): never shared, so it can't dangle.
    elf_buf_rc: ?*u32 = null, // (c)
    // Bottom of the user stack (lazy region start). Set by elf_loader. The
    // page-fault handler treats faults in [stack_base - GUARD_SIZE, stack_base)
    // as stack overflow rather than a generic segfault.
    stack_base: usize = 0, // (c) set at exec
    // Cycles spent descheduled inside the current syscall — bumped by blocking
    // primitives (yield/sleep) and subtracted by doSyscall so the syscall
    // counter reflects CPU time, not wall time.
    perf_gap_cyc: u64 = 0,
    // --- Process tree + exit/wait (Task #73) ---
    // 0 means "no parent" (kernel-spawned, e.g. desktop). When this process
    // exits, killProcess/destroyCurrent looks for procs[parent_pid] with a
    // matching wait_kind == .waitpid and wakes it.
    parent_pid: u8 = 0, // (c) set at create/fork
    // Exit status reported via sysWaitpid. Valid only when state == .zombie.
    exit_status: u32 = 0,
    // Generic blocking primitive (used by waitpid + pipe.read/write).
    // Scheduler skips PCBs with wait_kind != .none.
    wait_kind: WaitKind = .none, // (a) blockOn writes; wake() reads cross-CPU
    wait_target: u32 = 0, // (a) read by wake() to match waiters
    // --- POSIX signals (src/signals.zig) ---
    // Pending bitmap — bit N = signal N is pending. Cleared when delivered.
    // u32 caps us at NSIG=32 which matches POSIX 1..31; widening to u64 +
    // rt-signals is a future tunable in config.zig.
    pending_signals: u32 = 0, // (a) atomic OR by signal sender (any CPU)
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

    // --- Job control (POSIX stop/cont) ----------------------------------
    // True while job-control-stopped (default action of SIGSTOP/SIGTSTP/
    // SIGTTIN/SIGTTOU). pickNext skips a job_stopped pid so it burns zero CPU,
    // but the task stays in a NORMAL runnable state (.running→.ready), never
    // .sleeping — flipping a still-running, mid-delivery task to .sleeping is
    // the "running-but-marked-sleeping" double-dispatch hazard the blockOn
    // idiom avoids by descheduling in the same breath, which we can't do from
    // the IRQ-return delivery path (handleIRQ0's tail is not yield-safe). See
    // signals.stopForJobControl. Cleared by SIGCONT (resume) or SIGKILL (so the
    // task can run far enough to die), both in signals.send(). Atomic: set by
    // the stopping thread at its own delivery point; cleared by a signal sender
    // on any CPU; read by the picker on any CPU.
    job_stopped: bool = false, // (a)
    // Signal number of the current/last stop — for a parent's waitpid(WUNTRACED)
    // WIFSTOPPED status once that's wired up. 0 = never stopped. Plain (non-(a))
    // access is intentional: it's a single byte (atomic on x86), written only by
    // the stopping thread / a remote resumer alongside the seq_cst job_stopped
    // store-load that orders them, and read only by the not-yet-wired waitpid.
    stop_signo: u8 = 0,

    // --- Threads (sysClone) ---------------------------------------------
    // Thread group ID = pid of the lead thread that started the process.
    // Threads spawned via sysClone copy the parent's tgid; lead-thread
    // PCBs have tgid == self_pid. Per-process state — lazy_regions for
    // shared mmap, fd_table, etc. — is owned by `procs[tgid]`. The page
    // fault handler reads `procs[pcb.tgid].lazy_regions` so all threads
    // see the same mmap'd address space.
    //
    // 0xFF means "not assigned yet"; create() and clone() fill it in.
    tgid: u8 = 0xFF, // (c) set at create/clone

    // --- Sessions / process groups (POSIX setsid / setpgid) -------------
    // Process group ID = pid of the group leader. Default fill-in (by
    // process.create) is self_pid (own group). fork() and sysExec()
    // inherit parent's pgid; setpgid() moves into a different group;
    // setsid() makes the caller a group AND session leader (pgid = sid =
    // self_pid). Used for kill(-PID) → "signal whole group", for shell
    // job control's foreground-group concept, and for daemons that detach
    // from the parent shell's session via setsid.
    pgid: u8 = 0, // (c) inherited or set by setpgid/setsid
    // Session ID = pid of the session leader. Boot session is whatever sid
    // the desktop kernel-task ends up with (it's never set explicitly, so
    // its children inherit the create()-default of self_pid). User
    // sessions are created by setsid(): caller's sid becomes its own pid,
    // and it's no longer in any other process group. Daemons run their
    // own session so closing the parent shell's session leader doesn't
    // SIGHUP them.
    sid: u8 = 0, // (c) inherited or set by setsid

    // Per-thread TLS base (written to IA32_FS_BASE on dispatch). 0 = no
    // TLS / inherit. Set by sysSetTls.
    fs_base: u64 = 0,
    /// ABI personality of this process. .native = zigos's own syscall ABI
    /// (3×u32 args, native numbers) — the default. .linux = an unmodified
    /// Linux x86-64 binary (6×u64 args, Linux numbers, SysV initial stack);
    /// doSyscall reroutes these to syscall/linux.zig. Set by the Linux ELF
    /// load path and inherited across fork. (`Personality` is module-level.)
    personality: Personality = .native,
    // Userspace tid pointer — when this thread exits, futex-wake any
    // thread joining on this address. 0 = no join address.
    clear_child_tid: u32 = 0,
    // Per-thread snapshot of `per_cpu_user_rsp[cpu]`. The syscall entry
    // stub stashes the user RSP into the per-CPU slot; if this thread is
    // preempted mid-syscall and another thread on the same CPU enters its
    // own syscall, the per-CPU slot is overwritten. Schedule saves the
    // slot here on switch-out and restores from here on switch-in so each
    // thread's sysret pops the right user RSP.
    user_rsp_save: u64 = 0, // (p:rq.lock) switchTo saves on switch-out

    // PCID for this address space (CR4.PCIDE). 0 = no tagging (kernel
    // tasks or PCID feature unavailable). User PCBs get a non-zero PCID
    // from `pcid.alloc` when their page_dir_phys is assigned and free it
    // on destroyAddressSpace. The schedule path uses pcid + the per-CPU
    // generation tracker to set CR3 bit 63 (preserve-TLB) on reloads.
    pcid: u16 = 0, // (c) pcid.alloc in createAddressSpace; RO after

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
    is_idle: bool = false, // (c) set at idle-PCB creation
    // Which CPU owns this idle PCB. pickNext only picks an idle PCB when
    // cpu.cpu_id == idle_cpu — prevents two CPUs from racing onto the
    // same idle kstack (the bug we observed before per-CPU idle existed).
    idle_cpu: u8 = 0xFF, // (c)
    // CPU pin for non-idle kernel tasks (desktop). Only this CPU picks
    // them. 0xFF = unpinned (normal user task — schedulable anywhere).
    // Without this, an AP can pick the desktop kernel task (its priority
    // is higher than user tasks), causing two CPUs to run desktop on
    // its single kstack and trip BSP-only assertions. Set by
    // createKernelTask from its `cpu_id` arg.
    pinned_cpu: u8 = 0xFF, // (c)

    // --- Phase 1 runqueue parallel-tracking (scheduler rewrite) -----------
    // Which CPU's `runqueue` this PCB is enqueued on when state == .ready.
    // Set ONCE at create() via `assignInitialCpu` (round-robin for plain
    // user tasks; copies idle_cpu / pinned_cpu when those are set). Phase
    // 4's load balancer will mutate this under both rq.lock acquisitions.
    // 0xFF = not yet assigned (between allocSlot and the post-init assign).
    assigned_cpu: u8 = 0xFF, // (c) Phase 1; will become (p:rq.lock) in Phase 4 balancer
    // Cross-CPU exit signal. The killer sets this true atomically + IPIs
    // the assigned_cpu; that CPU's schedule() observes the flag on its
    // own current task and tears self down on its own kstack — closing
    // the kill-vs-save race without the dead-letter machinery. Phase 1
    // only stores the field; the consumer lands in Phase 2's cutover.
    exit_requested: bool = false, // (a) cross-CPU; set by killer, observed in schedule()
    // Teardown claim mark (lifecycle.claimTeardown). Two roles:
    //   1. Set under teardown_count_lock before counting surviving group
    //      members, so concurrent teardowns of two members can't BOTH see
    //      "someone else is alive" (AS leaked) or BOTH see "I'm last"
    //      (double destroyAddressSpace).
    //   2. Gates schedule()'s exit_requested escalation: teardown can reach
    //      schedule() (GPU ctxDestroy contending ctrl_lock → blockOnMutex →
    //      yield), and without this gate the still-set exit_requested would
    //      re-enter destroyCurrentWithStatus mid-teardown.
    // Cleared on slot reuse by resetPcbExceptState.
    teardown_marked: bool = false, // (a) set under lifecycle.teardown_count_lock; read in schedule()

    // --- CFS-style vruntime (scheduler rewrite, post-Phase 7) -------------
    // Accumulated CPU "fair-share" time in ticks. Bumped by accountRunningTick
    // each tick this PCB is currently running, scaled by the inverse of its
    // weight so that lower-nice (higher-priority) tasks accumulate vruntime
    // slower → get picked more often within their band. Pickers select the
    // lowest vruntime within each priority band.
    vruntime: u64 = 0, // (p:rq.lock) accountRunningTick + rqEnter / pickNext
    // Tick at which the current run-slice began (set by schedule() when
    // this PCB transitions to .running). On the next preempt or
    // checkPreempt firing, `tick_count - slice_start_tick` is the slice
    // length used for ideal_runtime gating.
    slice_start_tick: u64 = 0, // (p:rq.lock)
    // Linux-style nice value, range -20..19 (defaults to 0). Lower = more
    // CPU share, higher = less. Maps to a weight via NICE_WEIGHTS; vruntime
    // increment per tick = NICE_0_WEIGHT / weight[20+nice]. So nice=-20
    // (weight 88761) consumes vruntime ~12× slower than nice=0 (weight
    // 1024); nice=19 (weight 15) consumes ~68× faster. Within a priority
    // band, this lets userspace fine-tune CPU share without changing the
    // band. setpriority(#47) still picks the BAND; sysSetNice (#101) picks
    // the WEIGHT within the band.
    nice: i8 = 0, // (p:rq.lock)

    // --- Accounting (process accounting infra) ----------------------------
    // Counters maintained by scheduler / page-fault handler / syscall
    // dispatch / vmm.mapUserPage. Read by sysProcessList for sysmon. All
    // monotonically-increasing except `acct_current_rss` which goes both
    // ways. None of these participate in correctness — purely diagnostic.
    /// Total scheduler ticks ever consumed by this PCB. One tick = one
    /// timer-IRQ interval (LAPIC tick). Add `acct_cpu_ticks * tick_ms`
    /// to get wall-clock CPU time.
    /// (p:owning-cpu-cli) Bumped from IRQ0 on the CPU running this PCB.
    /// /proc/stat reader does a plain torn-tolerant 64-bit read (x86_64
    /// aligned u64 loads are atomic at the ISA level; snapshot may miss
    /// <1 tick — acceptable for human display).
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
    /// Tick at which this PCB became a zombie (stamped in tearDownTask).
    /// The stale-zombie sweep ages from THIS — it used to age from
    /// acct_start_tick (creation), which gave any process that had lived
    /// longer than the 30 s threshold a ZERO-second grace window between
    /// exit and force-reap, racing the parent's waitpid out of its status.
    death_tick: u64 = 0,

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

// Per-region demand-paging descriptor. Stored inside `PCB.lazy_regions`;
// all field reads/writes go through that array, so the access discipline
// is `(p:as_lock)` inherited from the array's annotation.
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
    // Shared-anon region id (POSIX MAP_SHARED|MAP_ANONYMOUS). When not
    // SHM_INVALID, the page-fault handler maps `shm.frameAt(shm_id, page_idx)`
    // instead of fresh-allocating a private zero page. fork() bumps the
    // region's refcount; munmap / teardown decrements.
    shm_id: u32 = 0xFFFFFFFF,
    // File-backed-via-page-cache region (currently ext2 file mmap). When
    // cache_inode != 0 the page-fault handler serves each page from the unified
    // page cache (mm/page_cache.zig) keyed on (inode, cache_off + (va - start)),
    // mapped read-only + COW: reads SHARE one physical frame across mappers; a
    // write COW-diverges into a private copy. No eager buffer (buf_owned stays
    // false), so teardown is the ordinary per-PTE refcount drop. Inherited by
    // value on fork; cleared on munmap of the region.
    cache_inode: u32 = 0, // 0 = not cache-backed
    cache_off: u64 = 0, // file byte offset corresponding to `start`
    // MAP_SHARED file mapping (Slice 3c). When cache_inode != 0 AND this is set,
    // pages map the shared cache frame WRITABLE (not RO+COW): writes land in the
    // shared page — visible to every other mapper and to read() — and are
    // written back to disk on msync()/munmap() (page_cache dirty tracking +
    // vfs.syncCacheFile). When cache_inode != 0 and this is false, the region is
    // the older RO+COW private mapping. Inherited by value on fork; the COW hatch
    // (fault.zig handleCowFault) keeps a forked shared page shared rather than
    // copying it. Ignored when cache_inode == 0.
    cache_shared: bool = false,
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

/// Per-CPU kill-kick (and any wake-IPI reusing this vector) receive count.
/// Read by debug CLI to compare against virtio_gpu_wake_ipis_sent — if
/// sent grows but receive doesn't grow on cpu1, IPI delivery is broken
/// under the current hypervisor. If both grow but cube still hangs, the
/// broken link is later in the schedule()/iretq path.
///
/// STAYS in process.zig (instead of sched.zig where killKickHandler /
/// wakeOnlyHandler live) because external readers (cli.zig,
/// virtio_gpu.zig) consume them as `process.X[idx]`. Zig re-exports
/// (`pub const X = mod.X`) copy a var's value at comptime — they don't
/// re-expose the mutable storage — so moving the array would silently
/// break those readers. The IPI handlers in sched.zig bump these via
/// `process.kick_handler_runs[idx]` / `process.wake_handler_runs[idx]`.
pub var kick_handler_runs: [smp.MAX_CPUS]u64 = blk: {
    var x: [smp.MAX_CPUS]u64 = undefined;
    for (&x) |*c| c.* = 0;
    break :blk x;
};
pub var wake_handler_runs: [smp.MAX_CPUS]u64 = blk: {
    var x: [smp.MAX_CPUS]u64 = undefined;
    for (&x) |*c| c.* = 0;
    break :blk x;
};

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
    const pmm = @import("../mm/pmm.zig");
    const paging = @import("../mm/paging.zig");
    // Allocate the kstack pool from PMM as ONE contiguous block (was static
    // BSS). Contiguous so the physmap VA is linear → slot i at base + i*SLOT,
    // identical to the old array math. At boot the free list is pristine, so a
    // multi-MB contiguous block is readily available.
    const frames: u32 = @intCast(KSTACK_POOL_BYTES / 4096);
    const block_phys = pmm.allocContiguous(frames) orelse {
        debug.klog("[proc] FATAL: kstack pool alloc failed ({d} frames / {d} KB)\n", .{ frames, KSTACK_POOL_BYTES / 1024 });
        @panic("kstack pool allocation failed");
    };
    kstack_pool_phys_base = block_phys;
    const region_va = paging.physToVirt(block_phys);
    kstack_pool = @ptrFromInt(region_va);
    // BSS was zero-initialized; preserve that — the kstack scanners and the
    // base canary both read these bytes.
    @memset(@as([*]u8, @ptrFromInt(region_va))[0..KSTACK_POOL_BYTES], 0);
    debug.klog("[proc] kstack pool: {d} slots PMM-backed @ phys 0x{X} va 0x{X} ({d} KB)\n", .{ MAX_PROCS, block_phys, region_va, KSTACK_POOL_BYTES / 1024 });

    // Punch the unmapped guard page at the bottom of every slot so a stack
    // overflow #PFs (a kernel-mode not-present fault → fatal autopsy, since the
    // demand-pager only services user-mode faults). UEFI carve-out preserved:
    // the firmware's huge-page split corrupts under PMM-allocated PT pages (see
    // history) so UEFI runs canary-only, exactly as before — but it still gets
    // the PMM-backing (and thus the BSS savings) above.
    //
    // PREMISE SHIFT (2026-06-04): the pool used to live in the PML4[511] image
    // window (2 MB pages → a single 2MB→4KB split). It's now in the physmap
    // (PML4[256]), which boot.asm maps with 1 GB pages on BOTH bootloaders, so
    // Multiboot now exercises the SAME 1GB→2MB→4KB triple-split the UEFI
    // carve-out blames. splitToPte handles it, but the first guard install is
    // the thing to boot-verify on Multiboot (triple-fault here = the 1GB-split
    // PT page, not firmware).
    if (@import("../boot/boot_info.zig").is_uefi) {
        debug.klog("[proc] kstack guards disabled on UEFI (see comment)\n", .{});
        return;
    }
    for (0..MAX_PROCS) |i| {
        const slot_base = region_va + i * KSTACK_SLOT_SIZE;
        if (!paging.installGuardPage(slot_base)) {
            debug.klog("[proc] guard page install failed for slot {d} @ 0x{X}\n", .{ i, slot_base });
        }
    }
}

// =============================================================================
// P4: base-of-kstack canary (2026-06-04 debug-infra pass)
// =============================================================================
//
// The kesp / iretq / saved-RIP guards all watch the switch + interrupt
// frames near the TOP of each kernel stack. Nothing watched the BASE. A deep
// overflow (KSTACK_SIZE's history in config.zig is a list of these — RSA
// modpow overran 32 KB and wrote modulus bytes over a saved RIP) or a runaway
// write that walks DOWN the stack clobbers the lowest qword, just above the
// unmapped guard page. We plant a per-pid magic there at create and verify it
// at every dispatch: a silent near-overflow becomes a localized panic (which
// pid, which CPU, with a save-trace) instead of a wild jump hours later. The
// pmm/desc canaries don't cover kstacks — this closes that gap. Compile out
// via STACK_CANARY_ENABLE.
pub const STACK_CANARY_ENABLE: bool = true;
var stack_canary_miss: u64 = 0;

/// Per-pid magic, so a cross-stack wild write carrying another task's canary
/// value still mismatches. High bits are a fixed, unlikely-natural value.
pub inline fn stackCanaryValue(pid: usize) u64 {
    return 0xCA11AB1E_5AFE_0000 ^ @as(u64, pid);
}

/// Address of the canary word: the lowest qword of the body, just above the
/// 4 KB guard page. Always-mapped BSS for pool-backed stacks.
inline fn stackCanaryAddr(pid: usize) usize {
    return @intFromPtr(&kstack_pool[pid]) + KSTACK_GUARD_SIZE;
}

/// True iff `pid` runs on its own pool slot (vs a heap-backed kstack of
/// non-default size, whose true base isn't top-KSTACK_SIZE — we skip those).
inline fn kstackPoolBacked(pid: usize) bool {
    return procs[pid].kernel_stack_top ==
        @intFromPtr(&kstack_pool[pid]) + KSTACK_SLOT_SIZE;
}

/// Plant (or refresh) `pid`'s base canary. Called at every create site so a
/// reused slot starts each life clean. No-op for non-pool-backed stacks. MUST
/// run after kernel_stack_top is assigned (the pool-backed gate reads it).
pub fn plantStackCanary(pid: usize) void {
    if (!STACK_CANARY_ENABLE) return;
    if (pid >= MAX_PROCS) return;
    if (!kstackPoolBacked(pid)) return;
    @as(*u64, @ptrFromInt(stackCanaryAddr(pid))).* = stackCanaryValue(pid);
}

/// Verify `pid`'s base canary. Returns true when intact OR not-applicable
/// (disabled / never-created / heap-backed); false ONLY on a real mismatch.
/// Gated on expected_kstack_tops != 0 AND pool-backed, so it can fire only for
/// a properly-created pool task — never a false positive on a bootstrap or
/// unused slot. The canary address is always-mapped BSS, so the read can't
/// fault.
pub inline fn checkStackCanary(pid: usize) bool {
    if (!STACK_CANARY_ENABLE) return true;
    if (pid >= MAX_PROCS) return true;
    if (@atomicLoad(usize, &expected_kstack_tops[pid], .acquire) == 0) return true;
    if (!kstackPoolBacked(pid)) return true;
    const ok = @as(*const u64, @ptrFromInt(stackCanaryAddr(pid))).* == stackCanaryValue(pid);
    if (!ok) _ = @atomicRmw(u64, &stack_canary_miss, .Add, 1, .monotonic);
    return ok;
}

/// Running count of canary mismatches seen at dispatch. Surfaced in the
/// [diag-hb] heartbeat so a near-miss that somehow didn't panic is still a
/// visible metric.
pub fn stackCanaryMismatches() u64 {
    return @atomicLoad(u64, &stack_canary_miss, .monotonic);
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


const ProcessInfo = struct { kernel_esp: usize, kernel_stack_top: usize };

pub fn getProcessInfo(pid: usize) ProcessInfo {
    return .{ .kernel_esp = procs[pid].kernel_esp, .kernel_stack_top = procs[pid].kernel_stack_top };
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

/// ETXTBSY oracle: is `inum` the executable image of any live process?
/// Walks procs[] for a slot whose text_inum matches (skipping slots without a
/// loaded-and-running image: .unused = free, .loading = text not mapped yet,
/// .zombie = execution already ended). Used by vfs.write and ext2.truncate to
/// refuse mutating a file that's currently being executed — POSIX ETXTBSY.
/// Inode-keyed, so path aliases (/bin/redteam.elf vs //bin//redteam.elf)
/// collapse to the same identity. O(MAX_PROCS) reads, no lock: text_inum is
/// (c) set-once-at-load, and a single missed/extra write is benign here (the
/// harness scratch-file fence is the belt to this suspenders). (2026-06-04)
pub fn isTextBusy(inum: u32) bool {
    if (inum == 0) return false;
    for (&procs) |*p| {
        const st = p.state;
        if (st == .unused or st == .loading or st == .zombie) continue;
        if (p.text_inum == inum) return true;
    }
    return false;
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

// --- Scheduler / dispatch / block-wake — moved to sched.zig (#810) ---
//
// Functions: setState, schedule, pickNext, checkPreempt, migrate,
// loadBalance, setAffinity, getAffinity, assignInitialCpu, rqAudit,
// killKickHandler, wakeOnlyHandler, initKillKickIpi, initWakeIpi,
// kickVector, wakeVector, enterFirstTask, enterFirstTaskAp,
// blockOn, blockOnInterruptible, blockOnFutex, blockOnMutex,
// blockOnSwapEvict, wake, wakeMutexWaiters, wakeSwapEvictWaiters,
// wakeExpired, deliverDueAlarms, kernelSleepMs.
// Types: BlockResult, FutexResult.
// Vars: setstate_in_flight (pub, internal use only — no external readers).
// Note: `kick_handler_runs` / `wake_handler_runs` arrays stay above in
// THIS file (see comment there) — sched.zig writes to them via
// `process.X[idx]`.
pub const setState = @import("sched.zig").setState;
pub const schedule = @import("sched.zig").schedule;
pub const pickNext = @import("sched.zig").pickNext;
pub const checkPreempt = @import("sched.zig").checkPreempt;
pub const migrate = @import("sched.zig").migrate;
pub const loadBalance = @import("sched.zig").loadBalance;
pub const tryStealWork = @import("sched.zig").tryStealWork;
pub const setAffinity = @import("sched.zig").setAffinity;
pub const getAffinity = @import("sched.zig").getAffinity;
pub const assignInitialCpu = @import("sched.zig").assignInitialCpu;
pub const rqAudit = @import("sched.zig").rqAudit;
pub const initKillKickIpi = @import("sched.zig").initKillKickIpi;
pub const initWakeIpi = @import("sched.zig").initWakeIpi;
pub const kickVector = @import("sched.zig").kickVector;
pub const kickReschedule = @import("sched.zig").kickReschedule;
pub const wakeVector = @import("sched.zig").wakeVector;
pub const enterFirstTask = @import("sched.zig").enterFirstTask;
pub const enterFirstTaskAp = @import("sched.zig").enterFirstTaskAp;
pub const blockOn = @import("sched.zig").blockOn;
pub const blockOnInterruptible = @import("sched.zig").blockOnInterruptible;
pub const blockOnFutex = @import("sched.zig").blockOnFutex;
pub const blockOnMutex = @import("sched.zig").blockOnMutex;
pub const blockOnSwapEvict = @import("sched.zig").blockOnSwapEvict;
pub const wake = @import("sched.zig").wake;
pub const wakeMutexWaiters = @import("sched.zig").wakeMutexWaiters;
pub const wakeSwapEvictWaiters = @import("sched.zig").wakeSwapEvictWaiters;
pub const wakeIoUringWorker = @import("sched.zig").wakeIoUringWorker;
pub const wakeIoUringCqWaiters = @import("sched.zig").wakeIoUringCqWaiters;
pub const wakeExpired = @import("sched.zig").wakeExpired;
pub const wakeHiresExpired = @import("sched.zig").wakeHiresExpired;
pub const nextHiresTsc = @import("sched.zig").nextHiresTsc;
pub const deliverDueAlarms = @import("sched.zig").deliverDueAlarms;
pub const kernelSleepMs = @import("sched.zig").kernelSleepMs;
pub const BlockResult = @import("sched.zig").BlockResult;
pub const FutexResult = @import("sched.zig").FutexResult;

// --- Process lifecycle — moved to lifecycle.zig (#810) ---
pub const create = @import("lifecycle.zig").create;
pub const countThreadsInGroup = @import("lifecycle.zig").countThreadsInGroup;
pub const cloneCurrent = @import("lifecycle.zig").cloneCurrent;
pub const forkCurrent = @import("lifecycle.zig").forkCurrent;
pub const createKernelIdle = @import("lifecycle.zig").createKernelIdle;
pub const resetKernelIdleForResume = @import("lifecycle.zig").resetKernelIdleForResume;
pub const createIdleProcess = @import("lifecycle.zig").createIdleProcess;
pub const createKernelTask = @import("lifecycle.zig").createKernelTask;
pub const setInflightSlot = @import("lifecycle.zig").setInflightSlot;
pub const clearInflightSlot = @import("lifecycle.zig").clearInflightSlot;
pub const reclaimInflightSlot = @import("lifecycle.zig").reclaimInflightSlot;
pub const killProcessWithStatus = @import("lifecycle.zig").killProcessWithStatus;
pub const killProcess = @import("lifecycle.zig").killProcess;
pub const killThreadGroup = @import("lifecycle.zig").killThreadGroup;
pub const reparentChildren = @import("lifecycle.zig").reparentChildren;
pub const maybeReapZombies = @import("lifecycle.zig").maybeReapZombies;
pub const reapStaleZombies = @import("lifecycle.zig").reapStaleZombies;
pub const destroyCurrentWithStatus = @import("lifecycle.zig").destroyCurrentWithStatus;
pub const destroyCurrentGraceful = @import("lifecycle.zig").destroyCurrentGraceful;
pub const destroyCurrent = @import("lifecycle.zig").destroyCurrent;
pub const reapZombie = @import("lifecycle.zig").reapZombie;
pub const findZombieChild = @import("lifecycle.zig").findZombieChild;
// Internal-only helpers (allocSlot, resetPcbExceptState, kernelIdle,
// waitForPidOffCpu, closePipeFds, parentIsWaiting, TerminateOp,
// tearDownTask, freeElfBuf) live only in lifecycle.zig — no re-export.

// --- Page fault + lazy regions + swap-in — moved to fault.zig (#810) ---
pub const addLazyRegion = @import("fault.zig").addLazyRegion;
pub const addLazyRegionWithSource = @import("fault.zig").addLazyRegionWithSource;
pub const ensureUserRangeWritable = @import("fault.zig").ensureUserRangeWritable;
pub const ensureUserRangeWritableFor = @import("fault.zig").ensureUserRangeWritableFor;
pub const handleUserPageFault = @import("fault.zig").handleUserPageFault;
pub const prefaultUserRange = @import("fault.zig").prefaultUserRange;
pub const allCurrentUserPagesMapped = @import("fault.zig").allCurrentUserPagesMapped;


pub fn setName(pid: u8, name: []const u8) void {
    const len = @min(name.len, 16);
    @memcpy(procs[pid].name[0..len], name[0..len]);
    procs[pid].name_len = @intCast(len);
}

/// Fill `pcb.argv` from a program name + the raw exec string. argv[0] is the
/// bare program name (no `.elf`); argv[1..] are space-separated tokens from
/// `raw` starting after `fname_len`. Tokens longer than MAX_ARG_LEN are
/// truncated; argc is capped at MAX_ARGS. Lives here (not in the syscall
/// layer) so both sysExec and elf_loader.loadAndStart can populate argv
/// before a Linux binary's SysV initial stack is built.
pub fn populateArgv(
    pcb: *PCB,
    prog_name: []const u8,
    raw: []const u8,
    fname_len: usize,
) void {
    // argv[0]
    const n0 = @min(prog_name.len, @as(usize, config.MAX_ARG_LEN));
    @memcpy(pcb.argv[0][0..n0], prog_name[0..n0]);
    pcb.arg_lens[0] = @intCast(n0);
    pcb.argc = 1;

    // argv[1..]: walk the bytes after the program name, splitting on spaces.
    var i: usize = if (fname_len < raw.len) fname_len + 1 else raw.len;
    while (i < raw.len and pcb.argc < config.MAX_ARGS) {
        while (i < raw.len and raw[i] == ' ') : (i += 1) {}
        if (i >= raw.len) break;
        const start = i;
        while (i < raw.len and raw[i] != ' ') : (i += 1) {}
        const tok_len = @min(i - start, @as(usize, config.MAX_ARG_LEN));
        const slot = pcb.argc;
        @memcpy(pcb.argv[slot][0..tok_len], raw[start..][0..tok_len]);
        pcb.arg_lens[slot] = @intCast(tok_len);
        pcb.argc += 1;
    }
}

pub fn getName(pid: u8) []const u8 {
    return procs[pid].name[0..procs[pid].name_len];
}
