const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");
const apic = @import("../irq/apic.zig");
const acpi = @import("../acpi/acpi.zig");
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");
const gdt = @import("arch/gdt.zig");
const msr = @import("arch/msr.zig");
const cpu_state = @import("cpu_state.zig");
const delay = @import("../time/delay.zig");
const vfs = @import("../fs/vfs.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const process = @import("../proc/process.zig");
const symbols = @import("../debug/symbols.zig");
const std = @import("std");

pub const MAX_CPUS = 32;

/// Per-CPU PMM magazine cache capacity (frames). Must match `pmm.CACHE_SIZE`.
pub const PMM_CACHE_SIZE: u32 = 32;

/// Per-CPU VFS path-resolution L1 capacity. 4 slots is enough to cover the
/// hot working set for typical workloads (httpd serving N pages, shell
/// repeatedly exec'ing /bin/*, app launches): each open() picks the same
/// few paths over and over. Bigger would just waste cache lines.
pub const PATH_L1_SIZE: u8 = 4;
/// Max cached path length. Longer paths bypass the cache entirely. Almost
/// every real path in ZigOS is well under this — `/bin/files.elf`,
/// `/share/index.html`, `/etc/zigos.conf`. Capping keeps the per-CPU
/// footprint at ~512 B.
pub const PATH_CACHE_PATH_MAX: u8 = 96;

/// Storage for one path-cache L1 / L2 slot. Lives here (not path_cache.zig)
/// because CpuLocal needs a concrete type and path_cache.zig imports smp —
/// flipping the dependency would create a cycle. path_cache.zig reads
/// `cpu.path_l1[i].tag` directly via the field.
pub const PathCacheEntry = struct {
    /// 0 = empty, 1 = ext2, 2 = fat32. Matches path_cache.FsTag.
    tag: u8 = 0,
    path_len: u8 = 0,
    path: [PATH_CACHE_PATH_MAX]u8 = [_]u8{0} ** PATH_CACHE_PATH_MAX,
    payload: [16]u8 = [_]u8{0} ** 16,
    /// Stored at insert; compared against `path_cache.global_epoch` on
    /// every L1 lookup. Bumped epoch ⇒ all L1 entries become invisible
    /// without needing per-slot writes.
    epoch: u64 = 0,
};

/// `.ap`: an AP enters it from INIT-SIPI-SIPI and leaves it in long mode, in
/// the entry `arm` gave it.
const trampoline = @import("../boot/trampoline.zig");

pub const CpuLocal = struct {
    cpu_id: u8 = 0,
    lapic_id: u8 = 0,
    current_pid: ?usize = null,
    idle_pid: ?usize = null,
    gdt_entries: [7]u64 = undefined,
    gdt_ptr: gdt.GdtPtr = undefined,
    tss: gdt.Tss64 = .{},
    isr_stack: [16384]u8 align(16) = [_]u8{0} ** 16384,
    /// True from the moment apEntry starts running on this AP. Set BEFORE
    /// any other init work so we can distinguish "AP never started"
    /// (sipi_acked=false at timeout) from "AP started but hung in init"
    /// (sipi_acked=true, alive=false). Real-HW BIOS/MADT mismatches and
    /// INIT-SIPI timing bugs show up as the first; init-path bugs (page
    /// table walk, kasan, MSR write) show up as the second.
    ///
    /// Cross-CPU handshake flags. The booting AP publishes them with
    /// @atomicStore(.release); the BSP bring-up spin loop and aliveCpuCount()
    /// observe them with @atomicLoad(.acquire). The atomics matter in the BSP
    /// spin loop — a plain load there is legally hoistable (it only worked
    /// while the wait in the loop was an opaque call that forced a reload),
    /// and the release/acquire pair makes this AP's per-CPU init visible before
    /// the BSP counts it online. Both are write-once-then-stable, so the many
    /// steady-state `if (!cpu.alive)` readers elsewhere stay plain reads.
    sipi_acked: bool = false,
    alive: bool = false,
    /// Per-CPU scheduler lock. Replaces the old global sched_lock — one CPU's
    /// schedule() can run while another's is in progress without contention,
    /// and (more importantly) the lock no longer lives at a single shared BSS
    /// address where one stray write deadlocks every CPU. Same architectural
    /// pattern as the per-CPU LSTAR stubs that replaced GS_BASE: kill the
    /// dependency on a stateful global.
    sched_lock: @import("../proc/spinlock.zig").SpinLock align(64) = .{},
    /// Distinguishes a software-triggered `int $0x20` (sysYield, sysSleep,
    /// pipe block, sysWaitpid) from a real hardware LAPIC timer IRQ.
    /// sched_asm.softYield sets it and issues `int $0x20` under one cli;
    /// `handleIRQ0` reads it and clears it on entry. Without this we used
    /// `from_user` as a proxy (kernel-mode = software), which made
    /// `tick_count` stop advancing whenever BSP was busy in any kernel-mode
    /// task (FAT32 read, virtio-gpu flush) — symptom: UI freezes during
    /// long kernel work because polling/wakeExpired stop with it.
    /// (u: this CPU only) Set by int $0x20 issuers on the same CPU
    /// immediately before issuing the software interrupt; cleared by
    /// handleIRQ0 at entry. NEVER set or cleared from a peer CPU — peer
    /// access would race with the entry-clear and lose the yield signal.
    pending_soft_yield: bool = false,

    // (Phase 5 retired: save_in_flight_prev. Per-CPU dispatch + the
    // exit_requested-aware schedule + the schedule-side prev_save→null
    // when prev's state is .zombie/.unused all combined to make the
    // cross-CPU bracket unnecessary. The killer-vs-save race no longer
    // exists by construction.)
    //
    // (Removed earlier: scheduler_kesp / scheduler_kstack_top /
    // scheduler_active. The legacy "scheduler context" model is gone —
    // both BSP (desktop) and APs (idle) run as real per-CPU kernel-mode
    // tasks from the very first dispatch.)

    /// Per-CPU PMM magazine cache (Bonwick-style). Lets allocFrame /
    /// freeFrame skip the global pmm.lock on the hot path: cache hits read
    /// or write a local LIFO with IF=0 (no SMP coordination needed since
    /// the cache is per-CPU and IRQs are disabled across the access). Cache
    /// misses bulk-refill / bulk-drain in one global-lock acquisition.
    /// 64-byte aligned to keep the count + cache slots on dedicated cache
    /// lines (no false sharing with neighboring fields).
    /// PMM_CACHE_SIZE here MUST match `pmm.CACHE_SIZE` — comptime asserted
    /// from pmm.zig so a drift compile-errors instead of silently breaking.
    pmm_cache: [PMM_CACHE_SIZE]usize align(64) = .{0} ** PMM_CACHE_SIZE,
    pmm_cache_count: u8 = 0,

    /// Per-CPU VFS path-resolution L1 cache. Lockless on hit (cli serializes
    /// against IRQ-driven schedule on this CPU only — no SMP coordination
    /// needed since the slot array is per-CPU). Round-robin replacement via
    /// `path_l1_next`. Same architectural pattern as `pmm_cache`.
    path_l1: [PATH_L1_SIZE]PathCacheEntry align(64) = [_]PathCacheEntry{.{}} ** PATH_L1_SIZE,
    path_l1_next: u8 = 0,

    /// Per-CPU runqueue — pickNext dispatches from here. Three priority
    /// queues holding pids whose state == .ready and assigned_cpu == this
    /// cpu; `sched.rqAudit` cross-checks them against the PCB states. See
    /// src/proc/runqueue.zig.
    runqueue: @import("../proc/runqueue.zig").Rq align(64) = .{},

    /// Migration counters — bumped by `process.migrate` when this cpu is
    /// the source (migrations_out) or the destination (migrations_in) of
    /// a load-balancer move or sysSetAffinity-driven shift. Read by
    /// /proc/sched. Monotonic, never reset; cumulative since boot.
    migrations_in: u64 = 0,
    migrations_out: u64 = 0,
    /// Total schedule() invocations on this cpu. Bumped at the top of
    /// schedule(); read by /proc/sched. The existing perf counter tracks
    /// the same number but isn't exposed via a stable name — this one
    /// is the canonical source for /proc/sched.
    schedule_count: u64 = 0,

    /// Incremented on every IRQ0 firing on this CPU (real or soft yield).
    /// Watchdog peers compare deltas: if a peer's tick stops advancing for
    /// N seconds, that CPU is wedged with cli — broadcast NMI + autopsy.
    /// Without this, silent freezes (kernel running but cli'd in tight
    /// loop, 100% CPU, no log output) leave us blind.
    /// (a) Self-write is under cli but uses @atomicStore so peer
    /// @atomicLoads compose with the StoreLoad fence the load implies
    /// — without atomics a future LICM hoist across IRQ-entry would
    /// freeze the displayed value forever. Reader: watchdog.peerCheck.
    irq_tick_count: u64 = 0,
    /// Idle time: the CPU is idle exactly while its idle PCB is current.
    /// idle_cyc sums the closed idle stretches in TSC cycles, idle_since is
    /// the TSC at which the open one began (0 while a task runs). Written
    /// by noteIdleSwitch only, on this CPU with IRQs off, inside the
    /// idle_seq seqcount; read through idleCycles.
    idle_cyc: u64 = 0,
    idle_since: u64 = 0,
    idle_seq: u32 = 0,
    /// Watchdog scratch — last `peer.irq_tick_count` snapshot taken by this
    /// CPU's watchdog check, and how many consecutive 1s windows the peer
    /// hasn't advanced. Threshold-cross fires the watchdog autopsy.
    watchdog_peer_last_tick: u64 = 0,
    watchdog_peer_strikes: u8 = 0,

    /// MONITOR target for `kernelIdle`. MWAIT sleeps until either the
    /// monitored cache line is written or an interrupt fires; future
    /// cross-CPU "wake idle without IPI" paths can bump this word
    /// instead of sending a TLB-shootdown-class IPI. Aligned to 64 B so
    /// it occupies its own cache line (no spurious wakes from neighbor
    /// writes). Field unused unless `mwait.mwait_supported` is true.
    idle_monitor_word: u32 align(64) = 0,

    /// Set by IRQ handlers (currently nvmeIrqHandler) that wake tasks and
    /// want a reschedule on the way out without calling `schedule()` from
    /// within the IRQ context (which leaves the handler running on whatever
    /// kstack the IRQ inherited — a known cross-stack-aliasing risk; mirror-
    /// flip caught nvme corrupting pid 2's kesp+48 via this path on
    /// 2026-05-19). `DynIrqStub`'s epilogue calls `check_and_preempt_dynirq`
    /// which observes this flag, clears it, and calls `schedule()` from the
    /// stub's frame instead. Net effect: ~50µs wake-latency preserved
    /// without the cross-stack hazard.
    /// (u: this CPU only) Set by dyn-IRQ handler bodies running on this
    /// CPU's isr_stack with IF=0, and by handleIRQ0 for a tick inside a
    /// syscall body; consumed by check_and_preempt_dynirq in the DynIrqStub
    /// epilogue or by doSyscall's endBody, also on this CPU. NEVER set from
    /// a peer.
    dynirq_preempt_pending: bool = false,

    /// Bracket-marker for the schedule() transient demote window. Set to the
    /// outgoing pid right before `setState(prev, .ready)` in schedule(),
    /// cleared inside save_trace_record once switchTo's `movq %rsp, (%rdi)`
    /// has updated procs[prev].kernel_esp. While set, the pid's PCB has
    /// state=.ready but kernel_esp is STALE — *(kesp+48) still reflects the
    /// previous save's slot, which the still-running prev task is busily
    /// overwriting with whatever its current code path is doing (often
    /// 0xAAAAAAAAAAAAAAAA from Zig's ReleaseSafe undefined-init pattern).
    /// pcb_invariants skips the saved-RIP validation when any CPU has this
    /// set for the inspected pid, otherwise
    /// they false-fire on transient stack residue.
    ///   0xFFFF = no transient in progress on this CPU.
    /// 2026-05-19: introduced after pcb-invariant panic'd on
    /// pid=2 *(kesp+48)=AAAA during NVMe async I/O schedule-from-IRQ paths.
    scheduling_out_pid: u16 = 0xFFFF,

    /// Mirror of `scheduling_out_pid` for the INBOUND direction. Set after
    /// pickNext's `ready→running` CAS succeeds, cleared inside
    /// `setCurrentPid` once `cpu.current_pid` is updated. Between those
    /// two points the invariant "state==.running ⇔ some cpu owns it"
    /// transiently breaks: the pid's state byte says .running, but no
    /// CPU yet reports it as current. `pcb_invariants` skips its
    /// running-but-no-owner check when any CPU has this set for the
    /// inspected pid. 0xFFFF = no inbound transient on this CPU.
    /// 2026-05-19: introduced after pcb-invariant panic'd on pid=4
    /// during normal sysSleep/wake cycling, caught by cross-CPU scan.
    dispatching_in_pid: u16 = 0xFFFF,

    /// Symmetric partner of `dispatching_in_pid` for the OUTBOUND
    /// (destroy/exit) direction. In `destroyCurrent`'s self-destroy
    /// path, `setCurrentPid(cpu, null)` is called BEFORE the dying
    /// pid's state transitions away from `.running` (to `.zombie` /
    /// `.unused`). Between those two writes `procs[pid].state ==
    /// .running` but no CPU's `current_pid` claims it — a cross-CPU
    /// `pcb_invariants` scan would false-fire "state==.running but no
    /// owner". The destroyer claims this bracket before the
    /// `setCurrentPid` write and clears it after the `setState` lands;
    /// scans skip the running-owner check when any CPU has this set
    /// for the inspected pid. 0xFFFF = no outbound transient.
    /// 2026-05-20: added as the long-planned symmetric partner the
    /// inbound bracket was missing — exposed during Q1 port stress.
    dispatching_out_pid: u16 = 0xFFFF,

    /// Pending bottom-half (softirq) bitmask for this CPU — one bit per
    /// `softirq.Softirq`. Set by `softirq.raise` from any context (atomic OR,
    /// safe under IF=0); read-and-cleared by this CPU's `ksoftirqd` drain.
    /// Per-CPU so `raise` needs no global lock. (a) cross-context on one CPU.
    softirq_pending: u32 = 0,
    /// PID of this CPU's pinned `ksoftirqd` bottom-half task, or null until
    /// `softirq.startAll()` (called from smp.init) spawns it. `raise` wakes
    /// this pid; while null, the tick falls back to inline device sweeps.
    ksoftirqd_pid: ?usize = null,

    // Tripwire (task #226 lite). LAST field of CpuLocal. If anything writes
    // past the end of cpus[N] — overflow from neighboring data, wild
    // pointer that lands here, sched_lock-state-write that overran — the
    // magic value gets clobbered, and `verifyEndCanary()` traps on the next
    // IRQ/schedule entry with the call path still on the stack. Cheap: one
    // u64 cmp on the hot path. Update both `MAGIC` and the array initializer
    // if this changes.
    magic_end: u64 = MAGIC_END,
};

pub const MAGIC_END: u64 = 0xDEAD_C0FF_EEFA_CADE;

/// Verify the trailing canary on the calling CPU's CpuLocal slot. Call from
/// the entry of any function that runs on a fresh kernel context boundary
/// (handleIRQ0, handleException, schedule, pickNext). Cheap one-u64 compare;
/// on miss, dump everything and panic — kernel call stack still intact.
pub fn verifyEndCanary() void {
    const cpu = myCpu();
    const got = cpu.magic_end;
    if (got == MAGIC_END) return;

    // Guard against re-entry: a panic that calls back into something which
    // calls back into verifyEndCanary would loop. Stamp a sentinel; if we
    // see it on re-entry, just hlt.
    const sentinel: u64 = 0x12345678_BAAAAAD0;
    if (got == sentinel) {
        asm volatile ("cli\nhlt" ::: .{ .memory = true });
        unreachable;
    }
    cpu.magic_end = sentinel;

    serial.print("\n!!! CpuLocal end-canary clobbered (cpu={d}, lapic={d}) !!!\n", .{
        cpu.cpu_id, cpu.lapic_id,
    });
    serial.print("  cpu_struct = 0x{X:0>16}\n", .{@intFromPtr(cpu)});
    serial.print("  &magic_end = 0x{X:0>16}\n", .{@intFromPtr(&cpu.magic_end)});
    serial.print("  expected   = 0x{X:0>16}\n", .{MAGIC_END});
    serial.print("  got        = 0x{X:0>16}\n", .{got});

    @import("../debug/kdbg.zig").dumpAll();
    @panic("CpuLocal end-canary clobbered — wild write into per-CPU slot");
}

/// Per-CPU storage for syscall/entry.zig's fast path. Just one slot now:
/// the LSTAR stub also needs a transient place to spill the user RSP
/// before it switches to the kernel stack (cpus[N].tss.rsp0). The
/// kernel-stack-top itself lives in `cpus[N].tss.rsp0` — the canonical
/// TSS field the CPU hardware reads on IDT-gate entries — so syscall
/// entry and IDT-gate entry can no longer disagree about which kstack
/// to land on. (Previously this file declared a `per_cpu_asm` mirror
/// in `.kdata_protected`; the two-field design tore under nested
/// setTssRsp0 — cpu-alias FAIL 2026-05-17.)
///
/// per_cpu_user_rsp lives in ordinary BSS, not page-protected: it's
/// written on every syscall and a write-trap on the hot path would cost
/// the CR0.WP toggle.
pub export var per_cpu_user_rsp: [MAX_CPUS]u64 = [_]u64{0} ** MAX_CPUS;

// The per-CPU LSTAR syscall stub needs the address of cpus[0] in inline
// asm so it can compute `cpus + N*sizeOf(CpuLocal) + offsetOf(tss) +
// offsetOf(rsp0)` to load the kernel RSP — the same memory the CPU
// hardware reads on IDT-gate entries. Can't `export var cpus` directly:
// CpuLocal isn't extern-compatible (has `?usize` optionals + Zig-only
// SpinLock with align(64)). Instead, export a u64 holding
// `@intFromPtr(&cpus[0])`, stamped at boot in `init()`. The stub does a
// two-instruction load (`movq cpus_base(%rip), %rax; movq <off>(%rax),
// %rsp`) — one extra cycle, negligible on the syscall path. Eliminates
// the per_cpu_asm mirror that used to drift under nested setTssRsp0.
pub var cpus: [MAX_CPUS]CpuLocal = [_]CpuLocal{.{}} ** MAX_CPUS;
pub export var cpus_base: u64 = 0;

comptime {
    // tss.rsp0 is loaded as a single 8-byte `movq <offset>(%rip), %rsp` from
    // the syscall LSTAR stub. Intel SDM Vol 3A §8.1.1 guarantees atomicity
    // for cache-line-contained 8-byte stores on P6+; if the field straddles
    // a 64-byte boundary we lose that and a torn write becomes observable
    // on the syscall hot path. Assert it doesn't straddle.
    const off = @offsetOf(CpuLocal, "tss") + @offsetOf(gdt.Tss64, "rsp0");
    // CpuLocal has align(64) (from inner SpinLock), so cpus[N] is 64-aligned
    // for every N — the within-cache-line offset is the same for every CPU.
    const within = off & 63;
    if (within + 8 > 64) {
        @compileError("cpus[N].tss.rsp0 spans two cache lines — non-atomic 8-byte store on syscall path");
    }
}
pub var cpu_count: u8 = 1;
var smp_initialized: bool = false;

// IA32_TSC_AUX (msr.TSC_AUX) — `rdtscp` returns it in ECX with no VM exit.
// Each CPU stores its LAPIC id there (armTscAux, from claimSlot) and
// myCpuId() reads it back with rdtscp instead of the LAPIC ID register.
// Measured on zigvm (nested Hyper-V → KVM, x2APIC; benchCpuIdRead prints it
// every boot): 14–31k cycles per LAPIC ID read — `rdmsr 0x802` is an exit —
// against a few dozen per rdtscp, and a plain SpinLock.acquire, the Mutex
// fast path, every IRQ0 tick and every Deadline each pay one read.

/// True while every online CPU identifies itself through TSC_AUX. The BSP
/// sets it once its own round trip (wrmsr, rdtscp, compare) passed; a CPU
/// whose round trip fails clears it and everyone falls back to the LAPIC
/// ID register. Atomic: an AP can clear it while the BSP is running.
var cpu_id_via_aux: bool = false;
/// Sticky companion: some CPU's round trip failed — never re-enable (the
/// BSP re-arms on S3 resume and would otherwise flip the flag back on).
var tsc_aux_refused: bool = false;

/// This CPU's id — its LAPIC id, which is also its cpus[] index. One
/// rdtscp while TSC_AUX carries it, the LAPIC ID register otherwise; 0
/// before SMP init (single-threaded boot on the BSP, whose id is 0).
pub fn myCpuId() u8 {
    if (!smp_initialized) return 0;
    if (@atomicLoad(bool, &cpu_id_via_aux, .monotonic)) return @truncate(rdtscpAux());
    return @truncate(apic.getLapicId());
}

/// Get current CPU's local data
pub fn myCpu() *CpuLocal {
    if (!smp_initialized) return &cpus[0];
    const id = myCpuId();
    if (id >= MAX_CPUS) return &cpus[0];
    return &cpus[id];
}

/// The pid running on this CPU, null before its first dispatch. Read with
/// interrupts off: finding "this CPU" and reading its current_pid are two
/// steps, and a preemptible caller moved to another CPU in between would
/// read the pid of whatever now runs on the CPU it left. Use this, not
/// `myCpu().current_pid`, for "who am I".
pub fn currentPid() ?usize {
    var flags: u64 = undefined;
    // Memory clobbers keep the load between the two.
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
        :
        : .{ .memory = true });
    const pid = myCpu().current_pid;
    if (flags & 0x200 != 0) asm volatile ("sti" ::: .{ .memory = true });
    return pid;
}

/// Get BSP CPU data (always CPU 0)
pub fn bspCpu() *CpuLocal {
    return &cpus[0];
}

inline fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

/// The current_pid setter's hook: `cpu`'s idle PCB stops or starts being
/// current. Sampling which PCB a timer tick interrupts can't stand in for
/// this: soft yields are ticks too, all charged to the task that yields,
/// and a tickless idle CPU takes few real ones.
pub fn noteIdleSwitch(cpu: *CpuLocal, was_idle: bool, now_idle: bool) void {
    if (was_idle == now_idle) return;
    var flags: u64 = undefined;
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
    );
    const now = rdtsc();
    @atomicStore(u32, &cpu.idle_seq, cpu.idle_seq +% 1, .release);
    if (was_idle) {
        if (cpu.idle_since != 0 and now > cpu.idle_since) {
            @atomicStore(u64, &cpu.idle_cyc, cpu.idle_cyc +% (now - cpu.idle_since), .release);
        }
        @atomicStore(u64, &cpu.idle_since, 0, .release);
    } else {
        @atomicStore(u64, &cpu.idle_since, now, .release);
    }
    @atomicStore(u32, &cpu.idle_seq, cpu.idle_seq +% 1, .release);
    if (flags & 0x200 != 0) asm volatile ("sti");
}

/// TSC cycles `c` has spent idle up to `now`, a TSC value the caller read
/// (one value for all CPUs keeps their spans comparable). Retries are
/// bounded: a CPU halted by an NMI inside noteIdleSwitch leaves idle_seq
/// odd for good, and then the closed stretches alone have to do.
pub fn idleCycles(c: *const CpuLocal, now: u64) u64 {
    for (0..64) |_| {
        const seq = @atomicLoad(u32, &c.idle_seq, .acquire);
        if (seq & 1 == 0) {
            const closed = @atomicLoad(u64, &c.idle_cyc, .acquire);
            const since = @atomicLoad(u64, &c.idle_since, .acquire);
            if (@atomicLoad(u32, &c.idle_seq, .acquire) == seq) {
                return if (since != 0 and now > since) closed +% (now - since) else closed;
            }
        }
        std.atomic.spinLoopHint();
    }
    return @atomicLoad(u64, &c.idle_cyc, .acquire);
}

/// `rdtscp` — the TSC plus IA32_TSC_AUX in ECX, never a VM exit. Only the
/// AUX half is wanted: it carries this CPU's LAPIC id (armTscAux), the way
/// Linux keeps the CPU number there for getcpu. ONE asm output on purpose,
/// the TSC halves are clobbers: every multi-output inline asm returns an
/// LLVM literal struct type, and a `{i32, i32, i32}` the kernel had never
/// emitted before re-rolled the LLVM 20 "Invalid type" bitcode bug (round
/// 9, cold build) — see reference-llvm-anon-struct-bitcode-bug.
inline fn rdtscpAux() u32 {
    var aux: u32 = undefined;
    asm volatile ("rdtscp"
        : [aux] "={ecx}" (aux),
        :
        : .{ .rax = true, .rdx = true }
    );
    return aux;
}

/// CPUID.80000001H:EDX[27] — RDTSCP present.
fn hasRdtscp() bool {
    var a: u32 = undefined;
    var b: u32 = undefined;
    var c: u32 = undefined;
    var d: u32 = undefined;
    asm volatile ("cpuid"
        : [a] "={eax}" (a),
          [b] "={ebx}" (b),
          [c] "={ecx}" (c),
          [d] "={edx}" (d),
        : [leaf] "{eax}" (@as(u32, 0x8000_0001)),
          [sub] "{ecx}" (@as(u32, 0)),
    );
    return (d & (1 << 27)) != 0;
}

/// Boot-time diagnostic: what one CPU-id read costs on this host, both
/// ways. A LAPIC ID read (x2APIC: `rdmsr 0x802`; xAPIC: an MMIO load) is a
/// VM exit under nested virtualization — 14–31k cycles on zigvm against a
/// few dozen for rdtscp, the measurement that moved myCpuId() onto
/// TSC_AUX. Printed every boot so a host where the ratio changes, or a boot
/// where the round trip failed and myCpu fell back, shows in the log. Wall
/// time with IRQs on: a tick or a host pause inside a loop lands in the
/// figure, which is why it is a ratio, not a datasheet number. Short on
/// purpose: 1024 reads stay under ~70 ms even at 200k cycles per exit.
fn benchCpuIdRead() void {
    const reads: u32 = 1024;
    var sink: u64 = 0;
    var i: u32 = 0;
    const rdtscp_ok = hasRdtscp(); // CPUID is an exit too — keep it out of both windows
    const t0 = rdtsc();
    while (i < reads) : (i += 1) sink +%= apic.getLapicId();
    const t1 = rdtsc();
    if (rdtscp_ok) {
        i = 0;
        while (i < reads) : (i += 1) sink +%= rdtscpAux();
    }
    const t2 = rdtsc();
    asm volatile (""
        :
        : [s] "r" (sink),
    );
    debug.klog("[smp] cpu-id read cost: lapic-id {d} cyc, rdtscp {d} cyc ({s}, {d} reads each, wall); myCpu via {s}\n", .{
        (t1 -| t0) / reads,
        if (rdtscp_ok) (t2 -| t1) / reads else 0,
        if (apic.x2apic_active) "x2apic" else "xapic",
        reads,
        if (@atomicLoad(bool, &cpu_id_via_aux, .monotonic)) "tsc_aux" else "lapic-id",
    });
}

/// Count of CPUs marked alive (BSP + APs that came up). For boot summary.
/// Iterate by pointer — CpuLocal contains an aligned SpinLock that's not
/// trivially copyable in a for-by-value loop.
pub fn aliveCpuCount() usize {
    var n: usize = 0;
    for (&cpus) |*c| {
        if (@atomicLoad(bool, &c.alive, .acquire)) n += 1;
    }
    return n;
}

/// True if we're currently executing on the BSP (CPU 0).
pub fn isBSP() bool {
    if (!smp_initialized) return true;
    return myCpuId() == 0;
}

/// SMP-correctness guard: panic if a BSP-only function is invoked from an AP.
/// Cheap (one rdtscp) and only fires when an audit invariant is violated, so
/// we can sprinkle it on every "BSP-only by design" entry point. Catches the
/// class of bugs where code that mutates desktop/USB/keyboard/mouse state
/// silently runs on an AP and corrupts BSP-private structures.
pub fn assertBSP(comptime site: []const u8) void {
    if (!smp_initialized) return;
    const id = myCpuId();
    if (id != 0) {
        @import("../debug/serial.zig").print("\n[SMP-AUDIT] {s}: called from CPU {d}, must be BSP\n", .{ site, id });
        @panic("BSP-only function ran on AP — see [SMP-AUDIT] line above");
    }
}

/// Initialize SMP: set up BSP per-CPU data, boot APs
/// Build the list of AP LAPIC ids to bring up. With ACPI MADT we get a
/// definitive list of present, enabled processors (their APIC ids are NOT
/// guaranteed to be 0..N-1 — real boards have gaps from hyperthreading or
/// socket layout); without MADT we fall back to the historical 1..MAX_CPUS-1
/// probe. The BSP is excluded. Returns the count written into `out`. Shared by
/// the boot bring-up (`init`) and the S3-resume re-online (`reonlineApsForS3Resume`).
fn collectApIds(bsp_id: u8, out: *[MAX_CPUS]u8) usize {
    var ap_count: usize = 0;
    if (acpi.getMadt() != null) {
        // flags bit 0 = enabled, bit 1 = online-capable. Only include CPUs
        // explicitly marked enabled. Both legacy MadtLapic (type 0) and
        // MadtX2Apic (type 9) carry the same shape we care about; type 9 has a
        // wider id, so its entries are skipped if the id doesn't fit our
        // u8/MAX_CPUS-bounded array.
        var it = acpi.madtEntries();
        while (it.next()) |h| {
            var apic_id_u32: u32 = 0;
            var flags: u32 = 0;
            switch (@as(acpi.MadtType, @enumFromInt(h.entry_type))) {
                .processor_lapic => {
                    const e: *align(1) const acpi.MadtLapic = @ptrCast(h);
                    apic_id_u32 = e.apic_id;
                    flags = e.flags;
                },
                .processor_x2apic => {
                    const e: *align(1) const acpi.MadtX2Apic = @ptrCast(h);
                    apic_id_u32 = e.x2apic_id;
                    flags = e.flags;
                },
                else => continue,
            }
            if (flags & 1 == 0) continue;
            if (apic_id_u32 == bsp_id) continue;
            if (apic_id_u32 >= MAX_CPUS) continue;
            if (ap_count >= MAX_CPUS) continue;
            out[ap_count] = @intCast(apic_id_u32);
            ap_count += 1;
        }
        debug.klog("[smp] MADT lists {d} AP(s)\n", .{ap_count});
    } else {
        // Fallback probe path — still bounded by MAX_CPUS.
        var i: u8 = 1;
        while (i < MAX_CPUS) : (i += 1) {
            out[ap_count] = i;
            ap_count += 1;
        }
        debug.klog("[smp] no MADT — probing {d} AP slot(s)\n", .{ap_count});
    }
    return ap_count;
}

pub fn init() void {
    // Stamp the address of cpus[0] into the exported `cpus_base` slot so
    // the per-CPU LSTAR syscall stubs (syscall/entry.zig) can load the
    // kernel RSP from `cpus[N].tss.rsp0` via a two-instruction indirect
    // load. Must happen BEFORE any syscall can fire from userspace,
    // which can't happen until after smp.init returns (BSP idle + first
    // desktop dispatch are both later in main.zig).
    cpus_base = @intFromPtr(&cpus);

    // Register the per-CPU sched_lock family with WITNESS under ONE lock-order
    // class. Every CPU only ever acquires its own sched_lock (sched.zig
    // schedule()), so a single per-CPU held bit is exact — see
    // spinlock.registerLockClass. This is the high-value class: the scheduler
    // sits beneath the allocator/driver paths, exactly where a lock-order
    // reversal would wedge the box. Done here while single-threaded (covers
    // every boot-mode path below) and before any AP can run schedule().
    {
        const spinlock = @import("../proc/spinlock.zig");
        const sched_class = spinlock.registerLockClass("sched_lock", &cpus[0].sched_lock);
        if (sched_class != 0xFF) {
            var i: usize = 1;
            while (i < MAX_CPUS) : (i += 1) cpus[i].sched_lock.witness_class = sched_class;
        }
    }

    if (!apic.apic_active) {
        debug.klog("[smp] No APIC, SMP disabled\n", .{});
        return;
    }

    // cpus[0] IS the BSP everywhere — bspCpu(), isBSP(), claimSlot on the
    // BSP's paths, the TSC_AUX flag raised only by "cpu 0". A board whose
    // BSP carries another LAPIC id would split the BSP across two slots;
    // assertBSP would panic on the first BSP-only call anyway, so say it
    // here, once, with the reason.
    if (apic.getLapicId() != 0) @panic("smp: BSP LAPIC id != 0 — cpus[0] is the BSP by invariant (bspCpu/isBSP/S3/TSC_AUX)");

    // The BSP's entries of the per-CPU list that had to wait for the LAPIC.
    cpu_state.apply(.identity);
    @atomicStore(bool, &cpus[0].alive, true, .release);
    // From the boot GDT/TSS of gdt.init() to its own. On the shared one
    // every CPU's setTssRsp0 would write the same `tss`: an AP dispatching
    // a task would silently move the BSP's RSP0 onto that task's kstack,
    // and the BSP's next IRQ from user mode would land there (seen as a
    // wild RIP on `cat`, with RSP in idle1's slot).
    cpu_state.apply(.descriptor_tables);
    smp_initialized = true;
    cpu_state.apply(.pmu);

    // Safe-mode boot (mode 2) starts no AP: a single CPU runs the whole
    // system. Useful for reproducing CPU-affinity bugs and as a recovery
    // option when SMP races make the system unstable.
    if (@import("../boot/boot_info.zig").boot_mode == 2) {
        debug.klog("[smp] BOOT MODE: SAFE — skipping AP startup, BSP-only\n", .{});
        debug.klog("[smp] 1 CPU online (safe mode)\n", .{});
        return;
    }

    benchCpuIdRead();

    const have_trampoline = trampoline.pageIsUsable(.ap);
    if (have_trampoline) {
        trampoline.install(.ap);
    } else {
        debug.klog("[smp] AP trampoline page 0x{X} is not usable RAM on this machine: staying single-CPU\n", .{trampoline.phys(.ap)});
    }

    const pml4_phys = paging.getKernelPML4Phys();
    // The AP loads CR3 in 32-bit mode. Both loaders keep the tables below
    // 4 GiB (boot_protocol.zig); a truncated CR3 would be a silent reset.
    if (pml4_phys >= 0x1_0000_0000)
        @panic("smp: kernel PML4 phys >= 4GB — AP 32-bit CR3 load would truncate");

    // Build the list of AP APIC IDs to try. With ACPI MADT we get a
    // definitive list of present, enabled processors; their APIC IDs
    // are not guaranteed to be 0..N-1 (real boards may have gaps from
    // hyperthreading or socket layout). Without MADT we fall back to
    // the historical 1..MAX_CPUS-1 probe loop.
    var ap_ids: [MAX_CPUS]u8 = undefined;
    const ap_count = if (have_trampoline) collectApIds(0, &ap_ids) else 0;

    var ap_idx: usize = 0;
    while (ap_idx < ap_count) : (ap_idx += 1) {
        const ap_id: u8 = ap_ids[ap_idx];

        // The AP runs on its isr_stack until apEntry dispatches into its idle.
        const stack_top = @intFromPtr(&cpus[ap_id].isr_stack) + cpus[ap_id].isr_stack.len;
        trampoline.arm(.ap, &apEntry, pml4_phys, stack_top);
        const sent = rdtsc();
        sendInitSipiSipi(ap_id);

        // Wait for AP to ACK the SIPI (apEntry start) — short window, then
        // for alive (apEntry full init done) — longer window. Splitting
        // these tells us on real HW whether a missing AP failed to start
        // (BIOS/MADT mismatch, INIT-SIPI timing, wrong APIC ID) or started
        // but hung in init. Without the split, both look identical.
        var ack_ms: u32 = 0;
        while (!@atomicLoad(bool, &cpus[ap_id].sipi_acked, .acquire) and ack_ms < 100) : (ack_ms += 1) {
            delay.ms(1);
        }
        var alive_ms: u32 = ack_ms;
        while (!@atomicLoad(bool, &cpus[ap_id].alive, .acquire) and alive_ms < 500) : (alive_ms += 1) {
            delay.ms(1);
        }

        if (@atomicLoad(bool, &cpus[ap_id].alive, .acquire)) {
            cpu_count += 1;
            debug.klog("[smp] AP {d} alive (LAPIC ID={d}, ack={d}ms init={d}ms)\n", .{ cpu_count - 1, ap_id, ack_ms, alive_ms - ack_ms });
            checkApCounter(ap_id, sent);
        } else if (@atomicLoad(bool, &cpus[ap_id].sipi_acked, .acquire)) {
            // Started but never reached end of apEntry. Init crashed or
            // hung — page-fault, MSR fault, kasan-shadow OOM, or stuck in
            // a syscall_entry/idle setup spin. Real HW: capture this and
            // keep going so other APs still come up.
            debug.klog("[smp] AP {d} STARTED BUT HUNG (LAPIC ID={d}, ack={d}ms, no alive in {d}ms) — likely init crash\n", .{ ap_idx, ap_id, ack_ms, alive_ms });
            if (acpi.getMadt() == null) break;
        } else {
            // The trampoline's progress tells a lost SIPI (BIOS/MADT
            // mismatch, INIT-SIPI delay too short for the chipset) from an
            // AP that ran it but never got as far as the ack in apEntry.
            debug.klog("[smp] AP {d} NO SIPI ACK (LAPIC ID={d}, {d}ms timeout; trampoline {s})\n", .{ ap_idx, ap_id, ack_ms, trampoline.describeProgress(.ap) });
            if (acpi.getMadt() == null) break;
        }
    }

    debug.klog("[smp] {d} CPU(s) online\n", .{cpu_count});

    // Stand up the bottom-half engine now that every AP is alive: one pinned
    // `ksoftirqd` per CPU. After this returns, `softirq.raise` from the IRQ0
    // tick (and, later, from device MSI-X top-halves) defers heavy completion
    // work here instead of running it in IF=0 hard-IRQ context.
    @import("../irq/softirq.zig").startAll();
}

/// Starts `lapic_id` in the armed AP trampoline.
fn sendInitSipiSipi(lapic_id: u8) void {
    const vector: u8 = @intCast(trampoline.phys(.ap) >> 12);
    apic.sendInitIPI(lapic_id);
    delay.ms(10);
    apic.sendSIPI(lapic_id, vector);
    delay.ms(1);
    apic.sendSIPI(lapic_id, vector);
}

/// What the two AP entries share: the whole per-CPU list (cpu_state.zig),
/// then `alive`. They differ only in what they dispatch into afterwards: a
/// fresh idle PCB, or the one that survived S3. Returns this CPU's id.
///
/// The AP's stack is its isr_stack, in the kernel image and so not a user
/// page: SMAP goes on with the rest, where the BSP has to wait.
fn apBringUp(comptime path: cpu_state.Path) u8 {
    cpu_state.restore(path);
    const my_id = myCpu().cpu_id;
    bringup_tsc[my_id] = rdtsc();
    // .release publishes everything above; the BSP reads `alive` with
    // .acquire before it counts this CPU online.
    @atomicStore(bool, &cpus[my_id].alive, true, .release);
    return my_id;
}

/// Each AP's counter at the end of its bring-up, for checkApCounter.
var bringup_tsc: [MAX_CPUS]u64 = [_]u64{0} ** MAX_CPUS;

/// Deadlines and clock readings pass between CPUs as raw TSC values, so a
/// CPU whose counter runs in another epoch — a reset the BSP did not share,
/// a sleep only one of them made up for — gets every one of them wrong, and
/// quietly. An AP's stamp from the end of its bring-up has to fall inside
/// the BSP's wait for it; `sent` is the BSP's counter before the INIT.
fn checkApCounter(ap_id: u8, sent: u64) void {
    const seen = rdtsc();
    const at = bringup_tsc[ap_id];
    if (at >= sent and at <= seen) return;
    const off = if (at < sent) sent - at else at - seen;
    debug.kwarn(@src(), "cpu{d}'s TSC is not the BSP's: {d} at bring-up, outside the BSP's wait [{d}, {d}] by {d} ms", .{ ap_id, at, sent, seen, apic.tscToUs(off) / 1000 });
}

/// cpu_state's `identity`: this CPU takes its cpus[] slot and stores its id
/// in IA32_TSC_AUX, where myCpuId() reads it. The BSP is CPU 0 by invariant
/// (init checks); an AP is the LAPIC id it woke with — readable because
/// `lapic_mode` ran first. Until here a CPU out of reset cannot say who it
/// is: its aux holds whatever the reset, or the firmware, left there.
///
/// The syscall scratch slot is zeroed with it. The kernel stack a syscall
/// lands on is tss.rsp0, stamped by setTssRsp0 at each dispatch.
pub fn claimSlot(path: cpu_state.Path) void {
    const id: u8 = if (path.isBsp()) 0 else blk: {
        // Never truncated: an x2APIC id of 256 would take the BSP's slot.
        // collectApIds starts no such CPU, so this is a kernel bug.
        const lapic_id = apic.getLapicId();
        if (lapic_id >= MAX_CPUS) @panic("smp: a CPU came up with a LAPIC id cpus[] has no slot for");
        break :blk @intCast(lapic_id);
    };
    const cpu = &cpus[id];
    // An AP acks before anything that could fault or hang: by this flag
    // the BSP's wait tells "never started" from "started and died".
    if (!path.isBsp()) @atomicStore(bool, &cpu.sipi_acked, true, .release);
    cpu.cpu_id = id;
    cpu.lapic_id = id;
    per_cpu_user_rsp[id] = 0;
    armTscAux(id);
}

/// cpu_state's `descriptor_tables`: this CPU's own GDT and TSS, the shared
/// IDT.
pub fn loadDescriptorTables(path: cpu_state.Path) void {
    const cpu = myCpu();
    // initPerCpuGdt points rsp0 at the isr_stack, which is right for a CPU
    // about to be dispatched anew: setTssRsp0 replaces it. The BSP after S3
    // is not — it goes back into the task that suspended, whose next
    // syscall has to land on that task's kernel stack.
    const rsp0 = cpu.tss.rsp0;
    initPerCpuGdt(cpu);
    if (path == .bsp_resume) cpu.tss.rsp0 = rsp0;
    gdt.loadIdt();
}

/// AP entry point — called from trampoline after entering 64-bit mode (boot).
export fn apEntry() callconv(.c) noreturn {
    const my_id = apBringUp(.ap_boot);

    // Per-CPU kernel-mode idle (task #235). Each AP gets its own idle PCB
    // with its own kstack — no more stack-aliasing failure mode where
    // multiple CPUs share the same idle.kstack. The idle PCB is what
    // every AP runs on as its "always-current" task — schedule() picks
    // user tasks when ready, falls back to this CPU's own idle when not.
    const idle_pid = process.createKernelIdle(my_id) orelse {
        serial.print("[smp] FATAL: AP {d} could not create idle PCB\n", .{my_id});
        while (true) asm volatile ("hlt");
    };
    cpus[my_id].idle_pid = idle_pid;

    serial.print("[smp] AP {d} running\n", .{my_id});

    // Dispatch into the idle PCB. From this instant the AP is a normal
    // kernel-task context (just like the BSP after enterFirstTask). The
    // trampoline stack we've been running on is abandoned — switchToCall
    // sets RSP to idle's kernel_esp and never returns to this caller.
    process.enterFirstTaskAp(idle_pid);
}

/// AP entry point for the S3-resume re-online path (CP2b-2b) — called from the
/// SAME trampoline blob at 0x8000, but reached via `reonlineApsForS3Resume`
/// arming it with this entry instead of `apEntry`. Identical per-CPU
/// bring-up, but REUSES this CPU's idle PCB (which survived S3 in RAM) instead
/// of creating a new one — `createKernelIdle` would allocate a fresh PCB slot
/// every resume and leak the old one. The surviving PCB's saved context is stale
/// (the CPU's live registers were lost at suspend), so we re-plant a fresh
/// `kernelIdle` switch frame before dispatching. Falls back to a fresh idle only
/// if this CPU somehow has no idle_pid (came up on resume but not at boot).
export fn apEntryS3Resume() callconv(.c) noreturn {
    const my_id = apBringUp(.ap_resume);

    // The bring-up ran on the resume CR3 — the suspending PROCESS's page tables,
    // which carry the 0x8000 low-identity the trampoline needed to enable paging.
    // Switch to the kernel master PML4 now, the stable table boot APs run their
    // idle on (page_dir_phys=0 idles resolve to getKernelPageDirPhys in schedule).
    // A process CR3 could be freed underneath us if that process later exits;
    // the bring-up touched only kernel-high memory, so nothing here depended on
    // the process low mappings. Use the same loadCr3 helper schedule() uses so
    // the per-CPU PCID bookkeeping stays consistent.
    {
        const pcid_mod = @import("mmu/pcid.zig");
        pcid_mod.loadCr3(paging.getKernelPageDirPhys(), 0, my_id);
    }

    const idle_pid = if (cpus[my_id].idle_pid) |pid| reuse: {
        process.resetKernelIdleForResume(pid);
        break :reuse pid;
    } else (process.createKernelIdle(my_id) orelse {
        serial.print("[smp] FATAL: AP {d} could not create idle PCB on resume\n", .{my_id});
        while (true) asm volatile ("hlt");
    });
    cpus[my_id].idle_pid = idle_pid;

    serial.print("[smp] AP {d} re-online after S3\n", .{my_id});

    process.enterFirstTaskAp(idle_pid);
}

/// The BSP after an S3 wake: the whole per-CPU list (cpu_state.zig), as on an
/// AP, but with no task to start. The caller (src/acpi/s3.zig) longjmps back
/// into the syscall that suspended, so the BSP goes on in the context it had.
/// Interrupts are off (the wake trampoline cleared IF) and stay off until
/// that syscall returns; the timer armed at the end ticks from then.
pub fn reinitForS3Resume() void {
    // The timer is about to be armed one quantum out, outside the tick's own
    // bookkeeping: what that recorded before the suspend (stretch flags, the
    // BSP's published fire) names a fire that is now in the past.
    @import("idt/irq0.zig").clearTicklessState();
    cpu_state.restore(.bsp_resume);
}

/// After an S3 resume only the BSP is running: S3 powered the APs down and the
/// firmware waking vector brings up CPU 0 alone. Mark every other CPU offline so
/// the scheduler, watchdog (nextAlivePeer skips !alive), and every
/// `if (!cpu.alive)` consumer treat this as a single-CPU system — a clean
/// single-CPU baseline that `reonlineApsForS3Resume` then builds back up from
/// (it relies on these cleared `alive` flags as its bring-up gate). Any task
/// left running on an offlined CPU at suspend is stranded (its live register
/// context was lost — only the BSP's was saved).
pub fn offlineApsForS3Resume() void {
    var i: usize = 1;
    while (i < MAX_CPUS) : (i += 1) {
        @atomicStore(bool, &cpus[i].alive, false, .release);
    }
    cpu_count = 1;
}

/// Re-online the APs S3 powered down (CP2b-2b). The counterpart to
/// `offlineApsForS3Resume`: where that degrades the box to single-CPU on wake,
/// this re-runs the INIT/SIPI bring-up so the machine comes back full-SMP.
///
/// MUST be called from the S3 resume path on the BSP with IF=0, AFTER
/// `offlineApsForS3Resume` (which clears the stale `alive` flags this function's
/// wait loop gates on) and BEFORE `removeLowIdentity`: the AP trampoline runs at
/// phys 0x8000 and needs the 2 MiB low-identity mapping (still live in the
/// post-resume CR3 the suspend path installed) the instant it enables paging.
/// `resume_cr3` is that CR3 (bare PML4 phys, PCID stripped) — the APs load it,
/// exactly as the BSP's own wake trampoline did, then switch to their idle PCB's
/// page tables on the first dispatch.
///
/// Each AP re-enters via `apEntryS3Resume`, which reuses its surviving idle PCB.
///
/// LIMITATION — S3 does not quiesce the APs before power-off, so an AP frozen
/// mid-execution at suspend has two unrecoverable hazards, both rooted in the
/// missing pre-suspend quiesce (the proper fix, and the next step):
///   1. Its live register context is lost (only the BSP's was saved), so a task
///      that was *running* on it at suspend can't be resumed — it's stranded.
///   2. Any lock it held at power-off stays stuck-held; the re-onlined AP's
///      idle→schedule path (sched_lock, setstate_locks) — or, for that matter,
///      the BSP's own resume device re-init (global pmm.lock via xHCI re-enum) —
///      can then spin forever on it. This is a pre-existing S3 risk, not new to
///      AP re-online. In practice a user suspends from an *idle* desktop: the APs
///      sit in kernelIdle's hlt/mwait holding nothing, so neither hazard fires.
///      A busy-system suspend can wedge a re-onlined AP (contained + watchdog-
///      visible: the BSP keeps running, the stuck AP stops ticking → autopsy).
pub fn reonlineApsForS3Resume(resume_cr3: u64) void {
    if (!apic.apic_active) return;
    if (@import("../boot/boot_info.zig").boot_mode == 2) return; // safe mode: stay single-CPU
    // The AP trampoline does a 32-bit `mov cr3, eax`, so the CR3 must fit in 32
    // bits or the AP loads a truncated value and triple-faults. installLowIdentity
    // already asserted this for resume_cr3 at suspend; re-check rather than risk it.
    if (resume_cr3 >= 0x1_0000_0000) {
        debug.klog("[smp] S3 re-online: resume CR3 0x{x} >= 4 GiB — skipped, staying single-CPU\n", .{resume_cr3});
        return;
    }

    // No trampoline, so no AP was started at boot either.
    if (!trampoline.pageIsUsable(.ap)) return;

    // Low memory is PMM-reserved and almost certainly survived S3; re-copy
    // anyway, so resume never depends on what the firmware left there.
    trampoline.install(.ap);

    const bsp_id: u8 = @truncate(apic.getLapicId());
    var ap_ids: [MAX_CPUS]u8 = undefined;
    const ap_count = collectApIds(bsp_id, &ap_ids);

    var brought: usize = 0;
    var ap_idx: usize = 0;
    while (ap_idx < ap_count) : (ap_idx += 1) {
        const ap_id: u8 = ap_ids[ap_idx];

        // Clear this AP's bring-up handshake flags (offlineApsForS3Resume cleared
        // `alive`; clear `sipi_acked` too so the alive-wait gates on a freshly-set
        // flag rather than a stale boot value).
        @atomicStore(bool, &cpus[ap_id].sipi_acked, false, .release);
        @atomicStore(bool, &cpus[ap_id].alive, false, .release);

        // resume_cr3, not the kernel master PML4: the master lost its low
        // identity at boot, resume_cr3 still maps the trampoline page.
        const stack_top = @intFromPtr(&cpus[ap_id].isr_stack) + cpus[ap_id].isr_stack.len;
        trampoline.arm(.ap, &apEntryS3Resume, resume_cr3, stack_top);
        const sent = rdtsc();
        sendInitSipiSipi(ap_id);

        // Wait for the AP to come back alive (apEntryS3Resume reached its end).
        var ms: u32 = 0;
        while (!@atomicLoad(bool, &cpus[ap_id].alive, .acquire) and ms < 500) : (ms += 1) {
            delay.ms(1);
        }
        if (@atomicLoad(bool, &cpus[ap_id].alive, .acquire)) {
            cpu_count += 1;
            brought += 1;
            debug.klog("[smp] S3 re-online: AP {d} back ({d}ms)\n", .{ ap_id, ms });
            checkApCounter(ap_id, sent);
        } else {
            debug.klog("[smp] S3 re-online: AP {d} did NOT come back ({d}ms timeout; trampoline {s})\n", .{ ap_id, ms, trampoline.describeProgress(.ap) });
        }
    }
    debug.klog("[smp] S3 re-online: {d}/{d} AP(s) back, {d} CPU(s) online\n", .{ brought, ap_count, cpu_count });
}

// ── Pre-suspend AP quiesce (S3 CP2b-2c) ──────────────────────────────────────
// S3 powers the APs down without warning. If an AP is powered off (1) running a
// task, that task's live registers are lost (only the BSP's context is saved by
// the suspend) → the task is stranded; or (2) holding a lock, that lock stays
// stuck-held in surviving RAM → the re-onlined AP deadlocks on it (its own
// per-CPU sched_lock is the sharpest case — it survives S3 in cpus[] and the
// re-onlined AP is the only one that ever takes it). The fix is to drive every AP
// to a lock-free safe point and cleanly deschedule its task BEFORE SLP_EN.
//
// Protocol: the BSP sets `quiesce_requested`; each AP's pickNext then steers it to
// its idle PCB (descheduling — and thus context-SAVING via switchTo — whatever it
// was running, so the task survives S3 in its PCB and is re-dispatched on resume),
// and kernelIdle parks it. The park is `cli; hlt`, NOT `sti; hlt`: once parked the
// AP runs no further code (no timer tick → no schedule() → no sched_lock), so it
// is guaranteed to be powered off holding nothing. A parked AP also marks itself
// `alive=false` so it drops out of every cross-CPU IPI broadcast — crucially TLB
// shootdowns (doShootdown skips !alive CPUs and otherwise spins forever on a
// cli;hlt AP that can never ack the shootdown IPI), and the watchdog. An AP leaves
// the park only via INIT/SIPI (reonlineApsForS3Resume, on real resume OR an aborted
// suspend), which resets it into apEntryS3Resume — the park frame is abandoned, so
// there is no flag for it to re-test.
var quiesce_requested: bool = false;
var quiesce_acked: [MAX_CPUS]bool = [_]bool{false} ** MAX_CPUS;

/// True while a pre-suspend quiesce is in effect. The cheap gate pickNext and
/// kernelIdle consult before any quiesce-specific work — a single bool load that
/// is false in all normal operation, so the quiesce path adds nothing measurable
/// to the scheduler/idle hot paths.
pub inline fn quiesceRequested() bool {
    return @atomicLoad(bool, &quiesce_requested, .acquire);
}

/// Called from an AP's kernelIdle at the lock-clean top of its loop. If a
/// pre-suspend quiesce is in effect, acknowledge it and park the AP holding NO
/// lock until power-off. The BSP is exempt — it drives the suspend and must keep
/// running the shutdown syscall. cli BEFORE the ack so that once the BSP observes
/// the ack this CPU is guaranteed IF=0 and will only hlt (no tick can sneak a
/// schedule() in between). Never returns when it parks.
pub fn parkForQuiesceIfRequested() void {
    if (!quiesceRequested()) return;
    if (isBSP()) return; // BSP drives the suspend; never parks itself
    const id = myCpu().lapic_id;
    asm volatile ("cli"); // no further IRQ/schedule on this CPU before power-off
    // Mark offline BEFORE acking. A parked cli;hlt AP can't service an inbound
    // IPI, so it MUST NOT remain a TLB-shootdown target: doShootdown skips
    // !alive CPUs (tlb.zig — `if (!cpus[i].alive) continue`), so any shootdown
    // the BSP issues between here and SLP_EN (e.g. a kernel-master page-table
    // mutation while it finishes staging/printing) would otherwise spin forever
    // on this CPU's missing ack. Publishing alive=false before quiesce_acked
    // (release/acquire) guarantees the BSP sees us offline the moment it sees us
    // parked. Also makes the watchdog skip our now-frozen tick. reonline resets it.
    @atomicStore(bool, &cpus[id].alive, false, .release);
    @atomicStore(bool, &quiesce_acked[id], true, .release);
    // Park. IF=0 hlt wakes only on NMI/SMI/INIT; the loop re-hlts on the first
    // two, and INIT (reonlineApsForS3Resume) resets the CPU out of this frame.
    while (true) asm volatile ("hlt");
}

/// BSP-only: drive every AP to its lock-free park point before suspending, then
/// wait up to `timeout_ms` for each alive AP to ack. Returns the number of APs
/// that did NOT park (0 = clean full quiesce). Best-effort: an AP that doesn't
/// reach the safe point in time (busy in a cli'd loop, or wedged) is logged and
/// left as-is — strictly no worse than the pre-quiesce behavior. The caller holds
/// IF=0, so this wait can't be preempted. APs in user mode or already idling park
/// within ~1-2 timer ticks (≤10 ms each: the tick preempts → schedule()→idle→park).
/// A kernel-busy AP (kernel thread, ksoftirqd, or a user thread mid-syscall) is NOT
/// steered by the tick — handleIRQ0 only preempts on from_user/soft-yield — so it
/// parks only when it next *voluntarily* reaches schedule(); otherwise the timeout
/// falls through, leaving exactly the busy-suspend hazard reonlineApsForS3Resume's
/// LIMITATION documents. (Forcibly preempting a kernel-busy AP would be worse — it
/// could deschedule the task mid-lock-hold; cooperative parking is the safe choice.)
pub fn quiesceApsForS3(timeout_ms: u32) u32 {
    if (!apic.apic_active) return 0;
    if (@import("../boot/boot_info.zig").boot_mode == 2) return 0; // already single-CPU

    const bsp_id: u8 = @truncate(apic.getLapicId());
    var ap_ids: [MAX_CPUS]u8 = undefined;
    const ap_count = collectApIds(bsp_id, &ap_ids);

    // Clear acks BEFORE publishing the request, so an AP can't observe a stale ack.
    var k: usize = 0;
    while (k < ap_count) : (k += 1) @atomicStore(bool, &quiesce_acked[ap_ids[k]], false, .release);
    @atomicStore(bool, &quiesce_requested, true, .release);

    var waited: u32 = 0;
    while (waited < timeout_ms) : (waited += 1) {
        var all_parked = true;
        var i: usize = 0;
        while (i < ap_count) : (i += 1) {
            const ap = ap_ids[i];
            if (!@atomicLoad(bool, &cpus[ap].alive, .acquire)) continue; // already offline
            if (!@atomicLoad(bool, &quiesce_acked[ap], .acquire)) {
                all_parked = false;
                break;
            }
        }
        if (all_parked) break;
        delay.ms(1); // a spin on the TSC: needs no tick, so safe with IF off
    }

    var not_parked: u32 = 0;
    var i: usize = 0;
    while (i < ap_count) : (i += 1) {
        const ap = ap_ids[i];
        if (@atomicLoad(bool, &cpus[ap].alive, .acquire) and !@atomicLoad(bool, &quiesce_acked[ap], .acquire)) {
            not_parked += 1;
            debug.klog("[smp] S3 quiesce: AP {d} did NOT park ({d}ms) — left running (busy/wedged)\n", .{ ap, timeout_ms });
        }
    }
    if (not_parked == 0)
        debug.klog("[smp] S3 quiesce: all {d} AP(s) parked at lock-free safe point ({d}ms)\n", .{ ap_count, waited });
    return not_parked;
}

/// End a pre-suspend quiesce: clear the request so APs brought back by
/// reonlineApsForS3Resume (a real resume OR an aborted suspend) resume normal idle
/// instead of immediately re-parking. MUST be called before reonline on every path
/// that re-onlines the APs.
pub fn endQuiesceAps() void {
    @atomicStore(bool, &quiesce_requested, false, .release);
}

/// Store this CPU's id in IA32_TSC_AUX and prove the round trip. Runs
/// before the IDT is loaded on this CPU (AP bring-up, S3 resume), so the
/// write is the plain wrmsr gated on CPUID — RDTSCP present implies the
/// MSR — not the #GP-fixup helper. A failed round trip (a hypervisor that
/// swallows the write, an aux that reads back wrong) demotes EVERY CPU to
/// the LAPIC ID register for the rest of the boot: global because
/// myCpuId() must answer the same way on all of them, sticky because the
/// BSP re-arms on S3 resume and would otherwise flip it back.
///
/// A refusal is reported, and klog asks myCpuId(), which by then reads the
/// LAPIC ID register: this CPU's `lapic_mode` has to have run (it is the
/// entry before `identity`), or that read takes the wrong path.
fn armTscAux(cpu_id: u8) void {
    const refused_before = @atomicLoad(bool, &tsc_aux_refused, .monotonic);
    if (!refused_before and hasRdtscp()) {
        msr.write(msr.TSC_AUX, cpu_id);
        if (rdtscpAux() == cpu_id) {
            if (cpu_id == 0) @atomicStore(bool, &cpu_id_via_aux, true, .release);
            return;
        }
        // Don't leave a lying aux behind for a future direct rdtscp reader.
        msr.write(msr.TSC_AUX, 0);
    }
    @atomicStore(bool, &tsc_aux_refused, true, .monotonic);
    @atomicStore(bool, &cpu_id_via_aux, false, .monotonic);
    debug.klog("[smp] cpu{d}: TSC_AUX {s} — myCpu() on the LAPIC ID register\n", .{
        cpu_id, if (refused_before) "refused earlier" else if (hasRdtscp()) "round trip failed" else "absent (no RDTSCP)",
    });
}

/// Once a second per CPU, from the IRQ0 tick: does TSC_AUX still agree
/// with the LAPIC ID register? The round trip proves the aux at arm time
/// only; if SMM, firmware or a hypervisor ever rewrote it, myCpuId() would
/// hand two CPUs one per-CPU slot (preempt_pin, spin targets, rq locks,
/// PMM magazines) with no symptom — a class the register could not
/// produce. On disagreement demote everyone (sticky) and kwarn. One LAPIC
/// read per CPU per second is noise next to what the aux saves. The tick
/// counter is indexed by the aux itself: a wrong aux only shares a
/// counter; the comparison does not depend on it.
var cpu_id_audit_ticks: [MAX_CPUS]u8 = [_]u8{0} ** MAX_CPUS;
const CPU_ID_AUDIT_EVERY_TICKS: u8 = 100; // 100 Hz tick → once a second

pub fn auditCpuIdTick() void {
    if (!@atomicLoad(bool, &cpu_id_via_aux, .monotonic)) return;
    const aux: u8 = @truncate(rdtscpAux());
    const slot: usize = if (aux < MAX_CPUS) aux else 0;
    cpu_id_audit_ticks[slot] +%= 1;
    if (cpu_id_audit_ticks[slot] < CPU_ID_AUDIT_EVERY_TICKS) return;
    cpu_id_audit_ticks[slot] = 0;
    const lapic: u8 = @truncate(apic.getLapicId());
    if (lapic == aux) return;
    @atomicStore(bool, &tsc_aux_refused, true, .monotonic);
    @atomicStore(bool, &cpu_id_via_aux, false, .monotonic);
    debug.kwarn(@src(), "[smp] TSC_AUX says cpu{d}, LAPIC ID says cpu{d} — myCpu() demoted to the LAPIC ID register\n", .{ aux, lapic });
}

/// Dedicated per-CPU NMI stack (TSS IST2, wired to vector 2 in idt.init). NMI
/// is non-maskable and can fire while RSP is invalid — most dangerously in the
/// SYSCALL-entry window, where `syscall` has set CPL=0 but the kernel hasn't
/// switched RSP off the USER stack yet (entry.zig). With IST=0 the CPU pushes
/// the NMI frame onto that user RSP; the user stack grows down lazily, so the
/// page below is typically unmapped → #PF → #DF. A dedicated IST makes NMI
/// delivery independent of the interrupted RSP. Kept OUT of CpuLocal (whose
/// layout is cache-line-sensitive — tss.rsp0 must not straddle a line) as its
/// own BSS array. Separate from IST1 (#DF) + the isr_stack dyn-IRQ trampoline
/// to avoid frame clobber; safe because nmiSnapshot never resumes-via-switchTo.
/// 8 KiB is ample: nmiSnapshot's deepest local is the ~520 B LbrSnap.
var nmi_stacks: [MAX_CPUS][8192]u8 align(16) = [_][8192]u8{[_]u8{0} ** 8192} ** MAX_CPUS;

fn initPerCpuGdt(cpu: *CpuLocal) void {
    // Copy standard segment entries from BSP
    const bsp_entries = gdt.getEntries();
    cpu.gdt_entries[0] = bsp_entries[0]; // null
    cpu.gdt_entries[1] = bsp_entries[1]; // kernel code
    cpu.gdt_entries[2] = bsp_entries[2]; // kernel data
    cpu.gdt_entries[3] = bsp_entries[3]; // user data
    cpu.gdt_entries[4] = bsp_entries[4]; // user code

    // Set up TSS with our ISR stack. RSP0 is the legacy slot used by IDT
    // gates with IST=0 on user→kernel transitions. setTssRsp0 overrides
    // this per-process to point at the dispatched task's kstack_top, so
    // this initial value matters only for the brief window before the
    // first process is dispatched.
    cpu.tss.rsp0 = @intFromPtr(&cpu.isr_stack) + cpu.isr_stack.len;
    // IST1 = per-CPU stack for the #DF gate (idt.init installs vector 8 with
    // ist=1; everything else is IST=0 — the 2026-05-17 attempt to put IRQ0 /
    // dyn IRQs here was reverted, see idt.init). The CPU loads RSP from here
    // on #DF delivery regardless of CPL, so a "couldn't push the exception
    // frame" double fault (kernel stack overflow into a guard page) still
    // reaches handleException's dump instead of triple-faulting. Re-uses the
    // isr_stack buffer top — the same buffer the dyn-IRQ Shape-D trampoline
    // uses in software; aliasing is safe because the #DF path is terminal
    // and never resumes what it interrupted.
    cpu.tss.ist1 = @intFromPtr(&cpu.isr_stack) + cpu.isr_stack.len;
    // IST2 = dedicated per-CPU NMI stack (vector 2 → ist=2 in idt.init). Lets a
    // non-maskable interrupt that lands while RSP is the user stack (the
    // syscall-entry window, CPL=0 pre stack-switch) push its frame onto a
    // known-good stack instead of an unmapped user page → no #DF. See nmi_stacks.
    if (cpu.cpu_id < MAX_CPUS) {
        cpu.tss.ist2 = @intFromPtr(&nmi_stacks[cpu.cpu_id]) + nmi_stacks[cpu.cpu_id].len;
    }

    // Build TSS descriptor pointing to our TSS
    const tss_base: u64 = @intFromPtr(&cpu.tss);
    const tss_limit: u32 = @sizeOf(gdt.Tss64) - 1;
    cpu.gdt_entries[5] = gdt.makeEntry(@truncate(tss_base), tss_limit, 0x89, 0x0);
    cpu.gdt_entries[6] = tss_base >> 32;

    cpu.gdt_ptr = .{
        .limit = @sizeOf(@TypeOf(cpu.gdt_entries)) - 1,
        .base = @intFromPtr(&cpu.gdt_entries),
    };

    // Load GDT + segments + TSS via the shared helper (same ritual as
    // gdt.init() runs for the BSP early-boot path).
    gdt.loadAndReload(&cpu.gdt_ptr);
}

// --- Async app loading (offload file I/O to AP) ---

const LoadState = enum(u8) { idle, pending, loading, loaded, done };

const LoadRequest = struct {
    state: LoadState = .idle,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    file_size: usize = 0, // set by AP after disk I/O
    // PMM-allocated buffer the AP read the file into. BSP transfers ownership
    // to elf_loader.loadAndStart, which either stashes it in pcb.elf_buf or
    // frees it on failure. Replaced the old fixed-VA staging at 0x400000 to
    // kill the BSS-overlap bug class.
    file_buf: ?[*]align(4) u8 = null,
    file_pages: u32 = 0,
    file_inode: u32 = 0, // ext2 inode (0 = non-ext2): lets the BSP cache-share RO segments (Slice 3e)
    result_pid: u32 = 0xFFFFFFFF, // set by BSP after process creation
};

var load_req: LoadRequest = .{};

/// Request async app load (called by BSP desktop). Returns true if accepted.
pub fn requestAppLoad(name: []const u8) bool {
    if (@atomicLoad(LoadState, &load_req.state, .acquire) != .idle) return false;
    const len: u8 = @intCast(@min(name.len, 32));
    @memcpy(load_req.name[0..len], name[0..len]);
    load_req.name_len = len;
    load_req.result_pid = 0xFFFFFFFF;
    @atomicStore(LoadState, &load_req.state, .pending, .release);
    return true;
}

/// Check if AP finished disk I/O. If so, BSP creates the process (safe on BSP).
pub fn pollAppLoad() ?u32 {
    if (@atomicLoad(LoadState, &load_req.state, .acquire) != .loaded) return null;
    const perf = @import("../debug/perf.zig");
    const t_start = perf.rdtsc();

    // AP finished disk I/O — BSP now creates the process (avoids race conditions).
    //
    // BSP's CR3 may currently point at the LAST user process that ran here.
    // Switch to the kernel page directory before reading the AP-allocated
    // buffer (whose virt = phys, identity-mapped in the kernel PD), then
    // restore.
    const pcid_mod = @import("mmu/pcid.zig");
    const caller_pd = if (process.currentPCB()) |pcb| pcb.page_dir_phys else 0;
    const caller_pcid: u16 = if (process.currentPCB()) |pcb| pcb.pcid else 0;
    pcid_mod.loadCr3(paging.getKernelPageDirPhys(), 0, myCpu().cpu_id);

    const fsize = load_req.file_size;
    var pid: u32 = 0xFFFFFFFF;
    var t_after_load: u64 = perf.rdtsc();

    if (fsize > 0) {
        if (load_req.file_buf) |buf| {
            // Hand ownership of the PMM-allocated buffer to elf_loader.
            // loadAndStart frees on failure, otherwise stashes in pcb.elf_buf.
            const t_before_las = perf.rdtsc();
            const las_result = elf_loader.loadAndStart(buf, fsize, load_req.file_pages, load_req.file_inode, null);
            t_after_load = perf.rdtsc();
            if (las_result) |p| {
                var nlen: usize = load_req.name_len;
                if (nlen >= 4 and load_req.name[nlen - 4] == '.') nlen -= 4;
                process.setName(@intCast(p), load_req.name[0..nlen]);
                // Promote to interactive immediately so the new process can
                // compete with the already-running app for CPU time and reach
                // its createWindow syscall — otherwise newly-launched apps
                // appear to "queue" behind the current foreground window.
                process.getPCB(@intCast(p)).priority = .interactive;
                pid = @intCast(p);
                serial.print(
                    "[smp.timing] BSP loadAndStart pid={d} size={d} cyc={d}M\n",
                    .{ pid, fsize, (t_after_load -% t_before_las) >> 20 },
                );
            } else {
                serial.print(
                    "[smp.timing] BSP loadAndStart FAILED size={d} cyc={d}M\n",
                    .{ fsize, (t_after_load -% t_before_las) >> 20 },
                );
            }
        }
    }

    // Buffer ownership has been transferred to elf_loader; clear the slot
    // so a subsequent request can claim a fresh allocation.
    load_req.file_buf = null;
    load_req.file_pages = 0;
    load_req.file_size = 0;
    load_req.file_inode = 0;

    // Restore caller's CR3 before returning so the desktop's main loop continues
    // executing in whatever address space it expected (PCID-aware so caller's
    // TLB survives the excursion).
    if (caller_pd != 0) pcid_mod.loadCr3(caller_pd, caller_pcid, myCpu().cpu_id);

    load_req.result_pid = pid;
    @atomicStore(LoadState, &load_req.state, .idle, .release);
    const t_total = perf.rdtsc();
    serial.print(
        "[smp.timing] BSP pollAppLoad total={d}M (las={d}M)\n",
        .{ (t_total -% t_start) >> 20, (t_after_load -% t_start) >> 20 },
    );
    if (pid == 0xFFFFFFFF) return null;
    return pid;
}

/// AP worker: only does disk I/O, BSP creates the process. Called from
/// any kernel idle task (BSP or AP) — the CAS pending->loading ensures
/// only one CPU services a given request, and CR3 is saved/restored so
/// the caller's address space is preserved.
pub fn apProcessLoadQueue() void {
    // CAS-claim the pending request. If another CPU already grabbed it
    // (state moved past .pending) or there's nothing to do, return.
    if (@cmpxchgStrong(LoadState, &load_req.state, .pending, .loading, .acquire, .acquire) != null) return;

    const name = load_req.name[0..load_req.name_len];
    const perf = @import("../debug/perf.zig");
    const t_start = perf.rdtsc();
    serial.print("[smp] AP reading: {s}\n", .{name});

    // Save caller's CR3 (including PCID bits 11:0), switch to kernel PML4
    // for I/O, restore at end via pcid.restoreSaved so the caller's TLB
    // is preserved if it had a tagged address space loaded.
    const pcid_mod = @import("mmu/pcid.zig");
    const caller_pd: u64 = @import("arch/cr.zig").cr3.read();
    pcid_mod.loadCr3(paging.getKernelPML4Phys(), 0, myCpu().cpu_id);
    const t_after_cr3 = perf.rdtsc();

    // PMM-allocate, read into the new buffer, hand the pointer to BSP via
    // load_req. Replaces the old fixed-VA staging at 0x400000 — see header
    // comment on LoadRequest for the bug class this kills.
    //
    // No outer ata.acquireLock here: the driver audit added per-call locking
    // inside ata.readSector(s)/writeSectorSecondary, so this used to be a
    // recursive acquire on the same non-recursive ticket lock — deadlocked
    // every queued load on cpu1 (caller=block.readSectors, ata_lock@0x3D4728).
    const fresh_opt = vfs.loadFileFresh(name);
    const t_after_load = perf.rdtsc();

    if (fresh_opt) |fresh| {
        load_req.file_buf = fresh.buf;
        load_req.file_pages = fresh.pages;
        load_req.file_size = fresh.size;
        load_req.file_inode = fresh.inode;
    } else {
        load_req.file_buf = null;
        load_req.file_pages = 0;
        load_req.file_size = 0;
        load_req.file_inode = 0;
    }

    const sz: usize = if (fresh_opt) |f| f.size else 0;
    serial.print(
        "[smp.timing] AP {s}: size={d} cr3={d}M loadFresh={d}M total={d}M\n",
        .{
            name,
            sz,
            (t_after_cr3 -% t_start) >> 20,
            (t_after_load -% t_after_cr3) >> 20,
            (t_after_load -% t_start) >> 20,
        },
    );

    // Restore caller's CR3 before signaling BSP — keeps the caller's
    // address space intact across this excursion (PCID-aware: TLB
    // preserved if generation matches).
    pcid_mod.restoreSaved(caller_pd, myCpu().cpu_id);

    // Signal BSP that disk I/O is done — BSP will create the process
    @atomicStore(LoadState, &load_req.state, .loaded, .release);
    // Wake the event-driven compositor so its pollAppLoad() runs
    // promptly. Without this the desktop sleeps until an unrelated
    // event (input, animation) brings it back, and the new window
    // appears delayed by up to the next wakeup.
    @import("../ui/desktop/wake.zig").requestWake();
}
