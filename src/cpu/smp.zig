const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");
const apic = @import("../time/apic.zig");
const acpi = @import("../acpi/acpi.zig");
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");
const gdt = @import("arch/gdt.zig");
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

/// Phys address the AP trampoline blob is copied to before SIPI. Must
/// match `AP_TRAMP_BASE` in src/boot/ap_trampoline.asm.
const TRAMPOLINE_ADDR: usize = 0x8000;

/// AP trampoline data slots — populated by BSP, read by trampoline. Each
/// is a u64 at a fixed phys offset within the 0x8000-page that holds the
/// blob; the trampoline itself is well under 0xFE8 bytes so the slots sit
/// past its tail. KEEP IN SYNC with the `%define`s in ap_trampoline.asm —
/// drift here = AP loads CR3 from the apEntry slot or vice versa, which
/// presents as a wedged AP at SIPI time.
const AP_ENTRY_SLOT: usize = 0x8FE8; // u64: &apEntry (kernel VA)
const AP_PML4_SLOT: usize = 0x8FF0; // u64: kernel PML4 phys addr
const AP_STACK_SLOT: usize = 0x8FF8; // u64: kstack top (16-aligned)
/// Real-mode SIPI vector. Encodes the trampoline page number: physical
/// load address = vector << 12. Matches TRAMPOLINE_ADDR.
const AP_SIPI_VECTOR: u8 = TRAMPOLINE_ADDR >> 12;

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
    /// because busyWait() is an opaque, non-inlined call that forced a reload),
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
    /// pipe block, sysWaitpid) from a real hardware LAPIC timer IRQ. The
    /// yield-issuing code sets this true *immediately before* `int $0x20`;
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

    /// Per-CPU runqueue (Phase 1 — shadow-only). Three priority queues
    /// holding pids whose state == .ready and assigned_cpu == this cpu.
    /// Phase 1 maintains membership alongside the legacy procs[]-scan
    /// pickNext but does NOT yet read from this for dispatch; the
    /// `process.rqAudit` call from schedule() catches drift between
    /// the two views. Phase 2 swaps pickNext to read from here and
    /// retires the cross-CPU CAS scan. See src/proc/runqueue.zig.
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
    /// freeze the displayed value forever. Readers: watchdog.peerCheck,
    /// menubar sample loop, sys.cpustat.
    irq_tick_count: u64 = 0,
    /// Counts only the IRQ0 firings that interrupted an idle PCB on this CPU.
    /// `(irq_tick_count - idle_tick_count) / irq_tick_count` over a window
    /// gives instantaneous CPU usage — what htop/top draw. Updated under the
    /// same cli as `irq_tick_count` so the pair stays monotonic to readers.
    /// (a) Same access rules as irq_tick_count above.
    idle_tick_count: u64 = 0,
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
    /// CPU's isr_stack with IF=0; consumed by check_and_preempt_dynirq in
    /// the DynIrqStub epilogue, also on this CPU. NEVER set from a peer.
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

/// Per-CPU storage for cpu/syscall/entry.zig's fast path. Just one slot now:
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

/// Get current CPU's local data via LAPIC ID
pub fn myCpu() *CpuLocal {
    if (!smp_initialized) return &cpus[0];
    const id: u8 = @truncate(apic.getLapicId());
    if (id >= MAX_CPUS) return &cpus[0];
    return &cpus[id];
}

/// Get BSP CPU data (always CPU 0)
pub fn bspCpu() *CpuLocal {
    return &cpus[0];
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
    const id: u8 = @truncate(apic.getLapicId());
    return id == 0;
}

/// SMP-correctness guard: panic if a BSP-only function is invoked from an AP.
/// Cheap (one MSR read) and only fires when an audit invariant is violated, so
/// we can sprinkle it on every "BSP-only by design" entry point. Catches the
/// class of bugs where code that mutates desktop/USB/keyboard/mouse state
/// silently runs on an AP and corrupts BSP-private structures.
pub fn assertBSP(comptime site: []const u8) void {
    if (!smp_initialized) return;
    const id: u8 = @truncate(apic.getLapicId());
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
    // the per-CPU LSTAR syscall stubs (cpu/syscall/entry.zig) can load the
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

    // Safe-mode boot (mode 2) skips AP startup so a single CPU runs the
    // whole system. Useful for reproducing CPU-affinity bugs and as a
    // recovery option when SMP races make the system unstable. BSP-only
    // init still runs below (per-CPU GDT/TSS, syscall MSRs).
    if (@import("../boot/boot_info.zig").boot_mode == 2) {
        debug.klog("[smp] BOOT MODE: SAFE — skipping AP startup, BSP-only\n", .{});
        const bsp_id: u8 = @truncate(apic.getLapicId());
        cpus[bsp_id].cpu_id = 0;
        cpus[bsp_id].lapic_id = bsp_id;
        @atomicStore(bool, &cpus[bsp_id].alive, true, .release);
        initPerCpuAsm(bsp_id);
        initPerCpuGdt(&cpus[bsp_id]);
        smp_initialized = true;
        debug.klog("[smp] 1 CPU online (safe mode)\n", .{});
        return;
    }

    // Set up BSP (CPU 0) per-CPU data
    const bsp_id: u8 = @truncate(apic.getLapicId());
    cpus[bsp_id].cpu_id = 0;
    cpus[bsp_id].lapic_id = bsp_id;
    @atomicStore(bool, &cpus[bsp_id].alive, true, .release);

    // Zero this CPU's per-CPU syscall scratch slot (user_rsp_save). The
    // kstack pointer itself lives in cpus[bsp_id].tss.rsp0 — written by
    // setTssRsp0 on the first per-process dispatch. The LSTAR stub reads
    // both via RIP-relative loads, no GS_BASE involvement.
    initPerCpuAsm(bsp_id);

    // Migrate BSP from the legacy shared GDT/TSS (set up by gdt.init()) to
    // its own per-CPU GDT/TSS. Without this, BSP keeps using the global
    // `tss` in gdt.zig, which every CPU's setTssRsp0 stomps on — so when
    // an AP's setTssRsp0 writes a value for ITS dispatched task, BSP's
    // TSS.RSP0 silently becomes that value too. The result is BSP loading
    // RSP from another CPU's kstack on the next user-mode IRQ — i.e. the
    // wild-RIP cross-stack-aliasing bug we've been hunting (B.3 caught it
    // on cat: BSP took IRQ from cat in user mode and landed RSP in idle1's
    // slot because cpu1 had just called setTssRsp0(0, idle1_top)).
    initPerCpuGdt(&cpus[bsp_id]);

    smp_initialized = true;

    // Copy trampoline to phys 0x8000. The AP boots in 16-bit real mode
    // and starts execution at this physical address; the kernel writes
    // through the physmap so the copy works without the legacy low identity.
    const trampoline: [*]const u8 = @ptrCast(&ap_trampoline_start);
    const trampoline_size = @intFromPtr(&ap_trampoline_end) - @intFromPtr(&ap_trampoline_start);
    // The blob must not grow into the BSP-populated data slots that share its
    // 0x8000 page (AP_ENTRY_SLOT, the lowest, sits at 0x8FE8). If it did, the
    // memcpy below would overwrite the entry pointer the instant after we write
    // it, and the AP would `call` a garbage address. NASM's preprocessor can't
    // compare label offsets, so the guard lives here — it fires at boot, before
    // any SIPI, with a clear panic instead of a wild AP jump.
    if (trampoline_size > AP_ENTRY_SLOT - TRAMPOLINE_ADDR)
        @panic("smp: AP trampoline blob overran its data slots (0x8000..0x8FE8)");
    const dest: [*]u8 = @ptrFromInt(paging.physToVirt(TRAMPOLINE_ADDR));
    @memcpy(dest[0..trampoline_size], trampoline[0..trampoline_size]);

    // Write data area for trampoline (0x8FE0-0x8FFF)
    const pml4_phys = paging.getKernelPML4Phys();
    // The trampoline loads CR3 with a 32-bit `mov eax, [AP_PML4_SLOT]` (it's in
    // 32-bit protected mode at that point), so the kernel PML4 phys MUST fit in
    // 32 bits or the AP loads a truncated CR3 and triple-faults. Holds for the
    // Multiboot path (pml4 ~1 MB) and normally for UEFI, but the UEFI allocator
    // isn't architecturally bound to < 4 GB — assert it rather than risk a
    // silent triple-fault on some firmware.
    if (pml4_phys >= 0x1_0000_0000)
        @panic("smp: kernel PML4 phys >= 4GB — AP 32-bit CR3 load would truncate");

    // Build the list of AP APIC IDs to try. With ACPI MADT we get a
    // definitive list of present, enabled processors; their APIC IDs
    // are not guaranteed to be 0..N-1 (real boards may have gaps from
    // hyperthreading or socket layout). Without MADT we fall back to
    // the historical 1..MAX_CPUS-1 probe loop.
    var ap_ids: [MAX_CPUS]u8 = undefined;
    const ap_count = collectApIds(bsp_id, &ap_ids);

    var ap_idx: usize = 0;
    while (ap_idx < ap_count) : (ap_idx += 1) {
        const ap_id: u8 = ap_ids[ap_idx];

        // Allocate AP kernel stack
        const stack_top = @intFromPtr(&cpus[ap_id].isr_stack) + cpus[ap_id].isr_stack.len;

        // Write trampoline data area (volatile u64 writes at fixed addresses).
        // The 0x8FE0 slot used to hold the kernel GDT pointer for the long-mode
        // far jump, but the trampoline now uses its own embedded ap_gdt for
        // that — a 32-bit `lgdt` couldn't load the higher-half kernel GDT
        // base anyway, since it truncates to 32 bits. apEntry installs the
        // per-CPU GDT later via initPerCpuGdt.
        // Slots are written through the physmap; the trampoline reads them
        // directly via their phys addresses from inside its 32-bit / 64-bit
        // bring-up path.
        const ap_entry_ptr: *volatile u64 = @ptrFromInt(paging.physToVirt(AP_ENTRY_SLOT));
        ap_entry_ptr.* = @intFromPtr(&apEntry);
        const pml4_ptr: *volatile u64 = @ptrFromInt(paging.physToVirt(AP_PML4_SLOT));
        pml4_ptr.* = pml4_phys;
        const stack_ptr: *volatile u64 = @ptrFromInt(paging.physToVirt(AP_STACK_SLOT));
        stack_ptr.* = stack_top;

        // Send INIT IPI
        apic.sendInitIPI(ap_id);

        // Wait ~10ms (spin on tick count — interrupts are enabled)
        busyWait(10);

        // Send SIPI twice (vector encodes phys page of trampoline)
        apic.sendSIPI(ap_id, AP_SIPI_VECTOR);
        busyWait(1);
        apic.sendSIPI(ap_id, AP_SIPI_VECTOR);

        // Wait for AP to ACK the SIPI (apEntry start) — short window, then
        // for alive (apEntry full init done) — longer window. Splitting
        // these tells us on real HW whether a missing AP failed to start
        // (BIOS/MADT mismatch, INIT-SIPI timing, wrong APIC ID) or started
        // but hung in init. Without the split, both look identical.
        var ack_ms: u32 = 0;
        while (!@atomicLoad(bool, &cpus[ap_id].sipi_acked, .acquire) and ack_ms < 100) : (ack_ms += 1) {
            busyWait(1);
        }
        var alive_ms: u32 = ack_ms;
        while (!@atomicLoad(bool, &cpus[ap_id].alive, .acquire) and alive_ms < 500) : (alive_ms += 1) {
            busyWait(1);
        }

        if (@atomicLoad(bool, &cpus[ap_id].alive, .acquire)) {
            cpu_count += 1;
            debug.klog("[smp] AP {d} alive (LAPIC ID={d}, ack={d}ms init={d}ms)\n", .{ cpu_count - 1, ap_id, ack_ms, alive_ms - ack_ms });
        } else if (@atomicLoad(bool, &cpus[ap_id].sipi_acked, .acquire)) {
            // Started but never reached end of apEntry. Init crashed or
            // hung — page-fault, MSR fault, kasan-shadow OOM, or stuck in
            // a syscall_entry/idle setup spin. Real HW: capture this and
            // keep going so other APs still come up.
            debug.klog("[smp] AP {d} STARTED BUT HUNG (LAPIC ID={d}, ack={d}ms, no alive in {d}ms) — likely init crash\n", .{ ap_idx, ap_id, ack_ms, alive_ms });
            if (acpi.getMadt() == null) break;
        } else {
            // Never reached apEntry at all. SIPI was lost or AP didn't
            // start. On real HW: BIOS/MADT inconsistency, INIT-SIPI delay
            // too short for the chipset, or wrong vector decoding.
            debug.klog("[smp] AP {d} NO SIPI ACK (LAPIC ID={d}, {d}ms timeout) — never entered apEntry\n", .{ ap_idx, ap_id, ack_ms });
            if (acpi.getMadt() == null) break;
        }
    }

    debug.klog("[smp] {d} CPU(s) online\n", .{cpu_count});

    // Stand up the bottom-half engine now that every AP is alive: one pinned
    // `ksoftirqd` per CPU. After this returns, `softirq.raise` from the IRQ0
    // tick (and, later, from device MSI-X top-halves) defers heavy completion
    // work here instead of running it in IF=0 hard-IRQ context.
    @import("../proc/softirq.zig").startAll();
}

fn busyWait(ms: u32) void {
    // Simple busy wait using port 0x80 (each I/O takes ~1µs)
    for (0..ms * 1000) |_| {
        asm volatile ("outb %%al, $0x80"
            :
            : [al] "{al}" (@as(u8, 0))
        );
    }
}

/// Per-CPU bring-up shared by the boot AP entry (`apEntry`) and the S3-resume
/// re-online entry (`apEntryS3Resume`). Stamps sipi_acked, then re-establishes
/// every piece of per-CPU CPU state (GDT/TSS, IDT, syscall MSRs, EFER.NXE,
/// SMEP/SMAP, MCE/PMU, LAPIC + timer, CR0.WP, PAT) and marks the CPU alive.
/// Returns this CPU's LAPIC id. The ONLY thing the two callers do differently is
/// what they dispatch into afterwards (a fresh idle PCB vs. the surviving one).
///
/// INVARIANT: EFER.NXE is still 0 on this AP until syscall_entry.init() (called
/// below) turns it on. Until then nothing here may walk a PTE with bit 63 (NX)
/// set, or the CPU takes a reserved-bit #PF → #DF → triple-fault with no IDT
/// installed yet. Safe today because the only memory touched pre-NXE is the
/// kernel image (.text/.bss, mapped NX-clear), including this AP's isr_stack —
/// keep any vmm-allocated / NX-mapped access *after* syscall_entry.init(). Same
/// deferral as boot.asm's BSP path.
fn apInitPerCpu() u8 {
    // Figure out our LAPIC ID
    const my_id: u8 = @truncate(apic.getLapicId());

    // Stamp sipi_acked FIRST — before any work that could fault or hang.
    // BSP-side wait loop uses this to discriminate startup vs init failure.
    // .release pairs with the BSP's .acquire load in the bring-up spin loop.
    @atomicStore(bool, &cpus[my_id].sipi_acked, true, .release);

    // Set up per-CPU data
    cpus[my_id].cpu_id = my_id;
    cpus[my_id].lapic_id = my_id;

    // Initialize per-CPU asm storage + GS_BASE for syscalls landing on this AP
    initPerCpuAsm(my_id);

    // Initialize per-CPU GDT with our own TSS
    initPerCpuGdt(&cpus[my_id]);

    // Load shared IDT
    gdt.loadIdt();

    // Program syscall/sysret MSRs on this AP. EFER.SCE, STAR, LSTAR, SFMASK
    // are *per-CPU* — without this, any user process scheduled on the AP
    // raises #UD on the `syscall` instruction (because SCE=0). Symptom is
    // very mute: the user just hangs / disappears with no trace, since #UD
    // from a process that hasn't issued any syscall yet means we have no
    // earlier dispatch to log around. (Spent an evening chasing exactly this
    // bug — see feedback_smp_syscall_msrs.md.)
    @import("syscall/entry.zig").init();
    // LBR is per-CPU — enable on each AP too, otherwise crashes on this
    // CPU dump an empty branch ring.
    @import("../debug/lbr.zig").enable();
    // Tripwire: assert MSRs landed correctly before we let the AP hit user
    // code. Catches future "init() got refactored and dropped a wrmsr" too.
    var label_buf: [16]u8 = undefined;
    const label = std.fmt.bufPrint(&label_buf, "AP{d}", .{my_id}) catch "AP?";
    @import("syscall/entry.zig").verifyMsrs(label);

    // SMEP/UMIP + SMAP. AP's kstack is allocated in the physmap (high-VA,
    // U/S=0) from the start, so SMAP enable is safe immediately — unlike
    // BSP which has to wait for paging.dropLowIdentity.
    @import("arch/protect.zig").applyEarlyCr4();
    @import("arch/protect.zig").enableSmapPerCpu();
    @import("arch/mce.zig").perCpuInit();
    @import("arch/pmu.zig").perCpuInit();

    // Enable our LAPIC
    apic.initLAPICForAP();

    // CR0.WP is per-CPU. Without this on APs, kernel-mode writes ignore
    // R/W=0 PTEs, so the MMU write-watch (idt.zig ww_page) only catches
    // BSP-side wild writes. Make it symmetric.
    @import("../mm/paging.zig").enableCR0WriteProtect();

    // PAT is per-CPU. BSP set PA4=WC at boot; APs need their own write
    // or they'll interpret PAT-bit pages as WB and the FB writes won't
    // coalesce on this CPU.
    @import("../mm/paging.zig").setupPat();

    // Start our LAPIC timer at 100Hz
    apic.startTimerForAP();

    // Mark alive — .release publishes all the per-CPU init above; the BSP
    // observes `alive` with an .acquire load before counting us online.
    @atomicStore(bool, &cpus[my_id].alive, true, .release);

    return my_id;
}

/// AP entry point — called from trampoline after entering 64-bit mode (boot).
export fn apEntry() callconv(.c) noreturn {
    const my_id = apInitPerCpu();

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
/// pointing AP_ENTRY_SLOT here instead of at `apEntry`. Identical per-CPU
/// bring-up, but REUSES this CPU's idle PCB (which survived S3 in RAM) instead
/// of creating a new one — `createKernelIdle` would allocate a fresh PCB slot
/// every resume and leak the old one. The surviving PCB's saved context is stale
/// (the CPU's live registers were lost at suspend), so we re-plant a fresh
/// `kernelIdle` switch frame before dispatching. Falls back to a fresh idle only
/// if this CPU somehow has no idle_pid (came up on resume but not at boot).
export fn apEntryS3Resume() callconv(.c) noreturn {
    const my_id = apInitPerCpu();

    // apInitPerCpu ran on the resume CR3 — the suspending PROCESS's page tables,
    // which carry the 0x8000 low-identity the trampoline needed to enable paging.
    // Switch to the kernel master PML4 now, the stable table boot APs run their
    // idle on (page_dir_phys=0 idles resolve to getKernelPageDirPhys in schedule).
    // A process CR3 could be freed underneath us if that process later exits;
    // apInitPerCpu touched only kernel-high memory, so nothing here depended on
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

/// Re-establish the BSP's per-CPU CPU state after an S3 (suspend-to-RAM) resume.
/// On S3 wake the CPU comes back with GDTR/IDTR/TR, the syscall MSRs, EFER.NXE,
/// CR0.WP, CR4, PAT, and the LAPIC all reset. This mirrors the per-CPU bring-up
/// `apEntry` runs on an AP, but for the BSP (CPU 0) and WITHOUT creating an idle
/// task: the caller (src/acpi/s3.zig) longjmps back into the suspending syscall
/// afterwards, so the BSP resumes its existing kernel context rather than
/// starting a new one.
///
/// NXE invariant (identical to apEntry): runs with EFER.NXE still 0 until
/// `syscall/entry.zig.init()` below re-enables it, so nothing here may touch an
/// NX-mapped page before that. Only the kernel image + cpus[]/GDT/IDT (all
/// mapped NX-clear) are touched pre-NXE, exactly as on the AP path.
pub fn reinitForS3Resume() void {
    const bsp = &cpus[0];

    // FIRST: re-enable the LAPIC and re-derive `x2apic_active` from the reset
    // IA32_APIC_BASE. Must precede any getLapicId()/myCpu() below — the stale
    // RAM flag would otherwise route LAPIC access down the wrong MMIO/MSR path
    // and #GP. Enabling the LAPIC this early is safe: IF is still 0 (the wake
    // trampoline cli'd and never sti'd) and the timer isn't armed until the end.
    apic.reinitLapicForS3Resume();

    // Per-CPU syscall scratch + per-CPU GDT/TSS. Preserve tss.rsp0 (the CURRENT
    // process's kernel stack, set by the last setTssRsp0) across initPerCpuGdt,
    // which would otherwise reset it to the isr_stack — the suspending app must
    // land its next syscall on its own kstack, not the IST/ISR stack (the
    // cross-stack-aliasing hazard). ist1 is process-independent, so letting
    // initPerCpuGdt re-set it to the isr_stack top is correct.
    initPerCpuAsm(0);
    const saved_rsp0 = bsp.tss.rsp0;
    initPerCpuGdt(bsp);
    bsp.tss.rsp0 = saved_rsp0;

    // Shared IDT.
    gdt.loadIdt();

    // syscall/sysret MSRs (SCE/STAR/LSTAR/SFMASK) + EFER.NXE. Required for the
    // eventual sysret back to userspace, and re-enables NXE for everything after.
    @import("syscall/entry.zig").init();
    @import("../debug/lbr.zig").enable();
    @import("syscall/entry.zig").verifyMsrs("S3-BSP");

    // SMEP/UMIP + SMAP, MCE, PMU — all per-CPU, all reset by S3.
    @import("arch/protect.zig").applyEarlyCr4();
    @import("arch/protect.zig").enableSmapPerCpu();
    @import("arch/mce.zig").perCpuInit();
    @import("arch/pmu.zig").perCpuInit();

    // CR0.WP + PAT (per-CPU, reset by S3).
    @import("../mm/paging.zig").enableCR0WriteProtect();
    @import("../mm/paging.zig").setupPat();

    // Timer last (mirrors apEntry) — arms IRQ0 at 100 Hz so the scheduler ticks
    // again the moment we return to userspace with IF=1.
    apic.startTimerForAP();
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

    // Re-copy the trampoline blob to 0x8000. Low memory [0,1 MiB) is PMM-reserved
    // so it almost certainly survived S3, but re-copy for determinism (and to
    // re-run the overrun guard) — mirrors init().
    const trampoline: [*]const u8 = @ptrCast(&ap_trampoline_start);
    const trampoline_size = @intFromPtr(&ap_trampoline_end) - @intFromPtr(&ap_trampoline_start);
    if (trampoline_size > AP_ENTRY_SLOT - TRAMPOLINE_ADDR)
        @panic("smp: AP trampoline blob overran its data slots (0x8000..0x8FE8)");
    const dest: [*]u8 = @ptrFromInt(paging.physToVirt(TRAMPOLINE_ADDR));
    @memcpy(dest[0..trampoline_size], trampoline[0..trampoline_size]);

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

        // Trampoline data slots: re-enter via apEntryS3Resume, load the live
        // resume CR3 (NOT the kernel master PML4 — its low identity was dropped
        // at boot; resume_cr3 still maps 0x8000), reuse the AP's isr_stack for
        // bring-up (abandoned once it dispatches into idle, same as boot).
        const stack_top = @intFromPtr(&cpus[ap_id].isr_stack) + cpus[ap_id].isr_stack.len;
        const ap_entry_ptr: *volatile u64 = @ptrFromInt(paging.physToVirt(AP_ENTRY_SLOT));
        ap_entry_ptr.* = @intFromPtr(&apEntryS3Resume);
        const pml4_ptr: *volatile u64 = @ptrFromInt(paging.physToVirt(AP_PML4_SLOT));
        pml4_ptr.* = resume_cr3;
        const stack_ptr: *volatile u64 = @ptrFromInt(paging.physToVirt(AP_STACK_SLOT));
        stack_ptr.* = stack_top;

        apic.sendInitIPI(ap_id);
        busyWait(10);
        apic.sendSIPI(ap_id, AP_SIPI_VECTOR);
        busyWait(1);
        apic.sendSIPI(ap_id, AP_SIPI_VECTOR);

        // Wait for the AP to come back alive (apEntryS3Resume reached its end).
        var ms: u32 = 0;
        while (!@atomicLoad(bool, &cpus[ap_id].alive, .acquire) and ms < 500) : (ms += 1) {
            busyWait(1);
        }
        if (@atomicLoad(bool, &cpus[ap_id].alive, .acquire)) {
            cpu_count += 1;
            brought += 1;
            debug.klog("[smp] S3 re-online: AP {d} back ({d}ms)\n", .{ ap_id, ms });
        } else {
            debug.klog("[smp] S3 re-online: AP {d} did NOT come back ({d}ms timeout)\n", .{ ap_id, ms });
        }
    }
    debug.klog("[smp] S3 re-online: {d}/{d} AP(s) back, {d} CPU(s) online\n", .{ brought, ap_count, cpu_count });
}

/// Initialize this CPU's per-CPU syscall scratch slot. The kstack pointer
/// itself lives in cpus[cpu_id].tss.rsp0 and is stamped by setTssRsp0 on
/// the first per-process dispatch; until then no syscall can fire on this
/// CPU (BSP enters user via desktop.yieldToScheduler which calls
/// setTssRsp0 first; APs never enter user mode in this kernel).
fn initPerCpuAsm(cpu_id: u8) void {
    per_cpu_user_rsp[cpu_id] = 0;
}

fn initPerCpuGdt(cpu: *CpuLocal) void {
    // Copy standard segment entries from BSP
    const bsp_entries = gdt.getEntries();
    cpu.gdt_entries[0] = bsp_entries[0]; // null
    cpu.gdt_entries[1] = bsp_entries[1]; // kernel code
    cpu.gdt_entries[2] = bsp_entries[2]; // kernel data
    cpu.gdt_entries[3] = bsp_entries[3]; // user code
    cpu.gdt_entries[4] = bsp_entries[4]; // user data

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
    const caller_pd: u64 = asm volatile ("mov %%cr3, %[r]"
        : [r] "=r" (-> u64),
    );
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

// External symbols from ap_trampoline.asm
extern const ap_trampoline_start: u8;
extern const ap_trampoline_end: u8;
