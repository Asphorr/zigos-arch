//! The control queue: one command in flight at a time under ctrl_lock,
//! spin-then-sleep waits, the MSI-X handler and the lost-IRQ sweep.

const paging = @import("../../../mm/paging.zig");
const debug = @import("../../../debug/debug.zig");
const msix = @import("../../../irq/msix.zig");
const SpinLock = @import("../../../proc/spinlock.zig").SpinLock;
const Mutex = @import("../../../proc/spinlock.zig").Mutex;
const apic = @import("../../../irq/apic.zig");
const perf = @import("../../../debug/perf.zig");
const Deadline = @import("../../../util/deadline.zig").Deadline;
const vg = @import("../virtio_gpu.zig");
const virtio = @import("../../bus/virtio.zig");
const proto = @import("protocol.zig");
const present = @import("present.zig");

/// Slow-submit threshold for sendCmdViaPhys. When wait exceeds this, log
/// the cmd_type (first u32 of cmd_phys, per virtio-gpu spec) + lengths
/// so we can see *which* particular command is the bottleneck. 50ms is
/// well above normal (real cmds <1ms, blob page-flips ~16ms vsync) so
/// it only fires for genuinely pathological waits.
pub const SLOW_GPU_SUBMIT_THRESHOLD_MS: u64 = 50;

// Wall budget for the POLLED ctrl-vq fallback paths (no blockOn available:
// early boot, emergency mode, no task context). Virgl host renders can take
// frames, not µs — but a second of dead polling means the device is gone.
pub const CTRL_POLL_BUDGET_MS: u64 = 1000;

// Serialises all access to the control virtqueue. Without this, BSP rendering
// (flushRect/transferToHost called from the desktop) races with AP syscalls
// (gpuGetCapsetInfo, gpuCtxCreate, etc.) and corrupts the descriptor ring —
// previously seen as syscalls returning garbage cmd_types for index >= 1.
//
// Mutex (not SpinLock): sendCmd holds this across blockOn(.gpu_io) while
// waiting for the host's MSI-X response (~50-80ms). A SpinLock here would
// deadlock — the holder yields via blockOn, scheduler picks another task
// on the same CPU, that task tries to acquire and spins forever because
// SpinLock keys ownership by CPU. Mutex keys by PCB, so the waiter
// correctly sleeps on .mutex and is woken on release. (See the
// 2026-05-16 fastfetch wedge for the original incident.)
pub var ctrl_lock: Mutex = .{};

/// True iff a GPU control-channel op is in flight on some pid. Used by the
/// panic-screen render path to skip post_blit_fn (= flushUnconditional)
/// when calling it would recursively acquire ctrl_lock from a pid that
/// already owns it (interrupted mid-sendCmd by a panic). Snapshot only —
/// fine for the panic case (single-shot, racy-but-not-fatal).
pub fn ctrlLockBusy() bool {
    return ctrl_lock.isHeld();
}

// MSI-X / IRQ-driven completion state. When `use_msix` is true, sendCmd
// blocks on `sti; hlt` instead of a `pause` spin — woken by either the
// virtio-gpu IRQ or the LAPIC tick. Saves milliseconds of CPU per Vulkan
// frame which would otherwise be burned in `pause`.
pub var use_msix: bool = false;

/// Diagnostic switch for bisecting async-wait wedges. When true,
/// sendCmdViaPhys skips the blockOn(.gpu_io) path and pause-spins
/// instead — same as the early-boot pre-MSI-X behaviour. CLI / kdbg
/// can flip this live; sendCmd reads it on entry so the next submit
/// uses the new mode. Cost when false: one memory load per submit.
pub var force_polled: bool = false;

/// True iff VIRTIO_F_RING_EVENT_IDX was negotiated. When set, sendCmdViaPhys
/// writes the target usedIdx into ctrl_vq.usedEvent() before HLT so the
/// device knows exactly when to fire MSI-X — workaround for QEMU's
/// re-entrancy guard silently dropping unconditional notifications.
pub var use_event_idx: bool = false;

/// MSI-X table entry kernel-virtual address, captured at arm time so
/// sendCmdViaPhys can re-target the entry to the calling CPU's APIC ID
/// before each wait. Steering MSI-X to the same CPU as the `sti; hlt`
/// waiter cuts cmd latency from ~10ms (next LAPIC tick) to ~µs (real
/// completion IRQ on the waiting CPU). 0 means "not armed".
pub var msix_entry_addr: usize = 0;

/// The single pid currently parked in blockOn(.gpu_io) via sendCmdViaPhys
/// / sendSimpleCmdPair. ctrl_lock serializes submitters so there's at
/// most one. 0xFF = nobody waiting; otherwise = pid. Updated atomically
/// because the IRQ handler reads it concurrently from any CPU.
pub var current_gpu_waiter: u8 = 0xFF;
pub fn virtioGpuIrqHandler() callconv(.c) void {
    vg.virtio_gpu_irq_count +%= 1;
    const smp_mod = @import("../../../cpu/smp.zig");
    const cpu_id = smp_mod.myCpu().cpu_id;
    if (cpu_id < vg.virtio_gpu_irq_per_cpu.len) vg.virtio_gpu_irq_per_cpu[cpu_id] +%= 1;
    const process = @import("../../../proc/process.zig");

    // Async flush completion: nobody is parked for it — hand the reap (and
    // the coalesced-rect resubmit) to ksoftirqd via the .virtio_gpu softirq,
    // same discipline as the NVMe reap. One atomic load when idle.
    if (@atomicLoad(bool, &present.aflush_in_flight, .acquire)) {
        _ = @import("../../../irq/softirq.zig").raise(.virtio_gpu);
        smp_mod.myCpu().dynirq_preempt_pending = true;
    }

    // Direct waiter lookup (gap #8): ctrl_lock serializes submitters, so
    // current_gpu_waiter is at most one pid. Parked on its command, or
    // about to park (wait_kind still .none): wake() readies it now, or
    // sets wake_pending for blockOn's handshake. A waiter that already
    // moved on to another wait is left to that wait's waker. The waiter's
    // own wake_tick stays the backstop for a dropped IRQ (CVE-2024-3446).
    // wake() is IF=0-safe — softirq.raise calls it from IRQs too.
    const pid = @atomicLoad(u8, &current_gpu_waiter, .acquire);
    if (pid == 0xFF) return;
    const kind = @atomicLoad(process.WaitKind, &process.procs[pid].wait_kind, .acquire);
    if (kind != .gpu_io and kind != .none) return;
    const wakelat = @import("../../../debug/wakelat.zig");
    const sched = @import("../../../proc/sched.zig");
    wakelat.noteGpuIrq(pid);
    wakelat.hintWake(pid, .gpu_io);
    sched.wake(pid);
    vg.virtio_gpu_waiter_wakes +%= 1;
    // Queued on this CPU: the dynirq epilogue runs it if it outranks the
    // current task. On another CPU, wake() sent the reschedule IPI.
    if (sched.wakeupPreemptsLocal(pid)) smp_mod.myCpu().dynirq_preempt_pending = true;
}
pub var ctrl_vq: vg.Virtqueue = .{};

// Pre-allocated command buffer (4 pages = 16KB for large attach_backing) and response page
pub const CMD_PAGES: u32 = 4;
pub var cmd_phys: usize = 0;
pub var resp_phys: usize = 0;

// --- Cache-coherence helpers (gap #1+#2, 2026-05-20) ---
//
// Same race class as `nvme.zig:562-565`'s clflush dance: QEMU's GTK /
// Venus / display backend runs on a different host CPU than the guest's
// vCPU0. The host writes `usedIdx` and `resp_phys` directly into guest
// memory through QEMU's mmap, BYPASSING the guest's vCPU. Without an
// explicit clflush + mfence on the guest side, our L1 keeps a stale
// (pre-DMA) cache line — we read zero / unchanged for the field the
// host already updated. Symptom: the Phase A poll spin times out, the
// hlt waiter only "sees" the change when the cache line gets evicted
// for other reasons (10+ ms later); on the resp read the cmd_type
// reads as 0 instead of RESP_OK_NODATA, the caller treats the (already-
// successful) command as failed, retries, retries, retries — the
// multi-minute compositor freeze user observed 2026-05-20.

/// Invalidate a single cache line (assumed aligned to 64 B) and order
/// the subsequent reads. mfence is the cross-CPU barrier; clflush alone
/// only invalidates the line on the local CPU.
pub inline fn clflushLine(addr: usize) void {
    asm volatile ("clflush (%[a])"
        :
        : [a] "r" (addr),
        : .{ .memory = true });
    asm volatile ("mfence" ::: .{ .memory = true });
}

/// Invalidate every cache line covering `[addr, addr+len)`. Used for
/// the response buffer, which can be larger than one cache line
/// (e.g. RESP_OK_DISPLAY_INFO is 280 B = 5 lines).
pub inline fn clflushRange(addr: usize, len: usize) void {
    var p = addr & ~@as(usize, 63);
    const end = addr + len;
    while (p < end) : (p += 64) {
        asm volatile ("clflush (%[a])"
            :
            : [a] "r" (p),
            : .{ .memory = true });
    }
    asm volatile ("mfence" ::: .{ .memory = true });
}

/// Coherent read of a virtqueue's used_idx. Replaces every bare
/// `vq.usedIdx().*` read in the wait paths. Without this the polling
/// loops were observing stale values for arbitrarily long until the
/// cache line got naturally evicted.
pub inline fn usedIdxCoherent(vq: *vg.Virtqueue) u16 {
    clflushLine(@intFromPtr(vq.usedIdx()));
    return vq.usedIdx().*;
}

// --- Command sending ---

/// Internal: run the descriptor-chain dance against ctrl_vq with a command
/// already sitting in `cmd_phys` (length `cmd_len`) and a zeroed response
/// buffer of `resp_len` at `resp_phys`. Caller holds `ctrl_lock`.
///
/// This is the shared implementation that `sendCmd` (caller buffer) and
/// the in-place builders (attachBacking, submit3D, resourceCreateGuestBlob)
/// both need. Before this existed, each in-place builder duplicated ~25
/// lines of identical descriptor-chain + wait-loop code.
pub fn sendCmdViaPhys(cmd_len: u32, resp_len: u32) bool {
    // Bracket the entire submit-and-wait so per-syscall latency attribution
    // can show "sysGpuSubmit3D dt=900ms = 870ms gpu_wait + 30ms misc".
    const sp = @import("../../../debug/syscall_perf.zig").scope(.gpu_wait);
    defer sp.end();
    if (ctrl_vq.num_free < 2) return false;

    const d0_idx = ctrl_vq.free_head;
    const d0 = ctrl_vq.descPtr(d0_idx);
    const d1_idx: u16 = @intCast(d0.next);
    const d1 = ctrl_vq.descPtr(d1_idx);
    ctrl_vq.free_head = @intCast(d1.next);
    ctrl_vq.num_free -= 2;

    d0.addr = cmd_phys;
    d0.len = cmd_len;
    d0.flags = virtio.VRING_DESC_F_NEXT;
    d0.next = d1_idx;

    d1.addr = resp_phys;
    d1.len = resp_len;
    d1.flags = virtio.VRING_DESC_F_WRITE;
    d1.next = 0;

    const ai = ctrl_vq.availIdx().*;
    ctrl_vq.availRing(ai % ctrl_vq.queue_size).* = d0_idx;
    asm volatile ("" ::: .{ .memory = true }); // compiler barrier; x86 TSO handles CPU ordering
    ctrl_vq.availIdx().* = ai +% 1;

    // Re-target MSI-X to the calling CPU's APIC ID BEFORE notifying the
    // host. Hyper-V halts a vCPU while it's in HLT — virtual LAPIC stops
    // ticking, so the only thing that wakes our `sti; hlt` is the actual
    // completion IRQ. If MSI-X is aimed at another CPU while we wait on
    // cpu1, the wake never arrives directly; cube only resumes when some
    // other CPU IPIs/NMIs cpu1 (e.g. spinlock NMI broadcast at ~50ms),
    // so wait_ms ends up dominated by that side-channel rather than real
    // host time. ctrl_lock serializes submitters, so retarget is race-free
    // — whoever holds the lock owns the MSI-X destination for this submit.
    if (msix_entry_addr != 0) {
        const my_cpu = @import("../../../cpu/smp.zig").myCpu();
        const my_apic_id: u32 = my_cpu.lapic_id;
        @import("../../../irq/msix.zig").retargetEntry(msix_entry_addr, my_apic_id);
        // One-shot diagnostic: confirm we're actually retargeting with a
        // sane lapic_id (not 0 from uninit). Also dump the post-retarget
        // entry contents so we can see whether QEMU honored the rewrite.
        const dbg_state = struct {
            var seen: [4]bool = .{ false, false, false, false };
        };
        if (my_cpu.cpu_id < 4 and !dbg_state.seen[my_cpu.cpu_id]) {
            dbg_state.seen[my_cpu.cpu_id] = true;
            const e_ptr: [*]const volatile u32 = @ptrFromInt(msix_entry_addr);
            debug.klog(
                "[gpu-msix-retarget] cpu={d} lapic_id={d} entry: addr_lo=0x{X} addr_hi=0x{X} data=0x{X} vc=0x{X}\n",
                .{ my_cpu.cpu_id, my_apic_id, e_ptr[0], e_ptr[1], e_ptr[2], e_ptr[3] },
            );
        }
    }

    // EVENT_IDX: tell the device "fire MSI-X when usedIdx reaches THIS value".
    // last_used_idx is the value we last consumed; we want a notification
    // when usedIdx advances past it. Spec: device fires when
    // `usedIdx == used_event + 1`. So write last_used_idx into used_event
    // and the very next response triggers an IRQ. Must be written BEFORE
    // notifyQueue so the device sees it before processing the cmd.
    if (use_event_idx) {
        ctrl_vq.usedEvent().* = ctrl_vq.last_used_idx;
        asm volatile ("" ::: .{ .memory = true }); // compiler barrier; x86 TSO handles CPU ordering
    }

    vg.notifyQueue(0, &ctrl_vq);

    // Bookend the wait in TSC so we can attribute slow submits to the
    // specific cmd_type (first u32 of cmd_phys per virtio-gpu spec).
    // Without this, all we see is "ctrl_lock held for 10s" — no clue
    // whether it was SUBMIT_3D, RESOURCE_CREATE_3D, TRANSFER_TO_HOST,
    // or a fence wait that triggered it.
    const wait_start_tsc = perf.rdtsc();

    // Wait for the host to advance used_idx. Two paths:
    //   * MSI-X armed (post-init): `sti; hlt` until either our handler
    //     fires or the LAPIC tick wakes us. Cheap — CPU is HLT-idle so
    //     it can serve other IRQs (network, disk, kbd) instead of
    //     burning ~3 ms of `pause` per command. 100 ticks ≈ 1 s
    //     timeout on the default 10 ms LAPIC period — was 1000 (=10s),
    //     way too long; real cmds complete in <1 ms.
    //   * Polled (init phase, before MSI-X is wired): legacy `pause`
    //     spin with a 10M-iteration cap.
    // Hoisted out of the blk so the slow-submit log can include it.
    var hlt_iters: u32 = 0;
    // Short adaptive spin-poll BEFORE falling to MSI-X-driven hlt.
    // Workaround for CVE-2024-3446's mem_reentrancy_guard side-effect:
    // QEMU's virtio devices silently drop virtio_notify() calls when
    // the host re-enters the device's MMIO region during command
    // processing — common for SUBMIT_3D where Venus touches blob/
    // dma-buf regions. Without phase A, simple flushes whose IRQ got
    // dropped would hlt for the full LAPIC tick (10 ms) waiting.
    //
    // Trade-off: phase A burns 100 % CPU. The old 100 ms window cost
    // ~21 ms per flush × 21 flushes/s = 40 %+ of one CPU. A 200 µs
    // window catches the truly fast path (most ctrl-vq cmds complete
    // in < 20 µs) and falls through to hlt for genuinely slow ones —
    // which now spend their wait in C-state at ~0 % CPU, woken by the
    // LAPIC tick to re-check usedIdx.
    var phase_a_pause_iters: u64 = 0;
    var phase_a_done_via_poll: bool = false;
    // Gap #5 (2026-05-20): read cmd_type up front so we can pass it as
    // the blockOn target. Was previously read only on the slow-gpu log
    // path (line ~807, post-wait); now also used to identify which cmd
    // is hanging when the yield-loop / stuck-waiter detector dumps us.
    const cmd_type_for_target: u32 = blk_ct: {
        const cv: [*]const volatile u32 = @ptrFromInt(paging.physToVirt(cmd_phys));
        break :blk_ct cv[0];
    };
    if (use_msix and vg.msix_safe_to_use and !force_polled) {
        const tsc_per_q = apic.tscPerQuantum();
        if (tsc_per_q > 0) {
            // 200 µs at 100 Hz tick (tsc_per_q = ticks per 10 ms) = q/50.
            const deadline = perf.rdtsc() +% (tsc_per_q / 50);
            while (perf.rdtsc() < deadline) : (phase_a_pause_iters +%= 1) {
                if (ctrl_vq.last_used_idx != usedIdxCoherent(&ctrl_vq)) {
                    phase_a_done_via_poll = true;
                    break;
                }
                asm volatile ("pause");
            }
        }
    }
    const wake_runs_before_cpu0 = @import("../../../proc/process.zig").wake_handler_runs[0];
    const wake_runs_before_cpu1 = @import("../../../proc/process.zig").wake_handler_runs[1];
    const got_response: bool = blk: {
        if (phase_a_done_via_poll) break :blk true;
        if (use_msix and vg.msix_safe_to_use and !force_polled) {
            // Sleep-yield wait. blockOn parks the calling PCB in .sleeping
            // with wait_kind=.gpu_io; schedule() then picks idle (or
            // another runnable task), so the wait counts as idle time.
            // Without this yield, the submitter holds current_pid
            // through the entire wait and the menubar / sysmon CPU bars
            // peg at 100 % even though the CPU is in C-state.
            // virtioGpuIrqHandler wakes the .gpu_io waiter when usedIdx
            // advances; ctrl_lock keeps the waiter count at ≤ 1.
            //
            // Timeout: re-check after each yield; bail after 100
            // schedule round-trips (~1 s if waking only via the 10 ms
            // LAPIC tick; far sooner under any real GPU IRQ delivery).
            const process = @import("../../../proc/process.zig");
            const cur_pid_outer = @import("../../../cpu/smp.zig").currentPid() orelse break :blk false;
            // Stamp ourselves as THE gpu_io waiter so virtioGpuIrqHandler
            // can wake us directly. Cleared by defer on every exit path
            // (true, false, or panic-unwind).
            @atomicStore(u8, &current_gpu_waiter, @intCast(cur_pid_outer), .release);
            defer @atomicStore(u8, &current_gpu_waiter, 0xFF, .release);
            while (true) {
                if (ctrl_vq.last_used_idx != usedIdxCoherent(&ctrl_vq)) {
                    break :blk true;
                }
                if (hlt_iters >= 100) {
                    break :blk false;
                }
                // Safety-net: set wake_tick = now + 1 tick (~10 ms) so
                // wakeExpired() wakes us if the GPU IRQ goes missing
                // (CVE-2024-3446 drops virtio_notify under reentrancy).
                // The primary waker is still virtioGpuIrqHandler — now
                // routes through current_gpu_waiter direct lookup. Set
                // wake_tick BEFORE blockOn so the soft-yield doesn't race
                // wakeExpired clearing it. @atomicStore to avoid racing
                // the IRQ handler's @atomicStore of wake_tick = now
                // (without atomicity, the IRQ's "wake now" could be
                // clobbered by our "wake at now+1" → one extra tick of
                // latency per loss).
                @atomicStore(
                    u64,
                    &process.procs[cur_pid_outer].wake_tick,
                    process.tick_count +% 1,
                    .release,
                );
                @import("../../../proc/sched.zig").registerWakeDeadline(process.tick_count +% 1);
                process.blockOn(.gpu_io, cmd_type_for_target);
                hlt_iters += 1;
            }
        } else {
            var d = Deadline.ms(CTRL_POLL_BUDGET_MS, "virtio-gpu ctrl vq (polled)");
            while (ctrl_vq.last_used_idx == usedIdxCoherent(&ctrl_vq) and d.live()) {
                asm volatile ("pause");
            }
            // Re-check rather than trust the deadline: a completion landing
            // on the final iteration is a success, not a timeout.
            break :blk ctrl_vq.last_used_idx != usedIdxCoherent(&ctrl_vq);
        }
    };

    // Free descriptors regardless of timeout. On timeout we re-sync our
    // cursor to the host's actual usedIdx — the original "leave it stale
    // to avoid poisoning" comment had the failure mode backwards: when
    // the host completes our cmd AFTER we time out, usedIdx advances and
    // the NEXT caller sees `last != used`, returns true immediately
    // without waiting, and reads a stale resp_phys for our (already-
    // dead) cmd. Re-syncing on timeout costs nothing if usedIdx hasn't
    // moved, and prevents the cascade if it has.
    if (got_response) {
        ctrl_vq.last_used_idx +%= 1;
    } else {
        ctrl_vq.last_used_idx = usedIdxCoherent(&ctrl_vq);
    }
    d1.next = ctrl_vq.free_head;
    d0.next = d1_idx;
    ctrl_vq.free_head = d0_idx;
    ctrl_vq.num_free += 2;

    // Slow-submit breadcrumb. Read cmd_type AFTER the wait so a partially-
    // initialised cmd buffer can't fault us in the hot path; the cmd has
    // been DMA-visible to the host since notifyQueue, so the read here
    // reflects what we actually submitted.
    const wait_dt = perf.rdtsc() -% wait_start_tsc;
    const wait_ms = apic.tscToMs(wait_dt);
    if (wait_ms >= SLOW_GPU_SUBMIT_THRESHOLD_MS) {
        const cmd_virt: [*]const volatile u32 = @ptrFromInt(paging.physToVirt(cmd_phys));
        const cmd_type = cmd_virt[0];
        const wake_d_cpu0 = @import("../../../proc/process.zig").wake_handler_runs[0] -% wake_runs_before_cpu0;
        const wake_d_cpu1 = @import("../../../proc/process.zig").wake_handler_runs[1] -% wake_runs_before_cpu1;
        debug.klog(
            "[slow-gpu] cmd_type=0x{X} cmd_len={d} resp_len={d} wait={d}ms hlt_iters={d} poll_iters={d} via_poll={any} wake_during(cpu0={d},cpu1={d}) ok={any}\n",
            .{ cmd_type, cmd_len, resp_len, wait_ms, hlt_iters, phase_a_pause_iters, phase_a_done_via_poll, wake_d_cpu0, wake_d_cpu1, got_response },
        );
    }

    if (!got_response) {
        debug.klog("[virtio-gpu] Command timeout (usedIdx now {d})\n", .{ctrl_vq.last_used_idx});
        return false;
    }
    return true;
}

pub fn sendCmd(cmd_buf: [*]const u8, cmd_len: u32, resp_buf: [*]u8, resp_len: u32) bool {
    // LIFO defers: runs AFTER the release below. If a flush-completion
    // softirq landed while we held the lock (ksoftirqd tryAcquire missed),
    // re-kick so pending damage doesn't wait on the 10 Hz backstop.
    defer present.kickPendingFromTask();
    ctrl_lock.acquire();
    defer ctrl_lock.release();
    // An async flush pair may still be outstanding — wait for + reap it so
    // the one-op-at-a-time last_used_idx accounting (and the shared cmd/
    // resp slots) are ours alone.
    present.waitAsyncFlushIdleLocked();

    const cmd_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(cmd_phys));
    @memcpy(@as([*]volatile u8, cmd_dst)[0..cmd_len], cmd_buf[0..cmd_len]);

    const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(resp_phys));
    @memset(@as([*]volatile u8, resp_dst)[0..resp_len], 0);

    if (!sendCmdViaPhys(cmd_len, resp_len)) return false;

    // Gap #2: clflush before reading the device-written resp. Without
    // this we sometimes saw cmd_type=0 (stale zero from the @memset
    // above) instead of the actual RESP_OK_*; caller then treated the
    // (already-successful) command as failed.
    clflushRange(@intFromPtr(resp_dst), resp_len);
    @memcpy(resp_buf[0..resp_len], @as([*]const volatile u8, resp_dst)[0..resp_len]);
    return true;
}

pub fn sendSimpleCmd(cmd_buf: [*]const u8, cmd_len: u32) bool {
    var resp: proto.CtrlHdr = .{};
    if (!sendCmd(cmd_buf, cmd_len, @as([*]u8, @ptrCast(&resp)), @sizeOf(proto.CtrlHdr))) return false;
    if (resp.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] Error response: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}

/// Per-chain cmd slot within `cmd_phys` for the batched-pair path. The
/// flush hot path only uses two slots (256 B each is way more than
/// `SetScanoutBlob` or `ResourceFlush` need) and we already have 16 KB
/// of `cmd_phys` reserved. Same offsets used for `resp_phys`.
pub const PAIR_CMD_SLOT_BYTES: u32 = 256;

/// Batched-submit equivalent of two back-to-back `sendSimpleCmd` calls.
/// Submits both cmds to the controlq before notifying the device once,
/// then blocks on a single MSI-X round-trip until *both* responses
/// arrive. Used by the compositor flush path where the
/// `SetScanoutBlob` + `ResourceFlush` pair previously took two host
/// round-trips (~41 ms mean) per frame; batching halves it.
///
/// Returns true only when both commands returned `RESP_OK_NODATA`.
pub fn sendSimpleCmdPair(
    cmd0_buf: [*]const u8,
    cmd0_len: u32,
    cmd1_buf: [*]const u8,
    cmd1_len: u32,
) bool {
    defer present.kickPendingFromTask(); // see sendCmd — runs after the release
    ctrl_lock.acquire();
    defer ctrl_lock.release();
    // See sendCmd: drain any outstanding async flush pair first.
    present.waitAsyncFlushIdleLocked();

    if (ctrl_vq.num_free < 4) return false;
    if (cmd0_len > PAIR_CMD_SLOT_BYTES or cmd1_len > PAIR_CMD_SLOT_BYTES) return false;

    // Stage cmd buffers into the shared cmd_phys page (slot 0 + slot 1)
    // and zero the response slots.
    const cmd_base: usize = paging.physToVirt(cmd_phys);
    const resp_base: usize = paging.physToVirt(resp_phys);
    const cmd0_dst: [*]volatile u8 = @ptrFromInt(cmd_base);
    const cmd1_dst: [*]volatile u8 = @ptrFromInt(cmd_base + PAIR_CMD_SLOT_BYTES);
    const resp0_dst: [*]volatile u8 = @ptrFromInt(resp_base);
    const resp1_dst: [*]volatile u8 = @ptrFromInt(resp_base + PAIR_CMD_SLOT_BYTES);
    @memcpy(cmd0_dst[0..cmd0_len], cmd0_buf[0..cmd0_len]);
    @memcpy(cmd1_dst[0..cmd1_len], cmd1_buf[0..cmd1_len]);
    @memset(resp0_dst[0..@sizeOf(proto.CtrlHdr)], 0);
    @memset(resp1_dst[0..@sizeOf(proto.CtrlHdr)], 0);

    const sp = @import("../../../debug/syscall_perf.zig").scope(.gpu_wait);
    defer sp.end();

    // Allocate two chains of two descriptors each: (cmd0→resp0), (cmd1→resp1).
    const c0d0_idx = ctrl_vq.free_head;
    const c0d0 = ctrl_vq.descPtr(c0d0_idx);
    const c0d1_idx: u16 = @intCast(c0d0.next);
    const c0d1 = ctrl_vq.descPtr(c0d1_idx);
    const c1d0_idx: u16 = @intCast(c0d1.next);
    const c1d0 = ctrl_vq.descPtr(c1d0_idx);
    const c1d1_idx: u16 = @intCast(c1d0.next);
    const c1d1 = ctrl_vq.descPtr(c1d1_idx);
    ctrl_vq.free_head = @intCast(c1d1.next);
    ctrl_vq.num_free -= 4;

    c0d0.addr = cmd_phys;
    c0d0.len = cmd0_len;
    c0d0.flags = virtio.VRING_DESC_F_NEXT;
    c0d0.next = c0d1_idx;
    c0d1.addr = resp_phys;
    c0d1.len = @sizeOf(proto.CtrlHdr);
    c0d1.flags = virtio.VRING_DESC_F_WRITE;
    c0d1.next = 0;

    c1d0.addr = cmd_phys + PAIR_CMD_SLOT_BYTES;
    c1d0.len = cmd1_len;
    c1d0.flags = virtio.VRING_DESC_F_NEXT;
    c1d0.next = c1d1_idx;
    c1d1.addr = resp_phys + PAIR_CMD_SLOT_BYTES;
    c1d1.len = @sizeOf(proto.CtrlHdr);
    c1d1.flags = virtio.VRING_DESC_F_WRITE;
    c1d1.next = 0;

    // Publish BOTH chain heads in avail before notifying. Two avail
    // entries, one notify — device sees a 2-deep batch and processes
    // them in pipeline; we only pay one MSI-X round-trip.
    var ai = ctrl_vq.availIdx().*;
    ctrl_vq.availRing(ai % ctrl_vq.queue_size).* = c0d0_idx;
    ai +%= 1;
    ctrl_vq.availRing(ai % ctrl_vq.queue_size).* = c1d0_idx;
    asm volatile ("" ::: .{ .memory = true });
    ctrl_vq.availIdx().* = ai +% 1;

    if (msix_entry_addr != 0) {
        const my_cpu = @import("../../../cpu/smp.zig").myCpu();
        const my_apic_id: u32 = my_cpu.lapic_id;
        @import("../../../irq/msix.zig").retargetEntry(msix_entry_addr, my_apic_id);
    }

    // EVENT_IDX: ask device to fire IRQ when usedIdx == used_event + 1.
    // Setting used_event = last_used_idx + 1 means we only get one IRQ
    // when BOTH responses have landed — no spurious wake on the first.
    if (use_event_idx) {
        ctrl_vq.usedEvent().* = ctrl_vq.last_used_idx +% 1;
        asm volatile ("" ::: .{ .memory = true });
    }

    vg.notifyQueue(0, &ctrl_vq);

    const wait_start_tsc = perf.rdtsc();
    var hlt_iters: u32 = 0;
    var phase_a_pause_iters: u64 = 0;
    var phase_a_done_via_poll: bool = false;
    const target_idx: u16 = ctrl_vq.last_used_idx +% 2;
    // Gap #5: pass cmd0_type as the blockOn target so the autopsy can
    // name the operation. For the pair path this is typically
    // CMD_SET_SCANOUT_BLOB or CMD_TRANSFER_TO_HOST_2D (the flush hot path).
    const cmd_type_for_target: u32 = blk_ct: {
        const cv: [*]const volatile u32 = @ptrFromInt(cmd_base);
        break :blk_ct cv[0];
    };
    if (use_msix and vg.msix_safe_to_use and !force_polled) {
        const tsc_per_q = apic.tscPerQuantum();
        if (tsc_per_q > 0) {
            const deadline = perf.rdtsc() +% (tsc_per_q / 50);
            while (perf.rdtsc() < deadline) : (phase_a_pause_iters +%= 1) {
                // Gap #6: use `>=` (with wrap) instead of `==`. If the
                // device advances past target_idx for any reason (a
                // concurrent op crammed in by a future caller, or a
                // wraparound race), strict `==` would never trigger.
                // u16 wrap-aware "is at least target_idx" check: the
                // difference is small (≤ MAX_QUEUE_SIZE), so signed
                // (i16) subtraction handles wraps correctly.
                const used = usedIdxCoherent(&ctrl_vq);
                if (@as(i16, @bitCast(used -% target_idx)) >= 0) {
                    phase_a_done_via_poll = true;
                    break;
                }
                asm volatile ("pause");
            }
        }
    }
    const got_response: bool = blk: {
        if (phase_a_done_via_poll) break :blk true;
        if (use_msix and vg.msix_safe_to_use and !force_polled) {
            const process = @import("../../../proc/process.zig");
            const cur_pid_outer = @import("../../../cpu/smp.zig").currentPid() orelse break :blk false;
            // Single-waiter / targeted-IPI stamp; see sendCmdViaPhys above.
            @atomicStore(u8, &current_gpu_waiter, @intCast(cur_pid_outer), .release);
            defer @atomicStore(u8, &current_gpu_waiter, 0xFF, .release);
            while (true) {
                const used = usedIdxCoherent(&ctrl_vq);
                if (@as(i16, @bitCast(used -% target_idx)) >= 0) break :blk true;
                if (hlt_iters >= 100) break :blk false;
                // @atomicStore to avoid racing virtioGpuIrqHandler's
                // @atomicStore of wake_tick = now (see sendCmdViaPhys
                // for the full rationale).
                @atomicStore(
                    u64,
                    &process.procs[cur_pid_outer].wake_tick,
                    process.tick_count +% 1,
                    .release,
                );
                @import("../../../proc/sched.zig").registerWakeDeadline(process.tick_count +% 1);
                process.blockOn(.gpu_io, cmd_type_for_target);
                hlt_iters += 1;
            }
        } else {
            var d = Deadline.ms(CTRL_POLL_BUDGET_MS, "virtio-gpu ctrl vq target (polled)");
            while (@as(i16, @bitCast(usedIdxCoherent(&ctrl_vq) -% target_idx)) < 0 and d.live()) {
                asm volatile ("pause");
            }
            break :blk @as(i16, @bitCast(usedIdxCoherent(&ctrl_vq) -% target_idx)) >= 0;
        }
    };

    if (got_response) {
        ctrl_vq.last_used_idx +%= 2;
    } else {
        ctrl_vq.last_used_idx = usedIdxCoherent(&ctrl_vq);
    }

    // Return all 4 descriptors to the free list (preserve original
    // chain order so the next allocator sees a contiguous run).
    c1d1.next = ctrl_vq.free_head;
    c1d0.next = c1d1_idx;
    c0d1.next = c1d0_idx;
    c0d0.next = c0d1_idx;
    ctrl_vq.free_head = c0d0_idx;
    ctrl_vq.num_free += 4;

    const wait_dt = perf.rdtsc() -% wait_start_tsc;
    const wait_ms = apic.tscToMs(wait_dt);
    if (wait_ms >= SLOW_GPU_SUBMIT_THRESHOLD_MS) {
        const cmd0_virt: [*]const volatile u32 = @ptrFromInt(cmd_base);
        const cmd1_virt: [*]const volatile u32 = @ptrFromInt(cmd_base + PAIR_CMD_SLOT_BYTES);
        debug.klog(
            "[slow-gpu pair] cmd0=0x{X} cmd1=0x{X} wait={d}ms hlt={d} poll={d} via_poll={any} ok={any}\n",
            .{ cmd0_virt[0], cmd1_virt[0], wait_ms, hlt_iters, phase_a_pause_iters, phase_a_done_via_poll, got_response },
        );
    }

    if (!got_response) return false;

    // Gap #2: clflush both resp slots before decoding. Each CtrlHdr is
    // 24 B; clflushRange aligns to 64-byte lines so a single line covers
    // each slot, but call twice for clarity.
    clflushRange(resp_base, @sizeOf(proto.CtrlHdr));
    clflushRange(resp_base + PAIR_CMD_SLOT_BYTES, @sizeOf(proto.CtrlHdr));
    const resp0: *const proto.CtrlHdr = @ptrFromInt(resp_base);
    const resp1: *const proto.CtrlHdr = @ptrFromInt(resp_base + PAIR_CMD_SLOT_BYTES);
    if (resp0.cmd_type != proto.RESP_OK_NODATA or resp1.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] Pair error: resp0=0x{X} resp1=0x{X}\n", .{ resp0.cmd_type, resp1.cmd_type });
        return false;
    }
    return true;
}

/// Gap #3 (2026-05-20): per-tick sweeper, called from `handleIRQ0` on
/// BSP. Catches the case where the GPU device DID complete the command
/// but the IRQ never reached us (CVE-2024-3446 reentrancy guard silently
/// dropping virtio_notify, or PCIe posted-write ordering hiding the CQE
/// from the IRQ-time read). Walks the ctrl queue's coherent used_idx
/// and pokes all .gpu_io waiters' wake_tick to "now" so wakeExpired()
/// kicks them on the same tick. Mirrors `nvme.tickSweep`.
///
/// Cost when idle: one clflush + one memory read per tick. Sub-microsecond.
/// Whether irq0's backstop has anything for tickSweep: async-flush
/// bookkeeping, or a used index the driver hasn't consumed (a lost
/// completion IRQ). RAM reads only.
pub fn sweepWanted() bool {
    if (!vg.active or !use_msix) return false;
    if (@atomicLoad(bool, &present.aflush_in_flight, .acquire) or
        @atomicLoad(bool, &present.aflush_pending, .acquire)) return true;
    return usedIdxCoherent(&ctrl_vq) != ctrl_vq.last_used_idx;
}

pub fn tickSweep() void {
    if (!vg.active) return;
    if (!use_msix) return;
    // Async flush bookkeeping: reap a completed pair + submit the coalesced
    // pending rect. tryAcquire, never block — ksoftirqd must not park
    // behind a sync sender holding ctrl_lock across a host wait (input's
    // .hid drain runs behind us in the same task). A miss is fine: the
    // next IRQ-raise / tick / flush call retries. The bools gate keeps the
    // early-boot inline-fallback path (IF=0, no task) from ever touching
    // the Mutex: both stay false until asyncFlushEligible() holds, which
    // requires ksoftirqd to exist.
    if (@atomicLoad(bool, &present.aflush_in_flight, .acquire) or
        @atomicLoad(bool, &present.aflush_pending, .acquire))
    {
        if (ctrl_lock.tryAcquire()) {
            _ = present.reapAsyncFlushLocked();
            present.kickPendingFlushLocked();
            ctrl_lock.release();
        }
    }
    const hw_used = usedIdxCoherent(&ctrl_vq);
    if (ctrl_vq.last_used_idx == hw_used) return;
    // HW advanced past SW — wake any .gpu_io waiter so its loop re-checks
    // (and via gap #1's clflush, observes the new used_idx this time).
    const process = @import("../../../proc/process.zig");
    var pid: u8 = 0;
    var any_woken = false;
    while (pid < process.MAX_PROCS) : (pid += 1) {
        const wk = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].wait_kind)), .acquire);
        if (wk == @intFromEnum(process.WaitKind.gpu_io)) {
            @atomicStore(u64, &process.procs[pid].wake_tick, process.tick_count, .release);
            any_woken = true;
        }
    }
    // Register the deadline once (now) if we set any wake_tick — avoids N
    // cmpxchg loops for N waiters all stamping the same tick.
    if (any_woken) @import("../../../proc/sched.zig").registerWakeDeadline(process.tick_count);
}

/// Gap #4 (2026-05-20): diagnostic dump for the yield-loop / stuck-waiter
/// detectors. Mirrors `nvme.dumpWaiterForTarget`. `target` is the cmd_type
/// the waiter passed to blockOn — names which GPU command is hanging.
/// Reports SW vs HW state so the autopsy can distinguish:
///   - HW done, SW missed       → tickSweep regression / cache miss
///   - HW pending, ctrl_lock idle → device-side stuck (Venus deadlock, etc.)
///   - ctrl_lock held by dead pid → mutex-leak class
pub fn dumpWaiterForTarget(target: u32) void {
    debug.klog("  virtio-gpu state (cmd_type=0x{X}):\n", .{target});
    debug.klog("    active        = {any}\n", .{vg.active});
    debug.klog("    use_msix      = {any}\n", .{use_msix});
    debug.klog("    msix_safe     = {any}\n", .{vg.msix_safe_to_use});
    debug.klog("    use_event_idx = {any}\n", .{use_event_idx});
    if (!vg.active) return;
    const hw_used = usedIdxCoherent(&ctrl_vq);
    debug.klog("    sw_last_used  = {d}\n", .{ctrl_vq.last_used_idx});
    debug.klog("    hw_used_idx   = {d}\n", .{hw_used});
    debug.klog("    avail_idx     = {d}\n", .{ctrl_vq.availIdx().*});
    debug.klog("    num_free      = {d}\n", .{ctrl_vq.num_free});
    debug.klog("    irq_count     = {d}\n", .{vg.virtio_gpu_irq_count});
    debug.klog("    waiter_wakes  = {d}\n", .{vg.virtio_gpu_waiter_wakes});
    debug.klog("    aflush: in_flight={any} ncmds={d} pend_rects={d} target={d} staging={any}\n", .{
        @atomicLoad(bool, &present.aflush_in_flight, .acquire),
        present.aflush_ncmds,
        present.apend_count,
        present.aflush_target_idx,
        present.staging_active,
    });
    if (hw_used != ctrl_vq.last_used_idx) {
        debug.klog("    ===> HW advanced beyond SW; tickSweep should pick this up next tick\n", .{});
    } else if (ctrl_vq.availIdx().* != ctrl_vq.last_used_idx) {
        debug.klog("    ===> SW submitted a cmd; HW has NOT completed — device-side wedge\n", .{});
    } else {
        debug.klog("    (queue idle — waiter is racing a future submit?)\n", .{});
    }
}
