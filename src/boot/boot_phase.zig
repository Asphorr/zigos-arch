//! Single authoritative "is the kernel past single-threaded boot?" signal.
//!
//! `complete` is false through all of `kernelMain` — AP bring-up, APIC/HPET,
//! PCI driver init, framebuffer setup — every bit of which runs single-threaded
//! on the BSP before any task is scheduled. It flips true exactly once, when the
//! first scheduled task enters steady-state preemptive multitasking
//! (`desktop.taskEntry`, alongside `nvme.enableAsync()`).
//!
//! This is the general form of a check the kernel already makes ad-hoc: NVMe's
//! `async_mode` defaults false and flips at `enableAsync` precisely because
//! `blockOn` needs a live scheduler. Any subsystem that needs to distinguish
//! "boot" from "steady state" can now consult one named flag instead of
//! re-deriving it (and `cpu_count > 1` is NOT that signal — APs come up early,
//! during boot; see the 2026-05-21 paging regression).
//!
//! Leaf module: imports nothing, so paging / proc / drivers can read it without
//! creating an import cycle.

var complete: bool = false;

/// Mark the boot -> steady-state transition. Call exactly once, from the first
/// scheduled task, after the scheduler is fully live (valid current_pid, IRQs
/// on). Idempotent if somehow called twice.
pub fn markComplete() void {
    @atomicStore(bool, &complete, true, .release);
}

/// True once steady-state preemptive multitasking has begun. Cheap acquire load
/// — safe to call on the hot path.
pub fn isComplete() bool {
    return @atomicLoad(bool, &complete, .acquire);
}
