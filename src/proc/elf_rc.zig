//! Shared refcounts for ELF demand-paging buffers.
//!
//! A process keeps its ELF file image in a PMM-allocated `elf_buf` so the
//! page-fault handler can lazily copy PT_LOAD bytes into freshly faulted pages
//! (PCB.elf_buf; see elf_loader.registerSegmentLazy). When a process forks
//! before those segments are fully resident, forkCurrent copies the parent's
//! `lazy_regions` by value, so the child's `lazy_regions[].source` pointers
//! point into the PARENT's elf_buf — a kernel buffer that COW does NOT remap.
//! The buffer must therefore outlive whichever of {parent, fork children}
//! faults it in last, not just its original owner. Previously the child simply
//! nulled its own `elf_buf` to dodge a double-free, leaving its source pointers
//! dangling if the parent exited first → a use-after-free into freed PMM pages.
//!
//! This module is that missing lifetime: one refcount cell per distinct
//! elf_buf, shared by every PCB (process-group lead) that references it.
//! forkCurrent bumps it via acquire(); freeElfBuf drops it via release() and
//! frees the PMM pages only at zero. A fork shares its parent's cell — it never
//! allocates a new one — so the number of live cells is bounded by the number
//! of distinct buffers, which is <= MAX_PROCS. The static pool can't be
//! outrun by any legal process table.

const config = @import("../config.zig");
const debug = @import("../debug/debug.zig");
const SpinLock = @import("spinlock.zig").SpinLock;

const MAX_CELLS = config.MAX_PROCS;

var cells: [MAX_CELLS]u32 = [_]u32{0} ** MAX_CELLS;
var used: [MAX_CELLS]bool = [_]bool{false} ** MAX_CELLS;
var lock: SpinLock = .{};

/// Allocate a fresh refcount cell initialized to 1 (the loader's own
/// reference). Returns null only if the pool is exhausted — which can't happen
/// for any reachable process table (see the module note) — in which case the
/// caller treats the buffer as an un-refcounted single owner and degrades to
/// the legacy free-on-exit path. Safe: a single-owner buffer is never shared,
/// so it can't dangle; it just can't be inherited across a fork.
pub fn create() ?*u32 {
    lock.acquire();
    defer lock.release();
    for (&used, 0..) |*u, idx| {
        if (!u.*) {
            u.* = true;
            cells[idx] = 1;
            return &cells[idx];
        }
    }
    debug.klog("[elf-rc] cell pool exhausted ({d}) — buffer falls back to single-owner\n", .{MAX_CELLS});
    return null;
}

/// Bump a cell's count. Called by forkCurrent for the inherited elf_buf.
pub fn acquire(cell: *u32) void {
    lock.acquire();
    defer lock.release();
    cell.* += 1;
}

/// Drop one reference. Returns true exactly when the count hits zero — the
/// caller then frees the elf_buf's PMM pages — and recycles the cell slot.
pub fn release(cell: *u32) bool {
    lock.acquire();
    defer lock.release();
    if (cell.* == 0) {
        debug.klog("[elf-rc] release on already-zero cell\n", .{});
        return false;
    }
    cell.* -= 1;
    if (cell.* == 0) {
        const idx = (@intFromPtr(cell) - @intFromPtr(&cells[0])) / @sizeOf(u32);
        if (idx < MAX_CELLS) used[idx] = false;
        return true;
    }
    return false;
}
