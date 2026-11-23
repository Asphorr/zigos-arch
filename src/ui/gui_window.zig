//! A process's GUI window from the kernel's side, around the desktop's
//! record of it: the lock its setup and teardown run under, its
//! framebuffer in the address space, and when it goes.
//!
//! A window goes with the task that made it (sysDestroyWindow, or the
//! task's end): its events go to that task, and lookups name it by a pid
//! that passes to another process next. sysDestroyWindow takes the
//! framebuffer out of the address space too and then gives up the GPU slot
//! behind it. A task's end cannot: one tearing itself down keeps
//! interrupts off to the last, and a slot's pages may only change hands
//! once out of every CPU's TLB, which takes them. So that framebuffer, and
//! the slot, stay with the group until its next window or its own end.

const process = @import("../proc/process.zig");
const vmm = @import("../mm/vmm.zig");
const paging = @import("../mm/paging.zig");
const memmap = @import("../mm/memmap.zig");
const debug = @import("../debug/debug.zig");
const spinlock = @import("../proc/spinlock.zig");
const desktop = @import("desktop.zig");
const gpu_comp = @import("gpu_compositor.zig");

/// Where a window's framebuffer sits in its process's address space.
pub const FB_BASE: usize = paging.GUI_FB_USER_BASE;
const MAX_FB_PAGES: usize = memmap.GUI_FB_PER_PID_SIZE / 4096;

/// One window is set up or taken down at a time. Either leaves the
/// framebuffer's place in the address space and the GPU slot behind it
/// out of step for a moment, and a slot may only be given up once its
/// pages are out of the address space: two threads of a process doing
/// this side by side could end up mapping a slot that is already another
/// window's. Registered, so a task killed inside lets go.
pub var setup_lock: spinlock.Mutex = .{};

/// At boot.
pub fn registerLocks() void {
    spinlock.registerMutex("ui.gui_setup", &setup_lock);
}

/// Take the first `pages` of the framebuffer out of `lead`'s address
/// space, on every CPU. A frame the PMM counts loses the mapping's
/// reference; a GPU slot's pages are the host's. Caller holds as_lock.
pub fn unmapFbLocked(lead: *process.PCB, pd: [*]align(4096) u64, pages: usize) void {
    if (pages == 0) return;
    var rc: vmm.Reclaim = .{ .pcid = lead.pcid };
    _ = vmm.unmapUserRange(pd, FB_BASE, FB_BASE + pages * 4096, &rc);
    @import("../cpu/mmu/tlb.zig").shootdownRange(lead.pcid, FB_BASE, pages);
    rc.release();
}

/// unmapFbLocked, if the group still has its address space.
pub fn unmapFb(lead: *process.PCB, pages: usize) void {
    if (pages == 0) return;
    lead.as_lock.acquire();
    defer lead.as_lock.release();
    const pd = lead.page_directory orelse return;
    unmapFbLocked(lead, pd, pages);
}

/// sysDestroyWindow: the windows task `pid` made, their framebuffer and
/// then their GPU slots. How many there were.
pub fn destroyByTask(pid: u8) u8 {
    setup_lock.acquire();
    defer setup_lock.release();
    const gone = desktop.destroyGuiWindow(.{ .task = pid });
    const lead = process.leader(&process.procs[pid]);
    unmapFb(lead, gone.fb_pages);
    var slots = gone.gpu_slots;
    while (slots != 0) : (slots &= slots - 1) {
        gpu_comp.releaseWindowImage(@intCast(@ctz(slots)), lead.tgid);
    }
    return gone.windows;
}

/// Task `pid` is ending and is not its group's last: its windows go, their
/// framebuffer and GPU slots stay (see the top of the file).
pub fn taskEnded(pid: u8) void {
    setup_lock.acquire();
    defer setup_lock.release();
    const gone = desktop.destroyGuiWindow(.{ .task = pid });
    if (gone.windows != 0) {
        debug.klog("[gui] pid {d} ended: {d} window(s) gone, framebuffer left to group {d}\n", .{ pid, gone.windows, process.procs[pid].tgid });
    }
}

/// The framebuffer at FB_BASE when `lead`'s group has no window left: one
/// whose task ended took only the window. It leaves the address space
/// now, and the group's GPU slots with it (no window draws through them).
/// False while the group has a window. Caller holds setup_lock.
pub fn reclaimLeftFb(lead: *process.PCB) bool {
    if (desktop.groupHasGuiWindow(lead.tgid)) return false;
    var pages: usize = 0;
    {
        lead.as_lock.acquire();
        defer lead.as_lock.release();
        const pd = lead.page_directory orelse return false;
        // Mapped from FB_BASE up, without gaps.
        while (pages < MAX_FB_PAGES and vmm.resolveUserPhys(pd, FB_BASE + pages * 4096) != null) pages += 1;
        unmapFbLocked(lead, pd, pages);
    }
    gpu_comp.releaseWindowImagesOf(lead.tgid);
    debug.klog("[gui] group {d}: framebuffer left by an ended task reclaimed ({d} pages)\n", .{ lead.tgid, pages });
    return true;
}
