// The pixels of a program's window: the framebuffer the program draws into,
// the snapshots sysPresent takes of it for the desktop to read, growing it
// when the window is zoomed, and giving the snapshots back when memory runs
// short.

const std = @import("std");
const gfx = @import("../gfx.zig");
const Phys = @import("../../util/addr.zig").Phys;
const paging = @import("../../mm/paging.zig");
const pmm = @import("../../mm/pmm.zig");
const debug = @import("../../debug/debug.zig");
const vmm = @import("../../mm/vmm.zig");
const process = @import("../../proc/process.zig");
const Mutex = @import("../../proc/spinlock.zig").Mutex;
const wm = @import("window.zig");
const Window = wm.Window;
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const z_stack = &wm.z_stack;
const lockWindows = wm.lockWindows;
const unlockWindows = wm.unlockWindows;
const wake = @import("wake.zig");
const MAX_WINDOWS: u32 = @import("../../config.zig").MAX_WINDOWS;

// Serializes growGuiFb's FB-mutation sequence against destroyGuiWindow's
// FB teardown. Without it, an F10-grown FB whose owner process exits in
// the narrow window between alloc/PTE-repoint and the publish step can be
// observed mid-update by destroyGuiWindow — which then frees the OLD phys
// block while growGuiFb is also freeing it (the 1789 freeFrame underflows
// the kernel panics on). Mutex (not SpinLock) because growGuiFb calls
// tlb.shootdownAll, which IPIs peer CPUs and waits for ACK — peers that
// are also spinning on windows_lock with IRQs off would never ACK and
// we'd hard-deadlock. The mutex sleeps the waiter through the scheduler
// (IF stays on) so the shootdown still completes.
pub var gui_fb_realloc_lock: Mutex = .{};

/// Grow window `idx`'s GUI framebuffer so the app can render crisply at
/// `need_w × need_h` content pixels instead of being upscaled from a smaller
/// allocation. GROW-only (the bigger block is kept until the window closes);
/// returns true once the FB covers need_w/need_h.
///
/// Runs in the DESKTOP TASK, sequential with renderScene — so there is no
/// render-vs-free race on the front buffer (the dangerous case an app-side
/// realloc syscall would have). Mirrors sysCreateWindow's legacy PMM path +
/// unmapGuiFB teardown:
///   1. alloc + zero a new contiguous block;
///   2. map the GROWTH pages first (only these can fail on PT-OOM → clean
///      abort, live mapping untouched), then overwrite the existing
///      [0,old_pages) PTEs in place (no unmapped gap → an app mid-write on
///      another CPU can't fault on GUI_FB_BASE);
///   3. shoot down the app's PCID so no CPU can still reach the old frames
///      (relies on the 2026-05-21 global-flush shootdown fix);
///   4. NULL the front + drain in-flight present snapshots, repoint the window,
///      then drop the old block's two refcounts + free its back buffers.
/// The app learns the new stride via sysGetWindowAlloc on the `.resize` event
/// toggleFullscreen pushes right after.
pub fn growGuiFb(idx: u8, need_w: u32, need_h: u32) bool {
    // Hold across the full grow so destroyGuiWindow (which also takes
    // this mutex) cannot observe gui_fb_phys_base / gui_alloc_w/h
    // mid-publish, and so it cannot race lines 836-840's OLD-frame
    // release against its own unmapGuiFB. windows_lock is NOT taken
    // around shootdownAll — that would deadlock against a peer CPU
    // spinning on windows_lock with IRQs off (it could not ACK our IPI).
    gui_fb_realloc_lock.acquire();
    defer gui_fb_realloc_lock.release();

    const w = &windows[idx];
    if (w.gpu_slot != null) return false; // GPU path scales via the compositor
    // Opt-in: only grow for apps that have queried getWindowAlloc and thus know
    // to re-fetch their stride on the resize event. Everything else keeps the
    // upscale fallback (no stride change → no shear/blank regression).
    if (!w.fb_growable) return false;
    const fb_kv = w.gui_fb orelse return false;
    const pid = w.owner_pid;
    if (pid >= process.procs.len) return false;

    const new_alloc_w: u32 = (need_w + 15) & ~@as(u32, 15); // 16-px stride
    const new_alloc_h: u32 = need_h;
    // Already big enough — just adopt the new logical content size.
    if (new_alloc_w <= w.gui_alloc_w and new_alloc_h <= w.gui_alloc_h) {
        w.gui_w = need_w;
        w.gui_h = need_h;
        return true;
    }
    const new_bytes: u64 = @as(u64, new_alloc_w) * new_alloc_h * 4;
    if (new_bytes > @import("../../mm/memmap.zig").GUI_FB_PER_PID_SIZE) return false;
    const new_pages: u32 = @intCast((new_bytes + 4095) / 4096);
    const old_bytes: u64 = @as(u64, w.gui_alloc_w) * w.gui_alloc_h * 4;
    const old_pages: u32 = @intCast((old_bytes + 4095) / 4096);
    const old_phys = Phys.of(paging.virtToPhys(@intFromPtr(fb_kv)) orelse return false);

    const new_phys = pmm.allocContiguous(new_pages) orelse {
        debug.klog("[maximize] growGuiFb pid={d}: allocContiguous({d} pages) failed; staying {d}x{d}\n", .{ pid, new_pages, w.gui_alloc_w, w.gui_alloc_h });
        return false;
    };
    const new_kv = new_phys.toVirt().ptr([*]volatile u32);
    @memset(@as([*]volatile u8, @ptrCast(new_kv))[0 .. new_pages * 4096], 0);

    const pd: [*]align(4096) u64 = @ptrFromInt(paging.physToVirt(process.procs[pid].page_dir_phys));
    const base = paging.GUI_FB_USER_BASE;
    const map_flags = paging.READ_WRITE | paging.USER;

    // Growth pages first — the only ones that can need (and fail to get) a new
    // page-table page. On failure the live [0,old_pages) mapping is untouched.
    var i: u32 = old_pages;
    while (i < new_pages) : (i += 1) {
        vmm.mapUserPage(pd, base + i * 4096, new_phys.add(i * 4096), map_flags) catch {
            var j: u32 = old_pages;
            while (j < i) : (j += 1) {
                _ = vmm.unmapUserPage(pd, base + j * 4096);
                pmm.releaseFrame(new_phys.add(j * 4096));
            }
            pmm.freeContiguous(new_phys, new_pages);
            debug.klog("[maximize] growGuiFb pid={d}: PT OOM at growth page {d}; aborted\n", .{ pid, i });
            return false;
        };
        pmm.acquireFrame(new_phys.add(i * 4096));
    }
    // Repoint the existing [0,old_pages) mapping. mapUserPage refuses to
    // overwrite a PTE that points at a different phys (vmm gap #2 →
    // error.AlreadyMapped), so clear each PTE first. unmapUserPage only zeroes
    // the PTE (no releaseFrame), so the old frame's refcount is left intact for
    // the explicit double-release below. The PT page for this VA already exists
    // (the old FB mapped it), so the subsequent map cannot fail.
    //
    // The one-page-wide gap between unmap and map is safe here: F10 is handled
    // by the desktop task while the app sits parked in its event loop (not
    // writing its FB). An app that renders continuously would want a
    // force-overwrite mapUserPage variant to close the gap entirely.
    i = 0;
    while (i < old_pages) : (i += 1) {
        _ = vmm.unmapUserPage(pd, base + i * 4096);
        vmm.mapUserPage(pd, base + i * 4096, new_phys.add(i * 4096), map_flags) catch |e| {
            debug.klog("[maximize] growGuiFb pid={d}: in-place remap page {d} failed: {s}\n", .{ pid, i, @errorName(e) });
            @panic("growGuiFb in-place remap (PT page should already exist)");
        };
        pmm.acquireFrame(new_phys.add(i * 4096));
    }
    // Old frames are now unreachable from the app once its TLB is flushed.
    @import("../../cpu/mmu/tlb.zig").shootdownAll(process.procs[pid].pcid);

    // Drain in-flight present snapshots BEFORE taking windows_lock — the
    // drain loop can spin millions of cycles waiting for a peer CPU's
    // sysPresent to finish, and holding windows_lock (IRQ-save spinlock)
    // through that would block IRQ delivery on this CPU for the whole
    // wait. snapshotGuiFb doesn't take windows_lock, so this drain is
    // safe outside it.
    var spin: u32 = 0;
    while (@atomicLoad(u32, &presenting_count, .acquire) > 0) {
        asm volatile ("pause");
        spin += 1;
        if (spin > 10_000_000) break;
    }

    // Publish the new geometry atomically with windows_lock held so the
    // compositor (and createGuiWindow / destroyGuiWindow) cannot observe
    // a half-updated window. NULL the front AND the stale back-buffer
    // pointers first (they point at the OLD, smaller, about-to-be-freed
    // blocks), THEN publish — the ordering reclaimBackBuffers uses. The
    // backs MUST be nulled before gui_fb_pixels grows and gui_fb is
    // re-published: otherwise the next snapshotGuiFb sees them non-null,
    // skips realloc, and memcpys the new (larger) pixel count into a
    // small freed back buffer → overflow + panic in sysPresent.
    var old_back_phys: [3]?Phys = .{ null, null, null };
    {
        const wflags = lockWindows();
        defer unlockWindows(wflags);
        w.gui_fb = null;
        w.has_presented = false;
        var s: u8 = 0;
        while (s < 3) : (s += 1) {
            w.gui_fb_backs[s] = null;
            old_back_phys[s] = paging.takeGuiFbBackPhys(pid, s);
        }
        w.gui_fb_pixels = @intCast(@as(u64, new_alloc_w) * new_alloc_h);
        w.gui_alloc_w = new_alloc_w;
        w.gui_alloc_h = new_alloc_h;
        w.gui_w = need_w;
        w.gui_h = need_h;
        w.gui_fb_pub.store(0, .release);
        paging.registerGuiFB(pid, new_phys);
        w.gui_fb = new_kv;
    }

    // Free the OLD block: front frames carry two refs (alloc + acquire) — drop
    // both; each old back buffer (phys taken above) is a single-owner block.
    // Outside windows_lock (refcount math is independent) but still inside
    // gui_fb_realloc_lock so destroyGuiWindow's unmapGuiFB can't also drop a
    // ref on the same OLD frames (it would have done that under
    // gui_fb_realloc_lock + windows_lock and our publish would have shown it
    // OLD-state values via gui_fb_phys_base/gui_alloc still being OLD).
    i = 0;
    while (i < old_pages) : (i += 1) {
        pmm.releaseFrame(old_phys.add(i * 4096));
        pmm.releaseFrame(old_phys.add(i * 4096));
    }
    {
        var s: u8 = 0;
        while (s < 3) : (s += 1) {
            if (old_back_phys[s]) |bp| pmm.freeContiguous(bp, old_pages);
        }
    }
    debug.klog("[maximize] grew pid={d} FB -> {d}x{d} ({d} pages, was {d} pages)\n", .{ pid, new_alloc_w, new_alloc_h, new_pages, old_pages });
    return true;
}

/// Write mouse position relative to the window's content area into user buffer.
/// Called by sysPresent — marks the GUI window for this PID as needing re-composite.
pub fn markGuiPresent(pid: u8) void {
    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].owner_pid == pid and windows[i].gui_fb != null) {
            windows[i].gui_present_pending = true;
            // Event-driven compositor wake: a GUI app pushed a new
            // frame, the desktop loop has work to do (re-composite
            // this window, blit the dirty rect). In legacy mode this
            // is a no-op gated by the 3-tick GUI floor; in event-
            // driven mode this is the only thing that brings the
            // compositor back from sleep.
            wake.requestWake();
            return;
        }
    }
}

/// Snapshot the user-writable front buffer into the kernel back buffer for
/// this PID's GUI window. Called by sysPresent before markGuiPresent. The
/// compositor reads from gui_fb_back, so this snapshot is what makes
/// renderWindow see a coherent frame instead of half-old / half-new data
/// (which is what produced the cube's flashing artifact pre-fix). The copy
/// is ~80 µs for a 320×240 window, scaling linearly with pixel count;
/// negligible at the rate sysPresent fires.
/// In-flight snapshotGuiFb counter. Bumped at the top of snapshotGuiFb,
/// released at the bottom. reclaimBackBuffers spin-waits this to zero
/// before freeing back-buffer phys frames — without this, reclaim could
/// race with a mid-memcpy snapshot from another CPU, writing through a
/// pointer we just freed and clobbering whoever PMM hands the frame to
/// next.
var presenting_count: u32 = 0;

pub fn snapshotGuiFb(pid: u8) void {
    _ = @atomicRmw(u32, &presenting_count, .Add, 1, .acquire);
    defer _ = @atomicRmw(u32, &presenting_count, .Sub, 1, .release);
    for (z_stack[0..wm.z_count]) |i| {
        const w = &windows[i];
        if (w.owner_pid == pid) {
            const front = w.gui_fb orelse return;
            const n = w.gui_fb_pixels;
            if (n == 0) return;
            // A slot window's framebuffer is the image the GPU compositor
            // samples: nothing reads a snapshot of it.
            if (w.gpu_slot != null) {
                w.has_presented = true;
                return;
            }
            // Race-free triple buffer: write slot (pub+1)%3, then publish
            // it. The compositor is currently reading slot pub; the just-
            // -published slot is a fresh slot it hasn't touched. With 3
            // slots total, we can rotate forward by 2 before we'd reach
            // the slot the compositor is on — so as long as snap rate
            // < 3× compositor rate (always true for 50fps cube/60fps
            // compositor), the in-flight slot is never overwritten.
            const cur_pub = w.gui_fb_pub.load(.acquire);
            const next: u32 = (cur_pub + 1) % 3;
            // Lazy back-buffer alloc. sysCreateWindow leaves all three
            // backs unallocated; we only create them when an app
            // actually calls sysPresent. Apps that never present
            // (sysmon, settings, many tools that rely on auto-refresh)
            // save 3× their framebuffer permanently. First-present pays
            // a one-shot pmm.allocContiguous(num_pages) per slot.
            //
            // If alloc fails (low memory), we silently skip the present:
            // has_presented stays false, the compositor's renderWindow
            // falls back to reading gui_fb directly. Visually
            // indistinguishable; only loses the tear-free property under
            // 60fps+ presenters (cube etc.) — which is a fair trade for
            // not crashing the present syscall under memory pressure.
            if (w.gui_fb_backs[next] == null) {
                const num_pages: u32 = @intCast((@as(usize, n) * 4 + 4095) / 4096);
                if (pmm.allocContiguous(num_pages)) |back_phys| {
                    const back_kv = back_phys.toVirt().ptr([*]volatile u32);
                    const back_u8: [*]volatile u8 = @ptrCast(back_kv);
                    @memset(back_u8[0 .. num_pages * 4096], 0);
                    w.gui_fb_backs[next] = back_kv;
                    paging.registerGuiFBBack(pid, @intCast(next), back_phys);
                } else {
                    // PMM exhausted — leave has_presented=false and let
                    // the compositor read gui_fb directly. App keeps
                    // running; only the tear-free property is lost.
                    return;
                }
            }
            const next_buf = w.gui_fb_backs[next] orelse return;
            const dst: [*]u32 = @ptrCast(@volatileCast(next_buf));
            const src: [*]const u32 = @ptrCast(@volatileCast(front));
            @memcpy(dst[0..n], src[0..n]);
            w.gui_fb_pub.store(next, .release);
            // Flip the "first present landed" gate AFTER publish so any
            // concurrent renderWindow that sees has_presented=true also
            // sees the freshly-published slot.
            w.has_presented = true;
            return;
        }
    }
}

/// PMM reclaim callback — drops the lazily-allocated back-buffer slots
/// of every GUI window, returning the freed frames to the PMM. Called
/// from pmm.tryReclaim when an allocation fails (typically from
/// handleUserPageFault on the OOM path). Returns frames actually freed.
///
/// Race safety: NULL the kernel pointer first so any new snapshotGuiFb
/// sees null and lazily reallocates. Then spin-wait `presenting_count`
/// to zero — guarantees no in-flight memcpy is still writing through a
/// pointer we already nulled. Only then do we hand the phys back to
/// PMM. Without the spin, a concurrent snapshotGuiFb on another CPU
/// could write 8 MB into a frame PMM already reassigned, corrupting
/// arbitrary kernel state.
///
/// `has_presented` is cleared so renderWindow falls back to reading
/// gui_fb directly (the existing fallback path). The next sysPresent
/// will lazily reallocate the slot.
pub fn reclaimBackBuffers(needed_frames: u32) u32 {
    var freed_frames: u32 = 0;
    // Phase 1: null all reclaimable back-buffer kernel pointers + take
    // their phys. Doing all the NULL writes first means by the time we
    // start the spin-wait, no new snapshotGuiFb call can latch a
    // pointer that we then free.
    // Each block with its own size: windows differ in theirs.
    var pending_phys: [MAX_WINDOWS * 3]Phys = undefined;
    var pending_pages: [MAX_WINDOWS * 3]u32 = undefined;
    var pending_count: usize = 0;
    for (0..MAX_WINDOWS) |k| {
        const i: u8 = @intCast(k);
        if (!slot_used[i]) continue;
        const w = &windows[i];
        if (w.gui_fb == null) continue;
        const aw = if (w.gui_alloc_w > 0) w.gui_alloc_w else w.gui_w;
        const ah = if (w.gui_alloc_h > 0) w.gui_alloc_h else w.gui_h;
        const npages_this: u32 = (aw * ah * 4 + 4095) / 4096;
        var slot: u8 = 0;
        while (slot < 3) : (slot += 1) {
            if (w.gui_fb_backs[slot] == null) continue;
            // NULL the kernel pointer first (atomic with respect to
            // snapshotGuiFb's pointer load). Even if a snapshot
            // already loaded the pointer, the spin-wait below handles
            // it.
            w.gui_fb_backs[slot] = null;
            if (paging.takeGuiFbBackPhys(w.owner_pid, slot)) |phys| {
                pending_phys[pending_count] = phys;
                pending_pages[pending_count] = npages_this;
                pending_count += 1;
                freed_frames += npages_this;
            }
        }
        // Force compositor onto the gui_fb fallback path. The next
        // sysPresent will lazily reallocate the slot.
        w.has_presented = false;
        if (freed_frames >= needed_frames) break;
    }
    if (pending_count == 0) return 0;

    // Phase 2: spin-wait for any in-flight snapshotGuiFb to finish.
    // Bounded by snapshotGuiFb's memcpy time — fullscreen 1920×1080
    // RGBA is ~8 MB, memcpy at ~5 GB/s is ~1.6 ms worst case. The
    // `pause` lets the other CPU make progress instead of cache-
    // ping-ponging us.
    var spin_iters: u32 = 0;
    while (@atomicLoad(u32, &presenting_count, .acquire) > 0) {
        asm volatile ("pause");
        spin_iters += 1;
        if (spin_iters > 10_000_000) {
            // Sanity bound — if we somehow miss a decrement, don't
            // hang forever. Log + bail; the deferred free might race
            // a snapshot, but at this point the system is in a worse
            // state than a single torn 8 MB write.
            debug.klog("[reclaim] WARN snapshotGuiFb drain timeout, freeing anyway\n", .{});
            break;
        }
    }

    // Phase 3: now safe — actually return the frames to PMM.
    var i: usize = 0;
    while (i < pending_count) : (i += 1) {
        pmm.freeContiguous(pending_phys[i], pending_pages[i]);
    }
    return freed_frames;
}

/// Hash of the pixels a GUI window's live framebuffer shows. An app that
/// never presents is polled; this tells a poll that found nothing new, so
/// that a still window costs no frame. Any one changed pixel changes it.
pub fn guiContentHash(w: *const Window) u64 {
    const fb = w.gui_fb orelse return 0;
    const stride: usize = if (w.gui_alloc_w > 0) w.gui_alloc_w else w.gui_w;
    const cols: usize = @min(w.gui_w, stride);
    if (cols == 0) return 0;
    const rows: usize = @min(
        if (w.gui_alloc_h > 0) @min(w.gui_h, w.gui_alloc_h) else w.gui_h,
        w.gui_fb_pixels / stride,
    );
    const px: [*]const u32 = @ptrCast(@volatileCast(fb));
    var h: u64 = 0x9E3779B97F4A7C15;
    var y: usize = 0;
    while (y < rows) : (y += 1) {
        const row = px + y * stride;
        const pairs: [*]align(4) const u64 = @ptrCast(row);
        var i: usize = 0;
        while (i < cols / 2) : (i += 1) h = std.math.rotl(u64, h ^ pairs[i], 29) *% 0x100000001B3;
        if (cols & 1 != 0) h = std.math.rotl(u64, h ^ row[cols - 1], 29) *% 0x100000001B3;
    }
    return h;
}

pub fn hasGuiWindows() bool {
    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].gui_fb != null and windows[i].visible) return true;
    }
    return false;
}

/// Paint the content of a program's window into the back buffer, below its
/// titlebar. False for a window that has no framebuffer (a terminal).
pub fn paintContent(w: *const Window, content_y: i32, content_h: u32) bool {
    // Read the published back buffer if the app has presented at least
    // once. Until then, read gui_fb directly so apps that never call
    // libc.present() still render. Apps that do present (cube) get
    // tear-free reads via the triple-buffer rotation.
    const pub_idx = w.gui_fb_pub.load(.acquire);
    const active_back: ?[*]volatile u32 = if (w.has_presented) w.gui_fb_backs[pub_idx] else w.gui_fb;
    // A slot window: the GPU compositor's per-window draw samples the
    // dmabuf itself and lays it over the back buffer in the pass that takes
    // the back buffer for the background, so a blit here would only write
    // pixels the GPU overdraws. The frame around it stays in the back buffer.
    if (w.gpu_slot != null) return true;
    const fb = active_back orelse w.gui_fb orelse return false;
    // GUI app window — blit the active kernel back buffer to the desktop
    // back buffer. Falls back to gui_fb only on legacy windows that
    // pre-date the triple-buffer change (none should exist post-
    // sysCreateWindow change; defensive fallback).

    // Source = the app's rendered content extent, capped to its FB
    // allocation (reading past it would walk into the next row through
    // the smaller stride).
    const src_w: u32 = if (w.gui_alloc_w > 0) @min(w.gui_w, w.gui_alloc_w) else w.gui_w;
    const src_h: u32 = if (w.gui_alloc_h > 0) @min(w.gui_h, w.gui_alloc_h) else w.gui_h;
    const stride = if (w.gui_alloc_w > 0) w.gui_alloc_w else w.gui_w;
    // Destination = the FULL window content area. When it equals the source
    // (normal/dragged window — drag is capped at the alloc) we blit 1:1:
    // crisp + fast (rep movsl). When it's larger (F10 maximize past the FB
    // alloc) we nearest-neighbor UPSCALE so the content fills the window
    // instead of sitting alloc-sized in the corner with wallpaper around it.
    // (cpu-comp path; the GPU compositor does the equivalent via uv_scale.)
    const dst_w: u32 = w.width;
    const dst_h: u32 = content_h;
    if (src_w != 0 and src_h != 0 and dst_w != 0 and dst_h != 0) {
        if (src_w == dst_w and src_h == dst_h) {
            var row: u32 = 0;
            while (row < dst_h) : (row += 1) {
                const py = content_y + @as(i32, @intCast(row));
                if (py < 0) continue;
                if (py >= @as(i32, @intCast(gfx.target_h))) break;
                if (w.x >= @as(i32, @intCast(gfx.target_w))) continue;
                const dst_x: u32 = if (w.x < 0) 0 else @intCast(w.x);
                const src_skip: u32 = if (w.x < 0) @intCast(-w.x) else 0;
                const avail = gfx.target_w - dst_x;
                const count = @min(dst_w -| src_skip, avail);
                if (count == 0) continue;
                const dst_off = @as(u32, @intCast(py)) * gfx.target_w + dst_x;
                const src_off = row * stride + src_skip;
                const dest = @intFromPtr(gfx.target) + dst_off * 4;
                const src = @intFromPtr(fb) + src_off * 4;
                asm volatile ("cld; rep movsl"
                    :
                    : [dst] "{rdi}" (dest),
                      [src] "{rsi}" (src),
                      [cnt] "{rcx}" (count),
                    : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
                );
            }
        } else {
            // Nearest-neighbor scale src→dst. 16.16 fixed-point sampled per
            // pixel (stateless, so the screen-edge `continue`/`break` clips
            // can't desync the source index) — no per-pixel divide and no
            // large stack buffer, keeping pid 2's kstack lean.
            const x_step: u32 = (src_w << 16) / dst_w;
            const y_step: u32 = (src_h << 16) / dst_h;
            var row: u32 = 0;
            while (row < dst_h) : (row += 1) {
                const py = content_y + @as(i32, @intCast(row));
                if (py < 0) continue;
                if (py >= @as(i32, @intCast(gfx.target_h))) break;
                const sy: u32 = @min((row * y_step) >> 16, src_h - 1);
                const src_row: [*]volatile u32 = @ptrFromInt(@intFromPtr(fb) + @as(usize, sy) * stride * 4);
                const dst_row_base = @as(u32, @intCast(py)) * gfx.target_w;
                var col: u32 = 0;
                while (col < dst_w) : (col += 1) {
                    const dx = w.x + @as(i32, @intCast(col));
                    if (dx < 0) continue;
                    if (dx >= @as(i32, @intCast(gfx.target_w))) break;
                    const sx: u32 = @min((col * x_step) >> 16, src_w - 1);
                    gfx.target[dst_row_base + @as(u32, @intCast(dx))] = src_row[sx];
                }
            }
        }
    }
    return true;
}

/// Auto-refresh: a GUI window whose app never calls sysPresent is read
/// from the app's live framebuffer, so it is re-composited on a timer, at
/// most every 5 ticks (~20 Hz) however often the loop wakes. A window that
/// presents is read from the snapshot sysPresent took and is marked by it
/// (markGuiPresent): nothing to pick up here. True while such a window is
/// on screen: the desktop then keeps waking to look at it.
pub fn pollUnpresented() bool {
    var gui_autorefresh_active = false;
    const AUTO_REFRESH_INTERVAL_TICKS: u64 = 5;
    for (z_stack[0..wm.z_count]) |gi| {
        const w = &windows[gi];
        if (w.gui_fb == null or !w.visible or w.has_presented) continue;
        gui_autorefresh_active = true;
        if (process.tick_count -% w.last_auto_refresh_tick >= AUTO_REFRESH_INTERVAL_TICKS) {
            w.last_auto_refresh_tick = process.tick_count;
            const h = guiContentHash(w);
            if (h != w.auto_refresh_hash) {
                w.auto_refresh_hash = h;
                w.auto_refresh_settle = true;
                w.gui_present_pending = true;
            } else if (w.auto_refresh_settle) {
                w.auto_refresh_settle = false;
                w.gui_present_pending = true;
            }
        }
    }
    return gui_autorefresh_active;
}
