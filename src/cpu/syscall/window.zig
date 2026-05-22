//! Syscall handlers (window) — split out of syscall.zig (#797).
//! Dispatched from cpu/syscall.zig doSyscallInner; named in SYSCALLS.

const std = @import("std");
const vga = @import("../../ui/vga.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const keyboard = @import("../../driver/keyboard.zig");
const process = @import("../../proc/process.zig");
const vmm = @import("../../mm/vmm.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const bga = @import("../../ui/bga.zig");
const vfs = @import("../../fs/vfs.zig");
const desktop = @import("../../ui/desktop.zig");
const xhci = @import("../../driver/xhci.zig");
const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");
const pipe = @import("../../proc/pipe.zig");
const memmap = @import("../../mm/memmap.zig");
const config = @import("../../config.zig");
const smp = @import("../smp.zig");
const signals = @import("../../proc/signals.zig");
const errno = @import("../../proc/errno.zig");
const sched_asm = @import("../../proc/sched_asm.zig");
const apic = @import("../../time/apic.zig");

const common = @import("common.zig");
const validateUserPtr = common.validateUserPtr;
const validateUserPtrAligned = common.validateUserPtrAligned;
const USER_SPACE_START = common.USER_SPACE_START;
const USER_SPACE_END = common.USER_SPACE_END;
const E_INVAL = common.E_INVAL;
const E_NOENT = common.E_NOENT;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;
const E_NOMEM = common.E_NOMEM;
const E_AGAIN = common.E_AGAIN;
const E_BUSY = common.E_BUSY;
const E_NAMETOOLONG = common.E_NAMETOOLONG;
const E_PIPE = common.E_PIPE;
const E_SRCH = common.E_SRCH;
const E_NOSYS = common.E_NOSYS;
const E_PERM = common.E_PERM;
const E_CHILD = common.E_CHILD;
const E_INTR = common.E_INTR;

pub fn sysPrint(arg1: u32, arg2: u32) u32 {
    if (!validateUserPtr(arg1, arg2)) return E_FAULT;
    const ptr: [*]const u8 = @ptrFromInt(@as(usize, arg1));
    const msg = ptr[0..arg2];
    vga.print("{s}", .{msg});
    @import("../../debug/serial.zig").print("[app] {s}", .{msg});
    return 0;
}

pub fn sysClear() u32 {
    vga.clear();
    return 0;
}

pub fn sysRead() u32 {
    const pcb = process.currentPCB() orelse return 0;
    const fd0 = &pcb.fd_table[0];
    if (!fd0.in_use) return 0;
    switch (fd0.fs_type) {
        .console => {
            // Reads from the focused window's per-window event queue
            // (see ui/events.zig). The queue is filled only when this
            // window is focused, so background apps' polling loops
            // naturally see nothing rather than stealing input.
            const cur: u8 = @intCast(process.getCurrentPid());
            if (desktop.popCharEvent(cur)) |ch| return @as(u32, ch);
            return 0;
        },
        .pipe => {
            var buf: [1]u8 = .{0};
            const n = @import("../../proc/pipe.zig").tryRead(fd0.pipe_id, &buf);
            if (n == 0) return 0;
            return buf[0];
        },
        else => return 0,
    }
}

/// Blocking counterpart to sysRead for fd 0. Parks the caller until a byte is
/// available (woken by the pipe writer — e.g. the desktop pushing a keystroke
/// into kb_pipe) or a signal is pending, instead of returning 0 immediately.
/// Lets the interactive shell sleep until a keystroke arrives rather than
/// busy-polling read()+sleep() — the #1 idle-CPU hog in the perf profile
/// (sys#04 + sys#08 each ~59.5k calls/sample on the resident shell).
///
/// Only the .pipe fd path blocks: it reuses pipe.read's proven block/wake +
/// .signalled (EINTR) handshake, so Ctrl+C still interrupts a parked read and
/// pipe.read returns 0, letting the syscall-return signal path run. The
/// .console event-queue path has no blocked-reader wake hook, so it falls back
/// to the non-blocking sysRead behavior (console apps use poll_event anyway).
pub fn sysReadBlocking() u32 {
    const pcb = process.currentPCB() orelse return 0;
    const fd0 = &pcb.fd_table[0];
    if (!fd0.in_use) return 0;
    switch (fd0.fs_type) {
        .pipe => {
            var buf: [1]u8 = .{0};
            // Blocks until >=1 byte; returns 0 on EOF (writer closed) or a
            // pending signal. Caller treats 0 as "handle signal / retry".
            const n = @import("../../proc/pipe.zig").read(fd0.pipe_id, &buf);
            if (n == 0) return 0;
            return buf[0];
        },
        else => return sysRead(),
    }
}

pub fn sysGetKeyState(arg1: u32) u32 {
    if (arg1 < 256) return @intFromBool(keyboard.key_state[arg1]);
    return 0;
}

/// poll_event(buf_ptr): drain one event from the focused window's queue
/// into the user-space `Event` (16 bytes) at `buf_ptr`. Returns the
/// event kind on success, 0 if no events / not focused / etc. Apps that
/// want non-blocking input call this in their loop and dispatch on
/// the returned kind.
///
/// Replaces the patchwork of `getKeyState`-polling-plus-readChar that
/// existing apps use for input. Existing apps keep working — sysRead
/// is now a thin wrapper around the same per-window queue, so each
/// keystroke is delivered exactly once whether you read via fd 0 or
/// poll_event (apps must pick one — mixing both will lose events).
pub fn sysPollEvent(buf_ptr: u32) u32 {
    if (buf_ptr == 0) return 0;
    if (!validateUserPtrAligned(buf_ptr, @sizeOf(desktop.Event), @alignOf(desktop.Event))) return 0;
    var ev: desktop.Event = .{ .kind = 0 };
    const cur: u8 = @intCast(process.getCurrentPid());
    if (!desktop.popEvent(cur, &ev)) return 0;
    const dst: *desktop.Event = @ptrFromInt(@as(usize, buf_ptr));
    dst.* = ev;
    return ev.kind;
}

pub fn sysSetCursorVisible(arg1: u32) u32 {
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.setCursorHidden(pid, arg1 == 0);
    return 0;
}

pub fn sysCenterMouse() u32 {
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.centerMouse(pid);
    return 0;
}

/// Push an RGBA8 wallpaper image into the desktop's background module.
/// Pass `(0, 0, 0)` to clear the wallpaper and fall back to the gradient.
/// Pixel format must match what the screen expects (B8G8R8A8 packed u32
/// on x86 little-endian). Caller is responsible for any decoding +
/// pixel-format conversion (e.g. RGBA→BGRA from stb_image output).
pub fn sysSetWallpaper(buf_ptr: u32, w: u32, h: u32) u32 {
    const background = @import("../../ui/desktop/background.zig");
    const dirty = @import("../../ui/desktop/dirty.zig");
    const pmm_diag = @import("../../mm/pmm.zig");
    const free_entry = pmm_diag.freeFrameCount();
    debug.klog("[sysSetWallpaper] buf=0x{X} w={d} h={d} pmm_free={d}\n", .{ buf_ptr, w, h, free_entry });
    if (w == 0 and h == 0 and buf_ptr == 0) {
        background.clearWallpaper();
        dirty.force_full_kind = true;
        desktop.wake.requestWake();
        debug.klog("[sysSetWallpaper] cleared pmm_free={d} delta={d}\n", .{ pmm_diag.freeFrameCount(), pmm_diag.freeFrameCount() -% free_entry });
        return 0;
    }
    if (w == 0 or h == 0 or w > 4096 or h > 4096) {
        debug.klog("[sysSetWallpaper] EINVAL dims\n", .{});
        return E_INVAL;
    }
    const total: usize = @as(usize, w) * @as(usize, h) * 4;
    if (!validateUserPtrAligned(buf_ptr, total, 4)) {
        debug.klog("[sysSetWallpaper] EFAULT validateUserPtr({d} bytes)\n", .{total});
        return E_FAULT;
    }
    const free_before_clear = pmm_diag.freeFrameCount();
    // allocateWallpaper internally calls clearWallpaper() first; we want
    // to see frees + allocs broken apart, so do clear here explicitly.
    background.clearWallpaper();
    const free_after_clear = pmm_diag.freeFrameCount();
    if (!background.allocateWallpaper(w, h)) {
        debug.klog("[sysSetWallpaper] ENOMEM allocateWallpaper({d}x{d})\n", .{ w, h });
        return E_NOMEM;
    }
    const free_after_alloc = pmm_diag.freeFrameCount();
    debug.klog("[wallpaper-diag] before_clear={d} after_clear={d} (freed={d}) after_alloc={d} (consumed={d})\n", .{
        free_before_clear, free_after_clear, free_after_clear -% free_before_clear,
        free_after_alloc, free_after_clear -% free_after_alloc,
    });
    const dst = background.wallpaperSlice() orelse {
        debug.klog("[sysSetWallpaper] wallpaperSlice() null after alloc\n", .{});
        return E_INVAL;
    };
    const src: [*]const u32 = @ptrFromInt(@as(usize, buf_ptr));
    @memcpy(dst, src[0..dst.len]);
    dirty.force_full_kind = true;
    desktop.wake.requestWake();
    debug.klog("[sysSetWallpaper] OK installed {d}x{d}, force_full=true\n", .{ w, h });
    return 0;
}

pub fn sysNotify(text_ptr: u32, len: u32) u32 {
    const actual_len = @min(len, 64);
    if (!validateUserPtr(text_ptr, actual_len)) return E_FAULT;
    const src: [*]const u8 = @ptrFromInt(@as(usize, text_ptr));
    desktop.showNotification(src[0..actual_len]);
    return 0;
}

const GUI_FB_BASE: usize = 0x08000000; // User GUI FB virtual address
const GUI_MAX_SIZE: u32 = 8 * 1024 * 1024;
const GUI_FB_PER_PID: usize = memmap.GUI_FB_PER_PID_SIZE; // per-window size cap

pub fn sysCreateWindow(alloc_width_in: u32, alloc_height: u32, display_wh: u32) u32 {
    if (alloc_width_in == 0 or alloc_height == 0 or alloc_width_in > 1920 or alloc_height > 1080) {
        debug.klog("[sysCW] reject dims w={d} h={d}\n", .{ alloc_width_in, alloc_height });
        return E_INVAL;
    }
    // The kernel must NOT silently round alloc_width — the app already
    // chose its row stride and uses it directly via Canvas.init(fb,
    // alloc_w, alloc_h). Any kernel-side rounding (e.g. up to 16 for
    // Lavapipe alignment) creates a stride mismatch: app writes at
    // stride 712, kernel-side renderWindow + slot image read at stride
    // 720, content shears diagonally across rows. Slot allocation that
    // *needs* 16-aligned alloc_w gets rejected by allocateWindowImage's
    // pre-check (mem_w & 15) instead, which falls back to the legacy
    // PMM path silently — apps that want the slot fast-path can opt in
    // by passing 16-aligned dims themselves.
    const alloc_width: u32 = alloc_width_in;
    const fb_size: u64 = @as(u64, alloc_width) * alloc_height * 4;
    if (fb_size > GUI_MAX_SIZE) {
        debug.klog("[sysCW] reject fb_size={d} > GUI_MAX_SIZE={d}\n", .{ fb_size, GUI_MAX_SIZE });
        return E_INVAL;
    }

    // Display size: if arg3 is 0, use alloc size; otherwise unpack.
    // disp dims are independent of alloc dims (smaller visible region).
    var disp_w = alloc_width;
    var disp_h = alloc_height;
    if (display_wh != 0) {
        disp_w = display_wh & 0xFFFF;
        disp_h = display_wh >> 16;
        if (disp_w > alloc_width) disp_w = alloc_width;
        if (disp_h > alloc_height) disp_h = alloc_height;
    }
    // disp_w must also be 16-aligned for the B.2 image extent to match
    // the slot's row stride (mem_w must equal image_w padded to 16).
    // If disp_w == alloc_width — typical case — they're already aligned
    // because alloc_width was rounded above. If they differ, we just
    // use alloc_width as the image width too (safe but sampler reads
    // the alloc-width column-extent, with the visible-rect rendering
    // doing the right thing because gui_w is what determines the
    // window's screen rect anyway).
    if ((disp_w & 15) != 0) disp_w = alloc_width;

    const pcb = process.currentPCB() orelse {
        debug.klog("[sysCW] reject: no current PCB\n", .{});
        return E_INVAL;
    };
    const pd = pcb.page_directory orelse {
        debug.klog("[sysCW] reject: pcb.page_directory is null\n", .{});
        return E_INVAL;
    };

    const pid: u8 = @intCast(process.getCurrentPid());
    if (fb_size > GUI_FB_PER_PID) {
        debug.klog("[sysCW] reject fb_size={d} > GUI_FB_PER_PID={d}\n", .{ fb_size, GUI_FB_PER_PID });
        return E_INVAL;
    }
    const fb_size_u: usize = @intCast(fb_size); // Safe: checked <= GUI_MAX_SIZE (8MB)
    const num_pages: u32 = @intCast((fb_size_u + 4095) / 4096);
    const fb_pixels: u32 = @intCast(fb_size_u / 4);

    // Auto-focus policy: don't yank focus from a terminal whose shell
    // spawned this process. The user is typing into the shell; a
    // background-launched GUI app appearing on top of the z-stack but
    // unfocused matches what every modern desktop does. Shortcut/dock
    // launches go through a different (non-shell-parent) chain so they
    // still get focus as the user expects.
    const auto_focus = !desktop.focusedShellSpawnedPid(pid);

    // Step 9.4 Phase B.2: try to allocate a Venus dmabuf slot. If it
    // works, the dmabuf IS gui_fb — user-space maps directly at the
    // BAR-phys, so app writes go straight into the texture the
    // compositor samples. No PMM allocation, no triple-buffer copy.
    var gpu_slot: ?u8 = null;
    var kern_fb: [*]volatile u32 = undefined;
    const kern_fb_backs: [3]?[*]volatile u32 = .{ null, null, null };
    {
        const gpu_comp = @import("../../ui/gpu_compositor.zig");
        if (gpu_comp.isReady()) {
            gpu_slot = gpu_comp.allocateWindowImage(disp_w, disp_h, alloc_width, alloc_height);
        }
    }

    if (gpu_slot) |idx| {
        const gpu_comp = @import("../../ui/gpu_compositor.zig");
        const sl = &gpu_comp.window_slots[idx];
        const slot_phys = sl.phys;
        const slot_pages: u32 = @intCast((sl.mem_bytes + 4095) / 4096);
        // Map the dmabuf into user-space at GUI_FB_BASE. The phys is
        // in the SHM BAR range — vmm.mapUserPage just sets PTE flags,
        // any phys works. Rollback on any per-page failure: in normal
        // flow none of mapUserPage's error variants should fire
        // (GUI_FB_BASE is empty per process, the phys range is valid,
        // PMM has room for PT pages), but defensive coverage is the
        // whole point of gap #1's MapError migration.
        var mapped_pages: usize = 0;
        for (0..slot_pages) |i| {
            vmm.mapUserPage(pd, GUI_FB_BASE + i * 4096, slot_phys + i * 4096, paging.READ_WRITE | paging.USER) catch |e| {
                debug.klog("[sysCW] BLOB mapUserPage failed at page={d} virt=0x{X}: {s}\n", .{ i, GUI_FB_BASE + i * 4096, @errorName(e) });
                var j: usize = 0;
                while (j < mapped_pages) : (j += 1) {
                    _ = vmm.unmapUserPage(pd, GUI_FB_BASE + j * 4096);
                }
                return E_INVAL;
            };
            mapped_pages += 1;
        }
        asm volatile ("movq %%cr3, %%rax\n movq %%rax, %%cr3" ::: .{ .rax = true });
        // Zero the dmabuf so the compositor's first sample doesn't
        // read uninitialized pixels.
        const kfb_u8: [*]volatile u8 = sl.kernel_ptr.?;
        @memset(kfb_u8[0..@intCast(sl.mem_bytes)], 0);
        kern_fb = @ptrCast(@alignCast(sl.kernel_ptr.?));
        // No PMM allocation, no triple-buffer backs. Apps that call
        // sysPresent on a slot-backed window still bump
        // gui_present_pending — that's fine; sysPresent's snapshot
        // step is a no-op when gui_fb_backs[0] is null.
        // pmm_phys_base stays 0 — sysDestroyWindow path checks this
        // and skips PMM unmap for slot-backed windows.
    } else {
        // Legacy PMM path — compositor not ready or slot alloc failed.
        // Allocate ONLY the front buffer (num_pages). Triple back-buffers
        // (3 × num_pages) are allocated lazily on first sysPresent in
        // desktop.snapshotGuiFb. Apps that never call sysPresent (sysmon,
        // any direct-fb GUI app relying on auto-refresh) save 3× their
        // framebuffer in PMM — at 1920×1080 alloc that's 24 MB saved per
        // such window. On a 95 MB system that's the difference between
        // "OOM at three apps" and "OOM at six". Compositor's renderWindow
        // handles `gui_fb_backs[i] == null` by falling back to gui_fb
        // (see desktop.zig: `if (w.has_presented) backs[pub] else
        // gui_fb`), so visual output is identical until the app actually
        // presents.
        const phys_base = pmm.allocContiguous(num_pages) orelse {
            debug.klog("[sysCW] reject: pmm.allocContiguous({d} pages = {d} KB) FAILED\n", .{ num_pages, num_pages * 4 });
            return E_INVAL;
        };
        var mapped_pages: usize = 0;
        for (0..num_pages) |i| {
            const phys = phys_base + i * 4096;
            vmm.mapUserPage(pd, GUI_FB_BASE + i * 4096, phys, paging.READ_WRITE | paging.USER) catch |e| {
                // Rollback: undo dual-owner refs on what we mapped, then
                // free the whole contiguous block. releaseFrame here pairs
                // with the (skipped) acquireFrame we never reached on this
                // iteration; the earlier mapped_pages iterations got their
                // acquireFrame so we owe them a release apiece.
                debug.klog("[sysCW] legacy mapUserPage failed at page={d} virt=0x{X}: {s}\n", .{ i, GUI_FB_BASE + i * 4096, @errorName(e) });
                var j: usize = 0;
                while (j < mapped_pages) : (j += 1) {
                    _ = vmm.unmapUserPage(pd, GUI_FB_BASE + j * 4096);
                    pmm.releaseFrame(phys_base + j * 4096);
                }
                pmm.freeContiguous(phys_base, num_pages);
                return E_INVAL;
            };
            // Dual-owner refcount bump: front-buffer pages live in BOTH the
            // user PML4 (released by destroyAddressSpace on process exit) AND
            // the kernel desktop's gui_fb_phys_base table (released by
            // unmapGuiFB on window destroy). Without the extra acquire, the
            // second owner's release underflows. Back-buffer pages stay
            // single-owner (kernel-only, never mapped to user).
            pmm.acquireFrame(phys);
            const ptr: [*]u8 = @ptrFromInt(paging.physToVirt(phys));
            @memset(ptr[0..4096], 0);
            mapped_pages += 1;
        }
        paging.registerGuiFB(pid, phys_base);
        asm volatile ("movq %%cr3, %%rax\n movq %%rax, %%cr3" ::: .{ .rax = true });
        kern_fb = @ptrFromInt(paging.physToVirt(phys_base));
        // kern_fb_backs stays { null, null, null } — snapshotGuiFb will
        // populate on first present (or skip cleanly on alloc failure,
        // leaving the compositor on the gui_fb fallback path).
    }

    if (desktop.createGuiWindow(pid, kern_fb, kern_fb_backs, fb_pixels, disp_w, disp_h, alloc_width, alloc_height, auto_focus, gpu_slot) == null) {
        debug.klog("[syscall] Failed to create GUI window\n", .{});
        return E_INVAL;
    }

    // GUI apps get interactive priority automatically
    pcb.priority = .interactive;

    // Re-bind fd 0 to the console keyboard ring. GUI apps launched from
    // the shell inherit shell's kb_pipe as fd 0; once focus shifts to
    // their window, the desktop stops writing to that pipe and the GUI
    // app's readChar() spins on an empty pipe forever (e.g. threadbrot's
    // 1/2/4/8 hotkeys silently dropped). Console-fd0 reads from the
    // global keyboard ring, which the desktop deliberately leaves alone
    // for non-terminal focus, so the GUI app's readChar() pops it
    // directly. Apps that genuinely want pipe-stdin can re-open fd 0.
    pcb.fd_table[0] = .{ .in_use = true, .inode = 0, .offset = 0, .flags = 0, .fs_type = .console };

    debug.klog("[syscall] GUI window created: {d}x{d} (alloc {d}x{d}) pid={d}\n", .{ disp_w, disp_h, alloc_width, alloc_height, pid });
    return @intCast(GUI_FB_BASE);
}

pub fn sysPresent() u32 {
    const t = perf.enter();
    defer perf.leave(.present, t);
    // Snapshot the user-writable front buffer into the kernel back buffer.
    // The compositor reads gui_fb_back; without this copy we'd race against
    // the app's next-frame writes and tear. See window.gui_fb_back doc.
    desktop.snapshotGuiFb(@intCast(process.getCurrentPid()));
    desktop.markGuiPresent(@intCast(process.getCurrentPid()));
    // Do NOT pre-set state=.ready — schedule() owns the
    // .running → .switching_out → .ready handoff so another CPU
    // can't dispatch this PCB while its kstack is still in use.
    return 0;
}

pub fn sysGetMouse(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 20, 4)) return E_FAULT; // 5 u32s = 20 bytes
    const pid: u8 = @intCast(process.getCurrentPid());
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    desktop.getMouseRelative(pid, buf);
    // DEBUG: log every edge-press button event (rising edge of left button) per PID
    const dbg = struct {
        var counts: [16]u8 = [_]u8{0} ** 16;
        var prev_btn: [16]u8 = [_]u8{0} ** 16;
    };
    if (pid < 16) {
        const cur: u8 = @intCast(buf[2] & 0xFF);
        const edge = (cur & 1) != 0 and (dbg.prev_btn[pid] & 1) == 0;
        dbg.prev_btn[pid] = cur;
        if (edge and dbg.counts[pid] < 30) {
            dbg.counts[pid] += 1;
            const x: i32 = @bitCast(buf[0]);
            const y: i32 = @bitCast(buf[1]);
            const focused_pid = desktop.focusedPid();
            debug.klog("[click#{d}] PID={d} relx={d} rely={d} btn={X} focusPID={d}\n", .{ dbg.counts[pid], pid, x, y, buf[2], focused_pid });
        }
    }
    return 0;
}

pub fn sysDestroyWindow() u32 {
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.destroyGuiWindow(pid);
    return 0;
}

pub fn sysGetScreenSize(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 8, 4)) return E_FAULT;
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    const gfx = @import("../../ui/gfx.zig");
    buf[0] = gfx.screen_w;
    buf[1] = gfx.screen_h;
    return 0;
}

pub fn sysGetWindowSize(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 8, 4)) return E_FAULT;
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.getWindowContentSize(pid, buf);
    return 0;
}

/// Report the current framebuffer allocation (stride width, rows) of the
/// calling process's window. The compositor can grow this on F10 maximize
/// (desktop.growGuiFb); the app re-fetches it on a `.resize` event so it can
/// rebuild its canvas at the new stride and render crisply. buf[0]=alloc_w,
/// buf[1]=alloc_h.
pub fn sysGetWindowAlloc(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 8, 4)) return E_FAULT;
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.getWindowAllocSize(pid, buf);
    return 0;
}

pub const CLIPBOARD_MAX: u32 = 64 * 1024;
var clipboard_buf: [CLIPBOARD_MAX]u8 = [_]u8{0} ** CLIPBOARD_MAX;
var clipboard_len: u32 = 0;
var clipboard_lock: @import("../../proc/spinlock.zig").SpinLock = .{};

pub fn sysSetClipboard(buf_ptr: u32, len: u32) u32 {
    if (len == 0) {
        clipboard_lock.acquire();
        defer clipboard_lock.release();
        clipboard_len = 0;
        return 0;
    }
    if (len > CLIPBOARD_MAX) return E_INVAL;
    if (!validateUserPtr(buf_ptr, len)) return E_FAULT;
    const src: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    clipboard_lock.acquire();
    defer clipboard_lock.release();
    @memcpy(clipboard_buf[0..len], src[0..len]);
    clipboard_len = len;
    return len;
}

pub fn sysGetClipboard(buf_ptr: u32, max_len: u32) u32 {
    clipboard_lock.acquire();
    defer clipboard_lock.release();
    const actual = clipboard_len;
    if (actual == 0 or max_len == 0) return 0;
    const copy_n = @min(actual, max_len);
    if (!validateUserPtr(buf_ptr, copy_n)) return E_FAULT;
    const dst: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    @memcpy(dst[0..copy_n], clipboard_buf[0..copy_n]);
    return actual;
}

// --- Process tree + IPC syscalls (Task #73) ---

