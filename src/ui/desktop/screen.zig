// The surface the desktop draws into and how it reaches the display: the
// back buffer (its own pages, the device's resource, or the GPU compositor's
// source in mode 9), a change of resolution, and the software pointer, which
// is stamped over a frame on its way out and taken back off.

const gfx = @import("../gfx.zig");
const bga = @import("../../driver.zig").bga;
const vga = @import("../../driver.zig").vga;
const display = @import("../display.zig");
const mouse = @import("../../driver.zig").mouse;
const paging = @import("../../mm/paging.zig");
const debug = @import("../../debug/debug.zig");
const wm = @import("window.zig");
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const layout = @import("layout.zig");
const BORDER = layout.BORDER;

// --- Back buffer ---
pub var backbuf: ?[*]volatile u32 = null;
pub var bb_pages: u32 = 0;

/// Read-only access for the GPU compositor (mode 9). Returns null until
/// desktop.run() has finished allocating the back buffer; the compositor
/// polls until non-null before sampling.
pub fn getBackBuffer() ?[*]volatile u32 {
    return backbuf;
}

/// Mode 9: draw into `nb`, the GPU compositor's background source, from
/// now on. Caller holds the compositor's source lock. The old buffer is
/// the boot-reserved region; freeBackBuffer would be a no-op anyway.
pub fn adoptBackBuffer(nb: [*]volatile u32) void {
    const old = backbuf orelse return;
    const qwords: usize = @as(usize, gfx.target_w) * gfx.target_h / 2;
    asm volatile ("cld; rep movsq"
        :
        : [dst] "{rdi}" (@intFromPtr(nb)),
          [src] "{rsi}" (@intFromPtr(old)),
          [cnt] "{rcx}" (qwords),
        : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true });
    backbuf = nb;
    bb_pages = 0;
    gfx.setTarget(nb, gfx.target_w, gfx.target_h);
    @import("../gpu_compositor.zig").backBufferAdopted();
    debug.klog("[desktop] Back buffer: drawing into the GPU compositor's source\n", .{});
}

/// True when run() picked the GOP scanout as the desktop's display (real
/// hardware: no virtio, no BGA). Resolution is then immutable — GOP SetMode
/// is a boot service, gone after ExitBootServices — and the back-buffer
/// policy treats GUEST_FB as the compositing surface in blit mode.
pub var display_is_gop: bool = false;

pub fn changeResolution(new_w: u16, new_h: u16) void {
    const virtio_gpu = @import("../../driver.zig").virtio_gpu;

    if (display_is_gop) {
        debug.klog("[desktop] resolution change unavailable on GOP scanout (SetMode died with boot services)\n", .{});
        return;
    }

    // Free old back buffer (only allocated in BGA mode — virtio-gpu shares
    // the resource backing). bb_pages == 0 signals the no-alloc path.
    if (bb_pages != 0) paging.freeBackBuffer(bb_pages);
    backbuf = null;

    if (virtio_gpu.active) {
        // Virtio-GPU mode change
        if (!virtio_gpu.changeMode(new_w, new_h)) {
            debug.klog("[desktop] virtio-gpu mode change failed\n", .{});
            return;
        }
        gfx.setScreen(virtio_gpu.framebuffer, virtio_gpu.width, virtio_gpu.height);
    } else {
        // BGA mode change
        _ = bga.init(new_w, new_h);
        gfx.setScreen(bga.framebuffer, bga.width, bga.height);
    }

    if (virtio_gpu.active) {
        backbuf = @as([*]volatile u32, @ptrCast(virtio_gpu.framebuffer));
        bb_pages = 0;
        gfx.useFramebuffer();
        debug.klog("[desktop] Resolution: {d}x{d} (direct-to-resource)\n", .{ gfx.screen_w, gfx.screen_h });
    } else {
        bb_pages = (gfx.screen_w * gfx.screen_h * 4 + 4095) / 4096;
        if (paging.allocBackBuffer(bb_pages)) |buf| {
            backbuf = buf;
            gfx.setTarget(buf, gfx.screen_w, gfx.screen_h);
            debug.klog("[desktop] Resolution: {d}x{d} ({d} pages)\n", .{ gfx.screen_w, gfx.screen_h, bb_pages });
        } else {
            gfx.useFramebuffer();
            debug.klog("[desktop] WARNING: no back buffer at new res\n", .{});
        }
    }

    // Update mouse bounds
    mouse.screen_w = @intCast(gfx.screen_w);
    mouse.screen_h = @intCast(gfx.screen_h);
    if (mouse.x >= mouse.screen_w) mouse.x = mouse.screen_w - 1;
    if (mouse.y >= mouse.screen_h) mouse.y = mouse.screen_h - 1;
}

pub fn blitWindowBounds(idx: u8) void {
    const w = &windows[idx];
    const bx: u32 = if (w.x < @as(i32, BORDER)) 0 else @intCast(w.x - @as(i32, BORDER));
    const by: u32 = if (w.y < @as(i32, BORDER)) 0 else @intCast(w.y - @as(i32, BORDER));
    // Include shadow tail (24 px right + down) plus borders. Without this,
    // partial flushes during drag leave shadow ghosts at the old position.
    gfx.blitRectToScreen(bx, by, w.width + BORDER * 2 + 26, w.height + BORDER * 2 + 26);
}

// --- Cursor ---
const CURSOR_W: u32 = 12;
const CURSOR_H: u32 = 16;
const cursor_sprite = [CURSOR_H][CURSOR_W]u8{
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 0 },
    .{ 1, 2, 2, 1, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
};
var last_cursor_x: i32 = 0;
var last_cursor_y: i32 = 0;

/// Software-cursor visibility gate. The SW cursor is stamped into the
/// framebuffer only when there's no HW cursor AND the focused app hasn't
/// requested cursor-hide (DOOM/Quake fullscreen call setCursorVisible(false)).
/// Mirrors the gate in renderFrame (search: `app_hides`) so the main-loop fast
/// paths can't drift from it and re-stamp a frozen cursor over a fullscreen
/// game. Erase sites stay gated on `!use_hw_cursor` alone so a cursor drawn
/// before the hide still gets cleaned up.
pub fn swCursorActive(use_hw_cursor: bool) bool {
    return !use_hw_cursor and !(slot_used[wm.focused] and windows[wm.focused].cursor_hidden_by_app);
}

var cursor_save_buf: [CURSOR_W * CURSOR_H]u32 = [_]u32{0} ** (CURSOR_W * CURSOR_H);

pub fn eraseCursor() void {
    // Restore from back buffer at old cursor position
    const cx: u32 = if (last_cursor_x < 0) 0 else @intCast(last_cursor_x);
    const cy: u32 = if (last_cursor_y < 0) 0 else @intCast(last_cursor_y);
    gfx.blitRectToScreen(cx, cy, CURSOR_W, CURSOR_H);
    // Flush erased region to the scanout (virtio rect / GOP blit; no-op on
    // a live framebuffer like BGA or GOP-direct).
    display.flushRect(cx, cy, CURSOR_W, CURSOR_H);
}

pub fn drawCursorOnScreen() void {
    const mx = mouse.x;
    const my = mouse.y;
    for (0..CURSOR_H) |row| {
        for (0..CURSOR_W) |col| {
            const pixel = cursor_sprite[row][col];
            if (pixel != 0) {
                const color: u32 = if (pixel == 1) 0x000000 else 0xFFFFFF;
                gfx.putPixelDirect(mx + @as(i32, @intCast(col)), my + @as(i32, @intCast(row)), color);
            }
        }
    }
    last_cursor_x = mx;
    last_cursor_y = my;
    // Flush cursor region (direct screen writes need an explicit flush on
    // flush-based scanouts — virtio resource or GOP blit).
    {
        const cx: u32 = if (mx < 0) 0 else @intCast(mx);
        const cy: u32 = if (my < 0) 0 else @intCast(my);
        display.flushRect(cx, cy, CURSOR_W, CURSOR_H);
    }
}

/// Draw cursor into back buffer (save pixels underneath first).
/// Call before blitToScreen so cursor is included in the blit — no flicker.
pub fn bakeCursorToBackBuffer() void {
    const mx = mouse.x;
    const my = mouse.y;
    for (0..CURSOR_H) |row| {
        for (0..CURSOR_W) |col| {
            const sx = mx + @as(i32, @intCast(col));
            const sy = my + @as(i32, @intCast(row));
            if (sx >= 0 and sy >= 0 and @as(u32, @intCast(sx)) < gfx.target_w and @as(u32, @intCast(sy)) < gfx.target_h) {
                const off = @as(u32, @intCast(sy)) * gfx.target_w + @as(u32, @intCast(sx));
                cursor_save_buf[row * CURSOR_W + col] = gfx.target[off];
                if (cursor_sprite[row][col] != 0) {
                    gfx.target[off] = if (cursor_sprite[row][col] == 1) 0x000000 else 0xFFFFFF;
                }
            }
        }
    }
    last_cursor_x = mx;
    last_cursor_y = my;
}

/// Restore back buffer pixels that were overwritten by bakeCursorToBackBuffer.
pub fn unbakeCursorFromBackBuffer() void {
    for (0..CURSOR_H) |row| {
        for (0..CURSOR_W) |col| {
            const sx = last_cursor_x + @as(i32, @intCast(col));
            const sy = last_cursor_y + @as(i32, @intCast(row));
            if (sx >= 0 and sy >= 0 and @as(u32, @intCast(sx)) < gfx.target_w and @as(u32, @intCast(sy)) < gfx.target_h) {
                const off = @as(u32, @intCast(sy)) * gfx.target_w + @as(u32, @intCast(sx));
                gfx.target[off] = cursor_save_buf[row * CURSOR_W + col];
            }
        }
    }
}

/// Pick the display (scanout.zig) and the surface the desktop draws into.
/// Null, with a line on the text console, when there is no display.
pub fn bringUp() ?@import("../scanout.zig").Scanout {
    const virtio_gpu = @import("../../driver.zig").virtio_gpu;
    const gop = @import("../../driver.zig").gop_fb;

    // Device selection (virtio-gpu → BGA → GOP) lives in ui/scanout.zig so the
    // installer boots onto the same display the desktop would have picked.
    const so = @import("../scanout.zig").bringUp() orelse {
        vga.fg = .LightRed;
        vga.print("No display available!\n", .{});
        vga.fg = .LightGray;
        return null;
    };
    const disp_w = so.width;
    const disp_h = so.height;
    display_is_gop = (so.kind == .gop);

    // Back-buffer policy:
    //   * virtio-gpu mode: composite directly into the device resource backing.
    //     The host doesn't see writes until TRANSFER_TO_HOST_2D + RESOURCE_FLUSH,
    //     so the backing IS already a back buffer — no separate alloc, no SSE
    //     memcpy of the full frame on every redraw. Saves ~8MB per .full /
    //     .drag re-render at 1920×1080.
    //   * BGA mode: live framebuffer, host scans out continuously, so we still
    //     need a separate back buffer to avoid tearing.
    // Mode 9 (GPU compositor) forces back-buffer mode even on virtio-gpu
    // so the compositor can sample the desktop's fully rendered scene
    // (windows + chrome + menubar + dock + cursor) without racing the
    // CPU compositor's writes against the GPU compositor's screen-FB
    // writes. Together with `gfx.skip_blit_to_screen = true` below, this
    // makes the compositor the sole writer of virtio-gpu's framebuffer.
    const force_back_buffer = (@import("../../boot/boot_info.zig").boot_mode == 9);
    if (virtio_gpu.active and !force_back_buffer) {
        backbuf = @as([*]volatile u32, @ptrCast(virtio_gpu.framebuffer));
        bb_pages = 0;
        gfx.useFramebuffer(); // target := screen (= virtio-gpu resource backing)
        debug.klog("[desktop] Compositor: direct-to-resource (no back buffer)\n", .{});
    } else if (display_is_gop and !gop.direct and !force_back_buffer) {
        // GOP blit mode: GUEST_FB only reaches the panel on flush — it IS a
        // back buffer already, the same shape as virtio's direct-to-resource.
        backbuf = @as([*]volatile u32, @ptrCast(gop.framebuffer));
        bb_pages = 0;
        gfx.useFramebuffer(); // target := screen (= GUEST_FB blit source)
        debug.klog("[desktop] Compositor: direct-to-GUEST_FB (no extra back buffer)\n", .{});
    } else {
        bb_pages = (disp_w * disp_h * 4 + 4095) / 4096;
        if (paging.allocBackBuffer(bb_pages)) |buf| {
            backbuf = buf;
            gfx.setTarget(buf, disp_w, disp_h);
            debug.klog("[desktop] Back buffer: {d} pages (mode={d})\n", .{ bb_pages, @import("../../boot/boot_info.zig").boot_mode });
        } else {
            gfx.useFramebuffer();
            debug.klog("[desktop] WARNING: no back buffer\n", .{});
        }
    }
    if (force_back_buffer) {
        gfx.skip_blit_to_screen = true;
        @import("../../driver.zig").virtio_gpu.skip_external_flush = true;
        debug.klog("[desktop] Mode 9: blit-to-screen + flush suppressed; GPU compositor owns screen FB\n", .{});
    }
    return so;
}

/// The device's own pointer (virtio-gpu's cursor plane): it follows the
/// mouse, and hides while the focused program asks for that. Nothing in the
/// framebuffer is touched.
pub fn placePointer(use_hw_cursor: bool, cursor_moved: bool) void {
    if (use_hw_cursor) {
        const vgpu_cur = @import("../../driver.zig").virtio_gpu;
        // App override (setCursorVisible(false) on the focused window) wins
        // over auto-hide heuristics — keeps DOOM-style FPS apps from
        // re-showing the cursor on every mouse move.
        if (slot_used[wm.focused]) {
            const fw = &windows[wm.focused];
            if (fw.cursor_hidden_by_app) {
                // Explicit app override — Doom etc. set this and they
                // want the cursor gone regardless of window state.
                if (!vgpu_cur.cursor_hidden) vgpu_cur.hideCursor();
            } else if (fw.gui_fb == null and vgpu_cur.cursor_hidden) {
                vgpu_cur.showCursor();
                vgpu_cur.moveCursor(mouse.x, mouse.y);
            } else if (cursor_moved) {
                vgpu_cur.moveCursor(mouse.x, mouse.y);
            }
        } else if (cursor_moved) {
            vgpu_cur.moveCursor(mouse.x, mouse.y);
        }
    }
}
