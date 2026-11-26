// Starting a program from the desktop: a pinned app (the Terminal is a
// window with a shell, the rest are ELF files) or a path. The load runs on
// another CPU when there is one; a click that finds it busy is queued.

const debug = @import("../../debug/debug.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const process = @import("../../proc/process.zig");
const sound = @import("../../driver.zig").sound;
const client = @import("client.zig");
const createWindow = client.createWindow;
const emulator = @import("term/emulator.zig");
const cells = @import("term/cells.zig");
const FONT_H = cells.FONT_H;
const TERM_WIN_W = cells.TERM_WIN_W;
const session = @import("term/session.zig");
const spawnShellOnWindow = session.spawnShellOnWindow;
const notify = @import("notify.zig");
const showNotification = notify.showNotification;
const wm = @import("window.zig");
const setFocused = wm.setFocused;
const pinned = @import("pinned.zig");
const launch_queue = @import("launch_queue.zig");
const layout = @import("layout.zig");
const TITLEBAR_H = layout.TITLEBAR_H;
const TERM_ROWS = emulator.TERM_ROWS;

pub fn launchShortcut(idx: usize) void {
    const sc = &pinned.list[idx];
    debug.klog("[launch] shortcut idx={d} name='{s}' cmd='{s}'\n", .{ idx, sc.name, sc.cmd });
    if (sc.cmd.len == 0) {
        // Terminal shortcut: create a window, allocate kb_pipe + out_pipe,
        // spawn app.elf (Ring 3) with stdin/stdout/stderr wired to those
        // pipes. The shell is now a real user process — the desktop just
        // forwards keystrokes and drains stdout each frame.
        // window_count is u8; widen before the multiply or `9 * 30 = 270`
        // overflows u8 arithmetic and Zig's runtime safety panics.
        const off: i32 = @intCast(@as(u32, wm.window_count) * 30);
        const nw: u32 = TERM_WIN_W;
        const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
        if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
            setFocused(ni);
            spawnShellOnWindow(ni);
        }
        sound.open();
    } else {
        launchPath(sc.cmd);
    }
}

/// Start the ELF at `path` as an interactive app.
pub fn launchPath(path: []const u8) void {
    // Try the async load on an AP first.
    const smp = @import("../../cpu/smp.zig");
    if (smp.cpu_count > 1) {
        if (smp.requestAppLoad(path)) {
            debug.klog("[launch] requestAppLoad accepted '{s}'\n", .{path});
            showNotification("Loading...");
        } else {
            // AP mid-flight on a previous load — can't fall back to a
            // BSP-side sync read (both paths share NVMe bounce_buf w/o
            // serialization). Queue instead so the click isn't lost;
            // launch_queue.drain in the main loop will submit it once
            // the AP goes idle.
            if (launch_queue.push(path)) {
                debug.klog("[launch] queued '{s}' (depth: {d})\n", .{ path, launch_queue.depth() });
                showNotification("Queued...");
            } else {
                debug.klog("[launch] queue full, dropped '{s}'\n", .{path});
                showNotification("Launch queue full");
            }
        }
    } else {
        // Single-core only — sync fallback is safe (no concurrent
        // reader to race against).
        if (@import("../../fs/vfs.zig").loadFileFresh(path)) |fresh| {
            if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null)) |pid| {
                var nlen = path.len;
                if (nlen >= 4 and path[nlen - 4] == '.') nlen -= 4;
                process.setName(@intCast(pid), path[0..nlen]);
                process.getPCB(pid).priority = .interactive;
            }
        }
    }
    sound.open();
}
