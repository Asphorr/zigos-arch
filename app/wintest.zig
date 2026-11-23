// wintest — a GUI window outlives neither the thread that made it nor its
// framebuffer's place in the address space.
//
//   1. A worker thread opens a window and ends without closing it: the
//      window goes with the thread, its framebuffer stays mapped.
//   2. The main thread opens one: the kernel reclaims what the worker left
//      (gui_window.reclaimLeftFb), so this succeeds.
//   3. It closes it (sysDestroyWindow) and opens another: the plain path.
//   4. It ends with that window open: the group's end takes it.
//
// Each step prints `[wintest] <step> ok` or a red FAIL, mirrored to serial.

const libc = @import("libc");

const W: u32 = 480;
const H: u32 = 320;

var worker_ok: bool = false;

fn fill(win: libc.WindowFb, color: u32) void {
    for (0..@as(usize, win.alloc_w) * win.alloc_h) |i| win.fb[i] = color;
    libc.present();
}

fn report(step: []const u8, ok: bool) void {
    if (ok) {
        libc.print("[wintest] ");
        libc.print(step);
        libc.print(" ok\n");
        libc.klogFmt("[wintest] {s} ok\n", .{step});
    } else {
        libc.print("\x1b[31m[wintest] ");
        libc.print(step);
        libc.print(" FAIL\x1b[0m\n");
        libc.klogFmt("[wintest] {s} FAIL\n", .{step});
    }
}

fn worker(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = arg;
    const win = libc.createWindow(W, H) orelse return null;
    worker_ok = true;
    fill(win, 0xFFC03030);
    libc.sleep(1500);
    return null; // no destroyWindow: the thread's end takes the window
}

/// The worker's teardown runs after join returns: give it a moment.
fn openAfterWorker() ?libc.WindowFb {
    var tries: u32 = 0;
    while (tries < 20) : (tries += 1) {
        if (libc.createWindow(W, H)) |win| return win;
        libc.sleep(100);
    }
    return null;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const tcb = libc.pthreadCreate(worker, null) orelse {
        report("spawn", false);
        libc.exit();
    };
    _ = libc.pthreadJoin(tcb);
    report("worker window", worker_ok);

    const second = openAfterWorker();
    report("window after the worker ended", second != null);
    if (second) |win| {
        fill(win, 0xFF30A040);
        libc.sleep(1500);
        libc.destroyWindow();
    }

    const third = libc.createWindow(W, H);
    report("window after destroyWindow", third != null);
    if (third) |win| {
        fill(win, 0xFF3060C0);
        libc.sleep(1000);
    }
    report("done", true);
    libc.exit(); // the window still open: the group's end takes it
}
