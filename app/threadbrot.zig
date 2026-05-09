// threadbrot — parallel mandelbrot renderer.
//
// Splits the framebuffer into N horizontal stripes; each stripe is one
// pthread. No mutex needed (stripes don't overlap). The header bar
// reports last render time + speedup vs the 1-thread baseline so you
// can see the cost of N=1 vs N=4 vs N=8 directly.
//
// Controls: 1/2/4/8 set thread count and re-render; r re-render at
// current count; ESC quits.

const std = @import("std");
const libc = @import("libc");
const gfx = @import("graphics");

const W: u32 = 480;
const H: u32 = 320;
const HEADER_H: u32 = 18;
const RENDER_H: u32 = H - HEADER_H;

const MAX_ITERS: u32 = 200;

// View parameters — Mandelbrot zoomed on the main cardioid.
const CX_MIN: f64 = -2.5;
const CX_MAX: f64 = 1.0;
const CY_MIN: f64 = -1.1;
const CY_MAX: f64 = 1.1;

const MAX_THREADS: u32 = 8;

const Job = extern struct {
    fb: [*]volatile u32,
    y_start: u32,
    y_end: u32,
};

fn iterPalette(n: u32) u32 {
    if (n >= MAX_ITERS) return 0x000000;
    // Cheap "fire" gradient: ramp red, then add green, then add blue.
    const t = @as(u32, n) * 255 / MAX_ITERS;
    const r: u32 = if (t < 128) t * 2 else 255;
    const g: u32 = if (t < 64) 0 else if (t < 192) (t - 64) * 2 else 255;
    const b: u32 = if (t < 128) 0 else (t - 128) * 2;
    return (r << 16) | (g << 8) | b;
}

fn renderStripe(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const job: *Job = @ptrCast(@alignCast(arg.?));
    const dx = (CX_MAX - CX_MIN) / @as(f64, @floatFromInt(W));
    const dy = (CY_MAX - CY_MIN) / @as(f64, @floatFromInt(RENDER_H));
    var py: u32 = job.y_start;
    while (py < job.y_end) : (py += 1) {
        const cy: f64 = CY_MIN + dy * @as(f64, @floatFromInt(py));
        var px: u32 = 0;
        while (px < W) : (px += 1) {
            const cx: f64 = CX_MIN + dx * @as(f64, @floatFromInt(px));
            var x: f64 = 0;
            var y: f64 = 0;
            var n: u32 = 0;
            while (n < MAX_ITERS) : (n += 1) {
                const xx = x * x;
                const yy = y * y;
                if (xx + yy > 4.0) break;
                const xy = x * y;
                x = xx - yy + cx;
                y = xy + xy + cy;
            }
            const fb_y = py + HEADER_H;
            job.fb[fb_y * W + px] = iterPalette(n);
        }
    }
    return null;
}

fn renderWithThreads(canvas: *gfx.Canvas, n_threads: u32) u32 {
    const t0 = libc.gettimeofday();

    var jobs: [MAX_THREADS]Job = undefined;
    var tcbs: [MAX_THREADS]?*libc.Tcb = .{null} ** MAX_THREADS;

    const rows_per = RENDER_H / n_threads;
    var i: u32 = 0;
    while (i < n_threads) : (i += 1) {
        jobs[i] = .{
            .fb = canvas.fb,
            .y_start = i * rows_per,
            .y_end = if (i == n_threads - 1) RENDER_H else (i + 1) * rows_per,
        };
        // Workers run on top of the main thread when n=1 — but for
        // consistency we always go through pthreadCreate so the timing
        // includes spawn+join overhead in every case.
        tcbs[i] = libc.pthreadCreate(renderStripe, &jobs[i]);
    }
    i = 0;
    while (i < n_threads) : (i += 1) {
        if (tcbs[i]) |tcb| _ = libc.pthreadJoin(tcb);
    }

    const t1 = libc.gettimeofday();
    const elapsed_us: u64 = (@as(u64, t1.sec) - @as(u64, t0.sec)) * 1_000_000 +
        @as(u64, t1.usec) -% @as(u64, t0.usec);
    return @intCast(elapsed_us / 1000);
}

fn drawHeader(canvas: *gfx.Canvas, n_threads: u32, last_ms: u32, baseline_ms: u32) void {
    canvas.fillRect(0, 0, W, HEADER_H, 0x202028);

    var buf: [128]u8 = undefined;
    const text = if (baseline_ms == 0)
        std.fmt.bufPrint(&buf, "Threads: {d}  Time: {d} ms  [1/2/4/8 R Esc]", .{ n_threads, last_ms }) catch "?"
    else blk: {
        // speedup × 100 for one decimal of precision without floats
        const speedup_x100: u64 = if (last_ms == 0) 0 else (@as(u64, baseline_ms) * 100) / last_ms;
        break :blk std.fmt.bufPrint(
            &buf,
            "Threads: {d}  Time: {d} ms  Speedup: {d}.{d:0>2}x  [1/2/4/8 R Esc]",
            .{ n_threads, last_ms, speedup_x100 / 100, speedup_x100 % 100 },
        ) catch "?";
    };
    canvas.drawText(4, 5, text, 0xFFFFFF);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const win = libc.createWindow(W, H) orelse {
        libc.println("threadbrot: createWindow failed");
        libc.exit();
    };
    var canvas = gfx.Canvas.init(win.fb, win.alloc_w, win.alloc_h);

    canvas.clear(0x101018);
    drawHeader(&canvas, 1, 0, 0);
    libc.present();

    var n_threads: u32 = 1;
    var baseline_ms: u32 = 0;

    // Initial render at N=1 to set the baseline.
    var last_ms = renderWithThreads(&canvas, 1);
    baseline_ms = last_ms;
    drawHeader(&canvas, 1, last_ms, baseline_ms);
    libc.present();

    while (true) {
        const ch = libc.readChar();
        if (ch == 0x1B) break; // ESC

        var redraw = false;
        switch (ch) {
            '1' => {
                n_threads = 1;
                redraw = true;
            },
            '2' => {
                n_threads = 2;
                redraw = true;
            },
            '4' => {
                n_threads = 4;
                redraw = true;
            },
            '8' => {
                n_threads = 8;
                redraw = true;
            },
            'r', 'R' => redraw = true,
            else => {},
        }

        if (redraw) {
            last_ms = renderWithThreads(&canvas, n_threads);
            if (n_threads == 1) baseline_ms = last_ms;
            drawHeader(&canvas, n_threads, last_ms, baseline_ms);
            libc.present();
        }
    }

    libc.destroyWindow();
    libc.exit();
}
