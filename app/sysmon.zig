const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const C = gfx.Canvas;

const BG: u32 = 0x1A1A2E;

var alloc_w: u32 = 0;
var alloc_h: u32 = 0;
var vis_w: u32 = 0;
var vis_h: u32 = 0;

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    var init_w = scr.w / 4;
    if (init_w < 280) init_w = 280;
    if (init_w > 500) init_w = 500;
    const init_h = init_w * 3 / 4;
    alloc_w = @min(init_w * 2, scr.w);
    alloc_h = @min(init_h * 2, scr.h);
    while (alloc_w * alloc_h > 524288) {
        if (alloc_w > alloc_h) alloc_w -= 16 else alloc_h -= 16;
    }
    vis_w = init_w;
    vis_h = init_h;

    const win = libc.createWindowEx(alloc_w, alloc_h, init_w, init_h) orelse {
        libc.exit();
    };
    alloc_w = win.alloc_w; // libc may have rounded up to 16-px stride
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    fa.ensureLoaded();

    // Draw static elements once
    canvas.clear(BG);
    fa.drawTextOpaque(&canvas, 10, 8, "System Monitor", 0x4488CC, BG, &fa.default_24);
    canvas.drawHLine(10, 38, vis_w -| 20, 0x333355);
    fa.drawTextOpaque(&canvas, 10, 46, "Uptime:", 0xCCCCCC, BG, &fa.default_16);
    fa.drawTextOpaque(&canvas, 10, 68, "Memory:", 0xCCCCCC, BG, &fa.default_16);
    fa.drawTextOpaque(&canvas, 10, 90, "Usage:", 0xCCCCCC, BG, &fa.default_16);
    fa.drawTextOpaque(&canvas, 10, 134, "Ticks:", 0xCCCCCC, BG, &fa.default_16);
    fa.drawTextOpaque(&canvas, 10, 156, "Frames:", 0xCCCCCC, BG, &fa.default_16);
    fa.drawTextOpaque(&canvas, 10, 184, "Screen:", 0xCCCCCC, BG, &fa.default_16);
    fa.drawTextOpaque(&canvas, 10, 206, "Procs:", 0xCCCCCC, BG, &fa.default_16);
    // Screen size (static)
    var cx: u32 = fa.drawNumOpaque(&canvas, 110, 184, scr.w, 0x88CCFF, BG, &fa.default_16);
    fa.drawCharOpaque(&canvas, cx, 184, 'x', 0x88CCFF, BG, &fa.default_16);
    _ = fa.drawNumOpaque(&canvas, cx + fa.default_16.size_px, 184, scr.h, 0x88CCFF, BG, &fa.default_16);

    var frame: u32 = 0;
    while (true) {
        if (libc.readChar() == 0x1B) break;

        // Check for window resize
        const ws = libc.getWindowSize();
        if (ws.w > 0 and ws.h > 0) {
            const new_w = @min(ws.w, alloc_w);
            const new_h = @min(ws.h, alloc_h);
            if (new_w != vis_w or new_h != vis_h) {
                vis_w = new_w;
                vis_h = new_h;
                frame = 0;
            }
        }

        frame += 1;
        if (frame % 50 != 1) {
            libc.sleep(10);
            continue;
        }

        // Only update dynamic values — clear each row before redrawing
        const ticks = libc.uptime();
        const secs = ticks / 100;
        const mins = secs / 60;
        const hrs = mins / 60;

        // Uptime row
        canvas.fillRect(110, 46, vis_w -| 120, fa.default_16.line_height, BG);
        cx = fa.drawNumOpaque(&canvas, 110, 46, hrs, 0x88FF88, BG, &fa.default_16);
        fa.drawCharOpaque(&canvas, cx, 46, 'h', 0x88FF88, BG, &fa.default_16);
        cx = fa.drawNumOpaque(&canvas, cx + fa.default_16.size_px + 4, 46, mins % 60, 0x88FF88, BG, &fa.default_16);
        fa.drawCharOpaque(&canvas, cx, 46, 'm', 0x88FF88, BG, &fa.default_16);

        // Memory row
        const mem = libc.meminfo();
        const used = mem.total_frames - mem.free_frames;
        canvas.fillRect(110, 68, vis_w -| 120, fa.default_16.line_height, BG);
        cx = fa.drawNumOpaque(&canvas, 110, 68, mem.free_frames * 4, 0x88FF88, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, 68, "KB free", 0x88FF88, BG, &fa.default_16);

        // Progress bar
        const bar = ui.ProgressBar{
            .x = 10,
            .y = 108,
            .w = vis_w -| 20,
            .h = 18,
            .bg_color = 0x333355,
            .fill_color = 0x4488CC,
            .border_color = 0x666688,
        };
        bar.draw(&canvas, used, mem.total_frames);
        if (mem.total_frames > 0) {
            const pct = used * 100 / mem.total_frames;
            cx = fa.drawNumOpaque(&canvas, bar.x + 4, bar.y + 1, pct, 0xFFFFFF, 0x4488CC, &fa.default_16);
            fa.drawCharOpaque(&canvas, cx, bar.y + 1, '%', 0xFFFFFF, 0x4488CC, &fa.default_16);
        }

        // Ticks row
        canvas.fillRect(110, 134, vis_w -| 120, fa.default_16.line_height, BG);
        _ = fa.drawNumOpaque(&canvas, 110, 134, ticks, 0x88FF88, BG, &fa.default_16);

        // Frames row
        canvas.fillRect(110, 156, vis_w -| 120, fa.default_16.line_height, BG);
        cx = fa.drawNumOpaque(&canvas, 110, 156, used, 0xFF8888, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, 156, " used", 0xFF8888, BG, &fa.default_16);

        // Process summary — uses sysProcessList (#78). Shows alive count
        // plus a quick state breakdown so the user can see if the system
        // is mostly idle (sleeping) vs busy (running/ready).
        var pl_buf: [32]libc.ProcInfo = undefined;
        const pl_n = libc.processList(&pl_buf);
        var n_run: u32 = 0;
        var n_rdy: u32 = 0;
        var n_slp: u32 = 0;
        var k: u32 = 0;
        while (k < pl_n) : (k += 1) {
            switch (pl_buf[k].state) {
                libc.PROC_STATE_RUNNING => n_run += 1,
                libc.PROC_STATE_READY => n_rdy += 1,
                libc.PROC_STATE_SLEEPING => n_slp += 1,
                else => {},
            }
        }
        canvas.fillRect(110, 206, vis_w -| 120, fa.default_16.line_height, BG);
        cx = fa.drawNumOpaque(&canvas, 110, 206, pl_n, 0x88FF88, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, 206, " (", 0xCCCCCC, BG, &fa.default_16);
        cx += fa.default_16.size_px * 2;
        cx = fa.drawNumOpaque(&canvas, cx, 206, n_run, 0x88FF88, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, 206, "R ", 0x88FF88, BG, &fa.default_16);
        cx += fa.default_16.size_px * 2;
        cx = fa.drawNumOpaque(&canvas, cx, 206, n_rdy, 0x88CCFF, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, 206, "Q ", 0x88CCFF, BG, &fa.default_16);
        cx += fa.default_16.size_px * 2;
        cx = fa.drawNumOpaque(&canvas, cx, 206, n_slp, 0xFFCC88, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, 206, "S)", 0xFFCC88, BG, &fa.default_16);

        libc.sleep(10);
    }

    libc.destroyWindow();
    libc.exit();
}
