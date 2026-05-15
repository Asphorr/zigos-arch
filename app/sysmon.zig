const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const C = gfx.Canvas;

const BG: u32 = 0x1A1A2E;
const BAR_EMPTY: u32 = 0x2A2A40;
const BAR_BORDER: u32 = 0x404060;

// Band colors — same palette as fastfetch's terminal memory bar so the
// look is consistent across tools.
const BAND_GREEN: u32 = 0x5FB85F;
const BAND_YELLOW: u32 = 0xF5C842;
const BAND_RED: u32 = 0xE5484D;

// Band thresholds in percent. <60% = green, 60..85% = yellow, ≥85% = red.
fn bandForPct(pct: u32) u32 {
    if (pct >= 85) return BAND_RED;
    if (pct >= 60) return BAND_YELLOW;
    return BAND_GREEN;
}

/// One 20-cell colored bar. The fill paints the leftmost `filled` cells in
/// the band color and the rest in dim. Matches the fastfetch logo's bar
/// shape (filled left, dim right, 1px gutter between cells reads as the
/// halftone-ish stippling we got from the inverse-trick terminal bar).
fn drawBar(canvas: *C, x: u32, y: u32, w: u32, h: u32, pct: u32) void {
    const CELLS: u32 = 20;
    const gap: u32 = 1;
    canvas.drawHLine(x, y, w, BAR_BORDER);
    canvas.drawHLine(x, y + h -| 1, w, BAR_BORDER);

    const inner_y: u32 = y + 1;
    const inner_h: u32 = h -| 2;
    const cell_pitch: u32 = w / CELLS;
    const cell_w: u32 = if (cell_pitch > gap) cell_pitch - gap else 1;
    const filled: u32 = blk: {
        if (pct >= 100) break :blk CELLS;
        const raw = (pct * CELLS) / 100;
        if (pct > 0 and raw == 0) break :blk 1;
        break :blk raw;
    };
    const band = bandForPct(pct);
    var i: u32 = 0;
    while (i < CELLS) : (i += 1) {
        const cx: u32 = x + i * cell_pitch;
        const color: u32 = if (i < filled) band else BAR_EMPTY;
        canvas.fillRect(cx, inner_y, cell_w, inner_h, color);
    }
}

const MAX_CPUS: u32 = 4;
const POLL_FRAMES: u32 = 50; // ~500ms between refreshes
var prev_stats: [MAX_CPUS]libc.CpuStat = [_]libc.CpuStat{.{ .irq_ticks = 0, .idle_ticks = 0 }} ** MAX_CPUS;
var prev_valid: bool = false;

// Layout constants — y-coords of each row in the dynamic content area.
const Y_TITLE: u32 = 8;
const Y_SEP: u32 = 38;
const Y_UPTIME: u32 = 46;
const Y_PROCS: u32 = 68;
const Y_MEM_LABEL: u32 = 92;
const Y_MEM_BAR: u32 = 110;
const Y_CPU_START: u32 = 134; // first CPU bar; each subsequent +24
const CPU_PITCH: u32 = 24;
const FOOTER_BASE: u32 = 134 + CPU_PITCH * MAX_CPUS + 8;

var alloc_w: u32 = 0;
var alloc_h: u32 = 0;
var vis_w: u32 = 0;
var vis_h: u32 = 0;

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    var init_w = scr.w / 4;
    if (init_w < 320) init_w = 320;
    if (init_w > 540) init_w = 540;
    // Tall enough for title + memory bar + up to MAX_CPUS bars + footer rows.
    var init_h: u32 = FOOTER_BASE + 60;
    if (init_h > scr.h) init_h = scr.h;
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
    alloc_w = win.alloc_w;
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    fa.ensureLoaded();

    // Static chrome — labels that never change.
    canvas.clear(BG);
    fa.drawTextOpaque(&canvas, 10, Y_TITLE, "System Monitor", 0x4488CC, BG, &fa.default_24);
    canvas.drawHLine(10, Y_SEP, vis_w -| 20, 0x333355);
    fa.drawTextOpaque(&canvas, 10, Y_UPTIME, "Uptime:", 0xCCCCCC, BG, &fa.default_16);
    fa.drawTextOpaque(&canvas, 10, Y_PROCS, "Procs:", 0xCCCCCC, BG, &fa.default_16);
    fa.drawTextOpaque(&canvas, 10, Y_MEM_LABEL, "Memory:", 0xCCCCCC, BG, &fa.default_16);

    var frame: u32 = 0;
    while (true) {
        if (libc.readChar() == 0x1B) break;

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
        if (frame % POLL_FRAMES != 1) {
            libc.sleep(10);
            continue;
        }

        // ─── Uptime row ────────────────────────────────────────────
        const ticks = libc.uptime();
        const secs = ticks / 100;
        const mins = secs / 60;
        const hrs = mins / 60;
        canvas.fillRect(110, Y_UPTIME, vis_w -| 120, fa.default_16.line_height, BG);
        var cx: u32 = fa.drawNumOpaque(&canvas, 110, Y_UPTIME, hrs, 0x88FF88, BG, &fa.default_16);
        fa.drawCharOpaque(&canvas, cx, Y_UPTIME, 'h', 0x88FF88, BG, &fa.default_16);
        cx = fa.drawNumOpaque(&canvas, cx + fa.default_16.size_px + 4, Y_UPTIME, mins % 60, 0x88FF88, BG, &fa.default_16);
        fa.drawCharOpaque(&canvas, cx, Y_UPTIME, 'm', 0x88FF88, BG, &fa.default_16);
        cx = fa.drawNumOpaque(&canvas, cx + fa.default_16.size_px + 4, Y_UPTIME, secs % 60, 0x88FF88, BG, &fa.default_16);
        fa.drawCharOpaque(&canvas, cx, Y_UPTIME, 's', 0x88FF88, BG, &fa.default_16);

        // ─── Process count row ─────────────────────────────────────
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
        canvas.fillRect(110, Y_PROCS, vis_w -| 120, fa.default_16.line_height, BG);
        cx = fa.drawNumOpaque(&canvas, 110, Y_PROCS, pl_n, 0x88FF88, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, Y_PROCS, " (", 0xCCCCCC, BG, &fa.default_16);
        cx += fa.default_16.size_px * 2;
        cx = fa.drawNumOpaque(&canvas, cx, Y_PROCS, n_run, 0x88FF88, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, Y_PROCS, "R ", 0x88FF88, BG, &fa.default_16);
        cx += fa.default_16.size_px * 2;
        cx = fa.drawNumOpaque(&canvas, cx, Y_PROCS, n_rdy, 0x88CCFF, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, Y_PROCS, "Q ", 0x88CCFF, BG, &fa.default_16);
        cx += fa.default_16.size_px * 2;
        cx = fa.drawNumOpaque(&canvas, cx, Y_PROCS, n_slp, 0xFFCC88, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, Y_PROCS, "S)", 0xFFCC88, BG, &fa.default_16);

        // ─── Memory bar ────────────────────────────────────────────
        const mem = libc.meminfo();
        const used_frames = if (mem.total_frames > mem.free_frames) mem.total_frames - mem.free_frames else 0;
        const used_mb = used_frames / 256;
        const total_mb = mem.total_frames / 256;
        const mem_pct: u32 = if (mem.total_frames > 0) (used_frames * 100) / mem.total_frames else 0;
        canvas.fillRect(80, Y_MEM_LABEL, vis_w -| 90, fa.default_16.line_height, BG);
        cx = fa.drawNumOpaque(&canvas, 80, Y_MEM_LABEL, used_mb, 0xCCCCCC, BG, &fa.default_16);
        fa.drawCharOpaque(&canvas, cx, Y_MEM_LABEL, '/', 0xCCCCCC, BG, &fa.default_16);
        cx = fa.drawNumOpaque(&canvas, cx + fa.default_16.size_px, Y_MEM_LABEL, total_mb, 0xCCCCCC, BG, &fa.default_16);
        fa.drawTextOpaque(&canvas, cx, Y_MEM_LABEL, " MiB  ", 0xCCCCCC, BG, &fa.default_16);
        cx += fa.default_16.size_px * 6;
        cx = fa.drawNumOpaque(&canvas, cx, Y_MEM_LABEL, mem_pct, 0xFFFFFF, BG, &fa.default_16);
        fa.drawCharOpaque(&canvas, cx, Y_MEM_LABEL, '%', 0xFFFFFF, BG, &fa.default_16);
        drawBar(&canvas, 10, Y_MEM_BAR, vis_w -| 20, 16, mem_pct);

        // ─── CPU bars (per CPU) ────────────────────────────────────
        var stat_buf: [MAX_CPUS]libc.CpuStat = undefined;
        const n_cpus = libc.cpuStats(stat_buf[0..]);
        const cpu_count: u32 = if (n_cpus > MAX_CPUS) 0 else n_cpus;
        var c: u32 = 0;
        while (c < cpu_count) : (c += 1) {
            const y: u32 = Y_CPU_START + c * CPU_PITCH;
            // Delta-based utilization: (irq_d - idle_d) / irq_d.
            // First sample has prev=0 so we skip and show 0% to avoid a
            // bogus spike on the first frame.
            var pct: u32 = 0;
            if (prev_valid) {
                const d_irq = stat_buf[c].irq_ticks -% prev_stats[c].irq_ticks;
                const d_idle = stat_buf[c].idle_ticks -% prev_stats[c].idle_ticks;
                if (d_irq > 0) {
                    const busy = if (d_irq > d_idle) d_irq - d_idle else 0;
                    pct = @intCast((busy * 100) / d_irq);
                    if (pct > 100) pct = 100;
                }
            }
            canvas.fillRect(10, y, vis_w -| 20, fa.default_16.line_height + 18, BG);
            // Label "CPU N" + %.
            fa.drawTextOpaque(&canvas, 10, y, "CPU", 0xCCCCCC, BG, &fa.default_16);
            cx = 10 + fa.default_16.size_px * 4;
            cx = fa.drawNumOpaque(&canvas, cx, y, c, 0xCCCCCC, BG, &fa.default_16);
            fa.drawCharOpaque(&canvas, cx + 4, y, ':', 0xCCCCCC, BG, &fa.default_16);
            cx = fa.drawNumOpaque(&canvas, cx + fa.default_16.size_px + 6, y, pct, 0xFFFFFF, BG, &fa.default_16);
            fa.drawCharOpaque(&canvas, cx, y, '%', 0xFFFFFF, BG, &fa.default_16);
            drawBar(&canvas, 10, y + 18, vis_w -| 20, 12, pct);
            prev_stats[c] = stat_buf[c];
        }
        if (cpu_count > 0) prev_valid = true;

        libc.sleep(10);
    }

    libc.destroyWindow();
    libc.exit();
}
