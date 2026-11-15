const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const app = @import("app");
const C = gfx.Canvas;

const BG: u32 = 0x1E1E20;
const BAR_EMPTY: u32 = 0x2A2A2D;
const BAR_BORDER: u32 = 0x45454A;
const RULE: u32 = 0x38383C;
const TITLE: u32 = 0xF2F2F4;
const LABEL: u32 = 0xA8A8AE;
const VALUE: u32 = 0xF2F2F4;
const RUNNING: u32 = 0x6FD58A;
const READY: u32 = 0x6CB6FF;
const SLEEPING: u32 = 0xE8B25A;

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
const SAMPLE_MS: u32 = 500;

// Layout: y of each row, x of the margins and of the value column.
const PAD: u32 = 12;
const VALUE_X: u32 = 96;
const Y_TITLE: u32 = 8;
const Y_SEP: u32 = 40;
const Y_UPTIME: u32 = 50;
const Y_PROCS: u32 = 72;
const Y_MEM: u32 = 98;
const Y_MEM_BAR: u32 = 120;
const Y_CPU_START: u32 = 146; // first CPU row; each subsequent +CPU_PITCH
const CPU_PITCH: u32 = 36;
const BOTTOM: u32 = Y_CPU_START + CPU_PITCH * MAX_CPUS + 8;

/// What the window shows, as of the last sample().
const Sample = struct {
    uptime_s: u32 = 0,
    procs: u32 = 0,
    running: u32 = 0,
    ready: u32 = 0,
    sleeping: u32 = 0,
    mem_used_mb: u32 = 0,
    mem_total_mb: u32 = 0,
    mem_pct: u32 = 0,
    cpus: u32 = 0,
    cpu_pct: [MAX_CPUS]u32 = .{0} ** MAX_CPUS,
};
var shown: Sample = .{};
var prev_stats: [MAX_CPUS]libc.CpuStat = [_]libc.CpuStat{.{ .total_cyc = 0, .idle_cyc = 0 }} ** MAX_CPUS;
var prev_valid: bool = false;

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    const w = @min(@max(scr.w / 4, 320), 540);
    app.run(@This(), .{ .width = w, .height = BOTTOM, .escape_closes = true, .tick_ms = SAMPLE_MS });
}

pub fn init(_: *app.Window) void {
    sample();
}

pub fn tick(win: *app.Window) void {
    sample();
    win.invalidate();
}

fn sample() void {
    shown.uptime_s = libc.uptime() / 100;

    var procs: [libc.MAX_PROCS]libc.ProcInfo = undefined;
    const n = libc.processList(&procs);
    shown.procs = n;
    shown.running = 0;
    shown.ready = 0;
    shown.sleeping = 0;
    for (procs[0..n]) |p| {
        switch (p.state) {
            libc.PROC_STATE_RUNNING => shown.running += 1,
            libc.PROC_STATE_READY => shown.ready += 1,
            libc.PROC_STATE_SLEEPING => shown.sleeping += 1,
            else => {},
        }
    }

    const mem = libc.meminfo();
    const used_frames = mem.total_frames -| mem.free_frames;
    shown.mem_used_mb = used_frames / 256;
    shown.mem_total_mb = mem.total_frames / 256;
    shown.mem_pct = if (mem.total_frames > 0) (used_frames * 100) / mem.total_frames else 0;

    // Utilization over the interval since the previous sample:
    // (total_d - idle_d) / total_d. The first sample has nothing to
    // subtract from and shows 0%.
    var stats: [MAX_CPUS]libc.CpuStat = undefined;
    const n_cpus = libc.cpuStats(stats[0..]);
    shown.cpus = if (n_cpus > MAX_CPUS) 0 else n_cpus;
    for (0..shown.cpus) |c| {
        var pct: u32 = 0;
        if (prev_valid) {
            const d_total = stats[c].total_cyc -% prev_stats[c].total_cyc;
            const d_idle = stats[c].idle_cyc -% prev_stats[c].idle_cyc;
            if (d_total > 0) pct = @intCast(@min((d_total -| d_idle) * 100 / d_total, 100));
        }
        shown.cpu_pct[c] = pct;
        prev_stats[c] = stats[c];
    }
    if (shown.cpus > 0) prev_valid = true;
}

/// Draw `n` in decimal at the row's cursor.
fn num(row: *ui.HStack, n: u32, color: u32) void {
    var buf: [10]u8 = undefined;
    var i: usize = buf.len;
    var v = n;
    while (true) {
        i -= 1;
        buf[i] = @intCast('0' + v % 10);
        v /= 10;
        if (v == 0) break;
    }
    row.label(buf[i..], color, fa.getDefault16());
}

/// "NN%" with its right edge at `right`.
fn percentRight(canvas: *C, right: u32, y: u32, pct: u32) void {
    const a16 = fa.getDefault16();
    const digits: u32 = if (pct >= 100) 3 else if (pct >= 10) 2 else 1;
    const width = a16.measure("0") * digits + a16.measure("%");
    var row = ui.HStack.init(canvas, right -| width, y, a16.line_height);
    num(&row, pct, VALUE);
    row.label("%", VALUE, a16);
}

pub fn draw(win: *app.Window) void {
    const canvas = &win.canvas;
    const a16 = fa.getDefault16();
    const right = win.w -| PAD;
    const bar_w = win.w -| PAD * 2;
    const s = shown;

    canvas.clear(BG);
    fa.drawText(canvas, PAD, Y_TITLE, "System Monitor", TITLE, fa.getDefault24());
    canvas.drawHLine(PAD, Y_SEP, bar_w, RULE);

    var row = ui.HStack.init(canvas, PAD, Y_UPTIME, a16.line_height);
    row.label("Uptime", LABEL, a16);
    row.skipTo(VALUE_X);
    num(&row, s.uptime_s / 3600, VALUE);
    row.label("h ", VALUE, a16);
    num(&row, s.uptime_s / 60 % 60, VALUE);
    row.label("m ", VALUE, a16);
    num(&row, s.uptime_s % 60, VALUE);
    row.label("s", VALUE, a16);

    row = ui.HStack.init(canvas, PAD, Y_PROCS, a16.line_height);
    row.label("Procs", LABEL, a16);
    row.skipTo(VALUE_X);
    num(&row, s.procs, VALUE);
    row.gap(14);
    num(&row, s.running, RUNNING);
    row.label(" running", RUNNING, a16);
    row.gap(10);
    num(&row, s.ready, READY);
    row.label(" ready", READY, a16);
    row.gap(10);
    num(&row, s.sleeping, SLEEPING);
    row.label(" asleep", SLEEPING, a16);

    row = ui.HStack.init(canvas, PAD, Y_MEM, a16.line_height);
    row.label("Memory", LABEL, a16);
    row.skipTo(VALUE_X);
    num(&row, s.mem_used_mb, VALUE);
    row.label(" / ", LABEL, a16);
    num(&row, s.mem_total_mb, VALUE);
    row.label(" MiB", LABEL, a16);
    percentRight(canvas, right, Y_MEM, s.mem_pct);
    drawBar(canvas, PAD, Y_MEM_BAR, bar_w, 14, s.mem_pct);

    for (0..s.cpus) |c| {
        const y: u32 = Y_CPU_START + @as(u32, @intCast(c)) * CPU_PITCH;
        row = ui.HStack.init(canvas, PAD, y, a16.line_height);
        row.label("CPU ", LABEL, a16);
        num(&row, @intCast(c), LABEL);
        percentRight(canvas, right, y, s.cpu_pct[c]);
        drawBar(canvas, PAD, y + 20, bar_w, 12, s.cpu_pct[c]);
    }
}
