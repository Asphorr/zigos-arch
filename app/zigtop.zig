// zigtop — live TUI system dashboard.
//
// Window split into 4 panels:
//   - Top header:    title, uptime, total CPU%, process count
//   - Memory panel:  free/used bar + KiB readout
//   - Sparkline:     free-frames history (last N samples, ~30 s window)
//   - Process list:  top-N processes by CPU%, columns PID/STATE/CPU%/RSS/NAME
//
// Press 'q' or Escape to quit. Auto-refreshes every REFRESH_MS milliseconds.

const std = @import("std");
const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");

// === Layout ===
const WIN_W: u32 = 880;
const WIN_H: u32 = 600;
const REFRESH_MS: u64 = 500;
const SPARK_HISTORY: u32 = 90;

// === Colors ===
const C_BG: u32 = 0x0E0E18;
const C_PANEL_BG: u32 = 0x161628;
const C_BORDER: u32 = 0x2A2A48;
const C_TITLE: u32 = 0xCFE4FF;
const C_LABEL: u32 = 0x88AACC;
const C_VAL: u32 = 0xE0E0F0;
const C_DIM: u32 = 0x707088;
const C_OK: u32 = 0x90EE90;
const C_WARN: u32 = 0xFFD080;
const C_HOT: u32 = 0xFF6B6B;
const C_BAR_BG: u32 = 0x1F1F36;
const C_BAR_FILL: u32 = 0x4488EE;
const C_BAR_HOT: u32 = 0xEE6644;
const C_SPARK: u32 = 0x66BBFF;
const C_SPARK_DIM: u32 = 0x335577;

// === Sample ring (free-frames over time, decimated for the sparkline) ===
var free_frame_history: [SPARK_HISTORY]u32 = [_]u32{0} ** SPARK_HISTORY;
var sample_count: u32 = 0; // number of samples written (saturating)

fn pushSample(free_frames: u32) void {
    if (sample_count < SPARK_HISTORY) {
        free_frame_history[sample_count] = free_frames;
        sample_count += 1;
    } else {
        // Slide window: drop oldest, append newest.
        var i: u32 = 0;
        while (i < SPARK_HISTORY - 1) : (i += 1) {
            free_frame_history[i] = free_frame_history[i + 1];
        }
        free_frame_history[SPARK_HISTORY - 1] = free_frames;
    }
}

// === Util ===
fn formatU32(out: []u8, val: u32) []const u8 {
    if (val == 0) {
        out[0] = '0';
        return out[0..1];
    }
    var v = val;
    var tmp: [10]u8 = undefined;
    var n: usize = 0;
    while (v > 0) : (v /= 10) {
        tmp[n] = '0' + @as(u8, @intCast(v % 10));
        n += 1;
    }
    var i: usize = 0;
    while (i < n) : (i += 1) out[i] = tmp[n - 1 - i];
    return out[0..n];
}

fn formatPadU32(out: []u8, val: u32, width: usize) []const u8 {
    var tmp: [10]u8 = undefined;
    const s = formatU32(&tmp, val);
    if (s.len >= width) {
        @memcpy(out[0..s.len], s);
        return out[0..s.len];
    }
    const pad = width - s.len;
    var i: usize = 0;
    while (i < pad) : (i += 1) out[i] = ' ';
    @memcpy(out[pad .. pad + s.len], s);
    return out[0..width];
}

fn drawPanel(canvas: *gfx.Canvas, x: u32, y: u32, w: u32, h: u32, title: []const u8) void {
    canvas.fillRect(x, y, w, h, C_PANEL_BG);
    // 1px border (drawn as 4 thin rects so we don't depend on shape helpers).
    canvas.fillRect(x, y, w, 1, C_BORDER);
    canvas.fillRect(x, y + h - 1, w, 1, C_BORDER);
    canvas.fillRect(x, y, 1, h, C_BORDER);
    canvas.fillRect(x + w - 1, y, 1, h, C_BORDER);
    // Title strip.
    fa.drawText(canvas, @intCast(x + 10), @intCast(y + 6), title, C_TITLE, &fa.default_16);
}

fn drawBar(canvas: *gfx.Canvas, x: u32, y: u32, w: u32, h: u32, pct: u32) void {
    canvas.fillRect(x, y, w, h, C_BAR_BG);
    canvas.fillRect(x, y, w, 1, C_BORDER);
    canvas.fillRect(x, y + h - 1, w, 1, C_BORDER);
    const fill_w: u32 = if (w > 2) (w - 2) * @min(pct, 100) / 100 else 0;
    const fill_color: u32 = if (pct >= 85) C_BAR_HOT else C_BAR_FILL;
    if (fill_w > 0) canvas.fillRect(x + 1, y + 1, fill_w, h - 2, fill_color);
}

fn drawSparkline(canvas: *gfx.Canvas, x: u32, y: u32, w: u32, h: u32) void {
    if (sample_count == 0) return;
    // Find min/max in the window for autoscale.
    var lo: u32 = 0xFFFFFFFF;
    var hi: u32 = 0;
    for (free_frame_history[0..sample_count]) |v| {
        if (v < lo) lo = v;
        if (v > hi) hi = v;
    }
    const range: u32 = if (hi > lo) hi - lo else 1;
    // Plot bars across the width.
    const col_w: u32 = if (sample_count > 0) w / sample_count else 1;
    if (col_w == 0) return;
    var i: u32 = 0;
    while (i < sample_count) : (i += 1) {
        const v = free_frame_history[i];
        const norm = ((v - lo) * (h - 2)) / range;
        const bar_h: u32 = @max(1, norm);
        const bx = x + i * col_w;
        const by = y + h - 1 - bar_h;
        // Most recent sample drawn brighter than older ones.
        const color: u32 = if (i + 5 >= sample_count) C_SPARK else C_SPARK_DIM;
        if (col_w > 1) {
            canvas.fillRect(bx, by, col_w - 1, bar_h, color);
        } else {
            canvas.fillRect(bx, by, 1, bar_h, color);
        }
    }
}

// === Process list — sort top-N by CPU% ===

const MAX_PROCS: u32 = 32;
const TOP_N: u32 = 12;

const Row = struct {
    pid: u8,
    state: u8,
    cpu_pct: u32,
    rss_kb: u32,
    name_len: u8,
    name: [16]u8,
};

var rows: [MAX_PROCS]Row = undefined;
var rows_count: u32 = 0;

fn collectProcs() void {
    var procs: [MAX_PROCS]libc.ProcInfo = undefined;
    const n = libc.processList(&procs);
    rows_count = 0;
    // Same CPU% formula ps.zig uses: cpu_ticks / process_uptime_ticks.
    const uptime_ticks: u64 = @max(1, libc.uptime() / 10);
    for (procs[0..n]) |p| {
        if (p.state == libc.PROC_STATE_UNUSED) continue;
        const proc_age = if (uptime_ticks > p.start_tick) uptime_ticks - p.start_tick else uptime_ticks;
        const denom: u64 = if (proc_age > 0) proc_age else 1;
        const pct: u32 = @intCast(@min(@as(u64, 999), p.cpu_ticks * 100 / denom));
        rows[rows_count] = .{
            .pid = p.pid,
            .state = p.state,
            .cpu_pct = pct,
            .rss_kb = p.current_rss_pages * 4,
            .name_len = p.name_len,
            .name = p.name,
        };
        rows_count += 1;
    }
    // Insertion sort by cpu_pct descending, then rss_kb descending. With
    // <= 32 entries the O(n²) is fine.
    var i: u32 = 1;
    while (i < rows_count) : (i += 1) {
        var j = i;
        while (j > 0 and rowCmp(rows[j], rows[j - 1]) > 0) : (j -= 1) {
            const tmp = rows[j];
            rows[j] = rows[j - 1];
            rows[j - 1] = tmp;
        }
    }
}

fn rowCmp(a: Row, b: Row) i32 {
    if (a.cpu_pct != b.cpu_pct) return @as(i32, @intCast(a.cpu_pct)) - @as(i32, @intCast(b.cpu_pct));
    return @as(i32, @intCast(a.rss_kb)) - @as(i32, @intCast(b.rss_kb));
}

fn stateLabel(s: u8) []const u8 {
    return switch (s) {
        libc.PROC_STATE_READY => "ready",
        libc.PROC_STATE_RUNNING => "run",
        libc.PROC_STATE_SLEEPING => "sleep",
        libc.PROC_STATE_ZOMBIE => "zomb",
        else => "?",
    };
}

fn stateColor(s: u8) u32 {
    return switch (s) {
        libc.PROC_STATE_RUNNING => C_OK,
        libc.PROC_STATE_READY => 0x88CCEE,
        libc.PROC_STATE_SLEEPING => C_DIM,
        libc.PROC_STATE_ZOMBIE => C_HOT,
        else => C_DIM,
    };
}

// === Drawing ===

fn drawHeader(canvas: *gfx.Canvas, x: u32, y: u32, w: u32, h: u32, mi: libc.MemInfo) void {
    drawPanel(canvas, x, y, w, h, "zigtop");
    // Right-aligned subtitle: live tag.
    fa.drawText(canvas, @intCast(x + w - 240), @intCast(y + 6), "live • q to quit", C_DIM, &fa.default_16);

    // Uptime line.
    const ticks = libc.uptime();
    const total_s = ticks / 100;
    const days = total_s / 86400;
    const hours = (total_s % 86400) / 3600;
    const mins = (total_s % 3600) / 60;
    const secs = total_s % 60;
    var buf: [80]u8 = undefined;
    const ln = std.fmt.bufPrint(&buf, "Uptime {d}d {d}h {d}m {d}s", .{ days, hours, mins, secs }) catch buf[0..0];
    fa.drawText(canvas, @intCast(x + 10), @intCast(y + 30), ln, C_VAL, &fa.default_16);

    // Aggregate from process snapshot: total CPU% (sum), process count.
    var total_pct: u32 = 0;
    for (rows[0..rows_count]) |r| total_pct += r.cpu_pct;
    var buf2: [80]u8 = undefined;
    const ln2 = std.fmt.bufPrint(&buf2, "Total CPU {d}%   Procs {d}   Free {d} MiB / {d} MiB", .{
        total_pct,
        rows_count,
        mi.free_frames / 256,
        mi.total_frames / 256,
    }) catch buf2[0..0];
    fa.drawText(canvas, @intCast(x + 10), @intCast(y + 50), ln2, C_LABEL, &fa.default_16);
}

fn drawMemPanel(canvas: *gfx.Canvas, x: u32, y: u32, w: u32, h: u32, mi: libc.MemInfo) void {
    drawPanel(canvas, x, y, w, h, "Memory");
    const used = if (mi.total_frames > mi.free_frames) mi.total_frames - mi.free_frames else 0;
    const pct: u32 = if (mi.total_frames > 0) used * 100 / mi.total_frames else 0;
    drawBar(canvas, x + 10, y + 32, w - 20, 18, pct);
    var buf: [80]u8 = undefined;
    const ln = std.fmt.bufPrint(&buf, "{d}% used   {d} / {d} MiB", .{
        pct,
        used / 256,
        mi.total_frames / 256,
    }) catch buf[0..0];
    fa.drawText(canvas, @intCast(x + 10), @intCast(y + 56), ln, C_VAL, &fa.default_16);
}

fn drawSparkPanel(canvas: *gfx.Canvas, x: u32, y: u32, w: u32, h: u32) void {
    drawPanel(canvas, x, y, w, h, "Free frames (last ~45s)");
    drawSparkline(canvas, x + 10, y + 32, w - 20, h - 42);
    if (sample_count > 0) {
        const latest = free_frame_history[sample_count - 1];
        var buf: [40]u8 = undefined;
        const ln = std.fmt.bufPrint(&buf, "now {d}", .{latest}) catch buf[0..0];
        fa.drawText(canvas, @intCast(x + w - 80), @intCast(y + 6), ln, C_DIM, &fa.default_16);
    }
}

fn drawProcPanel(canvas: *gfx.Canvas, x: u32, y: u32, w: u32, h: u32) void {
    drawPanel(canvas, x, y, w, h, "Top processes (sorted by CPU%)");

    // Column header.
    const hy: u32 = y + 30;
    fa.drawText(canvas, @intCast(x + 10), @intCast(hy), "PID", C_LABEL, &fa.default_16);
    fa.drawText(canvas, @intCast(x + 56), @intCast(hy), "STATE", C_LABEL, &fa.default_16);
    fa.drawText(canvas, @intCast(x + 130), @intCast(hy), "CPU%", C_LABEL, &fa.default_16);
    fa.drawText(canvas, @intCast(x + 200), @intCast(hy), "RSS KB", C_LABEL, &fa.default_16);
    fa.drawText(canvas, @intCast(x + 290), @intCast(hy), "NAME", C_LABEL, &fa.default_16);
    canvas.fillRect(x + 10, hy + 18, w - 20, 1, C_BORDER);

    var row_y: u32 = hy + 24;
    const line_h: u32 = 18;
    var i: u32 = 0;
    const limit = @min(rows_count, TOP_N);
    while (i < limit) : (i += 1) {
        const r = rows[i];
        // PID.
        var pid_buf: [4]u8 = undefined;
        const pid_str = formatPadU32(&pid_buf, r.pid, 3);
        fa.drawText(canvas, @intCast(x + 10), @intCast(row_y), pid_str, C_VAL, &fa.default_16);
        // STATE (colored).
        fa.drawText(canvas, @intCast(x + 56), @intCast(row_y), stateLabel(r.state), stateColor(r.state), &fa.default_16);
        // CPU%.
        var cpu_buf: [8]u8 = undefined;
        const cpu_str = formatPadU32(&cpu_buf, r.cpu_pct, 4);
        const cpu_color: u32 = if (r.cpu_pct >= 50) C_HOT else if (r.cpu_pct >= 10) C_WARN else C_VAL;
        fa.drawText(canvas, @intCast(x + 130), @intCast(row_y), cpu_str, cpu_color, &fa.default_16);
        // RSS.
        var rss_buf: [12]u8 = undefined;
        const rss_str = formatPadU32(&rss_buf, r.rss_kb, 6);
        fa.drawText(canvas, @intCast(x + 200), @intCast(row_y), rss_str, C_VAL, &fa.default_16);
        // NAME.
        if (r.name_len > 0 and r.name_len <= 16) {
            fa.drawText(canvas, @intCast(x + 290), @intCast(row_y), r.name[0..r.name_len], C_VAL, &fa.default_16);
        } else {
            fa.drawText(canvas, @intCast(x + 290), @intCast(row_y), "?", C_DIM, &fa.default_16);
        }
        row_y += line_h;
    }
    if (rows_count > TOP_N) {
        var buf: [40]u8 = undefined;
        const ln = std.fmt.bufPrint(&buf, "... {d} more", .{rows_count - TOP_N}) catch buf[0..0];
        fa.drawText(canvas, @intCast(x + 10), @intCast(row_y), ln, C_DIM, &fa.default_16);
    }
}

fn timeMs() u64 {
    const t = libc.gettimeofday();
    return @as(u64, t.sec) * 1000 + @as(u64, t.usec) / 1000;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const win = libc.createWindow(WIN_W, WIN_H) orelse libc.exit();
    var canvas = gfx.Canvas.init(win.fb, win.alloc_w, win.alloc_h);
    fa.ensureLoaded();

    var last_refresh_ms: u64 = 0;

    while (true) {
        var should_quit = false;
        var did_redraw = false;

        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 'q' or ch == 'Q' or ch == 0x1B) should_quit = true;
                    if (ch == 'r' or ch == 'R') last_refresh_ms = 0; // force refresh
                },
                .close_request => should_quit = true,
                else => {},
            }
        }
        if (should_quit) break;

        const now = timeMs();
        if (now - last_refresh_ms >= REFRESH_MS) {
            last_refresh_ms = now;
            const mi = libc.meminfo();
            pushSample(mi.free_frames);
            collectProcs();

            canvas.fillRect(0, 0, WIN_W, WIN_H, C_BG);
            // Layout: header (full width, 78), then memory (left half, 90) +
            // sparkline (right half, 90), then process panel (full width).
            drawHeader(&canvas, 8, 8, WIN_W - 16, 78, mi);
            drawMemPanel(&canvas, 8, 94, (WIN_W - 24) / 2, 88, mi);
            drawSparkPanel(&canvas, 16 + (WIN_W - 24) / 2, 94, (WIN_W - 24) / 2, 88);
            drawProcPanel(&canvas, 8, 190, WIN_W - 16, WIN_H - 198);

            libc.present();
            did_redraw = true;
        }

        if (!did_redraw) libc.sleep(20);
    }

    libc.destroyWindow();
    libc.exit();
}
