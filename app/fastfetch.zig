// fastfetch — one-shot ZigOS system info card.
//
// Layout matches the Linux convention: ASCII logo on the left, key:value
// pairs on the right. Every reading is *real* — CPU brand via CPUID
// 0x80000002..4, logical-processor count via CPUID leaf 1, uptime/meminfo/
// process count via existing syscalls, build_id read from /BUILD.ID. No
// hardcoded fields.
//
// Terminal-only app: prints with ANSI colors and exits.

const std = @import("std");
const libc = @import("libc");

// === ANSI colors ===
const ANSI_RESET = "\x1b[0m";
const ANSI_BOLD = "\x1b[1m";
const ANSI_DIM = "\x1b[2m";
const C_LOGO = "\x1b[36m"; // cyan
const C_KEY = "\x1b[1;33m"; // bold yellow
const C_VAL = "\x1b[37m"; // white
const C_SEP = "\x1b[2m"; // dim

// === ASCII Z logo (8 rows × 13 cols, slanted single-letter) ===
const LOGO_LINES = [_][]const u8{
    " ___________ ",
    "|___________|",
    "          /  ",
    "        /    ",
    "      /      ",
    "    /        ",
    " ___________ ",
    "|___________|",
};
const LOGO_WIDTH: u32 = 13;

// === CPUID helpers ===

const CpuId = struct { eax: u32, ebx: u32, ecx: u32, edx: u32 };

fn cpuid(leaf: u32, sub: u32) CpuId {
    var ra: u32 = leaf;
    var rb: u32 = undefined;
    var rc: u32 = sub;
    var rd: u32 = undefined;
    asm volatile ("cpuid"
        : [ra] "+{eax}" (ra),
          [rb] "={ebx}" (rb),
          [rc] "+{ecx}" (rc),
          [rd] "={edx}" (rd),
    );
    return .{ .eax = ra, .ebx = rb, .ecx = rc, .edx = rd };
}

fn writeU32LE(buf: []u8, val: u32) void {
    buf[0] = @truncate(val);
    buf[1] = @truncate(val >> 8);
    buf[2] = @truncate(val >> 16);
    buf[3] = @truncate(val >> 24);
}

/// CPU vendor (12 bytes from leaf 0: EBX-EDX-ECX, in that exact order).
fn cpuVendor(out: *[12]u8) void {
    const r = cpuid(0, 0);
    writeU32LE(out[0..4], r.ebx);
    writeU32LE(out[4..8], r.edx);
    writeU32LE(out[8..12], r.ecx);
}

/// CPU brand string (48 bytes from leaves 0x80000002..4, EAX/EBX/ECX/EDX).
/// Some CPUs leave trailing spaces; we return a slice that trims them.
fn cpuBrand(out: *[48]u8) []const u8 {
    const leaves = [_]u32{ 0x80000002, 0x80000003, 0x80000004 };
    for (leaves, 0..) |leaf, i| {
        const r = cpuid(leaf, 0);
        const base = i * 16;
        writeU32LE(out[base..][0..4], r.eax);
        writeU32LE(out[base + 4 ..][0..4], r.ebx);
        writeU32LE(out[base + 8 ..][0..4], r.ecx);
        writeU32LE(out[base + 12 ..][0..4], r.edx);
    }
    // Trim leading + trailing whitespace + null bytes.
    var start: usize = 0;
    while (start < 48 and (out[start] == ' ' or out[start] == 0)) start += 1;
    var end: usize = 48;
    while (end > start and (out[end - 1] == ' ' or out[end - 1] == 0)) end -= 1;
    return out[start..end];
}

/// Logical processor count — from CPUID leaf 1, EBX[23:16]. This is the
/// max addressable logical proc count, equal to count when HT is on.
fn cpuLogicalCount() u8 {
    const r = cpuid(1, 0);
    return @truncate((r.ebx >> 16) & 0xFF);
}

/// True iff CPUID leaf 1, EDX bit 28 (HTT) is set.
fn cpuHasHT() bool {
    const r = cpuid(1, 0);
    return (r.edx & (1 << 28)) != 0;
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

fn formatU64(out: []u8, val: u64) []const u8 {
    if (val == 0) {
        out[0] = '0';
        return out[0..1];
    }
    var v = val;
    var tmp: [20]u8 = undefined;
    var n: usize = 0;
    while (v > 0) : (v /= 10) {
        tmp[n] = '0' + @as(u8, @intCast(v % 10));
        n += 1;
    }
    var i: usize = 0;
    while (i < n) : (i += 1) out[i] = tmp[n - 1 - i];
    return out[0..n];
}

/// Append `s` into `buf` at `*pos`, advancing the cursor. Truncates if needed.
fn append(buf: []u8, pos: *usize, s: []const u8) void {
    const room = buf.len - pos.*;
    const n = @min(s.len, room);
    @memcpy(buf[pos.*..][0..n], s[0..n]);
    pos.* += n;
}

fn appendU32(buf: []u8, pos: *usize, val: u32) void {
    var tmp: [10]u8 = undefined;
    const s = formatU32(&tmp, val);
    append(buf, pos, s);
}

/// Read /BUILD.ID (16 ASCII hex chars = 8 bytes). Returns null on failure.
fn readBuildId(buf: *[16]u8) ?[]const u8 {
    const fd = libc.open("/BUILD.ID") orelse return null;
    defer libc.close(fd);
    const n = libc.fread(fd, buf[0..]);
    if (n < 16) return null;
    return buf[0..16];
}

// === Info-line builders ===
//
// Each returns a slice into a caller-provided buffer. Doing all formatting
// in place avoids any heap allocation — fastfetch should stay tiny.

fn lineOs(buf: []u8) []const u8 {
    var p: usize = 0;
    append(buf, &p, "ZigOS \x1b[2mx86_64 freestanding\x1b[0m");
    return buf[0..p];
}

fn lineHost(buf: []u8) []const u8 {
    // Detect: are we under QEMU? CPUID leaf 0x40000000 hypervisor signature.
    // KVMKVMKVM, TCGTCGTCGTCG, Microsoft Hv, VMwareVMware, ...
    var vendor: [12]u8 = undefined;
    const r = cpuid(0x40000000, 0);
    writeU32LE(vendor[0..4], r.ebx);
    writeU32LE(vendor[4..8], r.ecx);
    writeU32LE(vendor[8..12], r.edx);
    var p: usize = 0;
    if (r.ebx == 0) {
        append(buf, &p, "bare metal");
    } else if (vendor[0] == 'K') {
        append(buf, &p, "QEMU (KVM)");
    } else if (vendor[0] == 'T') {
        append(buf, &p, "QEMU (TCG)");
    } else if (vendor[0] == 'M') {
        append(buf, &p, "Hyper-V");
    } else if (vendor[0] == 'V') {
        append(buf, &p, "VMware");
    } else {
        append(buf, &p, "VM (");
        append(buf, &p, vendor[0..12]);
        append(buf, &p, ")");
    }
    return buf[0..p];
}

fn lineKernel(buf: []u8) []const u8 {
    var p: usize = 0;
    var bid_buf: [16]u8 = undefined;
    if (readBuildId(&bid_buf)) |bid| {
        append(buf, &p, "ZigOS build #");
        append(buf, &p, bid);
    } else {
        append(buf, &p, "ZigOS (build id unknown)");
    }
    return buf[0..p];
}

fn lineUptime(buf: []u8) []const u8 {
    // libc.uptime() returns ticks at 100 Hz (per sysmon's interpretation).
    const ticks = libc.uptime();
    const total_s = ticks / 100;
    const days = total_s / 86400;
    const hours = (total_s % 86400) / 3600;
    const mins = (total_s % 3600) / 60;
    const secs = total_s % 60;
    var p: usize = 0;
    if (days > 0) {
        appendU32(buf, &p, days);
        append(buf, &p, "d ");
    }
    if (days > 0 or hours > 0) {
        appendU32(buf, &p, hours);
        append(buf, &p, "h ");
    }
    if (days > 0 or hours > 0 or mins > 0) {
        appendU32(buf, &p, mins);
        append(buf, &p, "m ");
    }
    appendU32(buf, &p, secs);
    append(buf, &p, "s");
    return buf[0..p];
}

fn lineCpu(buf: []u8) []const u8 {
    var brand_buf: [48]u8 = undefined;
    const brand = cpuBrand(&brand_buf);
    const log = cpuLogicalCount();
    const ht = cpuHasHT();
    var p: usize = 0;
    append(buf, &p, brand);
    append(buf, &p, " (");
    appendU32(buf, &p, log);
    if (ht) append(buf, &p, " HT");
    append(buf, &p, ")");
    return buf[0..p];
}

fn lineMemory(buf: []u8) []const u8 {
    const mi = libc.meminfo();
    // 4 KB per frame → MB = frames * 4 / 1024 = frames / 256.
    const total_mb = mi.total_frames / 256;
    const used_mb = (if (mi.total_frames > mi.free_frames) mi.total_frames - mi.free_frames else 0) / 256;
    const pct: u32 = if (mi.total_frames > 0) used_mb * 100 / total_mb else 0;
    var p: usize = 0;
    appendU32(buf, &p, used_mb);
    append(buf, &p, " / ");
    appendU32(buf, &p, total_mb);
    append(buf, &p, " MiB (");
    appendU32(buf, &p, pct);
    append(buf, &p, "%)");
    return buf[0..p];
}

fn lineProcs(buf: []u8) []const u8 {
    var procs: [32]libc.ProcInfo = undefined;
    const n = libc.processList(&procs);
    var running: u32 = 0;
    var sleeping: u32 = 0;
    for (procs[0..n]) |p2| {
        if (p2.state == libc.PROC_STATE_RUNNING) running += 1;
        if (p2.state == libc.PROC_STATE_SLEEPING) sleeping += 1;
    }
    var p: usize = 0;
    appendU32(buf, &p, n);
    append(buf, &p, " (");
    appendU32(buf, &p, running);
    append(buf, &p, " running, ");
    appendU32(buf, &p, sleeping);
    append(buf, &p, " sleeping)");
    return buf[0..p];
}

fn lineScreen(buf: []u8) []const u8 {
    const s = libc.getScreenSize();
    var p: usize = 0;
    appendU32(buf, &p, s.w);
    append(buf, &p, "x");
    appendU32(buf, &p, s.h);
    return buf[0..p];
}

fn lineCompiler(buf: []u8) []const u8 {
    const builtin = @import("builtin");
    var p: usize = 0;
    append(buf, &p, "Zig ");
    var ver_buf: [24]u8 = undefined;
    const ver = std.fmt.bufPrint(&ver_buf, "{d}.{d}.{d}", .{
        builtin.zig_version.major,
        builtin.zig_version.minor,
        builtin.zig_version.patch,
    }) catch return buf[0..p];
    append(buf, &p, ver);
    append(buf, &p, " / ");
    append(buf, &p, switch (builtin.mode) {
        .Debug => "Debug",
        .ReleaseSafe => "ReleaseSafe",
        .ReleaseFast => "ReleaseFast",
        .ReleaseSmall => "ReleaseSmall",
    });
    return buf[0..p];
}

// === Output ===

// Pad matches LOGO_WIDTH, used for info lines past LOGO_LINES.len.
const LOGO_PAD: []const u8 = "             "; // 13 spaces
comptime {
    if (LOGO_PAD.len != LOGO_WIDTH) @compileError("LOGO_PAD length must match LOGO_WIDTH");
}

fn printLogoLine(idx: usize) void {
    libc.print(C_LOGO);
    if (idx < LOGO_LINES.len) {
        libc.print(LOGO_LINES[idx]);
    } else {
        libc.print(LOGO_PAD);
    }
    libc.print(ANSI_RESET);
}

fn printInfoLine(key: []const u8, value: []const u8) void {
    libc.print(C_KEY);
    libc.print(key);
    libc.print(C_SEP);
    libc.print(": ");
    libc.print(C_VAL);
    libc.print(value);
    libc.print(ANSI_RESET);
}

/// One row of fastfetch = logo line N, two spaces, key:value (or empty).
fn row(logo_idx: usize, key: []const u8, value: []const u8) void {
    printLogoLine(logo_idx);
    libc.print("  ");
    if (key.len > 0) printInfoLine(key, value);
    libc.printChar('\n');
}

/// Color-swatch row at the bottom — the classic neofetch flourish. Pad of
/// LOGO_WIDTH + 2 (separator) so swatches align under the info column.
const COLOR_ROW_PAD: []const u8 = "               "; // LOGO_WIDTH + 2 = 15
comptime {
    if (COLOR_ROW_PAD.len != LOGO_WIDTH + 2) @compileError("COLOR_ROW_PAD length must be LOGO_WIDTH + 2");
}

fn colorRow() void {
    libc.print(COLOR_ROW_PAD);
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        var esc: [12]u8 = undefined;
        var p: usize = 0;
        append(&esc, &p, "\x1b[4");
        var d: [2]u8 = undefined;
        const ds = formatU32(&d, i);
        append(&esc, &p, ds);
        append(&esc, &p, "m  ");
        libc.print(esc[0..p]);
    }
    libc.print(ANSI_RESET);
    libc.printChar('\n');
    libc.print(COLOR_ROW_PAD);
    i = 0;
    while (i < 8) : (i += 1) {
        var esc: [16]u8 = undefined;
        var p: usize = 0;
        append(&esc, &p, "\x1b[10");
        var d: [2]u8 = undefined;
        const ds = formatU32(&d, i);
        append(&esc, &p, ds);
        append(&esc, &p, "m  ");
        libc.print(esc[0..p]);
    }
    libc.print(ANSI_RESET);
    libc.printChar('\n');
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.printChar('\n');

    // Build each value into its own buffer so they live for the print row.
    var buf_os: [80]u8 = undefined;
    var buf_host: [80]u8 = undefined;
    var buf_kern: [80]u8 = undefined;
    var buf_up: [40]u8 = undefined;
    var buf_cpu: [128]u8 = undefined;
    var buf_mem: [80]u8 = undefined;
    var buf_proc: [80]u8 = undefined;
    var buf_scr: [40]u8 = undefined;
    var buf_comp: [40]u8 = undefined;

    // Header (logo row 0).
    var header_buf: [64]u8 = undefined;
    var hp: usize = 0;
    append(&header_buf, &hp, "PID ");
    appendU32(&header_buf, &hp, libc.getpid());
    append(&header_buf, &hp, " @ zigos");
    row(0, "user", header_buf[0..hp]);

    // Separator under header (logo row 1).
    printLogoLine(1);
    libc.print("  ");
    libc.print(C_SEP);
    libc.print("-------------------------------------------");
    libc.print(ANSI_RESET);
    libc.printChar('\n');

    row(2, "OS",        lineOs(&buf_os));
    row(3, "Host",      lineHost(&buf_host));
    row(4, "Kernel",    lineKernel(&buf_kern));
    row(5, "Uptime",    lineUptime(&buf_up));
    row(6, "CPU",       lineCpu(&buf_cpu));
    row(7, "Memory",    lineMemory(&buf_mem));

    // Lines beyond the logo height get printed with empty logo column
    // (idx >= LOGO_LINES.len triggers LOGO_PAD in printLogoLine).
    row(LOGO_LINES.len, "Processes", lineProcs(&buf_proc));
    row(LOGO_LINES.len, "Screen",    lineScreen(&buf_scr));
    row(LOGO_LINES.len, "Compiler",  lineCompiler(&buf_comp));

    libc.printChar('\n');
    colorRow();
    libc.printChar('\n');

    libc.exit();
}
