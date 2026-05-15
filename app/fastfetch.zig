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
// Zig brand orange (#F7A41D) via 24-bit ANSI. The terminal supports
// the truecolor escape — fastfetch was emitting plain cyan before.
const C_LOGO = "\x1b[38;2;247;164;29m";
const C_KEY = "\x1b[1;33m"; // bold yellow
const C_VAL = "\x1b[37m"; // white
const C_SEP = "\x1b[2m"; // dim

// === 3D-extruded Z logo (10 rows × 13 cols) ===
//
// Each diagonal step uses three glyph kinds:
//   ▞ (0x8D)  upper-right + lower-left quarter — gives a sub-cell `/` slope
//             that bridges the 2-col step between consecutive rows so the
//             diagonal reads as a smooth slope rather than a staircase.
//   █ (0x80)  solid bright orange — the front face of the diagonal "ribbon".
//   ▓ (0x83)  75% halftone — the shadow trail falling off to the right,
//             same trick as in the bar shadow rows.
//
// Top/bottom bar shadow rows shift right by one cell relative to the bar so
// they read as a drop shadow cast onto the ground by light from the upper-
// left, not just a uniform fade-off.
const FB: [1]u8 = .{0x80}; // █ full block
const HT: [1]u8 = .{0x83}; // ▓ 75% halftone
const QR: [1]u8 = .{0x8D}; // ▞ UR+LL quarter — `/` sub-cell slope
const SP: [1]u8 = .{' '};
const ESC_BRIGHT = [_]u8{ 0x1b, '[', '3', '8', ';', '2', ';', '2', '4', '7', ';', '1', '6', '4', ';', '2', '9', 'm' };
const ESC_RESET = [_]u8{ 0x1b, '[', '0', 'm' };

// Bars: 11 full blocks at cols 1..11.
const ROW_BAR_SOLID  = SP ++ ESC_BRIGHT ++ FB ** 11 ++ ESC_RESET ++ SP;
// Shadow rows: same 11 cells but shifted 1 col right — drop-shadow offset.
const ROW_BAR_SHADOW = SP ** 2 ++ ESC_BRIGHT ++ HT ** 11 ++ ESC_RESET;
// Diagonal motif `▞██▓` (4 cells): slope-in, mass, mass, halftone trail.
// Repeats 4 times, each row shifted 2 cols left. The motif spans cols A..A+3.
const ROW_D_8 = SP ** 8 ++ ESC_BRIGHT ++ QR ++ FB ** 2 ++ HT ++ ESC_RESET ++ SP;
const ROW_D_6 = SP ** 6 ++ ESC_BRIGHT ++ QR ++ FB ** 2 ++ HT ++ ESC_RESET ++ SP ** 3;
const ROW_D_4 = SP ** 4 ++ ESC_BRIGHT ++ QR ++ FB ** 2 ++ HT ++ ESC_RESET ++ SP ** 5;
const ROW_D_2 = SP ** 2 ++ ESC_BRIGHT ++ QR ++ FB ** 2 ++ HT ++ ESC_RESET ++ SP ** 7;

const LOGO_LINES = [_][]const u8{
    &ROW_BAR_SOLID,   // top bar — solid
    &ROW_BAR_SOLID,   // top bar — solid
    &ROW_BAR_SHADOW,  // top bar — drop shadow
    &ROW_D_8,         // diagonal motif at cols 8..11
    &ROW_D_6,         // diagonal motif at cols 6..9
    &ROW_D_4,         // diagonal motif at cols 4..7
    &ROW_D_2,         // diagonal motif at cols 2..5
    &ROW_BAR_SOLID,   // bottom bar — solid
    &ROW_BAR_SOLID,   // bottom bar — solid
    &ROW_BAR_SHADOW,  // bottom bar — drop shadow
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

/// CPU base/max/bus frequency from CPUID leaf 0x16 (MHz). Null when the
/// leaf isn't supported (pre-Skylake or AMD); Kaby Lake and newer carry it.
fn cpuFreqMHz() ?struct { base: u32, max: u32, bus: u32 } {
    const max_leaf = cpuid(0, 0).eax;
    if (max_leaf < 0x16) return null;
    const r = cpuid(0x16, 0);
    if (r.eax == 0 and r.ebx == 0) return null;
    return .{
        .base = r.eax & 0xFFFF,
        .max = r.ebx & 0xFFFF,
        .bus = r.ecx & 0xFFFF,
    };
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

/// On-screen column count, skipping ANSI CSI sequences (ESC [ ... <final>).
/// The memory line embeds ~90 bytes of escapes for its colored bar but only
/// renders as ~40 visible chars; using raw byte length to size the separator
/// would draw a comically wide rule.
fn visibleLen(s: []const u8) u32 {
    var n: u32 = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == 0x1b) {
            i += 1;
            if (i < s.len and s[i] == '[') i += 1;
            // CSI runs until a "final byte" in 0x40..0x7E (we only emit 'm').
            while (i < s.len) {
                const c = s[i];
                i += 1;
                if (c >= 0x40 and c <= 0x7E) break;
            }
            continue;
        }
        n += 1;
        i += 1;
    }
    return n;
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

/// Parse 16 ASCII hex chars as a big-endian u64. Returns null on bad chars.
/// /BUILD.ID happens to be a Unix epoch packed as hex (build-timestamp), so
/// we re-use this to derive the build date for fastfetch's Kernel line.
fn parseHex64(s: []const u8) ?u64 {
    if (s.len < 16) return null;
    var v: u64 = 0;
    for (s[0..16]) |c| {
        const d: u4 = switch (c) {
            '0'...'9' => @intCast(c - '0'),
            'a'...'f' => @intCast(c - 'a' + 10),
            'A'...'F' => @intCast(c - 'A' + 10),
            else => return null,
        };
        v = (v << 4) | d;
    }
    return v;
}

/// Convert a Unix timestamp into (year, month, day). Howard Hinnant's
/// civil_from_days algorithm — branch-free, integer-only, valid for
/// 0001-01-01 through 9999-12-31. No leap-second handling; we just want
/// "what date was this image built" so seconds-precision is overkill.
fn ymdFromUnix(secs: u64) struct { y: u32, m: u32, d: u32 } {
    const days_total: i64 = @intCast(secs / 86400);
    const z = days_total + 719468;
    const era: i64 = @divTrunc(if (z >= 0) z else z - 146096, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe: u64 = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u64 = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp: u64 = (5 * doy + 2) / 153;
    const d: u64 = doy - (153 * mp + 2) / 5 + 1;
    const m: u64 = if (mp < 10) mp + 3 else mp - 9;
    const year: u32 = @intCast(if (m <= 2) y + 1 else y);
    return .{ .y = year, .m = @intCast(m), .d = @intCast(d) };
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
        // The build_id IS the Unix epoch of the build; format as ISO date
        // so users can read "when did I compile this" at a glance.
        if (parseHex64(bid)) |epoch| {
            const ymd = ymdFromUnix(epoch);
            append(buf, &p, " (");
            appendU32(buf, &p, ymd.y);
            append(buf, &p, "-");
            if (ymd.m < 10) append(buf, &p, "0");
            appendU32(buf, &p, ymd.m);
            append(buf, &p, "-");
            if (ymd.d < 10) append(buf, &p, "0");
            appendU32(buf, &p, ymd.d);
            append(buf, &p, ")");
        }
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

/// Strip the corporate noise from a CPUID brand string. `Intel(R) Core(TM)
/// i7-7700 CPU @ 3.60GHz` becomes `Intel Core i7-7700 @ 3.60GHz` — same
/// information, ~20 fewer chars, stops the line from getting clipped under
/// narrow terminals. AMD/other strings pass through untouched.
fn trimCpuBrand(brand: []const u8, out: []u8) []const u8 {
    var p: usize = 0;
    var i: usize = 0;
    while (i < brand.len) {
        if (i + 3 <= brand.len and brand[i] == '(' and brand[i + 1] == 'R' and brand[i + 2] == ')') {
            i += 3;
            continue;
        }
        if (i + 4 <= brand.len and brand[i] == '(' and brand[i + 1] == 'T' and brand[i + 2] == 'M' and brand[i + 3] == ')') {
            i += 4;
            continue;
        }
        // " CPU @" → " @" — the freq tail already implies "CPU".
        if (i + 6 <= brand.len and
            brand[i] == ' ' and brand[i + 1] == 'C' and brand[i + 2] == 'P' and brand[i + 3] == 'U' and brand[i + 4] == ' ' and brand[i + 5] == '@')
        {
            i += 4; // skip " CPU", keep " @"
            continue;
        }
        // Collapse runs of internal whitespace to a single space.
        if (brand[i] == ' ' and p > 0 and out[p - 1] == ' ') {
            i += 1;
            continue;
        }
        if (p < out.len) {
            out[p] = brand[i];
            p += 1;
        }
        i += 1;
    }
    while (p > 0 and out[p - 1] == ' ') p -= 1;
    return out[0..p];
}

fn lineCpu(buf: []u8) []const u8 {
    var brand_buf: [48]u8 = undefined;
    const brand_raw = cpuBrand(&brand_buf);
    var trimmed_buf: [48]u8 = undefined;
    const brand = trimCpuBrand(brand_raw, &trimmed_buf);
    const log = cpuLogicalCount();
    const ht = cpuHasHT();
    // HT implies 2 threads per physical core for Intel client chips (this
    // doesn't hold for SMT4/8 on POWER/zSeries, but those don't run here).
    const phys: u8 = if (ht and log > 1) log / 2 else log;
    var p: usize = 0;
    append(buf, &p, brand);
    append(buf, &p, " (");
    appendU32(buf, &p, phys);
    append(buf, &p, "C/");
    appendU32(buf, &p, log);
    append(buf, &p, "T");
    if (cpuFreqMHz()) |f| {
        // Only print turbo if it's actually higher than base; some CPUs
        // report identical values and the redundant line is noise.
        if (f.max > f.base and f.max > 0) {
            append(buf, &p, ", turbo ");
            appendU32(buf, &p, f.max / 1000);
            append(buf, &p, ".");
            appendU32(buf, &p, (f.max % 1000) / 100);
            append(buf, &p, " GHz");
        }
    }
    append(buf, &p, ")");
    return buf[0..p];
}

/// Render a 24-bit RGB block (one space rendered as a colored cell).
///
/// The terminal SGR parser handles `38;2;R;G;B` (truecolor fg) and `7`
/// (inverse) but not `48;2;...` (truecolor bg) — so we set fg=color +
/// inverse=on, which swaps fg/bg per cell, yielding a colored bg under
/// the space. The caller emits the inverse-toggle once and just changes
/// fg between segments to avoid repeating it.
fn appendRgbFg(buf: []u8, p: *usize, r: u32, g: u32, b: u32) void {
    append(buf, p, "\x1b[38;2;");
    appendU32(buf, p, r);
    append(buf, p, ";");
    appendU32(buf, p, g);
    append(buf, p, ";");
    appendU32(buf, p, b);
    append(buf, p, "m");
}

const BAR_WIDTH: u32 = 20;

fn lineMemory(buf: []u8) []const u8 {
    const mi = libc.meminfo();
    // 4 KB per frame → MB = frames * 4 / 1024 = frames / 256.
    const total_mb = mi.total_frames / 256;
    const used_mb = (if (mi.total_frames > mi.free_frames) mi.total_frames - mi.free_frames else 0) / 256;
    const pct: u32 = if (mi.total_frames > 0) used_mb * 100 / total_mb else 0;

    // Bar color picks a band by usage: green < 60% < yellow < 85% < red.
    // Values chosen to match the rest of the truecolor palette (slightly
    // muted so it doesn't fight the Zig orange logo).
    var fr: u32 = 95;
    var fg_: u32 = 184;
    var fb: u32 = 95;
    if (pct >= 85) {
        fr = 229; fg_ = 72; fb = 77;   // red
    } else if (pct >= 60) {
        fr = 245; fg_ = 200; fb = 66;  // yellow
    }
    // Empty cells render dim gray so the bar's full width is always visible.
    const er: u32 = 50;
    const eg: u32 = 50;
    const eb: u32 = 50;

    const filled: u32 = blk: {
        if (pct >= 100) break :blk BAR_WIDTH;
        const raw = (pct * BAR_WIDTH) / 100;
        // <5% rounds to 0 cells in a 20-wide bar — force min-1 so the band
        // is always visible. Distinguishes "tiny usage" from "uninitialised".
        if (pct > 0 and raw == 0) break :blk 1;
        break :blk raw;
    };

    var p: usize = 0;
    append(buf, &p, "[");
    append(buf, &p, "\x1b[7m"); // inverse on — turns truecolor fg into bg
    appendRgbFg(buf, &p, fr, fg_, fb);
    var i: u32 = 0;
    while (i < filled) : (i += 1) append(buf, &p, " ");
    appendRgbFg(buf, &p, er, eg, eb);
    while (i < BAR_WIDTH) : (i += 1) append(buf, &p, " ");
    append(buf, &p, "\x1b[0m]");
    append(buf, &p, " ");
    appendU32(buf, &p, used_mb);
    append(buf, &p, "/");
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

/// GPU summary — derived from `gpuGetCapsetInfo` probes. Capset id 1 =
/// VirGL classic, 2 = VirGL v2, 4 = Venus (Vulkan-over-virtio). If any
/// probe succeeds we know the virtio-gpu driver is up; otherwise no GPU
/// accel is wired (CPU compositor only).
fn lineGpu(buf: []u8) []const u8 {
    var p: usize = 0;
    var caps: [3]u32 = undefined;
    var found: bool = false;
    var has_virgl: bool = false;
    var has_venus: bool = false;
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        if (libc.gpuGetCapsetInfo(i, &caps)) {
            found = true;
            if (caps[0] == 1 or caps[0] == 2) has_virgl = true;
            if (caps[0] == 4) has_venus = true;
        }
    }
    if (!found) {
        append(buf, &p, "(no accelerator — CPU compositor)");
        return buf[0..p];
    }
    append(buf, &p, "virtio-gpu");
    if (has_virgl or has_venus) {
        append(buf, &p, " (");
        if (has_virgl) append(buf, &p, "VirGL");
        if (has_virgl and has_venus) append(buf, &p, " + ");
        if (has_venus) append(buf, &p, "Venus");
        append(buf, &p, ")");
    }
    return buf[0..p];
}

/// Shell = our parent process's name. Walk processList: find self, then
/// look up parent_pid. Falls back to "(detached)" if no parent slot is
/// found (init, or fastfetch invoked via a stale pid).
fn lineShell(buf: []u8) []const u8 {
    var p: usize = 0;
    var procs: [32]libc.ProcInfo = undefined;
    const n = libc.processList(&procs);
    const my_pid: u8 = @intCast(libc.getpid());
    var ppid: u8 = 0xFF;
    for (procs[0..n]) |pr| {
        if (pr.pid == my_pid) {
            ppid = pr.parent_pid;
            break;
        }
    }
    if (ppid == 0xFF) {
        append(buf, &p, "(detached)");
        return buf[0..p];
    }
    for (procs[0..n]) |pr| {
        if (pr.pid == ppid) {
            const name = pr.name[0..pr.name_len];
            append(buf, &p, name);
            return buf[0..p];
        }
    }
    append(buf, &p, "pid ");
    appendU32(buf, &p, ppid);
    return buf[0..p];
}

/// Theme = current /etc/zigos.conf `theme=` value, mapped to Light/Dark.
/// Falls back to "(default)" when the config doesn't exist or omits
/// the key — same neutral phrasing the Settings app uses pre-Apply.
fn lineTheme(buf: []u8) []const u8 {
    var p: usize = 0;
    var cfg: [1024]u8 = undefined;
    const fd_opt = libc.open("/etc/zigos.conf");
    if (fd_opt == null) {
        append(buf, &p, "(default)");
        return buf[0..p];
    }
    const fd = fd_opt.?;
    defer libc.close(fd);
    const got = libc.fread(fd, &cfg);
    if (got == 0 or got == 0xFFFFFFFF) {
        append(buf, &p, "(default)");
        return buf[0..p];
    }
    const text = cfg[0..@min(got, cfg.len)];
    // Find a "theme=" line.
    var i: usize = 0;
    while (i + 6 <= text.len) {
        const at_line_start = i == 0 or text[i - 1] == '\n';
        if (at_line_start and text[i] == 't' and text[i + 1] == 'h' and
            text[i + 2] == 'e' and text[i + 3] == 'm' and text[i + 4] == 'e' and
            text[i + 5] == '=') {
            const v = text[i + 6];
            if (v == '0') append(buf, &p, "Light");
            if (v == '1') append(buf, &p, "Dark");
            if (v != '0' and v != '1') append(buf, &p, "(unknown)");
            return buf[0..p];
        }
        i += 1;
    }
    append(buf, &p, "(default)");
    return buf[0..p];
}

/// Network — derived from the same hypervisor signature `lineHost` uses.
/// QEMU's user-mode networking gives us 10.0.2.0/24 (guest) and the host
/// at 10.0.2.2 — there's no DHCP introspection syscall yet, so we report
/// the static convention. Bare metal stays "unknown" until we wire a DHCP
/// status read.
/// Count consecutive leading 1-bits in a 4-byte subnet mask, MSB-first.
/// 255.255.255.0 → 24. Returns 0 on a non-contiguous mask (shouldn't
/// happen in IPv4 in practice, but we don't validate — just count).
fn maskToPrefix(mask: [4]u8) u8 {
    var bits: u8 = 0;
    for (mask) |b| {
        var bit: u8 = 0x80;
        while (bit != 0) : (bit >>= 1) {
            if (b & bit != 0) bits += 1 else return bits;
        }
    }
    return bits;
}

/// Append a short human-readable duration ("24h", "30m", "45s") for a
/// lease time. Avoid floats — integer arithmetic only.
fn appendDuration(buf: []u8, p: *usize, secs: u32) void {
    if (secs == 0) { append(buf, p, "?"); return; }
    if (secs >= 86400) { appendU32(buf, p, secs / 86400); append(buf, p, "d"); return; }
    if (secs >= 3600)  { appendU32(buf, p, secs / 3600);  append(buf, p, "h"); return; }
    if (secs >= 60)    { appendU32(buf, p, secs / 60);    append(buf, p, "m"); return; }
    appendU32(buf, p, secs);
    append(buf, p, "s");
}

fn appendIp(buf: []u8, p: *usize, ip: [4]u8) void {
    appendU32(buf, p, ip[0]); append(buf, p, ".");
    appendU32(buf, p, ip[1]); append(buf, p, ".");
    appendU32(buf, p, ip[2]); append(buf, p, ".");
    appendU32(buf, p, ip[3]);
}

fn lineNetwork(buf: []u8) []const u8 {
    var p: usize = 0;
    var info: libc.NetInfo = undefined;
    if (libc.netInfo(&info) != 0 or info.nic_present == 0) {
        append(buf, &p, "\x1b[2m(no NIC)\x1b[0m");
        return buf[0..p];
    }
    appendIp(buf, &p, info.local_ip);
    append(buf, &p, "/");
    appendU32(buf, &p, maskToPrefix(info.subnet_mask));
    append(buf, &p, " via ");
    appendIp(buf, &p, info.gateway_ip);
    append(buf, &p, " \x1b[2m[");
    if (info.dhcp_configured != 0) {
        append(buf, &p, "DHCP, ");
        appendDuration(buf, &p, info.dhcp_lease_secs);
    } else {
        append(buf, &p, "static");
    }
    append(buf, &p, "]\x1b[0m");
    return buf[0..p];
}

/// Second network row — DNS + MAC. Pulled out of lineNetwork because the
/// primary line is already at the edge of pleasant width on the IP+gateway
/// pair, and these two fields are most useful as a follow-up sanity check
/// (DNS is what `nslookup` will use; MAC is what shows up in `arp -a`).
fn lineDns(buf: []u8) []const u8 {
    var p: usize = 0;
    var info: libc.NetInfo = undefined;
    if (libc.netInfo(&info) != 0 or info.nic_present == 0) {
        return buf[0..0];
    }
    appendIp(buf, &p, info.dns_ip);
    append(buf, &p, "  \x1b[2mMAC\x1b[0m ");
    const hex = "0123456789abcdef";
    for (info.mac, 0..) |b, i| {
        if (i > 0) append(buf, &p, ":");
        buf[p] = hex[b >> 4]; p += 1;
        buf[p] = hex[b & 0x0F]; p += 1;
    }
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

/// Width of the key column (left-padded to this many chars). Picked to
/// fit the longest current key — "Processes" at 9 chars — with a single
/// trailing space before the vertical separator. Bump if a new label
/// stretches past it.
const KEY_COL: u32 = 10;
const KEY_PAD: []const u8 = "          "; // KEY_COL spaces
comptime {
    if (KEY_PAD.len != KEY_COL) @compileError("KEY_PAD length must match KEY_COL");
}

fn printInfoLine(key: []const u8, value: []const u8) void {
    libc.print(C_KEY);
    libc.print(key);
    // Right-pad the key out to KEY_COL chars so values align across rows.
    if (key.len < KEY_COL) libc.print(KEY_PAD[key.len..KEY_COL]);
    libc.print(C_SEP);
    libc.print(" | ");
    libc.print(C_VAL);
    libc.print(value);
    libc.print(ANSI_RESET);
}

/// One row of fastfetch = logo line N, two spaces, key | value (or empty).
fn row(logo_idx: usize, key: []const u8, value: []const u8) void {
    printLogoLine(logo_idx);
    libc.print("  ");
    if (key.len > 0) printInfoLine(key, value);
    libc.printChar('\n');
}

/// Header separator length = KEY_COL + " | " (3) + N dashes, where N
/// matches the longest value width we've actually printed in this run.
/// Caller passes the longest value seen so the rule sits flush with the
/// content beneath it — no hardcoded length.
fn printSeparator(longest_value: u32) void {
    libc.print(C_SEP);
    var n: u32 = 0;
    const total = KEY_COL + 3 + longest_value;
    while (n < total) : (n += 1) libc.printChar('-');
    libc.print(ANSI_RESET);
}

/// Color-swatch row at the bottom — the classic neofetch flourish. Pad of
/// LOGO_WIDTH + 2 (separator) so swatches align under the info column.
const COLOR_ROW_PAD: []const u8 = "               "; // LOGO_WIDTH + 2 = 15
comptime {
    if (COLOR_ROW_PAD.len != LOGO_WIDTH + 2) @compileError("COLOR_ROW_PAD length must be LOGO_WIDTH + 2");
}

/// 16-step Zig-orange-themed truecolor gradient. The legacy 0-15 ANSI
/// background swatches the original colorRow emitted didn't render at
/// all — the terminal's SGR parser doesn't handle `40..47`/`100..107` —
/// so we replace them with one row of truecolor swatches that actually
/// demonstrates 24-bit support. Inverse mode turns fg color into bg.
fn colorRow() void {
    libc.print(COLOR_ROW_PAD);
    libc.print("\x1b[7m");
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        // Gradient: dark (#3D2806) → Zig orange (#F7A41D) → cream (#FFE5B0).
        // Two halves linearly interpolated, 8 steps each.
        var r: u32 = undefined;
        var g: u32 = undefined;
        var b: u32 = undefined;
        if (i < 8) {
            r = 0x3D + ((0xF7 - 0x3D) * i) / 7;
            g = 0x28 + ((0xA4 - 0x28) * i) / 7;
            b = 0x06 + ((0x1D - 0x06) * i) / 7;
        } else {
            const j = i - 8;
            r = 0xF7 + ((0xFF - 0xF7) * j) / 7;
            g = 0xA4 + ((0xE5 - 0xA4) * j) / 7;
            b = 0x1D + ((0xB0 - 0x1D) * j) / 7;
        }
        var esc: [32]u8 = undefined;
        var p: usize = 0;
        appendRgbFg(&esc, &p, r, g, b);
        append(&esc, &p, "   "); // 3-cell-wide swatch per step → 48 wide
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
    var buf_shell: [32]u8 = undefined;
    var buf_cpu: [128]u8 = undefined;
    var buf_gpu: [80]u8 = undefined;
    // Memory line carries a 20-cell colored bar made of inverse-mode
    // truecolor escapes — needs ~90 bytes for the bar alone plus label.
    var buf_mem: [256]u8 = undefined;
    var buf_theme: [24]u8 = undefined;
    var buf_net: [96]u8 = undefined;
    var buf_net2: [80]u8 = undefined;
    var buf_proc: [80]u8 = undefined;
    var buf_scr: [40]u8 = undefined;
    var buf_comp: [40]u8 = undefined;

    // Build everything up-front so we can compute the separator length
    // from the widest value before any printing. Two-pass approach beats
    // a hardcoded 43-dash rule.
    const v_os = lineOs(&buf_os);
    const v_host = lineHost(&buf_host);
    const v_kern = lineKernel(&buf_kern);
    const v_up = lineUptime(&buf_up);
    const v_shell = lineShell(&buf_shell);
    const v_cpu = lineCpu(&buf_cpu);
    const v_gpu = lineGpu(&buf_gpu);
    const v_mem = lineMemory(&buf_mem);
    const v_theme = lineTheme(&buf_theme);
    const v_net = lineNetwork(&buf_net);
    const v_dns = lineDns(&buf_net2);
    const v_proc = lineProcs(&buf_proc);
    const v_scr = lineScreen(&buf_scr);
    const v_comp = lineCompiler(&buf_comp);

    var header_buf: [64]u8 = undefined;
    var hp: usize = 0;
    append(&header_buf, &hp, "PID ");
    appendU32(&header_buf, &hp, libc.getpid());
    append(&header_buf, &hp, " @ zigos");
    const v_header = header_buf[0..hp];

    var longest: u32 = 0;
    inline for ([_][]const u8{ v_os, v_host, v_kern, v_up, v_shell, v_cpu, v_gpu, v_mem, v_theme, v_net, v_dns, v_proc, v_scr, v_comp, v_header }) |s| {
        const w = visibleLen(s);
        if (w > longest) longest = w;
    }

    // Header (logo row 0).
    row(0, "user", v_header);

    // Separator (logo row 1) — width derived from the longest value.
    printLogoLine(1);
    libc.print("  ");
    printSeparator(longest);
    libc.printChar('\n');

    row(2, "OS",     v_os);
    row(3, "Host",   v_host);
    row(4, "Kernel", v_kern);
    row(5, "Uptime", v_up);
    row(6, "Shell",  v_shell);
    row(7, "CPU",    v_cpu);
    row(8, "GPU",    v_gpu);
    row(9, "Memory", v_mem);

    // Lines beyond the logo height get printed with empty logo column
    // (idx >= LOGO_LINES.len triggers LOGO_PAD in printLogoLine).
    row(LOGO_LINES.len, "Theme",     v_theme);
    row(LOGO_LINES.len, "Network",   v_net);
    if (v_dns.len > 0) row(LOGO_LINES.len, "DNS",      v_dns);
    row(LOGO_LINES.len, "Processes", v_proc);
    row(LOGO_LINES.len, "Screen",    v_scr);
    row(LOGO_LINES.len, "Compiler",  v_comp);

    libc.printChar('\n');
    colorRow();
    libc.printChar('\n');

    libc.exit();
}
