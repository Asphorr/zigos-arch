// ZigOS UEFI boot menu — drawn directly to GOP framebuffer.
// Pure UEFI (boot services + GraphicsOutput + SimpleTextInput); no kernel
// dependencies. Returns the selected entry index after Enter/timeout/Esc.

const std = @import("std");
const uefi = std.os.uefi;
const GraphicsOutput = uefi.protocol.GraphicsOutput;
const SimpleTextInput = uefi.protocol.SimpleTextInput;
const BootServices = uefi.tables.BootServices;
const RuntimeServices = uefi.tables.RuntimeServices;
const aa = @import("aa_font");
const layout = @import("layout.zig");
const nvram = @import("nvram.zig");
const cmdline_editor = @import("cmdline_editor.zig");

// Layout-math constant: cell height we use for vertical positioning. With the
// AA atlas this no longer corresponds to a "char_h" — pick the 16-px body
// atlas's line_height as the de-facto row height and the 24-px display atlas's
// `size_px` for the scaled splash logo. Concrete values drop in once
// `aa.ensureLoaded()` has parsed the blobs at the start of `show()`.
//
// For the giant ZIGOS logo we pixel-double via `aa.drawTextScaled` so it
// keeps the same imposing ~96 px cap-height of the bitmap-scaled original.
const LOGO_BASE_H: u32 = 24; // default_24.size_px — matches our blob

// Color words for OVMF's BGRA / "blue_green_red_reserved" pixel format.
// Bytes [B,G,R,A] little-endian → u32 0x00RRGGBB. Reserved/alpha is don't-care.
const COLOR_BG: u32 = 0x00050811;
const COLOR_PANEL: u32 = 0x00121A2C;
const COLOR_BORDER_OUT: u32 = 0x00304566;
const COLOR_BORDER_IN: u32 = 0x001A2238;
const COLOR_TITLE: u32 = 0x008FA8C8;
const COLOR_TEXT: u32 = 0x00D8DEEC;
const COLOR_DIM: u32 = 0x006A788C;
const COLOR_SEL_BG: u32 = 0x002A55C8;
const COLOR_SEL_BORDER: u32 = 0x004D7AE6;
const COLOR_SEL_TEXT: u32 = 0x00FFFFFF;
const COLOR_SEL_DESC: u32 = 0x00C8D6F0;
const COLOR_ACCENT: u32 = 0x0050A8FF;
const COLOR_LOGO: u32 = 0x00E8EEFA;
const COLOR_LOGO_SHADOW: u32 = 0x001E2E60;
const COLOR_SHADOW: u32 = 0x00010204;
const COLOR_PULSE: u32 = 0x00E84030; // red — countdown final 3s
const COLOR_BADGE_NORMAL: u32 = 0x0034C870;
const COLOR_BADGE_VERBOSE: u32 = 0x00E8B83A;
const COLOR_BADGE_SAFE: u32 = 0x00E87C3A;
const COLOR_BADGE_INFO: u32 = 0x009085A8;
const COLOR_BADGE_STRESS: u32 = 0x00C04AE8; // purple — diagnostic / non-default
const COLOR_BADGE_GPU: u32 = 0x0020D0E0; // teal — experimental / GPU compositor
const COLOR_BADGE_TEXT: u32 = 0x00081020;

pub const Entry = struct {
    label: []const u8,
    desc: []const u8,
    boot_mode: u32,
    badge: []const u8,
    badge_color: u32,
};

// Sentinel boot_mode values used for menu navigation only — never returned
// to the bootloader. 0xFD = "back to main"; 0xFE = "open Tests submenu";
// 0xFF = "show About screen, stay in menu". Real boot_modes are 0..127.
const BOOT_MODE_BACK: u32 = 0xFD;
const BOOT_MODE_TESTS: u32 = 0xFE;
const BOOT_MODE_ABOUT: u32 = 0xFF;

pub const ENTRIES = [_]Entry{
    .{ .label = "ZigOS - Normal", .desc = "Default boot. Full hardware, all drivers, SMP.", .boot_mode = 0, .badge = "NORMAL", .badge_color = COLOR_BADGE_NORMAL },
    .{ .label = "ZigOS - Verbose klog", .desc = "Same as Normal plus verbose serial logging.", .boot_mode = 1, .badge = "VERBOSE", .badge_color = COLOR_BADGE_VERBOSE },
    .{ .label = "ZigOS - Safe (no SMP, polled IO)", .desc = "Single CPU, polled drivers. Recovery mode.", .boot_mode = 2, .badge = "SAFE", .badge_color = COLOR_BADGE_SAFE },
    .{ .label = "ZigOS - GPU Compositor (experimental)", .desc = "Vulkan/Lavapipe-driven compositor. Step 1 stub: paints solid teal and parks. Pick Normal for daily use.", .boot_mode = 9, .badge = "GPU", .badge_color = COLOR_BADGE_GPU },
    .{ .label = "Tests >", .desc = "Stress harnesses for hunting race + UAF bugs.", .boot_mode = BOOT_MODE_TESTS, .badge = "TESTS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "About this build", .desc = "Show kernel info, then return.", .boot_mode = BOOT_MODE_ABOUT, .badge = "INFO", .badge_color = COLOR_BADGE_INFO },
};

// Submenu — opened via the "Tests >" entry. Each test replaces the desktop
// kernel task in src/main.zig's boot_mode dispatch. Boot-modes here MUST be
// disjoint from main-menu boot-modes and the sentinels above.
pub const TEST_ENTRIES = [_]Entry{
    .{ .label = "Stress: kstack churn", .desc = "Spawn/exit/reap kernel tasks in a tight loop. Hunts task #267 family (kstack UAF, rsp0 alias).", .boot_mode = 3, .badge = "STRESS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "Stress: iretq race", .desc = "Ring-3 spinners + kernel-task churn. Hunts cross-CPU iretq frame race (paint-click cascade).", .boot_mode = 4, .badge = "STRESS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "Stress: Phase 3 cleanup", .desc = "Spawn/kill/reap user processes. Hunts phys-vs-physmap-VA confusion in destroyAddressSpace, freeElfBuf, lazy_regions cleanup.", .boot_mode = 5, .badge = "STRESS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "Stress: kill race", .desc = "Spawn kernel worker on cpu1, kill from cpu0. Hunts setTssRsp0 mismatch (scheduler picks pid mid-kill, expected_kstack_tops cleared between pickNext and dispatch).", .boot_mode = 6, .badge = "STRESS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "Stress: async exec race", .desc = "Async requestAppLoad spawn-kill churn. Hunts wild kernel RIP=0x46 at switchTo+0x0 — fired when files.elf launched editor.elf with rapid task migration cpu0->cpu1->cpu0.", .boot_mode = 8, .badge = "STRESS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "Stress: wake-IPI", .desc = "Cross-CPU wake latency: cpu0 driver wakes a cpu1 worker N times, histograms latency. Hunts the bug where setState(.ready) on a remote CPU's PCB doesn't IPI it out of idle.", .boot_mode = 10, .badge = "STRESS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "Stress: I/O chain", .desc = "Concurrent NVMe loadFileFresh from N workers + virtio-gpu flushRect on main. Hunts the 2026-05-19 cpu1-wedge / watchdog trip — determines code-bug vs host-SMI.", .boot_mode = 11, .badge = "STRESS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "Stress: PMM heavy", .desc = "14-phase PMM stress: single/contig churn, cross-region big allocs, fragmentation+coalesce, run pool exhaustion, UAF canary, SMP concurrent. Validates the 2026-05-24 region-bucketed rewrite. Output in serial.log.", .boot_mode = 12, .badge = "STRESS", .badge_color = COLOR_BADGE_STRESS },
    .{ .label = "Test: panic UI", .desc = "Trigger a controlled @panic after boot to render the panic screen for visual review. Switch trigger kind (PF / UD / panic) by editing src/test/panic_test.zig.", .boot_mode = 7, .badge = "DEMO", .badge_color = COLOR_BADGE_INFO },
    .{ .label = "< Back", .desc = "Return to the main boot menu.", .boot_mode = BOOT_MODE_BACK, .badge = "BACK", .badge_color = COLOR_BADGE_INFO },
};

const TIMEOUT_SEC: u32 = 15;
const VERSION_STR: []const u8 = "v0.1";

const Fb = aa.Fb;

fn fillRect(fb: Fb, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    const x_end = @min(x + w, fb.w);
    const y_end = @min(y + h, fb.h);
    var yy: u32 = y;
    while (yy < y_end) : (yy += 1) {
        var xx: u32 = x;
        while (xx < x_end) : (xx += 1) {
            fb.base[yy * fb.stride + xx] = color;
        }
    }
}

fn hLine(fb: Fb, x: u32, y: u32, w: u32, color: u32) void {
    fillRect(fb, x, y, w, 1, color);
}

fn vLine(fb: Fb, x: u32, y: u32, h: u32, color: u32) void {
    fillRect(fb, x, y, 1, h, color);
}

fn drawBorder(fb: Fb, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    hLine(fb, x, y, w, color);
    hLine(fb, x, y + h - 1, w, color);
    vLine(fb, x, y, h, color);
    vLine(fb, x + w - 1, y, h, color);
}

// AA-font wrappers preserving the old (Fb, x, y, text, fg, bg?) signature.
// Body text uses `default_16`; the scaled logo path uses `default_24` then
// pixel-doubles to honour the caller's `scale`. `bg` of `null` means
// transparent (alpha-blend over current pixels); a concrete value first
// fills the measured rect with that bg, then renders glyphs on top.
fn drawText(fb: Fb, x: u32, y: u32, text: []const u8, fg: u32, bg: ?u32) void {
    if (bg) |b| {
        const tw = aa.default_16.measure(text);
        fillRect(fb, x, y, tw, aa.default_16.line_height, b);
    }
    aa.drawText(fb, @intCast(x), @intCast(y), text, fg, &aa.default_16);
}

fn textWidth(text: []const u8) u32 {
    return aa.default_16.measure(text);
}

fn drawTextScaled(fb: Fb, x: u32, y: u32, text: []const u8, scale: u32, fg: u32) void {
    aa.drawTextScaled(fb, @intCast(x), @intCast(y), text, fg, &aa.default_24, scale);
}

fn textWidthScaled(text: []const u8, scale: u32) u32 {
    return aa.default_24.measureScaled(text, scale);
}

fn confirmBoot(fb: Fb, st_in: *SimpleTextInput, boot_services: *BootServices, label: []const u8) bool {
    // Modal: "Booting: <label> — Esc cancels". Returns true on timeout, false on Esc.
    const ow: u32 = 540;
    const oh: u32 = 110;
    const ox = (fb.w - ow) / 2;
    const oy = (fb.h - oh) / 2;

    fillRect(fb, ox + 6, oy + 6, ow, oh, COLOR_SHADOW);
    fillRect(fb, ox, oy, ow, oh, COLOR_PANEL);
    drawBorder(fb, ox, oy, ow, oh, COLOR_ACCENT);
    drawBorder(fb, ox + 1, oy + 1, ow - 2, oh - 2, COLOR_BORDER_OUT);

    const head = "booting...";
    const hw = textWidth(head);
    drawText(fb, ox + (ow - hw) / 2, oy + 18, head, COLOR_TITLE, null);

    var buf: [96]u8 = undefined;
    var bi: usize = 0;
    for (label) |c| {
        buf[bi] = c;
        bi += 1;
    }
    const lblw = textWidth(buf[0..bi]);
    drawText(fb, ox + (ow - lblw) / 2, oy + 44, buf[0..bi], COLOR_TEXT, null);

    const cancel = "press [Esc] to cancel";
    const cw = textWidth(cancel);
    drawText(fb, ox + (ow - cw) / 2, oy + 78, cancel, COLOR_DIM, null);

    // Poll ~1.4s for Esc
    var ticks: u32 = 0;
    while (ticks < 28) : (ticks += 1) {
        if (st_in.readKeyStroke()) |key| {
            if (key.scan_code == 0x17) return false;
            // Any other key short-circuits the wait — proceed
            return true;
        } else |_| {}

        // Animated dot trail under the cancel hint. AA cancel line ends
        // ~oy+98 with line_height 20, so place the dot row at oy+102 to
        // keep a 4-px breathing room (was oy+96 → bitmap-tight overlap).
        const dot_y = oy + 102;
        const dot_x = ox + ow / 2 - 16;
        fillRect(fb, dot_x, dot_y, 32, 4, COLOR_PANEL);
        const dot_count: u32 = (ticks / 4) % 4 + 1;
        var di: u32 = 0;
        while (di < dot_count) : (di += 1) {
            fillRect(fb, dot_x + di * 8, dot_y, 4, 4, COLOR_ACCENT);
        }

        boot_services.stall(50_000) catch {};
    }
    return true;
}

fn drawTriangleRight(fb: Fb, x: u32, y: u32, size: u32, color: u32) void {
    // Right-pointing isoceles triangle, 'size' tall on each slope (so 2*size-1 rows total)
    var i: u32 = 0;
    while (i < size * 2 - 1) : (i += 1) {
        const len: u32 = if (i < size) i + 1 else size * 2 - 1 - i;
        fillRect(fb, x, y + i, len, 1, color);
    }
}

fn drawDottedRow(fb: Fb, x: u32, y: u32, count: u32, dot_size: u32, gap: u32, color: u32) void {
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        fillRect(fb, x + i * (dot_size + gap), y, dot_size, dot_size, color);
    }
}

fn u64Hex(buf: []u8, n: u64) []u8 {
    const hex = "0123456789ABCDEF";
    buf[0] = '0';
    buf[1] = 'x';
    var i: usize = 2;
    var started = false;
    var shift: u6 = 60;
    while (true) : (shift -= 4) {
        const nib: u4 = @truncate(n >> shift);
        if (nib != 0) started = true;
        if (started) {
            buf[i] = hex[nib];
            i += 1;
        }
        if (shift == 0) break;
    }
    if (!started) {
        buf[i] = '0';
        i += 1;
    }
    return buf[0..i];
}

fn u32ToStr(buf: []u8, n: u32) []u8 {
    if (n == 0) {
        buf[0] = '0';
        return buf[0..1];
    }
    var num = n;
    var digits: [16]u8 = undefined;
    var len: usize = 0;
    while (num > 0) : (num /= 10) {
        digits[len] = '0' + @as(u8, @intCast(num % 10));
        len += 1;
    }
    for (0..len) |i| buf[i] = digits[len - 1 - i];
    return buf[0..len];
}

// VStack-friendly variants of the old `drawLabeledHex/Dec`. Take a stack
// pointer instead of (fb, x, y) so the caller doesn't have to track a
// running `ly += lh` cursor — the kvRow helper auto-advances the stack by
// `atlas.line_height`.
fn aboutHex(stack: *layout.VStack, label: []const u8, value: u64) void {
    var buf: [20]u8 = undefined;
    const s = u64Hex(&buf, value);
    stack.kvRow(40, label, COLOR_DIM, 240, s, COLOR_TEXT, &aa.default_16);
}

fn aboutDec(stack: *layout.VStack, label: []const u8, value: u32) void {
    var buf: [16]u8 = undefined;
    const s = u32ToStr(&buf, value);
    stack.kvRow(40, label, COLOR_DIM, 240, s, COLOR_TEXT, &aa.default_16);
}

fn aboutText(stack: *layout.VStack, label: []const u8, value: []const u8) void {
    stack.kvRow(40, label, COLOR_DIM, 240, value, COLOR_TEXT, &aa.default_16);
}

// Per-entry rendering for the menu list. Selection bg + border, triangle
// cursor for the selected row, label + desc, right-aligned mode badge.
// Pulled out of the showImpl loop so the loop body becomes
// `for (entries, ...) { drawEntry(...); }`.
const ENTRY_H: u32 = 60;

fn drawEntry(fb: Fb, panel_x: u32, ey: u32, panel_w: u32, entry: Entry, is_sel: bool) void {
    if (is_sel) {
        fillRect(fb, panel_x + 24, ey, panel_w - 48, ENTRY_H - 8, COLOR_SEL_BG);
        drawBorder(fb, panel_x + 24, ey, panel_w - 48, ENTRY_H - 8, COLOR_SEL_BORDER);
        drawTriangleRight(fb, panel_x + 36, ey + 16, 7, COLOR_SEL_TEXT);
    }
    const text_color = if (is_sel) COLOR_SEL_TEXT else COLOR_TEXT;
    const desc_color = if (is_sel) COLOR_SEL_DESC else COLOR_DIM;
    aa.drawText(fb, @intCast(panel_x + 60), @intCast(ey + 10), entry.label, text_color, &aa.default_16);

    // Mode badge — right-aligned, vertically centered inside the 52 px
    // selection box. Computed BEFORE drawing the description so the
    // description can be truncated to whatever space remains.
    const badge_h: u32 = 22;
    const badge_w = aa.default_16.measure(entry.badge) + 12;
    const badge_x = panel_x + panel_w - 24 - badge_w - 8;
    const badge_y = ey + (ENTRY_H - 8 -| badge_h) / 2;

    // Description column: left of badge with a small gap. Truncate with
    // "..." if the full text doesn't fit. Without this, long descs
    // (e.g. the wake-IPI entry's ~180 chars) overflow past the badge and
    // out of the panel — see screenshot in feedback_desc_overflow.
    const desc_x = panel_x + 60;
    const desc_avail: u32 = if (badge_x > desc_x + 12) badge_x - desc_x - 12 else 0;
    const desc_full = entry.desc;
    if (aa.default_16.measure(desc_full) <= desc_avail) {
        aa.drawText(fb, @intCast(desc_x), @intCast(ey + 30), desc_full, desc_color, &aa.default_16);
    } else {
        const ell = "...";
        const ell_w = aa.default_16.measure(ell);
        const budget: u32 = if (desc_avail > ell_w) desc_avail - ell_w else 0;
        var end: usize = desc_full.len;
        while (end > 0) : (end -= 1) {
            if (aa.default_16.measure(desc_full[0..end]) <= budget) break;
        }
        aa.drawText(fb, @intCast(desc_x), @intCast(ey + 30), desc_full[0..end], desc_color, &aa.default_16);
        const drawn_w = aa.default_16.measure(desc_full[0..end]);
        aa.drawText(fb, @intCast(desc_x + drawn_w), @intCast(ey + 30), ell, desc_color, &aa.default_16);
    }

    var bs = layout.HStack.init(fb, badge_x, badge_y, badge_h);
    bs.badge(entry.badge, COLOR_BADGE_TEXT, entry.badge_color, &aa.default_16);
}

const KEYCAP_BG: u32 = 0x001E2740;

fn modeShortName(mode: u32) []const u8 {
    return switch (mode) {
        0 => "Normal",
        1 => "Verbose",
        2 => "Safe",
        3 => "stress kstack",
        4 => "stress iretq",
        5 => "stress phase3",
        6 => "stress kill",
        7 => "panic test",
        8 => "stress async-exec",
        10 => "stress wake-ipi",
        11 => "stress io-chain",
        else => "?",
    };
}

fn outcomeLabel(outcome: u8) []const u8 {
    return switch (outcome) {
        @intFromEnum(nvram.BootStatus.unknown) => "?",
        @intFromEnum(nvram.BootStatus.in_progress) => "IN-PROGRESS",
        @intFromEnum(nvram.BootStatus.success) => "OK",
        @intFromEnum(nvram.BootStatus.crashed) => "CRASHED",
        else => "?",
    };
}

fn outcomeColor(outcome: u8) u32 {
    return switch (outcome) {
        @intFromEnum(nvram.BootStatus.success) => COLOR_BADGE_NORMAL,
        @intFromEnum(nvram.BootStatus.in_progress) => COLOR_BADGE_VERBOSE,
        @intFromEnum(nvram.BootStatus.crashed) => COLOR_PULSE,
        else => COLOR_DIM,
    };
}

/// Render one boot-history entry into the About screen's history panel.
/// Layout: `Boot {N}: {mode}  →  STATUS    bl=hex  k=hex` plus an optional
/// indented `fp:` line for crashed entries. STATUS is colored by outcome.
/// The `*skew*` tag (red) flags entries where bootloader_build_id and
/// kernel_build_id disagree — i.e. somebody updated one half without the
/// other and they raced into the same boot.
fn drawHistoryRow(stack: *layout.VStack, position: u32, e: *const nvram.BootHistoryEntry) void {
    const row_y = stack.cursor();
    const x = stack.x;
    const line_h: u32 = aa.default_16.line_height;

    // Column 1 — "Boot N:"
    var num_buf: [16]u8 = undefined;
    var lbuf: [32]u8 = undefined;
    var li: usize = 0;
    for ("Boot ") |c| { lbuf[li] = c; li += 1; }
    const ns = u32ToStr(&num_buf, position + 1);
    for (ns) |c| { lbuf[li] = c; li += 1; }
    lbuf[li] = ':'; li += 1;
    aa.drawText(stack.fb, @intCast(x + 24), @intCast(row_y), lbuf[0..li], COLOR_DIM, &aa.default_16);

    // Column 2 — mode short name
    const mode_str = modeShortName(e.mode);
    aa.drawText(stack.fb, @intCast(x + 110), @intCast(row_y), mode_str, COLOR_TEXT, &aa.default_16);

    // Column 3 — outcome (colored)
    const out_str = outcomeLabel(e.outcome);
    aa.drawText(stack.fb, @intCast(x + 240), @intCast(row_y), out_str, outcomeColor(e.outcome), &aa.default_16);

    // Column 4 — bl + k build_ids (lower 32 bits each), with skew flag.
    var hex_buf: [12]u8 = undefined;
    const bl_low: u32 = @truncate(e.bootloader_build_id);
    const k_low: u32 = @truncate(e.kernel_build_id);
    {
        var t: usize = 0;
        for ("bl=") |c| { hex_buf[t] = c; t += 1; }
        formatHex32(&hex_buf, t, bl_low);
        aa.drawText(stack.fb, @intCast(x + 380), @intCast(row_y), hex_buf[0..11], COLOR_DIM, &aa.default_16);
    }
    {
        var t: usize = 0;
        for ("k=") |c| { hex_buf[t] = c; t += 1; }
        formatHex32(&hex_buf, t, k_low);
        aa.drawText(stack.fb, @intCast(x + 480), @intCast(row_y), hex_buf[0..10], COLOR_DIM, &aa.default_16);
    }
    if (e.kernel_build_id != 0 and e.bootloader_build_id != e.kernel_build_id) {
        aa.drawText(stack.fb, @intCast(x + 560), @intCast(row_y), "*skew*", COLOR_PULSE, &aa.default_16);
    }
    stack.gap(line_h);

    // Optional second line — crash fingerprint, indented.
    if (e.outcome == @intFromEnum(nvram.BootStatus.crashed) and e.crash_fp_len > 0) {
        const fp_y = stack.cursor();
        const n: usize = @min(@as(usize, e.crash_fp_len), nvram.HISTORY_FP_CAP);
        aa.drawText(stack.fb, @intCast(x + 110), @intCast(fp_y), "fp:", COLOR_DIM, &aa.default_16);
        aa.drawText(stack.fb, @intCast(x + 140), @intCast(fp_y), e.crash_fp[0..n], COLOR_TEXT, &aa.default_16);
        stack.gap(line_h);
    }
    stack.gap(2);
}

/// Format the lower 8 hex digits of `value` into `buf[start..start+8]`.
/// Caller is responsible for ensuring `buf.len >= start + 8`.
fn formatHex32(buf: []u8, start: usize, value: u32) void {
    const hex = "0123456789ABCDEF";
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const nib: u4 = @truncate(value >> @intCast((7 - i) * 4));
        buf[start + i] = hex[nib];
    }
}

fn drawAboutScreen(fb: Fb, gop: *GraphicsOutput, boot_history: ?*const nvram.BootHistoryRing) void {
    fillRect(fb, 0, 0, fb.w, fb.h, COLOR_BG);
    aa.ensureLoaded();

    // Header logo — pixel-doubled SF Pro Display 24 atlas, drawn with a
    // separate shadow pass at +3,+3. Logo lives outside the VStack since
    // the shadow + main are two stacked draws sharing the same y; flowing
    // them through a stack would advance the cursor twice.
    const logo_text = "ZIGOS";
    const logo_scale: u32 = 2;
    const logo_h: u32 = LOGO_BASE_H * logo_scale;
    const logo_w = textWidthScaled(logo_text, logo_scale);
    const logo_x = (fb.w - logo_w) / 2;
    const logo_y: u32 = 80;
    drawTextScaled(fb, logo_x + 3, logo_y + 3, logo_text, logo_scale, COLOR_LOGO_SHADOW);
    drawTextScaled(fb, logo_x, logo_y, logo_text, logo_scale, COLOR_LOGO);

    // Subtitle below logo — full-width VStack just for the centered subtitle.
    var hdr = layout.VStack.init(fb, 0, logo_y + logo_h + 16, fb.w);
    hdr.textCentered("UEFI bootloader / boot manager", COLOR_DIM, &aa.default_16);

    // Info panel — rendered as a chrome rectangle then a VStack inside it
    // for the header band (title + accent rule) and the labeled rows. Each
    // row is a two-text kvRow (label dim at +40, value bright at +240).
    const info_w: u32 = 600;
    const info_h: u32 = 320;
    const info_x = (fb.w - info_w) / 2;
    const info_y: u32 = logo_y + logo_h + 60;
    fillRect(fb, info_x, info_y, info_w, info_h, COLOR_PANEL);
    drawBorder(fb, info_x, info_y, info_w, info_h, COLOR_BORDER_OUT);
    drawBorder(fb, info_x + 1, info_y + 1, info_w - 2, info_h - 2, COLOR_BORDER_IN);

    var info = layout.VStack.init(fb, info_x, info_y, info_w);
    info.gap(16);
    info.textCentered("firmware info", COLOR_TITLE, &aa.default_16);
    info.gap(2);
    info.rule(60, COLOR_ACCENT);
    info.gap(20);

    const m = gop.mode;
    const i = m.info;
    aboutDec(&info, "GOP width:", i.horizontal_resolution);
    aboutDec(&info, "GOP height:", i.vertical_resolution);
    aboutDec(&info, "GOP stride:", i.pixels_per_scan_line);
    aboutHex(&info, "Framebuffer base:", m.frame_buffer_base);
    aboutHex(&info, "Framebuffer size:", m.frame_buffer_size);
    const fmt_label: []const u8 = switch (i.pixel_format) {
        .blue_green_red_reserved_8_bit_per_color => "BGRA 8888",
        .red_green_blue_reserved_8_bit_per_color => "RGBA 8888",
        else => "other",
    };
    aboutText(&info, "Pixel format:", fmt_label);
    aboutText(&info, "Built with:", "Zig 0.15.2 (freestanding x86_64)");
    aboutText(&info, "ESP path:", "/EFI/BOOT/BOOTX64.EFI");
    aboutText(&info, "Kernel image:", "/kernel.elf  (ELF64, x86_64)");

    // Boot-history panel — only drawn if the ring exists AND the screen has
    // room below the firmware-info panel for at least the title + 2 rows.
    // Displays the last `HISTORY_VIEW` entries oldest-first so the most
    // recent boot is at the bottom (matching how a terminal scroll feels).
    const HISTORY_VIEW: usize = 4;
    const hist_w: u32 = info_w;
    const hist_h: u32 = 220;
    const hist_y: u32 = info_y + info_h + 24;
    const have_room = (hist_y + hist_h + 24 + aa.default_16.line_height) < fb.h;
    if (boot_history) |ring| if (have_room and ring.next > 0) {
        const hist_x = (fb.w - hist_w) / 2;
        fillRect(fb, hist_x, hist_y, hist_w, hist_h, COLOR_PANEL);
        drawBorder(fb, hist_x, hist_y, hist_w, hist_h, COLOR_BORDER_OUT);
        drawBorder(fb, hist_x + 1, hist_y + 1, hist_w - 2, hist_h - 2, COLOR_BORDER_IN);

        var hist = layout.VStack.init(fb, hist_x, hist_y, hist_w);
        hist.gap(16);
        hist.textCentered("recent boots", COLOR_TITLE, &aa.default_16);
        hist.gap(2);
        hist.rule(60, COLOR_ACCENT);
        hist.gap(14);

        const total_visible: usize = @min(HISTORY_VIEW, @as(usize, ring.next));
        var k: usize = 0;
        while (k < total_visible) : (k += 1) {
            const slot: usize = @intCast((@as(u64, ring.next) -% (total_visible - k)) % nvram.HISTORY_DEPTH);
            drawHistoryRow(&hist, @intCast(k), &ring.entries[slot]);
        }
    };

    // Footer hint — anchored to whichever panel is the bottom-most.
    const hint_y: u32 = if (boot_history != null and have_room and (boot_history.?.next > 0))
        hist_y + hist_h + 24
    else
        info_y + info_h + 28;
    var foot = layout.VStack.init(fb, 0, hint_y, fb.w);
    foot.textCentered("press any key to return", COLOR_ACCENT, &aa.default_16);
}

/// Public entry — renders the main menu, recurses into the Tests submenu
/// when the user picks "Tests >", and returns a real `boot_mode` (never a
/// sentinel). `default_selection` is an INDEX into `ENTRIES`.
pub fn show(
    gop: *GraphicsOutput,
    st_in: *SimpleTextInput,
    boot_services: *BootServices,
    runtime_services: *RuntimeServices,
    default_selection: u32,
    last_crash_fp: []const u8,
    boot_history: ?*const nvram.BootHistoryRing,
) u32 {
    const mode = gop.mode;
    const info = mode.info;
    const fb = Fb{
        .base = @ptrFromInt(@as(usize, @intCast(mode.frame_buffer_base))),
        .stride = info.pixels_per_scan_line,
        .w = info.horizontal_resolution,
        .h = info.vertical_resolution,
    };

    // If firmware gave us a tiny mode, skip the menu (default-boot Normal).
    // Layout needs ~700px height for the logo+panel+footer not to underflow.
    if (fb.w < 1024 or fb.h < 700) return 0;

    // Parse the embedded SF Pro Text 16 + SF Pro Display 24 atlases. Cheap
    // (single bool check after first call); idempotent across recursion into
    // the Tests submenu.
    aa.ensureLoaded();

    var ds: u32 = if (default_selection < ENTRIES.len) default_selection else 0;
    while (true) {
        const sel = showImpl(gop, fb, st_in, boot_services, runtime_services, &ENTRIES, ds, last_crash_fp, true, boot_history);
        const m = ENTRIES[sel].boot_mode;
        if (m != BOOT_MODE_TESTS) return m;
        // Tests submenu — no auto-boot, no crash strip; returns either a
        // real boot_mode or BOOT_MODE_BACK.
        const tsel = showImpl(gop, fb, st_in, boot_services, runtime_services, &TEST_ENTRIES, 0, &.{}, false, boot_history);
        const tm = TEST_ENTRIES[tsel].boot_mode;
        if (tm != BOOT_MODE_BACK) return tm;
        // Back: redraw main with Tests entry still selected.
        ds = sel;
    }
}

fn showImpl(
    gop: *GraphicsOutput,
    fb: Fb,
    st_in: *SimpleTextInput,
    boot_services: *BootServices,
    runtime_services: *RuntimeServices,
    entries: []const Entry,
    default_selection: u32,
    last_crash_fp: []const u8,
    auto_boot: bool,
    boot_history: ?*const nvram.BootHistoryRing,
) u32 {
    const info = gop.mode.info;
    const entries_len_u32: u32 = @intCast(entries.len);

    var selected: u32 = if (default_selection < entries_len_u32) default_selection else 0;
    var seconds_left: u32 = TIMEOUT_SEC;
    var auto_boot_active: bool = auto_boot;

    const panel_w: u32 = 760;
    // Bumped from 420 → 480 once the AA atlas swap landed: SF Pro Text's
    // line_height (~20 px) is larger than the bitmap's 16, so the crash
    // strip + HW info couldn't both fit between the title-bar accent and
    // the entries without overlap.
    //
    // Now grows dynamically with entries.len: the Tests submenu added a
    // 7th entry (wake-IPI) and the fixed 480 left the footer key-cap
    // row drawn over the last entry. `overhead` is the non-entry
    // vertical space (title strip + gap + footer + countdown bar area).
    const min_panel_h: u32 = 480;
    const overhead_h: u32 = 60 + 7 + 80;
    const needed_h: u32 = @as(u32, @intCast(entries.len)) * ENTRY_H + overhead_h;
    const panel_h: u32 = @max(min_panel_h, needed_h);
    const panel_x = (fb.w - panel_w) / 2;
    const panel_y = (fb.h - panel_h) / 2 + 40;
    // Crash on previous boot disables auto-boot — the user clearly needs to
    // pick something deliberately, and freeing the countdown-bar strip lets
    // the crash banner sit cleanly above the entries.
    const has_crash: bool = last_crash_fp.len > 0;
    if (has_crash) auto_boot_active = false;

    // Loop-invariant precomputes — do once before the redraw loop. The HW
    // info string and the title's measured width never change during this
    // showImpl, and recomputing them every keypress is wasted work.
    const TITLE_STR: []const u8 = "Choose a boot entry";
    const title_w: u32 = aa.default_16.measure(TITLE_STR);
    var hwbuf: [80]u8 = undefined;
    const hw_msg: []const u8 = blk: {
        var hi: usize = 0;
        for ("GOP ") |c| { hwbuf[hi] = c; hi += 1; }
        var nb: [16]u8 = undefined;
        const ws = u32ToStr(&nb, info.horizontal_resolution);
        for (ws) |c| { hwbuf[hi] = c; hi += 1; }
        hwbuf[hi] = 'x'; hi += 1;
        const hs = u32ToStr(&nb, info.vertical_resolution);
        for (hs) |c| { hwbuf[hi] = c; hi += 1; }
        const fmt: []const u8 = switch (info.pixel_format) {
            .blue_green_red_reserved_8_bit_per_color => "  BGRA",
            .red_green_blue_reserved_8_bit_per_color => "  RGBA",
            else => "  ?",
        };
        for (fmt) |c| { hwbuf[hi] = c; hi += 1; }
        break :blk hwbuf[0..hi];
    };

    var redraw = true;
    var poll_count: u32 = 0;

    while (true) {
        if (redraw) {
            fillRect(fb, 0, 0, fb.w, fb.h, COLOR_BG);

            // Splash header — logo (with shadow) above panel, then subtitle
            // and version line. Anchored upwards from `panel_y` so the
            // version line always lands exactly `panel_gap` px above the
            // panel regardless of the atlas's `line_height`.
            const logo_scale: u32 = 4;
            const logo_h: u32 = LOGO_BASE_H * logo_scale;
            const line_h: u32 = aa.default_16.line_height;
            const splash_h = logo_h + 12 + line_h + 4 + line_h;
            const splash_y = panel_y -| (splash_h + 20);

            const logo_w = textWidthScaled("ZIGOS", logo_scale);
            const logo_x = (fb.w - logo_w) / 2;
            drawTextScaled(fb, logo_x + 4, splash_y + 4, "ZIGOS", logo_scale, COLOR_LOGO_SHADOW);
            drawTextScaled(fb, logo_x, splash_y, "ZIGOS", logo_scale, COLOR_LOGO);

            var splash = layout.VStack.init(fb, 0, splash_y + logo_h, fb.w);
            splash.gap(12);
            splash.textCentered("boot manager", COLOR_DIM, &aa.default_16);
            splash.gap(4);
            splash.textCentered(VERSION_STR, COLOR_ACCENT, &aa.default_16);

            // Panel chrome — drop shadow, fill, double border. The VStack
            // for inside-panel content uses `panel_x` / `panel_w` directly.
            fillRect(fb, panel_x + 6, panel_y + 6, panel_w, panel_h, COLOR_SHADOW);
            fillRect(fb, panel_x, panel_y, panel_w, panel_h, COLOR_PANEL);
            drawBorder(fb, panel_x, panel_y, panel_w, panel_h, COLOR_BORDER_OUT);
            drawBorder(fb, panel_x + 1, panel_y + 1, panel_w - 2, panel_h - 2, COLOR_BORDER_IN);

            // Inside-panel flow: title → accent rule → HW info → optional
            // crash banner → entries. Each row asks the atlas for its own
            // height; gap values are visual breathing room only, no longer
            // hand-tuned to the bitmap font's 16-px line.
            var ps = layout.VStack.init(fb, panel_x, panel_y, panel_w);
            ps.gap(22);
            const title_y = ps.cursor();
            ps.textCentered(TITLE_STR, COLOR_TITLE, &aa.default_16);

            // Dotted accents flanking the title — drawn outside the flow so
            // they sit alongside the title text rather than below it.
            const dots_w: u32 = 5 * 4 + 4 * 2; // 5 × 4-px dots with 2-px gaps
            const title_left = panel_x + (panel_w - title_w) / 2;
            const dots_y = title_y + (line_h -| 4) / 2;
            drawDottedRow(fb, title_left -| (dots_w + 12), dots_y, 5, 4, 2, COLOR_ACCENT);
            drawDottedRow(fb, title_left + title_w + 12, dots_y, 5, 4, 2, COLOR_ACCENT);

            ps.gap(8);
            ps.rule(80, COLOR_ACCENT);
            ps.gap(8);
            ps.textCentered(hw_msg, COLOR_DIM, &aa.default_16);

            if (has_crash) {
                ps.gap(6);
                const strip_h: u32 = line_h + 4;
                const strip_y = ps.reserve(strip_h);
                fillRect(fb, panel_x + 24, strip_y, panel_w -| 48, strip_h, COLOR_PULSE & 0x00302020);

                // Place the crash text inside the strip — the prefix in red
                // and the fingerprint in dim white. Two-color text doesn't
                // fit kvRow, so we measure both, center the pair, and draw
                // them at the strip's vertical midpoint manually.
                const prefix = "Last boot crashed: ";
                const usable_px: u32 = if (panel_w > 80) panel_w - 80 else 0;
                const prefix_w: u32 = aa.default_16.measure(prefix);
                const fp_full_w: u32 = aa.default_16.measure(last_crash_fp);
                const fp_fits = (prefix_w + fp_full_w) <= usable_px;
                const fp_show: []const u8 = if (fp_fits) last_crash_fp else last_crash_fp[0..0];
                const fp_show_w: u32 = if (fp_fits) fp_full_w else 0;
                const text_w: u32 = prefix_w + fp_show_w;
                const text_y = strip_y + 2;
                const start_x: u32 = panel_x + (panel_w -| text_w) / 2;
                aa.drawText(fb, @intCast(start_x), @intCast(text_y), prefix, COLOR_PULSE, &aa.default_16);
                aa.drawText(fb, @intCast(start_x +| prefix_w), @intCast(text_y), fp_show, COLOR_TEXT, &aa.default_16);
            }

            ps.gap(7); // separator before entries
            for (entries, 0..) |entry, i| {
                const idx: u32 = @intCast(i);
                const ey = ps.reserve(ENTRY_H);
                drawEntry(fb, panel_x, ey, panel_w, entry, idx == selected);
            }

            // Bottom-anchored items — countdown bar + footer key row.
            // Computed from `panel_y + panel_h` rather than the entry-flow
            // cursor so they stay glued to the panel bottom.
            if (auto_boot_active) {
                const bar_y = panel_y + panel_h - 50;
                const bar_h: u32 = 4;
                const bar_x = panel_x + 32;
                const bar_w = panel_w - 64;
                fillRect(fb, bar_x, bar_y, bar_w, bar_h, COLOR_BORDER_IN);
                var tick_i: u32 = 0;
                while (tick_i <= TIMEOUT_SEC) : (tick_i += 1) {
                    var tx = bar_x + (bar_w * tick_i) / TIMEOUT_SEC;
                    if (tx >= bar_x + bar_w) tx = bar_x + bar_w - 1;
                    fillRect(fb, tx, bar_y - 4, 1, 3, COLOR_BORDER_OUT);
                }
                const ticks_total = TIMEOUT_SEC * 20;
                const ticks_passed: u32 = (TIMEOUT_SEC - seconds_left) * 20 + poll_count;
                const ticks_left: u32 = if (ticks_total > ticks_passed) ticks_total - ticks_passed else 0;
                const fill_w = bar_w * ticks_left / ticks_total;
                const bar_color = if (seconds_left <= 3) COLOR_PULSE else COLOR_ACCENT;
                fillRect(fb, bar_x, bar_y, fill_w, bar_h, bar_color);
            }

            // Footer key-cap row using HStack — each `keycap()` /
            // `label()` / `gap()` advances the cursor so adding/removing a
            // key is a one-line change rather than a chain of `fx += ...`.
            const footer_row_h: u32 = 22;
            const footer_y = panel_y + panel_h - 30;
            fillRect(fb, panel_x + 40, footer_y - 12, panel_w - 80, 1, COLOR_BORDER_OUT);
            var fs = layout.HStack.init(fb, panel_x + 28, footer_y - 4, footer_row_h);
            const keys = [_]struct { cap: []const u8, label: []const u8 }{
                .{ .cap = "Up/Dn", .label = "move" },
                .{ .cap = "1-4", .label = "jump" },
                .{ .cap = "Enter", .label = "boot" },
                .{ .cap = "E", .label = "cmdline" },
                .{ .cap = "Esc", .label = "skip" },
            };
            for (keys, 0..) |k, idx| {
                if (idx > 0) fs.gap(12);
                fs.keycap(k.cap, COLOR_TEXT, KEYCAP_BG, COLOR_BORDER_OUT, &aa.default_16);
                fs.gap(4);
                fs.label(k.label, COLOR_DIM, &aa.default_16);
            }

            // Auto-boot countdown tag, right-aligned. Vertically aligned
            // with the keycap row's text-center so it sits on the same
            // baseline as the labels.
            if (auto_boot_active) {
                var num_buf: [8]u8 = undefined;
                var msg_buf: [24]u8 = undefined;
                const num_str = u32ToStr(&num_buf, seconds_left);
                var i: usize = 0;
                for (num_str) |c| { msg_buf[i] = c; i += 1; }
                msg_buf[i] = 's'; i += 1;
                const msg = msg_buf[0..i];
                const mw = aa.default_16.measure(msg);
                const cy = (footer_y - 4) + (footer_row_h -| line_h) / 2;
                aa.drawText(fb, @intCast(panel_x + panel_w - 32 -| mw), @intCast(cy), msg, COLOR_ACCENT, &aa.default_16);
            }

            redraw = false;
        }

        // Poll keyboard (non-blocking — NotReady is the common case)
        if (st_in.readKeyStroke()) |key| {
            auto_boot_active = false;
            redraw = true;
            switch (key.scan_code) {
                0x01 => { // Up
                    if (selected == 0) selected = entries_len_u32 - 1 else selected -= 1;
                },
                0x02 => { // Down
                    selected = (selected + 1) % entries_len_u32;
                },
                0x17 => { // Esc — return the menu's "back/default" entry.
                    // If the last entry is a Back sentinel (submenu), return
                    // its index so the caller can pop. Otherwise default to 0
                    // (Normal boot in the main menu).
                    if (entries.len > 0 and entries[entries.len - 1].boot_mode == BOOT_MODE_BACK) {
                        return entries_len_u32 - 1;
                    }
                    return 0;
                },
                else => {
                    // Number keys 1..N — jump to entry directly
                    if (key.unicode_char >= '1' and key.unicode_char < '1' + @as(u16, @intCast(entries_len_u32))) {
                        selected = @as(u32, key.unicode_char - '1');
                    }
                    // Enter (CR or LF) — act on the selected entry.
                    if (key.unicode_char == 0x0D or key.unicode_char == 0x0A) {
                        const sel_mode = entries[selected].boot_mode;
                        if (sel_mode == BOOT_MODE_ABOUT) {
                            // About: draw info screen, wait for key, return to menu
                            drawAboutScreen(fb, gop, boot_history);
                            // Drain any queued keys, then wait for a fresh one
                            while (st_in.readKeyStroke()) |_| {} else |_| {}
                            while (true) {
                                if (st_in.readKeyStroke()) |_| break else |_| {}
                                boot_services.stall(50_000) catch {};
                            }
                            redraw = true;
                            seconds_left = TIMEOUT_SEC;
                            poll_count = 0;
                        } else if (sel_mode == BOOT_MODE_TESTS or sel_mode == BOOT_MODE_BACK) {
                            // Submenu navigation — bypass the "booting..." modal.
                            return selected;
                        } else {
                            // Show "booting..." modal with Esc-cancel window
                            if (confirmBoot(fb, st_in, boot_services, entries[selected].label)) {
                                return selected;
                            }
                            // Cancelled — back to menu
                            redraw = true;
                            seconds_left = TIMEOUT_SEC;
                            poll_count = 0;
                        }
                    }
                    // Fallback nav for firmwares that mis-map arrows
                    if (key.unicode_char == 'k' or key.unicode_char == 'K') {
                        if (selected == 0) selected = entries_len_u32 - 1 else selected -= 1;
                    } else if (key.unicode_char == 'j' or key.unicode_char == 'J') {
                        selected = (selected + 1) % entries_len_u32;
                    }
                    // 'e' / 'E' — open the cmdline editor on the selected entry's
                    // mode (no-op if a sentinel like Tests/About is selected since
                    // those don't take cmdline). On commit (Enter), persist to
                    // NVRAM and redraw — the user picks a boot entry separately.
                    if (key.unicode_char == 'e' or key.unicode_char == 'E') {
                        const sel_mode = entries[selected].boot_mode;
                        const is_real = (sel_mode != BOOT_MODE_ABOUT and
                            sel_mode != BOOT_MODE_TESTS and
                            sel_mode != BOOT_MODE_BACK);
                        if (is_real) {
                            var cur_buf: [cmdline_editor.MAX_CMDLINE]u8 = undefined;
                            const cur_len = nvram.getCmdline(runtime_services, &cur_buf);
                            var new_buf: [cmdline_editor.MAX_CMDLINE]u8 = undefined;
                            if (cmdline_editor.edit(fb, st_in, boot_services, cur_buf[0..cur_len], &new_buf)) |new_len| {
                                nvram.setCmdline(runtime_services, new_buf[0..new_len]);
                            }
                            redraw = true;
                            seconds_left = TIMEOUT_SEC;
                            poll_count = 0;
                        }
                    }
                },
            }
        } else |_| {
            // No key — fall through to sleep
        }

        boot_services.stall(50_000) catch {};

        if (auto_boot_active) {
            poll_count += 1;
            if (poll_count >= 20) { // ~1 second
                poll_count = 0;
                if (seconds_left == 0) return selected;
                seconds_left -= 1;
                redraw = true;
            }
        }
    }
}

