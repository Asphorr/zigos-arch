// Pretty kernel panic screen.
//
// Two backends, picked at draw time:
//   - Graphical: writes directly to gfx framebuffer (UEFI GOP or virtio-gpu)
//     using the BDF font in gfx.drawString. Active when gfx.screen_w > 0.
//   - VGA text:  80x25 fallback for legacy multiboot pre-FB. Activated when
//     vga.available is true regardless of gfx state — VGA text mode is a
//     reliable last-resort surface (phys 0xB8000 always reachable).
//
// Contract: NEVER calls anything that might recurse into panic. No allocation;
// all formatting via stack buffers. Symbol resolution is the only nontrivial
// dependency, and it's a pure read on a static table.
//
// The serial autopsy / NMI broadcast / NVRAM persist live in main.zig's
// panic() and idt.zig's handleException. This module ONLY paints the
// user-visible screen.

const std = @import("std");
const vga = @import("../ui/vga.zig");
const gfx = @import("../ui/gfx.zig");
const aa_font = @import("../ui/aa_font.zig");
const symbols = @import("symbols.zig");
const memmap = @import("../mm/memmap.zig");
const debug_mod = @import("debug.zig");

pub const PanicInfo = struct {
    /// Exception vector. 6=#UD, 13=#GP, 14=#PF, 255=@panic, else=other.
    int_no: u64 = 255,
    /// @panic message text. Null for hardware exceptions.
    msg: ?[]const u8 = null,
    /// Saved RIP at the fault site.
    crash_rip: ?u64 = null,
    /// CR2 (faulting address) — only meaningful for #PF.
    cr2: ?u64 = null,
    /// CPU error code pushed by hardware (for #PF / #GP).
    error_code: ?u64 = null,
    /// CPU id we panicked on. Resolved at draw time when null.
    cpu_id: ?u32 = null,
};

// ARGB palette — graphical backend.
const COLOR_BG: u32 = 0x18_0000; // very dark red wash
const COLOR_PANEL: u32 = 0x22_0808; // panel face
const COLOR_BORDER: u32 = 0xC0_3030; // muted red rim
const COLOR_TITLE_BG: u32 = 0x90_1010;
const COLOR_TITLE_FG: u32 = 0xFFFFFF;
const COLOR_LABEL: u32 = 0xC0_C0C0;
const COLOR_VALUE: u32 = 0xFFFFFF;
const COLOR_HINT: u32 = 0xFFD0_60;
const COLOR_FOOTER: u32 = 0x80_8080;
const COLOR_SECTION_RULE: u32 = 0x60_2020;
const COLOR_BADGE_BG: u32 = 0xE0_3030;

// Approximate cell width — AA fonts are variable-width, so this is only
// used for label-vs-value column alignment (labels are fixed-width strings
// like "Where:   " whose pixel width is reasonably consistent).
const LABEL_COL_W: i32 = 96;

pub fn draw(info: PanicInfo) void {
    if (gfx.screen_w > 0 and gfx.screen_h > 0) {
        drawGraphical(info);
        if (gfx.post_blit_fn) |flush| {
            // Skip the GPU post-blit when virtio_gpu's ctrl_lock is already
            // held — typically because we're panicking on an IRQ that
            // interrupted desktop mid-sendCmd. flush()'s sendCmd would
            // re-enter the Mutex, hit the recursive-acquire detector, and
            // cascade panics until the watchdog NMI fires. The panel is
            // still drawn into the framebuffer; on UEFI GOP it's directly
            // visible. On virtio-gpu the user sees the last desktop frame
            // — acceptable, serial has the full autopsy.
            const vgpu = @import("../driver/virtio_gpu.zig");
            if (!vgpu.ctrlLockBusy()) flush();
        }
    }
    if (vga.available) drawVga(info);
}

// ---- Graphical backend ----------------------------------------------------

fn drawGraphical(info: PanicInfo) void {
    // Bypass any back-buffer the desktop may have set up.
    gfx.useFramebuffer();
    aa_font.ensureLoaded();
    const a16 = aa_font.getDefault16();
    const a24 = aa_font.getDefault24();
    const line_h: i32 = @intCast(a16.line_height);

    const sw = gfx.screen_w;
    const sh = gfx.screen_h;

    gfx.fillRect(0, 0, sw, sh, COLOR_BG);

    // Centered panel, sized for any common resolution.
    const panel_w: u32 = if (sw >= 880) 880 else sw -| 16;
    const panel_h: u32 = if (sh >= 560) 560 else sh -| 16;
    const px: i32 = @intCast((sw -| panel_w) / 2);
    const py: i32 = @intCast((sh -| panel_h) / 2);
    gfx.fillRect(px, py, panel_w, panel_h, COLOR_PANEL);
    gfx.drawRect(px, py, panel_w, panel_h, COLOR_BORDER);

    // Title bar with severity badge — sized to fit the 24px display font.
    const title_h: u32 = @as(u32, a24.line_height) + 18;
    gfx.fillRect(px, py, panel_w, title_h, COLOR_TITLE_BG);

    // Severity badge — fixed 14px tag pill.
    const badge_text = badgeName(info.int_no);
    const badge_text_w = a16.measure(badge_text);
    const badge_w: u32 = badge_text_w + 24;
    const badge_h: u32 = @as(u32, a16.line_height) + 6;
    const badge_y: i32 = py + @divTrunc(@as(i32, @intCast(title_h)) - @as(i32, @intCast(badge_h)), 2);
    gfx.fillRect(px + 16, badge_y, badge_w, badge_h, COLOR_BADGE_BG);
    aa_font.drawTextCentered(px + 16, badge_y + 3, badge_w, badge_text, COLOR_TITLE_FG, a16);

    const title = "ZigOS  -  Kernel Panic";
    const title_x: i32 = px + 16 + @as(i32, @intCast(badge_w)) + 18;
    const title_y: i32 = py + @divTrunc(@as(i32, @intCast(title_h)) - @as(i32, @intCast(a24.line_height)), 2);
    aa_font.drawText(title_x, title_y, title, COLOR_TITLE_FG, a24);

    // ---- Body ----
    var y_cur: i32 = py + @as(i32, @intCast(title_h)) + 18;
    const x_left: i32 = px + 28;
    const inner_w: u32 = panel_w -| 56;

    drawLabeled(x_left, y_cur, "What", typeName(info.int_no), a16);
    y_cur += line_h + 2;

    var rip_buf: [192]u8 = undefined;
    drawLabeled(x_left, y_cur, "Where", formatRip(&rip_buf, info.crash_rip), a16);
    y_cur += line_h + 2;

    if (info.int_no == 14) {
        var cr2_buf: [192]u8 = undefined;
        drawLabeled(x_left, y_cur, "Address", formatCr2(&cr2_buf, info.cr2 orelse 0), a16);
        y_cur += line_h + 2;
    }

    var meta_buf: [128]u8 = undefined;
    drawLabeled(x_left, y_cur, "CPU", formatMeta(&meta_buf, info.cpu_id), a16);
    y_cur += line_h + 6;

    if (info.msg) |m| {
        drawLabeled(x_left, y_cur, "Message", m, a16);
        y_cur += line_h + 6;
    }

    // Section rule
    gfx.fillRect(x_left, y_cur, inner_w, 1, COLOR_SECTION_RULE);
    y_cur += 14;

    // Hint — labeled, value in amber.
    var hint_buf: [192]u8 = undefined;
    const hint = classifierHint(&hint_buf, info);
    aa_font.drawText(x_left, y_cur, "Hint", COLOR_LABEL, a16);
    aa_font.drawText(x_left + LABEL_COL_W, y_cur, hint, COLOR_HINT, a16);
    y_cur += line_h + 10;

    // Section rule
    gfx.fillRect(x_left, y_cur, inner_w, 1, COLOR_SECTION_RULE);
    y_cur += 14;

    aa_font.drawText(x_left, y_cur, "What to do", COLOR_LABEL, a16);
    y_cur += line_h + 4;
    for (whatToDo(info.int_no)) |s| {
        aa_font.drawText(x_left + 18, y_cur, s, COLOR_VALUE, a16);
        y_cur += line_h + 2;
    }

    // Footer pinned to panel bottom.
    const footer_y: i32 = py + @as(i32, @intCast(panel_h)) - line_h - 14;
    aa_font.drawText(
        px + 28,
        footer_y,
        "System halted. Full crash log on serial port. Reboot to recover.",
        COLOR_FOOTER,
        a16,
    );
}

fn drawLabeled(x: i32, y: i32, label: []const u8, value: []const u8, atlas: *const aa_font.Atlas) void {
    aa_font.drawText(x, y, label, COLOR_LABEL, atlas);
    aa_font.drawText(x + LABEL_COL_W, y, value, COLOR_VALUE, atlas);
}

// ---- Content helpers (shared) ---------------------------------------------

fn typeName(int_no: u64) []const u8 {
    return switch (int_no) {
        6 => "#UD invalid opcode",
        13 => "#GP general protection fault",
        14 => "#PF page fault",
        255 => "@panic / kernel assertion",
        else => "unknown exception",
    };
}

fn badgeName(int_no: u64) []const u8 {
    return switch (int_no) {
        6 => "UD",
        13 => "GP",
        14 => "PF",
        255 => "PANIC",
        else => "EXC",
    };
}

fn formatRip(buf: []u8, crash_rip: ?u64) []const u8 {
    const rip = crash_rip orelse return "(unknown)";
    if (symbols.resolveKernel(rip)) |r| {
        return std.fmt.bufPrint(buf, "{s}+0x{X}  (0x{X:0>16})", .{ r.name, r.offset, rip }) catch "(fmt)";
    }
    return std.fmt.bufPrint(buf, "0x{X:0>16}", .{rip}) catch "(fmt)";
}

fn formatCr2(buf: []u8, cr2: u64) []const u8 {
    const decode: []const u8 = if (cr2 < 0x1000)
        "low 4KB - null deref?"
    else if (cr2 >= 0x0000_8000_0000_0000 and cr2 < 0xFFFF_8000_0000_0000)
        "non-canonical - wild pointer"
    else if (cr2 < memmap.KERNEL_PHYS_START)
        "below kernel image"
    else if (cr2 >= memmap.USER_VA_FLOOR and cr2 < memmap.USER_VA_MAX)
        "user range"
    else
        "kernel range";
    return std.fmt.bufPrint(buf, "0x{X:0>16}  ({s})", .{ cr2, decode }) catch "(fmt)";
}

fn formatMeta(buf: []u8, cpu_id_opt: ?u32) []const u8 {
    const apic = @import("../time/apic.zig");
    const cid = cpu_id_opt orelse @as(u32, @intCast(apic.getLapicId()));
    const build_id = @import("build_options").build_id;
    return std.fmt.bufPrint(buf, "cpu{d}    Build: 0x{X:0>16}", .{ cid, build_id }) catch "(fmt)";
}

fn classifierHint(buf: []u8, info: PanicInfo) []const u8 {
    const rip = info.crash_rip orelse 0;
    const cr2 = info.cr2 orelse 0;
    const h = debug_mod.classifyCrash(info.int_no, rip, cr2, 0);
    const prefix = "Likely cause: ";
    const body: []const u8 = if (h.len >= prefix.len and std.mem.startsWith(u8, h, prefix))
        h[prefix.len..]
    else
        h;
    return std.fmt.bufPrint(buf, "{s}", .{body}) catch body;
}

fn whatToDo(int_no: u64) []const []const u8 {
    return switch (int_no) {
        14 => &.{
            "1. Reboot — the next boot menu offers crash recovery",
            "2. Memory corruption suspected; try Safe boot mode",
            "3. Save serial.log + the build_id above for triage",
        },
        13 => &.{
            "1. Reboot to recover — menu remembers this crash",
            "2. Possible build mismatch — run `zig build` to refresh",
            "3. If reproducible, check recent inline-asm or trampoline edits",
        },
        6 => &.{
            "1. Reboot to recover",
            "2. Possible stack smash; check the symbol shown above",
            "3. Save serial.log for full backtrace",
        },
        255 => &.{
            "1. Reboot — the next boot menu offers crash recovery",
            "2. Invariant failed; full message above + serial log",
            "3. If reproducible, share serial.log + the build_id",
        },
        else => &.{
            "1. Reboot to recover",
            "2. Save serial.log for full crash autopsy",
            "3. Note the exception vector + RIP shown above",
        },
    };
}

// ---- VGA text-mode backend ------------------------------------------------

fn drawVga(info: PanicInfo) void {
    vga.bg = .Red;
    vga.fg = .White;
    vga.clear();

    // Top border
    vga.print("\n", .{});
    vga.fg = .Yellow;
    vga.print("  *** ZigOS - KERNEL PANIC ***   [{s}]\n", .{badgeName(info.int_no)});
    vga.fg = .White;
    vga.print("  ----------------------------------------------------------------\n", .{});

    vga.print("  What:    {s}\n", .{typeName(info.int_no)});

    var rip_buf: [160]u8 = undefined;
    vga.print("  Where:   {s}\n", .{formatRip(&rip_buf, info.crash_rip)});

    if (info.int_no == 14) {
        var cr2_buf: [160]u8 = undefined;
        vga.print("  Address: {s}\n", .{formatCr2(&cr2_buf, info.cr2 orelse 0)});
    }

    var meta_buf: [128]u8 = undefined;
    vga.print("  CPU:     {s}\n", .{formatMeta(&meta_buf, info.cpu_id)});

    if (info.msg) |m| {
        vga.print("  Message: {s}\n", .{m});
    }

    vga.print("  ----------------------------------------------------------------\n", .{});

    var hint_buf: [192]u8 = undefined;
    const hint = classifierHint(&hint_buf, info);
    vga.fg = .Yellow;
    vga.print("  Hint:    {s}\n", .{hint});
    vga.fg = .White;
    vga.print("  ----------------------------------------------------------------\n", .{});

    vga.print("  What to do:\n", .{});
    for (whatToDo(info.int_no)) |s| {
        vga.print("    {s}\n", .{s});
    }

    vga.fg = .LightGray;
    vga.print("\n  System halted. Full crash log on serial port. Reboot to recover.\n", .{});
    vga.fg = .White;
}
