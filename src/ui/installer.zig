// installer — the graphical front end for the partition + mkfs path.
//
// Boot mode 17. Runs as the first and only task, owns the whole screen, and
// paints a fixed panel rather than creating a window: there is no desktop
// under it, so there is nothing to be a window *in*. The look follows the
// macOS installer, which is the design the user asked to copy — five steps
// down the left, one pane of content, actions bottom-right.
//
// The whole install is real (2026-08-22): GPT + mkfs (the same code the
// boot-16 self-test drives), the system tree copied from the live root onto
// the new ext2 (fs/ext2/populate.zig — a slice of dirents per frame, so the
// bar moves because work happened, not because a timer ticked), BOOTX64.EFI
// and kernel.elf laid into the fresh ESP (fs/fat32_populate.zig, fed from
// /boot/ of the root fs — the kernel cannot read its own boot media), and a
// Boot#### entry pushed through UEFI Runtime Services. The boot-entry step
// alone is non-fatal: firmware that lost the entry (or a QEMU run whose vars
// were refreshed) still boots the disk through the \EFI\BOOT\BOOTX64.EFI
// removable-media fallback the installer also provides.
//
// The install runs one step per frame, rendering before it blocks. mkfs takes
// long enough to see, and a step whose label goes up only *after* it finishes
// leaves the screen frozen on the previous step for the whole write.
//
// Run: zig build -Dboot-mode=17 && ./run-installer.sh

const std = @import("std");

const gfx = @import("gfx.zig");
const aa = @import("aa_font.zig");
const scanout = @import("scanout.zig");
const display = @import("display.zig");

const mouse = @import("../driver/mouse.zig");
const keyboard = @import("../driver/keyboard.zig");
const xhci = @import("../driver/xhci.zig");
const block = @import("../driver/block.zig");
const nvme = @import("../driver/nvme.zig");

const gpt = @import("../fs/gpt.zig");
const ext2_mkfs = @import("../fs/ext2/mkfs.zig");
const fat_mkfs = @import("../fs/fat32_mkfs.zig");
const ext2_layout = @import("../fs/ext2/layout.zig");
const ext2 = @import("../fs/ext2/ext2.zig");
const ext2_blk = @import("../fs/ext2/block.zig");
const populate = @import("../fs/ext2/populate.zig");
const fat_pop = @import("../fs/fat32_populate.zig");
const uefi_nvram = @import("../boot/uefi_nvram.zig");

const paging = @import("../mm/paging.zig");
const acpi = @import("../acpi/acpi.zig");
const io = @import("../io.zig");
const serial = @import("../debug/serial.zig");

// =============================================================================
// Palette — macOS light. Values lifted from the mockup so the two stay
// comparable; see the artifact for the dark set if this ever grows a toggle.
// =============================================================================

const GROUND_TOP: u32 = 0xDFE2E8;
const GROUND_BOT: u32 = 0xC6CBD6;
const CHROME: u32 = 0xECECED;
const SIDEBAR: u32 = 0xE6E7EA;
const PANE: u32 = 0xFFFFFF;
const INK: u32 = 0x1C1C1E;
const INK_DIM: u32 = 0x6B6F76;
const INK_FAINT: u32 = 0x9AA0A8;
const RULE: u32 = 0xD5D7DC;
const RULE_SOFT: u32 = 0xE4E6EA;
const ACCENT: u32 = 0x0A6CF0;
const ACCENT_WASH: u32 = 0xE8F0FE;
const AMBER: u32 = 0xF7A41D;
const OK: u32 = 0x30A14E;
const FAIL: u32 = 0xC0392B;
const WARN_BG: u32 = 0xFDF3E0;
const WARN_INK: u32 = 0x8A5A08;
const MONO_BG: u32 = 0xF5F6F8;
const BTN_BG: u32 = 0xFDFDFD;
const BTN_RULE: u32 = 0xC6C9CF;

const LIGHT_RED: u32 = 0xFF5F57;
const LIGHT_OFF: u32 = 0xC8CACE;

// =============================================================================
// Layout — the mockup's CSS pixel values, used directly. The panel is a fixed
// size and centred; at 1920x1080 that leaves a wide margin, which is what the
// macOS installer does too.
// =============================================================================

const PANEL_W: u32 = 880;
const PANEL_H: u32 = 560;
const TITLEBAR_H: u32 = 40;
const FOOTER_H: u32 = 58;
const SIDEBAR_W: u32 = 210;
const BODY_H: u32 = PANEL_H - TITLEBAR_H - FOOTER_H;
const PANE_W: u32 = PANEL_W - SIDEBAR_W;
const PAD_X: i32 = 40;
const PAD_Y: i32 = 34;
const STEP_H: i32 = 28;
const BTN_H: u32 = 28;
const BTN_R: u32 = 6;

var panel_x: i32 = 0;
var panel_y: i32 = 0;

inline fn paneX() i32 {
    return panel_x + @as(i32, SIDEBAR_W);
}
inline fn bodyY() i32 {
    return panel_y + @as(i32, TITLEBAR_H);
}
inline fn footerY() i32 {
    return panel_y + @as(i32, PANEL_H - FOOTER_H);
}
/// Left edge of pane text, and the width available to it.
inline fn contentX() i32 {
    return paneX() + PAD_X;
}
inline fn contentW() u32 {
    return PANE_W - 2 * @as(u32, @intCast(PAD_X));
}

// =============================================================================
// Screens and steps
// =============================================================================

const Screen = enum(u8) {
    intro = 0,
    destination = 1,
    layout = 2,
    installing = 3,
    done = 4,
};

const STEP_NAMES = [_][]const u8{
    "Introduction",
    "Destination",
    "Partition Layout",
    "Installation",
    "Restart",
};

/// The install phases that actually touch the disk, in order. `complete` and
/// `failed` are terminal and never render as a row.
const Phase = enum(u8) {
    write_gpt = 0,
    reread_gpt = 1,
    mkfs_esp = 2,
    mkfs_root = 3,
    copy_root = 4,
    install_boot = 5,
    boot_entry = 6,
    verify = 7,
    complete = 8,
    failed = 9,

    fn label(self: Phase) []const u8 {
        return switch (self) {
            .write_gpt => "Writing GPT partition table",
            .reread_gpt => "Re-reading the partition table",
            .mkfs_esp => "Formatting EFI System Partition (FAT32)",
            .mkfs_root => "Formatting root partition (ext2)",
            .copy_root => "Copying the system",
            .install_boot => "Installing the bootloader",
            .boot_entry => "Registering the firmware boot entry",
            .verify => "Verifying on-disk signatures",
            .complete => "Done",
            .failed => "Stopped",
        };
    }
};

const PHASE_COUNT: u32 = 8;

// =============================================================================
// State
// =============================================================================

/// A block device the kernel enumerated, with what it is already being used
/// for. Only `.target` is selectable — the others are live under our feet, and
/// an installer that offers you the disk it is running from is a trap.
const Role = enum {
    tarfs,
    root,
    swap,
    target,
    unknown,

    fn note(self: Role) []const u8 {
        // Longest label sets the floor for CARD_W — the full string must fit
        // a card, and the notice below carries the long-form explanation.
        return switch (self) {
            .tarfs => "in use - archive",
            .root => "in use - root",
            .swap => "in use - swap",
            .target => "available",
            .unknown => "unknown role",
        };
    }
    fn selectable(self: Role) bool {
        return self == .target;
    }
};

const Disk = struct {
    ctrl: usize,
    sectors: u64,
    role: Role,
};

const MAX_DISKS: usize = 4;
var disks: [MAX_DISKS]Disk = undefined;
var disk_count: usize = 0;
var selected: usize = 0;

var screen: Screen = .intro;
var phase: Phase = .write_gpt;
/// Phases that finished successfully. Drives the progress bar. Kept separate
/// from `phase` because the failure state sorts *after* every real phase in
/// the enum, so deriving progress from it alone would paint a full bar the
/// moment anything went wrong.
var phases_done: u32 = 0;
/// Result of the install, only meaningful once `phase` is terminal.
var fail_reason: []const u8 = "";
/// copy_root's first frame mounts the target + arms the walk; later frames
/// step it. Reset when a fresh install starts.
var copy_started: bool = false;
/// Boot#### slot the firmware accepted, when the NVRAM step succeeded.
var boot_entry_slot: ?u16 = null;

/// Partition geometry, computed on entry to the layout screen so the table
/// shows the numbers that will actually be written rather than a guess.
var esp_start: u64 = 0;
var esp_end: u64 = 0;
var root_start: u64 = 0;
var root_end: u64 = 0;

/// The table as re-read from the disk. Every step after `reread_gpt` works off
/// this rather than the specs, so a table that round-trips wrong misplaces the
/// mkfs visibly instead of passing quietly.
var table: gpt.Table = undefined;

var dirty: bool = true;
var prev_buttons: u8 = 0;
/// Set for exactly one frame when the left button goes down, with the position
/// latched at the transition. Hit-tests read these, so a button that moves
/// under a held cursor can't retro-claim the click.
var click: bool = false;
var click_x: i32 = 0;
var click_y: i32 = 0;

// =============================================================================
// Log pane
// =============================================================================

const LOG_LINES: usize = 12;
const LOG_COLS: usize = 76;
var log_buf: [LOG_LINES][LOG_COLS]u8 = [_][LOG_COLS]u8{[_]u8{0} ** LOG_COLS} ** LOG_LINES;
var log_len: [LOG_LINES]usize = [_]usize{0} ** LOG_LINES;
var log_total: usize = 0;

/// Append one line to the rolling log and mirror it to serial. The mirror is
/// the point: the panel shows the last dozen lines, the serial log keeps all
/// of them, and it is the serial log you read when the install fails.
fn logLine(comptime f: []const u8, args: anytype) void {
    const slot = log_total % LOG_LINES;
    // Truncating is fine and deliberate — this is a display buffer, and a
    // too-long line is a formatting bug, not a reason to lose the message.
    const written = std.fmt.bufPrint(&log_buf[slot], f, args) catch blk: {
        const tail = "...";
        @memcpy(log_buf[slot][LOG_COLS - tail.len ..], tail);
        break :blk log_buf[slot][0..LOG_COLS];
    };
    log_len[slot] = written.len;
    log_total += 1;
    serial.print("[installer] {s}\n", .{written});
}

/// Iterate the visible window of the log, oldest first.
fn logVisible(i: usize) ?[]const u8 {
    const shown = @min(log_total, LOG_LINES);
    if (i >= shown) return null;
    const first = log_total - shown;
    const slot = (first + i) % LOG_LINES;
    return log_buf[slot][0..log_len[slot]];
}

// =============================================================================
// Text helpers
// =============================================================================

/// Scratch for one formatted string. Single-threaded UI code, one call per
/// use site, consumed before the next format — a per-call stack buffer in
/// every drawing function would cost far more stack than this is worth.
var fmt_buf: [160]u8 = undefined;

fn fmt(comptime f: []const u8, args: anytype) []const u8 {
    return std.fmt.bufPrint(&fmt_buf, f, args) catch fmt_buf[0..0];
}

fn text(x: i32, y: i32, s: []const u8, color: u32) void {
    aa.drawText(x, y, s, color, aa.getDefault16());
}
fn textBig(x: i32, y: i32, s: []const u8, color: u32) void {
    aa.drawText(x, y, s, color, aa.getDefault24());
}
fn textMono(x: i32, y: i32, s: []const u8, color: u32) void {
    aa.drawText(x, y, s, color, aa.getDefaultMono());
}
fn textCentered(x: i32, y: i32, w: u32, s: []const u8, color: u32) void {
    aa.drawTextCentered(x, y, w, s, color, aa.getDefault16());
}
fn width16(s: []const u8) u32 {
    return aa.getDefault16().measure(s);
}
fn widthMono(s: []const u8) u32 {
    return aa.getDefaultMono().measure(s);
}

/// Line advance for the body font. The atlas carries its own metric; reading
/// it here means a font swap re-flows the panel instead of overlapping it.
fn lineH() i32 {
    return @intCast(aa.getDefault16().line_height);
}

/// Half a line, for vertically centring one line of text in a box.
fn lineHalf() i32 {
    return @divTrunc(lineH(), 2);
}

/// Wrap `s` to `max_w` and draw it as a paragraph. Returns the y below the
/// last line. Breaks on spaces only — every string here is prose we wrote.
fn paragraph(x: i32, y: i32, max_w: u32, s: []const u8, color: u32) i32 {
    const atlas = aa.getDefault16();
    var line_y = y;
    var start: usize = 0;
    var last_space: ?usize = null;
    var i: usize = 0;
    while (i <= s.len) : (i += 1) {
        if (i < s.len and s[i] != ' ') continue;
        if (atlas.measure(s[start..i]) > max_w) {
            if (last_space) |sp| {
                aa.drawText(x, line_y, s[start..sp], color, atlas);
                line_y += lineH();
                start = sp + 1;
                last_space = if (i > start) i else null;
                continue;
            }
        }
        if (i < s.len) last_space = i;
    }
    if (start < s.len) {
        aa.drawText(x, line_y, s[start..], color, atlas);
        line_y += lineH();
    }
    return line_y;
}

// =============================================================================
// Hit testing
// =============================================================================

fn inRect(px: i32, py: i32, x: i32, y: i32, w: u32, h: u32) bool {
    return px >= x and px < x + @as(i32, @intCast(w)) and
        py >= y and py < y + @as(i32, @intCast(h));
}

fn hovered(x: i32, y: i32, w: u32, h: u32) bool {
    return inRect(mouse.x, mouse.y, x, y, w, h);
}

fn clickedIn(x: i32, y: i32, w: u32, h: u32) bool {
    return click and inRect(click_x, click_y, x, y, w, h);
}

// =============================================================================
// Chrome
// =============================================================================

fn drawBackground(w: u32, h: u32) void {
    // Vertical ramp between the two ground tones. The mockup uses a radial
    // gradient; a vertical one reads the same at this contrast and costs one
    // fillRect per row instead of a per-pixel distance.
    //
    // Signed channel deltas: the ramp runs light-to-dark, so every delta is
    // negative and unsigned arithmetic would wrap on the first row.
    const height: i32 = @intCast(@max(h, 1));
    var row: i32 = 0;
    while (row < height) : (row += 1) {
        const r = rampChannel(GROUND_TOP, GROUND_BOT, 16, row, height);
        const g = rampChannel(GROUND_TOP, GROUND_BOT, 8, row, height);
        const b = rampChannel(GROUND_TOP, GROUND_BOT, 0, row, height);
        gfx.fillRect(0, row, w, 1, (r << 16) | (g << 8) | b);
    }
}

/// One channel of a two-stop linear ramp, `shift` selecting R/G/B.
fn rampChannel(from: u32, to: u32, shift: u5, step: i32, steps: i32) u32 {
    const a: i32 = @intCast((from >> shift) & 0xFF);
    const b: i32 = @intCast((to >> shift) & 0xFF);
    return @intCast(a + @divTrunc((b - a) * step, steps));
}

fn drawPanelShadow() void {
    // Four expanding rounded rects at low alpha. Cheaper than a real blur and
    // indistinguishable at this size against a flat backdrop.
    var i: i32 = 4;
    while (i >= 1) : (i -= 1) {
        const spread: i32 = i * 5;
        const alpha: u32 = @intCast(10 + (4 - i) * 6);
        gfx.fillRoundedRectAlpha(
            panel_x - spread,
            panel_y - spread + 6,
            PANEL_W + @as(u32, @intCast(spread * 2)),
            PANEL_H + @as(u32, @intCast(spread * 2)),
            14 + @as(u32, @intCast(spread)),
            (alpha << 24) | 0x181E2D,
        );
    }
}

fn drawTitlebar() void {
    gfx.fillRect(panel_x, panel_y, PANEL_W, TITLEBAR_H, CHROME);
    gfx.fillRect(panel_x, panel_y + @as(i32, TITLEBAR_H) - 1, PANEL_W, 1, RULE);

    // Only close is live; minimize and zoom are off, as they are in the real
    // installer — there is nowhere to minimize to.
    const cy = panel_y + @as(i32, TITLEBAR_H / 2);
    gfx.drawFilledCircle(panel_x + 20, cy, 6, LIGHT_RED);
    gfx.drawFilledCircle(panel_x + 40, cy, 6, LIGHT_OFF);
    gfx.drawFilledCircle(panel_x + 60, cy, 6, LIGHT_OFF);

    const title = "Install ZigOS";
    const ty = cy - lineHalf();
    textCentered(panel_x, ty, PANEL_W, title, INK_DIM);
}

fn drawSidebar() void {
    gfx.fillRect(panel_x, bodyY(), SIDEBAR_W, BODY_H, SIDEBAR);
    gfx.fillRect(panel_x + @as(i32, SIDEBAR_W) - 1, bodyY(), 1, BODY_H, RULE);

    const now: usize = @intFromEnum(screen);
    var y = bodyY() + 26;
    for (STEP_NAMES, 0..) |name, i| {
        const is_now = (i == now);
        const is_done = (i < now);
        const dot_x = panel_x + 22 + 3;
        const dot_y = y + lineHalf();
        if (is_now) {
            gfx.drawFilledCircle(dot_x, dot_y, 4, ACCENT);
        } else if (is_done) {
            gfx.drawFilledCircle(dot_x, dot_y, 4, INK_FAINT);
        } else {
            gfx.drawFilledCircle(dot_x, dot_y, 4, SIDEBAR);
            gfx.drawCircleAA(dot_x, dot_y, 4, 1, INK_FAINT);
        }
        text(panel_x + 37, y, name, if (is_now) ACCENT else INK_DIM);
        y += STEP_H;
    }
}

/// What `button` reports back: how wide it drew, and whether this frame's
/// click landed on it.
///
/// Named rather than an anonymous struct literal in the return position, as
/// are `Point`, `Bullet` and `Row` below. Anonymous struct types reachable
/// from the kernel's call graph make Zig 0.15.2 emit bitcode LLVM 20.1.2 then
/// rejects — "Invalid type", and in its other form "Only named structs can be
/// forward referenced". Naming them is the workaround; the compiler bug is
/// not fixed and the same shape will bite again elsewhere.
const ButtonResult = struct { w: u32, hit: bool };

fn button(x: i32, label: []const u8, primary: bool, enabled: bool) ButtonResult {
    const pad: u32 = 17;
    const w = width16(label) + pad * 2;
    const y = footerY() + @as(i32, (FOOTER_H - BTN_H) / 2);
    const bx = x - @as(i32, @intCast(w));

    const hot = enabled and hovered(bx, y, w, BTN_H);
    const bg = if (!enabled)
        (if (primary) mix(ACCENT, CHROME, 60) else mix(BTN_BG, CHROME, 60))
    else if (primary)
        (if (hot) mix(ACCENT, 0xFFFFFF, 18) else ACCENT)
    else if (hot) mix(BTN_BG, 0x000000, 8) else BTN_BG;

    gfx.fillRoundedRect(bx, y, w, BTN_H, BTN_R, bg);
    if (!primary) {
        gfx.drawRect(bx, y, w, BTN_H, if (enabled) BTN_RULE else mix(BTN_RULE, CHROME, 60));
    }

    const ink = if (primary)
        (if (enabled) 0xFFFFFF else mix(0xFFFFFF, CHROME, 55))
    else if (enabled) INK else INK_FAINT;
    const label_y = y + @divTrunc(@as(i32, @intCast(BTN_H)) - lineH(), 2);
    textCentered(bx, label_y, w, label, ink);

    return .{ .w = w, .hit = enabled and clickedIn(bx, y, w, BTN_H) };
}

/// Blend `b` into `a` by `pct` percent. Used for hover/disabled tints so the
/// palette above stays the single source of the base colors.
fn mix(a: u32, b: u32, pct: u32) u32 {
    const ia = 100 - pct;
    const r = (((a >> 16) & 0xFF) * ia + ((b >> 16) & 0xFF) * pct) / 100;
    const g = (((a >> 8) & 0xFF) * ia + ((b >> 8) & 0xFF) * pct) / 100;
    const bl = ((a & 0xFF) * ia + (b & 0xFF) * pct) / 100;
    return (r << 16) | (g << 8) | bl;
}

/// Primary/secondary button labels per screen. An empty primary label means
/// the button is not drawn at all (the install screen has no way forward but
/// through).
fn primaryLabel() []const u8 {
    return switch (screen) {
        .intro => "Continue",
        .destination => "Continue",
        .layout => "Install",
        .installing => "",
        .done => "Restart",
    };
}

fn drawFooter() void {
    gfx.fillRect(panel_x, footerY(), PANEL_W, FOOTER_H, CHROME);
    gfx.fillRect(panel_x, footerY(), PANEL_W, 1, RULE);

    // Left: which disk we are pointed at, once one is chosen.
    const stamp_y = footerY() + @as(i32, @intCast(FOOTER_H / 2)) - lineHalf();
    if (screen == .intro or disk_count == 0) {
        textMono(panel_x + 22, stamp_y, "zigos - install", INK_FAINT);
    } else {
        const d = disks[selected];
        textMono(panel_x + 22, stamp_y, fmt("nvme{d} - {d} MiB", .{ d.ctrl, d.sectors / 2048 }), INK_FAINT);
    }

    var x = panel_x + @as(i32, PANEL_W) - 22;
    const p_label = primaryLabel();
    if (p_label.len != 0) {
        const p = button(x, p_label, true, primaryEnabled());
        if (p.hit) advance();
        x -= @as(i32, @intCast(p.w)) + 10;
    }

    const back_ok = (screen == .destination or screen == .layout);
    const b = button(x, "Go Back", false, back_ok);
    if (b.hit) goBack();
}

fn primaryEnabled() bool {
    return switch (screen) {
        .destination => disk_count > 0 and disks[selected].role.selectable(),
        .installing => false,
        else => true,
    };
}

// =============================================================================
// Screen 1 — introduction
// =============================================================================

/// The Zig bolt, traced from the logo path in the mockup at 2x scale and cut
/// into triangles (it is concave, so `fillPolygonConvex` cannot take it whole).
/// Vertex names follow the path order: top-left, top-right, the inner notch,
/// the right shoulder, the point, the return notch, bottom-left.
const Point = struct { x: i32, y: i32 };

/// One numbered line on the introduction screen.
const Bullet = struct { n: []const u8, head: []const u8, body: []const u8 };

/// One row of the partition table on the layout screen.
const Row = struct { n: []const u8, name: []const u8, kind: []const u8, first: u64, last: u64 };

fn drawBolt(ox: i32, oy: i32) void {
    const P0 = Point{ .x = 12, .y = 14 };
    const P1 = Point{ .x = 48, .y = 14 };
    const P2 = Point{ .x = 35, .y = 30 };
    const P3 = Point{ .x = 48, .y = 30 };
    const P4 = Point{ .x = 20, .y = 48 };
    const P5 = Point{ .x = 30, .y = 29 };
    const P6 = Point{ .x = 12, .y = 29 };

    // Upper arm: split at the notch so each piece stays convex.
    boltTri(ox, oy, P0, P1, P5);
    boltTri(ox, oy, P1, P2, P5);
    boltTri(ox, oy, P0, P5, P6);
    // Lower arm, the quad P2-P3-P4-P5 as two triangles.
    boltTri(ox, oy, P2, P3, P4);
    boltTri(ox, oy, P2, P4, P5);
}

fn boltTri(ox: i32, oy: i32, a: Point, b: Point, c: Point) void {
    gfx.fillTriangle(ox + a.x, oy + a.y, ox + b.x, oy + b.y, ox + c.x, oy + c.y, AMBER);
}

fn drawIntro() void {
    const x = contentX();
    var y = bodyY() + PAD_Y;

    // App mark: rounded slate tile with the bolt centred in it.
    gfx.fillRoundedRect(x, y, 56, 56, 13, 0x2B2E34);
    drawBolt(x - 2, y - 3);

    textBig(x + 74, y + 6, "Install ZigOS", INK);
    text(x + 74, y + 38, "x86_64  -  UEFI  -  ReleaseSafe", INK_DIM);
    y += 56 + 24;

    y = paragraph(x, y, contentW(), "This installer partitions a disk and creates the filesystems " ++
        "ZigOS boots from. Nothing is written until you confirm the layout.", INK_DIM);
    y += 12;

    gfx.fillRect(x, y, contentW(), 1, RULE_SOFT);
    y += 18;

    const items = [_]Bullet{
        .{ .n = "1", .head = "Choose a disk.", .body = "Every disk the kernel enumerated is listed; the ones it is already using are locked." },
        .{ .n = "2", .head = "Review the layout.", .body = "A GPT table with an EFI System Partition and an ext2 root." },
        .{ .n = "3", .head = "Write it.", .body = "The table goes down, both partitions are formatted, then everything is read back." },
    };
    for (items) |it| {
        textMono(x, y, it.n, ACCENT);
        text(x + 18, y, it.head, INK);
        const head_w = width16(it.head);
        y = paragraph(x + 18 + @as(i32, @intCast(head_w)) + 6, y, contentW() - 24 - head_w, it.body, INK_DIM);
        y += 6;
    }
}

// =============================================================================
// Screen 2 — destination
// =============================================================================

// The full row of MAX_DISKS cards must fit the content strip — the dev
// topology really does attach four disks, and at 168 px the fourth card ran
// past the panel edge. 4*140 + 3*10 lands flush on the 590 px strip.
const CARD_W: u32 = 140;
const CARD_H: u32 = 118;
const CARD_GAP: i32 = 10;

comptime {
    const row_w = MAX_DISKS * CARD_W + (MAX_DISKS - 1) * @as(u32, @intCast(CARD_GAP));
    if (row_w > PANE_W - 2 * @as(u32, @intCast(PAD_X)))
        @compileError("disk cards overflow the destination pane - shrink CARD_W/CARD_GAP");
}

fn diskCardRect(i: usize) Point {
    const stride = @as(i32, @intCast(CARD_W)) + CARD_GAP;
    return .{
        .x = contentX() + @as(i32, @intCast(i)) * stride,
        .y = bodyY() + PAD_Y + 62,
    };
}

fn drawDestination() void {
    const x = contentX();
    var y = bodyY() + PAD_Y;

    text(x, y, "Select the disk to install ZigOS on", INK);
    y += lineH() + 4;
    text(x, y, "The selected disk will be erased.", INK_DIM);

    if (disk_count == 0) {
        drawNotice(noticeY(), WARN_BG, WARN_INK, "No disks available. The install target is NVMe controller #3 - attach install.img and reboot.");
        return;
    }

    for (disks[0..disk_count], 0..) |d, i| {
        const r = diskCardRect(i);
        const sel = (i == selected);
        const usable = d.role.selectable();

        if (sel and usable) {
            gfx.fillRoundedRect(r.x, r.y, CARD_W, CARD_H, 9, ACCENT_WASH);
            gfx.drawRect(r.x, r.y, CARD_W, CARD_H, mix(ACCENT, PANE, 55));
        } else if (usable and hovered(r.x, r.y, CARD_W, CARD_H)) {
            gfx.fillRoundedRect(r.x, r.y, CARD_W, CARD_H, 9, MONO_BG);
        }

        // Locked disks are drawn in the faint ink throughout, so "you can't
        // pick this" is legible before you try.
        const ink = if (!usable) INK_FAINT else if (sel) ACCENT else INK;
        const dim = if (!usable) INK_FAINT else INK_DIM;

        drawDiskGlyph(r.x + @as(i32, @intCast(CARD_W / 2)) - 23, r.y + 16, dim);

        const name = fmt("nvme{d}", .{d.ctrl});
        aa.drawTextCentered(r.x, r.y + 58, CARD_W, name, ink, aa.getDefault16());
        aa.drawTextCentered(r.x, r.y + 78, CARD_W, fmt("{d} MiB", .{d.sectors / 2048}), dim, aa.getDefaultMono());
        aa.drawTextCentered(r.x, r.y + 94, CARD_W, d.role.note(), dim, aa.getDefaultMono());
    }

    // Explain the locks, since three of the four cards are usually locked.
    var locked: usize = 0;
    for (disks[0..disk_count]) |d| {
        if (!d.role.selectable()) locked += 1;
    }
    if (locked != 0) {
        drawNotice(noticeY(), MONO_BG, INK_DIM, "Disks the running kernel is already using cannot be targets - the boot archive, the live root and swap are all in use right now.");
    }
}

/// A 46x34 disk outline — the flat rectangle-with-slot look from the mockup.
fn drawDiskGlyph(x: i32, y: i32, color: u32) void {
    gfx.drawRect(x + 3, y + 6, 40, 22, color);
    gfx.drawRect(x + 10, y + 12, 26, 10, color);
    var i: i32 = 0;
    while (i < 3) : (i += 1) {
        const px = x + 14 + i * 9;
        gfx.fillRect(px, y + 2, 1, 4, color);
        gfx.fillRect(px, y + 28, 1, 4, color);
    }
}

/// The bottom-anchored callout used on several screens. Fixed at three lines
/// of body text plus padding — every message here is written to fit.
const NOTICE_H: u32 = 68;

fn drawNotice(y: i32, bg: u32, ink: u32, msg: []const u8) void {
    const x = contentX();
    const w = contentW();
    gfx.fillRoundedRect(x, y, w, NOTICE_H, 7, bg);
    _ = paragraph(x + 13, y + 11, w - 26, msg, ink);
}

/// Y of the bottom-anchored notice, so the three screens that use one agree.
fn noticeY() i32 {
    return bodyY() + @as(i32, BODY_H) - @as(i32, NOTICE_H) - 18;
}

// =============================================================================
// Screen 3 — partition layout
// =============================================================================

fn drawLayout() void {
    const x = contentX();
    const w = contentW();
    var y = bodyY() + PAD_Y;

    text(x, y, "Partition layout", INK);
    y += lineH() + 4;
    text(x, y, fmt("ZigOS will write a GPT table to nvme{d} with two partitions.", .{disks[selected].ctrl}), INK_DIM);
    y += lineH() + 18;

    // Proportional bar. The ESP is a fixed 64 MiB and the root takes the rest,
    // so on a large disk the amber sliver is genuinely that small.
    const total = (esp_end - esp_start + 1) + (root_end - root_start + 1);
    const esp_share = (esp_end - esp_start + 1) * @as(u64, w) / total;
    // Floor the amber segment so the label still fits: on a large disk a 64 MiB
    // ESP is a two-pixel sliver, and a bar with an invisible segment reads as
    // one partition.
    const esp_w: u32 = @intCast(@max(@as(u64, 48), esp_share));
    gfx.fillRect(x, y, esp_w, 34, AMBER);
    gfx.fillRect(x + @as(i32, @intCast(esp_w)), y, w - esp_w, 34, ACCENT);
    gfx.drawRect(x, y, w, 34, RULE);
    aa.drawTextCentered(x, y + 9, esp_w, "ESP", 0x402A02, aa.getDefaultMono());
    aa.drawTextCentered(x + @as(i32, @intCast(esp_w)), y + 9, w - esp_w, "ZIGOS - ext2", 0xFFFFFF, aa.getDefaultMono());
    y += 34 + 20;

    // Table. Columns are laid out by hand — five of them, fixed.
    const col = [_]i32{ 0, 34, 150, 240, 330, 430 };
    const heads = [_][]const u8{ "#", "NAME", "TYPE", "SIZE", "FIRST LBA", "LAST LBA" };
    for (heads, 0..) |hname, i| {
        text(x + col[i], y, hname, INK_FAINT);
    }
    y += lineH() + 6;
    gfx.fillRect(x, y, w, 1, RULE_SOFT);
    y += 8;

    const rows = [_]Row{
        .{ .n = "1", .name = "EFI System", .kind = "FAT32", .first = esp_start, .last = esp_end },
        .{ .n = "2", .name = "ZIGOS", .kind = "ext2", .first = root_start, .last = root_end },
    };
    for (rows) |r| {
        textMono(x + col[0], y, r.n, INK);
        text(x + col[1], y, r.name, INK_DIM);
        textMono(x + col[2], y, r.kind, INK_DIM);
        textMono(x + col[3], y, fmt("{d} MiB", .{(r.last - r.first + 1) / 2048}), INK_DIM);
        textMono(x + col[4], y, fmt("{d}", .{r.first}), INK_DIM);
        textMono(x + col[5], y, fmt("{d}", .{r.last}), INK_DIM);
        y += lineH() + 6;
        gfx.fillRect(x, y - 3, w, 1, RULE_SOFT);
    }

    drawNotice(noticeY(), WARN_BG, WARN_INK, fmt("Everything on nvme{d} will be lost. Click Install to begin writing.", .{disks[selected].ctrl}));
}

// =============================================================================
// Screen 4 — installing
// =============================================================================

fn drawInstalling() void {
    const x = contentX();
    const w = contentW();
    var y = bodyY() + PAD_Y;

    text(x, y, if (phase == .failed) "Installation stopped" else "Installing ZigOS", INK);
    y += lineH() + 20;

    // Progress. Completed phases over total — no time estimate, because we
    // have no basis for one and a wrong "2 minutes remaining" is a lie the
    // user can check.
    const done_count: u32 = @min(phases_done, PHASE_COUNT);
    const pct: u32 = done_count * 100 / PHASE_COUNT;
    gfx.fillRoundedRect(x, y, w, 7, 4, mix(INK_FAINT, PANE, 74));
    if (pct != 0) {
        gfx.fillRoundedRect(x, y, w * pct / 100, 7, 4, if (phase == .failed) FAIL else ACCENT);
    }
    y += 7 + 9;

    const status = switch (phase) {
        .complete => "All steps finished.",
        .failed => fail_reason,
        // Live totals while the tree streams across — the one phase whose
        // duration the user would otherwise have to take on faith.
        .copy_root => fmt("Copying the system - {d} files, {d} MiB", .{ populate.stats.files, populate.stats.bytes / (1024 * 1024) }),
        else => phase.label(),
    };
    text(x, y, status, if (phase == .failed) FAIL else INK_DIM);
    const pct_s = fmt("{d}%", .{pct});
    text(x + @as(i32, @intCast(w - width16(pct_s))), y, pct_s, INK_DIM);
    y += lineH() + 16;

    // Log. Always open — this screen has nothing else to show, and the whole
    // reason to watch an installer is to see what it is doing.
    const log_h: u32 = @intCast(@as(i32, @intCast(LOG_LINES)) * (lineH() - 2) + 20);
    gfx.fillRoundedRect(x, y, w, log_h, 7, MONO_BG);
    gfx.drawRect(x, y, w, log_h, RULE_SOFT);
    var ly = y + 10;
    var i: usize = 0;
    while (logVisible(i)) |line| : (i += 1) {
        // The tag in brackets is colored, the message is not — same shape the
        // serial log has, so the two read alike.
        var ink = INK_DIM;
        if (line.len > 2 and line[0] == '[') ink = INK_DIM;
        if (std.mem.startsWith(u8, line, "ok ")) ink = OK;
        if (std.mem.startsWith(u8, line, "FAIL")) ink = FAIL;
        textMono(x + 12, ly, line, ink);
        ly += lineH() - 2;
    }
}

// =============================================================================
// Screen 5 — restart
// =============================================================================

fn drawDone() void {
    const x = contentX();
    const w = contentW();
    var y = bodyY() + 44;

    const cx = x + @as(i32, @intCast(w / 2));
    gfx.drawFilledCircle(cx, y + 29, 29, mix(OK, PANE, 84));
    gfx.drawThickLineAA(cx - 13, y + 29, cx - 4, y + 38, 3, OK);
    gfx.drawThickLineAA(cx - 4, y + 38, cx + 14, y + 20, 3, OK);
    y += 58 + 22;

    aa.drawTextCentered(x, y, w, "Installation complete", INK, aa.getDefault24());
    y += 40;

    y = paragraphCentered(x, y, w, fmt("nvme{d} now carries the full system: {d} files ({d} MiB) on the ext2 root, BOOTX64.EFI and the kernel on the EFI System Partition.", .{ disks[selected].ctrl, populate.stats.files, populate.stats.bytes / (1024 * 1024) }), INK_DIM);
    y += 16;

    if (boot_entry_slot) |slot| {
        _ = paragraphCentered(x, y, w, fmt("Firmware entry Boot{X:0>4} points at the new disk. Restart to boot it.", .{slot}), INK_DIM);
    } else {
        // Honest about the one step that didn't land: no fake certainty
        // about NVRAM, but no false alarm either — the fallback path is
        // what most firmware boots removable disks through anyway.
        gfx.fillRoundedRect(x + 40, y, w - 80, 58, 7, WARN_BG);
        _ = paragraph(x + 54, y + 12, w - 108, "No firmware boot entry was written (runtime services unreachable). The disk still boots through its \\EFI\\BOOT\\BOOTX64.EFI fallback path.", WARN_INK);
    }
}

/// Centred paragraph. Same wrapper as `paragraph` but each line is centred in
/// the box, which is what the final screen wants and nothing else does.
fn paragraphCentered(x: i32, y: i32, max_w: u32, s: []const u8, color: u32) i32 {
    const atlas = aa.getDefault16();
    var line_y = y;
    var start: usize = 0;
    var last_space: ?usize = null;
    var i: usize = 0;
    while (i <= s.len) : (i += 1) {
        if (i < s.len and s[i] != ' ') continue;
        if (atlas.measure(s[start..i]) > max_w) {
            if (last_space) |sp| {
                aa.drawTextCentered(x, line_y, max_w, s[start..sp], color, atlas);
                line_y += lineH();
                start = sp + 1;
                last_space = if (i > start) i else null;
                continue;
            }
        }
        if (i < s.len) last_space = i;
    }
    if (start < s.len) {
        aa.drawTextCentered(x, line_y, max_w, s[start..], color, atlas);
        line_y += lineH();
    }
    return line_y;
}

// =============================================================================
// Cursor
// =============================================================================

const CURSOR_W: u32 = 12;
const CURSOR_H: u32 = 16;

/// The desktop's arrow (1 = black outline, 2 = white fill), same pixels as
/// ui/desktop.zig's cursor_sprite. Duplicated rather than imported: pulling
/// desktop.zig into the forced -Dboot-mode builds' module set would reshuffle
/// bitcode emission order, and that is the dice roll behind the LLVM
/// "Invalid type" linker fault. Keep the two arrays in sync by hand.
const cursor_sprite = [CURSOR_H][CURSOR_W]u8{
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 0 },
    .{ 1, 2, 2, 1, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
};

/// Drawn last each frame into the back buffer, so there is no save/restore
/// to get wrong.
fn drawCursor() void {
    for (0..CURSOR_H) |row| {
        for (0..CURSOR_W) |col| {
            const pixel = cursor_sprite[row][col];
            if (pixel == 0) continue;
            const color: u32 = if (pixel == 1) 0x000000 else 0xFFFFFF;
            gfx.putPixel(mouse.x + @as(i32, @intCast(col)), mouse.y + @as(i32, @intCast(row)), color);
        }
    }
}

// =============================================================================
// Frame
// =============================================================================

fn render() void {
    drawBackground(gfx.target_w, gfx.target_h);
    drawPanelShadow();

    gfx.fillRoundedRect(panel_x, panel_y, PANEL_W, PANEL_H, 11, CHROME);
    gfx.fillRect(paneX(), bodyY(), PANE_W, BODY_H, PANE);

    drawTitlebar();
    drawSidebar();

    switch (screen) {
        .intro => drawIntro(),
        .destination => drawDestination(),
        .layout => drawLayout(),
        .installing => drawInstalling(),
        .done => drawDone(),
    }

    drawFooter();
    drawCursor();

    gfx.blitToScreen();
    display.flush();
}

// =============================================================================
// Navigation
// =============================================================================

fn advance() void {
    switch (screen) {
        .intro => {
            screen = .destination;
            // Land the selection on something usable rather than on card 0,
            // which is the boot archive and can never be chosen.
            for (disks[0..disk_count], 0..) |d, i| {
                if (d.role.selectable()) {
                    selected = i;
                    break;
                }
            }
        },
        .destination => {
            if (!computeLayout()) return;
            screen = .layout;
        },
        .layout => {
            screen = .installing;
            phase = .write_gpt;
            log_total = 0;
            copy_started = false;
            boot_entry_slot = null;
            logLine("target nvme{d}: {d} sectors ({d} MiB)", .{ disks[selected].ctrl, disks[selected].sectors, disks[selected].sectors / 2048 });
        },
        .installing => {},
        .done => reboot(),
    }
    dirty = true;
}

fn goBack() void {
    screen = switch (screen) {
        .layout => .destination,
        .destination => .intro,
        else => screen,
    };
    dirty = true;
}

/// Work out where the two partitions go on the selected disk. Returns false
/// (and logs why) when the disk cannot hold the layout, which is the one case
/// where Continue must not move.
fn computeLayout() bool {
    const d = disks[selected];
    // 64 MiB ESP: the conventional size, and comfortably above the FAT32
    // cluster-count floor — see the trap documented in fs/fat32_mkfs.zig.
    esp_start = gpt.alignUp(gpt.FIRST_USABLE_LBA);
    esp_end = esp_start + 64 * 2048 - 1;
    root_start = esp_end + 1;
    // Leave the backup entry array plus its header at the tail, then pull the
    // end back to an alignment boundary.
    root_end = gpt.alignEndDown(d.sectors - 1 - gpt.ENTRY_ARRAY_SECTORS - 1);

    if (esp_end >= d.sectors or root_start >= root_end) {
        fail_reason = "Disk is too small for a 64 MiB ESP plus a root.";
        screen = .installing;
        phase = .failed;
        logLine("FAIL: nvme{d} too small ({d} sectors)", .{ d.ctrl, d.sectors });
        return false;
    }
    return true;
}

/// Restart the machine. The only exit an installer has, and the first caller
/// in the tree to need one — `acpi.tryReset` was written for this and had no
/// users. Each mechanism falls through to the next on failure; the last one
/// cannot fail, because a null IDT plus an interrupt is a triple fault and the
/// CPU has no choice.
fn reboot() noreturn {
    serial.print("[installer] restart requested\n", .{});
    acpi.tryReset();

    // PCI reset control: set SYS_RST | RST_CPU.
    io.outb(0xCF9, 0x02);
    io.outb(0xCF9, 0x06);

    // 8042 pulse of the CPU reset line. Wait for the input buffer to drain
    // first, or the controller drops the command.
    var d = @import("../util/deadline.zig").Deadline.ms(10, "kbd-ctrl reboot drain");
    while (d.live()) {
        if (io.inb(0x64) & 0x02 == 0) break;
    }
    io.outb(0x64, 0xFE);

    // Triple fault.
    const null_idt = [_]u8{0} ** 10;
    asm volatile (
        \\lidt (%[p])
        \\int $3
        :
        : [p] "r" (&null_idt),
    );
    while (true) asm volatile ("hlt");
}

// =============================================================================
// The install itself — one phase per call, so the caller can paint between them
// =============================================================================

fn stepInstall() void {
    const dev = block.targetDevice() orelse {
        fail("The install target disk went away.");
        return;
    };

    switch (phase) {
        .write_gpt => {
            const specs = [_]gpt.PartSpec{
                .{ .type_guid = gpt.TYPE_ESP, .start_lba = esp_start, .end_lba = esp_end, .name = "EFI System" },
                .{ .type_guid = gpt.TYPE_LINUX_DATA, .start_lba = root_start, .end_lba = root_end, .name = "ZIGOS" },
            };
            logLine("[gpt] ESP  {d}..{d}", .{ esp_start, esp_end });
            logLine("[gpt] root {d}..{d}", .{ root_start, root_end });
            if (!gpt.create(dev, &specs)) {
                fail("Writing the partition table failed. See the serial log.");
                return;
            }
            logLine("ok   protective MBR, both headers, both entry arrays", .{});
            finished(.reread_gpt);
        },

        .reread_gpt => {
            table = gpt.parse(dev) catch {
                fail("We wrote a partition table our own parser rejects.");
                return;
            };
            if (table.from_backup) {
                fail("The primary header was unreadable; parse fell back to the backup.");
                return;
            }
            if (table.count != 2) {
                fail("The partition count changed across the round trip.");
                return;
            }
            for (table.parts[0..table.count]) |p| {
                logLine("[gpt] part {d} {d}..{d} \"{s}\"", .{ p.index + 1, p.start_lba, p.end_lba, p.name[0..p.name_len] });
            }
            logLine("ok   table re-read and matches", .{});
            finished(.mkfs_esp);
        },

        .mkfs_esp => {
            const p = table.parts[0];
            if (!p.isEsp()) {
                fail("Partition 1 did not come back as an EFI System Partition.");
                return;
            }
            if (!fat_mkfs.format(.{
                .dev = dev,
                .part_lba = @intCast(p.start_lba),
                .part_sectors = @intCast(p.sectorCount()),
            }, "ZIGOS ESP")) {
                fail("mkfs.fat32 failed. See the serial log.");
                return;
            }
            logLine("ok   FAT32 on partition 1 ({d} MiB)", .{p.sectorCount() / 2048});
            finished(.mkfs_root);
        },

        .mkfs_root => {
            const p = table.parts[1];
            if (!ext2_mkfs.format(.{
                .dev = dev,
                .part_lba = @intCast(p.start_lba),
                .part_sectors = @intCast(p.sectorCount()),
            }, "ZIGOS")) {
                fail("mkfs.ext2 failed. See the serial log.");
                return;
            }
            logLine("ok   ext2 on partition 2 ({d} MiB)", .{p.sectorCount() / 2048});
            finished(.copy_root);
        },

        .copy_root => {
            if (!copy_started) {
                const p = table.parts[1];
                const target_mount = populate.ensureWorkingSet() orelse {
                    fail("Out of memory for the copy working set.");
                    return;
                };
                if (!ext2_blk.mountAt(target_mount, block.readSectorsTargetU16, block.writeSectorsTargetU16, @intCast(p.start_lba))) {
                    fail("Mounting the freshly-formatted root failed.");
                    return;
                }
                if (!populate.copyBegin(target_mount)) {
                    fail("The live root is not mounted; nothing to copy from.");
                    return;
                }
                copy_started = true;
                logLine("[copy] system tree -> nvme{d} part 2", .{disks[selected].ctrl});
                return; // paint the label before the long haul
            }
            // A slice of the copy per frame: enough entries that the whole
            // tree lands in a few hundred frames, few enough that the screen
            // stays alive. ~2 MiB or 24 entries, whichever comes first.
            const start_bytes = populate.stats.bytes;
            var steps: u32 = 0;
            while (steps < 24 and populate.stats.bytes - start_bytes < 2 * 1024 * 1024) : (steps += 1) {
                switch (populate.copyStep()) {
                    .more => {},
                    .failed => {
                        fail("Copying the system failed. See the serial log.");
                        return;
                    },
                    .done => {
                        logLine("ok   {d} files, {d} dirs, {d} MiB copied", .{ populate.stats.files, populate.stats.dirs, populate.stats.bytes / (1024 * 1024) });
                        finished(.install_boot);
                        return;
                    },
                }
            }
        },

        .install_boot => {
            const p = table.parts[0];
            var esp = fat_pop.open(dev, @intCast(p.start_lba)) orelse {
                fail("Re-opening the fresh ESP failed.");
                return;
            };
            const efi_name = fat_pop.name83("EFI");
            const efi_dir = fat_pop.addDir(&esp, esp.root_cluster, &efi_name) orelse {
                fail("Creating \\EFI on the ESP failed.");
                return;
            };
            const boot_name = fat_pop.name83("BOOT");
            const boot_dir = fat_pop.addDir(&esp, efi_dir, &boot_name) orelse {
                fail("Creating \\EFI\\BOOT on the ESP failed.");
                return;
            };
            if (!espCopyFile(&esp, "boot/BOOTX64.EFI", boot_dir, "BOOTX64.EFI")) {
                fail("Writing BOOTX64.EFI to the ESP failed.");
                return;
            }
            if (!espCopyFile(&esp, "boot/kernel.elf", esp.root_cluster, "KERNEL.ELF")) {
                fail("Writing kernel.elf to the ESP failed.");
                return;
            }
            if (!fat_pop.finalize(&esp)) {
                fail("Updating the ESP's FSInfo failed.");
                return;
            }
            logLine("ok   \\EFI\\BOOT\\BOOTX64.EFI + \\kernel.elf on the ESP", .{});
            finished(.boot_entry);
        },

        .boot_entry => {
            const p = table.parts[0];
            if (uefi_nvram.addBootEntry("ZigOS", .{
                .partition_number = p.index + 1,
                .partition_start = p.start_lba,
                .partition_sectors = p.sectorCount(),
                .partition_guid = p.unique_guid,
            })) |slot| {
                boot_entry_slot = slot;
                logLine("ok   firmware entry Boot{X:0>4}, first in BootOrder", .{slot});
            } else {
                // Non-fatal by design: the \EFI\BOOT fallback path boots the
                // disk on any firmware, entry or no entry.
                logLine("[nvram] entry not written - \\EFI\\BOOT fallback still boots this disk", .{});
            }
            finished(.verify);
        },

        .verify => {
            if (!verifySignatures(dev)) return;
            logLine("ok   installation steps complete", .{});
            finished(.complete);
        },

        .complete, .failed => {},
    }
}

/// Record one phase as done and move to the next.
fn finished(next: Phase) void {
    phases_done += 1;
    phase = next;
}

fn fail(reason: []const u8) void {
    fail_reason = reason;
    phase = .failed;
    logLine("FAIL {s}", .{reason});
}

/// Stream one file from the live root into the target ESP, through the same
/// PMM-backed bounce buffer the copy phase used (the copy is finished by the
/// time this runs). `src_path` is an ext2 path without a leading slash
/// ("boot/BOOTX64.EFI"); `dst_name` must fit 8.3, which everything this
/// installer writes does.
fn espCopyFile(esp: *fat_pop.Esp, src_path: []const u8, dir_cluster: u32, dst_name: []const u8) bool {
    const buf = populate.copy_buf;
    if (buf.len == 0) return false; // working set never armed — can't happen after copy_root
    var h = ext2.openFile(src_path) orelse {
        logLine("FAIL {s} missing from the live root", .{src_path});
        return false;
    };
    defer ext2.closeFile(h);
    var writer = fat_pop.beginFile(esp);
    while (true) {
        const got = ext2.readFile(h, buf.ptr, @intCast(buf.len));
        if (got == 0) break;
        h.current_offset += got;
        if (!fat_pop.appendData(esp, &writer, buf[0..got])) return false;
    }
    if (writer.size != h.file_size) {
        logLine("FAIL {s}: {d} of {d} bytes read", .{ src_path, writer.size, h.file_size });
        return false;
    }
    const nm = fat_pop.name83(dst_name);
    if (!fat_pop.endFile(esp, &writer, dir_cluster, &nm)) return false;
    logLine("[esp] {s} ({d} KiB)", .{ dst_name, writer.size / 1024 });
    return true;
}

/// Read back what each formatter claims to have written. A smoke test, not a
/// checker — the real oracles are the host's e2fsck and fsck.fat, which know
/// things we do not. This catches the case where a format writes to the wrong
/// LBA and reports success.
fn verifySignatures(dev: block.Device) bool {
    var buf: [512]u8 = undefined;

    const esp = table.parts[0];
    if (!dev.readSectors(@intCast(esp.start_lba), 1, &buf)) {
        fail("Reading the ESP boot sector back failed.");
        return false;
    }
    if (buf[510] != 0x55 or buf[511] != 0xAA) {
        fail("The ESP boot signature is missing.");
        return false;
    }
    logLine("[fat32] boot signature 0x55AA present", .{});

    // The ext2 superblock lives at byte 1024 of the partition — two sectors in.
    const root = table.parts[1];
    if (!dev.readSectors(@as(u32, @intCast(root.start_lba)) + 2, 1, &buf)) {
        fail("Reading the ext2 superblock back failed.");
        return false;
    }
    const magic = @as(u16, buf[56]) | (@as(u16, buf[57]) << 8);
    if (magic != ext2_layout.MAGIC) {
        fail("The ext2 magic is wrong.");
        return false;
    }
    const blocks = @as(u32, buf[4]) | (@as(u32, buf[5]) << 8) |
        (@as(u32, buf[6]) << 16) | (@as(u32, buf[7]) << 24);
    if (blocks == 0) {
        fail("The ext2 superblock reports zero blocks.");
        return false;
    }
    logLine("[ext2] magic 0xEF53, {d} blocks", .{blocks});
    return true;
}

// =============================================================================
// Input
// =============================================================================

fn pollInput() void {
    // Drain USB HID from the frame loop. Live input rides the xHCI MSI-X
    // inline drain, but the backstop for a dropped interrupt is ksoftirqd's
    // 10 Hz .hid raise — and the installer never calls process.schedule(),
    // so ksoftirqd never runs and softirq.raise(.hid) swallows the inline
    // fallback in irq0 too. Without this call a lost MSI-X leaves input
    // (and the typematic-gate reopen) dead for good. pollHID cli-serializes
    // itself and no-ops with nothing pending, so per-frame from the sole
    // task on the BSP is exactly the ksoftirqd calling convention.
    xhci.pollHID();

    const buttons = mouse.buttons;
    click = (buttons & 1) != 0 and (prev_buttons & 1) == 0;
    if (click) {
        click_x = mouse.x;
        click_y = mouse.y;
        dirty = true;
    }
    if (buttons != prev_buttons) dirty = true;
    prev_buttons = buttons;

    if (mouse.moved) {
        mouse.moved = false;
        dirty = true;
    }

    // Card selection. Handled here rather than in the draw pass so a click
    // both selects and repaints in the same frame.
    if (click and screen == .destination) {
        for (disks[0..disk_count], 0..) |d, i| {
            if (!d.role.selectable()) continue;
            const r = diskCardRect(i);
            if (inRect(click_x, click_y, r.x, r.y, CARD_W, CARD_H)) selected = i;
        }
    }

    // Close button quits to a reboot — the only exit an installer has.
    if (click and inRect(click_x, click_y, panel_x + 14, panel_y + 14, 12, 12)) reboot();

    while (keyboard.pop()) |ch| {
        dirty = true;
        switch (ch) {
            '\n', '\r' => if (primaryEnabled() and primaryLabel().len != 0) advance(),
            0x1B => goBack(),
            keyboard.KEY_LEFT => moveSelection(-1),
            keyboard.KEY_RIGHT => moveSelection(1),
            else => {},
        }
    }
}

fn moveSelection(delta: i32) void {
    if (screen != .destination or disk_count == 0) return;
    var i: i32 = @intCast(selected);
    var tries: usize = 0;
    while (tries < disk_count) : (tries += 1) {
        i += delta;
        if (i < 0) i = @as(i32, @intCast(disk_count)) - 1;
        if (i >= @as(i32, @intCast(disk_count))) i = 0;
        if (disks[@intCast(i)].role.selectable()) {
            selected = @intCast(i);
            return;
        }
    }
}

// =============================================================================
// Bring-up
// =============================================================================

/// Enumerate NVMe namespaces into the disk list. The role of each index is
/// fixed by the order the run scripts attach them, and is the same mapping
/// `block.TARGET_CTRL_IDX` encodes — see driver/block.zig.
fn enumerateDisks() void {
    disk_count = 0;
    const n = @min(nvme.controllerCount(), MAX_DISKS);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const sectors = nvme.namespaceSectors(i);
        if (sectors == 0) continue;
        disks[disk_count] = .{
            .ctrl = i,
            .sectors = sectors,
            .role = switch (i) {
                0 => .tarfs,
                1 => .root,
                2 => .swap,
                3 => .target,
                else => .unknown,
            },
        };
        serial.print("[installer] nvme{d}: {d} sectors, {s}\n", .{ i, sectors, disks[disk_count].role.note() });
        disk_count += 1;
    }
    for (disks[0..disk_count], 0..) |d, idx| {
        if (d.role.selectable()) {
            selected = idx;
            break;
        }
    }
}

pub fn taskEntry() callconv(.c) noreturn {
    // The desktop retires the legacy low identity map at this point; the
    // installer KEEPS it. UEFI Runtime Services live in that low firmware
    // map, the boot-entry step calls SetVariable at the very end of the
    // install, and uefi_nvram.rsCallable() gates on exactly this mapping —
    // dropping it would turn the NVRAM write into a silent no-op. SMAP still
    // goes on; the EFI calls wrap themselves in beginNonSmepCall.
    @import("../cpu/arch/protect.zig").enableSmapPerCpu();
    asm volatile ("sti");
    @import("../boot/boot_phase.zig").markComplete();
    // Deliberately NOT nvme.enableAsync(). Submit-and-yield wants a scheduler
    // with other runnable work to yield *to*; the installer is the only task
    // on the machine. The synchronous polled path is what the boot-16 disk
    // self-test exercises, and mkfs is the same code here.

    serial.print("\n[installer] === graphical installer ===\n", .{});
    run();
    unreachable;
}

fn run() noreturn {
    // Drop the boot console before the mode switch, exactly as desktop.run
    // does — otherwise late klog output lands in a text framebuffer that is
    // about to be scanned out as pixels.
    @import("boot_screen.zig").disable();
    @import("early_fb.zig").release();
    const vga = @import("vga.zig");
    vga.bg = .Black;
    vga.fg = .Black;
    vga.clear();
    vga.available = false;

    const so = scanout.bringUp() orelse {
        serial.print("[installer] FATAL: no display available\n", .{});
        while (true) asm volatile ("hlt");
    };

    // Back-buffer policy. A deferred framebuffer only reaches the panel on
    // flush, so it is already a back buffer; a live one needs a separate
    // target or the full-screen repaint tears.
    if (so.deferred) {
        gfx.useFramebuffer();
    } else {
        const pages = (so.width * so.height * 4 + 4095) / 4096;
        if (paging.allocBackBuffer(pages)) |buf| {
            gfx.setTarget(buf, so.width, so.height);
        } else {
            serial.print("[installer] WARNING: no back buffer, expect tearing\n", .{});
            gfx.useFramebuffer();
        }
    }

    panel_x = @intCast((gfx.target_w -| PANEL_W) / 2);
    panel_y = @intCast((gfx.target_h -| PANEL_H) / 2);

    mouse.screen_w = @intCast(so.width);
    mouse.screen_h = @intCast(so.height);
    mouse.x = @intCast(so.width / 2);
    mouse.y = @intCast(so.height / 2);
    if (!xhci.hasUsbMouse()) {
        if (!mouse.init()) serial.print("[installer] PS/2 mouse not detected - keyboard only\n", .{});
        keyboard.reEnable();
    }

    aa.ensureLoaded();
    enumerateDisks();

    while (true) {
        pollInput();

        if (dirty) {
            render();
            dirty = false;
        }

        // One install phase per frame, after the paint. The label for the step
        // about to run is already on screen when the blocking write starts.
        if (screen == .installing) {
            switch (phase) {
                .complete => {
                    screen = .done;
                    dirty = true;
                },
                .failed => {},
                else => {
                    stepInstall();
                    dirty = true;
                },
            }
        }

        // Park until the next interrupt — timer at 100 Hz, or sooner on mouse
        // and keyboard IRQs. Nothing else runs on this machine to yield to.
        asm volatile ("hlt");
    }
}
