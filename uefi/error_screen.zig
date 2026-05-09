// Graphical error screen for fatal failures during kernel load, before
// the bootloader hands off. Same chrome aesthetic as `src/debug/panic_screen.zig`
// (kernel-side) — title bar with severity badge, info section, what-to-do
// steps, footer — but rendered via the bootloader's own `aa_font` +
// `layout` so nothing depends on the kernel module graph.
//
// Why graphical: previously a missing `kernel.elf` or a bad ELF header
// produced a `serialPrint(...)` and `return .aborted`, which on most
// firmware drops to a black screen or a default "boot device not found"
// dialog. Users without serial access had no signal beyond "QEMU froze".
// This screen makes the failure mode obvious + tells the user what to do
// (rebuild ESP, switch to Multiboot, etc.).
//
// Halts via `hlt` after rendering, polling for `space`/`Enter` to reset
// the machine if RuntimeServices is available — UEFI spec mandates
// runtime_services so this should always work.

const std = @import("std");
const uefi = std.os.uefi;
const GraphicsOutput = uefi.protocol.GraphicsOutput;
const SimpleTextInput = uefi.protocol.SimpleTextInput;
const RuntimeServices = uefi.tables.RuntimeServices;
const aa = @import("aa_font");
const layout = @import("layout.zig");

pub const Step = enum {
    no_filesystem,
    open_volume,
    open_kernel_file,
    read_elf_header,
    invalid_elf_magic,
    invalid_elf_class,
    no_kmain_symbol,
    memory_map,
    exit_boot_services,
};

const COLOR_BG: u32 = 0x00080010;
const COLOR_PANEL: u32 = 0x001A1424;
const COLOR_BORDER_OUT: u32 = 0x00603038;
const COLOR_BORDER_IN: u32 = 0x00301820;
const COLOR_TITLE: u32 = 0x00FFCEC8;
const COLOR_TEXT: u32 = 0x00E0DEEC;
const COLOR_DIM: u32 = 0x008A788C;
const COLOR_ACCENT: u32 = 0x00FF7A50;
const COLOR_BAD: u32 = 0x00E84030;
const COLOR_CODE: u32 = 0x00B8D8FF;
const COLOR_BADGE_BG: u32 = 0x00C03028;
const COLOR_BADGE_TEXT: u32 = 0x00FFE8E0;

fn fillRect(fb: aa.Fb, x: u32, y: u32, w: u32, h: u32, color: u32) void {
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

fn drawBorder(fb: aa.Fb, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    fillRect(fb, x, y, w, 1, color);
    if (h >= 2) fillRect(fb, x, y + h - 1, w, 1, color);
    fillRect(fb, x, y, 1, h, color);
    if (w >= 2) fillRect(fb, x + w - 1, y, 1, h, color);
}

fn stepLabel(step: Step) []const u8 {
    return switch (step) {
        .no_filesystem => "no UEFI SimpleFileSystem on the boot device",
        .open_volume => "could not openVolume() on the ESP",
        .open_kernel_file => "/kernel.elf is missing or unreadable",
        .read_elf_header => "could not read /kernel.elf header (truncated file?)",
        .invalid_elf_magic => "/kernel.elf doesn't have a valid ELF magic (0x7F 'E' 'L' 'F')",
        .invalid_elf_class => "/kernel.elf is the wrong ELF class (must be ELF64 little-endian, x86_64)",
        .no_kmain_symbol => "kernel ELF has no `kmain_uefi` symbol — bootloader can't pick an entry point",
        .memory_map => "UEFI getMemoryMap() failed — firmware is in a bad state",
        .exit_boot_services => "ExitBootServices() failed — firmware refused the handoff",
    };
}

fn stepHints(step: Step) []const []const u8 {
    return switch (step) {
        .no_filesystem, .open_volume => &.{
            "Boot device wasn't a partitioned disk with a FAT32 ESP.",
            "Run `sudo zig build esp` on the host to rebuild esp.img.",
            "Verify QEMU's `-drive file=...esp.img,if=ide` flag is right.",
        },
        .open_kernel_file => &.{
            "Run `zig build` then `sudo zig build esp` to refresh the ESP.",
            "Verify /EFI/BOOT/BOOTX64.EFI and /kernel.elf are both present.",
            "OVMF caches the FAT root — try `cp .../OVMF_VARS_4M.fd ovmf_vars.fd`.",
        },
        .read_elf_header, .invalid_elf_magic, .invalid_elf_class => &.{
            "The on-disk kernel.elf is corrupt or wrong-arch.",
            "Did `objcopy` strip too aggressively? (we only generate kernel32.elf for Multiboot.)",
            "`file zig-out/bin/kernel.elf` should report ELF 64-bit LSB executable, x86-64.",
        },
        .no_kmain_symbol => &.{
            "The kernel was built without `pub fn kmain_uefi(...)` exported.",
            "Check src/main.zig wasn't compiled with --strip or symbol-stripping.",
            "Try `zig build clean && zig build` to force a full rebuild.",
        },
        .memory_map, .exit_boot_services => &.{
            "Try a warm reset (Esc → resetSystem). Some OVMF builds leak memory descriptors.",
            "If the failure is reproducible, capture serial.log and file an issue.",
        },
    };
}

fn drawSeverityBadge(fb: aa.Fb, x: u32, y: u32, str: []const u8) u32 {
    const tw = aa.default_16.measure(str);
    const w = tw + 16;
    const h = aa.default_16.line_height + 6;
    fillRect(fb, x, y, w, h, COLOR_BADGE_BG);
    aa.drawText(fb, @intCast(x + 8), @intCast(y + 3), str, COLOR_BADGE_TEXT, &aa.default_16);
    return w;
}

/// Render a fatal-load error and halt. Polls keyboard for space/Enter to
/// trigger a warm reset via RuntimeServices, since the bootloader can't
/// recover and continuing into a broken kernel would just triple-fault.
pub fn show(
    gop_opt: ?*GraphicsOutput,
    stin_opt: ?*SimpleTextInput,
    rs: *RuntimeServices,
    step: Step,
    detail: []const u8,
) noreturn {
    aa.ensureLoaded();

    if (gop_opt) |gop| {
        const mode = gop.mode;
        const info = mode.info;
        const fb = aa.Fb{
            .base = @ptrFromInt(@as(usize, @intCast(mode.frame_buffer_base))),
            .stride = info.pixels_per_scan_line,
            .w = info.horizontal_resolution,
            .h = info.vertical_resolution,
        };

        // Background + centered panel.
        fillRect(fb, 0, 0, fb.w, fb.h, COLOR_BG);
        const panel_w: u32 = 800;
        const panel_h: u32 = 460;
        const panel_x = (fb.w -| panel_w) / 2;
        const panel_y = (fb.h -| panel_h) / 2;

        fillRect(fb, panel_x + 6, panel_y + 6, panel_w, panel_h, 0x00040208);
        fillRect(fb, panel_x, panel_y, panel_w, panel_h, COLOR_PANEL);
        drawBorder(fb, panel_x, panel_y, panel_w, panel_h, COLOR_BORDER_OUT);
        drawBorder(fb, panel_x + 1, panel_y + 1, panel_w - 2, panel_h - 2, COLOR_BORDER_IN);

        // Title row — severity badge + headline.
        const title_y: u32 = panel_y + 18;
        const title_x: u32 = panel_x + 24;
        const badge_w = drawSeverityBadge(fb, title_x, title_y, "FATAL");
        aa.drawText(fb, @intCast(title_x + badge_w + 12), @intCast(title_y + 4), "Kernel load failed", COLOR_TITLE, &aa.default_24);

        // Accent rule under the title.
        fillRect(fb, panel_x + 24, panel_y + 60, panel_w - 48, 1, COLOR_ACCENT);

        // Body — VStack inside the panel for what-failed + hints.
        var body = layout.VStack.init(fb, panel_x, panel_y + 70, panel_w);

        body.gap(0);
        body.kvRow(40, "Step:", COLOR_DIM, 130, stepLabel(step), COLOR_BAD, &aa.default_16);
        if (detail.len > 0) {
            body.kvRow(40, "Detail:", COLOR_DIM, 130, detail, COLOR_CODE, &aa.default_16);
        }
        body.gap(14);
        body.kvRow(40, "Why this matters:", COLOR_DIM, 0, "", COLOR_DIM, &aa.default_16);
        body.gap(2);
        // The body kvRow leaves cursor advanced; replace it for the
        // explanation line — we want left-aligned plain text below the
        // header line, not a kv pair.
        const expl: []const u8 = "The bootloader can't continue without a valid kernel.elf.";
        aa.drawText(fb, @intCast(panel_x + 40), @intCast(body.cursor() - aa.default_16.line_height + 18), expl, COLOR_TEXT, &aa.default_16);
        body.gap(20);

        // What to try — heading + bullet list.
        aa.drawText(fb, @intCast(panel_x + 40), @intCast(body.cursor()), "What to try:", COLOR_DIM, &aa.default_16);
        body.gap(aa.default_16.line_height + 4);
        for (stepHints(step)) |hint| {
            aa.drawText(fb, @intCast(panel_x + 60), @intCast(body.cursor()), "•", COLOR_ACCENT, &aa.default_16);
            aa.drawText(fb, @intCast(panel_x + 80), @intCast(body.cursor()), hint, COLOR_TEXT, &aa.default_16);
            body.gap(aa.default_16.line_height + 2);
        }

        // Footer hint — anchored to panel bottom.
        const footer_y = panel_y + panel_h - aa.default_16.line_height - 14;
        fillRect(fb, panel_x + 40, footer_y - 8, panel_w - 80, 1, COLOR_BORDER_OUT);
        aa.drawText(fb, @intCast(panel_x + 24), @intCast(footer_y), "press [space] or [Enter] to warm-reset, [Esc] to halt", COLOR_DIM, &aa.default_16);
    }

    // Halt + poll for reset/halt key. RuntimeServices.resetSystem returns
    // EFI_INVALID_PARAMETER on some firmware if data_size is wrong; we
    // pass 0 (no extra data) which is valid for warm/cold/shutdown.
    if (stin_opt) |stin| {
        while (true) {
            if (stin.readKeyStroke()) |key| {
                if (key.unicode_char == 0x0D or key.unicode_char == 0x0A or key.unicode_char == ' ') {
                    rs.resetSystem(.warm, .aborted, null);
                }
                if (key.scan_code == 0x17) {
                    // Esc — fall through to hlt loop
                    break;
                }
            } else |_| {}
            asm volatile ("hlt");
        }
    }
    while (true) asm volatile ("hlt");
}
