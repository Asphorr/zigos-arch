// Pinned-app manifest — single source of truth for the apps that appear
// both as desktop icons (renderDesktopIcons) and in the dock pill
// (renderDock). Edit this list to add/remove pinned apps; both surfaces
// pick up the change.
//
// `cmd == ""` means "open a Terminal window" (special-cased by
// launchShortcut). For everything else `cmd` is the absolute ELF path
// passed to smp.requestAppLoad.

const icons = @import("../icons.zig");

pub const Shortcut = struct {
    name: []const u8,
    cmd: []const u8,
    icon: *const [16][16]u32,
};

pub const list = [_]Shortcut{
    .{ .name = "Terminal", .cmd = "", .icon = &icons.terminal },
    .{ .name = "Paint", .cmd = "/bin/paint.elf", .icon = &icons.paint },
    .{ .name = "Calc", .cmd = "/bin/calc.elf", .icon = &icons.calc },
    .{ .name = "Files", .cmd = "/bin/files.elf", .icon = &icons.folder },
    .{ .name = "Settings", .cmd = "/bin/settings.elf", .icon = &icons.settings },
    .{ .name = "Monitor", .cmd = "/bin/sysmon.elf", .icon = &icons.monitor },
    .{ .name = "Editor", .cmd = "/bin/editor.elf", .icon = &icons.editor },
    .{ .name = "Photo", .cmd = "/bin/photo.elf", .icon = &icons.photo },
    .{ .name = "Wallpaper", .cmd = "/bin/wallpaper.elf", .icon = &icons.wallpaper },
    .{ .name = "Sigil", .cmd = "/bin/sigil.elf", .icon = &icons.sigil },
    .{ .name = "Telegram", .cmd = "/bin/tg.elf", .icon = &icons.tg },
    .{ .name = "Doom", .cmd = "/bin/doom_real.elf", .icon = &icons.doom },
};

/// Subset of `list` indices that appear permanently in the dock. The
/// desktop sidebar shows the full launcher (all of `list`); the dock is
/// reserved for the "system tray" of always-useful tools plus the running
/// windows. Keeps the two surfaces from being identical lists shown twice.
///
/// Indices are into `list` above, so launching and tooltip lookup paths
/// don't need any extra indirection.
pub const dock_indices = [_]u8{
    0, // Terminal
    3, // Files
    4, // Settings
    5, // Monitor
};
