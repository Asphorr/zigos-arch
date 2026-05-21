// Files — directory browser with folder navigation, AA fonts, and a path bar.
//
// Renders the cwd with one row per entry. Folders are double-click-into,
// regular files are double-click-to-launch (`.elf`) or open-in-editor.
// `..` row at the top of every non-root listing for parent navigation; an
// "Up" button in the toolbar does the same. Status bar tracks file count
// and the selected entry.
//
// Visual idiom mirrors the UEFI menu / About panel: SF Pro Text 16 body,
// SF Pro Display 24 title, dark "card" palette with subtle borders, colored
// icon chips per file type. The whole window redraws on selection or path
// change — directories are small, so no diff'ing.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");

// --- Palette (mirrors UEFI menu / About) ---
const COLOR_BG: u32 = 0x141826;
const COLOR_PANEL: u32 = 0x1C2032;
const COLOR_PANEL_ALT: u32 = 0x222640;
const COLOR_BORDER_OUT: u32 = 0x2E3450;
const COLOR_BORDER_IN: u32 = 0x171A28;
const COLOR_TITLE: u32 = 0x9FB6E0;
const COLOR_TEXT: u32 = 0xE0E4F0;
const COLOR_TEXT_DIM: u32 = 0x7A8298;
const COLOR_TEXT_MUTED: u32 = 0x586078;
const COLOR_ACCENT: u32 = 0x60A8FF;
const COLOR_SEL_BG: u32 = 0x2A4080;
const COLOR_SEL_BORDER: u32 = 0x4D7AE6;
const COLOR_PATH_BG: u32 = 0x161A2A;
const COLOR_DIVIDER: u32 = 0x2A2E48;

// --- Per-icon colors ---
const ICON_FOLDER: u32 = 0xE8B83A; // amber folder
const ICON_ELF: u32 = 0x34C870; // executable green
const ICON_DATA: u32 = 0x4D9CFF; // generic data blue
const ICON_TEXT: u32 = 0xC8C8D8; // plain text grey
const ICON_AUDIO: u32 = 0xE85FB8; // audio pink
const ICON_IMAGE: u32 = 0xE87C3A; // image orange
const ICON_SYMBOL: u32 = 0xC04AE8; // .sym/.id purple
const ICON_CONFIG: u32 = 0x4DDED0; // .conf teal — distinct from text grey

// --- Layout constants ---
const TITLEBAR_H: u32 = 38;
const PATHBAR_H: u32 = 30;
const ROW_H: u32 = 26;
const STATUSBAR_H: u32 = 24;
const TEXT_X: u32 = 38;
const ICON_X: u32 = 12;
const ICON_W: u32 = 18;
const ICON_H: u32 = 18;
const SCROLLBAR_W: u32 = 8;
const MAX_FILES: u32 = 64;

const FileKind = enum { directory, executable, symbol_table, data, text, config, audio, image, unknown };

fn endsWith(name: []const u8, suffix: []const u8) bool {
    if (name.len < suffix.len) return false;
    for (0..suffix.len) |i| {
        const a = name[name.len - suffix.len + i];
        const b = suffix[i];
        const al = if (a >= 'A' and a <= 'Z') a + 32 else a;
        const bl = if (b >= 'A' and b <= 'Z') b + 32 else b;
        if (al != bl) return false;
    }
    return true;
}

fn classify(entry: *const libc.FileEntry) FileKind {
    if (entry.flags & libc.FE_FLAG_IS_DIR != 0) return .directory;
    const name = entry.name[0..entry.name_len];
    if (endsWith(name, ".elf") or endsWith(name, ".efi")) return .executable;
    if (endsWith(name, ".sym") or endsWith(name, ".id")) return .symbol_table;
    if (endsWith(name, ".conf") or endsWith(name, ".cfg") or endsWith(name, ".ini") or endsWith(name, ".toml")) return .config;
    if (endsWith(name, ".txt") or endsWith(name, ".md") or endsWith(name, "motd")) return .text;
    if (endsWith(name, ".wad") or endsWith(name, ".dat") or endsWith(name, ".bin")) return .data;
    if (endsWith(name, ".wav") or endsWith(name, ".mp3") or endsWith(name, ".ogg")) return .audio;
    if (endsWith(name, ".png") or endsWith(name, ".jpg") or endsWith(name, ".bmp") or endsWith(name, ".html")) return .image;
    return .unknown;
}

fn iconColor(kind: FileKind) u32 {
    return switch (kind) {
        .directory => ICON_FOLDER,
        .executable => ICON_ELF,
        .symbol_table => ICON_SYMBOL,
        .text => ICON_TEXT,
        .config => ICON_CONFIG,
        .data => ICON_DATA,
        .audio => ICON_AUDIO,
        .image => ICON_IMAGE,
        .unknown => COLOR_TEXT_MUTED,
    };
}

// --- State ---
var alloc_w: u32 = 0;
var alloc_h: u32 = 0;
var vis_w: u32 = 0;
var vis_h: u32 = 0;
var visible_rows: u32 = 0;

var files: [MAX_FILES]libc.FileEntry = undefined;
var file_count: u32 = 0;
var scroll_offset: u32 = 0;
var selected: i32 = -1;
var scrollbar: ui.Scrollbar = .{ .x = 0, .y = 0, .w = 0, .h = 0 };

var cwd_buf: [256]u8 = undefined;
var cwd_len: usize = 0;

var status_msg: [80]u8 = undefined;
var status_len: u32 = 0;
var status_color: u32 = COLOR_TEXT_DIM;

fn setStatus(msg: []const u8, color: u32) void {
    const n = @min(msg.len, status_msg.len);
    @memcpy(status_msg[0..n], msg[0..n]);
    status_len = @intCast(n);
    status_color = color;
}

fn refreshCwd() void {
    if (libc.getCwd(&cwd_buf)) |c| {
        cwd_len = c.len;
    } else {
        cwd_buf[0] = '/';
        cwd_len = 1;
    }
}

fn refreshFileList() void {
    file_count = libc.listdir(&files);
    if (file_count > MAX_FILES) file_count = MAX_FILES;
    if (selected >= @as(i32, @intCast(file_count))) selected = @as(i32, @intCast(file_count)) - 1;
    if (selected < 0 and file_count > 0) selected = 0;
    scroll_offset = 0;
}

fn isAtRoot() bool {
    return cwd_len == 1 and cwd_buf[0] == '/';
}

/// Strip the last `/foo` component from `cwd_buf[0..cwd_len]`. Stops at
/// "/" (root). cwd is invariantly trailing-`/`-terminated by the kernel,
/// so we drop the trailing slash, walk back to the previous slash, and
/// keep that slash as the new ending.
fn parentPath(out: []u8) []const u8 {
    if (isAtRoot()) {
        out[0] = '/';
        return out[0..1];
    }
    var end: usize = cwd_len;
    if (cwd_buf[end - 1] == '/') end -= 1;
    while (end > 0 and cwd_buf[end - 1] != '/') end -= 1;
    if (end == 0) {
        out[0] = '/';
        return out[0..1];
    }
    @memcpy(out[0..end], cwd_buf[0..end]);
    return out[0..end];
}

fn navigateUp() void {
    var buf: [256]u8 = undefined;
    const parent = parentPath(&buf);
    if (libc.chdir(parent)) {
        refreshCwd();
        refreshFileList();
        setStatus(parent, COLOR_TEXT_DIM);
    } else {
        setStatus("chdir failed", 0xE85F50);
    }
}

fn navigateInto(name: []const u8) void {
    if (libc.chdir(name)) {
        refreshCwd();
        refreshFileList();
        setStatus(cwd_buf[0..cwd_len], COLOR_TEXT_DIM);
    } else {
        setStatus("chdir failed (not a dir?)", 0xE85F50);
    }
}

fn launchEntry(idx: u32) void {
    const entry = &files[idx];
    const kind = classify(entry);
    const name = entry.name[0..entry.name_len];
    switch (kind) {
        .directory => navigateInto(name),
        .executable => {
            _ = libc.exec(name);
            setStatus("Launched", 0x88CC88);
        },
        .text, .config => {
            var cmd: [128]u8 = undefined;
            const prefix = "editor.elf ";
            @memcpy(cmd[0..prefix.len], prefix);
            @memcpy(cmd[prefix.len..][0..name.len], name);
            _ = libc.exec(cmd[0 .. prefix.len + name.len]);
        },
        else => setStatus("No default action for this file type", COLOR_TEXT_DIM),
    }
}

// --- Layout ---

fn computeLayout(w: u32, h: u32) void {
    vis_w = w;
    vis_h = h;
    const list_h = h -| (TITLEBAR_H + PATHBAR_H + STATUSBAR_H);
    visible_rows = list_h / ROW_H;
    scrollbar.x = vis_w -| SCROLLBAR_W;
    scrollbar.y = TITLEBAR_H + PATHBAR_H;
    scrollbar.w = SCROLLBAR_W;
    scrollbar.h = list_h;
}

fn rowYAt(row: u32) u32 {
    return TITLEBAR_H + PATHBAR_H + row * ROW_H;
}

fn getClickedRow(my: i32) i32 {
    const top: i32 = @intCast(TITLEBAR_H + PATHBAR_H);
    const bot: i32 = @intCast(vis_h -| STATUSBAR_H);
    if (my < top or my >= bot) return -1;
    const rel: u32 = @intCast(my - top);
    const r = rel / ROW_H;
    if (r >= visible_rows) return -1;
    return @intCast(r);
}

// --- Drawing ---

// 18×18 icon bitmaps. Cell codes:
//   0 = transparent (skip)
//   1 = main color (from FileKind)
//   2 = highlight (lighten +50)
//   3 = shadow (darken −50)
//
// Folder is procedural (the user explicitly liked that one). Every other
// kind gets a distinct silhouette so a half-second glance tells you what
// type it is without reading the extension.

const Icon = [18][18]u8;

const doc_icon: Icon = .{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

const exec_icon: Icon = .{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 2, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 2, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

const text_icon: Icon = .{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

const audio_icon: Icon = .{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

const image_icon: Icon = .{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0 },
    .{ 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0 },
    .{ 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

const data_icon: Icon = .{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 },
    .{ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

const symbol_icon: Icon = .{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 1, 1, 1, 0, 0, 0, 0, 2, 2, 0, 0, 1, 1, 1, 0, 0, 0 },
    .{ 0, 1, 1, 1, 0, 0, 0, 0, 2, 2, 0, 0, 1, 1, 1, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

// Three horizontal slider tracks, each with a 4×2 highlighted knob at a
// different x-position — clearly reads as "settings/preferences" and matches
// the visual style of the other 18×18 file-type icons.
const config_icon: Icon = .{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 0, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
};

fn lighten(c: u32, amt: u32) u32 {
    const r: u32 = @min(((c >> 16) & 0xFF) + amt, 0xFF);
    const g: u32 = @min(((c >> 8) & 0xFF) + amt, 0xFF);
    const b: u32 = @min((c & 0xFF) + amt, 0xFF);
    return (r << 16) | (g << 8) | b;
}

fn darken(c: u32, amt: u32) u32 {
    const cr: u32 = (c >> 16) & 0xFF;
    const cg: u32 = (c >> 8) & 0xFF;
    const cb: u32 = c & 0xFF;
    const r: u32 = if (cr > amt) cr - amt else 0;
    const g: u32 = if (cg > amt) cg - amt else 0;
    const b: u32 = if (cb > amt) cb - amt else 0;
    return (r << 16) | (g << 8) | b;
}

fn iconBitmap(kind: FileKind) ?*const Icon {
    return switch (kind) {
        .directory => null,
        .executable => &exec_icon,
        .symbol_table => &symbol_icon,
        .text => &text_icon,
        .config => &config_icon,
        .data => &data_icon,
        .audio => &audio_icon,
        .image => &image_icon,
        .unknown => &doc_icon,
    };
}

fn drawBitmapIcon(canvas: *gfx.Canvas, x: u32, y: u32, bm: *const Icon, color: u32) void {
    const hi = lighten(color, 60);
    const dk = darken(color, 70);
    for (0..18) |row| {
        for (0..18) |col| {
            const code = bm[row][col];
            if (code == 0) continue;
            const px: u32 = switch (code) {
                1 => color,
                2 => hi,
                3 => dk,
                else => color,
            };
            canvas.putPixel(@intCast(x + col), @intCast(y + row), px);
        }
    }
}

fn drawFolderIcon(canvas: *gfx.Canvas, x: u32, y: u32, color: u32) void {
    // Tab on top + body. The "tab" is the small flap that distinguishes a
    // folder from a plain rectangle; lighter highlight on its top edge.
    const hi = lighten(color, 50);
    const dk = darken(color, 50);
    // Tab (top-left ~60% width, 4 px tall)
    const tab_w = ICON_W * 6 / 10;
    canvas.fillRect(x, y + 2, tab_w, 4, color);
    // Body
    canvas.fillRect(x, y + 4, ICON_W, ICON_H - 4, color);
    // Top edge highlight
    canvas.fillRect(x + 1, y + 5, ICON_W - 2, 1, hi);
    // Subtle bottom shadow
    canvas.fillRect(x, y + ICON_H - 1, ICON_W, 1, dk);
}

fn drawIcon(canvas: *gfx.Canvas, x: u32, y: u32, kind: FileKind) void {
    const color = iconColor(kind);
    if (kind == .directory) {
        drawFolderIcon(canvas, x, y, color);
    } else if (iconBitmap(kind)) |bm| {
        drawBitmapIcon(canvas, x, y, bm, color);
    }
}

fn drawSize(canvas: *gfx.Canvas, x_right: u32, y: u32, size: u32, bg: u32) void {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    if (size >= 1024 * 1024) {
        const mb = size / (1024 * 1024);
        pos = formatNum(&buf, mb);
        buf[pos] = ' '; pos += 1;
        buf[pos] = 'M'; pos += 1;
        buf[pos] = 'B'; pos += 1;
    } else if (size >= 1024) {
        const kb = size / 1024;
        pos = formatNum(&buf, kb);
        buf[pos] = ' '; pos += 1;
        buf[pos] = 'K'; pos += 1;
        buf[pos] = 'B'; pos += 1;
    } else {
        pos = formatNum(&buf, size);
        buf[pos] = ' '; pos += 1;
        buf[pos] = 'B'; pos += 1;
    }
    const w = fa.default_16.measure(buf[0..pos]);
    fa.drawTextOpaque(canvas, x_right -| w, y, buf[0..pos], COLOR_TEXT_DIM, bg, &fa.default_16);
}

fn formatNum(buf: []u8, n: u32) usize {
    if (n == 0) {
        buf[0] = '0';
        return 1;
    }
    var digits: [12]u8 = undefined;
    var v = n;
    var len: usize = 0;
    while (v > 0) : (v /= 10) {
        digits[len] = '0' + @as(u8, @intCast(v % 10));
        len += 1;
    }
    for (0..len) |i| buf[i] = digits[len - 1 - i];
    return len;
}

fn render(canvas: *gfx.Canvas) void {
    canvas.clear(COLOR_BG);

    // --- Title bar ---
    canvas.fillRect(0, 0, vis_w, TITLEBAR_H, COLOR_PANEL);
    canvas.fillRect(0, TITLEBAR_H - 1, vis_w, 1, COLOR_DIVIDER);
    fa.drawTextOpaque(canvas, 14, 6, "Files", COLOR_TITLE, COLOR_PANEL, &fa.default_24);

    // --- Path bar ---
    const path_y = TITLEBAR_H;
    canvas.fillRect(0, path_y, vis_w, PATHBAR_H, COLOR_PATH_BG);
    canvas.fillRect(0, path_y + PATHBAR_H - 1, vis_w, 1, COLOR_DIVIDER);

    // "↑" up button on the left of the path bar (if not at root).
    const up_w: u32 = 30;
    if (!isAtRoot()) {
        canvas.fillRect(8, path_y + 4, up_w, PATHBAR_H - 8, COLOR_PANEL_ALT);
        fa.drawTextOpaque(canvas, 16, path_y + 6, "Up", COLOR_ACCENT, COLOR_PANEL_ALT, &fa.default_16);
    }

    // Current path display.
    const path_text_x: u32 = if (isAtRoot()) 14 else 8 + up_w + 12;
    fa.drawTextOpaque(canvas, path_text_x, path_y + 6, cwd_buf[0..cwd_len], COLOR_TEXT, COLOR_PATH_BG, &fa.default_16);

    // --- File list ---
    const list_w = vis_w -| SCROLLBAR_W;
    const list_top = TITLEBAR_H + PATHBAR_H;
    const list_bot = vis_h -| STATUSBAR_H;
    canvas.fillRect(0, list_top, list_w, list_bot -| list_top, COLOR_BG);

    if (file_count == 0) {
        const msg = "(empty directory)";
        const w = fa.default_16.measure(msg);
        fa.drawTextOpaque(canvas, (vis_w -| w) / 2, list_top + 24, msg, COLOR_TEXT_MUTED, COLOR_BG, &fa.default_16);
    }

    var r: u32 = 0;
    while (r < visible_rows) : (r += 1) {
        const file_idx = scroll_offset + r;
        if (file_idx >= file_count) break;
        const entry = &files[file_idx];
        const y = rowYAt(r);
        const is_sel = (@as(i32, @intCast(file_idx)) == selected);
        const row_bg: u32 = if (is_sel) COLOR_SEL_BG else if (r % 2 == 0) COLOR_BG else COLOR_PANEL_ALT;
        canvas.fillRect(0, y, list_w, ROW_H, row_bg);
        if (is_sel) {
            canvas.fillRect(0, y, 3, ROW_H, COLOR_SEL_BORDER);
        }

        const kind = classify(entry);
        drawIcon(canvas, ICON_X, y + (ROW_H - ICON_H) / 2, kind);

        const name_y = y + (ROW_H -| fa.default_16.line_height) / 2;
        const name_color: u32 = if (kind == .directory) COLOR_ACCENT else COLOR_TEXT;
        fa.drawTextOpaque(canvas, TEXT_X, name_y, entry.name[0..entry.name_len], name_color, row_bg, &fa.default_16);

        // Trailing slash on directories so they're obvious without
        // depending on the icon.
        if (kind == .directory) {
            const name_w = fa.default_16.measure(entry.name[0..entry.name_len]);
            fa.drawTextOpaque(canvas, TEXT_X + name_w, name_y, "/", COLOR_ACCENT, row_bg, &fa.default_16);
        } else {
            // File size on the right (skip for dirs since they're inode-only).
            drawSize(canvas, list_w -| 12, name_y, entry.file_size, row_bg);
        }
    }

    scrollbar.draw(canvas, file_count, visible_rows, scroll_offset);

    // --- Status bar ---
    const sb_y = vis_h -| STATUSBAR_H;
    canvas.fillRect(0, sb_y, vis_w, STATUSBAR_H, COLOR_PANEL);
    canvas.fillRect(0, sb_y, vis_w, 1, COLOR_DIVIDER);

    const sb_text_y = sb_y + (STATUSBAR_H -| fa.default_16.line_height) / 2;
    if (status_len > 0) {
        fa.drawTextOpaque(canvas, 12, sb_text_y, status_msg[0..status_len], status_color, COLOR_PANEL, &fa.default_16);
    } else {
        var buf: [16]u8 = undefined;
        const n = formatNum(&buf, file_count);
        const cx = fa.drawNumOpaque(canvas, 12, sb_text_y, file_count, COLOR_TEXT_DIM, COLOR_PANEL, &fa.default_16);
        _ = n;
        fa.drawTextOpaque(canvas, cx, sb_text_y, " items  •  double-click to open", COLOR_TEXT_DIM, COLOR_PANEL, &fa.default_16);
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    var init_w = scr.w * 4 / 10;
    if (init_w < 420) init_w = 420;
    if (init_w > 720) init_w = 720;
    var init_h = scr.h * 5 / 10;
    if (init_h < 360) init_h = 360;
    if (init_h > 700) init_h = 700;
    alloc_w = @min(init_w + 200, scr.w);
    alloc_h = @min(init_h + 200, scr.h);
    while (alloc_w * alloc_h > 524288) {
        if (alloc_w > alloc_h) alloc_w -= 16 else alloc_h -= 16;
    }
    computeLayout(init_w, init_h);

    const win = libc.createWindowEx(alloc_w, alloc_h, init_w, init_h) orelse libc.exit();
    alloc_w = win.alloc_w; // libc may have rounded up to 16-px stride
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    _ = libc.getWindowAlloc(); // opt this window into F10 grow-on-maximize (re-fetched in .resize)
    fa.ensureLoaded();

    refreshCwd();
    refreshFileList();
    setStatus(cwd_buf[0..cwd_len], COLOR_TEXT_DIM);

    var needs_redraw: bool = true;
    var prev_left: bool = false;
    var last_click_tick: u32 = 0;
    var last_click_idx: i32 = -1;
    // Tracked mouse state — fed from mouse_move/mouse_button events.
    var cur_mx: i32 = 0;
    var cur_my: i32 = 0;
    var cur_btns: u32 = 0;

    while (true) {
        // Drain all queued events.
        while (libc.pollEvent()) |ev| {
            // Scrollbar consumes wheel + drag/track interactions globally;
            // app code only handles its own widgets (Up button, row click).
            if (scrollbar.handleEvent(ev, file_count, visible_rows, &scroll_offset)) {
                needs_redraw = true;
            }
            switch (ev.kindOf()) {
                .close_request => {
                    libc.destroyWindow();
                    libc.exit();
                },
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 0x1B) {
                        libc.destroyWindow();
                        libc.exit();
                    }
                    if (ch == 0x08 or ch == 0x7F) {
                        if (!isAtRoot()) {
                            navigateUp();
                            needs_redraw = true;
                        }
                    } else if (ch == 0x0D or ch == 0x0A) {
                        if (selected >= 0 and selected < @as(i32, @intCast(file_count))) {
                            launchEntry(@intCast(selected));
                            needs_redraw = true;
                        }
                    } else if (ch == 'h' or ch == 'H') {
                        if (libc.chdir("/")) {
                            refreshCwd();
                            refreshFileList();
                            needs_redraw = true;
                        }
                    }
                },
                .mouse_move => {
                    cur_mx = @bitCast(ev.a);
                    cur_my = @bitCast(ev.b);
                    cur_btns = ev.c;
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                    cur_mx = @bitCast(ev.b);
                    cur_my = @bitCast(ev.c);
                    needs_redraw = true; // press/release-edge may matter
                },
                .resize => {
                    // The compositor may have GROWN our framebuffer (F10
                    // maximize) past the alloc we requested at startup. Re-fetch
                    // it and rebuild the canvas at the new stride before laying
                    // out, so we render crisply into the bigger FB instead of
                    // being upscaled. The FB pointer (win.fb) is unchanged.
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != alloc_w or wa.h != alloc_h)) {
                        alloc_w = wa.w;
                        alloc_h = wa.h;
                        canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
                    }
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) {
                        computeLayout(new_w, new_h);
                        needs_redraw = true;
                    }
                },
                else => {},
            }
        }

        // Mouse state for app-owned widgets (Up button, row click).
        const left = (cur_btns & 1) != 0;
        const in_scrollbar = cur_mx >= @as(i32, @intCast(scrollbar.x)) and cur_mx < @as(i32, @intCast(scrollbar.x + scrollbar.w));

        // Up button click
        if (left and !prev_left and !isAtRoot()) {
            const up_w_signed: i32 = 30;
            if (cur_mx >= 8 and cur_mx < 8 + up_w_signed and
                cur_my >= @as(i32, @intCast(TITLEBAR_H + 4)) and
                cur_my < @as(i32, @intCast(TITLEBAR_H + PATHBAR_H - 4)))
            {
                navigateUp();
                needs_redraw = true;
            }
        }

        if (left and !prev_left and !in_scrollbar) {
            const click_row = getClickedRow(cur_my);
            if (click_row >= 0) {
                const file_idx = @as(i32, @intCast(scroll_offset)) + click_row;
                if (file_idx >= 0 and file_idx < @as(i32, @intCast(file_count))) {
                    const now = libc.uptime();
                    const is_double = (file_idx == last_click_idx and (now -% last_click_tick) < 80);
                    if (is_double) {
                        launchEntry(@intCast(file_idx));
                        last_click_idx = -1;
                    } else {
                        selected = file_idx;
                        last_click_idx = file_idx;
                        last_click_tick = now;
                    }
                    needs_redraw = true;
                }
            }
        }
        prev_left = left;

        if (!needs_redraw) {
            libc.sleep(10);
            continue;
        }
        needs_redraw = false;
        render(&canvas);
        libc.present();
        libc.sleep(10);
    }
}
