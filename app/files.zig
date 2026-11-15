// Files — directory browser.
//
// The toolbar goes up and home and shows the path as crumbs, each a click
// away. The list has one row per entry, folders first: a double click or
// Enter opens a folder, runs a program, or hands a file to the app for its
// kind. Typing a letter selects the next name that starts with it.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const app = @import("app");

const COLOR_TEXT_MUTED: u32 = 0x66666C;
/// Secondary columns of the selected row: white would shout.
const COLOR_ON_SELECTION: u32 = 0xD6E6FF;

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
const HEADER_H: u32 = 24;
const ROW_H: u32 = 26;
const TEXT_X: u32 = 42;
const ICON_X: u32 = 16;
const ICON_W: u32 = 18;
const ICON_H: u32 = 18;
const KIND_W: u32 = 104;
const SIZE_W: u32 = 76;
const COL_PAD: u32 = 14;
/// Below this list width the Kind column is dropped.
const KIND_MIN_LIST_W: u32 = 400;
const MAX_FILES: u32 = 256;

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
    if (endsWith(name, ".txt") or endsWith(name, ".md") or endsWith(name, "motd") or endsWith(name, ".html") or endsWith(name, ".zig")) return .text;
    if (endsWith(name, ".wad") or endsWith(name, ".dat") or endsWith(name, ".bin")) return .data;
    if (endsWith(name, ".wav") or endsWith(name, ".mp3") or endsWith(name, ".ogg")) return .audio;
    if (endsWith(name, ".png") or endsWith(name, ".jpg") or endsWith(name, ".jpeg") or endsWith(name, ".bmp")) return .image;
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

fn kindName(kind: FileKind) []const u8 {
    return switch (kind) {
        .directory => "Folder",
        .executable => "Program",
        .symbol_table => "Symbols",
        .text => "Text",
        .config => "Settings",
        .data => "Data",
        .audio => "Audio",
        .image => "Image",
        .unknown => "Document",
    };
}

fn lower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

// --- State ---
var files: [MAX_FILES]libc.FileEntry = undefined;
var file_count: u32 = 0;
var list: app.ListState = .{};

var cwd_buf: [256]u8 = undefined;
var cwd_len: usize = 0;

/// A message that replaces the selection's details in the status bar until
/// the selection or the folder changes.
var note_buf: [80]u8 = undefined;
var note_len: usize = 0;

fn setNote(msg: []const u8) void {
    note_len = @min(msg.len, note_buf.len);
    @memcpy(note_buf[0..note_len], msg[0..note_len]);
}

fn refreshCwd() void {
    if (libc.getCwd(&cwd_buf)) |c| {
        cwd_len = c.len;
    } else {
        cwd_buf[0] = '/';
        cwd_len = 1;
    }
}

fn nameOf(entry: *const libc.FileEntry) []const u8 {
    return entry.name[0..entry.name_len];
}

/// Folders first, then by name without regard to case.
fn sortsBefore(a: *const libc.FileEntry, b: *const libc.FileEntry) bool {
    const a_dir = a.flags & libc.FE_FLAG_IS_DIR != 0;
    const b_dir = b.flags & libc.FE_FLAG_IS_DIR != 0;
    if (a_dir != b_dir) return a_dir;
    const an = nameOf(a);
    const bn = nameOf(b);
    for (0..@min(an.len, bn.len)) |i| {
        const ac = lower(an[i]);
        const bc = lower(bn[i]);
        if (ac != bc) return ac < bc;
    }
    return an.len < bn.len;
}

fn refreshFileList() void {
    const n = libc.listdir(&files);
    // "." and ".." have the toolbar.
    var kept: u32 = 0;
    for (0..n) |i| {
        const name = nameOf(&files[i]);
        if (name.len == 0 or (name[0] == '.' and (name.len == 1 or (name.len == 2 and name[1] == '.')))) continue;
        files[kept] = files[i];
        kept += 1;
    }
    file_count = kept;
    // Insertion sort: a few hundred entries at most.
    var i: u32 = 1;
    while (i < file_count) : (i += 1) {
        const moving = files[i];
        var j = i;
        while (j > 0 and sortsBefore(&moving, &files[j - 1])) : (j -= 1) files[j] = files[j - 1];
        files[j] = moving;
    }
    list = .{ .selected = if (file_count > 0) 0 else null };
    note_len = 0;
}

fn isAtRoot() bool {
    return cwd_len == 1 and cwd_buf[0] == '/';
}

fn goTo(path: []const u8) void {
    if (libc.chdir(path)) {
        refreshCwd();
        refreshFileList();
    } else {
        setNote("Can't open that folder");
    }
}

/// The path of the folder above: the kernel ends cwd in '/', so cut that
/// and the name before it.
fn navigateUp() void {
    if (isAtRoot()) return;
    var end: usize = cwd_len;
    if (cwd_buf[end - 1] == '/') end -= 1;
    while (end > 0 and cwd_buf[end - 1] != '/') end -= 1;
    var parent: [256]u8 = undefined;
    @memcpy(parent[0..end], cwd_buf[0..end]);
    goTo(if (end == 0) "/" else parent[0..end]);
}

fn runWith(program: []const u8, name: []const u8) void {
    var cmd: [128]u8 = undefined;
    if (program.len + 1 + name.len > cmd.len) return;
    @memcpy(cmd[0..program.len], program);
    cmd[program.len] = ' ';
    @memcpy(cmd[program.len + 1 ..][0..name.len], name);
    _ = libc.exec(cmd[0 .. program.len + 1 + name.len]);
}

fn openEntry(idx: u32) void {
    const entry = &files[idx];
    const name = nameOf(entry);
    switch (classify(entry)) {
        .directory => goTo(name),
        .executable => {
            _ = libc.exec(name);
            setNote("Started");
        },
        .text, .config => runWith("editor.elf", name),
        .image => runWith("photo.elf", name),
        else => setNote("No app opens this kind of file"),
    }
}

/// Select the next entry whose name starts with `ch`, wrapping around.
fn selectByLetter(ch: u8) bool {
    if (file_count == 0) return false;
    const start: u32 = if (list.selected) |s| s + 1 else 0;
    for (0..file_count) |step| {
        const i: u32 = (start + @as(u32, @intCast(step))) % file_count;
        const name = nameOf(&files[i]);
        if (name.len != 0 and lower(name[0]) == lower(ch)) {
            list.select(i);
            return true;
        }
    }
    return false;
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

/// "812 bytes", "14 KB", "3.2 MB".
fn sizeText(buf: *[16]u8, size: u32) []const u8 {
    var pos: usize = 0;
    var unit: []const u8 = " bytes";
    if (size >= 1024 * 1024) {
        pos = formatNum(buf, size / (1024 * 1024));
        // One decimal below 10 MB, where it still says something.
        if (size < 10 * 1024 * 1024) {
            buf[pos] = '.';
            buf[pos + 1] = '0' + @as(u8, @intCast((size % (1024 * 1024)) * 10 / (1024 * 1024)));
            pos += 2;
        }
        unit = " MB";
    } else if (size >= 1024) {
        pos = formatNum(buf, size / 1024);
        unit = " KB";
    } else {
        pos = formatNum(buf, size);
    }
    @memcpy(buf[pos..][0..unit.len], unit);
    return buf[0 .. pos + unit.len];
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

// --- The window ---

/// The path as crumbs in `r`: "/" then each folder, the current one in
/// bold. A click on an ancestor goes there. Leading crumbs give way when
/// the path is wider than the bar.
fn crumbs(u: *app.Ui, r: app.Rect) void {
    const p = &ui.palette;
    const regular = &fa.default_13;
    const bold = &fa.default_13sb;
    const SEP_W: u32 = 14;
    const PAD: u32 = 6;

    // Ends of the path's components: cwd[0..end] is the folder to go to.
    var ends: [32]usize = undefined;
    var count: usize = 1;
    ends[0] = 1;
    var i: usize = 1;
    while (i < cwd_len and count < ends.len) : (i += 1) {
        if (cwd_buf[i] == '/') {
            ends[count] = i + 1;
            count += 1;
        }
    }
    // A cwd without its trailing '/' still has a last component.
    if (cwd_len > 1 and cwd_buf[cwd_len - 1] != '/' and count < ends.len) {
        ends[count] = cwd_len + 1;
        count += 1;
    }

    // Drop crumbs from the left until the rest fits.
    var first: usize = 0;
    while (first + 1 < count) : (first += 1) {
        var w: u32 = 0;
        for (first..count) |k| w += crumbWidth(ends, k, if (k + 1 == count) bold else regular) + 2 * PAD + SEP_W;
        if (w <= r.w + SEP_W) break;
    }

    var x = r.x;
    for (first..count) |k| {
        const is_last = k + 1 == count;
        const atlas = if (is_last) bold else regular;
        const text = crumbText(ends, k);
        const cell = app.Rect{ .x = x, .y = r.y, .w = @min(atlas.measure(text) + 2 * PAD, r.x + r.w -| x), .h = r.h };
        if (!is_last and u.clicked(cell)) {
            // `ends` describes the path just left.
            goTo(cwd_buf[0..ends[k]]);
            return;
        }
        if (u.painting) {
            const hot = !is_last and u.hovering(cell);
            if (hot) u.canvas.fillRoundedRect(cell.x, cell.y, cell.w, cell.h, 5, ui.lerpColor(p.bar_bg, p.text_strong, 1, 8));
            const color = if (is_last or hot) p.text_strong else p.text_muted;
            ui.drawTextFit(u.canvas, cell.x + PAD, cell.y + (cell.h -| atlas.line_height) / 2, cell.w -| 2 * PAD, text, color, atlas);
            if (!is_last) {
                const cx: i32 = @intCast(cell.x + cell.w + SEP_W / 2);
                const cy: i32 = @intCast(cell.y + cell.h / 2);
                u.canvas.drawLineAA(cx - 2, cy - 4, cx + 2, cy, p.text_muted);
                u.canvas.drawLineAA(cx + 2, cy, cx - 2, cy + 4, p.text_muted);
            }
        }
        x = cell.x + cell.w + SEP_W;
    }
}

fn crumbText(ends: [32]usize, k: usize) []const u8 {
    if (k == 0) return "/";
    return cwd_buf[ends[k - 1] .. ends[k] - 1];
}

fn crumbWidth(ends: [32]usize, k: usize, atlas: *const fa.FontAtlas) u32 {
    return atlas.measure(crumbText(ends, k));
}

fn statusText(buf: *[96]u8) []const u8 {
    if (note_len != 0) return note_buf[0..note_len];
    const sel = list.selected orelse return "";
    const entry = &files[sel];
    const kind = classify(entry);
    const name = nameOf(entry);
    var len: usize = 0;
    @memcpy(buf[0..name.len], name);
    len = name.len;
    const parts = [_][]const u8{ "  -  ", kindName(kind) };
    for (parts) |part| {
        @memcpy(buf[len..][0..part.len], part);
        len += part.len;
    }
    if (kind != .directory) {
        var size_buf: [16]u8 = undefined;
        const size = sizeText(&size_buf, entry.file_size);
        @memcpy(buf[len..][0..2], ", ");
        @memcpy(buf[len + 2 ..][0..size.len], size);
        len += 2 + size.len;
    }
    return buf[0..len];
}

fn countText(buf: *[24]u8) []const u8 {
    const n = formatNum(buf, file_count);
    const word: []const u8 = if (file_count == 1) " item" else " items";
    @memcpy(buf[n..][0..word.len], word);
    return buf[0 .. n + word.len];
}

fn drawHeader(u: *app.Ui, r: app.Rect, show_kind: bool) void {
    const p = &ui.palette;
    const atlas = &fa.default_13sb;
    const ty = r.y + (r.h - 1 -| atlas.line_height) / 2;
    u.canvas.fillRect(r.x, r.y + r.h - 1, r.w, 1, ui.lerpColor(p.window_bg, p.text_muted, 1, 5));
    fa.drawText(u.canvas, @intCast(r.x + TEXT_X), @intCast(ty), "Name", p.text_muted, atlas);
    const size_right = r.x + r.w -| COL_PAD;
    fa.drawText(u.canvas, @intCast(size_right -| atlas.measure("Size")), @intCast(ty), "Size", p.text_muted, atlas);
    if (show_kind) fa.drawText(u.canvas, @intCast(size_right -| SIZE_W -| KIND_W), @intCast(ty), "Kind", p.text_muted, atlas);
}

fn drawRow(u: *app.Ui, r: app.Rect, entry: *const libc.FileEntry, is_selected: bool, show_kind: bool) void {
    const p = &ui.palette;
    const kind = classify(entry);
    drawIcon(u.canvas, r.x + ICON_X, r.y + (ROW_H - ICON_H) / 2, kind);

    const small = &fa.default_13;
    const name_atlas = &fa.default_16;
    const size_right = r.x + r.w -| COL_PAD;
    const kind_x = size_right -| SIZE_W -| KIND_W;
    const name_end = if (show_kind) kind_x else size_right -| SIZE_W;
    const name_color = if (is_selected) p.selection_text else p.text_normal;
    const dim = if (is_selected) COLOR_ON_SELECTION else p.text_muted;

    ui.drawTextFit(u.canvas, r.x + TEXT_X, r.y + (ROW_H -| name_atlas.line_height) / 2, name_end -| (r.x + TEXT_X) -| COL_PAD, nameOf(entry), name_color, name_atlas);
    const small_y = r.y + (ROW_H -| small.line_height) / 2;
    if (show_kind) fa.drawText(u.canvas, @intCast(kind_x), @intCast(small_y), kindName(kind), dim, small);
    var size_buf: [16]u8 = undefined;
    const size: []const u8 = if (kind == .directory) "--" else sizeText(&size_buf, entry.file_size);
    fa.drawText(u.canvas, @intCast(size_right -| small.measure(size)), @intCast(small_y), size, dim, small);
}

pub fn init(_: *app.Window) void {
    refreshCwd();
    refreshFileList();
}

pub fn frame(u: *app.Ui) void {
    if (!u.painting) {
        if (u.key == 0x08 or u.key == 0x7F) {
            navigateUp();
            u.repaint();
        } else if (u.key > ' ' and u.key < 0x7F and u.mods & (libc.MOD_CTRL | libc.MOD_ALT) == 0) {
            if (selectByLetter(u.key)) note_len = 0;
            u.repaint();
        }
    }

    u.beginBar();
    if (u.iconButton(.up, !isAtRoot())) navigateUp();
    if (u.iconButton(.home, !isAtRoot())) goTo("/");
    crumbs(u, u.space(0, 22));
    u.endBar();

    var status_buf: [96]u8 = undefined;
    var count_buf: [24]u8 = undefined;
    u.statusBar(statusText(&status_buf), countText(&count_buf));

    const area = u.fill();
    const header = app.Rect{ .x = area.x, .y = area.y, .w = area.w, .h = @min(HEADER_H, area.h) };
    const body = app.Rect{ .x = area.x, .y = area.y + header.h, .w = area.w, .h = area.h - header.h };
    const selected_before = list.selected;
    const view = u.list(body, &list, file_count, ROW_H);
    if (view.selected != selected_before) note_len = 0;
    if (view.opened) |row| openEntry(row);

    if (u.painting) {
        const show_kind = view.area.w >= KIND_MIN_LIST_W;
        drawHeader(u, .{ .x = header.x, .y = header.y, .w = view.area.w, .h = header.h }, show_kind);
        if (file_count == 0) {
            const msg = "This folder is empty";
            fa.drawTextCentered(u.canvas, @intCast(body.x), @intCast(body.y + 28), body.w, msg, ui.palette.text_muted, &fa.default_16);
        }
        var row = view.first;
        while (row < view.first + view.count) : (row += 1) {
            drawRow(u, view.rowRect(row), &files[row], view.selected == row, show_kind);
        }
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    app.run(@This(), .{
        .width = @max(480, @min(scr.w * 4 / 10, 760)),
        .height = @max(360, @min(scr.h / 2, 700)),
        .escape_closes = true,
    });
}
