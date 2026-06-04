//! Syscall handlers (fs) — split out of syscall.zig (#797).
//! Dispatched from cpu/syscall.zig doSyscallInner; named in SYSCALLS.

const std = @import("std");
const vga = @import("../../ui/vga.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const keyboard = @import("../../driver/keyboard.zig");
const process = @import("../../proc/process.zig");
const vmm = @import("../../mm/vmm.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const bga = @import("../../ui/bga.zig");
const vfs = @import("../../fs/vfs.zig");
const desktop = @import("../../ui/desktop.zig");
const xhci = @import("../../driver/xhci.zig");
const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");
const pipe = @import("../../proc/pipe.zig");
const memmap = @import("../../mm/memmap.zig");
const config = @import("../../config.zig");
const smp = @import("../smp.zig");
const signals = @import("../../proc/signals.zig");
const errno = @import("../../proc/errno.zig");
const sched_asm = @import("../../proc/sched_asm.zig");
const apic = @import("../../time/apic.zig");

const common = @import("common.zig");
const validateUserPtr = common.validateUserPtr;
const validateUserPtrAligned = common.validateUserPtrAligned;
const validateUserPtrWrite = common.validateUserPtrWrite;
const validateUserPtrWriteAligned = common.validateUserPtrWriteAligned;
const USER_SPACE_START = common.USER_SPACE_START;
const USER_SPACE_END = common.USER_SPACE_END;
const E_INVAL = common.E_INVAL;
const E_NOENT = common.E_NOENT;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;
const E_NOMEM = common.E_NOMEM;
const E_AGAIN = common.E_AGAIN;
const E_BUSY = common.E_BUSY;
const E_NAMETOOLONG = common.E_NAMETOOLONG;
const E_PIPE = common.E_PIPE;
const E_SRCH = common.E_SRCH;
const E_NOSYS = common.E_NOSYS;
const E_PERM = common.E_PERM;
const E_CHILD = common.E_CHILD;
const E_INTR = common.E_INTR;

pub fn sysOpen(name_ptr: u32, flags: u32) u32 {
    if (!validateUserPtr(name_ptr, 1)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;

    // Read filename from user space (null-terminated, max 100 chars)
    const name_bytes: [*]const u8 = @ptrFromInt(@as(usize, name_ptr));
    var name_len: usize = 0;
    while (name_len < 100 and name_bytes[name_len] != 0) : (name_len += 1) {}
    if (name_len == 0) return E_INVAL;

    return vfs.openFlags(pcb, name_bytes[0..name_len], flags) orelse 0xFFFFFFFF;
}

pub fn sysFread(fd: u32, buf_ptr: u32, count: u32) u32 {
    if (count == 0) return 0;
    if (!validateUserPtrWrite(buf_ptr, count)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;
    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    return vfs.read(pcb, fd, buf, count);
}

pub fn sysFwrite(fd: u32, buf_ptr: u32, count: u32) u32 {
    if (count == 0) return 0;
    if (!validateUserPtr(buf_ptr, count)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;
    const buf: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    return vfs.write(pcb, fd, buf, count);
}

pub fn sysClose(fd: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    return vfs.close(pcb, fd);
}

/// Reposition an fd's read/write cursor. whence: 0=SET (absolute),
/// 1=CUR (relative to current offset). SEEK_END is intentionally
/// omitted — file_size lookup is fs-specific and userland can get it
/// via sysFsize for the rare case it matters. Quake's pak loader only
/// needs SEEK_SET.
///
/// Returns the new offset on success, or 0xFFFFFFFF on bad fd / overflow.
pub fn sysSeek(fd: u32, offset: u32, whence: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return 0xFFFFFFFF;
    if (fd < 3) return 0xFFFFFFFF;
    const fd_entry = &pcb.fd_table[fd];
    const new_off: u32 = switch (whence) {
        0 => offset,
        1 => fd_entry.offset +% offset,
        else => return 0xFFFFFFFF,
    };
    fd_entry.offset = new_off;
    return new_off;
}

// --- Graphics syscalls ---

const FileEntry = extern struct {
    name: [32]u8,
    name_len: u8,
    file_size: u32 align(1),
    flags: u8, // bit 0 = is_elf, bit 1 = from_fat32
    _pad: [10]u8,
};

pub fn sysListDir(buf_ptr: u32, buf_size: u32) u32 {
    const entry_size: u32 = @sizeOf(FileEntry);
    const max_entries = buf_size / entry_size;
    if (max_entries == 0) return E_INVAL;
    if (!validateUserPtrWriteAligned(buf_ptr, buf_size, @alignOf(FileEntry))) return E_FAULT;
    const entries: [*]FileEntry = @ptrFromInt(@as(usize, buf_ptr));

    // Dispatch by cwd → mount table. Previously hardcoded to FAT32 root,
    // which silently returned 0 entries when running with ext2.img on IDE2
    // (FAT32 disk.img unmapped). Default cwd is "/tar/" so an unmodified
    // shell launching files.elf gets tarfs contents — matching what the
    // boot tar holds.
    const pcb = process.currentPCB() orelse return E_FAULT;
    const cwd = pcb.cwd[0..pcb.cwd_len];
    if (cwd.len == 0) return 0;

    const m = vfs.findMount(cwd) orelse return 0;
    return switch (m.fs) {
        .tarfs => blk: {
            const tarfs = @import("../../fs/tarfs.zig");
            break :blk tarfs.listToBuffer(@ptrCast(entries), max_entries);
        },
        .fat32 => blk: {
            const fat32 = @import("../../fs/fat32.zig");
            break :blk listFatDir(fat32.root_cluster, entries, max_entries);
        },
        .ext2 => blk: {
            // ext2 has its own FileEntry type with the same layout —
            // @ptrCast across the type boundary (Zig treats identical
            // extern structs as distinct types). Walk cwd-relative path
            // (cwd[mount_prefix.len..]) to the right directory inode so
            // `cd /bin; ls` actually lists /bin and not the ext2 root.
            const ext2 = @import("../../fs/ext2/ext2.zig");
            const layout = @import("../../fs/ext2/layout.zig");
            const rel = cwd[m.prefix.len..];
            const dir_inum = if (rel.len == 0) layout.ROOT_INO else (ext2.resolveDirInum(rel) orelse layout.ROOT_INO);
            break :blk ext2.listDir(dir_inum, @ptrCast(entries), max_entries);
        },
        // devfs/procfs don't have a buffer-fill listing API yet — return
        // 0 entries; not an error, just an empty directory.
        .devfs, .procfs => 0,
    };
}

/// Fill `entries` with one FileEntry per non-deleted entry in the FAT32
/// directory rooted at `dir_cluster`. LFN-aware; `.` / `..` and the volume
/// label are filtered out. Subdirectory entries are *included* (with the
/// `is_dir` flag set) so user space can render them in listings.
///
/// `flags` byte layout (see lib/libc.zig FE_FLAG_*):
///   bit 0 = is_elf
///   bit 1 = is_directory
///   bit 2 = from_fat32 (always set here)
///   bit 3 = from_ext2
pub fn listFatDir(dir_cluster: u32, entries: [*]FileEntry, max_entries: u32) u32 {
    const fat32 = @import("../../fs/fat32.zig");
    var count: u32 = 0;
    var lfn_buf: [255]u8 = undefined;
    var lfn_len: usize = 0;
    var lfn_active: bool = false;
    const lfn_offsets = [13]u8{ 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };

    var fi: u32 = 0;
    while (fi < 4096 and count < max_entries) : (fi += 1) {
        const raw = fat32.readDirEntryRawAt(dir_cluster, fi) orelse break;
        if (raw[0] == 0) break;
        if (raw[0] == 0xE5) { lfn_active = false; continue; }

        if (raw[11] & 0x0F == 0x0F) {
            const seq = raw[0] & 0x1F;
            if (seq == 0 or seq > 20) { lfn_active = false; continue; }
            if (raw[0] & 0x40 != 0) { lfn_len = 0; lfn_active = true; }
            if (!lfn_active) continue;
            const pos_base = (@as(usize, seq) - 1) * 13;
            for (lfn_offsets, 0..) |off, ci| {
                const lo = raw[off];
                const hi = raw[off + 1];
                if (lo == 0 and hi == 0) break;
                if (lo == 0xFF and hi == 0xFF) break;
                const p = pos_base + ci;
                if (p < 255) {
                    lfn_buf[p] = if (hi == 0) lo else '?';
                    if (p + 1 > lfn_len) lfn_len = p + 1;
                }
            }
            continue;
        }

        if (raw[11] & 0x08 != 0) { lfn_active = false; continue; } // volume ID

        const is_dir = (raw[11] & 0x10) != 0;
        const de: *const fat32.DirEntry = @ptrCast(@alignCast(&raw));
        var entry: FileEntry = undefined;
        @memset(&entry.name, 0);
        @memset(&entry._pad, 0);

        if (lfn_active and lfn_len > 0) {
            const copy_len = @min(lfn_len, 32);
            @memcpy(entry.name[0..copy_len], lfn_buf[0..copy_len]);
            entry.name_len = @intCast(copy_len);
        } else {
            var pos: u8 = 0;
            var base_end: u8 = 8;
            while (base_end > 0 and de.name[base_end - 1] == ' ') base_end -= 1;
            for (0..base_end) |j| { entry.name[pos] = toLower(de.name[j]); pos += 1; }
            var ext_end: u8 = 3;
            while (ext_end > 0 and de.name[8 + ext_end - 1] == ' ') ext_end -= 1;
            if (ext_end > 0) {
                entry.name[pos] = '.'; pos += 1;
                for (0..ext_end) |j| { entry.name[pos] = toLower(de.name[8 + j]); pos += 1; }
            }
            entry.name_len = pos;
        }

        // Skip `.` and `..` self/parent links — most tools don't want them.
        if (entry.name_len == 1 and entry.name[0] == '.') { lfn_active = false; continue; }
        if (entry.name_len == 2 and entry.name[0] == '.' and entry.name[1] == '.') { lfn_active = false; continue; }

        entry.file_size = de.file_size;
        // Unified flag layout — see lib/libc.zig FE_FLAG_*.
        //   bit0 = is_elf, bit1 = is_dir, bit2 = from_fat32, bit3 = from_ext2.
        var f: u8 = 0x04; // from_fat32
        if (isElfName(entry.name[0..entry.name_len])) f |= 0x01;
        if (is_dir) f |= 0x02;
        entry.flags = f;
        entries[count] = entry;
        count += 1;
        lfn_active = false;
    }
    return count;
}

pub fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

pub fn isElfName(name: []const u8) bool {
    if (name.len < 4) return false;
    const ext = name[name.len - 4 ..];
    return (ext[0] == '.' and (ext[1] == 'e' or ext[1] == 'E') and
        (ext[2] == 'l' or ext[2] == 'L') and (ext[3] == 'f' or ext[3] == 'F'));
}

pub fn sysFsize(name_ptr: u32) u32 {
    if (!validateUserPtr(name_ptr, 1)) return E_FAULT;
    const name_bytes: [*]const u8 = @ptrFromInt(@as(usize, name_ptr));
    var name_len: usize = 0;
    while (name_len < 100 and name_bytes[name_len] != 0) : (name_len += 1) {}
    if (name_len == 0) return E_INVAL;
    const result = vfs.fileSize(name_bytes[0..name_len]) orelse 0xFFFFFFFF;
    if (process.getCurrentPid() == 4) {
        debug.klog("[fsize-dbg] pid=4 path='{s}' len={d} -> {x}\n", .{ name_bytes[0..name_len], name_len, result });
    }
    return result;
}

// --- GPU 3D syscalls ---

pub fn sysChdir(path_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    // Pre-cast guard: same null-cast safety check as sysMkdir.
    if (!validateUserPtr(path_ptr, 1)) return E_INVAL;

    // Read NUL-terminated path from user space.
    var path_buf: [256]u8 = undefined;
    var path_len: usize = 0;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));
    while (path_len < 256) : (path_len += 1) {
        if (!validateUserPtr(path_ptr + @as(u32, @intCast(path_len)), 1)) return E_INVAL;
        const ch = src[path_len];
        if (ch == 0) break;
        path_buf[path_len] = ch;
    }
    if (path_len == 0 or path_len >= 256) return E_NAMETOOLONG;

    // Build the absolute candidate. Relative paths get the current cwd
    // prepended (cwd is stored with a trailing '/' so concatenation is
    // straightforward — see the trailing-slash invariant below).
    var abs: [256]u8 = undefined;
    var abs_len: usize = 0;
    if (path_buf[0] == '/') {
        @memcpy(abs[0..path_len], path_buf[0..path_len]);
        abs_len = path_len;
    } else {
        const cwd = pcb.cwd[0..pcb.cwd_len];
        if (cwd.len == 0) return E_INVAL;
        const need_sep = cwd[cwd.len - 1] != '/';
        const need = cwd.len + path_len + (if (need_sep) @as(usize, 1) else 0);
        if (need > 256) return E_INVAL;
        @memcpy(abs[0..cwd.len], cwd);
        abs_len = cwd.len;
        if (need_sep) {
            abs[abs_len] = '/';
            abs_len += 1;
        }
        @memcpy(abs[abs_len..][0..path_len], path_buf[0..path_len]);
        abs_len += path_len;
    }

    // Normalize: strip duplicate slashes, drop "." components, and resolve
    // ".." by popping the previous component. ".." at or above the first
    // component is clamped (stays at the mount root) instead of escaping
    // up to "/", which has no mount and would always fail.
    abs_len = normalizePath(&abs, abs_len);
    if (abs_len == 0) return E_INVAL;

    // Trailing-slash invariant: cwd always ends with '/' so resolvePath's
    // relative-path concat ("cwd + child") doesn't produce missing or
    // doubled separators.
    if (abs[abs_len - 1] != '/') {
        if (abs_len >= 256) return E_INVAL;
        abs[abs_len] = '/';
        abs_len += 1;
    }

    // Validate. Two acceptable shapes:
    //   1. abs is a mount root exactly (e.g. "/tar/") — resolvePath rejects
    //      these because it requires a non-empty rel under the mount.
    //   2. abs (sans trailing '/') resolves under some mount, AND the
    //      resolved fs confirms the path is an existing directory.
    if (!vfs.isMountRoot(abs[0..abs_len])) {
        var rb: [256]u8 = undefined;
        const r = vfs.resolvePath(pcb, abs[0 .. abs_len - 1], &rb) orelse return E_NOENT;
        // Per-fs existence check. tarfs is flat (no real subdirs) so we
        // accept any junk and let later opens fail — matches historical
        // behavior. Other filesystems can verify, so they do.
        switch (r.fs) {
            .tarfs => {},
            .fat32 => {
                const fat32 = @import("../../fs/fat32.zig");
                if (fat32.resolveDirCluster(r.path) == null) return E_INVAL;
            },
            .devfs => {
                // devfs has no subdirectories — any non-empty path is a file.
                return E_INVAL;
            },
            .procfs => {
                const procfs = @import("../../fs/procfs.zig");
                if (!procfs.isDirectory(r.path)) return E_INVAL;
            },
            .ext2 => {
                const ext2 = @import("../../fs/ext2/ext2.zig");
                if (ext2.resolveDirInum(r.path) == null) return E_INVAL;
            },
        }
    }

    if (abs_len > pcb.cwd.len) return E_INVAL;
    @memcpy(pcb.cwd[0..abs_len], abs[0..abs_len]);
    pcb.cwd_len = @intCast(abs_len);
    return 0;
}

/// Collapse `.` and `..` components and duplicate slashes in an absolute
/// path. Mutates `buf` in place; returns the new length. ".." that would
/// pop the first (mount-name) component is silently dropped — `cd ..`
/// from `/tar/` should stay at `/tar/` rather than escape to `/`.
pub fn normalizePath(buf: *[256]u8, in_len: usize) usize {
    if (in_len == 0 or buf[0] != '/') return in_len;

    // Component table — offset/length within the input. 32 components is
    // way more than any realistic path; if exceeded we punt and return
    // the original length unchanged (callers will see the long path and
    // fail downstream).
    var comp_off: [32]u8 = undefined;
    var comp_len: [32]u8 = undefined;
    var n: usize = 0;

    var i: usize = 1;
    while (i < in_len) {
        var j = i;
        while (j < in_len and buf[j] != '/') j += 1;
        const len = j - i;
        if (len == 0) {
            // empty component (// in path) — skip
        } else if (len == 1 and buf[i] == '.') {
            // "." — skip
        } else if (len == 2 and buf[i] == '.' and buf[i + 1] == '.') {
            // ".." — pop, but never the first (mount) component
            if (n > 1) n -= 1;
        } else {
            if (n >= 32) return in_len;
            comp_off[n] = @intCast(i);
            comp_len[n] = @intCast(len);
            n += 1;
        }
        i = j + 1;
    }

    // Rebuild via a scratch buffer so we don't read-after-write issues —
    // comp_off points into `buf`, and we rewrite `buf` from the start.
    var out: [256]u8 = undefined;
    var out_len: usize = 1;
    out[0] = '/';
    for (0..n) |k| {
        const off = comp_off[k];
        const len = comp_len[k];
        if (out_len + len + 1 > out.len) return in_len;
        @memcpy(out[out_len..][0..len], buf[off..][0..len]);
        out_len += len;
        out[out_len] = '/';
        out_len += 1;
    }
    @memcpy(buf[0..out_len], out[0..out_len]);
    return out_len;
}

pub fn sysGetcwd(buf_ptr: u32, size: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    const cwd_len = pcb.cwd_len;
    if (size < cwd_len + 1) return E_INVAL; // need space for null terminator
    if (!validateUserPtrWrite(buf_ptr, cwd_len + 1)) return E_FAULT;

    const dest: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    @memcpy(dest[0..cwd_len], pcb.cwd[0..cwd_len]);
    dest[cwd_len] = 0; // null terminator

    return cwd_len;
}

pub fn sysMkdir(path_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    // Pre-cast guard. `[*]const u8 = @ptrFromInt(0)` triggers Zig's runtime
    // null-cast safety check before we ever reach the per-byte
    // validateUserPtr in the loop below — caught by redteam fuzzer hitting
    // sysMkdir with arg1=0. Validate at least the first byte upfront so the
    // cast itself is safe.
    if (!validateUserPtr(path_ptr, 1)) return E_INVAL;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    var path_len: usize = 0;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));

    while (path_len < 256) : (path_len += 1) {
        if (!validateUserPtr(path_ptr + @as(u32, @intCast(path_len)), 1)) return E_INVAL;
        const ch = src[path_len];
        if (ch == 0) break;
        path_buf[path_len] = ch;
    }

    if (path_len == 0 or path_len >= 256) return E_NAMETOOLONG;

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    switch (resolved.fs) {
        .fat32 => {
            const fat32 = @import("../../fs/fat32.zig");
            return if (fat32.createDirectory(resolved.path)) 0 else E_INVAL;
        },
        .ext2 => {
            const ext2 = @import("../../fs/ext2/ext2.zig");
            return if (ext2.mkdirPath(resolved.path)) 0 else E_INVAL;
        },
        else => return E_INVAL,
    }
}

pub fn sysReaddir(path_ptr: u32, buf_ptr: u32, buf_size: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    // Pre-cast guard: same null-cast safety check as sysMkdir.
    if (!validateUserPtr(path_ptr, 1)) return E_INVAL;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    var path_len: usize = 0;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));

    while (path_len < 256) : (path_len += 1) {
        if (!validateUserPtr(path_ptr + @as(u32, @intCast(path_len)), 1)) return E_INVAL;
        const ch = src[path_len];
        if (ch == 0) break;
        path_buf[path_len] = ch;
    }

    if (path_len == 0 or path_len >= 256) return E_NAMETOOLONG;
    if (!validateUserPtrWriteAligned(buf_ptr, buf_size, @alignOf(FileEntry))) return E_FAULT;

    const entry_size: u32 = @sizeOf(FileEntry);
    const max_entries = buf_size / entry_size;
    if (max_entries == 0) return E_INVAL;

    const entries: [*]FileEntry = @ptrFromInt(@as(usize, buf_ptr));

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    switch (resolved.fs) {
        .tarfs => {
            // List all files in tarfs index
            const tarfs = @import("../../fs/tarfs.zig");
            const count = tarfs.listToBuffer(@ptrCast(entries), max_entries);
            return count;
        },
        .fat32 => {
            const fat32 = @import("../../fs/fat32.zig");
            const dc = fat32.resolveDirCluster(resolved.path) orelse return E_INVAL;
            return listFatDir(dc, entries, max_entries);
        },
        .devfs => {
            const devfs = @import("../../fs/devfs.zig");
            return devfs.listToBuffer(@ptrCast(@alignCast(entries)), max_entries);
        },
        .procfs => {
            const procfs = @import("../../fs/procfs.zig");
            return procfs.listToBuffer(resolved.path, @ptrCast(@alignCast(entries)), max_entries);
        },
        .ext2 => {
            const ext2 = @import("../../fs/ext2/ext2.zig");
            const dir_inum = ext2.resolveDirInum(resolved.path) orelse return E_INVAL;
            return ext2.listDir(dir_inum, @ptrCast(@alignCast(entries)), max_entries);
        },
    }
}

pub fn sysUnlink(path_ptr: u32, path_len: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    if (path_len == 0 or path_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(path_ptr, path_len)) return E_FAULT;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));
    @memcpy(path_buf[0..path_len], src[0..path_len]);

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    switch (resolved.fs) {
        .tarfs => {
            // tarfs is read-only
            return E_INVAL;
        },
        .fat32 => {
            const fat32 = @import("../../fs/fat32.zig");
            if (fat32.deleteFile(resolved.path)) {
                return 0;
            }
            return E_INVAL;
        },
        .devfs => {
            // Can't delete device files
            return E_INVAL;
        },
        .procfs => return 0xFFFFFFFF,
        .ext2 => {
            const ext2 = @import("../../fs/ext2/ext2.zig");
            return if (ext2.unlinkPath(resolved.path)) 0 else E_INVAL;
        },
    }
}

const FileStat = extern struct {
    file_size: u32,
    is_directory: u32,
    create_time: u32,
    modify_time: u32,
};

pub fn sysStat(path_ptr: u32, path_len: u32, stat_buf_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    if (path_len == 0 or path_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(path_ptr, path_len)) return E_FAULT;
    if (!validateUserPtrWriteAligned(stat_buf_ptr, @sizeOf(FileStat), @alignOf(FileStat))) return E_INVAL;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));
    @memcpy(path_buf[0..path_len], src[0..path_len]);

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    const stat_buf: *FileStat = @ptrFromInt(@as(usize, stat_buf_ptr));

    switch (resolved.fs) {
        .tarfs => {
            const tarfs = @import("../../fs/tarfs.zig");
            if (tarfs.getFileStat(resolved.path, stat_buf)) {
                return 0;
            }
            return E_INVAL;
        },
        .fat32 => {
            const fat32 = @import("../../fs/fat32.zig");
            if (fat32.getFileStat(resolved.path, stat_buf)) {
                return 0;
            }
            return E_INVAL;
        },
        .devfs => {
            const devfs = @import("../../fs/devfs.zig");
            const idx = devfs.openFile(resolved.path) orelse return E_INVAL;
            const sz = devfs.deviceSize(idx);
            stat_buf.file_size = if (sz > 0xFFFFFFFF) 0xFFFFFFFF else @intCast(sz);
            stat_buf.is_directory = 0;
            stat_buf.create_time = 0;
            stat_buf.modify_time = 0;
            return 0;
        },
        .procfs => {
            const procfs = @import("../../fs/procfs.zig");
            if (procfs.isDirectory(resolved.path)) {
                stat_buf.file_size = 0;
                stat_buf.is_directory = 1;
                stat_buf.create_time = 0;
                stat_buf.modify_time = 0;
                return 0;
            }
            if (procfs.openFile(resolved.path)) |_| {
                stat_buf.file_size = 0;
                stat_buf.is_directory = 0;
                stat_buf.create_time = 0;
                stat_buf.modify_time = 0;
                return 0;
            }
            return E_INVAL;
        },
        .ext2 => {
            const ext2 = @import("../../fs/ext2/ext2.zig");
            if (ext2.getFileStat(resolved.path, stat_buf)) return 0;
            return E_INVAL;
        },
    }
}

pub fn sysRename(old_path_ptr: u32, old_len: u32, new_path_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    if (old_len == 0 or old_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(old_path_ptr, old_len)) return E_FAULT;

    // Read new path length from user space (stored at new_path_ptr as u32)
    if (!validateUserPtrAligned(new_path_ptr, 4, 4)) return E_FAULT;
    const new_len_ptr: *const u32 = @ptrFromInt(@as(usize, new_path_ptr));
    const new_len = new_len_ptr.*;

    if (new_len == 0 or new_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(new_path_ptr + 4, new_len)) return E_FAULT;

    // Read old path
    var old_path_buf: [256]u8 = undefined;
    const old_src: [*]const u8 = @ptrFromInt(@as(usize, old_path_ptr));
    @memcpy(old_path_buf[0..old_len], old_src[0..old_len]);

    // Read new path (skip the length prefix)
    var new_path_buf: [256]u8 = undefined;
    const new_src: [*]const u8 = @ptrFromInt(@as(usize, new_path_ptr + 4));
    @memcpy(new_path_buf[0..new_len], new_src[0..new_len]);

    // Resolve old path
    var old_resolve_buf: [256]u8 = undefined;
    const old_resolved = vfs.resolvePath(pcb, old_path_buf[0..old_len], &old_resolve_buf) orelse return E_NOENT;

    // Resolve new path
    var new_resolve_buf: [256]u8 = undefined;
    const new_resolved = vfs.resolvePath(pcb, new_path_buf[0..new_len], &new_resolve_buf) orelse return E_NOENT;

    // Must be same filesystem
    if (@intFromEnum(old_resolved.fs) != @intFromEnum(new_resolved.fs)) return E_INVAL;

    switch (old_resolved.fs) {
        .tarfs => {
            // tarfs is read-only
            return E_INVAL;
        },
        .fat32 => {
            const fat32 = @import("../../fs/fat32.zig");
            if (fat32.renameFile(old_resolved.path, new_resolved.path)) {
                return 0;
            }
            return E_INVAL;
        },
        .devfs => {
            // Can't rename device files
            return E_INVAL;
        },
        .procfs => return 0xFFFFFFFF,
        .ext2 => return E_INVAL, // Phase 2 will implement rename
    }
}

pub fn sysRmdir(path_ptr: u32, path_len: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    if (path_len == 0 or path_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(path_ptr, path_len)) return E_FAULT;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));
    @memcpy(path_buf[0..path_len], src[0..path_len]);

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    switch (resolved.fs) {
        .tarfs => {
            // tarfs is read-only
            return E_INVAL;
        },
        .fat32 => {
            const fat32 = @import("../../fs/fat32.zig");
            if (fat32.removeDirectory(resolved.path)) {
                return 0;
            }
            return E_INVAL;
        },
        .devfs => {
            // Can't remove device directories
            return E_INVAL;
        },
        .procfs => return 0xFFFFFFFF,
        .ext2 => {
            const ext2 = @import("../../fs/ext2/ext2.zig");
            return if (ext2.rmdirPath(resolved.path)) 0 else E_INVAL;
        },
    }
}

/// pipe(fds_ptr) — allocate an anonymous pipe and write [read_fd, write_fd]
/// (two u32s) into the user buffer. Returns 0 on success, 0xFFFFFFFF if the
/// pipe pool or fd table is full.
pub fn sysPipe(fds_ptr: u32) u32 {
    if (!validateUserPtrWriteAligned(fds_ptr, 8, 4)) return E_FAULT;
    const pcb = process.currentPCB() orelse return E_FAULT;

    const id = pipe.alloc() orelse return E_INVAL;

    // Find two free fd slots
    var read_fd: i32 = -1;
    var write_fd: i32 = -1;
    for (3..pcb.fd_table.len) |i| {
        if (pcb.fd_table[i].in_use) continue;
        if (read_fd < 0) {
            read_fd = @intCast(i);
        } else {
            write_fd = @intCast(i);
            break;
        }
    }
    if (read_fd < 0 or write_fd < 0) {
        // Roll back the pipe allocation
        pipe.closeReader(id);
        pipe.closeWriter(id);
        return E_INVAL;
    }

    pcb.fd_table[@intCast(read_fd)] = .{
        .in_use = true,
        .fs_type = .pipe,
        .pipe_id = id,
        .flags = 0, // read end
    };
    pcb.fd_table[@intCast(write_fd)] = .{
        .in_use = true,
        .fs_type = .pipe,
        .pipe_id = id,
        .flags = 1, // write end
    };

    const out: [*]u32 = @ptrFromInt(@as(usize, fds_ptr));
    out[0] = @intCast(read_fd);
    out[1] = @intCast(write_fd);
    return 0;
}

