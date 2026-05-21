const std = @import("std");
const fat32 = @import("fat32.zig");
const tarfs = @import("tarfs.zig");
const devfs = @import("devfs.zig");
const procfs = @import("procfs.zig");
const ext2 = @import("ext2/ext2.zig");
const process = @import("../proc/process.zig");
const keyboard = @import("../driver/keyboard.zig");
const vga = @import("../ui/vga.zig");
const pipe = @import("../proc/pipe.zig");
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");

pub const O_CREATE: u32 = 0x100;
pub const O_APPEND: u32 = 0x400; // start the fd's offset at file_size so writes append
pub const O_TRUNC: u32 = 0x200; // truncate to zero on open (writers replacing content)

pub const FsType = enum { tarfs, fat32, devfs, procfs, ext2 };

const ResolvedPath = struct {
    fs: FsType,
    path: []const u8, // path within the filesystem (without mount prefix)
};

// --- Mount table ---
//
// Filesystems are addressed via a mount-prefix → fs mapping rather than a
// hardcoded chain of `if (startsWith(p, "/tar/"))` branches scattered through
// resolvePath. The table is small (max 8 entries), statically initialized at
// comptime, and `mount()` is exposed for future runtime registration. Path
// resolution finds the *longest* matching prefix so nested mounts (e.g.
// adding "/tar/lib/" later) resolve to the more specific mount.
//
// Default mounts cover the only filesystems the kernel currently supports.
// Adding a new filesystem (e.g. tmpfs) means: register an FsType variant
// above, an entry here, and a switch arm in `read`/`write`/`close`/`open`.
pub const Mount = struct {
    prefix: []const u8, // includes leading and trailing '/' — e.g. "/tar/"
    fs: FsType,
};

pub const MAX_MOUNTS: usize = 8;

/// Mount slot table. `pub` so procfs (and any future tooling) can iterate
/// without going through findMount's path-based lookup. Writes still go
/// through `mount()` to preserve replace-or-first-free semantics.
pub var mounts: [MAX_MOUNTS]?Mount = blk: {
    var m: [MAX_MOUNTS]?Mount = [_]?Mount{null} ** MAX_MOUNTS;
    // Root mount — ext2 lives at "/". Any path that doesn't match a more
    // specific prefix below falls through to ext2 (longest-prefix-wins in
    // findMount means "/dev/foo" still goes to devfs, "/foo.elf" goes to
    // ext2 with rel="foo.elf").
    m[0] = .{ .prefix = "/", .fs = .ext2 };
    // Legacy tarfs — kept as a fallback during the ext2 migration window
    // so old paths like "/tar/app.elf" don't hard-fail. Will be dropped
    // once every consumer has moved to the root layout.
    m[1] = .{ .prefix = "/tar/", .fs = .tarfs };
    m[2] = .{ .prefix = "/fat/", .fs = .fat32 };
    m[3] = .{ .prefix = "/dev/", .fs = .devfs };
    m[4] = .{ .prefix = "/proc/", .fs = .procfs };
    break :blk m;
};

/// Register a mount. Idempotent: replaces an existing entry with the same
/// prefix, otherwise takes the first free slot. Silently no-ops when the
/// table is full — call sites today are static so this is fine; if a future
/// runtime caller needs error reporting, switch the return type to bool.
pub fn mount(prefix: []const u8, fs: FsType) void {
    for (&mounts) |*slot| {
        if (slot.*) |m| {
            if (std.mem.eql(u8, m.prefix, prefix)) {
                slot.* = .{ .prefix = prefix, .fs = fs };
                return;
            }
        }
    }
    for (&mounts) |*slot| {
        if (slot.* == null) {
            slot.* = .{ .prefix = prefix, .fs = fs };
            return;
        }
    }
}

/// True if `path` is exactly a registered mount's prefix (e.g. "/tar/").
/// Used by sysChdir so that `cd /tar/` succeeds even though the mount root
/// itself doesn't appear as a file inside the fs — `resolvePath` rejects
/// bare-mount inputs because it requires a non-empty path *under* the mount.
pub fn isMountRoot(path: []const u8) bool {
    for (mounts) |m_opt| {
        if (m_opt) |m| if (std.mem.eql(u8, m.prefix, path)) return true;
    }
    return false;
}

/// Find the mount entry whose prefix is the longest prefix of `path`.
/// Returns null if no mount matches — caller treats this as ENOENT.
pub fn findMount(path: []const u8) ?Mount {
    var best: ?Mount = null;
    for (mounts) |m_opt| {
        if (m_opt) |m| {
            if (path.len >= m.prefix.len and std.mem.startsWith(u8, path, m.prefix)) {
                if (best == null or m.prefix.len > best.?.prefix.len) {
                    best = m;
                }
            }
        }
    }
    return best;
}

/// Resolve a path to a filesystem and relative path.
/// Absolute paths look up the longest matching mount prefix.
/// Relative paths get cwd prepended and re-resolved as absolute.
pub fn resolvePath(pcb: *process.PCB, path: []const u8, path_buf: *[256]u8) ?ResolvedPath {
    if (path.len == 0) return null;

    // Absolute path → mount-table lookup.
    if (path[0] == '/') {
        const m = findMount(path) orelse return null;
        const rel = path[m.prefix.len..];
        // `rel` may already live inside `path_buf` (after a recursive cwd
        // prepend), so a plain @memcpy would alias. copyForwards is the
        // safe choice for the dst-below-src pattern we always have here.
        // Empty rel (the mount root itself, e.g. "/dev/") is allowed —
        // caller distinguishes; `open` will refuse, but `readdir` lists.
        if (rel.len > 0) std.mem.copyForwards(u8, path_buf[0..rel.len], rel);
        return .{ .fs = m.fs, .path = path_buf[0..rel.len] };
    }

    // Relative path — prepend cwd, recurse as absolute.
    const cwd = pcb.cwd[0..pcb.cwd_len];
    if (cwd.len == 0) return null;
    if (cwd.len + 1 + path.len > 256) return null;

    var buf_idx: usize = 0;
    @memcpy(path_buf[buf_idx..][0..cwd.len], cwd);
    buf_idx += cwd.len;

    if (cwd[cwd.len - 1] != '/') {
        path_buf[buf_idx] = '/';
        buf_idx += 1;
    }

    @memcpy(path_buf[buf_idx..][0..path.len], path);
    buf_idx += path.len;

    return resolvePath(pcb, path_buf[0..buf_idx], path_buf);
}

pub fn open(pcb: *process.PCB, name: []const u8) ?u32 {
    return openFlags(pcb, name, 0);
}

pub fn openFlags(pcb: *process.PCB, name: []const u8, flags: u32) ?u32 {
    var path_buf: [256]u8 = undefined;
    const resolved = resolvePath(pcb, name, &path_buf) orelse return null;

    switch (resolved.fs) {
        .tarfs => {
            if (tarfs.openFile(resolved.path)) |tar_idx| {
                if (allocFd(pcb)) |fd_idx| {
                    pcb.fd_table[fd_idx] = .{
                        .in_use = true,
                        .inode = tar_idx,
                        .offset = 0,
                        .flags = 2,
                        .fs_type = .tarfs,
                    };
                    return @intCast(fd_idx);
                }
                tarfs.closeFile(tar_idx);
            }
            return null;
        },
        .fat32 => {
            // Try to open existing file
            if (fat32.openFile(resolved.path)) |handle| {
                if (allocFd(pcb)) |fd_idx| {
                    // O_APPEND positions the offset at end-of-file so the first
                    // write extends rather than overwrites. fat32.writeFile
                    // already handles offset > file_size by allocating new
                    // clusters as needed.
                    const start_offset: u32 = if (flags & O_APPEND != 0) handle.file_size else 0;
                    pcb.fd_table[fd_idx] = .{
                        .in_use = true,
                        .inode = handle.dir_index,
                        .offset = start_offset,
                        .flags = 2,
                        .fs_type = .fat32,
                        .fat_dir_cluster = handle.dir_cluster,
                    };
                    return @intCast(fd_idx);
                }
                return null;
            }

            // Not found — create if O_CREATE flag set
            if (flags & O_CREATE != 0) {
                if (fat32.createFile(resolved.path)) |handle| {
                    if (allocFd(pcb)) |fd_idx| {
                        pcb.fd_table[fd_idx] = .{
                            .in_use = true,
                            .inode = handle.dir_index,
                            .offset = 0,
                            .flags = 2,
                            .fs_type = .fat32,
                            .fat_dir_cluster = handle.dir_cluster,
                        };
                        return @intCast(fd_idx);
                    }
                }
            }
            return null;
        },
        .devfs => {
            const dev_idx = devfs.openFile(resolved.path) orelse return null;
            const fd_idx = allocFd(pcb) orelse return null;
            pcb.fd_table[fd_idx] = .{
                .in_use = true,
                .inode = dev_idx,
                .offset = 0,
                .flags = 2,
                .fs_type = .devfs,
            };
            return @intCast(fd_idx);
        },
        .procfs => {
            const inode = procfs.openFile(resolved.path) orelse return null;
            const fd_idx = allocFd(pcb) orelse return null;
            pcb.fd_table[fd_idx] = .{
                .in_use = true,
                .inode = inode,
                .offset = 0,
                .flags = 0, // procfs is read-only
                .fs_type = .procfs,
            };
            return @intCast(fd_idx);
        },
        .ext2 => {
            // Try open existing first.
            if (ext2.openFile(resolved.path)) |handle| {
                // O_TRUNC on an existing file: free all data + indirect-tree
                // blocks and reset size to 0. The next writeFile re-allocates.
                if (flags & O_TRUNC != 0) _ = ext2.truncate(handle.inum);
                const start_offset: u32 = if (flags & O_APPEND != 0) @intCast(handle.file_size) else 0;
                const fd_idx = allocFd(pcb) orelse return null;
                pcb.fd_table[fd_idx] = .{
                    .in_use = true,
                    .inode = handle.inum,
                    .offset = start_offset,
                    .flags = 2,
                    .fs_type = .ext2,
                };
                return @intCast(fd_idx);
            }

            // Not found — create if O_CREATE flag set.
            if (flags & O_CREATE != 0) {
                if (ext2.createFilePath(resolved.path)) |handle| {
                    const fd_idx = allocFd(pcb) orelse return null;
                    pcb.fd_table[fd_idx] = .{
                        .in_use = true,
                        .inode = handle.inum,
                        .offset = 0,
                        .flags = 2,
                        .fs_type = .ext2,
                    };
                    return @intCast(fd_idx);
                }
            }
            return null;
        },
    }
}

pub fn read(pcb: *process.PCB, fd: u32, buf: [*]u8, count: u32) u32 {
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return 0xFFFFFFFF;
    const fd_entry = &pcb.fd_table[fd];

    switch (fd_entry.fs_type) {
        .console => {
            if (fd != 0) return 0;
            // Reads from the focused window's per-window event queue
            // (ui/events.zig). Lazy import to keep vfs ↔ desktop one-way.
            const desktop = @import("../ui/desktop.zig");
            const cur: u8 = @intCast(pcb.tgid);
            var bytes_read: u32 = 0;
            while (bytes_read < count) {
                if (desktop.popCharEvent(cur)) |ch| {
                    buf[bytes_read] = ch;
                    bytes_read += 1;
                } else break;
            }
            return bytes_read;
        },
        .fat32 => {
            const dc = if (fd_entry.fat_dir_cluster != 0) fd_entry.fat_dir_cluster else fat32.root_cluster;
            const handle = fat32.Handle{
                .dir_cluster = dc,
                .dir_index = fd_entry.inode,
                .first_cluster = fat32.getFirstClusterAt(dc, fd_entry.inode),
                .file_size = fat32.getFileSizeAt(dc, fd_entry.inode),
                .current_offset = fd_entry.offset,
            };
            var new_cluster: u32 = 0;
            var new_off: u32 = 0;
            const bytes_read = fat32.readFileAt(handle, buf, count, fd_entry.fat_cluster, fd_entry.fat_cluster_off, &new_cluster, &new_off);
            fd_entry.offset += @intCast(bytes_read);
            fd_entry.fat_cluster = new_cluster;
            fd_entry.fat_cluster_off = new_off;
            return @intCast(bytes_read);
        },
        .tarfs => {
            const bytes_read = tarfs.readFile(@intCast(fd_entry.inode), buf, count);
            fd_entry.offset += @intCast(bytes_read);
            return @intCast(bytes_read);
        },
        .pipe => {
            // Pipes only valid as read-side here. Write-side fds use sysFwrite path.
            if (fd_entry.flags != 0) return 0xFFFFFFFF;
            const n = pipe.read(fd_entry.pipe_id, buf[0..count]);
            return @intCast(n);
        },
        .devfs => {
            // devfs.read advances fd_entry.offset itself — kmsg's stream
            // position has to move past bytes that aged out of the ring,
            // which is more than just the count returned.
            return devfs.read(fd_entry.inode, &fd_entry.offset, buf, count);
        },
        .procfs => {
            const n = procfs.read(fd_entry.inode, fd_entry.offset, buf, count);
            fd_entry.offset += n;
            return n;
        },
        .ext2 => {
            const handle = ext2.Handle{
                .inum = fd_entry.inode,
                .file_size = 0, // Phase 1 readFile doesn't enforce; readInodeBytes clips at EOF
                .current_offset = fd_entry.offset,
            };
            const n = ext2.readFile(handle, buf, count);
            fd_entry.offset += @intCast(n);
            return @intCast(n);
        },
    }
}

pub fn write(pcb: *process.PCB, fd: u32, buf: [*]const u8, count: u32) u32 {
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return 0xFFFFFFFF;
    const fd_entry = &pcb.fd_table[fd];

    switch (fd_entry.fs_type) {
        .console => {
            if (fd != 1 and fd != 2) return 0;
            vga.print("{s}", .{buf[0..count]});
            // Mirror to serial with an [app] prefix so kernel-side traces
            // can correlate user output with kernel events. This used to
            // live in sysPrint (syscall 1), but libc.print now routes via
            // fwrite(1, ...) so the logging moved here to follow the data.
            @import("../debug/serial.zig").print("[app] {s}", .{buf[0..count]});
            return count;
        },
        .fat32 => {
            const dc = if (fd_entry.fat_dir_cluster != 0) fd_entry.fat_dir_cluster else fat32.root_cluster;
            var handle = fat32.Handle{
                .dir_cluster = dc,
                .dir_index = fd_entry.inode,
                .first_cluster = fat32.getFirstClusterAt(dc, fd_entry.inode),
                .file_size = fat32.getFileSizeAt(dc, fd_entry.inode),
                .current_offset = fd_entry.offset,
            };
            const bytes_written = fat32.writeFile(&handle, buf, count);
            fd_entry.offset += @intCast(bytes_written);
            return @intCast(bytes_written);
        },
        .tarfs => {
            return 0xFFFFFFFF; // tarfs is read-only
        },
        .pipe => {
            // Only valid as write-side here. Read-side fds use sysFread path.
            if (fd_entry.flags != 1) return 0xFFFFFFFF;
            const n = pipe.write(fd_entry.pipe_id, buf[0..count]);
            return @intCast(n);
        },
        .devfs => {
            const n = devfs.write(fd_entry.inode, fd_entry.offset, buf, count);
            if (n != 0xFFFFFFFF) fd_entry.offset += n;
            return n;
        },
        .procfs => return 0xFFFFFFFF, // read-only
        .ext2 => {
            var handle = ext2.Handle{
                .inum = fd_entry.inode,
                .file_size = 0, // refreshed by writeFile
                .current_offset = fd_entry.offset,
            };
            const bytes_written = ext2.writeFile(&handle, buf, count);
            fd_entry.offset += bytes_written;
            return bytes_written;
        },
    }
}

pub fn close(pcb: *process.PCB, fd: u32) u32 {
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return 0xFFFFFFFF;
    if (fd < 3) return 0xFFFFFFFF; // can't close stdin/stdout/stderr
    const fd_entry = &pcb.fd_table[fd];

    switch (fd_entry.fs_type) {
        .console => {},
        .fat32 => {
            const dc = if (fd_entry.fat_dir_cluster != 0) fd_entry.fat_dir_cluster else fat32.root_cluster;
            fat32.closeFile(fat32.Handle{
                .dir_cluster = dc,
                .dir_index = fd_entry.inode,
                .first_cluster = fat32.getFirstClusterAt(dc, fd_entry.inode),
                .file_size = fat32.getFileSizeAt(dc, fd_entry.inode),
                .current_offset = fd_entry.offset,
            });
        },
        .tarfs => {
            tarfs.closeFile(@intCast(fd_entry.inode));
        },
        .pipe => {
            if (fd_entry.flags == 0) {
                pipe.closeReader(fd_entry.pipe_id);
            } else {
                pipe.closeWriter(fd_entry.pipe_id);
            }
        },
        .devfs => {
            devfs.closeFile(fd_entry.inode);
        },
        .procfs => {
            procfs.closeFile(fd_entry.inode);
        },
        .ext2 => {
            // ext2.closeFile is a no-op — Handle is pure value, nothing to release.
        },
    }
    fd_entry.in_use = false;
    return 0;
}

pub fn ls() void {
    tarfs.ls();
    fat32.listFiles();
}

pub fn loadFile(name: []const u8, dest: []align(4) u8) ?usize {
    // Kernel-context load (no PCB, so no cwd) — strictly absolute paths.
    // Mount table dispatch matches the per-fs `read`/`open` paths used
    // from user processes, so behavior is consistent across both.
    if (name.len > 0 and name[0] == '/') {
        const m = findMount(name) orelse return null;
        const rel = name[m.prefix.len..];
        return switch (m.fs) {
            .tarfs => tarfs.loadFile(rel, dest),
            .ext2 => ext2.loadFile(rel, dest),
            .fat32 => blk: {
                if (fat32.openFile(rel)) |handle| {
                    const size = handle.file_size;
                    if (size > 0) {
                        const want: u32 = @intCast(@min(@as(u64, size), dest.len));
                        const r = fat32.readFile(handle, @ptrCast(dest.ptr), want);
                        fat32.closeFile(handle);
                        if (r > 0) break :blk r;
                    } else {
                        fat32.closeFile(handle);
                    }
                }
                break :blk null;
            },
            // devfs/procfs aren't loadable as files (they're streamed) — kernel
            // load callers shouldn't be asking for them.
            else => null,
        };
    }

    // Bare-filename fallback for legacy callers (sysExec passing "cat.elf"
    // unqualified, KERNEL.SYM / BUILD.ID lookups). Resolution order:
    //   1. ext2 root  — for files at `/` like KERNEL.SYM, BUILD.ID
    //   2. ext2 /bin  — for shell-style `cat` → /bin/cat.elf (PATH analogue)
    //   3. tarfs      — legacy fallback during migration
    //   4. fat32      — only matters with /fat/ disk attached
    if (ext2.loadFile(name, dest)) |size| return size;
    if (binFallback(name, dest)) |size| return size;
    if (tarfs.loadFile(name, dest)) |size| return size;
    if (fat32.openFile(name)) |handle| {
        const size = handle.file_size;
        if (size > 0) {
            const want: u32 = @intCast(@min(@as(u64, size), dest.len));
            const r = fat32.readFile(handle, @ptrCast(dest.ptr), want);
            fat32.closeFile(handle);
            if (r > 0) return r;
        } else {
            fat32.closeFile(handle);
        }
    }
    return null;
}

/// Try `ext2.loadFile("bin/" ++ name)`. Used by the bare-name fallback
/// path so that `sysExec("cat.elf")` finds `/bin/cat.elf` without the
/// shell having to prepend the prefix itself.
fn binFallback(name: []const u8, dest: []align(4) u8) ?usize {
    var buf: [128]u8 = undefined;
    const prefix = "bin/";
    if (name.len + prefix.len > buf.len) return null;
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..name.len], name);
    return ext2.loadFile(buf[0 .. prefix.len + name.len], dest);
}

fn binFallbackSize(name: []const u8) ?u64 {
    var buf: [128]u8 = undefined;
    const prefix = "bin/";
    if (name.len + prefix.len > buf.len) return null;
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..name.len], name);
    return ext2.fileSize(buf[0 .. prefix.len + name.len]);
}

pub fn fileSize(name: []const u8) ?u32 {
    // Mount-table dispatch — matches `loadFile` exactly so any path that
    // succeeds in one will succeed in the other.
    if (name.len > 0 and name[0] == '/') {
        const m = findMount(name) orelse return null;
        const rel = name[m.prefix.len..];
        return switch (m.fs) {
            .tarfs => if (tarfs.fileSize(rel)) |s| @as(?u32, @intCast(s)) else null,
            .ext2 => if (ext2.fileSize(rel)) |s| @as(?u32, @intCast(s)) else null,
            .fat32 => blk: {
                if (fat32.openFile(rel)) |handle| {
                    const size = handle.file_size;
                    fat32.closeFile(handle);
                    break :blk size;
                }
                break :blk null;
            },
            .devfs => devfs.fileSize(rel),
            .procfs => procfs.fileSize(rel),
        };
    }

    // Bare-filename fallback — same chain as `loadFile`: ext2 root,
    // ext2 /bin, tarfs, fat32. Keep the two paths in lock-step or
    // `loadFileFresh` will allocate the wrong buffer size.
    if (ext2.fileSize(name)) |s| return @intCast(s);
    if (binFallbackSize(name)) |s| return @intCast(s);
    if (tarfs.fileSize(name)) |s| return @intCast(s);
    if (fat32.openFile(name)) |handle| {
        const size = handle.file_size;
        fat32.closeFile(handle);
        return size;
    }
    return null;
}

/// A PMM-allocated file buffer ready to hand to elf_loader.loadAndStart
/// (which takes ownership) or pmm.freeFrame'd by the caller on cleanup.
pub const FreshFile = struct {
    buf: [*]align(4) u8,
    size: usize,
    pages: u32,
};

/// Architectural replacement for the `staging` pattern: size the file via
/// the directory entry, allocate from PMM (which excludes kernel image and
/// other reserved phys ranges), then read directly into that buffer. No
/// fixed-VA staging, so a growing kernel image can never collide with the
/// load destination — the bug class is impossible by construction.
///
/// Caller owns the returned buffer. Either pass it to
/// elf_loader.loadAndStart (which takes ownership), or free pages with
/// pmm.freeFrame on each phys page.
pub fn loadFileFresh(name: []const u8) ?FreshFile {
    const perf = @import("../debug/perf.zig");
    const serial = @import("../debug/serial.zig");
    const nvme = @import("../driver/nvme.zig");
    // Per-syscall latency attribution — sysExec, sysExecAs, sysFsize, etc.
    // all bottom out here. Brackets the disk read so slow-sc shows the
    // disk-vs-other split instead of just total ms.
    const sp = @import("../debug/syscall_perf.zig").scope(.disk_read);
    defer sp.end();
    const t0 = perf.rdtsc();
    const size = fileSize(name) orelse return null;
    const t1 = perf.rdtsc();
    if (size == 0) return null;
    const pages: u32 = @intCast((@as(usize, size) + 4095) / 4096);
    const phys = pmm.allocContiguous(pages) orelse return null;
    const t2 = perf.rdtsc();
    // Reach the PMM-allocated buffer through the kernel physmap.
    const buf: [*]align(4) u8 = @ptrFromInt(paging.physToVirt(phys));

    // NVMe-stats snapshot — diff'd after loadFile to attribute calls/cycles
    // to this specific load rather than the global counters.
    const io_calls0 = nvme.io_call_count;
    const io_cyc0 = nvme.io_total_cycles;
    const io_wait0 = nvme.io_wait_cycles;
    const io_retgt0 = nvme.io_msix_retargets;
    const io_irq0 = nvme.irq_count;
    nvme.io_max_wait_cycles = 0; // local-max for this load only

    if (loadFile(name, buf[0 .. @as(usize, pages) * 4096])) |got| {
        const t3 = perf.rdtsc();
        const io_calls = nvme.io_call_count - io_calls0;
        const io_cyc = nvme.io_total_cycles - io_cyc0;
        const io_wait = nvme.io_wait_cycles - io_wait0;
        const io_retgt = nvme.io_msix_retargets - io_retgt0;
        const io_irqs = nvme.irq_count - io_irq0;
        const max_wait = nvme.io_max_wait_cycles;
        const per_call_avg = if (io_calls > 0) (io_cyc / io_calls) else 0;
        const per_wait_avg = if (io_calls > 0) (io_wait / io_calls) else 0;
        serial.print(
            "[vfs.timing] {s}: size={d} pages={d} fileSize={d}M alloc={d}M loadFile={d}M | nvme calls={d} cyc={d}M wait={d}M retgt={d} irqs={d} avg_call={d}c avg_wait={d}c max_wait={d}c\n",
            .{
                name,
                size,
                pages,
                (t1 -% t0) >> 20,
                (t2 -% t1) >> 20,
                (t3 -% t2) >> 20,
                io_calls,
                io_cyc >> 20,
                io_wait >> 20,
                io_retgt,
                io_irqs,
                per_call_avg,
                per_wait_avg,
                max_wait,
            },
        );
        if (got == size) return .{ .buf = buf, .size = size, .pages = pages };
    }
    pmm.freeContiguous(phys, @intCast(pages));
    return null;
}

fn allocFd(pcb: *process.PCB) ?usize {
    for (3..pcb.fd_table.len) |fd_idx| {
        if (!pcb.fd_table[fd_idx].in_use) return fd_idx;
    }
    return null;
}
