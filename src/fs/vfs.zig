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
const page_cache = @import("../mm/page_cache.zig");

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

/// Open a directory for getdents-style enumeration (ext2 only — the writable
/// root fs). Returns an fd whose `.inode` is the directory's inum and
/// `.fs_type == .ext2`. ext2.openFile rejects non-regular files, so a Linux
/// binary's openat(O_DIRECTORY) falls back to this when the regular-file open
/// path returns null. No "is-dir" bit is stored — getdents64 / fstat re-read
/// the inode to learn the type.
pub fn openDir(pcb: *process.PCB, name: []const u8) ?u32 {
    var path_buf: [256]u8 = undefined;
    const resolved = resolvePath(pcb, name, &path_buf) orelse return null;
    if (resolved.fs != .ext2) return null;
    const dir_inum = ext2.resolveDirInum(resolved.path) orelse return null;
    const fd_idx = allocFd(pcb) orelse return null;
    pcb.fd_table[fd_idx] = .{
        .in_use = true,
        .inode = dir_inum,
        .offset = 0,
        .flags = 0,
        .fs_type = .ext2,
    };
    return @intCast(fd_idx);
}

/// Shared stat shape (file_size / is_directory / times) used by the Linux
/// personality's newfstatat to reshape into a Linux `struct stat`.
pub const StatInfo = extern struct {
    file_size: u32,
    is_directory: u32,
    create_time: u32,
    modify_time: u32,
};

/// Path-based stat for the Linux personality (ext2 root fs only — where
/// unmodified Linux binaries actually operate). Fills `out`; caller reshapes.
pub fn statPath(pcb: *process.PCB, name: []const u8, out: *StatInfo) bool {
    var path_buf: [256]u8 = undefined;
    const resolved = resolvePath(pcb, name, &path_buf) orelse return false;
    if (resolved.fs != .ext2) return false;
    return ext2.getFileStat(resolved.path, out);
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
            // Through the unified page cache (Slice 3b): a page read here is the
            // SAME physical frame a later mmap of this file maps, and vice versa.
            // Falls back to a private uncached read only under frame OOM.
            const n = readThroughCache(fd_entry.inode, fd_entry.offset, buf, count);
            fd_entry.offset += n;
            return n;
        },
        .tcp_sock => {
            // Non-blocking read on the conn ring. Pollers handle blocking
            // via OP_POLL; raw read() returns 0 when there's nothing yet
            // (mirrors sys#72 net_tcp_recv semantics).
            const net = @import("../net/net.zig");
            net.poll();
            return @intCast(net.tcpRecv(@intCast(fd_entry.inode), buf[0..count]));
        },
        .tcp_listener => return 0xFFFFFFFF, // listeners aren't readable; use accept()
    }
}

/// Demand-fill one page for the unified page cache: read up to one page (4 KiB)
/// at absolute byte `offset` from ext2 inode `inode` into `buf`, WITHOUT an fd
/// or FileDesc — a file mmap can outlive the fd that created it. Returns the
/// number of bytes read (clipped at EOF; the caller zero-fills the tail). ext2
/// only: sysMmap routes only ext2 fds through the cache, so this is the only
/// backing store the page-cache fault path needs today.
pub fn fillCachePage(inode: u32, offset: u64, buf: [*]u8) u32 {
    const handle = ext2.Handle{ .inum = inode, .file_size = 0, .current_offset = offset };
    return @intCast(ext2.readFile(handle, buf, 0x1000));
}

/// Read up to `count` bytes from ext2 inode `inum` at byte `offset` into user
/// `buf`, THROUGH the unified page cache — the read() half of the cache
/// unification (Slice 3b). Each touched page is pinned on a hit, or read into a
/// private frame and published on a miss, so a page pulled in by read() is the
/// same physical frame a later mmap of this file maps (and vice versa). Mirrors
/// faultInCachePage's hit-or-fill, but copies to the user buffer instead of
/// mapping. Returns bytes read, clipped at EOF exactly like readInodeBytes; the
/// caller advances the fd offset by the return value.
///
/// The per-page copy is deliberately two-step: frame → kstack scratch while
/// holding the cache reference (kernel-to-kernel, so eviction can't free the
/// page and the copy can't fault-kill), then scratch → user AFTER dropping the
/// reference (so a malformed user buffer that #PFs can't leak the frame's
/// refcount). The 64 KB kstack swallows the 4 KB scratch with room to spare.
pub fn readThroughCache(inum: u32, offset: u64, buf: [*]u8, count: u32) u32 {
    if (count == 0) return 0;
    // Only REGULAR-file data rides the page cache — it's the sole thing the
    // write/truncate/free invalidation (Slice 3a) and the mmap path cover.
    // Directories, symlinks, devices (and an unreadable inode) bypass the cache
    // and read straight through, exactly as before, so e.g. a directory mutation
    // (which doesn't touch the page cache) can never serve stale dirents.
    const info = ext2.cacheReadInfo(inum);
    if (!info.is_reg)
        return @intCast(ext2.readFile(.{ .inum = inum, .file_size = 0, .current_offset = offset }, buf, count));
    // EOF clip from the inode's current size — the same source readInodeBytes
    // uses, so we stop where the old path did and never surface a cached page's
    // zero-filled past-EOF tail as data. info.size is NOT u32-bounded (ext2
    // LARGE_FILE reaches 2^48), so the `@as(u64, count)` is load-bearing — it
    // clamps want to count (<= u32max). Don't "simplify" it to a bare `count`.
    if (offset >= info.size) return 0;
    const want: u64 = @min(@as(u64, count), info.size - offset);

    const file_id = page_cache.ext2FileId(inum);
    var scratch: [0x1000]u8 align(8) = undefined;
    var done: u64 = 0;
    while (done < want) {
        const cur = offset + done;
        const page_off = cur & ~@as(u64, 0xFFF);
        const in_page: u64 = cur & 0xFFF;
        const chunk: u64 = @min(@as(u64, 0x1000) - in_page, want - done);
        const ip: usize = @intCast(in_page);
        const ck: usize = @intCast(chunk);
        const dst_off: usize = @intCast(done);

        const frame = page_cache.pin(file_id, page_off) orelse blk: {
            // Miss (or the resident page is at PIN_SATURATION): fill a PRIVATE
            // frame with NO cache lock held, then publish it atomically.
            const pf = pmm.allocFrameUser() orelse {
                // Out of frames: finish the remainder with a direct uncached
                // read so the call still makes forward progress, then stop.
                const nread: u64 = @intCast(ext2.readFile(.{ .inum = inum, .file_size = 0, .current_offset = cur }, buf + dst_off, @intCast(want - done)));
                return @intCast(done + nread);
            };
            const fdst: [*]u8 = @ptrFromInt(paging.physToVirt(pf));
            const got: u64 = @min(@as(u64, fillCachePage(inum, page_off, fdst)), 0x1000);
            if (got < 0x1000) @memset(fdst[@as(usize, @intCast(got))..0x1000], 0); // zero tail past EOF
            break :blk page_cache.insertFilled(file_id, page_off, pf);
        };

        // frame -> kstack scratch, under the reference (cannot fault-kill).
        const src: [*]const u8 = @ptrFromInt(paging.physToVirt(frame));
        @memcpy(scratch[0..ck], src[ip .. ip + ck]);
        pmm.releaseFrame(frame); // drop the pin / insertFilled ref BEFORE the user copy

        // scratch -> user (no cache ref held; a faulting user page is safe now).
        // Like the existing readInodeBytes path this user write isn't SMAP-
        // bracketed — it rides the syscall-context AC discipline, same as before.
        @memcpy((buf + dst_off)[0..ck], scratch[0..ck]);
        done += chunk;
    }
    return @intCast(done);
}

/// Write every dirty page of ext2 inode `inum` back to disk — the orchestration
/// half of MAP_SHARED writeback (Slice 3c). Drives page_cache.takeNextDirty
/// (which PINS each dirty page so the lockless writeback I/O can't race eviction
/// or a concurrent unmap freeing the frame) → ext2.writebackPage → releaseFrame,
/// looping on a strictly-increasing offset cursor so it always terminates.
///
/// `clear` clears the dirty flag on pages that are now cache-only (no remaining
/// writable mapper): munmap/teardown pass true (the mapping is gone, so the page
/// returns to the evictable pool); msync passes false (the mapping stays live —
/// its still-writable PTE means future writes won't re-fault to re-mark the page,
/// so the bit must stay set or those writes would never be flushed by a later
/// msync). The clear runs AFTER releaseFrame so clearDirtyIfCacheOnly's
/// refcount==1 test sees the true mapper count, not our transient writeback pin.
///
/// MUST be called with NO page_cache/as_lock spinlock held: writebackPage blocks
/// on NVMe I/O. Returns the number of pages written back.
pub fn syncCacheFile(inum: u32, clear: bool) u32 {
    const file_id = page_cache.ext2FileId(inum);
    var off: u64 = 0;
    var written: u32 = 0;
    while (page_cache.takeNextDirty(file_id, off)) |dp| {
        off = dp.page_off + page_cache.PAGE_SIZE; // advance cursor → guarantees termination
        const src: [*]const u8 = @ptrFromInt(paging.physToVirt(dp.frame));
        _ = ext2.writebackPage(inum, dp.page_off, src);
        pmm.releaseFrame(dp.frame); // drop the writeback pin BEFORE the refcount-gated clear
        if (clear) _ = page_cache.clearDirtyIfCacheOnly(file_id, dp.page_off);
        written += 1;
    }
    // Disk-truth trace for MAP_SHARED writeback (Slice 3c). Silent on the common
    // case (no dirty shared pages → written==0): only msync()/munmap() of a
    // writable file mapping reaches here with work to do, so this never fires on
    // ordinary read/write/exec workloads.
    if (written > 0)
        @import("../debug/serial.zig").print("[3c] writeback inum={d} pages={d} clear={}\n", .{ inum, written, clear });
    return written;
}

/// Background page-cache writeback (Slice 3d-2's worker half) — the global
/// analogue of syncCacheFile. Flushes EVERY dirty cache page to disk: the
/// pgflushd kernel thread (main.zig) calls this on a timer so MAP_SHARED writes
/// persist to disk periodically without an explicit msync — a live mapping's
/// pages are re-flushed every pass (refcount>1 keeps them dirty), bounding
/// crash / bare-exit data loss to one flush interval instead of all of it — and
/// so any orphaned refcount==1 dirty page is written back and then made
/// reclaimable. (Full bare-exit persistence of the final pre-exit window needs
/// the OOM-safe teardown change deferred to Slice 3d-2b.)
///
/// Same lock discipline as syncCacheFile: takeNextDirtyGlobal PINS each page
/// under page_cache.lock, then we drop the lock, do the blocking ext2 writeback,
/// releaseFrame, and refcount-gate the dirty clear. clearDirtyIfCacheOnly clears
/// only refcount==1 pages, so a still-live mapper's page stays dirty and is
/// re-flushed next pass (periodic durability) while an orphaned page is cleaned
/// and becomes evictable. MUST run with NO spinlock held (writebackPage blocks on
/// NVMe I/O) — only from the daemon thread, never a syscall under a lock. Returns
/// the number of pages written back.
pub fn flushAllDirty() u32 {
    var cursor: u32 = 0;
    var written: u32 = 0;
    while (page_cache.takeNextDirtyGlobal(cursor)) |dp| {
        cursor = dp.next_idx; // strictly advances -> the pass terminates
        // The cache is ext2-only, so a dirty page is always an ext2 file page; the
        // FILE_ID_EXT2 tag-check is defensive against a future fs that would need
        // its own writeback path.
        if (dp.file_id & page_cache.FILE_ID_EXT2 != 0) {
            const inum: u32 = @intCast(dp.file_id & ~page_cache.FILE_ID_EXT2);
            const src: [*]const u8 = @ptrFromInt(paging.physToVirt(dp.frame));
            _ = ext2.writebackPage(inum, dp.page_off, src);
        }
        pmm.releaseFrame(dp.frame); // drop the writeback pin BEFORE the refcount-gated clear
        _ = page_cache.clearDirtyIfCacheOnly(dp.file_id, dp.page_off);
        written += 1;
    }
    if (written > 0)
        @import("../debug/serial.zig").print("[3d] pgflushd wrote {d} dirty page(s)\n", .{written});
    return written;
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
            // ETXTBSY: refuse to overwrite the text image of a live process.
            // This is the choke-point the fuzzer hit — fwrite-ing into its own
            // /bin/redteam.elf while running. Inode-keyed, so the //bin//…
            // path alias is covered too. (2026-06-04)
            if (process.isTextBusy(fd_entry.inode)) return @import("../proc/errno.zig").err(.ETXTBSY);
            var handle = ext2.Handle{
                .inum = fd_entry.inode,
                .file_size = 0, // refreshed by writeFile
                .current_offset = fd_entry.offset,
            };
            const bytes_written = ext2.writeFile(&handle, buf, count);
            fd_entry.offset += bytes_written;
            return bytes_written;
        },
        .tcp_sock => {
            const net = @import("../net/net.zig");
            if (!net.tcpSend(@intCast(fd_entry.inode), buf[0..count])) return 0xFFFFFFFF;
            return count;
        },
        .tcp_listener => return 0xFFFFFFFF, // listeners aren't writable
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
        .tcp_sock => {
            const net = @import("../net/net.zig");
            net.tcpClose(@intCast(fd_entry.inode));
        },
        .tcp_listener => {
            const net = @import("../net/net.zig");
            net.tcpUnlisten(@intCast(fd_entry.inode));
        },
    }
    fd_entry.in_use = false;
    return 0;
}

pub fn ls() void {
    tarfs.ls();
    fat32.listFiles();
}

/// `out_inode`, if non-null, receives the ext2 inode number of the file that
/// was actually read — or 0 if the file came from a non-ext2 mount (tarfs/fat32)
/// or wasn't found. Callers that cache-key on the file (ELF text sharing, Slice
/// 3e) use it; everyone else passes null. The inum is captured from the SAME
/// resolution that read the bytes (ext2.loadFileInum), so it can never name a
/// different file than the one whose contents landed in `dest`.
pub fn loadFile(name: []const u8, dest: []align(4) u8, out_inode: ?*u32) ?usize {
    if (out_inode) |p| p.* = 0; // default: no ext2 cache key

    // Kernel-context load (no PCB, so no cwd) — strictly absolute paths.
    // Mount table dispatch matches the per-fs `read`/`open` paths used
    // from user processes, so behavior is consistent across both.
    if (name.len > 0 and name[0] == '/') {
        const m = findMount(name) orelse return null;
        const rel = name[m.prefix.len..];
        return switch (m.fs) {
            .tarfs => tarfs.loadFile(rel, dest),
            .ext2 => blk_ext2: {
                const r = ext2.loadFileInum(rel, dest) orelse break :blk_ext2 null;
                if (out_inode) |p| p.* = r.inum;
                break :blk_ext2 r.size;
            },
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
    if (ext2.loadFileInum(name, dest)) |r| {
        if (out_inode) |p| p.* = r.inum;
        return r.size;
    }
    if (binFallback(name, dest, out_inode)) |size| return size;
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
fn binFallback(name: []const u8, dest: []align(4) u8, out_inode: ?*u32) ?usize {
    var buf: [128]u8 = undefined;
    const prefix = "bin/";
    if (name.len + prefix.len > buf.len) return null;
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..name.len], name);
    const r = ext2.loadFileInum(buf[0 .. prefix.len + name.len], dest) orelse return null;
    if (out_inode) |p| p.* = r.inum;
    return r.size;
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
/// (which takes ownership) or freed by the caller via `pmm.freeRange(phys,
/// fresh.pages)` on cleanup. Use `freeRange` (NOT a per-frame `freeFrame`
/// loop) — the buffer came from `pmm.allocContiguous`, which is the bulk
/// allocator; a per-frame free loop stamps a spurious canary onto every
/// page and produces fake UAF reports at the next allocation.
pub const FreshFile = struct {
    buf: [*]align(4) u8,
    size: usize,
    pages: u32,
    /// ext2 inode of the loaded file, or 0 if it came from a non-ext2 mount.
    /// The ELF loader uses it to cache-share read-only segments (Slice 3e);
    /// 0 makes the loader fall back to the private elf_buf path.
    inode: u32 = 0,
};

/// Architectural replacement for the `staging` pattern: size the file via
/// the directory entry, allocate from PMM (which excludes kernel image and
/// other reserved phys ranges), then read directly into that buffer. No
/// fixed-VA staging, so a growing kernel image can never collide with the
/// load destination — the bug class is impossible by construction.
///
/// Caller owns the returned buffer. Either pass it to
/// elf_loader.loadAndStart (which takes ownership), or call
/// `pmm.freeRange(phys_base, fresh.pages)` to release it. Per-frame
/// `freeFrame` loops are the wrong API pairing — see FreshFile doc.
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
    const size = fileSize(name) orelse {
        // [probe] which loadFileFresh early-exit fired — temporary diagnostic
        // for the redteam "can't re-launch its own inode" investigation.
        serial.print("[loadFresh-fail] {s}: fileSize -> null (name unresolvable / inode unreadable / not-regular)\n", .{name});
        return null;
    };
    const t1 = perf.rdtsc();
    if (size == 0) {
        serial.print("[loadFresh-fail] {s}: size == 0\n", .{name});
        return null;
    }
    const pages: u32 = @intCast((@as(usize, size) + 4095) / 4096);
    const phys = pmm.allocContiguous(pages) orelse {
        serial.print("[loadFresh-fail] {s}: allocContiguous({d} pages) -> null  (free={d} frames; fragmentation iff free >> pages)\n", .{ name, pages, pmm.freeFrameCount() });
        return null;
    };
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

    var inode_out: u32 = 0;
    if (loadFile(name, buf[0 .. @as(usize, pages) * 4096], &inode_out)) |got| {
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
        if (got == size) return .{ .buf = buf, .size = size, .pages = pages, .inode = inode_out };
        serial.print("[loadFresh-fail] {s}: short read got={d} != size={d} (inode={d}) — data blocks unreadable\n", .{ name, got, size, inode_out });
    } else {
        serial.print("[loadFresh-fail] {s}: loadFile -> null (inode/blocks unreadable)\n", .{name});
    }
    pmm.freeRange(phys, @intCast(pages));
    return null;
}

pub fn allocFd(pcb: *process.PCB) ?usize {
    for (3..pcb.fd_table.len) |fd_idx| {
        if (!pcb.fd_table[fd_idx].in_use) return fd_idx;
    }
    return null;
}
