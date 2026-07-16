// vfs — the filesystem dispatch hub: mount table (longest-prefix path
// resolution), per-process fd operations (open/read/write/close), the
// kernel-context loaders (loadFile/loadFileFresh), and the ext2 page-cache
// read + writeback orchestration (readThroughCache/syncCacheFile/
// flushAllDirty).
//
// Dispatch contract: the FsType/FdType switches below are exhaustive on
// purpose — adding a filesystem is adding an enum variant, after which the
// compiler names every dispatch point that still needs an arm. That IS the
// backend interface; five static filesystems don't need vtable indirection.
//
// Error convention: fd ops return VFS_ERR for "bad fd / not permitted" and
// 0 for "nothing transferred" (write may also return an errno encoding —
// see the ext2 ETXTBSY arm); path helpers return null.

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

/// fd-op failure sentinel — the u32 the syscall layer treats as -1. Distinct
/// from the errno encodings some arms return (write's ETXTBSY).
const VFS_ERR: u32 = 0xFFFFFFFF;

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

    // Claim the fd index up front. allocFd only names a free slot — nothing
    // is reserved until the single install below — so an early return leaks
    // nothing, and no fs-side open (or truncate) can run for a process whose
    // table is already full. This ordering is load-bearing for O_TRUNC: the
    // truncate used to run before the fd allocation, so open() on a full
    // table destroyed the file's contents and then failed.
    const fd_idx = allocFd(pcb) orelse return null;

    // Each arm resolves the fs-specific open to the FileDesc to install, or
    // null. Exactly one install point below — per-arm fd bookkeeping is how
    // the truncate-before-alloc bug stayed hidden.
    const maybe_desc: ?process.FileDesc = switch (resolved.fs) {
        .tarfs => blk: {
            const tar_idx = tarfs.openFile(resolved.path) orelse break :blk null;
            break :blk .{ .in_use = true, .inode = tar_idx, .offset = 0, .flags = 2, .fs_type = .tarfs };
        },
        .fat32 => blk: {
            if (fat32.openFile(resolved.path)) |handle| {
                // O_APPEND positions the offset at end-of-file so the first
                // write extends rather than overwrites. fat32.writeFile
                // already handles offset > file_size by allocating new
                // clusters as needed.
                const start_offset: u32 = if (flags & O_APPEND != 0) handle.file_size else 0;
                break :blk .{
                    .in_use = true,
                    .inode = handle.dir_index,
                    .offset = start_offset,
                    .flags = 2,
                    .fs_type = .fat32,
                    .fat_dir_cluster = handle.dir_cluster,
                };
            }
            // Not found — create if O_CREATE flag set.
            if (flags & O_CREATE != 0) {
                if (fat32.createFile(resolved.path)) |handle| {
                    break :blk .{
                        .in_use = true,
                        .inode = handle.dir_index,
                        .offset = 0,
                        .flags = 2,
                        .fs_type = .fat32,
                        .fat_dir_cluster = handle.dir_cluster,
                    };
                }
            }
            break :blk null;
        },
        .devfs => blk: {
            const dev_idx = devfs.openFile(resolved.path) orelse break :blk null;
            break :blk .{ .in_use = true, .inode = dev_idx, .offset = 0, .flags = 2, .fs_type = .devfs };
        },
        .procfs => blk: {
            const inode = procfs.openFile(resolved.path) orelse break :blk null;
            // flags = 0: procfs is read-only.
            break :blk .{ .in_use = true, .inode = inode, .offset = 0, .flags = 0, .fs_type = .procfs };
        },
        .ext2 => blk: {
            if (ext2.openFile(resolved.path)) |handle| {
                // O_TRUNC on an existing file: free all data + indirect-tree
                // blocks and reset size to 0. The next writeFile re-allocates.
                // Safe to do here — with the fd already claimed, nothing after
                // this point can fail and turn the open into a destructive no-op.
                if (flags & O_TRUNC != 0) _ = ext2.truncate(handle.inum);
                // ext2 LARGE_FILE sizes exceed the fd's u32 offset — refuse
                // O_APPEND there instead of panicking on the cast (corrupt-
                // image class). handle.file_size is the pre-truncate snapshot,
                // so O_TRUNC|O_APPEND on such a file also refuses — strictly
                // better than the checked-@intCast panic it replaces.
                const start_offset: u32 = if (flags & O_APPEND != 0)
                    (std.math.cast(u32, handle.file_size) orelse break :blk null)
                else
                    0;
                break :blk .{ .in_use = true, .inode = handle.inum, .offset = start_offset, .flags = 2, .fs_type = .ext2 };
            }
            // Not found — create if O_CREATE flag set.
            if (flags & O_CREATE != 0) {
                if (ext2.createFilePath(resolved.path)) |handle| {
                    break :blk .{ .in_use = true, .inode = handle.inum, .offset = 0, .flags = 2, .fs_type = .ext2 };
                }
            }
            break :blk null;
        },
    };
    const desc = maybe_desc orelse return null;
    pcb.fd_table[fd_idx] = desc;
    return @intCast(fd_idx);
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

/// Rebuild the fat32 handle a FileDesc describes. read/write/close all need
/// the same reconstruction; one definition keeps the dir-cluster default
/// ("0 means root" — see FileDesc.fat_dir_cluster) in a single place.
fn fatHandle(fd_entry: *const process.FileDesc) fat32.Handle {
    const dc = if (fd_entry.fat_dir_cluster != 0) fd_entry.fat_dir_cluster else fat32.root_cluster;
    return .{
        .dir_cluster = dc,
        .dir_index = fd_entry.inode,
        .first_cluster = fat32.getFirstClusterAt(dc, fd_entry.inode),
        .file_size = fat32.getFileSizeAt(dc, fd_entry.inode),
        .current_offset = fd_entry.offset,
    };
}

pub fn read(pcb: *process.PCB, fd: u32, buf: [*]u8, count: u32) u32 {
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return VFS_ERR;
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
            const handle = fatHandle(fd_entry);
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
            if (fd_entry.flags != 0) return VFS_ERR;
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
        .tcp_listener => return VFS_ERR, // listeners aren't readable; use accept()
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
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return VFS_ERR;
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
            var handle = fatHandle(fd_entry);
            const bytes_written = fat32.writeFile(&handle, buf, count);
            fd_entry.offset += @intCast(bytes_written);
            return @intCast(bytes_written);
        },
        .tarfs => {
            return VFS_ERR; // tarfs is read-only
        },
        .pipe => {
            // Only valid as write-side here. Read-side fds use sysFread path.
            if (fd_entry.flags != 1) return VFS_ERR;
            const n = pipe.write(fd_entry.pipe_id, buf[0..count]);
            return @intCast(n);
        },
        .devfs => {
            const n = devfs.write(fd_entry.inode, fd_entry.offset, buf, count);
            if (n != VFS_ERR) fd_entry.offset += n;
            return n;
        },
        .procfs => return VFS_ERR, // read-only
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
            if (!net.tcpSend(@intCast(fd_entry.inode), buf[0..count])) return VFS_ERR;
            return count;
        },
        .tcp_listener => return VFS_ERR, // listeners aren't writable
    }
}

pub fn close(pcb: *process.PCB, fd: u32) u32 {
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return VFS_ERR;
    if (fd < 3) return VFS_ERR; // can't close stdin/stdout/stderr
    const fd_entry = &pcb.fd_table[fd];

    switch (fd_entry.fs_type) {
        .console => {},
        .fat32 => {
            fat32.closeFile(fatHandle(fd_entry));
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

// --- Kernel-context name resolution (loadFile / fileSize) -------------------
//
// Both loaders resolve a name the same way: absolute paths dispatch through
// the mount table; bare names walk the legacy fallback chain (ext2 root →
// ext2 /bin → tarfs → fat32). loadFileFresh sizes the file with one and
// reads it with the other, so if the two ever disagreed about WHICH file a
// name means, it would allocate the wrong buffer. That used to be a "keep
// the two paths in lock-step" comment; now the sequence exists once, in
// resolveFirst, and the two only differ in the per-fs operation applied —
// drift is structurally impossible (rule 5, aimed at control flow).

/// Walk the name-resolution sequence and return the first non-null result of
/// `op.run(fs, rel)`. `op` is duck-typed: any struct with
/// `fn run(self, fs: FsType, rel: []const u8) ?R`.
fn resolveFirst(comptime R: type, name: []const u8, op: anytype) ?R {
    // Absolute path → longest-prefix mount dispatch, one candidate.
    if (name.len > 0 and name[0] == '/') {
        const m = findMount(name) orelse return null;
        return op.run(m.fs, name[m.prefix.len..]);
    }
    // Bare-filename fallback for legacy callers (sysExec passing "cat.elf"
    // unqualified, KERNEL.SYM / BUILD.ID lookups). Resolution order:
    //   1. ext2 root  — for files at `/` like KERNEL.SYM, BUILD.ID
    //   2. ext2 /bin  — for shell-style `cat` → /bin/cat.elf (PATH analogue)
    //   3. tarfs      — legacy fallback during migration
    //   4. fat32      — only matters with /fat/ disk attached
    if (op.run(.ext2, name)) |r| return r;
    var bin_buf: [128]u8 = undefined;
    if (binPath(&bin_buf, name)) |bp| {
        if (op.run(.ext2, bp)) |r| return r;
    }
    if (op.run(.tarfs, name)) |r| return r;
    return op.run(.fat32, name);
}

/// "bin/" ++ name into `buf`, or null if it doesn't fit.
fn binPath(buf: *[128]u8, name: []const u8) ?[]const u8 {
    const prefix = "bin/";
    if (name.len + prefix.len > buf.len) return null;
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..name.len], name);
    return buf[0 .. prefix.len + name.len];
}

/// The loadFile operation: read the candidate into `dest`, reporting the ext2
/// inum through `out_inode` from the SAME resolution that read the bytes — so
/// it can never name a different file than the one whose contents landed.
const LoadOp = struct {
    dest: []align(4) u8,
    out_inode: ?*u32,

    fn run(self: @This(), fs: FsType, rel: []const u8) ?usize {
        return switch (fs) {
            .tarfs => tarfs.loadFile(rel, self.dest),
            .ext2 => blk: {
                const r = ext2.loadFileInum(rel, self.dest) orelse break :blk null;
                if (self.out_inode) |p| p.* = r.inum;
                break :blk r.size;
            },
            .fat32 => blk: {
                if (fat32.openFile(rel)) |handle| {
                    const size = handle.file_size;
                    if (size > 0) {
                        const want: u32 = @intCast(@min(@as(u64, size), self.dest.len));
                        const r = fat32.readFile(handle, @ptrCast(self.dest.ptr), want);
                        fat32.closeFile(handle);
                        if (r > 0) break :blk r;
                    } else {
                        fat32.closeFile(handle);
                    }
                }
                break :blk null;
            },
            // devfs/procfs aren't loadable as files (they're streamed) — kernel
            // load callers shouldn't be asking for them. fileSize DOES report
            // their sizes (SizeOp below), so a loadFileFresh of one sizes fine
            // and then fails here — wasteful but unreachable from real callers.
            .devfs, .procfs => null,
        };
    }
};

/// The fileSize operation. ext2/tarfs report u64 sizes (ext2 LARGE_FILE
/// reaches 2^48): a size that doesn't fit the u32 world of fd offsets and
/// loadFileFresh is "no usable size" (null), never a checked-cast panic —
/// the size is fs-image-provided data, and a corrupt image must not be able
/// to crash the kernel (the NVMe LBADS lesson).
const SizeOp = struct {
    fn run(_: @This(), fs: FsType, rel: []const u8) ?u32 {
        return switch (fs) {
            .tarfs => std.math.cast(u32, tarfs.fileSize(rel) orelse return null),
            .ext2 => std.math.cast(u32, ext2.fileSize(rel) orelse return null),
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
};

/// `out_inode`, if non-null, receives the ext2 inode number of the file that
/// was actually read — or 0 if the file came from a non-ext2 mount (tarfs/fat32)
/// or wasn't found. Callers that cache-key on the file (ELF text sharing, Slice
/// 3e) use it; everyone else passes null. Kernel-context load (no PCB, so no
/// cwd) — absolute paths plus the bare-name chain, see resolveFirst.
pub fn loadFile(name: []const u8, dest: []align(4) u8, out_inode: ?*u32) ?usize {
    if (out_inode) |p| p.* = 0; // default: no ext2 cache key
    return resolveFirst(usize, name, LoadOp{ .dest = dest, .out_inode = out_inode });
}

/// Size of the file `name` resolves to, via the SAME candidate sequence
/// loadFile reads through (resolveFirst) — the pairing loadFileFresh relies on.
pub fn fileSize(name: []const u8) ?u32 {
    return resolveFirst(u32, name, SizeOp{});
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

/// Find a free fd index. NAMES a slot only — nothing is reserved until the
/// caller installs into fd_table[fd_idx]. Safe because every fd_table has
/// exactly one accessor today (tables are COPIED on clone, never shared —
/// lifecycle.cloneCurrent). If CLONE_FILES sharing ever lands, this needs a
/// reservation (in_use placeholder) or an fd-table lock.
pub fn allocFd(pcb: *process.PCB) ?usize {
    for (3..pcb.fd_table.len) |fd_idx| {
        if (!pcb.fd_table[fd_idx].in_use) return fd_idx;
    }
    return null;
}
