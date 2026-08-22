// populate — copy the live ext2 root onto a second, freshly-formatted mount.
//
// The installer's "copy the system" step. Everything here runs against an
// EXPLICIT target Mount (block.mountAt into `target_mount`) through the
// cache-bypassing `*On` inode helpers, because the global-mount API and the
// inode cache both key on bare inum — and with two mounts alive, inum 12 on
// the live root and inum 12 on the target are different files on different
// disks. Reads of the SOURCE go through the ordinary global-mount API, which
// is exactly the live root.
//
// Deliberately not a general-purpose writer:
//   - no exists-checks and no rollback — the target came out of mkfs seconds
//     ago, every name is fresh, and a failed copy fails the install (the
//     retry path re-formats);
//   - symlinks and special files are skipped with a log line (the build
//     stage contains none today);
//   - the walk is iterative with an explicit stack, one shared dir-block
//     buffer, and a (lblock, boff) resume cursor per level — a recursive
//     walk would stack a 4 KB block buffer per directory level.
//
// Inode timestamps, mode, and uid/gid are copied from the source so the
// installed tree matches what the build staged, not the moment of install.

const std = @import("std");
const layout = @import("layout.zig");
const block = @import("block.zig");
const inode = @import("inode.zig");
const ext2 = @import("ext2.zig");
const debug = @import("../../debug/debug.zig");

/// The installer-only working set: the target's Mount (265 KB — it carries
/// the same 256 KB sector cache the live mount does) plus a 64 KiB bounce
/// buffer for source → target file data (16 fs blocks per round trip;
/// writeBlockRun folds each into one or two NVMe commands on a fresh fs).
///
/// PMM-BACKED, allocated on first use and reached through the physmap —
/// NOT static BSS. As statics these pushed _kernel_end past
/// KERNEL_HEAP_BASE and the boot died in assertKernelImageFits; same
/// lesson proc.process.kstack_pool learned. Never freed: one install per
/// boot, and the installer's only exit is a reboot.
var target_mount_ptr: ?*block.Mount = null;
pub var copy_buf: []u8 = &.{};
const COPY_BUF_BYTES: usize = 64 * 1024;

/// Allocate (once) and return the target Mount slot, arming copy_buf along
/// with it. Null when PMM has no contiguous run — the installer fails the
/// phase honestly.
pub fn ensureWorkingSet() ?*block.Mount {
    if (target_mount_ptr) |m| return m;
    const pmm = @import("../../mm/pmm.zig");
    const paging = @import("../../mm/paging.zig");
    const bytes = @sizeOf(block.Mount) + COPY_BUF_BYTES;
    const pages: u32 = @intCast((bytes + 4095) / 4096);
    const phys = pmm.allocContiguous(pages) orelse {
        debug.klog("[populate] allocContiguous({d} pages) failed\n", .{pages});
        return null;
    };
    const base: [*]u8 = @ptrFromInt(paging.physToVirt(phys));
    const m: *block.Mount = @ptrCast(@alignCast(base));
    copy_buf = (base + @sizeOf(block.Mount))[0..COPY_BUF_BYTES];
    target_mount_ptr = m;
    return m;
}

/// The source directory block currently being walked. Shared across all
/// stack levels — re-read (through the mount's sector cache) after every
/// descent, which is what the per-level resume cursor is for.
var dir_buf: [4096]u8 align(8) = undefined;

/// Zero-padded staging for a file's final partial block, and the . / ..
/// block of a fresh directory.
var scratch_block: [4096]u8 align(8) = undefined;

const MAX_DEPTH: usize = 16;

const WorkItem = struct {
    src: u32,
    dst: u32,
    /// Resume cursor into the SOURCE directory's data: next logical block
    /// and byte offset within it to scan from.
    lblock: u32,
    boff: u32,
};

var work_stack: [MAX_DEPTH]WorkItem = undefined;

pub const CopyStats = struct {
    files: u32 = 0,
    dirs: u32 = 0,
    bytes: u64 = 0,
    skipped: u32 = 0,
};

/// Running totals of the copy in progress (reset by copyBegin). The
/// installer reads these for its progress display.
pub var stats: CopyStats = .{};

/// Name of the entry the last copyStep processed, for the installer's
/// status line. Empty until the first file lands.
pub var last_name: [255]u8 = undefined;
pub var last_name_len: usize = 0;

var sp: usize = 0;
var src_mount: *block.Mount = undefined;
var dst_mount: *block.Mount = undefined;

pub const StepResult = enum { more, done, failed };

/// Arm the copy: live root as the source, `m_dst` (rooted at its ROOT_INO)
/// as the destination. The walk itself runs through repeated copyStep calls
/// so the installer can paint between them.
pub fn copyBegin(m_dst: *block.Mount) bool {
    src_mount = block.getMount() orelse {
        debug.klog("[populate] no live root to copy from\n", .{});
        return false;
    };
    dst_mount = m_dst;
    stats = .{};
    last_name_len = 0;
    work_stack[0] = .{ .src = layout.ROOT_INO, .dst = layout.ROOT_INO, .lblock = 0, .boff = 0 };
    sp = 1;
    return true;
}

/// Process ONE source directory entry: copy a file, create a directory and
/// descend, or pop an exhausted level. `.more` means call again; `.failed`
/// means the target is scrap (the reason is in the serial log). `lost+found`
/// is skipped (mkfs gave the target its own); "." / ".." are structural.
pub fn copyStep() StepResult {
    if (sp == 0) return .done;
    const m_src = src_mount;
    const m_dst = dst_mount;

    const top = &work_stack[sp - 1];
    const dir_ino = inode.readInodeOn(m_src, top.src) orelse {
        debug.klog("[populate] source dir inode {d} unreadable\n", .{top.src});
        return .failed;
    };
    const bs = m_src.block_size;
    if (@as(u64, top.lblock) * bs >= inode.fileSize(&dir_ino)) {
        sp -= 1; // directory exhausted
        return if (sp == 0) .done else .more;
    }
    if (!inode.readInodeBlockOn(m_src, &dir_ino, top.lblock, dir_buf[0..bs])) {
        debug.klog("[populate] source dir {d} block {d} unreadable\n", .{ top.src, top.lblock });
        return .failed;
    }

    // Pull ONE entry at the cursor and advance it before dispatching — the
    // dispatch reuses dir_buf, so the entry's name is copied out first.
    var walk = ext2.DirWalk{ .buf = dir_buf[0..bs], .off = top.boff };
    const item = walk.next() orelse {
        top.lblock += 1;
        top.boff = 0;
        return .more;
    };
    if (walk.off >= bs) {
        top.lblock += 1;
        top.boff = 0;
    } else {
        top.boff = walk.off;
    }

    if (item.e.inode == 0 or item.name.len == 0) return .more;
    if (isDot(item.name) or std.mem.eql(u8, item.name, "lost+found")) return .more;

    const nlen = @min(item.name.len, last_name.len);
    @memcpy(last_name[0..nlen], item.name[0..nlen]);
    last_name_len = nlen;
    const name = last_name[0..nlen];
    const child_inum = item.e.inode;

    const child = inode.readInodeOn(m_src, child_inum) orelse {
        debug.klog("[populate] source inode {d} ({s}) unreadable\n", .{ child_inum, name });
        return .failed;
    };
    if (inode.isDir(&child)) {
        const new_dir = mkdirOn(m_dst, top.dst, name, &child) orelse {
            debug.klog("[populate] mkdir {s} failed on target\n", .{name});
            return .failed;
        };
        if (sp == MAX_DEPTH) {
            debug.klog("[populate] tree deeper than {d} levels at {s}\n", .{ MAX_DEPTH, name });
            return .failed;
        }
        work_stack[sp] = .{ .src = child_inum, .dst = new_dir, .lblock = 0, .boff = 0 };
        sp += 1;
        stats.dirs += 1;
    } else if (inode.isReg(&child)) {
        if (!copyFile(m_dst, child_inum, &child, top.dst, name)) {
            debug.klog("[populate] copy of {s} failed\n", .{name});
            return .failed;
        }
        stats.files += 1;
        stats.bytes += inode.fileSize(&child);
    } else {
        debug.klog("[populate] skipping {s} (not a file or dir, mode 0x{X})\n", .{ name, child.mode });
        stats.skipped += 1;
    }
    return .more;
}

inline fn isDot(name: []const u8) bool {
    return std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..");
}

/// Create directory `name` under `parent_inum` on the target, with mode and
/// timestamps from the source inode. Mirrors ext2.mkdirPath's on-disk shape
/// (., .. block; links_count bookkeeping) minus path walking and rollback.
fn mkdirOn(m: *block.Mount, parent_inum: u32, name: []const u8, src_ino: *const layout.Inode) ?u32 {
    if (name.len == 0 or name.len > 255) return null;
    block.lockMount(m);
    defer block.unlockMount(m);
    var parent = inode.readInodeOn(m, parent_inum) orelse return null;

    const new_inum = inode.allocInodeOn(m, true) orelse return null;
    var new_ino: layout.Inode = std.mem.zeroes(layout.Inode);
    new_ino.mode = src_ino.mode;
    new_ino.uid = src_ino.uid;
    new_ino.gid = src_ino.gid;
    new_ino.links_count = 2; // "." + the parent's entry
    new_ino.atime = src_ino.atime;
    new_ino.ctime = src_ino.ctime;
    new_ino.mtime = src_ino.mtime;

    const bs = m.block_size;
    const data_block = inode.ensurePhysicalBlock(m, &new_ino, 0) orelse return null;
    @memset(scratch_block[0..bs], 0);
    const dot = std.mem.bytesAsValue(layout.DirEntry, scratch_block[0..layout.DIR_ENTRY_HDR]);
    const dot_rec: u16 = layout.dirEntryAlign(1);
    dot.inode = new_inum;
    dot.rec_len = dot_rec;
    dot.name_len = 1;
    dot.file_type = layout.FT_DIR;
    scratch_block[layout.DIR_ENTRY_HDR] = '.';
    const dotdot = std.mem.bytesAsValue(layout.DirEntry, scratch_block[dot_rec..][0..layout.DIR_ENTRY_HDR]);
    dotdot.inode = parent_inum;
    dotdot.rec_len = @intCast(bs - dot_rec);
    dotdot.name_len = 2;
    dotdot.file_type = layout.FT_DIR;
    scratch_block[dot_rec + layout.DIR_ENTRY_HDR] = '.';
    scratch_block[dot_rec + layout.DIR_ENTRY_HDR + 1] = '.';
    if (!block.writeBlock(m, data_block, scratch_block[0..bs])) return null;
    new_ino.size = @intCast(bs);
    if (!inode.writeInodeOn(m, new_inum, &new_ino)) return null;

    if (!dirInsertOn(m, &parent, name, new_inum, layout.FT_DIR)) return null;
    parent.links_count += 1; // the new dir's ".." points back at the parent
    if (!inode.writeInodeOn(m, parent_inum, &parent)) return null;
    return new_inum;
}

/// Copy one regular file: create it on the target under `dst_dir`, stream
/// the source's bytes across in copy_buf-sized rounds, then stamp size +
/// source metadata. Metadata flushes (BGD/SB counters) batch per file.
fn copyFile(m_dst: *block.Mount, src_inum: u32, src_ino: *const layout.Inode, dst_dir: u32, name: []const u8) bool {
    const new_inum = createFileOn(m_dst, dst_dir, name, src_ino) orelse return false;
    var ino = inode.readInodeOn(m_dst, new_inum) orelse return false;

    const fsize = inode.fileSize(src_ino);
    block.lockMount(m_dst);
    block.beginMetaDefer(m_dst);
    var off: u64 = 0;
    var ok = true;
    while (off < fsize) {
        const want: u32 = @intCast(@min(fsize - off, copy_buf.len));
        const got = inode.readInodeBytes(src_inum, off, copy_buf[0..want]);
        if (got != want) {
            debug.klog("[populate] short source read: {s} at {d} ({d}/{d})\n", .{ name, off, got, want });
            ok = false;
            break;
        }
        if (!appendChunk(m_dst, &ino, off, copy_buf[0..want])) {
            ok = false;
            break;
        }
        off += want;
    }
    block.endMetaDefer(m_dst);
    block.unlockMount(m_dst);
    if (!ok) return false;

    // LARGE_FILE split, same as ext2.writeFile: high size bits in dir_acl.
    ino.size = @truncate(fsize);
    ino.dir_acl = @intCast(fsize >> 32);
    return inode.writeInodeOn(m_dst, new_inum, &ino);
}

/// Create an empty regular file on the target with the source's mode,
/// owner, and timestamps. ext2.createFile minus exists-check and rollback.
fn createFileOn(m: *block.Mount, parent_inum: u32, name: []const u8, src_ino: *const layout.Inode) ?u32 {
    if (name.len == 0 or name.len > 255) return null;
    block.lockMount(m);
    defer block.unlockMount(m);
    var parent = inode.readInodeOn(m, parent_inum) orelse return null;

    const new_inum = inode.allocInodeOn(m, false) orelse return null;
    var new_ino: layout.Inode = std.mem.zeroes(layout.Inode);
    new_ino.mode = src_ino.mode;
    new_ino.uid = src_ino.uid;
    new_ino.gid = src_ino.gid;
    new_ino.links_count = 1;
    new_ino.atime = src_ino.atime;
    new_ino.ctime = src_ino.ctime;
    new_ino.mtime = src_ino.mtime;
    if (!inode.writeInodeOn(m, new_inum, &new_ino)) return null;

    if (!dirInsertOn(m, &parent, name, new_inum, layout.FT_REG_FILE)) return null;
    if (!inode.writeInodeOn(m, parent_inum, &parent)) return null;
    return new_inum;
}

/// Append `data` at block-aligned `file_off` of the target inode. Full
/// blocks accumulate into physically-contiguous runs flushed as single
/// writeBlockRun calls; only a file's final chunk may end mid-block (zero-
/// padded to a full-block write — the block is freshly allocated, there is
/// nothing to preserve). Caller holds the mount lock (ensurePhysicalBlock's
/// precondition) and does the eventual writeInodeOn.
fn appendChunk(m: *block.Mount, ino: *layout.Inode, file_off: u64, data: []const u8) bool {
    const bs = m.block_size;
    var done: u32 = 0;
    var pend_phys: u32 = 0;
    var pend_blocks: u32 = 0;
    var pend_src: u32 = 0;
    while (done < data.len) {
        const logical: u32 = @intCast((file_off + done) / bs);
        const take: u32 = @intCast(@min(@as(u64, bs), data.len - done));
        const phys = inode.ensurePhysicalBlock(m, ino, logical) orelse {
            debug.klog("[populate] target filesystem full\n", .{});
            return false;
        };
        if (take == bs) {
            if (pend_blocks != 0 and phys == pend_phys + pend_blocks) {
                pend_blocks += 1;
                done += bs;
                continue;
            }
            if (pend_blocks != 0) {
                if (!block.writeBlockRun(m, pend_phys, pend_blocks, data.ptr + pend_src)) return false;
            }
            pend_phys = phys;
            pend_src = done;
            pend_blocks = 1;
            done += bs;
        } else {
            if (pend_blocks != 0) {
                if (!block.writeBlockRun(m, pend_phys, pend_blocks, data.ptr + pend_src)) return false;
                pend_blocks = 0;
            }
            @memset(scratch_block[0..bs], 0);
            @memcpy(scratch_block[0..take], data[done..]);
            if (!block.writeBlock(m, phys, scratch_block[0..bs])) return false;
            done += take;
        }
    }
    if (pend_blocks != 0) {
        if (!block.writeBlockRun(m, pend_phys, pend_blocks, data.ptr + pend_src)) return false;
    }
    return true;
}

/// ext2.dirInsert against an explicit mount: walk the directory for slack,
/// split the entry that has room, or extend the directory by one block.
/// Mutates `dir_ino` (size, block map) — caller persists it.
fn dirInsertOn(m: *block.Mount, dir_ino: *layout.Inode, name: []const u8, child_inum: u32, file_type: u8) bool {
    const bs = m.block_size;
    const needed: u16 = layout.dirEntryAlign(@intCast(name.len));
    if (needed > bs) return false;

    const total = inode.fileSize(dir_ino);
    if (total + bs > std.math.maxInt(u32)) return false;
    var lblock: u32 = 0;
    var blkbuf: [4096]u8 align(8) = undefined;
    while (@as(u64, lblock) * bs < total) : (lblock += 1) {
        if (!inode.readInodeBlockOn(m, dir_ino, lblock, blkbuf[0..bs])) return false;
        var w = ext2.DirWalk{ .buf = blkbuf[0..bs] };
        while (w.next()) |d| {
            const tight: u16 = if (d.e.inode == 0)
                layout.DIR_ENTRY_HDR
            else
                layout.dirEntryAlign(d.e.name_len);
            if (d.e.rec_len >= tight + needed) {
                const new_off: u32 = d.off + tight;
                const slack: u16 = d.e.rec_len - tight;
                d.e.rec_len = tight;
                const ne = std.mem.bytesAsValue(layout.DirEntry, blkbuf[new_off..][0..layout.DIR_ENTRY_HDR]);
                ne.inode = child_inum;
                ne.rec_len = slack;
                ne.name_len = @intCast(name.len);
                ne.file_type = file_type;
                @memcpy(blkbuf[new_off + layout.DIR_ENTRY_HDR ..][0..name.len], name);
                const phys = inode.blockMapLookupOn(m, dir_ino, lblock) orelse return false;
                return block.writeBlock(m, phys, blkbuf[0..bs]);
            }
        }
    }

    const new_lblock: u32 = @intCast(total / bs);
    const new_phys = inode.ensurePhysicalBlock(m, dir_ino, new_lblock) orelse return false;
    @memset(blkbuf[0..bs], 0);
    const e = std.mem.bytesAsValue(layout.DirEntry, blkbuf[0..layout.DIR_ENTRY_HDR]);
    e.inode = child_inum;
    e.rec_len = @intCast(bs);
    e.name_len = @intCast(name.len);
    e.file_type = file_type;
    @memcpy(blkbuf[layout.DIR_ENTRY_HDR..][0..name.len], name);
    if (!block.writeBlock(m, new_phys, blkbuf[0..bs])) return false;
    dir_ino.size = @intCast(total + bs);
    return true;
}
