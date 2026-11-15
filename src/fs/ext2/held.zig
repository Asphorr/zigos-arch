//! Inodes that open files hold.
//!
//! An unlink that takes the last name of an inode an open file still refers
//! to must not free it: the file goes on reading and writing, and the inode
//! number must not go to a new file under it. Such an inode stays in place
//! with no links, marked an orphan here, and is freed when its last holder
//! lets go (ext2.release).
//!
//! Holds are taken and orphans made under the mount lock, so an open by
//! name and the unlink of that name can't pass each other. The table is in
//! memory only: an orphan whose holders never released it (a crash) keeps
//! its blocks until a check of the file system frees them.

const SpinLock = @import("../../proc/spinlock.zig").SpinLock;
const heap = @import("../../mm/heap.zig");

const Node = struct {
    inum: u32,
    holders: u32,
    orphan: bool,
    next: ?*Node,
};

const BUCKETS: usize = 256;

var buckets: [BUCKETS]?*Node = [_]?*Node{null} ** BUCKETS; // (p:lock)
var lock: SpinLock = .{};

fn find(inum: u32) ?*Node {
    var n = buckets[inum % BUCKETS];
    while (n) |node| : (n = node.next) {
        if (node.inum == inum) return node;
    }
    return null;
}

/// One more holder of `inum`. False when memory is out.
pub fn hold(inum: u32) bool {
    {
        const f = lock.acquireIrqSave();
        defer lock.releaseIrqRestore(f);
        if (find(inum)) |node| {
            node.holders += 1;
            return true;
        }
    }
    // First holder: the node comes from the heap with the lock dropped, and
    // another first holder may get in before it is linked.
    const raw = heap.kmallocAligned(@sizeOf(Node), @alignOf(Node)) orelse return false;
    const fresh: *Node = @ptrCast(@alignCast(raw));
    const f = lock.acquireIrqSave();
    if (find(inum)) |node| {
        node.holders += 1;
        lock.releaseIrqRestore(f);
        heap.kfree(raw);
        return true;
    }
    const head = &buckets[inum % BUCKETS];
    fresh.* = .{ .inum = inum, .holders = 1, .orphan = false, .next = head.* };
    head.* = fresh;
    lock.releaseIrqRestore(f);
    return true;
}

/// One holder of `inum` fewer. True when that was the last one and the
/// inode is an orphan: the caller frees it.
pub fn unhold(inum: u32) bool {
    var gone: ?*Node = null;
    var orphan = false;
    {
        const f = lock.acquireIrqSave();
        defer lock.releaseIrqRestore(f);
        var link = &buckets[inum % BUCKETS];
        while (link.*) |node| : (link = &node.next) {
            if (node.inum != inum) continue;
            node.holders -= 1;
            if (node.holders == 0) {
                link.* = node.next;
                gone = node;
                orphan = node.orphan;
            }
            break;
        }
    }
    if (gone) |node| heap.kfree(@ptrCast(node));
    return orphan;
}

/// `inum` lost its last name. True if an open file holds it, and it is now
/// an orphan the last unhold reports; false if nothing holds it and the
/// caller frees it at once.
pub fn orphanIfHeld(inum: u32) bool {
    const f = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(f);
    const node = find(inum) orelse return false;
    node.orphan = true;
    return true;
}
