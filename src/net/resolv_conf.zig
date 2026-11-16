//! /etc/resolv.conf for Linux programs: musl's resolver takes its name
//! servers from it and, without it, asks 127.0.0.1. Written from the DHCP
//! lease, as udhcpc's script does; a file that isn't ours is left alone.

const std = @import("std");
const ext2 = @import("../fs/ext2/ext2.zig");
const debug = @import("../debug/debug.zig");

const PATH = "/etc/resolv.conf";
const MARK = "# zigos: from the DHCP lease\n";

/// Point the file at `dns`. No-op without an ext2 root or an /etc in it.
pub fn publish(dns: [4]u8) void {
    if (!ext2.isInitialized() or std.mem.eql(u8, &dns, &.{ 0, 0, 0, 0 })) return;
    var text_buf: [96]u8 = undefined;
    const text = std.fmt.bufPrint(&text_buf, MARK ++ "nameserver {d}.{d}.{d}.{d}\n", .{ dns[0], dns[1], dns[2], dns[3] }) catch return;
    var h = if (ext2.openFile(PATH)) |old| blk: {
        if (!ours(old)) return;
        if (!ext2.truncate(old.inum)) return;
        break :blk ext2.Handle{ .inum = old.inum, .file_size = 0 };
    } else ext2.createFilePath(PATH) orelse return;
    if (ext2.writeFile(&h, text.ptr, @intCast(text.len)) != text.len) {
        debug.klog("[dhcp] {s}: short write\n", .{PATH});
        return;
    }
    debug.klog("[dhcp] {s}: nameserver {d}.{d}.{d}.{d}\n", .{ PATH, dns[0], dns[1], dns[2], dns[3] });
}

/// An empty file, or one this module wrote.
fn ours(h: ext2.Handle) bool {
    if (h.file_size == 0) return true;
    var head: [MARK.len]u8 = undefined;
    if (ext2.readFile(h, &head, head.len) != head.len) return false;
    return std.mem.eql(u8, &head, MARK);
}
