// A notification: the pill (toast.zig), a wake of the desktop to draw it, and
// the sound.

const process = @import("../../proc/process.zig");
const sound = @import("../../driver.zig").sound;
const toast = @import("toast.zig");
const pinned = @import("pinned.zig");
const wake = @import("wake.zig");
const win_title = @import("title.zig");

pub fn showNotification(text: []const u8) void {
    toast.show(text);
    // The next tick() starts the slide-in, which repaints the pill.
    wake.requestWake();
    sound.notify();
}

/// A program's notification. The pill names the sender, so none passes for
/// the kernel's own, which alone come unnamed (showNotification).
pub fn showNotificationFrom(pid: u8, text: []const u8) void {
    var name: [32]u8 = undefined;
    const pname = process.getName(pid);
    const n: usize = if (pinned.nameForProcess(pname)) |known| blk: {
        const k = @min(known.len, name.len);
        @memcpy(name[0..k], known[0..k]);
        break :blk k;
    } else win_title.pretty(&name, pname);
    toast.showFrom(if (n > 0) name[0..n] else "App", text);
    wake.requestWake();
    sound.notify();
}
