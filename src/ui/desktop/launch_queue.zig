// Pending-app-launch ring. The desktop's spawn path tries `smp.requestAppLoad`
// first (async load on the AP); when the AP is mid-flight on a previous load
// we can't race a second request through the shared NVMe bounce buffer, so
// we buffer the name here and retry every frame from the main loop until
// the AP frees up.
//
// Without this, fast double-clicks on a dock/desktop icon while another app
// is loading would silently drop the second click. Cap is small (8) — if
// the user manages to queue more than that the latest is dropped and a
// "Launch queue full" toast is shown.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const smp = @import("../../cpu/smp.zig");

const CAP: u8 = 8;

var names: [CAP][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** CAP;
var lens: [CAP]u8 = [_]u8{0} ** CAP;
var head: u8 = 0; // pop here
var count: u8 = 0;

/// Add `cmd` to the queue. Returns false iff the queue was already full —
/// caller should surface a "queue full" message in that case.
pub fn push(cmd: []const u8) bool {
    if (count >= CAP) return false;
    const tail = (head + count) % CAP;
    const n: u8 = @intCast(@min(cmd.len, 32));
    @memcpy(names[tail][0..n], cmd[0..n]);
    lens[tail] = n;
    count += 1;
    return true;
}

/// Try to submit the oldest queued name to `smp.requestAppLoad`. No-op if
/// empty or if the AP is still busy. Called once per desktop frame.
pub fn drain() void {
    if (count == 0) return;
    const idx = head;
    const cmd = names[idx][0..lens[idx]];
    if (smp.requestAppLoad(cmd)) {
        head = (head + 1) % CAP;
        count -= 1;
        debug.klog("[launch] dequeued '{s}' (queued: {d})\n", .{ cmd, count });
    }
}

pub fn depth() u8 {
    return count;
}
