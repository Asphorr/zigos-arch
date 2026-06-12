// PC Speaker driver — PIT channel 2 + speaker gate
// Supports multi-note sequences for richer sounds

const io = @import("../io.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

const Note = struct { freq: u16, ticks: u8 };
const MAX_NOTES: u8 = 8;

var queue: [MAX_NOTES]Note = undefined;
var queue_len: u8 = 0;
var queue_pos: u8 = 0;
var remaining_ticks: u32 = 0;

/// Serializes queue + PIT register sequence (channel-2 program). Without
/// this, two CPUs racing in beep()/playSeq() interleave their queue writes
/// and tick() pulls a half-written note.
var lock: SpinLock = .{};

fn startTone(freq: u16) void {
    if (freq == 0) {
        // Silence
        io.outb(0x61, io.inb(0x61) & 0xFC);
        return;
    }
    const divisor: u32 = 1193182 / @as(u32, freq);
    io.outb(0x43, 0xB6);
    io.outb(0x42, @truncate(divisor));
    io.outb(0x42, @truncate(divisor >> 8));
    io.outb(0x61, io.inb(0x61) | 0x03);
}

fn stopTone() void {
    io.outb(0x61, io.inb(0x61) & 0xFC);
}

/// Start a single tone.
pub fn beep(freq: u16, duration_ticks: u32) void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    queue_len = 1;
    queue_pos = 0;
    queue[0] = .{ .freq = freq, .ticks = @intCast(@min(duration_ticks, 255)) };
    remaining_ticks = duration_ticks;
    startTone(freq);
}

/// Play a sequence of notes.
fn playSeq(notes: []const Note) void {
    // Caller (the public effect functions below) holds `lock`.
    const len = @min(notes.len, MAX_NOTES);
    for (0..len) |i| queue[i] = notes[i];
    queue_len = @intCast(len);
    queue_pos = 0;
    if (len > 0) {
        remaining_ticks = notes[0].ticks;
        startTone(notes[0].freq);
    }
}

/// True while a note queue is mid-playback (tick() still counts beats).
/// Unlocked read — gates the tickless-idle stretch only.
pub fn isActive() bool {
    return queue_len != 0;
}

/// Called from timer IRQ handler.
pub fn tick() void {
    if (queue_len == 0) return;
    // Already cli'd in IRQ context; plain acquire is safe and the lock
    // synchronizes against syscall-side mutators on other CPUs.
    lock.acquire();
    defer lock.release();
    if (queue_len == 0) return;
    if (remaining_ticks > 0) {
        remaining_ticks -= 1;
        if (remaining_ticks == 0) {
            queue_pos += 1;
            if (queue_pos < queue_len) {
                remaining_ticks = queue[queue_pos].ticks;
                startTone(queue[queue_pos].freq);
            } else {
                stopTone();
                queue_len = 0;
            }
        }
    }
}

// --- Sound effects ---

/// Startup chime: ascending 3-note arpeggio
pub fn startup() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    playSeq(&[_]Note{
        .{ .freq = 523, .ticks = 6 },  // C5
        .{ .freq = 659, .ticks = 6 },  // E5
        .{ .freq = 784, .ticks = 8 },  // G5
    });
}

/// Short UI click
pub fn click() void {
    beep(1400, 1);
}

/// Window open: quick ascending
pub fn open() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    playSeq(&[_]Note{
        .{ .freq = 600, .ticks = 2 },
        .{ .freq = 900, .ticks = 2 },
    });
}

/// Window close: quick descending
pub fn close() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    playSeq(&[_]Note{
        .{ .freq = 800, .ticks = 2 },
        .{ .freq = 500, .ticks = 2 },
    });
}

/// Error: two low buzzes
pub fn err() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    playSeq(&[_]Note{
        .{ .freq = 250, .ticks = 4 },
        .{ .freq = 0, .ticks = 2 },   // gap
        .{ .freq = 200, .ticks = 6 },
    });
}

/// Notification ping: pleasant two-note
pub fn notify() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    playSeq(&[_]Note{
        .{ .freq = 880, .ticks = 3 },  // A5
        .{ .freq = 1100, .ticks = 4 }, // ~C#6
    });
}
