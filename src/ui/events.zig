// Window event model — Phase 1: keyboard events.
//
// Replaces the patchwork "global keyboard ring + per-terminal kb_pipe +
// mouse-special-case + ad-hoc focus polling" with a per-window typed
// event queue. The desktop is the sole producer (drains the keyboard
// IRQ ring and publishes events into the focused window's queue); the
// owning process is the sole consumer (drains via syscall).
//
// Phase 1 scope: key_char + key_special events only. Mouse, focus
// transitions, resize, and close events are reserved kinds for later
// phases — adding them is a one-line enum entry plus desktop publish
// site, no API change for existing consumers.
//
// Why per-window not per-pid:
//   - A single pid may own multiple windows (e.g. a future toolbox app);
//     events naturally route to the focused window, not "the process".
//   - A terminal window has shell_pid != owner_pid; per-window queue
//     decouples "which window receives" from "which process is reader".
//   - Each window already has a stable lifetime tied to its slot, so
//     adding one queue per window costs MAX_WINDOWS × QUEUE_BYTES of
//     BSS and disappears with the window.
//
// SPSC safety: desktop is the only producer (single kernel task), and
// only the focused window's owner can consume (kernel filters by pid in
// `desktop.popEvent`). On x86 with TSO, head/tail u8 stores and reads
// are sequenced enough that the producer's queue write becomes visible
// before the head bump. No locks needed.

const std = @import("std");

/// Event categories. Numeric values are part of the user-space ABI —
/// libc maps these to constants and apps switch on them. Don't reorder
/// existing entries; append new ones.
pub const EventKind = enum(u8) {
    none = 0,
    /// `a` = translated character (post-modifier), `b` = modifier bitmap
    /// (bit 0 shift, 1 ctrl, 2 alt, 3 caps_lock).
    key_char = 1,
    /// `a` = special key code (keyboard.KEY_UP / KEY_DOWN / KEY_F1 etc),
    /// `b` = modifier bitmap. Used for arrows / function keys / pgup-pgdn /
    /// home/end / insert/delete — keys that don't have a single-byte
    /// printable form.
    key_special = 2,
    /// Cursor moved while this window is focused. `a`/`b` = window-local
    /// x/y (i32 cast to u32), measured from the content-area top-left
    /// (i.e. y=0 is the row just below the titlebar). `c` = current
    /// buttons bitmap (bit 0 = left, 1 = right, 2 = middle).
    mouse_move = 3,
    /// A mouse button changed state. `a` low byte = button index
    /// (0/1/2 for L/R/M), `a` second byte = 1 if pressed, 0 if released,
    /// `a` third byte = current full buttons bitmap (post-transition).
    /// `b`/`c` = window-local x/y at the moment of transition.
    mouse_button = 4,
    /// Mouse wheel rotated. `a` = signed notch count (i32 cast to u32 —
    /// positive = scroll up). `b`/`c` = window-local x/y of cursor.
    mouse_wheel = 5,
    /// This window just became the focused window. `a` = pid that was
    /// previously focused, or 0xFF.
    focus_in = 6,
    /// This window just lost focus. `a` = pid that's now focused, or 0xFF.
    focus_out = 7,
    /// Window content area was resized (interactive resize completed).
    /// `a` = new width, `b` = new height.
    resize = 8,
    /// User initiated close (clicked the X button or chose "Close" from
    /// the titlebar context menu). The window's destroy animation has
    /// already started; the app has the duration of the animation
    /// (~200 ms) to call `exit()` itself. If it doesn't, the desktop's
    /// existing close path destroys it forcibly.
    close_request = 9,
};

/// Modifier bits packed into `Event.b` for key events. Numbered to
/// match libc's expected MOD_* constants.
pub const MOD_SHIFT: u32 = 1 << 0;
pub const MOD_CTRL: u32 = 1 << 1;
pub const MOD_ALT: u32 = 1 << 2;
pub const MOD_CAPS: u32 = 1 << 3;

/// 16-byte event record. Three u32 payload slots are enough for every
/// kind we currently emit (char + mods uses 2 slots, mouse_move would
/// use 3 for x/y/buttons, etc). The fixed size means user-space libc
/// can read events into a stack array without dynamic sizing logic.
pub const Event = extern struct {
    kind: u8,
    _pad: [3]u8 = .{ 0, 0, 0 },
    a: u32 = 0,
    b: u32 = 0,
    c: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(Event) == 16);
}

/// Per-window event queue. Power-of-two size lets the modulo collapse
/// to a mask. 32 entries is generous for a 10 ms desktop frame at
/// realistic typing rates (~10 keys/sec sustained, ~30 keys/sec peak
/// burst with autorepeat) — the queue would overflow only if the
/// app's drain loop stops running for >300 ms while the user types.
pub const QUEUE_SIZE: u8 = 32;
const QUEUE_MASK: u8 = QUEUE_SIZE - 1;

pub const EventQueue = struct {
    buf: [QUEUE_SIZE]Event = [_]Event{.{ .kind = 0 }} ** QUEUE_SIZE,
    head: u8 = 0,
    tail: u8 = 0,

    /// Push an event. If the queue is full, the new event is dropped
    /// (overflow). Drop-newest matches the user's intent better than
    /// drop-oldest — when the app is too slow to drain, the user is
    /// usually about to retry rather than missing a stale stroke.
    pub fn push(self: *EventQueue, ev: Event) void {
        const next = (self.head + 1) & QUEUE_MASK;
        if (next == self.tail) return;
        self.buf[self.head] = ev;
        self.head = next;
    }

    /// Pop the oldest event. Returns null when empty.
    pub fn pop(self: *EventQueue) ?Event {
        if (self.head == self.tail) return null;
        const ev = self.buf[self.tail];
        self.tail = (self.tail + 1) & QUEUE_MASK;
        return ev;
    }

    pub fn isEmpty(self: *const EventQueue) bool {
        return self.head == self.tail;
    }

    /// Discard all queued events. Used on focus loss / window destroy
    /// so a window doesn't deliver stale events when it next becomes
    /// focused (or to a future tenant of the same slot).
    pub fn clear(self: *EventQueue) void {
        self.tail = self.head;
    }
};
