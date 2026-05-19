const io = @import("../io.zig");
const debug = @import("../debug/debug.zig");

/// True after initPS2() succeeds. Read by main.zig at the end of hardware
/// probe to decide whether to warn about missing input devices.
pub var ps2_present: bool = false;

// --- PS/2 controller initialization ---

fn ps2Wait() bool {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if (io.inb(0x64) & 2 == 0) return true;
    }
    return false;
}

fn ps2WaitOutput() bool {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if (io.inb(0x64) & 1 != 0) return true;
    }
    return false;
}

fn ps2Flush() void {
    for (0..64) |_| {
        if (io.inb(0x64) & 1 == 0) break;
        _ = io.inb(0x60);
    }
}

/// Initialize PS/2 controller and keyboard. Call before enabling IRQs.
/// Returns false if PS/2 controller is not present (USB-only system).
pub fn initPS2() bool {
    // Check if PS/2 controller exists by testing status port
    const status = io.inb(0x64);
    if (status == 0xFF) {
        debug.klog("[kbd] No PS/2 controller detected\n", .{});
        return false;
    }

    // Disable both PS/2 ports during setup
    if (!ps2Wait()) return false;
    io.outb(0x64, 0xAD); // Disable port 1 (keyboard)
    if (!ps2Wait()) return false;
    io.outb(0x64, 0xA7); // Disable port 2 (mouse)

    // Flush output buffer
    ps2Flush();

    // Read controller config byte
    if (!ps2Wait()) return false;
    io.outb(0x64, 0x20);
    if (!ps2WaitOutput()) {
        debug.klog("[kbd] PS/2 controller not responding\n", .{});
        return false;
    }
    var config = io.inb(0x60);

    // Enable IRQ1 (keyboard), keep IRQ12 off for now (mouse does it later)
    // Enable translation (bit 6) for scancode set 1 compatibility
    config |= 0x01; // Enable IRQ1
    config |= 0x40; // Enable translation
    config &= ~@as(u8, 0x10); // Clear "disable keyboard clock"

    // Write back config
    _ = ps2Wait();
    io.outb(0x64, 0x60);
    _ = ps2Wait();
    io.outb(0x60, config);

    // Re-enable keyboard port
    _ = ps2Wait();
    io.outb(0x64, 0xAE);

    // Reset keyboard
    _ = ps2Wait();
    io.outb(0x60, 0xFF);
    _ = ps2WaitOutput();
    _ = io.inb(0x60); // ACK (0xFA)
    _ = ps2WaitOutput();
    _ = io.inb(0x60); // Self-test result (0xAA)

    // Enable scanning
    _ = ps2Wait();
    io.outb(0x60, 0xF4);
    _ = ps2WaitOutput();
    _ = io.inb(0x60); // ACK

    debug.klog("[kbd] PS/2 keyboard initialized\n", .{});
    ps2_present = true;
    return true;
}

/// Mask PS/2 IRQ1 in the i8042 controller config and disable port 1
/// (keyboard) entirely. Called when a USB keyboard is up and PS/2 input
/// is redundant — QEMU's i8042 emulation otherwise spuriously asserts
/// IRQ1 at ~2200/sec on an idle system (the IRQ-status-bit-stuck class
/// of i8042 quirks), burning ~4 % of one CPU in handleIRQ1 + EOI for
/// nothing.
///
/// We don't disable IRQ12 (mouse) here — if the user has a PS/2 mouse
/// alongside a USB keyboard, dropping IRQ12 would silently kill mouse
/// input. The mouse path has its own enable/disable knob.
pub fn disableIRQ1() void {
    if (!ps2_present) return;
    asm volatile ("cli");
    // Drain anything sitting in port 1's data buffer so it can't latch
    // the IRQ line again after we mask.
    ps2Flush();
    // Disable port 1 entirely (keyboard clock off).
    if (!ps2Wait()) {
        asm volatile ("sti");
        return;
    }
    io.outb(0x64, 0xAD);
    // Read controller config and clear "IRQ1 enable" (bit 0). Leave the
    // mouse-side bits (bit 1, bit 5) untouched — if the user has a PS/2
    // touchpad alongside a USB keyboard, dropping IRQ12 would silently
    // kill input.
    if (!ps2Wait()) {
        asm volatile ("sti");
        return;
    }
    io.outb(0x64, 0x20);
    if (!ps2WaitOutput()) {
        asm volatile ("sti");
        return;
    }
    var config = io.inb(0x60);
    config &= ~@as(u8, 0x01); // clear IRQ1 enable
    config |= 0x10; // set "disable keyboard clock"
    _ = ps2Wait();
    io.outb(0x64, 0x60);
    _ = ps2Wait();
    io.outb(0x60, config);
    ps2_present = false; // input ring stays drained from here on
    debug.klog("[kbd] PS/2 IRQ1 masked (USB keyboard active)\n", .{});
    asm volatile ("sti");
}

/// Re-enable keyboard IRQ after mouse init may have changed the PS/2 config.
/// Disables interrupts during config byte read/write to prevent mouse IRQ
/// from stealing the data byte.
pub fn reEnable() void {
    // Disable interrupts so mouse IRQ can't eat config byte from port 0x60
    asm volatile ("cli");
    // Flush any pending data first
    ps2Flush();
    // Enable keyboard port
    _ = ps2Wait();
    io.outb(0x64, 0xAE);
    // Read config byte
    _ = ps2Wait();
    io.outb(0x64, 0x20);
    _ = ps2WaitOutput();
    var config = io.inb(0x60);
    config |= 0x01; // IRQ1 enable
    config |= 0x02; // IRQ12 enable (mouse)
    config |= 0x40; // Translation
    config &= ~@as(u8, 0x10); // Don't disable keyboard clock
    config &= ~@as(u8, 0x20); // Don't disable mouse clock
    // Write config byte
    _ = ps2Wait();
    io.outb(0x64, 0x60);
    _ = ps2Wait();
    io.outb(0x60, config);
    // Re-enable interrupts
    asm volatile ("sti");
}

// Normal scancode-to-ASCII map (scancodes 0x00-0x39, 58 entries)
pub const key_map = [58]u8{
    0,    0x1B, '1',  '2',  '3',  '4',  '5',  '6',  '7',  '8',  // 0x00-0x09
    '9',  '0',  '-',  '=',  0x08, '\t', 'q',  'w',  'e',  'r',  // 0x0A-0x13
    't',  'y',  'u',  'i',  'o',  'p',  '[',  ']',  '\n', 0,    // 0x14-0x1D (0x1D=LCtrl)
    'a',  's',  'd',  'f',  'g',  'h',  'j',  'k',  'l',  ';',  // 0x1E-0x27
    '\'', '`',  0,    '\\', 'z',  'x',  'c',  'v',  'b',  'n',  // 0x28-0x31 (0x2A=LShift)
    'm',  ',',  '.',  '/',  0,    '*',  0,    ' ',              // 0x32-0x39 (0x36=RShift,0x38=LAlt)
};

// Shifted scancode-to-ASCII map
pub const shift_map = [58]u8{
    0,    0x1B, '!',  '@',  '#',  '$',  '%',  '^',  '&',  '*',  // 0x00-0x09
    '(',  ')',  '_',  '+',  0x08, '\t', 'Q',  'W',  'E',  'R',  // 0x0A-0x13
    'T',  'Y',  'U',  'I',  'O',  'P',  '{',  '}',  '\n', 0,    // 0x14-0x1D
    'A',  'S',  'D',  'F',  'G',  'H',  'J',  'K',  'L',  ':',  // 0x1E-0x27
    '"',  '~',  0,    '|',  'Z',  'X',  'C',  'V',  'B',  'N',  // 0x28-0x31
    'M',  '<',  '>',  '?',  0,    '*',  0,    ' ',              // 0x32-0x39
};

// Special key codes (>= 0x80, pushed to ring buffer)
pub const KEY_UP: u8 = 0x80;
pub const KEY_DOWN: u8 = 0x81;
pub const KEY_LEFT: u8 = 0x82;
pub const KEY_RIGHT: u8 = 0x83;
pub const KEY_HOME: u8 = 0x84;
pub const KEY_END: u8 = 0x85;
pub const KEY_PGUP: u8 = 0x86;
pub const KEY_PGDN: u8 = 0x87;
pub const KEY_DELETE: u8 = 0x88;
pub const KEY_INSERT: u8 = 0x89;
pub const KEY_F1: u8 = 0x90;
// F2=0x91, F3=0x92, ..., F10=0x99, F11=0x9A, F12=0x9B
/// Pseudo-key pushed to global_buffer when Ctrl+C is pressed. Desktop main
/// loop sees this and posts SIGINT to the focused window's pid. Apps don't
/// see a literal 0x03 byte anymore — installing a SIGINT handler is the way
/// to react. Matches the Unix terminal "interrupt key" convention.
pub const KEY_SIGINT: u8 = 0xA0;

// Modifier state (packed for efficiency)
pub const Modifiers = packed struct(u8) {
    shift: bool = false,
    ctrl: bool = false,
    alt: bool = false,
    caps_lock: bool = false,
    _pad: u4 = 0,
};
pub var mods: Modifiers = .{};
// Legacy accessors for compatibility
pub var shift_held: bool = false;
pub var ctrl_held: bool = false;
pub var alt_held: bool = false;
pub var caps_lock: bool = false;
var extended: bool = false;

// Key state bitmap — tracks which scancodes are currently held
pub var key_state: [256]bool = [_]bool{false} ** 256;

// --- Typematic auto-repeat ---
// When a key stays held past REPEAT_DELAY_TICKS, the keyboard ring auto-pushes
// the same resolved character every REPEAT_INTERVAL_TICKS until release. This
// is what makes holding backspace erase a paragraph in a couple of seconds
// instead of one char per real keypress. Driven by `pollRepeat(tick_count)`
// which the desktop main loop calls each iteration.
//
// Tuned 2026-05-07 from 300/50 ms → 200/30 ms after user-reported "hold-to-
// delete feels broken." Faster initial repeat + ~33 chars/sec sustained
// matches the snappiness most desktops ship with.
const REPEAT_DELAY_TICKS: u64 = 20; // 200ms initial pause before repeat starts
const REPEAT_INTERVAL_TICKS: u64 = 3; // 30ms between repeats → ~33 chars/sec
var repeat_scancode: u8 = 0; // 0 = nothing tracked
var repeat_char: u8 = 0;
var repeat_press_tick: u64 = 0;
var repeat_last_tick: u64 = 0;
/// Diagnostic flag so the kernel can emit one klog line per fresh
/// typematic burst — i.e. exactly when the first repeat for a held key
/// fires. Helps confirm pollRepeat is actually being driven by the
/// desktop loop without filling serial.log on every repeat tick.
var repeat_logged_for_scancode: u8 = 0;

/// Begin tracking a held key for typematic auto-repeat. Called from both
/// PS/2 (`handleScancode`) and USB (`xhci.processKeyboardReport`) on every
/// fresh key press. Replaces any previous tracked key — only one repeats
/// at a time, matching standard typematic behavior.
pub fn beginRepeatTracking(scancode: u8, ch: u8, now: u64) void {
    repeat_scancode = scancode;
    repeat_char = ch;
    repeat_press_tick = now;
    repeat_last_tick = now;
}

/// Stop tracking the typematic-repeat key. Useful when a USB report shows
/// the previously-tracked usage is no longer held — equivalent to a PS/2
/// release for the same scancode.
pub fn clearRepeatTracking() void {
    repeat_scancode = 0;
    repeat_logged_for_scancode = 0;
}

/// Push another copy of the held key's char if the repeat threshold has
/// elapsed. Idempotent — safe to call every loop iteration. Stops on its
/// own when the scancode is released (key_state goes false).
pub fn pollRepeat(now: u64) void {
    if (repeat_scancode == 0) return;
    if (!key_state[repeat_scancode]) {
        repeat_scancode = 0;
        repeat_logged_for_scancode = 0;
        return;
    }
    if (now -% repeat_press_tick < REPEAT_DELAY_TICKS) return;
    if (now -% repeat_last_tick < REPEAT_INTERVAL_TICKS) return;
    if (repeat_logged_for_scancode != repeat_scancode) {
        repeat_logged_for_scancode = repeat_scancode;
        debug.klog("[kbd] typematic active scancode=0x{x:0>2} char=0x{x:0>2}\n", .{ repeat_scancode, repeat_char });
    }
    push(repeat_char);
    repeat_last_tick = now;
}

/// True when a held key is due for another repeat insertion. Used by the
/// timer IRQ's `shouldResumeDesktop` so the loop wakes promptly to deliver
/// repeats at the configured cadence.
pub fn repeatDue(now: u64) bool {
    if (repeat_scancode == 0) return false;
    if (!key_state[repeat_scancode]) return false;
    if (now -% repeat_press_tick < REPEAT_DELAY_TICKS) return false;
    return (now -% repeat_last_tick) >= REPEAT_INTERVAL_TICKS;
}

// Ring buffer for app-readable keystrokes (printable ASCII + control codes
// + arrow keys). Apps drain this via syscall 4 / libc.readChar.
var buffer: [256]u8 = [_]u8{0} ** 256;
var head: usize = 0;
var tail: usize = 0;

// Separate ring for desktop-only global shortcuts (currently F1..F12 →
// 0x90..0x9F). Splitting these out prevents fullscreen GUI apps from
// draining F10 in their pollKeys loops before the desktop's intercept
// gets a chance to run. Smaller (32 bytes) — no app uses this.
var global_buffer: [32]u8 = [_]u8{0} ** 32;
var global_head: usize = 0;
var global_tail: usize = 0;

// Diagnostic counters for input-pipeline debugging. Read by /proc/sched
// or dumped on demand via klog. Atomic so any IRQ context is safe.
pub var dbg_push_total: u64 = 0;
pub var dbg_push_dropped: u64 = 0;

pub fn push(ch: u8) void {
    @import("std").debug.assert(true); // suppress unused-import warning if any
    _ = @atomicRmw(u64, &dbg_push_total, .Add, 1, .monotonic);
    // Ctrl+C (literal byte 0x03) from ANY source — PS/2 handleScancode, USB
    // xhci.processKeyboardReport, future kbd drivers — delivers SIGINT
    // *directly* at IRQ time to the focused window's signal target.
    //
    // Why direct dispatch: routing through the global buffer + desktop main
    // loop is fragile — if desktop is stalled in a long net syscall (httpd
    // serving a request, tg.elf waiting on the relay, etc.) the KEY_SIGINT
    // event sits in the buffer until the loop runs again, which can be many
    // seconds. From IRQ context we can call signals.send straight through —
    // it's pure field writes + an optional process.wake, both lock-free.
    if (ch == 0x03) {
        const desktop = @import("../ui/desktop.zig");
        const signals = @import("../proc/signals.zig");
        const target = desktop.focusedSignalTarget();
        if (target != 0xFF) _ = signals.send(target, signals.SIGINT);
        return;
    }
    // F1..F12 (0x90..0x9F) are global shortcuts — route to the desktop-only
    // ring so a focused fullscreen app's `while (readChar() != 0) {}` drain
    // doesn't eat them. See desktop.zig F10 handler.
    if (ch >= 0x90 and ch <= 0x9F) {
        pushGlobal(ch);
        return;
    }
    const next = (head + 1) % buffer.len;
    if (next != tail) {
        buffer[head] = ch;
        head = next;
    } else {
        _ = @atomicRmw(u64, &dbg_push_dropped, .Add, 1, .monotonic);
    }
}

fn pushGlobal(ch: u8) void {
    const next = (global_head + 1) % global_buffer.len;
    if (next != global_tail) {
        global_buffer[global_head] = ch;
        global_head = next;
    }
}

pub fn hasData() bool {
    return head != tail;
}

pub fn peek() ?u8 {
    if (head == tail) return null;
    return buffer[tail];
}

pub fn pop() ?u8 {
    if (head == tail) return null;
    const ch = buffer[tail];
    tail = (tail + 1) % buffer.len;
    return ch;
}

/// Peek the desktop-only global-shortcut ring. Used by the desktop's F10 /
/// future shortcut intercepts. Apps don't have access — there's no syscall
/// for it.
pub fn peekGlobal() ?u8 {
    if (global_head == global_tail) return null;
    return global_buffer[global_tail];
}

pub fn popGlobal() ?u8 {
    if (global_head == global_tail) return null;
    const ch = global_buffer[global_tail];
    global_tail = (global_tail + 1) % global_buffer.len;
    return ch;
}

/// Process a raw scancode from IRQ1. Handles modifiers, extended scancodes, and key mapping.
pub fn handleScancode(scancode: u8) void {
    // Extended scancode prefix
    if (scancode == 0xE0) {
        extended = true;
        return;
    }

    const is_release = (scancode & 0x80) != 0;
    const code = scancode & 0x7F;

    // Track key state for games (press/release)
    key_state[code] = !is_release;

    if (extended) {
        extended = false;
        if (!is_release) {
            const special: ?u8 = switch (code) {
                0x48 => KEY_UP,
                0x50 => KEY_DOWN,
                0x4B => KEY_LEFT,
                0x4D => KEY_RIGHT,
                0x47 => KEY_HOME,
                0x4F => KEY_END,
                0x49 => KEY_PGUP,
                0x51 => KEY_PGDN,
                0x53 => KEY_DELETE,
                0x52 => KEY_INSERT,
                else => null,
            };
            if (special) |key| {
                push(key);
                beginRepeatTracking(code, key, @import("../proc/process.zig").tick_count);
            }
        } else if (code == repeat_scancode) {
            repeat_scancode = 0;
        }
        return;
    }

    // Modifier keys — track press and release
    if (code == 0x2A or code == 0x36) { // Left/Right Shift
        shift_held = !is_release;
        mods.shift = shift_held;
        return;
    }
    if (code == 0x1D) { // Left Ctrl
        ctrl_held = !is_release;
        mods.ctrl = ctrl_held;
        return;
    }
    if (code == 0x38) { // Left Alt
        alt_held = !is_release;
        mods.alt = alt_held;
        return;
    }
    if (code == 0x3A and !is_release) { // Caps Lock toggle
        caps_lock = !caps_lock;
        mods.caps_lock = caps_lock;
        return;
    }

    // Only process key presses from here. Releases of the currently-tracked
    // repeat scancode also clear it so the typematic loop stops.
    if (is_release) {
        if (code == repeat_scancode) repeat_scancode = 0;
        return;
    }

    // Function keys F1-F10 (scancodes 0x3B-0x44)
    if (code >= 0x3B and code <= 0x44) {
        const ch = KEY_F1 + (code - 0x3B);
        push(ch);
        beginRepeatTracking(code, ch, @import("../proc/process.zig").tick_count);
        return;
    }
    // F11=0x57, F12=0x58
    if (code == 0x57) {
        push(KEY_F1 + 10);
        beginRepeatTracking(code, KEY_F1 + 10, @import("../proc/process.zig").tick_count);
        return;
    }
    if (code == 0x58) {
        push(KEY_F1 + 11);
        beginRepeatTracking(code, KEY_F1 + 11, @import("../proc/process.zig").tick_count);
        return;
    }

    // Normal keys
    if (code < key_map.len) {
        var ch = if (shift_held) shift_map[code] else key_map[code];
        if (ch == 0) return;

        // Caps lock: toggle case for letters (XOR with shift)
        if (!shift_held and caps_lock and ch >= 'a' and ch <= 'z') {
            ch -= 32;
        } else if (shift_held and caps_lock and ch >= 'A' and ch <= 'Z') {
            ch += 32;
        }

        // Ctrl+letter → ASCII 1-26. push() rewrites 0x03 (Ctrl+C) into a
        // KEY_SIGINT global-buffer entry so we don't need a special-case here.
        if (ctrl_held) {
            if (ch >= 'a' and ch <= 'z') {
                ch = ch - 'a' + 1;
            } else if (ch >= 'A' and ch <= 'Z') {
                ch = ch - 'A' + 1;
            }
        }

        push(ch);
        beginRepeatTracking(code, ch, @import("../proc/process.zig").tick_count);
    }
}
