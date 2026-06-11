const io = @import("../io.zig");
const pic = @import("../time/pic.zig");
const debug = @import("../debug/debug.zig");

const DATA_PORT: u16 = 0x60;
const STATUS_PORT: u16 = 0x64;
const COMMAND_PORT: u16 = 0x64;

const ACK: u8 = 0xFA;
const RESEND: u8 = 0xFE;

pub var x: i32 = 640;
pub var y: i32 = 360;
pub var buttons: u8 = 0;
pub var moved: bool = false;
// Accumulated deltas since last read (for FPS-style mouse input)
pub var accum_dx: i32 = 0;
pub var accum_dy: i32 = 0;

// Raw, pre-clamp relative motion accumulated by the HID/PS2 mouse drivers and
// drained by desktop.getMouseRelative into the per-app FPS delta channel
// (buf[3..4]). Kept separate from the screen-clamped absolute x/y so mouse-
// look doesn't saturate to 0 when the visible cursor pins to a screen edge.
pub var raw_dx: i32 = 0;
pub var raw_dy: i32 = 0;
// Accumulated scroll-wheel notches since last consumer read.
// Positive = wheel-up (scroll content down / view earlier history).
// Consumer (desktop.handleMouseEvents) reads then resets to 0.
pub var wheel: i32 = 0;
pub var screen_w: i32 = 1280;
pub var screen_h: i32 = 720;
pub var speed: u8 = 1; // 0=slow, 1=normal, 2=fast
pub var ps2_active: bool = false;

// One of these is set after init based on what the device announced:
// IntelliMouse → 4-byte packets with Z (wheel) byte.
// Synaptics    → 6-byte absolute-mode packets with X/Y/Z/W and tap detect.
// neither      → standard PS/2 3-byte packets.
var is_intellimouse: bool = false;
var is_synaptics: bool = false;
var packet_len: u8 = 3;

var cycle: u8 = 0;
var mouse_bytes: [6]u8 = undefined;

// Synaptics state — only meaningful when is_synaptics.
var syn_prev_x: i32 = 0;
var syn_prev_y: i32 = 0;
var syn_finger_down: bool = false;
// Tap-to-click bookkeeping: count IRQ ticks finger was on the pad. Brief
// touch (< TAP_MAX_TICKS) without significant movement = synthetic click.
var syn_tap_ticks: u32 = 0;
var syn_tap_moved: bool = false;
const TAP_MAX_TICKS: u32 = 8; // ≈ 80 ms at default 100 Hz sample rate
// Compared against per-packet |dx|+|dy| AFTER the /4 mouse-feel scaling
// (and speed scaling), so in raw pad units this is ~40+ per sample — a
// single-packet jerk. Slow drags rely on TAP_MAX_TICKS to disqualify.
const TAP_MOVE_THRESHOLD: i32 = 10;
// Two-finger scroll: when W reports two fingers, accumulate vertical motion
// into the wheel accumulator instead of moving the cursor.
const SYN_W_TWO_FINGERS: u8 = 0;
// Pending synthetic-click button mask, OR'd into `buttons` for one IRQ then
// cleared. Lets the desktop see a real press+release transition.
var syn_synth_click: u8 = 0;
// True while `buttons` carries a synthetic tap-click whose release edge has
// not been published yet. handleIRQ drops it on the very next aux byte —
// see the comment there for why waiting for a full packet was too late.
var syn_synth_latched: bool = false;

/// Wait for the i8042 controller to be ready. Returns false if the budget
/// elapsed without the condition becoming true — caller treats as a missing
/// or wedged device, NOT as success-with-bad-data.
fn mouseWait(is_signal: bool) bool {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if (is_signal) {
            if (io.inb(STATUS_PORT) & 1 != 0) return true;
        } else {
            if (io.inb(STATUS_PORT) & 2 == 0) return true;
        }
    }
    return false;
}

/// Optional read — returns null if no byte arrived within budget.
fn mouseReadOpt() ?u8 {
    if (!mouseWait(true)) return null;
    return io.inb(DATA_PORT);
}

/// Send a single command byte to the aux device and consume the reply.
/// Treats RESEND (0xFE) by retrying up to 3 times. Returns false if the
/// controller / mouse never responds, or replies with anything other than
/// ACK / RESEND.
fn mouseCommand(data: u8) bool {
    var attempts: u32 = 0;
    while (attempts < 3) : (attempts += 1) {
        if (!mouseWait(false)) return false;
        io.outb(COMMAND_PORT, 0xD4);
        if (!mouseWait(false)) return false;
        io.outb(DATA_PORT, data);
        const reply = mouseReadOpt() orelse return false;
        if (reply == ACK) return true;
        if (reply != RESEND) return false;
    }
    return false;
}

/// Two-byte command sequence (e.g. 0xF3 set-sample-rate + the rate value).
/// Each byte gets its own ACK.
fn mouseCommand2(cmd: u8, arg: u8) bool {
    if (!mouseCommand(cmd)) return false;
    if (!mouseWait(false)) return false;
    io.outb(COMMAND_PORT, 0xD4);
    if (!mouseWait(false)) return false;
    io.outb(DATA_PORT, arg);
    const reply = mouseReadOpt() orelse return false;
    return reply == ACK;
}

/// Synaptics-specific: encode an 8-bit query/argument as four 2-bit
/// "set resolution" commands. The pad cooks the four 2-bit chunks back
/// together internally and uses them as the operand for the next
/// 0xE9 (status request) or 0xF3 (sample rate magic).
fn synEncode8(value: u8) bool {
    if (!mouseCommand(0xE6)) return false; // set scaling 1:1 — required prelude
    if (!mouseCommand2(0xE8, (value >> 6) & 0x03)) return false;
    if (!mouseCommand2(0xE8, (value >> 4) & 0x03)) return false;
    if (!mouseCommand2(0xE8, (value >> 2) & 0x03)) return false;
    if (!mouseCommand2(0xE8, value & 0x03)) return false;
    return true;
}

/// Synaptics query: encode `query_type`, then send 0xE9 to read the 3-byte
/// response. Used for Identify (0x00) and Capabilities (0x02).
fn synQuery(query_type: u8, response: *[3]u8) bool {
    if (!synEncode8(query_type)) return false;
    if (!mouseCommand(0xE9)) return false;
    response[0] = mouseReadOpt() orelse return false;
    response[1] = mouseReadOpt() orelse return false;
    response[2] = mouseReadOpt() orelse return false;
    return true;
}

/// Probe + initialize a Synaptics touchpad. Returns true on success
/// (is_synaptics + packet_len set). False = not present, init left
/// untouched so the IntelliMouse fallback can run.
fn enableSynaptics() bool {
    var resp: [3]u8 = undefined;
    if (!synQuery(0x00, &resp)) return false;
    // Synaptics signature: response[1] is constant 0x47 on real Synaptics
    // touchpads. Anything else = not Synaptics, bail without disturbing
    // device state.
    if (resp[1] != 0x47) return false;

    const major = resp[2] >> 4;
    const minor = resp[2] & 0x0F;
    debug.klog("[mouse] Synaptics touchpad detected (v{d}.{d})\n", .{ major, minor });

    // Switch to absolute mode with W reporting. Mode byte = 0x80 (bit 7
    // set = absolute mode, bit 0 set in W field would enable high-rate;
    // 0x80 alone is the conservative baseline that all Synaptics versions
    // accept). Encode the mode byte via the same four-nibble dance, then
    // send 0xF3 with arg 20 (a magic "set sample rate" that Synaptics uses
    // as a commit signal to apply the queued mode).
    if (!synEncode8(0x80)) return false;
    if (!mouseCommand2(0xF3, 20)) return false;

    is_synaptics = true;
    packet_len = 6;
    syn_finger_down = false;
    syn_tap_ticks = 0;
    syn_tap_moved = false;
    syn_synth_click = 0;
    syn_synth_latched = false;
    return true;
}

/// Magic knock for IntelliMouse: set sample rate to 200, 100, then 80,
/// then query device ID. If the mouse supports a wheel it switches itself
/// to 4-byte packets and reports ID 0x03. Older 3-button mice respond 0x00
/// and stay on 3-byte packets — we silently fall back.
fn enableIntellimouse() void {
    if (!mouseCommand2(0xF3, 200)) return;
    if (!mouseCommand2(0xF3, 100)) return;
    if (!mouseCommand2(0xF3, 80)) return;
    if (!mouseCommand(0xF2)) return;
    const id = mouseReadOpt() orelse return;
    if (id == 0x03) {
        is_intellimouse = true;
        packet_len = 4;
        debug.klog("[mouse] IntelliMouse wheel enabled\n", .{});
    } else {
        debug.klog("[mouse] device id 0x{x:0>2} — no wheel\n", .{id});
    }
}

/// Returns true on full-init success. False = no mouse / wedged device;
/// caller (desktop.zig) logs it but keeps booting.
pub fn init() bool {
    // Enable auxiliary mouse device.
    if (!mouseWait(false)) return false;
    io.outb(COMMAND_PORT, 0xA8);

    // Read controller config byte → enable IRQ12 + clear disable-clock.
    if (!mouseWait(false)) return false;
    io.outb(COMMAND_PORT, 0x20);
    if (!mouseWait(true)) return false;
    var status = io.inb(DATA_PORT);
    status |= 2; // IRQ12 enable
    status &= ~@as(u8, 0x20); // clear disable mouse clock
    if (!mouseWait(false)) return false;
    io.outb(COMMAND_PORT, 0x60);
    if (!mouseWait(false)) return false;
    io.outb(DATA_PORT, status);

    // Use default settings (resets sample rate, resolution, scaling).
    if (!mouseCommand(0xF6)) return false;

    // Probe order matters: Synaptics first, because the IntelliMouse magic
    // knock alters device state in a way Synaptics interprets differently
    // and would then refuse the absolute-mode command. If Synaptics says
    // "not me", we fall back to IntelliMouse, then to standard PS/2.
    if (!enableSynaptics()) {
        enableIntellimouse();
    }

    // Enable data reporting (0xF4) — packets start flowing now.
    if (!mouseCommand(0xF4)) return false;

    pic.enableIRQ(12);

    cycle = 0;
    x = @divTrunc(screen_w, 2);
    y = @divTrunc(screen_h, 2);
    moved = false;
    ps2_active = true;
    debug.klog("[mouse] PS/2 mouse initialized ({d}-byte packets)\n", .{packet_len});
    return true;
}

pub fn handleIRQ() void {
    // Gate on the i8042 status byte BEFORE touching the data port: bit 0
    // (output buffer full) must be set — IRQ12 can fire spuriously — and
    // bit 5 (AUX) must mark the byte as mouse data. The controller is
    // shared with the keyboard; the old unconditional read could steal a
    // pending KEYBOARD byte (one eaten keystroke) and feed it to the
    // packet state machine as mouse data.
    const st = io.inb(STATUS_PORT);
    if (st & 0x01 == 0 or st & 0x20 == 0) return;
    const data = io.inb(DATA_PORT);

    // A latched synthetic tap-click must not outlive the stream: its
    // release edge only becomes visible when `buttons` is next recomputed,
    // which used to require a complete subsequent packet (3-6 bytes). Any
    // aux byte is proof the stream is alive — publish the release NOW.
    // (A pad that sends nothing at all after the lift packet still strands
    // the latch; accepted residual — the next touch clears it.)
    if (syn_synth_latched) {
        syn_synth_latched = false;
        buttons &= ~@as(u8, 0x01);
        moved = true;
    }

    switch (cycle) {
        0 => {
            // First-byte sync check, mode-aware. Standard/IntelliMouse
            // byte 0 always has bit 3 set. Synaptics ABSOLUTE-mode byte 0
            // is `1 0 Yo Xo Bp Wn3 R L` — bit 3 there is the pad-button
            // bit, LOW with no button held, so the old bit-3-only gate
            // dropped byte 0 of essentially every unclicked touchpad
            // packet and re-synced on interior bytes: permanent framing
            // garbage. Absolute byte 0 is `10xxxxxx` (byte 3 is
            // `11xxxxxx`), which is the sync property to key on.
            const in_sync = if (is_synaptics)
                (data & 0xC0) == 0x80
            else
                (data & 0x08) != 0;
            if (in_sync) {
                mouse_bytes[0] = data;
                cycle = 1;
            }
        },
        1, 2, 3, 4 => |c| {
            mouse_bytes[c] = data;
            const next = c + 1;
            if (next >= packet_len) {
                cycle = 0;
                processPacket();
            } else {
                cycle = next;
            }
        },
        5 => {
            mouse_bytes[5] = data;
            cycle = 0;
            processPacket();
        },
        else => {
            cycle = 0;
        },
    }
}

fn processPacket() void {
    if (is_synaptics) {
        processSynapticsPacket();
        return;
    }

    // Standard / IntelliMouse path.
    if (mouse_bytes[0] & 0xC0 != 0) return; // overflow → likely desync, drop

    buttons = mouse_bytes[0] & 0x07;

    var dx: i32 = @intCast(mouse_bytes[1]);
    var dy: i32 = @intCast(mouse_bytes[2]);
    if (mouse_bytes[0] & 0x10 != 0) dx -= 256;
    if (mouse_bytes[0] & 0x20 != 0) dy -= 256;

    if (speed == 0) {
        dx = @divTrunc(dx, 2);
        dy = @divTrunc(dy, 2);
    } else if (speed == 2) {
        dx *= 2;
        dy *= 2;
    }

    raw_dx +%= dx;
    raw_dy -%= dy; // PS/2 dy is up-positive; match the screen's down-positive y
    x += dx;
    y -= dy;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x >= screen_w) x = screen_w - 1;
    if (y >= screen_h) y = screen_h - 1;

    if (is_intellimouse) {
        const z: i8 = @bitCast(mouse_bytes[3]);
        if (z != 0) wheel -= z;
    }

    moved = true;
}

fn processSynapticsPacket() void {
    // Synaptics 6-byte absolute mode layout:
    //   byte 0: 1 0 Yo Xo Bp Wn3 R L
    //   byte 1: Yh3..Yh0 Xh3..Xh0  (high nibble of Y, X positions)
    //   byte 2: Z[7:0]              (pressure / "Z-axis")
    //   byte 3: 1 1 Yc Xc Wn2 Wn1 R L
    //   byte 4: Y[7:0]              (low byte of Y)
    //   byte 5: X[7:0]              (low byte of X)
    //
    // The two button bits in byte 0 vs byte 3 toggle on each packet — this
    // is how Synaptics signals button state changes. We OR them together
    // for a stable read.
    const z: u8 = mouse_bytes[2];
    const finger_present = z > 8; // common Synaptics "no finger" floor

    const x_hi: u32 = @as(u32, mouse_bytes[1]) & 0x0F;
    const y_hi: u32 = @as(u32, mouse_bytes[1]) >> 4;
    const x_lo: u32 = mouse_bytes[5];
    const y_lo: u32 = mouse_bytes[4];
    const abs_x: i32 = @intCast((x_hi << 8) | x_lo);
    const abs_y: i32 = @intCast((y_hi << 8) | y_lo);

    // Reconstruct W (finger-width) from scattered bits across byte 0 and 3.
    const w0: u8 = (mouse_bytes[3] >> 2) & 0x01;
    const w1_2: u8 = (mouse_bytes[3] >> 4) & 0x03;
    const w3: u8 = (mouse_bytes[0] >> 2) & 0x01;
    const w: u8 = (w3 << 3) | (w1_2 << 1) | w0;

    // Hardware buttons (left / right). The two copies XOR-toggle on every
    // packet (Synaptics convention) so OR is the right combine.
    const real_btns: u8 = (mouse_bytes[0] & 0x03) | (mouse_bytes[3] & 0x03);

    if (finger_present) {
        if (syn_finger_down) {
            // Continuing touch: deliver delta against last sample.
            var dx: i32 = abs_x - syn_prev_x;
            var dy: i32 = syn_prev_y - abs_y; // Y inverted for screen coords
            // Synaptics units are way finer than PS/2 — divide to bring it
            // into "mouse-feel" range.
            dx = @divTrunc(dx, 4);
            dy = @divTrunc(dy, 4);

            if (w == SYN_W_TWO_FINGERS) {
                // Two-finger gesture: vertical motion → wheel scroll, no
                // cursor movement.
                if (dy != 0) wheel += @divTrunc(dy, 2);
            } else {
                if (speed == 0) {
                    dx = @divTrunc(dx, 2);
                    dy = @divTrunc(dy, 2);
                } else if (speed == 2) {
                    dx *= 2;
                    dy *= 2;
                }
                raw_dx +%= dx;
                raw_dy +%= dy;
                x += dx;
                y += dy;
                if (x < 0) x = 0;
                if (y < 0) y = 0;
                if (x >= screen_w) x = screen_w - 1;
                if (y >= screen_h) y = screen_h - 1;
                if (dx != 0 or dy != 0) {
                    moved = true;
                    if (@as(u32, @intCast(@abs(dx))) +
                        @as(u32, @intCast(@abs(dy))) >
                        @as(u32, @intCast(TAP_MOVE_THRESHOLD)))
                    {
                        syn_tap_moved = true;
                    }
                }
            }
        } else {
            // Finger just landed.
            syn_finger_down = true;
            syn_tap_ticks = 0;
            syn_tap_moved = false;
        }
        syn_prev_x = abs_x;
        syn_prev_y = abs_y;
        if (syn_tap_ticks < 0xFFFF_FFFF) syn_tap_ticks +%= 1;
    } else {
        // No finger.
        if (syn_finger_down) {
            // Lift event. If the touch was brief and didn't move much,
            // synthesize a one-packet left-click for the desktop to see.
            // Skip when the physical left button is held: the synth bit
            // aliases real bit 0, and handleIRQ's latch-clear would then
            // briefly release a genuinely-held button (phantom double-
            // click edge).
            if (!syn_tap_moved and syn_tap_ticks <= TAP_MAX_TICKS and (real_btns & 0x01) == 0) {
                syn_synth_click = 0x01; // left button
            }
            syn_finger_down = false;
            syn_tap_ticks = 0;
            syn_tap_moved = false;
        }
    }

    // Final button state visible to the desktop: real hardware buttons,
    // OR'd with any pending synthetic click for one packet.
    buttons = real_btns | syn_synth_click;
    if (syn_synth_click != 0) {
        // Arm the release: handleIRQ publishes it on the next aux byte.
        syn_synth_click = 0;
        syn_synth_latched = true;
        moved = true;
    }
}
