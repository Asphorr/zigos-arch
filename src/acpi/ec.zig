//! src/acpi/ec.zig — ACPI Embedded Controller (PNP0C09) region handler.
//!
//! Real laptops put battery (_BST), thermal (_TMP), lid, AC, and hotkey state
//! behind the EC: an 8-bit microcontroller the host reaches through two I/O ports
//! — a command/status port (default 0x66) and a data port (default 0x62) — using
//! the ACPI 6.x §12 transaction protocol (RD_EC / WR_EC, with IBF/OBF handshake
//! polling). AML touches it through `OperationRegion(…, EmbeddedControl, …)`; the
//! field engine in aml.zig (a leaf) routes any non-built-in address space through
//! its handler registry, and this module plugs into space 0x03.
//!
//! Dependency direction: aml.zig stays the leaf — it never imports this; this
//! imports it (registerRegionHandler / RegionHandler / SPACE_EC), the same shape
//! the SMBus/GPIO handlers will follow.
//!
//! VERIFICATION. Our QEMU q35 target ships no EC, so the part worth proving — the
//! transaction state machine itself — is exercised at boot by selfTest() against
//! a faithful software EC model (a 256-byte register file + the IBF/OBF command
//! handshake). On real hardware the exact same readByte/writeByte code drives the
//! physical chip at 0x66/0x62; the software model is engaged ONLY for the duration
//! of selfTest() (it flips `sim_active`, then restores real-port I/O).
//!
//! INCREMENT 1 SCOPE: the EmbeddedControl region handler (byte read/write
//! transactions, multi-byte assembled little-endian) + registry registration +
//! the software-EC loopback proof + MAX_NODES bump (in aml.zig). DEFERRED to a
//! follow-up (all need the GPE/SCI wiring or table parsing): ECDT/_CRS-based port
//! & GPE discovery, _Qxx SCI query dispatch, and burst mode.

const std = @import("std");
const io = @import("../io.zig");
const debug = @import("../debug/debug.zig");
const aml = @import("aml.zig");

// --- EC hardware interface (ACPI 6.x §12.2.1) --------------------------------
// Default ports: the legacy values essentially every x86 EC uses. A later
// increment will override them from the ECDT table or the PNP0C09 device's _CRS.
var cmd_port: u16 = 0x66; // EC_SC: write = command, read = status
var data_port: u16 = 0x62; // EC_DATA: byte in / out

// Status register (read from cmd_port) bits.
const ST_OBF: u8 = 0x01; // Output Buffer Full — a byte is ready for us to read
const ST_IBF: u8 = 0x02; // Input Buffer Full — the EC hasn't consumed our last write
const ST_BURST: u8 = 0x10; // (unused in increment 1 — burst mode deferred)
const ST_SCI: u8 = 0x20; // SCI event pending — a _Qxx query is queued (deferred)

// Commands (written to cmd_port).
const RD_EC: u8 = 0x80;
const WR_EC: u8 = 0x81;
const BE_EC: u8 = 0x82; // burst enable (deferred)
const BD_EC: u8 = 0x83; // burst disable (deferred)
const QR_EC: u8 = 0x84; // query (deferred — needs the GPE path)

// A transaction polls a handshake bit up to this many times, then gives up (→ the
// field access degrades to uninit, NEVER a hang). Generous for a real EC, which
// can take milliseconds; the software model answers on the first poll. Real
// time-based timeouts arrive with the ECDT increment.
const POLL_MAX: u32 = 1_000_000;

/// A handler is registered for the EmbeddedControl space.
pub var present: bool = false;

// --- port backend: real hardware vs. the self-test's software EC --------------
// Normal operation drives the real ports. selfTest() sets `sim_active` so the
// transaction code loops back through the software EC below — proving the
// protocol on a target with no physical EC — then clears it again.
var sim_active: bool = false;

fn scRead() u8 {
    return if (sim_active) simStatus() else io.inb(cmd_port);
}
fn cmdWrite(v: u8) void {
    if (sim_active) simCmd(v) else io.outb(cmd_port, v);
}
fn dataRead() u8 {
    return if (sim_active) simDataRead() else io.inb(data_port);
}
fn dataWrite(v: u8) void {
    if (sim_active) simData(v) else io.outb(data_port, v);
}

/// Spin until `(status & mask) != 0` equals `want_set`, or POLL_MAX expires.
fn waitStatus(mask: u8, want_set: bool) bool {
    var i: u32 = 0;
    while (i < POLL_MAX) : (i += 1) {
        if (((scRead() & mask) != 0) == want_set) return true;
        std.atomic.spinLoopHint();
    }
    return false;
}

/// Read one byte from EC address `addr`. Null on a handshake timeout.
pub fn readByte(addr: u8) ?u8 {
    if (!waitStatus(ST_IBF, false)) return null; // EC ready to accept a command
    cmdWrite(RD_EC);
    if (!waitStatus(ST_IBF, false)) return null; // command consumed
    dataWrite(addr);
    if (!waitStatus(ST_OBF, true)) return null; // result byte ready
    return dataRead();
}

/// Write `val` to EC address `addr`. False on a handshake timeout.
pub fn writeByte(addr: u8, val: u8) bool {
    if (!waitStatus(ST_IBF, false)) return false;
    cmdWrite(WR_EC);
    if (!waitStatus(ST_IBF, false)) return false;
    dataWrite(addr);
    if (!waitStatus(ST_IBF, false)) return false;
    dataWrite(val);
    return waitStatus(ST_IBF, false); // the value byte drained into the EC
}

// --- aml.zig region handler (EmbeddedControl, space 0x03) --------------------
// `off` is the ABSOLUTE EC address (region base + field byte offset). The EC is
// byte-addressed, so an N-byte access-width unit is N consecutive single-byte
// transactions assembled little-endian — the order the AML field engine expects.

fn ecRead(space: u8, off: u64, width: u32) ?u64 {
    _ = space;
    const w: u64 = width;
    if (off >= 0x100 or w == 0 or w > 8 or off + w > 0x100) return null;
    var result: u64 = 0;
    var i: u64 = 0;
    while (i < w) : (i += 1) {
        const b = readByte(@intCast(off + i)) orelse return null;
        result |= @as(u64, b) << @as(u6, @intCast(i * 8));
    }
    return result;
}

fn ecWrite(space: u8, off: u64, width: u32, val: u64) bool {
    _ = space;
    const w: u64 = width;
    if (off >= 0x100 or w == 0 or w > 8 or off + w > 0x100) return false;
    var i: u64 = 0;
    while (i < w) : (i += 1) {
        const b: u8 = @truncate(val >> @as(u6, @intCast(i * 8)));
        if (!writeByte(@intCast(off + i), b)) return false;
    }
    return true;
}

/// Register the EmbeddedControl handler so AML field access reaches the EC. Call
/// BEFORE aml.load() so a real DSDT's EC OperationRegion resolves to us.
pub fn init() void {
    present = aml.registerRegionHandler(aml.SPACE_EC, .{ .read = &ecRead, .write = &ecWrite });
    if (present) {
        debug.klog("[ec] EmbeddedControl handler registered (cmd=0x{X} data=0x{X})\n", .{ cmd_port, data_port });
    } else {
        debug.klog("[ec] WARN: region-handler table full — EC field access degrades to uninit\n", .{});
    }
}

// --- software EC (self-test backend) -----------------------------------------
// A faithful-enough ACPI EC: a 256-byte register file plus the command/handshake
// state machine readByte/writeByte drive. Synchronous — IBF is never left set,
// OBF is raised the instant a result is ready — so the real poll loops converge
// on their first iteration. Engaged only while sim_active (inside selfTest).
var ec_ram: [256]u8 = [_]u8{0} ** 256;
var sim_status: u8 = 0;
var sim_data_out: u8 = 0;
var sim_addr: u8 = 0;
const SimState = enum { idle, rd_addr, wr_addr, wr_data };
var sim_state: SimState = .idle;

fn simStatus() u8 {
    return sim_status;
}
fn simCmd(v: u8) void {
    switch (v) {
        RD_EC => sim_state = .rd_addr,
        WR_EC => sim_state = .wr_addr,
        else => {}, // QR_EC / burst enable/disable: not modeled in increment 1
    }
}
fn simData(v: u8) void {
    switch (sim_state) {
        .rd_addr => {
            sim_data_out = ec_ram[v]; // `v` is the address byte
            sim_status |= ST_OBF;
            sim_state = .idle;
        },
        .wr_addr => {
            sim_addr = v;
            sim_state = .wr_data;
        },
        .wr_data => {
            ec_ram[sim_addr] = v;
            sim_state = .idle;
        },
        .idle => {},
    }
}
fn simDataRead() u8 {
    sim_status &= ~ST_OBF; // reading the data port clears OBF
    return sim_data_out;
}

/// Boot proof: drive the REAL transaction protocol against the software EC and
/// confirm a single-byte round-trip plus a multi-byte little-endian unit through
/// the region handler. Returns the failure count (0 = pass). This is what
/// exercises readByte/writeByte/ecRead/ecWrite end-to-end on a target (QEMU) with
/// no physical EC.
pub fn selfTest() u32 {
    var fails: u32 = 0;
    sim_active = true;
    defer sim_active = false;
    sim_state = .idle;
    sim_status = 0;
    @memset(&ec_ram, 0);

    // (1) single-byte write/read round-trip via readByte/writeByte.
    if (!writeByte(0x05, 0xAB)) fails += 1;
    const rb = readByte(0x05);
    if (rb == null or rb.? != 0xAB) fails += 1;
    if (ec_ram[0x05] != 0xAB) fails += 1; // the write actually reached EC RAM

    // (2) 4-byte little-endian unit via the AML region-handler path.
    if (!ecWrite(aml.SPACE_EC, 0x10, 4, 0xDDCC_BBAA)) fails += 1;
    const rd = ecRead(aml.SPACE_EC, 0x10, 4);
    if (rd == null or rd.? != 0xDDCC_BBAA) fails += 1;
    // byte order in RAM must be LE: 0xAA at the lowest address, 0xDD highest.
    if (ec_ram[0x10] != 0xAA or ec_ram[0x11] != 0xBB or ec_ram[0x12] != 0xCC or ec_ram[0x13] != 0xDD) fails += 1;

    debug.klog("[ec] software-EC self-test: {s} ({d}/6 checks failed)\n", .{ if (fails == 0) "PASS" else "FAIL", fails });
    return fails;
}
