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

// --- _Qxx query dispatch (ACPI 6.x §12.3, QR_EC) -----------------------------
// When the EC has an event (lid, hotkey, AC, battery, thermal) it sets SCI_EVT
// and asserts its GPE; the OS answers by issuing QR_EC to read a one-byte query
// code Q, then runs the EC device's `_Q<XX>` method. discover() locates the EC
// device in the namespace so those handlers can be addressed by path. (The GPE
// that TRIGGERS this is wired in the next increment; here processQueries() is
// driven by the boot self-test against the software model.)

var ec_path_buf: [96]u8 = undefined; // the EC device's namespace path (e.g. "\_SB_.EC0_")
var ec_path_len: usize = 0;

/// After aml.load(): locate the EC device (a real one wins; the synthetic q35
/// stand-in otherwise) so its _Qxx handlers can be run by path.
pub fn discover() void {
    ec_path_len = 0;
    const p = aml.findDevicePathByHid("PNP0C09") orelse {
        debug.klog("[ec] no PNP0C09 device in namespace — query dispatch idle\n", .{});
        return;
    };
    if (p.len > ec_path_buf.len) return;
    @memcpy(ec_path_buf[0..p.len], p);
    ec_path_len = p.len;
    debug.klog("[ec] EC device: {s} — _Qxx query dispatch armed\n", .{ec_path_buf[0..ec_path_len]});
}

/// Issue QR_EC and return the pending query byte (0 = no event), null on timeout.
pub fn queryByte() ?u8 {
    if (!waitStatus(ST_IBF, false)) return null;
    cmdWrite(QR_EC);
    if (!waitStatus(ST_OBF, true)) return null;
    return dataRead();
}

fn hexU(nib: u8) u8 {
    return "0123456789ABCDEF"[nib & 0x0F];
}

/// Run "<ec_path>._Q<XX>" (XX = uppercase hex of q). A missing handler is a clean
/// no-op (evalMethod returns null). evalMethod serializes on the interpreter lock.
fn runQuery(q: u8) void {
    if (ec_path_len == 0) return;
    var buf: [104]u8 = undefined;
    if (ec_path_len + 5 > buf.len) return;
    @memcpy(buf[0..ec_path_len], ec_path_buf[0..ec_path_len]);
    var n = ec_path_len;
    buf[n] = '.';
    buf[n + 1] = '_';
    buf[n + 2] = 'Q';
    buf[n + 3] = hexU(q >> 4);
    buf[n + 4] = hexU(q & 0x0F);
    n += 5;
    _ = aml.evalMethod(buf[0..n]);
}

/// Drain pending EC SCI queries: while SCI_EVT is set, QR_EC → run `_Q<XX>`.
/// Bounded so a wedged EC can't spin the caller. MUST be called under the AML
/// interpreter lock in production (it shares the EC ports with AML field access);
/// the GPE-trigger wiring that will call this holds it, and the boot self-test is
/// single-threaded.
pub fn processQueries() void {
    if (ec_path_len == 0) return;
    var guard: u32 = 0;
    while (guard < 64) : (guard += 1) { // ACPI allows ≤255 query slots; ample per SCI
        if ((scRead() & ST_SCI) == 0) break; // no events pending
        const q = queryByte() orelse break;
        if (q == 0) break; // spurious / no event
        runQuery(q);
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
var sim_query: u8 = 0; // a pending SCI query code (0 = none), returned by QR_EC
const SimState = enum { idle, rd_addr, wr_addr, wr_data };
var sim_state: SimState = .idle;

fn simStatus() u8 {
    return sim_status;
}
fn simCmd(v: u8) void {
    switch (v) {
        RD_EC => sim_state = .rd_addr,
        WR_EC => sim_state = .wr_addr,
        QR_EC => {
            sim_data_out = sim_query; // hand back the queued query code
            sim_status |= ST_OBF; // ...ready to read
            sim_status &= ~ST_SCI; // the event is consumed
            sim_query = 0; // one-shot
            sim_state = .idle;
        },
        else => {}, // burst enable/disable: not modeled
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

/// Queue one SCI query event (raise SCI_EVT) — the self-test's stand-in for an EC
/// asserting its GPE with a pending _Qxx.
fn simRaiseQuery(q: u8) void {
    sim_query = q;
    sim_status |= ST_SCI;
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
    sim_query = 0;
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

    // (3) _Qxx query dispatch (only if an EC device was discovered): raise a
    //     simulated SCI query 0x01 and confirm the EC's _Q01 handler actually ran
    //     — it stores 0x99 into \ECQF, which \QCHK reads back — and that the event
    //     was consumed (SCI_EVT cleared). Exercises queryByte→runQuery→evalMethod.
    if (ec_path_len > 0) {
        simRaiseQuery(0x01);
        processQueries();
        var got: u64 = 0xDEAD;
        if (aml.evalMethod("\\QCHK")) |v| {
            if (v == .integer) got = v.integer;
        }
        if (got != 0x99) fails += 1;
        if ((scRead() & ST_SCI) != 0) fails += 1; // the query must have been consumed
    }

    debug.klog("[ec] software-EC self-test: {s} ({d} checks failed)\n", .{ if (fails == 0) "PASS" else "FAIL", fails });
    return fails;
}
