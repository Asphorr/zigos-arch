// Crash-consistent append-only log on the NVDIMM (N4).
//
// A persistent write-ahead-style log living in the byte-addressable pmem region.
// It is the capstone of the NVDIMM arc: it turns "the region survives reboots"
// (N2) and "we can read/write/DAX it" (N3) into a real persistent data
// structure with the one property that makes persistent memory hard — crash
// consistency: a power loss in the middle of an append must never leave a
// half-written record visible to the next boot.
//
// On-pmem layout (byte offsets into the region; clear of the N2 boot-counter
// header at 0 and the pmemdax test window at 4096):
//
//   LOG_BASE ───► Header { magic:u64, capacity:u64 }              (16 bytes)
//   entries  ───► Entry  { seq:u64, len:u32, payload[len], crc:u32 }
//                 (each padded up to an 8-byte boundary for the next entry)
//
// The crc is the COMMIT MARKER and is computed over [seq ++ len ++ payload]. The
// append protocol writes — and durably persists — the body FIRST, then the crc
// SECOND, each via pmem.writeAt (which flushes the touched lines + SFENCEs). The
// SFENCE after the body orders it strictly before the crc reaches the
// persistence domain, so:
//   * crash before the crc is persisted → recovery recomputes the crc over the
//     body, finds it != the stored (stale/zero) crc, and DISCARDS the entry and
//     everything after it. The half-written body is invisible.
//   * crash after the crc is persisted → the entry is fully committed.
//
// Recovery scans entries from the front, validating each crc and that seq is the
// expected next value; the first entry that fails (or whose header is out of
// bounds) marks the end of the committed log. There is no mutable head pointer
// in the header — the committed tail is *derived* by scanning, so the header
// itself is never a crash-consistency hazard.
//
// Boot demo (logBoot, called once from pmem.init after the N2 self-test): each
// boot recovers the log, appends one boot record (carrying the N2 boot counter),
// and — to keep proving crash consistency on every single boot — injects a
// deliberately torn tail (a body with no valid commit marker) that the NEXT
// boot's recovery must detect and discard. So the committed-record count climbs
// by one per boot while the simulated mid-append crash is skipped every time.

const pmem = @import("pmem.zig");
const debug = @import("../debug/debug.zig");

const LOG_BASE: u64 = 64 * 1024; // 0x10000 — past the N2 header + pmemdax window
const LOG_MAGIC: u64 = 0x3130474F4C4D505A; // bytes "ZPMLOG01" in memory order
const MAX_PAYLOAD: u32 = 256; // recovery bounds-guard: a larger len is treated as torn
const HEADER_BYTES: u64 = 16; // magic(8) + capacity(8)

// Deliberately simulate a crash mid-append on every boot so recovery's
// torn-write handling is exercised continuously. Set false for a plain durable
// log with no synthetic torn tail.
const INJECT_TORN_TAIL = true;

// Derived committed tail + next sequence, (re)established by recover().
var tail_off: u64 = 0;
var next_seq: u64 = 0;
var committed: u64 = 0;

/// Number of committed records recovered/known after the last logBoot().
pub fn count() u64 {
    return committed;
}

// --- CRC-32 (ISO-HDLC / zlib, reflected poly 0xEDB88320) -------------------
// Table-free Sarwate, exposed as a rolling start/feed/end so a record's crc can
// be computed over its header slice and payload slice without copying them into
// one contiguous buffer. Fine for the small records we checksum.

fn crc32Start() u32 {
    return 0xFFFFFFFF;
}

fn crc32Feed(crc_in: u32, bytes: []const u8) u32 {
    var crc = crc_in;
    for (bytes) |b| {
        crc ^= b;
        var k: u8 = 0;
        while (k < 8) : (k += 1) {
            const mask: u32 = @bitCast(-@as(i32, @intCast(crc & 1)));
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return crc;
}

fn crc32End(crc: u32) u32 {
    return ~crc;
}

// --- little-endian scalar helpers over the pmem byte interface -------------

fn put32(off: u64, v: u32) void {
    var b: [4]u8 = .{
        @truncate(v), @truncate(v >> 8), @truncate(v >> 16), @truncate(v >> 24),
    };
    _ = pmem.writeAt(off, &b); // durable: writeAt flushes + SFENCEs
}

fn put64(off: u64, v: u64) void {
    var b: [8]u8 = undefined;
    var i: u6 = 0;
    while (i < 8) : (i += 1) b[i] = @truncate(v >> (@as(u6, i) * 8));
    _ = pmem.writeAt(off, &b);
}

fn get32(off: u64) u32 {
    var b: [4]u8 = undefined;
    if (pmem.readAt(off, &b) != 4) return 0;
    return @as(u32, b[0]) | (@as(u32, b[1]) << 8) | (@as(u32, b[2]) << 16) | (@as(u32, b[3]) << 24);
}

fn get64(off: u64) u64 {
    var b: [8]u8 = undefined;
    if (pmem.readAt(off, &b) != 8) return 0;
    var v: u64 = 0;
    var i: u6 = 0;
    while (i < 8) : (i += 1) v |= @as(u64, b[i]) << (@as(u6, i) * 8);
    return v;
}

fn align8(x: u64) u64 {
    return (x + 7) & ~@as(u64, 7);
}

const ENTRIES_BASE: u64 = LOG_BASE + HEADER_BYTES;

/// Total on-pmem span of an entry with `len`-byte payload, padded to 8 bytes:
/// seq(8) + len(4) + payload + crc(4).
fn entrySpan(len: u32) u64 {
    return align8(12 + @as(u64, len) + 4);
}

// --- append (the crash-consistent write) -----------------------------------

/// Append `payload` as a committed record. Body is written + persisted first,
/// then the crc commit marker — so a crash between the two leaves an entry that
/// recovery discards. Returns false if the log is full. Caller must have run
/// recover() so tail_off/next_seq are valid.
fn append(payload: []const u8) bool {
    const len: u32 = @intCast(payload.len);
    if (len > MAX_PAYLOAD) return false;
    const off = tail_off;
    if (off + entrySpan(len) > pmem.size()) return false; // out of room

    // 1. Body: seq, len, payload — each writeAt is durable, so on return the
    //    full body has reached the persistence domain (crc not yet written).
    put64(off, next_seq);
    put32(off + 8, len);
    if (len != 0) _ = pmem.writeAt(off + 12, payload);

    // 2. Commit marker: crc over seq ++ len ++ payload, written + persisted
    //    LAST. The SFENCE inside the body writeAts orders the body strictly
    //    before this marker becomes durable.
    var hdr: [12]u8 = undefined;
    var i: u6 = 0;
    while (i < 8) : (i += 1) hdr[i] = @truncate(next_seq >> (@as(u6, i) * 8));
    hdr[8] = @truncate(len);
    hdr[9] = @truncate(len >> 8);
    hdr[10] = @truncate(len >> 16);
    hdr[11] = @truncate(len >> 24);
    var crc = crc32Start();
    crc = crc32Feed(crc, &hdr);
    crc = crc32Feed(crc, payload);
    put32(off + 12 + len, crc32End(crc));

    tail_off = off + entrySpan(len);
    next_seq += 1;
    committed += 1;
    return true;
}

/// Recompute and verify the crc of the entry at `off` whose payload length is
/// `len`. Reads the body back out of pmem (so it validates what actually
/// persisted, not what we think we wrote).
fn entryValid(off: u64, len: u32) bool {
    var buf: [12 + MAX_PAYLOAD]u8 = undefined;
    const body_len: usize = 12 + @as(usize, len);
    if (pmem.readAt(off, buf[0..body_len]) != body_len) return false;
    var crc = crc32Start();
    crc = crc32Feed(crc, buf[0..body_len]);
    const want = crc32End(crc);
    return get32(off + 12 + len) == want;
}

// --- recover (derive the committed tail by scanning) -----------------------

const Recovery = struct { recovered: u64, torn: bool };

/// Walk the committed log from the front. Stops at the first entry that is out
/// of bounds, has an implausible length, fails its crc, or is out of sequence —
/// that boundary is the committed tail. `torn` is true when the stop was caused
/// by a plausible-looking entry whose crc didn't validate (i.e. a half-written
/// append from a crash / our injected tail), as opposed to a clean end.
fn recover() Recovery {
    // Fresh region (or different/no log): (re)initialize the header.
    if (get64(LOG_BASE) != LOG_MAGIC) {
        put64(LOG_BASE, LOG_MAGIC);
        put64(LOG_BASE + 8, pmem.size() - LOG_BASE);
        tail_off = ENTRIES_BASE;
        next_seq = 0;
        committed = 0;
        return .{ .recovered = 0, .torn = false };
    }

    var off = ENTRIES_BASE;
    var seq_expected: u64 = 0;
    var torn = false;
    while (off + 16 <= pmem.size()) {
        const seq = get64(off);
        const len = get32(off + 8);
        if (len == 0 or len > MAX_PAYLOAD) break; // clean end (zeroed space) or garbage
        if (off + entrySpan(len) > pmem.size()) break; // header runs past the region
        if (!entryValid(off, len)) {
            torn = true; // plausible entry, bad crc → a torn append
            break;
        }
        if (seq != seq_expected) {
            torn = true; // valid crc but wrong order → corrupt chain
            break;
        }
        seq_expected += 1;
        off += entrySpan(len);
    }
    tail_off = off;
    next_seq = seq_expected;
    committed = seq_expected;
    return .{ .recovered = seq_expected, .torn = torn };
}

/// Write a torn tail: a durable body with NO valid commit marker, simulating a
/// crash partway through the next append. Does NOT advance tail_off/next_seq —
/// the entry is uncommitted, so the next good append overwrites it. The next
/// boot's recover() must detect and discard it.
fn injectTornTail() void {
    const marker = "TORN-WRITE-CRASH-SIM";
    const len: u32 = marker.len;
    const off = tail_off;
    if (off + entrySpan(len) > pmem.size()) return;
    put64(off, next_seq); // a plausible seq, so recovery treats it as a real entry...
    put32(off + 8, len);
    _ = pmem.writeAt(off + 12, marker);
    put32(off + 12 + len, 0); // ...but the commit crc is invalid (0) → torn
}

// --- boot demo --------------------------------------------------------------

/// Recover the log, report it, append this boot's record, and (for the demo)
/// leave a torn tail for the next boot to discard. Called once at boot from the
/// boot sequence (main.zig), right after pmem.init (kept out of pmem.init itself
/// so pmem.zig doesn't import its own consumer). No-op without an NVDIMM.
pub fn logBoot() void {
    if (!pmem.isPresent() or pmem.size() < ENTRIES_BASE + 64) return;

    const r = recover();
    if (r.recovered == 0 and !r.torn) {
        debug.klog("[pmem] log: fresh region — initialized crash-consistent log @ +0x{x}\n", .{LOG_BASE});
    } else if (r.torn) {
        debug.klog("[pmem] log: recovered {d} committed record(s) (seq 0..{d}); discarded a torn tail at seq={d} (crc mismatch) — crash-consistent\n", .{
            r.recovered, r.recovered -| 1, next_seq,
        });
    } else {
        debug.klog("[pmem] log: recovered {d} committed record(s) (seq 0..{d}); clean tail\n", .{
            r.recovered, r.recovered -| 1,
        });
    }

    // Append this boot's record: the N2 boot counter as an 8-byte payload.
    const bc = pmem.bootCount();
    var rec: [8]u8 = undefined;
    var i: u6 = 0;
    while (i < 8) : (i += 1) rec[i] = @truncate(bc >> (@as(u6, i) * 8));
    if (append(&rec)) {
        debug.klog("[pmem] log: appended record seq={d} (boot #{d}); {d} committed total\n", .{ next_seq - 1, bc, committed });
    } else {
        debug.klog("[pmem] log: FULL — could not append (cap reached)\n", .{});
    }

    if (INJECT_TORN_TAIL) {
        injectTornTail();
        debug.klog("[pmem] log: injected a torn tail (simulated mid-append crash) for next-boot recovery to discard\n", .{});
    }
}
