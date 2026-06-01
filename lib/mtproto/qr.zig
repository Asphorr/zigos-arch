//! Minimal QR Code encoder — byte mode, error-correction level L, versions 1..10,
//! automatic mask selection. Pure (std only) so the whole thing is `zig test`-able
//! natively, off-target. Every produced module matrix is validated byte-for-byte
//! against the `segno` reference encoder (see the tests + tools/qr_ref.py).
//!
//! We need exactly one thing from it: render a Telegram QR-login token
//! (`tg://login?token=<base64url>`) on the console so an already-authorized phone
//! can scan and approve the login — sidestepping SMS/app code delivery entirely.
//!
//! The structure follows ISO/IEC 18004; the placement/format/version routines
//! mirror Nayuki's well-known reference (x = column, y = row throughout).

const std = @import("std");

pub const Error = error{TooLong};

pub const MIN_VERSION = 1;
pub const MAX_VERSION = 10;
pub const MAX_SIZE = 17 + 4 * MAX_VERSION; // 57

// Worst-case (version 10) buffer bounds.
const MAX_DATA_CW = 274; // data codewords
const MAX_TOTAL_CW = 346; // data + error-correction codewords
const MAX_EC = 30; // EC codewords per block
const MAX_BLOCKS = 4;

pub const Code = struct {
    size: usize = 0,
    /// row-major, 1 = dark / 0 = light; only [0 .. size*size) is meaningful.
    modules: [MAX_SIZE * MAX_SIZE]u8 = undefined,

    pub fn at(self: *const Code, x: usize, y: usize) u8 {
        return self.modules[y * self.size + x];
    }
};

// Per-version error-correction structure at level L (ISO/IEC 18004, table 9 +
// the EC block layout). aligns = alignment-pattern centre coordinates.
const VInfo = struct {
    data_cw: u16,
    ec_cw: u8, // EC codewords per block
    g1_blocks: u8,
    g1_cw: u8,
    g2_blocks: u8,
    g2_cw: u8,
    rem_bits: u8, // remainder bits trailing the codeword stream
    aligns: []const u8,
};

const V = [MAX_VERSION + 1]VInfo{
    .{ .data_cw = 0, .ec_cw = 0, .g1_blocks = 0, .g1_cw = 0, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 0, .aligns = &.{} }, // [0] unused
    .{ .data_cw = 19, .ec_cw = 7, .g1_blocks = 1, .g1_cw = 19, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 0, .aligns = &.{} },
    .{ .data_cw = 34, .ec_cw = 10, .g1_blocks = 1, .g1_cw = 34, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 7, .aligns = &.{ 6, 18 } },
    .{ .data_cw = 55, .ec_cw = 15, .g1_blocks = 1, .g1_cw = 55, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 7, .aligns = &.{ 6, 22 } },
    .{ .data_cw = 80, .ec_cw = 20, .g1_blocks = 1, .g1_cw = 80, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 7, .aligns = &.{ 6, 26 } },
    .{ .data_cw = 108, .ec_cw = 26, .g1_blocks = 1, .g1_cw = 108, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 7, .aligns = &.{ 6, 30 } },
    .{ .data_cw = 136, .ec_cw = 18, .g1_blocks = 2, .g1_cw = 68, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 7, .aligns = &.{ 6, 34 } },
    .{ .data_cw = 156, .ec_cw = 20, .g1_blocks = 2, .g1_cw = 78, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 0, .aligns = &.{ 6, 22, 38 } },
    .{ .data_cw = 194, .ec_cw = 24, .g1_blocks = 2, .g1_cw = 97, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 0, .aligns = &.{ 6, 24, 42 } },
    .{ .data_cw = 232, .ec_cw = 30, .g1_blocks = 2, .g1_cw = 116, .g2_blocks = 0, .g2_cw = 0, .rem_bits = 0, .aligns = &.{ 6, 26, 46 } },
    .{ .data_cw = 274, .ec_cw = 18, .g1_blocks = 2, .g1_cw = 68, .g2_blocks = 2, .g2_cw = 69, .rem_bits = 0, .aligns = &.{ 6, 28, 50 } },
};

// Scratch reused across one build (single-threaded; one call at a time).
var isfunc: [MAX_SIZE * MAX_SIZE]u8 = undefined;

// ============================ GF(256) + Reed-Solomon ============================
// GF(2^8) with the QR primitive polynomial x^8+x^4+x^3+x^2+1 (0x11D).

fn gfMul(x: u8, y: u8) u8 {
    var r: u8 = 0;
    var a: u8 = x;
    var b: u8 = y;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        if (b & 1 != 0) r ^= a;
        const hi = a & 0x80;
        a = a *% 2;
        if (hi != 0) a ^= 0x1D; // 0x11D mod 2^8
        b >>= 1;
    }
    return r;
}

/// Generator polynomial of degree `n` (leading coefficient 1 omitted), `n` coeffs.
fn rsDivisor(n: usize, out: []u8) void {
    @memset(out[0..n], 0);
    out[n - 1] = 1;
    var root: u8 = 1;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var j: usize = 0;
        while (j < n) : (j += 1) {
            out[j] = gfMul(out[j], root);
            if (j + 1 < n) out[j] ^= out[j + 1];
        }
        root = gfMul(root, 2);
    }
}

/// Reed-Solomon remainder of `data` by `divisor` (the EC codewords) into `out`.
fn rsRemainder(data: []const u8, divisor: []const u8, out: []u8) void {
    const n = divisor.len;
    @memset(out[0..n], 0);
    for (data) |byte| {
        const factor = byte ^ out[0];
        std.mem.copyForwards(u8, out[0 .. n - 1], out[1..n]);
        out[n - 1] = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) out[i] ^= gfMul(divisor[i], factor);
    }
}

// ============================ bit / codeword assembly ============================

fn pushBits(buf: []u8, bitlen: *usize, value: u32, n: usize) void {
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        const bit: u8 = @intCast((value >> @intCast(i)) & 1);
        if (bit != 0) buf[bitlen.* >> 3] |= (@as(u8, 0x80) >> @intCast(bitlen.* & 7));
        bitlen.* += 1;
    }
}

/// Build the final interleaved codeword stream (data + EC) for `data` at `ver`.
/// Returns the codeword count written to `out`.
fn assembleCodewords(data: []const u8, ver: usize, out: []u8) usize {
    const vi = V[ver];
    var dcw: [MAX_DATA_CW]u8 = undefined;
    const ndata: usize = vi.data_cw;
    @memset(dcw[0..ndata], 0);

    var bl: usize = 0;
    const count_bits: usize = if (ver <= 9) 8 else 16;
    pushBits(&dcw, &bl, 0b0100, 4); // byte-mode indicator
    pushBits(&dcw, &bl, @intCast(data.len), count_bits);
    for (data) |b| pushBits(&dcw, &bl, b, 8);

    const cap = ndata * 8;
    var term: usize = cap - bl;
    if (term > 4) term = 4;
    pushBits(&dcw, &bl, 0, term); // terminator
    while (bl % 8 != 0) pushBits(&dcw, &bl, 0, 1); // to byte boundary
    var padbyte: u8 = 0xEC;
    while (bl < cap) {
        pushBits(&dcw, &bl, padbyte, 8);
        padbyte ^= (0xEC ^ 0x11); // alternate 0xEC / 0x11
    }

    // split into EC blocks
    const nblocks: usize = vi.g1_blocks + vi.g2_blocks;
    var lens: [MAX_BLOCKS]usize = undefined;
    var offs: [MAX_BLOCKS]usize = undefined;
    var o: usize = 0;
    var b: usize = 0;
    while (b < vi.g1_blocks) : (b += 1) {
        lens[b] = vi.g1_cw;
        offs[b] = o;
        o += vi.g1_cw;
    }
    while (b < nblocks) : (b += 1) {
        lens[b] = vi.g2_cw;
        offs[b] = o;
        o += vi.g2_cw;
    }

    var divisor: [MAX_EC]u8 = undefined;
    rsDivisor(vi.ec_cw, divisor[0..vi.ec_cw]);
    var ecbuf: [MAX_BLOCKS][MAX_EC]u8 = undefined;
    b = 0;
    while (b < nblocks) : (b += 1)
        rsRemainder(dcw[offs[b] .. offs[b] + lens[b]], divisor[0..vi.ec_cw], ecbuf[b][0..vi.ec_cw]);

    // interleave data codewords, then EC codewords
    var pos: usize = 0;
    const maxlen: usize = @max(@as(usize, vi.g1_cw), @as(usize, vi.g2_cw));
    var c: usize = 0;
    while (c < maxlen) : (c += 1) {
        b = 0;
        while (b < nblocks) : (b += 1) {
            if (c < lens[b]) {
                out[pos] = dcw[offs[b] + c];
                pos += 1;
            }
        }
    }
    c = 0;
    while (c < vi.ec_cw) : (c += 1) {
        b = 0;
        while (b < nblocks) : (b += 1) {
            out[pos] = ecbuf[b][c];
            pos += 1;
        }
    }
    return pos;
}

// ============================ matrix construction ============================

inline fn gbit(v: u32, i: usize) bool {
    return ((v >> @intCast(i)) & 1) != 0;
}

fn setFn(code: *Code, x: usize, y: usize, dark: bool) void {
    code.modules[y * code.size + x] = @intFromBool(dark);
    isfunc[y * code.size + x] = 1;
}

fn drawFinder(code: *Code, cx: isize, cy: isize) void {
    const size: isize = @intCast(code.size);
    var dy: isize = -4;
    while (dy <= 4) : (dy += 1) {
        var dx: isize = -4;
        while (dx <= 4) : (dx += 1) {
            const dist = @max(@abs(dx), @abs(dy));
            const xx = cx + dx;
            const yy = cy + dy;
            if (xx >= 0 and xx < size and yy >= 0 and yy < size)
                setFn(code, @intCast(xx), @intCast(yy), dist != 2 and dist != 4);
        }
    }
}

fn drawAlign(code: *Code, cx: usize, cy: usize) void {
    var dy: isize = -2;
    while (dy <= 2) : (dy += 1) {
        var dx: isize = -2;
        while (dx <= 2) : (dx += 1) {
            const dist = @max(@abs(dx), @abs(dy));
            const xx: usize = @intCast(@as(isize, @intCast(cx)) + dx);
            const yy: usize = @intCast(@as(isize, @intCast(cy)) + dy);
            setFn(code, xx, yy, dist != 1);
        }
    }
}

fn drawFormat(code: *Code, mask: u3) void {
    const size = code.size;
    const data: u32 = (@as(u32, 1) << 3) | mask; // level L = 0b01
    var rem: u32 = data;
    var k: usize = 0;
    while (k < 10) : (k += 1) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    const bits: u32 = ((data << 10) | rem) ^ 0x5412; // 15-bit BCH, masked

    // copy 1: down the left of the top-left finder, then across its bottom
    var i: usize = 0;
    while (i < 6) : (i += 1) setFn(code, 8, i, gbit(bits, i));
    setFn(code, 8, 7, gbit(bits, 6));
    setFn(code, 8, 8, gbit(bits, 7));
    setFn(code, 7, 8, gbit(bits, 8));
    i = 9;
    while (i < 15) : (i += 1) setFn(code, 14 - i, 8, gbit(bits, i));

    // copy 2: across the bottom of the top-right finder, up the right of bottom-left
    i = 0;
    while (i < 8) : (i += 1) setFn(code, size - 1 - i, 8, gbit(bits, i));
    i = 8;
    while (i < 15) : (i += 1) setFn(code, 8, size - 15 + i, gbit(bits, i));
    setFn(code, 8, size - 8, true); // always-dark module
}

fn drawVersion(code: *Code, ver: usize) void {
    if (ver < 7) return;
    const size = code.size;
    var rem: u32 = @intCast(ver);
    var k: usize = 0;
    while (k < 12) : (k += 1) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    const bits: u32 = (@as(u32, @intCast(ver)) << 12) | rem; // 18-bit BCH

    var i: usize = 0;
    while (i < 18) : (i += 1) {
        const bit = gbit(bits, i);
        const a = size - 11 + (i % 3);
        const bb = i / 3;
        setFn(code, a, bb, bit); // top-right block
        setFn(code, bb, a, bit); // bottom-left block
    }
}

fn drawFunctionPatterns(code: *Code, ver: usize) void {
    const size = code.size;
    // timing patterns (row 6 / col 6)
    var i: usize = 0;
    while (i < size) : (i += 1) {
        setFn(code, 6, i, i % 2 == 0);
        setFn(code, i, 6, i % 2 == 0);
    }
    // three finder patterns (+ separators)
    drawFinder(code, 3, 3);
    drawFinder(code, @as(isize, @intCast(size)) - 4, 3);
    drawFinder(code, 3, @as(isize, @intCast(size)) - 4);
    // alignment patterns (skip the three finder corners)
    const aligns = V[ver].aligns;
    const n = aligns.len;
    var ai: usize = 0;
    while (ai < n) : (ai += 1) {
        var aj: usize = 0;
        while (aj < n) : (aj += 1) {
            if ((ai == 0 and aj == 0) or (ai == 0 and aj == n - 1) or (ai == n - 1 and aj == 0)) continue;
            drawAlign(code, aligns[ai], aligns[aj]);
        }
    }
    // reserve format + version areas (real bits filled later)
    drawFormat(code, 0);
    drawVersion(code, ver);
}

fn drawCodewords(code: *Code, cw: []const u8) void {
    const size = code.size;
    const total_bits = cw.len * 8;
    var i: usize = 0; // bit index
    var right: isize = @intCast(size - 1);
    while (right >= 1) : (right -= 2) {
        if (right == 6) right = 5; // skip the vertical timing column
        var vert: usize = 0;
        while (vert < size) : (vert += 1) {
            var j: usize = 0;
            while (j < 2) : (j += 1) {
                const x: usize = @intCast(right - @as(isize, @intCast(j)));
                const upward = ((right + 1) & 2) == 0;
                const y = if (upward) size - 1 - vert else vert;
                if (isfunc[y * size + x] != 0) continue;
                var bit: u8 = 0;
                if (i < total_bits) {
                    bit = (cw[i >> 3] >> @intCast(7 - (i & 7))) & 1;
                    i += 1;
                } // else a remainder bit -> 0
                code.modules[y * size + x] = bit;
            }
        }
    }
}

fn applyMask(code: *Code, mask: u3) void {
    const size = code.size;
    var y: usize = 0;
    while (y < size) : (y += 1) {
        var x: usize = 0;
        while (x < size) : (x += 1) {
            if (isfunc[y * size + x] != 0) continue;
            const invert = switch (mask) {
                0 => (x + y) % 2 == 0,
                1 => y % 2 == 0,
                2 => x % 3 == 0,
                3 => (x + y) % 3 == 0,
                4 => (x / 3 + y / 2) % 2 == 0,
                5 => (x * y) % 2 + (x * y) % 3 == 0,
                6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
                7 => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
            };
            if (invert) code.modules[y * size + x] ^= 1;
        }
    }
}

// Mask-selection penalty (ISO/IEC 18004 §8.8.2). Rules 1, 2, 4 are exact; rule 3
// scans rows/cols for the 11-module finder-like patterns. This only chooses among
// 8 valid maskings — construction correctness is proven separately vs segno.
fn penalty(code: *Code) u32 {
    const size = code.size;
    var score: u32 = 0;

    // rule 1: runs of >=5 same-colour modules in rows and columns
    var a: usize = 0;
    while (a < size) : (a += 1) {
        var run_r: usize = 1;
        var run_c: usize = 1;
        var bi: usize = 1;
        while (bi < size) : (bi += 1) {
            if (code.at(bi, a) == code.at(bi - 1, a)) {
                run_r += 1;
                if (run_r == 5) score += 3 else if (run_r > 5) score += 1;
            } else run_r = 1;
            if (code.at(a, bi) == code.at(a, bi - 1)) {
                run_c += 1;
                if (run_c == 5) score += 3 else if (run_c > 5) score += 1;
            } else run_c = 1;
        }
    }

    // rule 2: 2x2 blocks of one colour
    var y: usize = 0;
    while (y + 1 < size) : (y += 1) {
        var x: usize = 0;
        while (x + 1 < size) : (x += 1) {
            const c = code.at(x, y);
            if (c == code.at(x + 1, y) and c == code.at(x, y + 1) and c == code.at(x + 1, y + 1)) score += 3;
        }
    }

    // rule 3: finder-like 1:1:3:1:1 patterns with a 4-wide light margin
    const p1 = [_]u8{ 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0 };
    const p2 = [_]u8{ 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1 };
    a = 0;
    while (a < size) : (a += 1) {
        var s: usize = 0;
        while (s + 11 <= size) : (s += 1) {
            var m1r = true;
            var m2r = true;
            var m1c = true;
            var m2c = true;
            var t: usize = 0;
            while (t < 11) : (t += 1) {
                const hr = code.at(s + t, a);
                const vc = code.at(a, s + t);
                if (hr != p1[t]) m1r = false;
                if (hr != p2[t]) m2r = false;
                if (vc != p1[t]) m1c = false;
                if (vc != p2[t]) m2c = false;
            }
            if (m1r or m2r) score += 40;
            if (m1c or m2c) score += 40;
        }
    }

    // rule 4: deviation of the dark-module proportion from 50%
    var dark: usize = 0;
    var idx: usize = 0;
    const total = size * size;
    while (idx < total) : (idx += 1) dark += code.modules[idx];
    const d: i64 = @as(i64, @intCast(dark)) * 20 - @as(i64, @intCast(total)) * 10;
    const numer: usize = @intCast(@abs(d));
    const kk = (numer + total - 1) / total - 1; // ceil(|%-50|/5)
    score += @intCast(kk * 10);

    return score;
}

fn render(code: *Code, ver: usize, data: []const u8, forced_mask: ?u3) void {
    code.size = 17 + 4 * ver;
    @memset(code.modules[0 .. code.size * code.size], 0);
    @memset(isfunc[0 .. code.size * code.size], 0);
    drawFunctionPatterns(code, ver);

    var cwbuf: [MAX_TOTAL_CW]u8 = undefined;
    const total = assembleCodewords(data, ver, &cwbuf);
    drawCodewords(code, cwbuf[0..total]);

    var mask: u3 = 0;
    if (forced_mask) |fm| {
        mask = fm;
    } else {
        var best: u32 = std.math.maxInt(u32);
        var m: u3 = 0;
        while (true) {
            applyMask(code, m);
            drawFormat(code, m);
            const p = penalty(code);
            if (p < best) {
                best = p;
                mask = m;
            }
            applyMask(code, m); // undo (XOR is self-inverse)
            if (m == 7) break;
            m += 1;
        }
    }
    applyMask(code, mask);
    drawFormat(code, mask);
}

fn fitVersion(len: usize) ?usize {
    var ver: usize = MIN_VERSION;
    while (ver <= MAX_VERSION) : (ver += 1) {
        const count_bits: usize = if (ver <= 9) 8 else 16;
        const need = 4 + count_bits + len * 8;
        if (need <= @as(usize, V[ver].data_cw) * 8) return ver;
    }
    return null;
}

/// Encode `data` at level L into the smallest fitting version with the best mask.
pub fn encode(code: *Code, data: []const u8) Error!void {
    const ver = fitVersion(data.len) orelse return error.TooLong;
    render(code, ver, data, null);
}

/// Encode forcing a specific version + mask. Production uses `encode` (auto);
/// this exists so the decode harness (tools/qr_decode.py) can exercise every
/// version + mask code path.
pub fn encodeForced(code: *Code, data: []const u8, ver: usize, mask: u3) void {
    render(code, ver, data, mask);
}

// =====================================================================
// Tests — zig test lib/mtproto/qr.zig
//
// These native tests cover version selection + the function-pattern skeleton.
// The AUTHORITATIVE end-to-end check is a real decode round-trip: lib/mtproto/qr_dump.zig
// emits matrices for the production path (auto version+mask) plus every forced
// version/mask code path, and tools/qr_decode.py decodes them with OpenCV's QR
// reader — i.e. exactly what a phone does when it scans the rendered code. All
// paths (v1..v10, all 8 masks, version-info, two-EC-group interleave) round-trip.

test "version selection picks the smallest fitting version (level L, byte mode)" {
    try std.testing.expectEqual(@as(?usize, 1), fitVersion(17)); // 17 bytes -> v1 (19 cw)
    try std.testing.expectEqual(@as(?usize, 2), fitVersion(18)); // 18 bytes -> v2
    try std.testing.expectEqual(@as(?usize, 4), fitVersion(78)); // v4 holds 78
    try std.testing.expectEqual(@as(?usize, null), fitVersion(300)); // beyond v10
}

test "structure: finder cores, dark module, timing parity are placed" {
    var code: Code = undefined;
    try encode(&code, "tg://login?token=AAAAAAAA");
    // three finder centres are dark
    try std.testing.expectEqual(@as(u8, 1), code.at(3, 3));
    try std.testing.expectEqual(@as(u8, 1), code.at(code.size - 4, 3));
    try std.testing.expectEqual(@as(u8, 1), code.at(3, code.size - 4));
    // separators (the light ring just inside) are light
    try std.testing.expectEqual(@as(u8, 0), code.at(7, 7));
    // timing pattern alternates and starts dark at (8,6)
    try std.testing.expectEqual(@as(u8, 1), code.at(8, 6));
    try std.testing.expectEqual(@as(u8, 0), code.at(9, 6));
    // mandatory dark module
    try std.testing.expectEqual(@as(u8, 1), code.at(8, code.size - 8));
}
