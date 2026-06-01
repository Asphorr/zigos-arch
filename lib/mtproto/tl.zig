// MTProto TL (Type Language) serialization primitives.
//
// Bare wire encoding only — int/long/int128/int256/bytes/string/vector —
// over a caller-provided fixed buffer (no allocator, so this whole file
// is pure and `zig test`-able natively, off-target).
//
// TL rules that bite:
//   - everything little-endian
//   - `bytes`/`string`: a length prefix then the data then zero-padding
//     so the TOTAL (prefix+data+pad) is a multiple of 4. Prefix is 1 byte
//     if len<=253, else a 0xFE marker + 3-byte LE length.
//   - `vector`: constructor 0x1cb5c415, then an int count, then elements.
//
// Constructor numbers (the 4-byte CRC-ish ids) are not computed here;
// callers write them with writeU32 / match them with readU32.

const std = @import("std");

pub const VECTOR_CTOR: u32 = 0x1cb5c415;

pub const WriteError = error{Overflow};
pub const ReadError = error{ Truncated, Malformed };

pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }

    fn ensure(self: *Writer, n: usize) WriteError!void {
        if (self.pos + n > self.buf.len) return error.Overflow;
    }

    pub fn writeRaw(self: *Writer, data: []const u8) WriteError!void {
        try self.ensure(data.len);
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    pub fn writeU32(self: *Writer, v: u32) WriteError!void {
        try self.ensure(4);
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], v, .little);
        self.pos += 4;
    }

    pub fn writeInt(self: *Writer, v: i32) WriteError!void {
        try self.ensure(4);
        std.mem.writeInt(i32, self.buf[self.pos..][0..4], v, .little);
        self.pos += 4;
    }

    pub fn writeLong(self: *Writer, v: u64) WriteError!void {
        try self.ensure(8);
        std.mem.writeInt(u64, self.buf[self.pos..][0..8], v, .little);
        self.pos += 8;
    }

    /// int128 / int256 are just raw byte runs (used for nonces).
    pub fn writeInt128(self: *Writer, v: [16]u8) WriteError!void {
        try self.writeRaw(&v);
    }
    pub fn writeInt256(self: *Writer, v: [32]u8) WriteError!void {
        try self.writeRaw(&v);
    }

    /// TL `bytes` / `string`: length-prefixed, zero-padded to 4.
    pub fn writeBytes(self: *Writer, data: []const u8) WriteError!void {
        if (data.len <= 253) {
            try self.ensure(1);
            self.buf[self.pos] = @intCast(data.len);
            self.pos += 1;
        } else {
            if (data.len > 0xFF_FFFF) return error.Overflow;
            try self.ensure(4);
            self.buf[self.pos] = 0xFE;
            self.buf[self.pos + 1] = @intCast(data.len & 0xFF);
            self.buf[self.pos + 2] = @intCast((data.len >> 8) & 0xFF);
            self.buf[self.pos + 3] = @intCast((data.len >> 16) & 0xFF);
            self.pos += 4;
        }
        try self.writeRaw(data);
        while (self.pos % 4 != 0) {
            try self.ensure(1);
            self.buf[self.pos] = 0;
            self.pos += 1;
        }
    }
};

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }

    fn need(self: *Reader, n: usize) ReadError!void {
        if (self.pos + n > self.buf.len) return error.Truncated;
    }

    pub fn readU32(self: *Reader) ReadError!u32 {
        try self.need(4);
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .little);
        self.pos += 4;
        return v;
    }

    pub fn readInt(self: *Reader) ReadError!i32 {
        try self.need(4);
        const v = std.mem.readInt(i32, self.buf[self.pos..][0..4], .little);
        self.pos += 4;
        return v;
    }

    pub fn readLong(self: *Reader) ReadError!u64 {
        try self.need(8);
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .little);
        self.pos += 8;
        return v;
    }

    /// Borrow `n` raw bytes (slice into the source buffer; no copy).
    pub fn readRaw(self: *Reader, n: usize) ReadError![]const u8 {
        try self.need(n);
        const s = self.buf[self.pos..][0..n];
        self.pos += n;
        return s;
    }

    pub fn readInt128(self: *Reader) ReadError![16]u8 {
        const s = try self.readRaw(16);
        return s[0..16].*;
    }
    pub fn readInt256(self: *Reader) ReadError![32]u8 {
        const s = try self.readRaw(32);
        return s[0..32].*;
    }

    /// TL `bytes` / `string`: returns a slice into the source buffer and
    /// advances past the data AND its 4-byte padding.
    pub fn readBytes(self: *Reader) ReadError![]const u8 {
        try self.need(1);
        const first = self.buf[self.pos];
        var dlen: usize = undefined;
        var header: usize = undefined;
        if (first < 0xFE) {
            dlen = first;
            header = 1;
        } else if (first == 0xFE) {
            try self.need(4);
            dlen = @as(usize, self.buf[self.pos + 1]) |
                (@as(usize, self.buf[self.pos + 2]) << 8) |
                (@as(usize, self.buf[self.pos + 3]) << 16);
            header = 4;
        } else {
            // 0xFF is reserved / not used for plain bytes.
            return error.Malformed;
        }
        const total = header + dlen;
        const pad = (4 - (total % 4)) % 4;
        try self.need(total + pad);
        const data = self.buf[self.pos + header ..][0..dlen];
        self.pos += total + pad;
        return data;
    }
};

// =====================================================================
// Tests — pure, run with: zig test lib/mtproto/tl.zig

test "bytes roundtrip + 4-byte alignment across the length-prefix boundary" {
    const lens = [_]usize{ 0, 1, 2, 3, 4, 5, 7, 8, 253, 254, 255, 256, 1000 };
    var buf: [2048]u8 = undefined;
    var data: [1000]u8 = undefined;
    for (0..data.len) |i| data[i] = @intCast(i & 0xFF);
    for (lens) |L| {
        var w = Writer.init(&buf);
        try w.writeBytes(data[0..L]);
        try std.testing.expect(w.pos % 4 == 0); // always padded to 4
        var r = Reader.init(w.written());
        const got = try r.readBytes();
        try std.testing.expectEqualSlices(u8, data[0..L], got);
        try std.testing.expectEqual(@as(usize, 0), r.remaining()); // padding consumed
    }
}

test "scalar little-endian encoding + roundtrip" {
    var buf: [32]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeU32(0xbe7e8ef1); // req_pq_multi constructor
    try w.writeLong(0x1122334455667788);
    try w.writeInt(-2);
    // bytes on the wire are little-endian
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xf1, 0x8e, 0x7e, 0xbe }, buf[0..4]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 }, buf[4..12]);

    var r = Reader.init(w.written());
    try std.testing.expectEqual(@as(u32, 0xbe7e8ef1), try r.readU32());
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), try r.readLong());
    try std.testing.expectEqual(@as(i32, -2), try r.readInt());
}

test "int128 / int256 nonce passthrough" {
    var nonce: [16]u8 = undefined;
    for (0..16) |i| nonce[i] = @intCast(0xA0 + i);
    var newn: [32]u8 = undefined;
    for (0..32) |i| newn[i] = @intCast(i * 5 + 1);

    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeInt128(nonce);
    try w.writeInt256(newn);

    var r = Reader.init(w.written());
    try std.testing.expectEqual(nonce, try r.readInt128());
    try std.testing.expectEqual(newn, try r.readInt256());
}

test "vector<long> shape" {
    var buf: [64]u8 = undefined;
    var w = Writer.init(&buf);
    try w.writeU32(VECTOR_CTOR);
    try w.writeInt(2);
    try w.writeLong(0xAAAA_0000_0000_AAAA);
    try w.writeLong(0xBBBB_0000_0000_BBBB);

    var r = Reader.init(w.written());
    try std.testing.expectEqual(VECTOR_CTOR, try r.readU32());
    try std.testing.expectEqual(@as(i32, 2), try r.readInt());
    try std.testing.expectEqual(@as(u64, 0xAAAA_0000_0000_AAAA), try r.readLong());
    try std.testing.expectEqual(@as(u64, 0xBBBB_0000_0000_BBBB), try r.readLong());
}

test "truncated input is rejected, not UB" {
    var r = Reader.init(&[_]u8{ 0x01, 0x02 });
    try std.testing.expectError(error.Truncated, r.readU32());
}
