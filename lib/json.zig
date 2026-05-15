// Minimal JSON parser. Recursive-descent over RFC 8259. Builds a
// tagged-value tree using libc.malloc; the caller frees with
// `Value.deinit()` when done.
//
// Why malloc rather than a caller bump-arena: JSON objects and arrays
// grow as we parse, and nested values can interleave with their parent's
// items in any bump layout. malloc + realloc keeps the allocator
// orthogonal to the parser logic. The userspace heap is fast enough for
// JSON-sized blobs — we're not parsing gigabyte CSVs.
//
// Usage:
//   var v = try json.parse(text);
//   defer v.deinit();
//   const name = v.get("user").?.get("name").?.asString().?;
//   const age  = v.get("user").?.get("age").?.asInt().?;
//
// String unescape handles \", \\, \/, \b, \f, \n, \r, \t, and \uXXXX
// (with surrogate-pair recombination). Numbers are parsed as i64 when
// they fit and have no fractional or exponent part; otherwise f64.

const std = @import("std");
const libc = @import("libc");

pub const Error = error{
    OutOfMemory,
    UnexpectedEof,
    InvalidToken,
    InvalidEscape,
    InvalidNumber,
    DepthExceeded,
    TrailingGarbage,
};

pub const MAX_DEPTH: u32 = 64;

pub const Field = struct {
    name: []u8,
    value: Value,
};

pub const Value = union(enum) {
    null_: void,
    bool_: bool,
    int: i64,
    number: f64,
    string: []u8,
    array: []Value,
    object: []Field,

    pub fn deinit(self: *Value) void {
        switch (self.*) {
            .null_, .bool_, .int, .number => {},
            .string => |s| freeBytes(s),
            .array => |items| {
                for (items) |*it| it.deinit();
                freeSlice(Value, items);
            },
            .object => |fields| {
                for (fields) |*f| {
                    freeBytes(f.name);
                    f.value.deinit();
                }
                freeSlice(Field, fields);
            },
        }
        self.* = .{ .null_ = {} };
    }

    /// Object lookup. Returns null on non-object or missing key.
    pub fn get(self: Value, key: []const u8) ?Value {
        if (self != .object) return null;
        for (self.object) |f| {
            if (std.mem.eql(u8, f.name, key)) return f.value;
        }
        return null;
    }

    /// Array index. Returns null on non-array or out-of-range.
    pub fn at(self: Value, idx: usize) ?Value {
        if (self != .array) return null;
        if (idx >= self.array.len) return null;
        return self.array[idx];
    }

    pub fn len(self: Value) usize {
        return switch (self) {
            .array => |a| a.len,
            .object => |o| o.len,
            .string => |s| s.len,
            else => 0,
        };
    }

    pub fn asString(self: Value) ?[]const u8 {
        return switch (self) {
            .string => |s| s,
            else => null,
        };
    }

    pub fn asInt(self: Value) ?i64 {
        return switch (self) {
            .int => |i| i,
            .number => |n| if (@trunc(n) == n) @intFromFloat(n) else null,
            else => null,
        };
    }

    pub fn asNumber(self: Value) ?f64 {
        return switch (self) {
            .int => |i| @floatFromInt(i),
            .number => |n| n,
            else => null,
        };
    }

    pub fn asBool(self: Value) ?bool {
        return switch (self) {
            .bool_ => |b| b,
            else => null,
        };
    }

    pub fn isNull(self: Value) bool {
        return self == .null_;
    }
};

// ---------------------------------------------------------------------
// Public entry point.

pub fn parse(input: []const u8) Error!Value {
    var p = Parser{ .src = input, .pos = 0, .depth = 0 };
    p.skipWs();
    var v = try p.parseValue();
    p.skipWs();
    if (p.pos != p.src.len) {
        v.deinit();
        return Error.TrailingGarbage;
    }
    return v;
}

// ---------------------------------------------------------------------

const Parser = struct {
    src: []const u8,
    pos: usize,
    depth: u32,

    fn peek(self: *Parser) Error!u8 {
        if (self.pos >= self.src.len) return Error.UnexpectedEof;
        return self.src[self.pos];
    }

    fn advance(self: *Parser) void {
        self.pos += 1;
    }

    fn expect(self: *Parser, c: u8) Error!void {
        if (self.pos >= self.src.len) return Error.UnexpectedEof;
        if (self.src[self.pos] != c) return Error.InvalidToken;
        self.pos += 1;
    }

    fn skipWs(self: *Parser) void {
        while (self.pos < self.src.len) {
            const c = self.src[self.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') {
                self.pos += 1;
            } else break;
        }
    }

    fn parseValue(self: *Parser) Error!Value {
        if (self.depth >= MAX_DEPTH) return Error.DepthExceeded;
        self.skipWs();
        const c = try self.peek();
        return switch (c) {
            '{' => try self.parseObject(),
            '[' => try self.parseArray(),
            '"' => .{ .string = try self.parseString() },
            't', 'f' => try self.parseBool(),
            'n' => try self.parseNull(),
            '-', '0'...'9' => try self.parseNumber(),
            else => Error.InvalidToken,
        };
    }

    fn parseNull(self: *Parser) Error!Value {
        if (self.pos + 4 > self.src.len) return Error.UnexpectedEof;
        if (!std.mem.eql(u8, self.src[self.pos .. self.pos + 4], "null")) return Error.InvalidToken;
        self.pos += 4;
        return .{ .null_ = {} };
    }

    fn parseBool(self: *Parser) Error!Value {
        if (self.src[self.pos] == 't') {
            if (self.pos + 4 > self.src.len) return Error.UnexpectedEof;
            if (!std.mem.eql(u8, self.src[self.pos .. self.pos + 4], "true")) return Error.InvalidToken;
            self.pos += 4;
            return .{ .bool_ = true };
        } else {
            if (self.pos + 5 > self.src.len) return Error.UnexpectedEof;
            if (!std.mem.eql(u8, self.src[self.pos .. self.pos + 5], "false")) return Error.InvalidToken;
            self.pos += 5;
            return .{ .bool_ = false };
        }
    }

    /// Parse a JSON number per RFC 8259 grammar. Tries i64 first; falls
    /// back to f64 if the source contains '.', 'e', or 'E'.
    fn parseNumber(self: *Parser) Error!Value {
        const start = self.pos;
        var has_frac_or_exp = false;
        if (self.src[self.pos] == '-') self.pos += 1;

        // int part: 0 OR [1-9][0-9]*
        if (self.pos >= self.src.len) return Error.InvalidNumber;
        if (self.src[self.pos] == '0') {
            self.pos += 1;
        } else if (self.src[self.pos] >= '1' and self.src[self.pos] <= '9') {
            self.pos += 1;
            while (self.pos < self.src.len and self.src[self.pos] >= '0' and self.src[self.pos] <= '9') self.pos += 1;
        } else return Error.InvalidNumber;

        // frac
        if (self.pos < self.src.len and self.src[self.pos] == '.') {
            has_frac_or_exp = true;
            self.pos += 1;
            if (self.pos >= self.src.len or self.src[self.pos] < '0' or self.src[self.pos] > '9') return Error.InvalidNumber;
            while (self.pos < self.src.len and self.src[self.pos] >= '0' and self.src[self.pos] <= '9') self.pos += 1;
        }
        // exp
        if (self.pos < self.src.len and (self.src[self.pos] == 'e' or self.src[self.pos] == 'E')) {
            has_frac_or_exp = true;
            self.pos += 1;
            if (self.pos < self.src.len and (self.src[self.pos] == '+' or self.src[self.pos] == '-')) self.pos += 1;
            if (self.pos >= self.src.len or self.src[self.pos] < '0' or self.src[self.pos] > '9') return Error.InvalidNumber;
            while (self.pos < self.src.len and self.src[self.pos] >= '0' and self.src[self.pos] <= '9') self.pos += 1;
        }

        const slice = self.src[start..self.pos];
        if (!has_frac_or_exp) {
            if (std.fmt.parseInt(i64, slice, 10)) |n| {
                return .{ .int = n };
            } else |_| {
                // Overflowed i64 — fall through to float.
            }
        }
        const f = std.fmt.parseFloat(f64, slice) catch return Error.InvalidNumber;
        return .{ .number = f };
    }

    /// Parse a "..."-delimited string into a freshly-malloced []u8 with
    /// all escapes resolved. Caller (or the parent Value tree) owns it.
    fn parseString(self: *Parser) Error![]u8 {
        try self.expect('"');
        const start = self.pos;
        // First pass: find closing quote, count unescaped output length.
        var out_len: usize = 0;
        var i = start;
        while (true) {
            if (i >= self.src.len) return Error.UnexpectedEof;
            const c = self.src[i];
            if (c == '"') break;
            if (c == '\\') {
                if (i + 1 >= self.src.len) return Error.UnexpectedEof;
                const esc = self.src[i + 1];
                switch (esc) {
                    '"', '\\', '/', 'b', 'f', 'n', 'r', 't' => {
                        out_len += 1;
                        i += 2;
                    },
                    'u' => {
                        if (i + 6 > self.src.len) return Error.UnexpectedEof;
                        const cp = parseHex4(self.src[i + 2 .. i + 6]) orelse return Error.InvalidEscape;
                        // Check for surrogate pair.
                        if (cp >= 0xD800 and cp <= 0xDBFF) {
                            // High surrogate; expect "\uXXXX" low surrogate next.
                            if (i + 12 > self.src.len) return Error.UnexpectedEof;
                            if (self.src[i + 6] != '\\' or self.src[i + 7] != 'u') return Error.InvalidEscape;
                            const lo = parseHex4(self.src[i + 8 .. i + 12]) orelse return Error.InvalidEscape;
                            if (lo < 0xDC00 or lo > 0xDFFF) return Error.InvalidEscape;
                            const code = 0x10000 + (@as(u32, cp - 0xD800) << 10) + (lo - 0xDC00);
                            out_len += utf8Len(code);
                            i += 12;
                        } else if (cp >= 0xDC00 and cp <= 0xDFFF) {
                            return Error.InvalidEscape; // stray low surrogate
                        } else {
                            out_len += utf8Len(@as(u32, cp));
                            i += 6;
                        }
                    },
                    else => return Error.InvalidEscape,
                }
            } else {
                // Reject raw control chars per RFC 8259, but be lenient — many
                // real-world feeds have them and rejecting kills usability.
                out_len += 1;
                i += 1;
            }
        }
        const raw_end = i;

        // Second pass: allocate + emit.
        const out = allocBytes(out_len) catch return Error.OutOfMemory;
        var w: usize = 0;
        var p = start;
        while (p < raw_end) {
            const c = self.src[p];
            if (c != '\\') {
                out[w] = c;
                w += 1;
                p += 1;
                continue;
            }
            const esc = self.src[p + 1];
            switch (esc) {
                '"' => {
                    out[w] = '"';
                    w += 1;
                    p += 2;
                },
                '\\' => {
                    out[w] = '\\';
                    w += 1;
                    p += 2;
                },
                '/' => {
                    out[w] = '/';
                    w += 1;
                    p += 2;
                },
                'b' => {
                    out[w] = 0x08;
                    w += 1;
                    p += 2;
                },
                'f' => {
                    out[w] = 0x0C;
                    w += 1;
                    p += 2;
                },
                'n' => {
                    out[w] = '\n';
                    w += 1;
                    p += 2;
                },
                'r' => {
                    out[w] = '\r';
                    w += 1;
                    p += 2;
                },
                't' => {
                    out[w] = '\t';
                    w += 1;
                    p += 2;
                },
                'u' => {
                    const cp = parseHex4(self.src[p + 2 .. p + 6]).?;
                    if (cp >= 0xD800 and cp <= 0xDBFF) {
                        const lo = parseHex4(self.src[p + 8 .. p + 12]).?;
                        const code = 0x10000 + (@as(u32, cp - 0xD800) << 10) + (lo - 0xDC00);
                        w += encodeUtf8(out[w..], code);
                        p += 12;
                    } else {
                        w += encodeUtf8(out[w..], @as(u32, cp));
                        p += 6;
                    }
                },
                else => unreachable, // already validated in first pass
            }
        }
        // Skip closing quote.
        self.pos = raw_end + 1;
        return out[0..w];
    }

    fn parseArray(self: *Parser) Error!Value {
        try self.expect('[');
        self.depth += 1;
        defer self.depth -= 1;
        var b = ListBuilder(Value){};
        errdefer b.deinitAll();
        self.skipWs();
        if ((try self.peek()) == ']') {
            self.pos += 1;
            return .{ .array = b.finalize() };
        }
        while (true) {
            self.skipWs();
            var v = try self.parseValue();
            b.append(v) catch {
                v.deinit();
                return Error.OutOfMemory;
            };
            self.skipWs();
            const c = try self.peek();
            if (c == ',') {
                self.pos += 1;
                continue;
            }
            if (c == ']') {
                self.pos += 1;
                return .{ .array = b.finalize() };
            }
            return Error.InvalidToken;
        }
    }

    fn parseObject(self: *Parser) Error!Value {
        try self.expect('{');
        self.depth += 1;
        defer self.depth -= 1;
        var b = ListBuilder(Field){};
        errdefer b.deinitAll();
        self.skipWs();
        if ((try self.peek()) == '}') {
            self.pos += 1;
            return .{ .object = b.finalize() };
        }
        while (true) {
            self.skipWs();
            if ((try self.peek()) != '"') return Error.InvalidToken;
            const name = try self.parseString();
            errdefer freeBytes(name);
            self.skipWs();
            try self.expect(':');
            self.skipWs();
            var val = try self.parseValue();
            b.append(.{ .name = name, .value = val }) catch {
                val.deinit();
                return Error.OutOfMemory;
            };
            self.skipWs();
            const c = try self.peek();
            if (c == ',') {
                self.pos += 1;
                continue;
            }
            if (c == '}') {
                self.pos += 1;
                return .{ .object = b.finalize() };
            }
            return Error.InvalidToken;
        }
    }
};

// ---------------------------------------------------------------------
// Growing slice backed by libc.realloc. Used for arrays + objects.
// Doubles cap on overflow; final slice is shrink-to-fit (one extra
// realloc) to save heap when a big object is followed by a small one.

fn ListBuilder(comptime T: type) type {
    return struct {
        ptr: ?[*]T = null,
        cap: usize = 0,
        n: usize = 0,

        const Self = @This();

        fn append(self: *Self, item: T) !void {
            if (self.n >= self.cap) {
                const new_cap: usize = if (self.cap == 0) 4 else self.cap * 2;
                const new_raw = libc.realloc(
                    if (self.ptr) |p| @ptrCast(p) else null,
                    new_cap * @sizeOf(T),
                ) orelse return error.OutOfMemory;
                self.ptr = @ptrCast(@alignCast(new_raw));
                self.cap = new_cap;
            }
            self.ptr.?[self.n] = item;
            self.n += 1;
        }

        fn finalize(self: *Self) []T {
            if (self.n == 0) {
                if (self.ptr) |p| libc.free(@ptrCast(p));
                return &[_]T{};
            }
            if (self.n < self.cap) {
                if (libc.realloc(@ptrCast(self.ptr.?), self.n * @sizeOf(T))) |shrunk| {
                    self.ptr = @ptrCast(@alignCast(shrunk));
                    self.cap = self.n;
                }
                // realloc-shrink failure is non-fatal — keep oversize block.
            }
            return self.ptr.?[0..self.n];
        }

        /// Free everything (used on error paths). Walks finished items
        /// for nested cleanup.
        fn deinitAll(self: *Self) void {
            if (self.ptr) |p| {
                var i: usize = 0;
                while (i < self.n) : (i += 1) {
                    deinitItem(T, &p[i]);
                }
                libc.free(@ptrCast(p));
                self.ptr = null;
                self.cap = 0;
                self.n = 0;
            }
        }
    };
}

fn deinitItem(comptime T: type, item: *T) void {
    if (T == Value) {
        item.deinit();
    } else if (T == Field) {
        freeBytes(item.name);
        item.value.deinit();
    }
}

// ---------------------------------------------------------------------
// Byte-slice allocation helpers. Centralized so swapping to a different
// allocator later only touches three functions.

fn allocBytes(n: usize) ![]u8 {
    if (n == 0) return &[_]u8{};
    const ptr = libc.malloc(n) orelse return error.OutOfMemory;
    return ptr[0..n];
}

fn freeBytes(s: []u8) void {
    if (s.len == 0) return;
    libc.free(s.ptr);
}

fn freeSlice(comptime T: type, s: []T) void {
    if (s.len == 0) return;
    libc.free(@ptrCast(s.ptr));
}

// ---------------------------------------------------------------------
// Number / hex helpers.

fn parseHex4(s: []const u8) ?u16 {
    if (s.len < 4) return null;
    var v: u16 = 0;
    for (s[0..4]) |c| {
        const d: u16 = if (c >= '0' and c <= '9')
            c - '0'
        else if (c >= 'a' and c <= 'f')
            c - 'a' + 10
        else if (c >= 'A' and c <= 'F')
            c - 'A' + 10
        else
            return null;
        v = (v << 4) | d;
    }
    return v;
}

fn utf8Len(cp: u32) usize {
    if (cp < 0x80) return 1;
    if (cp < 0x800) return 2;
    if (cp < 0x10000) return 3;
    return 4;
}

fn encodeUtf8(out: []u8, cp: u32) usize {
    if (cp < 0x80) {
        out[0] = @intCast(cp);
        return 1;
    }
    if (cp < 0x800) {
        out[0] = @intCast(0xC0 | (cp >> 6));
        out[1] = @intCast(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = @intCast(0xE0 | (cp >> 12));
        out[1] = @intCast(0x80 | ((cp >> 6) & 0x3F));
        out[2] = @intCast(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = @intCast(0xF0 | (cp >> 18));
    out[1] = @intCast(0x80 | ((cp >> 12) & 0x3F));
    out[2] = @intCast(0x80 | ((cp >> 6) & 0x3F));
    out[3] = @intCast(0x80 | (cp & 0x3F));
    return 4;
}
