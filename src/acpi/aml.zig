// AML (ACPI Machine Language) interpreter — the dynamic, bytecode half of ACPI.
//
// acpi.zig parses the *static* tables (FADT/MADT/…) and even pattern-matches the
// DSDT's `\_S5_` package, but it deliberately does NOT interpret AML. This file
// does: it decodes the DSDT/SSDT bytecode into a namespace of named objects
// (Scopes, Devices, Methods, Names, OperationRegions, Fields, …) and — in later
// slices — evaluates control methods (GPE handlers _Lxx/_Exx, _TMP, _BST, …).
//
// Design: the decoder is DATA-DRIVEN. Rather than a giant per-opcode switch, a
// comptime `op_table` of {opcode, kind, shape} rows describes each
// namespace-relevant opcode's structure, and the walker switches on a small set
// of `Shape`s. Adding an opcode is a table row, not new control flow.
//
// Safety: AML is untrusted firmware. Like acpi.zig's `_S5_` scan, EVERY byte
// access is bounds-checked via the Reader; a malformed table degrades to a
// short/partial walk + a log line, never an out-of-bounds read or a panic.
//
// Slice B1: decode the DSDT, walk the namespace, dump it (named object + full
// ACPI path + kind), like `acpidump`/`iasl`. Slice B2a (this file now): also
// *record* every object into a flat store and *evaluate* AML data — integer
// constants, Buffer, Package — proven by evaluating \_S5_ to the same SLP_TYP
// the static scan finds. Statement execution (Store/If/While, method calls)
// is B2b; OperationRegion/Field hardware I/O is B2c. The store is what GPE
// dispatch (Slice C) and thermal/battery (Slice D) look objects up in.
//
// Reference: ACPI 6.4 §20 (AML), §20.2.2 (NameString), §20.2.4 (PkgLength),
// §20.2.5 (named objects), §20.3 (opcode encoding).

const std = @import("std");
const acpi = @import("acpi.zig");
const debug = @import("../debug/debug.zig");

// Flip to false once the namespace dump has served its purpose (it's one-time
// boot noise). Kept on through Slice B bring-up so each boot shows the walk.
const DUMP = true;

// --- AML object value (tagged union) ----------------------------------------
// The evaluator (Slice B2+) produces these. Defined now so the namespace can
// carry resolved constant Names and so the type is stable across slices.

pub const Value = union(enum) {
    uninit,
    integer: u64,
    string: []const u8, // points into the DSDT body (no copy)
    buffer: []const u8,
    package: []const Value,
};

// --- Namespace object kinds -------------------------------------------------

pub const NodeKind = enum {
    scope,
    device,
    method,
    name,
    op_region,
    field,
    processor,
    thermal_zone,
    power_res,
    mutex,
    event,
    other,

    fn label(self: NodeKind) []const u8 {
        return switch (self) {
            .scope => "Scope",
            .device => "Device",
            .method => "Method",
            .name => "Name",
            .op_region => "OpRegion",
            .field => "Field",
            .processor => "Processor",
            .thermal_zone => "ThermalZone",
            .power_res => "PowerRes",
            .mutex => "Mutex",
            .event => "Event",
            .other => "?",
        };
    }
};

// --- opcode structural shapes ----------------------------------------------
// How the walker consumes an opcode. The point of the table: per-opcode logic
// collapses to one of these, so the walker is ~10 cases not ~30 opcodes.

const Shape = enum {
    scope, // PkgLength NameString <extra> TermList — record + recurse as new scope
    method, // PkgLength NameString flags TermList — record, do NOT recurse (body is code)
    leaf_pkg, // PkgLength NameString … — record, jump past the package (Field/IndexField/BankField)
    name, // NameString DataRefObject — record, skip the value object
    op_region, // NameString space(byte) offset(TermArg) len(TermArg) — record
    name_byte, // NameString byte — record (Mutex sync flags)
    name_only, // NameString — record (Event)
    alias, // NameString NameString — record
    ctrl_pkg, // PkgLength … — control flow (If/Else/While); skip the package
};

const OpInfo = struct {
    code: u16, // extended opcodes (0x5B prefix) encoded as 0x5B00 | second_byte
    kind: NodeKind,
    shape: Shape,
    extra: u8 = 0, // fixed bytes consumed after NameString, before the TermList (scope shape)
};

// The namespace-relevant opcode table. Everything else at term level is either
// an executable statement we skip or (for B1) an opcode we log and stop on.
const op_table = [_]OpInfo{
    .{ .code = 0x10, .kind = .scope, .shape = .scope }, // ScopeOp
    .{ .code = 0x14, .kind = .method, .shape = .method, .extra = 1 }, // MethodOp (flags)
    .{ .code = 0x08, .kind = .name, .shape = .name }, // NameOp
    .{ .code = 0x06, .kind = .other, .shape = .alias }, // AliasOp
    .{ .code = 0x5B82, .kind = .device, .shape = .scope }, // DeviceOp
    .{ .code = 0x5B85, .kind = .thermal_zone, .shape = .scope }, // ThermalZoneOp
    .{ .code = 0x5B84, .kind = .power_res, .shape = .scope, .extra = 3 }, // PowerResOp: SystemLevel(1)+ResourceOrder(2)
    .{ .code = 0x5B83, .kind = .processor, .shape = .scope, .extra = 6 }, // ProcessorOp: ProcID(1)+PblkAddr(4)+PblkLen(1)
    .{ .code = 0x5B80, .kind = .op_region, .shape = .op_region }, // OperationRegionOp
    .{ .code = 0x5B81, .kind = .field, .shape = .leaf_pkg }, // FieldOp
    .{ .code = 0x5B86, .kind = .field, .shape = .leaf_pkg }, // IndexFieldOp
    .{ .code = 0x5B87, .kind = .field, .shape = .leaf_pkg }, // BankFieldOp
    .{ .code = 0x5B01, .kind = .mutex, .shape = .name_byte }, // MutexOp
    .{ .code = 0x5B02, .kind = .event, .shape = .name_only }, // EventOp
    .{ .code = 0xA0, .kind = .other, .shape = .ctrl_pkg }, // IfOp
    .{ .code = 0xA1, .kind = .other, .shape = .ctrl_pkg }, // ElseOp
    .{ .code = 0xA2, .kind = .other, .shape = .ctrl_pkg }, // WhileOp
};

fn lookup(code: u16) ?OpInfo {
    inline for (op_table) |o| {
        if (o.code == code) return o;
    }
    return null;
}

// --- byte reader (bounds-checked) -------------------------------------------

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn rem(self: Reader) usize {
        return if (self.pos <= self.buf.len) self.buf.len - self.pos else 0;
    }

    /// Byte at absolute offset `self.pos + off`, or null if past the end.
    fn peek(self: Reader, off: usize) ?u8 {
        const i = self.pos + off;
        return if (i < self.buf.len) self.buf[i] else null;
    }

    /// Consume and return one byte, or null at EOF.
    fn next(self: *Reader) ?u8 {
        if (self.pos >= self.buf.len) return null;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    /// Advance by n, clamped so pos never exceeds buf.len.
    fn skip(self: *Reader, n: usize) void {
        self.pos = @min(self.pos +| n, self.buf.len);
    }
};

// --- PkgLength (ACPI 6.4 §20.2.4) -------------------------------------------
// The lead byte's top two bits give the count of following bytes. The encoded
// length INCLUDES the PkgLength bytes themselves, so a package that starts at
// the lead byte ends at lead_pos + len.

const PkgLen = struct { value: usize, header_bytes: usize };

fn readPkgLength(r: *Reader) ?PkgLen {
    const b0 = r.next() orelse return null;
    const follow: usize = b0 >> 6;
    if (follow == 0) return .{ .value = b0 & 0x3F, .header_bytes = 1 };
    var value: usize = b0 & 0x0F; // low nibble
    var i: usize = 0;
    while (i < follow) : (i += 1) {
        const b = r.next() orelse return null;
        value |= @as(usize, b) << @intCast(4 + 8 * i);
    }
    return .{ .value = value, .header_bytes = 1 + follow };
}

// --- NameString (ACPI 6.4 §20.2.2) ------------------------------------------
// Optional prefix: RootChar '\' (0x5C) or one-or-more ParentPrefix '^' (0x5E).
// Then a NamePath: a single NameSeg, DualNamePrefix(0x2E)+2 segs,
// MultiNamePrefix(0x2F)+count+segs, or NullName(0x00).

const MAX_SEGS = 16;

const NameString = struct {
    rooted: bool, // leading '\'
    parents: u8, // count of leading '^'
    segs: [MAX_SEGS][4]u8,
    nsegs: u8,
};

fn readNameString(r: *Reader) ?NameString {
    var ns = NameString{ .rooted = false, .parents = 0, .segs = undefined, .nsegs = 0 };

    // Prefix.
    if (r.peek(0)) |c| {
        if (c == 0x5C) { // RootChar
            ns.rooted = true;
            _ = r.next();
        } else {
            while (r.peek(0)) |p| {
                if (p != 0x5E) break; // ParentPrefixChar
                ns.parents +|= 1;
                _ = r.next();
            }
        }
    }

    // NamePath.
    const lead = r.peek(0) orelse return ns; // NullName-ish / truncated → empty path
    switch (lead) {
        0x00 => _ = r.next(), // NullName
        0x2E => { // DualNamePrefix
            _ = r.next();
            if (!readSeg(r, &ns)) return null;
            if (!readSeg(r, &ns)) return null;
        },
        0x2F => { // MultiNamePrefix
            _ = r.next();
            const count = r.next() orelse return null;
            var i: u8 = 0;
            while (i < count) : (i += 1) {
                if (!readSeg(r, &ns)) return null;
            }
        },
        else => {
            if (!readSeg(r, &ns)) return null;
        },
    }
    return ns;
}

/// Read one 4-byte NameSeg into ns, validating the lead char class so a desync
/// surfaces as a parse failure rather than recording garbage.
fn readSeg(r: *Reader, ns: *NameString) bool {
    if (ns.nsegs >= MAX_SEGS) return false;
    if (r.rem() < 4) return false;
    var seg: [4]u8 = undefined;
    seg[0] = r.next().?;
    seg[1] = r.next().?;
    seg[2] = r.next().?;
    seg[3] = r.next().?;
    // LeadNameChar = '_' or 'A'..'Z'; the rest add '0'..'9'. Reject otherwise.
    if (!(seg[0] == '_' or (seg[0] >= 'A' and seg[0] <= 'Z'))) return false;
    ns.segs[ns.nsegs] = seg;
    ns.nsegs += 1;
    return true;
}

// --- scope path tracking ----------------------------------------------------
// A fixed buffer holding the current absolute ACPI path (e.g. "\_SB_.PCI0").
// Recursion pushes a child segment and restores on the way out — no allocator.

const PathBuf = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,

    fn reset(self: *PathBuf) void {
        self.buf[0] = '\\';
        self.len = 1;
    }

    fn snapshot(self: *const PathBuf) []const u8 {
        return self.buf[0..self.len];
    }

    fn append(self: *PathBuf, bytes: []const u8) void {
        for (bytes) |b| {
            if (self.len >= self.buf.len) return;
            self.buf[self.len] = b;
            self.len += 1;
        }
    }

    /// Resolve a NameString against the current path, mutating in place to the
    /// object's absolute path. Returns a mark to restore the previous path with.
    /// Handles rooted '\' (reset to root), parent '^' (drop trailing segments),
    /// and relative (append). Multi-seg names append each seg dot-separated.
    fn enter(self: *PathBuf, ns: NameString) usize {
        const mark = self.len;
        if (ns.rooted) {
            self.len = 1; // back to "\"
        } else {
            var p: u8 = 0;
            while (p < ns.parents) : (p += 1) self.dropSegment();
        }
        var i: u8 = 0;
        while (i < ns.nsegs) : (i += 1) {
            if (self.len > 1) self.append(".");
            self.append(&ns.segs[i]);
        }
        return mark;
    }

    fn restore(self: *PathBuf, mark: usize) void {
        self.len = mark;
    }

    /// Drop the last '.'-separated component (for '^'). Never goes below root.
    fn dropSegment(self: *PathBuf) void {
        var i = self.len;
        while (i > 1) : (i -= 1) {
            if (self.buf[i - 1] == '.') {
                self.len = i - 1;
                return;
            }
        }
        self.len = 1; // no dot → back to root
    }
};

// --- the walk ---------------------------------------------------------------

var node_count: u32 = 0;
var unknown_op_seen: u16 = 0; // first unrecognized term-level opcode, for diagnostics

/// Read the opcode at the cursor. Extended opcodes (lead 0x5B) are folded into
/// 0x5B00 | second_byte so the table can key on a single u16.
fn readOpcode(r: *Reader) ?u16 {
    const b = r.next() orelse return null;
    if (b == 0x5B) { // ExtOpPrefix
        const b2 = r.next() orelse return null;
        return 0x5B00 | @as(u16, b2);
    }
    return b;
}

/// Walk a TermList in [r.pos, end), recording named objects under `path`.
/// Recurses into scope-creating objects. depth is for the dump indent only.
fn walkTerms(r: *Reader, end: usize, path: *PathBuf, depth: u8) void {
    while (r.pos < end) {
        const term_start = r.pos;
        const op = readOpcode(r) orelse return;

        const info = lookup(op) orelse {
            // Not a namespace/scoping opcode. At the top level of a DSDT this is
            // rare (most terms are object definitions); when it happens it's an
            // executable statement whose length we don't model yet. Skipping
            // blindly would desync the stream, so stop this list and record the
            // opcode for diagnostics — the caller still has every object found
            // before this point.
            if (unknown_op_seen == 0) unknown_op_seen = op;
            return;
        };

        switch (info.shape) {
            .scope => {
                const pkg_end = packageEnd(r, term_start) orelse return;
                const ns = readNameString(r) orelse return;
                if (info.extra > 0) r.skip(info.extra);
                record(info.kind, path, ns, depth);
                storeNode(info.kind, path, ns, .{});
                const mark = path.enter(ns);
                walkTerms(r, pkg_end, path, depth + 1);
                path.restore(mark);
                r.pos = pkg_end;
            },
            .method => {
                const pkg_end = packageEnd(r, term_start) orelse return;
                const ns = readNameString(r) orelse return;
                const flags = r.next() orelse return; // MethodFlags
                const body_off = r.pos;
                record(info.kind, path, ns, depth);
                storeNode(.method, path, ns, .{
                    .val_off = body_off,
                    .val_len = if (pkg_end > body_off) pkg_end - body_off else 0,
                    .arg_count = flags & 0x07,
                });
                r.pos = pkg_end; // body not walked here (executed on call, B2b)
            },
            .leaf_pkg => {
                const pkg_end = packageEnd(r, term_start) orelse return;
                const ns = readNameString(r) orelse return;
                record(info.kind, path, ns, depth);
                storeNode(info.kind, path, ns, .{}); // Field elements parsed in B2c
                r.pos = pkg_end;
            },
            .name => {
                const ns = readNameString(r) orelse return;
                const val_off = r.pos;
                record(info.kind, path, ns, depth);
                if (!skipDataObject(r)) return;
                storeNode(.name, path, ns, .{ .val_off = val_off, .val_len = r.pos - val_off });
            },
            .op_region => {
                const ns = readNameString(r) orelse return;
                const space = r.next() orelse return; // RegionSpace
                const off = evalConstInt(r) orelse 0; // RegionOffset (TermArg, ~always const)
                const len = evalConstInt(r) orelse 0; // RegionLen
                record(info.kind, path, ns, depth);
                storeNode(.op_region, path, ns, .{ .region_space = space, .region_off = off, .region_len = len });
            },
            .name_byte => {
                const ns = readNameString(r) orelse return;
                r.skip(1);
                record(info.kind, path, ns, depth);
                storeNode(info.kind, path, ns, .{});
            },
            .name_only => {
                const ns = readNameString(r) orelse return;
                record(info.kind, path, ns, depth);
                storeNode(info.kind, path, ns, .{});
            },
            .alias => {
                const ns = readNameString(r) orelse return;
                _ = readNameString(r) orelse return; // alias target
                record(info.kind, path, ns, depth);
                storeNode(info.kind, path, ns, .{});
            },
            .ctrl_pkg => {
                // Control flow (If/Else/While). Skip the whole package. (A later
                // slice may recurse to catch objects defined inside `If (cond)`.)
                const pkg_end = packageEnd(r, term_start) orelse return;
                r.pos = pkg_end;
            },
        }
    }
}

/// For a PkgLength-prefixed opcode whose opcode byte(s) started at `op_start`,
/// read the PkgLength and return the absolute end offset of the package. The
/// PkgLength's encoded value is measured from the PkgLength's first byte (which
/// is r.pos right now, just after the opcode).
fn packageEnd(r: *Reader, op_start: usize) ?usize {
    _ = op_start;
    const pkg_start = r.pos;
    const pl = readPkgLength(r) orelse return null;
    const end = pkg_start + pl.value;
    if (end > r.buf.len or end < r.pos) return null; // truncated / nonsense
    return end;
}

/// Skip one DataObject (the value of a Name): integer/string/buffer/package
/// literal. Returns false on truncation/unknown so the caller stops cleanly.
fn skipDataObject(r: *Reader) bool {
    const op = r.peek(0) orelse return false;
    switch (op) {
        0x00, 0x01, 0xFF => {
            _ = r.next();
            return true;
        }, // Zero/One/Ones
        0x0A => {
            r.skip(2);
            return true;
        }, // BytePrefix + 1
        0x0B => {
            r.skip(3);
            return true;
        }, // WordPrefix + 2
        0x0C => {
            r.skip(5);
            return true;
        }, // DWordPrefix + 4
        0x0E => {
            r.skip(9);
            return true;
        }, // QWordPrefix + 8
        0x0D => { // StringPrefix: bytes until NUL
            _ = r.next();
            while (r.next()) |c| {
                if (c == 0) return true;
            }
            return false;
        },
        0x11, 0x12, 0x13 => { // Buffer / Package / VarPackage: opcode + PkgLength-delimited
            _ = r.next();
            const pkg_start = r.pos;
            const pl = readPkgLength(r) orelse return false;
            const end = pkg_start + pl.value;
            if (end > r.buf.len or end < r.pos) return false;
            r.pos = end;
            return true;
        },
        else => {
            // A NameString reference or expression as a value. Best-effort: try
            // to consume it as a NameString (common for Name(X, \Y) aliases).
            return readNameString(r) != null;
        },
    }
}

/// Skip one TermArg (used for OperationRegion offset/length). These are almost
/// always integer literals in practice; fall back to DataObject skipping, which
/// covers the literal forms and a NameString reference.
fn skipTermArg(r: *Reader) bool {
    return skipDataObject(r);
}

/// Record (dump) one discovered named object.
fn record(kind: NodeKind, path: *PathBuf, ns: NameString, depth: u8) void {
    node_count += 1;
    if (!DUMP) return;
    // Build the object's absolute path by entering+restoring (non-destructive).
    const mark = path.enter(ns);
    const full = path.snapshot();
    var indent: [32]u8 = undefined;
    const ind_n = @min(@as(usize, depth) * 2, indent.len);
    @memset(indent[0..ind_n], ' ');
    debug.klog("[aml] {s}{s} {s}\n", .{ indent[0..ind_n], kind.label(), full });
    path.restore(mark);
}

// === B2: namespace store + value evaluator ==================================
// B1 walks and dumps; B2 also *records* each object into a flat store and can
// *evaluate* AML data. This section is the store + the data evaluator
// (constants, Buffer, Package). Statement execution (Store, If, method calls)
// is B2b; OperationRegion/Field I/O is B2c.

const PATH_MAX = 64;
const MAX_NODES = 512;

/// One resolved namespace entry. Which payload fields matter depends on `kind`:
///   .name      -> val_off/val_len: the DataRefObject's byte range in the body
///   .method    -> val_off/val_len: the method body's TermList range; arg_count
///   .op_region -> region_space/off/len
/// Other kinds (scope/device/field/…) are stored for path resolution only.
const StoredNode = struct {
    path: [PATH_MAX]u8 = undefined,
    path_len: u8 = 0,
    kind: NodeKind = .other,
    val_off: usize = 0,
    val_len: usize = 0,
    arg_count: u8 = 0,
    region_space: u8 = 0,
    region_off: u64 = 0,
    region_len: u64 = 0,
};

/// Optional payload passed to storeNode; defaults keep call sites terse.
const Payload = struct {
    val_off: usize = 0,
    val_len: usize = 0,
    arg_count: u8 = 0,
    region_space: u8 = 0,
    region_off: u64 = 0,
    region_len: u64 = 0,
};

var nodes: [MAX_NODES]StoredNode = undefined;
var nnodes: usize = 0;
var store_overflow: bool = false;

/// The DSDT AML body, cached by load() so evaluator helpers can build Readers
/// over the same bytes the stored offsets index into.
var dsdt_body: []const u8 = &.{};

fn storeNode(kind: NodeKind, path: *PathBuf, ns: NameString, p: Payload) void {
    if (nnodes >= nodes.len) {
        store_overflow = true;
        return;
    }
    const mark = path.enter(ns);
    const full = path.snapshot();
    const n = &nodes[nnodes];
    n.* = .{
        .kind = kind,
        .val_off = p.val_off,
        .val_len = p.val_len,
        .arg_count = p.arg_count,
        .region_space = p.region_space,
        .region_off = p.region_off,
        .region_len = p.region_len,
    };
    const cl = @min(full.len, @as(usize, PATH_MAX));
    @memcpy(n.path[0..cl], full[0..cl]);
    n.path_len = @intCast(cl);
    path.restore(mark);
    nnodes += 1;
}

/// Exact absolute-path lookup (e.g. "\\_S5_"). B2b adds scope-relative search.
fn findExact(abs: []const u8) ?*StoredNode {
    var i: usize = 0;
    while (i < nnodes) : (i += 1) {
        const n = &nodes[i];
        if (std.mem.eql(u8, n.path[0..n.path_len], abs)) return n;
    }
    return null;
}

// --- value arena ------------------------------------------------------------
// Packages need backing storage for their element Values. A fixed bump arena,
// reset before each top-level evaluation, avoids an allocator on the AML path.

const VALUE_ARENA = 2048;
var value_arena: [VALUE_ARENA]Value = undefined;
var arena_top: usize = 0;

fn arenaReset() void {
    arena_top = 0;
}

fn arenaAlloc(n: usize) ?[]Value {
    if (arena_top + n > value_arena.len) return null;
    const s = value_arena[arena_top .. arena_top + n];
    arena_top += n;
    return s;
}

// --- data evaluator ---------------------------------------------------------
// Evaluate one DataObject / computational-data TermArg at the cursor into a
// Value. Handles the literal forms (the bulk of Name values and Package
// elements). Non-constant expressions return null (B2b extends this).

fn evalData(r: *Reader) ?Value {
    const op = r.peek(0) orelse return null;
    switch (op) {
        0x00 => { // ZeroOp
            _ = r.next();
            return .{ .integer = 0 };
        },
        0x01 => { // OneOp
            _ = r.next();
            return .{ .integer = 1 };
        },
        0xFF => { // OnesOp (64-bit all-ones)
            _ = r.next();
            return .{ .integer = ~@as(u64, 0) };
        },
        0x0A => { // BytePrefix
            _ = r.next();
            const b = r.next() orelse return null;
            return .{ .integer = b };
        },
        0x0B => { // WordPrefix
            _ = r.next();
            return .{ .integer = readLe(r, 2) orelse return null };
        },
        0x0C => { // DWordPrefix
            _ = r.next();
            return .{ .integer = readLe(r, 4) orelse return null };
        },
        0x0E => { // QWordPrefix
            _ = r.next();
            return .{ .integer = readLe(r, 8) orelse return null };
        },
        0x0D => { // StringPrefix: AsciiCharList NullChar
            _ = r.next();
            const start = r.pos;
            while (r.next()) |c| {
                if (c == 0) return .{ .string = r.buf[start .. r.pos - 1] };
            }
            return null;
        },
        0x11 => { // BufferOp: PkgLength BufferSize ByteList
            _ = r.next();
            const pkg_start = r.pos;
            const pl = readPkgLength(r) orelse return null;
            const end = pkg_start + pl.value;
            if (end > r.buf.len or end < r.pos) return null;
            _ = evalData(r); // BufferSize TermArg (real length is the byte count)
            const bytes = if (r.pos <= end) r.buf[r.pos..end] else r.buf[0..0];
            r.pos = end;
            return .{ .buffer = bytes };
        },
        0x12, 0x13 => { // PackageOp / VarPackageOp
            _ = r.next();
            const pkg_start = r.pos;
            const pl = readPkgLength(r) orelse return null;
            const end = pkg_start + pl.value;
            if (end > r.buf.len or end < r.pos) return null;
            var num: usize = 0;
            if (op == 0x12) {
                num = r.next() orelse return null; // NumElements: ByteData
            } else {
                const v = evalData(r) orelse return null; // NumElements: TermArg
                num = if (v == .integer) @intCast(@min(v.integer, VALUE_ARENA)) else 0;
            }
            const elems = arenaAlloc(num) orelse return null;
            var i: usize = 0;
            while (i < num) : (i += 1) {
                elems[i] = if (r.pos < end) (evalData(r) orelse .uninit) else .uninit;
            }
            r.pos = end;
            return .{ .package = elems };
        },
        else => {
            // A NameString reference or unmodeled expression used as data (e.g.
            // a Package element naming another object). Consume a NameString if
            // that's what it is so the surrounding Package stays in sync; the
            // referenced value is left unresolved (B2b resolves references).
            if (isNameLead(op)) {
                _ = readNameString(r) orelse return null;
                return .uninit;
            }
            return null;
        },
    }
}

fn readLe(r: *Reader, n: usize) ?u64 {
    if (r.rem() < n) return null;
    var v: u64 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        v |= @as(u64, r.next().?) << @intCast(8 * i);
    }
    return v;
}

fn isNameLead(c: u8) bool {
    return c == 0x5C or c == 0x5E or c == 0x2E or c == 0x2F or c == '_' or (c >= 'A' and c <= 'Z');
}

/// Evaluate a TermArg expected to be a constant integer (OpRegion offset/len).
/// On a non-constant expression, skip the TermArg and return null.
fn evalConstInt(r: *Reader) ?u64 {
    const save = r.pos;
    if (evalData(r)) |v| {
        if (v == .integer) return v.integer;
    }
    r.pos = save;
    _ = skipTermArg(r);
    return null;
}

/// SLP_TYPa from \_S5_ as evaluated from AML (cross-checks Slice A's static
/// scan; usable by the shutdown path later). Null if \_S5_ is absent or not a
/// Package of integers. Call after load() has populated the store.
pub fn s5SlpTyp() ?u8 {
    if (dsdt_body.len == 0) return null;
    const n = findExact("\\_S5_") orelse return null;
    arenaReset();
    var r = Reader{ .buf = dsdt_body, .pos = n.val_off };
    const v = evalData(&r) orelse return null;
    if (v != .package or v.package.len < 1 or v.package[0] != .integer) return null;
    return @truncate(v.package[0].integer);
}

// --- entry point ------------------------------------------------------------

/// Decode the cached DSDT and walk its namespace. Call after acpi.init has
/// cached the DSDT (acpi.getDsdt()). Best-effort: logs a summary; a malformed
/// DSDT yields a partial walk, never a fault. Returns the object count.
pub fn load() u32 {
    node_count = 0;
    unknown_op_seen = 0;
    nnodes = 0;
    store_overflow = false;
    arenaReset();

    const dsdt = acpi.getDsdt() orelse {
        debug.klog("[aml] no DSDT cached — namespace unavailable\n", .{});
        return 0;
    };
    // AML body begins after the 36-byte SDT header. acpi.zig already validated
    // the length + that the whole table is mapped, so this slice is safe.
    const hdr_len = @sizeOf(acpi.SdtHeader);
    if (dsdt.length <= hdr_len) return 0;
    const body = @as([*]const u8, @ptrCast(dsdt))[hdr_len..dsdt.length];
    dsdt_body = body;

    if (DUMP) debug.klog("[aml] walking DSDT namespace ({d} AML bytes)\n", .{body.len});

    var r = Reader{ .buf = body };
    var path = PathBuf{};
    path.reset();
    walkTerms(&r, body.len, &path, 0);

    if (unknown_op_seen != 0) {
        debug.klog("[aml] walk stopped early at unmodeled opcode 0x{X} ({d} objects so far)\n", .{ unknown_op_seen, node_count });
    } else {
        debug.klog("[aml] namespace walk complete: {d} named objects\n", .{node_count});
    }
    debug.klog("[aml] namespace store: {d} objects{s}\n", .{ nnodes, if (store_overflow) " (TRUNCATED)" else "" });

    // B2a proof: evaluate \_S5_ through the interpreter and report SLP_TYP — the
    // same datum Slice A's static scan extracts, now produced by the general
    // value path (Name lookup + Package/integer decode).
    arenaReset();
    if (findExact("\\_S5_")) |n| {
        var er = Reader{ .buf = body, .pos = n.val_off };
        if (evalData(&er)) |v| {
            if (v == .package and v.package.len >= 1 and v.package[0] == .integer) {
                const a = v.package[0].integer;
                const b = if (v.package.len >= 2 and v.package[1] == .integer) v.package[1].integer else 0;
                // Cross-check against acpi.zig's independent static byte-scan of
                // the same package — two unrelated decoders, one verdict.
                if (acpi.getS5SleepTypes()) |st| {
                    const ok = (a == st.a) and (b == st.b);
                    debug.klog("[aml] evaluated \\_S5_ = Package[{d}]: SLP_TYPa={d} SLP_TYPb={d} (static scan a={d} b={d}: {s})\n", .{ v.package.len, a, b, st.a, st.b, if (ok) "MATCH" else "MISMATCH" });
                } else {
                    debug.klog("[aml] evaluated \\_S5_ = Package[{d}]: SLP_TYPa={d} SLP_TYPb={d} (no static scan to compare)\n", .{ v.package.len, a, b });
                }
            } else {
                debug.klog("[aml] \\_S5_ present but not an integer Package\n", .{});
            }
        }
    } else {
        debug.klog("[aml] \\_S5_ not found in namespace store\n", .{});
    }
    return node_count;
}
