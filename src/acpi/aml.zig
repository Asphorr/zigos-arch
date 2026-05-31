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
const io = @import("../io.zig"); // SystemIO field access (B2c)
const paging = @import("../mm/paging.zig"); // SystemMemory field access (B2c)

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
    field, // PkgLength NameString(region) flags FieldList — parse elements (B2c)
    leaf_pkg, // PkgLength NameString … — record, jump past the package (IndexField/BankField)
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
    .{ .code = 0x5B81, .kind = .field, .shape = .field }, // FieldOp — parse FieldList (B2c)
    .{ .code = 0x5B86, .kind = .field, .shape = .leaf_pkg }, // IndexFieldOp (opaque: indirect)
    .{ .code = 0x5B87, .kind = .field, .shape = .leaf_pkg }, // BankFieldOp (opaque: banked)
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
                storeNode(info.kind, path, ns, .{}); // IndexField/BankField: opaque (indirect)
                r.pos = pkg_end;
            },
            .field => {
                // FieldOp PkgLength NameString(region) FieldFlags FieldList. The
                // region NameString is a *reference* (already an OpRegion node),
                // not a new object; the FieldList's NamedFields are the objects,
                // created in the current scope. Resolve the region to its node so
                // each element can reach the hardware (B2c).
                const pkg_end = packageEnd(r, term_start) orelse return;
                const region_ns = readNameString(r) orelse return;
                var region_idx: i32 = -1;
                if (resolve(path.snapshot(), region_ns)) |rn| {
                    if (rn.kind == .op_region) region_idx = @intCast(nodeIndexOf(rn));
                }
                const flags = r.next() orelse return; // FieldFlags
                parseFieldList(r, pkg_end, path, region_idx, flags & 0x0F, depth);
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
    // Field element (B2c, kind == .field): the parent OperationRegion's node
    // index (-1 if unresolved) plus this element's bit position/width/access.
    field_region: i32 = -1,
    field_bit_off: u32 = 0,
    field_bit_width: u32 = 0,
    field_access: u8 = 0,
    // Runtime mutable value (B2b): Store-to-Name updates this; reads prefer it
    // over the static DSDT value. Reset every load() (nnodes = 0 re-walks).
    runtime_val: Value = .uninit,
    has_runtime: bool = false,
};

/// Optional payload passed to storeNode; defaults keep call sites terse.
const Payload = struct {
    val_off: usize = 0,
    val_len: usize = 0,
    arg_count: u8 = 0,
    region_space: u8 = 0,
    region_off: u64 = 0,
    region_len: u64 = 0,
    field_region: i32 = -1,
    field_bit_off: u32 = 0,
    field_bit_width: u32 = 0,
    field_access: u8 = 0,
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
        .field_region = p.field_region,
        .field_bit_off = p.field_bit_off,
        .field_bit_width = p.field_bit_width,
        .field_access = p.field_access,
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

const VALUE_ARENA = 4096;
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

// === B2b: statement executor + method invocation ============================
// B2a evaluates static data; B2b *runs* control methods. A method body is a
// TermList executed against a Frame (Arg0-6 / Local0-7). Expressions resolve
// via evalTermArg; statements (Store/If/While/Return/Notify) via execTermList.
// Arithmetic/logic opcodes collapse to two comptime tables so one code path
// covers Add…LLess rather than ~20 near-identical cases.
//
// Scope: integer/logic ops, If/Else/While, Store, method calls, scope-relative
// name resolution. OperationRegion/Field reads still yield uninit — that's B2c
// (the hardware bridge). A method that hits an unmodeled op stops cleanly with
// whatever it has returned so far; it never faults or desyncs the stream.

const MAX_CALL_DEPTH = 16;
const MAX_LOOP_ITERS = 100_000;

const Frame = struct {
    args: [7]Value = [_]Value{.uninit} ** 7,
    locals: [8]Value = [_]Value{.uninit} ** 8,
};

const ExecState = struct {
    frame: *Frame,
    scope: []const u8, // absolute path of the executing method, for name lookup
    depth: u8,
    ret: Value = .uninit,
    returned: bool = false,
    last_if_taken: bool = false,
    break_loop: bool = false,
};

fn toInt(v: Value) u64 {
    return switch (v) {
        .integer => |i| i,
        else => 0,
    };
}

fn toBool(v: Value) bool {
    return toInt(v) != 0;
}

fn boolVal(b: bool) u64 {
    return if (b) ~@as(u64, 0) else 0; // AML true = Ones, false = Zero
}

// --- arithmetic/logic opcode tables -----------------------------------------
// has_target: the op writes its result to a trailing Target (Add/And/…). The
// logical ops (LAnd/LEqual/…) take no Target.

const BinOp = struct { code: u16, has_target: bool, apply: *const fn (u64, u64) u64 };

fn aAdd(a: u64, b: u64) u64 {
    return a +% b;
}
fn aSub(a: u64, b: u64) u64 {
    return a -% b;
}
fn aMul(a: u64, b: u64) u64 {
    return a *% b;
}
fn aAnd(a: u64, b: u64) u64 {
    return a & b;
}
fn aOr(a: u64, b: u64) u64 {
    return a | b;
}
fn aXor(a: u64, b: u64) u64 {
    return a ^ b;
}
fn aShl(a: u64, b: u64) u64 {
    return if (b >= 64) 0 else a << @as(u6, @intCast(b));
}
fn aShr(a: u64, b: u64) u64 {
    return if (b >= 64) 0 else a >> @as(u6, @intCast(b));
}
fn aMod(a: u64, b: u64) u64 {
    return if (b == 0) 0 else a % b;
}
fn aLAnd(a: u64, b: u64) u64 {
    return boolVal(a != 0 and b != 0);
}
fn aLOr(a: u64, b: u64) u64 {
    return boolVal(a != 0 or b != 0);
}
fn aLEq(a: u64, b: u64) u64 {
    return boolVal(a == b);
}
fn aLGt(a: u64, b: u64) u64 {
    return boolVal(a > b);
}
fn aLLt(a: u64, b: u64) u64 {
    return boolVal(a < b);
}

const bin_table = [_]BinOp{
    .{ .code = 0x72, .has_target = true, .apply = aAdd }, // Add
    .{ .code = 0x74, .has_target = true, .apply = aSub }, // Subtract
    .{ .code = 0x77, .has_target = true, .apply = aMul }, // Multiply
    .{ .code = 0x79, .has_target = true, .apply = aShl }, // ShiftLeft
    .{ .code = 0x7A, .has_target = true, .apply = aShr }, // ShiftRight
    .{ .code = 0x7B, .has_target = true, .apply = aAnd }, // And
    .{ .code = 0x7D, .has_target = true, .apply = aOr }, // Or
    .{ .code = 0x7F, .has_target = true, .apply = aXor }, // Xor
    .{ .code = 0x85, .has_target = true, .apply = aMod }, // Mod
    .{ .code = 0x90, .has_target = false, .apply = aLAnd }, // LAnd
    .{ .code = 0x91, .has_target = false, .apply = aLOr }, // LOr
    .{ .code = 0x93, .has_target = false, .apply = aLEq }, // LEqual
    .{ .code = 0x94, .has_target = false, .apply = aLGt }, // LGreater
    .{ .code = 0x95, .has_target = false, .apply = aLLt }, // LLess
};

fn binLookup(code: u16) ?BinOp {
    inline for (bin_table) |o| {
        if (o.code == code) return o;
    }
    return null;
}

const UnOp = struct { code: u16, has_target: bool, apply: *const fn (u64) u64 };

fn aNot(a: u64) u64 {
    return ~a;
}
fn aLNot(a: u64) u64 {
    return boolVal(a == 0);
}

const un_table = [_]UnOp{
    .{ .code = 0x80, .has_target = true, .apply = aNot }, // Not
    .{ .code = 0x92, .has_target = false, .apply = aLNot }, // LNot (also prefixes LGE/LLE/LNE)
};

fn unLookup(code: u16) ?UnOp {
    inline for (un_table) |o| {
        if (o.code == code) return o;
    }
    return null;
}

// --- scope-relative name resolution (ACPI 6.4 §5.3) -------------------------

fn seedPath(pb: *PathBuf, scope: []const u8) void {
    const n = @min(scope.len, pb.buf.len);
    @memcpy(pb.buf[0..n], scope[0..n]);
    pb.len = n;
    if (pb.len == 0) {
        pb.buf[0] = '\\';
        pb.len = 1;
    }
}

/// Resolve a NameString referenced from `scope` to a stored node. A single
/// relative NameSeg searches the current scope and each ancestor up to root
/// (the AML upward-search rule); a rooted, parent-prefixed, or multi-seg name
/// is resolved anchored (no upward search).
fn resolve(scope: []const u8, ns: NameString) ?*StoredNode {
    if (ns.nsegs == 0) return null;
    var pb = PathBuf{};
    const single_relative = !ns.rooted and ns.parents == 0 and ns.nsegs == 1;
    if (!single_relative) {
        seedPath(&pb, scope);
        const mark = pb.enter(ns);
        const hit = findExact(pb.snapshot());
        pb.restore(mark);
        return hit;
    }
    seedPath(&pb, scope);
    while (true) {
        const mark = pb.enter(ns);
        if (findExact(pb.snapshot())) |n| {
            pb.restore(mark);
            return n;
        }
        pb.restore(mark);
        if (pb.len <= 1) return null; // tested root too
        pb.dropSegment();
    }
}

// --- expression evaluation --------------------------------------------------

/// Consume a SuperName operand (e.g. the Mutex object of Acquire/Release) without
/// evaluating it — just enough to keep the cursor aligned. Handles the forms a
/// lock target actually takes: a NameString, or a Local/Arg byte. Returns false
/// only on truncation/desync so the caller can bail cleanly.
fn skipSuperName(r: *Reader) bool {
    const lead = r.peek(0) orelse return false;
    if (lead >= 0x60 and lead <= 0x6E) { // Local0..7 / Arg0..6
        _ = r.next();
        return true;
    }
    return readNameString(r) != null;
}

/// Extended (0x5B-prefixed) opcodes in expression/statement position. The
/// synchronization ops are modeled as no-ops: acpid runs every GPE/AML handler
/// serially in a single thread, so a Mutex is always uncontended — Acquire
/// "succeeds" (returns 0 = no timeout) and Release does nothing. This lets real
/// firmware methods run *past* their lock: e.g. the PCI-hotplug \_GPE._E01
/// serializes on \_SB.PCI0.BLCK before touching the controller, then walks the
/// slots (PCIU/PCID field I/O) and Notifies. Any other extended opcode stays
/// unmodeled → null so the caller bails cleanly.
fn evalExtTerm(r: *Reader) ?Value {
    const ext = r.peek(1) orelse return null;
    switch (ext) {
        0x23 => { // AcquireOp SuperName WordData(timeout)
            _ = r.next(); // 0x5B (ExtOpPrefix)
            _ = r.next(); // 0x23 (AcquireOp)
            if (!skipSuperName(r)) return null;
            _ = r.next(); // timeout lo
            _ = r.next(); // timeout hi (WordData, a raw literal — not a TermArg)
            return .{ .integer = 0 }; // 0 ⇒ acquired, no timeout
        },
        0x27 => { // ReleaseOp SuperName
            _ = r.next(); // 0x5B (ExtOpPrefix)
            _ = r.next(); // 0x27 (ReleaseOp)
            if (!skipSuperName(r)) return null;
            return .uninit;
        },
        else => return null, // unmodeled extended op — bail cleanly
    }
}

fn evalTermArg(r: *Reader, st: *ExecState) ?Value {
    const op = r.peek(0) orelse return null;
    switch (op) {
        0x60...0x67 => { // Local0..7
            _ = r.next();
            return st.frame.locals[@as(usize, op) - 0x60];
        },
        0x68...0x6E => { // Arg0..6
            _ = r.next();
            return st.frame.args[@as(usize, op) - 0x68];
        },
        0x70 => { // Store used as an expression: yields the stored value
            _ = r.next();
            const src = evalTermArg(r, st) orelse return null;
            _ = storeTarget(r, st, src);
            return src;
        },
        0x78 => return evalDivide(r, st),
        0x75, 0x76 => return evalIncDec(r, st, op),
        0x5B => return evalExtTerm(r), // extended opcodes (Acquire/Release/…)
        else => {
            if (binLookup(op)) |bi| return evalBinary(r, st, bi);
            if (unLookup(op)) |ui| return evalUnary(r, st, ui);
            if (op == 0x88) return evalIndexExpr(r, st); // Index (best-effort)
            if (op == 0x83) return evalDerefExpr(r, st); // DerefOf (best-effort)
            if (isNameLead(op)) return evalNameRef(r, st);
            return evalData(r); // literal / Buffer / Package
        },
    }
}

fn evalBinary(r: *Reader, st: *ExecState, bi: BinOp) ?Value {
    _ = r.next(); // opcode
    const a = toInt(evalTermArg(r, st) orelse return null);
    const b = toInt(evalTermArg(r, st) orelse return null);
    const res = bi.apply(a, b);
    if (bi.has_target) {
        if (!storeTarget(r, st, .{ .integer = res })) return null;
    }
    return .{ .integer = res };
}

fn evalUnary(r: *Reader, st: *ExecState, ui: UnOp) ?Value {
    _ = r.next(); // opcode
    const a = toInt(evalTermArg(r, st) orelse return null);
    const res = ui.apply(a);
    if (ui.has_target) {
        if (!storeTarget(r, st, .{ .integer = res })) return null;
    }
    return .{ .integer = res };
}

fn evalDivide(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // DivideOp: Dividend Divisor Remainder Quotient
    const a = toInt(evalTermArg(r, st) orelse return null);
    const b = toInt(evalTermArg(r, st) orelse return null);
    const q = if (b == 0) 0 else a / b;
    const rem = if (b == 0) 0 else a % b;
    if (!storeTarget(r, st, .{ .integer = rem })) return null;
    if (!storeTarget(r, st, .{ .integer = q })) return null;
    return .{ .integer = q };
}

fn evalIncDec(r: *Reader, st: *ExecState, op: u8) ?Value {
    _ = r.next(); // Increment/Decrement: SuperName (read-modify-write)
    const tpos = r.pos;
    const cur = toInt(evalTermArg(r, st) orelse return null);
    const nv = if (op == 0x75) cur +% 1 else cur -% 1;
    const after = r.pos;
    r.pos = tpos;
    _ = storeTarget(r, st, .{ .integer = nv });
    r.pos = after;
    return .{ .integer = nv };
}

fn evalIndexExpr(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // IndexOp: Source Index Target
    _ = evalTermArg(r, st) orelse return null;
    _ = evalTermArg(r, st) orelse return null;
    _ = storeTarget(r, st, .uninit);
    return .uninit; // element references are B2c
}

fn evalDerefExpr(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // DerefOfOp
    _ = evalTermArg(r, st) orelse return null;
    return .uninit;
}

/// A NameString in expression position: a method invocation (consume its args)
/// or a reference to a Name (yield its value). Unresolved / non-value objects
/// yield uninit so a method keeps running.
fn evalNameRef(r: *Reader, st: *ExecState) ?Value {
    const ns = readNameString(r) orelse return null;
    const node = resolve(st.scope, ns) orelse return .uninit;
    switch (node.kind) {
        .method => {
            var args: [7]Value = [_]Value{.uninit} ** 7;
            var i: usize = 0;
            while (i < @as(usize, node.arg_count) and i < 7) : (i += 1) {
                args[i] = evalTermArg(r, st) orelse .uninit;
            }
            return callMethod(node, args[0 .. @min(@as(usize, node.arg_count), 7)], st.depth + 1);
        },
        .name => {
            if (node.has_runtime) return node.runtime_val;
            var rr = Reader{ .buf = dsdt_body, .pos = node.val_off };
            return evalData(&rr) orelse .uninit;
        },
        .field => { // B2c: read the backing hardware
            if (readField(node)) |fv| return .{ .integer = fv };
            return .uninit;
        },
        else => return .uninit, // op_region/device → not a value
    }
}

// --- Target writes ----------------------------------------------------------

fn storeTarget(r: *Reader, st: *ExecState, v: Value) bool {
    const op = r.peek(0) orelse return false;
    switch (op) {
        0x00 => { // Null target — discard
            _ = r.next();
            return true;
        },
        0x60...0x67 => {
            _ = r.next();
            st.frame.locals[@as(usize, op) - 0x60] = v;
            return true;
        },
        0x68...0x6E => {
            _ = r.next();
            st.frame.args[@as(usize, op) - 0x68] = v;
            return true;
        },
        else => {
            if (isNameLead(op)) {
                const ns = readNameString(r) orelse return false;
                if (resolve(st.scope, ns)) |n| {
                    switch (n.kind) {
                        .name => {
                            n.runtime_val = v;
                            n.has_runtime = true;
                        },
                        .field => _ = writeField(n, toInt(v)), // B2c: write hardware
                        else => {},
                    }
                }
                return true;
            }
            // Index()/DerefOf() target: consume as an expression, best-effort.
            return evalTermArg(r, st) != null;
        },
    }
}

// --- statement execution ----------------------------------------------------

fn execTermList(r: *Reader, end: usize, st: *ExecState) void {
    while (r.pos < end and !st.returned and !st.break_loop) {
        const op = r.peek(0) orelse return;
        switch (op) {
            0x70 => { // Store SourceTermArg Target
                _ = r.next();
                const src = evalTermArg(r, st) orelse return;
                _ = storeTarget(r, st, src);
            },
            0xA0 => execIf(r, st),
            0xA1 => execElse(r, st),
            0xA2 => execWhile(r, st),
            0xA4 => { // Return
                _ = r.next();
                st.ret = evalTermArg(r, st) orelse .uninit;
                st.returned = true;
                return;
            },
            0xA5 => { // Break
                _ = r.next();
                st.break_loop = true;
                return;
            },
            0x9F => { // Continue (simplified: end this list pass)
                _ = r.next();
                return;
            },
            0xA3 => { // Noop
                _ = r.next();
            },
            0x86 => execNotify(r, st),
            else => {
                // An expression / method call evaluated for side effect.
                const before = r.pos;
                if (evalTermArg(r, st)) |_| {
                    if (r.pos == before) _ = r.next(); // guarantee forward progress
                } else {
                    return; // unmodeled term — stop this list cleanly
                }
            },
        }
    }
}

fn execIf(r: *Reader, st: *ExecState) void {
    const start = r.pos;
    _ = r.next(); // IfOp
    const pkg_end = packageEnd(r, start) orelse {
        st.returned = true; // can't bound the package → stop safely
        return;
    };
    const pred = evalTermArg(r, st) orelse {
        r.pos = pkg_end;
        st.last_if_taken = false;
        return;
    };
    if (toBool(pred)) {
        execTermList(r, pkg_end, st);
        st.last_if_taken = true;
    } else {
        st.last_if_taken = false;
    }
    if (r.pos < pkg_end) r.pos = pkg_end;
}

fn execElse(r: *Reader, st: *ExecState) void {
    const start = r.pos;
    _ = r.next(); // ElseOp
    const pkg_end = packageEnd(r, start) orelse {
        st.returned = true;
        return;
    };
    if (!st.last_if_taken) execTermList(r, pkg_end, st);
    st.last_if_taken = false;
    if (r.pos < pkg_end) r.pos = pkg_end;
}

fn execWhile(r: *Reader, st: *ExecState) void {
    const start = r.pos;
    _ = r.next(); // WhileOp
    const pkg_end = packageEnd(r, start) orelse {
        st.returned = true;
        return;
    };
    const cond_start = r.pos;
    var iters: u32 = 0;
    while (iters < MAX_LOOP_ITERS) : (iters += 1) {
        r.pos = cond_start;
        const pred = evalTermArg(r, st) orelse break;
        if (!toBool(pred)) break;
        execTermList(r, pkg_end, st);
        if (st.returned) return;
        if (st.break_loop) {
            st.break_loop = false;
            break;
        }
    }
    r.pos = pkg_end;
}

/// Hook invoked for every executed Notify(object, value). The integrator
/// (main.zig) registers one to react to ACPI device notifications without this
/// leaf AML module having to know about drivers: PCI hotplug (Bus/Device Check
/// 0x00/0x01, Eject 0x03 → pci.rescan), thermal/battery (0x80, Slice D), etc.
/// Runs in acpid thread context (Notify only executes inside a GPE handler).
pub const NotifyFn = *const fn (obj_path: []const u8, value: u64) void;
var notify_hook: ?NotifyFn = null;
pub fn setNotifyHook(f: NotifyFn) void {
    notify_hook = f;
}

fn execNotify(r: *Reader, st: *ExecState) void {
    _ = r.next(); // NotifyOp: NotifyObject NotifyValue
    const obj_op = r.peek(0) orelse return;
    var obj_path: []const u8 = "?";
    if (isNameLead(obj_op)) {
        const ns = readNameString(r) orelse return;
        if (resolve(st.scope, ns)) |n| obj_path = n.path[0..n.path_len];
    } else {
        _ = evalTermArg(r, st); // Local/Arg holding a reference
    }
    const val = evalTermArg(r, st) orelse .uninit;
    const v = toInt(val);
    debug.klog("[aml] Notify({s}, 0x{X})\n", .{ obj_path, v });
    if (notify_hook) |h| h(obj_path, v);
}

// --- method invocation ------------------------------------------------------

/// Invoke a stored Method node with `args`. Returns its Return value (uninit if
/// it falls off the end). Depth-guarded against runaway recursion.
fn callMethod(node: *StoredNode, args: []const Value, depth: u8) ?Value {
    if (depth > MAX_CALL_DEPTH) return null;
    if (node.kind != .method or dsdt_body.len == 0) return null;
    var frame = Frame{};
    var i: usize = 0;
    while (i < args.len and i < 7) : (i += 1) frame.args[i] = args[i];
    var st = ExecState{ .frame = &frame, .scope = node.path[0..node.path_len], .depth = depth };
    var r = Reader{ .buf = dsdt_body, .pos = node.val_off };
    const end = @min(node.val_off + node.val_len, dsdt_body.len);
    execTermList(&r, end, &st);
    return st.ret;
}

/// Evaluate a no-argument control method by absolute path (e.g.
/// "\\_SB_.PCI0._PRT"). Public entry for GPE dispatch (Slice C) + diagnostics.
pub fn evalMethod(abs: []const u8) ?Value {
    const n = findExact(abs) orelse return null;
    if (n.kind != .method) return null;
    arenaReset();
    return callMethod(n, &.{}, 0);
}

/// Find the AML handler method for GPE bit `n` of block 0: `\_GPE._E<nn>` (edge)
/// or `\_GPE._L<nn>` (level), where nn is the two uppercase hex digits of n.
/// Returns the method's absolute path (into the static store) and sets
/// `is_level.*`. Null if neither method exists. (Slice C uses this to decide
/// which GPEs to enable and which method to run when one fires.)
pub fn gpeHandler(n: u8, is_level: *bool) ?[]const u8 {
    const hex = "0123456789ABCDEF";
    var buf = [_]u8{ '\\', '_', 'G', 'P', 'E', '.', '_', 'E', 0, 0 };
    buf[8] = hex[(n >> 4) & 0xF];
    buf[9] = hex[n & 0xF];
    if (findExact(&buf)) |node| {
        if (node.kind == .method) {
            is_level.* = false;
            return node.path[0..node.path_len];
        }
    }
    buf[7] = 'L'; // _L<nn>
    if (findExact(&buf)) |node| {
        if (node.kind == .method) {
            is_level.* = true;
            return node.path[0..node.path_len];
        }
    }
    return null;
}

/// Run the GPE handler for bit `n` (block 0) if one exists; true if it ran.
/// MUST be called from thread context — it evaluates AML (field I/O, Notify),
/// which is unsafe in the SCI IRQ.
pub fn runGpeHandler(n: u8) bool {
    var lvl: bool = false;
    const path = gpeHandler(n, &lvl) orelse return false;
    _ = evalMethod(path);
    return true;
}

/// Deterministic executor self-test, independent of firmware: run the AML for
/// `Add(2, 3) -> Local0; Return(Local0)` and expect 5. Proves operand decode, a
/// binary op writing a Target, Local store/load, and Return.
fn selfTest() void {
    const prog = [_]u8{ 0x72, 0x0A, 0x02, 0x0A, 0x03, 0x60, 0xA4, 0x60 };
    var frame = Frame{};
    var st = ExecState{ .frame = &frame, .scope = "\\", .depth = 0 };
    var r = Reader{ .buf = &prog };
    arenaReset();
    execTermList(&r, prog.len, &st);
    const got = toInt(st.ret);
    debug.klog("[aml] executor self-test Add(2,3)->Local0; Return(Local0) = {d} ({s})\n", .{ got, if (got == 5) "PASS" else "FAIL" });
}

// === B2c: OperationRegion / Field hardware I/O ==============================
// A Field declares named bit-slices over an OperationRegion. B2c parses the
// FieldList into .field nodes (parent region + bit offset/width/access) and
// reads/writes the backing hardware: SystemIO (port in/out) and SystemMemory
// (physmap). PCI_Config is deferred (needs the enclosing device's _ADR/_BBN).
// Field reads wire into evalNameRef; writes into storeTarget. Every access is
// bounds-/mapping-checked — a bad region degrades to uninit, never a fault.

const SPACE_MEM: u8 = 0;
const SPACE_IO: u8 = 1;
const SPACE_PCI: u8 = 2;

fn nodeIndexOf(n: *StoredNode) usize {
    return (@intFromPtr(n) - @intFromPtr(&nodes[0])) / @sizeOf(StoredNode);
}

/// Parse a FieldList in [r.pos, end), creating a .field node per NamedField in
/// `path`, tracking the running bit offset and the current AccessType.
fn parseFieldList(r: *Reader, end: usize, path: *PathBuf, region_idx: i32, access0: u8, depth: u8) void {
    var bit_off: u32 = 0;
    var access = access0;
    while (r.pos < end) {
        const lead = r.peek(0) orelse return;
        switch (lead) {
            0x00 => { // ReservedField: 0x00 PkgLength (= bit width)
                _ = r.next();
                const pl = readPkgLength(r) orelse return;
                bit_off +%= @truncate(pl.value);
            },
            0x01 => { // AccessField: 0x01 AccessType AccessAttrib
                _ = r.next();
                const at = r.next() orelse return;
                _ = r.next(); // AccessAttrib
                access = at & 0x0F;
            },
            0x02 => return, // ConnectField (GPIO/SerialBus): hard to bound — stop list
            0x03 => { // ExtendedAccessField: 0x03 AccessType ExtAttrib AccessLength
                _ = r.next();
                const at = r.next() orelse return;
                _ = r.next();
                _ = r.next();
                access = at & 0x0F;
            },
            else => { // NamedField: NameSeg(4) PkgLength (= bit width)
                if (r.rem() < 4) return;
                var seg: [4]u8 = undefined;
                seg[0] = r.next().?;
                seg[1] = r.next().?;
                seg[2] = r.next().?;
                seg[3] = r.next().?;
                if (!(seg[0] == '_' or (seg[0] >= 'A' and seg[0] <= 'Z'))) return; // desync guard
                const pl = readPkgLength(r) orelse return;
                const width: u32 = @truncate(pl.value);
                var ns = NameString{ .rooted = false, .parents = 0, .segs = undefined, .nsegs = 1 };
                ns.segs[0] = seg;
                record(.field, path, ns, depth);
                storeNode(.field, path, ns, .{
                    .field_region = region_idx,
                    .field_bit_off = bit_off,
                    .field_bit_width = width,
                    .field_access = access,
                });
                bit_off +%= width;
            },
        }
    }
}

fn accessWidthBytes(access: u8) u32 {
    return switch (access) {
        1 => 1, // ByteAcc
        2 => 2, // WordAcc
        3 => 4, // DWordAcc
        4 => 8, // QWordAcc
        else => 1, // AnyAcc / BufferAcc / unknown → byte
    };
}

fn physMapped(phys: u64, len: u64) bool {
    if (phys == 0 or len == 0) return false;
    if (phys > paging.PHYSMAP_SIZE or len > paging.PHYSMAP_SIZE - phys) return false;
    return paging.isMapped(paging.physToVirt(phys));
}

/// Read one access-width unit (1/2/4/8 bytes) from a region at a byte offset.
fn readRegionUnit(region: *const StoredNode, byte_off: u64, width: u32) ?u64 {
    switch (region.region_space) {
        SPACE_IO => {
            const base = region.region_off + byte_off;
            if (base > 0xFFFF) return null;
            const port: u16 = @intCast(base);
            return switch (width) {
                1 => io.inb(port),
                2 => io.inw(port),
                4 => io.inl(port),
                8 => @as(u64, io.inl(port)) | (@as(u64, io.inl(port +% 4)) << 32),
                else => null,
            };
        },
        SPACE_MEM => {
            const phys = region.region_off + byte_off;
            if (!physMapped(phys, width)) return null;
            const va = paging.physToVirt(phys);
            return switch (width) {
                1 => @as(*align(1) const u8, @ptrFromInt(va)).*,
                2 => @as(*align(1) const u16, @ptrFromInt(va)).*,
                4 => @as(*align(1) const u32, @ptrFromInt(va)).*,
                8 => @as(*align(1) const u64, @ptrFromInt(va)).*,
                else => null,
            };
        },
        else => return null, // PCI_Config + others: deferred
    }
}

fn writeRegionUnit(region: *const StoredNode, byte_off: u64, width: u32, val: u64) bool {
    switch (region.region_space) {
        SPACE_IO => {
            const base = region.region_off + byte_off;
            if (base > 0xFFFF) return false;
            const port: u16 = @intCast(base);
            switch (width) {
                1 => io.outb(port, @truncate(val)),
                2 => io.outw(port, @truncate(val)),
                4 => io.outl(port, @truncate(val)),
                8 => {
                    io.outl(port, @truncate(val));
                    io.outl(port +% 4, @truncate(val >> 32));
                },
                else => return false,
            }
            return true;
        },
        SPACE_MEM => {
            const phys = region.region_off + byte_off;
            if (!physMapped(phys, width)) return false;
            const va = paging.physToVirt(phys);
            switch (width) {
                1 => @as(*align(1) u8, @ptrFromInt(va)).* = @truncate(val),
                2 => @as(*align(1) u16, @ptrFromInt(va)).* = @truncate(val),
                4 => @as(*align(1) u32, @ptrFromInt(va)).* = @truncate(val),
                8 => @as(*align(1) u64, @ptrFromInt(va)).* = val,
                else => return false,
            }
            return true;
        },
        else => return false,
    }
}

/// Read a scalar field (≤ 64 bits) by assembling the access-width units it
/// spans and extracting its bit-slice. Null for unsupported widths, unresolved
/// regions, or an access window too wide to fit a u64.
fn readField(field: *const StoredNode) ?u64 {
    if (field.field_region < 0) return null;
    const ridx: usize = @intCast(field.field_region);
    if (ridx >= nnodes) return null;
    const region = &nodes[ridx];
    const width = field.field_bit_width;
    if (width == 0 or width > 64) return null;
    const ab = accessWidthBytes(field.field_access);
    const abits = ab * 8;
    const first_unit = field.field_bit_off / abits;
    const last_unit = (field.field_bit_off + width - 1) / abits;
    const n_units = last_unit - first_unit + 1;
    if (n_units * abits > 64) return null;
    var raw: u64 = 0;
    var u: u32 = 0;
    while (u < n_units) : (u += 1) {
        const unit_byte = @as(u64, first_unit + u) * @as(u64, ab);
        const v = readRegionUnit(region, unit_byte, ab) orelse return null;
        raw |= v << @as(u6, @intCast(u * abits));
    }
    const shift: u32 = field.field_bit_off - first_unit * abits;
    const shifted = raw >> @as(u6, @intCast(shift));
    if (width >= 64) return shifted;
    return shifted & ((@as(u64, 1) << @as(u6, @intCast(width))) - 1);
}

/// Write a scalar field (≤ 64 bits), preserving surrounding bits (Preserve
/// UpdateRule) via read-modify-write across the spanned access units.
fn writeField(field: *const StoredNode, value: u64) bool {
    if (field.field_region < 0) return false;
    const ridx: usize = @intCast(field.field_region);
    if (ridx >= nnodes) return false;
    const region = &nodes[ridx];
    const width = field.field_bit_width;
    if (width == 0 or width > 64) return false;
    const ab = accessWidthBytes(field.field_access);
    const abits = ab * 8;
    const first_unit = field.field_bit_off / abits;
    const last_unit = (field.field_bit_off + width - 1) / abits;
    const n_units = last_unit - first_unit + 1;
    if (n_units * abits > 64) return false;
    const shift: u32 = field.field_bit_off - first_unit * abits;
    const field_mask: u64 = if (width >= 64) ~@as(u64, 0) else (@as(u64, 1) << @as(u6, @intCast(width))) - 1;
    const window_mask = field_mask << @as(u6, @intCast(shift));
    var cur: u64 = 0;
    var u: u32 = 0;
    while (u < n_units) : (u += 1) {
        const unit_byte = @as(u64, first_unit + u) * @as(u64, ab);
        const v = readRegionUnit(region, unit_byte, ab) orelse return false;
        cur |= v << @as(u6, @intCast(u * abits));
    }
    cur = (cur & ~window_mask) | ((value & field_mask) << @as(u6, @intCast(shift)));
    const unit_mask: u64 = if (abits >= 64) ~@as(u64, 0) else (@as(u64, 1) << @as(u6, @intCast(abits))) - 1;
    u = 0;
    while (u < n_units) : (u += 1) {
        const unit_byte = @as(u64, first_unit + u) * @as(u64, ab);
        const piece = (cur >> @as(u6, @intCast(u * abits))) & unit_mask;
        if (!writeRegionUnit(region, unit_byte, ab, piece)) return false;
    }
    return true;
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

    // B2b proof: run the executor. First a deterministic self-test, then invoke
    // a real firmware control method (\_SB_.PCI0._PRT: If/Else on \PICF returning
    // a PCI-routing Package) to exercise method calls + control flow end to end.
    selfTest();
    if (evalMethod("\\_SB_.PCI0._PRT")) |rv| {
        switch (rv) {
            .package => |p| debug.klog("[aml] invoked \\_SB_.PCI0._PRT -> Package[{d}] (PCI IRQ routing)\n", .{p.len}),
            .integer => |iv| debug.klog("[aml] invoked \\_SB_.PCI0._PRT -> integer {d}\n", .{iv}),
            else => debug.klog("[aml] invoked \\_SB_.PCI0._PRT -> (unhandled result type)\n", .{}),
        }
    } else {
        debug.klog("[aml] \\_SB_.PCI0._PRT not found / not invokable\n", .{});
    }

    // B2c proof: report parsed field elements and read one live hardware field
    // (the first SystemIO field — a port `in`, side-effect-free on these ACPI
    // status registers). Proves FieldList parse + region access end to end.
    var nfields: u32 = 0;
    var first_io: ?usize = null;
    var fi: usize = 0;
    while (fi < nnodes) : (fi += 1) {
        if (nodes[fi].kind == .field and nodes[fi].field_region >= 0) {
            nfields += 1;
            if (first_io == null) {
                const ridx: usize = @intCast(nodes[fi].field_region);
                if (ridx < nnodes and nodes[ridx].region_space == SPACE_IO) first_io = fi;
            }
        }
    }
    debug.klog("[aml] parsed {d} field elements over OperationRegions\n", .{nfields});
    if (first_io) |idx| {
        const f = &nodes[idx];
        const region = &nodes[@as(usize, @intCast(f.field_region))];
        if (readField(f)) |val| {
            debug.klog("[aml] live field read {s} @ SystemIO 0x{X}+{d}b w{d} = 0x{X}\n", .{ f.path[0..f.path_len], region.region_off, f.field_bit_off, f.field_bit_width, val });
        } else {
            debug.klog("[aml] live field read {s}: unsupported\n", .{f.path[0..f.path_len]});
        }
    }
    return node_count;
}
