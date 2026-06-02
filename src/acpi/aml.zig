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
    string: []const u8, // immutable: into the table body, or into the byte arena
    buffer: []const u8, // read view; runtime/mutable buffers live in the byte arena
    package: []Value, // mutable elements (value arena) so Index() can write through
    name_ref: [4]u8, // a NamePath used as data (e.g. a _PRT source link) — its last NameSeg
    ref: Ref, // an lvalue: Index()/RefOf()/CreateField result (a writable location)
};

/// A writable reference — the AML "reference" object produced by Index(),
/// RefOf() and the CreateField family. DerefOf reads through it; Store writes
/// through it. The buffer variants point into the byte arena (mutable storage),
/// so a write to one is visible to every alias of the same underlying object.
pub const Ref = union(enum) {
    buf_byte: struct { buf: []u8, idx: usize }, // Index(Buffer/String, i) → one byte
    pkg_elem: struct { pkg: []Value, idx: usize }, // Index(Package, i) → one element slot
    buf_field: struct { buf: []u8, bit_off: u32, bit_width: u32 }, // CreateField window (A2)
    node: usize, // RefOf(Name/Field) → a nodes[] index
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
    /// Which loaded table (DSDT=0, SSDTs=1..) this node's byte offsets index, so
    /// the evaluator reads val_off/val_len from the right table body (Slice D).
    table_id: u8 = 0,
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
    // A1/A2: this Name is a CreateField buffer-field window (runtime_val holds a
    // .ref => .buf_field). Reads/writes auto-deref through it instead of
    // replacing it. Created dynamically at exec time (beyond static_nnodes).
    is_buffer_field: bool = false,
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
/// Count of nodes from the static namespace walk. CreateField creates nodes
/// dynamically at exec time (nnodes grows past this); each top-level arenaReset
/// truncates back to here, so dynamic buffer-field windows live exactly one
/// method-call tree — the same lifetime as the byte arena they point into.
var static_nnodes: usize = 0;

/// Loaded AML table bodies, indexed by StoredNode.table_id. The DSDT is table 0;
/// SSDTs (and the synthetic test table) follow. Evaluator helpers build their
/// Readers over bodies[node.table_id], so a node's byte offsets always index the
/// table it was decoded from — the multi-table generalization of what used to be
/// a single `dsdt_body`.
const MAX_TABLES = 24;
var bodies: [MAX_TABLES][]const u8 = [_][]const u8{&[_]u8{}} ** MAX_TABLES;
var nbodies: u8 = 0;
/// Stamped onto every node storeNode() records; set before each table's walk
/// (walkBody) so nodes inherit the body they came from.
var cur_table_id: u8 = 0;

/// The AML body a stored node's offsets index into (its source table).
fn bodyOf(n: *const StoredNode) []const u8 {
    return if (n.table_id < nbodies) bodies[n.table_id] else &[_]u8{};
}

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
        .table_id = cur_table_id,
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

/// One NVDIMM-root discovery result: the device's namespace path plus which of
/// the firmware control methods are present. Consumed by the NVDIMM driver
/// (mm/pmem.zig).
pub const NvdimmInfo = struct {
    path: []const u8, // into the StoredNode path buffer (stable module storage)
    has_fit: bool,
    has_dsm: bool,
    has_ncal: bool,
};

/// True if the namespace holds an object at "<dev_path>.<seg>". Probes for a
/// control method WITHOUT evaluating it — evaluating _FIT would fire the QEMU
/// DSM mailbox; here we only want presence.
fn childExists(dev_path: []const u8, seg: []const u8) bool {
    var buf: [128]u8 = undefined;
    if (dev_path.len + 1 + seg.len > buf.len) return false;
    @memcpy(buf[0..dev_path.len], dev_path);
    buf[dev_path.len] = '.';
    @memcpy(buf[dev_path.len + 1 ..][0..seg.len], seg);
    return findExact(buf[0 .. dev_path.len + 1 + seg.len]) != null;
}

/// Find the NVDIMM root device — the Device with _HID "ACPI0012" — and report
/// whether its _FIT / _DSM / NCAL control methods are present. The AML-side
/// half of NVDIMM discovery: the static NFIT gives the memory geometry, this
/// confirms the firmware's dynamic (DSM-mailbox) interface exists.
pub fn nvdimmInfo() ?NvdimmInfo {
    var i: usize = 0;
    while (i < nnodes) : (i += 1) {
        const n = &nodes[i];
        if (n.kind != .device) continue;
        const path = n.path[0..n.path_len];
        const hid = evalDeviceChild(path, "_HID") orelse continue;
        if (hid != .string) continue;
        if (!std.mem.eql(u8, hid.string, "ACPI0012")) continue;
        return .{
            .path = path,
            .has_fit = childExists(path, "_FIT"),
            .has_dsm = childExists(path, "_DSM"),
            .has_ncal = childExists(path, "NCAL"),
        };
    }
    return null;
}

// --- value arena ------------------------------------------------------------
// Packages need backing storage for their element Values. A fixed bump arena,
// reset before each top-level evaluation, avoids an allocator on the AML path.

const VALUE_ARENA = 4096;
var value_arena: [VALUE_ARENA]Value = undefined;
var arena_top: usize = 0;

fn arenaAlloc(n: usize) ?[]Value {
    if (arena_top + n > value_arena.len) return null;
    const s = value_arena[arena_top .. arena_top + n];
    arena_top += n;
    return s;
}

// --- byte arena (mutable buffer/string storage) -----------------------------
// Runtime buffers (Buffer(n){}, Concatenate/ToBuffer results, wide field reads)
// and the windows CreateField carves over them need WRITABLE backing the table
// body can't provide. The byte arena is that storage: a bump allocator reset
// per top-level evaluation alongside the value arena. A buffer Value pointing
// into this arena is mutable; one pointing into a table body is read-only. The
// rule that makes Index()/CreateField aliasing correct: every object created or
// mutated during a single method-call tree lives here and shares its lifetime.

const BYTE_ARENA = 8192;
var byte_arena: [BYTE_ARENA]u8 = undefined;
var byte_top: usize = 0;

fn bufAlloc(n: usize) ?[]u8 {
    if (byte_top + n > byte_arena.len) return null;
    const s = byte_arena[byte_top .. byte_top + n];
    byte_top += n;
    return s;
}

/// True if a slice lives in the writable byte arena (⇒ its bytes are mutable).
fn inByteArena(b: []const u8) bool {
    if (b.len == 0) return false;
    const base = @intFromPtr(&byte_arena[0]);
    const p = @intFromPtr(b.ptr);
    return p >= base and p < base + byte_arena.len;
}

/// The mutable view of an arena-backed buffer, or null if it's a table literal.
fn mutBuf(b: []const u8) ?[]u8 {
    if (!inByteArena(b)) return null;
    const base = @intFromPtr(&byte_arena[0]);
    const off = @intFromPtr(b.ptr) - base;
    return byte_arena[off .. off + b.len];
}

/// Ensure `b` is arena-backed + writable, copying a table literal in first.
/// Returns the mutable view, or null only if the arena is exhausted.
fn materializeBuf(b: []const u8) ?[]u8 {
    if (mutBuf(b)) |m| return m;
    const m = bufAlloc(b.len) orelse return null;
    @memcpy(m, b);
    return m;
}

/// Allocate a fresh zeroed arena buffer of `n` bytes.
fn newBuf(n: usize) ?[]u8 {
    const m = bufAlloc(n) orelse return null;
    @memset(m, 0);
    return m;
}

// --- arena reset (per top-level evaluation) ---------------------------------
// Called at every public entry (evalMethod, reportThermal, buildPrt, the load()
// proofs, the self-tests). Resets both arenas, then invalidates any cached
// runtime Name value that points into the (now-recycled) arenas — a stale
// buffer/package/ref would dangle. Integer/string runtime values survive, so a
// Name written by one method (e.g. \PICF set by _PIC, read later by _PRT) keeps
// its value across calls; only arena-backed objects are dropped.
fn arenaReset() void {
    arena_top = 0;
    byte_top = 0;
    if (nnodes > static_nnodes) nnodes = static_nnodes; // drop dynamic CreateField nodes
    var i: usize = 0;
    while (i < nnodes) : (i += 1) {
        if (!nodes[i].has_runtime) continue;
        switch (nodes[i].runtime_val) {
            .buffer, .package, .ref => {
                nodes[i].has_runtime = false;
                nodes[i].runtime_val = .uninit;
                nodes[i].is_buffer_field = false;
            },
            else => {},
        }
    }
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
            // A NameString reference used as data (e.g. a _PRT entry's source
            // naming a PCI interrupt-link device). Capture its last NameSeg so
            // consumers can resolve the reference; non-name leads are unmodeled.
            if (isNameLead(op)) {
                const ns = readNameString(r) orelse return null;
                if (ns.nsegs > 0) return .{ .name_ref = ns.segs[ns.nsegs - 1] };
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
    if (nbodies == 0) return null;
    const n = findExact("\\_S5_") orelse return null;
    arenaReset();
    var r = Reader{ .buf = bodyOf(n), .pos = n.val_off };
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
    continue_loop: bool = false, // Continue: unwind to the enclosing While's condition
};

fn toInt(v: Value) u64 {
    return switch (v) {
        .integer => |i| i,
        .ref => |rf| toInt(readThroughRef(rf)), // an Index/RefOf result used as an integer auto-derefs
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
fn evalExtTerm(r: *Reader, st: *ExecState) ?Value {
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
        0x13 => { // CreateFieldOp Source BitIndex NumBits Name (arbitrary width)
            _ = r.next(); // 0x5B
            _ = r.next(); // 0x13
            const src = evalTermArg(r, st) orelse return null;
            const bit_index = toInt(evalTermArg(r, st) orelse return null);
            const num_bits = toInt(evalTermArg(r, st) orelse return null);
            const ns = readNameString(r) orelse return null;
            return bindBufferField(st, ns, src, @intCast(bit_index & 0xFFFF_FFFF), @intCast(num_bits & 0xFFFF_FFFF));
        },
        0x21, 0x22 => { // Stall(usec) / Sleep(msec): consume the TermArg, no-op.
            _ = r.next(); // 0x5B
            _ = r.next(); // 0x21 / 0x22
            _ = evalTermArg(r, st); // acpid runs serially and the QEMU mailbox is
            return .uninit; // synchronous, so pacing delays are unnecessary here.
        },
        else => return null, // unmodeled extended op — bail cleanly
    }
}

/// _OSI(InterfaceString): the OS-supplied interface query. Firmware gates code
/// paths on it; we answer like a current Windows so the DSDT runs its modern
/// branches. Ones ⇒ supported, Zero ⇒ not. (Intercepted by name, since _OSI is
/// not a DSDT object.)
fn osiVerdict(arg: Value) u64 {
    const s = switch (derefValue(arg)) {
        .string => |x| x,
        else => return 0,
    };
    const known = [_][]const u8{
        "Windows", // Windows 2000
        "Windows 2001",    "Windows 2001 SP1", "Windows 2001 SP2", "Windows 2001 SP3",
        "Windows 2001.1",  "Windows 2001.1 SP1", "Windows 2006",   "Windows 2006 SP1",
        "Windows 2006.1",  "Windows 2009",     "Windows 2012",     "Windows 2013",
        "Windows 2015",    "Windows 2016",     "Windows 2017",     "Windows 2017.2",
        "Windows 2018",    "Windows 2018.2",   "Windows 2019",     "Windows 2020",
        "Windows 2021",    "Windows 2022",
    };
    for (known) |k| {
        if (std.mem.eql(u8, s, k)) return ~@as(u64, 0);
    }
    return 0;
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
        0x11 => return evalBufferRuntime(r, st), // Buffer(): arena-backed (mutable)
        0x87 => return evalSizeOf(r, st), // SizeOf
        0x88 => return evalIndexExpr(r, st), // Index → reference
        0x83 => return evalDerefExpr(r, st), // DerefOf
        0x71 => return evalRefOf(r, st), // RefOf → reference
        0x8A, 0x8B, 0x8C, 0x8D, 0x8F => return evalCreateField(r, st, op), // CreateDWord/Word/Byte/Bit/QWordField
        0x73 => return evalConcat(r, st), // Concatenate
        0x96 => return evalToBuffer(r, st), // ToBuffer
        0x99 => return evalToInteger(r, st), // ToInteger
        0x98 => return evalToHexString(r, st), // ToHexString
        0x9C => return evalToString(r, st), // ToString
        0x9E => return evalMid(r, st), // Mid
        0x8E => return evalObjectType(r, st), // ObjectType
        0x9D => return evalCopyObject(r, st), // CopyObject
        0x5B => return evalExtTerm(r, st), // extended opcodes (Acquire/Release/CreateField/…)
        else => {
            if (binLookup(op)) |bi| return evalBinary(r, st, bi);
            if (unLookup(op)) |ui| return evalUnary(r, st, ui);
            if (isNameLead(op)) return evalNameRef(r, st);
            return evalData(r); // literal / Package
        },
    }
}

// --- reference read/write + buffer-field bit access -------------------------

/// Extract a ≤64-bit little-endian bit-slice from a byte buffer (CreateField).
fn bufFieldRead(buf: []const u8, bit_off: u32, bit_width: u32) u64 {
    if (bit_width == 0 or bit_width > 64) return 0;
    var v: u64 = 0;
    var i: u32 = 0;
    while (i < bit_width) : (i += 1) {
        const bit = bit_off + i;
        const byte = bit >> 3;
        if (byte >= buf.len) break;
        if ((buf[byte] >> @as(u3, @intCast(bit & 7))) & 1 != 0) v |= @as(u64, 1) << @as(u6, @intCast(i));
    }
    return v;
}

/// Deposit a ≤64-bit value into a byte buffer's bit-slice (CreateField write).
fn bufFieldWrite(buf: []u8, bit_off: u32, bit_width: u32, val: u64) void {
    if (bit_width == 0 or bit_width > 64) return;
    var i: u32 = 0;
    while (i < bit_width) : (i += 1) {
        const bit = bit_off + i;
        const byte = bit >> 3;
        if (byte >= buf.len) break;
        const mask = @as(u8, 1) << @as(u3, @intCast(bit & 7));
        if ((val >> @as(u6, @intCast(i))) & 1 != 0) buf[byte] |= mask else buf[byte] &= ~mask;
    }
}

/// Read the value a reference points at (DerefOf / auto-deref).
fn readThroughRef(rf: Ref) Value {
    switch (rf) {
        .buf_byte => |bb| return .{ .integer = if (bb.idx < bb.buf.len) bb.buf[bb.idx] else 0 },
        .pkg_elem => |pe| return if (pe.idx < pe.pkg.len) pe.pkg[pe.idx] else .uninit,
        .buf_field => |bf| return .{ .integer = bufFieldRead(bf.buf, bf.bit_off, bf.bit_width) },
        .node => |ni| {
            if (ni >= nnodes) return .uninit;
            const n = &nodes[ni];
            return switch (n.kind) {
                .name => if (n.has_runtime) n.runtime_val else blk: {
                    var rr = Reader{ .buf = bodyOf(n), .pos = n.val_off };
                    break :blk (evalData(&rr) orelse .uninit);
                },
                .field => .{ .integer = readField(n) orelse 0 },
                else => .uninit,
            };
        },
    }
}

/// Write a value through a reference (Store-to-lvalue). True on success.
fn writeThroughRef(rf: Ref, v: Value) bool {
    switch (rf) {
        .buf_byte => |bb| {
            if (bb.idx >= bb.buf.len) return false;
            bb.buf[bb.idx] = @truncate(toInt(v));
            return true;
        },
        .pkg_elem => |pe| {
            if (pe.idx >= pe.pkg.len) return false;
            pe.pkg[pe.idx] = v;
            return true;
        },
        .buf_field => |bf| {
            bufFieldWrite(bf.buf, bf.bit_off, bf.bit_width, toInt(v));
            return true;
        },
        .node => |ni| {
            if (ni >= nnodes) return false;
            const n = &nodes[ni];
            switch (n.kind) {
                .name => {
                    n.runtime_val = v;
                    n.has_runtime = true;
                    return true;
                },
                .field => return writeField(n, toInt(v)),
                else => return false,
            }
        },
    }
}

/// DerefOf on a value: through a reference, else the value unchanged (lenient).
fn derefValue(v: Value) Value {
    return switch (v) {
        .ref => |rf| readThroughRef(rf),
        else => v,
    };
}

// --- Buffer()/SizeOf/Index/DerefOf/RefOf ------------------------------------

/// Runtime Buffer(): BufferSize TermArg + ByteList → a fresh arena buffer (so
/// it is mutable and Index/CreateField over it alias correctly). The declared
/// size is the length; the byte list initializes the front, the rest is zero.
fn evalBufferRuntime(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x11 BufferOp
    const pkg_start = r.pos;
    const pl = readPkgLength(r) orelse return null;
    const end = pkg_start + pl.value;
    if (end > r.buf.len or end < r.pos) return null;
    const size_v = evalTermArg(r, st) orelse return null; // BufferSize TermArg
    const declared: usize = @intCast(@min(toInt(size_v), @as(u64, BYTE_ARENA)));
    const init_bytes = if (r.pos <= end) r.buf[r.pos..end] else r.buf[0..0];
    r.pos = end;
    const mb = newBuf(declared) orelse return null;
    const copy_n = @min(init_bytes.len, declared);
    @memcpy(mb[0..copy_n], init_bytes[0..copy_n]);
    return .{ .buffer = mb };
}

/// SizeOf(obj): element/byte count of a Buffer, String or Package; 0 otherwise.
fn evalSizeOf(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x87 SizeOfOp
    const v = derefValue(evalTermArg(r, st) orelse return null);
    return .{ .integer = switch (v) {
        .string => |s| s.len,
        .buffer => |b| b.len,
        .package => |p| p.len,
        else => 0,
    } };
}

/// Build the reference Index(src, idx) names: a byte of a Buffer/String, or an
/// element slot of a Package. Null if out of range or src isn't indexable.
fn refForIndex(src: Value, idx: u64) ?Ref {
    switch (src) {
        .buffer => |b| {
            const mb = materializeBuf(b) orelse return null;
            if (idx >= mb.len) return null;
            return Ref{ .buf_byte = .{ .buf = mb, .idx = @intCast(idx) } };
        },
        .string => |s| {
            const mb = materializeBuf(s) orelse return null;
            if (idx >= mb.len) return null;
            return Ref{ .buf_byte = .{ .buf = mb, .idx = @intCast(idx) } };
        },
        .package => |p| {
            if (idx >= p.len) return null;
            return Ref{ .pkg_elem = .{ .pkg = p, .idx = @intCast(idx) } };
        },
        else => return null,
    }
}

/// Index(Source, Index, Target): yield a reference to the indexed element and
/// (optionally) store it into Target. Auto-derefs when used as an integer.
fn evalIndexExpr(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // IndexOp
    const src = evalTermArg(r, st) orelse return null;
    const idx = toInt(evalTermArg(r, st) orelse return null);
    const rv: Value = if (refForIndex(src, idx)) |rf| .{ .ref = rf } else .uninit;
    if (!storeTarget(r, st, rv)) return null; // trailing Target (often Null)
    return rv;
}

/// DerefOf(ref): the value the reference points at.
fn evalDerefExpr(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // DerefOfOp
    const v = evalTermArg(r, st) orelse return null;
    return derefValue(v);
}

/// RefOf(obj): a reference to a named object (Name or Field). References to
/// frame slots (Local/Arg) aren't modeled — the operand is consumed, uninit.
fn evalRefOf(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // RefOfOp
    const op = r.peek(0) orelse return null;
    if (isNameLead(op)) {
        const ns = readNameString(r) orelse return null;
        if (resolve(st.scope, ns)) |n| return .{ .ref = .{ .node = nodeIndexOf(n) } };
        return .uninit;
    }
    _ = evalTermArg(r, st);
    return .uninit;
}

// --- CreateField family (buffer-field windows) ------------------------------
// CreateByteField/Word/DWord/QWord/BitField and the general CreateField create
// a NAMED window over a Buffer's bits. They run at EXECUTION time, so the node
// is created dynamically (beyond static_nnodes) and reclaimed at the next
// top-level arenaReset. Reads/writes of the name auto-deref through the window.

/// Find-or-create a namespace node for `ns` resolved against `scope`. Returns an
/// existing node (CreateField re-target) or a freshly appended one; null if the
/// store is full.
fn createDynNode(scope: []const u8, ns: NameString) ?*StoredNode {
    var pb = PathBuf{};
    seedPath(&pb, scope);
    _ = pb.enter(ns);
    const abs = pb.snapshot();
    if (findExact(abs)) |n| return n;
    if (nnodes >= nodes.len) {
        store_overflow = true;
        return null;
    }
    const n = &nodes[nnodes];
    n.* = .{};
    const cl = @min(abs.len, @as(usize, PATH_MAX));
    @memcpy(n.path[0..cl], abs[0..cl]);
    n.path_len = @intCast(cl);
    nnodes += 1;
    return n;
}

/// Bind `ns` as a buffer-field window [bit_off, bit_off+bit_width) over `src`'s
/// bytes (materialized into the byte arena so writes alias the source object).
fn bindBufferField(st: *ExecState, ns: NameString, src: Value, bit_off: u32, bit_width: u32) ?Value {
    const buf: []u8 = switch (derefValue(src)) {
        .buffer => |b| materializeBuf(b) orelse return .uninit,
        else => return .uninit, // CreateField over a non-buffer: ignore (lenient)
    };
    const node = createDynNode(st.scope, ns) orelse return .uninit;
    node.kind = .name;
    node.is_buffer_field = true;
    node.has_runtime = true;
    node.runtime_val = .{ .ref = .{ .buf_field = .{ .buf = buf, .bit_off = bit_off, .bit_width = bit_width } } };
    return .uninit;
}

/// CreateByteField(0x8C)/Word(0x8B)/DWord(0x8A)/QWord(0x8F)/BitField(0x8D):
/// Source ByteIndex(or BitIndex) Name. Fixed widths; byte-indexed except
/// CreateBitField which is bit-indexed.
fn evalCreateField(r: *Reader, st: *ExecState, op: u8) ?Value {
    _ = r.next(); // CreateXFieldOp
    const src = evalTermArg(r, st) orelse return null;
    const index = toInt(evalTermArg(r, st) orelse return null);
    const ns = readNameString(r) orelse return null;
    const bits: u32 = switch (op) {
        0x8D => 1, // CreateBitField
        0x8C => 8, // CreateByteField
        0x8B => 16, // CreateWordField
        0x8A => 32, // CreateDWordField
        0x8F => 64, // CreateQWordField
        else => 8,
    };
    const bit_off: u32 = if (op == 0x8D) @intCast(index) else @intCast(index *% 8);
    return bindBufferField(st, ns, src, bit_off, bits);
}

// --- conversions + buffer/string manipulation (A3) --------------------------
// Concatenate, ToBuffer, ToInteger, ToHexString, ToString, Mid, ObjectType,
// CopyObject — the operators real control methods use to marshal data in and
// out of mailbox buffers. Results that need fresh storage land in the byte
// arena (buffers/strings) or value arena and live for the call.

fn writeLe(out: []u8, v: u64) void {
    var i: usize = 0;
    while (i < out.len and i < 8) : (i += 1) out[i] = @truncate(v >> @as(u6, @intCast(i * 8)));
}

fn readLeBytes(b: []const u8) u64 {
    var v: u64 = 0;
    var i: usize = 0;
    while (i < b.len and i < 8) : (i += 1) v |= @as(u64, b[i]) << @as(u6, @intCast(i * 8));
    return v;
}

/// The raw bytes of a value as a Buffer view: Buffer/String pass through;
/// Integer is laid out as 8 little-endian bytes in a fresh arena slice.
fn toBufferBytes(v: Value) []const u8 {
    return switch (derefValue(v)) {
        .buffer => |b| b,
        .string => |s| s,
        .integer => |iv| blk: {
            const out = bufAlloc(8) orelse break :blk &[_]u8{};
            writeLe(out, iv);
            break :blk out;
        },
        else => &[_]u8{},
    };
}

/// Parse a String as an Integer (leading "0x" ⇒ hex, else decimal; stops at the
/// first non-digit) — ACPI's ToInteger(String) rule.
fn parseIntStr(s: []const u8) u64 {
    var i: usize = 0;
    while (i < s.len and s[i] == ' ') i += 1;
    var v: u64 = 0;
    if (i + 1 < s.len and s[i] == '0' and (s[i + 1] == 'x' or s[i + 1] == 'X')) {
        i += 2;
        while (i < s.len) : (i += 1) {
            const c = s[i];
            const d: u64 = if (c >= '0' and c <= '9') c - '0' else if (c >= 'A' and c <= 'F') c - 'A' + 10 else if (c >= 'a' and c <= 'f') c - 'a' + 10 else break;
            v = v *% 16 +% d;
        }
    } else {
        while (i < s.len) : (i += 1) {
            if (s[i] < '0' or s[i] > '9') break;
            v = v *% 10 +% (s[i] - '0');
        }
    }
    return v;
}

/// Concatenate(a, b): result type follows `a` (Integer→Buffer). `b` is coerced
/// to that type, then the two are joined into a fresh arena object.
fn concatValues(a: Value, b: Value) ?Value {
    switch (a) {
        .string => |sa| {
            const sb = toBufferBytes(b); // string bytes (or coerced)
            const out = bufAlloc(sa.len + sb.len) orelse return null;
            @memcpy(out[0..sa.len], sa);
            @memcpy(out[sa.len..], sb);
            return .{ .string = out };
        },
        .buffer => |ba| {
            const bb = toBufferBytes(b);
            const out = bufAlloc(ba.len + bb.len) orelse return null;
            @memcpy(out[0..ba.len], ba);
            @memcpy(out[ba.len..], bb);
            return .{ .buffer = out };
        },
        .integer => |ia| {
            const bb = toBufferBytes(b);
            const out = bufAlloc(8 + bb.len) orelse return null;
            writeLe(out[0..8], ia);
            @memcpy(out[8..], bb);
            return .{ .buffer = out };
        },
        else => return null,
    }
}

fn evalConcat(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x73 ConcatOp
    const a = derefValue(evalTermArg(r, st) orelse return null);
    const b = derefValue(evalTermArg(r, st) orelse return null);
    const res = concatValues(a, b) orelse Value.uninit;
    if (!storeTarget(r, st, res)) return null;
    return res;
}

fn evalToBuffer(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x96 ToBufferOp
    const s = derefValue(evalTermArg(r, st) orelse return null);
    const res: Value = switch (s) {
        .buffer => s,
        .string => |str| blk: {
            const out = newBuf(str.len) orelse break :blk Value.uninit;
            @memcpy(out, str);
            break :blk Value{ .buffer = out };
        },
        .integer => |iv| blk: {
            const out = newBuf(8) orelse break :blk Value.uninit;
            writeLe(out, iv);
            break :blk Value{ .buffer = out };
        },
        else => Value.uninit,
    };
    if (!storeTarget(r, st, res)) return null;
    return res;
}

fn evalToInteger(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x99 ToIntegerOp
    const s = derefValue(evalTermArg(r, st) orelse return null);
    const v: u64 = switch (s) {
        .integer => |iv| iv,
        .buffer => |b| readLeBytes(b),
        .string => |str| parseIntStr(str),
        else => 0,
    };
    const res = Value{ .integer = v };
    if (!storeTarget(r, st, res)) return null;
    return res;
}

const HEX = "0123456789ABCDEF";

/// ToHexString(int): uppercase hex digits (minimal width, ≥1 digit). Buffers
/// stringify as comma-separated byte hex per ACPI, but the integer form is what
/// firmware logging paths use; a buffer falls back to its first 8 bytes.
fn evalToHexString(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x98 ToHexStringOp
    const s = derefValue(evalTermArg(r, st) orelse return null);
    const iv: u64 = switch (s) {
        .integer => |x| x,
        .buffer => |b| readLeBytes(b),
        .string => {
            if (!storeTarget(r, st, s)) return null;
            return s;
        },
        else => 0,
    };
    var tmp: [16]u8 = undefined;
    var n: usize = 0;
    var shift: i32 = 60;
    var started = false;
    while (shift >= 0) : (shift -= 4) {
        const nib: u8 = @intCast((iv >> @as(u6, @intCast(shift))) & 0xF);
        if (nib != 0 or started or shift == 0) {
            tmp[n] = HEX[nib];
            n += 1;
            started = true;
        }
    }
    const out = bufAlloc(n) orelse return null;
    @memcpy(out, tmp[0..n]);
    const res = Value{ .string = out };
    if (!storeTarget(r, st, res)) return null;
    return res;
}

/// ToString(Source, Length): a String of Source's bytes up to a NUL or Length
/// (whichever first); Length = Ones (0xFFFF_FFFF…) means "to the NUL".
fn evalToString(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x9C ToStringOp
    const src = derefValue(evalTermArg(r, st) orelse return null);
    const length = toInt(evalTermArg(r, st) orelse return null);
    const bytes = switch (src) {
        .buffer => |b| b,
        .string => |s| s,
        else => &[_]u8{},
    };
    var n: usize = 0;
    const cap = if (length == ~@as(u64, 0)) bytes.len else @min(@as(usize, @intCast(@min(length, bytes.len))), bytes.len);
    while (n < cap and bytes[n] != 0) n += 1;
    const out = bufAlloc(n) orelse return null;
    @memcpy(out, bytes[0..n]);
    const res = Value{ .string = out };
    if (!storeTarget(r, st, res)) return null;
    return res;
}

/// Mid(Source, Index, Length): a sub-Buffer/sub-String (type follows Source).
fn evalMid(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x9E MidOp
    const src = derefValue(evalTermArg(r, st) orelse return null);
    const index = toInt(evalTermArg(r, st) orelse return null);
    const length = toInt(evalTermArg(r, st) orelse return null);
    const bytes = switch (src) {
        .buffer => |b| b,
        .string => |s| s,
        else => {
            if (!storeTarget(r, st, .uninit)) return null;
            return .uninit;
        },
    };
    const start: usize = @intCast(@min(index, bytes.len));
    const end: usize = @intCast(@min(start + @min(length, bytes.len), bytes.len));
    const n = end - start;
    const out = bufAlloc(n) orelse return null;
    @memcpy(out, bytes[start..end]);
    const res: Value = if (src == .string) .{ .string = out } else .{ .buffer = out };
    if (!storeTarget(r, st, res)) return null;
    return res;
}

/// ObjectType(obj): the ACPI type code (0=uninit,1=int,2=str,3=buffer,4=pkg).
fn evalObjectType(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x8E ObjectTypeOp
    const v = derefValue(evalTermArg(r, st) orelse return null);
    return .{ .integer = switch (v) {
        .integer => 1,
        .string => 2,
        .buffer => 3,
        .package => 4,
        else => 0,
    } };
}

/// CopyObject(Source, Target): store Source into Target (value semantics).
fn evalCopyObject(r: *Reader, st: *ExecState) ?Value {
    _ = r.next(); // 0x9D CopyObjectOp
    const s = evalTermArg(r, st) orelse return null;
    if (!storeTarget(r, st, s)) return null;
    return s;
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

/// A NameString in expression position: a method invocation (consume its args)
/// or a reference to a Name (yield its value). Unresolved / non-value objects
/// yield uninit so a method keeps running.
fn evalNameRef(r: *Reader, st: *ExecState) ?Value {
    const ns = readNameString(r) orelse return null;
    // _OSI(str): OS-supplied, not a DSDT object — intercept and answer directly.
    if (ns.nsegs > 0 and std.mem.eql(u8, &ns.segs[ns.nsegs - 1], "_OSI")) {
        const arg = evalTermArg(r, st) orelse Value.uninit;
        return .{ .integer = osiVerdict(arg) };
    }
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
            // A CreateField window auto-derefs: reading the name yields the
            // value of the bits it covers, not the reference object itself.
            if (node.is_buffer_field and node.has_runtime) return readThroughRef(node.runtime_val.ref);
            if (node.has_runtime) return node.runtime_val;
            var rr = Reader{ .buf = bodyOf(node), .pos = node.val_off };
            var v = evalData(&rr) orelse .uninit;
            // A buffer-valued Name materializes into the byte arena on first
            // access and caches the arena copy as its runtime value — so a later
            // Index()/CreateField over this Name aliases the SAME storage and
            // writes persist. (Invalidated at the next arenaReset.)
            if (v == .buffer) {
                if (materializeBuf(v.buffer)) |mb| {
                    v = .{ .buffer = mb };
                    node.runtime_val = v;
                    node.has_runtime = true;
                }
            }
            return v;
        },
        .field => { // B2c/A4: read the backing hardware
            if (node.field_bit_width > 64) return readFieldBuffer(node) orelse .uninit;
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
                            // A CreateField window: deposit v into its bits
                            // instead of replacing the reference object.
                            if (n.is_buffer_field and n.has_runtime) {
                                _ = writeThroughRef(n.runtime_val.ref, v);
                            } else {
                                n.runtime_val = v;
                                n.has_runtime = true;
                            }
                        },
                        .field => { // B2c/A4: write hardware (scalar, or wide ← Buffer)
                            if (n.field_bit_width > 64) {
                                _ = writeFieldBuffer(n, toBufferBytes(v));
                            } else {
                                _ = writeField(n, toInt(v));
                            }
                        },
                        else => {},
                    }
                }
                return true;
            }
            // Index() as a Store target: evaluate it to a reference (consuming
            // its own trailing Target), then write v through that reference —
            // Store(x, Index(BUF, i)) deposits x into BUF's i-th element.
            if (op == 0x88) {
                const rv = evalIndexExpr(r, st) orelse return false;
                if (rv == .ref) return writeThroughRef(rv.ref, v);
                return true;
            }
            // DerefOf(ref) as a target: write through the dereferenced location.
            if (op == 0x83) {
                _ = r.next(); // DerefOfOp
                const refv = evalTermArg(r, st) orelse return false;
                if (refv == .ref) return writeThroughRef(refv.ref, v);
                return true;
            }
            // Some other expression as a target — evaluate for its side effect;
            // if it yields a reference, honor it.
            const tv = evalTermArg(r, st) orelse return false;
            if (tv == .ref) return writeThroughRef(tv.ref, v);
            return true;
        },
    }
}

// --- statement execution ----------------------------------------------------

fn execTermList(r: *Reader, end: usize, st: *ExecState) void {
    while (r.pos < end and !st.returned and !st.break_loop and !st.continue_loop) {
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
            0x9F => { // Continue: unwind nested lists to the enclosing While
                _ = r.next();
                st.continue_loop = true;
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
        if (st.continue_loop) {
            st.continue_loop = false; // swallow it here → re-evaluate the condition
            continue;
        }
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
    if (node.kind != .method or bodyOf(node).len == 0) return null;
    var frame = Frame{};
    var i: usize = 0;
    while (i < args.len and i < 7) : (i += 1) frame.args[i] = args[i];
    var st = ExecState{ .frame = &frame, .scope = node.path[0..node.path_len], .depth = depth };
    const body = bodyOf(node);
    var r = Reader{ .buf = body, .pos = node.val_off };
    const end = @min(node.val_off + node.val_len, body.len);
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

/// Like evalMethod but passes one argument — e.g. _PIC(1) to tell the firmware we
/// use the IOAPIC, so _PRT yields GSI (not 8259 IRQ) routing.
pub fn evalMethodArg1(abs: []const u8, arg: Value) ?Value {
    const n = findExact(abs) orelse return null;
    if (n.kind != .method) return null;
    arenaReset();
    return callMethod(n, &.{arg}, 0);
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

// === deterministic self-tests (firmware-independent) ========================
// Each check runs a hand-assembled AML program and compares the result against
// an expected value, counting failures. selfTestExtended() is the SINGLE source
// of truth: load() runs it at boot (one PASS/FAIL klog per check), and the
// native harness (tools/aml test rig) asserts it returns 0. Extending the
// interpreter ⇒ add a check here — so every capability has a pinned proof that
// runs both natively (fast) and on real firmware (boot).

/// Reset the namespace store + arenas so a self-test can walk its own
/// hand-assembled table into a clean namespace. Mirrors the head of load().
fn tNsReset() void {
    node_count = 0;
    unknown_op_seen = 0;
    nnodes = 0;
    static_nnodes = 0;
    store_overflow = false;
    nbodies = 0;
    arenaReset();
}

/// Run a bare TermList (no enclosing method) against a fresh Frame and return
/// its Return value. Starts from an empty namespace so CreateField-style tests
/// (which create nodes at the root) are isolated from one another.
fn runProg(body: []const u8) Value {
    tNsReset();
    var frame = Frame{};
    var st = ExecState{ .frame = &frame, .scope = "\\", .depth = 0 };
    var r = Reader{ .buf = body };
    execTermList(&r, body.len, &st);
    return st.ret;
}

/// Walk a hand-assembled AML body into a fresh namespace, then invoke a method
/// by absolute path and return its result. For tests that need named objects
/// (CreateField, method calls, OperationRegion/Field I/O).
fn tWalkEval(body: []const u8, method_abs: []const u8) Value {
    tNsReset();
    _ = walkBody(body);
    static_nnodes = nnodes; // the walked nodes are the static baseline
    return evalMethod(method_abs) orelse .uninit;
}

/// Run a bare TermList against the CURRENT namespace (no reset) — for tests that
/// pre-built region/field nodes the program references by name.
fn runProgKeepNs(body: []const u8) Value {
    var frame = Frame{};
    var st = ExecState{ .frame = &frame, .scope = "\\", .depth = 0 };
    var r = Reader{ .buf = body };
    arenaReset();
    execTermList(&r, body.len, &st);
    return st.ret;
}

/// Programmatically append a namespace node at an absolute path (self-tests that
/// build OperationRegion/Field nodes pointing at a runtime address).
fn stMakeNode(abs: []const u8) ?*StoredNode {
    if (nnodes >= nodes.len) return null;
    const n = &nodes[nnodes];
    n.* = .{};
    const cl = @min(abs.len, @as(usize, PATH_MAX));
    @memcpy(n.path[0..cl], abs[0..cl]);
    n.path_len = @intCast(cl);
    nnodes += 1;
    return n;
}

/// Backing store for the wide-field self-test's OperationRegion: a real,
/// kernel-owned, mapped buffer. The region is placed at this buffer's PHYSICAL
/// address (via virtToPhys), so the test drives readRegionUnit/writeRegionUnit
/// over genuine SystemMemory in both the native harness and on hardware — no
/// fake address, nothing else's memory touched.
var st_region_buf: [16]u8 align(16) = [_]u8{0} ** 16;

/// Wide (96-bit) SystemMemory field round-trip: write a 12-byte buffer through
/// the field, read it back, check byte 5 == 0x06. Exercises the >64-bit
/// readFieldBuffer/writeFieldBuffer path over a real mapped region.
fn stWideFieldTest(fails: *u32) void {
    tNsReset();
    const phys = paging.virtToPhys(@intFromPtr(&st_region_buf)) orelse {
        debug.klog("[aml] selftest wide field buffer r/w: SKIP (test buffer not mapped)\n", .{});
        return;
    };
    @memset(&st_region_buf, 0);
    const reg = stMakeNode("\\RAM_") orelse return;
    reg.kind = .op_region;
    reg.region_space = SPACE_MEM;
    reg.region_off = phys;
    reg.region_len = st_region_buf.len;
    const reg_idx = nnodes - 1;
    const fld = stMakeNode("\\WIDE") orelse return;
    fld.kind = .field;
    fld.field_region = @intCast(reg_idx);
    fld.field_bit_off = 0;
    fld.field_bit_width = 96;
    fld.field_access = 1; // ByteAcc
    static_nnodes = nnodes; // keep RAM_/WIDE across the program's arenaReset
    const got = toInt(runProgKeepNs(&[_]u8{
        0x70, 0x11, 0x0F, 0x0A, 0x0C, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x60, // Store Buffer(12){1..12} -> L0
        0x70, 0x60, 'W', 'I', 'D', 'E', // Store(L0, WIDE)  — wide write ← Buffer
        0x70, 'W', 'I', 'D', 'E', 0x61, // Store(WIDE, L1)  — wide read → Buffer
        0xA4, 0x83, 0x88, 0x61, 0x0A, 0x05, 0x00, // Return DerefOf(Index(L1,5)) == 0x06
    }));
    stCheck("wide field buffer r/w", got, 0x06, fails);
}

/// Compare got/want, log PASS/FAIL, bump fails on mismatch.
fn stCheck(name: []const u8, got: u64, want: u64, fails: *u32) void {
    const ok = got == want;
    if (!ok) fails.* += 1;
    debug.klog("[aml] selftest {s}: got 0x{X} want 0x{X} ({s})\n", .{ name, got, want, if (ok) "PASS" else "FAIL" });
}

/// All deterministic self-tests. Returns the count that FAILED (0 = all pass).
/// Self-contained: each check resets the namespace it needs, so calling this at
/// the very top of load() leaves the real DSDT walk a clean store.
pub fn selfTestExtended() u32 {
    var fails: u32 = 0;

    // Executor smoke test: Add(2,3) -> Local0; Return(Local0) == 5. Proves
    // operand decode, a binary op writing a Target, Local store/load, Return.
    stCheck("Add(2,3)", toInt(runProg(&[_]u8{ 0x72, 0x0A, 0x02, 0x0A, 0x03, 0x60, 0xA4, 0x60 })), 5, &fails);

    // === A1: object model — mutable buffers, references, SizeOf =============

    // Return(SizeOf(Buffer(4){})) == 4. Proves runtime Buffer() + SizeOf.
    stCheck("SizeOf(Buffer(4))", toInt(runProg(&[_]u8{
        0xA4, 0x87, 0x11, 0x03, 0x0A, 0x04, // Return SizeOf Buffer(PkgLen=3){ size=4 }
    })), 4, &fails);

    // Return(SizeOf("AB")) == 2; Return(SizeOf(Package(3){0,0,0})) == 3.
    stCheck("SizeOf(\"AB\")", toInt(runProg(&[_]u8{ 0xA4, 0x87, 0x0D, 0x41, 0x42, 0x00 })), 2, &fails);
    stCheck("SizeOf(Package(3))", toInt(runProg(&[_]u8{ 0xA4, 0x87, 0x12, 0x05, 0x03, 0x00, 0x00, 0x00 })), 3, &fails);

    // Buffer write-through-Index: Store(Buffer(4){},L0); Store(0x42,Index(L0,1));
    // Return(DerefOf(Index(L0,1))) == 0x42. Proves a runtime buffer is mutable
    // and that Index() aliases the same storage (write then read back).
    stCheck("Index(Buffer) store/deref", toInt(runProg(&[_]u8{
        0x70, 0x11, 0x03, 0x0A, 0x04, 0x60, // Store Buffer(4){} -> Local0
        0x70, 0x0A, 0x42, 0x88, 0x60, 0x0A, 0x01, 0x00, // Store 0x42 -> Index(Local0,1)
        0xA4, 0x83, 0x88, 0x60, 0x0A, 0x01, 0x00, // Return DerefOf(Index(Local0,1))
    })), 0x42, &fails);

    // Package element read: Store(Package(2){0x11,0x22},L0);
    // Return(DerefOf(Index(L0,1))) == 0x22.
    stCheck("Index(Package) deref", toInt(runProg(&[_]u8{
        0x70, 0x12, 0x06, 0x02, 0x0A, 0x11, 0x0A, 0x22, 0x60, // Store Package(2){0x11,0x22} -> L0
        0xA4, 0x83, 0x88, 0x60, 0x0A, 0x01, 0x00, // Return DerefOf(Index(Local0,1))
    })), 0x22, &fails);

    // === A2: CreateField family (buffer-field windows) =====================

    // CreateDWordField round-trip: over Buffer(8) in L0, FLD = dword@0;
    // Store(0x12345678,FLD); Return(FLD) == 0x12345678.
    stCheck("CreateDWordField r/w", toInt(runProg(&[_]u8{
        0x70, 0x11, 0x03, 0x0A, 0x08, 0x60, // Store Buffer(8){} -> Local0
        0x8A, 0x60, 0x00, 'F', 'L', 'D', '_', // CreateDWordField(Local0, 0, FLD)
        0x70, 0x0C, 0x78, 0x56, 0x34, 0x12, 'F', 'L', 'D', '_', // Store 0x12345678 -> FLD
        0xA4, 'F', 'L', 'D', '_', // Return(FLD)
    })), 0x12345678, &fails);

    // Same write, but read byte 1 via Index — proves the window writes into the
    // SAME buffer and little-endian layout: byte1 of 0x12345678 == 0x56.
    stCheck("CreateDWordField LE alias", toInt(runProg(&[_]u8{
        0x70, 0x11, 0x03, 0x0A, 0x08, 0x60, // Store Buffer(8){} -> Local0
        0x8A, 0x60, 0x00, 'F', 'L', 'D', '_', // CreateDWordField(Local0, 0, FLD)
        0x70, 0x0C, 0x78, 0x56, 0x34, 0x12, 'F', 'L', 'D', '_', // Store 0x12345678 -> FLD
        0xA4, 0x83, 0x88, 0x60, 0x0A, 0x01, 0x00, // Return DerefOf(Index(Local0,1))
    })), 0x56, &fails);

    // Arbitrary-width CreateField: 8 bits at bit offset 4 → straddles byte0/byte1.
    // Store(0xFF,F); byte0 gets its top nibble set → 0xF0.
    stCheck("CreateField bits@4 w8", toInt(runProg(&[_]u8{
        0x70, 0x11, 0x03, 0x0A, 0x08, 0x60, // Store Buffer(8){} -> Local0
        0x5B, 0x13, 0x60, 0x0A, 0x04, 0x0A, 0x08, 'B', 'Y', 'T', '_', // CreateField(Local0, 4, 8, BYT)
        0x70, 0x0A, 0xFF, 'B', 'Y', 'T', '_', // Store 0xFF -> BYT
        0xA4, 0x83, 0x88, 0x60, 0x00, 0x00, // Return DerefOf(Index(Local0,0)) == 0xF0
    })), 0xF0, &fails);

    // CreateBitField: single bit 5; Store(One,B); byte0 == 0x20.
    stCheck("CreateBitField bit5", toInt(runProg(&[_]u8{
        0x70, 0x11, 0x03, 0x0A, 0x08, 0x60, // Store Buffer(8){} -> Local0
        0x8D, 0x60, 0x0A, 0x05, 'B', 'I', 'T', '_', // CreateBitField(Local0, 5, BIT)
        0x70, 0x01, 'B', 'I', 'T', '_', // Store One -> BIT
        0xA4, 0x83, 0x88, 0x60, 0x00, 0x00, // Return DerefOf(Index(Local0,0)) == 0x20
    })), 0x20, &fails);

    // === A3: conversions + buffer/string manipulation ======================

    // Concatenate(Buffer{0x11,0x22}, Buffer{0x33,0x44}) -> L0; byte 2 == 0x33.
    stCheck("Concatenate(buf,buf)", toInt(runProg(&[_]u8{
        0x73, 0x11, 0x05, 0x0A, 0x02, 0x11, 0x22, 0x11, 0x05, 0x0A, 0x02, 0x33, 0x44, 0x60, // Concatenate(.., .., Local0)
        0xA4, 0x83, 0x88, 0x60, 0x0A, 0x02, 0x00, // Return DerefOf(Index(Local0,2)) == 0x33
    })), 0x33, &fails);

    // ToBuffer(0x11223344) -> L0; little-endian, byte 0 == 0x44.
    stCheck("ToBuffer(int) LE", toInt(runProg(&[_]u8{
        0x96, 0x0C, 0x44, 0x33, 0x22, 0x11, 0x60, // ToBuffer(0x11223344, Local0)
        0xA4, 0x83, 0x88, 0x60, 0x00, 0x00, // Return DerefOf(Index(Local0,0)) == 0x44
    })), 0x44, &fails);

    // ToInteger(Buffer{0x44,0x33,0x22,0x11}) == 0x11223344.
    stCheck("ToInteger(buf) LE", toInt(runProg(&[_]u8{
        0x70, 0x11, 0x07, 0x0A, 0x04, 0x44, 0x33, 0x22, 0x11, 0x60, // Store Buffer(4){..} -> L0
        0x99, 0x60, 0x61, // ToInteger(Local0, Local1)
        0xA4, 0x61, // Return(Local1)
    })), 0x11223344, &fails);

    // Mid(Buffer{0x10,0x20,0x30,0x40}, 1, 2) -> L0 = {0x20,0x30}; byte 1 == 0x30.
    stCheck("Mid(buf,1,2)", toInt(runProg(&[_]u8{
        0x9E, 0x11, 0x07, 0x0A, 0x04, 0x10, 0x20, 0x30, 0x40, 0x0A, 0x01, 0x0A, 0x02, 0x60, // Mid(.., 1, 2, L0)
        0xA4, 0x83, 0x88, 0x60, 0x0A, 0x01, 0x00, // Return DerefOf(Index(Local0,1)) == 0x30
    })), 0x30, &fails);

    // ObjectType: Buffer==3, String==2, Integer==1.
    stCheck("ObjectType(Buffer)", toInt(runProg(&[_]u8{ 0xA4, 0x8E, 0x11, 0x03, 0x0A, 0x01 })), 3, &fails);
    stCheck("ObjectType(String)", toInt(runProg(&[_]u8{ 0xA4, 0x8E, 0x0D, 'X', 0x00 })), 2, &fails);
    stCheck("ObjectType(Integer)", toInt(runProg(&[_]u8{ 0xA4, 0x8E, 0x0A, 0x05 })), 1, &fails);

    // === A4: wide fields ↔ Buffer, Continue, _OSI ==========================

    // A 96-bit SystemMemory field over a real kernel-owned buffer: write a
    // 12-byte buffer through it, read it back, check byte 5 == 0x06. Proves the
    // wide-field ↔ Buffer data path through genuine region I/O (boot + harness).
    stWideFieldTest(&fails);

    // Continue inside If inside While: sum 1..5 but skip 3 → 12. Without a
    // proper continue this mis-sums to 15 (the Add after the If still runs).
    stCheck("Continue in While", toInt(runProg(&[_]u8{
        0x70, 0x00, 0x60, // Store(0, Local0)  counter
        0x70, 0x00, 0x61, // Store(0, Local1)  sum
        0xA2, 0x12, 0x95, 0x60, 0x0A, 0x05, // While(LLess(Local0,5)) { ...13 bytes...
        0x75, 0x60, //   Increment(Local0)
        0xA0, 0x06, 0x93, 0x60, 0x0A, 0x03, 0x9F, //   If(LEqual(Local0,3)) { Continue }
        0x72, 0x61, 0x60, 0x61, //   Add(Local1, Local0, Local1)
        0xA4, 0x61, // Return(Local1) == 12
    })), 12, &fails);

    // _OSI: a claimed Windows interface ⇒ Ones; an unknown one ⇒ Zero.
    stCheck("_OSI(\"Windows 2009\")", toInt(runProg(&[_]u8{
        0xA4, 0x5F, 0x4F, 0x53, 0x49, 0x0D, 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', '2', '0', '0', '9', 0x00,
    })), ~@as(u64, 0), &fails);
    stCheck("_OSI(\"Linux\")", toInt(runProg(&[_]u8{
        0xA4, 0x5F, 0x4F, 0x53, 0x49, 0x0D, 'L', 'i', 'n', 'u', 'x', 0x00,
    })), 0, &fails);

    return fails;
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

// --- wide fields (> 64 bits) ↔ Buffer (A4) ----------------------------------
// The DSM mailbox carries request/response payloads far wider than a u64. A
// Field element wider than 64 bits reads into a Buffer (LSB-first: field bit 0
// → buffer byte 0 bit 0) and is written from a Buffer the same way. Each access
// unit is read/written once; partial leading/trailing units are RMW-preserved
// by walking only the field's own bits.

/// Read a field of any width into a fresh arena Buffer ((width+7)/8 bytes).
fn readFieldBuffer(field: *const StoredNode) ?Value {
    if (field.field_region < 0) return null;
    const ridx: usize = @intCast(field.field_region);
    if (ridx >= nnodes) return null;
    const region = &nodes[ridx];
    const width = field.field_bit_width;
    if (width == 0) return null;
    const out = newBuf((width + 7) / 8) orelse return null;
    const ab = accessWidthBytes(field.field_access);
    const abits = ab * 8;
    var fpos: u32 = 0;
    while (fpos < width) {
        const abs_bit = field.field_bit_off + fpos;
        const unit = abs_bit / abits;
        const v = readRegionUnit(region, @as(u64, unit) * ab, ab) orelse return null;
        var k: u32 = abs_bit - unit * abits;
        while (k < abits and fpos < width) : ({
            k += 1;
            fpos += 1;
        }) {
            if ((v >> @as(u6, @intCast(k))) & 1 != 0) out[fpos >> 3] |= @as(u8, 1) << @as(u3, @intCast(fpos & 7));
        }
    }
    return .{ .buffer = out };
}

/// Write a Buffer's bytes into a field of any width (RMW per access unit).
fn writeFieldBuffer(field: *const StoredNode, bytes: []const u8) bool {
    if (field.field_region < 0) return false;
    const ridx: usize = @intCast(field.field_region);
    if (ridx >= nnodes) return false;
    const region = &nodes[ridx];
    const width = field.field_bit_width;
    if (width == 0) return false;
    const ab = accessWidthBytes(field.field_access);
    const abits = ab * 8;
    var fpos: u32 = 0;
    while (fpos < width) {
        const abs_bit = field.field_bit_off + fpos;
        const unit = abs_bit / abits;
        const unit_byte = @as(u64, unit) * ab;
        var v = readRegionUnit(region, unit_byte, ab) orelse 0;
        var k: u32 = abs_bit - unit * abits;
        while (k < abits and fpos < width) : ({
            k += 1;
            fpos += 1;
        }) {
            const mask = @as(u64, 1) << @as(u6, @intCast(k));
            const src_set = if ((fpos >> 3) < bytes.len) (bytes[fpos >> 3] >> @as(u3, @intCast(fpos & 7))) & 1 else 0;
            if (src_set != 0) v |= mask else v &= ~mask;
        }
        if (!writeRegionUnit(region, unit_byte, ab, v)) return false;
    }
    return true;
}

// --- Slice D: multi-table load + thermal/battery readout --------------------

/// Walk one already-validated AML body into the shared namespace, tagging every
/// node with this table's id so the evaluator later reads val_off/val_len from
/// the right table's bytes. Returns how many named objects it added. A body past
/// MAX_TABLES is dropped with a diagnostic — never a fault.
fn walkBody(body: []const u8) u32 {
    if (body.len == 0) return 0;
    if (nbodies >= MAX_TABLES) {
        debug.klog("[aml] table registry full ({d}); a table is unloaded\n", .{MAX_TABLES});
        return 0;
    }
    const id = nbodies;
    bodies[id] = body;
    nbodies += 1;
    cur_table_id = id;
    const before = node_count;
    if (DUMP) debug.klog("[aml] walking table {d} ({d} AML bytes)\n", .{ id, body.len });
    var r = Reader{ .buf = body };
    var path = PathBuf{};
    path.reset();
    walkTerms(&r, body.len, &path, 0);
    return node_count - before;
}

/// Slice past an (X)SDT-supplied table's 36-byte header to its AML body and walk
/// it. acpi.zig already validated the length + mapping, so the slice is safe.
fn walkTable(hdr: *align(1) const acpi.SdtHeader) u32 {
    const hdr_len = @sizeOf(acpi.SdtHeader);
    if (hdr.length <= hdr_len) return 0;
    const body = @as([*]const u8, @ptrCast(hdr))[hdr_len..hdr.length];
    return walkBody(body);
}

/// Compile in a deterministic thermal zone so Slice D's readout has a target on
/// firmware (QEMU) that ships none. Set false to test against only real tables.
const SYNTH_TEST = true;

/// Hand-assembled AML body (no SDT header — QEMU synthesizes that for a real
/// `-acpitable` table; here we feed the body straight to walkBody). Decodes to
///   Scope(\_SB) { ThermalZone(TZ0) { Method(_TMP, 0) { Return(0x0BB8) } } }
/// 0x0BB8 = 3000 tenths-of-Kelvin = 26.85 C. Encoding per ACPI 6.4 §20.2; every
/// PkgLength here is the 1-byte form (length < 0x40).
const synth_ssdt = [_]u8{
    0x10, 0x18, // ScopeOp, PkgLength=24
    0x5C, 0x5F, 0x53, 0x42, 0x5F, // RootChar '\' + "_SB_"
    0x5B, 0x85, 0x10, // ThermalZoneOp, PkgLength=16
    0x54, 0x5A, 0x30, 0x5F, // "TZ0_"
    0x14, 0x0A, // MethodOp, PkgLength=10
    0x5F, 0x54, 0x4D, 0x50, // "_TMP"
    0x00, // MethodFlags (0 args)
    0xA4, 0x0B, 0xB8, 0x0B, // Return(WordPrefix 0x0BB8)
};

/// Companion synthetic table: Scope(\_SB) { Device(BAT0) { _BST, _BIF } }, so
/// battery evaluation has a deterministic target too. Kept separate from
/// synth_ssdt so the (already boot-verified) thermal blob stays byte-identical.
///   _BST -> Package(4){ 1, 0x0BB8, 0x0FA0, 0x2EE0 }
///           = discharging, 3000 mW rate, 4000 mWh remaining, 12000 mV
///   _BIF -> Package(5){ 0, 0x1388, 0x1388, 1, 0x2EE0 }
///           = mWh unit, 5000 design, 5000 last-full, rechargeable, 12000 mV
/// remaining 4000 / last-full 5000 = 80%. Each PkgLength is the 1-byte form.
const synth_battery = [_]u8{
    0x10, 0x38, // ScopeOp, PkgLength=56
    0x5C, 0x5F, 0x53, 0x42, 0x5F, // RootChar '\' + "_SB_"
    0x5B, 0x82, 0x30, // DeviceOp, PkgLength=48
    0x42, 0x41, 0x54, 0x30, // "BAT0"
    // Method(_BST, 0) { Return(Package(4){ 1, 0x0BB8, 0x0FA0, 0x2EE0 }) }
    0x14, 0x14, // MethodOp, PkgLength=20
    0x5F, 0x42, 0x53, 0x54, // "_BST"
    0x00, // MethodFlags (0 args)
    0xA4, // Return
    0x12, 0x0C, 0x04, // PackageOp, PkgLength=12, NumElements=4
    0x01, // 1 (status: discharging)
    0x0B, 0xB8, 0x0B, // 0x0BB8 = 3000 mW present rate
    0x0B, 0xA0, 0x0F, // 0x0FA0 = 4000 mWh remaining capacity
    0x0B, 0xE0, 0x2E, // 0x2EE0 = 12000 mV present voltage
    // Method(_BIF, 0) { Return(Package(5){ 0, 0x1388, 0x1388, 1, 0x2EE0 }) }
    0x14, 0x15, // MethodOp, PkgLength=21
    0x5F, 0x42, 0x49, 0x46, // "_BIF"
    0x00, // MethodFlags (0 args)
    0xA4, // Return
    0x12, 0x0D, 0x05, // PackageOp, PkgLength=13, NumElements=5
    0x00, // 0 (power unit: mWh)
    0x0B, 0x88, 0x13, // 0x1388 = 5000 design capacity
    0x0B, 0x88, 0x13, // 0x1388 = 5000 last-full-charge capacity
    0x01, // 1 (battery technology: rechargeable)
    0x0B, 0xE0, 0x2E, // 0x2EE0 = 12000 mV design voltage
};

/// True when `path`'s final '.'-separated component equals `seg` (a 4-char
/// NameSeg like "_TMP"/"_BST"). Finds a well-known method anywhere in the
/// namespace without caring which device/zone it hangs off.
fn pathEndsWithSeg(path: []const u8, seg: []const u8) bool {
    if (path.len < seg.len) return false;
    if (!std.mem.eql(u8, path[path.len - seg.len ..], seg)) return false;
    if (path.len == seg.len) return true;
    const pc = path[path.len - seg.len - 1];
    return pc == '.' or pc == '\\';
}

/// Log one _TMP reading. _TMP is tenths of Kelvin (ACPI 6.4 §11.4.13); convert
/// to C in centidegrees (deci_k*10 - 27315) for two decimals without floats.
fn logTempDeciK(path: []const u8, deci_k: u64) void {
    // Cap before the i64 math: a garbage region read could otherwise overflow.
    // Real temperatures are a few thousand dK; 1e6 dK (~99726 C) is absurd-high.
    const dk: i64 = if (deci_k > 1_000_000) 1_000_000 else @intCast(deci_k);
    const centi_c: i64 = dk * 10 - 27315;
    const neg = centi_c < 0;
    const mag: u64 = @intCast(if (neg) -centi_c else centi_c);
    debug.klog("[aml] thermal {s} = {d} dK ({s}{d}.{d:0>2} C)\n", .{
        path, deci_k, if (neg) "-" else "", mag / 100, mag % 100,
    });
}

/// Slice D: evaluate every thermal-zone temperature method (\..._TMP) and report
/// it. Returns the count read. A zone whose _TMP needs an unsupported region
/// (e.g. an embedded controller) just won't evaluate to an integer and is
/// skipped — best-effort, never a fault. Public so a CLI/acpid can re-poll.
pub fn reportThermal() u32 {
    var found: u32 = 0;
    var i: usize = 0;
    while (i < nnodes) : (i += 1) {
        const n = &nodes[i];
        if (n.kind != .method) continue;
        if (!pathEndsWithSeg(n.path[0..n.path_len], "_TMP")) continue;
        arenaReset();
        const v = callMethod(n, &.{}, 0) orelse continue;
        if (v != .integer) continue;
        logTempDeciK(n.path[0..n.path_len], v.integer);
        found += 1;
    }
    if (found == 0) debug.klog("[aml] no readable thermal zones (_TMP) in namespace\n", .{});
    return found;
}

/// Integer at `idx` in a Package value, or 0 if absent / not an integer.
fn pkgInt(pkg: []const Value, idx: usize) u64 {
    if (idx >= pkg.len) return 0;
    return switch (pkg[idx]) {
        .integer => |v| v,
        else => 0,
    };
}

/// Battery state label from _BST's status bitfield (ACPI 6.4 §10.2.2.6).
fn batteryState(s: u64) []const u8 {
    if (s & 0x04 != 0) return "critical";
    if (s & 0x02 != 0) return "charging";
    if (s & 0x01 != 0) return "discharging";
    return "idle/full";
}

fn logBattery(path: []const u8, state: u64, rate: u64, remaining: u64, voltage: u64, full: u64, pct: u64) void {
    if (full != 0) {
        debug.klog("[aml] battery {s}: {s}, {d} mWh / {d} mWh ({d}%), {d} mW, {d} mV\n", .{ path, batteryState(state), remaining, full, pct, rate, voltage });
    } else {
        debug.klog("[aml] battery {s}: {s}, {d} mWh, {d} mW, {d} mV\n", .{ path, batteryState(state), remaining, rate, voltage });
    }
}

/// Slice D: evaluate every battery status method (\..._BST) and report it,
/// pairing each with its sibling _BIF (last-full-charge capacity at index 2) for
/// a charge percentage when present. Returns the count read. Best-effort: a _BST
/// that doesn't yield a 4+ element Package is skipped — never a fault. Public so
/// a CLI/acpid can re-poll.
pub fn reportBattery() u32 {
    var found: u32 = 0;
    var i: usize = 0;
    while (i < nnodes) : (i += 1) {
        const n = &nodes[i];
        if (n.kind != .method) continue;
        const path = n.path[0..n.path_len];
        if (!pathEndsWithSeg(path, "_BST")) continue;
        arenaReset();
        const bst = callMethod(n, &.{}, 0) orelse continue;
        if (bst != .package or bst.package.len < 4) continue;
        // Copy the fields out before any further eval reuses the value arena.
        const state = pkgInt(bst.package, 0);
        const rate = pkgInt(bst.package, 1);
        const remaining = pkgInt(bst.package, 2);
        const voltage = pkgInt(bst.package, 3);

        // Sibling _BIF (rewrite the trailing "_BST" seg -> "_BIF"): index 2 is the
        // last-full-charge capacity, which turns remaining mWh into a percentage.
        var full: u64 = 0;
        if (path.len <= PATH_MAX and path.len >= 4) {
            var bif_buf: [PATH_MAX]u8 = undefined;
            @memcpy(bif_buf[0..path.len], path);
            bif_buf[path.len - 2] = 'I';
            bif_buf[path.len - 1] = 'F';
            if (findExact(bif_buf[0..path.len])) |bn| {
                if (bn.kind == .method) {
                    arenaReset();
                    if (callMethod(bn, &.{}, 0)) |bif| {
                        if (bif == .package) full = pkgInt(bif.package, 2);
                    }
                }
            }
        }

        // Guard the multiply: a garbage remaining could otherwise overflow u64.
        const pct: u64 = if (full != 0 and remaining <= 100_000_000) @min(remaining * 100 / full, 100) else 0;
        logBattery(path, state, rate, remaining, voltage, full, pct);
        found += 1;
    }
    if (found == 0) debug.klog("[aml] no batteries (_BST) in namespace\n", .{});
    return found;
}

// === Slice F: ACPI namespace device enumeration =============================
// The static tables (MADT/FADT/HPET) describe the platform's interrupt + timer
// topology; the AML namespace describes its *devices*. This walks every Device()
// object, evaluates its _STA (presence), _HID/_CID (PNP/ACPI id) and _CRS
// (resource template), and reports each with decoded I/O / IRQ / memory ranges —
// the data a real OS uses to find and bind drivers (the legacy UART, the EC, the
// PCI host bridge, HPET, …). Like `acpidump` + iasl's resource decode, but live.
// Best-effort + bounds-checked: a device whose _CRS needs an unsupported region
// just lists without resources; a malformed descriptor ends that one device's
// resource list, never the walk. ACPI 6.4 §6 (device config), §6.4.2/§6.4.3
// (small/large resource data types), §5.6.4 (EISA-ID compression).

/// Decode a 32-bit EISA/PNP id (the integer form of _HID/_CID) to its 7-char
/// "PNP0501" / "ACPI0003" string. The stored DWord is byte-swapped, then 3×5-bit
/// letters ('@'+n, i.e. A=1..Z=26) followed by 4 hex nibbles.
fn eisaIdToString(v: u32, out: *[7]u8) void {
    const s = @byteSwap(v);
    const hex = "0123456789ABCDEF";
    out[0] = '@' + @as(u8, @intCast((s >> 26) & 0x1F));
    out[1] = '@' + @as(u8, @intCast((s >> 21) & 0x1F));
    out[2] = '@' + @as(u8, @intCast((s >> 16) & 0x1F));
    out[3] = hex[@as(usize, (s >> 12) & 0xF)];
    out[4] = hex[@as(usize, (s >> 8) & 0xF)];
    out[5] = hex[@as(usize, (s >> 4) & 0xF)];
    out[6] = hex[@as(usize, s & 0xF)];
}

/// Evaluate a stored Name (static data) or no-arg Method (computed) to a Value —
/// the two forms _HID/_STA/_CRS take in practice. Resets the value arena first.
fn evalNamedNode(n: *StoredNode) ?Value {
    arenaReset();
    switch (n.kind) {
        .name => {
            if (n.has_runtime) return n.runtime_val;
            var rr = Reader{ .buf = bodyOf(n), .pos = n.val_off };
            return evalData(&rr);
        },
        .method => return callMethod(n, &.{}, 0),
        else => return null,
    }
}

/// Evaluate `<dev_path>.<seg>` (e.g. "\_SB_.COM1" + "_HID") if that child object
/// exists; null when the device doesn't define it.
fn evalDeviceChild(dev_path: []const u8, seg: []const u8) ?Value {
    if (dev_path.len + 1 + seg.len > PATH_MAX) return null;
    var buf: [PATH_MAX]u8 = undefined;
    @memcpy(buf[0..dev_path.len], dev_path);
    buf[dev_path.len] = '.';
    @memcpy(buf[dev_path.len + 1 ..][0..seg.len], seg);
    const n = findExact(buf[0 .. dev_path.len + 1 + seg.len]) orelse return null;
    return evalNamedNode(n);
}

fn leU16(b: []const u8, off: usize) u16 {
    return @as(u16, b[off]) | (@as(u16, b[off + 1]) << 8);
}
fn leU32(b: []const u8, off: usize) u32 {
    return @as(u32, b[off]) | (@as(u32, b[off + 1]) << 8) |
        (@as(u32, b[off + 2]) << 16) | (@as(u32, b[off + 3]) << 24);
}

/// Read a `w`-byte (1/2/4/8) little-endian integer at `off`, clamped to the slice.
fn leSlice(b: []const u8, off: usize, w: usize) u64 {
    var v: u64 = 0;
    var i: usize = 0;
    while (i < w and off + i < b.len) : (i += 1) v |= @as(u64, b[off + i]) << @intCast(8 * i);
    return v;
}

/// Print each IRQ number set in a 16-bit IRQ mask (small IRQ descriptor).
fn printIrqMask(mask: u16) void {
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        if (mask & (@as(u16, 1) << @as(u4, @intCast(i))) != 0) debug.klog(" irq {d}", .{i});
    }
}

/// Decode a Word/DWord/QWord Address Space descriptor (a bus/io/mem window, as
/// used by the PCI host bridge _CRS) and print its label + [min, +length). d[0]
/// is the ResourceType (0=mem,1=io,2=bus); granularity/min/max/translate/length
/// follow the two flag bytes, each `w` bytes wide. Bounds-checked.
fn printAddrSpace(rtype: u8, d: []const u8) u32 {
    if (d.len < 3) return 0;
    const label: []const u8 = switch (d[0]) {
        0 => "mem",
        1 => "io",
        2 => "bus",
        else => "win",
    };
    const w: usize = switch (rtype) {
        0x08 => 2, // WordAddressSpace
        0x0A => 8, // QWordAddressSpace
        else => 4, // DWordAddressSpace (0x07)
    };
    const min_off = 3 + w; // skip granularity (1st integer)
    const len_off = 3 + 4 * w; // length is the 5th integer
    if (len_off + w > d.len) return 0;
    const min = leSlice(d, min_off, w);
    const len = leSlice(d, len_off, w);
    debug.klog(" {s} 0x{X}+0x{X}", .{ label, min, len });
    return 1;
}

/// Parse a _CRS ResourceTemplate buffer, printing its I/O / IRQ / memory items
/// inline (continuing the current device's line). Returns the count printed. The
/// descriptor stream is bounds-checked at every step; the End Tag (or any
/// truncation) stops the list cleanly. ACPI 6.4 §6.4.
fn printCrsResources(buf: []const u8) u32 {
    var count: u32 = 0;
    var i: usize = 0;
    while (i < buf.len) {
        const tag = buf[i];
        if (tag & 0x80 == 0) {
            // Small resource: bit7=0, bits6:3 = type, bits2:0 = data length.
            const dlen: usize = @as(usize, tag) & 0x07;
            const rtype: u8 = (tag >> 3) & 0x0F;
            const ds = i + 1;
            if (ds + dlen > buf.len) return count;
            const d = buf[ds .. ds + dlen];
            switch (rtype) {
                0x04 => { // IRQ Format: 2-byte mask (+ optional 1-byte flags)
                    if (d.len >= 2) {
                        printIrqMask(leU16(d, 0));
                        count += 1;
                    }
                },
                0x08 => { // I/O Port: info, min(2), max(2), align, len
                    if (d.len >= 7) {
                        const base = leU16(d, 1);
                        const len = d[6];
                        const last = if (len > 0) base +% (@as(u16, len) - 1) else base;
                        debug.klog(" io 0x{X:0>4}-0x{X:0>4}", .{ base, last });
                        count += 1;
                    }
                },
                0x09 => { // Fixed Location I/O Port: base(2), len(1)
                    if (d.len >= 3) {
                        const base = leU16(d, 0);
                        const len = d[2];
                        const last = if (len > 0) base +% (@as(u16, len) - 1) else base;
                        debug.klog(" io 0x{X:0>4}-0x{X:0>4}", .{ base, last });
                        count += 1;
                    }
                },
                0x0F => return count, // End Tag
                else => {}, // DMA / dependent / vendor: skip
            }
            i = ds + dlen;
        } else {
            // Large resource: bits6:0 = type, then 2-byte length, then data.
            if (i + 3 > buf.len) return count;
            const rtype: u8 = tag & 0x7F;
            const dlen: usize = @as(usize, buf[i + 1]) | (@as(usize, buf[i + 2]) << 8);
            const ds = i + 3;
            if (ds + dlen > buf.len) return count;
            const d = buf[ds .. ds + dlen];
            switch (rtype) {
                0x06 => { // 32-bit Fixed Memory: info(1), base(4), len(4)
                    if (d.len >= 9) {
                        debug.klog(" mem 0x{X:0>8}+0x{X}", .{ leU32(d, 1), leU32(d, 5) });
                        count += 1;
                    }
                },
                0x01 => { // 24-bit Memory Range: info(1), min(2), max(2), aln(2), len(2)
                    if (d.len >= 9) {
                        debug.klog(" mem 0x{X:0>8}+0x{X}", .{ @as(u32, leU16(d, 1)) << 8, @as(u32, leU16(d, 7)) << 8 });
                        count += 1;
                    }
                },
                0x09 => { // Extended IRQ: flags(1), count(1), then count × 4-byte IRQ #s
                    if (d.len >= 2) {
                        const cnt = d[1];
                        var k: usize = 0;
                        while (k < cnt and 2 + k * 4 + 4 <= d.len) : (k += 1) {
                            debug.klog(" irq {d}", .{leU32(d, 2 + k * 4)});
                            count += 1;
                        }
                    }
                },
                0x07, 0x08, 0x0A => count += printAddrSpace(rtype, d), // bus/io/mem window
                else => {},
            }
            i = ds + dlen;
        }
    }
    return count;
}

/// Slice F: enumerate every present ACPI Device() in the namespace, reporting
/// _HID/_CID (or _ADR), _STA presence, and decoded _CRS resources. Devices whose
/// _STA marks them not-present (empty hotplug slots) are counted, not listed.
/// Returns the present-device count. Public so the `acpidev` CLI and boot path
/// can list the platform's ACPI-described hardware.
pub fn reportDevices() u32 {
    debug.klog("[acpi] ACPI namespace devices (Device + _HID/_CID + _CRS):\n", .{});
    var shown: u32 = 0;
    var hidden: u32 = 0;
    var i: usize = 0;
    while (i < nnodes) : (i += 1) {
        const n = &nodes[i];
        if (n.kind != .device) continue;
        const path = n.path[0..n.path_len];

        // _STA: absent ⇒ assume present+enabled (0x0F). bit0 clear ⇒ not present.
        var sta: u64 = 0x0F;
        if (evalDeviceChild(path, "_STA")) |v| {
            if (v == .integer) sta = v.integer;
        }
        if (sta & 0x01 == 0) {
            hidden += 1;
            continue;
        }

        debug.klog("[acpi]   {s}", .{path});

        // _HID (PNP/ACPI id) — integer EISAID or string; captured into idbuf for
        // the role lookup below. Falls back to _ADR for resource-only PCI slots.
        var idbuf: [16]u8 = undefined;
        var idlen: usize = 0;
        if (evalDeviceChild(path, "_HID")) |v| {
            switch (v) {
                .integer => |iv| {
                    var hid: [7]u8 = undefined;
                    eisaIdToString(@truncate(iv), &hid);
                    @memcpy(idbuf[0..7], &hid);
                    idlen = 7;
                },
                .string => |s| {
                    idlen = @min(s.len, idbuf.len);
                    @memcpy(idbuf[0..idlen], s[0..idlen]);
                },
                else => {},
            }
        }
        if (idlen > 0) {
            debug.klog("  {s}", .{idbuf[0..idlen]});
        } else if (evalDeviceChild(path, "_ADR")) |v| {
            if (v == .integer) debug.klog("  _ADR=0x{X}", .{v.integer}) else debug.klog("  ----", .{});
        } else {
            debug.klog("  ----", .{});
        }

        // _CID (compatible id), shown when it's a single EISAID/string.
        if (evalDeviceChild(path, "_CID")) |v| {
            switch (v) {
                .integer => |iv| {
                    var cid: [7]u8 = undefined;
                    eisaIdToString(@truncate(iv), &cid);
                    debug.klog("/{s}", .{&cid});
                },
                .string => |s| debug.klog("/{s}", .{s}),
                else => {},
            }
        }

        // Slice G: the kernel role/driver that claims this _HID, when known.
        if (idlen > 0) {
            if (roleForId(idbuf[0..idlen])) |role| debug.klog("  -> {s}", .{role});
        }

        // _CRS decoded resources, inline.
        if (evalDeviceChild(path, "_CRS")) |v| {
            if (v == .buffer) _ = printCrsResources(v.buffer);
        }

        debug.klog("\n", .{});
        shown += 1;
    }
    if (shown == 0 and hidden == 0) debug.klog("[acpi]   (no Device() objects in namespace)\n", .{});
    if (hidden > 0) {
        debug.klog("[acpi] {d} device(s) present, {d} absent/empty slot(s) hidden\n", .{ shown, hidden });
    } else {
        debug.klog("[acpi] {d} device(s) present\n", .{shown});
    }
    return shown;
}

// === Slice G: ACPI device → kernel-driver binding ===========================
// Slice F lists what hardware ACPI *describes*; this maps each device's _HID/_CID
// to the kernel role that drives it, and exposes findByHid() so a consumer can
// pull a device's I/O base / IRQ / MMIO from ACPI instead of hardcoding it. Most
// legacy drivers init *before* the AML namespace exists, so the namespace's job
// here is discovery + validation + late-binding (hotplug / EC / thermal);
// crossCheckBindings() proves the data is correct by agreeing with the values the
// kernel independently runs on — the same two-decoders-one-verdict idiom as the
// \_S5_ static-scan-vs-AML-eval check.

const HidRole = struct { id: []const u8, role: []const u8 };

/// Known PNP/ACPI/vendor ids → the kernel role/driver that claims them. Matched
/// against both _HID and _CID; first hit wins.
const hid_roles = [_]HidRole{
    .{ .id = "PNP0A08", .role = "pcie-host" },
    .{ .id = "PNP0A03", .role = "pci-host" },
    .{ .id = "PNP0A06", .role = "acpi-container" },
    .{ .id = "PNP0A05", .role = "acpi-bus" },
    .{ .id = "PNP0C0F", .role = "pci-link" },
    .{ .id = "PNP0C01", .role = "system-board" },
    .{ .id = "PNP0103", .role = "hpet" },
    .{ .id = "PNP0303", .role = "ps2-kbd" },
    .{ .id = "PNP0F13", .role = "ps2-mouse" },
    .{ .id = "PNP0501", .role = "uart-16550" },
    .{ .id = "PNP0400", .role = "parallel" },
    .{ .id = "PNP0B00", .role = "rtc-cmos" },
    .{ .id = "ACPI0010", .role = "cpu-container" },
    .{ .id = "ACPI0003", .role = "ac-adapter" },
    .{ .id = "PNP0C0A", .role = "battery" },
    .{ .id = "QEMU0002", .role = "fw-cfg" },
};

fn roleForId(id: []const u8) ?[]const u8 {
    for (hid_roles) |hr| {
        if (std.mem.eql(u8, hr.id, id)) return hr.role;
    }
    return null;
}

/// First-of-each decoded resource from a device's _CRS — what a driver needs to
/// claim the hardware.
pub const DevResources = struct {
    io_base: ?u16 = null,
    irq: ?u8 = null,
    mem_base: ?u64 = null,
};

/// Scan a _CRS buffer for the first I/O base, IRQ and memory base (best-effort,
/// bounds-checked) — the structured counterpart of printCrsResources.
fn extractCrs(buf: []const u8) DevResources {
    var out = DevResources{};
    var i: usize = 0;
    while (i < buf.len) {
        const tag = buf[i];
        if (tag & 0x80 == 0) {
            const dlen: usize = @as(usize, tag) & 0x07;
            const rtype: u8 = (tag >> 3) & 0x0F;
            const ds = i + 1;
            if (ds + dlen > buf.len) return out;
            const d = buf[ds .. ds + dlen];
            switch (rtype) {
                0x04 => if (out.irq == null and d.len >= 2) { // IRQ mask → lowest set line
                    const mask = leU16(d, 0);
                    var b: u32 = 0;
                    while (b < 16) : (b += 1) {
                        if (mask & (@as(u16, 1) << @as(u4, @intCast(b))) != 0) {
                            out.irq = @intCast(b);
                            break;
                        }
                    }
                },
                0x08 => if (out.io_base == null and d.len >= 7) {
                    out.io_base = leU16(d, 1);
                },
                0x09 => if (out.io_base == null and d.len >= 3) {
                    out.io_base = leU16(d, 0);
                },
                0x0F => return out, // End Tag
                else => {},
            }
            i = ds + dlen;
        } else {
            if (i + 3 > buf.len) return out;
            const rtype: u8 = tag & 0x7F;
            const dlen: usize = @as(usize, buf[i + 1]) | (@as(usize, buf[i + 2]) << 8);
            const ds = i + 3;
            if (ds + dlen > buf.len) return out;
            const d = buf[ds .. ds + dlen];
            switch (rtype) {
                0x06 => if (out.mem_base == null and d.len >= 9) {
                    out.mem_base = leU32(d, 1);
                },
                0x09 => if (out.irq == null and d.len >= 6) {
                    out.irq = @truncate(leU32(d, 2)); // Extended IRQ: first listed line
                },
                else => {},
            }
            i = ds + dlen;
        }
    }
    return out;
}

fn idMatches(v: Value, id: []const u8) bool {
    switch (v) {
        .integer => |iv| {
            var s: [7]u8 = undefined;
            eisaIdToString(@truncate(iv), &s);
            return std.mem.eql(u8, &s, id);
        },
        .string => |s| return std.mem.eql(u8, s, id),
        else => return false,
    }
}

fn deviceMatchesId(path: []const u8, id: []const u8) bool {
    if (evalDeviceChild(path, "_HID")) |v| {
        if (idMatches(v, id)) return true;
    }
    if (evalDeviceChild(path, "_CID")) |v| {
        if (idMatches(v, id)) return true;
    }
    return false;
}

/// Find the first *present* device whose _HID or _CID equals `id` and return its
/// decoded _CRS resources (null if none present). The consumption API: a driver
/// or late-binder pulls its I/O base / IRQ / MMIO from ACPI rather than hardcoding
/// it. `id` is a 7-char EISA id like "PNP0501" or a vendor string like "QEMU0002".
pub fn findByHid(id: []const u8) ?DevResources {
    var i: usize = 0;
    while (i < nnodes) : (i += 1) {
        const n = &nodes[i];
        if (n.kind != .device) continue;
        const path = n.path[0..n.path_len];
        var sta: u64 = 0x0F;
        if (evalDeviceChild(path, "_STA")) |v| {
            if (v == .integer) sta = v.integer;
        }
        if (sta & 0x01 == 0) continue;
        if (!deviceMatchesId(path, id)) continue;
        if (evalDeviceChild(path, "_CRS")) |v| {
            if (v == .buffer) return extractCrs(v.buffer);
        }
        return DevResources{}; // matched, but defines no _CRS
    }
    return null;
}

/// Slice G proof: cross-check a few enumerated legacy-device resources against
/// the values the kernel independently knows — proving the namespace yields
/// correct, consumable resource data.
fn crossCheckBindings() void {
    if (findByHid("PNP0501")) |r| { // COM1 → 16550 UART
        const iob = r.io_base orelse 0;
        debug.klog("[acpi] bind uart-16550: ACPI COM1 io 0x{X} irq {d} ({s} 0x3F8)\n", .{ iob, r.irq orelse 0, if (iob == 0x3F8) "matches" else "DIFFERS from" });
    }
    if (findByHid("PNP0103")) |r| { // HPET: namespace _CRS vs the static HPET table
        const ns = r.mem_base orelse 0;
        if (acpi.getHpet()) |h| {
            const tbl: u64 = h.address.address;
            debug.klog("[acpi] bind hpet: namespace _CRS 0x{X} vs HPET table 0x{X} ({s})\n", .{ ns, tbl, if (ns == tbl) "MATCH" else "MISMATCH" });
        } else {
            debug.klog("[acpi] bind hpet: namespace _CRS 0x{X} (no HPET table)\n", .{ns});
        }
    }
    if (findByHid("PNP0303")) |r| { // PS/2 keyboard → legacy IRQ 1
        const irq = r.irq orelse 0;
        debug.klog("[acpi] bind ps2-kbd: ACPI irq {d} ({s} 1)\n", .{ irq, if (irq == 1) "matches" else "DIFFERS from" });
    }
}

// === Slice H: PCI interrupt routing from _PRT ===============================
// \_SB.PCI0._PRT maps each PCI device's INTx pin to an interrupt source: either a
// GSI directly (integer source) or — on q35 — a reference to a PCI interrupt
// *link* device (GSIx in APIC mode, LNKx in PIC mode) whose _CRS carries the GSI.
// This builds that routing table (selecting APIC mode via _PIC first), resolves
// each link through a seg→GSI map, and caches it so gsiForPciPin() can hand the
// kernel's PCI/IOAPIC code the GSI for a legacy INTx interrupt — sourced from
// ACPI instead of guessed. ACPI 6.4 §6.2.13 (_PRT), §6.2.9 (link _PRS/_CRS).

const PrtRoute = struct { dev: u8, pin: u8, gsi: u32 };
var prt_routes: [160]PrtRoute = undefined;
var prt_nroutes: usize = 0;

// seg→GSI map for interrupt-link devices, built once *before* the _PRT package is
// walked (the per-link _CRS evals reset the value arena the package lives in).
const LinkGsi = struct { seg: [4]u8, gsi: u32 };
var link_map: [64]LinkGsi = undefined;
var nlink: usize = 0;

fn pinChar(p: u8) u8 {
    const idx: u8 = @min(p, 3);
    return 'A' + idx;
}

/// The final 4-byte NameSeg of an absolute path (e.g. "\_SB_.GSIA" → "GSIA").
fn lastSeg(path: []const u8) [4]u8 {
    var start: usize = 0;
    var k: usize = path.len;
    while (k > 0) : (k -= 1) {
        if (path[k - 1] == '.' or path[k - 1] == '\\') {
            start = k;
            break;
        }
    }
    var seg = [4]u8{ '_', '_', '_', '_' };
    const comp = path[start..];
    const n = @min(comp.len, 4);
    @memcpy(seg[0..n], comp[0..n]);
    return seg;
}

/// Resolve every device's _CRS IRQ into the seg→GSI map. The interrupt-link
/// devices (GSIx/LNKx) land here with their routed GSI; other devices' irqs are
/// harmless (their segs never match a _PRT source). Resets the value arena.
fn buildLinkMap() void {
    nlink = 0;
    var i: usize = 0;
    while (i < nnodes and nlink < link_map.len) : (i += 1) {
        const nd = &nodes[i];
        if (nd.kind != .device) continue;
        const p = nd.path[0..nd.path_len];
        if (evalDeviceChild(p, "_CRS")) |v| {
            if (v == .buffer) {
                const rr = extractCrs(v.buffer);
                if (rr.irq) |q| {
                    link_map[nlink] = .{ .seg = lastSeg(p), .gsi = q };
                    nlink += 1;
                }
            }
        }
    }
}

fn lookupLink(seg: [4]u8) ?u32 {
    var i: usize = 0;
    while (i < nlink) : (i += 1) {
        if (std.mem.eql(u8, &link_map[i].seg, &seg)) return link_map[i].gsi;
    }
    return null;
}

/// Slice H: build the PCI INTx → GSI routing table from \_SB.PCI0._PRT and cache
/// it for gsiForPciPin(). Returns the number of pins routed.
pub fn buildPrt() u32 {
    prt_nroutes = 0;
    // Announce APIC mode so q35 returns IOAPIC (GSIx) routing, not the 8259 table.
    _ = evalMethodArg1("\\_PIC", .{ .integer = 1 });
    buildLinkMap(); // before the _PRT eval — link _CRS evals reset the arena

    arenaReset();
    const prt = evalMethod("\\_SB_.PCI0._PRT") orelse {
        debug.klog("[acpi] _PRT: \\_SB_.PCI0._PRT not found\n", .{});
        return 0;
    };
    if (prt != .package) {
        debug.klog("[acpi] _PRT: not a Package\n", .{});
        return 0;
    }

    // Each entry: Package{ Address(DWord: dev<<16 | fn), Pin(0..3), Source, Index }.
    // Source is a link NameSeg (name_ref) or integer 0 (then Index is the GSI).
    for (prt.package) |entry| {
        if (prt_nroutes >= prt_routes.len) break;
        if (entry != .package or entry.package.len < 4) continue;
        const e = entry.package;
        if (e[0] != .integer or e[1] != .integer) continue;
        const dev: u8 = @truncate(e[0].integer >> 16);
        const pin: u8 = @truncate(e[1].integer);
        var gsi: ?u32 = null;
        switch (e[2]) {
            .name_ref => |s| gsi = lookupLink(s),
            .integer => |s| if (s == 0 and e[3] == .integer) {
                gsi = @truncate(e[3].integer);
            },
            else => {},
        }
        if (gsi) |g| {
            prt_routes[prt_nroutes] = .{ .dev = dev, .pin = pin, .gsi = g };
            prt_nroutes += 1;
        }
    }

    debug.klog("[acpi] PCI interrupt routing (\\_SB.PCI0._PRT, {d} entries -> {d} routed):\n", .{ prt.package.len, prt_nroutes });
    var shown: usize = 0;
    while (shown < prt_nroutes and shown < 8) : (shown += 1) {
        const r = prt_routes[shown];
        debug.klog("[acpi]   00:{X:0>2}.x INT{c} -> gsi {d}\n", .{ r.dev, pinChar(r.pin), r.gsi });
    }
    return @intCast(prt_nroutes);
}

/// The consumption API: the IOAPIC GSI a PCI device's INTx pin routes to per ACPI
/// _PRT (pin 0=INTA..3=INTD), or null if absent. A driver enabling a legacy INTx
/// interrupt programs its IOAPIC redirection entry for this GSI.
pub fn gsiForPciPin(dev: u8, pin: u8) ?u32 {
    var i: usize = 0;
    while (i < prt_nroutes) : (i += 1) {
        if (prt_routes[i].dev == dev and prt_routes[i].pin == pin) return prt_routes[i].gsi;
    }
    return null;
}

/// Join the cached _PRT routing against live PCI config space: for every bus-0
/// device that declares an INT pin (config 0x3D), show the ACPI-derived GSI — the
/// load-bearing proof that the routing table maps onto real hardware. Run from the
/// `acpiprt` CLI (after PCI enumeration has populated the device cache).
pub fn reportPrtPciJoin() void {
    const pci = @import("../driver/pci.zig");
    debug.klog("[acpi] _PRT join with live PCI config (bus 0):\n", .{});
    var matched: u32 = 0;
    var pinned: u32 = 0;
    for (pci.allDevices()) |d| {
        if (d.bus != 0) continue; // \_SB.PCI0._PRT covers bus 0
        const il = pci.configRead16(d.bus, d.dev, d.func, 0x3C);
        const pin_raw: u8 = @truncate(il >> 8); // config 0x3D: 0=none, 1=INTA..4=INTD
        if (pin_raw == 0 or pin_raw > 4) continue;
        pinned += 1;
        const pin = pin_raw - 1;
        if (gsiForPciPin(d.dev, pin)) |g| {
            debug.klog("[acpi]   00:{X:0>2}.{d} INT{c} -> gsi {d} (cfg line {d})\n", .{ d.dev, d.func, pinChar(pin), g, il & 0xFF });
            matched += 1;
        } else {
            debug.klog("[acpi]   00:{X:0>2}.{d} INT{c} -> (no _PRT route)\n", .{ d.dev, d.func, pinChar(pin) });
        }
    }
    debug.klog("[acpi] _PRT join: {d}/{d} INTx PCI device(s) matched an ACPI route\n", .{ matched, pinned });
}

// --- entry point ------------------------------------------------------------

/// Decode the cached DSDT plus every SSDT into one namespace, then run the
/// boot-time proofs. Call after acpi.init has cached the tables. Best-effort:
/// logs a summary; a malformed table yields a partial walk, never a fault.
/// Returns the total named-object count.
pub fn load() u32 {
    // Deterministic interpreter self-tests first. Each is self-contained (walks
    // its own hand-assembled table into the store), so it must run BEFORE the
    // reset below — which then hands the real DSDT walk a clean namespace.
    const st_fails = selfTestExtended();
    if (st_fails != 0) debug.klog("[aml] !!! {d} interpreter self-test(s) FAILED\n", .{st_fails});

    node_count = 0;
    unknown_op_seen = 0;
    nnodes = 0;
    store_overflow = false;
    nbodies = 0;
    arenaReset();

    // Table 0: the DSDT — the namespace root. SSDTs (next) re-open \_SB etc. by
    // path, so we still load them even if the DSDT is somehow absent.
    var dsdt_objs: u32 = 0;
    if (acpi.getDsdt()) |dsdt| {
        dsdt_objs = walkTable(dsdt);
    } else {
        debug.klog("[aml] no DSDT cached — namespace limited to SSDTs\n", .{});
    }

    // Tables 1..N: every SSDT. Real firmware splits thermal zones, batteries and
    // CPU objects across these; `-acpitable sig=SSDT,...` injects one here too.
    var ssdt_objs: u32 = 0;
    var si: usize = 0;
    while (si < acpi.ssdtCount()) : (si += 1) {
        if (acpi.getSsdt(si)) |s| ssdt_objs += walkTable(s);
    }

    // A built-in synthetic SSDT (\_SB.TZ0._TMP) so thermal evaluation has a
    // deterministic target even on firmware that ships no thermal zone. Loaded
    // through the exact same multi-table path — proves SSDT loading every boot.
    if (SYNTH_TEST) {
        _ = walkBody(&synth_ssdt); // thermal zone \_SB.TZ0
        _ = walkBody(&synth_battery); // battery \_SB.BAT0
    }

    // Freeze the static namespace size: everything walked so far is permanent;
    // CreateField nodes created later at exec time live past this mark and are
    // reclaimed by each top-level arenaReset.
    static_nnodes = nnodes;

    if (unknown_op_seen != 0) {
        debug.klog("[aml] walk stopped early at unmodeled opcode 0x{X} ({d} objects so far)\n", .{ unknown_op_seen, node_count });
    } else {
        debug.klog("[aml] namespace walk complete: {d} named objects\n", .{node_count});
    }
    debug.klog("[aml] namespace: DSDT {d} obj + {d} SSDT(s) {d} obj{s} = {d} total{s}\n", .{
        dsdt_objs, acpi.ssdtCount(), ssdt_objs,
        if (SYNTH_TEST) " + synthetic test SSDT" else "",
        nnodes, if (store_overflow) " (TRUNCATED)" else "",
    });

    // B2a proof: evaluate \_S5_ through the interpreter and report SLP_TYP — the
    // same datum Slice A's static scan extracts, now produced by the general
    // value path (Name lookup + Package/integer decode).
    arenaReset();
    if (findExact("\\_S5_")) |n| {
        var er = Reader{ .buf = bodyOf(n), .pos = n.val_off };
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

    // B2b proof: run the executor against a real firmware control method
    // (\_SB_.PCI0._PRT: If/Else on \PICF returning a PCI-routing Package) to
    // exercise method calls + control flow end to end. (The deterministic
    // interpreter self-tests already ran at the top of load(), before the walk.)
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

    // Slice D proof: read every thermal zone + battery — the synthetic \_SB.TZ0
    // and \_SB.BAT0 are always present; real/-acpitable objects report alongside.
    _ = reportThermal();
    _ = reportBattery();

    // Slice F proof: enumerate the namespace's Device() objects with decoded
    // _HID/_CID + _CRS resources — ACPI as the platform's device manager, run
    // against QEMU's real q35 DSDT (COM/PS2/RTC/HPET/PCI-root all carry _CRS).
    _ = reportDevices();

    // Slice G proof: the enumerated _HIDs map to kernel roles (shown above), and
    // a few legacy resources cross-check against what the kernel independently runs.
    crossCheckBindings();

    // Slice H proof: build the PCI INTx → GSI routing table from \_SB.PCI0._PRT
    // (selecting APIC mode via _PIC), resolving each link device to its GSI.
    _ = buildPrt();
    return node_count;
}
