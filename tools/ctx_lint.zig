//! ctx_lint — context-coloring + lock-discipline lint over the kernel tree.
//!
//! Host tool, run by build.zig before the kernel links (like
//! check_asm_alignment.py). Parses every `src/**/*.zig` with std.zig.Ast
//! and checks four disciplines the kernel documents in STYLE.md but the
//! compiler cannot enforce:
//!
//!   1. `data__` tripwire — Guarded(T)'s payload field is reachable only
//!      through a Held/IrqHeld token; `.data__` anywhere outside
//!      util/guarded.zig is a bypass. ERROR.
//!   2. Context coloring — a function annotated `// ctx: irq` (and every
//!      handler passed to idt.registerIrq / msix.allocVector / msix.armOne)
//!      runs with interrupts masked, on an IRQ frame, on whichever task
//!      happened to be current. It must never reach a function that may
//!      park the caller: the `sched.blockOn*` family, `Mutex.acquire` —
//!      identified structurally as "calls spinlock.mightSleep(@src())".
//!      The walk follows the statically resolvable call graph (same-file
//!      calls, `alias.fn()` through `@import` aliases and `const x =
//!      mod.fn` re-exports, `Type.method()` through type aliases, method
//!      calls by name within a file). A path root → … → sleeper is an
//!      ERROR, printed in full. `// ctx: irq-ok <reason>` on a function
//!      cuts the walk there — the documented "this branches on context"
//!      exemption; the reason is mandatory prose for the reviewer.
//!   3. Stale `(p:lock)` field tags — a field comment naming a lock that
//!      is neither a field of the enclosing struct, nor a file-scope var,
//!      nor one of the documented cross-object locks (`rq.lock`,
//!      `owning-cpu-cli`) is a tag that outlived its lock. ERROR.
//!   4. Sleep under spinlock — a body that takes a SpinLock / Guarded
//!      window (`.acquire()` / `.acquireIrqSave()` on a non-Mutex
//!      receiver) and, before the matching `.release*()` (a `defer`red
//!      release holds to the end of the body), calls a function that may
//!      sleep. Heuristic (textual receiver match) — WARNING, not error;
//!      spinlock.mightSleep is the runtime check with the last word.
//!
//! What it deliberately does not do: type inference. Method calls on
//! unknown receivers resolve by name within the file, calls through
//! function pointers (`.cb`, DynHandler tables) are not followed, and a
//! call the lint cannot resolve is counted, not guessed. Every ERROR names
//! file:line; a lint that inspected nothing refuses to PASS (see the
//! sanity floor in main).

const std = @import("std");
const Ast = std.zig.Ast;
const TokenIndex = Ast.TokenIndex;
const NodeIndex = Ast.Node.Index;

const NONE: u32 = std.math.maxInt(u32);

/// Registration calls whose function-valued arguments are IRQ roots.
const irq_registrars = [_][]const u8{ "registerIrq", "allocVector", "armOne" };
/// Cross-object locks a `(p:...)` tag may name without a same-scope decl.
const external_locks = [_][]const u8{ "rq.lock", "owning-cpu-cli" };
/// Method names that open a lock window / close one.
const acquire_names = [_][]const u8{ "acquire", "acquireIrqSave" };
const release_names = [_][]const u8{ "release", "releaseIrqRestore" };

const FieldInfo = struct {
    name: []const u8,
    type_text: []const u8,
};

const ContainerInfo = struct {
    file: u32,
    first: TokenIndex,
    last: TokenIndex,
    fields: std.ArrayList(FieldInfo) = .empty,
};

const FnInfo = struct {
    file: u32,
    name: []const u8,
    line: usize, // 1-based
    first: TokenIndex, // fn proto first token (for annotation scan)
    body_first: TokenIndex,
    body_last: TokenIndex,
    container: u32, // ContainerInfo index or NONE
    is_root: bool = false,
    is_cut: bool = false,
    /// `// ctx: lock-ok <reason>` — the sleep-under-spinlock heuristic is
    /// silenced for this body (a deliberate test, or a reviewed shape the
    /// textual receiver match cannot follow).
    lock_ok: bool = false,
    has_might_sleep: bool = false,
    /// Direct call sites: callee fn index + the call's first token (for
    /// the sleep-under-spinlock range test).
    calls: std.ArrayList(CallEdge) = .empty,
    /// DFS memo for may-sleep: 0 = unknown, 1 = no, 2 = yes.
    may_sleep_memo: u8 = 0,
    /// Cycle guard for the memo walk.
    visiting: bool = false,
};

const CallEdge = struct {
    callee: u32,
    tok: TokenIndex,
};

const AliasTarget = struct {
    file: u32,
    /// Decl name in `file`, or empty for a whole-module alias.
    name: []const u8,
};

const FileInfo = struct {
    path: []const u8, // normalized, relative to the src root
    source: [:0]const u8,
    tree: Ast,
    /// `const x = @import("...")` → module alias.
    imports: std.StringHashMap(u32),
    /// `const x = mod.decl` / `const x = @import("...").decl` → decl alias.
    decl_aliases: std.StringHashMap(AliasTarget),
    /// File-scope `var`/`const` names → declared type text ("" if inferred).
    vars: std.StringHashMap([]const u8),
    /// Indices into `fns` declared in this file.
    fns: std.ArrayList(u32) = .empty,
    /// Indices into `containers` declared in this file.
    containers: std.ArrayList(u32) = .empty,
};

/// What every container field of a given name is declared as, tree-wide.
/// Lets `x.as_lock.acquire()` in one file know that `as_lock` is a Mutex
/// declared on the PCB in another — without type inference. `mixed` means
/// the name is used for both kinds somewhere; the lint then refuses to
/// guess and treats the receiver as a spinlock window (the conservative
/// side for the sleep-under-lock check, the noisy side for warnings).
const FieldKind = enum(u8) { mutex, other, mixed };

const Lint = struct {
    alloc: std.mem.Allocator,
    files: std.ArrayList(FileInfo) = .empty,
    fns: std.ArrayList(FnInfo) = .empty,
    containers: std.ArrayList(ContainerInfo) = .empty,
    path_index: std.StringHashMap(u32),
    /// Files reachable from main.zig through @import — the compiled set.
    /// Anything else in the tree (stale staging copies, dead experiments)
    /// is skipped: it is not the kernel.
    reachable: std.AutoHashMap(u32, void),
    field_kinds: std.StringHashMap(FieldKind),
    errors: u32 = 0,
    warnings: u32 = 0,
    calls_total: u32 = 0,
    calls_unresolved: u32 = 0,
    lock_tags: u32 = 0,
    guarded_file: u32 = NONE,
    verbose: bool = false,

    fn err(self: *Lint, comptime fmt: []const u8, args: anytype) void {
        self.errors += 1;
        std.debug.print("[ctx-lint] ERROR " ++ fmt ++ "\n", args);
    }

    fn warn(self: *Lint, comptime fmt: []const u8, args: anytype) void {
        self.warnings += 1;
        std.debug.print("[ctx-lint] WARN  " ++ fmt ++ "\n", args);
    }

    // ---------------------------------------------------------------------
    // Loading
    // ---------------------------------------------------------------------

    fn loadTree(self: *Lint, root: []const u8) !void {
        var dir = try std.fs.cwd().openDir(root, .{ .iterate = true });
        defer dir.close();
        var walker = try dir.walk(self.alloc);
        defer walker.deinit();
        while (try walker.next()) |e| {
            if (e.kind != .file) continue;
            if (!std.mem.endsWith(u8, e.basename, ".zig")) continue;
            const bytes = try dir.readFileAlloc(self.alloc, e.path, 64 << 20);
            const src = try self.alloc.dupeZ(u8, bytes);
            const tree = try Ast.parse(self.alloc, src, .zig);
            if (tree.errors.len != 0) {
                // A file the compiler will reject anyway; not our verdict.
                std.debug.print("[ctx-lint] note: {s}: {d} parse error(s), skipped\n", .{ e.path, tree.errors.len });
                continue;
            }
            const path = try normalizeSlashes(self.alloc, e.path);
            const idx: u32 = @intCast(self.files.items.len);
            try self.files.append(self.alloc, .{
                .path = path,
                .source = src,
                .tree = tree,
                .imports = std.StringHashMap(u32).init(self.alloc),
                .decl_aliases = std.StringHashMap(AliasTarget).init(self.alloc),
                .vars = std.StringHashMap([]const u8).init(self.alloc),
            });
            try self.path_index.put(path, idx);
            if (std.mem.eql(u8, path, "util/guarded.zig")) self.guarded_file = idx;
        }
    }

    /// BFS over every `@import("x.zig")` from main.zig.
    fn computeReachable(self: *Lint) !void {
        const root = self.path_index.get("main.zig") orelse return error.NoMainZig;
        var queue: std.ArrayList(u32) = .empty;
        try queue.append(self.alloc, root);
        try self.reachable.put(root, {});
        var qi: usize = 0;
        while (qi < queue.items.len) : (qi += 1) {
            const fi = queue.items[qi];
            const tree = self.files.items[fi].tree;
            var i: u32 = 0;
            while (i < tree.nodes.len) : (i += 1) {
                const n: NodeIndex = @enumFromInt(i);
                switch (tree.nodeTag(n)) {
                    .builtin_call_two, .builtin_call_two_comma => {},
                    else => continue,
                }
                const target = self.importTarget(fi, n) orelse continue;
                if (self.reachable.contains(target)) continue;
                try self.reachable.put(target, {});
                try queue.append(self.alloc, target);
            }
        }
    }

    fn isReachable(self: *Lint, fi: u32) bool {
        return self.reachable.contains(fi);
    }

    // ---------------------------------------------------------------------
    // Pass 1: declarations — fns, containers + fields, aliases, data__.
    // ---------------------------------------------------------------------

    fn collectDecls(self: *Lint, fi: u32) !void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        var i: u32 = 0;
        while (i < tree.nodes.len) : (i += 1) {
            const n: NodeIndex = @enumFromInt(i);
            switch (tree.nodeTag(n)) {
                .fn_decl => try self.collectFn(fi, n),
                .container_decl,
                .container_decl_trailing,
                .container_decl_two,
                .container_decl_two_trailing,
                .container_decl_arg,
                .container_decl_arg_trailing,
                .tagged_union,
                .tagged_union_trailing,
                .tagged_union_two,
                .tagged_union_two_trailing,
                .tagged_union_enum_tag,
                .tagged_union_enum_tag_trailing,
                => try self.collectContainer(fi, n),
                .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => try self.collectVar(fi, n),
                .field_access => {
                    const name_tok = tree.nodeData(n).node_and_token[1];
                    if (std.mem.eql(u8, tree.tokenSlice(name_tok), "data__") and fi != self.guarded_file) {
                        self.err("`.data__` outside util/guarded.zig — Guarded payload reached without a Held token: {s}:{d}", .{ f.path, self.lineOf(fi, name_tok) });
                    }
                },
                else => {},
            }
        }
        // Container membership for fns: innermost container whose token
        // range contains the fn's first token.
        for (f.fns.items) |fn_idx| {
            const fnp = &self.fns.items[fn_idx];
            fnp.container = self.innermostContainer(fi, fnp.first);
        }
    }

    fn collectFn(self: *Lint, fi: u32, n: NodeIndex) !void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        const pair = tree.nodeData(n).node_and_node;
        const proto = pair[0];
        const body = pair[1];
        var buf: [1]NodeIndex = undefined;
        const fp = tree.fullFnProto(&buf, proto) orelse return;
        const name_tok = fp.name_token orelse return; // anonymous fn type — not a decl
        const first = fp.firstToken();
        var info: FnInfo = .{
            .file = fi,
            .name = tree.tokenSlice(name_tok),
            .line = self.lineOf(fi, name_tok),
            .first = first,
            .body_first = tree.firstToken(body),
            .body_last = tree.lastToken(body),
            .container = NONE,
        };
        // Annotation scan: comment lines immediately above the fn. Several
        // directives may stack (`ctx: irq` + `ctx: lock-ok`).
        const markers = self.markersAbove(fi, first);
        if (markers.irq) info.is_root = true;
        if (markers.irq_ok) info.is_cut = true;
        if (markers.lock_ok) info.lock_ok = true;
        const idx: u32 = @intCast(self.fns.items.len);
        try self.fns.append(self.alloc, info);
        try f.fns.append(self.alloc, idx);
    }

    const Markers = struct { irq: bool = false, irq_ok: bool = false, lock_ok: bool = false };

    /// Walk comment lines upward from the line above `tok` and collect the
    /// `ctx:` directives. Doc comments (`///`) and plain `//` both count.
    fn markersAbove(self: *Lint, fi: u32, tok: TokenIndex) Markers {
        const f = &self.files.items[fi];
        const loc = f.tree.tokenLocation(0, tok);
        var out: Markers = .{};
        var line_end = loc.line_start; // exclusive end of the previous line (its '\n')
        var guard: u32 = 0;
        while (line_end > 0 and guard < 64) : (guard += 1) {
            // previous line = [prev_start, line_end - 1)
            const prev_nl = std.mem.lastIndexOfScalar(u8, f.source[0 .. line_end - 1], '\n');
            const prev_start = if (prev_nl) |p| p + 1 else 0;
            const line = std.mem.trim(u8, f.source[prev_start .. line_end - 1], " \t\r");
            if (!std.mem.startsWith(u8, line, "//")) break;
            if (std.mem.indexOf(u8, line, "ctx: irq-ok")) |_| {
                out.irq_ok = true;
            } else if (std.mem.indexOf(u8, line, "ctx: irq")) |_| {
                out.irq = true;
            }
            if (std.mem.indexOf(u8, line, "ctx: lock-ok")) |_| out.lock_ok = true;
            line_end = prev_start;
        }
        return out;
    }

    fn collectContainer(self: *Lint, fi: u32, n: NodeIndex) !void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        var buf: [2]NodeIndex = undefined;
        const cd = tree.fullContainerDecl(&buf, n) orelse return;
        var info: ContainerInfo = .{
            .file = fi,
            .first = tree.firstToken(n),
            .last = tree.lastToken(n),
        };
        for (cd.ast.members) |m| {
            switch (tree.nodeTag(m)) {
                .container_field, .container_field_init, .container_field_align => {
                    const cf = tree.fullContainerField(m) orelse continue;
                    const type_text: []const u8 = if (cf.ast.type_expr.unwrap()) |t| tree.getNodeSource(t) else "";
                    const fname = tree.tokenSlice(cf.ast.main_token);
                    try info.fields.append(self.alloc, .{ .name = fname, .type_text = type_text });
                    // Tree-wide field-name → kind, for receivers declared in
                    // another file (see FieldKind).
                    const kind: FieldKind = if (typeTextIsMutex(type_text)) .mutex else .other;
                    if (self.field_kinds.get(fname)) |prev| {
                        if (prev != kind and prev != .mixed) try self.field_kinds.put(fname, .mixed);
                    } else {
                        try self.field_kinds.put(fname, kind);
                    }
                },
                else => {},
            }
        }
        const idx: u32 = @intCast(self.containers.items.len);
        try self.containers.append(self.alloc, info);
        try f.containers.append(self.alloc, idx);
    }

    fn collectVar(self: *Lint, fi: u32, n: NodeIndex) !void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        const vd = tree.fullVarDecl(n) orelse return;
        const name_tok = vd.ast.mut_token + 1;
        if (tree.tokenTag(name_tok) != .identifier) return;
        const name = tree.tokenSlice(name_tok);
        // Only file-scope vars feed the lock-tag and Mutex-type lookups; a
        // nested one would have to be inside a fn or container body.
        if (self.innermostFnByToken(fi, name_tok) == NONE and self.innermostContainer(fi, name_tok) == NONE) {
            const type_text: []const u8 = if (vd.ast.type_node.unwrap()) |t| tree.getNodeSource(t) else "";
            try f.vars.put(name, type_text);
        }
        const init = vd.ast.init_node.unwrap() orelse return;
        switch (tree.nodeTag(init)) {
            .builtin_call_two, .builtin_call_two_comma => {
                if (self.importTarget(fi, init)) |target| try f.imports.put(name, target);
            },
            .field_access => {
                const pair = tree.nodeData(init).node_and_token;
                const lhs = pair[0];
                const decl = tree.tokenSlice(pair[1]);
                switch (tree.nodeTag(lhs)) {
                    .identifier => {
                        const lhs_name = tree.tokenSlice(tree.nodeMainToken(lhs));
                        if (f.imports.get(lhs_name)) |target| {
                            try f.decl_aliases.put(name, .{ .file = target, .name = decl });
                        }
                    },
                    .builtin_call_two, .builtin_call_two_comma => {
                        if (self.importTarget(fi, lhs)) |target| {
                            try f.decl_aliases.put(name, .{ .file = target, .name = decl });
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }

    /// `@import("rel/path.zig")` → file index, or null (std, build_options,
    /// paths outside the tree, non-literal args).
    fn importTarget(self: *Lint, fi: u32, n: NodeIndex) ?u32 {
        const f = &self.files.items[fi];
        const tree = f.tree;
        if (!std.mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(n)), "@import")) return null;
        const args = tree.nodeData(n).opt_node_and_opt_node;
        const arg0 = args[0].unwrap() orelse return null;
        if (tree.nodeTag(arg0) != .string_literal) return null;
        const lit = tree.tokenSlice(tree.nodeMainToken(arg0));
        if (lit.len < 2) return null;
        const rel = lit[1 .. lit.len - 1];
        if (!std.mem.endsWith(u8, rel, ".zig")) return null;
        const dir = std.fs.path.dirnamePosix(f.path) orelse "";
        const joined = joinNormalize(self.alloc, dir, rel) catch return null;
        return self.path_index.get(joined);
    }

    // ---------------------------------------------------------------------
    // Pass 2: mightSleep sinks (must complete before edges resolve Mutex).
    // Pass 3: call edges + IRQ roots from registration arguments.
    // ---------------------------------------------------------------------

    fn markSinks(self: *Lint, fi: u32) void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        var i: u32 = 0;
        while (i < tree.nodes.len) : (i += 1) {
            const n: NodeIndex = @enumFromInt(i);
            if (!isCallTag(tree.nodeTag(n))) continue;
            var buf: [1]NodeIndex = undefined;
            const call = tree.fullCall(&buf, n) orelse continue;
            const callee_name = self.calleeLastName(fi, call.ast.fn_expr) orelse continue;
            if (!std.mem.eql(u8, callee_name, "mightSleep")) continue;
            const owner = self.innermostFnByToken(fi, tree.firstToken(n));
            if (owner != NONE) self.fns.items[owner].has_might_sleep = true;
        }
    }

    fn collectCalls(self: *Lint, fi: u32) !void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        var i: u32 = 0;
        while (i < tree.nodes.len) : (i += 1) {
            const n: NodeIndex = @enumFromInt(i);
            if (!isCallTag(tree.nodeTag(n))) continue;
            var buf: [1]NodeIndex = undefined;
            const call = tree.fullCall(&buf, n) orelse continue;
            const call_tok = tree.firstToken(n);
            const owner = self.innermostFnByToken(fi, call_tok);
            self.calls_total += 1;

            // IRQ roots by registration: any fn-valued argument to a registrar.
            if (self.calleeLastName(fi, call.ast.fn_expr)) |cname| {
                for (irq_registrars) |r| {
                    if (!std.mem.eql(u8, cname, r)) continue;
                    for (call.ast.params) |p| {
                        var arg = p;
                        if (tree.nodeTag(arg) == .address_of) arg = tree.nodeData(arg).node;
                        if (tree.nodeTag(arg) != .identifier) continue;
                        const aname = tree.tokenSlice(tree.nodeMainToken(arg));
                        for (f.fns.items) |fx| {
                            if (std.mem.eql(u8, self.fns.items[fx].name, aname)) self.fns.items[fx].is_root = true;
                        }
                    }
                }
            }

            if (owner == NONE) continue; // top-level comptime call
            var targets: std.ArrayList(u32) = .empty;
            try self.resolveCallee(fi, owner, call.ast.fn_expr, &targets);
            if (targets.items.len == 0) {
                self.calls_unresolved += 1;
                continue;
            }
            for (targets.items) |t| {
                try self.fns.items[owner].calls.append(self.alloc, .{ .callee = t, .tok = call_tok });
            }
        }
    }

    /// Rightmost identifier of a callee expression (`a.b.c` → "c", `c` → "c").
    fn calleeLastName(self: *Lint, fi: u32, expr: NodeIndex) ?[]const u8 {
        const tree = self.files.items[fi].tree;
        return switch (tree.nodeTag(expr)) {
            .identifier => tree.tokenSlice(tree.nodeMainToken(expr)),
            .field_access => tree.tokenSlice(tree.nodeData(expr).node_and_token[1]),
            else => null,
        };
    }

    fn resolveCallee(self: *Lint, fi: u32, owner: u32, expr: NodeIndex, out: *std.ArrayList(u32)) !void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        switch (tree.nodeTag(expr)) {
            .identifier => {
                const name = tree.tokenSlice(tree.nodeMainToken(expr));
                if (f.decl_aliases.get(name)) |a| {
                    try self.fnsNamedIn(a.file, a.name, NONE, out);
                    return;
                }
                try self.fnsNamedIn(fi, name, self.fns.items[owner].container, out);
            },
            .field_access => {
                const pair = tree.nodeData(expr).node_and_token;
                const lhs = pair[0];
                const name = tree.tokenSlice(pair[1]);
                switch (tree.nodeTag(lhs)) {
                    .identifier => {
                        const lhs_name = tree.tokenSlice(tree.nodeMainToken(lhs));
                        if (f.imports.get(lhs_name)) |target| {
                            try self.fnsNamedIn(target, name, NONE, out);
                            return;
                        }
                        if (f.decl_aliases.get(lhs_name)) |a| {
                            // Type alias: `Deadline.ms(...)` → fn `ms` in that file.
                            try self.fnsNamedIn(a.file, name, NONE, out);
                            return;
                        }
                    },
                    .builtin_call_two, .builtin_call_two_comma => {
                        if (self.importTarget(fi, lhs)) |target| {
                            try self.fnsNamedIn(target, name, NONE, out);
                            return;
                        }
                    },
                    else => {},
                }
                // Method call on a value. Mutex receivers park the caller:
                // route `.acquire()` on a Mutex-typed receiver to the
                // mightSleep-bearing acquire in spinlock.zig.
                if (isOneOf(name, &acquire_names) and self.receiverIsMutex(fi, owner, lhs)) {
                    if (self.path_index.get("proc/spinlock.zig")) |sl| {
                        for (self.files.items[sl].fns.items) |fx| {
                            const cand = &self.fns.items[fx];
                            if (std.mem.eql(u8, cand.name, name) and cand.has_might_sleep) try out.append(self.alloc, fx);
                        }
                    }
                    return;
                }
                // Otherwise: methods by name within this file, preferring the
                // caller's own container.
                try self.fnsNamedIn(fi, name, self.fns.items[owner].container, out);
            },
            else => {},
        }
    }

    /// All fns named `name` in `file`; if `prefer_container` is set and it
    /// declares one, only that one.
    fn fnsNamedIn(self: *Lint, file: u32, name: []const u8, prefer_container: u32, out: *std.ArrayList(u32)) !void {
        if (prefer_container != NONE) {
            for (self.files.items[file].fns.items) |fx| {
                const c = &self.fns.items[fx];
                if (c.container == prefer_container and std.mem.eql(u8, c.name, name)) {
                    try out.append(self.alloc, fx);
                }
            }
            if (out.items.len != 0) return;
        }
        for (self.files.items[file].fns.items) |fx| {
            if (std.mem.eql(u8, self.fns.items[fx].name, name)) try out.append(self.alloc, fx);
        }
    }

    /// Receiver `x` / `a.b.x` typed `Mutex` (or `spinlock.Mutex`, `*Mutex`)
    /// by an enclosing-container field or a file-scope var of that name.
    fn receiverIsMutex(self: *Lint, fi: u32, owner: u32, lhs: NodeIndex) bool {
        const f = &self.files.items[fi];
        const tree = f.tree;
        const var_name: []const u8 = switch (tree.nodeTag(lhs)) {
            .identifier => tree.tokenSlice(tree.nodeMainToken(lhs)),
            .field_access => tree.tokenSlice(tree.nodeData(lhs).node_and_token[1]),
            else => return false,
        };
        const container = self.fns.items[owner].container;
        if (container != NONE) {
            for (self.containers.items[container].fields.items) |fld| {
                if (std.mem.eql(u8, fld.name, var_name)) return typeTextIsMutex(fld.type_text);
            }
        }
        if (f.vars.get(var_name)) |t| return typeTextIsMutex(t);
        // `lead.as_lock` — a field of a struct declared elsewhere (PCB).
        if (self.field_kinds.get(var_name)) |k| return k == .mutex;
        return false;
    }

    // ---------------------------------------------------------------------
    // Pass 4: verdicts.
    // ---------------------------------------------------------------------

    fn maySleep(self: *Lint, idx: u32) bool {
        const fnp = &self.fns.items[idx];
        if (fnp.may_sleep_memo != 0) return fnp.may_sleep_memo == 2;
        if (fnp.has_might_sleep) {
            fnp.may_sleep_memo = 2;
            return true;
        }
        if (fnp.is_cut or fnp.visiting) return false;
        fnp.visiting = true;
        defer fnp.visiting = false;
        var result = false;
        for (fnp.calls.items) |e| {
            if (self.maySleep(e.callee)) {
                result = true;
                break;
            }
        }
        // A cycle member that saw `visiting` on a peer may be memoized
        // "no" too early; only memoize positive results and leaf negatives.
        if (result or fnp.calls.items.len == 0) fnp.may_sleep_memo = if (result) 2 else 1;
        return result;
    }

    /// DFS from an IRQ root; on reaching a sleeper, print the path. Returns
    /// true if a violation was found (one per root is enough).
    fn walkRoot(self: *Lint, root: u32) !bool {
        var path: std.ArrayList(u32) = .empty;
        var visited = std.AutoHashMap(u32, void).init(self.alloc);
        defer visited.deinit();
        try path.append(self.alloc, root);
        return self.dfs(root, &path, &visited);
    }

    fn dfs(self: *Lint, idx: u32, path: *std.ArrayList(u32), visited: *std.AutoHashMap(u32, void)) !bool {
        const fnp = &self.fns.items[idx];
        if (fnp.has_might_sleep) {
            self.errors += 1;
            std.debug.print("[ctx-lint] ERROR irq context reaches a sleeper:\n", .{});
            for (path.items, 0..) |p, i| {
                const pf = &self.fns.items[p];
                const role: []const u8 = if (i == 0) "root " else if (i + 1 == path.items.len) "SLEEP" else "     ";
                std.debug.print("           {s} {s}  ({s}:{d})\n", .{ role, pf.name, self.files.items[pf.file].path, pf.line });
            }
            return true;
        }
        if (fnp.is_cut) return false;
        for (fnp.calls.items) |e| {
            if (visited.contains(e.callee)) continue;
            try visited.put(e.callee, {});
            if (!self.maySleep(e.callee)) continue; // prune: nothing below sleeps
            try path.append(self.alloc, e.callee);
            if (try self.dfs(e.callee, path, visited)) return true;
            _ = path.pop();
        }
        return false;
    }

    fn checkLockTags(self: *Lint, fi: u32) void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        var i: u32 = 0;
        while (i < tree.nodes.len) : (i += 1) {
            const n: NodeIndex = @enumFromInt(i);
            switch (tree.nodeTag(n)) {
                .container_field, .container_field_init, .container_field_align => {},
                else => continue,
            }
            const cf = tree.fullContainerField(n) orelse continue;
            const loc = tree.tokenLocation(0, cf.ast.main_token);
            const line = f.source[loc.line_start..loc.line_end];
            // The tag lives in the trailing comment; the field text itself
            // may contain "(p:" only in a default-value string, ignore that.
            const comment_at = std.mem.indexOf(u8, line, "//") orelse continue;
            var rest = line[comment_at..];
            while (std.mem.indexOf(u8, rest, "(p:")) |at| {
                const after = rest[at + 3 ..];
                if (after.len == 0 or after[0] == ' ') { // `(p: u8)` — a param in prose, not a tag
                    rest = after;
                    continue;
                }
                const close = std.mem.indexOfScalar(u8, after, ')') orelse break;
                const body = after[0..close];
                self.lock_tags += 1;
                var it = std.mem.tokenizeAny(u8, body, "| ");
                while (it.next()) |lock| {
                    if (!self.lockResolves(fi, cf.ast.main_token, lock)) {
                        self.err("stale lock tag `(p:{s})` on field `{s}` — no such lock in scope: {s}:{d}", .{ body, tree.tokenSlice(cf.ast.main_token), f.path, loc.line + 1 });
                        break;
                    }
                }
                rest = after[close..];
            }
        }
    }

    fn lockResolves(self: *Lint, fi: u32, field_tok: TokenIndex, lock: []const u8) bool {
        if (isOneOf(lock, &external_locks)) return true;
        const base = if (std.mem.indexOfScalar(u8, lock, '.')) |d| lock[0..d] else lock;
        const f = &self.files.items[fi];
        if (f.vars.contains(base)) return true;
        const ci = self.innermostContainer(fi, field_tok);
        if (ci != NONE) {
            for (self.containers.items[ci].fields.items) |fld| {
                if (std.mem.eql(u8, fld.name, base)) return true;
            }
        }
        return false;
    }

    fn checkSleepUnderLock(self: *Lint, fi: u32) !void {
        const f = &self.files.items[fi];
        const tree = f.tree;
        // Token indices of release calls that sit directly under `defer`.
        var deferred = std.AutoHashMap(TokenIndex, void).init(self.alloc);
        defer deferred.deinit();
        var i: u32 = 0;
        while (i < tree.nodes.len) : (i += 1) {
            const n: NodeIndex = @enumFromInt(i);
            if (tree.nodeTag(n) != .@"defer") continue;
            const inner = tree.nodeData(n).node;
            if (isCallTag(tree.nodeTag(inner))) try deferred.put(tree.firstToken(inner), {});
        }

        const Window = struct { recv: []const u8, tok: TokenIndex, close: TokenIndex, line: usize };
        for (f.fns.items) |fx| {
            const fnp = &self.fns.items[fx];
            if (fnp.lock_ok) continue;
            var windows: std.ArrayList(Window) = .empty;
            var releases: std.ArrayList(struct { recv: []const u8, tok: TokenIndex, deferred: bool }) = .empty;
            // Gather acquire/release calls inside this body.
            var j: u32 = 0;
            while (j < tree.nodes.len) : (j += 1) {
                const n: NodeIndex = @enumFromInt(j);
                if (!isCallTag(tree.nodeTag(n))) continue;
                const tok = tree.firstToken(n);
                if (tok < fnp.body_first or tok > fnp.body_last) continue;
                var buf: [1]NodeIndex = undefined;
                const call = tree.fullCall(&buf, n) orelse continue;
                if (tree.nodeTag(call.ast.fn_expr) != .field_access) continue;
                const pair = tree.nodeData(call.ast.fn_expr).node_and_token;
                const name = tree.tokenSlice(pair[1]);
                const recv = tree.getNodeSource(pair[0]);
                if (isOneOf(name, &acquire_names)) {
                    if (self.receiverIsMutex(fi, fx, pair[0])) continue; // a sleeper, not a window
                    try windows.append(self.alloc, .{ .recv = recv, .tok = tok, .close = fnp.body_last, .line = self.lineOf(fi, tok) });
                } else if (isOneOf(name, &release_names)) {
                    try releases.append(self.alloc, .{ .recv = recv, .tok = tok, .deferred = deferred.contains(tok) });
                }
            }
            if (windows.items.len == 0) continue;
            // Close each window at the first later non-deferred release on the
            // same receiver text; a deferred release (or none) holds to the end.
            for (windows.items) |*w| {
                for (releases.items) |r| {
                    if (r.tok > w.tok and !r.deferred and std.mem.eql(u8, r.recv, w.recv)) {
                        if (r.tok < w.close) w.close = r.tok;
                    }
                }
            }
            // Any call to a may-sleep fn inside a window?
            for (fnp.calls.items) |e| {
                if (!self.maySleep(e.callee)) continue;
                for (windows.items) |w| {
                    if (e.tok > w.tok and e.tok < w.close) {
                        const callee = &self.fns.items[e.callee];
                        self.warn("sleep under spinlock: `{s}` window opened at {s}:{d} in `{s}` is still held at the call to `{s}` ({s}:{d}), which may park", .{
                            w.recv, f.path, w.line, fnp.name, callee.name, f.path, self.lineOf(fi, e.tok),
                        });
                        break;
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    fn lineOf(self: *Lint, fi: u32, tok: TokenIndex) usize {
        return self.files.items[fi].tree.tokenLocation(0, tok).line + 1;
    }

    fn innermostFnByToken(self: *Lint, fi: u32, tok: TokenIndex) u32 {
        var best: u32 = NONE;
        var best_span: u32 = std.math.maxInt(u32);
        for (self.files.items[fi].fns.items) |fx| {
            const fnp = &self.fns.items[fx];
            if (tok < fnp.body_first or tok > fnp.body_last) continue;
            const span = fnp.body_last - fnp.body_first;
            if (span < best_span) {
                best = fx;
                best_span = span;
            }
        }
        return best;
    }

    fn innermostContainer(self: *Lint, fi: u32, tok: TokenIndex) u32 {
        var best: u32 = NONE;
        var best_span: u32 = std.math.maxInt(u32);
        for (self.files.items[fi].containers.items) |ci| {
            const c = &self.containers.items[ci];
            if (tok < c.first or tok > c.last) continue;
            const span = c.last - c.first;
            if (span < best_span) {
                best = ci;
                best_span = span;
            }
        }
        return best;
    }
};

fn isCallTag(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .call_one, .call_one_comma, .call, .call_comma => true,
        else => false,
    };
}

fn isOneOf(s: []const u8, set: []const []const u8) bool {
    for (set) |x| if (std.mem.eql(u8, s, x)) return true;
    return false;
}

fn typeTextIsMutex(t: []const u8) bool {
    // `Mutex`, `spinlock.Mutex`, `*Mutex`, `?*Mutex` — but not `SpinLock`
    // and not Guarded(...): the token must END with "Mutex".
    return std.mem.endsWith(u8, std.mem.trimRight(u8, t, " "), "Mutex");
}

fn normalizeSlashes(alloc: std.mem.Allocator, p: []const u8) ![]const u8 {
    const out = try alloc.dupe(u8, p);
    for (out) |*c| if (c.* == '\\') {
        c.* = '/';
    };
    return out;
}

/// `dir` + `rel` with `.`/`..` folded, posix separators. Both relative to
/// the src root; a `..` escaping the root yields a path no file has.
fn joinNormalize(alloc: std.mem.Allocator, dir: []const u8, rel: []const u8) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, dir, '/');
    while (it.next()) |seg| try parts.append(alloc, seg);
    var it2 = std.mem.tokenizeScalar(u8, rel, '/');
    while (it2.next()) |seg| {
        if (std.mem.eql(u8, seg, ".")) continue;
        if (std.mem.eql(u8, seg, "..")) {
            if (parts.items.len == 0) return error.EscapesRoot;
            _ = parts.pop();
            continue;
        }
        try parts.append(alloc, seg);
    }
    return std.mem.join(alloc, "/", parts.items);
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    var root: []const u8 = "src";
    var verbose = false;
    for (args[1..]) |a| {
        if (std.mem.eql(u8, a, "--verbose") or std.mem.eql(u8, a, "-v")) {
            verbose = true;
        } else {
            root = a;
        }
    }

    var lint: Lint = .{
        .alloc = alloc,
        .path_index = std.StringHashMap(u32).init(alloc),
        .reachable = std.AutoHashMap(u32, void).init(alloc),
        .field_kinds = std.StringHashMap(FieldKind).init(alloc),
        .verbose = verbose,
    };
    try lint.loadTree(root);
    try lint.computeReachable();
    const total_files = lint.files.items.len;
    var skipped: u32 = 0;
    var fi: u32 = 0;
    while (fi < total_files) : (fi += 1) {
        if (lint.isReachable(fi)) continue;
        skipped += 1;
        if (verbose) std.debug.print("[ctx-lint] skip (not reachable from main.zig): {s}\n", .{lint.files.items[fi].path});
    }

    fi = 0;
    while (fi < total_files) : (fi += 1) if (lint.isReachable(fi)) try lint.collectDecls(fi);
    fi = 0;
    while (fi < total_files) : (fi += 1) if (lint.isReachable(fi)) lint.markSinks(fi);
    fi = 0;
    while (fi < total_files) : (fi += 1) if (lint.isReachable(fi)) try lint.collectCalls(fi);

    var roots: u32 = 0;
    var sinks: u32 = 0;
    for (lint.fns.items, 0..) |*fnp, idx| {
        if (fnp.has_might_sleep) {
            sinks += 1;
            if (verbose) std.debug.print("[ctx-lint] sleeper: {s} ({s}:{d})\n", .{ fnp.name, lint.files.items[fnp.file].path, fnp.line });
        }
        if (!fnp.is_root) continue;
        roots += 1;
        if (verbose) std.debug.print("[ctx-lint] irq root: {s} ({s}:{d})\n", .{ fnp.name, lint.files.items[fnp.file].path, fnp.line });
        _ = try lint.walkRoot(@intCast(idx));
    }
    fi = 0;
    while (fi < total_files) : (fi += 1) if (lint.isReachable(fi)) lint.checkLockTags(fi);
    fi = 0;
    while (fi < total_files) : (fi += 1) if (lint.isReachable(fi)) try lint.checkSleepUnderLock(fi);

    std.debug.print("[ctx-lint] {d} files ({d} unreachable skipped), {d} fns, {d} irq roots, {d} sleepers, {d} lock tags, {d} calls ({d} unresolved), {d} warning(s), {d} error(s)\n", .{
        total_files, skipped, lint.fns.items.len, roots, sinks, lint.lock_tags, lint.calls_total, lint.calls_unresolved, lint.warnings, lint.errors,
    });
    // Sanity floor: the kernel has IRQ roots and mightSleep sites; seeing
    // none means the lint is looking at the wrong tree or its own
    // detection regressed — refuse a vacuous PASS.
    if (roots == 0 or sinks == 0) {
        std.debug.print("[ctx-lint] FAIL — vacuous run (roots={d} sleepers={d})\n", .{ roots, sinks });
        std.process.exit(1);
    }
    if (lint.errors != 0) {
        std.debug.print("[ctx-lint] FAIL\n", .{});
        std.process.exit(1);
    }
    std.debug.print("[ctx-lint] PASS\n", .{});
}
