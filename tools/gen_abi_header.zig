// ABI-oracle header generator.
//
// Emits a C header file with one prototype per Zig `export fn` listed in
// the `Sigs` declaration below. The build system runs this once per build
// and drops the result into zig-out/abi/zigos_app_exports.h. C sources
// that include the header pick up the correct ABI (return registers,
// parameter classes) for every Zig export they call — protecting against
// the bug class surfaced by quake1's missing-prototype atof in 2026-05-21
// (C compiler inferred `int atof(...)` because no `extern double atof(...)`
// was visible, then read the return value from EAX while Zig's f64 return
// landed in XMM0).
//
// To force-include the header in every C TU of a target:
//   1. quake1.step.dependOn(&run_abi_gen.step);
//   2. quake1.root_module.addIncludePath(abi_header_dir);
//   3. add `#include "zigos_app_exports.h"` at the top of one .h that
//      every C TU already includes (e.g. quakedef.h), OR
//   4. add `-include zigos_app_exports.h` to the C cflags.
//
// Adding a new export: append a `pub const <name>: fn-type = ...` line to
// `Sigs` below. The fn-type literal mirrors the Zig export's signature; the
// generator inspects it via @typeInfo so the C prototype always tracks the
// declaration here. If the Zig export's actual signature drifts from Sigs,
// the linker (or the next round-trip compile) will catch the mismatch.
//
// Note: we do NOT import the app module directly, because freestanding
// app modules can't be compiled for the host where this tool runs. The
// `Sigs` namespace is the curated, type-checkable source of truth.
//
// Proposal P6 in the debug infra survey 2026-05-28.

const std = @import("std");

/// Signature catalogue. Each `pub const <name>` is a fn-pointer type
/// declaration whose @typeInfo drives the prototype emission.
const Sigs = struct {
    // === Quake-engine glue (sys_zigos.c links these) ===
    pub const zq_time_ms: fn () callconv(.c) c_uint = undefined;
    pub const zq_exit: fn (code: c_int) callconv(.c) noreturn = undefined;
    pub const zq_print: fn (s: ?[*:0]const u8) callconv(.c) void = undefined;
    pub const zq_audio_submit: fn (samples: [*]const i16, frames: u32) callconv(.c) void = undefined;
    pub const zq_poll_keys: fn () callconv(.c) void = undefined;
    pub const zq_next_key: fn (down_out: *c_int) callconv(.c) c_int = undefined;
    pub const zq_get_mouse_delta: fn (dx: *c_int, dy: *c_int) callconv(.c) void = undefined;
    pub const zq_present: fn () callconv(.c) void = undefined;
    // === C math shims (Q1's mathlib.c + r_main.c etc call these) ===
    pub const sqrt: fn (x: f64) callconv(.c) f64 = undefined;
    pub const sqrtf: fn (x: f32) callconv(.c) f32 = undefined;
    pub const sin: fn (x: f64) callconv(.c) f64 = undefined;
    pub const sinf: fn (x: f32) callconv(.c) f32 = undefined;
    pub const cos: fn (x: f64) callconv(.c) f64 = undefined;
    pub const cosf: fn (x: f32) callconv(.c) f32 = undefined;
    pub const tan: fn (x: f64) callconv(.c) f64 = undefined;
    pub const atan: fn (x: f64) callconv(.c) f64 = undefined;
    pub const atan2: fn (y: f64, x: f64) callconv(.c) f64 = undefined;
    pub const asin: fn (x: f64) callconv(.c) f64 = undefined;
    pub const acos: fn (x: f64) callconv(.c) f64 = undefined;
    pub const floor: fn (x: f64) callconv(.c) f64 = undefined;
    pub const floorf: fn (x: f32) callconv(.c) f32 = undefined;
    pub const ceil: fn (x: f64) callconv(.c) f64 = undefined;
    pub const ceilf: fn (x: f32) callconv(.c) f32 = undefined;
    pub const fabs: fn (x: f64) callconv(.c) f64 = undefined;
};

/// Map a Zig type to the C type spelling we emit in the prototype. Marked
/// `inline` so each invocation folds into the call site; the result is a
/// comptime-known string literal (or a comptimePrint product) regardless
/// of whether the surrounding emitPrototype runs at comptime or runtime —
/// it never depends on runtime values.
inline fn cTypeOf(comptime T: type) []const u8 {
    if (T == void) return "void";
    if (T == bool) return "_Bool";
    const info = @typeInfo(T);
    switch (info) {
        .int => |i| {
            const sgn: []const u8 = if (i.signedness == .signed) "int" else "uint";
            return std.fmt.comptimePrint("{s}{d}_t", .{ sgn, i.bits });
        },
        .float => |f| switch (f.bits) {
            32 => return "float",
            64 => return "double",
            else => @compileError(std.fmt.comptimePrint("unsupported float width: {d}", .{f.bits})),
        },
        .pointer => |p| {
            if (p.sentinel_ptr != null and p.child == u8) return "const char*";
            const child_str = comptime cTypeOf(p.child);
            const const_qual: []const u8 = if (p.is_const) "const " else "";
            return std.fmt.comptimePrint("{s}{s}*", .{ const_qual, child_str });
        },
        .optional => |o| return comptime cTypeOf(o.child),
        .void => return "void",
        .noreturn => return "void",
        else => @compileError("cTypeOf: unsupported Zig type — extend the mapping table"),
    }
}

/// Emit one C prototype to the writer. We write field-by-field rather than
/// building the full string at comptime — Zig 0.15 won't fold a `var` slice
/// across inline-for iterations into a comptime-known concat.
fn emitPrototype(w: anytype, comptime name: []const u8, comptime FnT: type) !void {
    const info = @typeInfo(FnT);
    if (info != .@"fn") @compileError("emitPrototype: not a fn type");
    const fn_info = info.@"fn";
    const ret_t = fn_info.return_type orelse void;
    if (ret_t == noreturn) try w.writeAll("__attribute__((noreturn)) ");
    try w.writeAll(cTypeOf(ret_t));
    try w.writeAll(" ");
    try w.writeAll(name);
    try w.writeAll("(");
    if (fn_info.params.len == 0) {
        try w.writeAll("void");
    } else {
        inline for (fn_info.params, 0..) |p, i| {
            const pt = p.type orelse @compileError("emitPrototype: missing param type for " ++ name);
            if (i > 0) try w.writeAll(", ");
            try w.writeAll(cTypeOf(pt));
        }
    }
    try w.writeAll(");\n");
}

pub fn main() !void {
    var args = std.process.args();
    _ = args.next() orelse return error.NoArgv;
    const out_path = args.next() orelse {
        std.debug.print("usage: gen_abi_header <output.h>\n", .{});
        return error.MissingOutput;
    };

    if (std.fs.path.dirname(out_path)) |dir| {
        std.fs.cwd().makePath(dir) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
    }

    var f = try std.fs.cwd().createFile(out_path, .{});
    defer f.close();

    var buf: [4096]u8 = undefined;
    var fw = f.writer(&buf);
    const w = &fw.interface;

    try w.writeAll("// AUTOGENERATED by tools/gen_abi_header.zig — DO NOT EDIT.\n");
    try w.writeAll("// Re-runs every kernel build; edit the source generator instead.\n");
    try w.writeAll("//\n");
    try w.writeAll("// Force-include into C app TUs that link against Zig exports so the\n");
    try w.writeAll("// compiler picks up the correct register ABI for every call site.\n");
    try w.writeAll("// See tools/gen_abi_header.zig header for rationale (P6 — quake atof bug).\n");
    try w.writeAll("\n");
    try w.writeAll("#ifndef ZIGOS_APP_EXPORTS_H\n");
    try w.writeAll("#define ZIGOS_APP_EXPORTS_H\n");
    try w.writeAll("\n");
    try w.writeAll("#include <stdint.h>\n");
    try w.writeAll("\n");
    try w.writeAll("#ifdef __cplusplus\n");
    try w.writeAll("extern \"C\" {\n");
    try w.writeAll("#endif\n");
    try w.writeAll("\n");

    const decls = @typeInfo(Sigs).@"struct".decls;
    inline for (decls) |d| {
        const FnT = @TypeOf(@field(Sigs, d.name));
        try emitPrototype(w, d.name, FnT);
    }

    try w.writeAll("\n");
    try w.writeAll("#ifdef __cplusplus\n");
    try w.writeAll("}\n");
    try w.writeAll("#endif\n");
    try w.writeAll("\n");
    try w.writeAll("#endif // ZIGOS_APP_EXPORTS_H\n");
    try w.flush();
}
