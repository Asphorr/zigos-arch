//! asm_lint — build-time checks over the kernel's inline assembly.
//!
//! Host tool, run by build.zig before the kernel links. Reads every
//! `src/**/*.zig` as text and checks two things:
//!
//!   1. Stack alignment at `call`. Inside one asm template it counts
//!      push/pop and `sub`/`add $N, %rsp` from the last label or `swapgs`
//!      and requires (delta + 8) % 16 == 0 at every `call` (the +8 is the
//!      call's own return address).
//!   2. Output shape. Zig 0.15.2 builds an asm's LLVM return struct over
//!      all its outputs but fills only the register ones. With two or more
//!      register outputs next to any `=m` output the leftover fields are
//!      typed from uninitialized compiler memory: LLVM rejects the module
//!      ("Invalid type") or silently takes a wrong type. One register
//!      output, or no memory outputs, is fine. tools/asm_ret_check.py
//!      verifies the bitcode.
//!
//! The matching is textual and only knows the obvious patterns: a template
//! written out as `\\` lines. The entry stubs are not — their text is
//! generated (src/cpu/idt/stub.zig, src/syscall/entry.zig) from frames
//! whose alignment is a comptime result (src/proc/frames.zig) — and each
//! tests RSP before its `call` at run time besides; so the first check may
//! find no `call` to look at, and says how many it did. A run that saw no
//! multi-line template or no output fails: a lint that inspected nothing
//! must not say PASS.

const std = @import("std");

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r' or c == 0x0B or c == 0x0C;
}

fn isWord(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\x0B\x0C");
}

/// Index just past the `(` of the `asm (` / `asm volatile (` that starts at
/// `at`, or null when `at` is not the start of one.
fn asmOpen(text: []const u8, at: usize) ?usize {
    if (at > 0 and isWord(text[at - 1])) return null;
    var p = at + "asm".len;
    const after_kw = p;
    while (p < text.len and isSpace(text[p])) p += 1;
    if (p == after_kw) return null;
    if (std.mem.startsWith(u8, text[p..], "volatile")) {
        var q = p + "volatile".len;
        const after_vol = q;
        while (q < text.len and isSpace(text[q])) q += 1;
        if (q != after_vol) p = q;
    }
    if (p < text.len and text[p] == '(') return p + 1;
    return null;
}

/// The multiline-string template right after the `(` at `open`: its `\\`
/// lines, newlines included, and the `//` comment lines between them (a
/// comment does not end the literal). Null when the asm starts with
/// something else.
fn asmTemplate(text: []const u8, open: usize) ?[]const u8 {
    var start = open;
    while (start < text.len and isSpace(text[start])) start += 1;
    var end = start; // just past the last `\\` line
    var next = start;
    while (true) {
        var q = next;
        while (q < text.len and (text[q] == ' ' or text[q] == '\t')) q += 1;
        const string_line = std.mem.startsWith(u8, text[q..], "\\\\");
        const comment_line = end > start and std.mem.startsWith(u8, text[q..], "//");
        if (!string_line and !comment_line) break;
        const nl = std.mem.indexOfScalarPos(u8, text, q, '\n') orelse break;
        next = nl + 1;
        if (string_line) end = next;
    }
    return if (end > start) text[start..end] else null;
}

/// The outputs section of the asm whose `(` ends at `open`: from the first
/// top-level ':' to the next one or to the closing paren. Strings, `\\`
/// lines and comments are skipped.
fn outputsSection(text: []const u8, open: usize) []const u8 {
    var depth: u32 = 1;
    var begin: ?usize = null;
    var i = open;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (c == '"') {
            i += 1;
            while (i < text.len and text[i] != '"') i += if (text[i] == '\\') 2 else 1;
        } else if ((c == '\\' and std.mem.startsWith(u8, text[i..], "\\\\")) or
            (c == '/' and std.mem.startsWith(u8, text[i..], "//")))
        {
            i = std.mem.indexOfScalarPos(u8, text, i, '\n') orelse break;
        } else if (c == '(' or c == '[' or c == '{') {
            depth += 1;
        } else if (c == ')' or c == ']' or c == '}') {
            depth -= 1;
            if (depth == 0) return if (begin) |b| text[b..i] else "";
        } else if (c == ':' and depth == 1) {
            if (begin) |b| return text[b..i];
            begin = i + 1;
        }
    }
    return "";
}

/// Whether an output constraint ("={rax}", "=m", "=r") is a memory one:
/// an 'm' outside its `{register}` part.
fn isMemoryConstraint(cons: []const u8) bool {
    var i: usize = 0;
    while (i < cons.len) : (i += 1) {
        if (cons[i] == '{') {
            if (std.mem.indexOfScalarPos(u8, cons, i, '}')) |close| {
                i = close;
                continue;
            }
        }
        if (cons[i] == 'm') return true;
    }
    return false;
}

/// The N of `$N` in a `sub`/`add` against the stack pointer, 0 when the
/// operand is not a plain number.
fn immediate(operands: []const u8) i64 {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, operands, i, '$')) |dollar| : (i = dollar + 1) {
        const rest = operands[dollar + 1 ..];
        if (rest.len == 0 or !std.ascii.isDigit(rest[0])) continue;
        const hex = rest.len > 2 and rest[0] == '0' and rest[1] == 'x' and std.ascii.isHex(rest[2]);
        const digits = if (hex) rest[2..] else rest;
        var len: usize = 0;
        while (len < digits.len and (if (hex) std.ascii.isHex(digits[len]) else std.ascii.isDigit(digits[len]))) len += 1;
        return std.fmt.parseInt(i64, digits[0..len], if (hex) 16 else 10) catch 0;
    }
    return 0;
}

const Lint = struct {
    root: []const u8,
    blocks: u32 = 0,
    multiline_blocks: u32 = 0,
    calls: u32 = 0,
    asm_outputs: u32 = 0,
    errors: u32 = 0,

    fn file(self: *Lint, path: []const u8, text: []const u8) void {
        var i: usize = 0;
        while (std.mem.indexOfPos(u8, text, i, "asm")) |at| {
            const open = asmOpen(text, at) orelse {
                i = at + 1;
                continue;
            };
            const line = 1 + std.mem.count(u8, text[0..at], "\n");
            if (asmTemplate(text, open)) |template| {
                self.blocks += 1;
                if (std.mem.count(u8, template, "\n") > 1) self.multiline_blocks += 1;
                self.alignment(path, line, template);
            }
            self.outputShape(path, line, outputsSection(text, open));
            i = open;
        }
    }

    fn alignment(self: *Lint, path: []const u8, line: usize, template: []const u8) void {
        var delta: i64 = 0;
        var lines = std.mem.splitScalar(u8, template, '\n');
        while (lines.next()) |raw| {
            var insn = trim(std.mem.trim(u8, trim(raw), "\\"));
            if (std.mem.indexOf(u8, insn, "//")) |c| insn = trim(insn[0..c]);
            if (std.mem.indexOfScalar(u8, insn, '#')) |c| insn = trim(insn[0..c]);
            if (insn.len == 0) continue;

            const op_len = std.mem.indexOfAny(u8, insn, " \t") orelse insn.len;
            const op = insn[0..op_len];
            const operands = trim(insn[op_len..]);
            const on_sp = std.mem.indexOf(u8, operands, "%rsp") != null or std.mem.indexOf(u8, operands, "%esp") != null;

            if (std.ascii.eqlIgnoreCase(op, "swapgs") or op[op.len - 1] == ':') {
                delta = 0;
            } else if (std.ascii.startsWithIgnoreCase(op, "push")) {
                delta += 8;
            } else if (std.ascii.startsWithIgnoreCase(op, "pop")) {
                delta -= 8;
            } else if (std.ascii.eqlIgnoreCase(op, "sub") and on_sp) {
                delta += immediate(operands);
            } else if (std.ascii.eqlIgnoreCase(op, "add") and on_sp) {
                delta -= immediate(operands);
            } else if (std.ascii.eqlIgnoreCase(op, "call")) {
                self.calls += 1;
                const off = @mod(delta + 8, 16);
                if (off != 0) {
                    std.debug.print("{s}/{s}:{d}: misaligned call to '{s}' (stack delta {d}, (delta + 8) % 16 = {d}, expected 0)\n", .{ self.root, path, line, operands, delta, off });
                    self.errors += 1;
                }
            }
        }
    }

    fn outputShape(self: *Lint, path: []const u8, line: usize, outs: []const u8) void {
        var direct: u32 = 0;
        var memory: u32 = 0;
        var i: usize = 0;
        while (i + 1 < outs.len) {
            if (outs[i] != '"' or outs[i + 1] != '=') {
                i += 1;
                continue;
            }
            const close = std.mem.indexOfScalarPos(u8, outs, i + 1, '"') orelse break;
            self.asm_outputs += 1;
            if (isMemoryConstraint(outs[i + 1 .. close])) memory += 1 else direct += 1;
            i = close + 1;
        }
        if (direct >= 2 and memory >= 1) {
            std.debug.print("{s}/{s}:{d}: asm with {d} register outputs and {d} memory output(s): Zig 0.15.2 emits a garbage return type for this shape (Invalid type). Keep one register output, move the rest to =m.\n", .{ self.root, path, line, direct, memory });
            self.errors += 1;
        }
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const args = try std.process.argsAlloc(alloc);
    const root: []const u8 = if (args.len > 1) args[1] else "src";

    var dir = try std.fs.cwd().openDir(root, .{ .iterate = true });
    defer dir.close();
    var walker = try dir.walk(alloc);
    defer walker.deinit();

    var lint: Lint = .{ .root = root };
    var files: u32 = 0;
    while (try walker.next()) |e| {
        if (e.kind != .file or !std.mem.endsWith(u8, e.basename, ".zig")) continue;
        const text = try dir.readFileAlloc(alloc, e.path, 64 << 20);
        files += 1;
        lint.file(e.path, text);
    }

    std.debug.print("[asm-lint] {d} files, {d} asm templates ({d} multi-line), {d} calls, {d} outputs, {d} error(s)\n", .{
        files, lint.blocks, lint.multiline_blocks, lint.calls, lint.asm_outputs, lint.errors,
    });
    if (lint.multiline_blocks == 0 or lint.asm_outputs == 0) {
        std.debug.print("[asm-lint] FAIL: vacuous run, the matching saw no multi-line templates or no asm outputs\n", .{});
        std.process.exit(1);
    }
    if (lint.errors != 0) {
        std.debug.print("[asm-lint] FAIL\n", .{});
        std.process.exit(1);
    }
    std.debug.print("[asm-lint] PASS\n", .{});
}
