// SUBLEQ backend for babel.
//
// One-instruction-set computer:  SUBLEQ a, b, c
//   if a == -1:  read 1 char from input, store in mem[b], result = char
//   elif b == -1: write mem[a] as char to output, result = mem[a]
//   else:        mem[b] -= mem[a], result = mem[b]
// Then: if result <= 0, PC = c; else PC += 3. Negative PC halts.
//
// Memory: 16K signed 32-bit cells. I/O at virtual address -1.
//
// Includes a two-pass assembler for the .subleq dialect; see asmProcessLine
// for the supported syntax (labels, .word, .asciz, char literals, label+offset).

const std = @import("std");

pub const MEM_SIZE: usize = 16384;
pub const OUT_RING_SIZE: u32 = 1024;
pub const MAX_SRC_SIZE: usize = 16384;
pub const MAX_LABELS: u32 = 256;
pub const MAX_NAME: u32 = 24;

pub const StepResult = enum { ok, output, halt, fault, input_needed };

pub const Core = struct {
    mem: [MEM_SIZE]i32 = [_]i32{0} ** MEM_SIZE,
    pc: i32 = 0,
    cycles: u32 = 0,
    halted: bool = true,
    running: bool = false,
    waiting_for_input: bool = false,
    input_pending: i32 = -1,

    last_output: u8 = 0,

    // Output ring buffer — drained by host between frames so a single
    // tickFrame can emit many chars without per-char host round-trips.
    out_ring: [OUT_RING_SIZE]u8 = undefined,
    out_head: u32 = 0,
    out_tail: u32 = 0,

    pub fn reset(self: *Core) void {
        @memset(&self.mem, 0);
        self.pc = 0;
        self.cycles = 0;
        self.halted = true;
        self.running = false;
        self.waiting_for_input = false;
        self.input_pending = -1;
        self.last_output = 0;
        self.out_head = 0;
        self.out_tail = 0;
    }

    fn cellInBounds(addr: i32) bool {
        return addr >= 0 and addr < @as(i32, @intCast(MEM_SIZE));
    }

    fn pushOutput(self: *Core, ch: u8) void {
        const next = (self.out_tail + 1) % OUT_RING_SIZE;
        if (next == self.out_head) {
            // Ring full — drop oldest to keep flowing. Hello-World-ish
            // programs never hit this; long output streams within a frame
            // would.
            self.out_head = (self.out_head + 1) % OUT_RING_SIZE;
        }
        self.out_ring[self.out_tail] = ch;
        self.out_tail = next;
    }

    pub fn popOutput(self: *Core) ?u8 {
        if (self.out_head == self.out_tail) return null;
        const ch = self.out_ring[self.out_head];
        self.out_head = (self.out_head + 1) % OUT_RING_SIZE;
        return ch;
    }

    pub fn feedInput(self: *Core, ch: u8) void {
        self.input_pending = @intCast(ch);
        self.waiting_for_input = false;
    }

    /// Load a raw program (cells) into memory and start fresh. Returns false
    /// if the program is too large.
    pub fn loadProgram(self: *Core, code: []const i32) bool {
        if (code.len > MEM_SIZE) return false;
        self.reset();
        for (code, 0..) |c, i| self.mem[i] = c;
        self.halted = false;
        return true;
    }

    pub fn step(self: *Core) StepResult {
        if (self.halted) return .halt;
        if (self.pc < 0 or self.pc + 2 >= @as(i32, @intCast(MEM_SIZE))) {
            self.halted = true;
            return .halt;
        }
        const a = self.mem[@intCast(self.pc)];
        const b = self.mem[@intCast(self.pc + 1)];
        const c = self.mem[@intCast(self.pc + 2)];

        var result: i32 = 0;
        var did_output: bool = false;

        if (a == -1) {
            if (self.input_pending == -1) {
                self.waiting_for_input = true;
                return .input_needed;
            }
            if (!cellInBounds(b)) {
                self.halted = true;
                return .fault;
            }
            self.mem[@intCast(b)] = self.input_pending;
            result = self.input_pending;
            self.input_pending = -1;
            self.waiting_for_input = false;
        } else if (b == -1) {
            if (!cellInBounds(a)) {
                self.halted = true;
                return .fault;
            }
            result = self.mem[@intCast(a)];
            did_output = true;
            self.last_output = @truncate(@as(u32, @bitCast(result)) & 0xFF);
            self.pushOutput(self.last_output);
        } else {
            if (!cellInBounds(a) or !cellInBounds(b)) {
                self.halted = true;
                return .fault;
            }
            self.mem[@intCast(b)] -= self.mem[@intCast(a)];
            result = self.mem[@intCast(b)];
        }

        self.cycles += 1;
        if (result <= 0) {
            self.pc = c;
        } else {
            self.pc += 3;
        }
        if (self.pc < 0) self.halted = true;

        if (did_output) return .output;
        return .ok;
    }

    /// Run up to `budget` instructions or until non-ok terminal result. The
    /// host then drains popOutput() to display the chars produced.
    pub fn tickFrame(self: *Core, budget: u32) StepResult {
        if (!self.running or self.halted) return .halt;
        var i: u32 = 0;
        while (i < budget) : (i += 1) {
            const r = self.step();
            switch (r) {
                .ok, .output => {},
                .halt, .fault => {
                    self.running = false;
                    return r;
                },
                .input_needed => return r,
            }
        }
        return .ok;
    }
};

// === Assembler ===
//
// Two-pass assembler for a small subleq dialect:
//
//   ; comments to end of line
//   label:                  ; label definition (own line or before content)
//   a b c                   ; SUBLEQ a, b, c
//   a b                     ; SUBLEQ a, b, <next PC>   (c defaults)
//   .word N                 ; emit one cell
//   .asciz "..."            ; emit string bytes + 0 terminator
//                           ; escapes: \n \t \\ \" \0
//
// Operands:
//   42, -1                  decimal literal
//   'A'                     char literal
//   loop                    label reference (resolved at pass 2)
//   msg+3, end-1            label + signed offset
//
// Module-level scratch buffers; only one assembly at a time, but the host
// always serializes assemblies behind a `load` command so that's fine.

pub var asm_err_msg: []const u8 = "";
pub var asm_err_line: u32 = 0;
pub var asm_label_count: u32 = 0;

const Label = struct {
    name: [MAX_NAME]u8 = [_]u8{0} ** MAX_NAME,
    name_len: u8 = 0,
    addr: u32 = 0,
};

var asm_labels: [MAX_LABELS]Label = undefined;

fn asmReset() void {
    asm_label_count = 0;
    asm_err_msg = "";
    asm_err_line = 0;
}

fn asmFindLabel(name: []const u8) ?u32 {
    var i: u32 = 0;
    while (i < asm_label_count) : (i += 1) {
        const L = &asm_labels[i];
        if (L.name_len == name.len) {
            var match = true;
            for (name, 0..) |ch, j| {
                if (L.name[j] != ch) {
                    match = false;
                    break;
                }
            }
            if (match) return L.addr;
        }
    }
    return null;
}

fn asmAddLabel(name: []const u8, addr: u32) bool {
    if (asm_label_count >= MAX_LABELS or name.len == 0 or name.len > MAX_NAME) return false;
    if (asmFindLabel(name) != null) return false;
    @memcpy(asm_labels[asm_label_count].name[0..name.len], name);
    asm_labels[asm_label_count].name_len = @intCast(name.len);
    asm_labels[asm_label_count].addr = addr;
    asm_label_count += 1;
    return true;
}

inline fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r';
}
inline fn isIdentStart(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
}
inline fn isIdentCont(c: u8) bool {
    return isIdentStart(c) or (c >= '0' and c <= '9');
}

fn asmSkipSpaces(s: []const u8, pos: *usize) void {
    while (pos.* < s.len and isSpace(s[pos.*])) pos.* += 1;
}

fn asmReadIdent(s: []const u8, pos: *usize) []const u8 {
    const start = pos.*;
    while (pos.* < s.len and isIdentCont(s[pos.*])) pos.* += 1;
    return s[start..pos.*];
}

fn parseInt(s: []const u8) ?i32 {
    if (s.len == 0) return null;
    var i: usize = 0;
    var neg = false;
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
    if (i == s.len) return null;
    var v: i64 = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] < '0' or s[i] > '9') return null;
        v = v * 10 + (s[i] - '0');
        if (v > 2_147_483_647) return null;
    }
    if (neg) v = -v;
    return @intCast(v);
}

fn asmReadNum(s: []const u8, pos: *usize) ?i32 {
    const start = pos.*;
    var p = pos.*;
    if (p < s.len and s[p] == '-') p += 1;
    var has = false;
    while (p < s.len and s[p] >= '0' and s[p] <= '9') {
        has = true;
        p += 1;
    }
    if (!has) return null;
    pos.* = p;
    return parseInt(s[start..p]);
}

const OpKind = enum { num, label_ref };
const Operand = struct {
    kind: OpKind,
    num: i32 = 0,
    label_name: []const u8 = "",
    label_offset: i32 = 0,
};

fn asmParseOperand(s: []const u8, pos: *usize) ?Operand {
    asmSkipSpaces(s, pos);
    if (pos.* >= s.len) return null;
    const c = s[pos.*];

    if (c == '\'') {
        if (pos.* + 2 >= s.len) return null;
        const ch = s[pos.* + 1];
        if (s[pos.* + 2] != '\'') return null;
        pos.* += 3;
        return Operand{ .kind = .num, .num = @intCast(ch) };
    }

    if (c == '-' or (c >= '0' and c <= '9')) {
        if (asmReadNum(s, pos)) |n| return Operand{ .kind = .num, .num = n };
        return null;
    }

    if (isIdentStart(c)) {
        const name = asmReadIdent(s, pos);
        var offset: i32 = 0;
        if (pos.* < s.len and (s[pos.*] == '+' or s[pos.*] == '-')) {
            const sign: i32 = if (s[pos.*] == '+') 1 else -1;
            pos.* += 1;
            const n = asmReadNum(s, pos) orelse return null;
            offset = sign * n;
        }
        return Operand{ .kind = .label_ref, .label_name = name, .label_offset = offset };
    }

    return null;
}

fn asmResolve(op: Operand) ?i32 {
    if (op.kind == .num) return op.num;
    if (asmFindLabel(op.label_name)) |addr| {
        return @as(i32, @intCast(addr)) + op.label_offset;
    }
    return null;
}

fn asmNextLine(src: []const u8, pos: *usize) ?[]const u8 {
    if (pos.* >= src.len) return null;
    const start = pos.*;
    while (pos.* < src.len and src[pos.*] != '\n') pos.* += 1;
    const line = src[start..pos.*];
    if (pos.* < src.len) pos.* += 1;
    return line;
}

fn asmStripComment(line: []const u8) []const u8 {
    for (line, 0..) |c, i| {
        if (c == ';') return line[0..i];
    }
    return line;
}

fn asmTrim(line: []const u8) []const u8 {
    var s = line;
    while (s.len > 0 and isSpace(s[0])) s = s[1..];
    while (s.len > 0 and isSpace(s[s.len - 1])) s = s[0 .. s.len - 1];
    return s;
}

/// `out == null` means pass 1 (count + register labels). `out != null` is
/// pass 2 (emit cells + resolve refs).
fn asmProcessLine(line_meat: []const u8, cell_idx: u32, out: ?[]i32) ?u32 {
    var pos: usize = 0;
    const s = line_meat;

    asmSkipSpaces(s, &pos);
    if (pos < s.len and isIdentStart(s[pos])) {
        const save = pos;
        const name = asmReadIdent(s, &pos);
        if (pos < s.len and s[pos] == ':') {
            pos += 1;
            if (out == null) {
                if (!asmAddLabel(name, cell_idx)) {
                    asm_err_msg = "label table full or duplicate";
                    return null;
                }
            }
            // fall through — line may have content after label
        } else {
            pos = save;
        }
    }

    asmSkipSpaces(s, &pos);
    if (pos >= s.len) return 0;

    if (s[pos] == '.') {
        pos += 1;
        const dir = asmReadIdent(s, &pos);
        if (dir.len == 4 and dir[0] == 'w' and dir[1] == 'o' and dir[2] == 'r' and dir[3] == 'd') {
            const op = asmParseOperand(s, &pos) orelse {
                asm_err_msg = ".word: missing operand";
                return null;
            };
            if (out) |o| {
                const v = asmResolve(op) orelse {
                    asm_err_msg = ".word: undefined label";
                    return null;
                };
                o[cell_idx] = v;
            }
            return 1;
        }
        if (dir.len == 5 and dir[0] == 'a' and dir[1] == 's' and dir[2] == 'c' and dir[3] == 'i' and dir[4] == 'z') {
            asmSkipSpaces(s, &pos);
            if (pos >= s.len or s[pos] != '"') {
                asm_err_msg = ".asciz: expected quoted string";
                return null;
            }
            pos += 1;
            var emitted: u32 = 0;
            while (pos < s.len and s[pos] != '"') {
                var ch: u8 = s[pos];
                if (ch == '\\' and pos + 1 < s.len) {
                    pos += 1;
                    ch = switch (s[pos]) {
                        'n' => '\n',
                        't' => '\t',
                        '\\' => '\\',
                        '"' => '"',
                        '0' => 0,
                        else => s[pos],
                    };
                }
                if (out) |o| o[cell_idx + emitted] = @intCast(ch);
                emitted += 1;
                pos += 1;
            }
            if (pos >= s.len) {
                asm_err_msg = ".asciz: unterminated string";
                return null;
            }
            if (out) |o| o[cell_idx + emitted] = 0;
            emitted += 1;
            return emitted;
        }
        asm_err_msg = "unknown directive";
        return null;
    }

    // Instruction: parse 2 or 3 operands.
    const a = asmParseOperand(s, &pos) orelse {
        asm_err_msg = "missing operand a";
        return null;
    };
    asmSkipSpaces(s, &pos);
    const b = asmParseOperand(s, &pos) orelse {
        asm_err_msg = "missing operand b";
        return null;
    };
    asmSkipSpaces(s, &pos);
    var c_op: ?Operand = null;
    if (pos < s.len) c_op = asmParseOperand(s, &pos);

    if (out) |o| {
        const va = asmResolve(a) orelse {
            asm_err_msg = "undefined label in a";
            return null;
        };
        const vb = asmResolve(b) orelse {
            asm_err_msg = "undefined label in b";
            return null;
        };
        const vc = if (c_op) |cc| (asmResolve(cc) orelse {
            asm_err_msg = "undefined label in c";
            return null;
        }) else @as(i32, @intCast(cell_idx + 3));
        o[cell_idx] = va;
        o[cell_idx + 1] = vb;
        o[cell_idx + 2] = vc;
    }
    return 3;
}

/// Assemble `src` into `out`. Returns cells emitted, or null on error (read
/// `asm_err_msg` and `asm_err_line` after).
pub fn assemble(src: []const u8, out: []i32) ?u32 {
    asmReset();

    var pos: usize = 0;
    var cell_idx: u32 = 0;
    var line_no: u32 = 0;
    while (asmNextLine(src, &pos)) |line| {
        line_no += 1;
        const meat = asmTrim(asmStripComment(line));
        if (meat.len == 0) continue;
        const n = asmProcessLine(meat, cell_idx, null) orelse {
            asm_err_line = line_no;
            return null;
        };
        cell_idx += n;
        if (cell_idx > out.len) {
            asm_err_msg = "program exceeds memory";
            asm_err_line = line_no;
            return null;
        }
    }

    pos = 0;
    cell_idx = 0;
    line_no = 0;
    while (asmNextLine(src, &pos)) |line| {
        line_no += 1;
        const meat = asmTrim(asmStripComment(line));
        if (meat.len == 0) continue;
        const n = asmProcessLine(meat, cell_idx, out) orelse {
            asm_err_line = line_no;
            return null;
        };
        cell_idx += n;
    }
    return cell_idx;
}

// === Built-in samples ===
// Build a "print text + halt" program at comptime.

fn buildOutputProgram(comptime text: []const u8) [4 * text.len + 4]i32 {
    @setEvalBranchQuota(1_000_000);
    var prog: [4 * text.len + 4]i32 = undefined;
    const n = text.len;
    const data_start: i32 = @intCast(n * 3 + 3);
    const z_addr: i32 = data_start + @as(i32, @intCast(n));
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const pc_here: i32 = @intCast(i * 3);
        prog[i * 3] = data_start + @as(i32, @intCast(i));
        prog[i * 3 + 1] = -1;
        prog[i * 3 + 2] = pc_here + 3;
    }
    const halt = n * 3;
    prog[halt] = z_addr;
    prog[halt + 1] = z_addr;
    prog[halt + 2] = -1;
    var j: usize = 0;
    while (j < n) : (j += 1) {
        prog[@as(usize, @intCast(data_start)) + j] = @intCast(text[j]);
    }
    prog[@as(usize, @intCast(z_addr))] = 0;
    return prog;
}

pub const SAMPLE_HELLO = buildOutputProgram("Hello, World!\n");
pub const SAMPLE_HI = buildOutputProgram("Hi from Subleq!\n");

// Echo loop — read char, write char, halt on 0/EOF.
pub const SAMPLE_ECHO: [14]i32 = .{
    -1, 12, 9,
    12, -1, 6,
    13, 13, 0,
    13, 13, -1,
    0,
    0,
};

pub const SAMPLE_COUNT = buildOutputProgram("5 4 3 2 1\n");

pub const Sample = struct {
    name: []const u8,
    desc: []const u8,
    code: []const i32,
};

pub const SAMPLES: []const Sample = &[_]Sample{
    .{ .name = "hello", .desc = "Print 'Hello, World!'", .code = &SAMPLE_HELLO },
    .{ .name = "hi", .desc = "Print 'Hi from Subleq!'", .code = &SAMPLE_HI },
    .{ .name = "echo", .desc = "Echo stdin to stdout until 0/EOF", .code = &SAMPLE_ECHO },
    .{ .name = "count", .desc = "Print '5 4 3 2 1'", .code = &SAMPLE_COUNT },
};
