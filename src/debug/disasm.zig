// Minimal x86-64 disassembler — best effort, prints the mnemonic for ONE
// instruction starting at the beginning of `bytes`. Targets the patterns that
// dominate real crash reports (MOV load/store with ModR/M+SIB, RET, CALL,
// INT3, indirect FF). Unknown opcodes fall through to "??", which is fine —
// the byte dump is right next to it.
//
// Scope: enough to make a fault site readable without reaching for objdump.
// NOT a full decoder; do not rely on this for anything other than diagnostics.

const serial = @import("serial.zig");

const REG64 = [_][]const u8{
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
};

const REG32 = [_][]const u8{
    "eax", "ecx", "edx",  "ebx",  "esp",  "ebp",  "esi",  "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
};

// 8-bit register names. The encoding splits on whether ANY REX prefix is
// present: without REX, indices 4..7 are the legacy high-byte regs AH..BH
// (and only 0..7 are reachable); with REX, 4..7 become SPL..DIL, 8..15 the
// extended byte regs, and AH..BH are no longer addressable. reg8Name picks
// the right table — getting this wrong would mislabel a byte access as a
// dword one in a fault dump, the exact thing this decoder exists to clarify.
const REG8_REX = [_][]const u8{
    "al",  "cl",  "dl",   "bl",   "spl",  "bpl",  "sil",  "dil",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
};
const REG8_NOREX = [_][]const u8{
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
};

const State = struct {
    bytes: []const u8,
    pos: usize = 0,
    rex_w: bool = false,
    rex_r: bool = false,
    rex_x: bool = false,
    rex_b: bool = false,
    has_rex: bool = false,

    fn peek(s: *State) ?u8 {
        if (s.pos >= s.bytes.len) return null;
        return s.bytes[s.pos];
    }
    fn next(s: *State) ?u8 {
        if (s.pos >= s.bytes.len) return null;
        const b = s.bytes[s.pos];
        s.pos += 1;
        return b;
    }
    fn regNames(s: *const State) [16][]const u8 {
        return if (s.rex_w) REG64 else REG32;
    }
};

fn regIdx(rex_high_bit: bool, low3: u8) u4 {
    var idx: u4 = @intCast(low3 & 7);
    if (rex_high_bit) idx |= 0x8;
    return idx;
}

/// 8-bit register name for `idx`, accounting for the REX-present split
/// described on REG8_REX/REG8_NOREX. Without REX only 0..7 are reachable
/// (regIdx can't set the high bit), so REG8_NOREX[idx & 7] is in-range.
fn reg8Name(s: *const State, idx: u4) []const u8 {
    return if (s.has_rex) REG8_REX[idx] else REG8_NOREX[idx & 7];
}

// Decode a ModR/M memory operand and write something like "[rsi+r8*8]" to the
// serial. Consumes the ModR/M byte plus optional SIB and displacement.
fn writeMemOperand(s: *State, modrm: u8, byte_op: bool) void {
    const mod: u2 = @intCast((modrm >> 6) & 3);
    const rm: u8 = modrm & 7;

    if (mod == 3) {
        // Register-direct, no memory. Operand size selects the table; memory
        // operands below always use 64-bit address registers regardless.
        const r = regIdx(s.rex_b, rm);
        if (byte_op) {
            serial.print("{s}", .{reg8Name(s, r)});
        } else {
            serial.print("{s}", .{s.regNames()[r]});
        }
        return;
    }

    // Memory operand. RM=4 means SIB follows; RM=5 with mod=0 means RIP-relative.
    if (rm == 4) {
        const sib = s.next() orelse {
            serial.print("[??]", .{});
            return;
        };
        const scale: u8 = @as(u8, 1) << @intCast((sib >> 6) & 3);
        const index_low: u8 = (sib >> 3) & 7;
        const base_low: u8 = sib & 7;
        const index = regIdx(s.rex_x, index_low);
        const base = regIdx(s.rex_b, base_low);
        const has_index = !(index_low == 4 and !s.rex_x); // RSP encodes "no index"

        // Special case: mod=0 with base=5 means [disp32 + index*scale] (no base).
        if (mod == 0 and base_low == 5) {
            const d = readDisp32(s) orelse 0;
            if (has_index) {
                serial.print("[{s}*{d}+0x{X}]", .{ REG64[index], scale, d });
            } else {
                serial.print("[0x{X}]", .{d});
            }
            return;
        }

        serial.print("[{s}", .{REG64[base]});
        if (has_index) serial.print("+{s}*{d}", .{ REG64[index], scale });
        if (mod == 1) {
            const d = readDisp8(s) orelse 0;
            const i: i32 = @as(i8, @bitCast(d));
            if (i >= 0) serial.print("+0x{X}", .{i}) else serial.print("-0x{X}", .{-i});
        } else if (mod == 2) {
            const d = readDisp32(s) orelse 0;
            serial.print("+0x{X}", .{d});
        }
        serial.print("]", .{});
        return;
    }

    if (rm == 5 and mod == 0) {
        const d = readDisp32(s) orelse 0;
        serial.print("[rip+0x{X}]", .{d});
        return;
    }

    const base = regIdx(s.rex_b, rm);
    serial.print("[{s}", .{REG64[base]});
    if (mod == 1) {
        const d = readDisp8(s) orelse 0;
        const i: i32 = @as(i8, @bitCast(d));
        if (i >= 0) serial.print("+0x{X}", .{i}) else serial.print("-0x{X}", .{-i});
    } else if (mod == 2) {
        const d = readDisp32(s) orelse 0;
        serial.print("+0x{X}", .{d});
    }
    serial.print("]", .{});
}

fn readDisp8(s: *State) ?u8 {
    return s.next();
}

fn readDisp32(s: *State) ?u32 {
    if (s.pos + 4 > s.bytes.len) return null;
    const lo: u32 = s.bytes[s.pos];
    const a: u32 = s.bytes[s.pos + 1];
    const c: u32 = s.bytes[s.pos + 2];
    const d: u32 = s.bytes[s.pos + 3];
    s.pos += 4;
    return lo | (a << 8) | (c << 16) | (d << 24);
}

/// Print one decoded instruction from `bytes`. Emits a mnemonic + operands or
/// `??` (with the offending opcode) when we don't recognize it.
pub fn printOne(bytes: []const u8) void {
    if (bytes.len == 0) {
        serial.print("(no bytes)", .{});
        return;
    }
    var s = State{ .bytes = bytes };

    // Skip simple prefixes (segment override, lock, rep). We don't render them
    // — they'd just clutter the line for diagnostics.
    while (s.peek()) |b| switch (b) {
        0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65 => s.pos += 1,
        else => break,
    };

    // REX prefix.
    if (s.peek()) |b| {
        if (b >= 0x40 and b <= 0x4F) {
            s.has_rex = true;
            s.rex_w = (b & 0x08) != 0;
            s.rex_r = (b & 0x04) != 0;
            s.rex_x = (b & 0x02) != 0;
            s.rex_b = (b & 0x01) != 0;
            s.pos += 1;
        }
    }

    const op = s.next() orelse {
        serial.print("??", .{});
        return;
    };

    switch (op) {
        0x88, 0x89 => { // MOV r/m, r  (0x88 = byte, 0x89 = word/dword/qword)
            const modrm = s.next() orelse {
                serial.print("mov ??", .{});
                return;
            };
            const byte_op = (op == 0x88);
            const reg = regIdx(s.rex_r, (modrm >> 3) & 7);
            serial.print("mov ", .{});
            writeMemOperand(&s, modrm, byte_op);
            if (byte_op) {
                serial.print(", {s}", .{reg8Name(&s, reg)});
            } else {
                serial.print(", {s}", .{s.regNames()[reg]});
            }
        },
        0x8A, 0x8B => { // MOV r, r/m  (0x8A = byte, 0x8B = word/dword/qword)
            const modrm = s.next() orelse {
                serial.print("mov ??", .{});
                return;
            };
            const byte_op = (op == 0x8A);
            const reg = regIdx(s.rex_r, (modrm >> 3) & 7);
            if (byte_op) {
                serial.print("mov {s}, ", .{reg8Name(&s, reg)});
            } else {
                serial.print("mov {s}, ", .{s.regNames()[reg]});
            }
            writeMemOperand(&s, modrm, byte_op);
        },
        0x3B => { // CMP r, r/m
            const modrm = s.next() orelse {
                serial.print("cmp ??", .{});
                return;
            };
            const reg_low = (modrm >> 3) & 7;
            const reg = regIdx(s.rex_r, reg_low);
            const regs = s.regNames();
            serial.print("cmp {s}, ", .{regs[reg]});
            writeMemOperand(&s, modrm, false);
        },
        0x39 => { // CMP r/m, r
            const modrm = s.next() orelse {
                serial.print("cmp ??", .{});
                return;
            };
            const reg_low = (modrm >> 3) & 7;
            const reg = regIdx(s.rex_r, reg_low);
            const regs = s.regNames();
            serial.print("cmp ", .{});
            writeMemOperand(&s, modrm, false);
            serial.print(", {s}", .{regs[reg]});
        },
        0x83 => { // ALU r/m, imm8 — sub-op encoded in ModR/M.reg
            const modrm = s.next() orelse {
                serial.print("?? ??", .{});
                return;
            };
            const op2 = (modrm >> 3) & 7;
            const name = switch (op2) {
                0 => "add",
                1 => "or",
                4 => "and",
                5 => "sub",
                6 => "xor",
                7 => "cmp",
                else => "??",
            };
            serial.print("{s} ", .{name});
            writeMemOperand(&s, modrm, false);
            const imm = s.next() orelse 0;
            serial.print(", 0x{X}", .{imm});
        },
        0xFF => { // CALL/JMP/PUSH indirect — sub-op in ModR/M.reg
            const modrm = s.next() orelse {
                serial.print("?? ??", .{});
                return;
            };
            const op2 = (modrm >> 3) & 7;
            const name = switch (op2) {
                2 => "call",
                4 => "jmp",
                6 => "push",
                else => "??",
            };
            serial.print("{s} ", .{name});
            writeMemOperand(&s, modrm, false);
        },
        0xE8 => serial.print("call rel32", .{}),
        0xE9 => serial.print("jmp rel32", .{}),
        0xEB => serial.print("jmp rel8", .{}),
        0xC3 => serial.print("ret", .{}),
        0xC2 => serial.print("ret imm16", .{}),
        0xCC => serial.print("int3", .{}),
        0x90 => serial.print("nop", .{}),
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57 => {
            const r = regIdx(s.rex_b, op - 0x50);
            serial.print("push {s}", .{REG64[r]});
        },
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F => {
            const r = regIdx(s.rex_b, op - 0x58);
            serial.print("pop {s}", .{REG64[r]});
        },
        else => serial.print("?? (op=0x{X:0>2})", .{op}),
    }
}
