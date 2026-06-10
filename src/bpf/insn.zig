//! bpf/insn — the eBPF instruction set (encoding + builders).
//!
//! This is the STANDARD eBPF ISA as specified in RFC 9669 ("BPF Instruction
//! Set Architecture", Nov 2024), not an invented one. Deliberate: the wheel
//! worth keeping here is the *format* — using the real encoding means
//! off-the-shelf tooling (clang -target bpf, ubpf test vectors, the kernel's
//! samples) emits programs ZigOS can eventually run, the same reasoning that
//! put ext2 on our disks instead of a homegrown FS. The implementation
//! (interpreter in vm.zig, later verifier/maps/hooks) is ours.
//!
//! Layout (RFC 9669 §3): 64-bit fixed-width instructions, little-endian:
//!
//!     bits  0..7   opcode
//!     bits  8..11  dst register
//!     bits 12..15  src register
//!     bits 16..31  signed 16-bit offset
//!     bits 32..63  signed 32-bit immediate
//!
//! The single exception is LD_IMM64 (opcode 0x18), which occupies TWO
//! consecutive slots: the second slot is a pseudo-instruction (opcode 0)
//! whose imm carries the upper 32 bits.
//!
//! Registers: r0 = return value, r1-r5 = helper/program arguments (scratch),
//! r6-r9 = callee-saved, r10 = read-only frame pointer (top of the 512-byte
//! stack; programs address it with negative offsets).
//!
//! M1 scope note: the constants below cover the full base ISA plus the v4
//! additions vm.zig implements (sdiv/smod via offset, movsx, bswap, memsx,
//! jmp32-class long JA). Legacy packet-access modes (ABS/IND) and atomics
//! are encoded here for completeness but rejected by the interpreter.

const std = @import("std");

/// One 64-bit instruction slot. extern struct => guaranteed C layout,
/// byte-identical to the on-wire format, so a `[]const u8` program image
/// (e.g. a clang-emitted .text section) can be reinterpreted directly.
pub const Insn = extern struct {
    opcode: u8,
    /// dst in the low nibble, src in the high nibble.
    regs: u8,
    offset: i16,
    imm: i32,

    pub inline fn dst(self: Insn) u4 {
        return @truncate(self.regs & 0x0F);
    }
    pub inline fn src(self: Insn) u4 {
        return @truncate(self.regs >> 4);
    }
};

comptime {
    if (@sizeOf(Insn) != 8) @compileError("eBPF insn must be exactly 8 bytes");
}

/// Classic eBPF program-size ceiling (pre-5.2 Linux). Plenty for tracing
/// programs; revisit when the verifier (M3) can budget bigger ones.
pub const MAX_INSNS: usize = 4096;

/// Per-program stack, addressed via r10 with negative offsets (RFC §4.4).
pub const STACK_SIZE: usize = 512;

pub const NUM_REGS: usize = 11; // r0..r10

// === Instruction classes (opcode bits 0..2) ===
pub const CLASS_LD: u8 = 0x00; // non-standard loads (ld_imm64; legacy ABS/IND)
pub const CLASS_LDX: u8 = 0x01; // memory load,  dst = *(size *)(src + off)
pub const CLASS_ST: u8 = 0x02; // memory store, *(size *)(dst + off) = imm
pub const CLASS_STX: u8 = 0x03; // memory store, *(size *)(dst + off) = src
pub const CLASS_ALU: u8 = 0x04; // 32-bit arithmetic
pub const CLASS_JMP: u8 = 0x05; // 64-bit jumps + call/exit
pub const CLASS_JMP32: u8 = 0x06; // 32-bit-compare jumps
pub const CLASS_ALU64: u8 = 0x07; // 64-bit arithmetic

// === Source-operand bit for ALU/JMP classes (opcode bit 3) ===
pub const SRC_K: u8 = 0x00; // use the 32-bit immediate
pub const SRC_X: u8 = 0x08; // use the src register

// === ALU operation codes (opcode bits 4..7), ALU and ALU64 classes ===
pub const AluCode = enum(u8) {
    add = 0x00,
    sub = 0x10,
    mul = 0x20,
    div = 0x30, // offset=0 unsigned; offset=1 => SDIV (v4)
    @"or" = 0x40,
    @"and" = 0x50,
    lsh = 0x60,
    rsh = 0x70,
    neg = 0x80, // no src variant
    mod = 0x90, // offset=0 unsigned; offset=1 => SMOD (v4)
    xor = 0xa0,
    mov = 0xb0, // offset=8/16/32 => MOVSX (v4)
    arsh = 0xc0,
    /// CLASS_ALU: byte-order conversion — SRC_K = to-little, SRC_X = to-big,
    /// imm = 16/32/64. CLASS_ALU64: unconditional BSWAP (v4), imm = width.
    end = 0xd0,
};

// === Jump operation codes (opcode bits 4..7), JMP and JMP32 classes ===
pub const JmpCode = enum(u8) {
    ja = 0x00, // JMP: pc += offset. JMP32 (v4): pc += imm (long jump)
    jeq = 0x10,
    jgt = 0x20, // unsigned
    jge = 0x30, // unsigned
    jset = 0x40, // dst & src
    jne = 0x50,
    jsgt = 0x60, // signed
    jsge = 0x70, // signed
    call = 0x80, // src=0 helper-by-id; src=1 bpf-to-bpf; src=2 runtime fn
    exit = 0x90,
    jlt = 0xa0, // unsigned
    jle = 0xb0, // unsigned
    jslt = 0xc0, // signed
    jsle = 0xd0, // signed
};

// === Memory-access size (opcode bits 3..4), LD/LDX/ST/STX classes ===
pub const Size = enum(u8) {
    w = 0x00, // 4 bytes
    h = 0x08, // 2 bytes
    b = 0x10, // 1 byte
    dw = 0x18, // 8 bytes

    pub fn bytes(self: Size) u64 {
        return switch (self) {
            .w => 4,
            .h => 2,
            .b => 1,
            .dw => 8,
        };
    }
};

// === Memory-access mode (opcode bits 5..7), LD/LDX/ST/STX classes ===
pub const MODE_IMM: u8 = 0x00; // ld_imm64 only
pub const MODE_ABS: u8 = 0x20; // legacy cBPF packet load — rejected
pub const MODE_IND: u8 = 0x40; // legacy cBPF packet load — rejected
pub const MODE_MEM: u8 = 0x60; // the normal load/store
pub const MODE_MEMSX: u8 = 0x80; // sign-extending load (v4)
pub const MODE_ATOMIC: u8 = 0xc0; // atomic ops — rejected until M2+

/// The full LD_IMM64 opcode (CLASS_LD | MODE_IMM | Size.dw).
pub const OP_LD_IMM64: u8 = 0x18;

// =========================================================================
// Builders — Zig spellings of the kernel's BPF_* macros, so harness tests
// and (later) in-kernel example programs read like assembly listings.
// =========================================================================

inline fn packRegs(d: u4, s: u4) u8 {
    return (@as(u8, s) << 4) | @as(u8, d);
}

pub fn alu64Imm(code: AluCode, d: u4, imm: i32) Insn {
    return .{ .opcode = @intFromEnum(code) | SRC_K | CLASS_ALU64, .regs = packRegs(d, 0), .offset = 0, .imm = imm };
}

pub fn alu64Reg(code: AluCode, d: u4, s: u4) Insn {
    return .{ .opcode = @intFromEnum(code) | SRC_X | CLASS_ALU64, .regs = packRegs(d, s), .offset = 0, .imm = 0 };
}

pub fn alu32Imm(code: AluCode, d: u4, imm: i32) Insn {
    return .{ .opcode = @intFromEnum(code) | SRC_K | CLASS_ALU, .regs = packRegs(d, 0), .offset = 0, .imm = imm };
}

pub fn alu32Reg(code: AluCode, d: u4, s: u4) Insn {
    return .{ .opcode = @intFromEnum(code) | SRC_X | CLASS_ALU, .regs = packRegs(d, s), .offset = 0, .imm = 0 };
}

/// Signed div/mod (v4): same opcode as div/mod, offset=1 selects signedness.
pub fn alu64SignedReg(code: AluCode, d: u4, s: u4) Insn {
    var i = alu64Reg(code, d, s);
    i.offset = 1;
    return i;
}

/// MOVSX (v4): mov with offset = source width (8/16/32) => sign-extend.
pub fn mov64Sx(d: u4, s: u4, width: i16) Insn {
    var i = alu64Reg(.mov, d, s);
    i.offset = width;
    return i;
}

pub fn mov64Imm(d: u4, imm: i32) Insn {
    return alu64Imm(.mov, d, imm);
}

pub fn mov64Reg(d: u4, s: u4) Insn {
    return alu64Reg(.mov, d, s);
}

/// Byte-order ops. CLASS_ALU + SRC_K/SRC_X = to_le/to_be (imm = 16/32/64).
pub fn endian(to_be: bool, d: u4, width: i32) Insn {
    const srcbit: u8 = if (to_be) SRC_X else SRC_K;
    return .{ .opcode = @intFromEnum(AluCode.end) | srcbit | CLASS_ALU, .regs = packRegs(d, 0), .offset = 0, .imm = width };
}

/// BSWAP (v4): unconditional byte swap, CLASS_ALU64.
pub fn bswap(d: u4, width: i32) Insn {
    return .{ .opcode = @intFromEnum(AluCode.end) | SRC_K | CLASS_ALU64, .regs = packRegs(d, 0), .offset = 0, .imm = width };
}

pub fn jmpImm(code: JmpCode, d: u4, imm: i32, off: i16) Insn {
    return .{ .opcode = @intFromEnum(code) | SRC_K | CLASS_JMP, .regs = packRegs(d, 0), .offset = off, .imm = imm };
}

pub fn jmpReg(code: JmpCode, d: u4, s: u4, off: i16) Insn {
    return .{ .opcode = @intFromEnum(code) | SRC_X | CLASS_JMP, .regs = packRegs(d, s), .offset = off, .imm = 0 };
}

pub fn jmp32Imm(code: JmpCode, d: u4, imm: i32, off: i16) Insn {
    return .{ .opcode = @intFromEnum(code) | SRC_K | CLASS_JMP32, .regs = packRegs(d, 0), .offset = off, .imm = imm };
}

pub fn jmp32Reg(code: JmpCode, d: u4, s: u4, off: i16) Insn {
    return .{ .opcode = @intFromEnum(code) | SRC_X | CLASS_JMP32, .regs = packRegs(d, s), .offset = off, .imm = 0 };
}

pub fn ja(off: i16) Insn {
    return .{ .opcode = @intFromEnum(JmpCode.ja) | CLASS_JMP, .regs = 0, .offset = off, .imm = 0 };
}

/// dst = *(size *)(src + off)
pub fn ldx(size: Size, d: u4, s: u4, off: i16) Insn {
    return .{ .opcode = MODE_MEM | @intFromEnum(size) | CLASS_LDX, .regs = packRegs(d, s), .offset = off, .imm = 0 };
}

/// Sign-extending load (v4): dst = (signed size)*(src + off)
pub fn ldxSx(size: Size, d: u4, s: u4, off: i16) Insn {
    return .{ .opcode = MODE_MEMSX | @intFromEnum(size) | CLASS_LDX, .regs = packRegs(d, s), .offset = off, .imm = 0 };
}

/// *(size *)(dst + off) = imm
pub fn st(size: Size, d: u4, off: i16, imm: i32) Insn {
    return .{ .opcode = MODE_MEM | @intFromEnum(size) | CLASS_ST, .regs = packRegs(d, 0), .offset = off, .imm = imm };
}

/// *(size *)(dst + off) = src
pub fn stx(size: Size, d: u4, s: u4, off: i16) Insn {
    return .{ .opcode = MODE_MEM | @intFromEnum(size) | CLASS_STX, .regs = packRegs(d, s), .offset = off, .imm = 0 };
}

/// dst = imm64 — occupies two slots.
pub fn ldImm64(d: u4, v: u64) [2]Insn {
    return .{
        .{ .opcode = OP_LD_IMM64, .regs = packRegs(d, 0), .offset = 0, .imm = @bitCast(@as(u32, @truncate(v))) },
        .{ .opcode = 0, .regs = 0, .offset = 0, .imm = @bitCast(@as(u32, @truncate(v >> 32))) },
    };
}

pub fn call(helper_id: i32) Insn {
    return .{ .opcode = @intFromEnum(JmpCode.call) | CLASS_JMP, .regs = 0, .offset = 0, .imm = helper_id };
}

pub fn exit() Insn {
    return .{ .opcode = @intFromEnum(JmpCode.exit) | CLASS_JMP, .regs = 0, .offset = 0, .imm = 0 };
}
