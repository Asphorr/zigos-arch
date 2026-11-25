//! frames — stack-frame contracts as comptime values.
//!
//! The disease this file cures has a name in the house history: an
//! agreement between two files, kept by authorial care and checked by
//! nothing. The switch frame was the worst offender — sched_asm.zig
//! pushed 6 callee-saves and lifecycle.zig's three forges (create /
//! cloneCurrent / forkCurrent) each hand-wrote "6 zero slots + ret
//! address + 15 GPR slots + 5 iretq words" with the offsets re-derived
//! in comments ("stack_top - 216", "frame[8] = arg  // RDI is 8th in
//! retToUserStub's pop order"). Write 5 where the asm pops 6 and every
//! warning level stays silent; the first dispatch then rets into a GPR
//! slot. The FXSAVE/init_template alias (MXCSR landing on a ret-addr
//! slot, 2026-06) was this exact class: frame arithmetic done in prose.
//!
//! The cure: the frame IS a comptime value — an ordered register list —
//! and everything both sides used to agree on is DERIVED from it:
//!   - the asm text (pushAll / popAll — pops are the reversal, so they
//!     cannot disagree with the pushes),
//!   - the byte sizes and slot indices (index(.rdi) replaces the magic
//!     8; changing the pop order re-derives every forge),
//!   - the SysV alignment arithmetic that used to live in comments with
//!     a hand-drawn ✓ (rspModAfter feeds comptime asserts).
//! Zig makes this possible where C++ cannot: an asm template is just a
//! comptime string, so generated text can flow into `asm volatile`
//! (precedent in-tree: dynirq.zig's comptimePrint stubs, SAFE_IRETQ's
//! `++` splice). The asm's SEMANTIC middle — save_trace hooks, on_cpu
//! publish points — stays hand-written; the spec owns only the frame
//! geometry, which is exactly the part humans get wrong.
//!
//! Customers: the first-dispatch contract below (sched_asm.zig's
//! switchTo/retToUserStub + lifecycle.zig's SIX forges — the user trio
//! create/clone/fork and the kthread trio idle/S3-replant/kernel-task)
//! plus the six saved-RIP diagnostics addressing [kesp+saved_rip_off];
//! and the entry contract after it — what the interrupt and exception
//! stubs (cpu/idt/stub.zig) leave on the stack, which their handlers and
//! signals.IrqFrame/ExcFrame read. The syscall entry (syscall/entry.zig,
//! signals.SyscallFrame) still counts by hand.

const std = @import("std");

/// `n` in decimal, for an offset spliced into asm text. Not
/// std.fmt.comptimePrint: a stub takes many numbers, and that costs a few
/// hundred of the default 1000 comptime branches for each.
pub fn decimal(comptime n: usize) []const u8 {
    const digit = [_]u8{'0' + @as(u8, n % 10)};
    return if (n < 10) &digit else decimal(n / 10) ++ &digit;
}

/// The 15 general-purpose registers a frame can carry (RSP is the frame).
/// @tagName doubles as the AT&T spelling, so the enum IS the asm text.
pub const Reg = enum {
    rax, rbx, rcx, rdx, rsi, rdi, rbp,
    r8, r9, r10, r11, r12, r13, r14, r15,
};

/// A contiguous run of qword register slots, in POP order: `order[0]` is
/// popped first, i.e. lives at the LOWEST address (offset 0 from the
/// frame base). The push text is the reversal, so a frame that is both
/// pushed and popped through its spec cannot tear the agreement.
pub fn Frame(comptime order: []const Reg) type {
    return struct {
        pub const regs = order;
        pub const count = order.len;
        pub const bytes = order.len * 8;

        /// Qword index of `r` from the frame base (= RSP after all
        /// pushes / before the first pop). This is the number the forges
        /// used to hard-code ("frame[8] = arg").
        pub fn index(comptime r: Reg) usize {
            inline for (order, 0..) |o, k| {
                if (o == r) return k;
            }
            @compileError("register " ++ @tagName(r) ++ " is not in this frame");
        }

        /// "popq %rbp\n..." in declared order. `%%` because the text is
        /// spliced into `asm volatile` templates, where % escapes (so
        /// these strings are for operand-substituting asm only). Ends
        /// with a trailing newline — a splice CALLER never adds one
        /// after it; a multiline literal BEFORE a splice still needs
        /// its own explicit "\n" terminator (literals carry none).
        pub const pop_asm: []const u8 = blk: {
            var s: []const u8 = "";
            for (order) |r| s = s ++ "popq %%" ++ @tagName(r) ++ "\n";
            break :blk s;
        };

        /// The pushes: reversed pops, BY CONSTRUCTION. There is no
        /// second list to keep in sync.
        pub const push_asm: []const u8 = blk: {
            var s: []const u8 = "";
            var k: usize = order.len;
            while (k > 0) {
                k -= 1;
                s = s ++ "pushq %%" ++ @tagName(order[k]) ++ "\n";
            }
            break :blk s;
        };

        /// RSP (mod 16) after pushing this whole frame, given RSP (mod
        /// 16) at entry. Replaces the hand-drawn "mod 16 = 8 ✓" comment
        /// arithmetic with something the compiler re-checks on every
        /// edit of the register list.
        pub fn rspModAfter(comptime entry_mod: usize) usize {
            return (entry_mod + 16 - (bytes % 16)) % 16;
        }
    };
}

// ---------------- the first-dispatch contract --------------------------------
//
// One value, three former copies. Layout of a fresh task's kstack at its
// first dispatch (low → high), all sizes DERIVED:
//
//   kernel_esp → [ switch.count zero callee-saves ][ &retToUserStub ]
//                [ gprs.count GPR slots            ][ 5 iretq words  ]
//                                                            ← stack_top
//
// switchTo rets through the planted address into retToUserStub, which
// pops `gprs` in order and iretqs through the 5-word frame.

pub const dispatch = struct {
    /// switchTo's callee-saved set, in POP order (r15 out first). The
    /// push text used in switchTo is the derived reversal: rbp first —
    /// byte-identical to the hand-written asm this replaced.
    pub const switch_frame = Frame(&.{ .r15, .r14, .r13, .r12, .rbx, .rbp });

    /// retToUserStub's GPR image, in POP order. forkCurrent's hand
    /// table f[0]=r15 … f[14]=rax was this list, transposed by eye.
    pub const gprs = Frame(&.{
        .r15, .r14, .r13, .r12, .r11, .r10, .r9, .r8,
        .rdi, .rsi, .rbp, .rbx, .rdx, .rcx, .rax,
    });

    /// The hardware iretq record, qword indices above the GPR slots.
    pub const iretq = enum(usize) {
        rip = 0, cs = 1, rflags = 2, rsp = 3, ss = 4,
        pub inline fn at(comptime f: iretq) usize {
            return gprs.count + @intFromEnum(f);
        }
    };
    pub const iretq_words: usize = 5;

    pub const pt_regs_qwords = gprs.count + iretq_words;
    pub const pt_regs_bytes = pt_regs_qwords * 8;
    /// +8 = the planted retToUserStub return slot switchTo rets through.
    pub const switch_frame_bytes = switch_frame.bytes + 8;
    pub const total_bytes = pt_regs_bytes + switch_frame_bytes;
    /// Qword index of the ret slot within the switch frame region.
    pub const ret_slot = switch_frame.count;

    /// switchTo's saved-RIP slot: the qword at [kesp + switch_frame.bytes]
    /// — after the callee-save pops, `ret` consumes it. The diagnostics
    /// (save_trace's HWBP mirror, watch's stale-kesp filter,
    /// pcb_invariants' .text check, sched's pre-dispatch guard) address
    /// the slot through THIS name; a hand-written "+ 48" is drift bait —
    /// if the frame ever grows, those checks would re-aim at a
    /// callee-save slot and pcb_invariants would start panicking on
    /// legitimate frames.
    pub const saved_rip_off = switch_frame.bytes;

    /// Kernel-thread variant (idle tasks, S3 idle re-plant, kernel
    /// tasks): no pt_regs — switchTo's ret lands DIRECTLY in the entry
    /// fn. The frame is the switch frame + planted entry address + one
    /// poison return slot, which also lands the entry fn at
    /// RSP ≡ 8 (mod 16), exactly what a SysV `call` would have produced.
    pub const kthread_bytes = switch_frame_bytes + 8;
    /// Qword index of the poison slot (the entry fn's would-be return
    /// address; kernel entries are noreturn, so 0 = trap-on-return).
    pub const kthread_ret_pad = ret_slot + 1;

    comptime {
        // The documented constants this contract replaces — the new
        // formulation must reproduce the old numbers (house rule; same
        // trick as pte.zig's 0x83 and gpt's re-derived LBAs).
        std.debug.assert(switch_frame_bytes == 56);
        std.debug.assert(pt_regs_bytes == 160);
        std.debug.assert(total_bytes == 216);
        std.debug.assert(gprs.index(.rdi) == 8); // cloneCurrent's arg slot
        std.debug.assert(gprs.index(.rax) == 14); // fork's child-return slot
        std.debug.assert(iretq.rip.at() == 15 and iretq.ss.at() == 19);
        std.debug.assert(saved_rip_off == 48); // the diagnostics' "+48"
        std.debug.assert(kthread_bytes == 64); // kthread forges' old FRAME_BYTES
        // Forged-vs-natural residue: total−switch ≡ 0 (mod 16) makes a
        // forged kernel_esp ≡ 8 (mod 16) — the SAME residue a naturally
        // switchTo-saved kesp has (entered via callq at ≡ 8, the saves
        // keep ≡ 8). Forged and natural frames are therefore
        // indistinguishable to switchTo. (The CPU's own iretq frames
        // land at TSS.RSP0 = kstack_top, whose 16-alignment is pinned
        // by config.zig's KSTACK_* 4096-multiple asserts and the pool's
        // align(4096) — a different property, proven elsewhere.)
        std.debug.assert((total_bytes - switch_frame_bytes) % 16 == 0);
        // switchTo's internal save_trace callsite. PREMISE (not provable
        // here — see the matching comment in sched_asm.zig): exactly ONE
        // extra push sits between the saves and the callq. Under it:
        // entry ≡ 8 (mod 16) per SysV callq, the saves keep it ≡ 8, and
        // that one pushq %rsi lands the callq on ≡ 0.
        std.debug.assert(switch_frame.rspModAfter(8) == 8);
        std.debug.assert(Frame(&.{.rsi}).rspModAfter(switch_frame.rspModAfter(8)) == 0);
    }
};

// ---------------- the entry contract -----------------------------------------
//
// What an interrupt or exception stub leaves on the kernel stack, low → high:
//
//   RSP at the call → [ FXSAVE image ][ padding ][ canary ]
//   the frame       → [ saved registers ][ vector words ][ rip cs rflags rsp ss ]
//
// A handler that looks at what it interrupted is handed the frame. The CPU
// pushes its record on an RSP it has first aligned to 16, so the padding
// that makes the stub's call ABI-clean follows from the lists below; each
// stub used to count it in a comment.

/// The record the CPU pushes on an interrupt and iretq pops, by qword.
pub const Iretq = enum(usize) { rip = 0, cs = 1, rflags = 2, rsp = 3, ss = 4 };

pub const FXSAVE_BYTES: usize = 512;

/// A word a stub pushes under its saved registers and compares on the way
/// out: a write that climbs into the frame from below goes through it.
/// The stub jumps to `panic` with the word's address; the frame is above.
pub const Canary = struct { value: u31, panic: []const u8 };

pub fn Entry(comptime spec: struct {
    /// The registers the stub saves, as a Frame.
    saved: type,
    /// What the vector's thunk pushes under the CPU's record before the
    /// stub proper, by name, lowest address first.
    vector_words: []const []const u8 = &.{},
    canary: ?Canary = null,
}) type {
    return struct {
        pub const saved = spec.saved;
        pub const vector_words = spec.vector_words;
        pub const canary = spec.canary;

        pub const vector_bytes = vector_words.len * 8;
        const canary_bytes: usize = if (canary != null) 8 else 0;

        /// The stub's `sub`: the FXSAVE image and, above it, the padding
        /// that leaves RSP 16-aligned for the image and for the call.
        pub const fp_bytes = FXSAVE_BYTES +
            (dispatch.iretq_words * 8 + vector_bytes + saved.bytes + canary_bytes) % 16;

        /// From the frame down to RSP at the call, where the image is.
        pub const fp_below = fp_bytes + canary_bytes;

        pub const qwords = saved.count + vector_words.len + dispatch.iretq_words;

        /// Qword index within the frame of one of the CPU's words.
        pub fn iretqIndex(comptime w: Iretq) usize {
            return saved.count + vector_words.len + @intFromEnum(w);
        }

        /// The same word as a byte offset from RSP at the call.
        pub fn iretqOffset(comptime w: Iretq) usize {
            return fp_below + iretqIndex(w) * 8;
        }

        /// Refuse to compile unless extern struct `T` is this frame, field
        /// for field: the handlers read the frame through such a struct.
        pub fn assertMirror(comptime T: type) void {
            const info = @typeInfo(T).@"struct";
            if (info.layout != .@"extern" or info.fields.len != qwords) {
                @compileError(@typeName(T) ++ " is not the frame its stub builds: wrong layout or field count");
            }
            for (saved.regs, 0..) |r, k| expectField(T, k, @tagName(r));
            for (vector_words, 0..) |w, k| expectField(T, saved.count + k, w);
            for (@typeInfo(Iretq).@"enum".fields) |w| {
                expectField(T, saved.count + vector_words.len + w.value, w.name);
            }
        }
    };
}

fn expectField(comptime T: type, comptime k: usize, comptime name: []const u8) void {
    const f = @typeInfo(T).@"struct".fields[k];
    if (!std.mem.eql(u8, f.name, name) or f.type != u64 or @offsetOf(T, f.name) != k * 8) {
        @compileError(@typeName(T) ++ ": the stub puts '" ++ name ++ "' where the struct has '" ++ f.name ++ "'");
    }
}

pub const entry = struct {
    /// What a C handler may clobber: all a stub saves when its handler
    /// never looks at what it interrupted.
    pub const scratch = Frame(&.{ .r11, .r10, .r9, .r8, .rsi, .rdi, .rdx, .rcx, .rax });

    /// A device interrupt or an IPI: keyboard, mouse, the TLB shootdown,
    /// the PMI, the MSI-X vectors.
    pub const device = Entry(.{ .saved = scratch });

    /// The timer tick, which switches tasks and delivers signals: every
    /// register, in the order a first dispatch pops them, and a canary.
    pub const tick = Entry(.{
        .saved = dispatch.gprs,
        .canary = .{ .value = 0x7B0FF1CE, .panic = "isr_irq0_canary_panic" },
    });

    /// An exception. Its thunk pushes the vector number over the error
    /// code, and a zero for the error code where the CPU pushes none.
    pub const exception = Entry(.{
        .saved = dispatch.gprs,
        .vector_words = &.{ "int_no", "error_code" },
    });

    comptime {
        // The numbers the stubs and their handlers carried by hand.
        std.debug.assert(device.fp_bytes == 512 and device.fp_below == 512);
        std.debug.assert(device.iretqOffset(.rip) == 584 and device.iretqOffset(.cs) == 592);
        std.debug.assert(tick.fp_bytes == 520 and tick.fp_below == 528);
        std.debug.assert(tick.iretqIndex(.rip) == 15 and tick.iretqIndex(.cs) == 16);
        std.debug.assert(exception.fp_bytes == 512 and exception.fp_below == 512);
        std.debug.assert(exception.iretqIndex(.rip) == 17 and exception.iretqIndex(.ss) == 21);
    }
};

// ---------------- the syscall contract ---------------------------------------
//
// What the SYSCALL entry (syscall/entry.zig) leaves on the kernel stack,
// low → high:
//
//   RSP at the call → [ FXSAVE image ][ exit mode ][ full rcx ][ full r11 ]
//   the frame       → [ saved registers ][ user rsp ]            ← tss.rsp0
//
// SYSCALL pushes nothing and switches no stack: the entry loads RSP from
// tss.rsp0 — 16-aligned, the top of the task's kernel stack — and pushes
// the user's RSP itself. doSyscall is handed the frame, a
// signals.SyscallFrame.

pub const syscall = struct {
    /// In pop order. rcx and r11 hold what SYSCALL put there, the user's
    /// RIP and RFLAGS, and SYSRET takes them back from those two.
    pub const saved = Frame(&.{
        .r10, .r9,  .r8,  .rdx, .rsi, .rdi, .r15,
        .r14, .r13, .r12, .rbp, .rbx, .rcx, .r11,
    });

    /// The frame's last word, above the registers.
    pub const user_rsp_index = saved.count;
    pub const qwords = saved.count + 1;

    /// The three words under the frame, by distance below it. Exit mode 0
    /// leaves by sysret; nonzero leaves by iretq with every register as
    /// the frame has it and rcx and r11 from the two words here — sysret
    /// cannot give those two back.
    pub const full_r11_below: usize = 8;
    pub const full_rcx_below: usize = 16;
    pub const exit_mode_below: usize = 24;

    /// From the frame down to RSP at the call, where the image is.
    pub const fp_below = FXSAVE_BYTES + exit_mode_below;

    /// Byte offsets from RSP at the call.
    pub fn offset(comptime r: Reg) usize {
        return fp_below + saved.index(r) * 8;
    }
    pub const user_rsp_offset = fp_below + user_rsp_index * 8;
    pub const exit_mode_offset = fp_below - exit_mode_below;
    pub const full_rcx_offset = fp_below - full_rcx_below;
    pub const full_r11_offset = fp_below - full_r11_below;

    /// Where the iretq exit builds its record: the top of the image, which
    /// the fxrstor before it has finished with.
    pub const iretq_offset = FXSAVE_BYTES - dispatch.iretq_words * 8;
    pub fn iretqOffset(comptime w: Iretq) usize {
        return iretq_offset + @intFromEnum(w) * 8;
    }

    /// Refuse to compile unless extern struct `T` is this frame.
    pub fn assertMirror(comptime T: type) void {
        const info = @typeInfo(T).@"struct";
        if (info.layout != .@"extern" or info.fields.len != qwords) {
            @compileError(@typeName(T) ++ " is not the frame the syscall entry builds: wrong layout or field count");
        }
        for (saved.regs, 0..) |r, k| expectField(T, k, @tagName(r));
        expectField(T, user_rsp_index, "user_rsp");
    }

    comptime {
        // The numbers the entry carried by hand.
        std.debug.assert(fp_below == 536);
        std.debug.assert(offset(.r10) == 536 and offset(.rcx) == 632 and offset(.r11) == 640);
        std.debug.assert(user_rsp_offset == 648);
        std.debug.assert(exit_mode_offset == 512 and full_rcx_offset == 520 and full_r11_offset == 528);
        std.debug.assert(iretq_offset == 472);
        // From a 16-aligned tss.rsp0 the call is ABI-clean.
        std.debug.assert((qwords * 8 + fp_below) % 16 == 0);
    }
};
