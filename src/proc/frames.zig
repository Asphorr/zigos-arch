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
//! Customers today: the first-dispatch contract below (sched_asm.zig's
//! switchTo/retToUserStub + lifecycle.zig's SIX forges — the user trio
//! create/clone/fork and the kthread trio idle/S3-replant/kernel-task)
//! plus the six saved-RIP diagnostics addressing [kesp+saved_rip_off].
//! The syscall and IRQ entry frames (their own push orders, their own
//! hand-checked alignment comments — misc_irq.zig line 60) are future
//! customers; convert them one at a time, each against its live
//! disassembly. ⚠ Until then: signals.IrqFrame/ExcFrame and the
//! IRQ-side push stubs are byte-identical to `dispatch.gprs` TODAY by
//! shared convention, NOT by derivation — reordering dispatch.gprs
//! "because it's derived now" would silently diverge four IRQ-side
//! consumers. Convert them first, reorder after.

const std = @import("std");

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
