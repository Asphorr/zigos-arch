//! Interrupt and exception entry stubs, as text generated from their frame
//! (proc/frames.zig, `Entry`). The pushes, the `sub`, where the frame and
//! the interrupted RIP are — all of it comes from the one declaration the
//! handler reads its frame by, so stub and handler cannot count differently.
//!
//! A stub is `save` ++ what it does ++ `restore`; `handler` is the whole of
//! one that only calls its handler. Between the two RSP is at the FXSAVE
//! image, 16-aligned: a stub that moves it puts it back before `restore`.

const serial = @import("../../debug/serial.zig");
const symbols = @import("../../debug/symbols.zig");
const sched_asm = @import("../../proc/sched_asm.zig");
const dec = @import("../../proc/frames.zig").decimal;

/// Save what a handler may clobber: the frame's registers and the FP/SSE
/// state, which kernel code uses freely.
///
/// cld: delivery keeps the interrupted DF — user code may hold DF=1 — and
/// the kernel's rep-string memcpy and memset assume DF=0. iretq restores
/// the interrupted one.
pub fn save(comptime E: type) []const u8 {
    return "cld\n" ++
        E.saved.push_asm ++
        (if (E.canary) |c| "pushq $" ++ dec(c.value) ++ "\n" else "") ++
        "subq $" ++ dec(E.fp_bytes) ++ ", %%rsp\n" ++
        "fxsaveq (%%rsp)\n";
}

/// Undo `save` and return to what was interrupted, through the check every
/// iretq to a task goes through (sched_asm.SAFE_IRETQ).
pub fn restore(comptime E: type) []const u8 {
    return "fxrstorq (%%rsp)\n" ++
        "addq $" ++ dec(E.fp_bytes) ++ ", %%rsp\n" ++
        (if (E.canary) |c|
            "cmpq $" ++ dec(c.value) ++ ", (%%rsp)\n" ++
                "je 4f\n" ++
                "movq %%rsp, %%rdi\n" ++
                "jmp " ++ c.panic ++ "\n" ++
                "4:\n" ++
                "addq $8, %%rsp\n"
        else
            "") ++
        E.saved.pop_asm ++
        (if (E.vector_bytes != 0) "addq $" ++ dec(E.vector_bytes) ++ ", %%rsp\n" else "") ++
        sched_asm.SAFE_IRETQ;
}

/// What a handler is called with.
pub const Arg = union(enum) {
    none,
    /// The frame: the handler reads or rewrites what it interrupted.
    frame,
    /// The interrupted RIP.
    rip,
    /// A constant: the vector, where several share a handler.
    value: u32,
};

/// `call`, on an RSP that must be 16-aligned. At the FXSAVE image the
/// layout makes it so; the test is for what the layout cannot see — a thunk
/// that pushed other than its declared vector words, an entry on an RSP the
/// CPU did not align, a stub that moved RSP elsewhere for the call (which
/// then cannot ask for `.frame` or `.rip`: they are found from the image).
pub fn call(comptime E: type, comptime name: []const u8, comptime arg: Arg) []const u8 {
    return (switch (arg) {
        .none => "",
        .frame => "leaq " ++ dec(E.fp_below) ++ "(%%rsp), %%rdi\n",
        .rip => "movq " ++ dec(E.iretqOffset(.rip)) ++ "(%%rsp), %%rdi\n",
        .value => |v| "movl $" ++ dec(v) ++ ", %%edi\n",
    }) ++
        "testq $0xF, %%rsp\n" ++
        "jz 3f\n" ++
        "leaq 0(%%rip), %%rdi\n" ++
        "jmp isr_align_panic\n" ++
        "3:\n" ++
        "call " ++ name ++ "\n";
}

/// The text of a stub that only calls its handler.
pub fn handler(comptime E: type, comptime name: []const u8, comptime arg: Arg) []const u8 {
    return save(E) ++ call(E, name, arg) ++ restore(E);
}

/// A stub found RSP off a 16-byte boundary at its call. `at` is inside it.
pub export fn isr_align_panic(at: u64) callconv(.c) noreturn {
    if (symbols.resolveKernel(at)) |r| {
        serial.print("\n[entry] {s}: RSP is not 16-aligned at the call to its handler\n", .{r.name});
    } else {
        serial.print("\n[entry] stub at 0x{X:0>16}: RSP is not 16-aligned at the call to its handler\n", .{at});
    }
    @panic("entry stub: RSP misaligned at its call — its frame declares other than what was pushed");
}
