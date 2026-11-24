//! Kernel half of the real mode -> long mode trampolines (trampoline.inc).
//!
//! A blob runs at the low physical address it was assembled for and carries
//! its params inside, so `install` + `arm` write one page and nothing else.

const paging = @import("../mm/paging.zig");

pub const Blob = enum {
    /// ap_trampoline.asm: INIT-SIPI-SIPI starts an AP in it (cpu/smp.zig).
    ap,
    /// wake_trampoline.asm: the BSP's S3 waking vector (acpi/s3.zig).
    wake,
};

/// == the params block in trampoline.inc.
pub const Params = extern struct {
    /// Loaded in 32-bit mode: below 4 GiB, page-aligned.
    cr3: u64,
    /// Kernel VA, 16-aligned.
    stack_top: u64,
    /// Kernel VA; called with every GPR but RSP zeroed.
    entry: u64,
    /// Set by the assembler: where the blob has to run.
    base: u32,
    /// Written by the CPU on its way up.
    progress: Progress,
};

/// == PROGRESS_* in trampoline.inc.
pub const Progress = enum(u32) {
    not_started = 0,
    real_mode = 1,
    protected_mode = 2,
    long_mode = 3,
    rejected_params = 0xFF,
    _,
};

pub const Entry = *const fn () callconv(.c) noreturn;

fn symbol(comptime T: type, comptime blob: Blob, comptime suffix: []const u8) T {
    return @extern(T, .{ .name = @tagName(blob) ++ "_trampoline_" ++ suffix });
}

fn blobStart(comptime blob: Blob) usize {
    return @intFromPtr(symbol(*const u8, blob, "start"));
}

fn blobEnd(comptime blob: Blob) usize {
    return @intFromPtr(symbol(*const u8, blob, "end"));
}

/// The params as linked into the kernel image, not the installed copy.
fn linkedParams(comptime blob: Blob) *const Params {
    return symbol(*const Params, blob, "params");
}

/// Page-aligned and below 64 KiB (the asm checks), so `phys(.ap) >> 12` is
/// the SIPI vector.
pub fn phys(comptime blob: Blob) u32 {
    return linkedParams(blob).base;
}

pub fn install(comptime blob: Blob) void {
    if (blobEnd(blob) - @intFromPtr(linkedParams(blob)) != @sizeOf(Params))
        @panic(@tagName(blob) ++ " trampoline: params block in the asm and trampoline.Params disagree");
    const size = blobEnd(blob) - blobStart(blob);
    const src: [*]const u8 = @ptrFromInt(blobStart(blob));
    const dst: [*]u8 = @ptrFromInt(paging.physToVirt(phys(blob)));
    @memcpy(dst[0..size], src[0..size]);
}

/// The params inside the installed copy.
pub fn params(comptime blob: Blob) *volatile Params {
    const offset = @intFromPtr(linkedParams(blob)) - blobStart(blob);
    return @ptrFromInt(paging.physToVirt(phys(blob) + offset));
}

pub fn arm(comptime blob: Blob, entry: Entry, cr3: u64, stack_top: usize) void {
    if (cr3 >= 1 << 32 or cr3 % 4096 != 0) @panic(@tagName(blob) ++ " trampoline: CR3 must be page-aligned and below 4 GiB");
    if (stack_top % 16 != 0) @panic(@tagName(blob) ++ " trampoline: stack_top must be 16-aligned");
    const p = params(blob);
    p.cr3 = cr3;
    p.stack_top = stack_top;
    p.entry = @intFromPtr(entry);
    p.progress = .not_started;
    // The CPU is started by an IPI or a sleep-state write, not by a store it
    // would be ordered after (an x2APIC ICR write is a WRMSR).
    asm volatile ("mfence" ::: .{ .memory = true });
}

pub fn progress(comptime blob: Blob) Progress {
    return params(blob).progress;
}

/// How far the last CPU sent into `blob` got, for a log line.
pub fn describeProgress(comptime blob: Blob) []const u8 {
    return switch (progress(blob)) {
        .not_started => "never ran",
        .real_mode => "stopped in real mode",
        .protected_mode => "stopped in protected mode",
        .long_mode => "called the entry",
        .rejected_params => "rejected its params",
        _ => "progress word corrupt",
    };
}
