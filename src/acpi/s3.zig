// S3 (suspend-to-RAM) suspend/resume.
//
// Entry (CP2a) writes SLP_TYP|SLP_EN to PM1a_CNT and the platform suspends.
// Resume (CP2b) is the hard half: on S3 wake the CPU comes back in 16-bit real
// mode with GDT/IDT/TR/MSRs/control-regs all reset, so the kernel cannot simply
// "return" from the SLP_EN write. The FACS firmware_waking_vector points at a
// real->long-mode trampoline (src/boot/wake_trampoline.asm, a near-copy of the
// proven AP bring-up trampoline) which re-enters 64-bit kernel code here.
//
// CP2b-1 (this step): prove the trampoline reaches long-mode kernel code at all.
// The trampoline runs, s3ResumeEntry logs a breadcrumb and halts. No CPU-state
// restore yet — re-init (mirroring smp.apEntry) + a setjmp/longjmp back into the
// suspender is CP2b-2.

const std = @import("std");
const acpi = @import("acpi.zig");
const paging = @import("../mm/paging.zig");
const io = @import("../io.zig");
const serial = @import("../debug/serial.zig");
const common = @import("../cpu/syscall/common.zig");

// Fixed low phys, < 1 MiB: the FACS 32-bit waking vector and the real-mode entry
// both require it. RAM is preserved across S3, so the blob + slots survive the
// suspend. Its own page is distinct from the AP trampoline's 0x8000 so SMP
// re-bring-up on resume never clobbers it. KEEP IN SYNC with wake_trampoline.asm.
const WAKE_TRAMP_BASE = 0x9000;
const WAKE_ENTRY_SLOT = 0x9FE8;
const WAKE_PML4_SLOT = 0x9FF0;
const WAKE_STACK_SLOT = 0x9FF8;

extern const wake_trampoline_start: u8;
extern const wake_trampoline_end: u8;

// Stack the trampoline hands to s3ResumeEntry. Kernel BSS (high VA), mapped by
// the resume CR3's shared kernel half.
var resume_stack: [16384]u8 align(16) = undefined;

/// SLP_EN (bit 13) | SLP_TYP (bits 12:10), masked to the 3-bit field so a stray
/// parse can't disturb adjacent PM1_CNT bits.
inline fn sleepWord(slp_typ: u8) u16 {
    return (@as(u16, slp_typ & 0x7) << 10) | (1 << 13);
}

fn readCr3() u64 {
    return asm volatile ("mov %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

/// Entry point the wake trampoline jumps to in 64-bit mode. CP2b-1: confirm we
/// reached long-mode kernel code, then halt (no restore yet).
export fn s3ResumeEntry() callconv(.c) noreturn {
    // Rawest possible breadcrumb FIRST: write straight to COM1 (0x3F8) before
    // touching any kernel infrastructure, so even if serial.print or per-CPU
    // (GS-based) state is unhappy this early post-resume, we still get proof the
    // trampoline reached 64-bit kernel code. QEMU's UART transmits a THR byte to
    // its backend regardless of line config.
    for ("\r\nS3WAKE\r\n") |c| io.outb(0x3F8, c);

    // Richer log (uses the stack the trampoline handed us; port I/O only — no
    // GDT/IDT/TR needed, and we never touch an NX page so EFER.NXE=0 is fine).
    serial.print("[s3] RESUME: reached 64-bit kernel via wake trampoline\n", .{});
    serial.print("[s3] RESUME: CP2b-1 stops here (full restore is CP2b-2) — halting\n", .{});
    while (true) asm volatile ("cli; hlt");
}

/// Install a temporary 2 MiB identity page at VA 0 in the current (suspending)
/// process's page tables so phys 0x9000 stays mapped the instant the wake
/// trampoline turns paging on. The process already has PML4[0]->PDPT[0]->PD
/// present (its user image lives at 4 MiB = PD[2]); PD[0] (the 0..2 MiB null
/// guard) is empty, so we borrow it without disturbing user mappings. Returns
/// the CR3 to load on resume, or null if the tables aren't shaped as expected.
fn installLowIdentity() ?u64 {
    const cr3 = readCr3();
    const pml4: [*]volatile u64 = @ptrFromInt(paging.physToVirt(cr3 & paging.PAGE_MASK));
    const pml4e = pml4[0];
    if (pml4e & paging.PRESENT == 0) return null;
    const pdpt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pml4e & paging.PAGE_MASK));
    const pdpte = pdpt[0];
    if (pdpte & paging.PRESENT == 0) return null;
    if (pdpte & paging.PAGE_SIZE_FLAG != 0) return null; // 1 GiB page: no PD to edit
    const pd: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pdpte & paging.PAGE_MASK));
    // 2 MiB identity page VA 0..2 MiB -> phys 0..2 MiB (covers 0x9000 + slots).
    pd[0] = paging.PRESENT | paging.READ_WRITE | paging.PAGE_SIZE_FLAG;
    // No flush needed: nothing reads VA 0..2 MiB until the trampoline reloads
    // CR3 on resume, which flushes the whole TLB.
    return cr3;
}

/// Copy the wake trampoline blob to WAKE_TRAMP_BASE (through the physmap) and
/// populate its data slots.
fn installWakeTrampoline(resume_cr3: u64) void {
    const blob: [*]const u8 = @ptrCast(&wake_trampoline_start);
    const size = @intFromPtr(&wake_trampoline_end) - @intFromPtr(&wake_trampoline_start);
    if (size > WAKE_ENTRY_SLOT - WAKE_TRAMP_BASE)
        @panic("s3: wake trampoline blob overran its data slots (0x9000..0x9FE8)");
    const dest: [*]u8 = @ptrFromInt(paging.physToVirt(WAKE_TRAMP_BASE));
    @memcpy(dest[0..size], blob[0..size]);

    const entry: *volatile u64 = @ptrFromInt(paging.physToVirt(WAKE_ENTRY_SLOT));
    entry.* = @intCast(@intFromPtr(&s3ResumeEntry));
    const pml4: *volatile u64 = @ptrFromInt(paging.physToVirt(WAKE_PML4_SLOT));
    pml4.* = resume_cr3;
    const stack: *volatile u64 = @ptrFromInt(paging.physToVirt(WAKE_STACK_SLOT));
    stack.* = @intCast(@intFromPtr(&resume_stack) + resume_stack.len);
}

/// Kernel side of `shutdown -s` (sysShutdown mode 2). Stages the resume path,
/// then writes SLP_EN. On a honored request the platform suspends inside this
/// call. CP2b-1 does not return on success (the trampoline halts in
/// s3ResumeEntry); on any failure it returns an errno so the shell survives.
pub fn suspendToRam() u32 {
    const s3 = acpi.getS3SleepTypes() orelse {
        serial.print("[s3] no \\_S3_ sleep codes — S3 unavailable\n", .{});
        return common.E_NOSYS;
    };
    const f = acpi.getFadt() orelse {
        serial.print("[s3] no FADT — S3 unavailable\n", .{});
        return common.E_NOSYS;
    };
    if (f.pm1a_cnt_blk == 0) {
        serial.print("[s3] PM1a_CNT_BLK is 0 — S3 unavailable\n", .{});
        return common.E_NOSYS;
    }
    const facs = acpi.getFacs() orelse {
        serial.print("[s3] no FACS — cannot set wake vector; S3 unavailable\n", .{});
        return common.E_NOSYS;
    };

    // Stage resume: low identity for the trampoline page, copy the trampoline +
    // slots, point the FACS wake vector at it (32-bit real-mode entry).
    const resume_cr3 = installLowIdentity() orelse {
        serial.print("[s3] could not install low identity — S3 aborted\n", .{});
        return common.E_NOSYS;
    };
    if (resume_cr3 >= 0x1_0000_0000) {
        serial.print("[s3] CR3 0x{x} >= 4 GiB — trampoline 32-bit CR3 load would truncate; S3 aborted\n", .{resume_cr3});
        return common.E_NOSYS;
    }
    installWakeTrampoline(resume_cr3);
    facs.firmware_waking_vector = WAKE_TRAMP_BASE;
    facs.x_firmware_waking_vector = 0; // force the 32-bit real-mode entry

    const word_a = sleepWord(s3.a);
    const word_b = sleepWord(s3.b);
    serial.print("[s3] suspending: wake_vector=0x{x} resume_cr3=0x{x}; PM1a_CNT port=0x{x} <- 0x{x}\n", .{ @as(u64, WAKE_TRAMP_BASE), resume_cr3, @as(u16, @truncate(f.pm1a_cnt_blk)), word_a });

    asm volatile ("cli");
    asm volatile ("wbinvd");
    io.outw(@truncate(f.pm1a_cnt_blk), word_a);
    if (f.pm1b_cnt_blk != 0) io.outw(@truncate(f.pm1b_cnt_blk), word_b);

    // Reached only if the platform ignored the sleep request.
    serial.print("[s3] SLP_EN write returned — platform did not suspend\n", .{});
    asm volatile ("sti");
    return common.E_BUSY;
}
