// S3 (suspend-to-RAM) suspend/resume.
//
// Entry (CP2a) writes SLP_TYP|SLP_EN to PM1a_CNT and the platform suspends.
// Resume (CP2b) is the hard half: on S3 wake the CPU comes back in 16-bit real
// mode with GDT/IDT/TR/MSRs/control-regs all reset, so the kernel cannot simply
// "return" from the SLP_EN write. The FACS firmware_waking_vector points at a
// real->long-mode trampoline (src/boot/wake_trampoline.asm, a near-copy of the
// proven AP bring-up trampoline) which re-enters 64-bit kernel code here.
//
// CP2b-2 (this step): full restore -> usable resume. s3ResumeEntry re-establishes
// the BSP CPU state (smp.reinitForS3Resume, mirroring apEntry) and longjmps back
// into suspendToRam, which returns 0 to the syscall so sysret lands the shutdown
// app back in userspace with the scheduler ticking again. Only the BSP comes
// back online (the APs are powered down by S3 and marked offline on resume —
// re-bringing them up, and any device/GPU re-init the display needs, are later
// steps).

const std = @import("std");
const acpi = @import("acpi.zig");
const paging = @import("../mm/paging.zig");
const io = @import("../io.zig");
const serial = @import("../debug/serial.zig");
const common = @import("../cpu/syscall/common.zig");
const smp = @import("../cpu/smp.zig");
const virtio_gpu = @import("../driver/virtio_gpu.zig");
const xhci = @import("../driver/xhci.zig");
const nvme = @import("../driver/nvme.zig");

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

// setjmp/longjmp buffer for the suspend -> resume hand-off. suspendToRam calls
// s3_save_context just before SLP_EN; the wake path (s3ResumeEntry, after the
// trampoline + smp.reinitForS3Resume) calls s3_longjmp to return into
// suspendToRam's resume branch as if s3_save_context had returned 1. Only
// callee-saved regs + rsp/rip/rflags survive the round trip — the resume branch
// must not rely on any caller-saved value computed before the suspend (it
// doesn't). Field order/offsets MUST match the asm in wake_trampoline.asm.
const JmpBuf = extern struct {
    rbx: u64 = 0,
    rbp: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    rsp: u64 = 0,
    rip: u64 = 0,
    rflags: u64 = 0,
};
extern fn s3_save_context(ctx: *JmpBuf) callconv(.c) usize;
extern fn s3_longjmp(ctx: *JmpBuf) callconv(.c) noreturn;
var s3_ctx: JmpBuf = .{};

// TSC value captured just before the SLP_EN write, restored first thing on
// resume. S3 powers the CPU down and the TSC comes back at ~0; the whole kernel
// measures elapsed time as `now -% start` deltas, so a backward TSC makes the
// very next delta enormous (the suspending syscall's own exit accounting ->
// apic.tscToMs(delta*10) overflows; the scheduler tick and the host-pause/SMI
// detector also break). Restoring continuity keeps every delta small + positive.
var saved_tsc: u64 = 0;

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

fn readTsc() u64 {
    var hi: u32 = undefined;
    var lo: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

/// Write IA32_TIME_STAMP_COUNTER (MSR 0x10). Under KVM this adjusts the guest
/// TSC offset; on real hardware it sets the counter directly.
fn writeTsc(val: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (@as(u32, 0x10)),
          [lo] "{eax}" (@as(u32, @truncate(val))),
          [hi] "{edx}" (@as(u32, @truncate(val >> 32))),
    );
}

/// Entry point the wake trampoline jumps to in 64-bit mode. Re-establishes the
/// BSP CPU state torn down by S3, then longjmps back into suspendToRam's resume
/// branch (never returns here).
export fn s3ResumeEntry() callconv(.c) noreturn {
    // Rawest possible breadcrumb FIRST: write straight to COM1 (0x3F8) before
    // touching any kernel infrastructure, so even if serial.print or per-CPU
    // (GS-based) state is unhappy this early post-resume, we still get proof the
    // trampoline reached 64-bit kernel code. QEMU's UART transmits a THR byte to
    // its backend regardless of line config. IF is 0 here (the trampoline cli'd).
    for ("\r\nS3WAKE\r\n") |c| io.outb(0x3F8, c);

    // Restore the TSC to its pre-suspend value FIRST: S3 reset it to ~0, and the
    // whole kernel measures elapsed time as `now -% start` deltas. A backward TSC
    // makes the next such delta enormous — the suspending syscall's own exit
    // accounting (apic.tscToMs(delta*10)) overflows, the scheduler tick freezes,
    // and the host-pause detector mis-fires. Must precede reinitForS3Resume (its
    // timer arm reads the TSC) and any scheduler/perf path.
    writeTsc(saved_tsc);

    // Re-establish the BSP's CPU state (GDT/IDT/TR, syscall MSRs, EFER.NXE,
    // CR0.WP, CR4, PAT, LAPIC + timer), mirroring AP bring-up. After this the
    // CPU is whole again and per-CPU / NX-page access are safe.
    smp.reinitForS3Resume();
    serial.print("[s3] RESUME: BSP CPU state re-established; longjmp -> suspendToRam\n", .{});

    // Hand control back to suspendToRam's resume branch (its s3_save_context call
    // appears to return 1 there). Never returns to this frame.
    s3_longjmp(&s3_ctx);
}

/// Undo installLowIdentity: restore the 0..2 MiB null-guard slot (PD[0] = 0) in
/// the current (post-resume) page tables so user null derefs fault again. Walks
/// the live CR3 rather than trusting a saved value. No-op if the tables aren't
/// shaped as installLowIdentity left them.
fn removeLowIdentity() void {
    const cr3 = readCr3();
    const pml4: [*]volatile u64 = @ptrFromInt(paging.physToVirt(cr3 & paging.PAGE_MASK));
    const pml4e = pml4[0];
    if (pml4e & paging.PRESENT == 0) return;
    const pdpt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pml4e & paging.PAGE_MASK));
    const pdpte = pdpt[0];
    if (pdpte & paging.PRESENT == 0) return;
    if (pdpte & paging.PAGE_SIZE_FLAG != 0) return;
    const pd: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pdpte & paging.PAGE_MASK));
    pd[0] = 0;
    // Flush the stale VA-0 translation: reload CR3 (the 2 MiB entry wasn't
    // GLOBAL, so a plain CR3 reload evicts it). Value-based reload so the
    // compiler picks the scratch reg; memory clobber pins it after the pd[0]
    // store.
    const cur = readCr3();
    asm volatile ("mov %[v], %%cr3"
        :
        : [v] "r" (cur),
        : .{ .memory = true });
}

/// Install a temporary 2 MiB identity page at VA 0 in the current (suspending)
/// process's page tables so phys 0x9000 stays mapped the instant the wake
/// trampoline turns paging on. The process already has PML4[0]->PDPT[0]->PD
/// present (its user image lives at 4 MiB = PD[2]); PD[0] (the 0..2 MiB null
/// guard) is empty, so we borrow it without disturbing user mappings. Returns
/// the CR3 to load on resume (PML4 phys with the low 12 bits stripped), or null
/// if the tables aren't shaped as expected.
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
    //
    // Return the BARE PML4 phys (low 12 bits masked off): at a syscall CR3 also
    // carries the process's PCID in bits [11:0] (e.g. 0x...004), but the resume
    // path re-enables CR4.PCIDE in reinitForS3Resume -> applyEarlyCr4, and the
    // CPU #GPs if PCIDE is set while CR3[11:0] != 0. The trampoline therefore
    // loads CR3 with PCID=0 (harmless: PCIDE is off at that point so the tag is
    // ignored, and the process re-acquires its PCID on the next context switch).
    return cr3 & paging.PAGE_MASK;
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
/// arms a setjmp, then writes SLP_EN; the platform suspends inside this call. On
/// S3 wake the trampoline -> s3ResumeEntry -> reinitForS3Resume -> s3_longjmp
/// re-enters here and this returns 0 (back to userspace via sysret). On any
/// staging failure, or if the platform ignores the request, it returns an errno
/// so the shell survives.
pub fn suspendToRam() u32 {
    // S3 resumes on the BSP only (the firmware waking vector brings up CPU 0), so
    // the context we save must belong to the BSP. If this syscall is running on
    // an AP, refuse rather than save a context we can't correctly resume.
    // (Migrating the caller onto the BSP first is a later refinement.)
    if (!smp.isBSP()) {
        serial.print("[s3] suspend syscall not on BSP — S3 needs the BSP; aborted\n", .{});
        return common.E_NOSYS;
    }

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

    // From here we mutate the resume staging (trampoline page + FACS wake vector)
    // and arm the setjmp. Disable interrupts so nothing runs between arming and
    // the SLP_EN write — and so the resume branch, reached via s3_longjmp
    // restoring THIS rflags, runs with IF=0 until it returns to the syscall
    // dispatcher (sysret restores the app's own IF on the way back to userspace).
    asm volatile ("cli");

    // Stage resume: low identity for the trampoline page, copy the trampoline +
    // slots, point the FACS wake vector at it (32-bit real-mode entry).
    const resume_cr3 = installLowIdentity() orelse {
        serial.print("[s3] could not install low identity — S3 aborted\n", .{});
        asm volatile ("sti");
        return common.E_NOSYS;
    };
    if (resume_cr3 >= 0x1_0000_0000) {
        serial.print("[s3] CR3 0x{x} >= 4 GiB — trampoline 32-bit CR3 load would truncate; S3 aborted\n", .{resume_cr3});
        asm volatile ("sti");
        return common.E_NOSYS;
    }
    installWakeTrampoline(resume_cr3);
    facs.firmware_waking_vector = WAKE_TRAMP_BASE;
    facs.x_firmware_waking_vector = 0; // force the 32-bit real-mode entry

    // setjmp: 0 = first pass (arm + suspend). On S3 wake the trampoline ->
    // s3ResumeEntry -> reinitForS3Resume -> s3_longjmp makes this "return" 1 and
    // execution falls through to the resume branch below.
    if (s3_save_context(&s3_ctx) == 0) {
        const word_a = sleepWord(s3.a);
        const word_b = sleepWord(s3.b);
        serial.print("[s3] suspending: wake_vector=0x{x} resume_cr3=0x{x}; PM1a_CNT port=0x{x} <- 0x{x}\n", .{ @as(u64, WAKE_TRAMP_BASE), resume_cr3, @as(u16, @truncate(f.pm1a_cnt_blk)), word_a });

        // Continuous-time baseline restored on resume (writeTsc in s3ResumeEntry).
        // Capture as late as possible so the restored TSC is closest to real time.
        saved_tsc = readTsc();
        asm volatile ("wbinvd");
        io.outw(@truncate(f.pm1a_cnt_blk), word_a);
        if (f.pm1b_cnt_blk != 0) io.outw(@truncate(f.pm1b_cnt_blk), word_b);

        // Reached only if the platform ignored the sleep request.
        serial.print("[s3] SLP_EN write returned — platform did not suspend\n", .{});
        asm volatile ("sti");
        return common.E_BUSY;
    }

    // ---- RESUME path (s3_longjmp landed here from s3ResumeEntry; IF=0) ----
    serial.print("[s3] resumed: back in suspendToRam via longjmp\n", .{});
    // S3 powered the APs down — only the BSP woke. Mark them offline first (a
    // clean single-CPU baseline that clears the stale `alive` flags), then
    // re-online them (CP2b-2b) so the machine comes back full-SMP. The re-online
    // INIT/SIPIs the APs through the trampoline at phys 0x8000, which is still
    // covered by the 2 MiB low-identity the suspend path installed in this CR3 —
    // so it MUST run before removeLowIdentity tears that mapping down. The APs
    // load this same resume CR3 (PCID stripped), exactly as the BSP's own wake
    // trampoline did. IF is still 0, so the whole bring-up is atomic w.r.t. the
    // watchdog/scheduler (no IRQ0 fires until we sysret back to userspace).
    smp.offlineApsForS3Resume();
    smp.reonlineApsForS3Resume(readCr3() & paging.PAGE_MASK);

    // Restore the 0..2 MiB null guard the suspend path borrowed for the
    // trampoline page (now that AP re-online is done with it).
    removeLowIdentity();

    // Disk first: the NVMe controllers (root fs + swap) were powered down by S3
    // like every other PCI device — BARs zeroed, controllers reset. Until they
    // are re-initialized, the first post-resume disk read (e.g. an app launch
    // loading its ELF) blocks forever on a dead controller and the desktop
    // appears frozen, even though the kernel keeps ticking. Re-init here (IF=0,
    // best-effort) ahead of the GPU/xHCI so storage is live before anything that
    // might touch it.
    if (nvme.resumeFromS3()) {
        serial.print("[s3] resumed: nvme re-initialized — disk I/O restored\n", .{});
    } else {
        serial.print("[s3] resumed: nvme re-init failed — disk I/O may hang\n", .{});
    }

    // Devices were powered down across S3. Bring the GPU back so the desktop
    // renders again. Runs here with IF=0 so it's atomic (no task can interleave
    // a half-initialized device) and uses the driver's polled submit path, which
    // needs no interrupts. Best-effort: a failure leaves the system running
    // headless (as it did before CP2c) rather than blocking the resume.
    if (virtio_gpu.resumeFromS3()) {
        serial.print("[s3] resumed: virtio-gpu re-initialized — display restored\n", .{});
    } else {
        serial.print("[s3] resumed: virtio-gpu re-init failed — staying headless\n", .{});
    }

    // USB keyboard + mouse hang off the xHCI controller, also powered down by
    // S3. Re-init it so input revives. Same IF=0 / best-effort contract.
    if (xhci.resumeFromS3()) {
        serial.print("[s3] resumed: xhci re-initialized — USB input restored\n", .{});
    } else {
        serial.print("[s3] resumed: xhci re-init failed — USB input stays dead\n", .{});
    }

    // The BSP's DR0-DR3/DR7 were reset by S3 like everything else, but
    // watch.zig's per-CPU applied-cache survived in RAM — without an explicit
    // invalidate+reapply every later applyLocal() cache-hits against the
    // pre-suspend value and the hardware watchpoints (kesp watchdog) stay
    // silently disarmed. The re-onlined APs do the same in apEntryS3Resume.
    @import("../debug/watch.zig").reapplyAfterDrReset();

    serial.print("[s3] resumed: APs re-onlined, devices + low identity restored — returning to userspace\n", .{});
    // return 0 -> sysShutdown -> syscall dispatcher -> sysret restores the app's
    // RFLAGS (IF=1) and lands it back in userspace; the LAPIC timer re-armed in
    // reinitForS3Resume drives the scheduler again from the next tick.
    return 0;
}
