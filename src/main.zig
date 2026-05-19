const std = @import("std");
const vga = @import("ui/vga.zig");
const gdt = @import("cpu/gdt.zig");
const idt = @import("cpu/idt.zig");
const pmm = @import("mm/pmm.zig");
const paging = @import("mm/paging.zig");
const heap = @import("mm/heap.zig");
const pit = @import("time/pit.zig");
const cli = @import("cli.zig");
const multiboot = @import("boot/multiboot.zig");
const boot_info_mod = @import("boot/boot_info.zig");
const serial = @import("debug/serial.zig");
const debug = @import("debug/debug.zig");
const kasan = @import("debug/kasan.zig");
// memcpy/memset/memmove/__zig_probe_stack — needed by the LLVM IR-pass
// KASAN pipeline (tools/kasan_pipeline.sh) which links manually with `ld`
// instead of going through `zig build-exe`. Regular `zig build` ignores
// these (compiler-rt provides the same symbols).
comptime {
    _ = @import("debug/kernel_builtins.zig");
}
const fat32 = @import("fs/fat32.zig");
const keyboard = @import("driver/keyboard.zig");
const xhci = @import("driver/xhci.zig");
const nic = @import("driver/nic.zig");

fn enableSSE() void {
    // In 64-bit long mode, SSE/SSE2 is always enabled by the CPU.
    // boot.asm already sets CR0/CR4 appropriately.
    // Verify the settings are correct.
    var cr0 = asm volatile ("mov %%cr0, %[ret]"
        : [ret] "=r" (-> u64),
    );
    cr0 &= ~@as(u64, 1 << 2); // clear EM
    cr0 |= 1 << 1; // set MP
    asm volatile ("mov %[val], %%cr0"
        :
        : [val] "r" (cr0),
    );
    var cr4 = asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
    cr4 |= (1 << 9) | (1 << 10); // OSFXSR + OSXMMEXCPT
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (cr4),
    );
}

fn testSSE2() void {
    // SSE2 is always available on x86_64, but log for confirmation
    var edx: u64 = undefined;
    asm volatile ("cpuid"
        : [edx] "={edx}" (edx),
        : [eax] "{eax}" (@as(u64, 1)),
        : .{ .ebx = true, .ecx = true });
    if (edx & (1 << 26) != 0) {
        serial.print("[sse2] CPUID reports SSE2 supported\n", .{});
    } else {
        serial.print("[sse2] CPUID says NO SSE2!\n", .{});
        return;
    }
    // Check CR0/CR4 state
    const cr0_val = asm volatile ("mov %%cr0, %[ret]"
        : [ret] "=r" (-> u64),
    );
    const cr4_val = asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
    serial.print("[sse2] CR0={X:0>16} CR4={X:0>16}\n", .{ cr0_val, cr4_val });
    serial.print("[sse2] CR0.EM={d} CR0.MP={d} CR4.OSFXSR={d} CR4.OSXMMEXCPT={d}\n", .{
        (cr0_val >> 2) & 1, (cr0_val >> 1) & 1,
        (cr4_val >> 9) & 1, (cr4_val >> 10) & 1,
    });
    // Try a simple SSE2 instruction
    asm volatile (
        \\ xorps %%xmm0, %%xmm0
        ::: .{ .xmm0 = true });
    serial.print("[sse2] xorps xmm0 OK!\n", .{});
}

export fn kmain(magic: u64, info: *multiboot.MultibootInfo) noreturn {
    serial.init();
    serial.print("[boot] Multiboot entry\n", .{});

    // ---- (DR0 watchpoint removed — superseded by MMU page-watch armed
    // later, after symbols load. Under TCG, DR0+BS double-firing on the
    // count++ inc caused a #DB recursion at the handler entry that didn't
    // happen under KVM but completely wedged TCG. The MMU watch covers
    // the same target page and doesn't have this problem.)

    enableSSE();
    testSSE2();

    vga.clear();
    if (magic != 0x2BADB002) @panic("Bootloader error!");

    const boot_info = boot_info_mod.fromMultiboot(info);
    kernelMain(&boot_info);
}

/// UEFI entry point — called by the UEFI bootloader after ExitBootServices.
export fn kmain_uefi(boot_info: *const boot_info_mod.BootInfo) callconv(.c) noreturn {
    serial.init();
    serial.print("[boot] UEFI entry\n", .{});
    boot_info_mod.is_uefi = true;
    enableSSE();
    vga.available = false;
    // Stash the RuntimeServices pointer so we can flip LastBootStatus
    // back to `success` (or `crashed`) before/after kernelMain runs.
    @import("boot/uefi_nvram.zig").init(boot_info);
    kernelMain(boot_info);
}

fn kernelMain(boot_info: *const boot_info_mod.BootInfo) noreturn {
    // Capture boot mode picked by the UEFI menu (always 0 on Multiboot).
    // Read by smp.init() and other gated paths.
    boot_info_mod.boot_mode = boot_info.boot_mode;
    serial.print("[boot] mode = {d} (0=normal, 1=verbose, 2=safe)\n", .{boot_info.boot_mode});

    // Phase 4: cross-check bootloader's build_id against ours. They came
    // from the same `zig build` if everything went right; divergence means
    // BOOTX64.efi or kernel.elf is stale on disk. We klog loudly but
    // don't halt — running stale-by-mistake is better than stuck-by-rule.
    {
        const my_build_id = @import("build_options").build_id;
        if (boot_info.bootloader_build_id != 0 and boot_info.bootloader_build_id != my_build_id) {
            serial.print("[boot] !!! BUILD ID MISMATCH !!!\n", .{});
            serial.print("[boot]   bootloader build_id = 0x{X:0>16}\n", .{boot_info.bootloader_build_id});
            serial.print("[boot]   kernel build_id     = 0x{X:0>16}\n", .{my_build_id});
            serial.print("[boot]   one of BOOTX64.efi or kernel.elf is stale on disk\n", .{});
        } else if (boot_info.bootloader_build_id != 0) {
            serial.print("[boot] bootloader build_id = 0x{X:0>16} (matches kernel)\n", .{boot_info.bootloader_build_id});
        }
    }

    // Phase 3: cmdline plumbing. UEFI path: comes from NVRAM `ZigOSCmdline`.
    // Multiboot path: empty. cmdline.find/value drives runtime config that
    // would otherwise need a recompile.
    @import("boot/cmdline.zig").init(boot_info);
    if (boot_info.cmdline_len > 0) {
        serial.print("[boot] cmdline=\"{s}\"\n", .{boot_info.cmdline[0..boot_info.cmdline_len]});
    }

    // Verbose mode: dump boot_info contents up front so we can see exactly
    // what the bootloader handed us. Useful for diagnosing UEFI/Multiboot
    // handoff mismatches without pulling out gdb.
    if (boot_info.boot_mode == 1) {
        serial.print("[boot/verbose] BootInfo dump:\n", .{});
        serial.print("[boot/verbose]   memory_map_count = {d}\n", .{boot_info.memory_map_count});
        serial.print("[boot/verbose]   has_framebuffer = {d}\n", .{boot_info.has_framebuffer});
        serial.print("[boot/verbose]   fb base=0x{x} {d}x{d} stride={d} fmt={d}\n", .{
            boot_info.framebuffer.base,
            boot_info.framebuffer.width,
            boot_info.framebuffer.height,
            boot_info.framebuffer.stride,
            boot_info.framebuffer.format,
        });
        serial.print("[boot/verbose]   pml4_phys = 0x{x}\n", .{boot_info.pml4_phys});
        serial.print("[boot/verbose]   rsdp_addr = 0x{x}\n", .{boot_info.rsdp_addr});
        var i: u32 = 0;
        while (i < boot_info.memory_map_count and i < 16) : (i += 1) {
            const r = boot_info.memory_map[i];
            serial.print("[boot/verbose]   mmap[{d}] base=0x{x} len=0x{x} kind={d}\n", .{ i, r.base, r.length, r.kind });
        }
        if (boot_info.memory_map_count > 16) {
            serial.print("[boot/verbose]   ... ({d} more entries)\n", .{boot_info.memory_map_count - 16});
        }
    }

    // Bring up an early framebuffer FIRST so the boot screen can render
    // graphically from Phase 1 onwards. Two paths inside early_fb.init:
    //   - UEFI: adopts the GOP framebuffer the bootloader already set up.
    //   - Multiboot: probes BGA via the Bochs VGA Adapter (works in
    //     QEMU's virtio-vga-gl compat layer and standard VGA devices).
    // boot.asm's 4 GB identity map covers BGA's BAR0 and OVMF's GOP FB
    // (when < 4 GB) — `paging.mapMMIO` is a no-op here because paging.init
    // hasn't run yet, but the writes still land via the boot identity map.
    // If neither path succeeds, boot_screen falls back to VGA text mode.
    _ = @import("ui/early_fb.zig").init(boot_info);

    const blog = @import("debug/boot_log.zig");
    blog.banner();
    blog.setTotalPhases(6);

    // ---- Phase 1: CPU bring-up -------------------------------------------
    blog.phase(.cpu, "\u{2699}", "CPU bring-up"); // ⚙
    // Verify required CPU features (FPU/TSC/MSR/APIC/CMOV/PAT/SSE2). Refuses
    // to boot with a clear message if any are missing, instead of GP-faulting
    // mute deep inside paging/syscall init. All x86_64 CPUs have these per
    // AMD64 spec, but a malformed `-cpu` model in a VM could omit one.
    @import("cpu/cpuid_info.zig").requireFeatures();
    blog.ok("CPU features verified");
    // Clear sticky NMI status latches in port 0x61 (legacy "system control").
    // BIOSes occasionally leave parity / I/O-check NMI status set; a thermal
    // NMI on a hot real-HW CPU can fire 30 min after boot if these aren't
    // cleared. Bits 2,3 are the mask bits (write 1 to disarm); bits 6,7 are
    // sticky status. The toggle clears status without permanently disabling
    // checks.
    {
        const io = @import("io.zig");
        const sys_ctrl = io.inb(0x61);
        io.outb(0x61, (sys_ctrl & 0x0F) | 0x0C); // raise mask bits → clear sticky
        io.outb(0x61, sys_ctrl & 0xF3); // restore, leaving checks armed
    }
    gdt.init();
    blog.ok("GDT loaded");
    if (keyboard.initPS2()) {
        blog.ok("PS/2 keyboard");
    } else {
        blog.skip("PS/2 keyboard", "USB-only system", .{});
    }
    idt.init();
    blog.ok("IDT installed");
    @import("debug/lbr.zig").enable();
    blog.ok("LBR enabled");
    @import("cpu/syscall_entry.zig").init();
    @import("cpu/syscall_entry.zig").verifyMsrs("BSP");
    blog.ok("Syscall/sysret MSRs");
    // SMEP/UMIP — safe to enable on BSP now. SMAP is deferred until
    // desktop.taskEntry has dropped the low-half identity map, because
    // the UEFI boot stack lives at low-VA with the USER bit set and
    // enabling SMAP here #PFs on the next push.
    @import("cpu/protect.zig").detectFeatures();
    @import("cpu/protect.zig").applyEarlyCr4();
    blog.ok("SMEP/UMIP (SMAP deferred to post-PML4[0] drop)");
    // Machine Check Exception: probe MCG_CAP, enable all banks, set
    // CR4.MCE so vector 18 actually delivers. Per-CPU init for APs lives
    // in smp.apEntry. Must run after detectFeatures (shares the cpuid
    // helper) and before any code that could fault on an MC bank state.
    @import("cpu/mce.zig").detect();
    blog.ok("MCE banks enabled");
    // MWAIT/MONITOR: detect support so kernelIdle can swap `sti; hlt`
    // for `sti; monitor; mwait` (faster IPI wake + deeper C-states).
    // No CR bits to flip — the instructions are gated purely on CPUID.
    @import("cpu/mwait.zig").detect();
    blog.ok("MWAIT/MONITOR detected");
    // PMU (Performance Monitoring Unit) — sets up PMC0 for cycles, PMI
    // routed via LAPIC LVT.PMI to vector 0xFE. Sampling profiler can be
    // armed from the kernel via pmu.start(...) at any later point.
    @import("cpu/pmu.zig").detect();
    blog.ok("PMU detected");
    // Capture the FPU/SSE "init" state used to seed every new process. Must
    // run after enableSSE() (CR0/CR4 already set) and before process.create()
    // can be called.
    @import("cpu/fp.zig").captureInitTemplate();
    blog.ok("FPU/SSE init template");
    // GDB stub on COM2 (remote debug via QEMU TCP serial)
    @import("debug/gdb_stub.zig").init();
    blog.ok("GDB stub on COM2");
    // Verify runtime kernel image doesn't intrude into static region map.
    @import("mm/memmap.zig").assertKernelImageFits();

    // ---- Phase 2: Memory & paging ----------------------------------------
    blog.phase(.memory, "\u{25A3}", "Memory & paging"); // ▣
    pmm.init(boot_info);
    blog.okNote("Physical memory manager", "{d} MB free", .{pmm.freeFrameCount() * 4 / 1024});
    paging.init(boot_info);
    blog.ok("4-level paging");
    // PAT slot 4 = WC. Required on real HW so the GOP framebuffer doesn't
    // get UC-mapped (which drops desktop draws to ~10 fps). No-op on QEMU+KVM
    // where MTRR coercion already gives us a sensible memory type.
    paging.setupPat();
    blog.ok("PAT (PA4=WC)");
    if (boot_info.has_framebuffer != 0 and boot_info.framebuffer.base != 0) {
        const fb = boot_info.framebuffer;
        const fb_size: u64 = @as(u64, fb.stride) * @as(u64, fb.height) * 4;
        paging.setRangeWriteCombining(fb.base, fb_size);
        blog.okNote("Framebuffer WC", "phys 0x{X} size {d} KB", .{ fb.base, fb_size / 1024 });
    }
    heap.init();
    blog.ok("Kernel heap");
    kasan.init();
    blog.ok("KASAN shadow");
    @import("mm/vmalloc.zig").init();
    blog.ok("vmalloc arena");
    @import("debug/symbols.zig").init();
    @import("debug/kcsan.zig").init();
    blog.ok("KCSAN runtime");
    @import("proc/process.zig").initKstackGuards();
    blog.ok("Kstack guard pages");
    {
        const config = @import("config.zig");
        const proc = @import("proc/process.zig");
        kasan.installKstackRedZones(
            @intFromPtr(&proc.kstack_pool[0]),
            config.MAX_PROCS,
            config.KSTACK_SLOT_SIZE,
            config.KSTACK_SIZE,
        );
        blog.ok("Kstack KASAN red zones");
    }

    // Multiboot path: with PMM + paging + heap up, we can finally bring
    // virtio-gpu online and upgrade the boot screen to graphical mode.
    // (UEFI already had GOP from kernelMain's first instruction via
    // early_fb.init.) BGA on virtio-vga-gl doesn't actually scan out,
    // so this is the only way to get a real graphical boot screen on
    // QEMU's `-kernel` path.
    if (@import("ui/early_fb.zig").tryVirtioGpu()) {
        @import("ui/boot_screen.zig").upgradeToGraphical();
    }

    // ---- Phase 3: Time & SMP ---------------------------------------------
    blog.phase(.time_smp, "\u{231A}", "Time & SMP"); // ⌚
    pit.init();
    blog.ok("PIT calibrated");
    // ACPI: parse RSDP/XSDT and cache FADT/MADT/HPET/MCFG. Must run before
    // APIC, HPET, SMP, PCI ECAM.
    @import("time/acpi.zig").init(boot_info.rsdp_addr);
    blog.ok("ACPI tables parsed");
    // Pure observability: dump CPU vendor/family/model/stepping/microcode/
    // LAPIC IDs to serial. These are the data points needed first the time
    // something feels off on real HW. No-op for QEMU + KVM (always identical).
    @import("cpu/cpuid_info.zig").dumpCpuInfo();
    @import("cpu/cpuid_info.zig").dumpMtrrs();
    // PCI ECAM — uses MCFG if present.
    @import("driver/pci.zig").applyAcpi();
    blog.ok("PCI configuration");
    // One-shot bus walk → device cache. Drivers below use the cache
    // instead of re-walking the bus per init() call.
    @import("driver/pci.zig").enumerate();
    blog.ok("PCI bus enumeration");
    // IOMMU (Intel VT-d) — pass-through phase. Programs every PCI
    // device's context entry as Translation-Type=pass-through so the
    // IOMMU is on but DMA addresses are 1:1. Buys us fault-recording
    // for off-the-rails DMA without changing driver semantics. No-op
    // when no DMAR table is present (no -device intel-iommu in QEMU,
    // or BIOS-mode boot on real hardware).
    @import("cpu/iommu.zig").init();
    blog.ok("IOMMU (VT-d pass-through)");
    // SMI / scheduler stall detector. Reads FADT.pm_tmr_blk for sampling.
    // Has to come after acpi.init (FADT cached) but before apic.init starts
    // the BSP IRQ0 — IRQ0's first tick will sample PM_TMR for baseline.
    @import("time/smi.zig").init();
    // HPET — high-precision monotonic clock. Brought up BEFORE APIC so
    // apic.calibrateTimer() can use it as the calibration reference (PIT
    // Channel 2 is disabled in firmware on some modern UEFI laptops, where
    // PIT-based calibration would silently produce tsc_per_quantum=0).
    @import("time/hpet.zig").init();
    blog.ok("HPET");
    // Hyper-V enlightenment detection. When QEMU exposes the frequency
    // MSRs (`-cpu host,hv-frequencies`) apic.calibrateTimer() reads them
    // directly instead of running the 10 ms HPET gate. enableHypercalls()
    // installs the hypercall thunk page so tlb.shootdownAll can issue
    // HvCallFlushVirtualAddressSpace instead of IPI fan-out.
    @import("virt/hyperv.zig").detect();
    @import("virt/hyperv.zig").enableHypercalls();
    if (@import("time/apic.zig").init()) {
        blog.ok("Local APIC + IOAPIC");
    } else {
        blog.warn("Local APIC + IOAPIC", "falling back to legacy PIC+PIT", .{});
    }
    // IOMMU fault MSI — couldn't be armed during iommu.init() because the
    // LAPIC wasn't running yet. Now that it is, hardware can deliver
    // fault-event MSIs to our IDT vector instead of accumulating silently
    // in FSTS/FRR.
    @import("cpu/iommu.zig").armFaultMsi();
    // Wall-clock time: latch boot epoch from RTC + HPET.
    @import("time/time.zig").init();
    blog.ok("Wall-clock epoch");
    // SMP: boot additional CPUs
    @import("cpu/smp.zig").init();
    blog.ok("SMP (additional CPUs)");
    // Static aliasing audit: assert no two alive CPUs share idle_pid /
    // current_pid / tss.rsp0 right at the end of SMP init. If they do,
    // the per-CPU bring-up itself is buggy and we'd rather panic with
    // the colliding pair named than diagnose a wild dispatch in some
    // downstream driver init.
    @import("debug/cpu_alias.zig").checkAtBoot();
    blog.ok("Cross-CPU alias audit");
    // DR-watchpoint cross-CPU sync via IPI — must come AFTER smp.init()
    // (so cpu.alive[] is populated) and BEFORE any arm() that needs cross-CPU
    // semantics. See project_iretq_race_ipi_fix.md.
    @import("debug/watch.zig").initIpi();
    blog.ok("DR-sync IPI vector");
    @import("proc/process.zig").initKillKickIpi();
    blog.ok("Kill-kick IPI vector");
    @import("proc/process.zig").initWakeIpi();
    blog.ok("Wake-only IPI vector");
    // Cross-CPU hang detector. Each CPU watches the next; if a peer's
    // IRQ0 tick stops advancing for ~3s, broadcast NMI + autopsy. Arm
    // AFTER smp.init() so cpu.alive[] is populated.
    @import("debug/watchdog.zig").arm();
    blog.ok("Hang watchdog");
    // C.1 supersedes the iretq RIP watchpoints — uses the same DR0-DR3 slots
    // for rotating kernel_esp watch (per-PCB write detection), driven by
    // handleIRQ0 every KESP_REROTATE_TICKS. The smoking gun for the wild-RIP
    // hunt now points at procs[].kernel_esp corruption (cross-stack aliasing),
    // not iretq frame RIP — covering kernel_esp directly catches the writer.
    // To re-enable iretq RIP coverage, swap this back; can't run both since
    // they share DR slots.
    // @import("debug/iretq_canary.zig").armPermanentWatchpoints();
    blog.ok("kernel_esp rotation watchpoints (C.1, via timer)");

    // ---- Phase 4: Storage & filesystems ----------------------------------
    blog.phase(.storage, "\u{25A4}", "Storage & filesystems"); // ▤
    @import("driver/block.zig").init();
    blog.ok("Block layer (NVMe/AHCI/IDE)");
    fat32.init();
    blog.ok("FAT32");
    @import("fs/tarfs.zig").buildIndex();
    blog.ok("TARFS index");
    // ext2 try-mount: silently fails if IDE2 isn't an ext2 image (the
    // common case during dev where IDE2 is FAT32). Swap disk.img →
    // ext2.img in the QEMU args to test ext2.
    if (@import("fs/ext2/ext2.zig").init()) blog.ok("ext2 (IDE2)");
    verifyBuildId();
    blog.ok("Build-ID stamp");
    @import("debug/symbols.zig").loadKernelSymbols();
    blog.ok("Kernel symbols loaded");
    @import("debug/dwarf_line.zig").init();
    blog.ok("Kernel line table loaded");

    // ---- Phase 5: Lockdown -----------------------------------------------
    blog.phase(.lockdown, "\u{2295}", "Lockdown"); // ⊕
    paging.enableCR0WriteProtect();
    blog.ok("CR0.WP (RO supervisor)");
    paging.protectKdataInit();
    blog.ok(".kdata_protected R/O");
    asm volatile ("sti");
    // virtio-gpu's sendCmd can now switch from polling to sti+hlt for
    // MSI-X completions — LAPIC is enabled (apic.init in Phase 3), IDT is
    // installed, and IF is now globally on. See msix_safe_to_use comment.
    @import("driver/virtio_gpu.zig").msix_safe_to_use = true;
    blog.ok("Interrupts enabled");
    @import("debug/abi_check.zig").runBootTests();
    blog.ok("ABI self-tests");

    // ---- Phase 6: Hardware probe -----------------------------------------
    blog.phase(.hardware, "\u{26A1}", "Hardware probe"); // ⚡
    const xhci_up = xhci.init();
    if (xhci_up) {
        blog.ok("xHCI USB 3.0");
    } else {
        blog.skip("xHCI USB 3.0", "controller not present", .{});
    }
    // Sanity check the input path. On real-HW USB-only systems where xhci
    // came up but enumerated no HID devices (BIOS quirk, controller errata,
    // or a Bluetooth-only built-in keyboard which we can't drive yet),
    // the desktop will boot but you can't interact with it. Warn loudly.
    if (!keyboard.ps2_present and (!xhci_up or !xhci.hasUsbKeyboard())) {
        blog.skip("Input devices", "no PS/2 nor USB HID keyboard found", .{});
        serial.print("[boot] WARNING: no keyboard input source detected — system will boot but won't be interactive.\n", .{});
    }
    // If a USB keyboard came up alongside PS/2, drop PS/2 IRQ1 — QEMU's
    // i8042 emulation otherwise spuriously asserts IRQ1 at ~2200/sec on
    // an idle guest, costing ~4 % of one CPU in handleIRQ1 + EOI for
    // no input. USB is the real input path; PS/2 is dead weight.
    if (keyboard.ps2_present and xhci_up and xhci.hasUsbKeyboard()) {
        keyboard.disableIRQ1();
    }
    if (nic.init()) {
        blog.ok("Network interface");
        // Acquire a DHCP lease so we don't depend on the QEMU-SLIRP-only
        // hardcoded IP/gateway/DNS triple. Total deadline is 5s (500 ticks
        // @ 100 Hz) split across up to 3 DISCOVER attempts. Failure is
        // soft: we fall back to the static SLIRP defaults still set in
        // src/net/net.zig so QEMU SLIRP keeps working.
        const dhcp = @import("net/dhcp.zig");
        const net = @import("net/net.zig");
        const proc = @import("proc/process.zig");
        if (dhcp.acquire(proc.tick_count + 500)) {
            blog.okNote("DHCP lease", "{d}.{d}.{d}.{d} via {d}.{d}.{d}.{d}", .{
                net.local_ip[0], net.local_ip[1], net.local_ip[2], net.local_ip[3],
                net.gateway_ip[0], net.gateway_ip[1], net.gateway_ip[2], net.gateway_ip[3],
            });
        } else {
            blog.skip("DHCP lease", "no server reply, using static SLIRP defaults", .{});
        }
    } else {
        blog.skip("Network interface", "no NIC found", .{});
    }
    @import("driver/sound.zig").init();
    blog.ok("Sound");

    // TLS step-1 spike: confirm std.crypto.{Sha256, ChaCha20Poly1305, X25519}
    // compile and execute freestanding in the kernel. If this fails to
    // build, the "hand-roll TLS on std.crypto primitives" plan is dead and
    // we'd pivot to vendoring BearSSL. Output goes through klog → serial,
    // not the boot panel — it's a one-shot diagnostic, not a routine boot
    // step. Remove this call once TLS infrastructure is wired in for real.
    @import("crypto/spike.zig").run();

    // Mozilla NSS root CA bundle — decode all 150-ish trust anchors at
    // boot so the TLS chain walker can resolve issuer DNs at handshake
    // time. Done once; idempotent if called again.
    @import("crypto/tls/trust_store.zig").init();

    // TLS step-2 probe: send a real ClientHello to 1.1.1.1:443, parse the
    // ServerHello, derive the X25519 shared secret. Validates our message
    // construction + parser against a real TLS 1.3 server's response.
    // Needs networking; gated on NIC presence (DHCP already ran above).
    if (nic.isReady()) {
        @import("crypto/tls/probe.zig").run();
    } else {
        @import("debug/debug.zig").klog("[tls] skipping probe — no NIC\n", .{});
    }

    blog.done("Boot complete -- {d} MB RAM free, {d} CPUs online", .{
        pmm.freeFrameCount() * 4 / 1024,
        @import("cpu/smp.zig").aliveCpuCount(),
    });

    // Audit the kernel's page-table mapping granularity. Surfaces TLB
    // working-set size and detects over-splitting (every 2 MB or 4 KB
    // page = extra TLB pressure). Healthy baseline: a couple of 1 GB
    // entries, a handful of 2 MB, double-digit 4 KB. Order: run AFTER
    // guard pages + kdata RO + write-watches so all splits are visible.
    @import("mm/paging.zig").dumpKernelMappingStats();

    // Hold the finished boot panel for ~1.2 s so the user can actually see
    // the all-OK state before desktop wipes the framebuffer with its splash.
    // No-op in VGA text mode — only matters in graphical mode where the
    // pretty layout is brief otherwise.
    @import("ui/boot_screen.zig").holdMinimum(1200);

    // Boot complete — record success in BOTH the ring (canonical) and the
    // legacy singleton (so the bootloader's pre-ring fallback path still
    // works). The ring stamps `kernel_build_id` so the next boot's About
    // screen can flag bootloader/kernel build skew. No-op on Multiboot
    // path; uefi_nvram.init bailed if there's no RuntimeServices.
    {
        const nvram = @import("boot/uefi_nvram.zig");
        const bo = @import("build_options");
        nvram.historyMarkCurrent(nvram.STATUS_SUCCESS, bo.build_id, &.{});
        nvram.setBootStatus(nvram.STATUS_SUCCESS);
    }

    // Convert from kmain bootstrap context to a real kernel task (task #235).
    // The desktop becomes a PCB with its own kstack; kmain's stack is
    // abandoned. From this point every CPU always has a current task —
    // no more "scheduler context" failure modes. enterFirstTask creates
    // the BSP idle + first kernel task and switchTo's into it; never returns.
    //
    // boot_mode dispatch:
    //   0/1/2  → desktop (Normal / Verbose / Safe; SMP/IO mode is gated upstream)
    //   3      → stress test (replaces desktop with kstack-churn loop; see
    //            src/test/stress_kstack.zig — used to repro task #267 KASAN UAF)
    //   4      → stress test (ring-3 spinners + kernel-task churn; see
    //            src/test/stress_iretq.zig — hunts the cross-CPU iretq frame
    //            race documented in project_iretq_race_ipi_fix.md)
    const desktop_mod = @import("ui/desktop.zig");
    // Read from the module global (set in line 118) rather than the
    // function-parameter pointer. The boot_info struct lives in a
    // UEFI-allocated frame whose ownership transfers to PMM at init; later
    // allocations clobber it, which is why `boot_info.boot_mode` reads as
    // 0 here despite the early-kmain log showing the right value. Closes
    // project_mode5_dispatch_mystery.md.
    const live_mode = boot_info_mod.boot_mode;
    const entry: usize = switch (live_mode) {
        3 => @intFromPtr(&@import("test/stress_kstack.zig").taskEntry),
        4 => @intFromPtr(&@import("test/stress_iretq.zig").taskEntry),
        5 => @intFromPtr(&@import("test/stress_phase3.zig").taskEntry),
        6 => @intFromPtr(&@import("test/stress_kill_race.zig").taskEntry),
        7 => @intFromPtr(&@import("test/panic_test.zig").taskEntry),
        8 => @intFromPtr(&@import("test/stress_async_exec.zig").taskEntry),
        10 => @intFromPtr(&@import("test/stress_wake_ipi.zig").taskEntry),
        11 => @intFromPtr(&@import("test/stress_io_chain.zig").taskEntry),
        // Mode 9 (GPU compositor) boots the regular desktop; the desktop
        // detects boot_mode==9 and spawns ui/gpu_compositor.zig as a
        // side-by-side kernel task so they share one screen.
        else => @intFromPtr(&desktop_mod.taskEntry),
    };
    debug.klog("[boot] boot_mode={d} (param={d}) entry=0x{X:0>16}\n", .{ live_mode, boot_info.boot_mode, entry });
    @import("proc/process.zig").enterFirstTask(entry);
}

pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    asm volatile ("cli");
    // Publish crash to Hyper-V crash MSRs FIRST — five wrmsrs, no allocations,
    // no locks. On real Hyper-V the host surfaces these as a BugCheck entry
    // in Event Viewer (source: "Hyper-V-Hypervisor"), so the crash is
    // readable post-mortem even if our own NVRAM write or serial print dies
    // mid-autopsy. No-op when crash MSRs aren't exposed.
    {
        const hyperv = @import("virt/hyperv.zig");
        const ret_u64: u64 = if (ret_addr) |a| @intCast(a) else 0;
        const rsp_u64 = asm volatile ("movq %%rsp, %[ret]"
            : [ret] "=r" (-> u64),
        );
        // P0 = sentinel marking "ZigOS @panic" (low 32 = bug code).
        // P1 = ret_addr (panic origin). P2 = rsp. P3/P4 = first/second
        // 8 bytes of the panic message, LE-packed.
        hyperv.writeCrash(0x5A49474F_53504E43, ret_u64, rsp_u64, hyperv.packMsg(msg, 0), hyperv.packMsg(msg, 8));
    }
    // Persist crash to NVRAM FIRST — before anything that might double-fault
    // (serial print can spuriously fail if the IO port state is corrupt;
    // VGA might be detached; the autopsy walks page tables). The earlier
    // we flip LastBootStatus = crashed, the more reliable the
    // crash-recovery hint on the next boot's menu becomes.
    {
        const nvram = @import("boot/uefi_nvram.zig");
        const bo = @import("build_options");
        // Cap msg to 240 bytes so there's room for the prefix and we stay
        // under the 256-byte NVRAM cap that uefi_nvram.setCrashFp enforces.
        var buf: [256]u8 = undefined;
        const prefix = "@panic: ";
        const msg_room = buf.len -| prefix.len;
        const msg_len = @min(msg.len, msg_room);
        @memcpy(buf[0..prefix.len], prefix);
        @memcpy(buf[prefix.len..][0..msg_len], msg[0..msg_len]);
        const fp = buf[0 .. prefix.len + msg_len];
        // Write to the ring first (canonical), then the legacy singletons
        // so the bootloader's pre-ring fallback also sees the crash.
        nvram.historyMarkCurrent(nvram.STATUS_CRASHED, bo.build_id, fp);
        nvram.setBootStatus(nvram.STATUS_CRASHED);
        nvram.setCrashFp(fp);
    }

    // Enter the panic critical section — idempotent per-CPU (handles the
    // common chain iretq_canary.report → @panic → main.panic where each
    // step would otherwise re-acquire). Other CPUs spin-wait or steal
    // after timeout. Output stays per-CPU sequential, not byte-interleaved.
    @import("debug/kdbg.zig").enterCritical();

    // Halt peers FIRST, before any serial output. Without this, the
    // panic banner / crashSummary / backtrace below byte-interleave with
    // whatever peer CPUs were klog'ing (slow-sc traces, perf dumps,
    // heartbeats) and the autopsy log is illegible at the moment we
    // need it most. broadcastNMI waits ~50 ms for peer snapshots to
    // land and halt; after it returns we have exclusive serial access.
    // Each peer still prints its own [nmi-snap cpuN] line before halting
    // so we don't lose the "what was the other CPU doing" signal.
    @import("debug/kdbg.zig").nmi_halt_after_snapshot = true;
    @import("debug/kdbg.zig").broadcastNMI();

    serial.print("\n!!! KERNEL PANIC !!!\n", .{});

    // Snapshot RSP for the stack-overflow heuristic in classifyCrash before
    // serial.print scribbles registers.
    const rsp = asm volatile ("movq %%rsp, %[ret]"
        : [ret] "=r" (-> u64),
    );

    // TL;DR + greppable [crash-fp] line — same path as a true exception,
    // just with int_no=255 (sentinel for @panic).
    @import("debug/kdbg.zig").crashSummary(.{
        .int_no = 255,
        .crash_rip = if (ret_addr) |a| @intCast(a) else null,
        .kernel_rsp = rsp,
        .msg = msg,
    });

    const sym = @import("debug/symbols.zig");

    // Control registers
    const cr3 = asm volatile ("movq %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );
    serial.print("  CR3=0x{X:0>16}\n", .{cr3});

    // Full backtrace with symbol resolution. Stop on any sign of stack
    // corruption: misaligned rbp, out-of-range, non-monotonic. Without
    // these guards an `@ptrFromInt(rbp)` on a corrupted rbp triggers
    // incorrectAlignment → recursive panic loop, hiding the real cause.
    //
    // Phase 3 layout: rbp is on a kstack which lives in either the
    // kernel-image .bss (kstack_pool) at 0xFFFFFFFF80... or the physmap
    // window (heap-allocated kstacks for kernel tasks) at
    // 0xFFFF800000... — both are in the canonical-high-half range. Reject
    // anything that's not in the kernel half OR not in the legacy boot
    // stack range (the boot stack is dead post-enterFirstTask but @panic
    // can still fire during early init from the boot stack at low phys).
    serial.print("  Backtrace:\n", .{});
    var rbp = asm volatile ("movq %%rbp, %[ret]"
        : [ret] "=r" (-> usize),
    );
    var depth: u32 = 0;
    while (depth < 16) : (depth += 1) {
        const in_low_boot = rbp >= 0x100000 and rbp < 0x4000000;
        const in_kernel_half = rbp >= 0xFFFF_8000_0000_0000;
        if (!in_low_boot and !in_kernel_half) break;
        if ((rbp & 7) != 0) {
            serial.print("    [{d}] (stop: rbp=0x{X:0>16} misaligned)\n", .{ depth, rbp });
            break;
        }
        const frame: [*]const usize = @ptrFromInt(rbp);
        const addr: u64 = @intCast(frame[1]);
        const dwarf = @import("debug/dwarf_line.zig");
        if (sym.resolveKernel(addr)) |r| {
            if (dwarf.lookup(addr)) |loc| {
                serial.print("    [{d}] {s}+0x{X} at {s}:{d} (0x{X:0>16})\n", .{ depth, r.name, r.offset, loc.file, loc.line, addr });
            } else {
                serial.print("    [{d}] {s}+0x{X} (0x{X:0>16})\n", .{ depth, r.name, r.offset, addr });
            }
        } else if (sym.resolveKernelNearest(addr)) |r| {
            if (r.offset < 0x4000) {
                if (dwarf.lookup(addr)) |loc| {
                    serial.print("    [{d}] (near {s}+0x{X}) at {s}:{d} (0x{X:0>16})\n", .{ depth, r.name, r.offset, loc.file, loc.line, addr });
                } else {
                    serial.print("    [{d}] (near {s}+0x{X}) (0x{X:0>16})\n", .{ depth, r.name, r.offset, addr });
                }
            } else {
                serial.print("    [{d}] 0x{X:0>16}\n", .{ depth, addr });
            }
        } else {
            serial.print("    [{d}] 0x{X:0>16}\n", .{ depth, addr });
        }
        const next = frame[0];
        if (next <= rbp) break; // non-monotonic — stack walked past end
        rbp = next;
    }

    // (NMI broadcast moved up — peers halted before any serial output so
    // the autopsy log isn't byte-interleaved.)

    // Dump every registered lock with holder + return-address. Catches
    // the "wedge because X held the lock and slept" class of bugs that
    // the wedged-CPU snapshot alone doesn't reveal.
    @import("proc/spinlock.zig").dumpAllLocks();

    // Per-PID syscall ring of whatever was running on this CPU. Last
    // 8 syscalls leading up to the panic — often points right at the
    // class of operation that triggered the fault (heavy fread loop,
    // mid-fork, etc.).
    {
        const process = @import("proc/process.zig");
        const cpu = @import("cpu/smp.zig").myCpu();
        if (cpu.current_pid) |cur| {
            process.dumpSyscallRing(@intCast(cur));
        }
    }

    // Slab cache forensics — which subsystems were live at crash time.
    // No-op when no caches were ever created.
    @import("mm/slab.zig").printAllCaches();

    serial.print("  SYSTEM HALTED.\n", .{});

    // Drop the boot_screen layout so its redirect_fn doesn't swallow our
    // panic text into the klog ring. Tear down BGA if it owned the
    // scanout — without this the VGA text fallback would be invisible
    // because BGA is scanning out its own buffer instead of the text mode
    // memory at 0xB8000.
    @import("ui/boot_screen.zig").disable();
    @import("ui/early_fb.zig").release();

    @import("debug/panic_screen.zig").draw(.{
        .int_no = 255,
        .msg = msg,
        .crash_rip = if (ret_addr) |a| @intCast(a) else null,
    });
    while (true) asm volatile ("cli; hlt");
}

// Verify the BUILD.ID file inside disk.tar matches the build_id embedded in
// this kernel. Mismatch means kernel.elf and disk.tar came from different
// builds — we screamed about it after losing an hour debugging stale code.
fn verifyBuildId() void {
    const build_options = @import("build_options");
    const vfs = @import("fs/vfs.zig");
    const expected: u64 = build_options.build_id;
    var buf: [32]u8 align(4) = undefined;
    // Try ext2 root first (canonical post-migration), fall back to tarfs
    // so older images keep working during the transition.
    const size = vfs.loadFile("/BUILD.ID", &buf) orelse vfs.loadFile("BUILD.ID", &buf) orelse {
        debug.klog("[buildid] WARNING: BUILD.ID missing from disk (kernel ID = {X:0>16})\n", .{expected});
        return;
    };
    if (size != 16) {
        debug.klog("[buildid] WARNING: BUILD.ID size {d} != 16 — malformed\n", .{size});
        return;
    }
    const disk_id = parseHex16(buf[0..16]) orelse {
        debug.klog("[buildid] WARNING: BUILD.ID '{s}' not valid hex\n", .{buf[0..16]});
        return;
    };
    if (disk_id != expected) {
        debug.klog("\n!!! STALE DISK IMAGE — REBUILD WITH `zig build` !!!\n", .{});
        debug.klog("  kernel build_id = 0x{X:0>16}\n", .{expected});
        debug.klog("  disk    id      = 0x{X:0>16}\n", .{disk_id});
        debug.klog("  apps loaded from disk are FROM A DIFFERENT BUILD — bugs you see\n", .{});
        debug.klog("  may already be fixed in source. Run `zig build` to refresh.\n\n", .{});
    } else {
        debug.klog("[buildid] OK 0x{X:0>16}\n", .{expected});
    }
}

fn parseHex16(s: []const u8) ?u64 {
    if (s.len != 16) return null;
    var v: u64 = 0;
    for (s) |c| {
        const d: u4 = switch (c) {
            '0'...'9' => @intCast(c - '0'),
            'a'...'f' => @intCast(c - 'a' + 10),
            'A'...'F' => @intCast(c - 'A' + 10),
            else => return null,
        };
        v = (v << 4) | d;
    }
    return v;
}
