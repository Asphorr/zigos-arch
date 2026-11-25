/* x86_64 higher-half kernel — linker script.
 *
 * Two parts, loaded back to back:
 *   - .boot.text / .boot.data: the Multiboot entry (src/boot/boot.asm) with
 *     its header, page tables and GDT. Linked where it is loaded, at low
 *     addresses: it runs in 32-bit mode with paging off. Dead weight under
 *     UEFI, whose loader builds its own tables.
 *   - the kernel proper (.text .. .bss): linked at KERNEL_VIRT_BASE, loaded
 *     right behind the boot part. A loader maps it there: boot.asm, or
 *     uefi/handoff.zig at whatever physical address the firmware had room.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

/* Where Multiboot loads the image. The UEFI loader puts it wherever the
 * firmware has room and maps it at the same virtual addresses. */
KERNEL_PHYS_BASE = 1M;
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;

SECTIONS {
    . = KERNEL_PHYS_BASE;

    /* ===== The Multiboot entry — linked where it is loaded =====
     * Two output sections, so each gets its flags: merged into one, LLD
     * dropped the X flag and _start was loaded non-executable.
     *   .boot.text   AX  the Multiboot header (a loader looks for it in the
     *                    file's first 8 KiB) and the code
     *   .boot.data   AW  page tables, GDT, messages
     */
    .boot.text ALIGN(4K) : {
        __boot_start = .;
        KEEP(*(.multiboot))
        *(.text.boot)
        *(.text.boot.*)
    }
    .boot.data ALIGN(4K) : {
        *(.data.boot)
        *(.data.boot.*)
        . = ALIGN(4K);
    }

    /* ===== Kernel proper — VMA at high half, LMA continues at low phys ===== */
    . += KERNEL_VIRT_BASE;

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VIRT_BASE) {
        __text_start = .;
        *(.text) *(.text.*)
        __text_end = .;
    }
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VIRT_BASE) {
        *(.rodata) *(.rodata.*)
    }
    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VIRT_BASE) {
        *(.data) *(.data.*)
    }
    /* Hardened-data section: page-aligned, gets its W-bit cleared at boot.
     * Critical kernel structs that are rarely written + must never be
     * wildly written opt in via `linksection(".kdata_protected")`. Their
     * only legit writers wrap writes with paging.unlockKdata()/lockKdata().
     * Any other write traps as #PF with the writer's RIP — turning a
     * class of silent BSS-corruption bugs into immediate panics.
     * Currently no opt-ins (per_cpu_asm.syscall_stack_top was retired
     * when the syscall LSTAR stub started loading RSP from
     * cpus[N].tss.rsp0 directly); section retained for future use. */
    .kdata_protected ALIGN(4K) : AT(ADDR(.kdata_protected) - KERNEL_VIRT_BASE) {
        __kdata_protected_start = .;
        *(.kdata_protected) *(.kdata_protected.*)
        . = ALIGN(4K);
        __kdata_protected_end = .;
    }
    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VIRT_BASE) {
        __bss_start = .;
        *(COMMON) *(.bss) *(.bss.*)
        . = ALIGN(4K);
        __bss_end = .;
    }
    _kernel_end = .;

    /* The image's first byte as the image window shows it (memmap.zig). */
    __kernel_image_start = __boot_start + KERNEL_VIRT_BASE;

    /* For boot.asm, which runs with paging off and cannot name a kernel
     * address: the same places as Multiboot loads them, at the image's
     * link addresses. It zeroes .bss and maps the image by these. */
    __bss_phys_start = __bss_start - KERNEL_VIRT_BASE;
    __bss_phys_end = __bss_end - KERNEL_VIRT_BASE;
    __image_phys_start = __boot_start;
    __image_phys_end = _kernel_end - KERNEL_VIRT_BASE;

    /* A loader maps the image through one page directory: 1 GiB of window. */
    ASSERT(__bss_phys_end <= 1024M, "kernel image outgrew its 1 GiB window")

    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
