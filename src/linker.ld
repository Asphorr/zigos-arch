/* x86_64 higher-half kernel — linker script.
 *
 * Phase 1 of the higher-half migration:
 *   - .boot/.boot.bss/.boot.rodata sections live at LOW phys = LOW VA.
 *     They contain the 32-bit/early-64-bit trampoline (boot.asm), the
 *     multiboot header, the bootstrap stack, and the boot-time page tables.
 *     boot.asm runs from here in 32-bit mode where high VAs aren't reachable.
 *   - The rest of the kernel (.text/.rodata/.data/.kdata_protected/.bss)
 *     links at the canonical kernel VA `KERNEL_VIRT_BASE = 0xFFFFFFFF80000000`
 *     while still LOADING (LMA) at low phys, contiguous with .boot.
 *
 * boot.asm sets up PML4[0]->low-PDPT (existing 64×1GB identity) AND
 * PML4[511]->high-PDPT (kernel image at -2GB), then far-jumps to the high
 * VA of long_mode_entry's tail, where it can `call kmain` (which now lives
 * at high VA). Symbols __bss_phys_{start,end} below give boot.asm low-phys
 * aliases for the kernel-proper BSS so the BSS-zero loop can still run from
 * 32-bit code.
 *
 * Phase 2 will add a real physmap and start migrating phys-direct accesses
 * through paging.physToVirt; once those are gone we can drop PML4[0]
 * entirely. Until then, the low identity map stays.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

KERNEL_PHYS_BASE = 1M;
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;

SECTIONS {
    . = KERNEL_PHYS_BASE;

    /* ===== Boot trampoline — runs at LOW phys = LOW VA =====
     * Three separate output sections so each gets the right flags:
     *   .boot.text   AX  (multiboot header + 32-bit/early-64 boot code)
     *   .boot.rodata A   (boot-only GDT + GDTR)
     *   .boot.bss    AW  (boot-only BSS — page tables + boot stack)
     * Merging them into one section made LLD strip the X flag from the
     * combined segment, so _start would be loaded RO and execution faulted.
     */
    .boot.text ALIGN(4K) : {
        __boot_start = .;
        KEEP(*(.multiboot))
        *(.text.boot)
        *(.text.boot.*)
    }
    .boot.rodata ALIGN(4K) : {
        *(.rodata.boot)
        *(.rodata.boot.*)
    }
    .boot.bss ALIGN(4K) : {
        __boot_bss_start = .;
        *(.bss.boot)
        *(.bss.boot.*)
        . = ALIGN(4K);
        __boot_bss_end = .;
        __boot_end = .;
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

    /* Phys-address aliases for boot.asm. boot.asm runs in 32-bit mode and
     * cannot dereference high VAs; it uses these to zero high-half BSS
     * via the low identity map (phys = virt - KERNEL_VIRT_BASE). */
    __bss_phys_start = __bss_start - KERNEL_VIRT_BASE;
    __bss_phys_end = __bss_end - KERNEL_VIRT_BASE;

    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
