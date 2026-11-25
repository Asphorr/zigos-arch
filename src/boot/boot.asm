; Multiboot entry: 32-bit protected mode -> long mode -> the kernel.
;
; A Multiboot loader (GRUB, `qemu -kernel`) enters at _start in protected
; mode with paging off and the image at its link addresses. From there this
; file is that path's boot loader in the sense of lib/boot_protocol.zig, and
; owes the kernel what uefi/handoff.zig owes it on the other path: long mode,
; interrupts off, and page tables with the same three windows.
;
;   identity   0 .. IDENTITY_GIB                    1 GiB pages, user
;   physmap    PHYSMAP_BASE .. + PHYSMAP_GIB        1 GiB pages, global
;   image      KERNEL_VIRT_BASE + the image's span  2 MiB pages, global
;
; The image window ends where the image does, as it does under UEFI: a read
; past the image that would fault there faults here.
;
; The windows' sizes and bases are lib/boot_protocol.zig's; build.zig passes
; them (-D). The first two tables are data, assembled; only the image's
; page directory is filled at run time, from the linker's symbols.
;
; CR0, CR4 and EFER are written whole (cpu.inc), not patched over what the
; loader left: the BSP comes out as an AP or a waking BSP does from
; trampoline.inc.
;
; No stack is handed over. The 32-bit code pushes two words to probe for
; CPUID, on a scratch stack of its own; the kernel takes its boot stack at
; multiboot_entry (src/main.zig), the one the UEFI entry takes.

%ifndef IDENTITY_GIB
    %fatal "build.zig passes -DIDENTITY_GIB -DPHYSMAP_GIB -DPHYSMAP_BASE -DKERNEL_VIRT_BASE from lib/boot_protocol.zig"
%endif

%include "cpu.inc"

%define MULTIBOOT_HEADER_MAGIC  0x1BADB002
%define MULTIBOOT_LOADER_MAGIC  0x2BADB002
%define MULTIBOOT_PAGE_ALIGN    (1 << 0)
%define MULTIBOOT_MEMORY_INFO   (1 << 1)        ; the memory map: the PMM is built from it
%define MULTIBOOT_FLAGS         (MULTIBOOT_PAGE_ALIGN | MULTIBOOT_MEMORY_INFO)

%define EFLAGS_ID               (1 << 21)
%define CPUID_EXT_MAX           0x80000000
%define CPUID_EXT_FEATURES      0x80000001
%define CPUID_EXT_GIB_PAGES     (1 << 26)       ; edx
%define CPUID_EXT_LONG_MODE     (1 << 29)       ; edx

%define PTE_PRESENT             (1 << 0)
%define PTE_WRITABLE            (1 << 1)
%define PTE_USER                (1 << 2)
%define PTE_HUGE                (1 << 7)
%define PTE_GLOBAL              (1 << 8)
%define PTE_TABLE               (PTE_PRESENT | PTE_WRITABLE)

%define GIB                     (1 << 30)
%define HUGE_PAGE_SHIFT         21              ; 2 MiB
%define HUGE_PAGE               (1 << HUGE_PAGE_SHIFT)
%define TABLE_ENTRIES           512
%define PML4_INDEX(virt)        (((virt) >> 39) & (TABLE_ENTRIES - 1))
%define PDPT_INDEX(virt)        (((virt) >> 30) & (TABLE_ENTRIES - 1))

%define KERNEL_CODE_SELECTOR    (gdt.kernel_code - gdt)
%define KERNEL_DATA_SELECTOR    (gdt.kernel_data - gdt)

%define COM1                    0x3F8
%define UART_DATA               0
%define UART_INT_ENABLE         1
%define UART_DIVISOR_LOW        0               ; with UART_LINE_DLAB set
%define UART_DIVISOR_HIGH       1
%define UART_LINE_CONTROL       3
%define UART_MODEM_CONTROL      4
%define UART_LINE_STATUS        5
%define UART_LINE_8N1           0x03
%define UART_LINE_DLAB          0x80
%define UART_MODEM_DTR_RTS      0x03
%define UART_STATUS_CAN_SEND    (1 << 5)
%define UART_DIVISOR_115200     1
%define UART_SEND_PATIENCE      0x10000         ; status reads: no UART, or a stuck one

%define VGA_TEXT                0xB8000
%define VGA_WHITE_ON_RED        0x4F

; A page table, its entries given in ascending order; the rest are zero.
%macro table 1 ; label
    align PAGE_SIZE, db 0
%1:
    %xdefine TABLE_START %1
%endmacro

%macro entry 2 ; index, value
    times (%1) - ($ - TABLE_START) / 8 dq 0
    dq %2
%endmacro

%macro end_table 0
    times TABLE_ENTRIES - ($ - TABLE_START) / 8 dq 0
    %undef TABLE_START
%endmacro

%macro outb 2 ; port, value
    mov dx, %1
    mov al, %2
    out dx, al
%endmacro


section .multiboot alloc noexec nowrite progbits
align 4
    dd MULTIBOOT_HEADER_MAGIC
    dd MULTIBOOT_FLAGS
    dd -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_FLAGS)


; Custom section names get no flags from NASM: spelled out, or ld makes the
; segment non-executable.
section .text.boot alloc exec nowrite progbits

global _start
extern multiboot_entry          ; src/main.zig, in the higher half
extern __bss_phys_start         ; src/linker.ld: where the image lies as loaded
extern __bss_phys_end
extern __image_phys_start
extern __image_phys_end

BITS 32
_start:
    cli
    cld
    mov esp, scratch_stack.top

    ; The loader's two words, out of the way of cpuid and the string stores.
    mov ebp, eax                ; its magic
    mov esi, ebx                ; its info structure

    cmp ebp, MULTIBOOT_LOADER_MAGIC
    jne .not_multiboot

    ; CPUID exists where EFLAGS.ID can be changed.
    pushfd
    pop eax
    mov ecx, eax
    xor eax, EFLAGS_ID
    push eax
    popfd
    pushfd
    pop eax
    push ecx
    popfd
    xor eax, ecx
    test eax, EFLAGS_ID
    jz .no_cpuid

    mov eax, CPUID_EXT_MAX
    cpuid
    cmp eax, CPUID_EXT_FEATURES
    jb .no_long_mode
    mov eax, CPUID_EXT_FEATURES
    cpuid
    test edx, CPUID_EXT_LONG_MODE
    jz .no_long_mode
    ; A CPU without them takes the huge bit of a PDPT entry for a reserved
    ; one: the first fetch after CR0.PG would be a triple fault.
    test edx, CPUID_EXT_GIB_PAGES
    jz .no_gib_pages

    ; The kernel's .bss, through its load address. A loader need not have
    ; zeroed it: `qemu -kernel` does not.
    mov edi, __bss_phys_start
    mov ecx, __bss_phys_end
    sub ecx, edi
    shr ecx, 2
    xor eax, eax
    rep stosd

    ; The image window: every 2 MiB page the image has a byte in. The
    ; entries' high halves are zero already: the image is below 4 GiB.
    mov eax, __image_phys_start
    and eax, -HUGE_PAGE
.map_image:
    mov edx, eax
    shr edx, HUGE_PAGE_SHIFT - 3                ; its index, times 8
    mov ecx, eax
    or  ecx, PTE_PRESENT | PTE_WRITABLE | PTE_HUGE | PTE_GLOBAL
    mov [pd_image + edx], ecx
    add eax, HUGE_PAGE
    cmp eax, __image_phys_end
    jb .map_image

    mov eax, LONG_MODE_CR4
    mov cr4, eax

    mov eax, pml4
    mov cr3, eax

    mov ecx, MSR_EFER
    mov eax, LONG_MODE_EFER
    xor edx, edx
    wrmsr

    lgdt [gdt_pointer]
    mov eax, LONG_MODE_CR0
    mov cr0, eax
    jmp KERNEL_CODE_SELECTOR:long_mode

.not_multiboot:
    mov esi, message.not_multiboot
    jmp fail
.no_cpuid:
    mov esi, message.no_cpuid
    jmp fail
.no_long_mode:
    mov esi, message.no_long_mode
    jmp fail
.no_gib_pages:
    mov esi, message.no_gib_pages
    ; and on into fail

; Says the message at esi on COM1 and at the top of the text screen, and
; stops. Whatever cannot boot here has no other way to say why.
fail:
    outb COM1 + UART_INT_ENABLE, 0
    outb COM1 + UART_LINE_CONTROL, UART_LINE_DLAB
    outb COM1 + UART_DIVISOR_LOW, UART_DIVISOR_115200
    outb COM1 + UART_DIVISOR_HIGH, 0
    outb COM1 + UART_LINE_CONTROL, UART_LINE_8N1
    outb COM1 + UART_MODEM_CONTROL, UART_MODEM_DTR_RTS

    mov edi, VGA_TEXT
.next_byte:
    lodsb
    test al, al
    jz .stop
    mov bl, al
    mov ecx, UART_SEND_PATIENCE
    mov dx, COM1 + UART_LINE_STATUS
.wait_to_send:
    in  al, dx
    test al, UART_STATUS_CAN_SEND
    loopz .wait_to_send
    outb COM1 + UART_DATA, bl
    cmp bl, ' '
    jb .next_byte                               ; the line end is the UART's alone
    mov ah, VGA_WHITE_ON_RED
    stosw
    jmp .next_byte
.stop:
    hlt
    jmp .stop


BITS 64
long_mode:
    load_data_segments KERNEL_DATA_SELECTOR

    ; The switch leaves the upper halves of the registers undefined.
    mov edi, ebp                ; kmain's magic
    mov esi, esi                ; and its info

    ; Out of the identity window and into the image's.
    mov rax, qword multiboot_entry
    jmp rax


section .data.boot alloc noexec write progbits align=4096

table pml4
    entry 0,                                pdpt_identity + PTE_TABLE + PTE_USER
    entry PML4_INDEX(PHYSMAP_BASE),         pdpt_physmap + PTE_TABLE
    entry PML4_INDEX(KERNEL_VIRT_BASE),     pdpt_image + PTE_TABLE
end_table

; USER: a process inherits the identity for the lazy-fault paths of early
; boot. The kernel drops the whole window once nothing walks it.
table pdpt_identity
%assign gib 0
%rep IDENTITY_GIB
    dq gib * GIB + (PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_HUGE)
%assign gib gib + 1
%endrep
end_table

; GLOBAL: the kernel's mappings outlive a CR3 reload once it sets CR4.PGE.
table pdpt_physmap
%assign gib 0
%rep PHYSMAP_GIB
    dq gib * GIB + (PTE_PRESENT | PTE_WRITABLE | PTE_HUGE | PTE_GLOBAL)
%assign gib gib + 1
%endrep
end_table

table pdpt_image
    entry PDPT_INDEX(KERNEL_VIRT_BASE),     pd_image + PTE_TABLE
end_table

; _start fills it.
table pd_image
end_table

; uefi/handoff.zig's GDT. The kernel loads its own; until then it runs on
; the first three entries.
align 16, db 0
gdt:
.null:          dq 0
.kernel_code:   flat_segment SEG_CODE, SEG_4K_GRANULAR | SEG_64BIT
.kernel_data:   flat_segment SEG_DATA, SEG_4K_GRANULAR | SEG_32BIT
.user_code:     flat_segment SEG_CODE | SEG_DPL3, SEG_4K_GRANULAR | SEG_64BIT
.user_data:     flat_segment SEG_DATA | SEG_DPL3, SEG_4K_GRANULAR | SEG_32BIT
.end:
gdt_pointer:
    dw gdt.end - gdt - 1
    dd gdt

message:
.not_multiboot: db "ZigOS: not started by a Multiboot loader", 13, 10, 0
.no_cpuid:      db "ZigOS: this CPU has no CPUID", 13, 10, 0
.no_long_mode:  db "ZigOS: this CPU has no 64-bit mode", 13, 10, 0
.no_gib_pages:  db "ZigOS: this CPU has no 1 GiB pages", 13, 10, 0

align 16, db 0
scratch_stack:
    times 64 db 0
.top:


static_assert IDENTITY_GIB <= TABLE_ENTRIES
static_assert PHYSMAP_GIB <= TABLE_ENTRIES
static_assert PHYSMAP_BASE % (TABLE_ENTRIES * GIB) == 0
static_assert KERNEL_VIRT_BASE % GIB == 0
static_assert KERNEL_CODE_SELECTOR == 0x08
static_assert KERNEL_DATA_SELECTOR == 0x10
