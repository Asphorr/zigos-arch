; Real mode -> long mode trampoline, the body of ap_trampoline.asm (AP
; startup) and wake_trampoline.asm (S3 resume).
;
; A CPU enters at the first byte, in real mode: an AP from INIT-SIPI-SIPI, the
; BSP from the firmware's S3 waking vector. It climbs to long mode and calls
; params.entry. The kernel half is src/boot/trampoline.zig: it copies the blob
; to TRAMPOLINE_BASE, arms the params inside that copy and reads `progress`
; back when a CPU stays silent.
;
; The including file defines:
;   TRAMPOLINE       symbol prefix of <TRAMPOLINE>_start, _params, _end
;   TRAMPOLINE_BASE  physical address the blob runs at

%ifndef TRAMPOLINE_BASE
    %fatal "define TRAMPOLINE and TRAMPOLINE_BASE before including trampoline.inc"
%endif

%include "cpu.inc"

%xdefine BLOB_START             %[TRAMPOLINE]_start
%xdefine BLOB_PARAMS            %[TRAMPOLINE]_params
%xdefine BLOB_END               %[TRAMPOLINE]_end

%define REAL_MODE_REACH         0x10000         ; DS = 0, 16-bit offsets
%define KERNEL_HALF_HIGH_DWORD  0xFFFF8000
%define STACK_ALIGNMENT         16

; Address of `label` in the copy at TRAMPOLINE_BASE.
%define PHYS(label)             (TRAMPOLINE_BASE + (label) - BLOB_START)
%define PARAM(field)            PHYS(%[TRAMPOLINE]_params.%+field)

%define CODE32_SELECTOR         (.gdt_code32 - .gdt)
%define DATA_SELECTOR           (.gdt_data - .gdt)
%define CODE64_SELECTOR         (.gdt_code64 - .gdt)

; trampoline.zig: Progress. 0 = the CPU never ran.
%define PROGRESS_REAL_MODE          1
%define PROGRESS_PROTECTED_MODE     2
%define PROGRESS_LONG_MODE          3
%define PROGRESS_REJECTED_PARAMS    0xFF

%macro set_progress 1
    mov dword [PARAM(progress)], PROGRESS_%1
%endmacro


section .rodata align=16

global BLOB_START
global BLOB_PARAMS
global BLOB_END

BITS 16
BLOB_START:
.real_mode:
    cli
    cld
    load_data_segments 0
    set_progress REAL_MODE

    o32 lgdt [PHYS(.gdt_pointer)]
    mov eax, CR0_PE
    mov cr0, eax
    jmp dword CODE32_SELECTOR:PHYS(.protected_mode)


BITS 32
.protected_mode:
    load_data_segments DATA_SELECTOR
    set_progress PROTECTED_MODE

    ; Past this point a bad param is a triple fault, which resets the whole
    ; machine; a parked CPU leaves the rest running and its progress readable.
    cmp dword [PARAM(cr3) + 4], 0
    jne .reject_params
    mov eax, [PARAM(cr3)]
    test eax, eax
    jz .reject_params
    test eax, PAGE_SIZE - 1
    jnz .reject_params

    cmp dword [PARAM(stack_top) + 4], KERNEL_HALF_HIGH_DWORD
    jb .reject_params
    test dword [PARAM(stack_top)], STACK_ALIGNMENT - 1
    jnz .reject_params

    cmp dword [PARAM(entry) + 4], KERNEL_HALF_HIGH_DWORD
    jb .reject_params

    mov eax, LONG_MODE_CR4
    mov cr4, eax

    mov eax, [PARAM(cr3)]
    mov cr3, eax

    mov ecx, MSR_EFER
    mov eax, LONG_MODE_EFER
    xor edx, edx
    wrmsr

    mov eax, LONG_MODE_CR0
    mov cr0, eax
    jmp CODE64_SELECTOR:PHYS(.long_mode)


BITS 64
.long_mode:
    set_progress LONG_MODE

    mov rsp, [PARAM(stack_top)]
    clear eax, ebx, ecx, edx, esi, edi, ebp, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d
    call [PARAM(entry)]
    ud2


BITS 32
.reject_params:
    set_progress REJECTED_PARAMS
.park:
    cli
    hlt
    jmp .park


; Stays loaded until the entry installs the kernel's GDT: that one lives in
; the higher half, out of reach of a 32-bit lgdt.
align 8, db 0
.gdt:
.gdt_null:      dq 0
.gdt_code32:    flat_segment SEG_CODE, SEG_4K_GRANULAR | SEG_32BIT
.gdt_data:      flat_segment SEG_DATA, SEG_4K_GRANULAR | SEG_32BIT
.gdt_code64:    flat_segment SEG_CODE, SEG_4K_GRANULAR | SEG_64BIT
.gdt_end:
.gdt_pointer:
    dw .gdt_end - .gdt - 1
    dd PHYS(.gdt)


; trampoline.zig: Params.
align 8, db 0
BLOB_PARAMS:
.cr3:           dq 0
.stack_top:     dq 0
.entry:         dq 0
.base:          dd TRAMPOLINE_BASE
.progress:      dd 0
BLOB_END:


static_assert TRAMPOLINE_BASE % PAGE_SIZE == 0
static_assert BLOB_END - BLOB_START <= PAGE_SIZE
static_assert PHYS(BLOB_END) <= REAL_MODE_REACH
static_assert (BLOB_PARAMS - BLOB_START) % 8 == 0
