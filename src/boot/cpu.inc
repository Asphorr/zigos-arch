; Names for what the mode switches write, shared by boot.asm (the Multiboot
; entry) and trampoline.inc (AP startup, S3 resume): all three leave a CPU
; in long mode with the same CR0, CR4 and EFER.

%ifndef CPU_INC
%define CPU_INC

%define PAGE_SIZE               0x1000

%define CR0_PE                  (1 << 0)
%define CR0_MP                  (1 << 1)
%define CR0_NE                  (1 << 5)
%define CR0_PG                  (1 << 31)

%define CR4_PAE                 (1 << 5)
%define CR4_OSFXSR              (1 << 9)
%define CR4_OSXMMEXCPT          (1 << 10)

%define MSR_EFER                0xC0000080
%define EFER_LME                (1 << 8)

; What a CPU enters long mode with. NXE stays 0 until syscall/entry.zig
; init(); see the NXE notes in smp.zig.
%define LONG_MODE_CR4           (CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT)
%define LONG_MODE_EFER          EFER_LME
%define LONG_MODE_CR0           (CR0_PE | CR0_MP | CR0_NE | CR0_PG)

%define SEG_PRESENT             (1 << 7)
%define SEG_DPL3                (3 << 5)
%define SEG_CODE_OR_DATA        (1 << 4)
%define SEG_EXECUTABLE          (1 << 3)
%define SEG_READ_WRITE          (1 << 1)
%define SEG_CODE                (SEG_PRESENT | SEG_CODE_OR_DATA | SEG_EXECUTABLE | SEG_READ_WRITE)
%define SEG_DATA                (SEG_PRESENT | SEG_CODE_OR_DATA | SEG_READ_WRITE)

%define SEG_4K_GRANULAR         (1 << 3)
%define SEG_32BIT               (1 << 2)
%define SEG_64BIT               (1 << 1)

%macro load_data_segments 1
    mov ax, %1
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
%endmacro

%macro clear 1-*
%rep %0
    xor %1, %1
%rotate 1
%endrep
%endmacro

; Base 0, limit 4 GiB.
%macro flat_segment 2 ; access, flags
    dw 0xFFFF
    dw 0
    db 0
    db %1
    db ((%2) << 4) | 0xF
    db 0
%endmacro

%macro static_assert 1
    times -!(%1) db 0
%endmacro

%endif
