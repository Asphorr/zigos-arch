; S3 (suspend-to-RAM) wake trampoline
; Copied to phys 0x9000 at suspend time and pointed at by FACS.firmware_waking_
; vector. On S3 resume the firmware re-enters the machine here in 16-bit real
; mode (the CPU was powered down, so GDT/IDT/TR/MSRs/control-regs are all reset).
; Transitions 16-bit real -> 32-bit protected -> 64-bit long mode exactly like
; the AP bring-up trampoline, then jumps to the Zig s3ResumeEntry.
;
; Unlike ap_trampoline.asm (which runs during boot while the legacy low identity
; map is still live), this runs long after paging.dropLowIdentity(). The suspend
; path in src/acpi/s3.zig therefore installs a temporary 2 MiB identity page at
; VA 0 in the resume CR3 so this blob's own page (0x9000) and its data slots stay
; mapped the instant `mov cr0, PG` turns paging on.

section .rodata
global wake_trampoline_start
global wake_trampoline_end

; Fixed physical addresses shared with the suspend path. KEEP IN SYNC with the
; matching `const`s in src/acpi/s3.zig — the suspend path populates each slot
; before writing SLP_EN; the trampoline reads them during long-mode entry.
%define WAKE_TRAMP_BASE  0x9000   ; trampoline gets memcpy'd here
%define WAKE_ENTRY_SLOT  0x9FE8   ; u64: &s3ResumeEntry (kernel VA)
%define WAKE_PML4_SLOT   0x9FF0   ; u64: resume CR3 phys (process PML4 + low identity)
%define WAKE_STACK_SLOT  0x9FF8   ; u64: resume stack top (16-aligned, kernel VA)

; All code is position-dependent on being at WAKE_TRAMP_BASE.
wake_trampoline_start:

; ---- 16-bit real mode (firmware enters here on S3 wake) ----
BITS 16
    cli

    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; Load the temporary 32-bit GDT (within this blob).
    lgdt [WAKE_TRAMP_BASE + (wake_gdt_ptr - wake_trampoline_start)]

    ; Enable protected mode (CR0.PE).
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    jmp 0x08:(WAKE_TRAMP_BASE + (wake_pm - wake_trampoline_start))

; ---- 32-bit protected mode ----
BITS 32
wake_pm:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; Enable PAE (CR4.5) + OSFXSR (9) + OSXMMEXCPT (10).
    mov eax, cr4
    or eax, (1 << 5) | (1 << 9) | (1 << 10)
    mov cr4, eax

    ; Load the resume CR3 (the suspending process's PML4, into which the suspend
    ; path stitched a temporary 2 MiB low-identity page so this very code stays
    ; mapped once paging is on). 32-bit load: the suspend path asserts CR3 < 4 GB.
    mov eax, [WAKE_PML4_SLOT]
    mov cr3, eax

    ; Enable long mode (EFER.LME).
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)
    wrmsr

    ; Enable paging (CR0.PG) + keep PE, set MP, clear EM.
    mov eax, cr0
    or eax, (1 << 31) | (1 << 0) | (1 << 1)
    and eax, ~(1 << 2)
    mov cr0, eax

    ; Far jump to 64-bit code using this blob's own 64-bit code segment (slot
    ; 0x18). Same reason as the AP trampoline: a 32-bit lgdt can't load the
    ; higher-half kernel GDT base, so we stay on the embedded GDT until
    ; s3ResumeEntry re-establishes the real one.
    jmp 0x18:(WAKE_TRAMP_BASE + (wake_lm - wake_trampoline_start))

; ---- 64-bit long mode ----
BITS 64
wake_lm:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Resume stack the suspend path handed us (16-aligned kernel VA; mapped by
    ; the resume CR3's shared kernel half). After the call pushes 8 bytes rsp is
    ; 8-mod-16, the SysV ABI entry alignment.
    mov rsp, [WAKE_STACK_SLOT]

    ; SysV ABI requires DF=0 at every call boundary.
    cld

    ; s3ResumeEntry is callconv(.c) with no args; zero the GPRs the ABI would
    ; pass in, defensively (firmware leaves them undefined).
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d

    ; Jump into Zig s3ResumeEntry (kernel VA, populated by the suspend path).
    mov rax, [WAKE_ENTRY_SLOT]
    call rax

    ; s3ResumeEntry is noreturn. Trap with #UD if we ever fall through.
    cli
    hlt
    ud2

; ---- Temporary GDT for the 16->32->64 transitions (identical to ap_gdt) ----
align 8
wake_gdt:
    dq 0                         ; 0x00: null
    dq 0x00CF9A000000FFFF        ; 0x08: 32-bit code: base=0 limit=4G
    dq 0x00CF92000000FFFF        ; 0x10: 32-bit data: base=0 limit=4G
    dq 0x00AF9A000000FFFF        ; 0x18: 64-bit code (L=1, D=0)
wake_gdt_end:

wake_gdt_ptr:
    dw wake_gdt_end - wake_gdt - 1                      ; limit
    dd WAKE_TRAMP_BASE + (wake_gdt - wake_trampoline_start)  ; base (physical addr)

; SIZE CONSTRAINT: the blob is memcpy'd to WAKE_TRAMP_BASE and the suspend path
; writes data slots into the SAME page starting at WAKE_ENTRY_SLOT (0x9FE8), so
; this blob must stay under (WAKE_ENTRY_SLOT - WAKE_TRAMP_BASE) = 0xFE8 bytes.
; Enforced at the memcpy site in src/acpi/s3.zig (panics before any suspend).
wake_trampoline_end:

; ============================================================================
; S3 setjmp / longjmp — the suspend -> resume hand-off (CP2b-2).
;
; These are ORDINARY 64-bit kernel functions, linked at their kernel VA. They
; sit past wake_trampoline_end and in .text, so the relocated 0x9000 blob above
; (and its size guard / memcpy in s3.zig) never include them.
;
; s3_save_context saves the callee-saved registers + rsp/rip/rflags and returns
; 0. The platform then suspends. On the far side of S3 the wake path
; (s3ResumeEntry -> smp.reinitForS3Resume) calls s3_longjmp, which restores that
; saved context and makes s3_save_context appear to return 1 — classic
; setjmp/longjmp, letting suspendToRam "fall through" to its resume branch.
;
; SysV AMD64: arg (ctx: *JmpBuf) arrives in rdi; usize result in rax. The JmpBuf
; layout MUST match the extern struct in src/acpi/s3.zig (9 x u64, this order):
;   0x00 rbx  0x08 rbp  0x10 r12  0x18 r13  0x20 r14  0x28 r15
;   0x30 rsp  0x38 rip  0x40 rflags
; ============================================================================
section .text
BITS 64

global s3_save_context
s3_save_context:
    mov [rdi + 0x00], rbx
    mov [rdi + 0x08], rbp
    mov [rdi + 0x10], r12
    mov [rdi + 0x18], r13
    mov [rdi + 0x20], r14
    mov [rdi + 0x28], r15
    lea rax, [rsp + 8]       ; rsp as it will be once our `ret` pops the retaddr
    mov [rdi + 0x30], rax
    mov rax, [rsp]           ; return address = where save "returns" to
    mov [rdi + 0x38], rax
    pushfq
    pop rax
    mov [rdi + 0x40], rax
    xor eax, eax            ; first return: 0
    ret

global s3_longjmp
s3_longjmp:
    mov rbx, [rdi + 0x00]
    mov rbp, [rdi + 0x08]
    mov r12, [rdi + 0x10]
    mov r13, [rdi + 0x18]
    mov r14, [rdi + 0x20]
    mov r15, [rdi + 0x28]
    mov rsp, [rdi + 0x30]    ; back onto the suspending syscall's kernel stack
    mov rax, [rdi + 0x40]
    push rax
    popfq                    ; restore rflags (IF included — suspend cli'd first)
    mov rcx, [rdi + 0x38]    ; resume rip (just after the s3_save_context call)
    mov eax, 1             ; longjmp return: 1
    jmp rcx
