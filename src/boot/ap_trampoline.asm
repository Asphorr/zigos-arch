; AP (Application Processor) startup trampoline
; Copied to 0x8000 at runtime. SIPI starts execution here in 16-bit real mode.
; Transitions: 16-bit real → 32-bit protected → 64-bit long mode → jump to Zig apEntry

section .rodata
global ap_trampoline_start
global ap_trampoline_end

; Fixed physical addresses shared with the BSP. Must stay in lockstep with
; the matching `pub const`s in src/cpu/smp.zig — the BSP populates each
; slot before sending SIPI, the trampoline reads it during long-mode entry.
%define AP_TRAMP_BASE  0x8000   ; trampoline gets memcpy'd here
%define AP_ENTRY_SLOT  0x8FE8   ; u64: &apEntry (kernel VA)
%define AP_PML4_SLOT   0x8FF0   ; u64: kernel PML4 phys addr
%define AP_STACK_SLOT  0x8FF8   ; u64: kstack top (16-aligned)

; All code is position-dependent on being at AP_TRAMP_BASE
ap_trampoline_start:

; ---- 16-bit real mode (CS:IP = 0x0800:0x0000 = phys 0x8000) ----
BITS 16
    cli

    ; Set up segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; Load temporary 32-bit GDT (within this blob)
    lgdt [AP_TRAMP_BASE + (ap_gdt_ptr - ap_trampoline_start)]

    ; Enable protected mode (CR0.PE)
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    ; Far jump to 32-bit code
    jmp 0x08:(AP_TRAMP_BASE + (ap_pm - ap_trampoline_start))

; ---- 32-bit protected mode ----
BITS 32
ap_pm:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; Enable PAE (CR4 bit 5) + OSFXSR (bit 9) + OSXMMEXCPT (bit 10)
    mov eax, cr4
    or eax, (1 << 5) | (1 << 9) | (1 << 10)
    mov cr4, eax

    ; Load kernel PML4 from BSP-populated data slot
    mov eax, [AP_PML4_SLOT]
    mov cr3, eax

    ; Enable long mode (LME = bit 8) via EFER MSR.
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)
    wrmsr

    ; Enable paging (CR0.PG) + keep PE, set MP, clear EM
    mov eax, cr0
    or eax, (1 << 31) | (1 << 0) | (1 << 1)
    and eax, ~(1 << 2)
    mov cr0, eax

    ; --- Far jump to 64-bit code, still using ap_gdt (slot 0x18) ---
    ; The kernel's master GDT lives at a higher-half VA, but a 32-bit `lgdt`
    ; only reads u16 limit + u32 base — it would silently truncate the
    ; high VA to its low 32 bits and load garbage. Instead we keep using
    ; the temporary ap_gdt that was loaded back in 16-bit real mode (which
    ; lives at low phys, reachable from 32-bit). Slot 0x18 in ap_gdt is a
    ; 64-bit code segment (L=1); the far jump reloads CS with that, so the
    ; CPU is in true 64-bit mode immediately. Once apEntry runs, it calls
    ; `initPerCpuGdt` which `lgdt`s the per-CPU GDT (high VA) — but that
    ; lgdt is in 64-bit mode and reads the full u16+u64 form, so the high
    ; base loads correctly.
    jmp 0x18:(AP_TRAMP_BASE + (ap_lm - ap_trampoline_start))

; ---- 64-bit long mode ----
BITS 64
ap_lm:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Load AP stack from BSP-populated data slot. stack_top is 16-aligned
    ; (isr_stack is `align(16)` and 16384 long), so rsp here is 16-aligned;
    ; the call below pushes 8 bytes, leaving rsp at the 8-mod-16 alignment
    ; that the System V ABI requires at function entry.
    mov rsp, [AP_STACK_SLOT]

    ; Clear DF — the System V ABI requires DF=0 at every call boundary.
    ; Real-mode entry typically has DF=0 but it's not guaranteed across
    ; firmware variants, and one stray `rep movs` in apEntry running
    ; backwards through the new kstack would be a deeply weird bug to chase.
    cld

    ; Zero the GPRs that aren't already loaded with meaningful state. INIT
    ; clears most of them, but the spec leaves a few "undefined" — apEntry
    ; is `callconv(.c)` with no args today, so this is just defense in
    ; depth in case the signature ever changes.
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d

    ; Jump to Zig apEntry function (slot populated by BSP).
    mov rax, [AP_ENTRY_SLOT]
    call rax

    ; apEntry is noreturn. If we ever fall through (corruption, stack
    ; smash, future signature change), trap with #UD instead of executing
    ; whatever data follows.
    cli
    hlt
    ud2

; ---- Temporary GDT for 16→32→64 bit transitions ----
; Three usable segments: 32-bit code/data for the protected-mode bring-up,
; plus a 64-bit code segment so the long-mode far-jump can reload CS with
; L=1 without ever touching the kernel's higher-half master GDT (which a
; 32-bit lgdt can't load — see comment at the long-mode jump above).
align 8
ap_gdt:
    dq 0                         ; 0x00: null
    dq 0x00CF9A000000FFFF        ; 0x08: 32-bit code: base=0 limit=4G
    dq 0x00CF92000000FFFF        ; 0x10: 32-bit data: base=0 limit=4G
    dq 0x00AF9A000000FFFF        ; 0x18: 64-bit code (L=1, D=0)
ap_gdt_end:

ap_gdt_ptr:
    dw ap_gdt_end - ap_gdt - 1   ; limit
    dd AP_TRAMP_BASE + (ap_gdt - ap_trampoline_start)  ; base (physical addr)

; SIZE CONSTRAINT: ap_trampoline_start..ap_trampoline_end is memcpy'd to
; AP_TRAMP_BASE (0x8000). The BSP writes data slots into the SAME page starting
; at AP_ENTRY_SLOT (0x8FE8), so this blob must stay under
; (AP_ENTRY_SLOT - AP_TRAMP_BASE) = 0xFE8 bytes or the copy clobbers the entry
; pointer. NASM's %if can't compare label offsets, so the bound is enforced at
; boot in smp.zig at the memcpy site (panics before any SIPI).
ap_trampoline_end:
