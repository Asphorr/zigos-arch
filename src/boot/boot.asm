; boot.asm — Multiboot1 entry (32-bit) → x86_64 long mode → high-half jump
;
; Boot code, the boot-time GDT, the bootstrap stack, and the boot-time page
; tables all live in LOW phys-mapped sections (.boot / .bss.boot /
; .rodata.boot / .text.boot in src/linker.ld) so 32-bit code can reach
; them. The Zig kernel proper links at the high-half VA
; KERNEL_VIRT_BASE = 0xFFFFFFFF80000000; we jump there via a 64-bit
; absolute jump after long mode is enabled.
;
; THREE mappings live in CR3 once we're done here:
;   PML4[0]    → pdpt_low      : 4×1GB pages, identity-maps phys 0..4 GB.
;                                USER bit set so per-process PML4[0..255]
;                                inheritance keeps working for lazy-fault
;                                paths. desktop.taskEntry zeroes this entry
;                                in the kernel master post-init once nothing
;                                still walks low identity. Width is 4 GB on
;                                purpose: kernel image + boot stack + page
;                                tables + multiboot info all sit well under
;                                1 GB phys, so anything above 4 GB faulting
;                                here is a pointer-corruption signal rather
;                                than a silent walk.
;   PML4[256]  → pdpt_physmap  : 512×1GB pages at VA 0xFFFF800000000000 →
;                                phys 0..512 GB, supervisor-only. The canonical
;                                "kernel can reach any phys page" view.
;                                physToVirt(p) returns PHYSMAP_BASE + p.
;                                Goes all the way to 512 GB because some MMIO
;                                BARs (e.g. xHCI at ~481 GB on -cpu host with
;                                39-bit maxphyaddr) land high.
;   PML4[511]  → pdpt_high     : one 1GB page at slot 510 (0xFFFFFFFF80000000),
;                                supervisor-only, covers the kernel image.
;
; The physmap entries strip USER so user processes inheriting kernel high
; halves can't see them. (Per-process PML4[0] is still sandboxed by vmm.)
;
; Boot stack: lives at `stack_top` in .bss.boot (low phys, < 16 MB). Used
; during _start and early kmain. The BSP transitions to its per-CPU kstack
; (high VA, allocated in kernel init) via enterFirstTask BEFORE
; desktop.taskEntry drops PML4[0]; once dropped, the boot stack is
; unreachable. No code path returns to use it again.
[BITS 32]

; Multiboot1 header
MBALIGN  equ 1 << 0
MEMINFO  equ 1 << 1
FLAGS    equ MBALIGN | MEMINFO
MAGIC    equ 0x1BADB002
CHECKSUM equ -(MAGIC + FLAGS)

; NASM only auto-infers flags from STANDARD section names (.text, .bss, .rodata).
; Custom names like .text.boot get bare ALLOC unless we say otherwise → ld
; produces a non-executable LOAD segment and `_start` faults on first fetch.
; Spell out exec/write/nobits explicitly here.

section .multiboot alloc noexec nowrite progbits
align 4
    dd MAGIC
    dd FLAGS
    dd CHECKSUM

; ===== Boot-only BSS — boot stack + boot-time page tables =====
section .bss.boot alloc nobits write
align 4096

; 4-level page tables — three sibling PDPTs, see header for layout.
;
; pdpt_low      : PML4[0]   → 4×1GB identity (0..4 GB), USER bit set.
;                              See header for why USER is set + why the width
;                              is deliberately small + when the whole entry
;                              is dropped post-init.
; pdpt_physmap  : PML4[256] → 512×1GB at VA 0xFFFF800000000000 → phys 0..512 GB,
;                              supervisor-only. The kernel's phys-frame view.
;                              (Must match memmap.PHYSMAP_SIZE + uefi/uefi_boot.zig.)
; pdpt_high     : PML4[511] → 1 GB at slot 510 (VA 0xFFFFFFFF80000000) →
;                              phys 0..1 GB, supervisor-only. Kernel image.
pml4:           resb 4096
pdpt_low:       resb 4096
pdpt_physmap:   resb 4096
pdpt_high:      resb 4096

global pml4

align 16
stack_bottom:
    resb 32768          ; 32KB stack (64-bit pushes are 8 bytes)
stack_top:

; ===== Boot-only rodata — GDT + GDTR (low addresses, fits in 32 bits) =====
section .rodata.boot alloc noexec nowrite progbits
align 16

; 64-bit GDT (loaded before far jump)
gdt64:
    dq 0                                ; 0x00: null
    dq 0x00AF9A000000FFFF               ; 0x08: kernel code (L=1, D=0, 64-bit)
    dq 0x00CF92000000FFFF               ; 0x10: kernel data
    dq 0x00AFFA000000FFFF               ; 0x18: user code (L=1, DPL=3)
    dq 0x00CFF2000000FFFF               ; 0x20: user data (DPL=3)
    ; TSS descriptor loaded later by Zig (16 bytes = 2 entries)
gdt64_end:

; 32-bit GDT pointer (used before long mode switch). The 4-byte base works
; because gdt64 is in .rodata.boot at low phys (well under 4 GB).
gdt64_ptr32:
    dw gdt64_end - gdt64 - 1           ; limit
    dd gdt64                            ; 4-byte base (kernel < 4GB)

; ===== Boot-only text — 32-bit + early-64-bit trampoline =====
section .text.boot alloc exec nowrite progbits
global _start
extern kmain
extern __bss_phys_start              ; from linker.ld — phys alias of __bss_start
extern __bss_phys_end                ; from linker.ld — phys alias of __bss_end

_start:
    cli
    mov esp, stack_top

    ; Zero the boot-time BSS (page tables + stack body) BEFORE anything else.
    ; QEMU's -kernel multiboot loader does NOT zero NOBITS sections; without
    ; this, BSS starts with whatever was in RAM, which led to a sched_lock
    ; whose now_serving field was 0x10000 at boot, deadlocking the first
    ; schedule() call. Multiboot params are in EAX/EBX from the loader; we
    ; stash them in EBP/EDX (registers — not stack, which is in BSS we're
    ; about to clobber) across the rep stosd.
    mov ebp, eax
    mov edx, ebx

    ; Zero boot.bss (this section). __boot_bss_start..__boot_bss_end live
    ; at low phys (covered by the 32-bit address space).
    extern __boot_bss_start
    extern __boot_bss_end
    mov edi, __boot_bss_start
    mov ecx, __boot_bss_end
    sub ecx, edi
    shr ecx, 2                  ; bytes → dwords
    xor eax, eax
    rep stosd

    ; Zero the kernel BSS too. The Zig kernel sees these symbols at high
    ; VAs (0xFFFFFFFF80...), which 32-bit code can't reach — but the linker
    ; computes phys-address aliases (__bss_phys_*) for us. After paging is
    ; up, the Zig kernel reads the same memory through the high-half VA.
    mov edi, __bss_phys_start
    mov ecx, __bss_phys_end
    sub ecx, edi
    shr ecx, 2
    xor eax, eax
    rep stosd

    ; Restore multiboot params into the SysV-ABI argument registers
    mov edi, ebp            ; magic → EDI (→ RDI)
    mov esi, edx            ; info  → ESI (→ RSI)

    ; --- Check for long mode support ---
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode

    mov eax, 0x80000001
    cpuid
    test edx, (1 << 29)    ; LM bit
    jz .no_long_mode

    ; --- Build the boot page tables (1 GB huge pages: 4 GB low identity +
    ;     512 GB physmap + 1 GB high kernel image; see the layout header) ---

    ; Zero PML4 + pdpt_low + pdpt_physmap + pdpt_high (4 pages). Boot.bss
    ; zeroing above already did this; redundant but cheap insurance against
    ; future layout changes.
    push edi
    push esi
    mov edi, pml4
    mov ecx, (4096 * 4) / 4
    xor eax, eax
    rep stosd
    pop esi
    pop edi

    ; PML4[0] → pdpt_low (USER bit so Ring 3 can walk through to user pages).
    ; All three PML4 writes below use 32-bit stores to a 64-bit PTE; the
    ; high 32 bits stay zero from the .bss.boot zero-fill above. That's
    ; why we need the boot.bss zeroing even though Multiboot loaders can
    ; sometimes pre-zero — we depend on it for PTE correctness, not just
    ; for clean BSS state.
    mov eax, pdpt_low
    or  eax, 0x07                       ; Present + R/W + USER
    mov dword [pml4], eax

    ; PML4[256] → pdpt_physmap (kernel-only — VA 0xFFFF800000000000).
    ; PML4[256] occupies bytes 256*8 = 2048..2055.
    mov eax, pdpt_physmap
    or  eax, 0x03                       ; Present + R/W (NO USER)
    mov dword [pml4 + 256 * 8], eax

    ; PML4[511] → pdpt_high (kernel-only — VA 0xFFFFFFFF80000000+).
    mov eax, pdpt_high
    or  eax, 0x03                       ; Present + R/W (NO USER)
    mov dword [pml4 + 511 * 8], eax

    ; Fill pdpt_low[0..3] with 1 GB huge pages (low identity map).
    ; PDPTE layout: phys[51:30]<<30 | PS (bit 7) | USER (bit 2) | RW | P
    ; Width is 4 GB on purpose — anything we need during early boot lives
    ; in low phys (kernel image + boot stack + page tables + multiboot
    ; info all under 16 MB typically); a stray pointer landing above 4 GB
    ; faulting here is a signal, not a hazard. Entries [4..511] stay zero
    ; from the rep-stosd zero-fill earlier.
    push edi
    mov edi, pdpt_low
    xor edx, edx                        ; high 32 bits of entry
    mov eax, 0x00000087                 ; phys=0 | PS | USER | RW | P
    mov ecx, 4                          ; 4 × 1 GB = 4 GB
.fill_pdpt_low:
    mov [edi], eax
    mov [edi + 4], edx
    add eax, 0x40000000                 ; next 1 GB
    adc edx, 0                          ; carry past every 4 GB boundary
    add edi, 8
    dec ecx
    jnz .fill_pdpt_low
    pop edi

    ; Fill pdpt_physmap[0..511] with 1 GB huge pages (kernel-only physmap).
    ; Full 512 GB PML4 slot so high-phys MMIO BARs (xHCI at ~481 GB on
    ; -cpu host with 39-bit maxphyaddr) are reachable via physToVirt().
    ; Must match memmap.PHYSMAP_SIZE (512 GB) and uefi/uefi_boot.zig.
    push edi
    mov edi, pdpt_physmap
    xor edx, edx
    mov eax, 0x00000183                 ; phys=0 | G | PS | RW | P  (no USER)
    mov ecx, 512
.fill_pdpt_physmap:
    mov [edi], eax
    mov [edi + 4], edx
    add eax, 0x40000000
    adc edx, 0
    add edi, 8
    dec ecx
    jnz .fill_pdpt_physmap
    pop edi

    ; Fill pdpt_high[510] = phys 0..1 GB at VA 0xFFFFFFFF80000000.
    ; The kernel image lives in 0..64 MB, so one 1 GB page at this slot
    ; covers the whole image (and 1 GB of low phys for kernel use).
    ; Slot 510 because (0xFFFFFFFF80000000 >> 30) & 0x1FF = 510.
    ; Flags: G+P+RW+PS, no USER (kernel-only). G=1 (bit 8) makes the
    ; entry survive CR3 reloads — kernel TLB persists across user
    ; context switches once CR4.PGE is on. Useless without CR4.PGE;
    ; protect.applyEarlyCr4 enables PGE at kernel init.
    ;
    ; Note: when applyEarlyCr4 flips CR4.PGE from 0→1, the act of writing
    ; CR4 with a PGE toggle flushes the entire TLB (Intel SDM Vol 3
    ; §4.10.4.1). So the pre-PGE TLB entries (which were treated as
    ; non-global despite our G=1 bit) get nuked and subsequent walks
    ; repopulate them with proper global semantics. No explicit flush
    ; needed at the PGE turn-on site.
    mov dword [pdpt_high + 510 * 8],     0x00000183
    mov dword [pdpt_high + 510 * 8 + 4], 0

    ; --- Enable PAE (CR4.PAE = bit 5) + SSE (bits 9, 10) ---
    mov eax, cr4
    or  eax, (1 << 5) | (1 << 9) | (1 << 10)
    mov cr4, eax

    ; --- Load PML4 into CR3 ---
    mov eax, pml4
    mov cr3, eax

    ; --- Enable Long Mode (EFER.LME = bit 8) ---
    ; NXE (bit 11) is intentionally NOT set here even though the kernel uses
    ; NX bits in PTEs (vmm.NX). It's enabled later in syscall_entry.init —
    ; safe because no PTE walked before that point has bit 63 set (the boot
    ; PDPTEs are 0x83/0x87/0x07; the kernel only starts emitting NX-bearing
    ; PTEs after init runs). Setting NXE early would be harmless but the
    ; deferred-init point is the canonical "MSRs come up here" spot.
    ;
    ; The AP trampoline (ap_trampoline.asm) inherits the same deferral, but for
    ; a different reason: an AP loads the ALREADY-LIVE kernel PML4, which by
    ; AP-boot time may hold NX-bearing PTEs. The AP is safe only because the
    ; window between its CR3 load and apEntry → syscall_entry.init() walks
    ; exclusively the kernel image (NX-clear); see the INVARIANT note at
    ; smp.apEntry before adding early-AP code that touches user/vmm pages.
    mov ecx, 0xC0000080         ; IA32_EFER MSR
    rdmsr
    or  eax, (1 << 8)           ; LME
    wrmsr

    ; --- Enable paging + protected mode, clear EM, set MP ---
    mov eax, cr0
    and eax, ~(1 << 2)         ; clear EM
    or  eax, (1 << 31) | (1 << 1) | (1 << 0)   ; PG + MP + PE
    mov cr0, eax

    ; Now in 32-bit compatibility mode (long mode enabled but CS.L=0)
    ; Load 64-bit GDT and far jump to 64-bit code segment (still low phys).
    lgdt [gdt64_ptr32]
    jmp 0x08:long_mode_entry

.no_long_mode:
    mov dword [0xB8000], 0x4F4E4F4F  ; "NO"
    mov dword [0xB8004], 0x4F344F36  ; "64"
    hlt
    jmp $

; ===================== 64-bit code (still at LOW phys) =====================
[BITS 64]

long_mode_entry:
    ; Load 64-bit data segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; 64-bit stack (still low phys — covered by PML4[0] identity map).
    mov rsp, stack_top

    ; EDI = magic, ESI = info (zero-extended to RDI/RSI automatically).
    ; Both are preserved across the upcoming high-half jump because they're
    ; just register state.

    ; Hand off to the high-half kernel. We're currently executing at low
    ; phys VA; PML4[511] gives us a parallel mapping of phys 0..1 GB at VA
    ; 0xFFFFFFFF80000000+, where the Zig kernel symbols (including kmain)
    ; resolve. A 64-bit absolute jump moves RIP into that mapping.
    mov rax, qword kernel_high_entry
    jmp rax

; ===================== High-half trampoline (.text, link at high VA) =====================
; Goes into the Zig kernel's normal .text section, which the linker places
; at 0xFFFFFFFF80000000+. Once we land here, RIP is in the high half.
section .text
[BITS 64]

global kernel_high_entry
kernel_high_entry:
    ; SysV ABI: arg1=RDI (multiboot magic), arg2=RSI (multiboot info).
    ; mov-rax-then-call uses imm64 absolute, so it works regardless of
    ; whether kmain is reachable by a 32-bit displacement from here.
    mov rax, qword kmain
    call rax

    ; kmain is declared `noreturn`. Reaching the next instruction means an
    ; invariant broke (stack smash, bogus ret target, signature change).
    ; ud2 makes that loud (#UD with this RIP) instead of silently spinning
    ; on a hlt-loop that looks indistinguishable from a healthy idle CPU.
    cli
    hlt
    ud2
