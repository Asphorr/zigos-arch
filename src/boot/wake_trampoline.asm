; S3 wake trampoline: the FACS firmware waking vector points here, and the BSP
; re-enters the kernel through it after suspend-to-RAM. acpi/s3.zig copies and
; arms it before SLP_EN; the climb itself is trampoline.inc.
;
; It runs on the resume CR3, long after the boot-time low identity is gone:
; s3.zig stitches a 2 MiB identity page into that CR3 so this page is still
; mapped the moment paging comes on.

%define TRAMPOLINE       wake_trampoline ; wake_trampoline_{start,params,end}
%define TRAMPOLINE_BASE  0x9000          ; own page: AP re-online reuses 0x8000

%include "trampoline.inc"


; The suspend -> resume hand-off, setjmp/longjmp style. Ordinary kernel
; functions, outside the blob: suspendToRam calls s3_save_context (returns 0)
; and suspends; on resume s3ResumeEntry calls s3_longjmp, and s3_save_context
; returns a second time, with 1.

section .text
BITS 64

global s3_save_context
global s3_longjmp

; s3.zig: JmpBuf.
%define JMPBUF_RBX      0x00
%define JMPBUF_RBP      0x08
%define JMPBUF_R12      0x10
%define JMPBUF_R13      0x18
%define JMPBUF_R14      0x20
%define JMPBUF_R15      0x28
%define JMPBUF_RSP      0x30
%define JMPBUF_RIP      0x38
%define JMPBUF_RFLAGS   0x40

; usize s3_save_context(JmpBuf *buf)
s3_save_context:
    mov [rdi + JMPBUF_RBX], rbx
    mov [rdi + JMPBUF_RBP], rbp
    mov [rdi + JMPBUF_R12], r12
    mov [rdi + JMPBUF_R13], r13
    mov [rdi + JMPBUF_R14], r14
    mov [rdi + JMPBUF_R15], r15
    lea rax, [rsp + 8]                  ; rsp once our ret has run
    mov [rdi + JMPBUF_RSP], rax
    mov rax, [rsp]
    mov [rdi + JMPBUF_RIP], rax
    pushfq
    pop qword [rdi + JMPBUF_RFLAGS]
    xor eax, eax
    ret

; noreturn s3_longjmp(JmpBuf *buf)
s3_longjmp:
    mov rbx, [rdi + JMPBUF_RBX]
    mov rbp, [rdi + JMPBUF_RBP]
    mov r12, [rdi + JMPBUF_R12]
    mov r13, [rdi + JMPBUF_R13]
    mov r14, [rdi + JMPBUF_R14]
    mov r15, [rdi + JMPBUF_R15]
    mov rsp, [rdi + JMPBUF_RSP]
    push qword [rdi + JMPBUF_RFLAGS]
    popfq                               ; IF too: suspendToRam saved it cli'd
    mov eax, 1
    jmp [rdi + JMPBUF_RIP]
