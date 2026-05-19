#ifndef _SETJMP_H
#define _SETJMP_H

// x86_64 System V jmp_buf: 8 callee-saved regs + RIP + RSP + pad.
// Layout matches our setjmp_x86_64.S: rbx, rbp, r12, r13, r14, r15, rsp, rip.
typedef struct { unsigned long __slots[8]; } jmp_buf[1];

int setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val) __attribute__((noreturn));

#define _setjmp setjmp
#define _longjmp longjmp

#endif
