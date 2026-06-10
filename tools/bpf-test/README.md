# zBPF interpreter native test harness

Drives [`src/bpf/vm.zig`](../../src/bpf/vm.zig) (and the
[`src/bpf/insn.zig`](../../src/bpf/insn.zig) encoding) under `zig test`,
off-target, in sub-seconds — no QEMU boot, no kernel.

## Why this exists

zBPF M1 is a sandboxed interpreter for the **standard eBPF ISA (RFC 9669)**:
fixed 8-byte instructions, 11 registers, a 512-byte stack, and — until the
verifier lands in M3 — runtime checks as the only sandbox boundary. That
boundary is exactly what must be proven before any of this is allowed near
ring 0: a malformed or hostile program must produce a clean `Error`, never a
wild memory access, a safety panic, or a hang.

The interpreter is pure computation with zero kernel imports, so unlike
net-test no stub tree is needed: `run.sh` copies the two live sources and
`zig test` runs them natively.

## What M1 covers

| group | what's asserted |
|-------|-----------------|
| ALU | wrapping arith, 32-bit zero-extension, shift masking, RFC div/mod-by-zero, signed div/mod incl. INT_MIN/-1, MOVSX, endian + v4 BSWAP |
| control flow | signed/unsigned compares (JMP + JMP32 lanes), JSET, real backward-jump loops, v4 long-JA, fall-off-end and out-of-range jumps rejected |
| memory | stack roundtrips at all sizes, sign-extending loads, per-run stack zeroing, every out-of-window access (incl. a live host address in r1 with no region) → `error.OutOfBounds` |
| regions (M2) | ctx structs readable via registered windows, read-only enforcement on stores, boundary-straddling accesses rejected, writable regions visible to the host |
| helpers (M2) | r1–r5 arrive as args / r0 takes the result, null-slot + out-of-range ids + bpf-to-bpf calls → `error.BadHelperId`, the in-kernel syscall-counter program byte-for-byte against a fake ctx |
| fuel | infinite loop → `error.TimeLimit`, step accounting |
| malformed input | garbage opcodes, truncated `LD_IMM64`, atomics/legacy packet modes → clean errors |

## In the kernel since M2

`src/bpf/kernel.zig` attaches the builtin counter program (assembled from
the same insn.zig builders this harness uses) at syscall entry: per-pid
counts land in a map read back at **`/proc/bpf`**. The hook runs outside
the `[perf] sys#` window and swallows program errors into a counter —
observation never breaks the observed.

## Deliberate limits (the roadmap, not bugs)

* **No verifier** — M3 (and with it userspace program loading). Until then
  only the builtin program runs, and the interpreter double-checks
  everything at runtime (it will keep doing so afterwards: defence in depth).
* **No atomics / bpf-to-bpf calls / JIT** — later, if ever needed.
* r10 writability and read-before-write are verifier-class checks (the
  runtime sandbox makes them harmless meanwhile: a clobbered r10 still
  bounds-checks, and the stack is zeroed per-run).

## Run

```sh
tools/bpf-test/run.sh              # zig from PATH
ZIG=~/zig tools/bpf-test/run.sh    # zigvm spelling
```
