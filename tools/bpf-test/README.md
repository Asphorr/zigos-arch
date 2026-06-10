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
| memory | stack roundtrips at all sizes, sign-extending loads, per-run stack zeroing, every out-of-stack access (incl. a live host address in r1) → `error.OutOfBounds` |
| fuel | infinite loop → `error.TimeLimit`, step accounting |
| malformed input | garbage opcodes, truncated `LD_IMM64`, calls/atomics/legacy packet modes (deferred features) → clean errors |

## Deliberate M1 limits (the roadmap, not bugs)

* **No helpers, no maps, no context regions** — M2 wires kernel hooks and
  defines the helper ABI; r1 is an opaque scalar until then.
* **No verifier** — M3. Until then the interpreter double-checks everything
  at runtime (and will keep doing so afterwards: defence in depth).
* **No atomics / bpf-to-bpf calls / JIT** — later, if ever needed.
* r10 writability and read-before-write are verifier-class checks (the
  runtime sandbox makes them harmless meanwhile: a clobbered r10 still
  bounds-checks, and the stack is zeroed per-run).

## Run

```sh
tools/bpf-test/run.sh              # zig from PATH
ZIG=~/zig tools/bpf-test/run.sh    # zigvm spelling
```
