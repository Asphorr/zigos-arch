# Kernel heap (TLSF) test harness

Drives [`src/mm/tlsf.zig`](../../src/mm/tlsf.zig) under `zig test`,
off-target, in seconds — no QEMU, no locks, no kernel.

`tlsf.zig` is the kernel heap's allocator core: block layout, free lists,
kfree's corruption detectors (`locate`, `tailFault`, `linksIntact`) and the
three validators. [`src/mm/heap.zig`](../../src/mm/heap.zig) wraps one
instance over the physmap heap window with the lock, stats, kasan/kdbg hooks
and the panics; everything here runs the same code over a 1 MiB static
buffer.

The module imports only `std`. `run.sh` copies the live source in beside
`test.zig` (gitignored) — Zig 0.15 forbids an `@import` that escapes the
harness module path — so every run tests current source.

## Run it

```sh
tools/heap-test/run.sh
ZIG=/opt/zig-x86_64-linux-0.15.2/zig tools/heap-test/run.sh
```

## What's pinned (`test.zig`)

| test | proves |
|------|--------|
| init | one free block before the wall, counters exact |
| every alignment | 1..4096 × six sizes: aligned, located, exact `user_size`, both layouts (natural and buried pad) occur, full coalesce back to one block |
| random operations | 6 seeds × 6000 ops with a per-allocation byte pattern: no overlap, no byte of a live allocation disturbed, all three validators after every step, every freed pointer reads as `double_free`, OOM only when no free block of the rounded class exists |
| double free | merged into a free predecessor, and heading its own run |
| buried pad grain | a free-looking header planted in a buried pad's dead grain never decides — the live-block scan runs first |
| wild pointers | interior, misaligned, region start |
| use-after-free over links | a write over a freed block's `prev` link fails the next unlink with `error.Corrupt` (`.links`) |
| tail bound | tail canary flip and an oversized `user_size` both caught, bounded by the block |
| shredded footer | a garbage footer below a block with PREV_FREE fails `release` with `.footer` |

The misaligned-pointer case found a real bug when this landed: the old
kfree read the head canary as an aligned `u32` at `addr - 4`, so
`kfree(p + 1)` died on "incorrect alignment" instead of the wild-pointer
diagnosis.

Mutants checked when this landed (each killed): no canary poison on
release, the free-header double-free check before the live-block scan,
`linksIntact` always true, the non-split alloc leaving the next block's
PREV_FREE set, `free_bytes` adding the merged size.
