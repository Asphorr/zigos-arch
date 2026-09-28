# Kernel heap (TLSF) test harness

Drives [`src/mm/tlsf.zig`](../../src/mm/tlsf.zig) under `zig test`,
off-target, in seconds — no QEMU, no locks, no kernel.

`tlsf.zig` is the kernel heap's allocator core: block layout, free lists,
the pool table, kfree's corruption detectors (`locate`, `tailFault`,
`linksIntact`) and the three validators. [`src/mm/heap.zig`](../../src/mm/heap.zig)
wraps one instance with the lock, pools taken from and given back to PMM,
stats, kasan/kdbg hooks and the panics; everything here runs the same code
over static buffers (a 1 MiB region, and an arena of 64 KiB slots that
stands in for PMM).

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
| wild pointers | interior, misaligned, pool start, wall, one past the pool |
| use-after-free over links | a write over a freed block's `prev` link fails the next unlink with `error.Corrupt` (`.links`) |
| tail bound | tail canary flip and an oversized `user_size` both caught, bounded by the block |
| shredded footer | a garbage footer below a block with PREV_FREE fails `release` with `.footer` |
| size past the wall | a listed free block whose header claims more than its pool holds fails `alloc` with `.size` before anything is written |
| merge sizes | a free neighbour whose size runs past the wall or under the minimum fails the forward merge with `.size`, one whose size doesn't end at the freed block fails the backward merge with `.footer`; nothing past the pool is written, nothing is unlinked |
| adjacent pools | two back-to-back pools (added out of order) never merge; each `release` reports its own pool empty; removing both leaves an empty allocator |
| pool table full | the 65th pool is refused |
| canServe | false on the search an OOM reported, true once a pool is added (the random tests check both on every OOM) |
| gaps | an address between pools is wild, a link into the gap fails the unlink |
| random with pools | 4 seeds × 6000 ops; on OOM a pool of the searched class is added at a random free slot run (must then serve the request), emptied pools are removed 3 times in 4; allocations up to 200 KB need multi-slot pools; addresses in free slots stay wild; all validators every step; ends with every pool removed |

The misaligned-pointer case found a real bug when this landed: the old
kfree read the head canary as an aligned `u32` at `addr - 4`, so
`kfree(p + 1)` died on "incorrect alignment" instead of the wild-pointer
diagnosis.

Mutants checked when this landed (each killed): no canary poison on
release, the free-header double-free check before the live-block scan,
`linksIntact` always true, the non-split alloc leaving the next block's
PREV_FREE set, `free_bytes` adding the merged size. With pools: the wall's
PREV_FREE not set by release, `removePool` keeping `total_bytes`, "pool
empty" without the wall check, the pool search skipping a pool that starts
at the address, no size check in `alloc`, `poolOf` counting one past the
end, a pool's first block with PREV_FREE set, each of `release`'s three
neighbour-size checks dropped, `canServe` always true, always false, or
without the class round-up.
