# PMM frame-index test harness

Drives [`src/mm/frame_index.zig`](../../src/mm/frame_index.zig) under
`zig test`, off-target, in seconds — no QEMU, no locks, no kernel.

`frame_index.zig` is the per-region free-frame index the PMM keeps over its
bitmap: two masks per 1024-frame region (`nonfull`, `allfree`) derived from
the bitmap words. It replaces the run-list layer, whose entries could go
stale against the bitmap (orphaned or overlapping runs after pool
exhaustion or `markRegionUsed` fragments); a mask recomputed from the words
cannot.

The module imports only `std`. `run.sh` copies the live source in beside
`test.zig` (gitignored) — Zig 0.15 forbids an `@import` that escapes the
harness module path — so every run tests current source.

## Run it

```sh
tools/pmm-test/run.sh
ZIG=/opt/zig-x86_64-linux-0.15.2/zig tools/pmm-test/run.sh
```

## What's pinned (`test.zig`)

| test | proves |
|------|--------|
| runStart matches brute force | the doubling run finder against a naive scan, edge + random masks |
| single frames from partial words | `allocOne` leaves fully free words whole while a partial one exists |
| short runs inside partial words | `findRun(n ≤ 32)` prefers a partial word over breaking a free one |
| runs straddle words | multi-word runs, whole-region runs, exact-fit boundaries |
| random operations vs oracle | 6 seeds × 20k ops: words, masks, count, edge helpers and `rangeFree` equal a `[1024]bool` model after every step; `allocRun` returns null **exactly** when no run of that length exists |

Mutants checked when this landed (each killed by the test named for it):
dropping the cross-word run continuation, `allocOne` ignoring partial
words, `refresh` never clearing `allfree`.
