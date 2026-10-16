# User address-space region set test harness

Drives [`src/mm/vma.zig`](../../src/mm/vma.zig) under `zig test`,
off-target, in seconds.

`vma.zig` is the sorted set of a process's user regions (VMAs): lookups,
insert with neighbor merging, `remove` that splits the regions straddling
either edge, `update` (mprotect's split-and-apply), `resizeEnd` (brk) and
the top-down gap search mmap places mappings with. The kernel instance
(`process.RegionSet`) stores `process.LazyRegion`s in kernel-heap memory
under the owner's `as_lock`; here the same code runs over a test region
type and `std.testing.allocator`.

The module imports only `std`. `run.sh` copies the live source in beside
`test.zig` (gitignored) — Zig 0.15 forbids an `@import` that escapes the
harness module path — so every run tests current source.

## Run it

```sh
tools/vma-test/run.sh
ZIG=/opt/zig-x86_64-linux-0.15.2/zig tools/vma-test/run.sh
```

## What's pinned (`test.zig`)

| test | proves |
|------|--------|
| random operations | 6 seeds × 6000 ops (insert, remove, update, resizeEnd, queries) against a page model over 256 pages: after every op each page resolves to a region with the model's prot and file offset, the set is sorted and disjoint; `remove`'s pieces tile exactly the mapped pages of the range with their attributes; `isFree`, `covers`, `atOrAbove` and `gapTopDown` agree with brute force; a clone is independent |
| merge both neighbors | inserting the middle of three mergeable regions leaves one |
| punching a hole | removing the middle of a region leaves two, offsets advanced on both the piece and the tail |
| failed allocation | an insert, a hole punch and an update that need a slot fail with `OutOfMemory` and change nothing; removing a whole region needs no slot |
| gapTopDown | highest hole, a hole that fits exactly, the lowest hole, none |

Mutants checked when this landed (each killed): the straddling piece
handed to `removed` untrimmed, merging without `canMerge`, the trimmed
tail keeping its old offset, `gapTopDown` without its underflow guard,
`isFree` off by one at the end, `resizeEnd` ignoring the next region.
