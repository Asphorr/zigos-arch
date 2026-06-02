# AML interpreter native test harness

Runs [`src/acpi/aml.zig`](../../src/acpi/aml.zig)'s `selfTestExtended()` under
`zig test`, off-target, in sub-seconds — no QEMU boot.

## Why this exists

`aml.zig` imports sibling kernel modules by `../`-relative path (`io`,
`mm/paging`, `debug/debug`, `driver/pci`, `acpi/acpi`), so it can't be
`zig test`'d in place — those imports escape the module root. This directory is a
stand-in module root one level up, with **stub** versions of exactly those
modules (enough to compile and exercise SystemIO / SystemMemory field I/O against
real Zig buffers), plus `test.zig`, which asserts `selfTestExtended()` returns 0.

`selfTestExtended()` is the single source of truth: it also runs at boot (one
PASS/FAIL klog per check, at the top of `aml.load()`), so every interpreter
capability has a pinned proof that runs **both** natively here (fast) and on real
firmware at boot (authoritative). Extending the interpreter ⇒ add a check to
`selfTestExtended()` ⇒ it runs in both places.

## Run it

```sh
tools/aml-test/run.sh                                        # `zig` from PATH
ZIG=/opt/zig-x86_64-linux-0.15.2/zig tools/aml-test/run.sh   # explicit compiler
```

`run.sh` copies the live `aml.zig` in on each run (the copy at `src/acpi/aml.zig`
is gitignored), so it always tests current source. Expect:

```
All 1 tests passed.
EXIT=0
```

A failure prints the offending `[aml] selftest <name>: got … want … (FAIL)` line.

## The stubs

| stub | what it fakes |
|------|---------------|
| `src/acpi/acpi.zig`   | table getters return null/0 (tests drive `walkBody()` directly) |
| `src/io.zig`          | a 64 KiB `PORTS[]` array so SystemIO field I/O round-trips |
| `src/mm/paging.zig`   | identity phys↔virt + permissive `isMapped` (regions point at real buffers) |
| `src/debug/debug.zig` | `klog` → `std.debug.print` |
| `src/driver/pci.zig`  | empty device list |

The one rule the stubs encode: a region-backed self-test must point at a **real,
live, kernel-owned buffer** (addressed via `virtToPhys`), never a hardcoded
physical address — so it behaves identically here and at boot. (A fake address
passes here but fails on firmware, where `isMapped` rejects it.)
