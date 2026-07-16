# ZigOS house style

Conventions specific to this codebase on top of stdlib Zig style. The
strict BSD `style(9)` ruleset lives in a separate project at
`D:\style9\os` and does **not** apply here — those rules (decls at top
of fn, no init-at-decl, sort-by-sizeof, etc.) are tracked in their own
codebase. This file is for ZigOS only.

## Field-access annotations on shared structs

Long-lived multi-CPU structs (`PCB`, `Frame`/`Region`, NVMe
`Controller`, `TcpConn`, `TcpListener`, `FileDesc`, anything else that
outlives a single function and is touched from more than one CPU)
carry a one-letter access tag on each field showing how the field is
allowed to be read/written:

| Tag             | Meaning                                                       |
| --------------- | ------------------------------------------------------------- |
| `(p:lockname)`  | Protected by the named lock. Reads + writes hold it.          |
| `(a)`           | Atomic — access via `@atomic{Load,Store,Rmw}`; no lock held.  |
| `(c)`           | Const-after-init. Written once during setup, read everywhere. |
| `(u)`           | User-mmap-shared. Kernel + userspace both touch via `@atomic*` with explicit ordering; producer side uses `.release`, consumer side uses `.acquire`. |

The tag goes at the start of the field's `//` comment so a `\w (p:` or
`\w (a)` grep finds every field with a given discipline:

```zig
state: State = .unused,                // (p:rq.lock) scheduler state
wake_pending: bool = false,            // (a) blockOn handshake — cross-CPU
page_dir_phys: usize = 0,              // (c) set in createAddressSpace, RO after
```

If a field has neither `(p:)` nor `(a)` nor `(c)`, the implicit reading
is **"single-CPU / single-context"** — touched only from one well-known
place (e.g. a per-CPU local, or a slot accessed only by its owner
process). State that field's owner in the doc comment when it's not
obvious from the type.

When you add a field, write the tag in the same commit. When you add a
new lock, retrofit the struct it protects. Don't leave shared fields
unannotated — the whole point is that the discipline is legible at the
declaration.

**Why:** several historic races at the multi-day-debug level (the 8-day
"silent corruption" hunt, the mtswap layered bugs, the futex lost-wake)
came down to a field's ownership being implicit. The annotation forces
authorial intent at the declaration site at zero runtime cost.

**On `(u)` specifically:** the kernel ↔ userspace ring protocol
(io_uring SQ/CQ head+tail counters, future shm consumer/producer rings)
isn't a normal atomic — it's a *cross-privilege* contract. Both sides
must agree on which counter is `.release`-written by the producer and
which is `.acquire`-read by the consumer. The reference implementation
lives in `src/cpu/iouring.zig`: kernel writes `sq_head` + `cq_tail`
with `.release`, reads `sq_tail` + `cq_head` with `.acquire`. Userspace
libc mirrors with the opposite direction. Any new userspace-mapped
ring should follow this same shape.

## comptime layout asserts on wire-format structs

Every `extern struct` that crosses a wire — DMA descriptor / ring entry,
on-disk inode/superblock/dirent, network header, MMIO register block,
ACPI table — gets a `comptime` block immediately below the struct that
asserts:

1. `@sizeOf(T) == SPEC_SIZE`
2. `@offsetOf(T, "field") == SPEC_OFFSET` for every offset the wire
   actually defines (skip pure padding).

```zig
const SqEntry = extern struct {
    opcode: u8,
    flags: u8,
    cid: u16 align(1),
    nsid: u32 align(1),
    _rsv0: u64 align(1),
    mptr: u64 align(1),
    prp1: u64 align(1),
    prp2: u64 align(1),
    cdw10: u32 align(1),
    // ... cdw11..cdw15 ...
};
comptime {
    const a = @import("std").debug.assert;
    a(@sizeOf(SqEntry) == 64);
    a(@offsetOf(SqEntry, "opcode") == 0);
    a(@offsetOf(SqEntry, "cid") == 2);
    a(@offsetOf(SqEntry, "nsid") == 4);
    a(@offsetOf(SqEntry, "prp1") == 24);
    a(@offsetOf(SqEntry, "prp2") == 32);
    a(@offsetOf(SqEntry, "cdw10") == 40);
}
```

**Why:** when the layout is wrong, every DMA submission corrupts
something the device or peer will only notice much later. The block
makes the spec contract a build-time check. `src/acpi/acpi.zig` already
follows this (the firmware-table audit); generalize.

**How to apply:** required on every new wire-shape `extern struct`.
When touching an existing wire struct without a block, add one in the
same edit. Place the `comptime` block directly under the struct (not at
file scope further down) so a reader sees the contract next to the
declaration. Assert only offsets the wire actually defines — don't
assert padding offsets; padding is an implementation detail of the
struct, not a wire commitment.

## Endian-typed wire fields (`LE(T)` / `BE(T)`)

Extern-struct fields that cross a wire have an implicit endianness that
`u32 field = 5` doesn't surface. Wrap each multi-byte wire field in
`util/endian.zig`'s `LE(T)` or `BE(T)`:

```zig
const DsmRange = extern struct {
    context_attributes: endian.LE(u32) = endian.LE(u32).init(0),
    length: endian.LE(u32) = endian.LE(u32).init(0),
    starting_lba: endian.LE(u64) = endian.LE(u64).init(0),
};
```

Read with `field.get()`, write with `field.set(value)`, construct with
`endian.LE(T).init(value)` for struct literals. Direct `.field = 5`
becomes a compile error — forcing the host-endian-to-wire-endian swap
to happen at every access site. Layout-invariant: `@sizeOf(LE(T)) ==
@sizeOf(T)`, so the comptime offset asserts still hold.

**Why:** silent byte-order bugs are the worst kind — code works on the
testing host, breaks on a port. Now the type system catches them.
**Reference exemplar:** `nvme.DsmRange`. **How to apply:** required on
new wire-format `extern struct`s for any field wider than `u8`. When
touching an existing one, wrap fields opportunistically — `@sizeOf` /
`@offsetOf` asserts under the struct verify the wrap didn't disturb
the layout.

## Lock-Guard pattern (compile-time-enforced lock-held)

For structs with a clearly delimited lock + a handful of lock-requiring
methods, expose the lock via an `acquire() Guard` method whose return
value is the receiver of every protected method:

```zig
const Region = struct {
    lock: SpinLock = .{},
    // ... fields ...

    pub fn acquire(self: *Region) Guard { ... }

    pub const Guard = struct {
        region: *Region,
        pub fn release(self: Guard) void { ... }
        pub fn pushRun(self: Guard, ...) bool { ... }  // requires lock
    };
};
```

Callers `const g = region.acquire(); defer g.release();` then call
`g.pushRun(...)`. Calling `pushRun` without going through `acquire()`
is a compile error — the Guard is a *witness of lock-held state*.
Strictly stronger than the `_locked` naming convention because the
compiler enforces it.

**When NOT to use:** for fields where dozens of unrelated sites touch
the lock-protected state (e.g. `PCB.pending_signals`), the Guard would
be more friction than the `(p:lockname)` tag is worth. Use Guards
where lock + protected methods cluster on one struct. **Reference
exemplar:** `pmm.Region.Guard.pushRun`. Existing `_Locked`-suffixed
module functions can coexist during the migration; new lock-protected
methods should be added as `Guard` methods directly.

## `lock.assertHeld()` runtime checks

Both `SpinLock` and `Mutex` carry holder identity already (`holder_cpu`
/ `owner_pid`). The cheapest possible "I claim the caller holds this
lock" check is `lock.assertHeld()` at function entry — compiled out
in non-ReleaseSafe builds, free in production, catches "caller
forgot to lock" on the first run instead of waiting for the timing-
dependent race. Linux's `lockdep_assert_held` analogue.

**Where to use:** every function whose docstring says "caller must
hold X" or whose name ends in `_Locked`. **Reference exemplar:**
`pmm.pushRunLocked` line 1 calls `r.lock.assertHeld()`.

## `UserPtr(T)` — type-safe user-space pointers

Raw `usize` / `u32` user VAs flowing through kernel code can't be
distinguished from kernel pointers at the type level — the "validate
before deref" contract is invisible at the deref site. Wrap user
pointers in `util/user_ptr.zig`'s `UserPtr(T)`:

```zig
// Read arg:
const up = UserPtr(u32).fromRaw(arg).validate() orelse return E_FAULT;
const value = up.copyIn() orelse return E_FAULT;
// Write target (proves the page writable, breaks COW):
const out = UserPtr(u32).fromRaw(arg).validateWrite() orelse return E_FAULT;
if (!out.copyOut(value)) return E_FAULT;
```

`UserPtr` itself has no dereference methods — `copyIn` lives only on
the proof handle `validate()` returns, and `copyOut` only on the one
from `validateWrite()`. Deref of an unvalidated pointer, or a write
through a read-proof, is a compile error — as is direct
`@ptrFromInt(arg).*`. The Zig-native equivalent of Linux's SPARSE
`__user` annotation, but enforced at compile time rather than by an
external tool.

The copies themselves are *faultable* (`cpu/arch/usercopy.zig`): the
copy instruction is a kernel exception-table site, so a validated page
that stops being resident mid-syscall (swap eviction while parked, a
sibling thread's munmap) is re-faulted-in transparently — or surfaces
as the null/false the caller maps to E_FAULT — instead of a ring-0 #PF
panic. That's why `copyIn` returns `?T` and `copyOut` returns `bool`.

**Reference exemplar:** `sysSigpending` in `cpu/syscall/proc.zig`.
Mass-rollout across ~50 syscall sites is incremental — new syscalls
should use UserPtr; existing ones migrate when touched.

## `Persistent(T)` — compile-time persistable proofs (pmem)

Bytes in the NVDIMM region outlive the kernel binary and can be torn
by a crash mid-store — two hazards ordinary RAM never shows.
`mm/pmem.zig`'s `Persistent(T)` makes the resulting bug classes
compile errors:

- instantiating it runs `assertPersistable(T)`, which rejects (naming
  the field path) pointers, bool/enum/union/optional (types with
  invalid bit patterns — loading a torn write would be UB),
  auto-layout structs, `usize`, and implicit padding;
- a locked `layoutId(T)` fingerprint (FNV-1a over field names,
  offsets, widths) turns "someone edited a persistent struct" into a
  build failure instead of a silent misread of last boot's bytes;
- the handle exposes only `load()` (snapshot out) and `store()`
  (write-through + `persistRange` — durable on return), so a store
  that skips the persistence domain does not compile through it.

```zig
const hdr = Persistent(Header).map(0) orelse return; // bounds+align proof
const cur = hdr.load();  // sound even after a torn write
hdr.store(next);         // durable on return
```

**Reference exemplar:** `persistenceSelfTest` in `mm/pmem.zig` (the
boot counter). New on-pmem structures go through `Persistent(T)`; the
raw `readAt`/`writeAt` byte path remains for /dev/pmem0 file I/O.

## `kwarn` — recoverable warnings

Three-level severity in `debug/debug.zig`:

- `klog(...)` — informational, expected events.
- `kwarn(@src(), ...)` — invariant violated but recovery is correct.
  Logs to serial+VGA AND bumps `debug.warn_count` (atomic counter).
  Non-zero count at shutdown is itself a finding worth investigating.
- `@panic(...)` / `kpanic(...)` — invariant violated, subsequent state
  unreasonable. Aborts.

Mirrors Linux's `WARN_ON` vs `BUG_ON` distinction. **Where to use
kwarn:** "this shouldn't have happened but we handled it" — e.g.
NVMe queue-full retries, fdpoll waiter registry exhaustion, an `E_BADF`
from a path that should always pass a live fd. The counter turns
silent self-recovery into observable metric.

## What we deliberately don't do

- **No separate prototypes / forward declarations.** Zig has no header
  files; zls + grep on `pub fn name` handle the same job. The `style(9)`
  "column-0 fn name" rule doesn't transfer.
- **No big-bang style retrofits.** Annotations land on structs as they
  get touched. Canonical exemplars (`PCB`, `pmm.Region`, NVMe
  `Controller`, `TcpConn`/`TcpListener`, `FileDesc`, NVMe `SqEntry` /
  `CqEntry`) were retrofitted in one pass — the rest stays incremental.

## Reference index

| Pattern             | Canonical exemplar                              |
| ------------------- | ----------------------------------------------- |
| `(p:lock)/(a)/(c)`  | `src/proc/process.zig` `PCB`                    |
| `(u)` user-mmap     | `src/cpu/iouring.zig` `RingHeader`              |
| Wire layout asserts | `src/driver/nvme.zig` `SqEntry`                 |
| `LE(T)` / `BE(T)`   | `src/driver/nvme.zig` `DsmRange`                |
| Lock-Guard          | `src/mm/pmm.zig` `Region.Guard.pushRun`         |
| `assertHeld()`      | `src/mm/pmm.zig` `pushRunLocked` line 1         |
| `UserPtr(T)`        | `src/cpu/syscall/proc.zig` `sysSigpending`      |
| `Persistent(T)`     | `src/mm/pmem.zig` `persistenceSelfTest`         |
| `kwarn(@src(),...)` | `src/debug/debug.zig` `kwarn`                   |
