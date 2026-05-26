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

## What we deliberately don't do

- **No separate prototypes / forward declarations.** Zig has no header
  files; zls + grep on `pub fn name` handle the same job. The `style(9)`
  "column-0 fn name" rule doesn't transfer.
- **No big-bang style retrofits.** Annotations land on structs as they
  get touched. Canonical exemplars (`PCB`, `pmm.Region`, NVMe
  `Controller`, `TcpConn`/`TcpListener`, `FileDesc`, NVMe `SqEntry` /
  `CqEntry`) were retrofitted in one pass — the rest stays incremental.
