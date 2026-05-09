# Wild-writer bug in a freestanding x86_64 Zig kernel — deep-think prompt

## Tl;dr of what we want
A wild kernel-mode store is scribbling **ASCII bytes from `compiler_rt` symbol names** across random BSS pages. We want to identify the root cause / writer site, given the constraints below. We don't need a code patch — we need a *theory* for what kind of code path emits stores whose values look like the bytes of a `compiler_rt` symbol name and whose target addresses look random within kernel BSS.

## Setup
- ZigOS, freestanding x86_64 long-mode kernel, Zig 0.15.2.
- 4-level paging, identity-mapped lower 4 GB.
- SMP (2 CPUs, BSP + 1 AP). Per-CPU LSTAR trampolines (no GS_BASE / no swapgs anywhere).
- Per-CPU `sched_lock` with atomic CAS on PCB state.
- Built with `-Doptimize=ReleaseSafe`, no special LTO.
- Source paths: `D:\zigos-arch\src\`. Mirror at `~/zigos-arch/src/` on a Linux VM that runs the build + QEMU.

## Symptoms (multiple runs)

**Common pattern**: kernel boots fine, desktop comes up. User runs an action (most reliably `ls | wc` from a shell) and crashes some hundreds of ms later. The crash site is *never* the writer site — it's downstream code that loaded a corrupted u64/u8 value.

**Specific captured corruptions**:
1. **`kernel_rsp` clobbered with `0x6d755f6863746566`** — that's `"fetch_um"` in little-endian. `kernel_rsp` is a `pub export var` used by the syscall return path (`returnToKernel` does `movq kernel_rsp_page(%%rip), %%rsp`). When the wild writer overwrites it, the next syscall return loads a bogus RSP and triple-faults. We caught this once via `qemu -d int,cpu_reset` (TCG accel) — saw `#GP at returnToKernel+0xc, RSP=0x6d755f6863746566`.

2. **`process.handleUserPageFault.dbg.counts[1]=110`** and **`dbg.counts[2]=114`** (the Zig-mangled symbol gives `dbg.counts` size 32 bytes / 32 entries). `dbg.counts` is a function-static `[MAX_PROCS]u8`, only ever incremented from 0..64 by the page-fault handler. A value of 110/114 is impossible from the legit writer. We added a defensive clamp that resets it on detection. The clamp fires on multiple runs.

3. After the clamp, the next crash is typically a downstream casualty — most recently:
   `!!! KERNEL PANIC !!! integer overflow at fat32.readDirEntryRaw+0x82` (called from `sysListDir` running for the `ls` half of `ls | wc`). Strongly suggests another fat32 BSS field has been clobbered too.

**Key clue — the values written look like symbol-name bytes**
- `0x6d755f6863746566` = `"fetch_um"` LE. This is the prefix of `compiler_rt.atomics.__atomic_fetch_umin_*` / `__atomic_fetch_umax_*`. Not a coincidence.
- `dbg.counts[i] = 110` is `'n'`; 114 is `'r'`. Could be from various symbol names too, but plausibly more compiler_rt strings.

We have not yet definitively identified WHAT range of bytes are being written — but the kernel_rsp value is unambiguous: it's exactly the 8-byte chunk `"fetch_um"` from a compiler_rt name, written aligned at the location of `kernel_rsp`.

**Key clue — different victim pages on different runs**
- Run A: only `kernel_rsp` (page `0x1EF000` post-isolation).
- Run B: only `dbg.counts` (page `0x3A7000`).
- Run C: both.
- Run D: `dbg.counts` + something in fat32 BSS that produced the integer overflow at `fat32.readDirEntryRaw+0x82`.

The choice of victim page seems random across runs but the corruption pattern is consistent (one or more u64-aligned 8-byte writes of ASCII content).

## What we've tried

1. **Initial blame: stack overflow corrupting kstack neighbor.** Reasonable a priori — kernel uses 16 KB per-process kernel stacks. We added unmapped guard pages below every kstack via `paging.installGuardPage` (split a 2 MB huge page → 4 KB) — overflow now panics with `#PF at guard page` rather than scribbling. Did not stop the wild writer. So it's not a kstack overflow.

2. **DR0 hardware watchpoint** on the byte holding `hb_state_count` (the only counter we suspected wild reads from at the time). Worked under KVM but caused a `#DB → #DB` recursion under TCG (the increment instruction's BS-after-instruction trap and DR0-on-write trap both fired and the handler entry's writes themselves re-tripped DR0 → infinite loop). Abandoned.

3. **MMU page-write protection.** CR0.WP=1 and `paging.installWriteWatch(virt)` clears the R/W bit on the 4 KB page containing the target. The `#PF (vec=14, error_code with W=1, U=0)` handler:
   - Looks up the faulting page in a 4-slot table (`ww_entries[]`), each slot has `{page, whitelist_sym, max_offset}`.
   - Resolves the saved RIP to a kernel symbol. If `r.name == whitelist_sym` and `r.offset <= max_offset`, the writer is the LEGIT one — un-protect the page, set RFLAGS.TF in the saved frame, return.
   - On the very next instruction's BS-bit `#DB`, re-protect the page and clear TF. (Vec=1 handler runs first.)
   - Otherwise: dump RIP + GPRs + 16-byte code window + RBP backtrace and panic.

   This works correctly — verified by the legit writer (`handleException` writing `dbg.counts[cur]+=1`) being whitelisted and stepped past, and by TCG `qemu_int.log` showing exactly the expected #PF→#DB pairs.

4. **4 KB-isolated key BSS variables** so the watch grain matches the variable: `kernel_rsp_page` and `hb_state_count_page` are now `extern struct { x: u64, _pad: [4088]u8 } align(4096)`. Confirmed isolated via `nm`.

5. **Multi-page watch with per-page whitelists** (current state). Two slots used; two slots free.

6. **TCG instead of KVM** for tracing. `qemu -accel tcg -no-reboot -d int,cpu_reset -D qemu_int.log` makes pre-reset state visible. Already part of the standard debug routine — KVM hides too much.

## What we've ruled out

- **Stack overflow** — guard pages would catch it. They don't fire at the time of the wild writes.
- **Off-by-one in `dbg.counts[cur] += 1`** — value goes 0..64 then stops; jump to 110/114 is not from this code. Verified with disassembly and the existing whitelist.
- **`handleException` being a runaway recursion** — exception entry log lines (`[exc-entry]`) show normal #PF dispatch only.
- **Single-stepping artifact** — clamp fires whether or not TF was ever set on the relevant CPU, and on slots far from any active BS-pending watch.
- **Per-CPU GS_BASE drift / missing swapgs** — entire bug class architecturally eliminated by the per-CPU LSTAR refactor (each CPU has its own naked entry stub addressing `per_cpu_asm[N]` via RIP-relative immediate; GS_BASE is never written, swapgs is gone).
- **AP not initialising syscall MSRs** — fixed earlier; verified each CPU's LSTAR matches its own stub via `verifyMsrs`.

## What might still be in scope

- **`compiler_rt.atomics.__atomic_fetch_umin/__atomic_fetch_umax`** — Zig emits these helpers when target lacks atomic instructions of a given width, OR when atomicity is requested over an unaligned range, OR for some softfloat / 128-bit cases. The `"fetch_um"` byte sequence written at kernel_rsp is plausibly *the symbol name itself* leaking into a store. That's bizarre — it would mean a code path is doing `*ptr = some_symbol_name_string_constant_treated_as_u64` somewhere.
- **`std.fmt` / `std.debug`** stringifying a function pointer's `@typeName(@TypeOf(fn))` and emitting the bytes into a buffer that, due to a dangling pointer or misaligned write, lands in BSS. Less likely but consistent with the byte content.
- **A naked-function ABI mistake** — naked stubs that mishandle alignment / use a callee-saved register without saving could allow values to leak from `rdi`/`rsi`/`rdx` set up for a `compiler_rt` call into an unrelated store.
- **A miscompiled `@memcpy` / `memmove`** — an unaligned overlapping copy that, due to a length miscalculation or stride bug, copies bytes of an `.rodata` symbol-name string region into BSS. Zig's `compiler_rt.memcpy` is itself the candidate; the values stored come from the same translation unit.
- **Stale TLB after a CR3 switch** — a kernel-mode write to what was a user-mapped VA continues to commit through a stale entry that now points to BSS. We do a few CR3 switches in the syscall path; if any path forgets `invlpg`, this could happen. But content from an ELF symbol name in user-mapped memory is unusual.
- **A use-after-free** in a kernel object whose payload happened to contain bytes from a recently-loaded ELF's `.symtab`/`.strtab` (which we DO load into kernel buffers via `symbols.parseElfSymbols` for crash decoding). That ELF buffer is `pmm.allocContiguous`-backed and is NOT freed until process exit — but if PMM gives the same frames to another allocation while a stale pointer still lives, you get exactly this kind of "ASCII from a symbol table at random BSS address" pattern.

The last hypothesis is the most concrete: **`symbols.parseElfSymbols` reads from `elf_buf` which lives in PMM-allocated frames. If any of those frames are double-allocated to BSS-adjacent kernel allocations, kernel writes through the kernel pointer would scribble symbol-name bytes onto BSS-adjacent allocations.** We have `pmm.allocContiguous` but we have not audited its free path. The "different victim page on every run" pattern matches PMM nondeterminism.

## What we haven't done

- Audited `pmm.freeFrame` / `pmm.allocContiguous` for double-allocation bugs in the presence of mixed-size requests.
- Confirmed whether `sym_table` (per-PCB pointer into elf_buf) is ever leaked across `pmm.freeFrame` calls during process destruction. `destroyAddressSpace` runs before/after `freePmmRange(elf_buf, elf_buf_pages)` — order matters.
- Confirmed whether `KERNEL.SYM` loading reuses any PMM frames it shouldn't.
- Single-stepped the lifetime of an `elf_buf` allocation: which other allocations occur between `pmm.allocContiguous(N)` for the ELF and `freePmmRange` at process exit, and whether any of them call into PMM with a size hint that could land back in the same range.

## Files of interest (paths inside `D:\zigos-arch\src\`)
- `process.zig` — PCB, lazy regions, page-fault handler, `handleUserPageFault.dbg.counts` / `.dbg.pages`.
- `elf_loader.zig` — `loadAndStart` / `loadAndExecute`, `kernel_rsp_page` (4 KB isolated), `enterUserMode` / `returnToKernel` naked fns.
- `pmm.zig` — bitmap allocator, `allocContiguous`.
- `paging.zig` — `installGuardPage`, `installWriteWatch`, `setWriteWatchRW`, `enableCR0WriteProtect`.
- `idt.zig` — `handleException`, `WwEntry`/`ww_entries`, `armWriteWatch`, BS-bit reprotect logic.
- `symbols.zig` — `parseElfSymbols` (reads from kernel-side ELF buffer); `loadKernelSymbols` (reads `KERNEL.SYM` from FAT32 into kernel heap).
- `syscall_entry.zig` — per-CPU LSTAR entry stubs.
- `smp.zig` — per-CPU init, AP boot, per-CPU GDT/TSS/IDT.
- `fat32.zig` — `readDirEntryRaw` (the latest crasher).

## The question

Given:
- The written bytes are recognizably from `compiler_rt` symbol names (`"fetch_um"` confirmed).
- The victim addresses are scattered across kernel BSS pages (different per run).
- The legit page-fault handler's `dbg.counts` array is one of the recurring victims.
- The corruption is timed around `sysExec` for the second half of a pipe (`ls | wc`).
- No swapgs, no GS_BASE, no per-CPU TLS — that bug class is dead.
- Stack overflow is excluded (guards in place).

**What classes of bug fit this signature in a freestanding kernel?** And what would be the next single experiment that produces the highest information yield to discriminate between them — given that we can MMU-watch any 4 KB page (and have 2 slots free), can run TCG with full `-d int,cpu_reset,exec` traces, can rebuild with `-Doptimize=Debug` if the optimizer is suspected of folding evidence, and can add ad-hoc serial logging anywhere?

We particularly want to know:
1. Could a `compiler_rt` builtin (atomics, memcpy, memset, soft-float) emit the wrong store address in a known way given some Zig 0.15.2 quirk? Any documented issues that match?
2. Is there a known-bad pattern with `pmm.allocContiguous` + later per-frame `pmm.freeFrame` that could double-allocate frames into kernel BSS-adjacent regions?
3. What about the second half of a pipe — `sysExecAs` / `sysFork`-equivalent — that creates a child process: any common failure modes that resemble "free a page table the original process still references and then re-allocate it"?
4. Is there a way to detect a stale-TLB write committing into a recycled physical page, short of installing a watchpoint on every BSS page?
