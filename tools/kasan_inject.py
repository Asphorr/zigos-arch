#!/usr/bin/env python3
"""
KASAN attribute injector for the LLVM IR-pass kernel pipeline.

Reads a textual LLVM IR file (.ll), determines each function's source file
from its `!dbg` metadata, and inserts `sanitize_address` into the function's
header for every function whose source file is NOT on the denylist below.

Functions on the denylist (early boot + KASAN runtime + their hot
dependencies) stay un-instrumented. They run before kasan.init() finishes
wiring up the shadow region, or are themselves part of that wiring.

Usage:  kasan_inject.py <input.ll> <output.ll>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# Source files whose functions must NOT be instrumented. Match is by basename
# of the path stored in `!DIFile`. Add a file here when KASAN trips on it
# during early boot (before kasan.init()) or when the function itself is part
# of the shadow / report path (recursive trip).
DENYLIST: set[str] = {
    # KASAN itself + report path. The crash-dump path (disasm, gdb_stub, lbr,
    # perf, abi_check) reads memory at "wild" addresses to format diagnostics
    # — the moment we instrument those, a phantom KASAN trip eats the actual
    # wild-pointer report we care about.
    "kasan.zig",
    "debug.zig",
    "kdbg.zig",
    "symbols.zig",
    "watch.zig",
    "kernel_builtins.zig",
    "serial.zig",
    "disasm.zig",
    "gdb_stub.zig",
    "lbr.zig",
    "perf.zig",
    "abi_check.zig",
    # Shadow allocation + identity map (run before kasan.init())
    "pmm.zig",
    "paging.zig",
    "vmm.zig",
    "memmap.zig",
    # Heap allocator: kmallocAligned walks the freelist by reading
    # `block.next` at offset 8; kfree backward-scans through allocated
    # blocks. Both legitimately read AllocHeader bytes that allocHook has
    # poisoned RED_ZONE. Instrumenting heap.zig itself trips on every
    # alloc/free traversal; clients of heap remain instrumented.
    "heap.zig",
    # APIC — serial.print uses getLapicId()
    "apic.zig",
    # Top-level kernel entry — runs before kasan.init()
    "main.zig",
    "boot_info.zig",
    "uefi_boot.zig",
    # Early-boot helpers called between [boot] UEFI entry and kasan.init().
    # All of these run while the KASAN shadow region is still uninitialised
    # (shadow_offset == 0), so any instrumented load/store immediately reads
    # poison from address 0 and reports a false trip.
    "uefi_nvram.zig",
    "cmdline.zig",
    "boot_phase.zig",
    "multiboot.zig",
    "early_fb.zig",
    "boot_log.zig",
    "cpuid_info.zig",
    "protect.zig",
    "mce.zig",
    "mwait.zig",
    "pmu.zig",
    "vga.zig",
    # KCSAN runtime — installed in the same Phase 2 block as kasan.init();
    # its callbacks run from instrumented code paths and would recurse.
    "kcsan.zig",
    # Zig stdlib pieces pulled into the kernel by even trivial code paths.
    # Every `serial.print("... {d} ...", ...)` reaches std.fmt.format;
    # @memcpy/@memset lower to std.mem helpers; Allocator/Writer glue is
    # everywhere. All of these run before kasan.init() the first time we
    # print anything formatted. Basename match also covers our own
    # src/lib/* shims if they exist.
    "fmt.zig",
    "mem.zig",
    "Allocator.zig",
    "Writer.zig",
    "Reader.zig",
    "builtin.zig",
    "atomic.zig",
    "DeprecatedReader.zig",
    "fixed_buffer_stream.zig",
    "File.zig",
    # Same idea for our own pre-init shims that print or allocate.
    "panic_handler.zig",
    # boot_log.banner() reaches into boot_screen.init() and the gfx/font/theme
    # helpers that paint the splash. All called before kasan.init().
    "boot_screen.zig",
    "gfx.zig",
    "theme.zig",
    "icons.zig",
    "font8x16.zig",
    "font16x32.zig",
    "aa_font.zig",
    # ALL crash/autopsy path files — once a phantom KASAN trip happens
    # pre-init, the panic handler itself recurses through these and the
    # trip becomes an infinite reboot loop. Caught with breadcrumb.dump
    # at the top of an unbounded crashAutopsy → handleException →
    # isr_common_exc cycle 2026-05-24.
    "breadcrumb.zig",
    "addrinfo.zig",
    "cpu_alias.zig",
    "cpu_struct_hash.zig",
    "diag.zig",
    "dwarf_line.zig",
    "exectrail.zig",
    "iretq_canary.zig",
    "panic_screen.zig",
    "pcb_invariants.zig",
    "pid_act.zig",
    "pid_trace.zig",
    "save_trace.zig",
    "stack_alias.zig",
    "syscall_perf.zig",
    "watchdog.zig",
    "yield_loop.zig",
    # Inline-asm-heavy modules. The asan pass leaves asm alone, but the Zig
    # wrappers around the asm sometimes have arg pointers that legitimately
    # point at TSS / per_cpu_asm — outside [REGION_LO, REGION_HI), bogus
    # shadow lookup.
    "idt.zig",
    "entry.zig", # cpu/syscall/entry.zig — LSTAR asm trampoline
    "sched_asm.zig",
    "smp.zig",
    "gdt.zig",
    "tss.zig",
    "fp.zig",
    "io.zig",
    "spinlock.zig",
    # Drivers — touch MMIO at high physical addresses (LAPIC 0xFEE00000,
    # PCI BARs around 0xF0000000, virtio SHM BAR ≥ 4 GB under UEFI).
    # Shadow lookup for an address that high lands outside the 32 MB shadow
    # region and reads random memory → phantom KASAN trip.
    "ata.zig",
    "ahci.zig",
    "nvme.zig",
    "block.zig",
    "pci.zig",
    "xhci.zig",
    "keyboard.zig",
    "mouse.zig",
    "virtio_gpu.zig",
    "virtio_net.zig",
    "virtio_sound.zig",
    "ac97.zig",
    "sound.zig",
    "speaker.zig",
    "e1000.zig",
    "nic.zig",
    "net.zig",
    # Time / IRQ controllers — all MMIO-heavy.
    "hpet.zig",
    "msix.zig",
    "pic.zig",
    "pit.zig",
    "rtc.zig",
    "time.zig",
    "acpi.zig",
    "ioapic.zig",
    "iommu.zig",
    # Process / scheduler — called from IRQ entry where a phantom KASAN trip
    # would recurse forever before the IRQ stub completes. Plus they touch
    # PCB structures whose pointers we don't fully cover.
    "process.zig",
    "scheduler.zig",
    # process.zig was split 2026-05-23 into lifecycle/sched/fault siblings;
    # they share the same IRQ-entry constraints as the parent and used to
    # be part of the single process.zig denylist entry.
    "lifecycle.zig",
    "sched.zig",
    "fault.zig",
    "runqueue.zig",
    "signals.zig",
    "elf_loader.zig",
    "pipe.zig",
    "errno.zig",
    # mm siblings to the already-denylisted core allocator files. These are
    # called from IRQ paths and from kasan.init itself (vmm.allocContiguous).
    "slab.zig",
    "shm.zig",
    "swap.zig",
}


FUNC_DEFINE_RE = re.compile(
    r"^(define\s+(?:dso_local\s+)?(?:internal\s+)?(?:weak\s+)?(?:linkonce_odr\s+)?[^@]*?@[^(]+\([^)]*\)[^{]*?)(\s*!dbg\s+!(\d+))?(\s*{)\s*$"
)
DIFILE_RE = re.compile(r'!DIFile\(filename:\s*"([^"]+)"')
DISUBPROGRAM_RE = re.compile(r"!DISubprogram\([^)]*?\bfile:\s*!(\d+)")


def build_metadata_index(text: str) -> tuple[dict[int, dict], dict[int, str]]:
    """
    Walk all `!N = ...` metadata lines once and build:
      - di_subprograms: map !N -> {'file': !M} for every DISubprogram
      - di_files:       map !M -> filename basename
    """
    di_subs: dict[int, dict] = {}
    di_files: dict[int, str] = {}

    for line in text.splitlines():
        if not line.startswith("!"):
            continue
        # !N = !DISubprogram(... file: !M ...)
        m = re.match(r"^!(\d+)\s*=\s*distinct?\s*!DISubprogram\(", line)
        if m:
            node_id = int(m.group(1))
            file_m = DISUBPROGRAM_RE.search(line)
            if file_m:
                di_subs[node_id] = {"file": int(file_m.group(1))}
            continue
        # !M = !DIFile(filename: "...", ...)
        m = re.match(r"^!(\d+)\s*=\s*!DIFile\(", line)
        if m:
            node_id = int(m.group(1))
            f = DIFILE_RE.search(line)
            if f:
                di_files[node_id] = Path(f.group(1)).name

    return di_subs, di_files


def function_source(line: str, di_subs: dict, di_files: dict) -> str | None:
    """Return the basename of the source file for a `define` line, or None."""
    m = FUNC_DEFINE_RE.match(line)
    if not m or not m.group(2):
        return None
    sub_id = int(m.group(3))
    sub = di_subs.get(sub_id)
    if not sub:
        return None
    return di_files.get(sub["file"])


def inject(text: str) -> tuple[str, int, int]:
    """Add `sanitize_address` to every non-denylisted function's header.

    Returns (transformed_text, total_funcs, instrumented_funcs).
    """
    di_subs, di_files = build_metadata_index(text)

    out_lines: list[str] = []
    total = 0
    instrumented = 0

    for line in text.splitlines(keepends=True):
        if not line.startswith("define "):
            out_lines.append(line)
            continue

        total += 1
        m = FUNC_DEFINE_RE.match(line.rstrip("\n"))
        if not m:
            out_lines.append(line)
            continue

        # Skip naked / internal stubs already with no_sanitize_address.
        if " sanitize_address " in line or " no_sanitize_address " in line or "naked" in line:
            out_lines.append(line)
            continue

        src = function_source(line.rstrip("\n"), di_subs, di_files)
        if src is None or src in DENYLIST:
            out_lines.append(line)
            continue

        # Insert ` sanitize_address` right before the trailing `{`.
        # Group 1 = head (up to but not including the `!dbg` or `{`).
        # Group 2 = optional `!dbg !N`.
        # Group 4 = trailing whitespace + `{`.
        head, dbg, _dbg_id, tail = m.group(1), m.group(2) or "", m.group(3), m.group(4)
        new_line = f"{head} sanitize_address{dbg}{tail}\n"
        out_lines.append(new_line)
        instrumented += 1

    return "".join(out_lines), total, instrumented


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: kasan_inject.py <input.ll> <output.ll>", file=sys.stderr)
        return 2

    inp = Path(sys.argv[1])
    outp = Path(sys.argv[2])

    text = inp.read_text()
    new_text, total, inst = inject(text)
    outp.write_text(new_text)

    print(f"[kasan_inject] {inst}/{total} functions tagged sanitize_address")
    print(f"[kasan_inject] denylist active: {len(DENYLIST)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
