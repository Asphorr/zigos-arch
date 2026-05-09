#!/usr/bin/env python3
"""
KCSAN attribute injector for the LLVM IR-pass kernel pipeline.

Mirror of kasan_inject.py but applies `sanitize_thread` instead of
`sanitize_address`. Functions tagged with `sanitize_thread` are visited by
LLVM's ThreadSanitizer pass (`-passes='tsan'`), which inserts calls to
`__tsan_read{1,2,4,8,16}` and `__tsan_write{1,2,4,8,16}` at every memory
access. Our runtime (src/debug/kcsan.zig) implements those callbacks using
the watchpoint protocol — read addr, register a per-CPU watchpoint, pause,
re-read; if the value changed during the window OR if another instrumented
CPU's access lands in our watchpoint range, log a concurrent-access race.

Compared to KASAN, the denylist must additionally exclude:
  - The KCSAN runtime itself (recursion).
  - Code paths that legitimately read shared state without synchronization
    (per-CPU current/idle pointers — we KNOW these race; reporting them is
    just noise).
  - Atomic-heavy modules where we want our own atomic primitives, not the
    compiler's tsan_atomic* shims.

Usage:  kcsan_inject.py <input.ll> <output.ll>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


# Source files whose functions must NOT be instrumented. KCSAN's denylist
# is a superset of KASAN's because tsan instrumentation runs on every load
# AND every store, including ones that are legitimately racy by design
# (per-CPU current pointer reads from IRQ context, etc.).
DENYLIST: set[str] = {
    # KCSAN/KASAN runtime + report path. Same recursion concerns as KASAN.
    "kcsan.zig",
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

    # Memory subsystem — runs before kcsan.init().
    "pmm.zig",
    "paging.zig",
    "vmm.zig",
    "memmap.zig",
    "heap.zig",

    # Top-level kernel entry — runs before kcsan.init().
    "main.zig",
    "boot_info.zig",
    "uefi_boot.zig",
    "apic.zig",

    # Inline-asm-heavy modules. Same reasoning as KASAN: arg pointers can
    # legitimately reference TSS/per_cpu_asm structures outside the watch
    # set; bogus instrumentation noise.
    "idt.zig",
    "syscall_entry.zig",
    "sched_asm.zig",
    "smp.zig",
    "gdt.zig",
    "tss.zig",
    "fp.zig",
    "io.zig",
    "spinlock.zig",

    # Drivers — MMIO at high physical addresses, plus they don't share
    # state with userspace-relevant code paths the way scheduler/IPC does.
    # Skipping cuts instrumentation cost without sacrificing coverage.
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

    # Time / IRQ controllers.
    "hpet.zig",
    "msix.zig",
    "pic.zig",
    "pit.zig",
    "rtc.zig",
    "time.zig",
    "acpi.zig",
    "ioapic.zig",

    # KCSAN-SPECIFIC additions: hot paths whose instrumentation cost makes
    # the OS unusable. Each memory access here becomes a __tsan_call —
    # schedule() runs every IRQ and reads/writes dozens of shared fields,
    # so leaving it instrumented multiplies schedule's wall cost ~50×
    # (observed: 11.7M cycles mean per call vs. normal ~200k).
    #
    # Trade-off: we lose direct race detection for code IN process.zig /
    # scheduler.zig, but races in OTHER modules that touch scheduler-
    # managed shared state will still trip via cross-CPU watchpoints
    # (the watchpoints themselves don't care which file the access is in).
    "process.zig",
    "scheduler.zig",
    # Frequently-called helpers from the IRQ path.
    "iretq_canary.zig",
}


FUNC_DEFINE_RE = re.compile(
    r"^(define\s+(?:dso_local\s+)?(?:internal\s+)?(?:weak\s+)?(?:linkonce_odr\s+)?[^@]*?@[^(]+\([^)]*\)[^{]*?)(\s*!dbg\s+!(\d+))?(\s*{)\s*$"
)
DIFILE_RE = re.compile(r'!DIFile\(filename:\s*"([^"]+)"(?:.*directory:\s*"([^"]+)")?')
DISUBPROGRAM_RE = re.compile(r"!DISubprogram\([^)]*?\bfile:\s*!(\d+)")


# Only instrument files whose path contains one of these substrings. This
# excludes Zig's stdlib (which lives under /opt/zig-*/lib/std/) — instrumenting
# fmt.zig + Writer.zig + ArrayList.zig etc. inflates the kernel by 100s of KB
# of __tsan_* calls and pushes it past USER_LOAD_BASE. Project-only
# instrumentation is what matters for race hunting; stdlib is well-tested.
PATH_ALLOWLIST: tuple[str, ...] = (
    "zigos-arch/src/",
    "zigos-arch/lib/",
    "zigos-arch\\src\\",
    "zigos-arch\\lib\\",
)


def build_metadata_index(text: str) -> tuple[dict[int, dict], dict[int, dict]]:
    di_subs: dict[int, dict] = {}
    di_files: dict[int, dict] = {}  # node_id -> {basename, full_path}
    for line in text.splitlines():
        if not line.startswith("!"):
            continue
        m = re.match(r"^!(\d+)\s*=\s*distinct?\s*!DISubprogram\(", line)
        if m:
            node_id = int(m.group(1))
            file_m = DISUBPROGRAM_RE.search(line)
            if file_m:
                di_subs[node_id] = {"file": int(file_m.group(1))}
            continue
        m = re.match(r"^!(\d+)\s*=\s*!DIFile\(", line)
        if m:
            node_id = int(m.group(1))
            f = DIFILE_RE.search(line)
            if f:
                filename = f.group(1)
                directory = f.group(2) or ""
                full_path = f"{directory}/{filename}" if directory else filename
                di_files[node_id] = {
                    "basename": Path(filename).name,
                    "full_path": full_path,
                }
    return di_subs, di_files


def function_source(line: str, di_subs: dict, di_files: dict) -> dict | None:
    m = FUNC_DEFINE_RE.match(line)
    if not m or not m.group(2):
        return None
    sub_id = int(m.group(3))
    sub = di_subs.get(sub_id)
    if not sub:
        return None
    return di_files.get(sub["file"])


def is_project_path(full_path: str) -> bool:
    return any(allow in full_path for allow in PATH_ALLOWLIST)


def inject(text: str) -> tuple[str, int, int]:
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
        if " sanitize_thread " in line or " no_sanitize_thread " in line or "naked" in line:
            out_lines.append(line)
            continue
        src = function_source(line.rstrip("\n"), di_subs, di_files)
        if src is None:
            out_lines.append(line)
            continue
        # Project-only filter: if the source path doesn't live under our
        # zigos-arch/src/ or zigos-arch/lib/, skip instrumentation. Stdlib
        # files (std.fmt, std.io.Writer, std.ArrayList) are excluded this way.
        if not is_project_path(src["full_path"]):
            out_lines.append(line)
            continue
        if src["basename"] in DENYLIST:
            out_lines.append(line)
            continue
        head, dbg, _dbg_id, tail = m.group(1), m.group(2) or "", m.group(3), m.group(4)
        new_line = f"{head} sanitize_thread{dbg}{tail}\n"
        out_lines.append(new_line)
        instrumented += 1
    return "".join(out_lines), total, instrumented


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: kcsan_inject.py <input.ll> <output.ll>", file=sys.stderr)
        return 2
    inp = Path(sys.argv[1])
    outp = Path(sys.argv[2])
    text = inp.read_text()
    new_text, total, inst = inject(text)
    outp.write_text(new_text)
    print(f"[kcsan_inject] {inst}/{total} functions tagged sanitize_thread")
    print(f"[kcsan_inject] denylist active: {len(DENYLIST)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
