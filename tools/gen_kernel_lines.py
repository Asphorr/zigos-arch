#!/usr/bin/env python3
"""Generate KERNEL.LINE binary from objdump --dwarf=decodedline output.

Usage:
  objdump --dwarf=decodedline zig-out/bin/kernel.elf | LC_ALL=C python3 gen_kernel_lines.py KERNEL.LINE

The objdump tool walks the DWARF .debug_line state machine and prints one
row per line-table entry: `FILE LINE ADDR [stmt-flags]`. We collect those
into a sorted (addr, file, line) array, dedupe consecutive entries that map
to the same (file, line) — only transition points matter for lookup — and
emit a compact binary the kernel loads at boot.

Binary format:
  u32 magic = 0x4C494E45 ("LINE")
  u32 entry_count
  u32 file_pool_size
  [entry_count] x {
    u64 addr,
    u32 file_off,    # offset into file pool (null-terminated string)
    u32 line,
  }
  [file_pool_size] bytes of null-terminated filenames

Lookup: binary search for the largest entry where entry.addr <= target.
That entry's (file, line) is the source location.
"""
import os
import re
import struct
import sys

MAGIC = 0x4C494E45  # "LINE"

# Match a data line:  "filename       LINENUM    0xADDR    [trailing flags]"
# The locale of objdump may localize column headers, but the data rows are
# always the same shape: filename token (may include ./ or other path bits),
# decimal line number, hex address starting 0x, optional flags.
LINE_RE = re.compile(r"^\s*(\S+)\s+(\d+)\s+0x([0-9a-fA-F]+)")


def main():
    if len(sys.argv) < 2:
        print("Usage: objdump --dwarf=decodedline kernel.elf | LC_ALL=C python3 gen_kernel_lines.py <output>", file=sys.stderr)
        sys.exit(1)

    output = sys.argv[1]
    entries = []  # list of (addr, file, line)

    for raw in sys.stdin:
        m = LINE_RE.match(raw)
        if not m:
            continue
        fname = m.group(1)
        # Skip header rows. The header column "File name" matches LINE_RE
        # because a literal "name" parses as a filename, then column "Line
        # number" contains digits, and there's no 0x address. So that path
        # is filtered out by 0x being mandatory in the regex. But objdump
        # also prints continuation markers like "./main.zig:[++]" — those
        # have no leading address so the regex won't match. We're good.
        try:
            line = int(m.group(2))
        except ValueError:
            continue
        try:
            addr = int(m.group(3), 16)
        except ValueError:
            continue
        # Skip absurd addresses (header artifacts on some binutils versions).
        if addr < 0x80000:
            continue
        entries.append((addr, fname, line))

    if not entries:
        print("[gen_kernel_lines] WARNING: no entries parsed — empty KERNEL.LINE", file=sys.stderr)

    # Sort by address.
    entries.sort(key=lambda e: e[0])

    # Dedupe consecutive entries with identical (file, line).
    deduped = []
    last_key = None
    for addr, fname, line in entries:
        # Keep just the basename to bound file pool size — line number
        # disambiguates within a file. Last 2 path components is a sweet
        # spot if collision becomes a problem; basename is fine for MVP.
        short = os.path.basename(fname)
        key = (short, line)
        if key != last_key:
            deduped.append((addr, short, line))
            last_key = key

    # Build the file pool (deduped names).
    file_pool = bytearray()
    file_offs = {}
    for _, fname, _ in deduped:
        if fname in file_offs:
            continue
        file_offs[fname] = len(file_pool)
        file_pool.extend(fname.encode("ascii", errors="replace"))
        file_pool.append(0)

    # Emit the binary.
    with open(output, "wb") as f:
        f.write(struct.pack("<III", MAGIC, len(deduped), len(file_pool)))
        for addr, fname, line in deduped:
            f.write(struct.pack("<QII", addr, file_offs[fname], line))
        f.write(bytes(file_pool))

    print(f"[gen_kernel_lines] {len(deduped)} entries, {len(file_offs)} files, {len(file_pool)} bytes name pool, output {os.path.getsize(output)} bytes", file=sys.stderr)


if __name__ == "__main__":
    main()
