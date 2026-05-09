#!/usr/bin/env python3
"""Generate kernel.sym binary from nm output.

Usage: nm -nS zig-out/bin/kernel.elf | grep ' [TtBbDdRr] ' | python3 gen_kernel_syms.py kernel.sym

Accepts text (T/t), BSS (B/b), data (D/d), and rodata (R/r) symbols so the
in-kernel address annotator can label BSS variables (e.g. expected_kstack_tops)
and not just functions.

Binary format:
  u32 magic = 0x53594D42 ("SYMB")
  u32 entry_count
  u32 name_pool_size
  [entry_count] x { u64 addr, u64 size, u32 name_off }
  [name_pool_size] bytes of null-terminated strings
"""
import struct
import sys

ACCEPTED_TYPES = ('T', 't', 'B', 'b', 'D', 'd', 'R', 'r')

def main():
    if len(sys.argv) < 2:
        print("Usage: nm -nS kernel.elf | grep ' [TtBbDdRr] ' | python3 gen_kernel_syms.py <output.sym>", file=sys.stderr)
        sys.exit(1)

    output = sys.argv[1]
    entries = []
    names = bytearray()

    for line in sys.stdin:
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        # nm -nS output: "addr size type name" or "addr type name"
        if len(parts) >= 4 and parts[2] in ACCEPTED_TYPES:
            addr = int(parts[0], 16)
            size = int(parts[1], 16)
            name = parts[3]
        elif len(parts) >= 3 and parts[1] in ACCEPTED_TYPES:
            addr = int(parts[0], 16)
            size = 0
            name = parts[2]
        else:
            continue

        # Truncate long names
        name = name[:63]
        name_off = len(names)
        names.extend(name.encode('ascii', errors='replace'))
        names.append(0)  # null terminator

        entries.append((addr, size, name_off))

    entry_count = len(entries)
    name_pool_size = len(names)

    with open(output, 'wb') as f:
        # Header
        f.write(struct.pack('<III', 0x53594D42, entry_count, name_pool_size))
        # Entries (already sorted by addr from nm -n)
        # SymEntry in Zig: u64 addr, u64 size, u32 name_off + 4 pad = 24 bytes
        for addr, size, name_off in entries:
            f.write(struct.pack('<QQI4x', addr, size, name_off))
        # Name pool
        f.write(bytes(names))

    print(f"Generated {output}: {entry_count} symbols, {name_pool_size} bytes names, {12 + entry_count * 24 + name_pool_size} bytes total", file=sys.stderr)

if __name__ == '__main__':
    main()
