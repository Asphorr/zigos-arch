#!/usr/bin/env python3
"""DDLC recon — RPA-3.0 inventory + .rpyc opcode histogram.

This script does NOT execute any pickle data. It walks the raw pickle
bytecode and tallies GLOBAL/STACK_GLOBAL opcode operands — those name
the Ren'Py AST classes used by the compiled scripts. The output tells
us which subset of Ren'Py's ~200 AST node types DDLC actually needs.

Usage:
    python recon.py path/to/scripts.rpa
"""

import io
import pickle
import pickletools
import struct
import sys
import zlib
from collections import Counter
from pathlib import Path


# ---- .rpa-3.0 reader -------------------------------------------------------

def rpa_open(path: Path):
    """Yield (filename, content_bytes) for each entry in an RPA-3.0 archive."""
    with path.open("rb") as f:
        header = f.readline().decode("ascii", errors="replace").strip()
        parts = header.split()
        if parts[0] != "RPA-3.0":
            raise ValueError(f"not RPA-3.0: {parts[0]}")
        index_offset = int(parts[1], 16)
        key = int(parts[2], 16)

        f.seek(index_offset)
        index_blob = zlib.decompress(f.read())
        index = pickle.loads(index_blob)

        for filename, entries in index.items():
            chunks = []
            for entry in entries:
                # Two formats observed: (offset, length, prefix) or
                # (offset, length). prefix is raw bytes prepended to the
                # data; offset/length get XOR'd with the key.
                if len(entry) == 3:
                    off, length, prefix = entry
                else:
                    off, length = entry
                    prefix = b""
                # Older RPA-2 wrote prefix as a str; coerce to bytes.
                if isinstance(prefix, str):
                    prefix = prefix.encode("latin-1")
                real_off = off ^ key
                real_len = length ^ key
                f.seek(real_off)
                chunks.append(prefix + f.read(real_len - len(prefix)))
            yield filename, b"".join(chunks)


# ---- .rpyc decoder ---------------------------------------------------------
#
# Ren'Py .rpyc-2 format (used by DDLC 1.1.1):
#   - 10-byte magic "RENPY RPC2"
#   - Repeated slot table: u32 slot_id, u32 offset, u32 length
#     (terminated by slot_id == 0)
#   - Then concatenated slot blobs at the given offsets, each zlib-compressed
#
# Slot 1 = the script (a Python pickle of a list of AST statements).
# Slot 2 = the source-file path mapping.
# We only care about slot 1.

def rpyc_extract_script_pickle(data: bytes) -> bytes | None:
    if data[:10] != b"RENPY RPC2":
        # Older format: whole file is one zlib-compressed pickle.
        try:
            return zlib.decompress(data)
        except zlib.error:
            return None
    pos = 10
    slots = []  # (slot_id, offset, length)
    while True:
        if pos + 12 > len(data):
            return None
        slot_id, offset, length = struct.unpack("<III", data[pos:pos+12])
        pos += 12
        if slot_id == 0:
            break
        slots.append((slot_id, offset, length))
    for slot_id, offset, length in slots:
        if slot_id == 1:
            return zlib.decompress(data[offset:offset+length])
    return None


# ---- Pickle bytecode walker (no execution) --------------------------------

def tally_classes(pickle_bytes: bytes, counter: Counter) -> None:
    """Walk pickle ops; count every (module, classname) seen in GLOBAL/STACK_GLOBAL.

    Tracks both the immediate GLOBAL operand (legacy pickle proto 0/1) and
    the (module, name) pair pushed via SHORT_BINUNICODE before STACK_GLOBAL
    (proto 4+).
    """
    # pickletools.genops yields (opcode_descriptor, arg, position).
    string_stack: list[str] = []
    for op, arg, _pos in pickletools.genops(pickle_bytes):
        name = op.name
        if name == "GLOBAL":
            # arg is "module classname"
            if isinstance(arg, str) and " " in arg:
                mod, cls = arg.split(" ", 1)
                counter[f"{mod}.{cls}"] += 1
        elif name == "STACK_GLOBAL":
            # Two unicode strings pushed before this op; consume them.
            if len(string_stack) >= 2:
                cls = string_stack.pop()
                mod = string_stack.pop()
                counter[f"{mod}.{cls}"] += 1
        elif name in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE"):
            if isinstance(arg, str):
                string_stack.append(arg)
        elif name == "MEMOIZE":
            pass  # doesn't pop the value, so keep stack as-is
        else:
            # Approximation: most other ops consume their operands, but for
            # this purpose only ordering of GLOBAL pairs matters. Clearing
            # the string stack on any non-string-pushing op overcounts —
            # leave the stack alone; STACK_GLOBAL will pop the top two
            # whether or not they were the immediately-prior pushes.
            pass


# ---- Main ------------------------------------------------------------------

def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} path/to/scripts.rpa", file=sys.stderr)
        return 1
    rpa = Path(sys.argv[1])
    if not rpa.exists():
        print(f"not found: {rpa}", file=sys.stderr)
        return 1

    print(f"# Recon: {rpa}")
    counter: Counter[str] = Counter()
    file_count = 0
    rpyc_count = 0
    fail_count = 0
    total_bytes = 0

    for name, content in rpa_open(rpa):
        file_count += 1
        total_bytes += len(content)
        if name.endswith(".rpyc") or name.endswith(".rpymc"):
            rpyc_count += 1
            script = rpyc_extract_script_pickle(content)
            if script is None:
                fail_count += 1
                continue
            try:
                tally_classes(script, counter)
            except Exception as e:
                fail_count += 1
                print(f"# fail: {name}: {e}", file=sys.stderr)

    print(f"# files:   {file_count}")
    print(f"# .rpyc:   {rpyc_count}   (decode-failed: {fail_count})")
    print(f"# bytes:   {total_bytes:,}")
    print(f"# unique class instantiations seen: {len(counter)}")
    print()
    print(f"# count    class")
    print(f"# -----    -----")
    for cls, n in counter.most_common():
        print(f"{n:>8}    {cls}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
