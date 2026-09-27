#!/usr/bin/env python3
"""Check every inline asm in an LLVM bitcode file against its return type.

Zig 0.15.2 builds an asm's return struct over ALL outputs but fills only
the register ones: an asm with >=2 register outputs and any `=m` output gets
struct fields typed from uninitialized compiler memory. LLVM's reader
rejects it ("Invalid type") only when the garbage points forward in the
type table; otherwise it is accepted — and `opt -passes=verify` says
nothing. This reads `llvm-bcanalyzer -dump` and compares, for each
INLINEASM record, the number of direct (`=` but not `=*`) outputs in its
constraint string with the field count of its function type's return.

Usage: zig build --verbose-llvm-bc=/tmp/k.bc ...   (kernel compile only)
       tools/asm_ret_check.py /tmp/k.bc [llvm-bcanalyzer]
Exit 0 = all consistent, 1 = mismatch found, 2 = usage/tool error.
"""
import re
import subprocess
import sys

OPS = re.compile(r"op\d+=(-?\d+)")
TYPE_DEFINERS_SKIP = {"NUMENTRY", "STRUCT_NAME"}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    tool = sys.argv[2] if len(sys.argv) > 2 else "/usr/lib/llvm-20/bin/llvm-bcanalyzer"
    proc = subprocess.Popen([tool, "-dump", sys.argv[1]], stdout=subprocess.PIPE, text=True, errors="replace")
    types: list[tuple[str, list[int]]] = []
    in_types = False
    bad = checked = 0
    for line in proc.stdout:
        s = line.strip()
        if s.startswith("<TYPE_BLOCK_ID"):
            in_types = True
            continue
        if s.startswith("</TYPE_BLOCK_ID"):
            in_types = False
            continue
        m = re.match(r"<([A-Za-z0-9_]+)", s)
        if not m:
            continue
        rec = m.group(1)
        if in_types:
            if rec not in TYPE_DEFINERS_SKIP:
                types.append((rec, [int(x) for x in OPS.findall(s)]))
            continue
        if rec != "INLINEASM":
            continue
        ops = [int(x) for x in OPS.findall(s)]
        fnty, n = ops[0], ops[2]
        asm = bytes(ops[3:3 + n]).decode(errors="replace")
        cn = ops[3 + n]
        cons = bytes(ops[4 + n:4 + n + cn]).decode(errors="replace")
        direct = sum(1 for c in cons.split(",") if c.startswith("=") and not c.startswith("=*"))
        kind, fops = types[fnty]
        if kind != "FUNCTION":
            print(f"asm type {fnty} is {kind}, not FUNCTION")
            bad += 1
            continue
        ret = fops[1]
        rkind, rops = types[ret] if ret < len(types) else ("FORWARD-REF", [])
        fields = len(rops) - 1 if rkind == "STRUCT_ANON" else (0 if rkind == "VOID" else 1)
        checked += 1
        if direct >= 2 and fields != direct or direct < 2 and rkind == "STRUCT_ANON" and direct != fields:
            bad += 1
            first = asm.strip().splitlines()[0] if asm.strip() else "(empty)"
            print(f"MISMATCH: {direct} register outputs, return type {ret} = {rkind}{rops[1:]} ({fields} fields)")
            print(f"  constraints: {cons}")
            print(f"  asm first line: {first}")
    proc.wait()
    print(f"[asm-ret-check] {checked} inline asm checked, {bad} mismatched, {len(types)} types")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
