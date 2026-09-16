#!/usr/bin/env python3
"""
Build-time inline-asm alignment linter for ZigOS.

Walks src/*.zig, finds every `asm volatile (` block, tokenizes the assembly,
counts push/pop/sub/add, and reports misalignment at any `call` instruction.

Exit 0 if all trampolines are aligned, nonzero on any failure. Invoked from
build.zig before linking — a failed linter aborts the build.

Acknowledged limitations:
- Regex parsing of asm is brittle. We only catch the obvious patterns (the
  ones that just bit us). False positives are acceptable if they force humans
  to add explicit alignment documentation.
- The runtime guards in cpu/syscall/entry.zig and idt.zig are still the
  authoritative check. This linter is a fast-fail convenience, not a proof.

History: from its birth until 2026-09-16 the block-capture regex required
every continuation line to START with `\\`, but Zig multiline-string lines
are indented — so only the first line of each block was ever captured, no
`call` was ever seen, and every build printed a vacuous PASS (found during
the FXSAVE work, when adding 512-byte saves to the trampolines should have
moved the verdict and didn't). The regex now allows leading whitespace per
line, and the self-check at the bottom of main() refuses to PASS unless the
capture actually saw multi-line blocks and at least one `call` — a linter
that inspects nothing must say so, not say PASS.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple

def parse_asm_block(asm_text: str, file_path: str, line_no: int) -> List[Tuple[str, str]]:
    """
    Tokenize an asm block into (opcode, operands) pairs.
    Returns a list of tuples: [("push", "%rax"), ("call", "doSyscall"), ...]
    """
    tokens = []
    # Split by newlines, strip leading/trailing whitespace and backslashes
    lines = [line.strip().strip('\\').strip() for line in asm_text.split('\n')]
    for line in lines:
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('#'):
            continue
        # Remove inline comments
        if '//' in line:
            line = line[:line.index('//')].strip()
        if '#' in line:
            line = line[:line.index('#')].strip()
        if not line:
            continue

        # Split into opcode and operands
        parts = line.split(None, 1)
        if not parts:
            continue
        opcode = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""
        tokens.append((opcode, operands))

    return tokens

def check_alignment(tokens: List[Tuple[str, str]], file_path: str, line_no: int) -> bool:
    """
    Walk the token stream and verify stack alignment at every `call`.
    Returns True if aligned, False + prints diagnostic on mismatch.

    Stack delta tracking:
    - push*: +8 per push
    - pop*: -8 per pop
    - sub $N, %rsp: +N
    - add $N, %rsp: -N
    - call: the call itself pushes 8 (return address), so we check that
      (delta + 8) % 16 == 0 at the call site.

    Reset points:
    - swapgs: often marks the start of a trampoline; reset delta to 0
    - Labels ending with ':' (e.g., "1:"): reset delta (new context)
    """
    delta = 0
    errors = []

    for i, (opcode, operands) in enumerate(tokens):
        # Reset on swapgs or label
        if opcode == 'swapgs' or opcode.endswith(':'):
            delta = 0
            continue

        # Track stack changes
        if opcode.startswith('push'):
            delta += 8
        elif opcode.startswith('pop'):
            delta -= 8
        elif opcode == 'sub' and ('%rsp' in operands or '%esp' in operands):
            # sub $N, %rsp
            match = re.search(r'\$(\d+|0x[0-9a-fA-F]+)', operands)
            if match:
                val_str = match.group(1)
                val = int(val_str, 16 if val_str.startswith('0x') else 10)
                delta += val
        elif opcode == 'add' and ('%rsp' in operands or '%esp' in operands):
            # add $N, %rsp
            match = re.search(r'\$(\d+|0x[0-9a-fA-F]+)', operands)
            if match:
                val_str = match.group(1)
                val = int(val_str, 16 if val_str.startswith('0x') else 10)
                delta -= val
        elif opcode == 'call':
            # Check alignment: (delta + 8) % 16 must == 0
            # The +8 accounts for the call's own return-address push.
            if (delta + 8) % 16 != 0:
                errors.append(
                    f"{file_path}:{line_no}: MISALIGNED call to '{operands}' "
                    f"(stack delta={delta}, (delta+8)%16={(delta+8)%16}, expected 0)"
                )

    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return False
    return True

# Coverage counters for the self-check in main(): a run that captured no
# multi-line block or no `call` is a run that inspected nothing.
STATS = {"blocks": 0, "multiline_blocks": 0, "calls": 0}

def lint_file(path: Path) -> bool:
    """
    Scan a single .zig file for inline asm blocks and check alignment.
    Returns True if all blocks pass, False on any failure.
    """
    text = path.read_text(encoding='utf-8', errors='ignore')

    # Find all `asm volatile (` / `asm (` blocks and capture the multi-line
    # string literal that follows: one or more lines of optional indentation,
    # `\\`, the asm text, newline. The `[ \t]*` per line is the 2026-09-16
    # fix — Zig indents continuation lines, so without it the capture ended
    # after the first line of every block (see the module docstring).
    pattern = re.compile(
        r'asm\s+(?:volatile\s+)?\(\s*'      # asm volatile ( or asm (
        r'((?:[ \t]*\\\\[^\n]*\n)+)',        # multi-line asm string (indented backslash-escaped lines)
        re.MULTILINE
    )

    all_pass = True
    for match in pattern.finditer(text):
        asm_text = match.group(1)
        # Find line number of the match
        line_no = text[:match.start()].count('\n') + 1

        STATS["blocks"] += 1
        if asm_text.count('\n') > 1:
            STATS["multiline_blocks"] += 1
        tokens = parse_asm_block(asm_text, str(path), line_no)
        STATS["calls"] += sum(1 for op, _ in tokens if op == 'call')
        if not check_alignment(tokens, str(path), line_no):
            all_pass = False

    return all_pass

def main():
    # Walk src/*.zig relative to the script location (tools/ sits beside src/).
    script_dir = Path(__file__).parent
    src_dir = script_dir.parent / 'src'

    if not src_dir.exists():
        print(f"ERROR: {src_dir} not found", file=sys.stderr)
        return 1

    zig_files = list(src_dir.rglob('*.zig'))
    if not zig_files:
        print(f"WARNING: No .zig files found in {src_dir}", file=sys.stderr)
        return 0

    print(f"[asm-lint] Checking {len(zig_files)} files in {src_dir}")

    all_pass = True
    for path in zig_files:
        if not lint_file(path):
            all_pass = False

    # Self-check: refuse a vacuous PASS. The kernel has dozens of multi-line
    # trampolines and several `call`s inside them; seeing none means the
    # capture regressed again and the verdict below would be meaningless.
    if STATS["multiline_blocks"] == 0 or STATS["calls"] == 0:
        print(
            f"[asm-lint] FAIL — vacuous run: blocks={STATS['blocks']} "
            f"multiline={STATS['multiline_blocks']} calls={STATS['calls']} "
            f"(the capture saw no trampolines; the regex has regressed)",
            file=sys.stderr,
        )
        return 1

    if all_pass:
        print(
            f"[asm-lint] PASS — all trampolines aligned "
            f"(blocks={STATS['blocks']} multiline={STATS['multiline_blocks']} calls={STATS['calls']})"
        )
        return 0
    else:
        print("[asm-lint] FAIL — see errors above", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
