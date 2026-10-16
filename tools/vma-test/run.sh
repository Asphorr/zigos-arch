#!/usr/bin/env bash
# Off-target test runner for the user address-space region set.
#
# src/mm/vma.zig imports only `std`, but Zig 0.15 forbids an `@import`
# that escapes the harness module path, so the live source is copied in
# beside test.zig (gitignored) on every run.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

cp "$ROOT/src/mm/vma.zig" "$HERE/vma.zig"

ZIG="${ZIG:-$(ls ~/Заг*/zig-x86_64-linux-*/zig 2>/dev/null | head -1 || true)}"
ZIG="${ZIG:-zig}"
echo "ZIG=$ZIG"

"$ZIG" test -O ReleaseSafe "$HERE/test.zig"
echo "EXIT=$?"
