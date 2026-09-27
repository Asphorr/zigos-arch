#!/usr/bin/env bash
# Off-target test runner for the kernel heap's pure TLSF core.
#
# src/mm/tlsf.zig imports only `std`, but Zig 0.15 forbids an `@import`
# that escapes the harness module path, so the live source is copied in
# beside test.zig (gitignored) on every run.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

cp "$ROOT/src/mm/tlsf.zig" "$HERE/tlsf.zig"

# Prefer $ZIG; else glob the Zig toolchain (the dir is Cyrillic "Загрузки").
ZIG="${ZIG:-$(ls ~/Заг*/zig-x86_64-linux-*/zig 2>/dev/null | head -1 || true)}"
ZIG="${ZIG:-zig}"
echo "ZIG=$ZIG"

# ReleaseSafe: keeps overflow/bounds checks, runs the random phase fast.
"$ZIG" test -O ReleaseSafe "$HERE/test.zig"
echo "EXIT=$?"
