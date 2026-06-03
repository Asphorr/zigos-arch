#!/usr/bin/env bash
# Off-target test runner for the hrtimer pure-arithmetic module (#1006).
#
# src/proc/hrtimer.zig imports only `std` (no kernel deps), so unlike
# tools/net-test there are no stub modules — but Zig 0.15 forbids an `@import`
# that escapes the harness module path, so we copy the live source in beside
# test.zig (gitignored) and import it locally. The copy keeps us testing current
# source on every run.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

cp "$ROOT/src/proc/hrtimer.zig" "$HERE/hrtimer.zig"

# Prefer $ZIG; else glob the Zig toolchain (the dir is Cyrillic "Загрузки").
ZIG="${ZIG:-$(ls ~/Заг*/zig-x86_64-linux-*/zig 2>/dev/null | head -1 || true)}"
ZIG="${ZIG:-zig}"
echo "ZIG=$ZIG"

"$ZIG" test "$HERE/test.zig"
echo "EXIT=$?"
