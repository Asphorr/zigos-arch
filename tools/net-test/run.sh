#!/usr/bin/env bash
# Off-target test harness for src/net/net.zig — see README.md.
#
#   tools/net-test/run.sh                                         # `zig` from PATH
#   ZIG=~/Загрузки/zig-x86_64-linux-0.15.2/zig tools/net-test/run.sh
#
# Copies the live net.zig in (gitignored) so the harness always tests current
# source, then runs `zig test` against the scripted-peer scenarios.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ZIG="${ZIG:-zig}"

mkdir -p "$HERE/src/net"
cp "$HERE/../../src/net/net.zig" "$HERE/src/net/net.zig"

cd "$HERE"
"$ZIG" test test.zig
echo "EXIT=$?"
