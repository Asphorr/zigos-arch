#!/usr/bin/env bash
# Off-target test harness for src/bpf/ — the zBPF interpreter. See README.md.
#
#   tools/bpf-test/run.sh                                         # `zig` from PATH
#   ZIG=~/zig tools/bpf-test/run.sh                               # zigvm spelling
#
# Copies the live bpf sources in (gitignored) so the harness always tests
# current code, then runs `zig test`. Same pattern as net-test / hrtimer-test.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ZIG="${ZIG:-zig}"

mkdir -p "$HERE/src/bpf"
cp "$HERE/../../src/bpf/insn.zig" "$HERE/src/bpf/insn.zig"
cp "$HERE/../../src/bpf/vm.zig" "$HERE/src/bpf/vm.zig"
cp "$HERE/../../src/bpf/verifier.zig" "$HERE/src/bpf/verifier.zig"

cd "$HERE"
"$ZIG" test test.zig        # interpreter (M1)
"$ZIG" test verify_test.zig # verifier    (M3a/M3b unit)
"$ZIG" test fuzz_test.zig   # verifier    (M3b soundness fuzz)
echo "EXIT=$?"
