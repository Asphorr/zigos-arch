#!/usr/bin/env bash
# Build the kernel through the LLVM IR-pass KCSAN pipeline.
#
# Mirror of kasan_pipeline.sh but uses the ThreadSanitizer pass with kernel-
# friendly options. The compiler emits calls to __tsan_read{1,2,4,8,16} and
# __tsan_write{1,2,4,8,16} at every memory access in tagged functions. Our
# runtime (src/debug/kcsan.zig) implements those callbacks with the
# watchpoint protocol — sample → register → pause → resample → race-detect.
#
# Pipeline stages:
#   1) zig build-obj   →  kernel-pre.ll  (whole-module LLVM IR for src/main.zig)
#   2) kcsan_inject.py →  kernel-tagged.ll  (sanitize_thread on allowlist)
#   3) llvm-as-20      →  kernel-tagged.bc
#   4) opt-20          →  kernel-tsan.bc  (tsan with kernel-friendly options)
#   5) llc-20          →  kernel-tsan.o
#   6) ld              →  kernel.elf
#
# tsan options used (matching Linux KCSAN config):
#   - default memory-access instrumentation: ON (the entire point)
#   - func-entry-exit instrumentation: OFF (we don't track happens-before;
#     skipping saves ~30% of the call overhead)
#   - atomics instrumentation: OFF (we have our own atomic ops; tsan_atomic*
#     would just add unbounded recursion through kernel synchronization
#     primitives without giving us new info)
#
# Usage:  kcsan_pipeline.sh <zig> <optimize> <out_dir>

set -euo pipefail

ZIG="${1:?missing zig path}"
OPT_LEVEL="${2:?missing optimize level}"
OUT_DIR="${3:?missing out_dir}"

mkdir -p "$OUT_DIR"
WORK="$OUT_DIR/kcsan-work"
mkdir -p "$WORK"

echo "[kcsan] stage 1/6: zig build-obj → IR"
cat > "$WORK/build_options.zig" <<'BOEOF'
pub const build_id: u64 = 0;
pub const kcsan_enabled: bool = true;
BOEOF

"$ZIG" build-obj \
    -target x86_64-freestanding-none \
    -O "$OPT_LEVEL" \
    -fno-emit-bin \
    -femit-llvm-ir="$WORK/kernel-pre.ll" \
    --dep build_options \
    -Mroot=src/main.zig \
    -Mbuild_options="$WORK/build_options.zig" 2>&1 | sed 's/^/  /' || {
    echo "[kcsan] FATAL: zig build-obj failed"
    exit 1
}

echo "[kcsan] stage 2/6: inject sanitize_thread (allowlist)"
python3 tools/kcsan_inject.py "$WORK/kernel-pre.ll" "$WORK/kernel-tagged.ll"

echo "[kcsan] stage 3/6: llvm-as-20"
llvm-as-20 "$WORK/kernel-tagged.ll" -o "$WORK/kernel-tagged.bc"

echo "[kcsan] stage 4/6: opt-20 -passes=tsan"
opt-20 \
    -passes='tsan-module,function(tsan)' \
    --tsan-instrument-func-entry-exit=false \
    --tsan-instrument-atomics=false \
    --tsan-instrument-memintrinsics=true \
    --tsan-distinguish-volatile=true \
    "$WORK/kernel-tagged.bc" \
    -o "$WORK/kernel-tsan.bc"

echo "[kcsan] stage 5/6: llc-20 → kernel-tsan.o"
llc-20 \
    -filetype=obj \
    -relocation-model=static \
    -code-model=kernel \
    "$WORK/kernel-tsan.bc" \
    -o "$WORK/kernel-tsan.o"

echo "[kcsan] stage 6/6: ld → kernel.elf"
nasm -f elf64 src/boot/boot.asm -o "$WORK/boot.o"
nasm -f elf64 src/boot/ap_trampoline.asm -o "$WORK/ap_trampoline.o"

ld -T src/linker.ld -nostdlib \
    "$WORK/boot.o" \
    "$WORK/ap_trampoline.o" \
    "$WORK/kernel-tsan.o" \
    -o "$OUT_DIR/kernel.elf"

objcopy -I elf64-x86-64 -O elf32-i386 "$OUT_DIR/kernel.elf" "$OUT_DIR/kernel32.elf"

echo "[kcsan] DONE: $OUT_DIR/kernel.elf, $OUT_DIR/kernel32.elf"
ls -la "$OUT_DIR/kernel.elf" "$OUT_DIR/kernel32.elf"
