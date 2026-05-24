#!/usr/bin/env bash
# Build the kernel through the LLVM IR-pass KASAN pipeline.
#
# Pipeline stages:
#   1) zig build-obj   →  kernel-pre.ll  (whole-module LLVM IR for src/main.zig)
#   2) kasan_inject.py →  kernel-tagged.ll  (sanitize_address on allowlist)
#   3) llvm-as-20      →  kernel-tagged.bc
#   4) opt-20          →  kernel-asan.bc  (asan<kernel> + dynamic shadow)
#   5) llc-20          →  kernel-asan.o
#   6) ld              →  kernel.elf  (links boot.o + ap_trampoline.o + kernel-asan.o)
#
# Outputs land in zig-out/bin/ matching the regular build's layout, so the
# downstream `mksym`, `disk`, `tar`, `objcopy` steps don't need to change.
#
# Required tools on $PATH:
#   - zig (the same version build.zig uses)
#   - python3, opt-20, llvm-as-20, llc-20, ld
#
# Usage:  kasan_pipeline.sh <zig> <optimize> <out_dir>
#   <zig>       absolute path to the zig binary
#   <optimize>  ReleaseSafe | Debug | ReleaseFast
#   <out_dir>   where kernel.elf lands (typically zig-out/bin)

set -euo pipefail

ZIG="${1:?missing zig path}"
OPT_LEVEL="${2:?missing optimize level}"
OUT_DIR="${3:?missing out_dir}"

mkdir -p "$OUT_DIR"
WORK="$OUT_DIR/kasan-work"
mkdir -p "$WORK"

echo "[kasan] stage 1/6: zig build-obj → IR"
# Generate a stub build_options module — kernel @imports it. The real build
# passes a freshly-generated build_id; for KASAN builds we don't care about
# tar/elf matching, so 0 is fine.
cat > "$WORK/build_options.zig" <<'BOEOF'
pub const build_id: u64 = 0;
pub const kcsan_enabled: bool = false;
pub const kasan_enabled: bool = true;
BOEOF

"$ZIG" build-obj \
    -target x86_64-freestanding-none \
    -mcmodel kernel \
    -O "$OPT_LEVEL" \
    -fno-emit-bin \
    -femit-llvm-ir="$WORK/kernel-pre.ll" \
    --dep build_options \
    --dep shapes \
    --dep font_blobs \
    --dep uefi_layout \
    -Mroot=src/main.zig \
    -Mbuild_options="$WORK/build_options.zig" \
    -Mshapes=lib/shapes.zig \
    -Mfont_blobs=lib/font_blobs.zig \
    -Muefi_layout=lib/uefi_layout.zig 2>&1 | sed 's/^/  /' || {
    echo "[kasan] FATAL: zig build-obj failed"
    exit 1
}

echo "[kasan] stage 2/6: inject sanitize_address (allowlist)"
python3 tools/kasan_inject.py "$WORK/kernel-pre.ll" "$WORK/kernel-tagged.ll"

echo "[kasan] stage 3/6: llvm-as-20"
llvm-as-20 "$WORK/kernel-tagged.ll" -o "$WORK/kernel-tagged.bc"

echo "[kasan] stage 4/6: opt-20 -passes=asan<kernel>"
opt-20 \
    -passes='asan<kernel>' \
    --asan-force-dynamic-shadow \
    --asan-stack=false \
    --asan-globals=false \
    --asan-instrumentation-with-call-threshold=0 \
    "$WORK/kernel-tagged.bc" \
    -o "$WORK/kernel-asan.bc"

echo "[kasan] stage 5/6: llc-20 → kernel-asan.o"
llc-20 \
    -filetype=obj \
    -relocation-model=static \
    -code-model=kernel \
    "$WORK/kernel-asan.bc" \
    -o "$WORK/kernel-asan.o"

echo "[kasan] stage 6/6: ld → kernel.elf"
# boot.o and ap_trampoline.o come from nasm; build.zig still drives those.
# We expect them under .zig-cache somewhere — find them or rebuild here.
nasm -f elf64 src/boot/boot.asm -o "$WORK/boot.o"
nasm -f elf64 src/boot/ap_trampoline.asm -o "$WORK/ap_trampoline.o"

ld -T src/linker.ld -nostdlib \
    "$WORK/boot.o" \
    "$WORK/ap_trampoline.o" \
    "$WORK/kernel-asan.o" \
    -o "$OUT_DIR/kernel.elf"

# 7) Extra: ELF32 for QEMU multiboot
objcopy -I elf64-x86-64 -O elf32-i386 "$OUT_DIR/kernel.elf" "$OUT_DIR/kernel32.elf"

echo "[kasan] DONE: $OUT_DIR/kernel.elf, $OUT_DIR/kernel32.elf"
ls -la "$OUT_DIR/kernel.elf" "$OUT_DIR/kernel32.elf"
