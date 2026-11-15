#!/bin/bash
# build_static_nasm.sh — build nasm as a static x86_64-linux-musl program with
# `zig cc`, into linux-bin/nasm. The ext2 image stage copies linux-bin/* to
# /bin, where a kernel build inside ZigOS (`zig build kernel`) finds it.
#
#   tools/build_static_nasm.sh [ZIG]
#     ZIG  default: the zig on PATH
#
# Same version as the nasm the host build uses, so both assemble the boot
# code alike. The source is fetched once and kept in the work directory.
set -e
ZIG=${1:-$(command -v zig)}
VER=2.16.01
WORK=${TMPDIR:-/tmp}/nasm-static
OUT=$(pwd)/linux-bin/nasm
[ -x "$ZIG" ] || { echo "no zig at '$ZIG'"; exit 1; }
mkdir -p "$WORK" linux-bin
cd "$WORK"
[ -f nasm-$VER.tar.xz ] || curl -fsSLO https://www.nasm.us/pub/nasm/releasebuilds/$VER/nasm-$VER.tar.xz
rm -rf nasm-$VER
tar xf nasm-$VER.tar.xz
cd nasm-$VER
# Non-PIE: the loader maps a static program where it was linked.
# -Wno-date-time: zig cc makes __DATE__ an error, and nasm's version string
# uses it.
CC="$ZIG cc -target x86_64-linux-musl" AR="$ZIG ar" RANLIB="$ZIG ranlib" \
    CFLAGS="-O2 -Wno-date-time" LDFLAGS="-static -no-pie" ./configure --host=x86_64-linux-musl >/dev/null
make -j"$(nproc)" nasm >/dev/null
cp nasm "$OUT"
# EI_OSABI=3, so the native shell starts it as a Linux program too.
printf '\003' | dd of="$OUT" bs=1 seek=7 count=1 conv=notrunc status=none
echo "linux-bin/nasm: $(stat -c %s "$OUT") bytes, $(file -b "$OUT" | cut -d, -f1-2)"
