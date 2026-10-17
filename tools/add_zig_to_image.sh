#!/bin/bash
# add_zig_to_image.sh — write an official static Zig compiler into ext2.img
# as /bin/zig, stamped EI_OSABI=3 so the loader runs it under the Linux
# personality, and the part of its lib/ that compiling Zig without libc
# reads as /lib/zig (the compiler finds it walking up from /bin). Boot mode
# 19 runs `zig version` when the image has it.
#
#   tools/add_zig_to_image.sh [ZIG] [IMG]
#     ZIG  default: the zig on PATH (must be the static x86_64-linux build,
#          with its lib/ beside it)
#     IMG  default: ext2.img
#
# `zig build` regenerates ext2.img from its staging tree, so run this after
# every build. Everything goes in with debugfs -w, without a staged copy;
# the stamped binary and the debugfs script sit in /dev/shm.
set -e
ZIG=${1:-$(command -v zig)}
IMG=${2:-ext2.img}
TMP=/dev/shm/zig-osabi-linux
CMDS=/dev/shm/zig-lib.debugfs
[ -f "$ZIG" ] || { echo "no zig binary at '$ZIG'"; exit 1; }
[ -f "$IMG" ] || { echo "no image at '$IMG'"; exit 1; }
LIB=$(cd "$(dirname "$ZIG")/lib" && pwd)
[ -f "$LIB/std/std.zig" ] || { echo "no lib/ beside '$ZIG'"; exit 1; }
if [ ! -f $TMP ] || [ "$ZIG" -nt $TMP ]; then
    cp "$ZIG" $TMP
    printf '\003' | dd of=$TMP bs=1 seek=7 count=1 conv=notrunc status=none
fi
debugfs -w -R "rm bin/zig" "$IMG" >/dev/null 2>&1 || true
debugfs -w -R "write $TMP bin/zig" "$IMG" >/dev/null
debugfs -R "stat bin/zig" "$IMG" 2>&1 | grep -E "Size:" | head -1

# lib/: std, compiler_rt and the build runner's compiler/, plus the root
# files the compiler opens by name. Not libc, libc++ or the C headers.
DIRS="std compiler compiler_rt c"
{
    echo "mkdir lib"
    echo "mkdir lib/zig"
    (cd "$LIB" && find $DIRS -type d | sort) | sed 's|^|mkdir lib/zig/|'
    (cd "$LIB" && find $DIRS -type f && ls *.zig zig.h) | while read -r f; do
        echo "write $LIB/$f lib/zig/$f"
    done
} > $CMDS
debugfs -w -f $CMDS "$IMG" >/dev/null 2>&1
echo "lib/zig: $(grep -c '^write' $CMDS) files"
debugfs -R "stat lib/zig/std/std.zig" "$IMG" 2>&1 | grep -E "Size:" | head -1
