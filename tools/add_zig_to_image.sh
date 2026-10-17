#!/bin/bash
# add_zig_to_image.sh — write an official static Zig compiler into ext2.img
# as /bin/zig, stamped EI_OSABI=3 so the loader runs it under the Linux
# personality. Boot mode 19 runs `zig version` when the image has it.
#
#   tools/add_zig_to_image.sh [ZIG] [IMG]
#     ZIG  default: the zig on PATH (must be the static x86_64-linux build)
#     IMG  default: ext2.img
#
# `zig build` regenerates ext2.img from its staging tree, so run this after
# every build. The file goes in with debugfs -w, without a staged copy; the
# stamped copy sits in /dev/shm.
set -e
ZIG=${1:-$(command -v zig)}
IMG=${2:-ext2.img}
TMP=/dev/shm/zig-osabi-linux
[ -f "$ZIG" ] || { echo "no zig binary at '$ZIG'"; exit 1; }
[ -f "$IMG" ] || { echo "no image at '$IMG'"; exit 1; }
if [ ! -f $TMP ] || [ "$ZIG" -nt $TMP ]; then
    cp "$ZIG" $TMP
    printf '\003' | dd of=$TMP bs=1 seek=7 count=1 conv=notrunc status=none
fi
debugfs -w -R "rm bin/zig" "$IMG" >/dev/null 2>&1 || true
debugfs -w -R "write $TMP bin/zig" "$IMG" >/dev/null
debugfs -R "stat bin/zig" "$IMG" 2>&1 | grep -E "Size:" | head -1
