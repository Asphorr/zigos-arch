#!/bin/bash
# add_tree_to_image.sh — write what `zig build kernel` reads into ext2.img as
# /work/zigos: build.zig, src/, lib/ and the two lint tools. Together with
# /bin/zig (tools/add_zig_to_image.sh) and /bin/nasm
# (tools/build_static_nasm.sh) the kernel then builds inside ZigOS; boot
# mode 19 runs that build when the image has the tree.
#
#   tools/add_tree_to_image.sh [IMG]
#     IMG  default: ext2.img
#
# `zig build` regenerates ext2.img, so run this after every build. The
# image wants room for the caches of a kernel build: -Dext2-mb=2048.
set -e
IMG=${1:-ext2.img}
DEST=work/zigos
CMDS=/dev/shm/zigos-tree.debugfs
[ -f "$IMG" ] || { echo "no image at '$IMG'"; exit 1; }
[ -f build.zig ] || { echo "run from the repository root"; exit 1; }
FILES="build.zig tools/asm_lint.zig tools/ctx_lint.zig $(find src lib -type f | sort)"
{
    echo "mkdir work"
    echo "mkdir $DEST"
    echo "mkdir $DEST/tools"
    find src lib -type d | sort | sed "s|^|mkdir $DEST/|"
    for f in $FILES; do
        echo "rm $DEST/$f"
        echo "write $f $DEST/$f"
    done
} > $CMDS
debugfs -w -f $CMDS "$IMG" >/dev/null 2>&1
echo "/$DEST: $(grep -c '^write' $CMDS) files"
debugfs -R "stat $DEST/build.zig" "$IMG" 2>&1 | grep -E "Size:" | head -1
