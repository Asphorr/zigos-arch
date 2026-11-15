#!/bin/bash
# add_busybox_to_image.sh — write a static busybox into ext2.img as
# /bin/busybox, a link in /bin for each applet the smoke test runs, and the
# test itself as /etc/bbtest.sh. Boot mode 19 runs `busybox sh
# /etc/bbtest.sh` when the image has them.
#
#   tools/add_busybox_to_image.sh BUSYBOX [IMG]
#     BUSYBOX  a statically linked x86-64 busybox (Alpine's busybox-static
#              package carries one as bin/busybox.static)
#     IMG      default: ext2.img
#
# `zig build` regenerates ext2.img, so run this after every build.
set -e
BB=${1:?path to a static busybox}
IMG=${2:-ext2.img}
[ -f "$BB" ] || { echo "no busybox at '$BB'"; exit 1; }
[ -f "$IMG" ] || { echo "no image at '$IMG'"; exit 1; }
[ -f linux-tests/bbtest.sh ] || { echo "run from the repository root"; exit 1; }

APPLETS="sh echo tr sort head tail wc sed grep awk cut seq expr basename
dirname xargs uname rm mkdir cat cp mv ln readlink ls find du touch sleep env
yes dd date true false kill ps id stat"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# The kernel starts this one itself, so it carries the Linux OSABI stamp the
# loader tells a Linux program by (toolchains leave 0 there).
cp "$BB" "$TMP/busybox"
printf '\003' | dd of="$TMP/busybox" bs=1 seek=7 count=1 conv=notrunc status=none
{
    echo "rm bin/busybox"
    echo "write $TMP/busybox bin/busybox"
    echo "mkdir etc"
    echo "mkdir tmp"
    echo "rm etc/bbtest.sh"
    echo "write linux-tests/bbtest.sh etc/bbtest.sh"
    for a in $APPLETS; do
        echo "rm bin/$a"
        echo "symlink bin/$a busybox"
    done
} > "$TMP/cmds"
debugfs -w -f "$TMP/cmds" "$IMG" >/dev/null 2>&1
debugfs -R "stat bin/busybox" "$IMG" 2>/dev/null | grep -E "Size" | head -1
debugfs -R "stat bin/sh" "$IMG" 2>/dev/null | grep -E "Fast link dest|Type" | head -2
