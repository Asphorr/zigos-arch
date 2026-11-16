#!/bin/bash
# add_musl_to_image.sh — write musl's dynamic linker into ext2.img as
# /lib/ld-musl-x86_64.so.1, the interpreter dynamically linked musl programs
# name, with /lib/libc.musl-x86_64.so.1 (the name Alpine's programs need it
# by) a link to it; and, if given, a dynamically linked busybox as
# /bin/busybox-dyn (a name busybox takes as its own, so the applet is the
# first argument). lt_dyn and the dynamic checks of bbtest.sh need them.
#
#   tools/add_musl_to_image.sh LD_MUSL [BUSYBOX|-] [IMG]
#     LD_MUSL  musl's lib/ld-musl-x86_64.so.1 (Alpine's musl package)
#     BUSYBOX  a dynamically linked busybox (Alpine's busybox package has
#              one as bin/busybox); - for none
#     IMG      default: ext2.img
#
# `zig build` regenerates ext2.img, so run this after every build.
set -e
LD=${1:?path to ld-musl-x86_64.so.1}
BB=${2:--}
IMG=${3:-ext2.img}
[ -f "$LD" ] || { echo "no dynamic linker at '$LD'"; exit 1; }
[ "$BB" = - ] || [ -f "$BB" ] || { echo "no busybox at '$BB'"; exit 1; }
[ -f "$IMG" ] || { echo "no image at '$IMG'"; exit 1; }

{
    echo "mkdir lib"
    echo "rm lib/ld-musl-x86_64.so.1"
    echo "write $LD lib/ld-musl-x86_64.so.1"
    echo "rm lib/libc.musl-x86_64.so.1"
    echo "symlink lib/libc.musl-x86_64.so.1 ld-musl-x86_64.so.1"
    if [ "$BB" != - ]; then
        echo "rm bin/busybox-dyn"
        echo "write $BB bin/busybox-dyn"
    fi
} | debugfs -w -f - "$IMG" >/dev/null 2>&1
debugfs -R "stat lib/ld-musl-x86_64.so.1" "$IMG" 2>/dev/null | grep -E "Size" | head -1
