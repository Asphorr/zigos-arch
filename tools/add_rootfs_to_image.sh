#!/bin/bash
# add_rootfs_to_image.sh — write a Linux root file tree (an Alpine root made
# with apk --root) into ext2.img: directories, files with their modes, and
# symbolic links. A name the image already has keeps what it has: ZigOS's
# own /etc files, the static busybox and its links. dev, proc and sys are
# left out: the kernel's own file systems answer there. Also writes the
# checks of that root, linux-tests/{alptest.sh,alptest.py,nettest.sh,
# nodetest.sh,nodetest.js,cctest.sh,nodestress.sh,netspeed.sh}, to /etc.
#
#   tools/add_rootfs_to_image.sh ROOT [IMG]
#     ROOT  the tree, e.g. made with
#           apk.static -X $MIRROR/v3.21/main -U --allow-untrusted --root ROOT \
#               --initdb --no-chown --no-scripts add alpine-baselayout busybox python3 git
#     IMG   default: ext2.img
#
# Run from the repository's root. `zig build` regenerates ext2.img, so run
# this after every build, after add_busybox_to_image.sh and
# add_musl_to_image.sh.
set -e
ROOT=${1:?path to a root file tree}
IMG=${2:-ext2.img}
[ -d "$ROOT" ] || { echo "no tree at '$ROOT'"; exit 1; }
[ -f "$IMG" ] || { echo "no image at '$IMG'"; exit 1; }
ROOT=$(cd "$ROOT" && pwd)

# debugfs reads one command per line and splits it at blanks.
if (cd "$ROOT" && find . -name '* *' -o -name '*"*' | grep -q .); then
    echo "a name in '$ROOT' has a blank or a quote; debugfs can't take it"
    exit 1
fi

# Parents come before what is in them (find lists a directory first); a
# command on a name that exists fails and changes nothing.
{
    (cd "$ROOT" && find . -mindepth 1 \( -path ./dev -o -path ./proc -o -path ./sys \) -prune -o -print) |
    while read -r p; do
        p=${p#./}
        if [ -L "$ROOT/$p" ]; then
            echo "symlink $p $(readlink "$ROOT/$p")"
        elif [ -d "$ROOT/$p" ]; then
            echo "mkdir $p"
        elif [ -f "$ROOT/$p" ]; then
            echo "write $ROOT/$p $p"
        fi
    done
    for f in alptest.sh alptest.py nettest.sh nodetest.sh nodetest.js cctest.sh nodestress.sh netspeed.sh; do
        echo "rm etc/$f"
        echo "write linux-tests/$f etc/$f"
    done
} | debugfs -w -f - "$IMG" >/dev/null 2>&1

debugfs -R stats "$IMG" 2>/dev/null | grep -E "^Free (blocks|inodes)"
