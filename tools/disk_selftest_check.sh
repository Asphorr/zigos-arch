#!/bin/bash
# Host-side oracles for the disk self-test.
#
# The kernel checking its own output only proves self-consistency. These three
# tools were written by people who know the formats far better than we do, and
# none of them shares a line of code with what produced install.img:
#
#   sgdisk -v     GPT: both headers, both entry arrays, both CRCs, geometry
#   e2fsck -fn    ext2: bitmaps vs. reality, inode table, directory tree
#   fsck.fat -n   FAT32: cluster chains, FSInfo, boot sector vs. its backup
#
# All three run read-only (-n / -v never write). Partitions are handed to the
# filesystem checkers through loop devices with an offset, so no image is
# copied and nothing is modified.
#
# Usage: sudo tools/disk_selftest_check.sh [install.img]
set -u
cd "$(dirname "$(readlink -f "$0")")/.."

IMG=${1:-install.img}
FAILED=0

step() { printf '\n=== %s ===\n' "$1"; }
verdict() {
    if [ "$1" -eq 0 ]; then echo "  -> OK"; else echo "  -> FAILED (exit $1)"; FAILED=1; fi
}

[ -f "$IMG" ] || { echo "no $IMG — run ./run-disk-selftest.sh first"; exit 1; }

step "sgdisk -v $IMG"
sgdisk -v "$IMG"
verdict $?

step "partition table"
sgdisk -p "$IMG"

# Offsets come from the table we are checking, not from constants duplicated
# here — a hardcoded offset would silently pass a wrong-by-a-partition layout.
read_part() { # $1 = partition number, echoes "start_sector sector_count"
    sgdisk -i "$1" "$IMG" 2>/dev/null | awk '
        /^First sector:/ { s=$3 }
        /^Last sector:/  { e=$3 }
        END { if (s != "" && e != "") print s, e - s + 1 }'
}

ESP=$(read_part 1)
ROOT=$(read_part 2)
[ -n "$ESP" ] && [ -n "$ROOT" ] || { echo "could not read partition geometry from $IMG"; exit 1; }

esp_start=${ESP%% *}; esp_count=${ESP##* }
root_start=${ROOT%% *}; root_count=${ROOT##* }

step "fsck.fat -n  (partition 1, ESP: sector $esp_start, $esp_count sectors)"
LOOP_ESP=$(losetup --find --show --read-only \
    --offset $((esp_start * 512)) --sizelimit $((esp_count * 512)) "$IMG") || exit 1
fsck.fat -n "$LOOP_ESP"
verdict $?
losetup -d "$LOOP_ESP"

step "e2fsck -fn  (partition 2, root: sector $root_start, $root_count sectors)"
LOOP_ROOT=$(losetup --find --show --read-only \
    --offset $((root_start * 512)) --sizelimit $((root_count * 512)) "$IMG") || exit 1
e2fsck -fn "$LOOP_ROOT"
verdict $?
losetup -d "$LOOP_ROOT"

step "result"
if [ "$FAILED" -eq 0 ]; then
    echo "  all host checkers accepted the kernel-written disk"
    exit 0
fi
echo "  at least one host checker rejected it"
exit 1
