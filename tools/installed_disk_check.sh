#!/bin/bash
# Host-side oracles for a FULL install (GPT + mkfs + system copy + boot files).
#
# Extends disk_selftest_check.sh's fsck pass with a content pass: both
# partitions are mounted read-only and compared byte-for-byte against the
# build's own originals —
#
#   ESP:  \EFI\BOOT\BOOTX64.EFI and \kernel.elf vs zig-out/bin/*
#   root: the whole tree vs zig-out/ext2-stage (the source genext2fs built
#         the live root from, which is what the installer copied)
#
# A passing run means the kernel's fat32_populate + ext2 populate wrote what
# three foreign tools and a recursive diff agree is a correct filesystem.
#
# Usage: sudo tools/installed_disk_check.sh [install.img]
set -u
cd "$(dirname "$(readlink -f "$0")")/.."

IMG=${1:-install.img}
FAILED=0

step() { printf '\n=== %s ===\n' "$1"; }
verdict() {
    if [ "$1" -eq 0 ]; then echo "  -> OK"; else echo "  -> FAILED (exit $1)"; FAILED=1; fi
}

[ -f "$IMG" ] || { echo "no $IMG — run the installer first"; exit 1; }

step "sgdisk -v $IMG"
sgdisk -v "$IMG"
verdict $?

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

LOOP_ESP=$(losetup --find --show --read-only \
    --offset $((esp_start * 512)) --sizelimit $((esp_count * 512)) "$IMG") || exit 1
LOOP_ROOT=$(losetup --find --show --read-only \
    --offset $((root_start * 512)) --sizelimit $((root_count * 512)) "$IMG") || { losetup -d "$LOOP_ESP"; exit 1; }
cleanup() {
    umount /tmp/zigos-check-esp 2>/dev/null
    umount /tmp/zigos-check-root 2>/dev/null
    losetup -d "$LOOP_ESP" 2>/dev/null
    losetup -d "$LOOP_ROOT" 2>/dev/null
}
trap cleanup EXIT

step "fsck.fat -n  (partition 1, ESP)"
fsck.fat -n "$LOOP_ESP"
verdict $?

step "e2fsck -fn  (partition 2, root)"
e2fsck -fn "$LOOP_ROOT"
verdict $?

step "ESP content vs the build's boot files"
mkdir -p /tmp/zigos-check-esp /tmp/zigos-check-root
mount -o ro "$LOOP_ESP" /tmp/zigos-check-esp || { echo "  ESP mount failed"; FAILED=1; }
if mountpoint -q /tmp/zigos-check-esp; then
    cmp /tmp/zigos-check-esp/EFI/BOOT/BOOTX64.EFI zig-out/bin/BOOTX64.efi
    verdict $?
    cmp /tmp/zigos-check-esp/kernel.elf zig-out/bin/kernel.elf
    verdict $?
fi

step "root tree vs zig-out/ext2-stage (recursive diff)"
mount -o ro "$LOOP_ROOT" /tmp/zigos-check-root || { echo "  root mount failed"; FAILED=1; }
if mountpoint -q /tmp/zigos-check-root; then
    diff -r --exclude=lost+found zig-out/ext2-stage /tmp/zigos-check-root
    verdict $?
    echo "  files on installed root: $(find /tmp/zigos-check-root -type f | wc -l)"
fi

step "result"
if [ "$FAILED" -eq 0 ]; then
    echo "  the installed disk is byte-identical to the build and fsck-clean"
    exit 0
fi
echo "  at least one check rejected the installed disk"
exit 1
