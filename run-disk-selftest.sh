#!/bin/bash
# Headless runner for the disk self-test (boot_mode 16).
#
# Every other run script opens an SDL window and boots to the desktop, which
# makes them unusable over ssh and unusable from a script. This one boots
# straight into src/test/disk_selftest.zig via -Dboot-mode=16, runs with no
# display, and exits on a timeout — so a CI-shaped "build, run, grep the log,
# check the image with host tools" sequence works.
#
# The self-test is destructive to install.img and nothing else.
#
# Usage: ./run-disk-selftest.sh [timeout-seconds]
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig
TIMEOUT=${1:-60}

# Dedicated NVRAM, refreshed every run. Sharing ovmf_vars.fd with the desktop
# scripts drags in Boot#### entries whose device paths were recorded under a
# different PCI layout; OVMF then fails to match them and drops to the EFI
# Shell instead of falling back to \EFI\BOOT\BOOTX64.EFI. A clean vars file
# has no stale entries to prefer, so the removable-media fallback wins.
cp -f /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars-disktest.fd

"$ZIG" build -Doptimize=ReleaseSafe -Dboot-mode=16 || { echo "[disk-selftest] build failed"; exit 1; }

[ -f swap.img ] || dd if=/dev/zero of=swap.img bs=1M count=128 status=none

# Recreate the target from scratch every run: the test must prove it can
# partition a blank disk, not that it can re-partition its own leftovers.
rm -f install.img
dd if=/dev/zero of=install.img bs=1M count=256 status=none

rm -f serial-disktest.log

# -display none with plain -vga std: the venus/virtio-gl stack the desktop
# scripts use needs a real display, and this test never draws anything.
timeout "$TIMEOUT" qemu-system-x86_64 \
    -m 256 -accel kvm -cpu host -smp 2 -no-reboot \
    -vga std -display none \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars-disktest.fd \
    -drive file=disk.tar,format=raw,if=none,id=nvm_tar \
    -device nvme,drive=nvm_tar,serial=zigos-tarfs \
    -drive file=fat:rw:zig-out/esp,if=none,id=esp \
    -device ide-hd,drive=esp,bus=ide.0,bootindex=0 \
    -drive file=ext2.img,format=raw,if=none,id=nvm_ext2 \
    -device nvme,drive=nvm_ext2,serial=zigos-ext2 \
    -drive file=swap.img,format=raw,if=none,id=nvm_swap \
    -device nvme,drive=nvm_swap,serial=zigos-swap \
    -drive file=install.img,format=raw,if=none,id=nvm_install \
    -device nvme,drive=nvm_install,serial=zigos-install \
    -serial file:serial-disktest.log

# -a: the log starts with OVMF's ANSI escapes, so grep classifies it as binary
# and prints "binary file matches" instead of the lines we came for.
echo "--- [disktest] lines from serial-disktest.log ---"
grep -a -E '\[disktest\]|\[gpt\]|\[mkfs' serial-disktest.log || echo "(none — did the kernel reach boot_mode dispatch?)"

if grep -aq '\[disktest\] PASS' serial-disktest.log 2>/dev/null; then
    echo "[disk-selftest] kernel-side PASS"
    exit 0
fi
echo "[disk-selftest] kernel-side FAIL or no result"
exit 1
