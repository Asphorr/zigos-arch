#!/bin/bash
# QEMU launcher for the graphical installer (boot_mode 17).
#
# The installer is picked from the UEFI boot menu ("Install ZigOS to
# disk..."), NOT baked in with -Dboot-mode=17: a forced boot mode is
# comptime-baked into kernel.elf, and THAT kernel is what /boot stages and
# the installer copies to the target — a 17-forced build installs a disk
# that can only ever boot back into the installer. The plain build's menu
# reaches everything.
#
# The installer runs on a plain stdvga scanout, 2D only — no Venus, no
# virtio-gl, no memfd backing — so this script deliberately does NOT carry
# run-uefi-ext2.sh's GPU plumbing.
#
# install.img is the only disk this can write. It is recreated blank on every
# run so the installer always faces an unpartitioned target; pass -keep to
# inspect the result of a previous run instead.
#
# Usage: ./run-installer.sh [-keep] [-headless] [extra qemu args...]
#
# -headless swaps SDL for no display plus two control sockets, for driving
# the installer over ssh: installer-mon.sock (HMP: sendkey, screendump) and
# installer-qmp.sock (QMP: input-send-event). Keyboard goes through HMP
# `sendkey`; the pointer MUST go through QMP abs events — HMP `mouse_move`
# emits relative events and the usb-tablet drops those on the floor.
# Read the outcome from serial-installer.log. Recipe: 4x `sendkey down` +
# `ret` picks Install off the boot menu (any key skips the confirm modal),
# then three `sendkey ret` run the default install end to end — see
# tools/installer_headless_test.sh.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

KEEP=0
HEADLESS=0
while :; do
    case "$1" in
        -keep) KEEP=1; shift ;;
        -headless) HEADLESS=1; shift ;;
        *) break ;;
    esac
done

# Dedicated NVRAM, refreshed every run — same reason as run-disk-selftest.sh:
# Boot#### entries recorded under a different PCI layout make OVMF drop to the
# EFI Shell rather than falling back to \EFI\BOOT\BOOTX64.EFI.
cp -f /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars-installer.fd

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-installer] build failed"; exit 1; }

[ -f swap.img ] || dd if=/dev/zero of=swap.img bs=1M count=128 status=none

# 1 GiB, SPARSE (count=0 seek=N writes no data): the copied system tree is
# ~230 MiB and the old 256 MiB disk left the root partition too small for it.
if [ "$KEEP" = "0" ]; then
    rm -f install.img
    dd if=/dev/zero of=install.img bs=1M count=0 seek=1024 status=none
    echo "[run-installer] install.img recreated blank (1 GiB sparse)"
else
    [ -f install.img ] || dd if=/dev/zero of=install.img bs=1M count=0 seek=1024 status=none
    echo "[run-installer] keeping existing install.img"
fi

rm -f serial-installer.log

if [ "$HEADLESS" = "1" ]; then
    rm -f installer-mon.sock installer-qmp.sock
    DISPLAY_ARGS="-display none -monitor unix:installer-mon.sock,server,nowait -qmp unix:installer-qmp.sock,server,nowait"
else
    DISPLAY_ARGS="-display sdl,show-cursor=off"
fi

# USB HID, same devices as run-uefi-ext2.sh. The first cut of this script bet
# on PS/2-only input and lost — input was dead. The installer now drains USB
# HID itself every frame (installer.zig pollInput calls xhci.pollHID), so it
# does not depend on ksoftirqd, which never runs here. usb-tablet also gives
# absolute coordinates, which is what a pointer under SDL wants; the PS/2
# fallback in installer.zig stays for hardware without USB.
#
# -device ide-hd,bootindex=0 on the ESP: with a fresh vars file OVMF has no
# recorded preference, and an explicit bootindex beats relying on probe order.
qemu-system-x86_64 \
    -m 256 -accel kvm -cpu host -smp 2 -no-reboot \
    -vga std $DISPLAY_ARGS \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars-installer.fd \
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
    -serial file:serial-installer.log "$@"

echo "--- [installer] lines from serial-installer.log ---"
grep -a -E '\[installer\]|\[gpt\]|\[mkfs|\[scanout\]' serial-installer.log \
    || echo "(none — did the kernel reach boot_mode dispatch?)"
