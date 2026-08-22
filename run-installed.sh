#!/bin/bash
# Boot the disk the graphical installer just wrote — install.img and NOTHING
# else attached. This is the installer's real acceptance test, exercising the
# full chain on the installed artifact alone:
#
#   OVMF (fresh vars, no recorded entries) falls back to the removable-media
#   path and runs \EFI\BOOT\BOOTX64.EFI off the GPT ESP the kernel formatted;
#   the bootloader opens ITS OWN volume (LoadedImage.device_handle) and loads
#   \kernel.elf; the kernel finds one NVMe controller carrying GPT, tarfs
#   finds no archive (fine), and ext2's initAuto discovers the root in
#   partition 2 by its TYPE_LINUX_DATA GUID.
#
# Headless by default (read serial-installed.log); pass -display for a
# window. The guest is left running in headless mode for ~90 s, long enough
# to reach the desktop, then shot.
#
# Usage: ./run-installed.sh [-display]
cd "$(dirname "$(readlink -f "$0")")"

[ -f install.img ] || { echo "[run-installed] no install.img — run the installer first"; exit 1; }

# Fresh vars every run, same reason as the other runners: stale Boot####
# entries from another PCI layout make OVMF drop to the EFI Shell.
cp -f /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars-installed.fd
rm -f serial-installed.log

DISPLAY_ARGS="-display none"
TIMEOUT="timeout 90"
if [ "${1:-}" = "-display" ]; then
    # Same windowed flags as run-installer.sh — see the comment there for why
    # gl=on and show-cursor=on matter (scaling quality + tablet coordinates).
    DISPLAY_ARGS="-display sdl,gl=on,show-cursor=on"
    TIMEOUT=""
fi

$TIMEOUT qemu-system-x86_64 \
    -m 256 -accel kvm -cpu host -smp 2 -no-reboot \
    -vga std $DISPLAY_ARGS \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars-installed.fd \
    -drive file=install.img,format=raw,if=none,id=nvm_installed \
    -device nvme,drive=nvm_installed,serial=zigos-installed,bootindex=0 \
    -serial file:serial-installed.log

echo "--- boot-chain lines from serial-installed.log ---"
grep -a -E '\[uefi\]|\[block\]|\[ext2\]|\[boot\] mode|ext2 root|desktop|\[installer\]' serial-installed.log | head -40 \
    || echo "(nothing — did OVMF find the ESP at all?)"
