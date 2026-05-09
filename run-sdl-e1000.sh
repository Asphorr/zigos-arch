#!/bin/bash
# QEMU launcher for ZigOS — fast Multiboot path.
# Loads zig-out/bin/kernel32.elf directly via QEMU's -kernel.
# No sudo, no esp.img rebuild — boots in seconds.
#
# Disk layout (post-Phase 2 ext2 migration):
#   IDE0 = disk.tar  — tarfs fallback at `/tar/` for legacy paths
#   IDE2 = ext2.img  — root filesystem at `/`, contains /bin /etc /share /KERNEL.SYM /BUILD.ID
#
# Both are rebuilt by the default `zig build` so they stay in sync with
# the kernel + apps. tarfs is kept around during the migration window so
# regressions don't brick boot; once the kernel + apps are fully on /bin/
# the tarfs drive can be dropped (task #394).
#
# For UEFI testing use run-uefi-ext2.sh (goes through OVMF, needs an ESP rebuild).
cd ~/zigos-arch

ZIG=/opt/zig-x86_64-linux-0.15.2/zig
"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-sdl-e1000] build failed"; exit 1; }

LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-9.2.0/build/qemu-system-x86_64 \
    -m 128 -accel kvm -smp 2 -no-reboot \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    -display sdl,gl=on,show-cursor=on \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
    -audiodev none,id=snd0 -machine pcspk-audiodev=snd0 -device AC97,audiodev=snd0 \
    -device virtio-sound-pci,audiodev=snd0 \
    -drive file=disk.tar,format=raw,index=0,if=ide \
    -drive file=ext2.img,format=raw,index=2,if=ide \
    -serial file:serial.log \
    -kernel zig-out/bin/kernel32.elf "$@"
