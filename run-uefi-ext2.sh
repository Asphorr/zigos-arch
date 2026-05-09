#!/bin/bash
# QEMU launcher for ZigOS — UEFI path with ext2 root.
# Goes through OVMF firmware → BOOTX64.efi → kernel.elf, with ext2.img on
# IDE2 as the canonical filesystem. Disk.tar (tarfs) stays on IDE0 as a
# fallback during the migration window (task #392); once paths are fully
# moved off /tar/ we'll drop the IDE0 drive (task #394).
#
# `zig build` (default) regenerates ext2.img via genext2fs — no sudo.
# `zig build esp` is still required (sudo) to refresh the partitioned ESP
# image, but only when BOOTX64.efi or kernel.elf changes.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-uefi-ext2] Initialized ovmf_vars.fd"
fi

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-uefi-ext2] build failed"; exit 1; }

if [ ! -f ext2.img ]; then
    echo "[run-uefi-ext2] ext2.img missing — build should have produced it" >&2
    exit 1
fi

# Archive previous serial.log into crashes/ (last 20). Same scheme as run-uefi.sh.
mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-9.2.0/build/qemu-system-x86_64 \
    -m 128 -accel kvm -smp 2 -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars.fd \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    -display sdl,gl=on,show-cursor=on \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
    -audiodev none,id=snd0 -machine pcspk-audiodev=snd0 -device AC97,audiodev=snd0 \
    -device virtio-sound-pci,audiodev=snd0 \
    -device intel-hda -device hda-duplex,audiodev=snd0 \
    -drive file=disk.tar,format=raw,index=0,if=ide \
    -drive file=fat:rw:zig-out/esp,index=1,if=ide \
    -drive file=ext2.img,format=raw,index=2,if=ide \
    -serial file:serial.log "$@"

# Post-mortem: parse [crash-fp] lines into crashes/db.csv and warn on dups.
[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
