#!/bin/bash
# Sibling of run-uefi-ext2.sh that builds with Zig 0.16 in Debug mode.
# The kernel forces -fllvm via build.zig (.use_llvm = true) because the
# 0.16 self-hosted x86 backend can't yet encode some of our inline-asm
# forms; userspace + UEFI bootloader use the new backend in Debug.
#
# Memory bumped 128M -> 256M because Debug kernel.elf is ~5x larger and
# carries DWARF; OVMF needs more headroom to load it.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-0.16/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-uefi-ext2-zig016] Initialized ovmf_vars.fd"
fi

"$ZIG" build || { echo "[run-uefi-ext2-zig016] build failed"; exit 1; }

if [ ! -f ext2.img ]; then
    echo "[run-uefi-ext2-zig016] ext2.img missing — build should have produced it" >&2
    exit 1
fi

mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-9.2.0/build/qemu-system-x86_64 \
    -m 256 -accel kvm -smp 2 -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars.fd \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    -display sdl,gl=on,show-cursor=on \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
    -audiodev none,id=snd0 -machine pcspk-audiodev=snd0 -device AC97,audiodev=snd0 \
    -device virtio-sound-pci,audiodev=snd0 \
    -drive file=disk.tar,format=raw,index=0,if=ide \
    -drive file=fat:rw:zig-out/esp,index=1,if=ide \
    -drive file=ext2.img,format=raw,index=2,if=ide \
    -serial file:serial.log "$@"

[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
