#!/bin/bash
# QEMU launcher for ZigOS — swap-subsystem demo variant of
# run-uefi-ext2-iommu.sh. IDENTICAL except guest RAM is lowered to 192 MiB
# (-m + memfd size) so a userspace working set can clearly exceed physical
# RAM and force the swap subsystem to evict pages to the swap disk. Use this
# to run `swaptest`. hostmem (host-side GPU blob memory) stays 256M — it is
# not guest RAM, so it doesn't affect the swap pressure.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-swaptest] Initialized ovmf_vars.fd"
fi

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-swaptest] build failed"; exit 1; }

if [ ! -f ext2.img ]; then
    echo "[run-swaptest] ext2.img missing — build should have produced it" >&2
    exit 1
fi

# Swap backing disk — a raw 128 MiB image presented as a 3rd NVMe controller.
# Created on first run so a fresh checkout works without a manual dd step.
if [ ! -f swap.img ]; then
    dd if=/dev/zero of=swap.img bs=1M count=128 status=none
    echo "[run-swaptest] Created swap.img (128 MiB swap disk)"
fi

mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

VKR_DEBUG=udmabuf \
LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-master/build/qemu-system-x86_64 \
    -m 192 -accel kvm -cpu host,hv-time,hv-frequencies -smp 2 -no-reboot \
    -object memory-backend-memfd,id=mem1,size=192M \
    -machine q35,kernel-irqchip=split,pcspk-audiodev=snd0,memory-backend=mem1 \
    -device intel-iommu,aw-bits=48 \
    -vga none \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars.fd \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    -display sdl,gl=on,show-cursor=on \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
    -audiodev none,id=snd0 -device AC97,audiodev=snd0 \
    -device virtio-sound-pci,audiodev=snd0 \
    -device intel-hda -device hda-duplex,audiodev=snd0 \
    -drive file=disk.tar,format=raw,if=none,id=nvm_tar \
    -device nvme,drive=nvm_tar,serial=zigos-tarfs \
    -drive file=fat:rw:zig-out/esp,if=none,id=esp -device ide-hd,drive=esp,bus=ide.0,bootindex=0 \
    -drive file=ext2.img,format=raw,if=none,id=nvm_ext2 \
    -device nvme,drive=nvm_ext2,serial=zigos-ext2 \
    -drive file=swap.img,format=raw,if=none,id=nvm_swap \
    -device nvme,drive=nvm_swap,serial=zigos-swap \
    -serial file:serial.log "$@"

[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
