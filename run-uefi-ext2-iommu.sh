#!/bin/bash
# QEMU launcher for ZigOS — UEFI path with ext2 root + Intel VT-d IOMMU
# enabled. Variant of run-uefi-ext2.sh that swaps machine type to q35
# (required for -device intel-iommu) and appends the IOMMU device.
#
# Phase 1: pass-through mode — IOMMU is on but DMA addresses are 1:1.
# Acts as a fault-recorder when drivers issue malformed DMA, without
# breaking existing driver semantics.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-uefi-ext2-iommu] Initialized ovmf_vars.fd"
fi

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-uefi-ext2-iommu] build failed"; exit 1; }

if [ ! -f ext2.img ]; then
    echo "[run-uefi-ext2-iommu] ext2.img missing — build should have produced it" >&2
    exit 1
fi

mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

# IOMMU notes:
#   -machine q35 — intel-iommu only works on q35 (PCIe machine type).
#   kernel-irqchip=split — required by intremap=on so IR can intercept MSI.
#   intel-iommu,intremap=on,aw-bits=48 — DMA remapping + interrupt
#       remapping + 48-bit guest address width (matches CPU phys, lets
#       AGAW=2 path succeed in our pass-through programming).
VKR_DEBUG=udmabuf \
LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-master/build/qemu-system-x86_64 \
    -m 256 -accel kvm -cpu host,hv-time,hv-frequencies -smp 2 -no-reboot \
    -object memory-backend-memfd,id=mem1,size=256M \
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
    -serial file:serial.log "$@"

[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
