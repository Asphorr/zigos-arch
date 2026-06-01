#!/bin/bash
# QEMU launcher for ZigOS — UEFI + ext2 root + Intel VT-d IOMMU, with a USB
# Attached SCSI (UAS) disk on the xHCI USB3 bus. Fork of
# run-uefi-ext2-iommu.sh: adds `usb-uas` + `scsi-hd` so the xHCI driver's UAS
# path (xHCI Streams) can be exercised.
#
# Why a fork (vs the stale run-usb.sh): that script is pinned to qemu-9.2.0 /
# kernel32.elf and an old venus setup. This tracks the current iommu runner.
#
# UAS needs SuperSpeed for streams: qemu-xhci exposes USB2 + USB3 ports, and
# a SuperSpeed-capable usb-uas device auto-lands on a USB3 port (usb-kbd /
# usb-tablet take the USB2 ports), so streams negotiate without pinning a port.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-uefi-ext2-iommu-uas] Initialized ovmf_vars.fd"
fi

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-uefi-ext2-iommu-uas] build failed"; exit 1; }

if [ ! -f ext2.img ]; then
    echo "[run-uefi-ext2-iommu-uas] ext2.img missing — build should have produced it" >&2
    exit 1
fi

# Swap backing disk — raw 128 MiB image presented as an NVMe controller.
if [ ! -f swap.img ]; then
    dd if=/dev/zero of=swap.img bs=1M count=128 status=none
    echo "[run-uefi-ext2-iommu-uas] Created swap.img (128 MiB swap disk)"
fi

# UAS test disk — raw 64 MiB image presented over USB Attached SCSI on the
# xHCI USB3 bus. A signature string at LBA 0 lets a READ(10) of sector 0 be
# verified end-to-end. Created on first run so a fresh checkout just works.
if [ ! -f uas.img ]; then
    dd if=/dev/zero of=uas.img bs=1M count=64 status=none
    printf 'ZIGOS-UAS-DISK-SECTOR0\n' | dd of=uas.img conv=notrunc status=none
    echo "[run-uefi-ext2-iommu-uas] Created uas.img (64 MiB UAS disk, signed LBA0)"
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
#   intel-iommu,aw-bits=48 — DMA remapping + 48-bit guest address width.
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
    -drive file=uas.img,format=raw,if=none,id=uasdisk \
    -device usb-uas,id=uas,bus=xhci.0 \
    -device scsi-hd,drive=uasdisk,bus=uas.0,scsi-id=0,lun=0 \
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
