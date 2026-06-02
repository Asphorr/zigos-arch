#!/bin/bash
# QEMU launcher for ZigOS — UEFI + ext2 root + Intel VT-d IOMMU, with an
# NVDIMM (persistent memory) device. Fork of run-uefi-ext2-iommu.sh that adds
# a file-backed pmem region so the ACPI NFIT and the NVDIMM _FIT/_DSM (AML)
# control methods can be driven, and data persistence across reboots verified.
#
# The pmem backing file (pmem.img) is created ONCE and never recreated, so
# data written to it survives VM reboots — that persistence is the whole point.
# Delete pmem.img by hand to reset the persistent region.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-uefi-ext2-iommu-nvdimm] Initialized ovmf_vars.fd"
fi

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-uefi-ext2-iommu-nvdimm] build failed"; exit 1; }

if [ ! -f ext2.img ]; then
    echo "[run-uefi-ext2-iommu-nvdimm] ext2.img missing — build should have produced it" >&2
    exit 1
fi

# Swap backing disk — raw 128 MiB image presented as an NVMe controller.
if [ ! -f swap.img ]; then
    dd if=/dev/zero of=swap.img bs=1M count=128 status=none
    echo "[run-uefi-ext2-iommu-nvdimm] Created swap.img (128 MiB swap disk)"
fi

# NVDIMM persistent-memory backing file — 256 MiB, file-backed so its contents
# survive VM reboots (data persistence is the feature under test). Created ONCE
# and left alone on subsequent runs; `rm pmem.img` to reset the region.
if [ ! -f pmem.img ]; then
    dd if=/dev/zero of=pmem.img bs=1M count=256 status=none
    echo "[run-uefi-ext2-iommu-nvdimm] Created pmem.img (256 MiB NVDIMM, blank)"
fi

mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

# IOMMU + NVDIMM notes:
#   -machine q35,...,nvdimm=on  — q35 (PCIe) for intel-iommu + enable the NFIT /
#                                 NVDIMM ACPI namespace machinery.
#   -m 256,slots=4,maxmem=4G    — maxmem must exceed boot RAM so the nvdimm gets
#                                 a memory slot; `slots` = hotplug slot count.
#   memory-backend-file,share=on — file-backed memory; share=on so guest writes
#                                 reach pmem.img and survive reboot. (pmem=on is
#                                 omitted: this QEMU build lacks libpmem; the file
#                                 still persists, we just skip libpmem's flush.)
#   -device nvdimm              — surfaces it via the NFIT table AND \_SB.NVDR
#                                 (_HID "ACPI0012", _FIT/_DSM control methods).
VKR_DEBUG=udmabuf \
LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-master/build/qemu-system-x86_64 \
    -m 256,slots=4,maxmem=4G -accel kvm -cpu host,hv-time,hv-frequencies -smp 2 -no-reboot \
    -object memory-backend-memfd,id=mem1,size=256M \
    -machine q35,kernel-irqchip=split,pcspk-audiodev=snd0,memory-backend=mem1,nvdimm=on \
    -device intel-iommu,aw-bits=48 \
    -object memory-backend-file,id=nvmem0,share=on,mem-path=pmem.img,size=256M,align=2M \
    -device nvdimm,memdev=nvmem0,id=nvd0 \
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
