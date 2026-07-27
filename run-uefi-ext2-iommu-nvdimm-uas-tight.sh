#!/bin/bash
# QEMU launcher for ZigOS — UEFI + ext2 root + Intel VT-d IOMMU, with BOTH the
# NVDIMM (persistent memory) and the UAS (USB Attached SCSI) device, running on
# deliberately tight RAM so the swap subsystem is under real pressure.
#
# Merge of run-uefi-ext2-iommu-nvdimm.sh and run-uefi-ext2-iommu-uas.sh, with
# run-uefi-ext2-iommu-swaptest.sh's memory sizing. Built to exercise the swap
# in-flight ownership fixes (2026-07-27): the evict/swap-in handoffs between the
# PCB channel, the PTE and the PMM.
#
# WHY TIGHT RAM: 192 MiB (vs 256) is the value the existing swaptest runner
# uses. mtswap self-sizes its buffer to (free RAM + 4 MiB), so it forces
# eviction at any RAM size — but the smaller the machine, the larger the cold
# set as a fraction of the working set, so reclaim runs hot and the racy windows
# are entered far more often per second.
#
# WHAT TO RUN once the desktop is up, in its terminal:
#
#     mtswap        — MT eviction stress, 2 threads over a buffer that exceeds
#                     free RAM. Pass = "0 corrupted byte-0 reads".
#     swaptest      — single-threaded, overshoots free RAM by 48 MiB to stress
#                     slot capacity rather than the MT races.
#
# ...and then, for the paths the 2026-07-27 fixes actually touch, KILL IT
# MID-SWEEP (Ctrl-C in the terminal, or `kill <pid>` from a second one). None of
# the stress apps kill themselves — mtswap's own header says the teardown slot
# reclaim is "not exercised by this test" — so an external kill while threads
# are parked in blockOn(.nvme_io) is the only way to enter the windows:
#
#     * a thread killed inside readPage  → swap_inflight_frame reclaim (frame
#       leak if the channel is missing);
#     * a thread killed inside writePage → swap_inflight_slot reclaim;
#     * a thread killed between the phase-3 CAS and the channel clear → the
#       double-free that could hand one swap slot to two pages.
#
# WHAT TO WATCH FOR in serial.log afterwards:
#
#     grep -a "double-free\|kwarn\|PANIC\|corrupt" serial.log
#     grep -a "\[swap\] out=" serial.log | tail -3   # slots=N/32768 should
#                                                    # fall back toward 0 once
#                                                    # the killed pids are reaped
#
# A `freeSlot double-free` kwarn is the BENIGN half of the old bug and should
# now be absent. The harmful half was always silent, so the real signal is
# `slots=` drifting upward across repeated kill cycles (slots lost to leaks) or
# mtswap reporting corrupted reads (slots handed to two owners).
#
# Usage: ./run-uefi-ext2-iommu-nvdimm-uas-tight.sh [extra qemu args...]
#        (append `-display egl-headless,gl=on` to run it over ssh with no
#         screen — the default sdl backend needs one.)
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-tight] Initialized ovmf_vars.fd"
fi

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-tight] build failed"; exit 1; }

if [ ! -f ext2.img ]; then
    echo "[run-tight] ext2.img missing — build should have produced it" >&2
    exit 1
fi

# Swap backing disk — raw 128 MiB image presented as an NVMe controller.
if [ ! -f swap.img ]; then
    dd if=/dev/zero of=swap.img bs=1M count=128 status=none
    echo "[run-tight] Created swap.img (128 MiB swap disk)"
fi

# UAS test disk — signature string at LBA 0 so a READ(10) of sector 0 can be
# verified end-to-end. Same image the uas runner uses.
if [ ! -f uas.img ]; then
    dd if=/dev/zero of=uas.img bs=1M count=64 status=none
    printf 'ZIGOS-UAS-DISK-SECTOR0\n' | dd of=uas.img conv=notrunc status=none
    echo "[run-tight] Created uas.img (64 MiB UAS disk, signed LBA0)"
fi

# NVDIMM backing file — created ONCE and never recreated, so its contents
# survive reboots (persistence is the feature under test). `rm pmem.img` to
# reset the region.
if [ ! -f pmem.img ]; then
    dd if=/dev/zero of=pmem.img bs=1M count=256 status=none
    echo "[run-tight] Created pmem.img (256 MiB NVDIMM, blank)"
fi

mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

# Machine notes (inherited from both parents):
#   q35 + kernel-irqchip=split — required for intel-iommu.
#   nvdimm=on                  — enables the NFIT / \_SB.NVDR ACPI machinery.
#   -m 192,slots=4,maxmem=4G   — 192 MiB of tight boot RAM; maxmem must exceed
#                                boot RAM for the nvdimm to get a memory slot.
#                                memory-backend-memfd size MUST match the 192M.
#   usb-uas on xhci.0          — SuperSpeed-capable, so it auto-lands on a USB3
#                                port while usb-kbd/usb-tablet take the USB2
#                                ones and streams negotiate without pinning.
VKR_DEBUG=udmabuf \
LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-master/build/qemu-system-x86_64 \
    -m 192,slots=4,maxmem=4G -accel kvm -cpu host,hv-time,hv-frequencies -smp 2 -no-reboot \
    -object memory-backend-memfd,id=mem1,size=192M \
    -machine q35,kernel-irqchip=split,pcspk-audiodev=snd0,memory-backend=mem1,nvdimm=on \
    -device intel-iommu,aw-bits=48 \
    -object memory-backend-file,id=nvmem0,share=on,mem-path=pmem.img,size=256M,align=2M \
    -device nvdimm,memdev=nvmem0,id=nvd0,label-size=2M \
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

echo "--- [run-tight] swap summary ---"
grep -a "\[swap\] out=" serial.log | tail -3 || echo "(no swap activity logged)"
echo "--- [run-tight] warnings ---"
grep -a "double-free\|PANIC\|corrupt" serial.log || echo "(none)"

[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
