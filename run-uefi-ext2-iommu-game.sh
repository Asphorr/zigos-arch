#!/bin/bash
# QEMU launcher for ZigOS — GAMING variant of run-uefi-ext2-iommu.sh.
#
# Difference from the daily driver: a RELATIVE pointer (usb-mouse) + SDL
# pointer grab (click-to-grab) instead of the absolute usb-tablet. FPS
# mouse-look (Quake/DOOM) needs unbounded relative motion + a confined,
# hidden host cursor — an absolute tablet caps turning at one screen width
# and leaves the host cursor visible on top of the game. The desktop is
# nicer with the tablet, so that stays the default; launch THIS script when
# you want to play. Pairs with the kernel-side raw-delta accumulator
# (mouse.raw_dx/dy → desktop.getMouseRelative) so the relative deltas don't
# re-saturate at the guest screen edge.
#
# Grab: with a RELATIVE usb-mouse (no tablet), SDL grabs + hides the host
# cursor when you CLICK in the window — that gives unbounded relative
# motion for mouse-look; press the SDL grab-mod (Ctrl+Alt by default) to
# release it. (qemu-master has no 'grab-on-hover' sdl suboption, so the
# display line is identical to the daily driver — only the device differs.)
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-uefi-ext2-iommu-game] Initialized ovmf_vars.fd"
fi

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-uefi-ext2-iommu-game] build failed"; exit 1; }
# mkesp_dir is cached by addSystemCommand, so the ESP can serve a stale
# kernel.elf forever — deploy the freshly-built one explicitly.
cp zig-out/bin/kernel.elf zig-out/esp/kernel.elf

if [ ! -f ext2.img ]; then
    echo "[run-uefi-ext2-iommu-game] ext2.img missing — build should have produced it" >&2
    exit 1
fi

mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

# IOMMU notes (identical to run-uefi-ext2-iommu.sh):
#   -machine q35 — intel-iommu only works on q35 (PCIe machine type).
#   kernel-irqchip=split — required by intremap=on so IR can intercept MSI.
#   intel-iommu,aw-bits=48 — DMA remapping + 48-bit guest address width.
VKR_DEBUG=udmabuf \
LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-master/build/qemu-system-x86_64 \
    -m 256 -accel kvm -cpu host,hv-time,hv-frequencies -smp 2 \
    -object memory-backend-memfd,id=mem1,size=256M \
    -machine q35,kernel-irqchip=split,pcspk-audiodev=snd0,memory-backend=mem1 \
    -device intel-iommu,aw-bits=48 \
    -vga none \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars.fd \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    -display sdl,gl=on,show-cursor=on \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-mouse \
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
