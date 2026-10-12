#!/bin/bash
# ZigOS under TCG in WSL2 on the host GPU: virtio-gpu Venus -> virglrenderer
# (render server in-process) -> Mesa dzn -> D3D12. See README.md here.
# Run from the repo after `zig build -Doptimize=ReleaseSafe`; pick
# "GPU Compositor (experimental)" in the boot menu for mode 9.
# ACCEL=kvm runs it under KVM instead, in a Hyper-V VM with GPU-PV.
# Usage: run-wsl-dzn.sh [sdl|none] [extra qemu args...]
set -e
GPUPV=${GPUPV:-$HOME/gpupv}
PREFIX=${PREFIX:-$GPUPV/install}
QEMU=${QEMU:-$GPUPV/qemu-11.1.0/build/qemu-system-x86_64}
cd "$(dirname "$(readlink -f "$0")")/../.."

case "${1:-sdl}" in
    sdl)  DISPLAY_ARGS="-display sdl,gl=on,show-cursor=on" ;;
    none) DISPLAY_ARGS="-display egl-headless" ;;
    *)    echo "display must be sdl or none" >&2; exit 1 ;;
esac
shift || true

[ -f swap.img ] || dd if=/dev/zero of=swap.img bs=1M count=128 status=none
# Fresh NVRAM: the boot history of an unclean exit would make the menu
# default to Safe mode.
VARS=/tmp/zigos-wsl-dzn-vars.fd
cp /usr/share/OVMF/OVMF_VARS_4M.fd $VARS

export LD_LIBRARY_PATH=$PREFIX/lib/x86_64-linux-gnu
export VK_ICD_FILENAMES=${VK_ICD_FILENAMES:-$PREFIX/share/vulkan/icd.d/dzn_icd.x86_64.json}
# WSLg's X11 has no DRI3 (GL falls back to swrast); Wayland EGL gets d3d12.
export SDL_VIDEODRIVER=${SDL_VIDEODRIVER:-wayland}
export GALLIUM_DRIVER=${GALLIUM_DRIVER:-d3d12}
# The in-process render server logs through virgl_log (errors only by default).
export VIRGL_LOG_LEVEL=${VIRGL_LOG_LEVEL:-info}

# TCG flags, each needed (README.md, "QEMU flags"):
#   thread=single + icount  guest TSC calibration under MTTCG is wildly off
#   phys-bits=39            keeps PCI BARs inside the kernel's 512 GB physmap
#   monitor=off             TCG advertises MWAIT IBE but #GPs on ECX != 0
#   x2apic=off              icount aborts on the x2APIC timer MSR read
if [ "${ACCEL:-tcg}" = kvm ]; then
    ACCEL_ARGS="-accel kvm -cpu host"
else
    ACCEL_ARGS="-accel tcg,thread=single -icount shift=auto,sleep=on -cpu max,phys-bits=39,monitor=off,x2apic=off"
fi
exec $QEMU_WRAP "$QEMU" \
    -m 256 $ACCEL_ARGS -smp 2 -no-reboot \
    -machine q35 -vga none \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=$VARS \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    $DISPLAY_ARGS \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -device e1000,netdev=net0 -netdev user,id=net0 \
    -audiodev none,id=snd0 -device AC97,audiodev=snd0 \
    -device intel-hda -device hda-duplex,audiodev=snd0 \
    -drive file=disk.tar,format=raw,if=none,id=nvm_tar \
    -device nvme,drive=nvm_tar,serial=zigos-tarfs \
    -drive file=fat:rw:zig-out/esp,index=1,if=ide \
    -drive file=ext2.img,format=raw,if=none,id=nvm_ext2 \
    -device nvme,drive=nvm_ext2,serial=zigos-ext2 \
    -drive file=swap.img,format=raw,if=none,id=nvm_swap \
    -device nvme,drive=nvm_swap,serial=zigos-swap \
    -serial file:serial.log "$@"
