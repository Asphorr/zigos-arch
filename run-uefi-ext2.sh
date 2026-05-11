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

# VKR_DEBUG=udmabuf — required for any Venus app expecting CPU-readable
# rendered output (vulkan_cube, GPU compositor's readback HOST3D blob).
# Without it virglrenderer skips the udmabuf import path and falls back
# to GBM, which on Hyper-V (no render node, only hyperv_drm synthvid)
# silently fails — Vulkan commands all return OK but the host's
# dpy_gl_scanout_dmabuf never sees the pixels. Result: black screen.
# Venus dma-buf scanout requires guest RAM backed by memfd (so
# virglrenderer can convert it to udmabuf-fd for the host display path
# via dpy_gl_scanout_dmabuf). Without `-object memory-backend-memfd` +
# `-machine memory-backend=mem1`, VKR_DEBUG=udmabuf is a no-op and
# SET_SCANOUT_BLOB silently fails (all kernel-side RESP_OK_NODATA, but
# the SDL window stays black). Confirmed working recipe from
# https://gist.github.com/peppergrayxyz/fdc9042760273d137dddd3e97034385f
# Size must match `-m`; bump both together.
#
# `-vga none` disables the implicit Cirrus/stdvga scanout — virtio-vga-gl
# is our only display, having two scanouts triggers GTK assertion
# failures and confuses the dma-buf path.
VKR_DEBUG=udmabuf \
LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-master/build/qemu-system-x86_64 \
    -m 128 -accel kvm -cpu host,hv-time,hv-frequencies -smp 2 -no-reboot \
    -object memory-backend-memfd,id=mem1,size=128M \
    -machine pcspk-audiodev=snd0,memory-backend=mem1 \
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
    -drive file=disk.tar,format=raw,index=0,if=ide \
    -drive file=fat:rw:zig-out/esp,index=1,if=ide \
    -drive file=ext2.img,format=raw,index=2,if=ide \
    -serial file:serial.log "$@"

# Post-mortem: parse [crash-fp] lines into crashes/db.csv and warn on dups.
[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
