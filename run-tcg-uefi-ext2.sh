#!/bin/bash
# TCG-accel UEFI+ext2 boot for capturing pre-reset exception chain via -d int.
# Same disk/firmware setup as run-uefi-ext2.sh, but software emulation so
# QEMU's interrupt log shows the full delivery sequence (KVM hides it).
#
# Use this when serial.log stays empty after a regular run-uefi-ext2.sh —
# the kernel is dying before serial init and the exception chain in
# qemu_int.log is the only window into where.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-tcg-uefi-ext2] Initialized ovmf_vars.fd"
fi

if [ ! -f ext2.img ]; then
    echo "[run-tcg-uefi-ext2] ext2.img missing — run 'sudo zig build ext2' first" >&2
    exit 1
fi

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-tcg-uefi-ext2] build failed"; exit 1; }

# Archive previous serial.log + qemu_int.log into crashes/ (last 20).
mkdir -p crashes
ts=$(date -u +%Y%m%dT%H%M%SZ)
if [ -f serial.log ]; then
    mv serial.log "crashes/serial-${ts}.log"
fi
if [ -f qemu_int.log ]; then
    mv qemu_int.log "crashes/qemu_int-${ts}.log"
fi
ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
ls -t crashes/qemu_int-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f

# Allow `-display none` for headless SSH runs by passing it via "$@".
# Default is GTK so the user gets a window when launched from the desktop.
DISPLAY_ARGS=(-display gtk,gl=on,show-cursor=on,grab-on-hover=on)
for arg in "$@"; do
    if [[ "$arg" == "-display" ]] || [[ "$arg" == "--headless" ]]; then
        DISPLAY_ARGS=(-display none)
        break
    fi
done

LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-9.2.0/build/qemu-system-x86_64 \
    -m 128 -accel tcg -smp 2 -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars.fd \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    "${DISPLAY_ARGS[@]}" \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
    -audiodev none,id=snd0 -machine pcspk-audiodev=snd0 -device AC97,audiodev=snd0 \
    -device virtio-sound-pci,audiodev=snd0 \
    -drive file=disk.tar,format=raw,index=0,if=ide \
    -drive file=fat:rw:zig-out/esp,index=1,if=ide \
    -drive file=ext2.img,format=raw,index=2,if=ide \
    -serial file:serial.log \
    -d int,cpu_reset -D qemu_int.log

# Post-mortem: parse [crash-fp] lines into crashes/db.csv and warn on dups.
[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
