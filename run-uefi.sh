#!/bin/bash
# QEMU launcher for ZigOS — UEFI / OVMF path.
# Same hardware loadout as run-sdl-e1000.sh but boots through OVMF firmware
# instead of QEMU's `-kernel` Multiboot loader.
#
# Why: OVMF's GOP (Graphics Output Protocol) hands the kernel a real linear
# framebuffer that's actually scanned out, so early_fb.init can adopt it
# directly. The Multiboot path falls back to BGA, which doesn't work on
# QEMU's virtio-vga-gl (BGA registers respond but the device scans out
# from its own virtio resource, not BGA's framebuffer).
#
# ESP is exposed via QEMU's `fat:rw:` virtual filesystem — OVMF sees a real
# FAT32 ESP synthesized on the fly from zig-out/esp/. No losetup, no mount,
# no sudo, no per-iteration image rebuild. Just `zig build` then re-run.
# `zig build esp` (the partitioned image variant) still exists for the rare
# case you want to test real-firmware ESP behavior.
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

# Reset OVMF variables to firmware defaults if missing (or stale enough
# that a previous run left it broken). One-time per checkout — leave alone
# afterwards so saved boot entries persist.
if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-uefi] Initialized ovmf_vars.fd from /usr/share/OVMF/OVMF_VARS_4M.fd"
fi

# Build kernel + ESP dir tree (no sudo). Cheap when up-to-date.
"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-uefi] build failed"; exit 1; }

# Archive last run's serial.log before QEMU truncates it. crashes/ accumulates
# the last 20 boots so a regression hunt has history without manual log
# wrangling. Naming scheme is sortable + collision-free per second.
mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-9.2.0/build/qemu-system-x86_64 \
    -m 128 -accel kvm -smp 2 -no-reboot \
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
    -drive file=disk.img,format=raw,index=2,if=ide \
    -serial file:serial.log "$@"

# Post-mortem: feed the just-finished serial.log to the crash DB. No-op if
# no [crash-fp] lines were emitted (clean shutdown). Prints a "seen N times"
# header for any duplicate fingerprint so regression patterns are visible.
[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
