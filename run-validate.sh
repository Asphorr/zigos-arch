#!/bin/bash
# Same shape as run-uefi-ext2.sh (auto-build, serial archival, crash_db
# post-mortem) but multiboot-loaded so we don't have to rebuild esp.img
# on every iteration. Use this when chasing Vulkan/Lavapipe issues
# (vulkan_cube DEVICE_LOST etc) — VK_LAYER_KHRONOS_validation prints
# VUID-* spec rules our renderer is breaking, captured into validate.log.
#
# Watch:
#   - validate.log         (Vulkan validation layer + virgl_render_server stderr)
#   - serial.log           (kernel klog)
#   - crashes/serial-*.log (last 20 runs)
cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

"$ZIG" build -Doptimize=ReleaseSafe || { echo "[run-validate] build failed"; exit 1; }

# Archive previous serial.log into crashes/ (last 20). Same scheme as run-uefi-ext2.sh.
mkdir -p crashes
if [ -f serial.log ]; then
    ts=$(date -u +%Y%m%dT%H%M%SZ)
    mv serial.log "crashes/serial-${ts}.log"
    ls -t crashes/serial-*.log 2>/dev/null | tail -n +21 | xargs -r rm -f
fi

VK_LAYER_PATH=/usr/share/vulkan/explicit_layer.d \
VK_INSTANCE_LAYERS=VK_LAYER_KHRONOS_validation \
VK_LOADER_DEBUG=error \
VKR_DEBUG=udmabuf,validate \
VN_DEBUG=init,result \
VREND_DEBUG=feat,obj \
LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-9.2.0/build/qemu-system-x86_64 \
    -m 128 -accel kvm -smp 2 -no-reboot \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    -display sdl,gl=on,show-cursor=on \
    -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
    -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
    -audiodev none,id=snd0 -machine pcspk-audiodev=snd0 -device AC97,audiodev=snd0 \
    -device virtio-sound-pci,audiodev=snd0 \
    -drive file=disk.tar,format=raw,index=0,if=ide \
    -drive file=disk.img,format=raw,index=2,if=ide \
    -serial file:serial.log \
    -kernel zig-out/bin/kernel32.elf "$@" \
    > >(tee validate.log) 2>&1

# Post-mortem: parse [crash-fp] lines into crashes/db.csv and warn on dups.
[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log

# VUID summary so user doesn't need to grep manually after every run.
if [ -f validate.log ]; then
    vuid_count=$(grep -c "VUID-" validate.log 2>/dev/null || echo 0)
    echo "[run-validate] $vuid_count VUID lines in validate.log (grep 'VUID-' validate.log | head)"
fi
