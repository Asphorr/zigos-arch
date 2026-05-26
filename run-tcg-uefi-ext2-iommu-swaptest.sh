#!/bin/bash
# TCG-accel variant of run-uefi-ext2-iommu-swaptest.sh.
#
# Use this when serial.log shows a hang / [exc-entry] / wedge with no
# follow-up output but the symptom is REPRODUCIBLE. TCG (software emul)
# lets QEMU log the full CPU-side interrupt + MMU + guest-error chain to
# qemu_int.log via `-d ...`, which KVM hides. Slow (~5-10× real time)
# but the only way to see "what the CPU did between the last serial print
# and the lockup".
#
# Mirrors the iommu-swaptest setup (192 MiB RAM, 3 NVMe ctrls incl. swap,
# IOMMU on) so the same userspace pressure pattern hits.

cd "$(dirname "$(readlink -f "$0")")"

ZIG=/opt/zig-x86_64-linux-0.15.2/zig

if [ ! -f ovmf_vars.fd ]; then
    cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
    echo "[run-tcg-swaptest] Initialized ovmf_vars.fd"
fi

KASAN_FLAG=""
if [ -n "${KASAN:-}" ]; then
    KASAN_FLAG="-Dkasan=true"
    echo "[run-tcg-swaptest] KASAN enabled"
fi
"$ZIG" build -Doptimize=ReleaseSafe $KASAN_FLAG || { echo "[run-tcg-swaptest] build failed"; exit 1; }

if [ ! -f ext2.img ]; then
    echo "[run-tcg-swaptest] ext2.img missing — build should have produced it" >&2
    exit 1
fi

if [ ! -f swap.img ]; then
    dd if=/dev/zero of=swap.img bs=1M count=128 status=none
    echo "[run-tcg-swaptest] Created swap.img (128 MiB swap disk)"
fi

# Rotate previous serial.log + qemu_int.log into crashes/ (keep last 20 of each).
mkdir -p crashes
ts=$(date -u +%Y%m%dT%H%M%SZ)
for f in serial.log qemu_int.log; do
    if [ -f "$f" ]; then
        base="${f%.log}"
        mv "$f" "crashes/${base}-${ts}.log"
    fi
done
ls -t crashes/serial-*.log    2>/dev/null | tail -n +21 | xargs -r rm -f
ls -t crashes/qemu_int-*.log  2>/dev/null | tail -n +21 | xargs -r rm -f

# Allow `-display none` / `--headless` via "$@".
DISPLAY_ARGS=(-display sdl,gl=off,show-cursor=on)
for arg in "$@"; do
    if [[ "$arg" == "-display" ]] || [[ "$arg" == "--headless" ]]; then
        DISPLAY_ARGS=(-display none)
        break
    fi
done

# QEMU -d log selectors. Goal: enough to identify a #DB / single-step /
# RFLAGS-TF source without exploding the log to GB. Filter list:
#   int           — every interrupt/exception delivery (vector, errcode,
#                   guest CS:RIP, CR2) — this is the one we actually need.
#   cpu_reset     — full CPU state dump on reset, catches triple faults.
#   guest_errors  — guest-side faults QEMU notices (PT walks, bad MSR
#                   writes, IOMMU faults — relevant given VT-d is on).
#   nochain       — disable TB chaining so int events stay in order.
# Deliberately OFF: exec, in_asm (multi-GB log), mmu (very chatty under
# IOMMU). Add them manually with `QEMU_LOG=... ./run-tcg-...sh` if needed.
QEMU_LOG="${QEMU_LOG:-int,cpu_reset,guest_errors,nochain}"
echo "[run-tcg-swaptest] -d ${QEMU_LOG} -> qemu_int.log"

LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
    ~/qemu-9.2.0/build/qemu-system-x86_64 \
    -m 192 -accel tcg -smp 2 -no-reboot \
    -machine q35,kernel-irqchip=split \
    -device intel-iommu,aw-bits=48 \
    -vga none \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=ovmf_vars.fd \
    -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
    "${DISPLAY_ARGS[@]}" \
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
    -serial file:serial.log \
    -d "$QEMU_LOG" -D qemu_int.log "$@"

echo "[run-tcg-swaptest] done — see serial.log + qemu_int.log"
[ -x tools/crash_db.sh ] && tools/crash_db.sh serial.log
