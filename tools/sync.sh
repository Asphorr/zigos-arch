#!/bin/bash
# Sync local files to VM, build, and optionally create ESP image
# Usage: bash sync.sh [esp]

# Uses the `zigvm` ssh alias (set up by ~/.claude/.../zigvm-fix-ip.ps1) so the
# IP can be rewritten on Hyper-V subnet drift without editing this script.
VM="zigvm"
REMOTE_DIR="~/zigos-arch"
ZIG="~/Загрузки/zig-x86_64-linux-0.15.2/zig"

echo "=== Syncing source files to VM ==="
scp -r src/ "$VM:$REMOTE_DIR/src/"
scp -r app/ "$VM:$REMOTE_DIR/app/"
scp -r lib/ "$VM:$REMOTE_DIR/lib/"
scp build.zig "$VM:$REMOTE_DIR/build.zig"

echo "=== Building on VM ==="
ssh "$VM" "cd $REMOTE_DIR && $ZIG build -Doptimize=ReleaseSafe 2>&1" | tail -5

if [ "$1" = "esp" ]; then
    echo "=== Creating ESP image ==="
    ssh "$VM" 'export PATH=/usr/bin:/usr/sbin:$PATH && cd ~/zigos-arch && \
        dd if=/dev/zero of=zig-out/bin/esp.img bs=1M count=34 2>/dev/null && \
        printf "o\nn\np\n1\n2048\n\nt\nef\na\nw\n" | fdisk zig-out/bin/esp.img 2>/dev/null && \
        LOOP=$(sudo losetup -f --show -o 1048576 --sizelimit 34603008 zig-out/bin/esp.img) && \
        sudo mkfs.fat -F 32 $LOOP 2>/dev/null && \
        sudo mkdir -p /tmp/esp && sudo mount $LOOP /tmp/esp && \
        sudo mkdir -p /tmp/esp/EFI/BOOT && \
        sudo cp zig-out/bin/BOOTX64.efi /tmp/esp/EFI/BOOT/BOOTX64.EFI && \
        sudo cp zig-out/bin/kernel.elf /tmp/esp/kernel.elf && \
        sync && sudo umount /tmp/esp && sudo losetup -d $LOOP && \
        cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd && \
        echo "ESP image ready"'
fi

echo "=== Done ==="
