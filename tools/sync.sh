#!/bin/bash
# Sync local files to VM, build, and optionally create ESP image
# Usage: bash sync.sh [esp]

VM="feroupc@172.20.220.60"
KEY="$HOME/.ssh/hyperv_vm"
ZIG="/opt/zig-x86_64-linux-0.15.2/zig"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no $VM"
SCP="scp -i $KEY -o StrictHostKeyChecking=no"

echo "=== Syncing source files to VM ==="
$SCP -r src/ "$VM:~/zigos-sse2/src/"
$SCP -r app/ "$VM:~/zigos-sse2/app/"
$SCP -r lib/ "$VM:~/zigos-sse2/lib/"
$SCP -r boot/ "$VM:~/zigos-sse2/boot/"
$SCP build.zig "$VM:~/zigos-sse2/build.zig"

echo "=== Building on VM ==="
$SSH "cd ~/zigos-sse2 && $ZIG build -Doptimize=ReleaseSafe 2>&1" | tail -5

if [ "$1" = "esp" ]; then
    echo "=== Creating ESP image ==="
    $SSH 'export PATH=/usr/bin:/usr/sbin:$PATH && cd ~/zigos-sse2 && \
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
