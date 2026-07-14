# ZigOS

![ZigOS desktop](docs/screenshots/screenshot5.png)

x86_64 hobby OS in Zig (~162 KLoC) — SMP + hybrid-CFS scheduler, demand
paging with swap, IOMMU isolation, NVMe with async Q_DEPTH=16, in-kernel
eBPF with a verifier and JIT, a Linux binary personality, TLS 1.3 with
Mozilla NSS roots, ACPI S3 suspend/resume, Vulkan compositor via
virtio-gpu + Venus, 83 userspace apps including Doom and Quake 1. Boots
on real hardware.

The screenshot above is a real boot: a shell with `fastfetch`, `wx Moscow`
(HTTPS + JSON over the kernel's TLS stack), the photo viewer (`stb_image`
PNG decode), and the file manager — all userspace ELFs on top of a fresh
kernel.

## Running it

**This is not a `git clone && qemu-system-x86_64 kernel.elf` project.**
The desktop's GL/Vulkan path requires virtio-gpu Venus, which only works
on a specific host stack:

- **QEMU master** with the Venus blob-scanout work (tested against
  `qemu-11.0.50`, built 2026-05-08). Stock QEMU 9.x lacks complete
  blob-scanout — the desktop boots to a black screen and the kernel
  logs report everything OK, because the guest-side path completes
  fine; the host just never produces a scanout.
- **virglrenderer** built with Venus enabled (`-Dvenus=enabled`),
  linked against your host mesa.
- **mesa** on the host providing the Venus driver.
- **Zig 0.15.2** — the build pins this exact version.
- An x86_64 Linux build host. Tested on Ubuntu 22.04 / 24.04.

Without Venus the kernel still boots: it falls back to 2D virtio scanout
or the plain UEFI GOP framebuffer — the GOP path is also how it runs on
real hardware — but the Vulkan apps and the GL compositor stay off.

Once the stack is in place:

```sh
zig build -Doptimize=ReleaseSafe
bash run-uefi-ext2-iommu.sh
```

`run-uefi-ext2-iommu.sh` is the canonical boot script — UEFI + ext2 root
image + IOMMU pass-through + the full driver stack (NVMe×3, xHCI,
virtio-net/gpu/sound, AC97, HDA, e1000, i225). The other `run-*.sh`
scripts either add devices (nvdimm/pmem, USB-attached storage) or
target degraded configurations (no IOMMU, SDL display, TCG-only) for
bisecting host-side regressions.

## What's in it

- **Kernel (`src/`):** SMP scheduler (hybrid-CFS, three priority bands ×
  min-vruntime within each), x86_64 4-level paging with PCID + global
  pages, demand paging with a page cache and swap, IOMMU isolation per
  DMA device, NVMe async I/O with IRQ-driven CQ reap, MSI-X with
  posted-write flush, sleep-aware mutexes, POSIX signals with job
  control (SIGSTOP/SIGCONT, EINTR, siginfo_t), MWAIT idle, MCE bank
  decode on #MC, PMU sampling on PMI.
- **eBPF (`src/bpf/`):** in-kernel VM with a verifier and x86_64 JIT
  (RFC 9669 ISA), programs loaded from userspace via `sys_bpf`.
- **Linux personality:** unmodified static Linux x86-64 binaries run
  through a syscall-translation layer.
- **ACPI (`src/acpi/`):** AML interpreter, SCI/EC handling, S3
  suspend-to-RAM with a working resume — PCI device re-init (GPU, xHCI,
  NVMe) and AP re-online included; Quake survives a suspend cycle.
- **Networking:** TCP/IP, DHCP client, 127.0.0.0/8 loopback,
  `/proc/net/{info,sock,arp}`, TLS 1.3 with 146 Mozilla NSS roots —
  outbound HTTPS from a userspace app works, and the Telegram client
  speaks MTProto against a real account.
- **Compositor:** virtio-gpu Venus blob scanout, zero-copy window
  framebuffers, 2D and GOP-framebuffer fallbacks for non-GL hosts and
  real hardware.
- **Debug machinery (`src/debug/`):** in-kernel GDB stub and debugger,
  KASAN + KCSAN, lock witness, watchdog, crash autopsy, per-phase perf
  accounting with a host-stall classifier. The kernel is deliberately
  loud about its own health.
- **Userspace (`app/`, 83 apps):** Doom (Chocolate Doom), Quake 1
  (id 1999 WinQuake), Vulkan cube/triangle, a small web browser,
  Telegram client, photo viewer, text editor, file manager, calc,
  paint, weather client (`wx`), fastfetch, netstat, syscall fuzzer.
- **Bootloader (`uefi/`):** custom UEFI app with GRUB-style cmdline
  editor, multi-mode boot dispatch, NVRAM boot-history ring.

## Layout

```
src/
  cpu/      idt gdt smp syscall (incl. Linux personality) mmu: paging pcid tlb iommu
  driver/   nvme xhci ahci e1000 i225 virtio_{net,gpu,sound} ac97 hda gop_fb pci
  proc/     process sched runqueue signals pipe hrtimer elf_loader spinlock
  mm/       pmm vmm heap slab page_cache swap shm pmem
  fs/       vfs ext2 fat32 tarfs devfs procfs
  net/      tcp ip dhcp dns
  crypto/   tls x509 asn1 random
  acpi/     aml s3 ec sci
  bpf/      vm verifier jit
  virt/     kvm hyperv vmx
  time/     apic hpet pit rtc smi
  ui/       desktop terminal compositor fonts icons
  debug/    kdbg gdb_stub kasan kcsan witness watchdog perf autopsy
app/        userspace ELFs
lib/        libc + venus + virgl wire encoders
uefi/       custom UEFI bootloader
tools/      host-side test harnesses
quake_src/  vendored Quake 1 source
doom_src/   vendored Chocolate DOOM source
```
