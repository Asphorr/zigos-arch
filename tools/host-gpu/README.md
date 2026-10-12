# Host GPU for Venus under WSL2 (Mesa dzn)

ZigOS's Venus clients (the mode-9 GPU compositor, `vulkan_triangle`) can run
on the Windows host's GPU through WSL2's GPU paravirtualization:

    guest virtio-gpu (Venus) -> QEMU -> virglrenderer (vkr, render server
    in-process) -> Mesa dzn (Vulkan on D3D12) -> /dev/dxg -> host GPU driver

Tested with an RTX 3050 on Windows 10 (WSL2, Ubuntu 24.04), QEMU under TCG:
Windows 10's WSL2 has no nested virtualization, so there is no KVM.

Upstream virglrenderer and QEMU cannot do this as is; the two patches here
fill the gaps. Nothing in them is ZigOS-specific.

## Patches

`virglrenderer-host-ptr.patch` — base: virglrenderer `main` at `c8e3fc3`.

vkr exports host-visible memory as an fd so the VMM can map it into the
guest. dzn cannot export host-visible memory at all (D3D12 forbids
CPU-visible shared heaps). With the render server built into QEMU
(`-Drender-server-mode=thread`) no fd is needed: the blob can be the
driver's own `vkMapMemory` pointer.

- New `VIRGL_RESOURCE_HOST_PTR` resource type. `virgl_renderer_resource_map`
  returns the pointer, and fd export is refused. The render protocol passes
  the pointer only when the server runs in-process.
- At allocation, each memory type is probed once with a 64 KB exportable
  allocation. Host-visible memory the driver cannot export is allocated
  without export, and its blob becomes the mapping (MAPPABLE blobs only, no
  CROSS_DEVICE).
- The guest can free memory that QEMU still maps into the guest. Such memory
  is kept until the resource is destroyed or the device goes away. The freed
  range is then backfilled with anonymous pages, so a late access reads zeros
  instead of faulting.

On drivers that can export, nothing changes.

`qemu-11.1-scanout-host-ptr.patch` — base: QEMU 11.1.0 release tarball.

`SET_SCANOUT_BLOB` required a dma-buf. When there is none but the blob is
mapped, QEMU now wraps the mapping in a pixman surface without copying it.
`RESOURCE_FLUSH` uploads just the flushed rect to the display, and a scanout
is disabled when its blob is unmapped.

## Build (Ubuntu 24.04 on WSL2)

```sh
sudo apt-get install build-essential git meson ninja-build pkg-config \
    python3-mako python3-yaml python3-packaging python3-ply python3-venv \
    bison flex glslang-tools libdrm-dev libexpat1-dev zlib1g-dev libzstd-dev \
    libepoxy-dev libvulkan-dev libgbm-dev libglib2.0-dev libpixman-1-dev \
    libslirp-dev libsdl2-dev ovmf python3-tomli wget xz-utils \
    nasm dosfstools mtools genext2fs
sudo pip install --break-system-packages meson   # Mesa 26.2 needs a newer meson (used 1.10.1)

P=$HOME/gpupv/install
export PKG_CONFIG_PATH=$P/lib/x86_64-linux-gnu/pkgconfig:$P/lib/pkgconfig
cd $HOME/gpupv

# Mesa 26.2.4, dzn only (meson fetches DirectX-Headers as a subproject)
git clone --depth 1 --branch mesa-26.2.4 https://gitlab.freedesktop.org/mesa/mesa.git
(cd mesa && meson setup build -Dbuildtype=release -Dprefix=$P -Dplatforms= \
    -Dgallium-drivers= -Dvulkan-drivers=microsoft-experimental -Dopengl=false \
    -Dgles1=disabled -Dgles2=disabled -Degl=disabled -Dglx=disabled \
    -Dgbm=disabled -Dllvm=disabled -Dvideo-codecs= && ninja -C build install)

# virglrenderer, render server in-process
git clone https://gitlab.freedesktop.org/virgl/virglrenderer.git
(cd virglrenderer && git checkout c8e3fc3 \
    && git apply /path/to/zigos-arch/tools/host-gpu/virglrenderer-host-ptr.patch \
    && meson setup build -Dbuildtype=release -Dprefix=$P -Dvenus=true \
       -Dplatforms=egl -Drender-server-mode=thread -Drender-server-worker=thread \
    && ninja -C build install)

# QEMU 11.1.0
wget https://download.qemu.org/qemu-11.1.0.tar.xz && tar xf qemu-11.1.0.tar.xz
(cd qemu-11.1.0 && patch -p1 < /path/to/zigos-arch/tools/host-gpu/qemu-11.1-scanout-host-ptr.patch \
    && ./configure --prefix=$P --target-list=x86_64-softmmu --enable-opengl \
       --enable-virglrenderer --enable-sdl --enable-slirp --disable-docs --disable-werror \
    && ninja -C build qemu-system-x86_64)
```

Then build ZigOS in WSL with Zig 0.15.2 (`zig build -Doptimize=ReleaseSafe`)
and run `tools/host-gpu/run-wsl-dzn.sh`. `GPUPV`, `PREFIX` and `QEMU`
override the paths above. In the boot menu, pick "GPU Compositor
(experimental)" to get mode 9.

The vkr log should say `memory type N: host-visible export unavailable,
mapping via host pointers`. The ZigOS log should show `[gpu-comp] ...
sources=staged (GPU upload)` and `scanout: single mapped buffer, damage
flush`. `vulkan_triangle` reads back `9600 red of 76800` pixels.

## QEMU flags

Each of these works around a TCG problem ZigOS hits:

- `-accel tcg,thread=single -icount shift=auto,sleep=on`: under MTTCG the
  guest TSC calibrates far too high (13 GHz seen), so deadlines never expire
  (e.g. hda self-test hangs).
- `-cpu max,phys-bits=39`: with the default physical address width, PCI
  BARs land above the kernel's 512 GB physmap (#PF in msix).
- `monitor=off`: TCG advertises MWAIT interrupt-break but its MWAIT raises
  #GP when ECX is non-zero.
- `x2apic=off`: with icount, QEMU aborts on the x2APIC timer MSR read ("Bad
  icount read").
- `SDL_VIDEODRIVER=wayland GALLIUM_DRIVER=d3d12`: WSLg's X11 has no DRI3, so
  GL would fall back to software rendering.

## Inside a Hyper-V VM (KVM)

Windows 10's WSL2 has no nested virtualization, but a Hyper-V VM can: a
Linux guest with nested virtualization runs QEMU under KVM, and Hyper-V's
GPU paravirtualization (GPU-PV) gives it the same `/dev/dxg` as WSL2.
Tested with an Ubuntu 24.04 guest on kernel 7.0 and an RTX 3050 host.

1. On the host, in an elevated PowerShell: `hyperv-gpupv.ps1 -VMName NAME
   [-DataDisk D:\path\data.vhdx]`. It shuts the VM down, adds the GPU
   partition and the MMIO space it needs, and starts the VM again. A VM
   with a GPU partition can be neither saved nor checkpointed, so the
   script turns automatic checkpoints off and makes the VM shut down with
   the host. The driver store and the builds below take about 6 GB; the
   optional data disk is for that.

2. In the guest, build `dxgkrnl` (the `/dev/dxg` driver; it is not in
   mainline) from the WSL kernel, ported to 7.0 by `dxgkrnl-linux-7.0.patch`:

   ```sh
   # linux-msft-wsl-6.18.y at rolling-lts/wsl/6.18.54.1
   mkdir wsl-kernel && cd wsl-kernel && git init -q
   git remote add origin https://github.com/microsoft/WSL2-Linux-Kernel.git
   git sparse-checkout set drivers/hv/dxgkrnl include/uapi/misc
   git fetch --depth 1 --filter=blob:none origin d504d40ab83839cb61942a812a99d183c42227b9
   git checkout FETCH_HEAD && cd ..
   S=/usr/src/dxgkrnl-6.18.54.1
   sudo mkdir -p $S/include/uapi/misc
   sudo cp wsl-kernel/drivers/hv/dxgkrnl/* $S/
   sudo cp wsl-kernel/include/uapi/misc/d3dkmthk.h $S/include/uapi/misc/
   (cd $S && sudo patch -p1 < /path/to/zigos-arch/tools/host-gpu/dxgkrnl-linux-7.0.patch)
   ```

   and install it with DKMS so kernel updates rebuild it. In `$S/dkms.conf`:

   ```
   PACKAGE_NAME="dxgkrnl"
   PACKAGE_VERSION="6.18.54.1"
   BUILT_MODULE_NAME[0]="dxgkrnl"
   DEST_MODULE_LOCATION[0]="/updates/dkms"
   MAKE[0]="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build modules"
   CLEAN="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build clean"
   AUTOINSTALL="yes"
   ```

   then `sudo dkms install dxgkrnl/6.18.54.1` and
   `echo dxgkrnl | sudo tee /etc/modules-load.d/dxgkrnl.conf`. Once loaded
   it binds the vGPU's two VMBus channels and its PCI device (`1414:008e`).

3. Copy the user-mode side from the host into `/usr/lib/wsl`, as WSL2
   mounts it:
   - `/usr/lib/wsl/lib`: `C:\Windows\System32\lxss\lib`, then overwrite
     `libd3d12.so`, `libd3d12core.so` and `libdxcore.so` with the ones in
     `C:\Program Files\WSL\lib`. WSL itself layers those over the System32
     ones; with the System32 versions the NVIDIA driver crashes on a
     misaligned SSE store while the D3D12 device is created.
   - `ln -s libd3d12core.so /usr/lib/wsl/lib/libD3D12Core.so`: libd3d12
     asks for that name, which WSL's case-insensitive mount resolves.
   - `/usr/lib/wsl/drivers`: the GPU driver's folders from
     `C:\Windows\System32\DriverStore\FileRepository`. For NVIDIA that is
     `nv_dispi.inf_amd64_*` and `nvmdi.inf_amd64_*`; the user-mode driver
     the host reports lives in the latter.
   - `echo /usr/lib/wsl/lib | sudo tee /etc/ld.so.conf.d/ld.wsl.conf; sudo ldconfig`

   `vulkaninfo --summary` with the dzn ICD then lists the host GPU as
   `Microsoft Direct3D12 (...)`.

4. Build Mesa, virglrenderer and QEMU as above, and run
   `ACCEL=kvm run-wsl-dzn.sh`. Only the TCG flags change; the rest of the
   command line is the same.

## Limitations

- TCG only under WSL2: a handful of frames per second, bound by guest CPU
  emulation, not the GPU. A Hyper-V VM runs it under KVM (see above).
- WSLg presents the QEMU window by copying it (`[WARN:COPY MODE]` in the
  title).
- Lavapipe under WSL crashes QEMU in vkr's gbm fallback (`gbm_bo_create`; no
  DRM device). Test the Lavapipe path on a Linux host with KVM instead.
- There, use the SDL display: `egl-headless` crashes QEMU on the dma-buf
  scanout, with or without these patches.
