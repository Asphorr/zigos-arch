const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const optimize = b.standardOptimizeOption(.{});

    // --- KASAN (LLVM IR-pass pipeline) ---
    // When `-Dkasan=true`, replace the normal `b.addExecutable` kernel build
    // with the IR-pass pipeline in tools/kasan_pipeline.sh: emit LLVM IR via
    // `zig build-obj`, sed-add `sanitize_address` to allowlisted functions,
    // run `opt-20 -passes='asan<kernel>' --asan-force-dynamic-shadow`, then
    // `llc-20` and `ld`. The resulting kernel.elf has compile-time KASAN
    // instrumentation on every memory access in instrumented functions —
    // wild writes blow up at the writer, not at a downstream iretq.
    const kasan_enabled = b.option(bool, "kasan", "Build kernel with LLVM IR-pass KASAN (slower, slow-spots wild writes)") orelse false;

    // --- KCSAN (LLVM IR-pass pipeline) ---
    // When `-Dkcsan=true`, replace the normal kernel build with the IR-pass
    // pipeline in tools/kcsan_pipeline.sh: emit LLVM IR via `zig build-obj`,
    // tag allowlisted functions `sanitize_thread`, run `opt-20 -passes='tsan'`
    // with kernel-friendly options, then `llc-20` and `ld`. Resulting kernel
    // has compiler-emitted calls to __tsan_read*/__tsan_write* at every
    // memory access in instrumented functions; runtime in src/debug/kcsan.zig
    // implements the watchpoint protocol (sample → pause → resample +
    // cross-CPU watchpoint table for race detection).
    //
    // Mutually exclusive with -Dkasan: only one of the two ASan/TSan IR
    // passes can be applied to a single build.
    const kcsan_enabled = b.option(bool, "kcsan", "Build kernel with LLVM IR-pass KCSAN (~10x slower, finds concurrent-access races)") orelse false;
    if (kasan_enabled and kcsan_enabled) {
        @panic("-Dkasan and -Dkcsan are mutually exclusive");
    }

    // --- BUILD ID ---
    // Each `zig build` invocation gets a unique 64-bit ID (Unix timestamp).
    // The kernel embeds it via build options; mktar writes the same value to
    // BUILD.ID inside disk.tar. At boot the kernel compares them and shouts
    // if they don't match — so we never silently run with a stale tar again.
    const build_id_value: u64 = blk: {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        break :blk @intCast(ts.sec);
    };
    const build_options = b.addOptions();
    build_options.addOption(u64, "build_id", build_id_value);
    build_options.addOption(bool, "kasan_enabled", kasan_enabled);
    build_options.addOption(bool, "kcsan_enabled", kcsan_enabled);

    // --- 1. KERNEL ---
    // Forward-declare the shapes module here so the kernel module can
    // import it. The full graphics_mod / ui_mod / etc. are created later
    // (only userspace needs those).
    const kernel_shapes_mod = b.createModule(.{
        .root_source_file = b.path("lib/shapes.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Single source of truth for SF Pro / SF Mono atlas .bin blobs. Lives in
    // lib/ so its @embedFile resolves inside lib/assets/, the same files
    // patched by tools/patch_atlas_blocks.py. Both kernel
    // (src/ui/aa_font.zig) and userspace (lib/font_atlas.zig) import from
    // this module, eliminating the prior dual-copy drift.
    const font_blobs_mod = b.createModule(.{
        .root_source_file = b.path("lib/font_blobs.zig"),
        .target = target,
        .optimize = optimize,
    });

    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            // Higher-half kernel — default code-model "small" assumes
            // symbols fit in the low 2 GB. We link the kernel at -2 GB
            // (0xFFFFFFFF80000000), so LLVM needs the "kernel" code model
            // to emit sign-extended 32-bit relocations (`R_X86_64_32S`)
            // instead of unsigned `R_X86_64_32`. Without this every
            // .rodata reference panics ld.lld with "relocation out of
            // range: 18446744071… is not in [0, 4294967295]".
            .code_model = .kernel,
            .imports = &.{
                .{ .name = "shapes", .module = kernel_shapes_mod },
                .{ .name = "font_blobs", .module = font_blobs_mod },
            },
        }),
        // Zig 0.16's self-hosted x86 backend can't yet encode some of our
        // inline-asm forms (moffs r64, indirect via [%[addr]]). Force LLVM
        // for the kernel until the encoder catches up. Userspace and the
        // UEFI bootloader don't use those forms and use the new backend.
        .use_llvm = true,
    });
    kernel.setLinkerScript(b.path("src/linker.ld"));
    kernel.root_module.addOptions("build_options", build_options);

    // --- ASM ALIGNMENT LINTER ---
    // Run before linking to catch push-count drift at build time. Exits nonzero
    // on misalignment → aborts the build. The runtime guards in syscall_entry
    // and idt.zig are still the authoritative check; this is a fast-fail.
    const asm_lint = b.addSystemCommand(&.{ "python3", "tools/check_asm_alignment.py" });
    kernel.step.dependOn(&asm_lint.step);

    // Use addFileArg / addPrefixedFileArg so Zig tracks the .asm content for
    // its build-cache hash. Passing the path as a bare string literal in the
    // argv tuple looks fine but means Zig never sees the file as an input —
    // the cache then keeps a stale boot.o forever, even after the asm changes.
    // (Found out the hard way switching the boot identity map to 1 GB pages.)
    const nasm = b.addSystemCommand(&.{ "nasm", "-f", "elf64" });
    nasm.addFileArg(b.path("src/boot/boot.asm"));
    nasm.addArg("-o");
    const boot_obj = nasm.addOutputFileArg("boot.o");
    kernel.root_module.addObjectFile(boot_obj);

    // AP trampoline for SMP
    const nasm_ap = b.addSystemCommand(&.{ "nasm", "-f", "elf64" });
    nasm_ap.addFileArg(b.path("src/boot/ap_trampoline.asm"));
    nasm_ap.addArg("-o");
    const ap_obj = nasm_ap.addOutputFileArg("ap_trampoline.o");
    kernel.root_module.addObjectFile(ap_obj);

    if (!kasan_enabled and !kcsan_enabled) {
        b.installArtifact(kernel);
    }

    // Convert ELF64 to ELF32 for QEMU Multiboot loading
    const objcopy = b.addSystemCommand(&.{
        "objcopy", "-I", "elf64-x86-64", "-O", "elf32-i386",
    });
    objcopy.addArtifactArg(kernel);
    const kernel32 = objcopy.addOutputFileArg("kernel32.elf");
    const install32 = b.addInstallBinFile(kernel32, "kernel32.elf");
    if (!kasan_enabled and !kcsan_enabled) {
        b.getInstallStep().dependOn(&install32.step);
    }

    // KASAN build path: drives tools/kasan_pipeline.sh which produces both
    // kernel.elf and kernel32.elf in zig-out/bin directly. We still let Zig
    // run the asm linter + nasm steps above so they catch errors early; the
    // linker output gets overwritten by the pipeline.
    if (kasan_enabled) {
        const opt_str = switch (optimize) {
            .Debug => "Debug",
            .ReleaseSafe => "ReleaseSafe",
            .ReleaseFast => "ReleaseFast",
            .ReleaseSmall => "ReleaseSmall",
        };
        const kasan_build = b.addSystemCommand(&.{
            "bash",
            "tools/kasan_pipeline.sh",
            "/opt/zig-x86_64-linux-0.15.2/zig",
            opt_str,
            "zig-out/bin",
        });
        // Run after the asm linter — pipeline runs nasm itself, but if the
        // linter rejects asm we'd rather know up-front than after the IR
        // transform.
        kasan_build.step.dependOn(&asm_lint.step);
        b.getInstallStep().dependOn(&kasan_build.step);
    }

    // KCSAN build path — mirror of KASAN's, drives tools/kcsan_pipeline.sh.
    if (kcsan_enabled) {
        const opt_str = switch (optimize) {
            .Debug => "Debug",
            .ReleaseSafe => "ReleaseSafe",
            .ReleaseFast => "ReleaseFast",
            .ReleaseSmall => "ReleaseSmall",
        };
        const kcsan_build = b.addSystemCommand(&.{
            "bash",
            "tools/kcsan_pipeline.sh",
            "/opt/zig-x86_64-linux-0.15.2/zig",
            opt_str,
            "zig-out/bin",
        });
        kcsan_build.step.dependOn(&asm_lint.step);
        b.getInstallStep().dependOn(&kcsan_build.step);
    }

    // --- Shared library modules ---
    const libc_mod = b.createModule(.{
        .root_source_file = b.path("lib/libc.zig"),
        .target = target,
        .optimize = optimize,
    });
    const font_mod = b.createModule(.{
        .root_source_file = b.path("lib/font.zig"),
        .target = target,
        .optimize = optimize,
    });
    const font16_mod = b.createModule(.{
        .root_source_file = b.path("lib/font8x16.zig"),
        .target = target,
        .optimize = optimize,
    });
    const font24_mod = b.createModule(.{
        .root_source_file = b.path("lib/font12x24.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Shared 2D rasterization primitives — kernel gfx.zig and userspace
    // Canvas both wrap these. Kept in lib/ so both targets can import.
    const shapes_mod = b.createModule(.{
        .root_source_file = b.path("lib/shapes.zig"),
        .target = target,
        .optimize = optimize,
    });
    const graphics_mod = b.createModule(.{
        .root_source_file = b.path("lib/graphics.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "font", .module = font_mod },
            .{ .name = "font8x16", .module = font16_mod },
            .{ .name = "font12x24", .module = font24_mod },
            .{ .name = "shapes", .module = shapes_mod },
        },
    });
    const font_atlas_mod = b.createModule(.{
        .root_source_file = b.path("lib/font_atlas.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "graphics", .module = graphics_mod },
        },
    });
    const ui_mod = b.createModule(.{
        .root_source_file = b.path("lib/ui.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "graphics", .module = graphics_mod },
            .{ .name = "font", .module = font_mod },
            .{ .name = "font_atlas", .module = font_atlas_mod },
            .{ .name = "libc", .module = libc_mod },
        },
    });
    const virgl_mod = b.createModule(.{
        .root_source_file = b.path("lib/virgl.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "libc", .module = libc_mod },
        },
    });

    const venus_mod = b.createModule(.{
        .root_source_file = b.path("lib/venus.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "libc", .module = libc_mod },
        },
    });

    const spirv_mod = b.createModule(.{
        .root_source_file = b.path("lib/spirv.zig"),
        .target = target,
        .optimize = optimize,
    });

    // HTTP/1.1 client + JSON parser. Both sit on top of libc (TLS / TCP
    // syscalls for http; malloc for json). Userspace apps import either
    // via the standard gui_imports tuple below.
    const http_mod = b.createModule(.{
        .root_source_file = b.path("lib/http.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "libc", .module = libc_mod },
        },
    });
    const json_mod = b.createModule(.{
        .root_source_file = b.path("lib/json.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "libc", .module = libc_mod },
        },
    });
    // Open-Meteo client built on http + json. Used by both the
    // terminal wx.elf and the GUI weather.elf so the API + WMO code
    // mapping lives in one place.
    const weather_mod = b.createModule(.{
        .root_source_file = b.path("lib/weather.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "libc", .module = libc_mod },
            .{ .name = "http", .module = http_mod },
            .{ .name = "json", .module = json_mod },
        },
    });

    // Helper to create a user-space app executable
    const gui_imports: []const std.Build.Module.Import = &.{
        .{ .name = "libc", .module = libc_mod },
        .{ .name = "graphics", .module = graphics_mod },
        .{ .name = "font", .module = font_mod },
        .{ .name = "ui", .module = ui_mod },
        .{ .name = "font_atlas", .module = font_atlas_mod },
        .{ .name = "http", .module = http_mod },
        .{ .name = "json", .module = json_mod },
        .{ .name = "weather", .module = weather_mod },
    };

    // --- 2. USER APPS ---
    const app = b.addExecutable(.{
        .name = "app.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/shell.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
            },
        }),
    });
    app.setLinkerScript(b.path("app/linker.ld"));
    b.installArtifact(app);

    // GUI apps
    const gui_apps = .{
        .{ "gui_demo.elf", "app/gui_demo.zig" },
        .{ "sysmon.elf", "app/sysmon.zig" },
        .{ "calc.elf", "app/calc.zig" },
        // settings.elf moved below — it needs stb_image for the wallpaper
        // picker's thumbnail decode, which isn't wired into gui_imports.
        .{ "paint.elf", "app/paint.zig" },
        .{ "files.elf", "app/files.zig" },
        .{ "editor.elf", "app/editor.zig" },
        .{ "doom.elf", "app/doom.zig" },
        .{ "wc.elf", "app/wc.zig" },
        .{ "ls.elf", "app/ls.zig" },
        .{ "pipetest.elf", "app/pipetest.zig" },
        .{ "cat.elf", "app/cat.zig" },
        .{ "echo.elf", "app/echo.zig" },
        .{ "grep.elf", "app/grep.zig" },
        .{ "head.elf", "app/head.zig" },
        .{ "mmaptest.elf", "app/mmaptest.zig" },
        .{ "swaptest.elf", "app/swaptest.zig" },
        .{ "swapsys.elf", "app/swapsys.zig" },
        .{ "mtswap.elf", "app/mtswap.zig" },
        .{ "shmtest.elf", "app/shmtest.zig" },
        .{ "threadtest.elf", "app/threadtest.zig" },
        .{ "threadbrot.elf", "app/threadbrot.zig" },
        .{ "synctest.elf", "app/synctest.zig" },
        .{ "babel.elf", "app/babel.zig" },
        .{ "sigtest.elf", "app/sigtest.zig" },
        .{ "forktest.elf", "app/forktest.zig" },
        .{ "daemontest.elf", "app/daemontest.zig" },
        .{ "logd.elf", "app/logd.zig" },
        .{ "sleep.elf", "app/sleep.zig" },
        .{ "taskset.elf", "app/taskset.zig" },
        .{ "nice.elf", "app/nice.zig" },
        .{ "yes.elf", "app/yes.zig" },
        .{ "iretq_spin.elf", "app/iretq_spin.zig" },
        .{ "wget.elf", "app/wget.zig" },
        .{ "nslookup.elf", "app/nslookup.zig" },
        .{ "nc.elf", "app/nc.zig" },
        .{ "httpd.elf", "app/httpd.zig" },
        .{ "beep.elf", "app/beep.zig" },
        .{ "ps.elf", "app/ps.zig" },
        .{ "usbinfo.elf", "app/usbinfo.zig" },
        .{ "usbcat.elf", "app/usbcat.zig" },
        .{ "usbwrite.elf", "app/usbwrite.zig" },
        .{ "mkdir.elf", "app/mkdir.zig" },
        .{ "rmdir.elf", "app/rmdir.zig" },
        .{ "rm.elf", "app/rm.zig" },
        .{ "touch.elf", "app/touch.zig" },
        .{ "shutdown.elf", "app/shutdown.zig" },
        .{ "dmesg.elf", "app/dmesg.zig" },
        .{ "about.elf", "app/about.zig" },
        .{ "fastfetch.elf", "app/fastfetch.zig" },
        .{ "zigtop.elf", "app/zigtop.zig" },
        .{ "sigil.elf", "app/sigil.zig" },
        .{ "tg.elf", "app/tg.zig" },
        .{ "redteam.elf", "app/redteam.zig" },
        .{ "netstat.elf", "app/netstat.zig" },
        .{ "httpsget.elf", "app/httpsget.zig" },
        .{ "curl.elf", "app/curl.zig" },
        .{ "jq.elf", "app/jq.zig" },
        .{ "wx.elf", "app/wx.zig" },
        .{ "weather.elf", "app/weather.zig" },
        .{ "web.elf", "app/web.zig" },
    };

    inline for (gui_apps) |entry| {
        const exe = b.addExecutable(.{
            .name = entry[0],
            .root_module = b.createModule(.{
                .root_source_file = b.path(entry[1]),
                .target = target,
                .optimize = optimize,
                .imports = gui_imports,
            }),
        });
        exe.setLinkerScript(b.path("app/linker.ld"));
        b.installArtifact(exe);
    }

    // --- DOOM (real engine via doomgeneric) ---
    const doom_real = b.addExecutable(.{
        .name = "doom_real.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/doom_real.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
            },
        }),
    });
    doom_real.setLinkerScript(b.path("app/linker.ld"));
    doom_real.root_module.addCSourceFiles(.{
        .root = b.path("doom_src"),
        .files = &.{
            "am_map.c",    "d_event.c",   "d_items.c",   "d_iwad.c",
            "d_loop.c",    "d_main.c",    "d_mode.c",    "d_net.c",
            "doomdef.c",   "doomgeneric.c", "doomstat.c", "dstrings.c",
            "dummy.c",     "f_finale.c",  "f_wipe.c",    "g_game.c",
            "hu_lib.c",    "hu_stuff.c",  "i_cdmus.c",   "i_endoom.c",
            "i_input.c",   "i_joystick.c", "i_scale.c",  "i_sound.c",
            "i_system.c",  "i_timer.c",   "i_video.c",   "info.c",
            "m_argv.c",    "m_bbox.c",    "m_cheat.c",   "m_config.c",
            "m_controls.c", "m_fixed.c",  "m_menu.c",    "m_misc.c",
            "m_random.c",  "memio.c",     "p_ceilng.c",  "p_doors.c",
            "p_enemy.c",   "p_floor.c",   "p_inter.c",   "p_lights.c",
            "p_map.c",     "p_maputl.c",  "p_mobj.c",    "p_plats.c",
            "p_pspr.c",    "p_saveg.c",   "p_setup.c",   "p_sight.c",
            "p_spec.c",    "p_switch.c",  "p_telept.c",  "p_tick.c",
            "p_user.c",    "r_bsp.c",     "r_data.c",    "r_draw.c",
            "r_main.c",    "r_plane.c",   "r_segs.c",    "r_sky.c",
            "r_things.c",  "s_sound.c",   "sha1.c",      "sounds.c",
            "st_lib.c",    "st_stuff.c",  "statdump.c",  "tables.c",
            "v_video.c",   "w_checksum.c", "w_file.c",   "w_file_stdc.c",
            "w_main.c",    "w_wad.c",     "wi_stuff.c",  "z_zone.c",
        },
        .flags = &.{
            "-DDOOMGENERIC_RESX=640",
            "-DDOOMGENERIC_RESY=400",
            "-fno-stack-protector",
            "-Wno-implicit-function-declaration",
            "-Wno-int-conversion",
            "-Wno-pointer-sign",
            "-Wno-return-type",
            "-Wno-format",
            "-Wno-missing-declarations",
            "-Wno-shift-negative-value",
        },
    });
    doom_real.root_module.addSystemIncludePath(b.path("doom_src/include"));
    doom_real.root_module.addIncludePath(b.path("doom_src"));
    b.installArtifact(doom_real);

    // --- Quake 1 (real engine via vendored id WinQuake 1999 source) ---
    const quake1 = b.addExecutable(.{
        .name = "quake1.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/quake1.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
            },
        }),
    });
    quake1.setLinkerScript(b.path("app/linker.ld"));
    quake1.root_module.addCSourceFiles(.{
        .root = b.path("quake_src"),
        .files = &.{
            "cl_demo.c",   "cl_input.c",  "cl_main.c",   "cl_parse.c",  "cl_tent.c",
            "chase.c",     "cmd.c",       "common.c",    "console.c",   "crc.c",
            "cvar.c",      "draw.c",
            "d_edge.c",    "d_fill.c",    "d_init.c",    "d_modech.c",  "d_part.c",
            "d_polyse.c",  "d_scan.c",    "d_sky.c",     "d_sprite.c",  "d_surf.c",
            "d_vars.c",    "d_zpoint.c",
            "host.c",      "host_cmd.c",  "keys.c",      "menu.c",      "mathlib.c",
            "model.c",
            "net_loop.c",  "net_main.c",  "net_none.c",
            "nonintel.c",
            "pr_cmds.c",   "pr_edict.c",  "pr_exec.c",
            "r_aclip.c",   "r_alias.c",   "r_bsp.c",     "r_light.c",   "r_draw.c",
            "r_efrag.c",   "r_edge.c",    "r_misc.c",    "r_main.c",    "r_sky.c",
            "r_sprite.c",  "r_surf.c",    "r_part.c",    "r_vars.c",
            "screen.c",    "sbar.c",
            "snd_dma.c",   "snd_mem.c",   "snd_mix.c",
            "sv_main.c",   "sv_phys.c",   "sv_move.c",   "sv_user.c",
            "view.c",      "wad.c",       "world.c",     "zone.c",
            "cd_null.c",
            "sys_zigos.c",
        },
        .flags = &.{
            "-fno-stack-protector",
            "-fno-strict-aliasing",
            "-fno-builtin",
            "-ffreestanding",
            "-Wno-implicit-function-declaration",
            "-Wno-int-conversion",
            "-Wno-pointer-sign",
            "-Wno-return-type",
            "-Wno-format",
            "-Wno-missing-declarations",
            "-Wno-shift-negative-value",
            "-Wno-incompatible-pointer-types",
            "-Wno-parentheses",
            "-Wno-date-time",
            // GCC <10 default. Q1's renderer has tentative defs that
            // collide under lld's default strict mode (sadjust, tadjust,
            // bbextents et al appear in several r_*.c files).
            "-fcommon",
        },
    });
    quake1.root_module.addSystemIncludePath(b.path("quake_src/include"));
    quake1.root_module.addSystemIncludePath(b.path("doom_src/include"));
    quake1.root_module.addIncludePath(b.path("quake_src"));
    b.installArtifact(quake1);

    // --- STB_IMAGE BINDINGS (shared by photo.elf, wallpaper.elf, settings.elf) ---
    // First Zig 0.16 addTranslateC user: vendor/photo_lib.h is a tiny C
    // header declaring the public stb_image API surface; translate-c
    // produces a Zig module from it. The implementation lives in
    // vendor/photo_lib.c which gets re-compiled per app via addCSourceFile.
    const stb_tc = b.addTranslateC(.{
        .root_source_file = b.path("vendor/photo_lib.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    });
    const stb_mod = stb_tc.createModule();

    // libc shim re-exports (malloc/realloc/free/memset/memcpy/...) that
    // stb_image's C code calls. Apps that link photo_lib.c need to pull
    // these into their link unit.
    const stb_shims_mod = b.createModule(.{
        .root_source_file = b.path("lib/stb_shims.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "libc", .module = libc_mod },
        },
    });

    // C-source wiring helper: every app importing `stb` needs to (a)
    // compile vendor/photo_lib.c, (b) include vendor/, (c) include
    // doom_src/include/ for the freestanding libc shim headers
    // (stdlib.h, string.h, math.h — declarations only).
    const stb_cflags = &[_][]const u8{
        "-fno-stack-protector",
        "-Wno-unused-but-set-variable",
        "-Wno-unused-variable",
        "-Wno-unused-function",
        "-Wno-shift-negative-value",
        "-DSTBI_NO_THREAD_LOCALS",
    };

    // --- SETTINGS (uses stb_image for the wallpaper-picker thumbnail
    //     decode; moved here so it can link against vendor/photo_lib.c
    //     and import the translate-c stb module) ---
    const settings_exe = b.addExecutable(.{
        .name = "settings.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/settings.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
                .{ .name = "graphics", .module = graphics_mod },
                .{ .name = "font", .module = font_mod },
                .{ .name = "ui", .module = ui_mod },
                .{ .name = "font_atlas", .module = font_atlas_mod },
                .{ .name = "stb", .module = stb_mod },
                .{ .name = "stb_shims", .module = stb_shims_mod },
            },
        }),
    });
    settings_exe.setLinkerScript(b.path("app/linker.ld"));
    settings_exe.root_module.addCSourceFile(.{
        .file = b.path("vendor/photo_lib.c"),
        .flags = stb_cflags,
    });
    settings_exe.root_module.addIncludePath(b.path("vendor"));
    settings_exe.root_module.addSystemIncludePath(b.path("doom_src/include"));
    b.installArtifact(settings_exe);

    // --- PHOTO VIEWER ---
    const photo = b.addExecutable(.{
        .name = "photo.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/photo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
                .{ .name = "stb", .module = stb_mod },
                .{ .name = "stb_shims", .module = stb_shims_mod },
                .{ .name = "graphics", .module = graphics_mod },
                .{ .name = "ui", .module = ui_mod },
                .{ .name = "font_atlas", .module = font_atlas_mod },
            },
        }),
    });
    photo.setLinkerScript(b.path("app/linker.ld"));
    photo.root_module.addCSourceFile(.{
        .file = b.path("vendor/photo_lib.c"),
        .flags = stb_cflags,
    });
    photo.root_module.addIncludePath(b.path("vendor"));
    photo.root_module.addSystemIncludePath(b.path("doom_src/include"));
    b.installArtifact(photo);

    // --- WALLPAPER (one-shot boot helper) ---
    const wallpaper = b.addExecutable(.{
        .name = "wallpaper.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/wallpaper.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
                .{ .name = "stb", .module = stb_mod },
                .{ .name = "stb_shims", .module = stb_shims_mod },
            },
        }),
    });
    wallpaper.setLinkerScript(b.path("app/linker.ld"));
    wallpaper.root_module.addCSourceFile(.{
        .file = b.path("vendor/photo_lib.c"),
        .flags = stb_cflags,
    });
    wallpaper.root_module.addIncludePath(b.path("vendor"));
    wallpaper.root_module.addSystemIncludePath(b.path("doom_src/include"));
    b.installArtifact(wallpaper);

    // --- GPU TEST APP ---
    const gpu_test = b.addExecutable(.{
        .name = "gpu_test.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/gpu_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
                .{ .name = "virgl", .module = virgl_mod },
            },
        }),
    });
    gpu_test.setLinkerScript(b.path("app/linker.ld"));
    b.installArtifact(gpu_test);

    // --- VENUS TEST APP ---
    const venus_test = b.addExecutable(.{
        .name = "venus_test.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/venus_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
                .{ .name = "venus", .module = venus_mod },
            },
        }),
    });
    venus_test.setLinkerScript(b.path("app/linker.ld"));
    b.installArtifact(venus_test);

    const vulkan_triangle = b.addExecutable(.{
        .name = "vulkan_triangle.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/vulkan_triangle.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
                .{ .name = "venus", .module = venus_mod },
            },
        }),
    });
    vulkan_triangle.setLinkerScript(b.path("app/linker.ld"));
    b.installArtifact(vulkan_triangle);

    // --- VULKAN CUBE APP ---
    const vulkan_cube = b.addExecutable(.{
        .name = "vulkan_cube.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("app/vulkan_cube.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "libc", .module = libc_mod },
                .{ .name = "venus", .module = venus_mod },
                .{ .name = "spirv", .module = spirv_mod },
            },
        }),
    });
    vulkan_cube.setLinkerScript(b.path("app/linker.ld"));
    b.installArtifact(vulkan_cube);

    // --- 3. KERNEL.SYM (binary symbol table for in-kernel backtraces) ---
    // Reads kernel.elf, runs nm + gen_kernel_syms.py, drops KERNEL.SYM into
    // zig-out/bin. Hashed by kernel artifact, so it only re-runs when the
    // kernel actually relinks — same as any other Zig artifact.
    const mksym = b.addSystemCommand(&.{
        "bash", "-c",
        \\nm -nS "$1" | grep ' [TtBbDdRr] ' | python3 tools/gen_kernel_syms.py "$2"
        ,
        "mksym",
    });
    mksym.addArtifactArg(kernel);
    const sym_lazy = mksym.addOutputFileArg("KERNEL.SYM");
    const install_sym = b.addInstallBinFile(sym_lazy, "KERNEL.SYM");
    b.getInstallStep().dependOn(&install_sym.step);

    const sym_step = b.step("sym", "Generate KERNEL.SYM");
    sym_step.dependOn(&install_sym.step);

    // --- KERNEL.LINE (DWARF line-table dump for source-level backtraces) ---
    // Pre-resolves every kernel RIP to (file, line) at build time so the
    // in-kernel autopsy can print `sysFoo+0xN at file.zig:123` without
    // shipping the full DWARF info. Same lifetime semantics as KERNEL.SYM.
    const mklines = b.addSystemCommand(&.{
        "bash", "-c",
        \\objdump --dwarf=decodedline "$1" | LC_ALL=C python3 tools/gen_kernel_lines.py "$2"
        ,
        "mklines",
    });
    mklines.addArtifactArg(kernel);
    const lines_lazy = mklines.addOutputFileArg("KERNEL.LINE");
    const install_lines = b.addInstallBinFile(lines_lazy, "KERNEL.LINE");
    b.getInstallStep().dependOn(&install_lines.step);

    const lines_step = b.step("lines", "Generate KERNEL.LINE (DWARF line table)");
    lines_step.dependOn(&install_lines.step);

    // --- Generate BUILD.ID file (matches the build_id option embedded in kernel) ---
    // Written as 16 ASCII hex chars (uppercase, no newline) so it parses identically
    // on the kernel side. Lives in zig-out/bin so mktar picks it up.
    const mk_buildid = b.addSystemCommand(&.{
        "bash", "-c",
        b.fmt(
            \\mkdir -p zig-out/bin
            \\printf '%016X' {d} > zig-out/bin/BUILD.ID
            \\echo "[build] ID = $(cat zig-out/bin/BUILD.ID)"
        , .{build_id_value}),
    });

    // --- Create FAT32 disk image (64MB) with ELF binaries + KERNEL.SYM + WAD ---
    const mkdisk = b.addSystemCommand(&.{
        "bash", "-c",
        \\set -e
        \\# Skip if disk.img is newer than every input — saves ~1s on kernel-only edits.
        \\if [ -f disk.img ]; then
        \\  newest=$(ls -t zig-out/bin/*.elf zig-out/bin/KERNEL.SYM zig-out/bin/BUILD.ID doom1.wad 2>/dev/null | head -1 || true)
        \\  if [ -n "$newest" ] && [ "$newest" -ot disk.img ]; then
        \\    echo "[disk] up-to-date"
        \\    exit 0
        \\  fi
        \\fi
        \\dd if=/dev/zero of=disk.img bs=1M count=256 2>/dev/null
        \\mkfs.fat -F 32 disk.img >/dev/null
        \\for f in zig-out/bin/*.elf; do
        \\  [ -f "$f" ] && mcopy -i disk.img "$f" ::
        \\done
        \\[ -f zig-out/bin/KERNEL.SYM ] && mcopy -i disk.img zig-out/bin/KERNEL.SYM ::
        \\[ -f zig-out/bin/BUILD.ID ] && mcopy -i disk.img zig-out/bin/BUILD.ID ::
        \\[ -f doom1.wad ] && mcopy -i disk.img doom1.wad ::
        \\for f in www/*; do
        \\  [ -f "$f" ] && mcopy -i disk.img "$f" ::
        \\done
        \\echo "[disk] rebuilt"
        ,
    });
    mkdisk.step.dependOn(b.getInstallStep());
    mkdisk.step.dependOn(&install_sym.step);
    mkdisk.step.dependOn(&mk_buildid.step);
    const populate_disk = b.step("disk", "Create FAT32 disk.img with ELFs + KERNEL.SYM + doom1.wad");
    populate_disk.dependOn(&mkdisk.step);

    // --- Create ext2 disk image (64 MB) via genext2fs ---
    // No sudo, no losetup, no mkfs.ext2 — `genext2fs` creates a fully-formed
    // rev-1 ext2 image from a staging directory in one shot. Reproducible:
    // same staging tree → byte-identical image (modulo timestamps, which
    // `-f` can fix if we ever need that for build caching).
    //
    // Layout: 4 KB blocks (matches our driver's clamp), 16 384 blocks =
    // 64 MB, ~512 inodes (lots of headroom for ~50 files we currently
    // ship). `-q` squashes uid/perm so everything is root-owned with
    // sane defaults — kernel ignores both, but it makes images
    // byte-deterministic.
    //
    // Staging tree mirrors the runtime layout we want once ext2 is rooted
    // at `/`:
    //   /bin/*.elf   — every shipped app
    //   /KERNEL.SYM  — symbol table for in-kernel backtraces
    //   /BUILD.ID    — bootloader/kernel build_id check
    //   /share/*     — doom1.wad + www/* assets
    //   /etc/motd    — sanity-check string read by ext2 smoke tests
    const mkext2 = b.addSystemCommand(&.{
        "bash", "-c",
        \\set -e
        \\IMG=ext2.img
        \\STAGE=zig-out/ext2-stage
        \\
        \\# Skip rebuild if every input file is older than the image.
        \\if [ -f $IMG ]; then
        \\  newest=$( { ls -t zig-out/bin/*.elf zig-out/bin/KERNEL.SYM zig-out/bin/BUILD.ID doom1.wad www/* 2>/dev/null; find share -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2; } | head -1 || true)
        \\  if [ -n "$newest" ] && [ "$newest" -ot $IMG ]; then
        \\    echo "[ext2] up-to-date"
        \\    exit 0
        \\  fi
        \\fi
        \\
        \\rm -rf $STAGE
        \\mkdir -p $STAGE/bin $STAGE/etc $STAGE/share $STAGE/var/log
        \\for f in zig-out/bin/*.elf; do
        \\  [ -f "$f" ] && cp "$f" $STAGE/bin/
        \\done
        \\[ -f zig-out/bin/KERNEL.SYM ] && cp zig-out/bin/KERNEL.SYM $STAGE/
        \\[ -f zig-out/bin/KERNEL.LINE ] && cp zig-out/bin/KERNEL.LINE $STAGE/
        \\[ -f zig-out/bin/BUILD.ID ] && cp zig-out/bin/BUILD.ID $STAGE/
        \\[ -f doom1.wad ] && cp doom1.wad $STAGE/share/
        \\for f in www/*; do
        \\  [ -f "$f" ] && cp "$f" $STAGE/share/
        \\done
        \\# Recursive copy so nested data dirs land at the right path —
        \\# e.g. share/quake/id1/pak0.pak → /share/quake/id1/pak0.pak.
        \\if [ -d share ]; then
        \\  cp -r share/. $STAGE/share/
        \\fi
        \\printf "ext2 read test, hello from /etc/motd\n" > $STAGE/etc/motd
        \\# Pre-touch /var/log/messages so logd can O_APPEND it (ext2 driver
        \\# has no createFile yet, so files must exist before first open).
        \\: > $STAGE/var/log/messages
        \\cat > $STAGE/etc/zigos.conf <<'EOF'
        \\# ZigOS UI configuration
        \\# Edit values 0..N to change appearance / input. Saved by the Settings
        \\# app and read by the desktop at boot. The editor opens this file too —
        \\# Ctrl+S to save your changes.
        \\#
        \\# resolution    0=1280x720, 1=1920x1080
        \\# background    0=blue, 1=purple, 2=green, 3=red
        \\# theme         0=light, 1=dark
        \\# mouse_speed   0=slow, 1=normal, 2=fast
        \\# dock_pos      0=bottom, 1=top
        \\resolution=1
        \\background=0
        \\theme=0
        \\mouse_speed=1
        \\dock_pos=0
        \\EOF
        \\
        \\genext2fs -B 4096 -b 65536 -N 2048 -d $STAGE -q $IMG
        \\echo "[ext2] rebuilt ($(du -h $IMG | cut -f1))"
        ,
    });
    mkext2.step.dependOn(b.getInstallStep());
    mkext2.step.dependOn(&mk_buildid.step);
    const ext2_step = b.step("ext2", "Create ext2.img via genext2fs (no sudo)");
    ext2_step.dependOn(&mkext2.step);

    // --- Create tarfs disk.tar (project root, used as IDE index=0) ---
    const mktar = b.addSystemCommand(&.{
        "bash", "-c",
        \\set -e
        \\# Skip if disk.tar is newer than every app .elf AND BUILD.ID — kernel-only
        \\# edits don't need a fresh tar, but app edits and new build IDs absolutely do.
        \\if [ -f disk.tar ]; then
        \\  newest=$(ls -t zig-out/bin/*.elf zig-out/bin/BUILD.ID 2>/dev/null | head -1 || true)
        \\  if [ -n "$newest" ] && [ "$newest" -ot disk.tar ]; then
        \\    echo "[tar] up-to-date"
        \\    exit 0
        \\  fi
        \\fi
        \\cd zig-out/bin
        \\# Order matters — tarfs scans only the first 8000 sectors (4 MB) for
        \\# its index. KERNEL.SYM goes early so symbols.loadKernelSymbols
        \\# always finds it regardless of what's on IDE2 (FAT32 or ext2 in
        \\# Phase 1-2 dev). app.elf next so the shell is always loadable.
        \\# Then tiny + CLI staples + GUI apps.
        \\tar cf ../../disk.tar \
        \\  BUILD.ID KERNEL.SYM KERNEL.LINE \
        \\  app.elf \
        \\  gui_demo.elf pipetest.elf sigtest.elf \
        \\  cat.elf ls.elf wc.elf echo.elf grep.elf head.elf sleep.elf taskset.elf nice.elf yes.elf iretq_spin.elf \
        \\  ps.elf dmesg.elf mkdir.elf rmdir.elf rm.elf touch.elf shutdown.elf beep.elf \
        \\  sysmon.elf calc.elf settings.elf files.elf about.elf fastfetch.elf zigtop.elf sigil.elf tg.elf \
        \\  paint.elf editor.elf doom.elf gpu_test.elf vulkan_triangle.elf \
        \\  venus_test.elf vulkan_cube.elf doom_real.elf \
        \\  mmaptest.elf threadtest.elf threadbrot.elf synctest.elf babel.elf forktest.elf daemontest.elf logd.elf photo.elf wallpaper.elf \
        \\  shmtest.elf redteam.elf
        \\echo "[tar] rebuilt"
        ,
    });
    mktar.step.dependOn(b.getInstallStep());
    mktar.step.dependOn(&mk_buildid.step);
    mktar.step.dependOn(b.getInstallStep());
    const tar_step = b.step("tar", "Create disk.tar (tarfs)");
    tar_step.dependOn(&mktar.step);

    // --- UEFI BOOTLOADER ---
    const uefi_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .uefi,
        .abi = .msvc,
    });

    // SF Pro AA atlases for the UEFI menu/splash. Lives in `lib/` so its
    // `@embedFile("assets/font_16.bin")` resolves inside the lib/ package.
    // Built as a module with the uefi/msvc target so it links into the
    // bootloader's PE/COFF output without ABI mismatch.
    const bootloader_aa_font_mod = b.createModule(.{
        .root_source_file = b.path("lib/aa_font_uefi.zig"),
        .target = uefi_target,
        .optimize = .ReleaseSafe,
    });

    const bootloader = b.addExecutable(.{
        .name = "BOOTX64",
        .root_module = b.createModule(.{
            .root_source_file = b.path("uefi/uefi_boot.zig"),
            .target = uefi_target,
            .optimize = .ReleaseSafe,
            .imports = &.{
                .{ .name = "aa_font", .module = bootloader_aa_font_mod },
            },
        }),
    });
    // Embed the same build_id into the bootloader so it can stamp every
    // BootInfo it produces. The kernel compares this to its own
    // compile-time build_id at startup — divergence means kernel.elf
    // and BOOTX64.efi came from different builds (one stale on disk).
    bootloader.root_module.addOptions("build_options", build_options);
    b.installArtifact(bootloader);

    // --- Create ESP (EFI System Partition) FAT32 image with MBR ---
    // Uses fdisk + losetup for proper partition table (required by OVMF)
    const mkesp = b.addSystemCommand(&.{
        "bash", "-c",
        \\set -e
        \\IMG=zig-out/bin/esp.img
        \\dd if=/dev/zero of=$IMG bs=1M count=34 2>/dev/null
        \\printf 'o\nn\np\n1\n2048\n\nt\nef\na\nw\n' | fdisk $IMG >/dev/null 2>&1
        \\LOOP=$(sudo losetup -f --show -o 1048576 --sizelimit 34603008 $IMG)
        \\sudo mkfs.fat -F 32 $LOOP >/dev/null 2>&1
        \\sudo mkdir -p /tmp/zigos_esp
        \\sudo mount $LOOP /tmp/zigos_esp
        \\sudo mkdir -p /tmp/zigos_esp/EFI/BOOT
        \\sudo cp zig-out/bin/BOOTX64.efi /tmp/zigos_esp/EFI/BOOT/BOOTX64.EFI
        \\sudo cp zig-out/bin/kernel.elf /tmp/zigos_esp/kernel.elf
        \\sync
        \\sudo umount /tmp/zigos_esp
        \\sudo losetup -d $LOOP
        \\[ -f ovmf_vars.fd ] || cp /usr/share/OVMF/OVMF_VARS_4M.fd ovmf_vars.fd
        \\echo "[build] ESP image ready: $IMG"
        ,
    });
    mkesp.step.dependOn(&bootloader.step);
    mkesp.step.dependOn(&kernel.step);
    const esp_step = b.step("esp", "Build UEFI ESP image (real partitioned image, needs sudo)");
    esp_step.dependOn(&mkesp.step);

    // --- ESP DIRECTORY for QEMU's fat:rw: virtual filesystem ---
    // Plain directory tree mirroring the ESP layout. QEMU exposes it as a
    // virtual FAT block device via `-drive file=fat:32:rw:zig-out/esp,...`,
    // so OVMF sees a real ESP without losetup/mount/sudo. Rebuild cost is
    // two `cp` calls per kernel change. Used by run-uefi.sh.
    const mkesp_dir = b.addSystemCommand(&.{
        "bash", "-c",
        \\set -e
        \\mkdir -p zig-out/esp/EFI/BOOT
        \\cp zig-out/bin/BOOTX64.efi zig-out/esp/EFI/BOOT/BOOTX64.EFI
        \\cp zig-out/bin/kernel.elf zig-out/esp/kernel.elf
        ,
    });
    mkesp_dir.step.dependOn(&bootloader.step);
    mkesp_dir.step.dependOn(&kernel.step);
    // The cp commands read from zig-out/bin/{kernel.elf,BOOTX64.efi} —
    // which only exist AFTER the install step copies them out of the
    // compile cache. Depending on kernel.step + bootloader.step alone
    // is NOT enough: those produce cache-path artifacts, not zig-out/bin
    // files. Without this dependency mkesp_dir can fire between compile
    // and install, reading a STALE zig-out/bin/kernel.elf from the
    // previous build — the exact symptom observed 2026-05-20 (esp had
    // build_id 24CC, bin had 253B, both touched within 35ms).
    mkesp_dir.step.dependOn(b.getInstallStep());
    // Declare the real file inputs so the step's input-hash flips when
    // either binary changes. Without this, Zig's addSystemCommand cache
    // treats the bash-script argv as the only input and skips the cp
    // forever after the first successful run — leaving zig-out/esp/
    // serving a stale kernel.elf even though kernel.step rebuilt.
    // (Captured 2026-05-15 in feedback_esp_kernel_cp_after_build memory;
    // 2026-05-20: structurally fixed here rather than via post-build cp.)
    mkesp_dir.addFileInput(kernel.getEmittedBin());
    mkesp_dir.addFileInput(bootloader.getEmittedBin());
    const esp_dir_step = b.step("esp-dir", "Create ESP dir tree for QEMU fat:rw: (no sudo)");
    esp_dir_step.dependOn(&mkesp_dir.step);

    // --- 4. META STEPS ---

    // `zig build all` — rebuild everything in one shot:
    // kernel + apps + KERNEL.SYM + disk.img + disk.tar + ext2.img + esp.img.
    // Skips per-step work that's already up-to-date (Zig hashes inputs).
    const all_step = b.step("all", "Build kernel, apps, KERNEL.SYM, disk.img, disk.tar, ext2.img, esp.img");
    all_step.dependOn(b.getInstallStep());
    all_step.dependOn(&mkdisk.step);
    all_step.dependOn(&mktar.step);
    all_step.dependOn(&mkext2.step);
    all_step.dependOn(&mkesp.step);

    // Make `zig build` (no args) regenerate disk.tar + disk.img + ext2.img too
    // — that way the running OS always boots fresh app binaries, no more
    // silently booting last hour's tar with this hour's kernel. ESP stays
    // out (needs sudo for the partitioned image, though `mkesp_dir` provides
    // a no-sudo dir-tree variant for QEMU's `fat:rw:`). We DO warn loudly if
    // esp.img is older than kernel.elf.
    const esp_stale_check = b.addSystemCommand(&.{
        "bash", "-c",
        \\if [ -f zig-out/bin/esp.img ] && [ zig-out/bin/kernel.elf -nt zig-out/bin/esp.img ]; then
        \\  echo "[esp] WARNING: zig-out/bin/esp.img is older than kernel.elf — run 'sudo zig build esp' before booting under UEFI" >&2
        \\fi
        \\true
        ,
    });
    esp_stale_check.step.dependOn(b.getInstallStep());

    const default_with_disk = b.step("default", "");
    default_with_disk.dependOn(b.getInstallStep());
    default_with_disk.dependOn(&mkdisk.step);
    default_with_disk.dependOn(&mktar.step);
    default_with_disk.dependOn(&mkext2.step);
    default_with_disk.dependOn(&mkesp_dir.step);
    default_with_disk.dependOn(&esp_stale_check.step);
    b.default_step = default_with_disk;

    // `zig build clean` — wipe local + global caches and zig-out.
    // Only needed when the cache poisons itself (rare); used to force a
    // full rebuild when source changes are silently ignored.
    const clean_cmd = b.addSystemCommand(&.{
        "bash", "-c",
        \\rm -rf .zig-cache zig-out
        \\rm -rf "$HOME/.cache/zig"
        \\echo "[clean] caches and zig-out cleared"
        ,
    });
    const clean_step = b.step("clean", "Wipe .zig-cache, ~/.cache/zig, and zig-out");
    clean_step.dependOn(&clean_cmd.step);

    // `zig build debug` — boot QEMU with QEMU's gdbstub on :1234 and our
    // in-kernel stub bridged via COM2 on :1235. Doesn't halt at boot; gdb can
    // attach any time (e.g. after a kernel crash drops into the stub). Pass
    // `-Dhalt=true` to halt CPU until gdb sends `continue`.
    const halt_at_boot = b.option(bool, "halt", "Halt CPU at boot until gdb attaches and continues") orelse false;
    const debug_args = if (halt_at_boot)
        &[_][]const u8{ "bash", "-c", "./run-debug.sh --halt" }
    else
        &[_][]const u8{ "bash", "-c", "./run-debug.sh" };
    const debug_cmd = b.addSystemCommand(debug_args);
    // Build kernel first so the .elf is fresh.
    debug_cmd.step.dependOn(b.getInstallStep());
    const debug_step = b.step("debug", "Boot under QEMU with gdbstub on :1234 (use -Dhalt=true to pause at boot)");
    debug_step.dependOn(&debug_cmd.step);
}
