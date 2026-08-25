// Disk self-test — boot_mode = 16 entry.
//
// Drives the partitioning and mkfs path end to end against the install-target
// disk: write a GPT, format both partitions, then read everything back through
// the parse path. It exists because the only other driver of that code is the
// `mkdisk` CLI command, which needs a keyboard — so on a headless VM there was
// no way to run it at all, and therefore no way to check it from a script.
//
// This test does NOT prove the results are correct, only self-consistent. The
// real oracles are the host's own tools, run against install.img afterwards:
//
//   sgdisk -v install.img          both headers + both CRCs
//   e2fsck -fn <root partition>    bitmaps, inode table, directory structure
//   fsck.fat -n <esp partition>    FAT chains, FSInfo, boot sector backup
//
// A checker written by the same hand as the writer agrees with its own
// mistakes; those three do not. `tools/disk_selftest_check.sh` runs them.
//
// Run: zig build -Dboot-mode=16 && ./run-disk-selftest.sh
// PASS criterion: "[disktest] PASS" appears in serial.log.

const serial = @import("../debug/serial.zig");

const block = @import("../driver/block.zig");
const gpt = @import("../fs/gpt.zig");
const ext2_mkfs = @import("../fs/ext2/mkfs.zig");
const fat_mkfs = @import("../fs/fat32_mkfs.zig");
const ext2_layout = @import("../fs/ext2/layout.zig");

/// ESP size. 64 MiB is the conventional EFI System Partition size, and it is
/// also comfortably above the FAT32 cluster-count floor — see the trap
/// documented in fs/fat32_mkfs.zig.
const ESP_MIB: u64 = 64;

var fail_count: u32 = 0;

fn check(cond: bool, comptime msg: []const u8) void {
    if (!cond) {
        serial.print("[disktest] FAIL: " ++ msg ++ "\n", .{});
        fail_count += 1;
    }
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("\n[disktest] === disk self-test start ===\n", .{});

    run();

    if (fail_count == 0) {
        serial.print("[disktest] PASS — GPT written and re-read, both partitions formatted and verified\n", .{});
    } else {
        serial.print("[disktest] FAIL — {d} check(s) failed\n", .{fail_count});
    }
    serial.print("[disktest] === end; idling ===\n", .{});
    idle();
}

fn run() void {
    const dev = block.targetDevice() orelse {
        serial.print("[disktest] FAIL: no install target disk (expected NVMe controller #3)\n", .{});
        fail_count += 1;
        return;
    };
    serial.print("[disktest] target: {d} sectors ({d} MiB)\n", .{ dev.sectors, dev.sectors / 2048 });

    // --- 1. Partition, on 1 MiB boundaries (see gpt.ALIGN_SECTORS).
    const geom = @import("../util/geom.zig");
    const esp_span = geom.Span.fromFirstCount(gpt.alignUp(gpt.FIRST_USABLE_LBA), geom.Sectors.of(ESP_MIB * 2048));
    const root_start = esp_span.last.add(geom.Sectors.of(1));
    // Leave the backup entry array plus its header at the tail of the disk,
    // then pull the end back to an alignment boundary.
    const root_end = gpt.alignEndDown(geom.Lba.of(dev.sectors - 1 - gpt.ENTRY_ARRAY_SECTORS - 1));

    if (root_start.raw() >= root_end.raw()) {
        serial.print("[disktest] FAIL: target disk too small for a {d} MiB ESP plus a root\n", .{ESP_MIB});
        fail_count += 1;
        return;
    }
    const root_span = geom.Span.fromFirstLast(root_start, root_end);

    const specs = [_]gpt.PartSpec{
        .{ .type_guid = gpt.TYPE_ESP, .span = esp_span, .name = "EFI System" },
        .{ .type_guid = gpt.TYPE_LINUX_DATA, .span = root_span, .name = "ZIGOS" },
    };

    serial.print("[disktest] 1: writing GPT (ESP {d}..{d}, root {d}..{d})\n", .{ esp_span.first.raw(), esp_span.last.raw(), root_span.first.raw(), root_span.last.raw() });
    check(gpt.create(dev, &specs), "gpt.create failed");
    if (fail_count != 0) return;

    // --- 2. Re-read. Everything downstream works off the parsed table rather
    //        than the specs, so a table that round-trips wrong misplaces the
    //        formats instead of quietly passing.
    serial.print("[disktest] 2: re-reading GPT\n", .{});
    const table = gpt.parse(dev) catch |e| {
        serial.print("[disktest] FAIL: gpt.parse rejected our own table ({s})\n", .{@errorName(e)});
        @import("../util/errtrace.zig").dump(e, @errorReturnTrace());
        fail_count += 1;
        return;
    };
    check(!table.from_backup, "primary header unreadable — parse fell back to the backup");
    check(table.count == specs.len, "partition count changed across the round trip");
    if (fail_count != 0) return;

    for (table.parts[0..table.count], 0..) |p, i| {
        check(p.span.first == specs[i].span.first, "start_lba changed across the round trip");
        check(p.span.last == specs[i].span.last, "end_lba changed across the round trip");
        serial.print("[disktest]    part {d}: {d}..{d} ({d} MiB) name=\"{s}\"\n", .{ p.index + 1, p.span.first.raw(), p.span.last.raw(), p.sectorCount().raw() / 2048, p.name[0..p.name_len] });
    }
    check(table.parts[0].isEsp(), "partition 1 did not come back as an ESP");
    if (fail_count != 0) return;

    // --- 3. Format both.
    serial.print("[disktest] 3: mkfs\n", .{});
    for (table.parts[0..table.count]) |p| {
        const part_lba: u32 = @intCast(p.span.first.raw());
        const part_sectors: u32 = @intCast(p.sectorCount().raw());
        if (p.isEsp()) {
            check(fat_mkfs.format(.{ .dev = dev, .part_lba = part_lba, .part_sectors = part_sectors }, "ZIGOS ESP"), "mkfs.fat32 failed");
        } else {
            check(ext2_mkfs.format(.{ .dev = dev, .part_lba = part_lba, .part_sectors = part_sectors }, "ZIGOS"), "mkfs.ext2 failed");
        }
    }
    if (fail_count != 0) return;

    // --- 4. Read the signatures back off the disk.
    serial.print("[disktest] 4: verifying on-disk signatures\n", .{});
    for (table.parts[0..table.count]) |p| {
        const part_lba: u32 = @intCast(p.span.first.raw());
        var buf: [512]u8 = undefined;

        if (p.isEsp()) {
            check(dev.readSectors(part_lba, 1, &buf), "ESP boot sector read failed");
            check(buf[510] == 0x55 and buf[511] == 0xAA, "ESP boot signature missing");
            // fs_type at offset 82 is the human-readable format tag. It is
            // advisory per the spec, which is exactly why checking it is
            // worthwhile: nothing else would notice if we stopped writing it.
            check(buf[82] == 'F' and buf[83] == 'A' and buf[84] == 'T' and buf[85] == '3' and buf[86] == '2', "ESP fs_type is not FAT32");
        } else {
            // ext2 superblock is at byte 1024 of the partition — two sectors in.
            check(dev.readSectors(part_lba + 2, 1, &buf), "ext2 superblock read failed");
            const magic = @as(u16, buf[56]) | (@as(u16, buf[57]) << 8);
            check(magic == ext2_layout.MAGIC, "ext2 magic wrong");
            // A zero block count means the superblock was written but never
            // populated — the failure a magic-only check would sail past.
            const blocks = @as(u32, buf[4]) | (@as(u32, buf[5]) << 8) | (@as(u32, buf[6]) << 16) | (@as(u32, buf[7]) << 24);
            check(blocks > 0, "ext2 blocks_count is zero");
            serial.print("[disktest]    ext2: {d} blocks\n", .{blocks});
        }
    }
}

fn idle() noreturn {
    while (true) asm volatile ("hlt");
}
