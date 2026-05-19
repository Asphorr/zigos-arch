// Single source of truth for the SF Pro / SF Mono atlas blobs.
//
// Before 2026-05-19 there were two copies — one embedded by
// `lib/font_atlas.zig` (userspace libc + UEFI bootloader) and one by
// `src/ui/aa_font.zig` (kernel terminal). When tools/patch_atlas_blocks.py
// extended the lib/assets/ versions with block elements at 0x80..0x8F,
// the kernel's separate copy in src/ui/assets/ stayed ASCII-only —
// fastfetch's Z silently vanished because the kernel atlas didn't have
// the glyphs for 0x80/0x83/0x8D.
//
// This module is the single embed-site for all three blobs. Both the
// kernel parser (src/ui/aa_font.zig) and the userspace parser
// (lib/font_atlas.zig) import from here so a single
// `patch_atlas_blocks.py --in/--out lib/assets/font_*.bin` invocation
// updates everyone. The UEFI bootloader (lib/aa_font_uefi.zig) is
// statically linked separately and still @embedFile's directly from
// lib/assets/ — same files, different package, no divergence risk.

pub const blob_16: []const u8 align(2) = @embedFile("assets/font_16.bin");
pub const blob_24: []const u8 align(2) = @embedFile("assets/font_24.bin");
pub const blob_mono: []const u8 align(2) = @embedFile("assets/font_mono.bin");
