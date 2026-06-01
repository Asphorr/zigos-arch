//! Bundled font for the Telegram client GUI.
//!
//! DejaVu Sans (Bitstream Vera / DejaVu license — freely redistributable) is
//! the only font in the tree with full Cyrillic coverage. The pre-rendered SF
//! Pro AA atlas (lib/font_atlas.zig) is ASCII-only (codepoints 32..126), so it
//! cannot draw Russian contact names or messages. We rasterize this TTF on the
//! fly via lib/ttf_text.zig (stb_truetype) and cache the glyphs.
pub const bytes = @embedFile("assets/dejavu.ttf");
