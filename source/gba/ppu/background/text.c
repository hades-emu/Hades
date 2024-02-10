/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include "gba/gba.h"
#include "gba/ppu.h"

/*
** Render the bitmap background of given index.
*/
void
ppu_render_background_text(
    struct gba const *gba,
    struct scanline *scanline,
    uint32_t line,
    uint32_t bg_idx
) {
    struct io const *io;
    bool mosaic;
    bool palette_type;
    uint32_t bg_size;
    uint32_t screen_addr;
    uint32_t chrs_addr;
    uint32_t x;
    int32_t rel_y;          // Y coord of the pixel within the bg
    uint32_t tile_y;        // Y coord of the tile in the tilemap
    uint32_t chr_y;         // Y coord of the pixel we want to render within the tile
    bool up_y;

    io = &gba->io;
    scanline->top_idx = bg_idx;

    /* Retrieve all those before so that we don't have to read them for each pixel. */
    mosaic = io->bgcnt[bg_idx].mosaic;
    bg_size = io->bgcnt[bg_idx].size;
    palette_type = io->bgcnt[bg_idx].palette_type;
    screen_addr = (uint32_t)io->bgcnt[bg_idx].screen_base * 0x800;
    chrs_addr = (uint32_t)io->bgcnt[bg_idx].character_base * 0x4000;

    /*
    ** Do all the maths for the Y coordinate first, since those do not change until the next scanline.
    */

    if (mosaic) {
        rel_y = line / (io->mosaic.bg_vsize + 1) * (io->mosaic.bg_vsize + 1);
    } else {
        rel_y = line;
    }
    rel_y += io->bg_voffset[bg_idx].raw;
    tile_y = (rel_y / 8);
    up_y = tile_y & 0b100000;
    tile_y %= 32;
    chr_y = rel_y % 8;

    /* Now iterate for each pixels of this scanline. */
    for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
        int32_t rel_x;          // X coord of the pixel within the bg
        uint32_t tile_x;        // X coord of the tile in the tilemap
        uint32_t chr_x;         // X coord of the pixel we want to render within the tile
        uint32_t chr_vy;        // Y coord of the pixel we want to render within the tile
        uint32_t screen_idx;
        uint8_t palette_idx;
        union tile tile;
        bool up_x;

        if (mosaic) {
            rel_x = x / (io->mosaic.bg_hsize + 1) * (io->mosaic.bg_hsize + 1);
        } else {
            rel_x = x;
        }

        rel_x += io->bg_hoffset[bg_idx].raw;

        tile_x = (rel_x / 8);
        up_x = tile_x & 0b100000;
        tile_x %= 32;
        chr_x = rel_x % 8;

        switch (bg_size) {
            case 0b00: // 256x256 (32x32)
                screen_idx = tile_y * 32 + tile_x;
                break;
            case 0b01: // 512x256 (64x32)
                screen_idx = tile_y * 32 + tile_x + up_x * 1024;
                break;
            case 0b10: // 256x512 (32x64)
                screen_idx = tile_y * 32 + tile_x + up_y * 1024;
                break;
            case 0b11: // 512x512 (64x64)
                screen_idx = tile_y * 32 + tile_x + up_x * 1024 + up_y * 2048;
                break;
        }

        tile.raw = mem_vram_read16(gba, screen_addr + screen_idx * sizeof(union tile));
        chr_vy = chr_y ^ tile.vflip * 0b111;
        chr_x ^= tile.hflip * 0b111;

        if (palette_type) { // 256 colors, 1 palette
            palette_idx = mem_vram_read8(gba, chrs_addr + tile.number * 64 + chr_vy * 8 + chr_x);
        } else { // 16 colors, 16 palettes

            /*
            ** In this mode, each byte represents two pixels:
            **   * The lower 4 bits define the color of the left pixel
            **   * The upper 4 bits define the color of the right pixel
            */

            palette_idx = mem_vram_read8(gba, chrs_addr + tile.number * 32 + chr_vy * 4 + (chr_x >> 1));
            palette_idx >>= (chr_x % 2) * 4;
            palette_idx &= 0xF;
        }

        if (palette_idx) {
            struct rich_color c;

            c.raw = mem_palram_read16(
                gba,
                (tile.palette * 16 * !palette_type + palette_idx) * sizeof(union color)
            );

            c.visible = true;
            c.idx = bg_idx;
            c.force_blend = false;
            scanline->bg[x] = c;
        } else {
            scanline->bg[x].visible = false;
        }
    }
}
