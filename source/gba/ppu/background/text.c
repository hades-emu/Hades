/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
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
    uint32_t x;
    struct io const *io;

    io = &gba->io;
    scanline->top_idx = bg_idx;
    for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
        uint32_t tile_x; // X coord of the tile in the tilemap
        uint32_t tile_y; // Y coord of the tile in the tilemap
        uint32_t chr_x;  // X coord of the pixel we want to render within the tile
        uint32_t chr_y;  // Y coord of the pixel we want to render within the tile
        uint32_t screen_addr;
        uint32_t screen_idx;
        uint32_t chrs_addr;
        uint8_t palette_idx;
        union tile tile;
        bool up_x;
        bool up_y;

        tile_x = ((x + io->bg_hoffset[bg_idx].raw) / 8);
        tile_y = ((line + io->bg_voffset[bg_idx].raw) / 8);
        up_x = bitfield_get(tile_x, 5);
        up_y = bitfield_get(tile_y, 5);
        tile_x %= 32;
        tile_y %= 32;
        chr_x  = (x + io->bg_hoffset[bg_idx].raw) % 8;
        chr_y  = (line + io->bg_voffset[bg_idx].raw) % 8;

        screen_addr = (uint32_t)io->bgcnt[bg_idx].screen_base * 0x800;
        chrs_addr = (uint32_t)io->bgcnt[bg_idx].character_base * 0x4000;

        switch (io->bgcnt[bg_idx].size) {
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
        chr_y ^= tile.vflip * 0b111;
        chr_x ^= tile.hflip * 0b111;

        if (io->bgcnt[bg_idx].palette_type) { // 256 colors, 1 palette
            palette_idx = mem_vram_read8(gba, chrs_addr + tile.number * 64 + chr_y * 8 + chr_x);
        } else { // 16 colors, 16 palettes

            /*
            ** In this mode, each byte represents two pixels:
            **   * The lower 4 bits define the color of the left pixel
            **   * The upper 4 bits define the color of the right pixel
            */

            palette_idx = mem_vram_read8(gba, chrs_addr + tile.number * 32 + chr_y * 4 + (chr_x >> 1));
            palette_idx >>= (chr_x % 2) * 4;
            palette_idx &= 0xF;
        }

        if (palette_idx) {
            struct rich_color c;

            c.raw = mem_palram_read16(
                gba,
                (tile.palette * 16 * !io->bgcnt[bg_idx].palette_type + palette_idx) * sizeof(union color)
            );

            c.visible = true;
            c.idx = bg_idx;
            scanline->top[x] = c;
        }
    }
}