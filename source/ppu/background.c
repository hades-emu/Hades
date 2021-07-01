/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "gba.h"
#include "ppu.h"

void
ppu_render_background_bitmap(
    struct gba *gba,
    uint32_t line,
    bool palette
) {
    uint32_t x;

    for (x = 0; x < SCREEN_WIDTH; ++x) {
        union color c;

        if (palette) {
            uint8_t palette_idx;

            palette_idx = mem_read8(gba, VRAM_START + (SCREEN_WIDTH * line + x) + 0xA000 * gba->io.dispcnt.frame);
            c.raw = mem_read16(gba, PALRAM_START + palette_idx * sizeof(union color));
        } else {
            c.raw = mem_read16(gba, VRAM_START + (SCREEN_WIDTH * line + x) * sizeof(union color));
        }

        ppu_plot_pixel(gba, c, x, line);
    }
}

void
ppu_render_background_affine(
    struct gba *gba __unused,
    uint32_t line __unused,
    uint32_t bg_idx __unused
) {
    // TODO
}

void
ppu_render_background_text(
    struct gba *gba,
    uint32_t line,
    uint32_t bg_idx
) {
    uint32_t x;
    struct io *io;

    io = &gba->io;
    for (x = 0; x < SCREEN_WIDTH; ++x) {
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

        switch (io->bgcnt[bg_idx].screen_size) {
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

        tile.raw = mem_read16(gba, VRAM_START + screen_addr + screen_idx * sizeof(union tile));
        chr_y ^= tile.vflip * 0b111;
        chr_x ^= tile.hflip * 0b111;

        if (io->bgcnt[bg_idx].palette_type) { // 256 colors, 1 palette
            palette_idx = mem_read8(gba,
                VRAM_START + chrs_addr + tile.number * 64 + chr_y * 8 + chr_x
            );
        } else { // 16 colors, 16 palettes

            /*
            ** In this mode, each byte represents two pixels:
            **   * The lower 4 bits define the color for the left pixel
            **   * The upper 4 bits define the color for the right pixel
            */

            palette_idx = mem_read8(gba,
                VRAM_START + chrs_addr + tile.number * 32 + chr_y * 4 + (chr_x >> 1)
            );
            palette_idx >>= (chr_x % 2) * 4;
            palette_idx &= 0xF;
        }

        if (palette_idx) {
            union color c;

            c.raw = mem_read16(
                gba,
                PALRAM_START + (tile.palette * 16 * !io->bgcnt[bg_idx].palette_type + palette_idx) * sizeof(union color)
            );

            ppu_plot_pixel(gba, c, x, line);
        }
    }
}