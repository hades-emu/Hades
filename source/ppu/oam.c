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

/*
**  0000: 8  x 8         1000: 8  x 16
**  0001: 16 x 16        1001: 8  x 32
**  0010: 32 x 32        1010: 16 x 32
**  0011: 64 x 64        1011: 32 x 64
**  0100: 16 x 8         1100: Not used
**  0101: 32 x 8         1101: Not used
**  0110: 32 x 16        1110: Not used
**  0111: 64 x 32        1111: Not used
*/
int32_t sprite_size_x[16] = { 8, 16, 32, 64, 16, 32, 32, 64, 8, 8, 16, 32, 0, 0, 0, 0};
int32_t sprite_size_y[16] = { 8, 16, 32, 64, 8, 8, 16, 32, 16, 32, 32, 64, 0, 0, 0, 0};

void
ppu_render_oam(
    struct gba *gba,
    int32_t line,
    uint32_t prio
) {
    struct io const *io;
    int32_t oam_idx;

    io = &gba->io;

    if (!io->dispcnt.obj) {
        return ;
    }

    for (oam_idx = 127; oam_idx >= 0; --oam_idx) {
        union oam_entry oam;
        int32_t coord_y;
        int32_t x;
        int32_t size_x;
        int32_t size_y;

        oam.raw[0] = *(uint16_t *)((uint8_t *)gba->memory.oam + (oam_idx * 4 + 0) * 2);
        oam.raw[1] = *(uint16_t *)((uint8_t *)gba->memory.oam + (oam_idx * 4 + 1) * 2);
        oam.raw[2] = *(uint16_t *)((uint8_t *)gba->memory.oam + (oam_idx * 4 + 2) * 2);

        if (oam.priority != prio || (!oam.affine && oam.virt_dsize)) {
            continue;
        }

        /*
        ** When using BG Mode 3-5 (Bitmap Modes), only tile numbers 512-1023 may be used.
        ** That is because lower 16K of OBJ memory are used for BG.
        ** Attempts to use tiles 0-511 are ignored (not displayed).
        **    - GBATek
        */
        if (io->dispcnt.bg_mode >= 3 && oam.tile_idx < 512) {
            continue;
        }

        //if (oam.affine) { // TODO: Handle affine sprites
        //    continue;
        //}

        coord_y = oam.coord_y;
        size_x = sprite_size_x[(oam.size_high << 2) | oam.size_low];
        size_y = sprite_size_y[(oam.size_high <<2) | oam.size_low];

        if (coord_y + size_y >= 255) {
            coord_y -= 256;
        }

        // Filter and keep only the sprites that cross the current scanline
        if (line >= coord_y && line < coord_y + size_y) {
            for (x = 0; x < size_x; ++x) {
                uint32_t palette_idx;
                int32_t coord_x;
                int32_t plot_x;
                uint32_t chr_x;
                uint32_t chr_y;
                uint32_t tile_x;
                uint32_t tile_y;
                uint32_t tile_addr;
                uint32_t tile_size;

                tile_x = x / 8;
                tile_y = (line - coord_y) / 8;
                chr_x = x % 8;
                chr_y = (line - coord_y) % 8;
                coord_x = sign_extend9(oam.coord_x);
                plot_x = coord_x + x;

                // Filter-out pixels that are outside of the screen
                if (plot_x < 0 || plot_x >= SCREEN_WIDTH) {
                    continue;
                }

                if (!oam.affine && oam.hflip) {
                    tile_x = (size_x / 8) - 1 - tile_x;
                    chr_x ^= 0b111;
                }

                if (!oam.affine && oam.vflip) {
                    tile_y = (size_y / 8) - 1 - tile_y;
                    chr_y ^= 0b111;
                }

                tile_size = oam.color_256 ? 64 : 32;
                tile_addr = 0x10000 + oam.tile_idx * 32;

                if (io->dispcnt.obj_dim) { // 1 Dimension
                    tile_addr += tile_y * (size_x / 8) * tile_size;
                } else { // 2 Dimension
                    tile_addr += tile_y * 32 * 32;
                }

                tile_addr += tile_x * tile_size;

                if (oam.color_256) { // 256 colors, 1 palette
                    uint32_t addr;

                    addr = tile_addr + chr_y * 8 + chr_x;
                    palette_idx = gba->memory.vram[addr];
                } else { // 16 colors, 16 palettes
                    uint32_t addr;

                    /*
                    ** In this mode, each byte represents two pixels:
                    **   * The lower 4 bits define the color for the left pixel
                    **   * The upper 4 bits define the color for the right pixel
                    */

                    addr = tile_addr + chr_y * 4 + (chr_x >> 1);
                    palette_idx = gba->memory.vram[addr];
                    palette_idx >>= (chr_x % 2) * 4;
                    palette_idx &= 0xF;
                }

                if (palette_idx) {
                    union color c;

                    // 16-bits palette mode
                    if (!oam.color_256) {
                        palette_idx += oam.palette_num * 16;
                    }

                    c.raw = mem_read16(
                        gba,
                        PALRAM_START + 0x200 + palette_idx * sizeof(union color)
                    );

                    ppu_plot_pixel(gba, c, plot_x, line);
                }
            }
        }
    }
}