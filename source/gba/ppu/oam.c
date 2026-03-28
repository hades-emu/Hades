/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/ppu.h"
#include "gba/core/helpers.h"

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

/*
** Pre-render all visible sprites.
*/
void
ppu_prerender_oam(
    struct gba *gba,
    struct scanline *scanline,
    int32_t line
) {
    uint32_t bg_mode;
    struct io const *io;
    int32_t oam_idx;

    io = &gba->io;
    bg_mode = io->dispcnt.bg_mode;

    if (!io->dispcnt.obj) {
        return;
    }

    for (oam_idx = 127; oam_idx >= 0; --oam_idx) {
        union oam_entry oam;
        int32_t x;

        int32_t win_oy;
        int32_t win_ox;
        int32_t win_sx;
        int32_t win_sy;
        int32_t sprite_sx;
        int32_t sprite_sy;

        oam.raw[0] = mem_oam_read16(gba, (oam_idx * 4 + 0) * 2);
        oam.raw[1] = mem_oam_read16(gba, (oam_idx * 4 + 1) * 2);
        oam.raw[2] = mem_oam_read16(gba, (oam_idx * 4 + 2) * 2);

        // Skip OAM entries that should'nt be displayed
        if (!oam.affine && oam.virt_dsize) {
            continue;
        }

        // Skip OAM entries of index < 512 for BG mode 3-5
        if (bg_mode >= 3 && bg_mode <= 5 && oam.tile_idx < 512) {
            continue;
        }

        win_oy = oam.coord_y;
        win_ox = sign_extend9(oam.coord_x);
        sprite_sx = sprite_size_x[(oam.size_high << 2) | oam.size_low];
        sprite_sy = sprite_size_y[(oam.size_high << 2) | oam.size_low];
        win_sx = sprite_sx;
        win_sy = sprite_sy;

        if (oam.affine && oam.virt_dsize) {
            win_sx *= 2;
            win_sy *= 2;
        }

        if (win_oy + win_sy >= 255) { // TODO Improve this for super large sprite
            win_oy -= 256;
        }

        if (line >= win_oy && line < win_oy + win_sy) {
            int32_t px;
            int32_t py;
            int16_t pa;
            int16_t pb;
            int16_t pc;
            int16_t pd;

            if (oam.affine) {
                pa = (int16_t)mem_oam_read16(gba, oam.affine_data_idx * 32 + 0x6);
                pb = (int16_t)mem_oam_read16(gba, oam.affine_data_idx * 32 + 0xe);
                pc = (int16_t)mem_oam_read16(gba, oam.affine_data_idx * 32 + 0x16);
                pd = (int16_t)mem_oam_read16(gba, oam.affine_data_idx * 32 + 0x1e);
            } else { // Identity matrix
                pa = 0x100;
                pb = 0;
                pc = 0;
                pd = 0x100;
            }

            /*
            ** We pre-compute PX and PY for x=0 and simply add the difference when X is increased.
            */
            px = pa * -(win_sx / 2) + pb * ((line - win_oy) - (win_sy / 2)) + ((sprite_sx / 2) << 8);
            py = pc * -(win_sx / 2) + pd * ((line - win_oy) - (win_sy / 2)) + ((sprite_sy / 2) << 8);

            for (x = 0; x < win_sx; ++x, px += pa, py += pc) {
                uint32_t palette_idx;
                int32_t rel_x;          // X coordinate of the pixel within the sprite
                int32_t rel_y;          // Y coordinate of the pixel within the sprite
                uint32_t chr_x;         // X coordinate of the pixel within the tile (0-7)
                uint32_t chr_y;         // Y coordinate of the pixel within the tile (0-7)
                uint32_t tile_x;        // X coordinate of the tile within the sprite
                uint32_t tile_y;        // Y coordinate of the tile within the sprite
                uint32_t tile_offset;   // Within VRAM
                uint32_t tile_size;     // In bytes

                // Filter-out pixels that are outside of the screen
                if (win_ox + x < 0 || win_ox + x >= GBA_SCREEN_WIDTH) {
                    continue;
                }

                rel_x = (px >> 8);
                rel_y = (py >> 8);

                if (oam.mosaic) {
                    rel_x = (win_ox + rel_x) / (io->mosaic.obj_hsize + 1) * (io->mosaic.obj_hsize + 1) - win_ox;
                    rel_y = (win_oy + rel_y) / (io->mosaic.obj_vsize + 1) * (io->mosaic.obj_vsize + 1) - win_oy;
                }

                tile_x = rel_x / 8;
                tile_y = rel_y / 8;
                chr_x = rel_x % 8;
                chr_y = rel_y % 8;

                // Filter out pixels that are rotated/shred/scaled outside of their sprite.
                if (
                       rel_x < 0 || tile_x >= sprite_sx / 8
                    || rel_y < 0 || tile_y >= sprite_sy / 8
                ) {
                    continue;
                }

                // Flip horizontally
                if (!oam.affine && oam.hflip) {
                    tile_x = (sprite_sx / 8) - 1 - tile_x;
                    chr_x ^= 0b111;
                }

                // Flip vertically
                if (!oam.affine && oam.vflip) {
                    tile_y = (sprite_sy / 8) - 1 - tile_y;
                    chr_y ^= 0b111;
                }

                tile_size = oam.color_256 ? 64 : 32;
                tile_offset = 0x10000 + oam.tile_idx * 32;

                if (io->dispcnt.obj_dim) { // 1 Dimension
                    tile_offset += tile_y * (sprite_sx / 8) * tile_size + tile_x * tile_size;
                } else { // 2 Dimension
                    tile_offset += tile_y * 32 * 32 + tile_x * tile_size;
                }

                if (oam.color_256) { // 256 colors, 1 palette
                    palette_idx = mem_vram_read8(gba, tile_offset + chr_y * 8 + chr_x);
                } else { // 16 colors, 16 palettes

                    /*
                    ** In this mode, each byte represents two pixels:
                    **   * The lower 4 bits define the color for the left pixel
                    **   * The upper 4 bits define the color for the right pixel
                    */

                    palette_idx = mem_vram_read8(gba, tile_offset + chr_y * 4 + (chr_x >> 1));
                    palette_idx >>= (chr_x % 2) * 4;
                    palette_idx &= 0xF;
                }

                if (palette_idx) {
                    if (oam.mode == OAM_MODE_WINDOW) {
                        scanline->win_obj_mask[win_ox + x] = true;
                    } else {
                        struct rich_color c;

                        // 16-bits palette mode
                        if (!oam.color_256) {
                            palette_idx += oam.palette_num * 16;
                        }

                        c.raw = mem_palram_read16(gba, 0x200 + palette_idx * sizeof(union color));
                        c.visible = true;
                        c.idx = 4;
                        c.force_blend = (oam.mode == OAM_MODE_BLEND);
                        scanline->oam[oam.priority][win_ox + x] = c;
                    }
                }
            }
        }
    }
}
