/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/ppu.h"

void
ppu_render_background_bitmap(
    struct gba const *gba,
    struct scanline *scanline,
    bool palette
) {
    int16_t pa;
    int16_t pc;
    int32_t px;
    int32_t py;
    uint32_t x;
    struct rich_color c;
    struct io const *io;

    io = &gba->io;
    scanline->top_idx = 2;

    px = gba->ppu.internal_px[0];
    py = gba->ppu.internal_py[0];

    pa = (int16_t)io->bg_pa[0].raw;
    pc = (int16_t)io->bg_pc[0].raw;

    for (x = 0; x < GBA_SCREEN_WIDTH; ++x, px += pa, py += pc) {
        int32_t rel_x;
        int32_t rel_y;

        rel_x = px >> 8;
        rel_y = py >> 8;

        if (   rel_x < 0
            || rel_x >= GBA_SCREEN_WIDTH
            || rel_y < 0
            || rel_y >= GBA_SCREEN_HEIGHT
        ) {
            continue;
        }

        if (palette) {
            uint8_t palette_idx;

            palette_idx = mem_vram_read8(gba, (GBA_SCREEN_WIDTH * rel_y + rel_x) + 0xA000 * gba->io.dispcnt.frame);
            if (palette_idx) {
                c.raw = mem_palram_read16(gba, palette_idx * sizeof(union color));
                c.visible = true;
                c.idx = 2;
                c.force_blend = false;
                scanline->bg[x] = c;
            }
        } else {
            c.raw = mem_vram_read16(gba, (GBA_SCREEN_WIDTH * rel_y + rel_x) * sizeof(union color));
            c.visible = true;
            c.idx = 2;
            c.force_blend = false;
            scanline->bg[x] = c;
        }
    }
}

void
ppu_render_background_bitmap_small(
    struct gba const *gba,
    struct scanline *scanline
) {
    int16_t pa;
    int16_t pc;
    int32_t px;
    int32_t py;
    uint32_t x;
    struct rich_color c;
    struct io const *io;

    io = &gba->io;
    scanline->top_idx = 2;

    px = gba->ppu.internal_px[0];
    py = gba->ppu.internal_py[0];

    pa = (int16_t)io->bg_pa[0].raw;
    pc = (int16_t)io->bg_pc[0].raw;

    for (x = 0; x < GBA_SCREEN_WIDTH; ++x, px += pa, py += pc) {
        int32_t rel_x;
        int32_t rel_y;

        rel_x = px >> 8;
        rel_y = py >> 8;

        if (   rel_x < 0
            || rel_x >= 160
            || rel_y < 0
            || rel_y >= 160
        ) {
            continue;
        }

        c.raw = mem_vram_read16(gba, 0xA000 * gba->io.dispcnt.frame + (160 * rel_y + rel_x) * sizeof(union color) );
        c.visible = true;
        c.idx = 2;
        c.force_blend = false;
        scanline->bg[x] = c;
    }
}
