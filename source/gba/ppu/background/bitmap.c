/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/ppu.h"

void
ppu_render_background_bitmap(
    struct gba const *gba,
    struct scanline *scanline,
    uint32_t line,
    uint32_t bg_idx,
    bool palette
) {
    uint32_t x;
    struct rich_color c;

    scanline->top_idx = bg_idx;
    for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
        if (palette) {
            uint8_t palette_idx;

            palette_idx = mem_vram_read8(gba, (GBA_SCREEN_WIDTH * line + x) + 0xA000 * gba->io.dispcnt.frame);
            c.raw = mem_palram_read16(gba, palette_idx * sizeof(union color));
            c.visible = true;
            c.idx = bg_idx;
            c.force_blend = false;
            scanline->top[x] = c;
        } else {
            c.raw = mem_vram_read16(gba, (GBA_SCREEN_WIDTH * line + x) * sizeof(union color));
            c.visible = true;
            c.idx = bg_idx;
            c.force_blend = false;
            scanline->top[x] = c;
        }
    }
}