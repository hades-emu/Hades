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

void
ppu_window_build_masks(
    struct gba *gba,
    uint32_t y
) {
    uint32_t idx;

    for (idx = 0; idx < 2; ++idx) {
        uint32_t x;
        uint32_t minx;
        uint32_t maxx;
        uint32_t miny;
        uint32_t maxy;
        uint32_t hash;
        bool enabled;
        bool within_y;

        miny = gba->io.winv[idx].min;
        maxy = gba->io.winv[idx].max;
        enabled = bitfield_get(gba->io.dispcnt.raw, 13 + idx);
        minx = gba->io.winh[idx].min;
        maxx = gba->io.winh[idx].max;
        within_y = !((miny <= maxy && (y < miny || y >= maxy)) || (miny > maxy  && (y >= miny || y < maxy)));

        /* Avoid rebuilding the masks if the parameters are the same. */
        hash = minx | (maxx << 8) | (enabled << 16) | (within_y << 17);
        if (hash == gba->ppu.win_masks_hash[idx]) {
            continue;
        }

        gba->ppu.win_masks_hash[idx] = hash;

        if (!enabled || !within_y) {
            memset(gba->ppu.win_masks[idx], 0, sizeof(gba->ppu.win_masks[WIN0]));
        } else {
            if (minx <= maxx) {
                for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
                    gba->ppu.win_masks[idx][x] = (x >= minx && x < maxx);
                }
            } else {
                for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
                    gba->ppu.win_masks[idx][x] = (x >= minx || x < maxx);
                }
            }
        }
    }
}

uint8_t
ppu_find_top_window(
    struct gba const *gba,
    struct scanline const *scanline,
    uint32_t x
) {
    if (gba->ppu.win_masks[WIN0][x]) {
        return (gba->io.winin.win0);
    } else if (gba->ppu.win_masks[WIN1][x]) {
        return (gba->io.winin.win1);
    } else if (scanline->win_obj_mask[x]) {
        return (gba->io.winout.winobj);
    } else {
        return (gba->io.winout.winout);
    }
}
