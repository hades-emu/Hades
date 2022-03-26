/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include "gba/gba.h"
#include "gba/ppu.h"

void
ppu_window_build_masks(
    struct gba const *gba,
    struct scanline *scanline,
    uint32_t y
) {
    uint32_t idx;

    for (idx = 0; idx < 2; ++idx) {
        uint32_t x;
        uint32_t minx;
        uint32_t maxx;
        uint32_t miny;
        uint32_t maxy;

        minx = gba->io.winh[idx].min;
        maxx = gba->io.winh[idx].max;
        miny = gba->io.winv[idx].min;
        maxy = gba->io.winv[idx].max;

        if (
               (miny <= maxy && (y < miny || y >= maxy))
            || (miny > maxy  && (y >= miny || y < maxy))
        ) {
            continue;
        }

        if (bitfield_get(gba->io.dispcnt.raw, 13 + idx)) {
            if (minx <= maxx) {
                for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
                    scanline->win[idx][x] = (x >= minx && x < maxx);
                }
            } else {
                for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
                    scanline->win[idx][x] = (x >= minx || x < maxx);
                }
            }
        }
    }
}

uint8_t
ppu_find_top_window(
    struct gba const *gba,
    struct scanline *scanline,
    uint32_t x
) {
    if (scanline->win[0][x]) {
        return (gba->io.winin.win0);
    } else if (scanline->win[1][x]) {
        return (gba->io.winin.win1);
    } else if (scanline->win[2][x]) {
        return (gba->io.winout.winobj);
    } else {
        return (gba->io.winout.winout);
    }
}