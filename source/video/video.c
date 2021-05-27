/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "gba.h"

union color {
    struct {
        uint16_t red: 5;
        uint16_t green: 5;
        uint16_t blue: 5;
        uint16_t : 1;
    } __packed;
    uint16_t raw;
} _packed;

static_assert(sizeof(union color) == sizeof(uint16_t));

void
video_build_framebuffer(
    struct gba *gba
) {
    size_t i;

    gba->video.h += 1;
    if (gba->video.h >= 308) {
        gba->video.h = 0;
        gba->video.v += 1;
    }

    if (gba->video.v >= 228) {
        gba->video.v = 0;
    }

    pthread_mutex_lock(&gba->framebuffer_mutex);

    if (gba->video.h < 240 && gba->video.v < 160) {
        uint8_t palette_idx;
        union color c;
        uint8_t red;
        uint8_t green;
        uint8_t blue;

        i = 240 * gba->video.v + gba->video.h;
        palette_idx = mem_read8(gba, VRAM_START + i);
        c.raw = mem_read16(gba, PALRAM_START + palette_idx * sizeof(union color));

        red = (uint32_t)c.red * 255 / 31;
        blue = (uint32_t)c.blue * 255 / 31;
        green = (uint32_t)c.green * 255 / 31;

        gba->framebuffer[i] = 0
            | (red   << 16)
            | (green <<  8)
            | (blue  <<  0)
        ;
    }

    pthread_mutex_unlock(&gba->framebuffer_mutex);
}