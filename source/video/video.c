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

/*
** Build the next pixel, stored in the framebuffer pointed to by `gba->framebuffer`.
*/
void
video_step(
    struct gba *gba
) {
    struct io *io;
    size_t fb_idx;
    union color c;


    io = &gba->io;

    gba->video.h += 1;
    if (gba->video.h >= SCREEN_REAL_WIDTH) {
        gba->video.h = 0;
        gba->video.v += 1;
    }

    if (gba->video.v >= SCREEN_REAL_HEIGHT) {
        gba->video.v = 0;
    }

    /* Update the REG_DISPSTAT register */
    io->dispstat.vblank = (gba->video.v >= SCREEN_HEIGHT);
    io->dispstat.hblank = (gba->video.h >= SCREEN_WIDTH);
    io->dispstat.vcount_eq = (gba->video.v == io->dispstat.vcount_val);

    /* Trigger the VBLANK DMA transfer */
    if (gba->video.v == SCREEN_HEIGHT) {
        if (io->dispstat.vblank_irq) {
            core_trigger_irq(gba, IRQ_VBLANK);
        }
        mem_dma_transfer(gba, DMA_TIMING_VBLANK);
    }

    /* Trigger the HBLANK DMA transfer */
    if (gba->video.h == SCREEN_WIDTH) {
        if (io->dispstat.hblank_irq) {
            core_trigger_irq(gba, IRQ_HBLANK);
        }
        mem_dma_transfer(gba, DMA_TIMING_HBLANK);
    }

    /* Trigger the VCOUNT IRQ */
    if (io->dispstat.vcount_eq && io->dispstat.vcount_irq) {
        core_trigger_irq(gba, IRQ_VCOUNTER);
    }

    fb_idx = SCREEN_WIDTH * gba->video.v + gba->video.h;

    pthread_mutex_lock(&gba->framebuffer_mutex);

    if (gba->video.h < SCREEN_WIDTH && gba->video.v < SCREEN_HEIGHT) {

        if (gba->video.h == 0 && gba->video.v == 0) {
            hs_logln(HS_VIDEO, "Video mode: %u", io->dispcnt.bg_mode);
            hs_logln(HS_VIDEO,
                "Video layout: BG0=%u BG1=%u BG2=%u BG3=%u OBJ=%u",
                io->dispcnt.bg0,
                io->dispcnt.bg1,
                io->dispcnt.bg2,
                io->dispcnt.bg3,
                io->dispcnt.obj
            );
        }

        c.raw = 0x0;

        switch (io->dispcnt.bg_mode) {
            // BG Mode 3: Bitmap without palette
            case 3:
                c.raw = mem_read16(gba, VRAM_START + fb_idx * sizeof(union color));
                break;
            // BG Mode 4: Bitmap with palette
            case 4:
                {
                    uint8_t palette_idx;

                    if (!io->dispcnt.frame) { // Frame 0
                        palette_idx = mem_read8(gba, VRAM_START + fb_idx);
                    } else { // Frame 1
                        palette_idx = mem_read8(gba, VRAM_START + 0xA000 + fb_idx);
                    }
                    c.raw = mem_read16(gba, PALRAM_START + palette_idx * sizeof(union color));
                }
                break;
        }

        // Set the calculated color in the framebuffer;

        gba->framebuffer[fb_idx] = 0
            | (((uint32_t)c.red * 255 / 31)     << 16)
            | (((uint32_t)c.green * 255 / 31)   << 8)
            | (((uint32_t)c.blue * 255 / 31)    << 0)
        ;

    }

    pthread_mutex_unlock(&gba->framebuffer_mutex);
}