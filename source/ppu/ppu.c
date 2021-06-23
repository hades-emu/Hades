/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "gba.h"

/*
** Set the calculated color in the framebuffer;
*/
void
ppu_plot_pixel(
    struct gba *gba,
    union color c,
    uint32_t x,
    uint32_t y
) {
    uint32_t fb_idx;

    fb_idx = SCREEN_WIDTH * y + x;

    gba->framebuffer[fb_idx] = 0x00
        | (((uint32_t)c.red   << 3 ) | (((uint32_t)c.red   >> 2) & 0b111)) << 16
        | (((uint32_t)c.green << 3 ) | (((uint32_t)c.green >> 2) & 0b111)) << 8
        | (((uint32_t)c.blue  << 3 ) | (((uint32_t)c.blue  >> 2) & 0b111)) << 0
    ;
}

static
void
ppu_render_scanline(
    struct gba *gba
) {
    struct io *io;
    union color bg;
    uint32_t x;
    uint32_t line;

    io = &gba->io;
    line = io->vcount.raw;

    pthread_mutex_lock(&gba->framebuffer_mutex);

    bg.raw = mem_read16(gba, PALRAM_START);

    for (x = 0; x < SCREEN_WIDTH; ++x) {
        ppu_plot_pixel(gba, bg, x, line);
    }

    switch (io->dispcnt.bg_mode) {
        case 0:
        case 1:
        case 2:
            {
                int32_t prio;

                for (prio = 3; prio >= 0; --prio) {
                    ppu_render_background_text(gba, line, prio);
                    ppu_render_oam(gba, line, prio);
                }
            }
            break;
        case 3:
            ppu_render_background_bitmap(gba, line, false);
            break;
        case 4:
            ppu_render_background_bitmap(gba, line, true);
            break;
    }

    pthread_mutex_unlock(&gba->framebuffer_mutex);
}

static
void
ppu_hdraw(
    struct gba *gba,
    uint64_t extra_cycles __unused
) {
    struct io *io;

    io = &gba->io;

    /* Increment VCOUNT */
    ++io->vcount.raw;
    if (io->vcount.raw >= SCREEN_REAL_HEIGHT) {
        io->vcount.raw = 0;
        gba->frame_counter++; // New frame, wouhou!
    }

    io->dispstat.vcount_eq = (io->vcount.raw == io->dispstat.vcount_val );
    io->dispstat.vblank = (io->vcount.raw >= SCREEN_HEIGHT);
    io->dispstat.hblank = false;

    /* Trigger the VBLANK IRQ & DMA transfer */
    if (io->vcount.raw == SCREEN_HEIGHT) {
        if (io->dispstat.vblank_irq) {
            core_trigger_irq(gba, IRQ_VBLANK);
        }
        mem_dma_transfer(gba, DMA_TIMING_VBLANK);
    }

    /* Trigger the VCOUNT IRQ */
    if (io->dispstat.vcount_eq && io->dispstat.vcount_irq) {
        core_trigger_irq(gba, IRQ_VCOUNTER);
    }
}

static
void
ppu_hblank(
    struct gba *gba,
    uint64_t extra_cycles __unused
) {
    struct io *io;

    io = &gba->io;

    if (io->vcount.raw < SCREEN_HEIGHT) {
        ppu_render_scanline(gba);
    }

    io->dispstat.hblank = true;

    /* Trigger the HBLANK DMA transfer */
    if (io->dispstat.hblank_irq) {
        core_trigger_irq(gba, IRQ_HBLANK);
    }
    mem_dma_transfer(gba, DMA_TIMING_HBLANK);
}

void
ppu_init(
    struct gba *gba
) {
    // HDraw
    sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            CYCLES_PER_PIXEL * SCREEN_REAL_WIDTH,       // Timing of first trigger
            CYCLES_PER_PIXEL * SCREEN_REAL_WIDTH,       // Period
            ppu_hdraw
        )
    );

    // HBlank
    sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            CYCLES_PER_PIXEL * SCREEN_WIDTH,            // Timing of first trigger
            CYCLES_PER_PIXEL * SCREEN_REAL_WIDTH,       // Period
            ppu_hblank
        )
    );
}