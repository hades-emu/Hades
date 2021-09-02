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

    gba->framebuffer_logic[fb_idx] = 0x00
        | (((uint32_t)c.red   << 3 ) | (((uint32_t)c.red   >> 2) & 0b111)) << 16
        | (((uint32_t)c.green << 3 ) | (((uint32_t)c.green >> 2) & 0b111)) << 8
        | (((uint32_t)c.blue  << 3 ) | (((uint32_t)c.blue  >> 2) & 0b111)) << 0
    ;
}

/*
** Render the current scanline and write the result in `gba->framebuffer`.
*/
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

    bg.raw = io->dispcnt.blank ? 0xffff : mem_read16_raw(gba, PALRAM_START);

    for (x = 0; x < SCREEN_WIDTH; ++x) {
        ppu_plot_pixel(gba, bg, x, line);
    }

    if (io->dispcnt.blank) {
        return ;
    }

    switch (io->dispcnt.bg_mode) {
        case 0:
        case 1:
        case 2:
            {
                int32_t bg_idx;
                int32_t prio;

                for (prio = 3; prio >= 0; --prio) {
                    for (bg_idx = 3; bg_idx >= 0; --bg_idx) {

                        // Only show enabled background that have the desired priority
                        if (!bitfield_get((uint8_t)io->dispcnt.bg, bg_idx) || io->bgcnt[bg_idx].priority != prio) {
                            continue;
                        }

                        if (io->dispcnt.bg_mode == 2 || (io->dispcnt.bg_mode == 1 && bg_idx == 2)) {
                            ppu_render_background_affine(gba, line, bg_idx);
                        } else {
                            ppu_render_background_text(gba, line, bg_idx);
                        }
                    }
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
}

/*
** Called when the PPU enters HDraw, this function updates some IO registers
** to reflect the progress of the PPU and eventually triggers an IRQ.
*/
static
void
ppu_hdraw(
    struct gba *gba,
    union event_data data __unused
) {
    struct io *io;

    io = &gba->io;

    /* Increment VCOUNT */
    ++io->vcount.raw;
    if (io->vcount.raw >= SCREEN_REAL_HEIGHT) {
        io->vcount.raw = 0;
    }

    io->dispstat.vcount_eq = (io->vcount.raw == io->dispstat.vcount_val );
    io->dispstat.vblank = (io->vcount.raw >= SCREEN_HEIGHT);
    io->dispstat.hblank = false;

    /* Trigger the VBLANK IRQ & DMA transfer */
    if (io->vcount.raw == SCREEN_HEIGHT) {
        if (io->dispstat.vblank_irq) {
            core_trigger_irq(gba, IRQ_VBLANK);
        }
        mem_schedule_dma_transfer(gba, DMA_TIMING_VBLANK);
    }

    /* Trigger the VCOUNT IRQ */
    if (io->dispstat.vcount_eq && io->dispstat.vcount_irq) {
        core_trigger_irq(gba, IRQ_VCOUNTER);
    }
}

/*
** Called when the PPU enters HBlank, this function updates some IO registers
** to reflect the progress of the PPU, eventually triggers an IRQ, and render
** the current scanline.
*/
static
void
ppu_hblank(
    struct gba *gba,
    union event_data data __unused
) {
    struct io *io;

    io = &gba->io;

    if (io->vcount.raw < SCREEN_HEIGHT) {
        ppu_render_scanline(gba);
    }

    io->dispstat.hblank = true;

    /* Trigger the HBLANK IRQ & DMA transfer */
    if (io->dispstat.hblank_irq) {
        core_trigger_irq(gba, IRQ_HBLANK);
    }
    if (io->vcount.raw < SCREEN_HEIGHT) {
        mem_schedule_dma_transfer(gba, DMA_TIMING_HBLANK);
    }
}

/*
** Initialize the PPU.
*/
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