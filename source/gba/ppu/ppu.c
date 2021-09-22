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

/*
** Initialize the content of the given `scanline` to a default, sane and working value.
*/
static
void
ppu_initialize_scanline(
    struct gba const *gba,
    struct scanline *scanline
) {
    struct rich_color backdrop;
    uint32_t x;

    memset(scanline, 0x00, sizeof(*scanline));

    backdrop.visible = true;
    backdrop.idx = 5;
    backdrop.raw = (gba->io.dispcnt.blank ? 0x7fff : mem_palram_read16(gba, PALRAM_START));

    for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
        scanline->bot[x] = backdrop;
    }

    scanline->result = scanline->bot;
}

/*
** Merge the current layer with any previous ones (using alpha blending) as stated in REG_BLDCNT.
*/
static
void
ppu_merge_layer(
    struct gba const *gba,
    struct scanline *scanline
) {
    uint32_t eva;
    uint32_t evb;
    uint32_t evy;
    struct io const *io;
    uint32_t x;

    io = &gba->io;
    eva = min(16, io->bldalpha.top_coef);
    evb = min(16, io->bldalpha.bot_coef);
    evy = min(16, io->bldy.coef);
    for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
        bool bot_enabled;
        struct rich_color topc;
        struct rich_color botc;
        uint32_t mode;

        topc = scanline->top[x];
        botc = scanline->bot[x];

        /* Skip transparent pixels */
        if (!topc.visible) {
            continue;
        }

        mode = gba->io.bldcnt.mode;
        bot_enabled = bitfield_get(io->bldcnt.raw, botc.idx + 8);

        /* Apply windowing, if any */
        if (io->dispcnt.win0 || io->dispcnt.win1 || io->dispcnt.winobj) {
            uint8_t win_opts;

            win_opts = ppu_find_top_window(gba, scanline, x);

            /* Hide pixels that belong to a layer that this window doesn't show. */
            if (!bitfield_get(win_opts, scanline->top_idx)) {
                continue;
            }

            /* Windows can disable blending */
            if (!bitfield_get(win_opts, 5)) {
                mode = BLEND_OFF;
            }
        }

        /* Sprite can force blending no matter what BLDCNT says */
        if (topc.force_blend && bot_enabled) {
            mode = BLEND_ALPHA;
        }

        switch (mode) {
            case BLEND_OFF:
                scanline->bot[x] = topc;
                break;
            case BLEND_ALPHA:
                {
                    bool top_enabled;

                    /*
                    ** If both the top and bot layers are enabled, blend the colors.
                    ** Otherwise, the top layer takes priority.
                    */

                    top_enabled = bitfield_get(io->bldcnt.raw, scanline->top_idx) || topc.force_blend;
                    if (top_enabled && bot_enabled && botc.visible) {
                        scanline->bot[x].red = min(31, (topc.red * eva + botc.red * evb) >> 4);
                        scanline->bot[x].green = min(31, (topc.green * eva + botc.green * evb) >> 4);
                        scanline->bot[x].blue = min(31, (topc.blue * eva + botc.blue * evb) >> 4);
                        scanline->bot[x].visible = true;
                        scanline->bot[x].idx = scanline->top_idx;
                    } else {
                        scanline->bot[x] = topc;
                    }
                }
                break;
            case BLEND_LIGHT:
                if (bitfield_get(io->bldcnt.raw, scanline->top_idx)) {
                    scanline->bot[x].red = topc.red + (((31 - topc.red) * evy) >> 4);
                    scanline->bot[x].green = topc.green + (((31 - topc.green) * evy) >> 4);
                    scanline->bot[x].blue = topc.blue + (((31 - topc.blue) * evy) >> 4);
                    scanline->bot[x].idx = topc.idx;
                    scanline->bot[x].visible = true;
                } else {
                    scanline->bot[x] = topc;
                }
                break;
            case BLEND_DARK:
                if (bitfield_get(io->bldcnt.raw, scanline->top_idx)) {
                    scanline->bot[x].red = topc.red - ((topc.red * evy) >> 4);
                    scanline->bot[x].green = topc.green - ((topc.green * evy) >> 4);
                    scanline->bot[x].blue = topc.blue - ((topc.blue * evy) >> 4);
                    scanline->bot[x].idx = topc.idx;
                    scanline->bot[x].visible = true;
                } else {
                    scanline->bot[x] = topc;
                }
                break;
        }
    }

    /* Reset the top layer to full transparency */
    memset(scanline->top, 0x00, sizeof(scanline->top));
}

/*
** Render the current scanline and write the result in `gba->framebuffer`.
*/
static
void
ppu_render_scanline(
    struct gba *gba,
    struct scanline *scanline
) {
    struct io const *io;
    int32_t prio;
    uint32_t y;

    io = &gba->io;
    y = gba->io.vcount.raw;

    switch (io->dispcnt.bg_mode) {
        case 0:
        case 1:
        case 2:
            {
                int32_t bg_idx;

                for (prio = 3; prio >= 0; --prio) {
                    for (bg_idx = 3; bg_idx >= 0; --bg_idx) {

                        // Only render enabled background that have the desired priority
                        if (!bitfield_get((uint8_t)io->dispcnt.bg, bg_idx) || io->bgcnt[bg_idx].priority != prio) {
                            continue;
                        }

                        if (io->dispcnt.bg_mode == 2 || (io->dispcnt.bg_mode == 1 && bg_idx == 2)) {
                            ppu_render_background_affine(gba, scanline, y, bg_idx);
                        } else {
                            ppu_render_background_text(gba, scanline, y, bg_idx);
                        }
                        ppu_merge_layer(gba, scanline);
                    }
                    ppu_render_oam(gba, scanline, y, prio);
                    ppu_merge_layer(gba, scanline);
                }
            }
            break;
        case 3:
            for (prio = 3; prio >= 0; --prio) {
                if (bitfield_get((uint8_t)io->dispcnt.bg, 2) && io->bgcnt[2].priority == prio) {
                    ppu_render_background_bitmap(gba, scanline, y, 2, false);
                    ppu_merge_layer(gba, scanline);
                }
                ppu_render_oam(gba, scanline, y, prio);
                ppu_merge_layer(gba, scanline);
            }
            break;
        case 4:
            for (prio = 3; prio >= 0; --prio) {
                if (bitfield_get((uint8_t)io->dispcnt.bg, 2) && io->bgcnt[2].priority == prio) {
                    ppu_render_background_bitmap(gba, scanline, y, 2, true);
                    ppu_merge_layer(gba, scanline);
                }
                ppu_render_oam(gba, scanline, y, prio);
                ppu_merge_layer(gba, scanline);
            }
            break;
    }
}

/*
** Compose the content of the framebuffer based on the content of `scanline->result` and/or the backdrop color.
*/
static
void
ppu_draw_scanline(
    struct gba *gba,
    struct scanline const *scanline
) {
    uint32_t x;
    uint32_t y;

    y = gba->io.vcount.raw;
    for (x = 0; x < GBA_SCREEN_WIDTH; ++x) {
        struct rich_color c;

        c = scanline->result[x];
        gba->framebuffer[GBA_SCREEN_WIDTH * y + x] = 0xFF << 24
            | (((uint32_t)c.red   << 3 ) | (((uint32_t)c.red   >> 2) & 0b111)) << 0
            | (((uint32_t)c.green << 3 ) | (((uint32_t)c.green >> 2) & 0b111)) << 8
            | (((uint32_t)c.blue  << 3 ) | (((uint32_t)c.blue  >> 2) & 0b111)) << 16
        ;
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
    if (io->vcount.raw >= GBA_SCREEN_REAL_HEIGHT) {
        io->vcount.raw = 0;
        gba->framecounter += 1;

        /*
        ** Now that the frame is finished, we can copy the current framebuffer to
        ** the one the frontend uses.
        **
        ** Doing it now will avoid tearing.
        */
        pthread_mutex_lock(&gba->framebuffer_frontend_mutex);
        memcpy(gba->framebuffer_frontend, gba->framebuffer, sizeof(gba->framebuffer));
        pthread_mutex_unlock(&gba->framebuffer_frontend_mutex);
    }

    io->dispstat.vcount_eq = (io->vcount.raw == io->dispstat.vcount_val );
    io->dispstat.vblank = (io->vcount.raw >= GBA_SCREEN_HEIGHT);
    io->dispstat.hblank = false;

    /* Trigger the VBLANK IRQ & DMA transfer */
    if (io->vcount.raw == GBA_SCREEN_HEIGHT) {
        if (io->dispstat.vblank_irq) {
            core_trigger_irq(gba, IRQ_VBLANK);
        }
        mem_schedule_dma_transfer(gba, DMA_TIMING_VBLANK);
        ppu_reload_affine_internal_registers(gba, 0);
        ppu_reload_affine_internal_registers(gba, 1);
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

    if (io->vcount.raw < GBA_SCREEN_HEIGHT) {
        struct scanline scanline;

        ppu_initialize_scanline(gba, &scanline);
        ppu_window_build_masks(gba, &scanline, io->vcount.raw);
        ppu_prerender_oam(gba, &scanline, io->vcount.raw);

        if (!gba->io.dispcnt.blank) {
            ppu_render_scanline(gba, &scanline);
        }

        ppu_draw_scanline(gba, &scanline);
        ppu_step_affine_internal_registers(gba);
    }

    io->dispstat.hblank = true;

    /* Trigger the HBLANK IRQ & DMA transfer */
    if (io->dispstat.hblank_irq) {
        core_trigger_irq(gba, IRQ_HBLANK);
    }
    if (io->vcount.raw < GBA_SCREEN_HEIGHT) {
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
            CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH,       // Timing of first trigger
            CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH,       // Period
            ppu_hdraw
        )
    );

    // HBlank
    sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            CYCLES_PER_PIXEL * GBA_SCREEN_WIDTH,            // Timing of first trigger
            CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH,       // Period
            ppu_hblank
        )
    );
}