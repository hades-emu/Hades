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
                io->dispcnt.bg >> 0,
                io->dispcnt.bg >> 1,
                io->dispcnt.bg >> 2,
                io->dispcnt.bg >> 3,
                io->dispcnt.obj
            );
        }

        c.raw = mem_read16(gba, PALRAM_START);

        switch (io->dispcnt.bg_mode) {
            case 0:
            case 1:
            case 2:
                {
                    int32_t prio;

                    prio = 3;
                    while (prio >= 0) {
                        int32_t bg_idx;

                        bg_idx = 3;
                        while (bg_idx >= 0) {
                            uint32_t tile_x; // X coord of the tile in the tilemap
                            uint32_t tile_y; // Y coord of the tile in the tilemap
                            uint32_t chr_x; // X coord of the pixel we want to render within the tile
                            uint32_t chr_y; // Y coord of the pixel we want to render within the tile
                            uint32_t screen_addr;
                            uint32_t screen_idx;
                            uint32_t chrs_addr;
                            uint8_t palette_idx;
                            union tile tile;

                            if (!(io->dispcnt.bg & (1 << bg_idx)) || io->bgcnt[bg_idx].priority != prio) {
                                --bg_idx;
                                continue;
                            }

                            tile_x = (gba->video.h + io->bg_hoffset[bg_idx].raw) / 8;
                            tile_y = (gba->video.v + io->bg_voffset[bg_idx].raw) / 8;
                            chr_x =  (gba->video.h + io->bg_hoffset[bg_idx].raw) % 8;
                            chr_y =  (gba->video.v + io->bg_voffset[bg_idx].raw) % 8;

                            screen_addr = (uint32_t)io->bgcnt[bg_idx].screen_base * 0x800;
                            chrs_addr = (uint32_t)io->bgcnt[bg_idx].character_base * 0x4000;

                            switch (io->bgcnt[bg_idx].screen_size) {
                                case 0b00: // 256x256 (32x32)
                                    screen_idx = tile_y * 32 + tile_x; // OK
                                    break;
                                case 0b01: // 512x256 (64x32)
                                    unimplemented(HS_VIDEO, "512x256 tile mode not implemented yet");
                                    break;
                                case 0b10: // 256x512 (32x64)
                                    screen_idx = tile_y * 32 + tile_x; // OK
                                    break;
                                case 0b11: // 512x512 (64x64)
                                    unimplemented(HS_VIDEO, "512x512 tile mode not implemented yet");
                                    break;
                            }

                            tile.raw = mem_read16(gba, VRAM_START + screen_addr + screen_idx * sizeof(union tile));

                            if (io->bgcnt[bg_idx].palette_type) { // 256 colors, 1 palette
                                palette_idx = mem_read8(gba,
                                    VRAM_START + chrs_addr + tile.number * 64 + chr_y * 8 + chr_x
                                );
                            } else { // 16 colors, 16 palettes

                                /*
                                ** In this mode, each byte represents two pixels:
                                **   * The lower 4 bits define the color for the left pixel
                                **   * The upper 4 bits define the color for the right pixel
                                */

                                palette_idx = mem_read8(gba,
                                    VRAM_START + chrs_addr + tile.number * 32 + chr_y * 4 + (chr_x >> 1)
                                );
                                palette_idx >>= (chr_x % 2) * 4;
                                palette_idx &= 0xF;
                            }

                            if (palette_idx) {
                                c.raw = mem_read16(
                                    gba,
                                    PALRAM_START + (tile.palette * 16 + palette_idx) * sizeof(union color)
                                );
                            }

                            --bg_idx;
                        }
                        --prio;
                    }
                }
                break;
            // BG Mode 3: Bitmap without palette
            case 3:
                c.raw = mem_read16(gba, VRAM_START + fb_idx * sizeof(union color));
                break;
            // BG Mode 4: Bitmap with palette
            case 4:
                {
                    uint8_t palette_idx;

                    palette_idx = mem_read8(gba, VRAM_START + fb_idx + 0xA000 * io->dispcnt.frame);
                    c.raw = mem_read16(gba, PALRAM_START + palette_idx * sizeof(union color));
                }
                break;
        }

        // Set the calculated color in the framebuffer;

        gba->framebuffer[fb_idx] = 0x00
            | (((uint32_t)c.red   << 3 ) | (((uint32_t)c.red   >> 2) & 0b111)) << 16
            | (((uint32_t)c.green << 3 ) | (((uint32_t)c.green >> 2) & 0b111)) << 8
            | (((uint32_t)c.blue  << 3 ) | (((uint32_t)c.blue  >> 2) & 0b111)) << 0
        ;
    }

    pthread_mutex_unlock(&gba->framebuffer_mutex);
}