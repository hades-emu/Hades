/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/ppu.h"

void
ppu_reload_affine_internal_registers(
    struct gba *gba,
    uint32_t idx
) {
    gba->ppu.internal_px[idx] = sign_extend28(gba->io.bg_x[idx].raw & 0x0FFFFFFF);
    gba->ppu.internal_py[idx] = sign_extend28(gba->io.bg_y[idx].raw & 0x0FFFFFFF);
}

void
ppu_step_affine_internal_registers(
    struct gba *gba
) {
    uint32_t idx;
    int16_t pb;
    int16_t pd;

    for (idx = 0; idx < 2; ++idx) {
        pb = (int16_t)gba->io.bg_pb[idx].raw;
        pd = (int16_t)gba->io.bg_pd[idx].raw;
        gba->ppu.internal_px[idx] += pb;
        gba->ppu.internal_py[idx] += pd;
    }
}

void
ppu_render_background_affine(
    struct gba *gba,
    struct scanline *scanline,
    uint32_t line,
    uint32_t bg_idx
) {
    uint32_t screen_addr;
    uint32_t chrs_addr;
    int16_t pa;
    int16_t pc;
    int32_t px;
    int32_t py;
    int32_t bg_size;
    uint32_t x;
    struct io const *io;

    io = &gba->io;
    scanline->top_idx = bg_idx;

    switch (gba->io.bgcnt[bg_idx].size) {
        case 0b00: bg_size = 128; break;
        case 0b01: bg_size = 256; break;
        case 0b10: bg_size = 512; break;
        case 0b11: bg_size = 1024; break;
    }

    px = gba->ppu.internal_px[bg_idx % 2];
    py = gba->ppu.internal_py[bg_idx % 2];

    pa = (int16_t)io->bg_pa[bg_idx % 2].raw;
    pc = (int16_t)io->bg_pc[bg_idx % 2].raw;

    screen_addr = (uint32_t)io->bgcnt[bg_idx].screen_base * 0x800;
    chrs_addr = (uint32_t)io->bgcnt[bg_idx].character_base * 0x4000;

    for (x = 0; x < GBA_SCREEN_WIDTH; ++x, px += pa, py += pc) {
        uint32_t palette_idx;
        uint32_t tile_idx;
        int32_t tile_x;
        int32_t tile_y;
        uint32_t chr_x;
        uint32_t chr_y;

        tile_x = px >> 8;
        tile_y = py >> 8;

        if (io->bgcnt[bg_idx].wrap) {
            tile_x = tile_x >= 0 ? (tile_x % bg_size) : (bg_size + (tile_x % bg_size));
            tile_y = tile_y >= 0 ? (tile_y % bg_size) : (bg_size + (tile_y % bg_size));
        } else if (tile_x < 0 || tile_x >= bg_size || tile_y < 0 || tile_y >= bg_size) {
            continue;
        }

        chr_x = tile_x % 8;
        chr_y = tile_y % 8;

        tile_idx = mem_vram_read8(gba, screen_addr + (tile_y / 8) * (bg_size / 8) + (tile_x / 8));
        palette_idx = mem_vram_read8(gba, chrs_addr + tile_idx * 64 + chr_y * 8 + chr_x);

        if (palette_idx) {
            struct rich_color c;

            c.raw = mem_palram_read16(gba, palette_idx * sizeof(union color));
            c.visible = true;
            c.idx = bg_idx;
            c.force_blend = false;
            scanline->bg[x] = c;
        }
    }
}
