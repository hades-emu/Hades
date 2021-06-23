/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef PPU_H
# define PPU_H

# include "hades.h"

# define SCREEN_WIDTH           240
# define SCREEN_HEIGHT          160
# define SCREEN_REAL_WIDTH      308
# define SCREEN_REAL_HEIGHT     228
# define CYCLES_PER_PIXEL       4

union color {
    struct {
        uint16_t red: 5;
        uint16_t green: 5;
        uint16_t blue: 5;
        uint16_t : 1;
    } __packed;
    uint16_t raw;
};

static_assert(sizeof(union color) == sizeof(uint16_t));

union tile {
    struct {
        uint16_t number: 10;
        uint16_t hflip: 1;
        uint16_t vflip: 1;
        uint16_t palette: 4;
    } __packed;
    uint16_t raw;
};

static_assert(sizeof(union tile) == sizeof(uint16_t));

union oam_entry {
    struct {
        struct {
            uint16_t coord_y: 8;
            uint16_t affine: 1;
            uint16_t virt_dsize: 1;
            uint16_t blend: 2;
            uint16_t mosaic: 1;
            uint16_t color_256: 1;
            uint16_t size_high : 2;
        } __packed;
        struct {
            uint16_t coord_x: 9;
            uint16_t : 3;
            uint16_t hflip: 1;
            uint16_t vflip: 1;
            uint16_t size_low : 2;
        } __packed;
        struct {
            uint16_t tile_idx: 10;
            uint16_t priority: 2;
            uint16_t palette_num: 4;
        } __packed;
    } __packed;
    uint16_t raw[3];
};

static_assert(sizeof(union oam_entry) == 3 * sizeof(uint16_t));

/* ppu/background.c */
void ppu_render_background_bitmap(struct gba *gba, uint32_t line, bool palette);
void ppu_render_background_text(struct gba *gba, uint32_t line, uint32_t prio);
void ppu_plot_pixel(struct gba *gba, union color c, uint32_t x, uint32_t y);

/* ppu/oam.c */
void ppu_render_oam(struct gba *gba, int32_t line, uint32_t prio);

/* ppu/ppu.c */
void ppu_init(struct gba *);

/* sdl.c */
void *sdl_render_loop(struct gba *gba);

#endif /* !PPU_H */