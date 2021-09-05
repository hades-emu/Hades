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

enum oam_mode {
    OAM_MODE_NORMAL,
    OAM_MODE_BLEND,
    OAM_MODE_WINDOW,
    OAM_MODE_ILLEGAL,
};

enum blend_mode {
    BLEND_OFF,
    BLEND_ALPHA,
    BLEND_LIGHT,
    BLEND_DARK,
};

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

struct rich_color {
    union color;
    uint8_t idx: 6; // 0-4 for bgs, 5 for OAM
    uint8_t visible: 1;
    uint8_t force_blend: 1; // Only useful for OAM
};

struct scanline {
    struct rich_color top[SCREEN_WIDTH];
    struct rich_color bot[SCREEN_WIDTH];
    struct rich_color oam[4][SCREEN_WIDTH];
    bool win[3][SCREEN_WIDTH];
    struct rich_color *result;
    uint32_t top_idx;
};

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
            uint16_t mode: 2;
            uint16_t mosaic: 1;
            uint16_t color_256: 1;
            uint16_t size_high : 2;
        } __packed;
        union {
            struct {
                uint16_t coord_x: 9;
                uint16_t : 3;
                uint16_t hflip: 1;
                uint16_t vflip: 1;
                uint16_t size_low : 2;
            } __packed;
            struct {
                uint16_t : 9; // coord_x
                uint16_t affine_data_idx: 5;
                uint16_t : 2; // size_low
            } __packed;
        };
        struct {
            uint16_t tile_idx: 10;
            uint16_t priority: 2;
            uint16_t palette_num: 4;
        } __packed;
    } __packed;
    uint16_t raw[3];
};

static_assert(sizeof(union oam_entry) == 3 * sizeof(uint16_t));

union oam_float {
    struct {
        uint8_t fraction;
        int8_t integer;
    } __packed;
    uint16_t raw;
};

static_assert(sizeof(union oam_float) == sizeof(uint16_t));

/* ppu/background/bitmap.c */
void ppu_render_background_bitmap(struct gba const *gba, struct scanline *scanline, uint32_t line, uint32_t bg_idx, bool palette);

/* ppu/background/text.c */
void ppu_render_background_text(struct gba const *gba, struct scanline *scanline, uint32_t line, uint32_t bg_idx);

/* ppu/background/affine.c */
void ppu_render_background_affine(struct gba const *gba, uint32_t line, uint32_t bg_idx);

/* ppu/oam.c */
void ppu_prerender_oam(struct gba const *gba, struct scanline *scanline, int32_t line);
void ppu_render_oam(struct gba const *gba, struct scanline *scanline, int32_t line, uint32_t prio);

/* ppu/ppu.c */
void ppu_init(struct gba *);

/* ppu/window.c */
void ppu_window_build_masks(struct gba const *gba, struct scanline *scanline, uint32_t y);
uint8_t ppu_find_top_window(struct gba const *gba, struct scanline *scanline, uint32_t x);

/* platform/sdl.c */
void sdl_render_loop(struct gba *gba);

#endif /* !PPU_H */