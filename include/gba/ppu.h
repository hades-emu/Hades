/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef GBA_PPU_H
# define GBA_PPU_H

# include "hades.h"

# define GBA_SCREEN_WIDTH           240
# define GBA_SCREEN_HEIGHT          160
# define GBA_SCREEN_REAL_WIDTH      308
# define GBA_SCREEN_REAL_HEIGHT     228
# define CYCLES_PER_PIXEL           4
# define CYCLES_PER_FRAME           (CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH * GBA_SCREEN_REAL_HEIGHT)
# define CYCLES_PER_SECOND          (16 * 1024 * 1024)

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
    uint8_t idx: 6; // 0-3 for bgs, 4 for OAM, 5 for BD
    uint8_t visible: 1;
    uint8_t force_blend: 1; // Only useful for OAM
};

struct scanline {
    struct rich_color top[GBA_SCREEN_WIDTH];
    struct rich_color bot[GBA_SCREEN_WIDTH];
    struct rich_color oam[4][GBA_SCREEN_WIDTH];
    bool win[3][GBA_SCREEN_WIDTH];
    struct rich_color result[GBA_SCREEN_WIDTH];
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

union affine_float {
    struct {
        uint8_t fraction;
        int8_t integer;
    } __packed;
    int16_t raw;
};

static_assert(sizeof(union affine_float) == sizeof(uint16_t));

struct ppu {
    // Internal registers used for affine backgrounds
    int32_t internal_px[2];
    int32_t internal_py[2];
};

/* gba/ppu/background/bitmap.c */
void ppu_render_background_bitmap(struct gba const *gba, struct scanline *scanline, uint32_t line, uint32_t bg_idx, bool palette);

/* gba/ppu/background/text.c */
void ppu_render_background_text(struct gba const *gba, struct scanline *scanline, uint32_t line, uint32_t bg_idx);

/* gba/ppu/background/affine.c */
void ppu_render_background_affine(struct gba *gba, struct scanline *scanline, uint32_t line, uint32_t bg_idx);
void ppu_reload_affine_internal_registers(struct gba *gba, uint32_t idx);
void ppu_step_affine_internal_registers(struct gba *gba);

/* gba/ppu/oam.c */
void ppu_prerender_oam(struct gba const *gba, struct scanline *scanline, int32_t line);
void ppu_render_oam(struct gba const *gba, struct scanline *scanline, int32_t line, uint32_t prio);

/* gba/ppu/ppu.c */
void ppu_init(struct gba *);

/* gba/ppu/window.c */
void ppu_window_build_masks(struct gba const *gba, struct scanline *scanline, uint32_t y);
uint8_t ppu_find_top_window(struct gba const *gba, struct scanline *scanline, uint32_t x);

#endif /* !GBA_PPU_H */