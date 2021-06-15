/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef TIMER_H
# define TIMER_H

# define SCREEN_WIDTH           240
# define SCREEN_HEIGHT          160
# define SCREEN_REAL_WIDTH      308
# define SCREEN_REAL_HEIGHT     228

struct video {
    uint h;
    uint v;
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

union tile {
    struct {
        uint16_t number: 10;
        uint16_t hflip: 1;
        uint16_t vflip: 1;
        uint16_t palette: 4;
    } __packed;
    uint16_t raw;
};

static_assert(sizeof(union color) == sizeof(uint16_t));

/* video.c */
void video_step(struct gba *gba);

/* sdl.c */
void *sdl_render_loop(struct gba *gba);

#endif /* !TIMER_H */