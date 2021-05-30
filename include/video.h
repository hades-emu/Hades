/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef VIDEO_H
# define VIDEO_H

# define SCREEN_WIDTH       240
# define SCREEN_HEIGHT      160

struct video
{
    uint h;
    uint v;
};

/* video/video.c */
void video_step(struct gba *gba);

/* render/sdl.c */
void *sdl_render_loop(struct gba *gba);

#endif /* !VIDEO_H */