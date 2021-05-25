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

struct video
{
    uint h;
    uint v;
};

void video_build_framebuffer(struct gba *gba);

#endif /* !VIDEO_H */