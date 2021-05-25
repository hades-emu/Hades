/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef GBA_H
# define GBA_H

# include "core.h"
# include "memory.h"
# include "video.h"

struct gba
{
    bool stop;

    struct core core;
    struct memory memory;
    struct video video;

    uint32_t framebuffer[240 * 160]; // The result of the video controller and used
                                     // by the renderer to print things on screen.
                                     // Can be accessed by both the logic and render thread.
    pthread_mutex_t framebuffer_mutex;
};

#endif /* GBA_H */