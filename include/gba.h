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
# include "ppu.h"
# include "debugger.h"
# include "io.h"
# include "scheduler.h"
# include "event.h"

struct options
{
    bool debugger;      // True if the debugger is enabled
    uint32_t scale;     // The GUI's framebuffer scaling factor
    uint32_t speed;     // The emulator's speed multiplier.
    bool headless;      // Run Hades without a GUI (aka text/debugger only)
    uint32_t color;     // 0: auto, 1: never, 2: always
};

struct gba
{
    struct core core;
    struct memory memory;
#if ENABLE_DEBUGGER
    struct debugger debugger;
#endif
    struct io io;
    struct scheduler scheduler;
    struct options options;

    /*
    ** The event queue, used by the render thread to communicate
    ** with the logic thread.
    */
    struct event_queue event_queue;
    pthread_mutex_t event_queue_mutex;

    /*
    ** Read-only past initialization.
    ** Can therefore be used by all threads.
    */
    char const *rom_path;
    char *quicksave_path;
    char *backup_storage_path;
    FILE *backup_storage_file;

    /*
    ** The result of the video controller, used by the renderer to
    ** print things on screen.
    **
    ** Can be accessed by both the logic and render thread.
    */
    uint32_t framebuffer[SCREEN_WIDTH * SCREEN_HEIGHT];
    pthread_mutex_t framebuffer_mutex;

    /*
    ** Frame limiter related stuff.
    */
    atomic_uint frame_counter;          // Amount of frames since the beginning of the emulation.
    uint64_t    previous_frame_tick;    // Time, in milliseconds, when the previous frame was rendered.

    /*
    ** Read-only past initialization.
    ** Note that the logic thread == render thread if there's no rendering (headless).
    */
    pthread_t logic_thread;
    pthread_t render_thread;
};

/* gba/gba.c */
int gba_load_bios(struct gba *memory, char const *filename);
int gba_load_rom(struct gba *gba, char const *filename);

/* gba/quicksave.c */
void quicksave(struct gba *gba, char const *path);
void quickload(struct gba *gba, char const *path);

#endif /* GBA_H */