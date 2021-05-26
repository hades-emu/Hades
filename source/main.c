/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <errno.h>
#include <pthread.h>
#include "hades.h"
#include "gba.h"
#include "core/arm.h"
#include "core/thumb.h"
#include "memory.h"
#include "debugger.h"

void *sdl_render_loop(struct gba *gba);

int
main(
    int argc,
    char *argv[]
) {
    if (argc == 3) {
        pthread_t render_thread;
        struct gba *gba;

        /* First, initialize the GBA system */

        gba = malloc(sizeof(*gba));
        hs_assert(gba != NULL);

        memset(gba, 0, sizeof(*gba));

        pthread_mutex_init(&gba->framebuffer_mutex, NULL);

        core_arm_decode_insns();
        core_thumb_decode_insns();

        mem_init(&gba->memory);

        /* Load the BIOS */
        if (mem_load_bios(&gba->memory, argv[1]) < 0) {
            fprintf(stderr, "hades: can't load %s: %s", argv[1], strerror(errno));
            return (EXIT_FAILURE);
        }

        /* Load the given ROM */
        if (mem_load_rom(&gba->memory, argv[2]) < 0) {
            fprintf(stderr, "hades: can't load %s: %s", argv[1], strerror(errno));
            return (EXIT_FAILURE);
        }

        core_init(gba, &gba->memory);

        /* Create the render thread */

        pthread_create(
            &render_thread,
            NULL,
            (void *(*)(void *))
            sdl_render_loop,
            gba
        );

        /* Then enter the debugger's REPL. */

        debugger_repl(gba);

        free(gba);

        return (EXIT_SUCCESS);
    } else {
        fprintf(stderr, "Usage: %s <bios> <rom>\n", argv[0]);
        return (EXIT_FAILURE);
    }
    return (0);
}