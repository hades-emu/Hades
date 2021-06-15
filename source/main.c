/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <stdatomic.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include "hades.h"
#include "gba.h"
#include "core/arm.h"
#include "core/thumb.h"
#include "memory.h"
#include "debugger.h"

/*
** A global, atomic variable used to signal other threads it is time to stop and exit.
*/
atomic_bool g_stop;

/*
** A global, atomic variable used to signal other threads the execution should be interrupted.
*/
atomic_bool g_interrupt;

/*
** A global variable used to indicate the verbosity of all the different log levels.
** Restricted to the logic thread only.
*/
bool g_verbose[HS_END];
bool g_verbose_global;
/*
** The signal handler, used to set `stop` to true and signal
** all threads it is time to stop and exit.
*/
static
void
sighandler(
    int signal
) {
    g_interrupt = true;
}

int
main(
    int argc,
    char *argv[]
) {
    signal(SIGINT, &sighandler);

    g_verbose[HS_GLOBAL] = true;
    g_verbose[HS_WARNING] = true;
    g_verbose[HS_ERROR] = true;

    g_verbose[HS_CORE] = true;
    g_verbose[HS_IO] = true;
    g_verbose[HS_VIDEO] = true;
    g_verbose[HS_DMA] = true;
    g_verbose[HS_IRQ] = true;
    g_verbose[HS_MEMORY] = true;
    g_verbose[HS_TIMER] = true;

    if (argc == 2) {
        pthread_t render_thread;
        struct gba *gba;

        /* First, initialize the GBA system */

        gba = malloc(sizeof(*gba));
        hs_assert(gba != NULL);

        memset(gba, 0, sizeof(*gba));
        gba->input.raw = 0x3FF; // Every button set to "released"

        pthread_mutex_init(&gba->framebuffer_mutex, NULL);
        pthread_mutex_init(&gba->input_mutex, NULL);

        core_arm_decode_insns();
        core_thumb_decode_insns();

        mem_init(&gba->memory);
        io_init(&gba->io);

        /* Load the BIOS. NOTE: this function exits on failure. */
        mem_load_bios(&gba->memory, "gba_bios.gba");

        /* Load the given ROM. NOTE: this function exits on failure. */
        mem_load_rom(&gba->memory, argv[1]);

        core_init(gba);

        debugger_init(gba);

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

        g_stop = true;

        pthread_join(render_thread, NULL);

        debugger_destroy(gba);

        free(gba);

        return (EXIT_SUCCESS);
    } else {
        fprintf(stderr, "Usage: %s <rom>\n", argv[0]);
        return (EXIT_FAILURE);
    }
    return (0);
}