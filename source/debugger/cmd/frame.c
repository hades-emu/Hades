/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "gba.h"
#include "hades.h"
#include "debugger.h"

static
void
render_frame(
    struct gba *gba
) {
    while (!g_interrupt && gba->io.vcount.raw == 0) {
        sched_run_for(gba, 1);
    }

    while (!g_interrupt && gba->io.vcount.raw != 0) {
        sched_run_for(gba, 1);
    }
}

void
debugger_cmd_frame(
    struct gba *gba,
    size_t argc __unused,
    char const * const *argv __unused
) {
    if (argc == 1) {
        render_frame(gba);
        debugger_dump_context(gba, false);
    } else if (argc == 2) {
        unsigned long nb;

        nb = strtoul(argv[1], NULL, 0);
        while (!g_interrupt && nb > 0) {
            render_frame(gba);
            --nb;
        }
        debugger_dump_context(gba, false);
    } else {
        printf("Usage: %s\n", g_commands[CMD_STEP].usage);
    }
}