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

void
debugger_cmd_frame(
    struct gba *gba,
    size_t argc __unused,
    char const * const *argv __unused
) {
    while (!g_interrupt && gba->io.vcount.raw == 0) {
        sched_run_for(gba, 1);
    }

    while (!g_interrupt && gba->io.vcount.raw != 0) {
        sched_run_for(gba, 1);
    }
}