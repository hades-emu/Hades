/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "gba.h"
#include "hades.h"
#include "debugger.h"

void
debugger_cmd_continue(
    struct gba *gba,
    size_t argc __unused,
    char const * const *argv __unused
) {
    while (!g_interrupt) {
        sched_run_for(gba, UINT32_MAX);
    }
}
