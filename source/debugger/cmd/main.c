/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "debugger.h"
#include "gba.h"

void
debugger_cmd_main(
    struct gba *gba,
    size_t argc __unused,
    char const * const *argv __unused
) {
    size_t i;

    gba->core.pc = 0x0;
    core_reload_pipeline(gba);

    i = 0;
    while (i < 27) {
        core_step(gba);
        ++i;
    }

    gba->core.r4 = 0x0;

    gba->core.pc = 0x08000000;
    core_reload_pipeline(gba);
}