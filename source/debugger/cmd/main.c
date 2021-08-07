/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "debugger.h"
#include "gba.h"

void
debugger_cmd_main(
    struct gba *gba,
    size_t argc __unused,
    char const * const *argv __unused
) {
    struct core *core;

    core = &gba->core;

    memset(core->registers, 0, sizeof(core->registers));

    core->sp = 0x03007F00;
    core->lr = 0x08000000;
    core->pc = 0x08000000;
    core->cpsr.raw = 0x1F;

    core_reload_pipeline(gba);
}