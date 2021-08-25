/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "debugger.h"
#include "gba.h"

void
debugger_cmd_exit(
    struct gba *gba __unused,
    size_t argc __unused,
    char const * const *argv __unused
) {
    g_interrupt = true;
    g_stop = true;
}