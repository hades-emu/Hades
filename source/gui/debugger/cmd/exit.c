/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gui/app.h"
#include "gui/debugger.h"

void
debugger_cmd_exit(
    struct app *app,
    size_t argc __unused,
    struct arg const *argv __unused
) {
    app->run = false;
}