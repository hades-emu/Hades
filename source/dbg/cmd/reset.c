/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "app.h"
#include "dbg/dbg.h"

void
debugger_cmd_reset(
    struct app *app,
    size_t argc __unused,
    struct arg const *argv __unused
) {
    app->emulation.gba->debugger.interrupt.flag = false;
    app_game_reset(app);
    app_game_run(app);
    debugger_wait_for_emulator(app, true);
}