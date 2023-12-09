/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "app.h"
#include "dbg/dbg.h"

void
debugger_cmd_continue(
    struct app *app,
    size_t argc __unused,
    struct arg const *argv __unused
) {
    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    app_game_run(app);
    debugger_wait_for_emulator(app);
    debugger_dump_context_auto(app);
}
