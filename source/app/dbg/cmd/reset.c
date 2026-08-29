/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

void
debugger_cmd_reset(
    struct app *app,
    size_t argc __unused,
    struct arg const *argv __unused
) {
    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    // `app_emulator_reset()` eventually calls `SDL_SetWindowTitle()`, which on some
    // platforms (e.g. MacOS) is only allowed to be called from the main thread.
    SDL_RunOnMainThread((SDL_MainThreadCallback)app_emulator_reset_and_pause, app, true);

    debugger_wait_for_notif(app, NOTIFICATION_RESET);
    debugger_dump_context_auto(app);
}
