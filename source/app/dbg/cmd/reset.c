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
    // Since this debugger command runs on the debugger's own thread, we hop back to the
    // main thread before invoking it using `SDL_RunOnMainThread()`.
    // The last arg is set to `true` so that this command keeps its current, synchronous behavior.
    SDL_RunOnMainThread((SDL_MainThreadCallback)app_emulator_reset, app, true);
}
