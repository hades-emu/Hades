/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

void
debugger_cmd_screenshot(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    if (argc == 0) {
        app_emulator_screenshot(app);
    } else if (argc == 1) {
        if (debugger_check_arg_type(CMD_SCREENSHOT, &argv[0], ARGS_STRING)) {
            return ;
        }

        app_emulator_screenshot_path(app, argv[0].value.s);
    } else {
        printf("Usage: %s\n", g_commands[CMD_SCREENSHOT].usage);
        return ;
    }
}