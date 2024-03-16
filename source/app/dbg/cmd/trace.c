/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

void
debugger_cmd_trace(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    if (argc == 0) {
        debugger_dump_context_compact_header();
        app_emulator_trace(app, 1, debugger_dump_context_compact);
        debugger_wait_for_emulator(app);
        debugger_dump_context_compact_header();
    } else if (argc == 1) {
        if (debugger_check_arg_type(CMD_TRACE, &argv[0], ARGS_INTEGER)) {
            return;
        }

        debugger_dump_context_compact_header();
        app_emulator_trace(app, argv[0].value.i64, debugger_dump_context_compact);
        debugger_wait_for_emulator(app);
        debugger_dump_context_compact_header();
    } else {
        printf("Usage: %s\n", g_commands[CMD_TRACE].usage);
        return;
    }
}
