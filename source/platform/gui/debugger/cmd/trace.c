/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "platform/gui/app.h"
#include "platform/gui/debugger.h"
#include "utils/time.h"

void
debugger_cmd_trace(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) {
        debugger_dump_context_compact_header();
        app->emulation.gba->debugger.interrupt.flag = false;
        gui_game_trace(app, 1, debugger_dump_context_compact);
        debugger_wait_for_emulator(app, false);
        debugger_dump_context_compact_header();
    } else if (argc == 1) {

        if (debugger_check_arg_type(CMD_TRACE, &argv[0], ARGS_INTEGER)) {
            return ;
        }

        debugger_dump_context_compact_header();
        app->emulation.gba->debugger.interrupt.flag = false;
        gui_game_trace(app, argv[0].value.i64, debugger_dump_context_compact);
        debugger_wait_for_emulator(app, false);
        debugger_dump_context_compact_header();
    } else {
        printf("Usage: %s\n", g_commands[CMD_TRACE].usage);
        return ;
    }
}