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
debugger_cmd_step_in(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) {
        app->emulation.gba->debugger.interrupt.flag = false;
        app_game_step(app, false, 1);
        debugger_wait_for_emulator(app, true);
    } else if (argc == 1) {

        if (debugger_check_arg_type(CMD_STEP_IN, &argv[0], ARGS_INTEGER)) {
            return ;
        }

        app->emulation.gba->debugger.interrupt.flag = false;
        app_game_step(app, false, argv[0].value.i64);
        debugger_wait_for_emulator(app, true);
    } else {
        printf("Usage: %s\n", g_commands[CMD_STEP_IN].usage);
        return ;
    }
}

void
debugger_cmd_step_over(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) {
        app->emulation.gba->debugger.interrupt.flag = false;
        app_game_step(app, true, 1);
        debugger_wait_for_emulator(app, true);
    } else if (argc == 1) {

        if (debugger_check_arg_type(CMD_STEP_OVER, &argv[0], ARGS_INTEGER)) {
            return ;
        }

        app->emulation.gba->debugger.interrupt.flag = false;
        app_game_step(app, true, argv[0].value.i64);
        debugger_wait_for_emulator(app, true);
    } else {
        printf("Usage: %s\n", g_commands[CMD_STEP_OVER].usage);
        return ;
    }
}