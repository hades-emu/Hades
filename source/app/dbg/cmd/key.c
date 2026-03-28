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

static char const * const key_names[] = {
    [KEY_A] = "a",
    [KEY_B] = "b",
    [KEY_L] = "l",
    [KEY_R] = "r",
    [KEY_UP] = "up",
    [KEY_DOWN] = "down",
    [KEY_LEFT] = "left",
    [KEY_RIGHT] = "right",
    [KEY_START] = "start",
    [KEY_SELECT] = "select",
};

void
debugger_cmd_key(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (!app->debugger.is_started) {
        logln(HS_ERROR, "%s%s%s", g_red, "This command cannot be used when no game is running.", g_reset);
        return;
    }

    if (argc == 2) {
        enum keys i;

        if (debugger_check_arg_type(CMD_KEY, &argv[0], ARGS_STRING)
            || debugger_check_arg_type(CMD_KEY, &argv[1], ARGS_INTEGER)
        ) {
            return;
        }

        for (i = KEY_MIN; i < KEY_MAX; ++i) {
            if (!strcmp(argv[0].value.s, key_names[i])) {
                app_emulator_key(app, i, (bool)argv[1].value.i64);
                printf(
                    "Key \"%s\" set to %s.\n",
                    argv[0].value.s,
                    argv[1].value.i64 ? "true" : "false"
                );
                return;
            }
        }

        printf("Error: unknown key \"%s\".\n", argv[0].value.s);
    } else {
        printf("Usage: %s\n", g_commands[CMD_KEY].usage);
        return;
    }
}
