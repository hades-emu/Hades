/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

void
debugger_cmd_break(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) {
        if (app->debugger.breakpoints_len) {
            size_t i;

            printf("Breakpoints:\n");
            for (i = 0; i < app->debugger.breakpoints_len; ++i) {
                printf(
                    "  %s%2zi%s: %s0x%08x%s\n",
                    g_light_green,
                    i + 1,
                    g_reset,
                    g_light_magenta,
                    app->debugger.breakpoints[i].ptr,
                    g_reset
                );
            }
        } else {
            printf("There's no breakpoint.\n");
        }
    } else if (argc == 1) {
        if (!debugger_check_arg_type(CMD_BREAK, &argv[0], ARGS_INTEGER)) {
            app->debugger.breakpoints = realloc(
                app->debugger.breakpoints,
                sizeof(struct breakpoint) * (app->debugger.breakpoints_len + 1)
            );

            hs_assert(app->debugger.breakpoints);

            app->debugger.breakpoints[app->debugger.breakpoints_len].ptr = argv[0].value.i64;
            ++app->debugger.breakpoints_len;

            printf(
                "New breakpoint at address %s0x%08x%s\n",
                g_light_magenta,
                app->debugger.breakpoints[app->debugger.breakpoints_len - 1].ptr,
                g_reset
            );

            app_emulator_set_breakpoints_list(app, app->debugger.breakpoints, app->debugger.breakpoints_len);
        }
    } else if (argc == 2) {
        size_t idx;

        if (debugger_check_arg_type(CMD_BREAK, &argv[0], ARGS_STRING)
            || debugger_check_arg_type(CMD_BREAK, &argv[1], ARGS_INTEGER)
        ) {
            return;
        }

        if (strcmp(argv[0].value.s, "delete") && strcmp(argv[0].value.s, "d")) {
            printf("Usage: %s\n", g_commands[CMD_BREAK].usage);
            return;
        }

        idx = argv[1].value.i64;
        if (idx <= 0 || idx > app->debugger.breakpoints_len) {
            printf("Unknown breakpoint with ID %zu.\n", idx);
            return;
        }
        idx -= 1;

        memmove(
            app->debugger.breakpoints + idx,
            app->debugger.breakpoints + idx + 1,
            sizeof(struct breakpoint) * (app->debugger.breakpoints_len - idx - 1)
        );

        app->debugger.breakpoints = realloc(
            app->debugger.breakpoints,
            sizeof(struct breakpoint) * (app->debugger.breakpoints_len - 1)
        );
        --app->debugger.breakpoints_len;

        if (app->debugger.breakpoints_len > 0) {
            hs_assert(app->debugger.breakpoints);
        }

        app_emulator_set_breakpoints_list(app, app->debugger.breakpoints, app->debugger.breakpoints_len);
    } else {
        printf("Usage: %s\n", g_commands[CMD_BREAK].usage);
    }
}
