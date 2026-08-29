/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

void
debugger_cmd_break_hw(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) { // List hardware breakpoints
        size_t i;

        if (!app->debugger.hw_breakpoints_len) {
            printf("There's no hardware breakpoint.\n");
            return;
        }

        printf("Hardware breakpoints:\n");
        for (i = 0; i < app->debugger.hw_breakpoints_len; ++i) {
            printf(
                "  %s%2zi%s: %s0x%08x%s\n",
                g_light_green,
                i + 1,
                g_reset,
                g_light_magenta,
                app->debugger.hw_breakpoints[i].ptr,
                g_reset
            );
        }
    } else if (argc == 1) { // Create breakpoint
        if (debugger_check_arg_type(CMD_BREAK_HW, &argv[0], ARGS_INTEGER)) {
            return;
        }

        app->debugger.hw_breakpoints = realloc(
            app->debugger.hw_breakpoints,
            sizeof(struct hw_breakpoint) * (app->debugger.hw_breakpoints_len + 1)
        );

        hs_assert(app->debugger.hw_breakpoints);

        app->debugger.hw_breakpoints[app->debugger.hw_breakpoints_len].ptr = argv[0].value.i64;
        ++app->debugger.hw_breakpoints_len;

        printf(
            "New hardware breakpoint at address %s0x%08x%s\n",
            g_light_magenta,
            app->debugger.hw_breakpoints[app->debugger.hw_breakpoints_len - 1].ptr,
            g_reset
        );

        app_emulator_set_breakpoints_list(
            app,
            app->debugger.hw_breakpoints,
            app->debugger.hw_breakpoints_len,
            app->debugger.sw_breakpoints,
            app->debugger.sw_breakpoints_len
        );
    } else if (argc == 2) { // Delete breakpoint
        size_t idx;

        if (debugger_check_arg_type(CMD_BREAK_HW, &argv[0], ARGS_STRING)
            || debugger_check_arg_type(CMD_BREAK_HW, &argv[1], ARGS_INTEGER)
        ) {
            return;
        }

        if (strcmp(argv[0].value.s, "delete") && strcmp(argv[0].value.s, "d")) {
            printf("Usage: %s\n", g_commands[CMD_BREAK_HW].usage);
            return;
        }

        idx = argv[1].value.i64;
        if (idx <= 0 || idx > app->debugger.hw_breakpoints_len) {
            printf("Unknown hardware breakpoint with ID %zu.\n", idx);
            return;
        }
        idx -= 1;

        memmove(
            app->debugger.hw_breakpoints + idx,
            app->debugger.hw_breakpoints + idx + 1,
            sizeof(struct hw_breakpoint) * (app->debugger.hw_breakpoints_len - idx - 1)
        );

        app->debugger.hw_breakpoints = realloc(
            app->debugger.hw_breakpoints,
            sizeof(struct hw_breakpoint) * (app->debugger.hw_breakpoints_len - 1)
        );
        --app->debugger.hw_breakpoints_len;

        if (app->debugger.hw_breakpoints_len > 0) {
            hs_assert(app->debugger.hw_breakpoints);
        }

        app_emulator_set_breakpoints_list(
            app,
            app->debugger.hw_breakpoints,
            app->debugger.hw_breakpoints_len,
            app->debugger.sw_breakpoints,
            app->debugger.sw_breakpoints_len
        );
    } else {
        printf("Usage: %s\n", g_commands[CMD_BREAK_HW].usage);
    }
}
