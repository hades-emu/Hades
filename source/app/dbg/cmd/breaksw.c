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

static
void
debugger_cmd_break_sw_create(
    struct app *app,
    uint32_t addr,
    bool thumb
) {
    app->debugger.sw_breakpoints = realloc(
        app->debugger.sw_breakpoints,
        sizeof(struct sw_breakpoint) * (app->debugger.sw_breakpoints_len + 1)
    );

    hs_assert(app->debugger.sw_breakpoints);

    app->debugger.sw_breakpoints[app->debugger.sw_breakpoints_len].ptr = addr;
    app->debugger.sw_breakpoints[app->debugger.sw_breakpoints_len].thumb = thumb;
    ++app->debugger.sw_breakpoints_len;

    printf(
        "New software breakpoint at address %s0x%08x%s\n",
        g_light_magenta,
        app->debugger.sw_breakpoints[app->debugger.sw_breakpoints_len - 1].ptr,
        g_reset
    );

    app_emulator_set_breakpoints_list(
        app,
        app->debugger.hw_breakpoints,
        app->debugger.hw_breakpoints_len,
        app->debugger.sw_breakpoints,
        app->debugger.sw_breakpoints_len
    );
}

static
void
debugger_cmd_break_sw_delete(
    struct app *app,
    size_t idx
) {
    if (idx <= 0 || idx > app->debugger.sw_breakpoints_len) {
        printf("Unknown hardware breakpoint with ID %zu.\n", idx);
        return;
    }

    idx -= 1;

    memmove(
        app->debugger.sw_breakpoints + idx,
        app->debugger.sw_breakpoints + idx + 1,
        sizeof(struct sw_breakpoint) * (app->debugger.sw_breakpoints_len - idx - 1)
    );

    app->debugger.sw_breakpoints = realloc(
        app->debugger.sw_breakpoints,
        sizeof(struct sw_breakpoint) * (app->debugger.sw_breakpoints_len - 1)
    );
    --app->debugger.sw_breakpoints_len;

    if (app->debugger.sw_breakpoints_len > 0) {
        hs_assert(app->debugger.sw_breakpoints);
    }

    app_emulator_set_breakpoints_list(
        app,
        app->debugger.hw_breakpoints,
        app->debugger.hw_breakpoints_len,
        app->debugger.sw_breakpoints,
        app->debugger.sw_breakpoints_len
    );
}

void
debugger_cmd_break_sw(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) { // List software breakpoints
        size_t i;

        if (!app->debugger.sw_breakpoints_len) {
            printf("There's no software breakpoint.\n");
            return ;
        }

        printf("Software breakpoints:\n");
        for (i = 0; i < app->debugger.sw_breakpoints_len; ++i) {
            printf(
                "  %s%2zi%s: %s0x%08x%s\n",
                g_light_green,
                i + 1,
                g_reset,
                g_light_magenta,
                app->debugger.sw_breakpoints[i].ptr,
                g_reset
            );
        }
    } else if (argc == 2) { // Create or delete breakpoint
        if (debugger_check_arg_type(CMD_BREAK_SW, &argv[0], ARGS_STRING)
            || debugger_check_arg_type(CMD_BREAK_SW, &argv[1], ARGS_INTEGER)
        ) {
            return;
        }

        if (!strcmp(argv[0].value.s, "arm") || !strcmp(argv[0].value.s, "a")) {
            debugger_cmd_break_sw_create(app, argv[1].value.i64, false);
        } else if (!strcmp(argv[0].value.s, "thumb") || !strcmp(argv[0].value.s, "t")) {
            debugger_cmd_break_sw_create(app, argv[1].value.i64, true);
        } else if (!strcmp(argv[0].value.s, "delete") || !strcmp(argv[0].value.s, "d")) {
            debugger_cmd_break_sw_delete(app, argv[1].value.i64);
        } else {
            printf("Usage: %s\n", g_commands[CMD_BREAK_SW].usage);
        }
    } else {
        printf("Usage: %s\n", g_commands[CMD_BREAK_SW].usage);
    }
}
