/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "app.h"
#include "dbg/dbg.h"

void
debugger_cmd_watch(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    if (argc == 0) {
        if (app->debugger.watchpoints_len) {
            size_t i;

            printf("Watchpoints:\n");
            for (i = 0; i < app->debugger.watchpoints_len; ++i) {
                printf(
                    "  %s%2zi%s: %s0x%08x%s\n",
                    g_light_green,
                    i + 1,
                    g_reset,
                    g_light_magenta,
                    app->debugger.watchpoints[i].ptr,
                    g_reset
                );
            }
        } else {
            printf("There's no watchpoint.\n");
        }
    } else if (argc == 2) {
        bool read;
        bool write;

        if (debugger_check_arg_type(CMD_WATCH, &argv[0], ARGS_STRING)
            || debugger_check_arg_type(CMD_WATCH, &argv[1], ARGS_INTEGER)
        ) {
            printf("Usage: %s\n", g_commands[CMD_WATCH].usage);
            return ;
        }

        read = !strcmp(argv[0].value.s, "read") || !strcmp(argv[0].value.s, "r");
        write = !strcmp(argv[0].value.s, "write") || !strcmp(argv[0].value.s, "w");

        if (read || write) {
            struct watchpoint *clone;

            app->debugger.watchpoints = realloc(
                app->debugger.watchpoints,
                sizeof(struct watchpoint) * (app->debugger.watchpoints_len + 1)
            );

            app->debugger.watchpoints[app->debugger.watchpoints_len].ptr = argv[1].value.i64;
            app->debugger.watchpoints[app->debugger.watchpoints_len].write = write;
            ++app->debugger.watchpoints_len;

            printf(
                "New watchpoint at address %s0x%08x%s (%s%s%s)\n",
                g_light_magenta,
                app->debugger.watchpoints[app->debugger.watchpoints_len - 1].ptr,
                g_reset,
                g_light_green,
                write ? "write" : "read",
                g_reset
            );

            clone = malloc(sizeof(struct watchpoint) * (app->debugger.watchpoints_len));
            hs_assert(clone);
            memcpy(clone, app->debugger.watchpoints, sizeof(struct watchpoint) * (app->debugger.watchpoints_len));

            gba_send_dbg_watchpoints(app->emulation.gba, clone, app->debugger.watchpoints_len, free);
        } else if (!strcmp(argv[0].value.s, "delete") || !strcmp(argv[0].value.s, "d")) {
            struct watchpoint *clone;
            size_t idx;

            idx = argv[1].value.i64;
            if (idx <= 0 || idx > app->debugger.watchpoints_len) {
                printf("Unknown watchpoint with ID %zu.\n", idx);
                return ;
            }
            idx -= 1;

            memmove(
                app->debugger.watchpoints + idx,
                app->debugger.watchpoints + idx + 1,
                sizeof(struct watchpoint) * (app->debugger.watchpoints_len - idx - 1)
            );

            app->debugger.watchpoints = realloc(
                app->debugger.watchpoints,
                sizeof(struct watchpoint) * (app->debugger.watchpoints_len - 1)
            );
            app->debugger.watchpoints_len -= 1;
            hs_assert(app->debugger.watchpoints);

            clone = malloc(sizeof(struct watchpoint) * (app->debugger.watchpoints_len));
            hs_assert(clone);
            memcpy(clone, app->debugger.watchpoints, sizeof(struct watchpoint) * (app->debugger.watchpoints_len));

            gba_send_dbg_watchpoints(app->emulation.gba, clone, app->debugger.watchpoints_len, free);
        } else {
            printf("Usage: %s\n", g_commands[CMD_WATCH].usage);
        }
    } else {
        printf("Usage: %s\n", g_commands[CMD_WATCH].usage);
    }
}
