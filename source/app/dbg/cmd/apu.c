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
#include "log.h"

void
debugger_cmd_apu(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    char const * const names[] = {
        "psg0",
        "psg1",
        "psg2",
        "psg3",
        "fifo1",
        "fifo2",
    };

    bool *values[] = {
        &app->settings.audio.enable_psg_channels[0],
        &app->settings.audio.enable_psg_channels[1],
        &app->settings.audio.enable_psg_channels[2],
        &app->settings.audio.enable_psg_channels[3],
        &app->settings.audio.enable_fifo_channels[0],
        &app->settings.audio.enable_fifo_channels[1],
    };

    if (argc == 0) {
        size_t i;

        for (i = 0; i < array_length(names); ++i) {
            printf("%s%s%s: %s%s%s\n",
                g_light_magenta,
                names[i],
                g_reset,
                *values[i] ? g_light_green : g_light_red,
                *values[i] ? "true" : "false",
                g_reset
            );
        }
    } else if (argc == 1) {
        size_t i;

        if (debugger_check_arg_type(CMD_APU, &argv[0], ARGS_STRING)) {
            return;
        }

        for (i = 0; i < array_length(values); ++i) {
            if (!strcmp(argv[0].value.s, names[i])) {
                *values[i] ^= true;
                printf("%s%s%s set to %s%s%s\n",
                    g_light_magenta,
                    names[i],
                    g_reset,
                    *values[i] ? g_light_green : g_light_red,
                    *values[i] ? "true" : "false",
                    g_reset
                );
                app_emulator_settings(app);
                return;
            }
        }

        printf("Unknown APU settings \"%s\".", argv[0].value.s);
    } else {
        printf("Usage: %s\n", g_commands[CMD_APU].usage);
    }
}
