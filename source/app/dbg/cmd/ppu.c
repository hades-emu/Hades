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
#include "log.h"

void
debugger_cmd_ppu(
    struct app *app,
    size_t argc,
    struct arg const *argv
) {
    char const * const names[] = {
        "bg0",
        "bg1",
        "bg2",
        "bg3",
        "oam",
    };

    bool *values[] = {
        &app->settings.video.enable_bg_layers[0],
        &app->settings.video.enable_bg_layers[1],
        &app->settings.video.enable_bg_layers[2],
        &app->settings.video.enable_bg_layers[3],
        &app->settings.video.enable_oam,
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

        if (debugger_check_arg_type(CMD_PPU, &argv[0], ARGS_STRING)) {
            return ;
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
                return ;
            }
        }

        printf("Unknown PPU settings \"%s\".", argv[0].value.s);
    } else {
        printf("Usage: %s\n", g_commands[CMD_PPU].usage);
    }
}

