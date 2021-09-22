/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <frozen.h>
#include "hades.h"
#include "platform/gui.h"

void
gui_load_config(
    struct app *app
) {
    void *data;

    data = json_fread("./hades-config.json");

    if (!data) {
        return ;
    }

    json_scanf(
        data,
        strlen(data),
        STRINGIFY({
            recent_roms_0: %Q,
            recent_roms_1: %Q,
            recent_roms_2: %Q,
            recent_roms_3: %Q,
            recent_roms_4: %Q,
        }),
        &app->recent_roms[0],
        &app->recent_roms[1],
        &app->recent_roms[2],
        &app->recent_roms[3],
        &app->recent_roms[4]
    );
}

void
gui_save_config(
    struct app *app
) {
    json_fprintf(
        "./hades-config.json",
        STRINGIFY({
            recent_roms_0: %Q,
            recent_roms_1: %Q,
            recent_roms_2: %Q,
            recent_roms_3: %Q,
            recent_roms_4: %Q,
        }),
        app->recent_roms[0],
        app->recent_roms[1],
        app->recent_roms[2],
        app->recent_roms[3],
        app->recent_roms[4]
    );
}


void
gui_push_recent_roms(
    struct app *app
) {
    char *new_recent_roms[ARRAY_LEN(app->recent_roms)];
    int32_t i;
    int32_t j;
    size_t len;

    len = ARRAY_LEN(app->recent_roms);

    memset(new_recent_roms, 0, sizeof(new_recent_roms));
    new_recent_roms[0] = strdup(app->emulation.game_path);

    j = 0;
    for (i = 1; i < len && j < len; ++j) {
        if (!app->recent_roms[j] || strcmp(app->recent_roms[j], app->emulation.game_path)) {
            new_recent_roms[i] = app->recent_roms[j];
            ++i;
        } else {
            free(app->recent_roms[j]);
        }
    }

    while (j < len) {
        free(app->recent_roms[j]);
        ++j;
    }

    memcpy(app->recent_roms, new_recent_roms, sizeof(new_recent_roms));
}