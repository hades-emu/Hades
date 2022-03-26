/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include <stb_image_write.h>
#include "hades.h"
#include "platform/gui.h"
#include "gba/gba.h"
#include "utils/fs.h"

void
gui_game_screenshot(
    struct app *app
) {
    time_t now;
    struct tm *now_info;
    char filename[256];
    int out;

    time(&now);
    now_info = localtime(&now);

    hs_mkdir("screenshots");
    strftime(filename, sizeof(filename), "screenshots/%Y-%m-%d_%Hh%Mm%Ss.png", now_info);

    pthread_mutex_lock(&app->emulation.gba->framebuffer_frontend_mutex);
    out = stbi_write_png(
        filename,
        GBA_SCREEN_WIDTH,
        GBA_SCREEN_HEIGHT,
        4,
        app->emulation.gba->framebuffer_frontend,
        GBA_SCREEN_WIDTH * sizeof(uint32_t)
    );
    pthread_mutex_unlock(&app->emulation.gba->framebuffer_frontend_mutex);

    if (out) {
        logln(
            HS_GLOBAL,
            "Screenshot saved in %s%s%s...",
            g_light_green,
            filename,
            g_reset
        );
    } else {
        logln(
            HS_ERROR,
            "%sError: failed to save screenshot in %s%s%s.%s",
            g_light_red,
            g_light_green,
            filename,
            g_light_red,
            g_reset
        );
    }
}