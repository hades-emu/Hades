/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <GL/glew.h>
#include <SDL2/SDL_image.h>
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
    char file_name[256];
    SDL_Surface *screenshot;
    int out;

    time(&now);
    now_info = localtime(&now);

    hs_mkdir("screenshots");
    strftime(file_name, sizeof(file_name), "screenshots/%Y-%m-%d_%Hh%Mm%Ss.png", now_info);

    screenshot = SDL_CreateRGBSurface(0, GBA_SCREEN_WIDTH, GBA_SCREEN_HEIGHT, 32, 0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000);

    pthread_mutex_lock(&app->emulation.gba->framebuffer_frontend_mutex);
    memcpy(screenshot->pixels, app->emulation.gba->framebuffer_frontend, sizeof(app->emulation.gba->framebuffer_frontend));
    pthread_mutex_unlock(&app->emulation.gba->framebuffer_frontend_mutex);

    out = IMG_SavePNG(screenshot, file_name);
    SDL_FreeSurface(screenshot);

    if (!out) {
        logln(
            HS_GLOBAL,
            "Screenshot saved in %s%s%s...",
            g_light_green,
            file_name,
            g_reset
        );
    } else {
        logln(
            HS_ERROR,
            "%sError: failed to save screenshot in %s%s%s!%s",
            g_light_red,
            g_light_green,
            file_name,
            g_light_red,
            g_reset
        );
    }
}