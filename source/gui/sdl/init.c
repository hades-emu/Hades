/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#define SDL_MAIN_HANDLED
#include <SDL2/SDL.h>
#include <stdio.h>
#include "app.h"
#include "gui/gui.h"

void
gui_sdl_init(
    struct app *app
) {
    SDL_SetMainReady();

    /* Initialize the SDL */
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMECONTROLLER | SDL_INIT_AUDIO) < 0) {
        logln(HS_ERROR, "Failed to init the SDL: %s", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    gui_sdl_audio_init(app);
    gui_sdl_video_init(app);
}

void
gui_sdl_cleanup(
    struct app *app
) {

    gui_sdl_video_cleanup(app);
    gui_sdl_audio_cleanup(app);

    SDL_Quit();
}