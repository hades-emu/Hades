/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <SDL2/SDL.h>
#include <stdlib.h>
#include "app/app.h"

void
app_sdl_init(
    struct app *app
) {
    // On Linux, hint at SDL that we are using Wayland if WAYLAND_DISPLAY is set.
#if defined(__LINUX__) && SDL_VERSION_ATLEAST(2, 0, 22)
    if (getenv("WAYLAND_DISPLAY")) {
        SDL_SetHint(SDL_HINT_VIDEODRIVER, "wayland");
    }
#endif

    /* Initialize the SDL */
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMECONTROLLER | SDL_INIT_AUDIO) < 0) {
        logln(HS_ERROR, "Failed to init the SDL: %s", SDL_GetError());
        exit(EXIT_FAILURE);
    }

    app_sdl_audio_init(app);
    app_sdl_video_init(app);
}

void
app_sdl_cleanup(
    struct app *app
) {

    app_sdl_video_cleanup(app);
    app_sdl_audio_cleanup(app);

    SDL_Quit();
}
