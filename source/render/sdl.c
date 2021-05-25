/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <SDL2/SDL.h>
#include "hades.h"
#include "gba.h"

#include <stdio.h> // FIXME

struct sdl
{
    SDL_Renderer *renderer;
    SDL_Window *window;
    SDL_Texture *texture;
};

static
void
sdl_init(
    struct sdl *app
) {
    if (SDL_Init(SDL_INIT_VIDEO) < 0) {
        printf("Couldn't initialize SDL: %s\n", SDL_GetError());
        exit(1);
    }

    app->window = SDL_CreateWindow(
        "Hades",
        SDL_WINDOWPOS_UNDEFINED,
        SDL_WINDOWPOS_UNDEFINED,
        960,
        640,
        0
    );

    if (!app->window) {
        printf(
            "Failed to open window: %s\n",
            SDL_GetError()
        );
        exit(1);
    }

    SDL_SetHint(SDL_HINT_RENDER_SCALE_QUALITY, 0);

    app->renderer = SDL_CreateRenderer(app->window, -1, SDL_RENDERER_ACCELERATED);

    if (!app->renderer) {
        printf("Failed to create renderer: %s\n", SDL_GetError());
        exit(1);
    }

    app->texture = SDL_CreateTexture(
        app->renderer,
        SDL_PIXELFORMAT_ARGB8888,
        SDL_TEXTUREACCESS_STREAMING,
        240,
        160
    );
}

static
void
sdl_handle_inputs(
    struct gba *gba
) {
    SDL_Event event;

    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_QUIT:
                kill(getpid(), SIGTERM);        // Ask readline to stop waiting for user input
                pthread_exit(NULL);
                break;
            default:
                break;
        }
    }
}

void *
sdl_render_loop(
    struct gba *gba
) {
    struct sdl app;

    sdl_init(&app);

    while (true) { // UNSAFE TODO FIXME
        SDL_SetRenderDrawColor(app.renderer, 96, 128, 255, 255);
        SDL_RenderClear(app.renderer);

        sdl_handle_inputs(gba);

        pthread_mutex_lock(&gba->framebuffer_mutex);

        SDL_UpdateTexture(
            app.texture,
            NULL,
            gba->framebuffer,
            240 * sizeof (uint32_t)
        );

        SDL_RenderClear(app.renderer);
        SDL_RenderCopy(app.renderer, app.texture, NULL, NULL);

        pthread_mutex_unlock(&gba->framebuffer_mutex);

        SDL_RenderPresent(app.renderer);

        SDL_Delay(17);
    }
    return (NULL);
}