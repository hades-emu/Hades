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
        480,
        320,
        0
    );

    if (!app->window) {
        printf(
            "Failed to open window: %s\n",
            SDL_GetError()
        );
        exit(1);
    }

    app->renderer = SDL_CreateRenderer(
        app->window,
        -1,
        SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC
    );

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
            case SDL_KEYDOWN:
                switch (event.key.keysym.sym) {
                    case SDLK_UP:
                    case SDLK_w:                gba->io.keyinput.up = false; break;
                    case SDLK_DOWN:
                    case SDLK_s:                gba->io.keyinput.down = false; break;
                    case SDLK_LEFT:
                    case SDLK_a:                gba->io.keyinput.left = false; break;
                    case SDLK_RIGHT:
                    case SDLK_d:                gba->io.keyinput.right = false; break;
                    case SDLK_p:                gba->io.keyinput.a = false; break;
                    case SDLK_l:                gba->io.keyinput.b = false; break;
                    case SDLK_e:                gba->io.keyinput.l = false; break;
                    case SDLK_o:                gba->io.keyinput.r = false; break;
                    case SDLK_BACKSPACE:        gba->io.keyinput.select = false; break;
                    case SDLK_RETURN:           gba->io.keyinput.start = false; break;
                }
                break;
            case SDL_KEYUP:
                switch (event.key.keysym.sym) {
                    case SDLK_UP:
                    case SDLK_w:                gba->io.keyinput.up = true; break;
                    case SDLK_DOWN:
                    case SDLK_s:                gba->io.keyinput.down = true; break;
                    case SDLK_LEFT:
                    case SDLK_a:                gba->io.keyinput.left = true; break;
                    case SDLK_RIGHT:
                    case SDLK_d:                gba->io.keyinput.right = true; break;
                    case SDLK_p:                gba->io.keyinput.a = true; break;
                    case SDLK_l:                gba->io.keyinput.b = true; break;
                    case SDLK_e:                gba->io.keyinput.l = true; break;
                    case SDLK_o:                gba->io.keyinput.r = true; break;
                    case SDLK_BACKSPACE:        gba->io.keyinput.select = true; break;
                    case SDLK_RETURN:           gba->io.keyinput.start = true; break;
                    default:                                  break;
                }
                break;
            case SDL_QUIT:
                g_stop = true;
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

    while (!g_stop) {
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