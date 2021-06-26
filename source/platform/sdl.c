/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <errno.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <SDL2/SDL_image.h>
#include <SDL2/SDL.h>
#include "hades.h"
#include "gba.h"

struct sdl
{
    SDL_Renderer *renderer;
    SDL_Window *window;
    SDL_Texture *texture;
};

static
void
sdl_init(
    struct gba const *gba,
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
        240 * gba->options.scale,
        160 * gba->options.scale,
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
sdl_cleanup(
    struct sdl *app
) {
    SDL_DestroyTexture(app->texture);
    SDL_DestroyRenderer(app->renderer);
    SDL_DestroyWindow(app->window);
    SDL_Quit();
}

static
void
sdl_take_screenshot(
    struct sdl *app
) {
    time_t now;
    struct tm *now_info;
    char file_name[256];
    SDL_Surface *screenshot;
    int w;
    int h;
    int out;

    time(&now);
    now_info = localtime(&now);

    mkdir("screenshots", 0755);
    strftime(file_name, sizeof(file_name), "screenshots/%Y-%m-%d_%Hh%Mm%Ss.png", now_info);

    SDL_GetRendererOutputSize(app->renderer, &w, &h);
    screenshot = SDL_CreateRGBSurface(0, w, h, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000);
    SDL_RenderReadPixels(app->renderer, NULL, SDL_PIXELFORMAT_ARGB8888, screenshot->pixels, screenshot->pitch);
    out = IMG_SavePNG(screenshot, file_name);
    SDL_FreeSurface(screenshot);

    if (!out) {
        printf(
            "Screenshot saved in %s%s%s...\n",
            g_light_green,
            file_name,
            g_reset
        );
    } else {
        printf(
            "%sError: failed to save screenshot in %s%s%s!%s\n",
            g_light_red,
            g_light_green,
            file_name,
            g_light_red,
            g_reset
        );
    }

}

static
void
sdl_handle_inputs(
    struct gba *gba,
    struct sdl *app
) {
    SDL_Event event;

    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_KEYDOWN:
                {
                    pthread_mutex_lock(&gba->input_mutex);
                    switch (event.key.keysym.sym) {
                        case SDLK_UP:
                        case SDLK_w:                gba->input.up = false; break;
                        case SDLK_DOWN:
                        case SDLK_s:                gba->input.down = false; break;
                        case SDLK_LEFT:
                        case SDLK_a:                gba->input.left = false; break;
                        case SDLK_RIGHT:
                        case SDLK_d:                gba->input.right = false; break;
                        case SDLK_p:                gba->input.a = false; break;
                        case SDLK_l:                gba->input.b = false; break;
                        case SDLK_e:                gba->input.l = false; break;
                        case SDLK_o:                gba->input.r = false; break;
                        case SDLK_BACKSPACE:        gba->input.select = false; break;
                        case SDLK_RETURN:           gba->input.start = false; break;
                    }
                    pthread_mutex_unlock(&gba->input_mutex);
                }
                break;
            case SDL_KEYUP:
                {
                    pthread_mutex_lock(&gba->input_mutex);
                    switch (event.key.keysym.sym) {
                        case SDLK_UP:
                        case SDLK_w:                gba->input.up = true; break;
                        case SDLK_DOWN:
                        case SDLK_s:                gba->input.down = true; break;
                        case SDLK_LEFT:
                        case SDLK_a:                gba->input.left = true; break;
                        case SDLK_RIGHT:
                        case SDLK_d:                gba->input.right = true; break;
                        case SDLK_p:                gba->input.a = true; break;
                        case SDLK_l:                gba->input.b = true; break;
                        case SDLK_e:                gba->input.l = true; break;
                        case SDLK_o:                gba->input.r = true; break;
                        case SDLK_BACKSPACE:        gba->input.select = true; break;
                        case SDLK_RETURN:           gba->input.start = true; break;
                        case SDLK_F5:
                            g_interrupt = true;
                            pthread_mutex_lock(&gba->emulator_mutex);
                            if (!save_state(gba, gba->save_path)) {
                                logln(
                                    HS_GLOBAL,
                                    "State saved to %s%s%s",
                                    g_light_magenta,
                                    gba->save_path,
                                    g_reset
                                );
                            } else {
                                logln(
                                    HS_GLOBAL,
                                    "%sError: failed to save state to %s: %s%s",
                                    g_light_red,
                                    gba->save_path,
                                    strerror(errno),
                                    g_reset
                                );
                            }
                            g_interrupt = false;
                            pthread_mutex_unlock(&gba->emulator_mutex);
                            break;
                        case SDLK_F2:               sdl_take_screenshot(app); break;
                        case SDLK_F8:
                            g_interrupt = true;
                            pthread_mutex_lock(&gba->emulator_mutex);
                            if (!load_state(gba, gba->save_path)) {
                                logln(
                                    HS_GLOBAL,
                                    "State loaded from %s%s%s",
                                    g_light_magenta,
                                    gba->save_path,
                                    g_reset
                                );
                            } else {
                                logln(
                                    HS_GLOBAL,
                                    "%sError: failed to load state from %s: %s%s",
                                    g_light_red,
                                    gba->save_path,
                                    strerror(errno),
                                    g_reset
                                );
                            }
                            g_interrupt = false;
                            pthread_mutex_unlock(&gba->emulator_mutex);
                            break;
                        default:
                            break;
                    }
                    pthread_mutex_unlock(&gba->input_mutex);
                }
                break;
            case SDL_QUIT:
                g_stop = true;
                g_interrupt = true;
                kill(getpid(), SIGTERM);        // Ask readline to stop waiting for user input
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
    static uint old_frame_counter = 0;
    char title[1024];
    uint sdl_count;
    struct sdl app;

    sdl_init(gba, &app);

    sdl_count = 0;
    while (!g_stop) {
        SDL_SetRenderDrawColor(app.renderer, 255, 255, 255, 255);

        sdl_handle_inputs(gba, &app);

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
        ++sdl_count;

        if (sdl_count >= 120) {
            uint fps;

            // TODO: Actually count frame correctly instead of this shit
            fps = (gba->frame_counter - old_frame_counter) / 2; // 120 SDL frames is roughly 2 seconds
            old_frame_counter = gba->frame_counter;

            snprintf(title, sizeof(title), "Hades | %s | %u FPS", gba->game_title, fps);
            SDL_SetWindowTitle(app.window, title);
            sdl_count = 0;
        }
    }

    sdl_cleanup(&app);

    return (NULL);
}