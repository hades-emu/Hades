/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <SDL2/SDL_image.h>
#include <SDL2/SDL.h>
#include "hades.h"
#include "compat.h"
#include "gba.h"

struct sdl
{
    SDL_Renderer *renderer;
    SDL_Window *window;
    SDL_Texture *texture;

    // Game Controller
    SDL_GameController *controller;
    SDL_JoystickID joystick_idx;
    bool controller_connected;
};

/*
** Initialize the SDL sub-system and create the window.
*/
static
void
sdl_init(
    struct gba const *gba,
    struct sdl *app
) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_GAMECONTROLLER) < 0) {
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

    // Fallback with software rendering
    if (!app->renderer) {
        app->renderer = SDL_CreateRenderer(
            app->window,
            -1,
            SDL_RENDERER_SOFTWARE | SDL_RENDERER_PRESENTVSYNC
        );
    }

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

    app->controller = NULL;
    app->joystick_idx = -1;
    app->controller_connected = false;
}

/*
** Clean-up and quit the SDL sub-system, therefore closing the window.
*/
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

/*
** Take a screenshot (PNG) of the rendered output and put it in a
** file named after the current time.
**
** All screenshots are put in the `screenshot/`subdirectory.
*/
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

    hs_mkdir("screenshots");
    strftime(file_name, sizeof(file_name), "screenshots/%Y-%m-%d_%Hh%Mm%Ss.png", now_info);

    SDL_GetRendererOutputSize(app->renderer, &w, &h);
    screenshot = SDL_CreateRGBSurface(0, w, h, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000);
    SDL_RenderReadPixels(app->renderer, NULL, SDL_PIXELFORMAT_ARGB8888, screenshot->pixels, screenshot->pitch);
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

/*
** Handle all SDL events, processing them if any or instantly returning if not.
*/
static
void
sdl_handle_events(
    struct gba *gba,
    struct sdl *app
) {
    SDL_Event event;

    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_CONTROLLERDEVICEADDED:
                if (!app->controller_connected) {
                    SDL_Joystick *joystick;

                    app->controller = SDL_GameControllerOpen(event.cdevice.which);
                    joystick = SDL_GameControllerGetJoystick(app->controller);
                    app->joystick_idx = SDL_JoystickInstanceID(joystick);
                    app->controller_connected = true;
                    logln(
                        HS_GLOBAL,
                        "Controller \"%s%s%s\" connected.",
                        g_light_magenta,
                        SDL_GameControllerName(app->controller),
                        g_reset
                    );
                }
                break;
            case SDL_CONTROLLERDEVICEREMOVED:
                if (event.cdevice.which >= 0 && event.cdevice.which == app->joystick_idx) {
                    logln(
                        HS_GLOBAL,
                        "Controller \"%s%s%s\" disconnected.",
                        g_light_magenta,
                        SDL_GameControllerName(app->controller),
                        g_reset
                    );
                    SDL_GameControllerClose(app->controller);
                    app->controller = NULL;
                    app->joystick_idx = -1;
                    app->controller_connected = false;
                }
                break;
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
                        case SDLK_F2:               sdl_take_screenshot(app); break;
                        case SDLK_F5:               save_state(gba, gba->save_path); break;
                        case SDLK_F8:               load_state(gba, gba->save_path); break;
                        default:
                            break;
                    }
                    pthread_mutex_unlock(&gba->input_mutex);
                }
                break;
            case SDL_CONTROLLERBUTTONDOWN:
                {
                    pthread_mutex_lock(&gba->input_mutex);
                    switch (event.cbutton.button) {
                        case SDL_CONTROLLER_BUTTON_B:               gba->input.a = false; break;
                        case SDL_CONTROLLER_BUTTON_A:               gba->input.b = false; break;
                        case SDL_CONTROLLER_BUTTON_Y:               gba->input.a = false; break;
                        case SDL_CONTROLLER_BUTTON_X:               gba->input.b = false; break;
                        case SDL_CONTROLLER_BUTTON_DPAD_LEFT:       gba->input.left = false; break;
                        case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:      gba->input.right = false; break;
                        case SDL_CONTROLLER_BUTTON_DPAD_UP:         gba->input.up = false; break;
                        case SDL_CONTROLLER_BUTTON_DPAD_DOWN:       gba->input.down = false; break;
                        case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:    gba->input.l = false; break;
                        case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:   gba->input.r = false; break;
                        case SDL_CONTROLLER_BUTTON_START:           gba->input.start = false; break;
                        case SDL_CONTROLLER_BUTTON_BACK:            gba->input.select = false; break;
                    }
                    pthread_mutex_unlock(&gba->input_mutex);
                }
                break;
            case SDL_CONTROLLERBUTTONUP:
                {
                    pthread_mutex_lock(&gba->input_mutex);
                    switch (event.cbutton.button) {
                        case SDL_CONTROLLER_BUTTON_B:               gba->input.a = true; break;
                        case SDL_CONTROLLER_BUTTON_A:               gba->input.b = true; break;
                        case SDL_CONTROLLER_BUTTON_Y:               gba->input.a = true; break;
                        case SDL_CONTROLLER_BUTTON_X:               gba->input.b = true; break;
                        case SDL_CONTROLLER_BUTTON_DPAD_LEFT:       gba->input.left = true; break;
                        case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:      gba->input.right = true; break;
                        case SDL_CONTROLLER_BUTTON_DPAD_UP:         gba->input.up = true; break;
                        case SDL_CONTROLLER_BUTTON_DPAD_DOWN:       gba->input.down = true; break;
                        case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:    gba->input.l = true; break;
                        case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:   gba->input.r = true; break;
                        case SDL_CONTROLLER_BUTTON_START:           gba->input.start = true; break;
                        case SDL_CONTROLLER_BUTTON_BACK:            gba->input.select = true; break;
#if SDL_VERSION_ATLEAST(2, 0, 14)
                        case SDL_CONTROLLER_BUTTON_MISC1:           sdl_take_screenshot(app); break;
#endif
                    }
                    pthread_mutex_unlock(&gba->input_mutex);
                }
                break;
            case SDL_QUIT:
                g_stop = true;
                g_interrupt = true;
                break;
            default:
                break;
        }
    }
}

/*
** Main function of the render thread.
** This function initializes and handles all SDL-related stuff.
*/
void
sdl_render_loop(
    struct gba *gba
) {
    static uint32_t old_frame_counter = 0;
    uint32_t sdl_last_ticks;
    struct sdl app;
    char title[1024];

    memset(&app, 0, sizeof(app));
    sdl_init(gba, &app);

    sdl_last_ticks = 0;
    while (!g_stop) {
        SDL_SetRenderDrawColor(app.renderer, 255, 255, 255, 255);

        sdl_handle_events(gba, &app);

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

        if (SDL_GetTicks() - sdl_last_ticks > 1000) {  // Update FPS every seconds
            uint32_t fps;

            fps = (gba->frame_counter - old_frame_counter);
            old_frame_counter = gba->frame_counter;

            snprintf(title, sizeof(title), "Hades | %s | %u FPS", gba->game_title, fps);
            SDL_SetWindowTitle(app.window, title);
            sdl_last_ticks = SDL_GetTicks();
        }
    }

    sdl_cleanup(&app);
}
