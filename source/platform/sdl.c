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
#include "event.h"

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
            SDL_RENDERER_SOFTWARE
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
                    switch (event.key.keysym.sym) {
                        case SDLK_UP:
                        case SDLK_w:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_UP, true)); break;
                        case SDLK_DOWN:
                        case SDLK_s:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_DOWN, true)); break;
                        case SDLK_LEFT:
                        case SDLK_a:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_LEFT, true)); break;
                        case SDLK_RIGHT:
                        case SDLK_d:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_RIGHT, true)); break;
                        case SDLK_p:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_A, true)); break;
                        case SDLK_l:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_B, true)); break;
                        case SDLK_e:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_L, true)); break;
                        case SDLK_o:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_R, true)); break;
                        case SDLK_BACKSPACE:        message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_SELECT, true)); break;
                        case SDLK_RETURN:           message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_START, true)); break;
                    }
                }
                break;
            case SDL_KEYUP:
                {
                    switch (event.key.keysym.sym) {
                        case SDLK_UP:
                        case SDLK_w:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_UP, false)); break;
                        case SDLK_DOWN:
                        case SDLK_s:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_DOWN, false)); break;
                        case SDLK_LEFT:
                        case SDLK_a:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_LEFT, false)); break;
                        case SDLK_RIGHT:
                        case SDLK_d:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_RIGHT, false)); break;
                        case SDLK_p:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_A, false)); break;
                        case SDLK_l:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_B, false)); break;
                        case SDLK_e:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_L, false)); break;
                        case SDLK_o:                message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_R, false)); break;
                        case SDLK_BACKSPACE:        message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_SELECT, false)); break;
                        case SDLK_RETURN:           message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_START, false)); break;
                        case SDLK_F2:               sdl_take_screenshot(app); break;
                        case SDLK_F5:               message_new(gba, NEW_MESSAGE_QUICKSAVE()); break;
                        case SDLK_F8:               message_new(gba, NEW_MESSAGE_QUICKLOAD()); break;
                        default:
                            break;
                    }
                }
                break;
            case SDL_CONTROLLERBUTTONDOWN:
                {
                    switch (event.cbutton.button) {
                        case SDL_CONTROLLER_BUTTON_B:               message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_A, true)); break;
                        case SDL_CONTROLLER_BUTTON_A:               message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_B, true)); break;
                        case SDL_CONTROLLER_BUTTON_Y:               message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_A, true)); break;
                        case SDL_CONTROLLER_BUTTON_X:               message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_B, true)); break;
                        case SDL_CONTROLLER_BUTTON_DPAD_LEFT:       message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_LEFT, true)); break;
                        case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:      message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_RIGHT, true)); break;
                        case SDL_CONTROLLER_BUTTON_DPAD_UP:         message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_UP, true)); break;
                        case SDL_CONTROLLER_BUTTON_DPAD_DOWN:       message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_DOWN, true)); break;
                        case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:    message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_L, true)); break;
                        case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:   message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_R, true)); break;
                        case SDL_CONTROLLER_BUTTON_START:           message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_START, true)); break;
                        case SDL_CONTROLLER_BUTTON_BACK:            message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_SELECT, true)); break;
                    }
                }
                break;
            case SDL_CONTROLLERBUTTONUP:
                {
                    switch (event.cbutton.button) {
                        case SDL_CONTROLLER_BUTTON_B:               message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_A, false)); break;
                        case SDL_CONTROLLER_BUTTON_A:               message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_B, false)); break;
                        case SDL_CONTROLLER_BUTTON_Y:               message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_A, false)); break;
                        case SDL_CONTROLLER_BUTTON_X:               message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_B, false)); break;
                        case SDL_CONTROLLER_BUTTON_DPAD_LEFT:       message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_LEFT, false)); break;
                        case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:      message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_RIGHT, false)); break;
                        case SDL_CONTROLLER_BUTTON_DPAD_UP:         message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_UP, false)); break;
                        case SDL_CONTROLLER_BUTTON_DPAD_DOWN:       message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_DOWN, false)); break;
                        case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:    message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_L, false)); break;
                        case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:   message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_R, false)); break;
                        case SDL_CONTROLLER_BUTTON_START:           message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_START, false)); break;
                        case SDL_CONTROLLER_BUTTON_BACK:            message_new(gba, NEW_MESSAGE_KEYINPUT(KEY_SELECT, false)); break;
#if SDL_VERSION_ATLEAST(2, 0, 14)
                        case SDL_CONTROLLER_BUTTON_MISC1:           sdl_take_screenshot(app); break;
#endif
                    }
                }
                break;
            case SDL_QUIT:
                g_stop = true;
                g_interrupt = true;
#if ENABLE_DEBUGGER
                pthread_kill(gba->logic_thread, SIGTERM); // Ask readline to stop waiting for user input
#endif
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

        pthread_mutex_lock(&gba->framebuffer_render_mutex);

        SDL_UpdateTexture(
            app.texture,
            NULL,
            gba->framebuffer_render,
            240 * sizeof (uint32_t)
        );

        SDL_RenderClear(app.renderer);
        SDL_RenderCopy(app.renderer, app.texture, NULL, NULL);

        pthread_mutex_unlock(&gba->framebuffer_render_mutex);

        SDL_RenderPresent(app.renderer);

        SDL_Delay(17);

        if (SDL_GetTicks() - sdl_last_ticks > 1000) {  // Update FPS every seconds
            uint32_t fps;

            fps = (gba->frame_counter - old_frame_counter);
            old_frame_counter = gba->frame_counter;

            snprintf(title, sizeof(title), "Hades - %u FPS", fps);
            SDL_SetWindowTitle(app.window, title);
            sdl_last_ticks = SDL_GetTicks();
        }
    }

    sdl_cleanup(&app);
}
