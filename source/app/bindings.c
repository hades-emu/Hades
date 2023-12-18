/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#define SDL_MAIN_HANDLED
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS

#include <SDL2/SDL.h>
#include <cimgui.h>
#include <cimgui_impl.h>
#include "hades.h"
#include "gba/event.h"
#include "app/app.h"

void
app_bindings_setup_default(
    struct app *app
) {
    size_t i;

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        app->binds.keyboard[i] = SDLK_UNKNOWN;
        app->binds.keyboard_alt[i] = SDLK_UNKNOWN;
        app->binds.controller[i] = SDL_CONTROLLER_BUTTON_INVALID;
        app->binds.controller_alt[i] = SDL_CONTROLLER_BUTTON_INVALID;
    }

    app->binds.keyboard[BIND_GBA_A] = SDL_GetKeyFromName("P");
    app->binds.keyboard[BIND_GBA_B] = SDL_GetKeyFromName("L");
    app->binds.keyboard[BIND_GBA_L] = SDL_GetKeyFromName("E");
    app->binds.keyboard[BIND_GBA_R] = SDL_GetKeyFromName("O");
    app->binds.keyboard[BIND_GBA_UP] = SDL_GetKeyFromName("W");
    app->binds.keyboard[BIND_GBA_DOWN] = SDL_GetKeyFromName("S");
    app->binds.keyboard[BIND_GBA_LEFT] = SDL_GetKeyFromName("A");
    app->binds.keyboard[BIND_GBA_RIGHT] = SDL_GetKeyFromName("D");
    app->binds.keyboard[BIND_GBA_START] = SDL_GetKeyFromName("Return");
    app->binds.keyboard[BIND_GBA_SELECT] = SDL_GetKeyFromName("Backspace");
    app->binds.keyboard[BIND_EMULATOR_SPEED_X1] = SDL_GetKeyFromName("1");
    app->binds.keyboard[BIND_EMULATOR_SPEED_X2] = SDL_GetKeyFromName("2");
    app->binds.keyboard[BIND_EMULATOR_SPEED_X3] = SDL_GetKeyFromName("3");
    app->binds.keyboard[BIND_EMULATOR_SPEED_X4] = SDL_GetKeyFromName("4");
    app->binds.keyboard[BIND_EMULATOR_SPEED_X5] = SDL_GetKeyFromName("5");
    app->binds.keyboard[BIND_EMULATOR_SPEED_MAX] = SDL_GetKeyFromName("0");
    app->binds.keyboard[BIND_EMULATOR_SPEED_MAX_HOLD] = SDL_GetKeyFromName("Space");
    app->binds.keyboard[BIND_EMULATOR_SCREENSHOT] = SDL_GetKeyFromName("F2");
    app->binds.keyboard[BIND_EMULATOR_QUICKSAVE] = SDL_GetKeyFromName("F5");
    app->binds.keyboard[BIND_EMULATOR_QUICKLOAD] = SDL_GetKeyFromName("F8");
    app->binds.keyboard[BIND_EMULATOR_PAUSE] = SDL_GetKeyFromName("F3");

    app->binds.keyboard_alt[BIND_GBA_UP] = SDL_GetKeyFromName("Up");
    app->binds.keyboard_alt[BIND_GBA_DOWN] = SDL_GetKeyFromName("Down");
    app->binds.keyboard_alt[BIND_GBA_LEFT] = SDL_GetKeyFromName("Left");
    app->binds.keyboard_alt[BIND_GBA_RIGHT] = SDL_GetKeyFromName("Right");

    app->binds.controller[BIND_GBA_A] = SDL_CONTROLLER_BUTTON_A;
    app->binds.controller[BIND_GBA_B] = SDL_CONTROLLER_BUTTON_B;
    app->binds.controller[BIND_GBA_L] = SDL_CONTROLLER_BUTTON_LEFTSHOULDER;
    app->binds.controller[BIND_GBA_R] = SDL_CONTROLLER_BUTTON_RIGHTSHOULDER;
    app->binds.controller[BIND_GBA_UP] = SDL_CONTROLLER_BUTTON_DPAD_UP;
    app->binds.controller[BIND_GBA_DOWN] = SDL_CONTROLLER_BUTTON_DPAD_DOWN;
    app->binds.controller[BIND_GBA_LEFT] = SDL_CONTROLLER_BUTTON_DPAD_LEFT;
    app->binds.controller[BIND_GBA_RIGHT] = SDL_CONTROLLER_BUTTON_DPAD_RIGHT;
    app->binds.controller[BIND_GBA_START] = SDL_CONTROLLER_BUTTON_START;
    app->binds.controller[BIND_GBA_SELECT] = SDL_CONTROLLER_BUTTON_BACK;
    app->binds.controller[BIND_EMULATOR_SCREENSHOT] = SDL_CONTROLLER_BUTTON_GUIDE;
    app->binds.controller[BIND_EMULATOR_SPEED_X1] = SDL_CONTROLLER_BUTTON_LEFTSTICK;
    app->binds.controller[BIND_EMULATOR_SPEED_X2] = SDL_CONTROLLER_BUTTON_RIGHTSTICK;
#if SDL_VERSION_ATLEAST(2, 0, 14)
    app->binds.controller[BIND_EMULATOR_SPEED_MAX_HOLD] = SDL_CONTROLLER_BUTTON_TOUCHPAD;
#endif

    app->binds.controller_alt[BIND_GBA_A] = SDL_CONTROLLER_BUTTON_Y;
    app->binds.controller_alt[BIND_GBA_B] = SDL_CONTROLLER_BUTTON_X;
}

/*
** Clear any existing keyboard bindings matching the given key.
*/
void
app_bindings_keyboard_clear(
    struct app *app,
    SDL_KeyCode key
) {
    size_t i;

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        if (app->binds.keyboard[i] == key) {
            app->binds.keyboard[i] = SDLK_UNKNOWN;
        }

        if (app->binds.keyboard_alt[i] == key) {
            app->binds.keyboard_alt[i] = SDLK_UNKNOWN;
        }
    }
}

/*
** Clear any existing controller bindings matching the given key.
*/
void
app_bindings_controller_clear(
    struct app *app,
    SDL_GameControllerButton btn
) {
    size_t i;

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        if (app->binds.controller[i] == btn) {
            app->binds.controller[i] = SDL_CONTROLLER_BUTTON_INVALID;
        }

        if (app->binds.controller_alt[i] == btn) {
            app->binds.controller_alt[i] = SDL_CONTROLLER_BUTTON_INVALID;
        }
    }
}

/*
** Handle a given binding.
*/
void
app_bindings_handle(
    struct app *app,
    enum bind_actions bind,
    bool pressed
) {
    switch (bind) {
        case BIND_GBA_UP:                       app_emulator_key(app, KEY_UP, pressed); break;
        case BIND_GBA_DOWN:                     app_emulator_key(app, KEY_DOWN, pressed); break;
        case BIND_GBA_LEFT:                     app_emulator_key(app, KEY_LEFT, pressed); break;
        case BIND_GBA_RIGHT:                    app_emulator_key(app, KEY_RIGHT, pressed); break;
        case BIND_GBA_A:                        app_emulator_key(app, KEY_A, pressed); break;
        case BIND_GBA_B:                        app_emulator_key(app, KEY_B, pressed); break;
        case BIND_GBA_L:                        app_emulator_key(app, KEY_L, pressed); break;
        case BIND_GBA_R:                        app_emulator_key(app, KEY_R, pressed); break;
        case BIND_GBA_SELECT:                   app_emulator_key(app, KEY_SELECT, pressed); break;
        case BIND_GBA_START:                    app_emulator_key(app, KEY_START, pressed); break;
        case BIND_EMULATOR_SPEED_MAX_HOLD: {
            app->emulation.unbounded = pressed;
            app_emulator_speed(app, app->emulation.speed * !app->emulation.unbounded);
            break;
        };
        default: break;
    }

    /* The next binds are only triggered when the key is pressed, not when it is released. */
    if (!pressed) {
        return ;
    }

    switch (bind) {
        case BIND_EMULATOR_SPEED_MAX:
        case BIND_EMULATOR_SPEED_X1:
        case BIND_EMULATOR_SPEED_X2:
        case BIND_EMULATOR_SPEED_X3:
        case BIND_EMULATOR_SPEED_X4:
        case BIND_EMULATOR_SPEED_X5: {
            app->emulation.unbounded = false;
            app->emulation.speed = bind - BIND_EMULATOR_SPEED_MAX;
            app_emulator_speed(app, app->emulation.speed);
            break;
        };
        case BIND_EMULATOR_SCREENSHOT:          app_emulator_screenshot(app); break;
        case BIND_EMULATOR_QUICKSAVE:           app_emulator_quicksave(app, 0); break;
        case BIND_EMULATOR_QUICKLOAD:           app_emulator_quickload(app, 0); break;
        case BIND_EMULATOR_PAUSE:               app->emulation.is_running ? app_emulator_pause(app) : app_emulator_run(app); break;
        case BIND_EMULATOR_RESET:               app_emulator_reset(app); app_emulator_run(app); break;
        default: break;
    }
}
