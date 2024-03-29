/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <SDL2/SDL.h>
#include <cimgui.h>
#include <cimgui_impl.h>
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
    app->binds.keyboard[BIND_EMULATOR_MUTE] = SDL_GetKeyFromName("M");
    app->binds.keyboard[BIND_EMULATOR_SCREENSHOT] = SDL_GetKeyFromName("F2");
    app->binds.keyboard[BIND_EMULATOR_PAUSE] = SDL_GetKeyFromName("F3");
    app->binds.keyboard[BIND_EMULATOR_FAST_FORWARD_HOLD] = SDL_GetKeyFromName("Space");
    app->binds.keyboard[BIND_EMULATOR_QUICKSAVE_1] = SDL_GetKeyFromName("F5");
    app->binds.keyboard[BIND_EMULATOR_QUICKLOAD_1] = SDL_GetKeyFromName("F8");

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
    app->binds.controller[BIND_EMULATOR_FAST_FORWARD_HOLD] = SDL_CONTROLLER_BUTTON_TOUCHPAD;
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
    SDL_Keycode key
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
        case BIND_EMULATOR_FAST_FORWARD_HOLD: {
            app->settings.emulation.fast_forward = pressed;
            app_emulator_settings(app);
            break;
        };
        default: break;
    }

    /* The next binds are only triggered when the key is pressed, not when it is released. */
    if (!pressed) {
        return;
    }

    /* Bindings that can be used outside of a game */
    switch (bind) {
        // So far, none
        default: break;
    }

    if (!app->emulation.is_started) {
        return;
    }

    /* Bindings that cannot be used outside of a game */
    switch (bind) {
        case BIND_EMULATOR_MUTE:                app->settings.audio.mute ^= 1; break;
        case BIND_EMULATOR_SCREENSHOT:          app_emulator_screenshot(app); break;
        case BIND_EMULATOR_PAUSE:               app->emulation.is_running ? app_emulator_pause(app) : app_emulator_run(app); break;
        case BIND_EMULATOR_STOP:                app_emulator_stop(app); break;
        case BIND_EMULATOR_RESET:               app_emulator_reset(app); break;
        case BIND_EMULATOR_SPEED_X0_25:
        case BIND_EMULATOR_SPEED_X0_50:
        case BIND_EMULATOR_SPEED_X1:
        case BIND_EMULATOR_SPEED_X2:
        case BIND_EMULATOR_SPEED_X3:
        case BIND_EMULATOR_SPEED_X4:
        case BIND_EMULATOR_SPEED_X5: {
            float speeds[] = {
                0.25f,
                0.50f,
                1.00f,
                2.00f,
                3.00f,
                4.00f,
                5.00f,
            };
            app->settings.emulation.fast_forward = false;
            app->settings.emulation.speed = speeds[bind - BIND_EMULATOR_SPEED_X0_25];
            app_emulator_settings(app);
            break;
        };
        case BIND_EMULATOR_FAST_FORWARD_TOGGLE: {
            app->settings.emulation.fast_forward ^= true;
            app_emulator_settings(app);
            break;
        }
        case BIND_EMULATOR_QUICKSAVE_1:
        case BIND_EMULATOR_QUICKSAVE_2:
        case BIND_EMULATOR_QUICKSAVE_3:
        case BIND_EMULATOR_QUICKSAVE_4:
        case BIND_EMULATOR_QUICKSAVE_5:
        case BIND_EMULATOR_QUICKSAVE_6:
        case BIND_EMULATOR_QUICKSAVE_7:
        case BIND_EMULATOR_QUICKSAVE_8:
        case BIND_EMULATOR_QUICKSAVE_9:
        case BIND_EMULATOR_QUICKSAVE_10: {
            app_emulator_quicksave(app, bind - BIND_EMULATOR_QUICKSAVE_1);
            break;
        };
        case BIND_EMULATOR_QUICKLOAD_1:
        case BIND_EMULATOR_QUICKLOAD_2:
        case BIND_EMULATOR_QUICKLOAD_3:
        case BIND_EMULATOR_QUICKLOAD_4:
        case BIND_EMULATOR_QUICKLOAD_5:
        case BIND_EMULATOR_QUICKLOAD_6:
        case BIND_EMULATOR_QUICKLOAD_7:
        case BIND_EMULATOR_QUICKLOAD_8:
        case BIND_EMULATOR_QUICKLOAD_9:
        case BIND_EMULATOR_QUICKLOAD_10: {
            app_emulator_quickload(app, bind - BIND_EMULATOR_QUICKLOAD_1);
            break;
        };
        default: break;
    }
}
