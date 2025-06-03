/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE

#include <SDL2/SDL.h>
#include <cimgui.h>
#include <cimgui_impl.h>
#include "SDL_keycode.h"
#include "app/app.h"

void
app_bindings_setup_default(
    struct app *app
) {
    size_t i;

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        app_bindings_keyboard_binding_build(&app->binds.keyboard[i], SDLK_UNKNOWN, false, false, false);
        app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[i], SDLK_UNKNOWN, false, false, false);
    }

    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_A], SDL_GetKeyFromName("P"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_B], SDL_GetKeyFromName("L"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_L], SDL_GetKeyFromName("E"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_R], SDL_GetKeyFromName("O"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_UP], SDL_GetKeyFromName("W"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_DOWN], SDL_GetKeyFromName("S"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_LEFT], SDL_GetKeyFromName("A"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_RIGHT], SDL_GetKeyFromName("D"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_START], SDL_GetKeyFromName("Return"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_SELECT], SDL_GetKeyFromName("Backspace"), false, false, false);

    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_RESET], SDL_GetKeyFromName("R"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_MUTE], SDL_GetKeyFromName("M"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_PAUSE], SDL_GetKeyFromName("P"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_STOP], SDL_GetKeyFromName("Q"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_SHOW_FPS], SDL_GetKeyFromName("F"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_SETTINGS], SDL_GetKeyFromName("Escape"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_FULLSCREEN], SDL_GetKeyFromName("F11"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_SCREENSHOT], SDL_GetKeyFromName("F12"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_ALT_SPEED_HOLD], SDL_GetKeyFromName("Space"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_ALT_SPEED_TOGGLE], SDL_GetKeyFromName("Space"), true, false, false);

    for (i = 0; i < MAX_QUICKSAVES && i < 10; ++i) {
        app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_QUICKSAVE_1 + i], SDL_GetKeyFromName("F1") + i, false, false, false);
        app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_QUICKLOAD_1 + i], SDL_GetKeyFromName("F1") + i, false, true, false);
    }

    app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[BIND_GBA_UP], SDL_GetKeyFromName("Up"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[BIND_GBA_DOWN], SDL_GetKeyFromName("Down"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[BIND_GBA_LEFT], SDL_GetKeyFromName("Left"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[BIND_GBA_RIGHT], SDL_GetKeyFromName("Right"), false, false, false);

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        app->binds.controller[i] = SDL_CONTROLLER_BUTTON_INVALID;
        app->binds.controller_alt[i] = SDL_CONTROLLER_BUTTON_INVALID;
    }

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
    app->binds.controller[BIND_EMULATOR_ALT_SPEED_TOGGLE] = SDL_CONTROLLER_BUTTON_RIGHTSTICK;
#if SDL_VERSION_ATLEAST(2, 0, 14)
    app->binds.controller[BIND_EMULATOR_ALT_SPEED_HOLD] = SDL_CONTROLLER_BUTTON_TOUCHPAD;
#endif

    app->binds.controller_alt[BIND_GBA_A] = SDL_CONTROLLER_BUTTON_Y;
    app->binds.controller_alt[BIND_GBA_B] = SDL_CONTROLLER_BUTTON_X;
}

/*
** Setup the content of `bind` to match when `key` is pressed with the given modifiers.
*/
void
app_bindings_keyboard_binding_build(
    struct keyboard_binding *bind,
    SDL_Keycode key,
    bool ctrl,
    bool alt,
    bool shift
) {
    bind->key = key;
    bind->ctrl = ctrl;
    bind->alt = alt;
    bind->shift = shift;
}

/*
** Return true if the two given bindings match.
*/
bool
app_bindings_keyboard_binding_match(
    struct keyboard_binding const *left,
    struct keyboard_binding const *right
) {
    return left->key == right->key
        && left->ctrl == right->ctrl
        && left->alt == right->alt
        && left->shift == right->shift
    ;
}

/*
** Return the user-printable name of the given bind.
** Eg: `Ctrl-Alt-P`.
**
** The return value should be passed to `free()`.
*/
char *
app_bindings_keyboard_binding_to_str(
    struct keyboard_binding const *bind
) {
    char const *key_name;

    key_name = SDL_GetKeyName(bind->key);

    if (!key_name) {
        return NULL;
    }

    return hs_format(
        "%s%s%s%s",
        bind->ctrl ? "Ctrl-" : "",
        bind->alt ? "Alt-" : "",
        bind->shift ? "Shift-" : "",
        key_name
    );
}

/*
** Clear any existing keyboard bindings matching the one given in argument.
*/
void
app_bindings_keyboard_binding_clear(
    struct app *app,
    struct keyboard_binding const *binding
) {
    size_t i;

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        if (app_bindings_keyboard_binding_match(&app->binds.keyboard[i], binding)) {
            app_bindings_keyboard_binding_build(&app->binds.keyboard[i], SDLK_UNKNOWN, false, false, false);
        }

        if (app_bindings_keyboard_binding_match(&app->binds.keyboard_alt[i], binding)) {
            app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[i], SDLK_UNKNOWN, false, false, false);
        }
    }
}

/*
** Clear any existing controller bindings matching the one given in argument.
*/
void
app_bindings_controller_binding_clear(
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
** Process a given binding, doing the action it represents.
*/
void
app_bindings_process(
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
        case BIND_EMULATOR_ALT_SPEED_HOLD: {
            app->emulation.use_alt_speed = pressed;
            app_emulator_settings(app);
            break;
        };
        default: break;
    }

    // The next binds are only triggered when the key is pressed, not when it is released.
    if (!pressed) {
        return;
    }

    // Bindings that can be used both in and outside of a game
    switch (bind) {
        case BIND_EMULATOR_MUTE:                app->settings.audio.mute ^= true; break;
        case BIND_EMULATOR_SHOW_FPS:            app->settings.general.show_fps ^= true; break;
        case BIND_EMULATOR_FULLSCREEN: {
            app->settings.video.display_mode = app->settings.video.display_mode == DISPLAY_MODE_WINDOWED ? DISPLAY_MODE_BORDERLESS : DISPLAY_MODE_WINDOWED;
            app_sdl_video_update_display_mode(app);
            break;
        };
        case BIND_EMULATOR_SETTINGS:            app->ui.settings.open ^= true; break;
        default:                                break;
    }

    if (!app->emulation.is_started) {
        return;
    }

    // Bindings that can only be used in game.
    switch (bind) {
        case BIND_EMULATOR_SCREENSHOT:          app_emulator_screenshot(app); break;
        case BIND_EMULATOR_PAUSE:               app->emulation.is_running ? app_emulator_pause(app) : app_emulator_run(app); break;
        case BIND_EMULATOR_STOP:                app_emulator_stop(app); break;
        case BIND_EMULATOR_RESET:               app_emulator_reset(app); break;
        case BIND_EMULATOR_ALT_SPEED_TOGGLE: {
            app->emulation.use_alt_speed ^= true;
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
