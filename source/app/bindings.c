/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE

#include <SDL3/SDL.h>
#include <cimgui.h>
#include "app/app.h"

char const * const binds_pretty_name[] = {
    [BIND_GBA_A] = "A",
    [BIND_GBA_B] = "B",
    [BIND_GBA_L] = "L",
    [BIND_GBA_R] = "R",
    [BIND_GBA_UP] = "Up",
    [BIND_GBA_DOWN] = "Down",
    [BIND_GBA_LEFT] = "Left",
    [BIND_GBA_RIGHT] = "Right",
    [BIND_GBA_START] = "Start",
    [BIND_GBA_SELECT] = "Select",

    [BIND_EMULATOR_RESET] = "Reset",
    [BIND_EMULATOR_MUTE] = "Mute",
    [BIND_EMULATOR_PAUSE] = "Pause",
    [BIND_EMULATOR_STOP] = "Stop",
    [BIND_EMULATOR_SHOW_FPS] = "Toggle FPS",
    [BIND_EMULATOR_FULLSCREEN] = "Toggle Fullscreen",
    [BIND_EMULATOR_SCREENSHOT] = "Screenshot",
    [BIND_EMULATOR_MENUBAR] = "Focus Menubar",
    [BIND_EMULATOR_SETTINGS] = "Toggle Settings",
    [BIND_EMULATOR_ALT_SPEED_TOGGLE] = "Alt. Speed (Toggle)",
    [BIND_EMULATOR_ALT_SPEED_HOLD] = "Alt. Speed (Hold)",
    [BIND_EMULATOR_QUICKSAVE_1] = "Quicksave 1",
    [BIND_EMULATOR_QUICKSAVE_2] = "Quicksave 2",
    [BIND_EMULATOR_QUICKSAVE_3] = "Quicksave 3",
    [BIND_EMULATOR_QUICKSAVE_4] = "Quicksave 4",
    [BIND_EMULATOR_QUICKSAVE_5] = "Quicksave 5",
    [BIND_EMULATOR_QUICKSAVE_6] = "Quicksave 6",
    [BIND_EMULATOR_QUICKSAVE_7] = "Quicksave 7",
    [BIND_EMULATOR_QUICKSAVE_8] = "Quicksave 8",
    [BIND_EMULATOR_QUICKSAVE_9] = "Quicksave 9",
    [BIND_EMULATOR_QUICKSAVE_10] = "Quicksave 10",
    [BIND_EMULATOR_QUICKLOAD_1] = "Quickload 1",
    [BIND_EMULATOR_QUICKLOAD_2] = "Quickload 2",
    [BIND_EMULATOR_QUICKLOAD_3] = "Quickload 3",
    [BIND_EMULATOR_QUICKLOAD_4] = "Quickload 4",
    [BIND_EMULATOR_QUICKLOAD_5] = "Quickload 5",
    [BIND_EMULATOR_QUICKLOAD_6] = "Quickload 6",
    [BIND_EMULATOR_QUICKLOAD_7] = "Quickload 7",
    [BIND_EMULATOR_QUICKLOAD_8] = "Quickload 8",
    [BIND_EMULATOR_QUICKLOAD_9] = "Quickload 9",
    [BIND_EMULATOR_QUICKLOAD_10] = "Quickload 10",
};

char const * const binds_slug[] = {
    [BIND_GBA_A] = "a",
    [BIND_GBA_B] = "b",
    [BIND_GBA_L] = "l",
    [BIND_GBA_R] = "r",
    [BIND_GBA_UP] = "up",
    [BIND_GBA_DOWN] = "down",
    [BIND_GBA_LEFT] = "left",
    [BIND_GBA_RIGHT] = "right",
    [BIND_GBA_START] = "start",
    [BIND_GBA_SELECT] = "select",

    [BIND_EMULATOR_RESET] = "reset",
    [BIND_EMULATOR_MUTE] = "mute",
    [BIND_EMULATOR_PAUSE] = "pause",
    [BIND_EMULATOR_STOP] = "stop",
    [BIND_EMULATOR_SHOW_FPS] = "toggle_show_fps",
    [BIND_EMULATOR_FULLSCREEN] = "fullscreen",
    [BIND_EMULATOR_SCREENSHOT] = "screenshot",
    [BIND_EMULATOR_MENUBAR] = "focus_menubar",
    [BIND_EMULATOR_SETTINGS] = "toggle_settings",
    [BIND_EMULATOR_ALT_SPEED_TOGGLE] = "alternative_speed_toggle",
    [BIND_EMULATOR_ALT_SPEED_HOLD] = "alternative_speed_hold",
    [BIND_EMULATOR_QUICKSAVE_1] = "quicksave_1",
    [BIND_EMULATOR_QUICKSAVE_2] = "quicksave_2",
    [BIND_EMULATOR_QUICKSAVE_3] = "quicksave_3",
    [BIND_EMULATOR_QUICKSAVE_4] = "quicksave_4",
    [BIND_EMULATOR_QUICKSAVE_5] = "quicksave_5",
    [BIND_EMULATOR_QUICKSAVE_6] = "quicksave_6",
    [BIND_EMULATOR_QUICKSAVE_7] = "quicksave_7",
    [BIND_EMULATOR_QUICKSAVE_8] = "quicksave_8",
    [BIND_EMULATOR_QUICKSAVE_9] = "quicksave_9",
    [BIND_EMULATOR_QUICKSAVE_10] = "quicksave_10",
    [BIND_EMULATOR_QUICKLOAD_1] = "quickload_1",
    [BIND_EMULATOR_QUICKLOAD_2] = "quickload_2",
    [BIND_EMULATOR_QUICKLOAD_3] = "quickload_3",
    [BIND_EMULATOR_QUICKLOAD_4] = "quickload_4",
    [BIND_EMULATOR_QUICKLOAD_5] = "quickload_5",
    [BIND_EMULATOR_QUICKLOAD_6] = "quickload_6",
    [BIND_EMULATOR_QUICKLOAD_7] = "quickload_7",
    [BIND_EMULATOR_QUICKLOAD_8] = "quickload_8",
    [BIND_EMULATOR_QUICKLOAD_9] = "quickload_9",
    [BIND_EMULATOR_QUICKLOAD_10] = "quickload_10",
};

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
** Clear any existing gamepad bindings matching the one given in argument.
*/
void
app_bindings_gamepad_binding_clear(
    struct app *app,
    SDL_GamepadButton btn
) {
    size_t i;

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        if (app->binds.gamepad[i] == btn) {
            app->binds.gamepad[i] = SDL_GAMEPAD_BUTTON_INVALID;
        }

        if (app->binds.gamepad_alt[i] == btn) {
            app->binds.gamepad_alt[i] = SDL_GAMEPAD_BUTTON_INVALID;
        }
    }
}

// Bindings that can only be used in game.
static
void
app_bindings_process_in_game_binds(
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

// Bindings that can be used both in and outside of a game
static
void
app_bindings_process_global_binds(
    struct app *app,
    enum bind_actions bind,
    bool pressed
) {
    // The next binds are only triggered when the key is pressed, not when it is released.
    if (!pressed) {
        return;
    }

    switch (bind) {
        case BIND_EMULATOR_MUTE:                app->settings.audio.mute ^= true; break;
        case BIND_EMULATOR_SHOW_FPS:            app->settings.general.show_fps ^= true; break;
        case BIND_EMULATOR_FULLSCREEN: {
            app->settings.video.display_mode = app->settings.video.display_mode == DISPLAY_MODE_WINDOW ? DISPLAY_MODE_BORDERLESS_FULLSCREEN : DISPLAY_MODE_WINDOW;
            app_sdl_video_update_display_mode(app);
            break;
        };
        default:                                break;
    }
}

// Bindings that can be used even when navigating the UI.
static
void
app_bindings_process_ui_binds(
    struct app *app,
    enum bind_actions bind,
    bool pressed
) {
    // The next binds are only triggered when the key is pressed, not when it is released.
    if (!pressed) {
        return;
    }

    switch (bind) {
        case BIND_EMULATOR_MENUBAR: {
            app->ui.menubar.force_show = true;
            app->ui.menubar.focus = true;
            app->ui.ioptr->NavActive = true;
            app->ui.ioptr->NavVisible = true;
            break;
        };
        case BIND_EMULATOR_SETTINGS: {
            app->ui.settings.open ^= true;
            app->ui.settings.focus = true;
            break;
        };
        default: break;
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
    app_bindings_process_ui_binds(app, bind, pressed);

    // Ignore the remaining bindings if the game is running and the UI is active and focused.
    // This ensures we can safely navigate the UI using the keyboard/gamepad without moving the character in the game
    // currently being played.
    if (igGetHoveredID() || igGetFocusID()) {
        return ;
    }

    app_bindings_process_global_binds(app, bind, pressed);

    if (app->emulation.is_started) {
        app_bindings_process_in_game_binds(app, bind, pressed);
    }
}
