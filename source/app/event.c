/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <SDL3/SDL.h>
#include <cimgui.h>
#include <cimgui_impl.h>
#include <math.h>

#include "hades.h"
#include "app/app.h"

/*
** Handle all SDL events.
*/
void
app_sdl_handle_events(
    struct app *app,
    SDL_Event *event
) {
    ImGui_ImplSDL3_ProcessEvent(event);

    switch (event->type) {
        case SDL_EVENT_QUIT: {
            app->run = false;
            break;
        };
        case SDL_EVENT_WINDOW_DISPLAY_SCALE_CHANGED: {
            app_sdl_video_update_scale(app);
            logln(
                HS_INFO,
                "Window Display Scale and Pixel Density changed to %s%.2f%s, %s%.2f%s.",
                g_light_magenta,
                app->ui.window_display_scale,
                g_reset,
                g_light_magenta,
                app->ui.window_pixel_density,
                g_reset
            );
            break;
        };
        case SDL_EVENT_WINDOW_CLOSE_REQUESTED: {
            app->run = false;
            break;
        };
        case SDL_EVENT_WINDOW_RESIZED: {
            app->ui.display.win.width = event->window.data1;
            app->ui.display.win.height = event->window.data2;
            app_win_game_refresh_game_area(app);
            break;
        };
        case SDL_EVENT_WINDOW_FOCUS_GAINED: {
            // If desired, continue the game when the window gains focus
            if (app->settings.general.window.pause_game_when_window_loses_focus && app->emulation.is_started && !app->emulation.is_running) {
                app_emulator_run(app);
            }
            // Reset the visibility of the menu bar
            app->ui.menubar.force_show = true;
            break;
        };
        case SDL_EVENT_WINDOW_FOCUS_LOST: {
            // If desired, pause the game when the window loses focus
            if (app->settings.general.window.pause_game_when_window_loses_focus && app->emulation.is_started && app->emulation.is_running) {
                app_emulator_pause(app);
            }
            // Hide the menu bar
            app->ui.menubar.force_hide = true;
            break;
        };
        case SDL_EVENT_GAMEPAD_ADDED: {
            if (!app->sdl.gamepad.connected) {
                SDL_PropertiesID gamepad_properties;

                app->sdl.gamepad.ptr = SDL_OpenGamepad(event->gdevice.which);
                gamepad_properties = SDL_GetGamepadProperties(app->sdl.gamepad.ptr);
                app->sdl.gamepad.can_rumble = SDL_GetBooleanProperty(gamepad_properties, SDL_PROP_GAMEPAD_CAP_RUMBLE_BOOLEAN, false);
                app->sdl.gamepad.joystick.ptr = SDL_GetGamepadJoystick(app->sdl.gamepad.ptr);
                app->sdl.gamepad.joystick.idx = SDL_GetJoystickID(app->sdl.gamepad.joystick.ptr);
                app->sdl.gamepad.connected = true;
                logln(
                    HS_INFO,
                    "Gamepad \"%s%s%s\" connected.",
                    g_light_magenta,
                    SDL_GetGamepadName(app->sdl.gamepad.ptr),
                    g_reset
                );

                // Disable any active rumble
                app_sdl_set_rumble(app, false);
            }
            break;
        };
        case SDL_EVENT_GAMEPAD_REMOVED: {
            if (event->gdevice.which == app->sdl.gamepad.joystick.idx) {
                logln(
                    HS_INFO,
                    "Gamepad \"%s%s%s\" disconnected.",
                    g_light_magenta,
                    SDL_GetGamepadName(app->sdl.gamepad.ptr),
                    g_reset
                );
                SDL_CloseGamepad(app->sdl.gamepad.ptr);
                app->sdl.gamepad.ptr = NULL;
                app->sdl.gamepad.can_rumble = false;
                app->sdl.gamepad.joystick.ptr = NULL;
                app->sdl.gamepad.joystick.idx = -1;
                app->sdl.gamepad.connected = false;
            }
            break;
        };
        case SDL_EVENT_KEY_DOWN:
        case SDL_EVENT_KEY_UP: {
            struct keyboard_binding bind;
            bool is_ctrl_mod_key;
            bool is_alt_mod_key;
            bool is_shift_mod_key;
            bool is_mod_key;
            size_t i;

            // Ignore repeat keys
            if (event->key.repeat) {
                break;
            }

            // Suspend power save mode on keyboard events
            app->ui.power_save_fcounter = POWER_SAVE_FRAME_DELAY;

            is_ctrl_mod_key = (event->key.key == SDLK_LCTRL) || (event->key.key == SDLK_RCTRL);
            is_alt_mod_key = (event->key.key == SDLK_LALT) || (event->key.key == SDLK_RALT);
            is_shift_mod_key = (event->key.key == SDLK_LSHIFT) || (event->key.key == SDLK_RSHIFT);
            is_mod_key = is_ctrl_mod_key || is_alt_mod_key || is_shift_mod_key;

            bind.key = event->key.key;
            bind.ctrl = (event->key.mod & SDL_KMOD_CTRL) && !is_ctrl_mod_key;
            bind.alt = (event->key.mod & SDL_KMOD_ALT) && !is_alt_mod_key;
            bind.shift = (event->key.mod & SDL_KMOD_SHIFT) && !is_shift_mod_key;

            // Ignore keys if the settings are open except the special case where we are creating new bindings.
            if (app->ui.settings.open) {
                // The `Escape` key is used to either close the settings menu or to clear a bind.
                if (event->type == SDL_EVENT_KEY_DOWN && event->key.key == SDLK_ESCAPE) {
                    if (app->ui.settings.keybindings_editor.keyboard_target) {
                        app->ui.settings.keybindings_editor.keyboard_target->key = SDLK_UNKNOWN;
                        app->ui.settings.keybindings_editor.keyboard_target->ctrl = false;
                        app->ui.settings.keybindings_editor.keyboard_target->alt = false;
                        app->ui.settings.keybindings_editor.keyboard_target->shift = false;
                        app->ui.settings.keybindings_editor.keyboard_target = NULL;
                    } else if (app->ui.settings.keybindings_editor.gamepad_target) {
                        *app->ui.settings.keybindings_editor.gamepad_target = SDL_GAMEPAD_BUTTON_INVALID;
                        app->ui.settings.keybindings_editor.gamepad_target = NULL;
                    } else {
                        app->ui.settings.open = false;
                    }
                } else if (app->ui.settings.keybindings_editor.keyboard_target && ((event->type == SDL_EVENT_KEY_DOWN && !is_mod_key) || (event->type == SDL_EVENT_KEY_UP && is_mod_key))) {
                    app_bindings_keyboard_binding_clear(app, &bind);
                    *app->ui.settings.keybindings_editor.keyboard_target = bind;
                    app->ui.settings.keybindings_editor.keyboard_target = NULL;
                }
                break;
            }

            // Ignore keys if the game is running and the UI is active and focused.
            // This ensures we can safely navigate the UI using the keyboard without moving the character in the game
            // currently being played.
            if (app->emulation.is_started && (igGetHoveredID() || igGetFocusID())) {
                break;
            }

            for (i = BIND_MIN; i < BIND_MAX; ++i) {
                // Normal binds
                if (app_bindings_keyboard_binding_match(&app->binds.keyboard[i], &bind)) {
                    app_bindings_process(app, i, event->type == SDL_EVENT_KEY_DOWN);
                }

                // Alternative binds
                if (app_bindings_keyboard_binding_match(&app->binds.keyboard_alt[i], &bind)) {
                    app_bindings_process(app, i, event->type == SDL_EVENT_KEY_DOWN);
                }
            }

            break;
        };
        case SDL_EVENT_GAMEPAD_BUTTON_UP:
        case SDL_EVENT_GAMEPAD_BUTTON_DOWN: {
            size_t i;

            // Suspend power save mode on gamepad button events
            app->ui.power_save_fcounter = POWER_SAVE_FRAME_DELAY;

            // Disable gamepad buttons if the settings are open except the special case where we are creating new bindings.
            if (app->ui.settings.open) {
                if (event->type == SDL_EVENT_GAMEPAD_BUTTON_DOWN && app->ui.settings.keybindings_editor.gamepad_target) {
                    app_bindings_gamepad_binding_clear(app, event->gbutton.button);
                    *app->ui.settings.keybindings_editor.gamepad_target = event->gbutton.button;
                    app->ui.settings.keybindings_editor.gamepad_target = NULL;
                }
                break;
            }

            // Ignore gamepad if the game is running and the UI is active and focused.
            // This ensures we can safely navigate the UI using the gamepad without moving the character in the game
            // currently being played.
            if (app->emulation.is_started && (igGetHoveredID() || igGetFocusID())) {
                break;
            }

            for (i = BIND_MIN; i < BIND_MAX; ++i) {
                // Normal binds
                if (app->binds.gamepad[i] == event->gbutton.button) {
                    app_bindings_process(app, i, event->type == SDL_EVENT_GAMEPAD_BUTTON_DOWN);
                }

                // Alternative binds
                if (app->binds.gamepad_alt[i] == event->gbutton.button) {
                    app_bindings_process(app, i, event->type == SDL_EVENT_GAMEPAD_BUTTON_DOWN);
                }
            }
            break;
        };
        case SDL_EVENT_GAMEPAD_AXIS_MOTION: {
            bool state_a;
            bool state_b;

            // Disable the joysticks if the settings are open
            // We do this to be consistent with keyboard events and prevent interactions with the game when
            // the settings are open.
            if (app->ui.settings.open) {
                break;
            }

            state_a = (event->jaxis.value >= INT16_MAX / 2);  // At least 50% of the axis
            state_b = (event->jaxis.value <= INT16_MIN / 2);
            if (event->jaxis.axis == 0 && state_a != app->sdl.gamepad.joystick.right) {
                app->sdl.gamepad.joystick.right = state_a;
                app_bindings_process(app, BIND_GBA_RIGHT, state_a);
            } else if (event->jaxis.axis == 0 && state_b != app->sdl.gamepad.joystick.left) {
                app->sdl.gamepad.joystick.left = state_b;
                app_bindings_process(app, BIND_GBA_LEFT, state_b);
            } else if (event->jaxis.axis == 1 && state_a != app->sdl.gamepad.joystick.down) {
                app->sdl.gamepad.joystick.down = state_a;
                app_bindings_process(app, BIND_GBA_DOWN, state_a);
            } else if (event->jaxis.axis == 1 && state_b != app->sdl.gamepad.joystick.up) {
                app->sdl.gamepad.joystick.up = state_b;
                app_bindings_process(app, BIND_GBA_UP, state_b);
            }
            break;
        }
        case SDL_EVENT_MOUSE_MOTION: {
            // Handle the "hide cursor on mouse inactivity" option by
            // resetting the "time_elapsed_since_last_mouse_motion_ms" counter.
            // The main loop will then update the cursor's visibility if needed.
            app->ui.time_elapsed_since_last_mouse_motion_ms = 0.f;

            // Suspend power save mode on mouse motion
            app->ui.power_save_fcounter = POWER_SAVE_FRAME_DELAY;
            break;
        }
        case SDL_EVENT_MOUSE_WHEEL: {
            // Suspend power save mode on mouse wheel
            app->ui.power_save_fcounter = POWER_SAVE_FRAME_DELAY;
            break;
        };
    }
}

void
app_sdl_set_rumble(
    struct app const *app,
    bool enable
) {
    if (!app->sdl.gamepad.ptr || !app->sdl.gamepad.can_rumble) {
        return;
    }

    // Rumble for 0.25s
    if (enable) {
        SDL_RumbleGamepad(app->sdl.gamepad.ptr, 0xFFFF, 0xFFFF, 250);
    } else {
        SDL_RumbleGamepad(app->sdl.gamepad.ptr, 0, 0, 0);
    }
}
