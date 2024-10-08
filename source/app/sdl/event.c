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
#include "SDL_keycode.h"
#include "hades.h"
#include "app/app.h"

/*
** Handle all SDL events.
*/
void
app_sdl_handle_events(
    struct app *app
) {
    SDL_Event event;

    while (SDL_PollEvent(&event) != 0) {
        ImGui_ImplSDL2_ProcessEvent(&event);

        switch (event.type) {
            case SDL_QUIT: {
                app->run = false;
                break;
            };
            case SDL_WINDOWEVENT: {
                /* Keep only events related to our current window. */
                if (event.window.windowID != SDL_GetWindowID(app->sdl.window)) {
                    break;
                }

                switch (event.window.event) {
                    case SDL_WINDOWEVENT_CLOSE: {
                        app->run = false;
                        break;
                    };
                    case SDL_WINDOWEVENT_MAXIMIZED: {
                        app->ui.win.maximized = true;
                        break;
                    };
                    case SDL_WINDOWEVENT_RESTORED: {
                        app->ui.win.maximized = false;
                        break;
                    };
                    case SDL_WINDOWEVENT_SIZE_CHANGED: {
                        app->ui.win.old_area = app->ui.win.width * app->ui.win.height;
                        app->ui.win.width = event.window.data1;
                        app->ui.win.height = event.window.data2;
                        app->ui.game.width = app->ui.win.width;
                        app->ui.game.height = app->ui.win.height - app->ui.menubar_size.y;
                        break;
                    };
                    case SDL_WINDOWEVENT_RESIZED: {
                        /*
                        ** The "auto-resize the window to keep the aspect ration" feature conflicts with the "maximized window" feature of modern
                        ** exploitation systems.
                        **
                        ** In that case, we do not auto-resize the window and display black borders instead.
                        */
                        if (app->settings.video.aspect_ratio == ASPECT_RATIO_RESIZE && !app->ui.win.maximized) {
                            app->ui.win.resize = true;
                            app->ui.win.resize_with_ratio = true;

                            if (app->ui.win.width * app->ui.win.height >= app->ui.win.old_area) { // The window was made bigger
                                app->ui.win.resize_ratio = max(app->ui.game.width / ((float)GBA_SCREEN_WIDTH * app->ui.scale), app->ui.game.height / ((float)GBA_SCREEN_HEIGHT * app->ui.scale));
                            } else {
                                app->ui.win.resize_ratio = min(app->ui.game.width / ((float)GBA_SCREEN_WIDTH * app->ui.scale), app->ui.game.height / ((float)GBA_SCREEN_HEIGHT * app->ui.scale));
                            }
                        }
                        break;
                    };
                    case SDL_WINDOWEVENT_FOCUS_GAINED: {
                        if (app->settings.misc.pause_when_window_inactive && app->emulation.is_started && !app->emulation.is_running) {
                            app_emulator_run(app);
                        }
                        break;
                    };
                    case SDL_WINDOWEVENT_FOCUS_LOST: {
                        if (app->settings.misc.pause_when_window_inactive && app->emulation.is_started && app->emulation.is_running) {
                            app_emulator_pause(app);
                        }
                        break;
                    };
                }
                break;
            };
            case SDL_CONTROLLERDEVICEADDED: {
                if (!app->sdl.controller.connected) {
                    app->sdl.controller.ptr = SDL_GameControllerOpen(event.cdevice.which);
                    app->sdl.controller.joystick.ptr = SDL_GameControllerGetJoystick(app->sdl.controller.ptr);
                    app->sdl.controller.joystick.idx = SDL_JoystickInstanceID(app->sdl.controller.joystick.ptr);
#if SDL_VERSION_ATLEAST(2, 0, 18)
                    app->sdl.controller.joystick.can_rumble = SDL_JoystickHasRumble(app->sdl.controller.joystick.ptr);
#else
                    app->sdl.controller.joystick.can_rumble = true;
#endif
                    app->sdl.controller.connected = true;
                    logln(
                        HS_INFO,
                        "Controller \"%s%s%s\" connected.",
                        g_light_magenta,
                        SDL_GameControllerName(app->sdl.controller.ptr),
                        g_reset
                    );

                    // Disable any active rumble
                    app_sdl_set_rumble(app, false);
                }
                break;
            };
            case SDL_CONTROLLERDEVICEREMOVED: {
                if (event.cdevice.which >= 0 && event.cdevice.which == app->sdl.controller.joystick.idx) {
                    logln(
                        HS_INFO,
                        "Controller \"%s%s%s\" disconnected.",
                        g_light_magenta,
                        SDL_GameControllerName(app->sdl.controller.ptr),
                        g_reset
                    );
                    SDL_GameControllerClose(app->sdl.controller.ptr);
                    app->sdl.controller.ptr = NULL;
                    app->sdl.controller.joystick.idx = -1;
                    app->sdl.controller.connected = false;
                }
                break;
            };
            case SDL_KEYDOWN:
            case SDL_KEYUP: {
                struct keyboard_binding bind;
                size_t i;

                // Ignore repeat keys
                if (event.key.repeat) {
                    break;
                }

                if (
                       event.key.keysym.sym == SDLK_LCTRL
                    || event.key.keysym.sym == SDLK_RCTRL
                    || event.key.keysym.sym == SDLK_LALT
                    || event.key.keysym.sym == SDLK_RALT
                    || event.key.keysym.sym == SDLK_LSHIFT
                    || event.key.keysym.sym == SDLK_RSHIFT
                ) {
                    break;
                }

                bind.key = event.key.keysym.sym;
                bind.ctrl = event.key.keysym.mod & KMOD_CTRL;
                bind.alt = event.key.keysym.mod & KMOD_ALT;
                bind.shift = event.key.keysym.mod & KMOD_SHIFT;

                /*
                ** Ignore keys if the settings are open except the special case where we are creating new bindings.
                */
                if (app->ui.settings.open) {
                    if (event.type == SDL_KEYDOWN) {
                        // The `Escape` key is used to clear a bind.
                        if (event.key.keysym.sym == SDLK_ESCAPE) {
                            if (app->ui.settings.keybindings_editor.keyboard_target) {
                                app->ui.settings.keybindings_editor.keyboard_target->key = SDLK_UNKNOWN;
                                app->ui.settings.keybindings_editor.keyboard_target->ctrl = false;
                                app->ui.settings.keybindings_editor.keyboard_target->alt = false;
                                app->ui.settings.keybindings_editor.keyboard_target->shift = false;
                                app->ui.settings.keybindings_editor.keyboard_target = NULL;
                            } else if (app->ui.settings.keybindings_editor.controller_target) {
                                *app->ui.settings.keybindings_editor.controller_target = SDL_CONTROLLER_BUTTON_INVALID;
                                app->ui.settings.keybindings_editor.controller_target = NULL;
                            } else {
                                app->ui.settings.open = false;
                            }
                        } else if (app->ui.settings.keybindings_editor.keyboard_target) {
                            app_bindings_keyboard_binding_clear(app, &bind);
                            *app->ui.settings.keybindings_editor.keyboard_target = bind;
                            app->ui.settings.keybindings_editor.keyboard_target = NULL;
                        }
                    }
                    break ;
                }

                for (i = BIND_MIN; i < BIND_MAX; ++i) {
                    // Normal binds
                    if (app_bindings_keyboard_binding_match(&app->binds.keyboard[i], &bind)) {
                        app_bindings_handle(app, i, event.type == SDL_KEYDOWN);
                    }

                    // Alternative binds
                    if (app_bindings_keyboard_binding_match(&app->binds.keyboard_alt[i], &bind)) {
                        app_bindings_handle(app, i, event.type == SDL_KEYDOWN);
                    }
                }

                break;
            };
            case SDL_CONTROLLERBUTTONUP:
            case SDL_CONTROLLERBUTTONDOWN: {
                size_t i;

                /*
                ** Ignore buttons if the settings are open except the special case where we are creating new bindings.
                */
                if (app->ui.settings.open) {
                    if (event.type == SDL_CONTROLLERBUTTONDOWN && app->ui.settings.keybindings_editor.controller_target) {
                        app_bindings_controller_binding_clear(app, event.cbutton.button);
                        *app->ui.settings.keybindings_editor.controller_target = event.cbutton.button;
                        app->ui.settings.keybindings_editor.controller_target = NULL;
                    }
                    break ;
                }

                for (i = BIND_MIN; i < BIND_MAX; ++i) {
                    // Normal binds
                    if (app->binds.controller[i] == event.cbutton.button) {
                        app_bindings_handle(app, i, event.type == SDL_CONTROLLERBUTTONDOWN);
                    }

                    // Alternative binds
                    if (app->binds.controller_alt[i] == event.cbutton.button) {
                        app_bindings_handle(app, i, event.type == SDL_CONTROLLERBUTTONDOWN);
                    }
                }
                break;
            };
            case SDL_CONTROLLERAXISMOTION: {
                bool state_a;
                bool state_b;

                /* Disable the joysticks if the settings are open */
                if (app->ui.settings.open) {
                    break;
                }

                state_a = (event.jaxis.value >= INT16_MAX / 2);  // At least 50% of the axis
                state_b = (event.jaxis.value <= INT16_MIN / 2);
                if (event.jaxis.axis == 0 && state_a != app->sdl.controller.joystick.right) {
                    app->sdl.controller.joystick.right = state_a;
                    app_bindings_handle(app, BIND_GBA_RIGHT, state_a);
                } else if (event.jaxis.axis == 0 && state_b != app->sdl.controller.joystick.left) {
                    app->sdl.controller.joystick.left = state_b;
                    app_bindings_handle(app, BIND_GBA_LEFT, state_b);
                } else if (event.jaxis.axis == 1 && state_a != app->sdl.controller.joystick.down) {
                    app->sdl.controller.joystick.down = state_a;
                    app_bindings_handle(app, BIND_GBA_DOWN, state_a);
                } else if (event.jaxis.axis == 1 && state_b != app->sdl.controller.joystick.up) {
                    app->sdl.controller.joystick.up = state_b;
                    app_bindings_handle(app, BIND_GBA_UP, state_b);
                }
                break;
            }
            case SDL_MOUSEMOTION: {
                // Handle the "hide cursor on mouse inactivity" option by
                // resetting the "time_elapsed_since_last_mouse_motion_ms" counter.
                // The main loop will then update the cursor's visibility if needed.
                app->ui.time_elapsed_since_last_mouse_motion_ms = 0.f;
            }
        }
    }
}

void
app_sdl_set_rumble(
    struct app *app,
    bool enable
) {
    if (!app->sdl.controller.ptr || !app->sdl.controller.joystick.ptr || !app->sdl.controller.joystick.can_rumble) {
        return ;
    }

    // Rumble for 0.25s
    if (enable) {
        SDL_JoystickRumble(app->sdl.controller.joystick.ptr, 0xFFFF, 0xFFFF, 250);
    } else {
        SDL_JoystickRumble(app->sdl.controller.joystick.ptr, 0, 0, 0);
    }
}
