/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <SDL2/SDL.h>
#include <cimgui.h>
#include <cimgui_impl.h>
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
                        if (app->video.aspect_ratio == ASPECT_RATIO_RESIZE && !app->ui.win.maximized) {
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
                }
                break;
            };
            case SDL_CONTROLLERDEVICEADDED: {
                if (!app->sdl.controller.connected) {
                    SDL_Joystick *joystick;

                    app->sdl.controller.ptr = SDL_GameControllerOpen(event.cdevice.which);
                    joystick = SDL_GameControllerGetJoystick(app->sdl.controller.ptr);
                    app->sdl.controller.joystick.idx = SDL_JoystickInstanceID(joystick);
                    app->sdl.controller.connected = true;
                    logln(
                        HS_INFO,
                        "Controller \"%s%s%s\" connected.",
                        g_light_magenta,
                        SDL_GameControllerName(app->sdl.controller.ptr),
                        g_reset
                    );
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
                size_t i;

                /* Ignore repeat keys */
                if (event.key.repeat) {
                    break;
                }

                /* Handle the special case where we are creating new keybindings. */
                if (app->ui.keybindings_editor.visible) {
                    if (event.type == SDL_KEYDOWN) {
                        // The `Escape` key is used to clear a bind.
                        if (event.key.keysym.sym == SDLK_ESCAPE) {
                            if (app->ui.keybindings_editor.keyboard_target) {
                                *app->ui.keybindings_editor.keyboard_target = SDLK_UNKNOWN;
                                app->ui.keybindings_editor.keyboard_target = NULL;
                            }
                            if (app->ui.keybindings_editor.controller_target) {
                                *app->ui.keybindings_editor.controller_target = SDL_CONTROLLER_BUTTON_INVALID;
                                app->ui.keybindings_editor.controller_target = NULL;
                            }
                        } else if (app->ui.keybindings_editor.keyboard_target) {
                            app_bindings_keyboard_clear(app, event.key.keysym.sym);
                            *app->ui.keybindings_editor.keyboard_target = event.key.keysym.sym;
                            app->ui.keybindings_editor.keyboard_target = NULL;
                        }
                    }
                    break ;
                }

                for (i = BIND_MIN; i < BIND_MAX; ++i) {
                    // Normal binds
                    if (app->binds.keyboard[i] == event.key.keysym.sym) {
                        app_bindings_handle(app, i, event.type == SDL_KEYDOWN);
                    }

                    // Alternative binds
                    if (app->binds.keyboard_alt[i] == event.key.keysym.sym) {
                        app_bindings_handle(app, i, event.type == SDL_KEYDOWN);
                    }
                }

                break;
            };
            case SDL_CONTROLLERBUTTONUP:
            case SDL_CONTROLLERBUTTONDOWN: {
                size_t i;

                /* Handle the special case where we are creating new keybindings. */
                if (app->ui.keybindings_editor.visible) {
                    if (event.type == SDL_CONTROLLERBUTTONDOWN && app->ui.keybindings_editor.controller_target) {
                        app_bindings_controller_clear(app, event.cbutton.button);
                        *app->ui.keybindings_editor.controller_target = event.cbutton.button;
                        app->ui.keybindings_editor.controller_target = NULL;
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

                /* Disable the joysticks if the keybindings editor is visible */
                if (app->ui.keybindings_editor.visible) {
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
        }
    }
}
