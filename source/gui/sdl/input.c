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
#include "app.h"
#include "gui/gui.h"

void
gui_sdl_setup_default_binds(
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
    app->binds.keyboard[BIND_EMULATOR_SPEED_MAX_TOGGLE] = SDL_GetKeyFromName("F1");
    app->binds.keyboard[BIND_EMULATOR_SPEED_MAX_HOLD] = SDL_GetKeyFromName("Space");
    app->binds.keyboard[BIND_EMULATOR_SCREENSHOT] = SDL_GetKeyFromName("F2");
    app->binds.keyboard[BIND_EMULATOR_QUICKSAVE] = SDL_GetKeyFromName("F5");
    app->binds.keyboard[BIND_EMULATOR_QUICKLOAD] = SDL_GetKeyFromName("F8");

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
    app->binds.controller[BIND_EMULATOR_SPEED_MAX_TOGGLE] = SDL_CONTROLLER_BUTTON_TOUCHPAD;
#endif

    app->binds.controller_alt[BIND_GBA_A] = SDL_CONTROLLER_BUTTON_Y;
    app->binds.controller_alt[BIND_GBA_B] = SDL_CONTROLLER_BUTTON_X;
}

/*
** Clear any existing keybindings matching the given key.
*/
static
void
gui_sdl_bind_keyboard_clear(
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
** Clear any existing keybindings matching the given key.
*/
static
void
gui_sdl_bind_controller_clear(
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

static
void
gui_sdl_handle_bind(
    struct app *app,
    enum bind_actions bind,
    bool pressed
) {
    switch (bind) {
        case BIND_GBA_UP:                       gba_send_keyinput(app->emulation.gba, KEY_UP, pressed); break;
        case BIND_GBA_DOWN:                     gba_send_keyinput(app->emulation.gba, KEY_DOWN, pressed); break;
        case BIND_GBA_LEFT:                     gba_send_keyinput(app->emulation.gba, KEY_LEFT, pressed); break;
        case BIND_GBA_RIGHT:                    gba_send_keyinput(app->emulation.gba, KEY_RIGHT, pressed); break;
        case BIND_GBA_A:                        gba_send_keyinput(app->emulation.gba, KEY_A, pressed); break;
        case BIND_GBA_B:                        gba_send_keyinput(app->emulation.gba, KEY_B, pressed); break;
        case BIND_GBA_L:                        gba_send_keyinput(app->emulation.gba, KEY_L, pressed); break;
        case BIND_GBA_R:                        gba_send_keyinput(app->emulation.gba, KEY_R, pressed); break;
        case BIND_GBA_SELECT:                   gba_send_keyinput(app->emulation.gba, KEY_SELECT, pressed); break;
        case BIND_GBA_START:                    gba_send_keyinput(app->emulation.gba, KEY_START, pressed); break;
        case BIND_EMULATOR_SPEED_MAX_HOLD: {
            app->emulation.unbounded = pressed;
            gba_send_speed(app->emulation.gba, app->emulation.speed * !app->emulation.unbounded);
            break;
        };
        default: break;
    }

    /* The next binds are only triggered when the key is pressed, not when it is released. */
    if (!pressed) {
        return ;
    }

    switch (bind) {
        case BIND_EMULATOR_SPEED_X1:
        case BIND_EMULATOR_SPEED_X2:
        case BIND_EMULATOR_SPEED_X3:
        case BIND_EMULATOR_SPEED_X4:
        case BIND_EMULATOR_SPEED_X5: {
            app->emulation.unbounded = false;
            app->emulation.speed = 1 + (bind - BIND_EMULATOR_SPEED_X1);
            gba_send_speed(app->emulation.gba, app->emulation.speed);
            break;
        };
        case BIND_EMULATOR_SPEED_MAX_TOGGLE: {
            app->emulation.unbounded ^= true;
            gba_send_speed(app->emulation.gba, app->emulation.speed * !app->emulation.unbounded);
            break;
        };
        case BIND_EMULATOR_SCREENSHOT:          app_game_screenshot(app); break;
        case BIND_EMULATOR_QUICKSAVE:           app_game_quicksave(app, 0); break;
        case BIND_EMULATOR_QUICKLOAD:           app_game_quickload(app, 0); break;
        default: break;
    }
}

void
gui_sdl_handle_inputs(
    struct app *app
) {
    SDL_Event event;

    /* Handle all SDL events */
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
                            gui_sdl_bind_keyboard_clear(app, event.key.keysym.sym);
                            *app->ui.keybindings_editor.keyboard_target = event.key.keysym.sym;
                            app->ui.keybindings_editor.keyboard_target = NULL;
                        }
                    }
                    break ;
                }

                for (i = BIND_MIN; i < BIND_MAX; ++i) {
                    // Normal binds
                    if (app->binds.keyboard[i] == event.key.keysym.sym) {
                        gui_sdl_handle_bind(app, i, event.type == SDL_KEYDOWN);
                    }

                    // Alternative binds
                    if (app->binds.keyboard_alt[i] == event.key.keysym.sym) {
                        gui_sdl_handle_bind(app, i, event.type == SDL_KEYDOWN);
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
                        gui_sdl_bind_controller_clear(app, event.cbutton.button);
                        *app->ui.keybindings_editor.controller_target = event.cbutton.button;
                        app->ui.keybindings_editor.controller_target = NULL;
                    }
                    break ;
                }

                for (i = BIND_MIN; i < BIND_MAX; ++i) {
                    // Normal binds
                    if (app->binds.controller[i] == event.cbutton.button) {
                        gui_sdl_handle_bind(app, i, event.type == SDL_CONTROLLERBUTTONDOWN);
                    }

                    // Alternative binds
                    if (app->binds.controller_alt[i] == event.cbutton.button) {
                        gui_sdl_handle_bind(app, i, event.type == SDL_CONTROLLERBUTTONDOWN);
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
                    gui_sdl_handle_bind(app, BIND_GBA_RIGHT, state_a);
                } else if (event.jaxis.axis == 0 && state_b != app->sdl.controller.joystick.left) {
                    app->sdl.controller.joystick.left = state_b;
                    gui_sdl_handle_bind(app, BIND_GBA_LEFT, state_b);
                } else if (event.jaxis.axis == 1 && state_a != app->sdl.controller.joystick.down) {
                    app->sdl.controller.joystick.down = state_a;
                    gui_sdl_handle_bind(app, BIND_GBA_DOWN, state_a);
                } else if (event.jaxis.axis == 1 && state_b != app->sdl.controller.joystick.up) {
                    app->sdl.controller.joystick.up = state_b;
                    gui_sdl_handle_bind(app, BIND_GBA_UP, state_b);
                }
                break;
            }
        }
    }
}
