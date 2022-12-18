/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
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
    app->binds.keyboard[BIND_EMULATOR_UNBOUNDED_SPEED] = SDL_GetKeyFromName("F1");
    app->binds.keyboard[BIND_EMULATOR_SCREENSHOT] = SDL_GetKeyFromName("F2");
    app->binds.keyboard[BIND_EMULATOR_QUICKSAVE] = SDL_GetKeyFromName("F5");
    app->binds.keyboard[BIND_EMULATOR_QUICKLOAD] = SDL_GetKeyFromName("F8");

    app->binds.controller[SDL_CONTROLLER_BUTTON_A] = BIND_GBA_A;
    app->binds.controller[SDL_CONTROLLER_BUTTON_B] = BIND_GBA_B;
    app->binds.controller[SDL_CONTROLLER_BUTTON_X] = BIND_GBA_B;
    app->binds.controller[SDL_CONTROLLER_BUTTON_Y] = BIND_GBA_A;
    app->binds.controller[SDL_CONTROLLER_BUTTON_LEFTSHOULDER] = BIND_GBA_L;
    app->binds.controller[SDL_CONTROLLER_BUTTON_RIGHTSHOULDER] = BIND_GBA_R;
    app->binds.controller[SDL_CONTROLLER_BUTTON_DPAD_UP] = BIND_GBA_UP;
    app->binds.controller[SDL_CONTROLLER_BUTTON_DPAD_DOWN] = BIND_GBA_DOWN;
    app->binds.controller[SDL_CONTROLLER_BUTTON_DPAD_LEFT] = BIND_GBA_LEFT;
    app->binds.controller[SDL_CONTROLLER_BUTTON_DPAD_RIGHT] = BIND_GBA_RIGHT;
    app->binds.controller[SDL_CONTROLLER_BUTTON_START] = BIND_GBA_START;
    app->binds.controller[SDL_CONTROLLER_BUTTON_BACK] = BIND_GBA_SELECT;
#if SDL_VERSION_ATLEAST(2, 0, 14)
    app->binds.controller[SDL_CONTROLLER_BUTTON_TOUCHPAD] = BIND_EMULATOR_UNBOUNDED_SPEED;
#endif
    printf("INPUT PRE-SET\n");
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
        default: break;
    }

    /* The next binds are only triggered when the key is pressed, not when it is released. */
    if (!pressed) {
        return ;
    }

    switch (bind) {
        case BIND_EMULATOR_UNBOUNDED_SPEED: {
            app->emulation.unbounded ^= 1;
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
                if (event.window.event == SDL_WINDOWEVENT_CLOSE
                    && event.window.windowID == SDL_GetWindowID(app->sdl.window)
                ) {
                    app->run = false;
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

                for (i = BIND_MIN; i < BIND_MAX; ++i) {
                    if (app->binds.keyboard[i] == event.key.keysym.sym) {
                        gui_sdl_handle_bind(app, i, event.type == SDL_KEYDOWN);
                    }
                }

                break;
            };
            case SDL_CONTROLLERBUTTONUP:
            case SDL_CONTROLLERBUTTONDOWN: {
                gui_sdl_handle_bind(app, app->binds.controller[event.cbutton.button], event.type == SDL_CONTROLLERBUTTONDOWN);
                break;
            };
            case SDL_CONTROLLERAXISMOTION: {
                bool state_a;
                bool state_b;

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
