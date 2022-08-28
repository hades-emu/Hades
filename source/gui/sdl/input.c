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
#include "gui/app.h"

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
                        HS_GLOBAL,
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
                        HS_GLOBAL,
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
            case SDL_KEYDOWN: {

                /* Ignore repeat keys */
                if (event.key.repeat) {
                    break;
                }

                switch (event.key.keysym.sym) {
                    case SDLK_UP:
                    case SDLK_w:                gba_send_keyinput(app->emulation.gba, KEY_UP, true); break;
                    case SDLK_DOWN:
                    case SDLK_s:                gba_send_keyinput(app->emulation.gba, KEY_DOWN, true); break;
                    case SDLK_LEFT:
                    case SDLK_a:                gba_send_keyinput(app->emulation.gba, KEY_LEFT, true); break;
                    case SDLK_RIGHT:
                    case SDLK_d:                gba_send_keyinput(app->emulation.gba, KEY_RIGHT, true); break;
                    case SDLK_p:                gba_send_keyinput(app->emulation.gba, KEY_A, true); break;
                    case SDLK_l:                gba_send_keyinput(app->emulation.gba, KEY_B, true); break;
                    case SDLK_e:                gba_send_keyinput(app->emulation.gba, KEY_L, true); break;
                    case SDLK_o:                gba_send_keyinput(app->emulation.gba, KEY_R, true); break;
                    case SDLK_BACKSPACE:        gba_send_keyinput(app->emulation.gba, KEY_SELECT, true); break;
                    case SDLK_RETURN:           gba_send_keyinput(app->emulation.gba, KEY_START, true); break;
                }
                break;
            };
            case SDL_KEYUP: {

                /* Ignore repeat keys */
                if (event.key.repeat) {
                    break;
                }

                switch (event.key.keysym.sym) {
                    case SDLK_UP:
                    case SDLK_w:                gba_send_keyinput(app->emulation.gba, KEY_UP, false); break;
                    case SDLK_DOWN:
                    case SDLK_s:                gba_send_keyinput(app->emulation.gba, KEY_DOWN, false); break;
                    case SDLK_LEFT:
                    case SDLK_a:                gba_send_keyinput(app->emulation.gba, KEY_LEFT, false); break;
                    case SDLK_RIGHT:
                    case SDLK_d:                gba_send_keyinput(app->emulation.gba, KEY_RIGHT, false); break;
                    case SDLK_p:                gba_send_keyinput(app->emulation.gba, KEY_A, false); break;
                    case SDLK_l:                gba_send_keyinput(app->emulation.gba, KEY_B, false); break;
                    case SDLK_e:                gba_send_keyinput(app->emulation.gba, KEY_L, false); break;
                    case SDLK_o:                gba_send_keyinput(app->emulation.gba, KEY_R, false); break;
                    case SDLK_BACKSPACE:        gba_send_keyinput(app->emulation.gba, KEY_SELECT, false); break;
                    case SDLK_RETURN:           gba_send_keyinput(app->emulation.gba, KEY_START, false); break;
                    case SDLK_F1: {
                        app->emulation.unbounded ^= 1;
                        gba_send_speed(app->emulation.gba, app->emulation.speed * !app->emulation.unbounded);
                        break;
                    };
                    case SDLK_F2:               gui_screenshot(app); break;
                    case SDLK_F5:               gba_send_quicksave(app->emulation.gba, app->file.qsave_path); break;
                    case SDLK_F8:               gba_send_quickload(app->emulation.gba, app->file.qsave_path); break;
                    default:
                        break;
                }
                break;
            };
            case SDL_CONTROLLERBUTTONDOWN: {
                switch (event.cbutton.button) {
                    case SDL_CONTROLLER_BUTTON_B:               gba_send_keyinput(app->emulation.gba, KEY_B, true); break;
                    case SDL_CONTROLLER_BUTTON_A:               gba_send_keyinput(app->emulation.gba, KEY_A, true); break;
                    case SDL_CONTROLLER_BUTTON_Y:               gba_send_keyinput(app->emulation.gba, KEY_A, true); break;
                    case SDL_CONTROLLER_BUTTON_X:               gba_send_keyinput(app->emulation.gba, KEY_B, true); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_LEFT:       gba_send_keyinput(app->emulation.gba, KEY_LEFT, true); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:      gba_send_keyinput(app->emulation.gba, KEY_RIGHT, true); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_UP:         gba_send_keyinput(app->emulation.gba, KEY_UP, true); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_DOWN:       gba_send_keyinput(app->emulation.gba, KEY_DOWN, true); break;
                    case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:    gba_send_keyinput(app->emulation.gba, KEY_L, true); break;
                    case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:   gba_send_keyinput(app->emulation.gba, KEY_R, true); break;
                    case SDL_CONTROLLER_BUTTON_START:           gba_send_keyinput(app->emulation.gba, KEY_START, true); break;
                    case SDL_CONTROLLER_BUTTON_BACK:            gba_send_keyinput(app->emulation.gba, KEY_SELECT, true); break;
                }
                break;
            };
            case SDL_CONTROLLERBUTTONUP: {
                switch (event.cbutton.button) {
                    case SDL_CONTROLLER_BUTTON_B:               gba_send_keyinput(app->emulation.gba, KEY_B, false); break;
                    case SDL_CONTROLLER_BUTTON_A:               gba_send_keyinput(app->emulation.gba, KEY_A, false); break;
                    case SDL_CONTROLLER_BUTTON_Y:               gba_send_keyinput(app->emulation.gba, KEY_A, false); break;
                    case SDL_CONTROLLER_BUTTON_X:               gba_send_keyinput(app->emulation.gba, KEY_B, false); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_LEFT:       gba_send_keyinput(app->emulation.gba, KEY_LEFT, false); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_RIGHT:      gba_send_keyinput(app->emulation.gba, KEY_RIGHT, false); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_UP:         gba_send_keyinput(app->emulation.gba, KEY_UP, false); break;
                    case SDL_CONTROLLER_BUTTON_DPAD_DOWN:       gba_send_keyinput(app->emulation.gba, KEY_DOWN, false); break;
                    case SDL_CONTROLLER_BUTTON_LEFTSHOULDER:    gba_send_keyinput(app->emulation.gba, KEY_L, false); break;
                    case SDL_CONTROLLER_BUTTON_RIGHTSHOULDER:   gba_send_keyinput(app->emulation.gba, KEY_R, false); break;
                    case SDL_CONTROLLER_BUTTON_START:           gba_send_keyinput(app->emulation.gba, KEY_START, false); break;
                    case SDL_CONTROLLER_BUTTON_BACK:            gba_send_keyinput(app->emulation.gba, KEY_SELECT, false); break;
#if SDL_VERSION_ATLEAST(2, 0, 14)
                    case SDL_CONTROLLER_BUTTON_MISC1:           gui_screenshot(app); break;
#endif
                }
                break;
            };
            case SDL_CONTROLLERAXISMOTION: {
                bool state_a;
                bool state_b;

                state_a = (event.jaxis.value >= INT16_MAX / 2);  // At least 50% of the axis
                state_b = (event.jaxis.value <= INT16_MIN / 2);
                if (event.jaxis.axis == 0 && state_a != app->sdl.controller.joystick.right) {
                    gba_send_keyinput(app->emulation.gba, KEY_RIGHT, state_a);
                    app->sdl.controller.joystick.right = state_a;
                } else if (event.jaxis.axis == 0 && state_b != app->sdl.controller.joystick.left) {
                    gba_send_keyinput(app->emulation.gba, KEY_LEFT, state_b);
                    app->sdl.controller.joystick.left = state_b;
                } else if (event.jaxis.axis == 1 && state_a != app->sdl.controller.joystick.down) {
                    gba_send_keyinput(app->emulation.gba, KEY_DOWN, state_a);
                    app->sdl.controller.joystick.down = state_a;
                } else if (event.jaxis.axis == 1 && state_b != app->sdl.controller.joystick.up) {
                    gba_send_keyinput(app->emulation.gba, KEY_UP, state_b);
                    app->sdl.controller.joystick.up = state_b;
                }
                break;
            }
        }
    }
}