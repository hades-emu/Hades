/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <cimgui.h>
#include <stdio.h>
#include "hades.h"
#include "gba/gba.h"
#include "platform/gui.h"

void
gui_main_menu_bar(
    struct app *app
) {
    ImVec2 menubar_size;

    if (igBeginMainMenuBar()) {

        /* File */
        if (igBeginMenu("File", true)) {
            if (igMenuItemBool("Open", "Ctrl+O", false, false)) {
            }

            if (igBeginMenu("Open Recent", false)) {
                uint32_t x;

                for (x = 0; x < 5; ++x) {
                    if (igMenuItemBool("xxx", NULL, false, true)) {

                    }
                }
                igEndMenu();
            }

            igSeparator();

            igMenuItemBool("Key Bindings", NULL, false, false);
            igEndMenu();
        }

        /* Emulation */
        if (igBeginMenu("Emulation", true)) {

            /* Color Correction */
            igMenuItemBool("Color correction", NULL, false, false);
            igSeparator();

            /* Save & backups */
            igMenuItemBool("Quick Save", "F5", false, false);
            igMenuItemBool("Quick Load", "F8", false, false);
            igMenuItemBool("Backup type", NULL, false, false);
            igSeparator();

            /* Pause */
            igMenuItemBoolPtr("Pause", NULL, &app->emulation.pause, app->emulation.enabled);

            /* Speed */
            if (igBeginMenu("Speed", false)) {
                uint32_t x;
                char const *speed[] = {
                    "Unbounded",
                    "x1",
                    "x2",
                    "x3",
                    "x4",
                    "x5"
                };

                for (x = 0; x <= 5; ++x) {
                    if (igMenuItemBool(speed[x], NULL, app->emulation.speed == x, false)) {
                        app->emulation.speed = x;
                    }

                    if (!x) {
                        igSeparator();
                    }
                }

                igEndMenu();
            }

            /* Display Size */
            if (igBeginMenu("Display size", true)) {
                uint32_t x;
                int width;
                int height;

                char const *speed[] = {
                    "x1",
                    "x2",
                    "x3",
                    "x4",
                    "x5",
                };

                SDL_GetWindowSize(app->window, &width, &height);
                height -= app->menubar_height;

                for (x = 1; x <= 5; ++x) {
                    if (igMenuItemBool(
                        speed[x - 1],
                        NULL,
                        width == GBA_SCREEN_WIDTH * x * app->gui_scale && height == GBA_SCREEN_HEIGHT * x * app->gui_scale,
                        true
                    )) {
                        SDL_SetWindowSize(
                            app->window,
                            GBA_SCREEN_WIDTH * x * app->gui_scale,
                            app->menubar_height + GBA_SCREEN_HEIGHT * x * app->gui_scale
                        );
                    }
                }

                igEndMenu();
            }

            igSeparator();

            /* Reset */
            if (igMenuItemBool("Reset", NULL, false, app->emulation.enabled)) {
                gui_reload_game(app);
            }
            igEndMenu();
        }

        /* Emulation */
        if (igBeginMenu("Debug", false)) {
            igMenuItemBoolPtr("Enable Debugger", NULL, &app->debugger.enabled, true);
            igEndMenu();
        }

        /* About */
        if (igMenuItemBool("About", NULL, true, true)) {
            igOpenPopup("About", ImGuiPopupFlags_None);
        }

        /*
        ** Capture the height of the menu bar
        */
        igGetWindowSize(&menubar_size);
        app->menubar_height = menubar_size.y;

        /*
        ** Show popup and modals
        */

        if (igBeginPopupModal("About", NULL, ImGuiWindowFlags_Popup | ImGuiWindowFlags_Modal | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {
            igText("Hades");
            igSpacing();
            igSeparator();
            igSpacing();
            igText("Version: %s", HADES_VERSION);
            igText("Build date: %s", __DATE__);
            igSpacing();
            igSeparator();
            igSpacing();
            igText("Software written by Arignir");
            igText("Thank you for using it <3");
            igSpacing();
            if (igButton("Close", (ImVec2){.x = igGetFontSize() * 4.f, .y = igGetFontSize() * 1.5f})) {
                igCloseCurrentPopup();
            }
            igEndPopup();
        }

        gui_errors(app);

        igEndMainMenuBar();
    }

}