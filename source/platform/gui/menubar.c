/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include <string.h>
#include <cimgui.h>
#include <nfd.h>
#include <stdio.h>
#include <float.h>
#include "hades.h"
#include "gba/gba.h"
#include "utils/fs.h"
#include "platform/gui.h"

void
gui_render_menubar(
    struct app *app
) {
    ImVec2 menubar_size;

    if (igBeginMainMenuBar()) {
        /* File */
        if (igBeginMenu("File", true)) {
            if (igMenuItemBool("Open", NULL, false, true)) {
                nfdresult_t result;
                nfdchar_t *path;

                result = NFD_OpenDialog(
                    &path,
                    (nfdfilteritem_t[1]){(nfdfilteritem_t){ .name = "GBA Rom", .spec = "gba"}},
                    1,
                    NULL
                );

                if (result == NFD_OKAY) {
                    free(app->emulation.game_path);
                    app->emulation.game_path = strdup(path);
                    gui_game_reset(app);
                    NFD_FreePath(path);
                }
            }

            if (igBeginMenu("Open Recent", app->recent_roms[0] != NULL)) {
                uint32_t x;

                for (x = 0; x < ARRAY_LEN(app->recent_roms) && app->recent_roms[x]; ++x) {
                    if (igMenuItemBool(hs_basename(app->recent_roms[x]), NULL, false, true)) {
                        free(app->emulation.game_path);
                        app->emulation.game_path = strdup(app->recent_roms[x]);
                        gui_game_reset(app);
                    }
                }
                igEndMenu();
            }

            if (igMenuItemBool("Open BIOS", NULL, false, true)) {
                nfdresult_t result;
                nfdchar_t *path;

                result = NFD_OpenDialog(
                    &path,
                    (nfdfilteritem_t[1]){(nfdfilteritem_t){ .name = "BIOS file", .spec = "bin,bios,raw"}},
                    1,
                    NULL
                );

                if (result == NFD_OKAY) {
                    free(app->emulation.bios_path);
                    app->emulation.bios_path = strdup(path);
                    NFD_FreePath(path);
                }
            }

            igSeparator();

            igMenuItemBool("Key Bindings", NULL, false, false);
            igEndMenu();
        }

        /* Emulation */
        if (igBeginMenu("Emulation", true)) {

            /* Color Correction */
            if (igMenuItemBool("Color correction", NULL, app->emulation.color_correction, true)) {
                app->emulation.color_correction ^= 1;
                gui_game_set_color_correction(app);
            }

            /* VSync */
            if (igMenuItemBool("Enable VSync", NULL, app->vsync, true)) {
                app->vsync ^= 1;
                SDL_GL_SetSwapInterval(app->vsync);
            }

            igSeparator();

            /* Save & backups */
            if (igMenuItemBool("Quick Save", "F5", false, app->emulation.enabled)) {
                gui_game_quicksave(app);
            }

            if (igMenuItemBool("Quick Load", "F8", false, app->emulation.enabled)) {
                gui_game_quickload(app);
            }

            igSeparator();

            /* Backup Type */
            if (igBeginMenu("Backup type", app->emulation.pause && !app->emulation.enabled)) {
                uint32_t x;
                char const *backup_types[] = {
                    "Auto-detect",
                    "None",
                    "EEPROM 4k",
                    "EEPROM 64k",
                    "SRAM",
                    "Flash 64k",
                    "Flash 128k"
                };

                for (x = 0; x < ARRAY_LEN(backup_types); ++x) {
                    if (!x) {
                        if (igMenuItemBool(backup_types[x], NULL, app->emulation.backup_type == BACKUP_AUTO_DETECT, true)) {
                            app->emulation.backup_type = BACKUP_AUTO_DETECT;
                            gui_game_set_backup_type(app);
                        }
                        igSeparator();
                    } else {
                        if (igMenuItemBool(backup_types[x], NULL, app->emulation.backup_type == x, true)) {
                            app->emulation.backup_type = x - 1;
                            gui_game_set_backup_type(app);
                        }
                    }
                }

                igEndMenu();
            }

            /* GPIO */
            if (igBeginMenu("Devices", app->emulation.pause && !app->emulation.enabled)) {
                if (igMenuItemBool("Auto-detect RTC", NULL, app->emulation.rtc_autodetect, true)) {
                    app->emulation.rtc_autodetect ^= 1;
                }
                if (igMenuItemBool("Enable RTC", NULL, app->emulation.rtc_enabled, !app->emulation.rtc_autodetect)) {
                    app->emulation.rtc_enabled ^= 1;
                }
                igEndMenu();
            }

            igSeparator();

            /* Pause */
            if (igMenuItemBool("Pause", NULL, app->emulation.pause, app->emulation.enabled)) {
                app->emulation.pause ^= 1;

                if (app->emulation.pause) {
                    gui_game_pause(app);
                } else {
                    gui_game_run(app);
                }
            }

            /* Speed */
            if (igBeginMenu("Speed", !app->emulation.pause && app->emulation.enabled)) {
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
                    if (!x) {
                        if (igMenuItemBool(speed[x], "F1", app->emulation.unbounded, true)) {
                            app->emulation.unbounded ^= 1;
                            gui_game_run(app);
                        }
                        igSeparator();
                    } else {
                        if (igMenuItemBool(speed[x], NULL, app->emulation.speed == x, !app->emulation.unbounded)) {
                            app->emulation.speed = x;
                            gui_game_run(app);
                        }
                    }
                }

                igEndMenu();
            }

            /* Take a screenshot */
            if (igMenuItemBool("Screenshot", "F2", false, app->emulation.enabled)) {
                gui_game_screenshot(app);
            }

            /* Display Size */
            if (igBeginMenu("Display size", true)) {
                uint32_t x;
                int width;
                int height;

                char const *display_sizes[] = {
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
                        display_sizes[x - 1],
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

            /* Stop */
            if (igMenuItemBool("Stop", NULL, false, app->emulation.enabled)) {
                gui_game_stop(app);
            }

            /* Reset */
            if (igMenuItemBool("Reset", NULL, false, app->emulation.enabled)) {
                gui_game_reset(app);
            }

            igEndMenu();
        }

        /* About */
        if (igMenuItemBool("About", NULL, true, true)) {
            igOpenPopup("About", ImGuiPopupFlags_None);
        }

        /* FPS Counter */
        if (app->emulation.enabled && !app->emulation.pause) {
            float spacing;
            ImVec2 out;

            spacing = igGetStyle()->ItemSpacing.x;

            igSameLine(igGetWindowWidth() - (app->menubar_fps_width + spacing * 2), 1);
            igText("FPS: %u (%u%%)", app->emulation.fps, (unsigned)(app->emulation.fps / 60.0 * 100.0));
            igGetItemRectSize(&out);
            app->menubar_fps_width = out.x;
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

        igEndMainMenuBar();
    }

}