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
#include "platform/gui/app.h"
#include "utils/fs.h"

static
void
gui_win_menubar_file(
    struct app *app
) {
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
                free(app->file.game_path);
                app->file.game_path = strdup(path);
                NFD_FreePath(path);
                gui_game_reset(app);
                gui_game_run(app);
            }
        }

        if (igBeginMenu("Open Recent", app->file.recent_roms[0] != NULL)) {
            uint32_t x;

            for (x = 0; x < ARRAY_LEN(app->file.recent_roms) && app->file.recent_roms[x]; ++x) {
                if (igMenuItemBool(hs_basename(app->file.recent_roms[x]), NULL, false, true)) {
                    free(app->file.game_path);
                    app->file.game_path = strdup(app->file.recent_roms[x]);
                    gui_game_reset(app);
                    gui_game_run(app);
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
                free(app->file.bios_path);
                app->file.bios_path = strdup(path);
                NFD_FreePath(path);
            }
        }
        igEndMenu();
    }
}

static
void
gui_win_menubar_emulation(
    struct app *app
) {
    if (igBeginMenu("Emulation", true)) {
        if (igBeginMenu("Speed", app->emulation.started)) {
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
                        gba_send_speed(app->emulation.gba, app->emulation.speed * !app->emulation.unbounded);
                    }
                    igSeparator();
                } else {
                    if (igMenuItemBool(speed[x], NULL, app->emulation.speed == x, !app->emulation.unbounded)) {
                        app->emulation.speed = x;
                        gba_send_speed(app->emulation.gba, app->emulation.speed * !app->emulation.unbounded);
                    }
                }
            }

            igEndMenu();
        }

        igSeparator();

        if (igBeginMenu("Backup type", !app->emulation.started)) {
            uint32_t x;
            char const *backup_types[] = {
                "None",
                "EEPROM 4k",
                "EEPROM 64k",
                "SRAM",
                "Flash 64k",
                "Flash 128k"
            };

            if (igMenuItemBool("Auto-detect", NULL, app->emulation.backup_type == BACKUP_AUTO_DETECT, true)) {
                app->emulation.backup_type = BACKUP_AUTO_DETECT;
            }

            igSeparator();

            for (x = 0; x < ARRAY_LEN(backup_types); ++x) {
                if (igMenuItemBool(backup_types[x], NULL, app->emulation.backup_type == x, true)) {
                    app->emulation.backup_type = x;
                }
            }

            igEndMenu();
        }

        /* GPIO */
        if (igBeginMenu("Devices", !app->emulation.started)) {

            igText("RTC");
            igSeparator();

            if (igMenuItemBool("Auto-detect", NULL, app->emulation.rtc_autodetect, true)) {
                app->emulation.rtc_autodetect ^= 1;
            }
            if (igMenuItemBool("Enable", NULL, app->emulation.rtc_force_enabled, !app->emulation.rtc_autodetect)) {
                app->emulation.rtc_force_enabled ^= 1;
            }
            igEndMenu();
        }

        igSeparator();

        if (igMenuItemBool("Pause", NULL, !app->emulation.running, app->emulation.started)) {
            if (app->emulation.running) {
                gui_game_pause(app);
            } else {
                gui_game_run(app);
            }
        }

        if (igMenuItemBool("Stop", NULL, false, app->emulation.started)) {
            gui_game_stop(app);
        }

        if (igMenuItemBool("Reset", NULL, false, app->emulation.started)) {
            gui_game_reset(app);
            gui_game_run(app);
        }

        igEndMenu();
    }
}

static
void
gui_win_menubar_video(
    struct app *app
) {
    if (igBeginMenu("Video", true)) {

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

            SDL_GetWindowSize(app->sdl.window, &width, &height);
            height = max(0, height - app->ui.menubar_size.y);

            for (x = 1; x <= 5; ++x) {
                if (igMenuItemBool(
                    display_sizes[x - 1],
                    NULL,
                    width == GBA_SCREEN_WIDTH * x * app->ui.scale && height == GBA_SCREEN_HEIGHT * x * app->ui.scale,
                    true
                )) {
                    app->video.display_size = x;
                    app->ui.refresh_windows_size = true;
                }
            }

            igEndMenu();
        }

        igSeparator();

        /* Color Correction */
        if (igMenuItemBool("Color correction", NULL, app->video.color_correction, true)) {
            app->video.color_correction ^= 1;
            gba_send_settings_color_correction(app->emulation.gba, app->video.color_correction);
        }

        /* VSync */
        if (igMenuItemBool("VSync", NULL, app->video.vsync, true)) {
            app->video.vsync ^= 1;
            SDL_GL_SetSwapInterval(app->video.vsync);
        }

        igEndMenu();
    }
}

static
void
gui_win_menubar_audio(
    struct app *app
) {
    if (igBeginMenu("Audio", true)) {
        float percent;

        /* VSync */
        if (igMenuItemBool("Mute", NULL, app->audio.mute, true)) {
            app->audio.mute ^= 1;
        }

        igSeparator();

        igText("Sound Level:");

        igSpacing();

        igSetNextItemWidth(100.f * app->ui.scale);

        percent = app->audio.level * 100.f;
        igSliderFloat("", &percent, 0.0f, 100.0f, "%.0f%%", ImGuiSliderFlags_None);
        app->audio.level = max(0.0f, min(percent / 100.f, 1.f));

        igSpacing();

        igEndMenu();
    }
}

static
void
gui_win_menubar_about(
    struct app *app
) {
    /* About */
    if (igMenuItemBool("About", NULL, true, true)) {
        igOpenPopup("About", ImGuiPopupFlags_None);
    }

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
}

static
void
gui_win_menubar_fps_counter(
    struct app *app
) {
    /* FPS Counter */
    if (app->emulation.started && app->emulation.running) {
        float spacing;
        ImVec2 out;

        spacing = igGetStyle()->ItemSpacing.x;

        igSameLine(igGetWindowWidth() - (app->ui.menubar_fps_width + spacing * 2), 1);
        igText("FPS: %u (%u%%)", app->emulation.fps, (unsigned)(app->emulation.fps / 60.0 * 100.0));
        igGetItemRectSize(&out);
        app->ui.menubar_fps_width = out.x;
    }
}

void
gui_win_menubar(
    struct app *app
) {
    if (igBeginMainMenuBar()) {

        /* File */
        gui_win_menubar_file(app);

        /* Emulation */
        gui_win_menubar_emulation(app);

        /* Video */
        gui_win_menubar_video(app);

        /* Audio */
        gui_win_menubar_audio(app);

        /* About */
        gui_win_menubar_about(app);

        /* FPS */
        gui_win_menubar_fps_counter(app);

        /* Capture the height of the menu bar */
        igGetWindowSize(&app->ui.menubar_size);

        igEndMainMenuBar();
    }
}