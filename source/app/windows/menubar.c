/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
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
#include "app/app.h"
#include "compat.h"

static
void
app_win_menubar_file(
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
                if (!app_emulator_configure(app, path)) {
                    app_emulator_run(app);
                }
                NFD_FreePath(path);
            }
        }

        if (igBeginMenu("Open Recent", app->file.recent_roms[0] != NULL)) {
            uint32_t x;

            for (x = 0; x < array_length(app->file.recent_roms) && app->file.recent_roms[x]; ++x) {
                if (igMenuItemBool(hs_basename(app->file.recent_roms[x]), NULL, false, true)) {
                    char *path;

                    // app->file.recent_roms[] is modified by `app_emulator_configure()` so we need to copy
                    // the path to a safe space first.
                    path = strdup(app->file.recent_roms[x]);

                    if (!app_emulator_configure(app, path)) {
                        app_emulator_run(app);
                    }

                    free(path);
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

        igSeparator();

        if (igMenuItemBool("Keybindings", NULL, false, true)) {
            app->ui.keybindings_editor.open = true;
        }

        igEndMenu();
    }
}

static
void
app_win_menubar_emulation(
    struct app *app
) {
    if (igBeginMenu("Emulation", true)) {
        if (igMenuItemBool("Skip BIOS", NULL, app->emulation.skip_bios, true)) {
            app->emulation.skip_bios ^= 1;
        }

        if (igBeginMenu("Speed", app->emulation.is_started)) {
            uint32_t x;
            char const *speed[] = {
                "Unbounded",
                "x1",
                "x2",
                "x3",
                "x4",
                "x5",
            };

            for (x = 0; x <= 5; ++x) {
                char const *bind;

                bind = SDL_GetKeyName(app->binds.keyboard[BIND_EMULATOR_SPEED_MAX + x]);
                if (igMenuItemBool(speed[x], bind ?: "", app->emulation.speed == x, true)) {
                    app->emulation.unbounded = false;
                    app->emulation.speed = x;
                    app_emulator_speed(app, app->emulation.speed);
                }

                if (!x) {
                    igSeparator();
                }
            }

            igEndMenu();
        }

        igSeparator();

        if (igBeginMenu("Quick Save", app->emulation.is_started)) {
            size_t i;

            for (i = 0; i < MAX_QUICKSAVES; ++i) {
                char *text;

                if (app->file.qsaves[i].exist && app->file.qsaves[i].mtime) {
                    text = hs_format("%zu: %s", i + 1, app->file.qsaves[i].mtime);
                } else {
                    text = hs_format("%zu: <empty>", i + 1);
                }

                hs_assert(text);

                if (igMenuItemBool(text, NULL, false, true)) {
                    app_emulator_quicksave(app, i);
                }

                free(text);
            }

            igEndMenu();
        }

        if (igBeginMenu("Quick Load", app->emulation.is_started)) {
            size_t i;

            for (i = 0; i < MAX_QUICKSAVES; ++i) {
                char *text;

                if (app->file.qsaves[i].exist && app->file.qsaves[i].mtime) {
                    text = hs_format("%zu: %s", i + 1, app->file.qsaves[i].mtime);
                } else {
                    text = hs_format("%zu: <empty>", i + 1);
                }

                hs_assert(text);

                if (igMenuItemBool(text, NULL, false, app->file.qsaves[i].exist && app->file.qsaves[i].mtime)) {
                    app_emulator_quickload(app, i);
                }

                free(text);
            }

            igEndMenu();
        }

        igSeparator();

        if (igBeginMenu("Backup Storage", !app->emulation.is_started)) {
            uint32_t x;

            if (igMenuItemBool("Auto-detect", NULL, app->emulation.backup_storage.autodetect, true)) {
                app->emulation.backup_storage.autodetect ^= 1;
            }

            igSeparator();

            for (x = BACKUP_MIN; x < BACKUP_LEN; ++x) {
                if (igMenuItemBool(backup_storage_names[x], NULL, !app->emulation.backup_storage.autodetect && app->emulation.backup_storage.type == x, true)) {
                    app->emulation.backup_storage.type = x;
                    app->emulation.backup_storage.autodetect = false;
                }
            }

            igEndMenu();
        }

        /* Backup storage & GPIO */
        if (igBeginMenu("Devices", !app->emulation.is_started)) {

            igText("RTC");
            igSeparator();

            if (igMenuItemBool("Auto-detect", NULL, app->emulation.rtc.autodetect, true)) {
                app->emulation.rtc.autodetect ^= 1;
            }
            if (igMenuItemBool("Enable", NULL, app->emulation.rtc.enabled, !app->emulation.rtc.autodetect)) {
                app->emulation.rtc.enabled ^= 1;
            }
            igEndMenu();
        }

        igSeparator();

        if (igMenuItemBool("Pause", NULL, !app->emulation.is_running, app->emulation.is_started)) {
            if (app->emulation.is_running) {
                app_emulator_pause(app);
            } else {
                app_emulator_run(app);
            }
        }

        if (igMenuItemBool("Stop", NULL, false, app->emulation.is_started)) {
            app_emulator_stop(app);
        }

        if (igMenuItemBool("Reset", NULL, false, app->emulation.is_started)) {
            app_emulator_reset(app);
            app_emulator_run(app);
        }

        igEndMenu();
    }
}

static
void
app_win_menubar_video(
    struct app *app
) {
    char const *bind;

    if (igBeginMenu("Video", true)) {

        /* Display Size */
        if (igBeginMenu("Display size", true)) {
            uint32_t x;
            int width;
            int height;

            static char const * const display_sizes[] = {
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
                    app->ui.win.resize = true;
                    app->ui.win.resize_with_ratio = false;
                }
            }

            igEndMenu();
        }

        /* Aspect Ratio */
        if (igBeginMenu("Aspect Ratio", true)) {
            if (igMenuItemBool(
                "Auto resize",
                NULL,
                app->video.aspect_ratio == ASPECT_RATIO_RESIZE,
                true
            )) {
                app->video.aspect_ratio = ASPECT_RATIO_RESIZE;
                app->ui.win.resize = true;
                app->ui.win.resize_with_ratio = true;
                app->ui.win.resize_ratio = min(app->ui.game.width / ((float)GBA_SCREEN_WIDTH * app->ui.scale), app->ui.game.height / ((float)GBA_SCREEN_HEIGHT * app->ui.scale));
            }

            if (igMenuItemBool(
                "Black borders",
                NULL,
                app->video.aspect_ratio == ASPECT_RATIO_BORDERS,
                true
            )) {
                app->video.aspect_ratio = ASPECT_RATIO_BORDERS;
            }

            if (igMenuItemBool(
                "Stretch",
                NULL,
                app->video.aspect_ratio == ASPECT_RATIO_STRETCH,
                true
            )) {
                app->video.aspect_ratio = ASPECT_RATIO_STRETCH;
            }

            igEndMenu();
        }

        igSeparator();

        /* Texture Filter */
        if (igBeginMenu("Texture Filter", true)) {
            if (igMenuItemBool("Nearest", NULL, app->gfx.texture_filter == TEXTURE_FILTER_NEAREST, true)) {
                app->gfx.texture_filter = TEXTURE_FILTER_NEAREST;
                app_sdl_video_rebuild_pipeline(app);
            }

            if (igMenuItemBool("Linear", NULL, app->gfx.texture_filter == TEXTURE_FILTER_LINEAR, true)) {
                app->gfx.texture_filter = TEXTURE_FILTER_LINEAR;
                app_sdl_video_rebuild_pipeline(app);
            }

            igEndMenu();
        }

        /* Color Correction */
        if (igMenuItemBool("Color correction", NULL, app->video.color_correction, true)) {
            app->video.color_correction ^= 1;
            app_sdl_video_rebuild_pipeline(app);
        }

        /* LCD Effect */
        if (igMenuItemBool("LCD Grid Effect", NULL, app->video.lcd_grid, true)) {
            app->video.lcd_grid ^= 1;
            app_sdl_video_rebuild_pipeline(app);
        }

        /* VSync */
        if (igMenuItemBool("VSync", NULL, app->video.vsync, true)) {
            app->video.vsync ^= 1;
            SDL_GL_SetSwapInterval(app->video.vsync);
        }

        igSeparator();

        /* Take a screenshot */
        bind = SDL_GetKeyName(app->binds.keyboard[BIND_EMULATOR_SCREENSHOT]);
        if (igMenuItemBool("Screenshot", bind ? bind : "", false, app->emulation.is_started)) {
            app_emulator_screenshot(app);
        }

        igEndMenu();
    }
}

static
void
app_win_menubar_audio(
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
app_win_menubar_help(
    struct app *app
) {
    bool open_about;

    open_about = false;

    if (igBeginMenu("Help", true)) {

        /* Report Issue */
        if (igMenuItemBool("Report Issue", NULL, false, true)) {
            hs_open_url("https://github.com/Arignir/Hades/issues/new");
        }

        igSeparator();

        /* About */
        if (igMenuItemBool("About", NULL, false, true)) {
            open_about = true;
        }
        igEndMenu();
    }

    if (open_about) {
        igOpenPopup("About", ImGuiPopupFlags_None);
    }

    // Always center the modal
    igSetNextWindowPos(
        (ImVec2){.x = app->ui.ioptr->DisplaySize.x * 0.5f, .y = app->ui.ioptr->DisplaySize.y * 0.5f},
        ImGuiCond_Always,
        (ImVec2){.x = 0.5f, .y = 0.5f}
    );

    if (
        igBeginPopupModal(
            "About",
            NULL,
            ImGuiWindowFlags_Popup
              | ImGuiWindowFlags_Modal
              | ImGuiWindowFlags_NoResize
              | ImGuiWindowFlags_NoMove
        )
    ) {
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
app_win_menubar_fps_counter(
    struct app *app
) {
    /* FPS Counter */
    if (app->emulation.is_started && app->emulation.is_running) {
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
app_win_menubar(
    struct app *app
) {
    if (igBeginMainMenuBar()) {

        /* File */
        app_win_menubar_file(app);

        /* Emulation */
        app_win_menubar_emulation(app);

        /* Video */
        app_win_menubar_video(app);

        /* Audio */
        app_win_menubar_audio(app);

        /* Help */
        app_win_menubar_help(app);

        /* FPS */
        app_win_menubar_fps_counter(app);

        /* Capture the height of the menu bar */
        igGetWindowSize(&app->ui.menubar_size);

        igEndMainMenuBar();
    }
}
