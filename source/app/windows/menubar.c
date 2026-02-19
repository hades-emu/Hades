/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE

#include <SDL3/SDL_dialog.h>
#include <cimgui.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "hades.h"
#include "app/app.h"
#include "compat.h"

static
void
app_win_menubar_file(
    struct app *app
) {
    char *bind_str;

    if (igBeginMenu("File", true)) {
        if (igMenuItem_Bool("Open", NULL, false, true)) {
            SDL_ShowOpenFileDialog(
                app_nfd_update_path,
                app_nfd_create_event(app, NFD_ROM_PATH),
                app->sdl.window,
                sdl_nfd_rom_filters,
                1,
                NULL,
                false
            );
        }

        if (igBeginMenu("Open Recent", app->file.recent_roms[0] != NULL)) {
            uint32_t x;

            for (x = 0; x < array_length(app->file.recent_roms) && app->file.recent_roms[x]; ++x) {
                char label[128];
                char const *basename;

                basename = hs_basename(app->file.recent_roms[x]);

                if (!strlen(basename)) {
                    continue;
                }

                snprintf(label, sizeof(label), "%s##%u", basename, x);

                if (igMenuItem_Bool(label, NULL, false, true)) {
                    char *path;

                    // app->file.recent_roms[] is modified by `app_emulator_configure_and_run()` so we need to copy
                    // the path to a safe space first.
                    path = strdup(app->file.recent_roms[x]);

                    app_emulator_configure_and_run(app, path, NULL);

                    free(path);
                }
            }
            igEndMenu();
        }

        if (igMenuItem_Bool("Open BIOS", NULL, false, true)) {
            SDL_ShowOpenFileDialog(
                app_nfd_update_path,
                app_nfd_create_event(app, NFD_BIOS_PATH),
                app->sdl.window,
                sdl_nfd_bios_filters,
                1,
                NULL,
                false
            );
        }

        igSeparator();

        bind_str = app_bindings_keyboard_binding_to_str(&app->binds.keyboard[BIND_EMULATOR_SETTINGS]);
        if (igMenuItem_Bool("Settings", bind_str, false, true)) {
            app->ui.settings.open = true;
        }
        free(bind_str);

        igSeparator();

        if (igMenuItem_Bool("Exit", NULL, false, true)) {
            app->run = false;
        }

        igEndMenu();
    }
}

static
void
app_win_menubar_emulation(
    struct app *app
) {
    char *bind_str;

    if (igBeginMenu("Emulation", true)) {
        size_t i;

        float *speeds_ptr[] = {
            &app->settings.emulation.speed,
            &app->settings.emulation.alt_speed,
        };

        char const *speeds_name[] = {
            "Speed",
            "Alternative Speed"
        };

        // Speed & Alt speed
        for (i = 0; i < array_length(speeds_ptr); ++i) {
            if (igBeginMenu(speeds_name[i], app->emulation.is_started)) {
                uint32_t x;

                static char const *speeds_str[] = {
                    "25%  (15fps)",
                    "50%  (30fps)",
                    "100% (60fps)",
                    "150% (90fps)",
                    "200% (120fps)",
                    "300% (180fps)",
                    "400% (240fps)",
                    "500% (300fps)",
                    "Fast forward",
                };

                static float speeds_value[] = {
                    0.25f,
                    0.50f,
                    1.00f,
                    1.50f,
                    2.00f,
                    3.00f,
                    4.00f,
                    5.00f,
                    -1.00f,
                };

                for (x = 0; x < array_length(speeds_value); ++x) {
                    bool is_equal;

                    if (speeds_value[x] <= 0.0) {
                        is_equal = *speeds_ptr[i] <= 0;
                    } else {
                        is_equal = *speeds_ptr[i] >= speeds_value[x] - 0.01 && *speeds_ptr[i] <= speeds_value[x] + 0.01;
                    }

                    if (igMenuItem_Bool(speeds_str[x], NULL, is_equal, true)) {
                        *speeds_ptr[i] = speeds_value[x];
                        app_emulator_settings(app);
                    }
                }

                igEndMenu();
            }
        }

        igSeparator();

        if (igBeginMenu("Quick Save", app->emulation.is_started)) {
            for (i = 0; i < MAX_QUICKSAVES; ++i) {
                char *text;

                if (app->file.qsaves[i].exist && app->file.qsaves[i].mtime) {
                    text = hs_format("%zu: %s", i + 1, app->file.qsaves[i].mtime);
                } else {
                    text = hs_format("%zu: <empty>", i + 1);
                }

                hs_assert(text);

                if (igMenuItem_Bool(text, NULL, false, true)) {
                    app_emulator_quicksave(app, i);
                }

                free(text);
            }

            igEndMenu();
        }

        if (igBeginMenu("Quick Load", app->emulation.is_started)) {
            for (i = 0; i < MAX_QUICKSAVES; ++i) {
                char *text;

                if (app->file.qsaves[i].exist && app->file.qsaves[i].mtime) {
                    text = hs_format("%zu: %s", i + 1, app->file.qsaves[i].mtime);
                } else {
                    text = hs_format("%zu: <empty>", i + 1);
                }

                hs_assert(text);

                if (igMenuItem_Bool(text, NULL, false, app->file.qsaves[i].exist && app->file.qsaves[i].mtime)) {
                    app_emulator_quickload(app, i);
                }

                free(text);
            }

            igEndMenu();
        }

        igSeparator();

        if (igMenuItem_Bool("Import Save File", NULL, false, app->emulation.is_started && (bool)app->emulation.gba->shared_data.backup_storage.data)) {
            SDL_ShowOpenFileDialog(
                app_nfd_update_path,
                app_nfd_create_event(app, NFD_IMPORT_SAVE),
                app->sdl.window,
                sdl_nfd_save_filters,
                1,
                NULL,
                false
            );
        }

        if (igMenuItem_Bool("Export Save File", NULL, false, app->emulation.is_started && (bool)app->emulation.gba->shared_data.backup_storage.data)) {
            SDL_ShowSaveFileDialog(
                app_nfd_update_path,
                app_nfd_create_event(app, NFD_EXPORT_SAVE),
                app->sdl.window,
                sdl_nfd_save_filters,
                1,
                NULL
            );
        }

        igSeparator();

        bind_str = app_bindings_keyboard_binding_to_str(&app->binds.keyboard[BIND_EMULATOR_PAUSE]);
        if (igMenuItem_Bool("Pause", bind_str, !app->emulation.is_running, app->emulation.is_started)) {
            if (app->emulation.is_running) {
                app_emulator_pause(app);
            } else {
                app_emulator_run(app);
            }
        }
        free(bind_str);

        bind_str = app_bindings_keyboard_binding_to_str(&app->binds.keyboard[BIND_EMULATOR_STOP]);
        if (igMenuItem_Bool("Stop", bind_str, false, app->emulation.is_started)) {
            app_emulator_stop(app);
        }
        free(bind_str);

        bind_str = app_bindings_keyboard_binding_to_str(&app->binds.keyboard[BIND_EMULATOR_RESET]);
        if (igMenuItem_Bool("Reset", bind_str, false, app->emulation.is_started)) {
            app_emulator_reset(app);
        }
        free(bind_str);

        igSeparator();

        if (igMenuItem_Bool("Emulation Settings", NULL, false, true)) {
            app->ui.settings.open = true;
            app->ui.settings.menu = MENU_EMULATION;
        }

        igEndMenu();
    }
}

static
void
app_win_menubar_video(
    struct app *app
) {
    char *bind_str;

    if (igBeginMenu("Video", true)) {

        /* Display Size */
        if (igBeginMenu("Display size", true)) {
            uint32_t x;

            static char const * const display_sizes[] = {
                "x1",
                "x2",
                "x3",
                "x4",
                "x5",
            };

            for (x = 1; x <= 5; ++x) {
                if (igMenuItem_Bool(
                    display_sizes[x - 1],
                    NULL,
                       app->ui.display.game.outer.width == (uint32_t)round(GBA_SCREEN_WIDTH * x / app->ui.window_pixel_density)
                    && app->ui.display.game.outer.height == (uint32_t)round(GBA_SCREEN_HEIGHT * x / app->ui.window_pixel_density),
                    true
                )) {
                    app->settings.video.display_size = x;
                    app_sdl_video_resize_window(app);
                }
            }

            igEndMenu();
        }

        igSeparator();

        /* Take a screenshot */
        bind_str = app_bindings_keyboard_binding_to_str(&app->binds.keyboard[BIND_EMULATOR_SCREENSHOT]);
        if (igMenuItem_Bool("Take Screenshot", bind_str, false, app->emulation.is_started)) {
            app_emulator_screenshot(app);
        }
        free(bind_str);

        /* Pixel Color Effect */
        if (igBeginMenu("Color Effect", true)) {
            if (igMenuItem_Bool("None", NULL, app->settings.video.pixel_color_filter == PIXEL_COLOR_FILTER_NONE, true)) {
                app->settings.video.pixel_color_filter = PIXEL_COLOR_FILTER_NONE;
                app_sdl_video_rebuild_pipeline(app);
            }

            igSeparator();

            if (igMenuItem_Bool("Color Correction", NULL, app->settings.video.pixel_color_filter == PIXEL_COLOR_FILTER_COLOR_CORRECTION, true)) {
                app->settings.video.pixel_color_filter = PIXEL_COLOR_FILTER_COLOR_CORRECTION;
                app_sdl_video_rebuild_pipeline(app);
            }

            if (igMenuItem_Bool("Grey Scale", NULL, app->settings.video.pixel_color_filter == PIXEL_COLOR_FILTER_GREY_SCALE, true)) {
                app->settings.video.pixel_color_filter = PIXEL_COLOR_FILTER_GREY_SCALE;
                app_sdl_video_rebuild_pipeline(app);
            }

            igEndMenu();
        }

        /* Pixel Scaling Effect */
        if (igBeginMenu("Scaling Effect", true)) {
            if (igMenuItem_Bool("None", NULL, app->settings.video.pixel_scaling_filter == PIXEL_SCALING_FILTER_NONE, true)) {
                app->settings.video.pixel_scaling_filter = PIXEL_SCALING_FILTER_NONE;
                app_sdl_video_rebuild_pipeline(app);
            }

            igSeparator();

            if (igMenuItem_Bool("LCD Grid /w RGB Stripes", NULL, app->settings.video.pixel_scaling_filter == PIXEL_SCALING_FILTER_LCD_GRID_WITH_RGB_STRIPES, true)) {
                app->settings.video.pixel_scaling_filter = PIXEL_SCALING_FILTER_LCD_GRID_WITH_RGB_STRIPES;
                app_sdl_video_rebuild_pipeline(app);
            }

            if (igMenuItem_Bool("LCD Grid", NULL, app->settings.video.pixel_scaling_filter == PIXEL_SCALING_FILTER_LCD_GRID, true)) {
                app->settings.video.pixel_scaling_filter = PIXEL_SCALING_FILTER_LCD_GRID;
                app_sdl_video_rebuild_pipeline(app);
            }

            igEndMenu();
        }

        igSeparator();

        if (igMenuItem_Bool("Video Settings", NULL, false, true)) {
            app->ui.settings.open = true;
            app->ui.settings.menu = MENU_VIDEO;
        }

        igEndMenu();
    }
}

static
void
app_win_menubar_audio(
    struct app *app
) {
    char *bind_str;

    if (igBeginMenu("Audio", true)) {
        bind_str = app_bindings_keyboard_binding_to_str(&app->binds.keyboard[BIND_EMULATOR_MUTE]);
        if (igMenuItem_Bool("Mute", bind_str, app->settings.audio.mute, true)) {
            app->settings.audio.mute ^= 1;
        }
        free(bind_str);

        igSeparator();

        if (igMenuItem_Bool("Audio Settings", NULL, false, true)) {
            app->ui.settings.open = true;
            app->ui.settings.menu = MENU_AUDIO;
        }

        igEndMenu();
    }
}

static
void
app_win_menubar_help(
    struct app const *app
) {
    bool open_about;

    open_about = false;

    if (igBeginMenu("Help", true)) {

        /* Report Issue */
        if (igMenuItem_Bool("Report Issue", NULL, false, true)) {
            hs_open_url("https://github.com/Arignir/Hades/issues/new");
        }

        igSeparator();

        /* About */
        if (igMenuItem_Bool("About", NULL, false, true)) {
            open_about = true;
        }
        igEndMenu();
    }

    if (open_about) {
        igOpenPopup_Str("About", ImGuiPopupFlags_None);
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
        igText("Icon designed by Totushi");
        igSpacing();
        igText("Thank you for using Hades <3");
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
    // FPS Counter
    if (
           app->settings.general.show_fps
        && app->emulation.is_started
        && app->emulation.is_running
        && igGetWindowWidth() >= GBA_SCREEN_WIDTH * 2
    ) {
        float spacing;
        ImVec2 out;

        spacing = igGetStyle()->ItemSpacing.x;

        igSameLine(igGetWindowWidth() - (app->ui.menubar.fps_width + spacing * 2), 1);
        igText("FPS: %.1f (%.1f%%)", app->emulation.fps, app->emulation.fps / 60.0 * 100.0);
        igGetItemRectSize(&out);
        app->ui.menubar.fps_width = out.x;
    }
}

void
app_win_menubar(
    struct app *app
) {
    float vp_y;

    if (app->ui.menubar.visibility <= 0.0f) {
        return;
    }

    // Hacking ImGui a bit to nicely fade the menubar away
    vp_y = igGetMainViewport()->Pos.y;
    igGetMainViewport()->Pos.y -= (1.0f - app->ui.menubar.visibility) * app->ui.menubar.size.y;

    if (igBeginMainMenuBar()) {
        // File
        app_win_menubar_file(app);

        // Emulation
        app_win_menubar_emulation(app);

        // Video
        app_win_menubar_video(app);

        // Audio
        app_win_menubar_audio(app);

        // Help
        app_win_menubar_help(app);

        // FPS
        app_win_menubar_fps_counter(app);

        // Capture the height of the menu bar
        igGetWindowSize(&app->ui.menubar.size);

        igEndMainMenuBar();
    }

    // Restore the viewport's position
    igGetMainViewport()->Pos.y = vp_y;
}
