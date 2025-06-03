/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <cimgui.h>
#include <nfd.h>
#include "hades.h"
#include "app/app.h"

static char const *menu_names[MENU_MAX] = {
    [MENU_GENERAL] = "General",
    [MENU_EMULATION] = "Emulation",
    [MENU_VIDEO] = "Video",
    [MENU_AUDIO] = "Audio",
    [MENU_BINDINGS] = "Bindings",
};

static char const *texture_filters_names[TEXTURE_FILTER_LEN] = {
    [TEXTURE_FILTER_NEAREST] = "Nearest",
    [TEXTURE_FILTER_LINEAR] = "Linear",
};

static char const *pixel_color_filters_names[PIXEL_COLOR_FILTER_LEN] = {
    [PIXEL_COLOR_FILTER_NONE] = "None",
    [PIXEL_COLOR_FILTER_COLOR_CORRECTION] = "Color correction",
    [PIXEL_COLOR_FILTER_GREY_SCALE] = "Grey scale",
};

static char const *pixel_scaling_filters_names[PIXEL_SCALING_FILTER_LEN] = {
    [PIXEL_SCALING_FILTER_NONE] = "None",
    [PIXEL_SCALING_FILTER_LCD_GRID] = "LCD Grid",
    [PIXEL_SCALING_FILTER_LCD_GRID_WITH_RGB_STRIPES] = "LCD Grid /w RGB Stripes",
};

static char const *aspect_ratio_names[ASPECT_RATIO_LEN] = {
    [ASPECT_RATIO_BORDERS] = "Black Borders",
    [ASPECT_RATIO_STRETCH] = "Stretch",
};

static char const *display_mode_names[DISPLAY_MODE_LEN] = {
    [DISPLAY_MODE_WINDOWED] = "Windowed",
    [DISPLAY_MODE_BORDERLESS] = "Borderless",
    [DISPLAY_MODE_FULLSCREEN] = "Fullscreen",
};

static char const *menubar_mode_names[MENUBAR_MODE_LEN] = {
    [MENUBAR_MODE_FIXED_ABOVE_GAME] = "Fixed above game",
    [MENUBAR_MODE_HOVER_OVER_GAME] = "Hover over game",
};

static char const * const display_size_names[] = {
    "x1",
    "x2",
    "x3",
    "x4",
    "x5",
};

char const * const binds_pretty_name[] = {
    [BIND_GBA_A] = "A",
    [BIND_GBA_B] = "B",
    [BIND_GBA_L] = "L",
    [BIND_GBA_R] = "R",
    [BIND_GBA_UP] = "Up",
    [BIND_GBA_DOWN] = "Down",
    [BIND_GBA_LEFT] = "Left",
    [BIND_GBA_RIGHT] = "Right",
    [BIND_GBA_START] = "Start",
    [BIND_GBA_SELECT] = "Select",

    [BIND_EMULATOR_SCREENSHOT] = "Screenshot",
    [BIND_EMULATOR_MUTE] = "Mute",
    [BIND_EMULATOR_PAUSE] = "Pause",
    [BIND_EMULATOR_STOP] = "Stop",
    [BIND_EMULATOR_RESET] = "Reset",
    [BIND_EMULATOR_SHOW_FPS] = "Toggle FPS",
    [BIND_EMULATOR_SETTINGS] = "Toggle Settings",
    [BIND_EMULATOR_ALT_SPEED_TOGGLE] = "Alt. Speed (Toggle)",
    [BIND_EMULATOR_ALT_SPEED_HOLD] = "Alt. Speed (Hold)",
    [BIND_EMULATOR_QUICKSAVE_1] = "Quicksave 1",
    [BIND_EMULATOR_QUICKSAVE_2] = "Quicksave 2",
    [BIND_EMULATOR_QUICKSAVE_3] = "Quicksave 3",
    [BIND_EMULATOR_QUICKSAVE_4] = "Quicksave 4",
    [BIND_EMULATOR_QUICKSAVE_5] = "Quicksave 5",
    [BIND_EMULATOR_QUICKSAVE_6] = "Quicksave 6",
    [BIND_EMULATOR_QUICKSAVE_7] = "Quicksave 7",
    [BIND_EMULATOR_QUICKSAVE_8] = "Quicksave 8",
    [BIND_EMULATOR_QUICKSAVE_9] = "Quicksave 9",
    [BIND_EMULATOR_QUICKSAVE_10] = "Quicksave 10",
    [BIND_EMULATOR_QUICKLOAD_1] = "Quickload 1",
    [BIND_EMULATOR_QUICKLOAD_2] = "Quickload 2",
    [BIND_EMULATOR_QUICKLOAD_3] = "Quickload 3",
    [BIND_EMULATOR_QUICKLOAD_4] = "Quickload 4",
    [BIND_EMULATOR_QUICKLOAD_5] = "Quickload 5",
    [BIND_EMULATOR_QUICKLOAD_6] = "Quickload 6",
    [BIND_EMULATOR_QUICKLOAD_7] = "Quickload 7",
    [BIND_EMULATOR_QUICKLOAD_8] = "Quickload 8",
    [BIND_EMULATOR_QUICKLOAD_9] = "Quickload 9",
    [BIND_EMULATOR_QUICKLOAD_10] = "Quickload 10",
};

char const * const binds_slug[] = {
    [BIND_GBA_A] = "a",
    [BIND_GBA_B] = "b",
    [BIND_GBA_L] = "l",
    [BIND_GBA_R] = "r",
    [BIND_GBA_UP] = "up",
    [BIND_GBA_DOWN] = "down",
    [BIND_GBA_LEFT] = "left",
    [BIND_GBA_RIGHT] = "right",
    [BIND_GBA_START] = "start",
    [BIND_GBA_SELECT] = "select",

    [BIND_EMULATOR_SCREENSHOT] = "screenshot",
    [BIND_EMULATOR_MUTE] = "mute",
    [BIND_EMULATOR_PAUSE] = "pause",
    [BIND_EMULATOR_STOP] = "stop",
    [BIND_EMULATOR_RESET] = "reset",
    [BIND_EMULATOR_SHOW_FPS] = "toggle_show_fps",
    [BIND_EMULATOR_SETTINGS] = "toggle_settings",
    [BIND_EMULATOR_ALT_SPEED_TOGGLE] = "alternative_speed_toggle",
    [BIND_EMULATOR_ALT_SPEED_HOLD] = "alternative_speed_hold",
    [BIND_EMULATOR_QUICKSAVE_1] = "quicksave_1",
    [BIND_EMULATOR_QUICKSAVE_2] = "quicksave_2",
    [BIND_EMULATOR_QUICKSAVE_3] = "quicksave_3",
    [BIND_EMULATOR_QUICKSAVE_4] = "quicksave_4",
    [BIND_EMULATOR_QUICKSAVE_5] = "quicksave_5",
    [BIND_EMULATOR_QUICKSAVE_6] = "quicksave_6",
    [BIND_EMULATOR_QUICKSAVE_7] = "quicksave_7",
    [BIND_EMULATOR_QUICKSAVE_8] = "quicksave_8",
    [BIND_EMULATOR_QUICKSAVE_9] = "quicksave_9",
    [BIND_EMULATOR_QUICKSAVE_10] = "quicksave_10",
    [BIND_EMULATOR_QUICKLOAD_1] = "quickload_1",
    [BIND_EMULATOR_QUICKLOAD_2] = "quickload_2",
    [BIND_EMULATOR_QUICKLOAD_3] = "quickload_3",
    [BIND_EMULATOR_QUICKLOAD_4] = "quickload_4",
    [BIND_EMULATOR_QUICKLOAD_5] = "quickload_5",
    [BIND_EMULATOR_QUICKLOAD_6] = "quickload_6",
    [BIND_EMULATOR_QUICKLOAD_7] = "quickload_7",
    [BIND_EMULATOR_QUICKLOAD_8] = "quickload_8",
    [BIND_EMULATOR_QUICKLOAD_9] = "quickload_9",
    [BIND_EMULATOR_QUICKLOAD_10] = "quickload_10",
};

static
void
app_win_settings_general(
    struct app *app
) {
    ImGuiViewport *vp;

    vp = igGetMainViewport();

    igTextWrapped("General Settings");
    igSpacing();
    igSeparator();
    igSpacing();

    igSeparatorText("Misc");

    if (igBeginTable("##GeneralSettingsMisc", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##GeneralSettingsMiscLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##GeneralSettingsMiscValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Show FPS
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Show FPS");

        igTableNextColumn();
        igCheckbox("##ShowFPS", &app->settings.general.show_fps);

        // Start the last played game on startup, when no game is provided
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Start last played game on startup");

        igTableNextColumn();
        igCheckbox("##StartLastPlayedGameOnStartup", &app->settings.general.start_last_played_game_on_startup);

        // Pause when the window is inactive
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Pause when window is inactive");

        igTableNextColumn();
        igCheckbox("##PauseWhenWindowInactive", &app->settings.general.pause_when_window_inactive);

#ifdef WITH_DEBUGGER
        // Pause when the game resets
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Pause when the game resets");

        igTableNextColumn();
        igCheckbox("##PauseWhenGameResets", &app->settings.general.pause_when_game_resets);
#endif

        igEndTable();
    }
}

static
void
app_win_settings_emulation(
    struct app *app
) {
    ImGuiViewport *vp;

    vp = igGetMainViewport();

    igTextWrapped("Emulation Settings");
    igSpacing();
    igSeparator();
    igSpacing();

    igSeparatorText("BIOS");

    if (igBeginTable("##EmulationSettingsBIOS", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##EmulationSettingsBIOSLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##EmulationSettingsBIOSValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // BIOS Path
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("BIOS Path");

        igTableNextColumn();
        igBeginDisabled(true);
        igInputText("##BiosPath", app->settings.emulation.bios_path, strlen(app->settings.emulation.bios_path), ImGuiInputTextFlags_ReadOnly, NULL, NULL);
        igEndDisabled();
        igSameLine(0.0f, -1.0f);
        if (igButton("Choose", (ImVec2){ 50.f, 0.f})) {
            nfdresult_t result;
            nfdchar_t *path;

            result = NFD_OpenDialog(
                &path,
                (nfdfilteritem_t[1]){(nfdfilteritem_t){ .name = "BIOS file", .spec = "bin,bios,raw"}},
                1,
                NULL
            );

            if (result == NFD_OKAY) {
                free(app->settings.emulation.bios_path);
                app->settings.emulation.bios_path = strdup(path);
                NFD_FreePath(path);
            }
        }

        // Skip BIOS
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Skip BIOS Intro");

        igTableNextColumn();
        igCheckbox("##SkipBIOS", &app->settings.emulation.skip_bios_intro);

        igEndTable();
    }

    igSeparatorText("Speed");

    if (igBeginTable("##EmulationSettingsSpeed", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        size_t i;

        float *speeds[] = {
            &app->settings.emulation.speed,
            &app->settings.emulation.alt_speed,
        };

        char const *speeds_name[] = {
            "Speed",
            "Alternative Speed"
        };

        char const *labels_name[] = {
            "##EmulationSettingsSpeedSlider",
            "##EmulationSettingsAltSpeedSlider",
        };

        igTableSetupColumn("##EmulationSettingsSpeedLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##EmulationSettingsSpeedValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Speed & Alt speed
        for (i = 0; i < array_length(speeds); ++i) {
            char label[32];
            int new_speed;
            int min_speed;
            int max_speed;
            int fast_forward_speed;

            // Adjust the speed to be a percentage rounded to the nearest multiple of 5.
            new_speed = *speeds[i] * 100.0;
            new_speed += 2;
            new_speed -= new_speed % 5;

            // Minimum and maximum adjustable speed
            min_speed = 10;
            max_speed = 500;

            // Adjust the "fast-forward" speed (which is represented as `speed <= 0.0`) as a number
            // above `max_speed` to enable it by dragging the slider to the right as far as possible.
            fast_forward_speed = max_speed + 1;

            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();
            igTextWrapped(speeds_name[i]);

            igTableNextColumn();

            if (new_speed <= 0) {
                new_speed = fast_forward_speed;
                snprintf(label, sizeof(label), "Fast forward");
            } else {
                // The 4 % are here to escape it twice, ensuring that igSliderFloat doesn't fail when
                // parsing the format string.
                snprintf(label, sizeof(label), "%i%%%%", new_speed);
            }

            if (igSliderInt(
                labels_name[i],
                &new_speed,
                min_speed,
                fast_forward_speed,
                label,
                ImGuiSliderFlags_AlwaysClamp
            )) {
                if (new_speed >= fast_forward_speed || new_speed <= 0)
                    *speeds[i] = -1.0;
                else {
                    // Round to nearest multiple of 5 and normalize
                    new_speed = new_speed + 2;
                    new_speed -= new_speed % 5;
                    *speeds[i] = new_speed / 100.0;
                }
                app_emulator_settings(app);
            }
        }

        igEndTable();
    }

    igSeparatorText("Backup Storage");

    if (igBeginTable("##EmulationSettingsBackupStorage", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##EmulationSettingsBackupStorageLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##EmulationSettingsBackupStorageValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Backup Storage Auto-Detect
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Auto-Detect");

        igTableNextColumn();
        igCheckbox("##BackupStorageTypeAutoDetect", &app->settings.emulation.backup_storage.autodetect);

        // Backup Storage Type
        igBeginDisabled(app->settings.emulation.backup_storage.autodetect);
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Type");

        igTableNextColumn();
        igCombo_Str_arr("##BackupStorageType", (int *)&app->settings.emulation.backup_storage.type, backup_storage_names, array_length(backup_storage_names), 0);
        igEndDisabled();

        igEndTable();
    }

    igSeparatorText("GPIO Devices");

    if (igBeginTable("##EmulationSettingsGPIODevices", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##EmulationSettingsGPIODevicesLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##EmulationSettingsGPIODevicesValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // GPIO Device Auto-Detect
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Auto-Detect");

        igTableNextColumn();
        igCheckbox("##GPIODeviceTypeAutoDetect", &app->settings.emulation.gpio_device.autodetect);

        // GPIO Device Type
        igBeginDisabled(app->settings.emulation.gpio_device.autodetect);
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Type");

        igTableNextColumn();
        igCombo_Str_arr("##GPIODeviceType", (int *)&app->settings.emulation.gpio_device.type, gpio_device_names, array_length(gpio_device_names), 0);
        igEndDisabled();

        igEndTable();
    }

    igSeparatorText("Misc");

    if (igBeginTable("##EmulationSettingsMisc", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##EmulationSettingsMiscLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##EmulationSettingsMiscValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Emulate the Prefetch Buffer
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Emulate the Prefetch Buffer");

        igTableNextColumn();
        igCheckbox("##PrefetchBuffer", &app->settings.emulation.prefetch_buffer);

        igEndTable();
    }
}

static
void
app_win_settings_video(
    struct app *app
) {
    int32_t display_size;
    ImGuiViewport *vp;
    uint32_t i;

    vp = igGetMainViewport();

    igTextWrapped("Video Settings");
    igSpacing();
    igSeparator();
    igSpacing();

    igSeparatorText("Display");

    if (igBeginTable("##VideoSettingsDisplay", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        char label[128];
        int32_t scale;

        igTableSetupColumn("##VideoSettingsDisplayLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##VideoSettingsDisplayValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Menubar Mode
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Menubar Mode");

        igTableNextColumn();
        if (igCombo_Str_arr("##MenubarMode", (int *)&app->settings.video.menubar_mode, menubar_mode_names, array_length(menubar_mode_names), 0)) {
            app->ui.display.resize_request_timer = DEFAULT_RESIZE_TIMER;
        }

        // Display Mode
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Display Mode");

        igTableNextColumn();
        if (igCombo_Str_arr("##DisplayMode", (int *)&app->settings.video.display_mode, display_mode_names, DISPLAY_MODE_LEN, 0)) {
            app_sdl_video_update_display_mode(app);
        }

        // Auto-Detect Scale
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Auto-Detect UI Scale");

        igTableNextColumn();
        if (igCheckbox("##AutoDetectScale", &app->settings.video.autodetect_scale)) {
            app->ui.request_scale_update = true;
        }

        // Scale
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("UI Scale");

        // Round to nearest multiple of 5 and normalize
        scale = app->settings.video.scale * 100.;
        scale += 2;
        scale -= scale % 5;

        // The 4 % are here to escape it twice, ensuring that igSliderFloat doesn't fail when
        // parsing the format string.
        snprintf(label, sizeof(label), "%i%%%%", scale);

        igTableNextColumn();
        igBeginDisabled(app->settings.video.autodetect_scale);
        if (igSliderInt(
            "##Scale",
            &scale,
            50,
            200,
            label,
            ImGuiSliderFlags_AlwaysClamp
        )) {
            // Round to nearest multiple of 5 and normalize
            scale = scale + 2;
            scale -= scale % 5;
            app->settings.video.scale = scale / 100.0;
            app->ui.request_scale_update = true;
        }
        igEndDisabled();

        // Display Size
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Display Size");

        igTableNextColumn();

        display_size = -1;
        for (i = 1; i < array_length(display_size_names) + 1; ++i) {
            if (
                   app->ui.display.game.outer.width == (uint32_t)round(GBA_SCREEN_WIDTH * i / app->ui.display_scale)
                && app->ui.display.game.outer.height == (uint32_t)round(GBA_SCREEN_HEIGHT * i / app->ui.display_scale)
            ) {
                display_size = i;
                break;
            }
        }

        if (igBeginCombo("##DisplaySize", display_size > 0 ? display_size_names[display_size - 1] : "<Other>", ImGuiComboFlags_None)) {
            for (i = 1; i < array_length(display_size_names) + 1; ++i) {
                bool is_selected;

                is_selected = (display_size == i);
                if (igSelectable_Bool(display_size_names[i - 1], is_selected, ImGuiSelectableFlags_None, (ImVec2){ 0.f, 0.f })) {
                    app->settings.video.display_size = i;
                    app->ui.display.resize_request_timer = DEFAULT_RESIZE_TIMER;
                }

                if (is_selected) {
                    igSetItemDefaultFocus();
                }
            }
            igEndCombo();
        }

        // Aspect Ratio
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Aspect Ratio");

        igTableNextColumn();
        if (igCombo_Str_arr("##AspectRatio", (int *)&app->settings.video.aspect_ratio, aspect_ratio_names, ASPECT_RATIO_LEN, 0)) {
            app_win_game_refresh_game_area(app);
        }

        // VSync
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("VSync");

        igTableNextColumn();
        if (igCheckbox("##VSync", &app->settings.video.vsync)) {
            SDL_GL_SetSwapInterval(app->settings.video.vsync);
        }

        igEndTable();
    }

    igSeparatorText("Filters");

    if (igBeginTable("##VideoSettingsFilters", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##VideoSettingsFiltersLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##VideoSettingsFiltersValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Texture Filter
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Texture Filter");

        igTableNextColumn();
        if (igCombo_Str_arr("##TextureFilters", (int *)&app->settings.video.texture_filter, texture_filters_names, TEXTURE_FILTER_LEN, 0)) {
            app_sdl_video_rebuild_pipeline(app);
        }

        // Color Filter
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Color Filter");

        igTableNextColumn();
        if (igCombo_Str_arr("##ColorFilter", (int *)&app->settings.video.pixel_color_filter, pixel_color_filters_names, PIXEL_COLOR_FILTER_LEN, 0)) {
            app_sdl_video_rebuild_pipeline(app);
        }

        // Scaling Filter
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Scaling Filter");

        igTableNextColumn();
        if (igCombo_Str_arr("##ScalingFilter", (int *)&app->settings.video.pixel_scaling_filter, pixel_scaling_filters_names, PIXEL_SCALING_FILTER_LEN, 0)) {
            app_sdl_video_rebuild_pipeline(app);
        }

        igEndTable();
    }

    igSeparatorText("Misc");

    if (igBeginTable("##VideoSettingsMisc", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##VideoSettingsMiscLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##VideoSettingsMiscValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Use System Directory For Screenshots
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Use System Directory For Screenshots");

        igTableNextColumn();
        igCheckbox("##UseSystemDirectoryForScreenshots", &app->settings.video.use_system_screenshot_dir_path);

        // Screenshot Directory
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Screenshot Directory");

        igBeginDisabled(app->settings.video.use_system_screenshot_dir_path);

        igTableNextColumn();
        igBeginDisabled(true);
        igInputText("##ScreenshotDirectory", app->settings.video.screenshot_dir_path, strlen(app->settings.video.screenshot_dir_path), ImGuiInputTextFlags_ReadOnly, NULL, NULL);
        igEndDisabled();
        igSameLine(0.0f, -1.0f);
        if (igButton("Choose", (ImVec2){ 50.f, 0.f})) {
            nfdresult_t result;
            nfdchar_t *path;

            result = NFD_PickFolder(
                &path,
                app->settings.video.screenshot_dir_path
            );

            if (result == NFD_OKAY) {
                free(app->settings.video.screenshot_dir_path);
                app->settings.video.screenshot_dir_path = strdup(path);
                NFD_FreePath(path);
            }
        }

        igEndDisabled();

        // Hide the cursor when the mouse is inactive
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Hide cursor when the mouse is inactive");

        igTableNextColumn();
        igCheckbox("##HideCursorWhenMouseInactive", &app->settings.video.hide_cursor_when_mouse_inactive);

        igEndTable();
    }

#ifdef WITH_DEBUGGER
    igSeparatorText("Debug");

    if (igBeginTable("##VideoSettingsDebug", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##VideoSettingsDebugLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##VideoSettingsDebugValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Enable BG layer X
        for (i = 0; i < array_length(app->settings.video.enable_bg_layers); ++i) {
            char label[32];

            snprintf(label, sizeof(label), "##BGLayer%u", i);

            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();
            igTextWrapped("BG Layer %u", i);

            igTableNextColumn();
            if (igCheckbox(label, &app->settings.video.enable_bg_layers[i])) {
                app_emulator_settings(app);
            }
        }

        // Enable OAM
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Sprites");

        igTableNextColumn();
        if (igCheckbox("##Sprites", &app->settings.video.enable_oam)) {
            app_emulator_settings(app);
        }

        igEndTable();
    }
#endif
}

static
void
app_win_settings_audio(
    struct app *app
) {
    ImGuiViewport *vp;
    float level;

    vp = igGetMainViewport();
    level = app->settings.audio.level * 100.f;

    igTextWrapped("Audio Settings");
    igSpacing();
    igSeparator();
    igSpacing();

    igSeparatorText("Volume");

    if (igBeginTable("##AudioSettings", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##AudioSettingsLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##AudioSettingsValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        // Mute
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Mute");

        igTableNextColumn();
        igCheckbox("##Mute", &app->settings.audio.mute);

        // Audio level
        igBeginDisabled(app->settings.audio.mute);
        igTableNextRow(ImGuiTableRowFlags_None, 0.f);
        igTableNextColumn();
        igTextWrapped("Audio Level");

        igTableNextColumn();
        if (igSliderFloat("##SoundLevel", &level, 0.0f, 100.0f, "%.0f%%", ImGuiSliderFlags_None)) {
            app->settings.audio.level = max(0.0f, min(level / 100.f, 1.f));
        }
        igEndDisabled();

        igEndTable();
    }

#ifdef WITH_DEBUGGER
    igSeparatorText("Debug");

    if (igBeginTable("##AudioSettingsDebug", 2, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
        igTableSetupColumn("##AudioSettingsDebugLabel", ImGuiTableColumnFlags_WidthFixed, vp->WorkSize.x / 5.f, 0);
        igTableSetupColumn("##AudioSettingsDebugValue", ImGuiTableColumnFlags_WidthStretch, 0.f, 0);

        uint32_t i;

        // Enable PSG Channel X
        for (i = 0; i < array_length(app->settings.audio.enable_psg_channels); ++i) {
            char label[32];

            snprintf(label, sizeof(label), "##PSGChannel%u", i);

            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();
            igTextWrapped("PSG Channel %u", i);

            igTableNextColumn();
            if (igCheckbox(label, &app->settings.audio.enable_psg_channels[i])) {
                app_emulator_settings(app);
            }
        }

        // Enable FIFO Channel X
        for (i = 0; i < array_length(app->settings.audio.enable_fifo_channels); ++i) {
            char label[32];

            snprintf(label, sizeof(label), "##FifoChannel%u", i);

            igTableNextRow(ImGuiTableRowFlags_None, 0.f);
            igTableNextColumn();
            igTextWrapped("Fifo Channel %u", i);

            igTableNextColumn();
            if (igCheckbox(label, &app->settings.audio.enable_fifo_channels[i])) {
                app_emulator_settings(app);
            }
        }

        igEndTable();
    }
#endif
}

static
void
app_win_settings_bindings_bind_keyboard(
    struct app *app,
    enum bind_actions bind
) {
    size_t j;

    struct keyboard_binding *keyboard_layers[] = {
        app->binds.keyboard,
        app->binds.keyboard_alt,
    };

    igTableNextRow(ImGuiTableRowFlags_None, 0.f);

    igTableNextColumn();
    igTextWrapped(binds_pretty_name[bind]);

    for (j = 0; j < 2; ++j) {
        struct keyboard_binding *keyboard_bind;
        char const *name;
        char label[128];

        keyboard_bind = &keyboard_layers[j][bind];
        name = app_bindings_keyboard_binding_to_str(keyboard_bind);

        if (keyboard_bind == app->ui.settings.keybindings_editor.keyboard_target) {
            snprintf(label, sizeof(label), ">> %s <<##BindingsSettingsKeyboard%zu", name ?: " ", bind * 10 + j);
        } else {
            snprintf(label, sizeof(label), "%s##BindingsSettingsKeyboard%zu", name ?: "", bind * 10 + j);
        }

        igTableNextColumn();
        if (igButton(label, (ImVec2){ -1.f, 0.f })) {
            app->ui.settings.keybindings_editor.keyboard_target = keyboard_bind;
            app->ui.settings.keybindings_editor.controller_target = NULL;
        }
    }
}

static
void
app_win_settings_bindings_bind_controller(
    struct app *app,
    size_t bind
) {
    size_t j;

    SDL_GameControllerButton *controller_layers[] = {
        app->binds.controller,
        app->binds.controller_alt,
    };

    igTableNextRow(ImGuiTableRowFlags_None, 0.f);

    igTableNextColumn();
    igTextWrapped(binds_pretty_name[bind]);

    for (j = 0; j < 2; ++j) {
        SDL_GameControllerButton *button;
        char const *name;
        char label[128];

        button = &controller_layers[j][bind];
        name = SDL_GameControllerGetStringForButton(*button);

        if (button == app->ui.settings.keybindings_editor.controller_target) {
            snprintf(label, sizeof(label), ">> %s <<##BindingsSettingsController%zu", name ?: " ", bind * 10 + j);
        } else {
            snprintf(label, sizeof(label), "%s##BindingsSettingsController%zu", name ?: "", bind * 10 + j);
        }

        igTableNextColumn();
        if (igButton(label, (ImVec2){ -1.f, 0.f })) {
            app->ui.settings.keybindings_editor.controller_target = button;
            app->ui.settings.keybindings_editor.keyboard_target = NULL;
        }
    }
}

static
void
app_win_settings_bindings(
    struct app *app
) {
    size_t bind;

    igTextWrapped("Bindings");
    igSpacing();
    igSeparator();
    igSpacing();

    if (igBeginTabBar("##BindingsSettings", ImGuiTabBarFlags_None)) {
        if (igBeginTabItem("Keyboard", NULL, ImGuiTabItemFlags_None)) {

            igSeparatorText("GBA");

            if (igBeginTable("##BindingsSettingsKeyboardGBA", 3, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
                igTableSetupColumn("##BindingsSettingsKeyboardGBALabel", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);
                igTableSetupColumn("##BindingsSettingsKeyboardGBABindMain", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);
                igTableSetupColumn("##BindingsSettingsKeyboardGBABindAlt", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);

                for (bind = BIND_GBA_MIN; bind <= BIND_GBA_MAX; ++bind) {
                    app_win_settings_bindings_bind_keyboard(app, bind);
                }

                igEndTable();
            }

            igSeparatorText("Emulator");

            if (igBeginTable("##BindingsSettingsKeyboardEmulator", 3, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
                igTableSetupColumn("##BindingsSettingsKeyboardEmulatorLabel", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);
                igTableSetupColumn("##BindingsSettingsKeyboardEmulatorBindMain", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);
                igTableSetupColumn("##BindingsSettingsKeyboardEmulatorBindAlt", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);

                for (bind = BIND_EMULATOR_MIN; bind <= BIND_EMULATOR_MAX; ++bind) {
                    app_win_settings_bindings_bind_keyboard(app, bind);
                }
                igEndTable();
            }

            igEndTabItem();
        }
        if (igBeginTabItem("Controller", NULL, ImGuiTabItemFlags_None)) {

            igSeparatorText("GBA");

            if (igBeginTable("##BindingsSettingsControllerGBA", 3, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
                igTableSetupColumn("##BindingsSettingsControllerGBALabel", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);
                igTableSetupColumn("##BindingsSettingsControllerGBABindMain", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);
                igTableSetupColumn("##BindingsSettingsControllerGBABindAlt", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);

                for (bind = BIND_GBA_MIN; bind <= BIND_GBA_MAX; ++bind) {
                    app_win_settings_bindings_bind_controller(app, bind);
                }

                igEndTable();
            }

            igSeparatorText("Emulator");

            if (igBeginTable("##BindingsSettingsControllerEmulator", 3, ImGuiTableFlags_None, (ImVec2){ .x = 0.f, .y = 0.f }, 0.f)) {
                igTableSetupColumn("##BindingsSettingsControllerEmulatorLabel", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);
                igTableSetupColumn("##BindingsSettingsControllerEmulatorBindMain", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);
                igTableSetupColumn("##BindingsSettingsControllerEmulatorBindAlt", ImGuiTableColumnFlags_WidthStretch, 1.f, 0);

                for (bind = BIND_EMULATOR_MIN; bind <= BIND_EMULATOR_MAX; ++bind) {
                    app_win_settings_bindings_bind_controller(app, bind);
                }
                igEndTable();
            }

            igEndTabItem();
        }
        igEndTabBar();
    }
}

static void (*menu_callbacks[MENU_MAX])(struct app *) = {
    [MENU_GENERAL] =                &app_win_settings_general,
    [MENU_EMULATION] =              &app_win_settings_emulation,
    [MENU_VIDEO] =                  &app_win_settings_video,
    [MENU_AUDIO] =                  &app_win_settings_audio,
    [MENU_BINDINGS] =               &app_win_settings_bindings,
};

void
app_win_settings(
    struct app *app
) {
    ImGuiViewport *vp;

    vp = igGetMainViewport();

    igSetNextWindowPos(vp->WorkPos, ImGuiCond_Always, (ImVec2){0.f, 0.f});
    igSetNextWindowSize(vp->WorkSize, ImGuiCond_Always);

    if (igBegin(
        "Settings",
        NULL,
        ImGuiWindowFlags_None
          | ImGuiWindowFlags_NoMove
          | ImGuiWindowFlags_NoResize
          | ImGuiWindowFlags_AlwaysAutoResize
          | ImGuiWindowFlags_NoTitleBar
          | ImGuiWindowFlags_NoNavInputs
          | ImGuiWindowFlags_NoNavFocus
    )) {
        uint32_t i;

        if (igBeginChild_Str("##SettingsMenu", (ImVec2){ vp->WorkSize.x / 4.f, 0.f}, ImGuiChildFlags_Border , ImGuiWindowFlags_None)) {
            for (i = 0; i < MENU_MAX; ++i) {
                if (igSelectable_Bool(menu_names[i], app->ui.settings.menu == i, ImGuiSelectableFlags_None, (ImVec2){ 0.f, 0.f})) {
                    app->ui.settings.menu = i;
                }
            }
            igEndChild();
        }

        igSameLine(0.0f, -1.0f);

        igBeginGroup();

        if (igBeginChild_Str("##SettingsVariables", (ImVec2){ 0.f, -igGetFrameHeightWithSpacing()}, ImGuiChildFlags_Border, ImGuiWindowFlags_None)) {
            if (menu_callbacks[app->ui.settings.menu]) {
                menu_callbacks[app->ui.settings.menu](app);
            }
            igEndChild();
        }

        if (igButton("Close", (ImVec2){ 0.f, 0.f})) {
            app->ui.settings.open = false;
        }

        igEndGroup();

        igEnd();
    }
}
