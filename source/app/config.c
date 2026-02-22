/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <errno.h>
#include <mjson.h>
#include "hades.h"
#include "app/app.h"
#include "compat.h"

static char const *gamepad_layers_name[] = {
    "gamepad",
    "gamepad_alt"
};

static char const *keyboard_layers_name[] = {
    "keyboard",
    "keyboard_alt",
};

/*
** Default value for all options, before config and argument parsing.
*/
void
app_config_default_settings(
    struct app *app
) {
    struct settings *settings;

    settings = &app->settings;
    settings->general.show_fps = false;
    settings->general.startup.start_last_played_game = false;
    settings->general.startup.pause_when_game_resets = false;
    settings->general.window.pause_game_when_window_loses_focus = false;
    settings->general.window.hide_cursor_when_mouse_inactive = true;
    settings->general.window.hide_pause_overlay = false;
    settings->general.directories.backup.use_dedicated_directory = false;
    settings->general.directories.backup.path = strdup("saves/");
    settings->general.directories.quicksave.use_dedicated_directory = false;
    settings->general.directories.quicksave.path = strdup("saves/");
    settings->general.directories.screenshot.use_system_directory = true;
    settings->general.directories.screenshot.path = strdup("screenshots/");
    settings->emulation.bios_path = strdup("./bios.bin");
    settings->emulation.skip_bios_intro = false;
    settings->emulation.speed = 1.0;
    settings->emulation.alt_speed = -1.0;
    settings->emulation.backup_storage.autodetect = true;
    settings->emulation.backup_storage.type = BACKUP_NONE;
    settings->emulation.gpio_device.autodetect = true;
    settings->emulation.gpio_device.type = GPIO_NONE;
    settings->emulation.prefetch_buffer = true;
    settings->video.enable_oam = true;
    memset(settings->video.enable_bg_layers, true, sizeof(settings->video.enable_bg_layers));
    memset(settings->audio.enable_psg_channels, true, sizeof(settings->audio.enable_psg_channels));
    memset(settings->audio.enable_fifo_channels, true, sizeof(settings->audio.enable_fifo_channels));
    settings->video.menubar_mode = MENUBAR_MODE_PINNED;
    settings->video.display_mode = DISPLAY_MODE_WINDOW;
    settings->video.display_size = 3;
    settings->video.autodetect_scale = true;
    settings->video.scale = 1.0f;
    settings->video.aspect_ratio = ASPECT_RATIO_BORDERS;
    settings->video.vsync = false;
    settings->video.texture_filter = TEXTURE_FILTER_NEAREST;
    settings->video.pixel_color_filter = PIXEL_COLOR_FILTER_COLOR_CORRECTION;
    settings->video.pixel_scaling_filter = PIXEL_SCALING_FILTER_LCD_GRID;
    settings->audio.mute = false;
    settings->audio.level = 1.0f;
}

/*
** Default value for all options, before config and argument parsing.
*/
void
app_config_default_bindings(
    struct app *app
) {
    size_t i;

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        app_bindings_keyboard_binding_build(&app->binds.keyboard[i], SDLK_UNKNOWN, false, false, false);
        app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[i], SDLK_UNKNOWN, false, false, false);
    }

    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_A], SDL_GetKeyFromName("P"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_B], SDL_GetKeyFromName("L"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_L], SDL_GetKeyFromName("E"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_R], SDL_GetKeyFromName("O"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_UP], SDL_GetKeyFromName("W"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_DOWN], SDL_GetKeyFromName("S"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_LEFT], SDL_GetKeyFromName("A"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_RIGHT], SDL_GetKeyFromName("D"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_START], SDL_GetKeyFromName("Return"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_GBA_SELECT], SDL_GetKeyFromName("Backspace"), false, false, false);

    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_RESET], SDL_GetKeyFromName("R"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_MUTE], SDL_GetKeyFromName("M"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_PAUSE], SDL_GetKeyFromName("P"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_STOP], SDL_GetKeyFromName("Q"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_SHOW_FPS], SDL_GetKeyFromName("F"), true, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_SETTINGS], SDL_GetKeyFromName("Escape"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_FULLSCREEN], SDL_GetKeyFromName("F11"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_SCREENSHOT], SDL_GetKeyFromName("F12"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_ALT_SPEED_HOLD], SDL_GetKeyFromName("Space"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_ALT_SPEED_TOGGLE], SDL_GetKeyFromName("Space"), true, false, false);

    for (i = 0; i < MAX_QUICKSAVES && i < 10; ++i) {
        app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_QUICKSAVE_1 + i], SDL_GetKeyFromName("F1") + i, false, false, false);
        app_bindings_keyboard_binding_build(&app->binds.keyboard[BIND_EMULATOR_QUICKLOAD_1 + i], SDL_GetKeyFromName("F1") + i, false, true, false);
    }

    app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[BIND_GBA_UP], SDL_GetKeyFromName("Up"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[BIND_GBA_DOWN], SDL_GetKeyFromName("Down"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[BIND_GBA_LEFT], SDL_GetKeyFromName("Left"), false, false, false);
    app_bindings_keyboard_binding_build(&app->binds.keyboard_alt[BIND_GBA_RIGHT], SDL_GetKeyFromName("Right"), false, false, false);

    for (i = BIND_MIN; i < BIND_MAX; ++i) {
        app->binds.gamepad[i] = SDL_GAMEPAD_BUTTON_INVALID;
        app->binds.gamepad_alt[i] = SDL_GAMEPAD_BUTTON_INVALID;
    }

    app->binds.gamepad[BIND_GBA_A] = SDL_GAMEPAD_BUTTON_SOUTH;
    app->binds.gamepad[BIND_GBA_B] = SDL_GAMEPAD_BUTTON_EAST;
    app->binds.gamepad[BIND_GBA_L] = SDL_GAMEPAD_BUTTON_LEFT_SHOULDER;
    app->binds.gamepad[BIND_GBA_R] = SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER;
    app->binds.gamepad[BIND_GBA_UP] = SDL_GAMEPAD_BUTTON_DPAD_UP;
    app->binds.gamepad[BIND_GBA_DOWN] = SDL_GAMEPAD_BUTTON_DPAD_DOWN;
    app->binds.gamepad[BIND_GBA_LEFT] = SDL_GAMEPAD_BUTTON_DPAD_LEFT;
    app->binds.gamepad[BIND_GBA_RIGHT] = SDL_GAMEPAD_BUTTON_DPAD_RIGHT;
    app->binds.gamepad[BIND_GBA_START] = SDL_GAMEPAD_BUTTON_START;
    app->binds.gamepad[BIND_GBA_SELECT] = SDL_GAMEPAD_BUTTON_BACK;
    app->binds.gamepad[BIND_EMULATOR_MENUBAR] = SDL_GAMEPAD_BUTTON_GUIDE;
    app->binds.gamepad[BIND_EMULATOR_ALT_SPEED_TOGGLE] = SDL_GAMEPAD_BUTTON_RIGHT_STICK;
#if SDL_VERSION_ATLEAST(2, 0, 14)
    app->binds.gamepad[BIND_EMULATOR_ALT_SPEED_HOLD] = SDL_GAMEPAD_BUTTON_TOUCHPAD;
#endif

    app->binds.gamepad_alt[BIND_GBA_A] = SDL_GAMEPAD_BUTTON_NORTH;
    app->binds.gamepad_alt[BIND_GBA_B] = SDL_GAMEPAD_BUTTON_WEST;
}

void
app_config_load(
    struct app *app
) {
    char const *path;
    FILE *config_file;
    char *data;
    size_t data_len;

    path = app_path_config(app);
    config_file = hs_fopen(path, "rb");
    if (!config_file) {
        logln(HS_ERROR, "Failed to open \"%s\": %s", path, strerror(errno));
        return;
    }

    fseek(config_file, 0, SEEK_END);
    data_len = ftell(config_file);
    rewind(config_file);

    data = calloc(1, data_len);
    hs_assert(data);

    if (fread(data, 1, data_len, config_file) != data_len) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to read %s: %s.",
            path,
            strerror(errno)
        );
        goto end;
    }

    // File
    {
        char str[4096];
        char *recent_rom_path;
        int i;

        if (mjson_get_string(data, data_len, "$.file.bios", str, sizeof(str)) > 0) {
            free(app->settings.emulation.bios_path);
            app->settings.emulation.bios_path = strdup(str);
        }

        recent_rom_path = strdup("$.file.recent_roms[0]");
        for (i = 0; i < MAX_RECENT_ROMS; ++i) {
            recent_rom_path[strlen(recent_rom_path) - 2] = '0' + i;
            if (mjson_get_string(data, data_len, recent_rom_path, str, sizeof(str)) > 0) {
                free(app->file.recent_roms[i]);
                app->file.recent_roms[i] = strdup(str);
            }
        }
        free(recent_rom_path);
    }

    // General
    {
        char str[4096];
        int b;

        if (mjson_get_bool(data, data_len, "$.general.show_fps", &b)) {
            app->settings.general.show_fps = b;
        }

        if (mjson_get_bool(data, data_len, "$.general.startup.start_last_played_game", &b)) {
            app->settings.general.startup.start_last_played_game = b;
        }

        if (mjson_get_bool(data, data_len, "$.general.startup.pause_when_game_resets", &b)) {
            app->settings.general.startup.pause_when_game_resets = b;
        }

        if (mjson_get_bool(data, data_len, "$.general.window.pause_game_when_window_loses_focus", &b)) {
            app->settings.general.window.pause_game_when_window_loses_focus = b;
        }

        if (mjson_get_bool(data, data_len, "$.general.window.hide_cursor_when_mouse_inactive", &b)) {
            app->settings.general.window.hide_cursor_when_mouse_inactive = b;
        }

        if (mjson_get_bool(data, data_len, "$.general.window.hide_pause_overlay", &b)) {
            app->settings.general.window.hide_pause_overlay = b;
        }

        if (mjson_get_bool(data, data_len, "$.general.directories.backup.use_dedicated_directory", &b)) {
            app->settings.general.directories.backup.use_dedicated_directory = b;
        }

        if (mjson_get_string(data, data_len, "$.general.directories.backup.path", str, sizeof(str)) > 0) {
            free(app->settings.general.directories.backup.path);
            app->settings.general.directories.backup.path = strdup(str);
        }

        if (mjson_get_bool(data, data_len, "$.general.directories.quicksave.use_dedicated_directory", &b)) {
            app->settings.general.directories.quicksave.use_dedicated_directory = b;
        }

        if (mjson_get_string(data, data_len, "$.general.directories.quicksave.path", str, sizeof(str)) > 0) {
            free(app->settings.general.directories.quicksave.path);
            app->settings.general.directories.quicksave.path = strdup(str);
        }

        if (mjson_get_bool(data, data_len, "$.general.directories.screenshot.use_system_directory", &b)) {
            app->settings.general.directories.screenshot.use_system_directory = b;
        }

        if (mjson_get_string(data, data_len, "$.general.directories.screenshot.path", str, sizeof(str)) > 0) {
            free(app->settings.general.directories.screenshot.path);
            app->settings.general.directories.screenshot.path = strdup(str);
        }
    }

    // Emulation
    {
        int b;
        double d;

        if (mjson_get_bool(data, data_len, "$.emulation.skip_bios", &b)) {
            app->settings.emulation.skip_bios_intro = b;
        }

        if (mjson_get_number(data, data_len, "$.emulation.speed", &d)) {
            app->settings.emulation.speed = (float)d;
        }

        if (mjson_get_number(data, data_len, "$.emulation.alt_speed", &d)) {
            app->settings.emulation.alt_speed = (float)d;
        }

        if (mjson_get_bool(data, data_len, "$.emulation.backup_storage.autodetect", &b)) {
            app->settings.emulation.backup_storage.autodetect = b;
        }

        if (mjson_get_number(data, data_len, "$.emulation.backup_storage.type", &d)) {
            app->settings.emulation.backup_storage.type = max(BACKUP_MIN, min((int)d, BACKUP_MAX));
        }

        if (mjson_get_bool(data, data_len, "$.emulation.gpio.autodetect", &b)) {
            app->settings.emulation.gpio_device.autodetect = b;
        }

        if (mjson_get_number(data, data_len, "$.emulation.gpio.type", &d)) {
            app->settings.emulation.gpio_device.type = max(GPIO_MIN, min((int)d, GPIO_MAX));
        }

        if (mjson_get_bool(data, data_len, "$.emulation.prefetch_buffer", &b)) {
            app->settings.emulation.prefetch_buffer = b;
        }
    }

    // Video
    {
        int b;
        double d;

        if (mjson_get_number(data, data_len, "$.video.menubar_mode", &d)) {
            app->settings.video.menubar_mode = (int)d;
            app->settings.video.menubar_mode = max(MENUBAR_MODE_MIN, min(app->settings.video.menubar_mode, MENUBAR_MODE_MAX));
        }

        if (mjson_get_number(data, data_len, "$.video.display_mode", &d)) {
            app->settings.video.display_mode = (int)d;
            app->settings.video.display_mode = max(DISPLAY_MODE_MIN, min(app->settings.video.display_mode, DISPLAY_MODE_MAX));
        }

        if (mjson_get_bool(data, data_len, "$.video.autodetect_scale", &b)) {
            app->settings.video.autodetect_scale = b;
        }

        if (mjson_get_number(data, data_len, "$.video.scale", &d)) {
            app->settings.video.scale = (float)d;
        }

        if (mjson_get_number(data, data_len, "$.video.display_size", &d)) {
            app->settings.video.display_size = (int)d;
            app->settings.video.display_size = max(1, min(app->settings.video.display_size, 5));
        }

        if (mjson_get_number(data, data_len, "$.video.aspect_ratio", &d)) {
            app->settings.video.aspect_ratio = (int)d;
            app->settings.video.aspect_ratio = max(ASPECT_RATIO_MIN, min(app->settings.video.aspect_ratio, ASPECT_RATIO_MAX));
        }

        if (mjson_get_bool(data, data_len, "$.video.vsync", &b)) {
            app->settings.video.vsync = b;
        }

        if (mjson_get_bool(data, data_len, "$.video.enable_frame_skip", &b)) {
            app->settings.video.enable_frame_skip = b;
        }

        if (mjson_get_number(data, data_len, "$.video.frame_skip_counter", &d)) {
            app->settings.video.frame_skip_counter = (int)d;
        }

        if (mjson_get_number(data, data_len, "$.video.texture_filter", &d)) {
            app->settings.video.texture_filter = (int)d;
            app->settings.video.texture_filter = max(TEXTURE_FILTER_MIN, min(app->settings.video.texture_filter, TEXTURE_FILTER_MAX));
        }

        if (mjson_get_number(data, data_len, "$.video.pixel_color_filter", &d)) {
            app->settings.video.pixel_color_filter = (int)d;
            app->settings.video.pixel_color_filter = max(PIXEL_COLOR_FILTER_MIN, min(app->settings.video.pixel_color_filter, PIXEL_COLOR_FILTER_MAX));
        }

        if (mjson_get_number(data, data_len, "$.video.pixel_scaling_filter", &d)) {
            app->settings.video.pixel_scaling_filter = (int)d;
            app->settings.video.pixel_scaling_filter = max(PIXEL_SCALING_FILTER_MIN, min(app->settings.video.pixel_scaling_filter, PIXEL_SCALING_FILTER_MAX));
        }
    }

    // Audio
    {
        int b;
        double d;

        if (mjson_get_bool(data, data_len, "$.audio.mute", &b)) {
            app->settings.audio.mute = b;
        }

        if (mjson_get_number(data, data_len, "$.audio.level", &d)) {
            app->settings.audio.level = (float)d;
            app->settings.audio.level = max(0.f, min(app->settings.audio.level, 1.f));
        }
    }

    // Binds
    {
        char path[256];
        char str[256];
        size_t layer;
        size_t bind;
        int len;

        struct keyboard_binding *keyboard_layers[] = {
            app->binds.keyboard,
            app->binds.keyboard_alt,
        };

        SDL_GamepadButton *gamepad_layers[] = {
            app->binds.gamepad,
            app->binds.gamepad_alt,
        };

        for (layer = 0; layer < array_length(keyboard_layers_name); ++layer) {
            for (bind = BIND_MIN; bind < BIND_MAX; ++bind) {
                struct keyboard_binding tmp;
                int b;

                memset(&tmp, 0, sizeof(tmp));

                snprintf(path, sizeof(path), "$.binds.%s.%s.key", keyboard_layers_name[layer], binds_slug[bind]);

                len = mjson_get_string(data, data_len, path, str, sizeof(str));
                if (len < 0) {
                    continue;
                }

                tmp.key = SDL_GetKeyFromName(str);
                if (tmp.key == SDLK_UNKNOWN) {
                    // Set the binding for that key to be invalid.
                    keyboard_layers[layer][bind] = tmp;
                    continue;
                }

                snprintf(path, sizeof(path), "$.binds.%s.%s.ctrl", keyboard_layers_name[layer], binds_slug[bind]);
                if (mjson_get_bool(data, data_len, path, &b)) {
                    tmp.ctrl = b;
                }

                snprintf(path, sizeof(path), "$.binds.%s.%s.alt", keyboard_layers_name[layer], binds_slug[bind]);
                if (mjson_get_bool(data, data_len, path, &b)) {
                    tmp.alt = b;
                }

                snprintf(path, sizeof(path), "$.binds.%s.%s.shift", keyboard_layers_name[layer], binds_slug[bind]);
                if (mjson_get_bool(data, data_len, path, &b)) {
                    tmp.shift = b;
                }

                // Clear any binding with that key and then set the binding
                app_bindings_keyboard_binding_clear(app, &tmp);
                keyboard_layers[layer][bind] = tmp;
            }
        }

        for (layer = 0; layer < array_length(gamepad_layers_name); ++layer) {
            for (bind = BIND_MIN; bind < BIND_MAX; ++bind) {
                SDL_GamepadButton button;

                snprintf(path, sizeof(path), "$.binds.%s.%s", gamepad_layers_name[layer], binds_slug[bind]);

                len = mjson_get_string(data, data_len, path, str, sizeof(str));
                if (len < 0) {
                    continue;
                }

                button = SDL_GetGamepadButtonFromString(str);

                // Clear any binding with that button and then set the binding
                if (button != SDL_GAMEPAD_BUTTON_INVALID) {
                    app_bindings_gamepad_binding_clear(app, button);
                }

                gamepad_layers[layer][bind] = button;
            }
        }
    }

end:
    free(data);
    fclose(config_file);
}

void
app_config_save(
    struct app *app
) {
    char const *path;
    FILE *config_file;
    int out;
    char *data;
    char *pretty_data;

    data = NULL;
    pretty_data = NULL;

    path = app_path_config(app);
    config_file = hs_fopen(path, "w");
    if (!config_file) {
        logln(HS_ERROR, "Failed to open \"%s\": %s", path, strerror(errno));
        return;
    }

    data = mjson_aprintf(
        STR({
            // File
            "file": {
                "bios": %Q,
                "recent_roms": [ %Q, %Q, %Q, %Q, %Q, %Q, %Q, %Q, %Q, %Q ]
            },

            // General
            "general": {
                "show_fps": %B,
                "startup": {
                    "start_last_played_game": %B,
                    "pause_when_game_resets": %B
                },
                "window": {
                    "pause_game_when_window_loses_focus": %B,
                    "hide_cursor_when_mouse_inactive": %B,
                    "hide_pause_overlay": %B
                },
                "directories": {
                    "backup": {
                        "use_dedicated_directory": %B,
                        "path": %Q
                    },
                    "quicksave": {
                        "use_dedicated_directory": %B,
                        "path": %Q
                    },
                    "screenshot": {
                        "use_system_directory": %B,
                        "path": %Q
                    }
                }
            },

            // Emulation
            "emulation": {
                "skip_bios": %B,
                "speed": %g,
                "alt_speed": %g,
                "backup_storage": {
                    "autodetect": %B,
                    "type": %d
                },
                "gpio": {
                    "autodetect": %B,
                    "type": %d
                },
                "prefetch_buffer": %B
            },

            // Video
            "video": {
                "menubar_mode": %d,
                "display_mode": %d,
                "autodetect_scale": %B,
                "scale": %g,
                "display_size": %d,
                "aspect_ratio": %d,
                "vsync": %B,
                "enable_frame_skip": %B,
                "frame_skip_counter": %d,
                "texture_filter": %d,
                "pixel_color_filter": %d,
                "pixel_scaling_filter": %d,
            },

            // Audio
            "audio": {
                "mute": %B,
                "level": %g
            },
        }),
        app->settings.emulation.bios_path,
        app->file.recent_roms[0],
        app->file.recent_roms[1],
        app->file.recent_roms[2],
        app->file.recent_roms[3],
        app->file.recent_roms[4],
        app->file.recent_roms[5],
        app->file.recent_roms[6],
        app->file.recent_roms[7],
        app->file.recent_roms[8],
        app->file.recent_roms[9],
        (int)app->settings.general.show_fps,
        (int)app->settings.general.startup.start_last_played_game,
        (int)app->settings.general.startup.pause_when_game_resets,
        (int)app->settings.general.window.pause_game_when_window_loses_focus,
        (int)app->settings.general.window.hide_cursor_when_mouse_inactive,
        (int)app->settings.general.window.hide_pause_overlay,
        (int)app->settings.general.directories.backup.use_dedicated_directory,
        app->settings.general.directories.backup.path,
        (int)app->settings.general.directories.quicksave.use_dedicated_directory,
        app->settings.general.directories.quicksave.path,
        (int)app->settings.general.directories.screenshot.use_system_directory,
        app->settings.general.directories.screenshot.path,
        (int)app->settings.emulation.skip_bios_intro,
        app->settings.emulation.speed,
        app->settings.emulation.alt_speed,
        (int)app->settings.emulation.backup_storage.autodetect,
        (int)app->settings.emulation.backup_storage.type,
        (int)app->settings.emulation.gpio_device.autodetect,
        (int)app->settings.emulation.gpio_device.type,
        (int)app->settings.emulation.prefetch_buffer,
        (int)app->settings.video.menubar_mode,
        (int)app->settings.video.display_mode,
        (int)app->settings.video.autodetect_scale,
        app->settings.video.scale,
        (int)app->settings.video.display_size,
        (int)app->settings.video.aspect_ratio,
        (int)app->settings.video.vsync,
        (int)app->settings.video.enable_frame_skip,
        (int)app->settings.video.frame_skip_counter,
        (int)app->settings.video.texture_filter,
        (int)app->settings.video.pixel_color_filter,
        (int)app->settings.video.pixel_scaling_filter,
        (int)app->settings.audio.mute,
        app->settings.audio.level
    );

    if (!data) {
        logln(HS_ERROR, "Failed to write the configuration to \"%s\": the formatted JSON is invalid.", path);
        goto end;
    }

    // Add binds dynamically
    {
        char str[256];
        size_t layer;
        size_t bind;

        struct keyboard_binding *keyboard_layers[] = {
            app->binds.keyboard,
            app->binds.keyboard_alt,
        };

        SDL_GamepadButton *gamepad_layers[] = {
            app->binds.gamepad,
            app->binds.gamepad_alt,
        };

        for (layer = 0; layer < array_length(keyboard_layers_name); ++layer) {
            for (bind = BIND_MIN; bind < BIND_MAX; ++bind) {
                struct keyboard_binding const *keyboard_bind;
                char const *key_name;
                char *tmp_data;

                keyboard_bind = &keyboard_layers[layer][bind];
                key_name = SDL_GetKeyName(keyboard_bind->key);

                // Build a temporary JSON containing our bind
                mjson_snprintf(
                    str,
                    sizeof(str),
                    STR({
                        "binds": {
                            "%s": {
                                "%s": {
                                    "key": "%s",
                                    "ctrl": %B,
                                    "alt": %B,
                                    "shift": %B
                                },
                            },
                        },
                    }),
                    keyboard_layers_name[layer],
                    binds_slug[bind],
                    key_name ?: "",
                    keyboard_bind->ctrl,
                    keyboard_bind->alt,
                    keyboard_bind->shift
                );

                tmp_data = NULL;

                // Merge that json with the previous one into `tmp_data`.
                mjson_merge(data, strlen(data), str, strlen(str), mjson_print_dynamic_buf, &tmp_data);

                // Swap `data` with `tmp_data`.
                free(data);
                data = tmp_data;
            }
        }

        for (layer = 0; layer < array_length(gamepad_layers_name); ++layer) {
            for (bind = BIND_MIN; bind < BIND_MAX; ++bind) {
                char const *button_name;
                char *tmp_data;

                button_name = SDL_GetGamepadStringForButton(gamepad_layers[layer][bind]);

                // Build a temporary JSON containing our bind
                snprintf(
                    str,
                    sizeof(str),
                    STR({
                        "binds": {
                            "%s": {
                                "%s": "%s"
                            },
                        },
                    }),
                    gamepad_layers_name[layer],
                    binds_slug[bind],
                    button_name ?: ""
                );

                tmp_data = NULL;

                // Merge that json with the previous one into `tmp_data`.
                mjson_merge(data, strlen(data), str, strlen(str), mjson_print_dynamic_buf, &tmp_data);

                // Swap `data` with `tmp_data`.
                free(data);
                data = tmp_data;
            }
        }
    }

    out = mjson_pretty(data, strlen(data), "  ", mjson_print_dynamic_buf, &pretty_data);

    if (out < 0) {
        logln(HS_ERROR, "Failed to write the configuration to \"%s\": the formatted JSON is invalid.", path);
        goto end;
    }

    if (fwrite(pretty_data, strlen(pretty_data), 1, config_file) != 1) {
        logln(HS_ERROR, "Failed to write the configuration to \"%s\": %s.", path, strerror(errno));
    }

end:
    free(data);
    free(pretty_data);
    fclose(config_file);
}

/*
** Push the current game's path at the top of the "Open recent" list.
*/
void
app_config_push_recent_rom(
    struct app *app,
    char const *rom_path
) {
    char *new_recent_roms[MAX_RECENT_ROMS];
    char *rom_abs_path;
    int32_t i;
    int32_t j;

    memset(new_recent_roms, 0, sizeof(new_recent_roms));

    rom_abs_path = hs_abspath(rom_path);
    new_recent_roms[0] = rom_abs_path;

    j = 0;
    for (i = 1; i < MAX_RECENT_ROMS && j < MAX_RECENT_ROMS; ++j) {
        if (!app->file.recent_roms[j] || strcmp(app->file.recent_roms[j], rom_abs_path)) {
            new_recent_roms[i] = app->file.recent_roms[j];
            ++i;
        } else {
            free(app->file.recent_roms[j]);
        }
    }

    while (j < MAX_RECENT_ROMS) {
        free(app->file.recent_roms[j]);
        ++j;
    }

    memcpy(app->file.recent_roms, new_recent_roms, sizeof(new_recent_roms));
}
