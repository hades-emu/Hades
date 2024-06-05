/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <errno.h>
#include <mjson.h>
#include "hades.h"
#include "app/app.h"
#include "compat.h"

void
app_config_load(
    struct app *app
) {
    char const *path;
    char data[4096];
    FILE *config_file;
    size_t data_len;

    path = app_path_config(app);
    config_file = hs_fopen(path, "r");
    if (!config_file) {
        logln(HS_ERROR, "Failed to open \"%s\": %s", path, strerror(errno));
        return;
    }

    data_len = fread(data, 1, sizeof(data) - 1, config_file);

    if (data_len == 0 && ferror(config_file)) {
        logln(HS_ERROR, "Failed to read \"%s\": %s", path, strerror(errno));
        goto end;
    }

    data[data_len] = '\0';

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

    // Emulation
    {
        int b;
        double d;

        if (mjson_get_number(data, data_len, "$.emulation.speed", &d)) {
            app->settings.emulation.speed = max(0.0, min(d, 5.0));
        }

        if (mjson_get_bool(data, data_len, "$.emulation.fast_forward", &b)) {
            app->settings.emulation.fast_forward = b;
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

        if (mjson_get_bool(data, data_len, "$.emulation.skip_bios", &b)) {
            app->settings.emulation.skip_bios = b;
        }
    }

    // Video
    {
        int b;
        double d;

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

    // Video
    {
        int b;
        double d;

        if (mjson_get_bool(data, data_len, "$.audio.mute", &b)) {
            app->settings.audio.mute = b;
        }

        if (mjson_get_number(data, data_len, "$.audio.level", &d)) {
            app->settings.audio.level = d;
            app->settings.audio.level = max(0.f, min(app->settings.audio.level, 1.f));
        }
    }

    // Misc
    {
        int b;

        if (mjson_get_bool(data, data_len, "$.misc.pause_when_window_inactive", &b)) {
            app->settings.misc.pause_when_window_inactive = b;
        }

        if (mjson_get_bool(data, data_len, "$.misc.pause_when_game_resets", &b)) {
            app->settings.misc.pause_when_game_resets = b;
        }
    }

    // Binds
    {
        char path[256];
        char str[256];
        size_t layer;
        size_t bind;
        int len;

        static char const *layers_name[] = {
            "keyboard",
            "keyboard_alt",
            "controller",
            "controller_alt"
        };

        for (layer = 0; layer < 4; ++layer) {
            for (bind = BIND_MIN; bind < BIND_MAX; ++bind) {
                snprintf(path, sizeof(path), "$.binds.%s.%s", layers_name[layer], binds_slug[bind]);

                len = mjson_get_string(data, data_len, path, str, sizeof(str));
                if (len < 0) {
                    continue;
                }

                if (layer <= 1) { // Keyboard
                    SDL_Keycode *target;
                    SDL_Keycode key;

                    target = (layer == 0) ? &app->binds.keyboard[bind] : &app->binds.keyboard_alt[bind];
                    key = SDL_GetKeyFromName(str);

                    // Clear any binding with that key and then set the binding
                    if (key != SDLK_UNKNOWN) {
                        app_bindings_keyboard_clear(app, key);
                    }
                    *target = key;
                } else { // Controller
                    SDL_GameControllerButton *target;
                    SDL_GameControllerButton button;

                    target = (layer == 2) ? &app->binds.controller[bind] : &app->binds.controller_alt[bind];
                    button = SDL_GameControllerGetButtonFromString(str);

                    // Clear any binding with that button and then set the binding
                    if (button != SDL_CONTROLLER_BUTTON_INVALID) {
                        app_bindings_controller_clear(app, button);
                    }
                    *target = button;
                }
            }
        }
    }

end:
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
    char *keyboard_binds_name[BIND_MAX];
    size_t i;

    data = NULL;
    pretty_data = NULL;

    path = app_path_config(app);
    config_file = hs_fopen(path, "w");
    if (!config_file) {
        logln(HS_ERROR, "Failed to open \"%s\": %s", path, strerror(errno));
        return;
    }

    // We need to fill `keyboard_binds_name` with a copy of all the keyboard's bind name because
    // the output of `SDL_GetKeyName()` lasts only until the next call to the function.
    for (i = 0; i < BIND_MAX; ++i) {
        keyboard_binds_name[i] = strdup(SDL_GetKeyName(app->binds.keyboard[i]));
    }

    data = mjson_aprintf(
        STR({
            // File
            "file": {
                "bios": %Q,
                "recent_roms": [ %Q, %Q, %Q, %Q, %Q ]
            },

            // Emulation
            "emulation": {
                "skip_bios": %B,
                "speed": %g,
                "fast_forward": %B,
                "backup_storage": {
                    "autodetect": %B,
                    "type": %d
                },
                "gpio": {
                    "autodetect": %B,
                    "type": %d
                },
            },

            // Video
            "video": {
                "display_size": %d,
                "aspect_ratio": %d,
                "vsync": %B,
                "texture_filter": %d,
                "pixel_color_filter": %d,
                "pixel_scaling_filter": %d
            },

            // Audio
            "audio": {
                "mute": %B,
                "level": %g
            },

            // Misc
            "misc": {
                "pause_when_window_inactive": %B,
                "pause_when_game_resets": %B
            }
        }),
        app->settings.emulation.bios_path,
        app->file.recent_roms[0],
        app->file.recent_roms[1],
        app->file.recent_roms[2],
        app->file.recent_roms[3],
        app->file.recent_roms[4],
        (int)app->settings.emulation.skip_bios,
        app->settings.emulation.speed,
        (int)app->settings.emulation.fast_forward,
        (int)app->settings.emulation.backup_storage.autodetect,
        (int)app->settings.emulation.backup_storage.type,
        (int)app->settings.emulation.gpio_device.autodetect,
        (int)app->settings.emulation.gpio_device.type,
        (int)app->settings.video.display_size,
        (int)app->settings.video.aspect_ratio,
        (int)app->settings.video.vsync,
        (int)app->settings.video.texture_filter,
        (int)app->settings.video.pixel_color_filter,
        (int)app->settings.video.pixel_scaling_filter,
        (int)app->settings.audio.mute,
        app->settings.audio.level,
        (int)app->settings.misc.pause_when_window_inactive,
        (int)app->settings.misc.pause_when_game_resets
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

        static char const *layers_name[] = {
            "keyboard",
            "keyboard_alt",
            "controller",
            "controller_alt"
        };

        for (layer = 0; layer < 4; ++layer) {
            for (bind = BIND_MIN; bind < BIND_MAX; ++bind) {
                char *tmp_data;
                char const *key_name;

                switch (layer) {
                    case 0: key_name = SDL_GetKeyName(app->binds.keyboard[bind]); break;
                    case 1: key_name = SDL_GetKeyName(app->binds.keyboard_alt[bind]); break;
                    case 2: key_name = SDL_GameControllerGetStringForButton(app->binds.controller[bind]); break;
                    case 3: key_name = SDL_GameControllerGetStringForButton(app->binds.controller_alt[bind]); break;
                }

                // Build a temporary JSON containing our bind
                snprintf(
                    str,
                    sizeof(str),
                    STR({
                        "binds": {
                            "%s": {
                                "%s": "%s",
                            },
                        },
                    }),
                    layers_name[layer],
                    binds_slug[bind],
                    key_name ?: ""
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
    for (i = 0; i < BIND_MAX; ++i) {
        free(keyboard_binds_name[i]);
    }

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
    char abs_path[4096];
    char const *path;
    int32_t i;
    int32_t j;

    // TODO FIXME: realpath() isn't defined on Windows
#if defined(__APPLE__) || defined(__unix__)
    path = realpath(rom_path, abs_path) ?: rom_path;
#else
    path = rom_path;
#endif
    new_recent_roms[0] = strdup(path);

    memset(new_recent_roms, 0, sizeof(new_recent_roms));
    new_recent_roms[0] = strdup(abs_path);

    j = 0;
    for (i = 1; i < MAX_RECENT_ROMS && j < MAX_RECENT_ROMS; ++j) {
        if (!app->file.recent_roms[j] || strcmp(app->file.recent_roms[j], path)) {
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
