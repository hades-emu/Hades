/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <errno.h>
#include <mjson.h>
#include "hades.h"
#include "app.h"
#include "gui/gui.h"
#include "compat.h"

void
gui_config_load(
    struct app *app
) {
    char data[4096];
    FILE *config_file;
    size_t data_len;

    config_file = hs_fopen(app->file.config_path, "r");
    if (!config_file) {
        logln(HS_ERROR, "Failed to open \"%s\": %s", app->file.config_path, strerror(errno));
        return ;
    }

    data_len = fread(data, 1, sizeof(data) - 1, config_file);

    if (data_len == 0 && ferror(config_file)) {
        logln(HS_ERROR, "Failed to read \"%s\": %s", app->file.config_path, strerror(errno));
        goto end;
    }

    data[data_len] = '\0';

    // File
    {
        char str[4096];
        char *recent_rom_path;
        int i;

        if (mjson_get_string(data, data_len, "$.file.bios", str, sizeof(str)) > 0) {
            free(app->file.bios_path);
            app->file.bios_path = strdup(str);
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

        if (mjson_get_bool(data, data_len, "$.emulation.unbounded", &b)) {
            app->emulation.unbounded = b;
        }

        if (mjson_get_number(data, data_len, "$.emulation.speed", &d)) {
            app->emulation.speed = (int)d;
            app->emulation.speed = max(1, min(app->emulation.speed, 5));
        }

        if (mjson_get_number(data, data_len, "$.emulation.backup_type", &d)) {
            app->emulation.backup_type = (int)d;
            app->emulation.backup_type = max(BACKUP_MIN, min(app->emulation.backup_type, BACKUP_MAX));
        }

        if (mjson_get_bool(data, data_len, "$.emulation.rtc_autodetect", &b)) {
            app->emulation.rtc_autodetect = b;
        }

        if (mjson_get_bool(data, data_len, "$.emulation.rtc_force_enabled", &b)) {
            app->emulation.rtc_force_enabled = b;
        }

        if (mjson_get_bool(data, data_len, "$.emulation.skip_bios", &b)) {
            app->emulation.skip_bios = b;
        }
    }

    // Video
    {
        int b;
        double d;

        if (mjson_get_number(data, data_len, "$.video.display_size", &d)) {
            app->video.display_size = (int)d;
            app->video.display_size = max(1, min(app->video.display_size, 5));
        }

        if (mjson_get_bool(data, data_len, "$.video.vsync", &b)) {
            app->video.vsync = b;
        }

        if (mjson_get_bool(data, data_len, "$.video.color_correction", &b)) {
            app->video.color_correction = b;
        }

        if (mjson_get_number(data, data_len, "$.video.texture_filter", &d)) {
            app->video.texture_filter.kind = (int)d;
            app->video.texture_filter.refresh = true;
        }
    }

    // Video
    {
        int b;
        double d;

        if (mjson_get_bool(data, data_len, "$.audio.mute", &b)) {
            app->audio.mute = b;
        }

        if (mjson_get_number(data, data_len, "$.audio.level", &d)) {
            app->audio.level = d;
            app->audio.level = max(0.f, min(app->audio.level, 1.f));
        }
    }

    // Binds
    {
        char str[4096];

        if (mjson_get_string(data, data_len, "$.binds.keyboard.a", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_A] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.b", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_B] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.l", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_L] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.r", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_R] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.up", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_UP] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.down", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_DOWN] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.left", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_LEFT] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.right", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_RIGHT] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.start", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_START] = SDL_GetKeyFromName(str);
        }

        if (mjson_get_string(data, data_len, "$.binds.keyboard.select", str, sizeof(str)) > 0) {
            app->binds.keyboard[BIND_GBA_SELECT] = SDL_GetKeyFromName(str);
        }
    }

end:
    fclose(config_file);
}

void
gui_config_save(
    struct app *app
) {
    FILE *config_file;
    int out;
    char *data;
    char *pretty_data;
    char *keyboard_binds_name[BIND_MAX];
    size_t i;

    data = NULL;
    pretty_data = NULL;

    config_file = hs_fopen(app->file.config_path, "w");
    if (!config_file) {
        logln(HS_ERROR, "Failed to open \"%s\": %s", app->file.config_path, strerror(errno));
        return ;
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
                "speed": %d,
                "unbounded": %B,
                "backup_type": %d,
                "rtc_autodetect": %B,
                "rtc_force_enabled": %B
            },

            // Video
            "video": {
                "display_size": %d,
                "vsync": %B,
                "color_correction": %B,
                "texture_filter": %d
            },

            // Audio
            "audio": {
                "mute": %B,
                "level": %g
            },

            // Binds
            "binds": {
                "keyboard": {
                    "a": %Q,
                    "b": %Q,
                    "l": %Q,
                    "r": %Q,
                    "up": %Q,
                    "down": %Q,
                    "left": %Q,
                    "right": %Q,
                    "start": %Q,
                    "select": %Q,
                }
            }
        }),
        app->file.bios_path,
        app->file.recent_roms[0],
        app->file.recent_roms[1],
        app->file.recent_roms[2],
        app->file.recent_roms[3],
        app->file.recent_roms[4],
        (int)app->emulation.skip_bios,
        (int)app->emulation.speed,
        (int)app->emulation.unbounded,
        (int)app->emulation.backup_type,
        (int)app->emulation.rtc_autodetect,
        (int)app->emulation.rtc_force_enabled,
        (int)app->video.display_size,
        (int)app->video.vsync,
        (int)app->video.color_correction,
        (int)app->video.texture_filter.kind,
        (int)app->audio.mute,
        app->audio.level,

        // Keyboard binds
        keyboard_binds_name[BIND_GBA_A],
        keyboard_binds_name[BIND_GBA_B],
        keyboard_binds_name[BIND_GBA_L],
        keyboard_binds_name[BIND_GBA_R],
        keyboard_binds_name[BIND_GBA_UP],
        keyboard_binds_name[BIND_GBA_DOWN],
        keyboard_binds_name[BIND_GBA_LEFT],
        keyboard_binds_name[BIND_GBA_RIGHT],
        keyboard_binds_name[BIND_GBA_START],
        keyboard_binds_name[BIND_GBA_SELECT]
    );

    if (!data) {
        logln(HS_ERROR, "Failed to write the configuration to \"%s\": the formatted JSON is invalid.", app->file.config_path);
        goto end;
    }

    out = mjson_pretty(data, strlen(data), "  ", mjson_print_dynamic_buf, &pretty_data);

    if (out < 0) {
        logln(HS_ERROR, "Failed to write the configuration to \"%s\": the formatted JSON is invalid.", app->file.config_path);
        goto end;
    }

    if (fwrite(pretty_data, strlen(pretty_data), 1, config_file) != 1) {
        logln(HS_ERROR, "Failed to write the configuration to \"%s\": %s.", app->file.config_path, strerror(errno));
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
gui_config_push_recent_rom(
    struct app *app
) {
    char *new_recent_roms[MAX_RECENT_ROMS];
    int32_t i;
    int32_t j;

    memset(new_recent_roms, 0, sizeof(new_recent_roms));
    new_recent_roms[0] = strdup(app->file.game_path);

    j = 0;
    for (i = 1; i < MAX_RECENT_ROMS && j < MAX_RECENT_ROMS; ++j) {
        if (!app->file.recent_roms[j] || strcmp(app->file.recent_roms[j], app->file.game_path)) {
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
