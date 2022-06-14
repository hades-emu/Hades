/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <frozen.h>
#include "hades.h"
#include "platform/gui/game.h"

void
gui_config_load(
    struct app *app
) {
    void *data;

    data = json_fread(app->file.config_path);

    if (data) {
        json_scanf(
            data,
            strlen(data),
            STRINGIFY({
                file: {
                    bios: %Q,
                    recent_roms_0: %Q,
                    recent_roms_1: %Q,
                    recent_roms_2: %Q,
                    recent_roms_3: %Q,
                    recent_roms_4: %Q,
                },
                emulation: {
                    unbounded: %B,
                    speed: %d,
                    backup_type: %d,
                    rtc_autodetect: %B,
                    rtc_force_enabled: %B,
                },
                video: {
                    display_size: %d,
                    vsync: %B,
                    color_correction: %B,
                },
                audio: {
                    mute: %B,
                    sound_level: %f,
                },
            }),
            &app->file.bios_path,
            &app->file.recent_roms[0],
            &app->file.recent_roms[1],
            &app->file.recent_roms[2],
            &app->file.recent_roms[3],
            &app->file.recent_roms[4],
            &app->emulation.unbounded,
            &app->emulation.speed,
            &app->emulation.backup_type,
            &app->emulation.rtc_autodetect,
            &app->emulation.rtc_force_enabled,
            &app->video.display_size,
            &app->video.vsync,
            &app->video.color_correction,
            &app->audio.mute,
            &app->audio.sound_level
        );

        free(data);
    }

    if (!app->file.bios_path) {
        app->file.bios_path = strdup("bios.bin");
    }

    app->video.display_size = max(1, min(app->video.display_size, 5));
    app->audio.sound_level = max(0.f, min(app->audio.sound_level, 1.f));
}

void
gui_config_save(
    struct app *app
) {
    json_fprintf(
        app->file.config_path,
        STRINGIFY({
            file: {
                bios: %Q,
                recent_roms_0: %Q,
                recent_roms_1: %Q,
                recent_roms_2: %Q,
                recent_roms_3: %Q,
                recent_roms_4: %Q,
            },
            emulation: {
                unbounded: %B,
                speed: %d,
                backup_type: %d,
                rtc_autodetect: %B,
                rtc_force_enabled: %B,
            },
            video: {
                display_size: %d,
                vsync: %B,
                color_correction: %B,
            },
            audio: {
                mute: %B,
                sound_level: %.2f,
            },
        }),
        app->file.bios_path,
        app->file.recent_roms[0],
        app->file.recent_roms[1],
        app->file.recent_roms[2],
        app->file.recent_roms[3],
        app->file.recent_roms[4],
        app->emulation.unbounded,
        app->emulation.speed,
        app->emulation.backup_type,
        app->emulation.rtc_autodetect,
        app->emulation.rtc_force_enabled,
        app->video.display_size,
        app->video.vsync,
        app->video.color_correction,
        app->audio.mute,
        app->audio.sound_level
    );

    json_prettify_file(app->file.config_path);
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