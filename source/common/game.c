/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#define STB_IMAGE_WRITE_IMPLEMENTATION

#include <stb_image_write.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "hades.h"
#include "app.h"
#include "compat.h"
#include "gba/gba.h"
#include "gui/gui.h"

static
bool
app_game_load_bios(
    struct app *app
) {
    FILE *file;
    void *data;
    char *error_msg;

    if (!app->file.bios_path) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "no BIOS found.\n\nPlease download and select a valid Nintendo GBA Bios using \"File\" -> \"Open BIOS\"."
        ));
        gui_new_error(app, error_msg);
        return (true);
    }

    file = hs_fopen(app->file.bios_path, "rb");
    if (!file) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "failed to open %s: %s.",
            app->file.bios_path,
            strerror(errno)
        ));
        gui_new_error(app, error_msg);
        return (true);
    }

    fseek(file, 0, SEEK_END);
    if (ftell(file) != 0x4000) {
        error_msg = strdup("the BIOS is invalid.");
        gui_new_error(app, error_msg);
        return (true);
    }

    rewind(file);

    data = calloc(1, BIOS_SIZE);
    hs_assert(data);

    if (fread(data, 1, BIOS_SIZE, file) != BIOS_SIZE) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "failed to read %s: %s.",
            app->file.bios_path,
            strerror(errno)
        ));
        gui_new_error(app, error_msg);
        free(data);
        return (true);
    }

    gba_send_bios(app->emulation.gba, data, free);

    return (false);
}

static
bool
app_game_load_rom(
    struct app *app
) {
    FILE *file;
    size_t file_len;
    void *data;
    char *error_msg;

    if (!app->file.game_path) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "no game ROM found.\n\nPlease download and select a valid Nintendo GBA ROM using \"File\" -> \"Open\"."
        ));
        gui_new_error(app, error_msg);
        return (true);
    }

    file = hs_fopen(app->file.game_path, "rb");
    if (!file) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "failed to open %s: %s.",
            app->file.game_path,
            strerror(errno)
        ));
        gui_new_error(app, error_msg);
        return (true);
    }

    fseek(file, 0, SEEK_END);
    file_len = ftell(file);
    if (file_len > CART_SIZE || file_len < 192) {
        error_msg = strdup("the ROM is invalid.");
        gui_new_error(app, error_msg);
        return (true);
    }

    rewind(file);

    data = calloc(1, file_len);
    hs_assert(data);

    if (fread(data, 1, file_len, file) != file_len) {
        hs_assert(-1 != asprintf(
            &error_msg,
            "failed to read %s: %s.",
            app->file.game_path,
            strerror(errno)
        ));
        gui_new_error(app, error_msg);
        free(data);
        return (true);
    }

    gba_send_rom(app->emulation.gba, data, file_len, free);

    return (false);
}

static
bool
app_game_load_devices(
    struct app *app
) {
    gba_send_backup_type(app->emulation.gba, app->emulation.backup_type);

    if (app->emulation.rtc_autodetect) {
        gba_send_settings_rtc(app->emulation.gba, DEVICE_AUTO_DETECT);
    } else {
        gba_send_settings_rtc(app->emulation.gba, app->emulation.rtc_force_enabled ? DEVICE_ENABLED : DEVICE_DISABLED);
    }

    return (false);
}

static
bool
app_game_load_save(
    struct app *app
) {
    size_t file_len;
    char *error_msg;

    if (app->file.backup_file) {
        fclose(app->file.backup_file);
    }

    app->file.backup_file = hs_fopen(app->file.backup_path, "rb+");

    if (app->file.backup_file) {
        void *data;
        size_t read_len;

        fseek(app->file.backup_file, 0, SEEK_END);
        file_len = ftell(app->file.backup_file);
        rewind(app->file.backup_file);

        data = calloc(1, file_len);
        hs_assert(data);
        read_len = fread(data, 1, file_len, app->file.backup_file);

        if (read_len != file_len) {
            logln(HS_WARNING, "Failed to read the save file. Is it corrupted?");
        } else {
            logln(HS_GLOBAL, "Save data successfully loaded.");
            gba_send_backup(app->emulation.gba, data, file_len, free);
        }
    } else {
        logln(HS_WARNING, "Failed to open the save file. A new one is created instead.");

        app->file.backup_file = hs_fopen(app->file.backup_path, "wb+");

        if (!app->file.backup_file) {
            hs_assert(-1 != asprintf(
                &error_msg,
                "failed to create %s: %s.",
                app->file.backup_path,
                strerror(errno)
            ));
            gui_new_error(app, error_msg);
            return (true);
        }
    }
    return (false);
}

/*
** Load the BIOS/ROM into the emulator's memory and reset it.
*/
void
app_game_reset(
    struct app *app
) {
    char *extension;
    size_t base_len;
    size_t i;

    gui_config_push_recent_rom(app);

    free(app->file.backup_path);

    extension = strrchr(app->file.game_path, '.');

    if (extension) {
        base_len = extension - app->file.game_path;
    } else {
        base_len = strlen(app->file.game_path);
    }

    for (i = 0; i < MAX_QUICKSAVES; ++i) {
        free(app->file.qsaves[i].path);
        free(app->file.qsaves[i].mtime);

        app->file.qsaves[i].mtime = NULL;

        hs_assert(-1 != asprintf(
            &app->file.qsaves[i].path,
            "%.*s.%zu.hds",
            (int)base_len,
            app->file.game_path,
            i + 1
        ));
    }

    app->file.flush_qsaves_cache = true;

    hs_assert(-1 != asprintf(
        &app->file.backup_path,
        "%.*s.sav",
        (int)base_len,
        app->file.game_path
    ));

    app_game_stop(app);

    /* Misc. */
    gba_send_speed(app->emulation.gba, app->emulation.speed * !app->emulation.unbounded);
    gba_send_settings_color_correction(app->emulation.gba, app->video.color_correction);

    if (
           !app_game_load_bios(app)
        && !app_game_load_rom(app)
        && !app_game_load_devices(app)
        && !app_game_load_save(app)
    ) {
        gba_send_reset(app->emulation.gba);
    } else {
        app_game_stop(app);
    }
}

/*
** Stop the emulation and return to a neutral state.
*/
void
app_game_stop(
    struct app *app
) {
    app->emulation.started = false;
    app->emulation.running = false;
    gba_send_reset(app->emulation.gba);
}

/*
** Continue the emulation.
*/
void
app_game_run(
    struct app *app
) {
    app->emulation.started = true;
    app->emulation.running = true;
    gba_send_run(app->emulation.gba);
}

/*
** Pause the emulation.
*/
void
app_game_pause(
    struct app *app
) {
    app->emulation.started = true;
    app->emulation.running = false;
    gba_send_pause(app->emulation.gba);
}

#ifdef WITH_DEBUGGER

/*
** Trace the emulation.
*/
void
app_game_trace(
    struct app *app,
    size_t count,
    void (*tracer)(struct app *app)
) {
    app->emulation.started = true;
    app->emulation.running = true;
    gba_send_dbg_trace(app->emulation.gba, count, app, (void (*)(void *))tracer);
}

/*
** Step over/in X instructions.
*/
void
app_game_step(
    struct app *app,
    bool over,
    size_t count
) {
    app->emulation.started = true;
    app->emulation.running = true;
    gba_send_dbg_step(app->emulation.gba, over, count);
}

#endif

/*
** Write the content of the backup storage on the disk.
*/
void
app_game_write_backup(
    struct app *app
) {
    if (   app->file.backup_file
        && app->emulation.gba->memory.backup_storage_data
        && app->emulation.gba->memory.backup_storage_dirty
    ) {
        fseek(app->file.backup_file, 0, SEEK_SET);
        fwrite(
            app->emulation.gba->memory.backup_storage_data,
            backup_storage_sizes[app->emulation.gba->memory.backup_storage_type],
            1,
            app->file.backup_file
        );
    }
    app->emulation.gba->memory.backup_storage_dirty = false;
}

void
app_game_quicksave(
    struct app *app,
    size_t idx
) {
    if (idx < MAX_QUICKSAVES) {
        gba_send_quicksave(app->emulation.gba, app->file.qsaves[idx].path);
        app->file.flush_qsaves_cache = true;
    }
}

void
app_game_quickload(
    struct app *app,
    size_t idx
) {
    if (idx < MAX_QUICKSAVES) {
        gba_send_quickload(app->emulation.gba, app->file.qsaves[idx].path);
    }
}

void
app_game_screenshot(
    struct app *app
) {
    time_t now;
    struct tm *now_info;
    char filename[256];
    int out;

    time(&now);
    now_info = localtime(&now);

    hs_mkdir("screenshots");
    strftime(filename, sizeof(filename), "screenshots/%Y-%m-%d_%Hh%Mm%Ss.png", now_info);

    pthread_mutex_lock(&app->emulation.gba->framebuffer_frontend_mutex);
    out = stbi_write_png(
        filename,
        GBA_SCREEN_WIDTH,
        GBA_SCREEN_HEIGHT,
        4,
        app->emulation.gba->framebuffer_frontend,
        GBA_SCREEN_WIDTH * sizeof(uint32_t)
    );
    pthread_mutex_unlock(&app->emulation.gba->framebuffer_frontend_mutex);

    if (out) {
        logln(
            HS_GLOBAL,
            "Screenshot saved in %s%s%s.",
            g_light_green,
            filename,
            g_reset
        );
    } else {
        logln(
            HS_ERROR,
            "Failed to save screenshot in %s%s%s.%s",
            g_light_green,
            filename,
            g_light_red,
            g_reset
        );
    }
}