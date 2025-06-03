/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#define STB_IMAGE_WRITE_IMPLEMENTATION

#include <archive.h>
#include <archive_entry.h>
#include <stb_image_write.h>
#include <errno.h>
#include "app/app.h"
#include "gba/gba.h"
#include "gba/event.h"
#include "compat.h"

/*
** Process and delete the given notification.
**
** NOTE: This only handles frontend notifications.
** The debugger is expected to handle its notification on its own.
*/
static
void
app_emulator_process_notif(
    struct app *app,
    struct event_header const *notif_header
) {
    struct notification const *notif;

    notif = (struct notification const *)notif_header;
    switch (notif->header.kind) {
        case NOTIFICATION_RUN: {
            app->emulation.is_started = true;
            app->emulation.is_running = true;
            break;
        };
        case NOTIFICATION_STOP: {
            app->emulation.is_started = false;
            app->emulation.is_running = false;
            break;
        };
        case NOTIFICATION_RESET: {
            app->emulation.is_started = true;
            break;
        };
        case NOTIFICATION_PAUSE: {
            app->emulation.is_running = false;
            break;
        };
        case NOTIFICATION_QUICKSAVE: {
            struct notification_quicksave *qsave;
            char const *path;
            FILE *file;

            qsave = (struct notification_quicksave *)notif;

            hs_assert(app->emulation.quicksave_request.enabled);
            path = app->file.qsaves[app->emulation.quicksave_request.idx].path;

            file = hs_fopen(path, "wb+");
            if (!file) {
                goto qsave_err;
            }

            if (fwrite(qsave->data, qsave->size, 1, file) != 1) {
                goto qsave_err;
            }

            app_new_notification(
                app,
                UI_NOTIFICATION_SUCCESS,
                "Game state saved."
            );

            goto qsave_finally;

qsave_err:
            app_new_notification(
                app,
                UI_NOTIFICATION_ERROR,
                "Failed to save game state: %s.",
                strerror(errno)
            );

qsave_finally:
            app->emulation.quicksave_request.enabled = false;
            app->emulation.quicksave_request.idx = 0;
            app->file.flush_qsaves_cache = true;

            if (file) {
                fclose(file);
            }

            break;
        };
        case NOTIFICATION_QUICKLOAD: {
            hs_assert(app->emulation.quickload_request.enabled);

            app_new_notification(
                app,
                UI_NOTIFICATION_SUCCESS,
                "Game state loaded."
            );

            free(app->emulation.quickload_request.data);

            app->emulation.quickload_request.enabled = false;
            app->emulation.quickload_request.data = NULL;
            break;
        };
        case NOTIFICATION_RUMBLE: {
            app_sdl_set_rumble(app, true);
            break;
        };
    }
    gba_delete_notification(notif);
}

void
app_emulator_process_all_notifs(
    struct app *app
) {
    struct channel *channel;
    struct event_header const *event;

    channel = &app->emulation.gba->channels.notifications;

    channel_lock(channel);
    {
        event = channel_next(channel, NULL);
        while (event) {
            app_emulator_process_notif(app, event);
            event = channel_next(channel, event);
        }
        channel_clear(channel);
    }
    channel_release(channel);
}

void
app_emulator_wait_for_notification(
    struct app *app,
    enum notification_kind kind
) {
    struct channel *channel;
    bool ok;

    channel = &app->emulation.gba->channels.notifications;
    ok = false;

    channel_lock(channel);

    while (!ok) {
        struct event_header const *event;

        event = channel_next(channel, NULL);
        while (event) {
            app_emulator_process_notif(app, event);
            ok = (event->kind == kind);
            event = channel_next(channel, event);
        }

        channel_clear(channel);

        if (!ok) {
            channel_wait(channel);
        }
    }

    channel_release(channel);
}

static inline
void
app_emulator_fill_gba_settings(
    struct app const *app,
    struct gba_settings *settings
) {
    float speed;

    memset(settings, 0, sizeof(*settings));

    speed = app->emulation.use_alt_speed ? app->settings.emulation.alt_speed : app->settings.emulation.speed;

    if (speed <= 0.0) {
        settings->fast_forward = true;
        settings->speed = 0.0;
    } else {
        settings->fast_forward = false;
        settings->speed = speed;
    }

    settings->prefetch_buffer = app->settings.emulation.prefetch_buffer;

    settings->ppu.enable_oam = app->settings.video.enable_oam;
    memcpy(settings->ppu.enable_bg_layers, app->settings.video.enable_bg_layers, sizeof(settings->ppu.enable_bg_layers));

    memcpy(settings->apu.enable_psg_channels, app->settings.audio.enable_psg_channels, sizeof(settings->apu.enable_psg_channels));
    memcpy(settings->apu.enable_fifo_channels, app->settings.audio.enable_fifo_channels, sizeof(settings->apu.enable_fifo_channels));
}

static
void
app_emulator_unconfigure(
    struct app *app
) {
    if (app->emulation.launch_config) {
        free(app->emulation.launch_config->bios.data);
        free(app->emulation.launch_config->rom.data);
        free(app->emulation.launch_config);
        app->emulation.launch_config = NULL;
    }

    if (app->emulation.backup_file) {
        fclose(app->emulation.backup_file);
        app->emulation.backup_file = NULL;
    }

    if (app->emulation.game_entry) {
        free(app->emulation.game_entry);
        app->emulation.game_entry = NULL;
    }

    if (app->emulation.game_path) {
        free(app->emulation.game_path);
        app->emulation.game_path = NULL;
    }
}

static
bool
app_emulator_configure_bios(
    struct app *app
) {
    char const *bios_path;
    FILE *file;
    void *data;

    bios_path = app->args.bios_path ?: app->settings.emulation.bios_path;
    if (!bios_path) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "No BIOS found.\nPlease download and select a valid Nintendo GBA Bios using \"File\" -> \"Open BIOS\"."
        );
        return (true);
    }

    file = hs_fopen(bios_path, "rb");
    if (!file) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to open %s: %s.",
            bios_path,
            strerror(errno)
        );
        return (true);
    }

    fseek(file, 0, SEEK_END);
    if (ftell(file) != 0x4000) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "The BIOS is invalid."
        );
        return (true);
    }

    rewind(file);

    data = calloc(1, BIOS_SIZE);
    hs_assert(data);

    if (fread(data, 1, BIOS_SIZE, file) != BIOS_SIZE) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to read %s: %s.",
            bios_path,
            strerror(errno)
        );
        free(data);
        return (true);
    }

    app->emulation.launch_config->bios.data = data;
    app->emulation.launch_config->bios.size = BIOS_SIZE;

    return (false);
}

static
bool
app_emulator_configure_rom_archive(
    struct app *app,
    char const *archive_path
) {
    struct archive *archive;
    struct archive_entry *entry;
    int err;
    bool game_found;

    logln(HS_INFO, "Path given identified as an archived.");

    game_found = false;
    archive = archive_read_new();
    hs_assert(archive);

    archive_read_support_filter_all(archive);
    archive_read_support_format_all(archive);

    err = archive_read_open_filename(archive, archive_path, 1024 * 1024); // 1MiB
    if (err != ARCHIVE_OK) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to open the path as an archive: %s.",
            archive_path,
            archive_error_string(archive)
        );
        return (true);
    }

    while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        char const *entry_name;
        char const *ext;

        entry_name = archive_entry_pathname(entry);
        ext = strrchr(entry_name, '.');
        if (ext && !strcmp(ext, ".gba")) {
            size_t file_len;
            ssize_t read_len;
            void *data;

            file_len = 0;
            data = NULL;
            do {
                data = realloc(data, file_len + 1024 * 1024); // 1MiB
                hs_assert(data);

                read_len = archive_read_data(archive, data + file_len, 1024 * 1024); // 1MiB
                if (read_len < 0) {
                    app_new_notification(
                        app,
                        UI_NOTIFICATION_ERROR,
                        "Failed to archive's entry %s: %s.",
                        entry_name,
                        archive_error_string(archive)
                    );
                    free(data);
                    goto cleanup;
                }
                file_len += read_len;
            } while (read_len > 0);

            game_found = true;

            app->emulation.launch_config->rom.data = data;
            app->emulation.launch_config->rom.size = file_len;

            goto cleanup;
        }

        archive_read_data_skip(archive);
    }

    app_new_notification(
        app,
        UI_NOTIFICATION_ERROR,
        "No valid GBA game found in the archive.",
        archive_path,
        archive_error_string(archive)
    );

cleanup:
    archive_read_free(archive);
    return (!game_found);
}

static
bool
app_emulator_configure_rom(
    struct app *app,
    char const *rom_path
) {
    FILE *file;
    size_t file_len;
    void *data;

    file = hs_fopen(rom_path, "rb");
    if (!file) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to open %s: %s.",
            rom_path,
            strerror(errno)
        );
        return (true);
    }

    fseek(file, 0, SEEK_END);
    file_len = ftell(file);
    if (file_len > CART_SIZE || file_len < 192) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "The ROM is invalid."
        );
        return (true);
    }

    rewind(file);

    data = calloc(1, file_len);
    hs_assert(data);

    if (fread(data, 1, file_len, file) != file_len) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to read %s: %s.",
            rom_path,
            strerror(errno)
        );
        free(data);
        return (true);
    }

    app->emulation.launch_config->rom.data = data;
    app->emulation.launch_config->rom.size = file_len;

    return (false);
}

static
bool
app_emulator_configure_backupe_storage(
    struct app *app,
    char const *backup_path
) {
    size_t file_len;

    app->emulation.backup_file = hs_fopen(backup_path, "rb+");

    if (app->emulation.backup_file) {
        void *data;
        size_t read_len;

        fseek(app->emulation.backup_file, 0, SEEK_END);
        file_len = ftell(app->emulation.backup_file);
        rewind(app->emulation.backup_file);

        data = calloc(1, file_len);
        hs_assert(data);

        read_len = fread(data, 1, file_len, app->emulation.backup_file);

        if (read_len != file_len) {
            logln(HS_WARNING, "Failed to read the save file. Is it corrupted?");
        } else {
            logln(HS_INFO, "Save file successfully read.");
        }

        app->emulation.launch_config->backup_storage.data = data;
        app->emulation.launch_config->backup_storage.size = file_len;
    } else {
        logln(HS_WARNING, "Failed to open the save file. A new one will be created instead.");

        app->emulation.backup_file = hs_fopen(backup_path, "wb+");

        if (!app->emulation.backup_file) {
            app_new_notification(
                app,
                UI_NOTIFICATION_ERROR,
                "Failed to create %s: %s.",
                backup_path,
                strerror(errno)
            );
            return (true);
        }
    }
    return (false);
}

static
bool
app_emulator_import_backup_storage(
    struct app *app,
    char const *backup_path_to_import,
    char const *backup_path
) {
    size_t file_len;
    size_t read_len;
    FILE *backup;
    void *data;


    backup = hs_fopen(backup_path_to_import, "rb");
    if (!backup) {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to import save file %s: %s.",
            backup_path_to_import,
            strerror(errno)
        );
        return (true);
    }

    fseek(backup, 0, SEEK_END);
    file_len = ftell(backup);
    rewind(backup);

    data = calloc(1, file_len);
    hs_assert(data);

    read_len = fread(data, 1, file_len, backup);

    if (read_len != file_len) {
        logln(HS_WARNING, "Failed to import the save file. Is it corrupted?");
    } else {
        app_new_notification(
            app,
            UI_NOTIFICATION_SUCCESS,
            "Save file successfully imported.",
            backup_path_to_import,
            strerror(errno)
        );
    }

    app->emulation.launch_config->backup_storage.data = data;
    app->emulation.launch_config->backup_storage.size = file_len;
    app->emulation.backup_file = hs_fopen(backup_path, "rb+");

    if (!app->emulation.backup_file) {
        logln(HS_WARNING, "Failed to open the save file. A new one will be created instead.");

        app->emulation.backup_file = hs_fopen(backup_path, "wb+");

        if (!app->emulation.backup_file) {
            app_new_notification(
                app,
                UI_NOTIFICATION_ERROR,
                "Failed to create %s: %s.",
                backup_path,
                strerror(errno)
            );
            return (true);
        }
    }
    return (false);
}

/*
** Update the GBA's launch configuration to load a new game & reset the emulator.
**
** This function abstracts all the different step needed to load a game:
**   - Read the BIOS/ROM files
**   - Extracting the game code
**   - Performing a database lookup to identify the features of the game
**   - Update the gba's launch configuration
**   - Reset the emulator
**   - Wait for the reset notification
**   - Run/Pause the emulator, according to the configuration
**
** NOTE: `backup_to_import` can be NULL if there is no backup to import.
*/
bool
app_emulator_configure_and_run(
    struct app *app,
    char const *rom_path,
    char const *backup_to_import
) {
    struct message_reset event;
    char *backup_path;
    char *extension;
    bool is_archive;
    size_t basename_len;
    size_t i;
    uint8_t *code;

    app_emulator_unconfigure(app);

    logln(HS_INFO, "Loading game at \"%s%s%s\".", g_light_green, rom_path, g_reset);

    app->emulation.launch_config = calloc(1, sizeof(struct launch_config));
    hs_assert(app->emulation.launch_config);

    extension = strrchr(rom_path, '.');

    // We consider anything that isn't ending with `.gba` or `.bin` an archive.
    // XXX: Should we build a hard-coded list instead?
    if (extension) {
        basename_len = extension - rom_path;
        is_archive = (bool)(strcmp(extension, ".gba") && strcmp(extension, ".bin"));
    } else {
        basename_len = strlen(rom_path);
        is_archive = false;
    }

    for (i = 0; i < MAX_QUICKSAVES; ++i) {
        free(app->file.qsaves[i].path);
        free(app->file.qsaves[i].mtime);

        app->file.qsaves[i].mtime = NULL;
        app->file.qsaves[i].path = hs_format(
            "%.*s.%zu.hds",
            (int)basename_len,
            rom_path,
            i + 1
        );
    }

    app->file.flush_qsaves_cache = true;

    backup_path = hs_format(
        "%.*s.sav",
        (int)basename_len,
        rom_path
    );

    if (app_emulator_configure_bios(app)
        || (is_archive ? app_emulator_configure_rom_archive(app, rom_path) : app_emulator_configure_rom(app, rom_path))
        || (backup_to_import ? app_emulator_import_backup_storage(app, backup_to_import, backup_path) : app_emulator_configure_backupe_storage(app, backup_path))
    ) {
        app_emulator_unconfigure(app);
        return (true);
    }

    code = app->emulation.launch_config->rom.data + 0xAC;
    app->emulation.game_entry = db_lookup_game(code);

    if (app->emulation.game_entry) {
        logln(
            HS_INFO,
            "Game code %s%.3s%s identified as %s%s%s.",
            g_light_magenta,
            code,
            g_reset,
            g_light_magenta,
            app->emulation.game_entry->title,
            g_reset
        );
    } else {
        logln(
            HS_WARNING,
            "No game with the code \"%s%.3s%s\" could be found in the Hades game database.",
            g_light_magenta,
            code,
            g_reset
        );

        app->emulation.game_entry = db_autodetect_game_features(app->emulation.launch_config->rom.data, app->emulation.launch_config->rom.size);
    }

    app->emulation.game_path = strdup(rom_path);
    app->emulation.launch_config->skip_bios = app->settings.emulation.skip_bios;
    app->emulation.launch_config->audio_frequency = GBA_CYCLES_PER_SECOND / app->audio.resample_frequency;

    if (app->settings.emulation.backup_storage.autodetect) {
        app->emulation.launch_config->backup_storage.type = app->emulation.game_entry->storage;
    } else {
        app->emulation.launch_config->backup_storage.type = app->settings.emulation.backup_storage.type;
    }

    if (app->settings.emulation.gpio_device.autodetect) {
        app->emulation.launch_config->gpio_device_type = app->emulation.game_entry->gpio;
    } else {
        app->emulation.launch_config->gpio_device_type = app->settings.emulation.gpio_device.type;
    }

    app_emulator_fill_gba_settings(app, &app->emulation.launch_config->settings);

    logln(HS_INFO, "Emulator's configuration:");
    logln(HS_INFO, "    Skip BIOS: %s", app->emulation.launch_config->skip_bios ? "true" : "false");
    logln(HS_INFO, "    Backup storage: %s", backup_storage_names[app->emulation.launch_config->backup_storage.type]);
    logln(HS_INFO, "    GPIO: %s", gpio_device_names[app->emulation.launch_config->gpio_device_type]);
    if (app->emulation.launch_config->settings.fast_forward) {
        logln(HS_INFO, "    Speed: Fast Forward");
    } else {
        logln(HS_INFO, "    Speed: %.0f%%", app->emulation.launch_config->settings.speed * 100.f);
    }
    logln(HS_INFO, "    Audio Frequency: %iHz (%i cycles)", app->audio.resample_frequency, app->emulation.launch_config->audio_frequency);

    event.header.kind = MESSAGE_RESET;
    event.header.size = sizeof(event);

    memcpy(&event.config, app->emulation.launch_config, sizeof(event.config));

    // Process all notifications before sending the reset message to make sure the NOTIFICATION_RESET we will
    // receive comes from the correct reset message.

    app_emulator_process_all_notifs(app);
    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);

    app_emulator_wait_for_notification(app, NOTIFICATION_RESET);

    app_config_push_recent_rom(app, rom_path);

    logln(HS_INFO, "Game successfully loaded.");

#ifdef WITH_DEBUGGER
    if (app->settings.emulation.pause_when_game_resets) {
        app_emulator_pause(app);
    } else {
        app_emulator_run(app);
    }
#else
    app_emulator_run(app);
#endif

    return (false);
}

/*
** Reset the emulator with the same configuration and settings.
*/
void
app_emulator_reset(
    struct app *app
) {
    char *game_path;

    game_path = strdup(app->emulation.game_path);
    app_emulator_configure_and_run(app, game_path, NULL);
    free(game_path);
}

/*
** Stop the emulation and return to a neutral state.
*/
void
app_emulator_stop(
    struct app *app
) {
    struct message event;

    app_emulator_unconfigure(app);

    event.header.kind = MESSAGE_STOP;
    event.header.size = sizeof(event);

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Continue the emulation.
*/
void
app_emulator_run(
    struct app *app
) {
    struct message event;

    event.header.kind = MESSAGE_RUN;
    event.header.size = sizeof(event);

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Pause the emulation.
*/
void
app_emulator_pause(
    struct app *app
) {
    struct message event;

    event.header.kind = MESSAGE_PAUSE;
    event.header.size = sizeof(event);

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Exit the emulation.
**
** NOTE: The emulator thread will stop and exit when processing this message.
** This message is used when shutting down Hades.
*/
void
app_emulator_exit(
    struct app *app
) {
    struct message event;

    event.header.kind = MESSAGE_EXIT;
    event.header.size = sizeof(event);

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Update a key's state.
*/
void
app_emulator_key(
    struct app *app,
    enum keys key,
    bool pressed
) {
    struct message_key event;

    event.header.kind = MESSAGE_KEY;
    event.header.size = sizeof(event);
    event.key = key;
    event.pressed = pressed;

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Update the emulator's runtime settings.
*/
void
app_emulator_settings(
    struct app *app
) {
    struct message_settings event;

    event.header.kind = MESSAGE_SETTINGS;
    event.header.size = sizeof(event);

    app_emulator_fill_gba_settings(app, &event.settings);

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Write the content of the backup storage on the disk, only if it's dirty.
*/
void
app_emulator_update_backup(
    struct app *app
) {
    bool dirty;

    dirty = atomic_exchange(&app->emulation.gba->shared_data.backup_storage.dirty, 0);
    if (dirty
        && app->emulation.backup_file
        && app->emulation.gba->shared_data.backup_storage.data
    ) {
        fseek(app->emulation.backup_file, 0, SEEK_SET);
        fwrite(
            app->emulation.gba->shared_data.backup_storage.data,
            app->emulation.gba->shared_data.backup_storage.size,
            1,
            app->emulation.backup_file
        );
    }
    app->emulation.gba->shared_data.backup_storage.dirty = false;
}

/*
** Write the content of the backup storage on the disk, regardless if it's dirty or not.
*/
void
app_emulator_export_save_to_path(
    struct app *app,
    char const *path
) {
    FILE *file;

    if (app->emulation.gba->shared_data.backup_storage.data) {
        file = hs_fopen(path, "wb");

        if (!file) {
            goto error;
        }

        if (
            fwrite(
                app->emulation.gba->shared_data.backup_storage.data,
                app->emulation.gba->shared_data.backup_storage.size,
                1,
                file
            ) != 1
        ) {
            goto error;
        }

        app_new_notification(
            app,
            UI_NOTIFICATION_SUCCESS,
            "Save file exported to \"%s\"",
            path
        );
    }

    return;

error:
    app_new_notification(
        app,
        UI_NOTIFICATION_ERROR,
        "Failed to export the save file to \"%s\": %s",
        path,
        strerror(errno)
    );
}

/*
** Take a screenshot of the game and writes it to the disk.
*/
void
app_emulator_screenshot_path(
    struct app *app,
    char const *path
) {
    int out;

    pthread_mutex_lock(&app->emulation.gba->shared_data.framebuffer.lock);
    out = stbi_write_png(
        path,
        GBA_SCREEN_WIDTH,
        GBA_SCREEN_HEIGHT,
        4,
        app->emulation.gba->shared_data.framebuffer.data,
        GBA_SCREEN_WIDTH * sizeof(uint32_t)
    );
    pthread_mutex_unlock(&app->emulation.gba->shared_data.framebuffer.lock);

    if (out) {
        app_new_notification(
            app,
            UI_NOTIFICATION_SUCCESS,
            "Screenshot saved as \"%s\".",
            path
        );
    } else {
        app_new_notification(
            app,
            UI_NOTIFICATION_ERROR,
            "Failed to save screenshot as \"%s\".",
            path
        );
    }
}

/*
** Take a screenshot of the game and writes it to the disk.
**
** The file's name depends on the current time.
*/
void
app_emulator_screenshot(
    struct app *app
) {
    time_t now;
    struct tm *now_info;
    char filename[256];
    char const *directory;
    char *path;

    time(&now);
    now_info = localtime(&now);

    directory = app_path_screenshots(app);
    if (!hs_fexists(directory)) {
        hs_mkdir(directory);
    }

    strftime(filename, sizeof(filename), "%Y-%m-%d_%Hh%Mm%Ss.png", now_info);

    path = hs_format("%s/%s", directory, filename);
    app_emulator_screenshot_path(app, path);
    free(path);
}

void
app_emulator_quicksave(
    struct app *app,
    size_t idx
) {
    struct message event;

    app->emulation.quicksave_request.enabled = true;
    app->emulation.quicksave_request.idx = idx;

    event.header.kind = MESSAGE_QUICKSAVE;
    event.header.size = sizeof(event);

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

void
app_emulator_quickload(
    struct app *app,
    size_t idx
) {
    struct message_quickload event;

    char const *path;
    FILE *file;
    uint8_t *data;
    size_t size;

    if (app->emulation.quickload_request.enabled) {
        logln(HS_WARNING, "A saved state is already being loaded by the emulator, ignoring the new request.");
        return;
    }

    data = NULL;
    path = app->file.qsaves[idx].path;

    file = hs_fopen(path, "rb");
    if (!file) {
        goto err;
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    data = calloc(1, size);
    hs_assert(data);

    if (fread(data, size, 1, file) != 1) {
        goto err;
    }

    app->emulation.quickload_request.enabled = true;
    app->emulation.quickload_request.data = data;

    event.header.kind = MESSAGE_QUICKLOAD;
    event.header.size = sizeof(event);
    event.data = data;
    event.size = size;

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);

    goto finally;

err:
    app_new_notification(
        app,
        UI_NOTIFICATION_ERROR,
        "Failed to load state from %s: %s",
        path,
        strerror(errno)
    );

    free(data);

finally:
    if (file) {
        fclose(file);
    }
}

#ifdef WITH_DEBUGGER

#include "app/dbg.h"

/*
** Run until the end of the current frame.
*/
void
app_emulator_frame(
    struct app *app,
    size_t count
) {
    struct message_frame event;

    event.header.kind = MESSAGE_FRAME;
    event.header.size = sizeof(event);
    event.count = count;

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Trace the emulation.
*/
void
app_emulator_trace(
    struct app *app,
    size_t count,
    void (*tracer_cb)(struct app *app)
) {
    struct message_trace event;

    event.header.kind = MESSAGE_TRACE;
    event.header.size = sizeof(event);
    event.count = count;
    event.tracer_cb = (void (*)(void *))tracer_cb;
    event.arg = app;

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Step in `count instructions.
*/
void
app_emulator_step_in(
    struct app *app,
    size_t count
) {
    struct message_step event;

    event.header.kind = MESSAGE_STEP_IN;
    event.header.size = sizeof(event);
    event.count = count;

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Step over `count overstructions.
*/
void
app_emulator_step_over(
    struct app *app,
    size_t count
) {
    struct message_step event;

    event.header.kind = MESSAGE_STEP_OVER;
    event.header.size = sizeof(event);
    event.count = count;

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Set the list of breakpoints and wait to make sure it was correctly copied by the emulator.
*/
void
app_emulator_set_breakpoints_list(
    struct app *app,
    struct breakpoint *breakpoints,
    size_t len
) {
    struct message_set_breakpoints_list event;

    event.header.kind = MESSAGE_SET_BREAKPOINTS_LIST;
    event.header.size = sizeof(event);
    event.breakpoints = breakpoints;
    event.len = len;

    /*
    ** Process all notifications before sending the message to make sure the notification we will
    ** receive comes from the correct message.
    */

    debugger_process_all_notifs(app);
    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
    debugger_wait_for_notif(app, NOTIFICATION_BREAKPOINTS_LIST_SET);
}

/*
** Set the list of watchpoints and wait to make sure it was correctly copied by the emulator.
*/
void
app_emulator_set_watchpoints_list(
    struct app *app,
    struct watchpoint *watchpoints,
    size_t len
) {
    struct message_set_watchpoints_list event;

    event.header.kind = MESSAGE_SET_WATCHPOINTS_LIST;
    event.header.size = sizeof(event);
    event.watchpoints = watchpoints;
    event.len = len;

    /*
    ** Process all notifications before sending the message to make sure the notification we will
    ** receive comes from the correct message.
    */

    debugger_process_all_notifs(app);
    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
    debugger_wait_for_notif(app, NOTIFICATION_WATCHPOINTS_LIST_SET);
}

#endif
