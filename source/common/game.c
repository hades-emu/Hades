/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE
#define STB_IMAGE_WRITE_IMPLEMENTATION

#include <stb_image_write.h>
#include <errno.h>
#include "app.h"
#include "gba/gba.h"
#include "gui/gui.h"
#include "common/compat.h"
#include "common/channel/event.h"

/*
** Process and delete the given notification.
**
** NOTE: This only handles frontend notifications.
** The debugger is expected to handle its notification on its own.
*/
static
void
app_game_process_notif(
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

            logln(
                HS_INFO,
                "State saved to %s%s%s",
                g_light_magenta,
                path,
                g_reset
            );

            goto qsave_finally;

qsave_err:
            logln(
                HS_INFO,
                "%sError: failed to save state to %s: %s%s",
                g_light_red,
                path,
                strerror(errno),
                g_reset
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
            char const *path;

            hs_assert(app->emulation.quickload_request.enabled);

            path = app->file.qsaves[app->emulation.quicksave_request.idx].path;

            logln(
                HS_INFO,
                "State loaded from %s%s%s",
                g_light_magenta,
                path,
                g_reset
            );

            free(app->emulation.quickload_request.data);

            app->emulation.quickload_request.enabled = false;
            app->emulation.quickload_request.data = NULL;
            break;
        };
    }
    gba_delete_notification(notif);
}

void
app_game_process_all_notifs(
    struct app *app
) {
    struct channel *channel;
    struct event_header const *event;

    channel = &app->emulation.gba->channels.notifications;

    channel_lock(channel);
    {
        event = channel_next(channel, NULL);
        while (event) {
            app_game_process_notif(app, event);
            event = channel_next(channel, event);
        }
        channel_clear(channel);
    }
    channel_release(channel);
}

void
app_game_wait_for_notif(
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
            app_game_process_notif(app, event);
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

static
void
app_game_unconfigure(
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
}

static
bool
app_game_configure_bios(
    struct app *app
) {
    FILE *file;
    void *data;
    char *error_msg;

    if (!app->file.bios_path) {
        error_msg = hs_format(
            "no BIOS found.\n\nPlease download and select a valid Nintendo GBA Bios using \"File\" -> \"Open BIOS\"."
        );
        gui_new_error(app, error_msg);
        return (true);
    }

    file = hs_fopen(app->file.bios_path, "rb");
    if (!file) {
        error_msg = hs_format(
            "failed to open %s: %s.",
            app->file.bios_path,
            strerror(errno)
        );
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
        error_msg = hs_format(
            "failed to read %s: %s.",
            app->file.bios_path,
            strerror(errno)
        );
        gui_new_error(app, error_msg);
        free(data);
        return (true);
    }

    app->emulation.launch_config->bios.data = data;
    app->emulation.launch_config->bios.size = BIOS_SIZE;

    return (false);
}

static
bool
app_game_configure_rom(
    struct app *app,
    char const *rom_path
) {
    FILE *file;
    size_t file_len;
    void *data;
    char *error_msg;

    file = hs_fopen(rom_path, "rb");
    if (!file) {
        error_msg = hs_format(
            "failed to open %s: %s.",
            rom_path,
            strerror(errno)
        );
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
        error_msg = hs_format(
            "failed to read %s: %s.",
            rom_path,
            strerror(errno)
        );
        gui_new_error(app, error_msg);
        free(data);
        return (true);
    }

    app->emulation.launch_config->rom.data = data;
    app->emulation.launch_config->rom.size = file_len;

    return (false);
}

static
bool
app_game_configure_backup(
    struct app *app,
    char const *backup_path
) {
    size_t file_len;
    char *error_msg;

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
        logln(HS_WARNING, "Failed to open the save file. A new one is created instead.");

        app->emulation.backup_file = hs_fopen(backup_path, "wb+");

        if (!app->emulation.backup_file) {
            error_msg = hs_format(
                "failed to create %s: %s.",
                backup_path,
                strerror(errno)
            );
            gui_new_error(app, error_msg);
            return (true);
        }
    }
    return (false);
}

/*
** Update the launch configuration with the current settings and print the emulator's configuration.
*/
static
void
app_game_configure_settings(
    struct app *app
) {
    app->emulation.launch_config->skip_bios = app->emulation.skip_bios;
    app->emulation.launch_config->speed = app->emulation.speed;
    app->emulation.launch_config->audio_frequency = GBA_CYCLES_PER_SECOND / app->audio.resample_frequency;

    if (app->emulation.rtc.autodetect) {
        app->emulation.launch_config->rtc = (bool)(app->emulation.game_entry->flags & GAME_ENTRY_FLAGS_RTC);
    } else {
        app->emulation.launch_config->rtc = app->emulation.rtc.enabled;
    }

    if (app->emulation.backup_storage.autodetect) {
        app->emulation.launch_config->backup_storage.type = app->emulation.game_entry->storage;
    } else {
        app->emulation.launch_config->backup_storage.type = app->emulation.backup_storage.type;
    }

    logln(HS_INFO, "Emulator's configuration:");
    logln(HS_INFO, "    Skip BIOS: %s", app->emulation.launch_config->skip_bios ? "true" : "false");
    logln(HS_INFO, "    Backup storage: %s", backup_storage_names[app->emulation.launch_config->backup_storage.type]);
    logln(HS_INFO, "    Rtc: %s", app->emulation.launch_config->rtc ? "true" : "false");
    logln(HS_INFO, "    Speed: %i", app->emulation.speed);
    logln(HS_INFO, "    Audio Frequency: %iHz (%i cycles)", app->audio.resample_frequency, app->emulation.launch_config->audio_frequency);
}

/*
** Update the GBA's launch configuration to load a new game
**
** This function abstracts all the different step needed to load a game:
**   - Read the BIOS/ROM files
**   - Extracting the game code
**   - Performing a database lookup to identify the features of the game
**   - Update the gba's launch configuration
*/
bool
app_game_configure(
    struct app *app,
    char const *rom_path
) {
    char *backup_path;
    char *extension;
    size_t basename_len;
    size_t i;
    uint8_t *code;

    app_game_unconfigure(app);

    app->emulation.launch_config = calloc(1, sizeof(struct launch_config));
    hs_assert(app->emulation.launch_config);

    extension = strrchr(rom_path, '.');

    if (extension) {
        basename_len = extension - rom_path;
    } else {
        basename_len = strlen(rom_path);
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

    if (app_game_configure_bios(app)
        || app_game_configure_rom(app, rom_path)
        || app_game_configure_backup(app, backup_path)
    ) {
        app_game_unconfigure(app);
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

    app_game_reset(app);

    gui_config_push_recent_rom(app, rom_path);

    return (false);
}

/*
** Reset the already-configured emulation.
*/
void
app_game_reset(
    struct app *app
) {
    struct message_reset event;

    hs_assert(app->emulation.launch_config);

    app_game_configure_settings(app);

    event.header.kind = MESSAGE_RESET;
    event.header.size = sizeof(event);

    memcpy(&event.config, app->emulation.launch_config, sizeof(event.config));

    /*
    ** Process all notifications before sending the reset message to make sure the NOTIFICATION_RESET we will
    ** receive comes from the correct reset message.
    */

    app_game_process_all_notifs(app);
    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);

    app_game_wait_for_notif(app, NOTIFICATION_RESET);
}

/*
** Stop the emulation and return to a neutral state.
*/
void
app_game_stop(
    struct app *app
) {
    struct message event;

    app_game_unconfigure(app);

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
app_game_run(
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
app_game_pause(
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
*/
void
app_game_exit(
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
app_game_key(
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
** Update the emulator's speed.
*/
void
app_game_speed(
    struct app *app,
    uint32_t speed
) {
    struct message_speed event;

    event.header.kind = MESSAGE_SPEED;
    event.header.size = sizeof(event);
    event.speed = speed;

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Write the content of the backup storage on the disk, only if it's dirty.
*/
void
app_game_update_backup(
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
** Take a screenshot of the game and writes it to the disk.
*/
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

    pthread_mutex_lock(&app->emulation.gba->shared_data.framebuffer.lock);
    out = stbi_write_png(
        filename,
        GBA_SCREEN_WIDTH,
        GBA_SCREEN_HEIGHT,
        4,
        app->emulation.gba->shared_data.framebuffer.data,
        GBA_SCREEN_WIDTH * sizeof(uint32_t)
    );
    pthread_mutex_unlock(&app->emulation.gba->shared_data.framebuffer.lock);

    if (out) {
        logln(
            HS_INFO,
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

void
app_game_quicksave(
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
app_game_quickload(
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
        return ;
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
    logln(
        HS_INFO,
        "%sError: failed to load state from %s: %s%s",
        g_light_red,
        path,
        strerror(errno),
        g_reset
    );

    free(data);

finally:
    if (file) {
        fclose(file);
    }
}

#ifdef WITH_DEBUGGER

#include "dbg/dbg.h"

/*
** Run until the end of the current frame.
*/
void
app_game_frame(
    struct app *app
) {
    struct message event;

    event.header.kind = MESSAGE_FRAME;
    event.header.size = sizeof(event);

    channel_lock(&app->emulation.gba->channels.messages);
    channel_push(&app->emulation.gba->channels.messages, &event.header);
    channel_release(&app->emulation.gba->channels.messages);
}

/*
** Trace the emulation.
*/
void
app_game_trace(
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
app_game_step_in(
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
app_game_step_over(
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
app_game_set_breakpoints_list(
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
app_game_set_watchpoints_list(
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
