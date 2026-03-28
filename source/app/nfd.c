/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "app/app.h"

void
app_nfd_process_events(
    struct app *app
) {
    struct nfd_event *event;
    struct nfd_event *next;

    pthread_mutex_lock(&app->sdl.nfd.lock);

    event = app->sdl.nfd.head;

    while (event) {
        switch (event->kind) {
            case NFD_BIOS_PATH: {
                free(app->settings.emulation.bios_path);
                app->settings.emulation.bios_path = event->path;
                logln(HS_INFO, "BIOS updated to \"%s%s%s\".", g_light_green, app->settings.emulation.bios_path, g_reset);
                break;
            };
            case NFD_ROM_PATH: {
                app_emulator_configure_and_run(app, event->path, NULL);
                free(event->path);
                break;
            };
            case NFD_EXPORT_SAVE: {
                app_emulator_export_save_to_path(app, event->path);
                free(event->path);
                break;
            };
            case NFD_IMPORT_SAVE: {
                char *game_path;

                game_path = strdup(app->emulation.game_path);
                app_emulator_configure_and_run(app, game_path, event->path);
                free(game_path);
                free(event->path);
                break;
            };
            case NFD_SAVE_DIR: {
                free(app->settings.general.directories.backup.path);
                app->settings.general.directories.backup.path = event->path;
                break;
            }
            case NFD_QUICKSAVE_DIR: {
                free(app->settings.general.directories.quicksave.path);
                app->settings.general.directories.quicksave.path = event->path;
                break;
            }
            case NFD_SCREENSHOT_DIR: {
                free(app->settings.general.directories.screenshot.path);
                app->settings.general.directories.screenshot.path = event->path;
                break;
            }
        }

        next = event->next;
        free(event);
        event = next;
    }

    app->sdl.nfd.head = NULL;

    pthread_mutex_unlock(&app->sdl.nfd.lock);
}

struct nfd_event *
app_nfd_create_event(
    struct app *app,
    enum nfd_event_kind kind
) {
    struct nfd_event *nfd_event;

    nfd_event = calloc(1, sizeof(struct nfd_event));
    hs_assert(nfd_event);

    nfd_event->app = app;
    nfd_event->kind = kind;

    return nfd_event;
}

void
app_nfd_update_path(
    void *raw_event,
    const char * const *filelist,
    int filter __unused
) {
    struct nfd_event *event;
    struct app *app;

    event = raw_event;
    app = event->app;

    if (!filelist || !*filelist) {
        free(event);
        return;
    }

    pthread_mutex_lock(&app->sdl.nfd.lock);
    event->next = app->sdl.nfd.head;
    event->path = strdup(filelist[0]);
    app->sdl.nfd.head = event;
    pthread_mutex_unlock(&app->sdl.nfd.lock);
}
