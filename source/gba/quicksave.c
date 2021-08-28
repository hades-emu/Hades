/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "gba.h"
#include "scheduler.h"

/*
** Save the current state of the emulator in the file pointed by `path`.
*/
void
quicksave(
    struct gba *gba,
    char const *path
) {
    FILE *file;
    size_t i;

    file = fopen(path, "wb");
    if (!file) {
        goto err;
    }

    if (
           fwrite(&gba->core, sizeof(gba->core), 1, file) != 1
        || fwrite(&gba->memory, sizeof(gba->memory), 1, file) != 1
        || fwrite(&gba->io, sizeof(gba->io), 1, file) != 1
        || fwrite(&gba->scheduler.next_event, sizeof(uint64_t), 1, file) != 1
    ) {
        goto err;
    }

    // Serialize the scheduler's event list
    for (i = 0; i < gba->scheduler.events_size; ++i) {
        struct scheduler_event *event;

        event = gba->scheduler.events + i;
        if (
               fwrite(&event->active, sizeof(bool), 1, file) != 1
            || fwrite(&event->repeat, sizeof(bool), 1, file) != 1
            || fwrite(&event->at, sizeof(uint64_t), 1, file) != 1
            || fwrite(&event->period, sizeof(uint64_t), 1, file) != 1
        ) {
            goto err;
        }
    }

    fflush(file);

    logln(
        HS_GLOBAL,
        "State saved to %s%s%s",
        g_light_magenta,
        path,
        g_reset
    );

    goto finally;

err:
    logln(
        HS_GLOBAL,
        "%sError: failed to save state to %s: %s%s",
        g_light_red,
        path,
        strerror(errno),
        g_reset
    );

finally:

    fclose(file);
}

/*
** Load a new state for the emulator from the content of the file pointed by `path`.
*/
void
quickload(
    struct gba *gba,
    char const *path
) {
    FILE *file;
    size_t i;

    file = fopen(path, "rb");
    if (!file) {
        goto err;
    }

    if (
           fread(&gba->core, sizeof(gba->core), 1, file) != 1
        || fread(&gba->memory, sizeof(gba->memory), 1, file) != 1
        || fread(&gba->io, sizeof(gba->io), 1, file) != 1
        || fread(&gba->scheduler.next_event, sizeof(uint64_t), 1, file) != 1
    ) {
        goto err;
    }

    // Serialize the scheduler's event list
    for (i = 0; i < gba->scheduler.events_size; ++i) {
        struct scheduler_event *event;

        event = gba->scheduler.events + i;
        if (
               fread(&event->active, sizeof(bool), 1, file) != 1
            || fread(&event->repeat, sizeof(bool), 1, file) != 1
            || fread(&event->at, sizeof(uint64_t), 1, file) != 1
            || fread(&event->period, sizeof(uint64_t), 1, file) != 1
        ) {
            goto err;
        }
    }

    logln(
        HS_GLOBAL,
        "State loaded from %s%s%s",
        g_light_magenta,
        path,
        g_reset
    );

    goto finally;

err:
    logln(
        HS_GLOBAL,
        "%sError: failed to load state from %s: %s%s",
        g_light_red,
        path,
        strerror(errno),
        g_reset
    );

finally:

    if (file) {
        fclose(file);
    }
}