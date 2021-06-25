/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <sys/stat.h>
#include <fcntl.h>
#include "gba.h"

int
save_state(
    struct gba const *gba,
    char const *path
) {
    FILE *file;

    file = fopen(path, "w");
    if (!file) {
        return (-1);
    }

    if (
           fwrite(&gba->core, sizeof(gba->core), 1, file) != 1
        || fwrite(&gba->memory, sizeof(gba->memory), 1, file) != 1
        || fwrite(&gba->io, sizeof(gba->io), 1, file) != 1
        //|| fwrite(&gba->scheduler, sizeof(gba->scheduler), 1, file) != 1
    ) {
        fclose(file);
        return (-1);
    }

    fclose(file);
    fflush(file);
    return (0);
}

int
load_state(
    struct gba *gba,
    char const *path
) {
    FILE *file;

    file = fopen(path, "r");
    if (!file) {
        return (-1);
    }

    if (
           fread(&gba->core, sizeof(gba->core), 1, file) != 1
        || fread(&gba->memory, sizeof(gba->memory), 1, file) != 1
        || fread(&gba->io, sizeof(gba->io), 1, file) != 1
        //|| fread(&gba->scheduler, sizeof(gba->scheduler), 1, file) != 1
    ) {
        fclose(file);
        return (-1);
    }

    fclose(file);
    return (0);
}