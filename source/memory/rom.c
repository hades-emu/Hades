/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "memory.h"
#include "hades.h"

/*
** Load the BIOS into the emulator's memory.
**
** This function exits on failure.
*/
int
mem_load_bios(
    struct memory *memory,
    char const *path
) {
    FILE *file;

    file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "hades: can't open gba_bios.gba: %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    if (ftell(file) != 0x4000) {
        fprintf(stderr, "hades: invalid bios given.\n");
        exit(EXIT_FAILURE);
        return (-1);
    }
    rewind(file);

    if (fread(memory->bios, 1, 0x4000, file) != 0x4000) {
        fprintf(stderr, "hades: failed to read gba_bios.gba: %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return (0);
}

/*
** Load the ROM into the emulator's memory.
**
** This function exits on failure.
*/
int
mem_load_rom(
    struct memory *memory,
    char const *path
) {
    FILE *file;
    size_t len __unused; // Used to silent the "Unused result" warning

    file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "hades: can't open %s: %s.\n", path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    len = fread(memory->bios, 1, 0x2000000, file);

    if (!feof(file)) {
        fprintf(stderr, "hades: failed to read %s: %s.\n", path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    return (0);
}