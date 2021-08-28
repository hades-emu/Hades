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
#include <stdio.h>
#include "gba.h"
#include "memory.h"
#include "hades.h"

/*
** Load the BIOS into the emulator's memory.
**
** This function exits on failure.
*/
int
gba_load_bios(
    struct gba *gba,
    char const *bios_path
) {
    FILE *file;

    file = fopen(bios_path, "rb");
    if (!file) {
        fprintf(stderr, "hades: can't open %s: %s.\n", bios_path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    if (ftell(file) != 0x4000) {
        fprintf(stderr, "hades: invalid bios.\n");
        exit(EXIT_FAILURE);
        return (-1);
    }
    rewind(file);

    if (fread(gba->memory.bios, 1, 0x4000, file) != 0x4000) {
        fprintf(stderr, "hades: failed to read %s: %s.\n", bios_path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    return (0);
}

/*
** Load the Game ROM into the emulator's memory.
**
** This function exits on failure.
**
** TODO: Ensure the loaded file is actually a GBA game.
*/
int
gba_load_rom(
    struct gba *gba,
    char const *rom_path
) {
    FILE *file;
    long file_len;
    size_t len;
    char *extension;

    file = fopen(rom_path, "rb");
    if (!file) {
        fprintf(stderr, "hades: can't open %s: %s.\n", rom_path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    file_len = ftell(file);
    if (file_len > 0x2000000 || file_len < 192) {
        fprintf(stderr, "hades: %s: invalid game.\n", rom_path);
        exit(EXIT_FAILURE);
    }
    rewind(file);

    len = fread(gba->memory.rom, 1, 0x2000000, file);

    if (len != file_len) {
        fprintf(stderr, "hades: failed to read %s: %s.\n", rom_path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    gba->rom_path = rom_path;

    // Build the path pointing to the save state
    // (aka path/to/rom.gba but ending with .hds instead)
    extension = strrchr(gba->rom_path, '.');
    gba->save_path = calloc(extension - gba->rom_path + 5, 1);
    hs_assert(gba->save_path);
    strncpy(gba->save_path, gba->rom_path, extension - gba->rom_path);
    strcat(gba->save_path, ".hds");

    return (0);
}