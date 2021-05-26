/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

/*
** References:
**   * GBATEK
**      https://problemkaputt.de/gbatek.htm
**
*/

#include <stdio.h>
#include "memory.h"
#include "hades.h"

/*
** Load the BIOS into the emulator's memory.
*/
int
mem_load_bios(
    struct memory *memory,
    char const *path
) {
    FILE *file;

    file = fopen(path, "rb");
    if (!file) {
        return (-1);
    }

    fread(memory->bios, 1, 0x4000, file);
    return (0);
}

/*
** Load the ROM into the emulator's memory.
*/
int
mem_load_rom(
    struct memory *memory,
    char const *path
) {
    FILE *file;

    file = fopen(path, "rb");
    if (!file) {
        return (-1);
    }

    fread(memory->rom, 1, 0x2000000, file);
    return (0);
}