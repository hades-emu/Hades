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
** Load the ROM into the given RAM.
*/
int
mem_load_rom(
    struct memory *memory,
    char const *filename
) {
    FILE *file;

    file = fopen(filename, "rb");
    if (!file) {
        return (-1);
    }

    fread(memory->rom, 1, 0x2000000, file);
    return (0);
}