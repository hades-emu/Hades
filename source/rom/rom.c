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
#include "rom.h"
#include "core.h"
#include "hades.h"

/*
** Load the ROM.
**
** It's recommended to reset the CPU before using (re)loading a ROM, or unpredictable things might happen.
*/
void
rom_load(
    struct core *core,
    FILE *file
) {
    fread(core->memory + 0x08000000, 1, 0x2000000, file);
    fread(core->memory + 0x0a000000, 1, 0x2000000, file);
    fread(core->memory + 0x0c000000, 1, 0x2000000, file);
}