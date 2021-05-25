/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "memory.h"

/*
** Call the appropriate module linked to each IO register.
** Only the address is given, the value can be fetched from memory.
*/
void
mem_io_write(
    struct memory *memory,
    uint32_t addr
) {
    //hs_logln(HS_IO, "IO write to %#08x: %#08x", addr, mem_read32(memory, addr));

    switch (addr) {
        case REG_DISPCNT:
            break;
    }
}