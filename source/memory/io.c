/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "memory.h"
#include "gba.h"

/*
**
*/
char const *
mem_io_reg_name(
    uint32_t addr
) {
    switch (addr) {
        case IO_REG_DISPCNT:
            return ("REG_DISPCNT");
        case IO_REG_GREENSWP:
            return ("REG_GREENSWP");
        case IO_REG_DISPSTAT:
            return ("REG_DISPSTAT");
        case IO_REG_VCOUNT:
            return ("REG_VCOUNT");
        default:
            return ("UNKNOWN");
    }
};

/*
** Call the appropriate module linked to each IO register to build and
** return the corresponding register value.
*/
uint16_t
mem_io_read8(
    struct gba const *gba,
    uint32_t addr
) {
    hs_logln(HS_IO, "IO read to %s (%#08x)", mem_io_reg_name(addr & ~1), addr);

    switch (addr) {
        case IO_REG_VCOUNT:
            return (gba->video.h);
        case IO_REG_DISPSTAT_0:
            {
                struct io_reg_dispstat dispstat;

                dispstat.vblank = (gba->video.v >= 160);
                dispstat.hblank = (gba->video.h >= 240);
                return (dispstat.byte0);
            }
            break;
    }
    return (0);
}

/*
** Write the given value to the internal data of the appropriate device.
*/
void
mem_io_write8(
    struct gba *gba,
    uint32_t addr,
    uint8_t val
) {
    hs_logln(HS_IO, "IO write to %s (%#08x)", mem_io_reg_name(addr & ~1), addr);
}