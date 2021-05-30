/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "memory.h"
#include "gba.h"

void
io_init(
    struct io *io
) {
    memset(io, 0, sizeof(*io));
    io->keyinput.raw = 0x3FF; // Every button set to "released"
}

/*
** Return the name of the given IO register.
*/
char const *
mem_io_reg_name(
    uint32_t addr
) {
    switch (addr & ~1) {
        case IO_REG_DISPCNT:        return ("REG_DISPCNT");
        case IO_REG_GREENSWP:       return ("REG_GREENSWP");
        case IO_REG_DISPSTAT:       return ("REG_DISPSTAT");
        case IO_REG_VCOUNT:         return ("REG_VCOUNT");
        case IO_REG_SOUNDBIAS:      return ("REG_SOUNDBIAS");
        case IO_REG_DMA0SAD_LO:     return ("REG_DMA0SAD_LO");
        case IO_REG_DMA0SAD_HI:     return ("REG_DMA0SAD_HI");
        case IO_REG_DMA0DAD_LO:     return ("REG_DMA0DAD_LO");
        case IO_REG_DMA0DAD_HI:     return ("REG_DMA0DAD_HI");
        case IO_REG_DMA0CNT:        return ("REG_DMA0CNT");
        case IO_REG_DMA0CTL:        return ("REG_DMA0CTL");
        case IO_REG_DMA1SAD_LO:     return ("REG_DMA1SAD_LO");
        case IO_REG_DMA1SAD_HI:     return ("REG_DMA1SAD_HI");
        case IO_REG_DMA1DAD_LO:     return ("REG_DMA1DAD_LO");
        case IO_REG_DMA1DAD_HI:     return ("REG_DMA1DAD_HI");
        case IO_REG_DMA1CNT:        return ("REG_DMA1CNT");
        case IO_REG_DMA1CTL:        return ("REG_DMA1CTL");
        case IO_REG_DMA2SAD_LO:     return ("REG_DMA2SAD_LO");
        case IO_REG_DMA2SAD_HI:     return ("REG_DMA2SAD_HI");
        case IO_REG_DMA2DAD_LO:     return ("REG_DMA2DAD_LO");
        case IO_REG_DMA2DAD_HI:     return ("REG_DMA2DAD_HI");
        case IO_REG_DMA2CNT:        return ("REG_DMA2CNT");
        case IO_REG_DMA2CTL:        return ("REG_DMA2CTL");
        case IO_REG_DMA3SAD_LO:     return ("REG_DMA3SAD_LO");
        case IO_REG_DMA3SAD_HI:     return ("REG_DMA3SAD_HI");
        case IO_REG_DMA3DAD_LO:     return ("REG_DMA3DAD_LO");
        case IO_REG_DMA3DAD_HI:     return ("REG_DMA3DAD_HI");
        case IO_REG_DMA3CNT:        return ("REG_DMA3CNT");
        case IO_REG_DMA3CTL:        return ("REG_DMA3CTL");
        case IO_REG_KEYINPUT:       return ("REG_KEYINPUT");
        case IO_REG_IE:             return ("REG_IE");
        case IO_REG_IF:             return ("REG_IF");
        case IO_REG_IME:            return ("REG_IME");
        default:                    return ("UNKNOWN");
    }
};

/*
** Read the value contained in the corresponding IO register.
*/
uint8_t
mem_io_read8(
    struct gba const *gba,
    uint32_t addr
) {
    struct io const *io;

    hs_logln(HS_IO, "IO read to %s (%#08x)", mem_io_reg_name(addr), addr);

    io = &gba->io;
    switch (addr) {

        /* Display */
        case IO_REG_DISPCNT:                return (io->dispcnt.bytes[0]);
        case IO_REG_DISPCNT + 1:            return (io->dispcnt.bytes[1]);
        case IO_REG_DISPSTAT:               return (io->dispstat.bytes[0]);
        case IO_REG_DISPSTAT + 1:           return (io->dispstat.bytes[1]);
        case IO_REG_VCOUNT:                 return (gba->video.h);

        /* Sound */
        case IO_REG_SOUNDBIAS:              return (0x0);
        case IO_REG_SOUNDBIAS + 1:          return (0b10);

        /* DMA - Channel 0 */
        case IO_REG_DMA0CTL:                return (io->dma[0].control.bytes[0]);
        case IO_REG_DMA0CTL + 1:            return (io->dma[0].control.bytes[1]);

        /* DMA - Channel 1 */
        case IO_REG_DMA1CTL:                return (io->dma[1].control.bytes[0]);
        case IO_REG_DMA1CTL + 1:            return (io->dma[1].control.bytes[1]);

        /* DMA - Channel 2 */
        case IO_REG_DMA2CTL:                return (io->dma[2].control.bytes[0]);
        case IO_REG_DMA2CTL + 1:            return (io->dma[2].control.bytes[1]);

        /* DMA - Channel 3 */
        case IO_REG_DMA3CTL:                return (io->dma[3].control.bytes[0]);
        case IO_REG_DMA3CTL + 1:            return (io->dma[3].control.bytes[1]);

        /* Inputs */
        case IO_REG_KEYINPUT:               return (io->keyinput.bytes[0]);
        case IO_REG_KEYINPUT + 1:           return (io->keyinput.bytes[1]);
    }
    return (0);
}

/*
** Write the given value to the corresponding IO register.
*/
void
mem_io_write8(
    struct gba *gba,
    uint32_t addr,
    uint8_t val
) {
    struct io *io;

    hs_logln(HS_IO, "IO write to %s (%#08x) (%x)", mem_io_reg_name(addr), addr, val);

    io = &gba->io;
    switch (addr) {

        /* Display */
        case IO_REG_DISPCNT:                io->dispcnt.bytes[0] = val; break;
        case IO_REG_DISPCNT + 1:            io->dispcnt.bytes[1] = val; break;
        case IO_REG_DISPSTAT:               io->dispstat.bytes[0] = val; break;
        case IO_REG_DISPSTAT + 1:           io->dispstat.bytes[1] = val; break;

        /* DMA - Channel 0 */
        case IO_REG_DMA0SAD:                io->dma[0].src.bytes[0] = val; break;
        case IO_REG_DMA0SAD + 1:            io->dma[0].src.bytes[1] = val; break;
        case IO_REG_DMA0SAD + 2:            io->dma[0].src.bytes[2] = val; break;
        case IO_REG_DMA0SAD + 3:            io->dma[0].src.bytes[3] = val; break;
        case IO_REG_DMA0DAD:                io->dma[0].dst.bytes[0] = val; break;
        case IO_REG_DMA0DAD + 1:            io->dma[0].dst.bytes[1] = val; break;
        case IO_REG_DMA0DAD + 2:            io->dma[0].dst.bytes[2] = val; break;
        case IO_REG_DMA0DAD + 3:            io->dma[0].dst.bytes[3] = val; break;
        case IO_REG_DMA0CNT:                io->dma[0].count.bytes[0] = val; break;
        case IO_REG_DMA0CNT + 1:            io->dma[0].count.bytes[1] = val; break;
        case IO_REG_DMA0CTL:                io->dma[0].control.bytes[0] = val; break;
        case IO_REG_DMA0CTL + 1:
            io->dma[0].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;

        /* DMA - Channel 1 */
        case IO_REG_DMA1SAD:                io->dma[1].src.bytes[0] = val; break;
        case IO_REG_DMA1SAD + 1:            io->dma[1].src.bytes[1] = val; break;
        case IO_REG_DMA1SAD + 2:            io->dma[1].src.bytes[2] = val; break;
        case IO_REG_DMA1SAD + 3:            io->dma[1].src.bytes[3] = val; break;
        case IO_REG_DMA1DAD:                io->dma[1].dst.bytes[0] = val; break;
        case IO_REG_DMA1DAD + 1:            io->dma[1].dst.bytes[1] = val; break;
        case IO_REG_DMA1DAD + 2:            io->dma[1].dst.bytes[2] = val; break;
        case IO_REG_DMA1DAD + 3:            io->dma[1].dst.bytes[3] = val; break;
        case IO_REG_DMA1CNT:                io->dma[1].count.bytes[0] = val; break;
        case IO_REG_DMA1CNT + 1:            io->dma[1].count.bytes[1] = val; break;
        case IO_REG_DMA1CTL:                io->dma[1].control.bytes[0] = val; break;
        case IO_REG_DMA1CTL + 1:
            io->dma[1].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;

        /* DMA - Channel 2 */
        case IO_REG_DMA2SAD:                io->dma[2].src.bytes[0] = val; break;
        case IO_REG_DMA2SAD + 1:            io->dma[2].src.bytes[1] = val; break;
        case IO_REG_DMA2SAD + 2:            io->dma[2].src.bytes[2] = val; break;
        case IO_REG_DMA2SAD + 3:            io->dma[2].src.bytes[3] = val; break;
        case IO_REG_DMA2DAD:                io->dma[2].dst.bytes[0] = val; break;
        case IO_REG_DMA2DAD + 1:            io->dma[2].dst.bytes[1] = val; break;
        case IO_REG_DMA2DAD + 2:            io->dma[2].dst.bytes[2] = val; break;
        case IO_REG_DMA2DAD + 3:            io->dma[2].dst.bytes[3] = val; break;
        case IO_REG_DMA2CNT:                io->dma[2].count.bytes[0] = val; break;
        case IO_REG_DMA2CNT + 1:            io->dma[2].count.bytes[1] = val; break;
        case IO_REG_DMA2CTL:                io->dma[2].control.bytes[0] = val; break;
        case IO_REG_DMA2CTL + 1:
            io->dma[2].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;

        /* DMA - Channel 3 */
        case IO_REG_DMA3SAD:                io->dma[3].src.bytes[0] = val; break;
        case IO_REG_DMA3SAD + 1:            io->dma[3].src.bytes[1] = val; break;
        case IO_REG_DMA3SAD + 2:            io->dma[3].src.bytes[2] = val; break;
        case IO_REG_DMA3SAD + 3:            io->dma[3].src.bytes[3] = val; break;
        case IO_REG_DMA3DAD:                io->dma[3].dst.bytes[0] = val; break;
        case IO_REG_DMA3DAD + 1:            io->dma[3].dst.bytes[1] = val; break;
        case IO_REG_DMA3DAD + 2:            io->dma[3].dst.bytes[2] = val; break;
        case IO_REG_DMA3DAD + 3:            io->dma[3].dst.bytes[3] = val; break;
        case IO_REG_DMA3CNT:                io->dma[3].count.bytes[0] = val; break;
        case IO_REG_DMA3CNT + 1:            io->dma[3].count.bytes[1] = val; break;
        case IO_REG_DMA3CTL:                io->dma[3].control.bytes[0] = val; break;
        case IO_REG_DMA3CTL + 1:
            io->dma[3].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;
    }
}