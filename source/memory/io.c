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
        case IO_REG_DISPCNT:        return ("REG_DISPCNT");
        case IO_REG_GREENSWP:       return ("REG_GREENSWP");
        case IO_REG_DISPSTAT:       return ("REG_DISPSTAT");
        case IO_REG_VCOUNT:         return ("REG_VCOUNT");
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
        default:                    return ("UNKNOWN");
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
        case IO_REG_VCOUNT:                 return (gba->video.h);
        case IO_REG_DISPSTAT_0:
            {
                struct io_reg_dispstat dispstat;

                dispstat.vblank = (gba->video.v >= 160);
                dispstat.hblank = (gba->video.h >= 240);
                return (dispstat.byte0);
            }
            break;
        case IO_REG_DMA0SAD_0:              return (gba->memory.dma_channels[0].src.bytes[0]);
        case IO_REG_DMA0SAD_1:              return (gba->memory.dma_channels[0].src.bytes[1]);
        case IO_REG_DMA0SAD_2:              return (gba->memory.dma_channels[0].src.bytes[2]);
        case IO_REG_DMA0SAD_3:              return (gba->memory.dma_channels[0].src.bytes[3]);
        case IO_REG_DMA0DAD_0:              return (gba->memory.dma_channels[0].dst.bytes[0]);
        case IO_REG_DMA0DAD_1:              return (gba->memory.dma_channels[0].dst.bytes[1]);
        case IO_REG_DMA0DAD_2:              return (gba->memory.dma_channels[0].dst.bytes[2]);
        case IO_REG_DMA0DAD_3:              return (gba->memory.dma_channels[0].dst.bytes[3]);
        case IO_REG_DMA0CNT_0:              return (gba->memory.dma_channels[0].count.bytes[0]);
        case IO_REG_DMA0CNT_1:              return (gba->memory.dma_channels[0].count.bytes[1]);
        case IO_REG_DMA0CTL_0:              return (gba->memory.dma_channels[0].control.bytes[0]);
        case IO_REG_DMA0CTL_1:              return (gba->memory.dma_channels[0].control.bytes[1]);
        case IO_REG_DMA1SAD_0:              return (gba->memory.dma_channels[1].src.bytes[0]);
        case IO_REG_DMA1SAD_1:              return (gba->memory.dma_channels[1].src.bytes[1]);
        case IO_REG_DMA1SAD_2:              return (gba->memory.dma_channels[1].src.bytes[2]);
        case IO_REG_DMA1SAD_3:              return (gba->memory.dma_channels[1].src.bytes[3]);
        case IO_REG_DMA1DAD_0:              return (gba->memory.dma_channels[1].dst.bytes[0]);
        case IO_REG_DMA1DAD_1:              return (gba->memory.dma_channels[1].dst.bytes[1]);
        case IO_REG_DMA1DAD_2:              return (gba->memory.dma_channels[1].dst.bytes[2]);
        case IO_REG_DMA1DAD_3:              return (gba->memory.dma_channels[1].dst.bytes[3]);
        case IO_REG_DMA1CNT_0:              return (gba->memory.dma_channels[1].count.bytes[0]);
        case IO_REG_DMA1CNT_1:              return (gba->memory.dma_channels[1].count.bytes[1]);
        case IO_REG_DMA1CTL_0:              return (gba->memory.dma_channels[1].control.bytes[0]);
        case IO_REG_DMA1CTL_1:              return (gba->memory.dma_channels[1].control.bytes[1]);
        case IO_REG_DMA2SAD_0:              return (gba->memory.dma_channels[2].src.bytes[0]);
        case IO_REG_DMA2SAD_1:              return (gba->memory.dma_channels[2].src.bytes[1]);
        case IO_REG_DMA2SAD_2:              return (gba->memory.dma_channels[2].src.bytes[2]);
        case IO_REG_DMA2SAD_3:              return (gba->memory.dma_channels[2].src.bytes[3]);
        case IO_REG_DMA2DAD_0:              return (gba->memory.dma_channels[2].dst.bytes[0]);
        case IO_REG_DMA2DAD_1:              return (gba->memory.dma_channels[2].dst.bytes[1]);
        case IO_REG_DMA2DAD_2:              return (gba->memory.dma_channels[2].dst.bytes[2]);
        case IO_REG_DMA2DAD_3:              return (gba->memory.dma_channels[2].dst.bytes[3]);
        case IO_REG_DMA2CNT_0:              return (gba->memory.dma_channels[2].count.bytes[0]);
        case IO_REG_DMA2CNT_1:              return (gba->memory.dma_channels[2].count.bytes[1]);
        case IO_REG_DMA2CTL_0:              return (gba->memory.dma_channels[2].control.bytes[0]);
        case IO_REG_DMA2CTL_1:              return (gba->memory.dma_channels[2].control.bytes[1]);
        case IO_REG_DMA3SAD_0:              return (gba->memory.dma_channels[3].src.bytes[0]);
        case IO_REG_DMA3SAD_1:              return (gba->memory.dma_channels[3].src.bytes[1]);
        case IO_REG_DMA3SAD_2:              return (gba->memory.dma_channels[3].src.bytes[2]);
        case IO_REG_DMA3SAD_3:              return (gba->memory.dma_channels[3].src.bytes[3]);
        case IO_REG_DMA3DAD_0:              return (gba->memory.dma_channels[3].dst.bytes[0]);
        case IO_REG_DMA3DAD_1:              return (gba->memory.dma_channels[3].dst.bytes[1]);
        case IO_REG_DMA3DAD_2:              return (gba->memory.dma_channels[3].dst.bytes[2]);
        case IO_REG_DMA3DAD_3:              return (gba->memory.dma_channels[3].dst.bytes[3]);
        case IO_REG_DMA3CNT_0:              return (gba->memory.dma_channels[3].count.bytes[0]);
        case IO_REG_DMA3CNT_1:              return (gba->memory.dma_channels[3].count.bytes[1]);
        case IO_REG_DMA3CTL_0:              return (gba->memory.dma_channels[3].control.bytes[0]);
        case IO_REG_DMA3CTL_1:              return (gba->memory.dma_channels[3].control.bytes[1]);
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
    hs_logln(HS_IO, "IO write to %s (%#08x) (%x)", mem_io_reg_name(addr & ~1), addr, val);
    switch (addr) {
        case IO_REG_DMA0SAD_0:              gba->memory.dma_channels[0].src.bytes[0] = val; break;
        case IO_REG_DMA0SAD_1:              gba->memory.dma_channels[0].src.bytes[1] = val; break;
        case IO_REG_DMA0SAD_2:              gba->memory.dma_channels[0].src.bytes[2] = val; break;
        case IO_REG_DMA0SAD_3:              gba->memory.dma_channels[0].src.bytes[3] = val; break;
        case IO_REG_DMA0DAD_0:              gba->memory.dma_channels[0].dst.bytes[0] = val; break;
        case IO_REG_DMA0DAD_1:              gba->memory.dma_channels[0].dst.bytes[1] = val; break;
        case IO_REG_DMA0DAD_2:              gba->memory.dma_channels[0].dst.bytes[2] = val; break;
        case IO_REG_DMA0DAD_3:              gba->memory.dma_channels[0].dst.bytes[3] = val; break;
        case IO_REG_DMA0CNT_0:              gba->memory.dma_channels[0].count.bytes[0] = val; break;
        case IO_REG_DMA0CNT_1:              gba->memory.dma_channels[0].count.bytes[1] = val; break;
        case IO_REG_DMA0CTL_0:              gba->memory.dma_channels[0].control.bytes[0] = val; break;
        case IO_REG_DMA0CTL_1:
            gba->memory.dma_channels[0].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;
        case IO_REG_DMA1SAD_0:              gba->memory.dma_channels[1].src.bytes[0] = val; break;
        case IO_REG_DMA1SAD_1:              gba->memory.dma_channels[1].src.bytes[1] = val; break;
        case IO_REG_DMA1SAD_2:              gba->memory.dma_channels[1].src.bytes[2] = val; break;
        case IO_REG_DMA1SAD_3:              gba->memory.dma_channels[1].src.bytes[3] = val; break;
        case IO_REG_DMA1DAD_0:              gba->memory.dma_channels[1].dst.bytes[0] = val; break;
        case IO_REG_DMA1DAD_1:              gba->memory.dma_channels[1].dst.bytes[1] = val; break;
        case IO_REG_DMA1DAD_2:              gba->memory.dma_channels[1].dst.bytes[2] = val; break;
        case IO_REG_DMA1DAD_3:              gba->memory.dma_channels[1].dst.bytes[3] = val; break;
        case IO_REG_DMA1CNT_0:              gba->memory.dma_channels[1].count.bytes[0] = val; break;
        case IO_REG_DMA1CNT_1:              gba->memory.dma_channels[1].count.bytes[1] = val; break;
        case IO_REG_DMA1CTL_0:              gba->memory.dma_channels[1].control.bytes[0] = val; break;
        case IO_REG_DMA1CTL_1:
            gba->memory.dma_channels[1].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;
        case IO_REG_DMA2SAD_0:              gba->memory.dma_channels[2].src.bytes[0] = val; break;
        case IO_REG_DMA2SAD_1:              gba->memory.dma_channels[2].src.bytes[1] = val; break;
        case IO_REG_DMA2SAD_2:              gba->memory.dma_channels[2].src.bytes[2] = val; break;
        case IO_REG_DMA2SAD_3:              gba->memory.dma_channels[2].src.bytes[3] = val; break;
        case IO_REG_DMA2DAD_0:              gba->memory.dma_channels[2].dst.bytes[0] = val; break;
        case IO_REG_DMA2DAD_1:              gba->memory.dma_channels[2].dst.bytes[1] = val; break;
        case IO_REG_DMA2DAD_2:              gba->memory.dma_channels[2].dst.bytes[2] = val; break;
        case IO_REG_DMA2DAD_3:              gba->memory.dma_channels[2].dst.bytes[3] = val; break;
        case IO_REG_DMA2CNT_0:              gba->memory.dma_channels[2].count.bytes[0] = val; break;
        case IO_REG_DMA2CNT_1:              gba->memory.dma_channels[2].count.bytes[1] = val; break;
        case IO_REG_DMA2CTL_0:              gba->memory.dma_channels[2].control.bytes[0] = val; break;
        case IO_REG_DMA2CTL_1:
            gba->memory.dma_channels[2].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;
        case IO_REG_DMA3SAD_0:              gba->memory.dma_channels[3].src.bytes[0] = val; break;
        case IO_REG_DMA3SAD_1:              gba->memory.dma_channels[3].src.bytes[1] = val; break;
        case IO_REG_DMA3SAD_2:              gba->memory.dma_channels[3].src.bytes[2] = val; break;
        case IO_REG_DMA3SAD_3:              gba->memory.dma_channels[3].src.bytes[3] = val; break;
        case IO_REG_DMA3DAD_0:              gba->memory.dma_channels[3].dst.bytes[0] = val; break;
        case IO_REG_DMA3DAD_1:              gba->memory.dma_channels[3].dst.bytes[1] = val; break;
        case IO_REG_DMA3DAD_2:              gba->memory.dma_channels[3].dst.bytes[2] = val; break;
        case IO_REG_DMA3DAD_3:              gba->memory.dma_channels[3].dst.bytes[3] = val; break;
        case IO_REG_DMA3CNT_0:              gba->memory.dma_channels[3].count.bytes[0] = val; break;
        case IO_REG_DMA3CNT_1:              gba->memory.dma_channels[3].count.bytes[1] = val; break;
        case IO_REG_DMA3CTL_0:              gba->memory.dma_channels[3].control.bytes[0] = val; break;
        case IO_REG_DMA3CTL_1:
            gba->memory.dma_channels[3].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;
    }
}