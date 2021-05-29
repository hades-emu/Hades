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
        default:                    return ("UNKNOWN");
    }
};

/*
** Call the appropriate module linked to each IO register to build and
** return the corresponding register value.
*/
uint8_t
mem_io_read8(
    struct gba const *gba,
    uint32_t addr
) {
    hs_logln(HS_IO, "IO read to %s (%#08x)", mem_io_reg_name(addr), addr);

    switch (addr) {
        /* General LCD Status */
        case IO_REG_DISPSTAT:
            {
                struct io_reg_dispstat dispstat;

                dispstat.vblank = (gba->video.v >= 160);
                dispstat.hblank = (gba->video.h >= 240);
                return (dispstat.byte0);
            }
            break;

        /* Vertical Counter */
        case IO_REG_VCOUNT:                 return (gba->video.h);

        /* Sound PWM Control */
        case IO_REG_SOUNDBIAS:              return (0x0);
        case IO_REG_SOUNDBIAS + 1:          return (0b10);

        /* DMA - Channel 0 */
        case IO_REG_DMA0CTL:                return (gba->memory.dma_channels[0].control.bytes[0]);
        case IO_REG_DMA0CTL + 1:            return (gba->memory.dma_channels[0].control.bytes[1]);

        /* DMA - Channel 1 */
        case IO_REG_DMA1CTL:                return (gba->memory.dma_channels[1].control.bytes[0]);
        case IO_REG_DMA1CTL + 1:            return (gba->memory.dma_channels[1].control.bytes[1]);

        /* DMA - Channel 2 */
        case IO_REG_DMA2CTL:                return (gba->memory.dma_channels[2].control.bytes[0]);
        case IO_REG_DMA2CTL + 1:            return (gba->memory.dma_channels[2].control.bytes[1]);

        /* DMA - Channel 3 */
        case IO_REG_DMA3CTL:                return (gba->memory.dma_channels[3].control.bytes[0]);
        case IO_REG_DMA3CTL + 1:            return (gba->memory.dma_channels[3].control.bytes[1]);
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
    hs_logln(HS_IO, "IO write to %s (%#08x) (%x)", mem_io_reg_name(addr), addr, val);
    switch (addr) {

        /* DMA - Channel 0 */
        case IO_REG_DMA0SAD:                gba->memory.dma_channels[0].src.bytes[0] = val; break;
        case IO_REG_DMA0SAD + 1:            gba->memory.dma_channels[0].src.bytes[1] = val; break;
        case IO_REG_DMA0SAD + 2:            gba->memory.dma_channels[0].src.bytes[2] = val; break;
        case IO_REG_DMA0SAD + 3:            gba->memory.dma_channels[0].src.bytes[3] = val; break;
        case IO_REG_DMA0DAD:                gba->memory.dma_channels[0].dst.bytes[0] = val; break;
        case IO_REG_DMA0DAD + 1:            gba->memory.dma_channels[0].dst.bytes[1] = val; break;
        case IO_REG_DMA0DAD + 2:            gba->memory.dma_channels[0].dst.bytes[2] = val; break;
        case IO_REG_DMA0DAD + 3:            gba->memory.dma_channels[0].dst.bytes[3] = val; break;
        case IO_REG_DMA0CNT:                gba->memory.dma_channels[0].count.bytes[0] = val; break;
        case IO_REG_DMA0CNT + 1:            gba->memory.dma_channels[0].count.bytes[1] = val; break;
        case IO_REG_DMA0CTL:                gba->memory.dma_channels[0].control.bytes[0] = val; break;
        case IO_REG_DMA0CTL + 1:
            gba->memory.dma_channels[0].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;

        /* DMA - Channel 1 */
        case IO_REG_DMA1SAD:                gba->memory.dma_channels[1].src.bytes[0] = val; break;
        case IO_REG_DMA1SAD + 1:            gba->memory.dma_channels[1].src.bytes[1] = val; break;
        case IO_REG_DMA1SAD + 2:            gba->memory.dma_channels[1].src.bytes[2] = val; break;
        case IO_REG_DMA1SAD + 3:            gba->memory.dma_channels[1].src.bytes[3] = val; break;
        case IO_REG_DMA1DAD:                gba->memory.dma_channels[1].dst.bytes[0] = val; break;
        case IO_REG_DMA1DAD + 1:            gba->memory.dma_channels[1].dst.bytes[1] = val; break;
        case IO_REG_DMA1DAD + 2:            gba->memory.dma_channels[1].dst.bytes[2] = val; break;
        case IO_REG_DMA1DAD + 3:            gba->memory.dma_channels[1].dst.bytes[3] = val; break;
        case IO_REG_DMA1CNT:                gba->memory.dma_channels[1].count.bytes[0] = val; break;
        case IO_REG_DMA1CNT + 1:            gba->memory.dma_channels[1].count.bytes[1] = val; break;
        case IO_REG_DMA1CTL:                gba->memory.dma_channels[1].control.bytes[0] = val; break;
        case IO_REG_DMA1CTL + 1:
            gba->memory.dma_channels[1].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;

        /* DMA - Channel 2 */
        case IO_REG_DMA2SAD:                gba->memory.dma_channels[2].src.bytes[0] = val; break;
        case IO_REG_DMA2SAD + 1:            gba->memory.dma_channels[2].src.bytes[1] = val; break;
        case IO_REG_DMA2SAD + 2:            gba->memory.dma_channels[2].src.bytes[2] = val; break;
        case IO_REG_DMA2SAD + 3:            gba->memory.dma_channels[2].src.bytes[3] = val; break;
        case IO_REG_DMA2DAD:                gba->memory.dma_channels[2].dst.bytes[0] = val; break;
        case IO_REG_DMA2DAD + 1:            gba->memory.dma_channels[2].dst.bytes[1] = val; break;
        case IO_REG_DMA2DAD + 2:            gba->memory.dma_channels[2].dst.bytes[2] = val; break;
        case IO_REG_DMA2DAD + 3:            gba->memory.dma_channels[2].dst.bytes[3] = val; break;
        case IO_REG_DMA2CNT:                gba->memory.dma_channels[2].count.bytes[0] = val; break;
        case IO_REG_DMA2CNT + 1:            gba->memory.dma_channels[2].count.bytes[1] = val; break;
        case IO_REG_DMA2CTL:                gba->memory.dma_channels[2].control.bytes[0] = val; break;
        case IO_REG_DMA2CTL + 1:
            gba->memory.dma_channels[2].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;

        /* DMA - Channel 3 */
        case IO_REG_DMA3SAD:                gba->memory.dma_channels[3].src.bytes[0] = val; break;
        case IO_REG_DMA3SAD + 1:            gba->memory.dma_channels[3].src.bytes[1] = val; break;
        case IO_REG_DMA3SAD + 2:            gba->memory.dma_channels[3].src.bytes[2] = val; break;
        case IO_REG_DMA3SAD + 3:            gba->memory.dma_channels[3].src.bytes[3] = val; break;
        case IO_REG_DMA3DAD:                gba->memory.dma_channels[3].dst.bytes[0] = val; break;
        case IO_REG_DMA3DAD + 1:            gba->memory.dma_channels[3].dst.bytes[1] = val; break;
        case IO_REG_DMA3DAD + 2:            gba->memory.dma_channels[3].dst.bytes[2] = val; break;
        case IO_REG_DMA3DAD + 3:            gba->memory.dma_channels[3].dst.bytes[3] = val; break;
        case IO_REG_DMA3CNT:                gba->memory.dma_channels[3].count.bytes[0] = val; break;
        case IO_REG_DMA3CNT + 1:            gba->memory.dma_channels[3].count.bytes[1] = val; break;
        case IO_REG_DMA3CTL:                gba->memory.dma_channels[3].control.bytes[0] = val; break;
        case IO_REG_DMA3CTL + 1:
            gba->memory.dma_channels[3].control.bytes[1] = val;
            mem_dma_transfer(gba);
            break;
    }
}