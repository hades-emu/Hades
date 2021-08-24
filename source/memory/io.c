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

/*
** Initialize the IO structure, giving the different IO registers their
** default value.
*/
void
io_init(
    struct io *io
) {
    memset(io, 0, sizeof(*io));
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
        case IO_REG_BG0CNT:         return ("REG_BG0CNT");
        case IO_REG_BG1CNT:         return ("REG_BG1CNT");
        case IO_REG_BG2CNT:         return ("REG_BG2CNT");
        case IO_REG_BG3CNT:         return ("REG_BG3CNT");
        case IO_REG_BG0VOFS:        return ("REG_BG0VOFS");
        case IO_REG_BG1VOFS:        return ("REG_BG1VOFS");
        case IO_REG_BG2VOFS:        return ("REG_BG2VOFS");
        case IO_REG_BG3VOFS:        return ("REG_BG3VOFS");
        case IO_REG_BG0HOFS:        return ("REG_BG0HOFS");
        case IO_REG_BG1HOFS:        return ("REG_BG1HOFS");
        case IO_REG_BG2HOFS:        return ("REG_BG2HOFS");
        case IO_REG_BG3HOFS:        return ("REG_BG3HOFS");
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
        case IO_REG_TM0CNT_LO:      return ("REG_TM0CNT_LO");
        case IO_REG_TM0CNT_HI:      return ("REG_TM0CNT_HI");
        case IO_REG_TM1CNT_LO:      return ("REG_TM1CNT_LO");
        case IO_REG_TM1CNT_HI:      return ("REG_TM1CNT_HI");
        case IO_REG_TM2CNT_LO:      return ("REG_TM2CNT_LO");
        case IO_REG_TM2CNT_HI:      return ("REG_TM2CNT_HI");
        case IO_REG_TM3CNT_LO:      return ("REG_TM3CNT_LO");
        case IO_REG_TM3CNT_HI:      return ("REG_TM3CNT_HI");
        case IO_REG_KEYINPUT:       return ("REG_KEYINPUT");
        case IO_REG_IE:             return ("REG_IE");
        case IO_REG_IF:             return ("REG_IF");
        case IO_REG_WAITCNT:        return ("REG_WAITCNT");
        case IO_REG_IME:            return ("REG_IME");
        case IO_REG_POSTFLG:        return ("REG_POSTFLG");
        case IO_REG_HALTCNT:        return ("REG_HALTCNT");
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

    logln(HS_IO, "IO read to %s (%#08x)", mem_io_reg_name(addr), addr);

    io = &gba->io;
    switch (addr) {

        /* Display */
        case IO_REG_DISPCNT:                return (io->dispcnt.bytes[0]);
        case IO_REG_DISPCNT + 1:            return (io->dispcnt.bytes[1]);
        case IO_REG_GREENSWP:               return (io->greenswp.bytes[0]);
        case IO_REG_GREENSWP + 1:           return (io->greenswp.bytes[1]);
        case IO_REG_DISPSTAT:               return (io->dispstat.bytes[0]);
        case IO_REG_DISPSTAT + 1:           return (io->dispstat.bytes[1]);
        case IO_REG_VCOUNT:                 return (io->vcount.bytes[0]);
        case IO_REG_VCOUNT + 1:             return (io->vcount.bytes[1]);
        case IO_REG_BG0CNT:                 return (io->bgcnt[0].bytes[0]);
        case IO_REG_BG0CNT + 1:             return (io->bgcnt[0].bytes[1]);
        case IO_REG_BG1CNT:                 return (io->bgcnt[1].bytes[0]);
        case IO_REG_BG1CNT + 1:             return (io->bgcnt[1].bytes[1]);
        case IO_REG_BG2CNT:                 return (io->bgcnt[2].bytes[0]);
        case IO_REG_BG2CNT + 1:             return (io->bgcnt[2].bytes[1]);
        case IO_REG_BG3CNT:                 return (io->bgcnt[3].bytes[0]);
        case IO_REG_BG3CNT + 1:             return (io->bgcnt[3].bytes[1]);
        case IO_REG_BG0HOFS:                return (io->bg_hoffset[0].bytes[0]);
        case IO_REG_BG0HOFS + 1:            return (io->bg_hoffset[0].bytes[1]);
        case IO_REG_BG0VOFS:                return (io->bg_voffset[0].bytes[0]);
        case IO_REG_BG0VOFS + 1:            return (io->bg_voffset[0].bytes[1]);
        case IO_REG_BG1HOFS:                return (io->bg_hoffset[1].bytes[0]);
        case IO_REG_BG1HOFS + 1:            return (io->bg_hoffset[1].bytes[1]);
        case IO_REG_BG1VOFS:                return (io->bg_voffset[1].bytes[0]);
        case IO_REG_BG1VOFS + 1:            return (io->bg_voffset[1].bytes[1]);
        case IO_REG_BG2HOFS:                return (io->bg_hoffset[2].bytes[0]);
        case IO_REG_BG2HOFS + 1:            return (io->bg_hoffset[2].bytes[1]);
        case IO_REG_BG2VOFS:                return (io->bg_voffset[2].bytes[0]);
        case IO_REG_BG2VOFS + 1:            return (io->bg_voffset[2].bytes[1]);
        case IO_REG_BG3HOFS:                return (io->bg_hoffset[3].bytes[0]);
        case IO_REG_BG3HOFS + 1:            return (io->bg_hoffset[3].bytes[1]);
        case IO_REG_BG3VOFS:                return (io->bg_voffset[3].bytes[0]);
        case IO_REG_BG3VOFS + 1:            return (io->bg_voffset[3].bytes[1]);

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

        /* Timer 0 */
        case IO_REG_TM0CNT_LO:              return (io->timers[0].counter.bytes[0]);
        case IO_REG_TM0CNT_LO + 1:          return (io->timers[0].counter.bytes[1]);
        case IO_REG_TM0CNT_HI:              return (io->timers[0].control.bytes[0]);
        case IO_REG_TM0CNT_HI + 1:          return (io->timers[0].control.bytes[1]);

        /* Timer 1 */
        case IO_REG_TM1CNT_LO:              return (io->timers[1].counter.bytes[0]);
        case IO_REG_TM1CNT_LO + 1:          return (io->timers[1].counter.bytes[1]);
        case IO_REG_TM1CNT_HI:              return (io->timers[1].control.bytes[0]);
        case IO_REG_TM1CNT_HI + 1:          return (io->timers[1].control.bytes[1]);

        /* Timer 2 */
        case IO_REG_TM2CNT_LO:              return (io->timers[2].counter.bytes[0]);
        case IO_REG_TM2CNT_LO + 1:          return (io->timers[2].counter.bytes[1]);
        case IO_REG_TM2CNT_HI:              return (io->timers[2].control.bytes[0]);
        case IO_REG_TM2CNT_HI + 1:          return (io->timers[2].control.bytes[1]);

        /* Timer 3 */
        case IO_REG_TM3CNT_LO:              return (io->timers[3].counter.bytes[0]);
        case IO_REG_TM3CNT_LO + 1:          return (io->timers[3].counter.bytes[1]);
        case IO_REG_TM3CNT_HI:              return (io->timers[3].control.bytes[0]);
        case IO_REG_TM3CNT_HI + 1:          return (io->timers[3].control.bytes[1]);

        /* Inputs */
        case IO_REG_KEYINPUT:
        case IO_REG_KEYINPUT + 1:
            {
                uint8_t out;
                pthread_mutex_t *mutex;

                mutex = (pthread_mutex_t *)&gba->input_mutex;
                pthread_mutex_lock(mutex);
                out = gba->input.bytes[addr - IO_REG_KEYINPUT];
                pthread_mutex_unlock(mutex);
                return (out);
            }

        case IO_REG_RCNT:                   return (io->rcnt.bytes[0]);
        case IO_REG_RCNT + 1:               return (io->rcnt.bytes[1]);

        /* Interrupts */
        case IO_REG_IE:                     return (io->int_enabled.bytes[0]);
        case IO_REG_IE + 1:                 return (io->int_enabled.bytes[1]);
        case IO_REG_IF:                     return (io->int_flag.bytes[0]);
        case IO_REG_IF + 1:                 return (io->int_flag.bytes[1]);
        case IO_REG_WAITCNT:                return (io->waitcnt.bytes[0]);
        case IO_REG_WAITCNT + 1:            return (io->waitcnt.bytes[1]);
        case IO_REG_IME:                    return (io->ime.bytes[0]);
        case IO_REG_IME + 1:                return (io->ime.bytes[1]);

        /* System */
        case IO_REG_POSTFLG:                return (io->postflg);
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

    logln(HS_IO, "IO write to %s (%#08x) (%x)", mem_io_reg_name(addr), addr, val);

    io = &gba->io;
    switch (addr) {

        /* Display */
        case IO_REG_DISPCNT:                io->dispcnt.bytes[0] = val; break;
        case IO_REG_DISPCNT + 1:            io->dispcnt.bytes[1] = val; break;
        case IO_REG_GREENSWP:               io->greenswp.bytes[0] = val; break;
        case IO_REG_GREENSWP + 1:           io->greenswp.bytes[1] = val; break;
        case IO_REG_DISPSTAT:               io->dispstat.bytes[0] = val; break;
        case IO_REG_DISPSTAT + 1:           io->dispstat.bytes[1] = val; break;
        case IO_REG_BG0CNT:                 io->bgcnt[0].bytes[0] = val; break;
        case IO_REG_BG0CNT + 1:             io->bgcnt[0].bytes[1] = val; break;
        case IO_REG_BG1CNT:                 io->bgcnt[1].bytes[0] = val; break;
        case IO_REG_BG1CNT + 1:             io->bgcnt[1].bytes[1] = val; break;
        case IO_REG_BG2CNT:                 io->bgcnt[2].bytes[0] = val; break;
        case IO_REG_BG2CNT + 1:             io->bgcnt[2].bytes[1] = val; break;
        case IO_REG_BG3CNT:                 io->bgcnt[3].bytes[0] = val; break;
        case IO_REG_BG3CNT + 1:             io->bgcnt[3].bytes[1] = val; break;
        case IO_REG_BG0HOFS:                io->bg_hoffset[0].bytes[0] = val; break;
        case IO_REG_BG0HOFS + 1:            io->bg_hoffset[0].bytes[1] = val; break;
        case IO_REG_BG0VOFS:                io->bg_voffset[0].bytes[0] = val; break;
        case IO_REG_BG0VOFS + 1:            io->bg_voffset[0].bytes[1] = val; break;
        case IO_REG_BG1HOFS:                io->bg_hoffset[1].bytes[0] = val; break;
        case IO_REG_BG1HOFS + 1:            io->bg_hoffset[1].bytes[1] = val; break;
        case IO_REG_BG1VOFS:                io->bg_voffset[1].bytes[0] = val; break;
        case IO_REG_BG1VOFS + 1:            io->bg_voffset[1].bytes[1] = val; break;
        case IO_REG_BG2HOFS:                io->bg_hoffset[2].bytes[0] = val; break;
        case IO_REG_BG2HOFS + 1:            io->bg_hoffset[2].bytes[1] = val; break;
        case IO_REG_BG2VOFS:                io->bg_voffset[2].bytes[0] = val; break;
        case IO_REG_BG2VOFS + 1:            io->bg_voffset[2].bytes[1] = val; break;
        case IO_REG_BG3HOFS:                io->bg_hoffset[3].bytes[0] = val; break;
        case IO_REG_BG3HOFS + 1:            io->bg_hoffset[3].bytes[1] = val; break;
        case IO_REG_BG3VOFS:                io->bg_voffset[3].bytes[0] = val; break;
        case IO_REG_BG3VOFS + 1:            io->bg_voffset[3].bytes[1] = val; break;


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
            mem_dma_load(io->dma + 0, 0);
            mem_dma_transfer(gba, DMA_TIMING_NOW);
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
            mem_dma_load(io->dma + 1, 1);
            mem_dma_transfer(gba, DMA_TIMING_NOW);
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
            mem_dma_load(io->dma + 2, 2);
            mem_dma_transfer(gba, DMA_TIMING_NOW);
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
            mem_dma_load(io->dma + 3, 3);
            mem_dma_transfer(gba, DMA_TIMING_NOW);
            break;

        /* Timer 0 */
        case IO_REG_TM0CNT_LO:              io->timers[0].reload.bytes[0] = val; break;
        case IO_REG_TM0CNT_LO + 1:          io->timers[0].reload.bytes[1] = val; break;
        case IO_REG_TM0CNT_HI:
            // Copy the reload value to the counter value if the enable bit changed from 0 to 1
            if (!io->timers[0].control.enable && (val & (1 << 7))) {
                io->timers[0].real_counter = io->timers[0].reload.raw;
                io->timers[0].counter.raw = io->timers[0].reload.raw;
                logln(HS_TIMER, "Timer 0 started with initial value %04x", io->timers[0].reload.raw);
            }
            io->timers[0].control.bytes[0] = val;
            break;
        case IO_REG_TM0CNT_HI + 1:          io->timers[0].control.bytes[1] = val; break;

        /* Timer 1 */
        case IO_REG_TM1CNT_LO:              io->timers[1].reload.bytes[0] = val; break;
        case IO_REG_TM1CNT_LO + 1:          io->timers[1].reload.bytes[1] = val; break;
        case IO_REG_TM1CNT_HI:
            // Copy the reload value to the counter value if the enable bit changed from 0 to 1
            if (!io->timers[1].control.enable && (val & (1 << 7))) {
                io->timers[1].real_counter = io->timers[1].reload.raw;
                io->timers[1].counter.raw = io->timers[1].reload.raw;
                logln(HS_TIMER, "Timer 1 started with initial value %04x", io->timers[1].reload.raw);
            }
            io->timers[1].control.bytes[0] = val;
            break;
        case IO_REG_TM1CNT_HI + 1:          io->timers[1].control.bytes[1] = val; break;

        /* Timer 2 */
        case IO_REG_TM2CNT_LO:              io->timers[2].reload.bytes[0] = val; break;
        case IO_REG_TM2CNT_LO + 1:          io->timers[2].reload.bytes[1] = val; break;
        case IO_REG_TM2CNT_HI:
            // Copy the reload value to the counter value if the enable bit changed from 0 to 1
            if (!io->timers[2].control.enable && (val & (1 << 7))) {
                io->timers[2].real_counter = io->timers[2].reload.raw;
                io->timers[2].counter.raw = io->timers[2].reload.raw;
                logln(HS_TIMER, "Timer 2 started with initial value %04x", io->timers[2].reload.raw);
            }
            io->timers[2].control.bytes[0] = val;
            break;
        case IO_REG_TM2CNT_HI + 1:          io->timers[2].control.bytes[1] = val; break;

        /* Timer 3 */
        case IO_REG_TM3CNT_LO:              io->timers[3].reload.bytes[0] = val; break;
        case IO_REG_TM3CNT_LO + 1:          io->timers[3].reload.bytes[1] = val; break;
        case IO_REG_TM3CNT_HI:
            // Copy the reload value to the counter value if the enable bit changed from 0 to 1
            if (!io->timers[3].control.enable && (val & (1 << 7))) {
                io->timers[3].real_counter = io->timers[3].reload.raw;
                io->timers[3].counter.raw = io->timers[3].reload.raw;
                logln(HS_TIMER, "Timer 3 started with initial value %04x", io->timers[3].reload.raw);
            }
            io->timers[3].control.bytes[0] = val;
            break;
        case IO_REG_TM3CNT_HI + 1:          io->timers[3].control.bytes[1] = val; break;

        /* Serial Communication (2) */
        case IO_REG_RCNT:
        case IO_REG_RCNT + 1:               io->rcnt.bytes[addr - IO_REG_RCNT] = val; break;

        /* Interrupt */
        case IO_REG_IE:
        case IO_REG_IE + 1:
            io->int_enabled.bytes[addr - IO_REG_IE] = val;
            core_scan_irq(gba);
            break;
        case IO_REG_IF:                     io->int_flag.bytes[0] &= ~val; break;
        case IO_REG_IF + 1:                 io->int_flag.bytes[1] &= ~val; break;
        case IO_REG_WAITCNT:
        case IO_REG_WAITCNT + 1:
            io->waitcnt.bytes[addr - IO_REG_WAITCNT] = val;
            mem_update_waitstates(gba);
            break;
        case IO_REG_IME:
        case IO_REG_IME + 1:
            io->ime.bytes[addr - IO_REG_IME] = val;
            core_scan_irq(gba);
            break;

        /* System */
        case IO_REG_POSTFLG:                io->postflg = val; break;
        case IO_REG_HALTCNT:                gba->core.halt = val + 1; break;
    }
}