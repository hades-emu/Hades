/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "memory.h"
#include "gba/gba.h"

/*
** Initialize the IO structure, giving the different IO registers their
** default value.
*/
void
io_init(
    struct io *io
) {
    memset(io, 0, sizeof(*io));
    io->keyinput.raw = 0x3FF; // Every button set to "released"
    io->bg_pa[0].raw = 0x100;
    io->bg_pd[0].raw = 0x100;
    io->bg_pa[1].raw = 0x100;
    io->bg_pd[1].raw = 0x100;
    io->timers[0].handler = INVALID_EVENT_HANDLE;
    io->timers[1].handler = INVALID_EVENT_HANDLE;
    io->timers[2].handler = INVALID_EVENT_HANDLE;
    io->timers[3].handler = INVALID_EVENT_HANDLE;
    io->dma[0].enable_event_handle = INVALID_EVENT_HANDLE;
    io->dma[1].enable_event_handle = INVALID_EVENT_HANDLE;
    io->dma[2].enable_event_handle = INVALID_EVENT_HANDLE;
    io->dma[3].enable_event_handle = INVALID_EVENT_HANDLE;
    io->soundbias.bias = 0x200;
    io->dma[0].index = 0;
    io->dma[1].index = 1;
    io->dma[2].index = 2;
    io->dma[3].index = 3;
}

/*
** Return the name of the given IO register.
*/
char const *
mem_io_reg_name(
    uint32_t addr
) {
    switch (addr & ~1) {
        case IO_REG_DISPCNT:        return ("dispcnt");
        case IO_REG_GREENSWP:       return ("greenswp");
        case IO_REG_DISPSTAT:       return ("dispstat");
        case IO_REG_VCOUNT:         return ("vcount");
        case IO_REG_BG0CNT:         return ("bg0cnt");
        case IO_REG_BG1CNT:         return ("bg1cnt");
        case IO_REG_BG2CNT:         return ("bg2cnt");
        case IO_REG_BG3CNT:         return ("bg3cnt");
        case IO_REG_BG0VOFS:        return ("bg0vofs");
        case IO_REG_BG1VOFS:        return ("bg1vofs");
        case IO_REG_BG2VOFS:        return ("bg2vofs");
        case IO_REG_BG3VOFS:        return ("bg3vofs");
        case IO_REG_BG0HOFS:        return ("bg0hofs");
        case IO_REG_BG1HOFS:        return ("bg1hofs");
        case IO_REG_BG2HOFS:        return ("bg2hofs");
        case IO_REG_BG3HOFS:        return ("bg3hofs");
        case IO_REG_BG2PA:          return ("bg2pa");
        case IO_REG_BG2PB:          return ("bg2pb");
        case IO_REG_BG2PC:          return ("bg2pc");
        case IO_REG_BG2PD:          return ("bg2pd");
        case IO_REG_BG2X:           return ("bg2x");
        case IO_REG_BG2Y:           return ("bg2y");
        case IO_REG_BG3PA:          return ("bg3pa");
        case IO_REG_BG3PB:          return ("bg3pb");
        case IO_REG_BG3PC:          return ("bg3pc");
        case IO_REG_BG3PD:          return ("bg3pd");
        case IO_REG_BG3X:           return ("bg3x");
        case IO_REG_BG3Y:           return ("bg3y");
        case IO_REG_WIN0H:          return ("win0h");
        case IO_REG_WIN1H:          return ("win1h");
        case IO_REG_WIN0V:          return ("win0v");
        case IO_REG_WIN1V:          return ("win1v");
        case IO_REG_WININ:          return ("winin");
        case IO_REG_WINOUT:         return ("winout");
        case IO_REG_MOSAIC:         return ("mosaic");
        case IO_REG_BLDCNT:         return ("bldcnt");
        case IO_REG_BLDALPHA:       return ("bldalpha");
        case IO_REG_BLDY:           return ("bldy");
        case IO_REG_SOUND1CNT_L:    return ("sound1cnt_l");
        case IO_REG_SOUND1CNT_H:    return ("sound1cnt_h");
        case IO_REG_SOUND1CNT_X:    return ("sound1cnt_x");
        case IO_REG_SOUND2CNT_L:    return ("sound2cnt_l");
        case IO_REG_SOUND2CNT_H:    return ("sound2cnt_h");
        case IO_REG_SOUND3CNT_L:    return ("sound3cnt_l");
        case IO_REG_SOUND3CNT_H:    return ("sound3cnt_h");
        case IO_REG_SOUND3CNT_X:    return ("sound3cnt_x");
        case IO_REG_SOUND4CNT_L:    return ("sound4cnt_l");
        case IO_REG_SOUND4CNT_H:    return ("sound4cnt_h");
        case IO_REG_SOUNDCNT_L:     return ("soundcnt_l");
        case IO_REG_SOUNDCNT_H:     return ("soundcnt_h");
        case IO_REG_SOUNDCNT_X:     return ("soundcnt_x");
        case IO_REG_SOUNDBIAS:      return ("soundbias");
        case IO_REG_WAVE_RAM0:      return ("wave_ram0");
        case IO_REG_WAVE_RAM1:      return ("wave_ram1");
        case IO_REG_WAVE_RAM2:      return ("wave_ram2");
        case IO_REG_WAVE_RAM3:      return ("wave_ram3");
        case IO_REG_FIFO_A_L:       return ("fifo_a_l");
        case IO_REG_FIFO_A_H:       return ("fifo_a_h");
        case IO_REG_FIFO_B_L:       return ("fifo_b_l");
        case IO_REG_FIFO_B_H:       return ("fifo_b_h");
        case IO_REG_DMA0SAD_LO:     return ("dma0sad_lo");
        case IO_REG_DMA0SAD_HI:     return ("dma0sad_hi");
        case IO_REG_DMA0DAD_LO:     return ("dma0dad_lo");
        case IO_REG_DMA0DAD_HI:     return ("dma0dad_hi");
        case IO_REG_DMA0CNT:        return ("dma0cnt");
        case IO_REG_DMA0CTL:        return ("dma0ctl");
        case IO_REG_DMA1SAD_LO:     return ("dma1sad_lo");
        case IO_REG_DMA1SAD_HI:     return ("dma1sad_hi");
        case IO_REG_DMA1DAD_LO:     return ("dma1dad_lo");
        case IO_REG_DMA1DAD_HI:     return ("dma1dad_hi");
        case IO_REG_DMA1CNT:        return ("dma1cnt");
        case IO_REG_DMA1CTL:        return ("dma1ctl");
        case IO_REG_DMA2SAD_LO:     return ("dma2sad_lo");
        case IO_REG_DMA2SAD_HI:     return ("dma2sad_hi");
        case IO_REG_DMA2DAD_LO:     return ("dma2dad_lo");
        case IO_REG_DMA2DAD_HI:     return ("dma2dad_hi");
        case IO_REG_DMA2CNT:        return ("dma2cnt");
        case IO_REG_DMA2CTL:        return ("dma2ctl");
        case IO_REG_DMA3SAD_LO:     return ("dma3sad_lo");
        case IO_REG_DMA3SAD_HI:     return ("dma3sad_hi");
        case IO_REG_DMA3DAD_LO:     return ("dma3dad_lo");
        case IO_REG_DMA3DAD_HI:     return ("dma3dad_hi");
        case IO_REG_DMA3CNT:        return ("dma3cnt");
        case IO_REG_DMA3CTL:        return ("dma3ctl");
        case IO_REG_TM0CNT_LO:      return ("tm0cnt_lo");
        case IO_REG_TM0CNT_HI:      return ("tm0cnt_hi");
        case IO_REG_TM1CNT_LO:      return ("tm1cnt_lo");
        case IO_REG_TM1CNT_HI:      return ("tm1cnt_hi");
        case IO_REG_TM2CNT_LO:      return ("tm2cnt_lo");
        case IO_REG_TM2CNT_HI:      return ("tm2cnt_hi");
        case IO_REG_TM3CNT_LO:      return ("tm3cnt_lo");
        case IO_REG_TM3CNT_HI:      return ("tm3cnt_hi");
        case IO_REG_KEYINPUT:       return ("keyinput");
        case IO_REG_KEYCNT:         return ("keycnt");
        case IO_REG_IE:             return ("ie");
        case IO_REG_IF:             return ("if");
        case IO_REG_WAITCNT:        return ("waitcnt");
        case IO_REG_IME:            return ("ime");
        case IO_REG_POSTFLG:        return ("postflg");
        case IO_REG_HALTCNT:        return ("haltcnt");
        case IO_REG_SIOCNT:         return ("siocnt");
        case IO_REG_RCNT:           return ("rcnt");
        default:                    return ("<unknown>");
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

    logln(HS_IO, "IO read to register %s (%#08x)", mem_io_reg_name(addr), addr);

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
        case IO_REG_WININ:                  return (io->winin.bytes[0]);
        case IO_REG_WININ + 1:              return (io->winin.bytes[1]);
        case IO_REG_WINOUT:                 return (io->winout.bytes[0]);
        case IO_REG_WINOUT + 1:             return (io->winout.bytes[1]);
        case IO_REG_BLDCNT:                 return (io->bldcnt.bytes[0]);
        case IO_REG_BLDCNT + 1:             return (io->bldcnt.bytes[1]);
        case IO_REG_BLDALPHA:               return (io->bldalpha.bytes[0]);
        case IO_REG_BLDALPHA + 1:           return (io->bldalpha.bytes[1]);

        /* Sound */
        case IO_REG_SOUND1CNT_L:            return (io->sound1cnt_l.bytes[0]);
        case IO_REG_SOUND1CNT_L + 1:        return (io->sound1cnt_l.bytes[1]);
        case IO_REG_SOUND1CNT_H:            return (io->sound1cnt_h.bytes[0] & 0xC0);
        case IO_REG_SOUND1CNT_H + 1:        return (io->sound1cnt_h.bytes[1]);
        case IO_REG_SOUND1CNT_X:            return (0);
        case IO_REG_SOUND1CNT_X + 1:        return (io->sound1cnt_x.bytes[1] & 0x40);
        case IO_REG_SOUND1CNT_X + 2:        return (0);
        case IO_REG_SOUND1CNT_X + 3:        return (0);
        case IO_REG_SOUND2CNT_L:            return (io->sound2cnt_l.bytes[0] & 0xC0);
        case IO_REG_SOUND2CNT_L + 1:        return (io->sound2cnt_l.bytes[1]);
        case IO_REG_SOUND2CNT_L + 2:        return (0);
        case IO_REG_SOUND2CNT_L + 3:        return (0);
        case IO_REG_SOUND2CNT_H:            return (0);
        case IO_REG_SOUND2CNT_H + 1:        return (io->sound2cnt_h.bytes[1] & 0x40);
        case IO_REG_SOUND2CNT_H + 2:        return (0);
        case IO_REG_SOUND2CNT_H + 3:        return (0);
        case IO_REG_SOUND3CNT_L:            return (io->sound3cnt_l.bytes[0] & 0xE0);
        case IO_REG_SOUND3CNT_L + 1:        return (0);
        case IO_REG_SOUND3CNT_H:            return (0);
        case IO_REG_SOUND3CNT_H + 1:        return (io->sound3cnt_h.bytes[1] & 0xE0);
        case IO_REG_SOUND3CNT_X:            return (0);
        case IO_REG_SOUND3CNT_X + 1:        return (io->sound3cnt_x.bytes[1] & 0x40);
        case IO_REG_SOUND3CNT_X + 2:
        case IO_REG_SOUND3CNT_X + 3:        return (0);
        case IO_REG_SOUND4CNT_L:            return (0);
        case IO_REG_SOUND4CNT_L + 1:        return (io->sound4cnt_l.bytes[1]);
        case IO_REG_SOUND4CNT_L + 2:        return (0);
        case IO_REG_SOUND4CNT_L + 3:        return (0);
        case IO_REG_SOUND4CNT_H:            return (io->sound4cnt_h.bytes[0]);
        case IO_REG_SOUND4CNT_H + 1:        return (io->sound4cnt_h.bytes[1] & 0x40);
        case IO_REG_SOUND4CNT_H + 2:        return (0);
        case IO_REG_SOUND4CNT_H + 3:        return (0);
        case IO_REG_SOUNDCNT_L:             return (io->soundcnt_l.bytes[0]);
        case IO_REG_SOUNDCNT_L + 1:         return (io->soundcnt_l.bytes[1]);
        case IO_REG_SOUNDCNT_H:             return (io->soundcnt_h.bytes[0]);
        case IO_REG_SOUNDCNT_H + 1:         return (io->soundcnt_h.bytes[1]);
        case IO_REG_SOUNDCNT_X:             return (io->soundcnt_x.bytes[0] & 0x8F);
        case IO_REG_SOUNDCNT_X + 1:
        case IO_REG_SOUNDCNT_X + 2:
        case IO_REG_SOUNDCNT_X + 3:         return (0);
        case IO_REG_SOUNDBIAS:              return (io->soundbias.bytes[0]);
        case IO_REG_SOUNDBIAS + 1:          return (io->soundbias.bytes[1]);
        case IO_REG_SOUNDBIAS + 2:
        case IO_REG_SOUNDBIAS + 3:          return (0);
        case IO_REG_WAVE_RAM0 + 0:
        case IO_REG_WAVE_RAM0 + 1:
        case IO_REG_WAVE_RAM0 + 2:
        case IO_REG_WAVE_RAM0 + 3:
        case IO_REG_WAVE_RAM1 + 0:
        case IO_REG_WAVE_RAM1 + 1:
        case IO_REG_WAVE_RAM1 + 2:
        case IO_REG_WAVE_RAM1 + 3:
        case IO_REG_WAVE_RAM2 + 0:
        case IO_REG_WAVE_RAM2 + 1:
        case IO_REG_WAVE_RAM2 + 2:
        case IO_REG_WAVE_RAM2 + 3:
        case IO_REG_WAVE_RAM3 + 0:
        case IO_REG_WAVE_RAM3 + 1:
        case IO_REG_WAVE_RAM3 + 2:
        case IO_REG_WAVE_RAM3 + 3:          return (io->waveram[!io->sound3cnt_l.bank_select][addr - IO_REG_WAVE_RAM0]);

        /* DMA */
        case IO_REG_DMA0CNT:
        case IO_REG_DMA0CNT + 1:            return (0);
        case IO_REG_DMA0CTL:                return (io->dma[0].control.bytes[0]);
        case IO_REG_DMA0CTL + 1:            return (io->dma[0].control.bytes[1]);
        case IO_REG_DMA1CNT:
        case IO_REG_DMA1CNT + 1:            return (0);
        case IO_REG_DMA1CTL:                return (io->dma[1].control.bytes[0]);
        case IO_REG_DMA1CTL + 1:            return (io->dma[1].control.bytes[1]);
        case IO_REG_DMA2CNT:
        case IO_REG_DMA2CNT + 1:            return (0);
        case IO_REG_DMA2CTL:                return (io->dma[2].control.bytes[0]);
        case IO_REG_DMA2CTL + 1:            return (io->dma[2].control.bytes[1]);
        case IO_REG_DMA3CNT:
        case IO_REG_DMA3CNT + 1:            return (0);
        case IO_REG_DMA3CTL:                return (io->dma[3].control.bytes[0]);
        case IO_REG_DMA3CTL + 1:            return (io->dma[3].control.bytes[1]);

        /* Timer 0 */
        case IO_REG_TM0CNT_LO:
        case IO_REG_TM0CNT_LO + 1: {
            uint16_t val;

            val = timer_read_value(gba, 0);
            return (val >> (8 * (addr - IO_REG_TM0CNT_LO)));
        };
        case IO_REG_TM0CNT_HI:              return (io->timers[0].control.bytes[0]);
        case IO_REG_TM0CNT_HI + 1:          return (0);

        /* Timer 1 */
        case IO_REG_TM1CNT_LO:
        case IO_REG_TM1CNT_LO + 1: {
            uint16_t val;

            val = timer_read_value(gba, 1);
            return (val >> (8 * (addr - IO_REG_TM1CNT_LO)));
        };
        case IO_REG_TM1CNT_HI:              return (io->timers[1].control.bytes[0]);
        case IO_REG_TM1CNT_HI + 1:          return (0);

        /* Timer 2 */
        case IO_REG_TM2CNT_LO:
        case IO_REG_TM2CNT_LO + 1: {
            uint16_t val;

            val = timer_read_value(gba, 2);
            return (val >> (8 * (addr - IO_REG_TM2CNT_LO)));
        };
        case IO_REG_TM2CNT_HI:              return (io->timers[2].control.bytes[0]);
        case IO_REG_TM2CNT_HI + 1:          return (0);

        /* Timer 3 */
        case IO_REG_TM3CNT_LO:
        case IO_REG_TM3CNT_LO + 1: {
            uint16_t val;

            val = timer_read_value(gba, 3);
            return (val >> (8 * (addr - IO_REG_TM3CNT_LO)));
        };
        case IO_REG_TM3CNT_HI:              return (io->timers[3].control.bytes[0]);
        case IO_REG_TM3CNT_HI + 1:          return (0);

        /* Key Input */
        case IO_REG_KEYINPUT:               return (io->keyinput.bytes[0]);
        case IO_REG_KEYINPUT + 1:           return (io->keyinput.bytes[1]);
        case IO_REG_KEYCNT:                 return (io->keycnt.bytes[0]);
        case IO_REG_KEYCNT + 1:             return (io->keycnt.bytes[1]);

        /* Serial communication */
        case IO_REG_SIOCNT:                 return (io->siocnt.bytes[0]);
        case IO_REG_SIOCNT + 1:             return (io->siocnt.bytes[1]);
        case IO_REG_RCNT:                   return (io->rcnt.bytes[0]);
        case IO_REG_RCNT + 1:               return (io->rcnt.bytes[1]);
        case IO_REG_IR:                     return (0);
        case IO_REG_IR + 1:                 return (0);
        case IO_REG_UNKNOWN_1:              return (0);
        case IO_REG_UNKNOWN_1 + 1:          return (0);
        case IO_REG_UNKNOWN_2:              return (0);
        case IO_REG_UNKNOWN_2 + 1:          return (0);

        /* Interrupts */
        case IO_REG_IE:                     return (io->int_enabled.bytes[0]);
        case IO_REG_IE + 1:                 return (io->int_enabled.bytes[1]);
        case IO_REG_IF:                     return (io->int_flag.bytes[0]);
        case IO_REG_IF + 1:                 return (io->int_flag.bytes[1]);
        case IO_REG_WAITCNT:                return (io->waitcnt.bytes[0]);
        case IO_REG_WAITCNT + 1:            return (io->waitcnt.bytes[1]);
        case IO_REG_WAITCNT + 2:
        case IO_REG_WAITCNT + 3:            return (0);
        case IO_REG_IME:                    return (io->ime.bytes[0]);
        case IO_REG_IME + 1:
        case IO_REG_IME + 2:
        case IO_REG_IME + 3:                return (0);
        case IO_REG_UNKNOWN_3:              return (0);
        case IO_REG_UNKNOWN_3 + 1:          return (0);

        /* System */
        case IO_REG_POSTFLG:                return (io->postflg);
    }
    return (mem_openbus_read(gba, addr));
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

    logln(HS_IO, "IO write to register %s (%#08x) (%#02x)", mem_io_reg_name(addr), addr, val);

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
        case IO_REG_BG0CNT + 1:             io->bgcnt[0].bytes[1] = val & 0xDF; break;
        case IO_REG_BG1CNT:                 io->bgcnt[1].bytes[0] = val; break;
        case IO_REG_BG1CNT + 1:             io->bgcnt[1].bytes[1] = val & 0xDF; break;
        case IO_REG_BG2CNT:                 io->bgcnt[2].bytes[0] = val; break;
        case IO_REG_BG2CNT + 1:             io->bgcnt[2].bytes[1] = val; break;
        case IO_REG_BG3CNT:                 io->bgcnt[3].bytes[0] = val; break;
        case IO_REG_BG3CNT + 1:             io->bgcnt[3].bytes[1] = val; break;
        case IO_REG_BG0HOFS:                io->bg_hoffset[0].bytes[0] = val; break;
        case IO_REG_BG0HOFS + 1:            io->bg_hoffset[0].bytes[1] = val & 0x1; break;
        case IO_REG_BG0VOFS:                io->bg_voffset[0].bytes[0] = val; break;
        case IO_REG_BG0VOFS + 1:            io->bg_voffset[0].bytes[1] = val & 0x1; break;
        case IO_REG_BG1HOFS:                io->bg_hoffset[1].bytes[0] = val; break;
        case IO_REG_BG1HOFS + 1:            io->bg_hoffset[1].bytes[1] = val & 0x1; break;
        case IO_REG_BG1VOFS:                io->bg_voffset[1].bytes[0] = val; break;
        case IO_REG_BG1VOFS + 1:            io->bg_voffset[1].bytes[1] = val & 0x1; break;
        case IO_REG_BG2HOFS:                io->bg_hoffset[2].bytes[0] = val; break;
        case IO_REG_BG2HOFS + 1:            io->bg_hoffset[2].bytes[1] = val & 0x1; break;
        case IO_REG_BG2VOFS:                io->bg_voffset[2].bytes[0] = val; break;
        case IO_REG_BG2VOFS + 1:            io->bg_voffset[2].bytes[1] = val & 0x1; break;
        case IO_REG_BG3HOFS:                io->bg_hoffset[3].bytes[0] = val; break;
        case IO_REG_BG3HOFS + 1:            io->bg_hoffset[3].bytes[1] = val & 0x1; break;
        case IO_REG_BG3VOFS:                io->bg_voffset[3].bytes[0] = val; break;
        case IO_REG_BG3VOFS + 1:            io->bg_voffset[3].bytes[1] = val & 0x1; break;

        /* Video - Affine Background */
        case IO_REG_BG2PA:                  io->bg_pa[0].bytes[0] = val; break;
        case IO_REG_BG2PA + 1:              io->bg_pa[0].bytes[1] = val; break;
        case IO_REG_BG2PB:                  io->bg_pb[0].bytes[0] = val; break;
        case IO_REG_BG2PB + 1:              io->bg_pb[0].bytes[1] = val; break;
        case IO_REG_BG2PC:                  io->bg_pc[0].bytes[0] = val; break;
        case IO_REG_BG2PC + 1:              io->bg_pc[0].bytes[1] = val; break;
        case IO_REG_BG2PD:                  io->bg_pd[0].bytes[0] = val; break;
        case IO_REG_BG2PD + 1:              io->bg_pd[0].bytes[1] = val; break;
        case IO_REG_BG2X:                   io->bg_x[0].bytes[0] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG2X + 1:               io->bg_x[0].bytes[1] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG2X + 2:               io->bg_x[0].bytes[2] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG2X + 3:               io->bg_x[0].bytes[3] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG2Y:                   io->bg_y[0].bytes[0] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG2Y + 1:               io->bg_y[0].bytes[1] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG2Y + 2:               io->bg_y[0].bytes[2] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG2Y + 3:               io->bg_y[0].bytes[3] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG3PA:                  io->bg_pa[1].bytes[0] = val; break;
        case IO_REG_BG3PA + 1:              io->bg_pa[1].bytes[1] = val; break;
        case IO_REG_BG3PB:                  io->bg_pb[1].bytes[0] = val; break;
        case IO_REG_BG3PB + 1:              io->bg_pb[1].bytes[1] = val; break;
        case IO_REG_BG3PC:                  io->bg_pc[1].bytes[0] = val; break;
        case IO_REG_BG3PC + 1:              io->bg_pc[1].bytes[1] = val; break;
        case IO_REG_BG3PD:                  io->bg_pd[1].bytes[0] = val; break;
        case IO_REG_BG3PD + 1:              io->bg_pd[1].bytes[1] = val; break;
        case IO_REG_BG3X:                   io->bg_x[1].bytes[0] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG3X + 1:               io->bg_x[1].bytes[1] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG3X + 2:               io->bg_x[1].bytes[2] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG3X + 3:               io->bg_x[1].bytes[3] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG3Y:                   io->bg_y[1].bytes[0] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG3Y + 1:               io->bg_y[1].bytes[1] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG3Y + 2:               io->bg_y[1].bytes[2] = val; gba->ppu.reload_internal_affine_regs = true; break;
        case IO_REG_BG3Y + 3:               io->bg_y[1].bytes[3] = val; gba->ppu.reload_internal_affine_regs = true; break;

        /* Video - Windows */
        case IO_REG_WIN0H:                  io->winh[0].bytes[0] = val; break;
        case IO_REG_WIN0H + 1:              io->winh[0].bytes[1] = val; break;
        case IO_REG_WIN1H:                  io->winh[1].bytes[0] = val; break;
        case IO_REG_WIN1H + 1:              io->winh[1].bytes[1] = val; break;
        case IO_REG_WIN0V:                  io->winv[0].bytes[0] = val; break;
        case IO_REG_WIN0V + 1:              io->winv[0].bytes[1] = val; break;
        case IO_REG_WIN1V:                  io->winv[1].bytes[0] = val; break;
        case IO_REG_WIN1V + 1:              io->winv[1].bytes[1] = val; break;
        case IO_REG_WININ:                  io->winin.bytes[0] = val & 0x3F; break;
        case IO_REG_WININ + 1:              io->winin.bytes[1] = val & 0x3F; break;
        case IO_REG_WINOUT:                 io->winout.bytes[0] = val & 0x3F; break;
        case IO_REG_WINOUT + 1:             io->winout.bytes[1] = val & 0x3F; break;

        /* Video - Mosaic */
        case IO_REG_MOSAIC:                 io->mosaic.bytes[0] = val; break;
        case IO_REG_MOSAIC + 1:             io->mosaic.bytes[1] = val; break;

        /* Video - Effects */
        case IO_REG_BLDCNT:                 io->bldcnt.bytes[0] = val; break;
        case IO_REG_BLDCNT + 1:             io->bldcnt.bytes[1] = val & 0x3F; break;
        case IO_REG_BLDALPHA:               io->bldalpha.bytes[0] = val & 0x1F; break;
        case IO_REG_BLDALPHA + 1:           io->bldalpha.bytes[1] = val & 0x1F; break;
        case IO_REG_BLDY:                   io->bldy.bytes[0] = val; break;
        case IO_REG_BLDY + 1:               io->bldy.bytes[1] = val; break;

        /* Sound */
        case IO_REG_SOUND1CNT_L:            io->sound1cnt_l.bytes[0] = val & 0x7F; break;
        case IO_REG_SOUND1CNT_H:            io->sound1cnt_h.bytes[0] = val; break;
        case IO_REG_SOUND1CNT_H + 1: {
            io->sound1cnt_h.bytes[1] = val;

            // Enveloppe set to decrease mode with a volume of 0 mutes the channel
            if (!gba->io.sound1cnt_h.envelope_direction && !gba->io.sound1cnt_h.envelope_initial_volume) {
                apu_tone_and_sweep_stop(gba);
            }

            break;
        };
        case IO_REG_SOUND1CNT_X:            io->sound1cnt_x.bytes[0] = val; break;
        case IO_REG_SOUND1CNT_X + 1: {
            io->sound1cnt_x.bytes[1] = val;

            /*
            ** Only the frequency (and not the shadow frequency) is updated on register writes.
            ** Reference:
            **   - https://gbdev.gg8.se/wiki/articles/Gameboy_sound_hardware#Frequency_Sweep
            */
            gba->apu.tone_and_sweep.sweep.frequency = io->sound1cnt_x.sample_rate;

            if (io->sound1cnt_x.reset) {
                apu_tone_and_sweep_reset(gba);
            }
            io->sound1cnt_x.reset = false;
            break;
        };
        case IO_REG_SOUND2CNT_L:            io->sound2cnt_l.bytes[0] = val; break;
        case IO_REG_SOUND2CNT_L + 1: {
            io->sound2cnt_l.bytes[1] = val;

            // Enveloppe set to decrease mode with a volume of 0 mutes the channel
            if (!gba->io.sound2cnt_l.envelope_direction && !gba->io.sound2cnt_l.envelope_initial_volume) {
                apu_tone_stop(gba);
            }

            break;
        };
        case IO_REG_SOUND2CNT_H:            io->sound2cnt_h.bytes[0] = val; break;
        case IO_REG_SOUND2CNT_H + 1: {
            io->sound2cnt_h.bytes[1] = val;
            if (io->sound2cnt_h.reset) {
                apu_tone_reset(gba);
            }
            io->sound2cnt_h.reset = false;
            break;
        };
        case IO_REG_SOUND3CNT_L: {
            io->sound3cnt_l.bytes[0] = val;
            if (!io->sound3cnt_l.enable) {
                apu_wave_stop(gba);
            }
        };
        case IO_REG_SOUND3CNT_L + 1:        io->sound3cnt_l.bytes[1] = val; break;
        case IO_REG_SOUND3CNT_H:            io->sound3cnt_h.bytes[0] = val; break;
        case IO_REG_SOUND3CNT_H + 1:        io->sound3cnt_h.bytes[1] = val; break;
        case IO_REG_SOUND3CNT_X:            io->sound3cnt_x.bytes[0] = val; break;
        case IO_REG_SOUND3CNT_X + 1: {
            io->sound3cnt_x.bytes[1] = val;
            if (io->sound3cnt_l.enable && io->sound3cnt_x.reset) {
                apu_wave_reset(gba);
            }
            io->sound3cnt_x.reset = false;
            break;
        };
        case IO_REG_SOUND4CNT_L:            io->sound4cnt_l.bytes[0] = val; break;
        case IO_REG_SOUND4CNT_L + 1: {
            io->sound4cnt_l.bytes[1] = val;

            // Enveloppe set to decrease mode with a volume of 0 mutes the channel
            if (!gba->io.sound4cnt_l.envelope_direction && !gba->io.sound4cnt_l.envelope_initial_volume) {
                apu_tone_and_sweep_stop(gba);
            }

            break;
        };
        case IO_REG_SOUND4CNT_H:            io->sound4cnt_h.bytes[0] = val; break;
        case IO_REG_SOUND4CNT_H + 1: {
            io->sound4cnt_h.bytes[1] = val;
            if (io->sound4cnt_h.reset) {
                apu_noise_reset(gba);
            }
            io->sound4cnt_h.reset = false;
            break;
        };
        case IO_REG_SOUNDCNT_L:             io->soundcnt_l.bytes[0] = val & 0x77; break;
        case IO_REG_SOUNDCNT_L + 1:         io->soundcnt_l.bytes[1] = val; break;
        case IO_REG_SOUNDCNT_H:             io->soundcnt_h.bytes[0] = val & 0x0F; break;
        case IO_REG_SOUNDCNT_H + 1: {
            io->soundcnt_h.bytes[1] = val;

            if (io->soundcnt_h.reset_fifo_a) {
                apu_reset_fifo(gba, FIFO_A);
                io->soundcnt_h.reset_fifo_a = false;
            }

            if (io->soundcnt_h.reset_fifo_b) {
                apu_reset_fifo(gba, FIFO_B);
                io->soundcnt_h.reset_fifo_b = false;
            }

            break;
        };
        case IO_REG_SOUNDCNT_X: {
            uint16_t old_master;

            old_master = io->soundcnt_x.bytes[0] & 0x80;
            io->soundcnt_x.bytes[0] = val & 0x80;

            if (old_master && !io->soundcnt_x.master_enable) {
                apu_reset_fifo(gba, 0);
                apu_reset_fifo(gba, 1);
                apu_wave_stop(gba);

                /*
                ** Registers 0x4000060 to 0x4000081 are reset.
                */

                io->sound3cnt_l.raw = 0;
                io->sound3cnt_h.raw = 0;
                io->sound3cnt_x.raw = 0;
            }
            break;
        };
        case IO_REG_SOUNDBIAS:              io->soundbias.bytes[0] = val; break;
        case IO_REG_SOUNDBIAS + 1:          io->soundbias.bytes[1] = val; break;
        case IO_REG_SOUNDBIAS + 2:          io->soundbias.bytes[2] = val; break;
        case IO_REG_SOUNDBIAS + 3:          io->soundbias.bytes[3] = val; break;
        case IO_REG_WAVE_RAM0 + 0:
        case IO_REG_WAVE_RAM0 + 1:
        case IO_REG_WAVE_RAM0 + 2:
        case IO_REG_WAVE_RAM0 + 3:
        case IO_REG_WAVE_RAM1 + 0:
        case IO_REG_WAVE_RAM1 + 1:
        case IO_REG_WAVE_RAM1 + 2:
        case IO_REG_WAVE_RAM1 + 3:
        case IO_REG_WAVE_RAM2 + 0:
        case IO_REG_WAVE_RAM2 + 1:
        case IO_REG_WAVE_RAM2 + 2:
        case IO_REG_WAVE_RAM2 + 3:
        case IO_REG_WAVE_RAM3 + 0:
        case IO_REG_WAVE_RAM3 + 1:
        case IO_REG_WAVE_RAM3 + 2:
        case IO_REG_WAVE_RAM3 + 3: {
            io->waveram[!io->sound3cnt_l.bank_select][addr - IO_REG_WAVE_RAM0] = val;
            break;
        };
        case IO_REG_FIFO_A_L + 0:
        case IO_REG_FIFO_A_L + 1:
        case IO_REG_FIFO_A_H + 0:
        case IO_REG_FIFO_A_H + 1: {
            apu_fifo_write8(gba, FIFO_A, val);
            break;
        };
        case IO_REG_FIFO_B_L + 0:
        case IO_REG_FIFO_B_L + 1:
        case IO_REG_FIFO_B_H + 0:
        case IO_REG_FIFO_B_H + 1: {
            apu_fifo_write8(gba, FIFO_B, val);
            break;
        };

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
        case IO_REG_DMA0CTL:                io->dma[0].control.bytes[0] = val & 0xE0; break;
        case IO_REG_DMA0CTL + 1:            mem_io_dma_ctl_write8(gba, &io->dma[0], val); break;

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
        case IO_REG_DMA1CTL:                io->dma[1].control.bytes[0] = val & 0xE0; break;
        case IO_REG_DMA1CTL + 1:            mem_io_dma_ctl_write8(gba, &io->dma[1], val); break;

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
        case IO_REG_DMA2CTL:                io->dma[2].control.bytes[0] = val & 0xE0; break;
        case IO_REG_DMA2CTL + 1:            mem_io_dma_ctl_write8(gba, &io->dma[2], val); break;

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
        case IO_REG_DMA3CTL:                io->dma[3].control.bytes[0] = val & 0xE0; break;
        case IO_REG_DMA3CTL + 1:            mem_io_dma_ctl_write8(gba, &io->dma[3], val); break;

        /* Timer 0 */
        case IO_REG_TM0CNT_LO:
        case IO_REG_TM0CNT_LO + 1: {
            io->pending.timers[0].reload.bytes[addr - IO_REG_TM0CNT_LO] = val;
            io_schedule_register_delayed_write(gba, IO_REG_TM0CNT_LO);
            break;
        };
        case IO_REG_TM0CNT_HI: {
            io->pending.timers[0].control.bytes[0] = val;
            io_schedule_register_delayed_write(gba, IO_REG_TM0CNT_HI);
            break;
        };

        /* Timer 1 */
        case IO_REG_TM1CNT_LO:
        case IO_REG_TM1CNT_LO + 1: {
            io->pending.timers[1].reload.bytes[addr - IO_REG_TM1CNT_LO] = val;
            io_schedule_register_delayed_write(gba, IO_REG_TM1CNT_LO);
            break;
        };
        case IO_REG_TM1CNT_HI: {
            io->pending.timers[1].control.bytes[0] = val;
            io_schedule_register_delayed_write(gba, IO_REG_TM1CNT_HI);
            break;
        };

        /* Timer 2 */
        case IO_REG_TM2CNT_LO:
        case IO_REG_TM2CNT_LO + 1: {
            io->pending.timers[2].reload.bytes[addr - IO_REG_TM2CNT_LO] = val;
            io_schedule_register_delayed_write(gba, IO_REG_TM2CNT_LO);
            break;
        };
        case IO_REG_TM2CNT_HI: {
            io->pending.timers[2].control.bytes[0] = val;
            io_schedule_register_delayed_write(gba, IO_REG_TM2CNT_HI);
            break;
        };

        /* Timer 3 */
        case IO_REG_TM3CNT_LO:
        case IO_REG_TM3CNT_LO + 1: {
            io->pending.timers[3].reload.bytes[addr - IO_REG_TM3CNT_LO] = val;
            io_schedule_register_delayed_write(gba, IO_REG_TM3CNT_LO);
            break;
        };
        case IO_REG_TM3CNT_HI: {
            io->pending.timers[3].control.bytes[0] = val;
            io_schedule_register_delayed_write(gba, IO_REG_TM3CNT_HI);
            break;
        };

        /* Serial communication */
        case IO_REG_SIOCNT:
        case IO_REG_SIOCNT + 1: {
            io->siocnt.bytes[addr - IO_REG_SIOCNT] = val;

            /* Stub */
            if (io->siocnt.start && io->siocnt.irq) {
                core_schedule_irq(gba, IRQ_SERIAL);
            }

            io->siocnt.start = false;
            break;
        };

        case IO_REG_RCNT:
        case IO_REG_RCNT + 1:               io->rcnt.bytes[addr - IO_REG_RCNT] = val; break;

        /* Keypad input */
        case IO_REG_KEYCNT:
        case IO_REG_KEYCNT + 1: {
            bool old_cond;
            uint32_t old_mask;

            old_mask = io->keycnt.mask;
            old_cond = io_evaluate_keypad_cond(gba);
            io->keycnt.bytes[addr - IO_REG_KEYCNT] = val;

            if (   (!old_cond && io_evaluate_keypad_cond(gba))  // Trigger an IRQ if the keypad condition switches to true.
                || (((old_mask ^ io->keycnt.mask) & io->keycnt.mask))  // Trigger an IRQ on a new mask that extends the current one
            ) {
                io_scan_keypad_irq(gba);
            }
            break;
        };

        /* Interrupt */
        case IO_REG_IE:
        case IO_REG_IE + 1: {
            io->pending.int_enabled.bytes[addr - IO_REG_IE] = val;
            io->pending.int_enabled.raw &= 0x3FFF;
            io_schedule_register_delayed_write(gba, IO_REG_IE);
            break;
        };
        case IO_REG_IF:
        case IO_REG_IF + 1: {
            io->pending.int_flag.bytes[addr - IO_REG_IF] &= ~val;
            io_schedule_register_delayed_write(gba, IO_REG_IF);
            break;
        };
        case IO_REG_WAITCNT:
        case IO_REG_WAITCNT + 1: {
            bool old_pbuffer_enabled;

            io->waitcnt.bytes[addr - IO_REG_WAITCNT] = val;
            old_pbuffer_enabled = gba->memory.pbuffer.enabled;

            if (old_pbuffer_enabled ^ io->waitcnt.gamepak_prefetch) {
                memset(&gba->memory.pbuffer, 0, sizeof(struct prefetch_buffer));
            }

            gba->memory.pbuffer.enabled = gba->settings.prefetch_buffer && io->waitcnt.gamepak_prefetch;

            mem_update_waitstates(gba);
            break;
        };
        case IO_REG_IME:
        case IO_REG_IME + 1: {
            io->pending.ime.bytes[addr - IO_REG_IME] = val;
            io_schedule_register_delayed_write(gba, IO_REG_IME);
            break;
        };

        /* System */
        case IO_REG_POSTFLG:                io->postflg = val; break;
        case IO_REG_HALTCNT: {
            gba->core.state = (val >> 7) + 1;
            if (gba->core.state == CORE_STOP) {
                ppu_render_black_screen(gba);
            }
            break;
        };
    }
}

bool
io_evaluate_keypad_cond(
    struct gba *gba
) {
    return ((gba->io.keycnt.irq_cond && (~gba->io.keyinput.raw & gba->io.keycnt.raw & 0x3FF) == (gba->io.keycnt.raw & 0x3FF))  // Logical AND
        || (!gba->io.keycnt.irq_cond && ~gba->io.keyinput.raw & gba->io.keycnt.raw & 0x3FF)  // Logical OR
    );
}

/*
** Check if the keyinput IO register matches the mask and condition described by
** the keycnt register and fire an IRQ if it is the case.
*/
void
io_scan_keypad_irq(
    struct gba *gba
) {
    if (io_evaluate_keypad_cond(gba) && gba->io.keycnt.irq_enable) {
        core_schedule_irq(gba, IRQ_KEYPAD);
    }
}

void
io_register_delayed_write(
    struct gba *gba,
    struct event_args args
) {
    struct io *io;
    uint32_t addr;

    io = &gba->io;
    addr = args.a1.u32;

    switch (addr) {
        /* Time reload */
        case IO_REG_TM0CNT_LO:
        case IO_REG_TM1CNT_LO:
        case IO_REG_TM2CNT_LO:
        case IO_REG_TM3CNT_LO: {
            uint16_t idx;

            idx = (addr - IO_REG_TM0CNT_LO) / sizeof(uint32_t);
            io->timers[idx].reload.raw = io->pending.timers[idx].reload.raw;
            break;
        };

        /* Time Control */
        case IO_REG_TM0CNT_HI:
        case IO_REG_TM1CNT_HI:
        case IO_REG_TM2CNT_HI:
        case IO_REG_TM3CNT_HI: {
            uint16_t idx;
            bool old_enable;
            bool new_enable;

            idx = (addr - IO_REG_TM0CNT_HI) / sizeof(uint32_t);

            old_enable = io->timers[idx].control.enable;
            io->timers[idx].control.raw = io->pending.timers[idx].control.raw;
            new_enable = io->timers[idx].control.enable;

            /* Timer 0 cannot use the count_up bit. */
            if (!idx) {
                io->timers[idx].control.count_up = false;
            }

            if (old_enable ^ new_enable) {
                if (new_enable) {
                    timer_schedule_start(gba, idx);
                } else {
                    timer_stop(gba, idx);
                }
            }
            break;
        };

        /* Interrupt-Related Registers */
        case IO_REG_IE:
        case IO_REG_IF:
        case IO_REG_IME: {
            bool int_available;
            bool new_irq_line;

            io->int_enabled.raw = io->pending.int_enabled.raw;
            io->int_flag.raw = io->pending.int_flag.raw;
            io->ime.raw = io->pending.ime.raw;

            int_available = (bool)(gba->io.int_enabled.raw & gba->io.int_flag.raw);

            // TODO FIXME This most likely has delay
            if (int_available && gba->core.state == CORE_HALT) {
                gba->core.state = CORE_RUN;
            }

            new_irq_line = int_available && gba->io.ime.raw;
            if (new_irq_line != gba->core.irq_line) {
                /* There's a two-cycle delay for the CPU to register the new IRQ line */
                core_schedule_update_irq_line(gba, new_irq_line);
            }
            break;
        };

        default: panic(HS_ERROR, "Delayed write to unsupported register %08x", addr);
    }
}

void
io_schedule_register_delayed_write(
    struct gba *gba,
    uint32_t reg
) {
    sched_add_event(
        gba,
        NEW_FIX_EVENT_ARGS(
            SCHED_EVENT_IO_WRITE,
            gba->scheduler.cycles + 1, // One cycle delay when writing to delayed IO registers
            EVENT_ARG(u32, reg)
        )
    );
}
