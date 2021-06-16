/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef IO_H
# define IO_H

# include "hades.h"

/*
** An enumeration of all IO registers.
*/
enum io_regs {
    IO_REG_START        = 0x04000000,

    /* Video */

    IO_REG_DISPCNT      = 0x04000000,
    IO_REG_GREENSWP     = 0x04000002,
    IO_REG_DISPSTAT     = 0x04000004,
    IO_REG_VCOUNT       = 0x04000006,
    IO_REG_BG0CNT       = 0x04000008,
    IO_REG_BG1CNT       = 0x0400000A,
    IO_REG_BG2CNT       = 0x0400000C,
    IO_REG_BG3CNT       = 0x0400000E,
    IO_REG_BG0HOFS      = 0x04000010,
    IO_REG_BG0VOFS      = 0x04000012,
    IO_REG_BG1HOFS      = 0x04000014,
    IO_REG_BG1VOFS      = 0x04000016,
    IO_REG_BG2HOFS      = 0x04000018,
    IO_REG_BG2VOFS      = 0x0400001A,
    IO_REG_BG3HOFS      = 0x0400001C,
    IO_REG_BG3VOFS      = 0x0400001E,

    /* Sound */

    IO_REG_SOUNDBIAS    = 0x04000088,

    /* DMA Transfer Channels */

    IO_REG_DMA0SAD      = 0x040000B0,
    IO_REG_DMA0SAD_LO   = 0x040000B0,
    IO_REG_DMA0SAD_HI   = 0x040000B2,
    IO_REG_DMA0DAD      = 0x040000B4,
    IO_REG_DMA0DAD_LO   = 0x040000B4,
    IO_REG_DMA0DAD_HI   = 0x040000B6,
    IO_REG_DMA0CNT      = 0x040000B8,
    IO_REG_DMA0CTL      = 0x040000BA,

    IO_REG_DMA1SAD      = 0x040000BC,
    IO_REG_DMA1SAD_LO   = 0x040000BC,
    IO_REG_DMA1SAD_HI   = 0x040000BE,
    IO_REG_DMA1DAD      = 0x040000C0,
    IO_REG_DMA1DAD_LO   = 0x040000C0,
    IO_REG_DMA1DAD_HI   = 0x040000C2,
    IO_REG_DMA1CNT      = 0x040000C4,
    IO_REG_DMA1CTL      = 0x040000C6,

    IO_REG_DMA2SAD      = 0x040000C8,
    IO_REG_DMA2SAD_LO   = 0x040000C8,
    IO_REG_DMA2SAD_HI   = 0x040000CA,
    IO_REG_DMA2DAD      = 0x040000CC,
    IO_REG_DMA2DAD_LO   = 0x040000CC,
    IO_REG_DMA2DAD_HI   = 0x040000CE,
    IO_REG_DMA2CNT      = 0x040000D0,
    IO_REG_DMA2CTL      = 0x040000D2,

    IO_REG_DMA3SAD      = 0x040000D4,
    IO_REG_DMA3SAD_LO   = 0x040000D4,
    IO_REG_DMA3SAD_HI   = 0x040000D6,
    IO_REG_DMA3DAD      = 0x040000D8,
    IO_REG_DMA3DAD_LO   = 0x040000D8,
    IO_REG_DMA3DAD_HI   = 0x040000DA,
    IO_REG_DMA3CNT      = 0x040000DC,
    IO_REG_DMA3CTL      = 0x040000DE,

    /* Timer */
    IO_REG_TM0CNT       = 0x04000100,
    IO_REG_TM0CNT_LO    = 0x04000100,
    IO_REG_TM0CNT_HI    = 0x04000102,
    IO_REG_TM1CNT       = 0x04000104,
    IO_REG_TM1CNT_LO    = 0x04000104,
    IO_REG_TM1CNT_HI    = 0x04000106,
    IO_REG_TM2CNT       = 0x04000108,
    IO_REG_TM2CNT_LO    = 0x04000108,
    IO_REG_TM2CNT_HI    = 0x0400010A,
    IO_REG_TM3CNT       = 0x0400010C,
    IO_REG_TM3CNT_LO    = 0x0400010C,
    IO_REG_TM3CNT_HI    = 0x0400010E,

    /* Input */

    IO_REG_KEYINPUT     = 0x04000130,

    /* Interrupts */

    IO_REG_IE           = 0x04000200,
    IO_REG_IF           = 0x04000202,
    IO_REG_IME          = 0x04000208,

    /* System */

    IO_REG_POSTFLG      = 0x04000300,
    IO_REG_HALTCNT      = 0x04000301,

    IO_REG_END,
};

/*
** A DMA channel and the content of the different IO registers associated with it.
*/
struct dma_channel {
    union {
        uint32_t raw;
        uint8_t  bytes[4];
    } src;

    union {
        uint32_t raw;
        uint8_t  bytes[4];
    } dst;

    union {
        uint16_t raw;
        uint8_t  bytes[2];
    } count;

    union {
        struct {
            uint16_t : 5;
            uint16_t dst_ctl: 2;
            uint16_t src_ctl: 2;
            uint16_t repeat: 1;
            uint16_t unit_size: 1;
            uint16_t gamepak_drq: 1;
            uint16_t timing: 2;
            uint16_t irq_end: 1;
            uint16_t enable: 1;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } control;
} __packed;

static_assert(sizeof(struct dma_channel) == 3 * sizeof(uint32_t));

struct timer {
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } counter;
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } reload;

    union {
        struct {
            uint16_t prescaler: 2;
            uint16_t count_up: 1;
            uint16_t : 3;
            uint16_t irq: 1;
            uint16_t enable: 1;
            uint16_t : 8;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } control;

    uint64_t real_counter;
};

/*
** A structure containing all the value of all the different IO registers.
*/
struct io {
    // REG_DISPCNT (LCD Control, Read/Write)
    union {
        struct {
            uint8_t bg_mode: 3;         // Background Mode
            uint8_t cbg_mode: 1;        // Can be set only by BIOS opcodes
            uint8_t frame: 1;           // Frame 0-1 (BG mode 4/5 only)
            uint8_t hblank_int_free: 1; // Allow access to OAM during H-Blank
            uint8_t obj_dim: 1;         // OBJ Character VRAM Mapping (0=Two dimensional, 1=One dimensional)
            uint8_t blank : 1;          // Allow FAST access to VRAM,Palette,OAM
            uint8_t bg: 4;
            uint8_t obj: 1;
            uint8_t win0: 1;
            uint8_t win1: 1;
            uint8_t obj_win: 1;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } dispcnt;

    // REG_GREENSWP
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } greenswp;

    // REG_DISPSTAT (General LCD Status, Read/Write)
    union {
        struct {
            uint8_t vblank: 1;          // Set if rendering the vblank
            uint8_t hblank: 1;          // Set if rendering the hblank
            uint8_t vcount_eq: 1;       // Set if vcount_stg == vcount
            uint8_t vblank_irq: 1;      // Enable to IRQ when vblank
            uint8_t hblank_irq: 1;      // Enable to IRQ when hblank
            uint8_t vcount_irq: 1;      // Enable to IRQ when vcount_stg == vcount
            uint8_t : 2;
            uint8_t vcount_val: 8;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } dispstat;

    // REG_BG{0,1,2,3}CNT
    union {
        struct {
            uint16_t priority: 2;
            uint16_t character_base: 2;
            uint16_t : 2;
            uint16_t mosaic: 1;
            uint16_t palette_type: 1;  // 0: 16/16, 1: 256/1
            uint16_t screen_base: 5;
            uint16_t overflow: 1;
            uint16_t screen_size: 2;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } bgcnt[4];

    union {
        uint16_t raw;
        uint8_t bytes[2];
    } bg_hoffset[4];

    union {
        uint16_t raw;
        uint8_t bytes[2];
    } bg_voffset[4];

    // DMA Channels
    struct dma_channel dma[4];

    // Timers
    struct timer timers[4];

    // REG_IME
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } ime;

    // REG_IE
    union {
        struct {
            uint16_t vblank: 1;
            uint16_t hblank: 1;
            uint16_t vcounter: 1;
            uint16_t timer0: 1;
            uint16_t timer1: 1;
            uint16_t timer2: 1;
            uint16_t timer3: 1;
            uint16_t serial: 1;
            uint16_t dma0: 1;
            uint16_t dma1: 1;
            uint16_t dma2: 1;
            uint16_t dma3: 1;
            uint16_t keypad: 1;
            uint16_t gamepak: 1;
            uint16_t : 2;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } int_enabled;

    // REG_IF
    union {
        struct {
            uint16_t vblank: 1;
            uint16_t hblank: 1;
            uint16_t vcounter: 1;
            uint16_t timer0: 1;
            uint16_t timer1: 1;
            uint16_t timer2: 1;
            uint16_t timer3: 1;
            uint16_t serial: 1;
            uint16_t dma0: 1;
            uint16_t dma1: 1;
            uint16_t dma2: 1;
            uint16_t dma3: 1;
            uint16_t keypad: 1;
            uint16_t gamepak: 1;
            uint16_t : 2;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } int_flag;

    // REG_POSTFLG
    uint8_t postflg;
};

static_assert(sizeof(((struct io *)NULL)->dispcnt) == sizeof(uint16_t));
static_assert(sizeof(((struct io *)NULL)->dispstat) == sizeof(uint16_t));

/* memory/io.c */
void io_init(struct io *io);

/* timer.c */
void timer_tick(struct gba *, uint32_t cycles);

#endif /* IO_H */