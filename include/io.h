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
** An union of a `uint32_t` and the four bytes it is made of.
*/
union split_uint32 {
    uint32_t raw;
    uint8_t  bytes[4];
};

static_assert(sizeof(union split_uint32) == sizeof(uint32_t));

/*
** An union of a `uint16_t` and the two bytes it is made of.
*/
union split_uint16 {
    uint16_t raw;
    uint8_t  bytes[2];
};

static_assert(sizeof(union split_uint16) == sizeof(uint16_t));

/*
** A DMA channel and the content of the different IO registers associated with it.
*/
struct dma_channel {
    union split_uint32 src;
    union split_uint32 dst;
    union split_uint16 count;

    union {
        struct {
            uint16_t : 5;
            uint16_t dst_ctl: 2;
            uint16_t src_ctl: 2;
            uint16_t repeat: 1;
            uint16_t type: 1;
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

/*
** A structure containing all the value of all the different IO registers.
*/
struct io {
    // Input
    union {
        struct {
            uint16_t a: 1;
            uint16_t b: 1;
            uint16_t select: 1;
            uint16_t start: 1;
            uint16_t right: 1;
            uint16_t left: 1;
            uint16_t up: 1;
            uint16_t down: 1;
            uint16_t r: 1;
            uint16_t l: 1;
            uint16_t : 6;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } input;

    // DMA Channels
    struct dma_channel dma_channels[4];
};

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

    /* Input */

    IO_REG_KEYINPUT     = 0x04000130,

    /* Interrupts */

    IO_REG_IE           = 0x04000200,
    IO_REG_IF           = 0x04000202,
    IO_REG_IME          = 0x04000208,

    IO_REG_END,
};

/*
** Most LCD-related IO registers aren't stored in `struct io` but generated on the fly when read/written to.
** The following structures represent their layout to facilitate their (de)construction.
*/

/*
** The LCD Display Control (IO_REG_DISPCNT) register layout.
*/
struct io_reg_dispcnt {
    union {
        struct {
            uint8_t bg_mode: 3;         // Background Mode
            uint8_t cbg_mode: 1;        // Can be set only by BIOS opcodes
            uint8_t frame: 1;           // Frame 0-1 (BG mode 4/5 only)
            uint8_t hblank_int_free: 1; // Allow access to OAM during H-Blank
            uint8_t obj_dim: 1;         // OBJ Character VRAM Mapping (0=Two dimensional, 1=One dimensional)
            uint8_t blank : 1;          // Allow FAST access to VRAM,Palette,OAM
        };
        uint8_t byte0;
    };
    union {
        struct {
            uint8_t bg0: 1;
            uint8_t bg1: 1;
            uint8_t bg2: 1;
            uint8_t bg3: 1;
            uint8_t obj: 1;
            uint8_t win0: 1;
            uint8_t win1: 1;
            uint8_t obj_win: 1;
        };
        uint8_t byte1;
    };
};

static_assert(sizeof(struct io_reg_dispcnt) == sizeof(uint16_t));

/*
** The LCD Display Status (IO_REG_DISPSTAT) register layout.
*/
struct io_reg_dispstat {
    union {
        struct {
            uint8_t vblank: 1;          // Set if rendering the vblank
            uint8_t hblank: 1;          // Set if rendering the hblank
            uint8_t vcount: 1;          // Set if vcount_stg == vcount
            uint8_t vblank_irq: 1;      // Enable to IRQ when vblank
            uint8_t hblank_irq: 1;      // Enable to IRQ when hblank
            uint8_t vcount_irq: 1;      // Enable to IRQ when vcount_stg == vcount
            uint8_t : 2;
        };
        uint8_t byte0;
    };
    uint8_t vcount_stg;
};

static_assert(sizeof(struct io_reg_dispstat) == sizeof(uint16_t));

/* io/io.c */
void io_init(struct io *io);

#endif /* IO_H */