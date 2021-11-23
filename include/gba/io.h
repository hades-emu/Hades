/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef GBA_IO_H
# define GBA_IO_H

# include "hades.h"
# include "gba/scheduler.h"

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

    IO_REG_BG2PA        = 0x04000020,
    IO_REG_BG2PB        = 0x04000022,
    IO_REG_BG2PC        = 0x04000024,
    IO_REG_BG2PD        = 0x04000026,
    IO_REG_BG2X         = 0x04000028,
    IO_REG_BG2Y         = 0x0400002C,
    IO_REG_BG3PA        = 0x04000030,
    IO_REG_BG3PB        = 0x04000032,
    IO_REG_BG3PC        = 0x04000034,
    IO_REG_BG3PD        = 0x04000036,
    IO_REG_BG3X         = 0x04000038,
    IO_REG_BG3Y         = 0x0400003C,

    IO_REG_WIN0H        = 0x04000040,
    IO_REG_WIN1H        = 0x04000042,
    IO_REG_WIN0V        = 0x04000044,
    IO_REG_WIN1V        = 0x04000046,
    IO_REG_WININ        = 0x04000048,
    IO_REG_WINOUT       = 0x0400004A,
    IO_REG_MOSAIC       = 0x0400004C,
    IO_REG_BLDCNT       = 0x04000050,
    IO_REG_BLDALPHA     = 0x04000052,
    IO_REG_BLDY         = 0x04000054,

    /* Sound */

    IO_REG_SOUNDCNT_L   = 0x04000080,
    IO_REG_SOUNDCNT_H   = 0x04000082,
    IO_REG_SOUNDCNT_X   = 0x04000084,
    IO_REG_SOUNDBIAS    = 0x04000088,
    IO_REG_FIFO_A       = 0x040000A0,
    IO_REG_FIFO_B       = 0x040000A4,

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
    IO_REG_KEYCNT       = 0x04000132,

    /* Serial Communication (2) */
    IO_REG_RCNT         = 0x04000134,

    /* Interrupts */

    IO_REG_IE           = 0x04000200,
    IO_REG_IF           = 0x04000202,
    IO_REG_WAITCNT      = 0x04000204,
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

    uint32_t internal_src;
    uint32_t internal_dst;
    uint32_t internal_count;

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
};

/*
** A timer and the different IO registers/internal values associated with it.
*/
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

    event_handler_t handler;
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
            uint8_t winobj: 1;
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

    union {
        uint16_t raw;
        uint8_t bytes[2];
    } vcount;

    // REG_BG{0,1,2,3}CNT
    union {
        struct {
            uint16_t priority: 2;
            uint16_t character_base: 2;
            uint16_t : 2;
            uint16_t mosaic: 1;
            uint16_t palette_type: 1;  // 0: 16/16, 1: 256/1
            uint16_t screen_base: 5;
            uint16_t wrap: 1;
            uint16_t size: 2;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } bgcnt[4];

    // REG_BGXHOFF
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } bg_hoffset[4];

    // REG_BGYHOFF
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } bg_voffset[4];

    // REG_BGXPA
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } bg_pa[2];

    // REG_BGXPB
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } bg_pb[2];

    // REG_BGXPC
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } bg_pc[2];

    // REG_BGXPD
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } bg_pd[2];

    // REG_BGXX
    union {
        uint32_t raw;
        uint8_t bytes[4];
    } bg_x[2];

    // REG_BGXY
    union {
        uint32_t raw;
        uint8_t bytes[4];
    } bg_y[2];

    // REG_WINH
    union {
        struct {
            uint16_t max: 8; // Exclusive
            uint16_t min: 8; // Inclusive
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } winh[2];

    // REG_WINY
    union {
        struct {
            uint16_t max: 8; // Exclusive
            uint16_t min: 8; // Inclusive
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } winv[2];

    // REG_WININ
    union {
        struct {
            union {
                struct {
                    uint16_t win0_bg: 4;
                    uint16_t win0_obj: 1;
                    uint16_t win0_effects: 1;
                    uint16_t : 2;
                } __packed;
                uint8_t win0;
            };
            union {
                struct {
                    uint16_t win1_bg: 4;
                    uint16_t win1_obj: 1;
                    uint16_t win1_effects: 1;
                    uint16_t : 2;
                } __packed;
                uint8_t win1;
            };
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } winin;

    // REG_WINOUT
    union {
        struct {
            union {
                struct {
                    uint16_t winout_bg: 4;
                    uint16_t winout_obj: 1;
                    uint16_t winout_effects: 1;
                    uint16_t : 2;
                } __packed;
                uint8_t winout;
            };
            union {
                struct {
                    uint16_t winobj_bg: 4;
                    uint16_t winobj_obj: 1;
                    uint16_t winobj_effects: 1;
                    uint16_t : 2;
                } __packed;
                uint8_t winobj;
            };
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } winout;

    // REG_MOSAIC
    union {
        struct {
            uint16_t bg_hsize: 4;
            uint16_t bg_vise: 4;
            uint16_t obj_hsize: 4;
            uint16_t obj_vise: 4;
            uint16_t : 16;
        } __packed;
        uint32_t raw;
        uint8_t bytes[4];
    } mosaic;

    // REG_BLDCNT
    union {
        struct {
            uint16_t top_bg: 4;
            uint16_t top_oam: 1;
            uint16_t top_backdrop: 1;
            uint16_t mode: 2;
            uint16_t bot_bg: 4;
            uint16_t bot_oam: 1;
            uint16_t bot_backdrop: 1;
            uint16_t : 2;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } bldcnt;

    // REG_BLDALPHA
    union {
        struct {
            uint16_t top_coef: 5;
            uint16_t : 3;
            uint16_t bot_coef: 6;
            uint16_t : 3;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } bldalpha;

    // REG_BLDY
    union {
        struct {
            uint16_t coef: 5;
            uint16_t : 11;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } bldy;

    // REG_SOUNDCNT_L
    union {
        struct {
            uint16_t master_sound_right: 3;
            uint16_t : 1;
            uint16_t master_sound_left: 3;
            uint16_t : 1;
            uint16_t enable_sound_right: 4;
            uint16_t enable_sound_left: 4;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } soundcnt_l;

    // REG_SOUNDCNT_H
    union {
        struct {
            uint16_t volume_sounds: 2;
            uint16_t volume_fifo_a: 1;
            uint16_t volume_fifo_b: 1;
            uint16_t : 4;
            uint16_t enable_fifo_a_right: 1;
            uint16_t enable_fifo_a_left: 1;
            uint16_t timer_fifo_a: 1;
            uint16_t reset_fifo_a: 1;
            uint16_t enable_fifo_b_right: 1;
            uint16_t enable_fifo_b_left: 1;
            uint16_t timer_fifo_b: 1;
            uint16_t reset_fifo_b: 1;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } soundcnt_h;

    // REG_SOUNDCNT_X
    union {
        struct {
            uint16_t sound_on: 4;
            uint16_t : 3;
            uint16_t master_fifo_enable: 1;
            uint16_t : 8;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } soundcnt_x;

    // DMA Channels
    struct dma_channel dma[4];

    // Timers
    struct timer timers[4];

    // REG_KEYINPUT
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
    } keyinput;

    // REG_KEYCNT
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
            uint16_t : 4;
            uint16_t irq_enable: 1;
            uint16_t irq_cond: 1;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } keycnt;

    // REG_RCNT
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } rcnt;

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

    // REG_WAITCNT
    union {
        struct {
            uint16_t sram: 2;
            uint16_t ws0_nonseq: 2;
            uint16_t ws0_seq: 1;
            uint16_t ws1_nonseq: 2;
            uint16_t ws1_seq: 1;
            uint16_t ws2_nonseq: 2;
            uint16_t ws2_seq: 1;
            uint16_t phi: 2;
            uint16_t : 1;
            uint16_t gamepak_prefetch: 1;
            uint16_t gamepak_type: 1;
        } __packed;
        uint16_t raw;
        uint8_t bytes[2];
    } waitcnt;

    // REG_IME
    union {
        uint16_t raw;
        uint8_t bytes[2];
    } ime;

    // REG_POSTFLG
    uint8_t postflg;
};

static_assert(sizeof(((struct io *)NULL)->dispcnt) == sizeof(uint16_t));
static_assert(sizeof(((struct io *)NULL)->dispstat) == sizeof(uint16_t));

struct gba;

/* gba/memory/io.c */
void io_init(struct io *io);
void io_scan_keypad_irq(struct gba *gba);

/* gba/timer.c */
void timer_start(struct gba *gba, uint32_t timer_idx);
void timer_stop(struct gba *gba, uint32_t timer_idx);
uint16_t timer_update_counter(struct gba const *gba, uint32_t timer_idx);

#endif /* GBA_IO_H */