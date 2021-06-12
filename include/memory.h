/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#ifndef MEMORY_H
# define MEMORY_H

# include <stdint.h>
# include "hades.h"

/*
** The overall memory of the Gameboy Advance.
*/
struct memory {
    // General Internal Memory
    uint8_t bios[0x4000];
    uint8_t ewram[0x40000];
    uint8_t iwram[0x8000];

    // Internal Display Memory
    uint8_t palram[0x400];
    uint8_t vram[0x18000];
    uint8_t oam[0x400];

    // External Memory (Game Pak)
    uint8_t rom[0x2000000];
    uint8_t sram[0x10000];
} __packed;

/*
** An enumeration of the different memory regions
** and other informations associated with them.
*/
enum memory_regions {
    BIOS_START          = 0x00000000,
    BIOS_END            = 0x00003FFF,
    BIOS_REGION         = BIOS_START >> 24,
    BIOS_MASK           = BIOS_END - BIOS_START,

    EWRAM_START         = 0x02000000,
    EWRAM_END           = 0x0203FFFF,
    EWRAM_REGION        = EWRAM_START >> 24,
    EWRAM_MASK          = EWRAM_END - EWRAM_START,

    IWRAM_START         = 0x03000000,
    IWRAM_END           = 0x03007FFF,
    IWRAM_REGION        = IWRAM_START >> 24,
    IWRAM_MASK          = IWRAM_END - IWRAM_START,

    IO_START            = 0x04000000,
    IO_END              = 0x040003FF,
    IO_REGION           = IO_START >> 24,
    IO_MASK             = IO_END - IO_START,

    PALRAM_START        = 0x05000000,
    PALRAM_END          = 0x050003FF,
    PALRAM_REGION       = PALRAM_START >> 24,
    PALRAM_MASK         = PALRAM_END - PALRAM_START,

    VRAM_START          = 0x06000000,
    VRAM_END            = 0x06017FFF,
    VRAM_REGION         = VRAM_START >> 24,
    VRAM_MASK_1         = 0x00017FFF,
    VRAM_MASK_2         = 0x0001FFFF,

    OAM_START           = 0x07000000,
    OAM_END             = 0x070003FF,
    OAM_REGION          = OAM_START >> 24,
    OAM_MASK            = OAM_END - OAM_START,

    CART_0_START        = 0x08000000,
    CART_0_END          = 0x09FFFFFF,
    CART_0_REGION_1     = CART_0_START >> 24,
    CART_0_REGION_2     = CART_0_END >> 24,

    CART_1_START        = 0x0A000000,
    CART_1_END          = 0x0BFFFFFF,
    CART_1_REGION_1     = CART_1_START >> 24,
    CART_1_REGION_2     = CART_1_END >> 24,

    CART_2_START        = 0x0C000000,
    CART_2_END          = 0x0DFFFFFF,
    CART_2_REGION_1     = CART_2_START >> 24,
    CART_2_REGION_2     = CART_2_END >> 24,

    CART_MASK           = CART_0_END - CART_0_START,

    CART_SRAM_START     = 0x0E000000,
    CART_SRAM_END       = 0x0E00FFFF,
    CART_SRAM_REGION    = CART_SRAM_START >> 24,
    CART_SRAM_MASK      = CART_SRAM_END - CART_SRAM_START,
};

/*
** The different timings at which a DMA transfer can occur.
*/
enum dma_timings {
    DMA_TIMING_NOW              = 0,
    DMA_TIMING_VBLANK           = 1,
    DMA_TIMING_HBLANK           = 2,
    DMA_TIMING_SPECIAL          = 3,
};

struct core;
struct gba;

/* memory/dma.c */
void mem_dma_transfer(struct gba *gba, enum dma_timings timing);

/* memory/io.c */
uint8_t mem_io_read8(struct gba const *gba, uint32_t addr);
void mem_io_write8(struct gba *gba, uint32_t addr, uint8_t val);

/* memory/memory.c */
void mem_init(struct memory *memory);
uint8_t mem_read8(struct gba const *gba, uint32_t addr);
uint32_t mem_read16(struct gba const *gba, uint32_t addr);
uint32_t mem_read32(struct gba const *gba, uint32_t addr);
uint32_t mem_read32_ror(struct gba const *gba, uint32_t addr);
void mem_write8(struct gba *gba, uint32_t addr, uint8_t val);
void mem_write16(struct gba *gba, uint32_t addr, uint16_t val);
void mem_write32(struct gba *gba, uint32_t addr, uint32_t val);

/* memory/rom.c */
int mem_load_bios(struct memory *memory, char const *filename);
int mem_load_rom(struct memory *memory, char const *filename);

#endif /* !MEMORY_H */