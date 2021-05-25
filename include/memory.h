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

struct memory
{
    // General Internal Memory
    uint8_t bios[0x4000];
    uint8_t ewram[0x40000];
    uint8_t iwram[0x8000];
    uint8_t io[0x400];

    // Internal Display Memory
    uint8_t palram[0x400];
    uint8_t vram[0x18000];
    uint8_t oam[0x400];

    // External Memory (Game Pak)
    uint8_t rom[0x2000000];
    uint8_t sram[0x10000];
} __packed;

enum memory_regions {
    BIOS_START      = 0x00000000,
    BIOS_END        = 0x00003FFF,

    EWRAM_START     = 0x02000000,
    EWRAM_END       = 0x0203FFFF,

    IWRAM_START     = 0x03000000,
    IWRAM_END       = 0x03007FFF,

    IO_START        = 0x04000000,
    IO_END          = 0x040003FF,

    PALRAM_START    = 0x05000000,
    PALRAM_END      = 0x050003FF,

    VRAM_START      = 0x06000000,
    VRAM_END        = 0x06017FFF,

    OAM_START       = 0x07000000,
    OAM_END         = 0x070003FF,

    CART_0_START    = 0x08000000,
    CART_0_END      = 0x09FFFFFF,

    CART_1_START    = 0x0A000000,
    CART_1_END      = 0x0BFFFFFF,

    CART_2_START    = 0x0C000000,
    CART_2_END      = 0x0DFFFFFF,

    CART_SRAM_START = 0x0E000000,
    CART_SRAM_END   = 0x0E00FFFF,
};

enum io_regs
{
    REG_DISPCNT     = 0x04000000,
    REG_DISPSTAT    = 0x04000004,
    REG_VCOUNT      = 0x04000006,
};

struct core;

/* memory/io.c */
void mem_io_write(struct memory *memory, uint32_t addr);

/* memory/memory.c */
void mem_init(struct memory *memory);
uint8_t mem_read8(struct memory const *memory, uint32_t addr);
uint32_t mem_read16(struct memory const *memory, uint32_t addr);
uint32_t mem_read32(struct memory const *memory, uint32_t addr);
uint8_t mem_try_read8(struct memory const *memory, uint32_t addr);
uint32_t mem_try_read16(struct memory const *memory, uint32_t addr);
uint32_t mem_try_read32(struct memory const *memory, uint32_t addr);
void mem_write8(struct memory *memory, uint32_t addr, uint8_t val);
void mem_write16(struct memory *memory, uint32_t addr, uint16_t val);
void mem_write32(struct memory *memory, uint32_t addr, uint32_t val);

/* memory/rom.c */
int mem_load_rom(struct memory *memory, char const *filename);

#endif /* !MEMORY_H */