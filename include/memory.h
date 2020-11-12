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

# define MEMORY_RAW_SIZE                0x10000000

struct memory
{
    union {
        struct {
            // General Internal Memory
            uint8_t bios[0x00004000];
            uint8_t _unused_1[0x1ffc000];
            uint8_t on_board_wram[0x40000];
            uint8_t _unused_2[0xfc0000];
            uint8_t on_chip_wram[0x8000];
            uint8_t _unused_3[0xff8000];
            uint8_t io[0x400];
            uint8_t _unused_4[0xfffc00];

            // Internal Display Memory
            uint8_t pram[0x400];
            uint8_t _unused_5[0xfffc00];
            uint8_t vram[0x18000];
            uint8_t _unused_6[0xfe8000];
            uint8_t oam[0x400];
            uint8_t _unused_7[0xfffc00];

            // External Memory (Game Pak)
            uint8_t gamepak_rom_0[0x2000000];
            uint8_t gamepak_rom_1[0x2000000];
            uint8_t gamepak_rom_2[0x2000000];
            uint8_t gamepak_sram[0x10000];
            uint8_t _unused_8[0x1ff0000];
        };
        uint8_t raw[0x10000000];
    };
} __packed;

static_assert(sizeof(((struct memory *)NULL)->raw) == MEMORY_RAW_SIZE);

struct core;

/* memory/memory.c */
void mem_init(struct memory *memory);
void mem_reset(struct memory *memory);
uint8_t mem_read8(struct core const *core, uint32_t addr);
void mem_write8(struct core *core, uint32_t addr, uint8_t val);
uint32_t mem_read16(struct core const *core, uint32_t addr);
void mem_write16(struct core *core, uint32_t addr, uint16_t val);
uint32_t mem_read32(struct core const *core, uint32_t addr);
void mem_write32(struct core *core, uint32_t addr, uint32_t val);

/* memory/rom.c */
int mem_load_rom(struct memory *memory, char const *filename);

#endif /* !MEMORY_H */