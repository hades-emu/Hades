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
#include "hades.h"
#include "core.h"
#include "gba.h"

void
mem_init(
    struct memory *memory
) {
    memset(memory, 0, sizeof(*memory));
}

/*
** Read the byte at the given address.
*/
uint8_t
mem_read8(
    struct gba const *gba,
    uint32_t addr
) {
    struct memory const *memory;

    memory = &gba->memory;
    switch (addr >> 24) {
        case BIOS_REGION:
            return (memory->bios[addr & BIOS_MASK]);
        case EWRAM_REGION:
            return (memory->ewram[addr & EWRAM_MASK]);
        case IWRAM_REGION:
            return (memory->iwram[addr & IWRAM_MASK]);
        case IO_REGION:
            return (mem_io_read8(gba, addr));
        case PALRAM_REGION:
            return (memory->palram[addr & PALRAM_MASK]);
        case VRAM_REGION:
            return (memory->vram[addr & ((addr & 0x10000) ? VRAM_MASK_1 : VRAM_MASK_2)]);
        case OAM_REGION:
            return (memory->oam[addr & OAM_MASK]);
        case CART_0_REGION_1:
        case CART_0_REGION_2:
        case CART_1_REGION_1:
        case CART_1_REGION_2:
        case CART_2_REGION_1:
        case CART_2_REGION_2:
            return (memory->rom[addr & CART_MASK]);
        case CART_SRAM_REGION:
            {
                if (addr == 0x0E000000) {
                    return (0x62);
                } else if (addr == 0x0E000001) {
                    return (0x13);
                } else {
                    return (memory->sram[addr & CART_SRAM_MASK]);
                }
            }
        default:
            logln(HS_MEMORY, "Invalid read at address 0x%08x", addr);
            return (0);
    }
}

/*
** Read the word at the given address.
**
** This function returns an `uint32_t` instead of an `uint16_t` to account for
** some of the shenanigans the ARM7TDMI does when supplied an unligned address.
*/
uint32_t
mem_read16(
    struct gba const *gba,
    uint32_t addr
) {
    uint32_t rotate;
    uint32_t value;

    rotate = (addr % 2) << 3;
    addr &= ~(sizeof(uint16_t) - 1);

    value =
        (mem_read8(gba, addr + 0) << 0) |
        (mem_read8(gba, addr + 1) << 8)
    ;

    /* Unaligned 16-bits loads are supposed to be unpredictable, but in practise the GBA rotates them */
    return (ror32(value, rotate));
}

/*
** Read the double-word at the given address.
*/
uint32_t
mem_read32(
    struct gba const *gba,
    uint32_t addr
) {
    addr &= ~(sizeof(uint32_t) - 1);

    return (
        (mem_read8(gba, addr + 0) << 0) |
        (mem_read8(gba, addr + 1) << 8) |
        (mem_read8(gba, addr + 2) << 16) |
        (mem_read8(gba, addr + 3) << 24)
    );
}

/*
** Read the double-word at the given address and ROR it if the
** address isn't aligned.
*/
uint32_t
mem_read32_ror(
    struct gba const *gba,
    uint32_t addr
) {
    uint32_t rotate;
    uint32_t value;

    rotate = (addr % 4) << 3;
    addr &= ~(sizeof(uint32_t) - 1);

    value =
        (mem_read8(gba, addr + 0) << 0) |
        (mem_read8(gba, addr + 1) << 8) |
        (mem_read8(gba, addr + 2) << 16) |
        (mem_read8(gba, addr + 3) << 24)
    ;

    /* Unaligned 32-bits loads are rotated */
    return (ror32(value, rotate));
}

/*
** Read the byte at the given address.
*/
void
mem_write8(
    struct gba *gba,
    uint32_t addr,
    uint8_t val
) {
    struct memory *memory;

    memory = &gba->memory;
    switch (addr >> 24) {
        case BIOS_REGION:
            /* Ignore writes attempts to the bios memory. */
            break;
        case EWRAM_REGION:
            memory->ewram[addr & EWRAM_MASK] = val;
            break;
        case IWRAM_REGION:
            memory->iwram[addr & IWRAM_MASK] = val;
            break;
        case IO_REGION:
            mem_io_write8(gba, addr, val);
            break;
        case PALRAM_REGION:
            memory->palram[addr & PALRAM_MASK] = val;
            break;
        case VRAM_REGION:
            memory->vram[addr & ((addr & 0x10000) ? VRAM_MASK_1 : VRAM_MASK_2)] = val;
            break;
        case OAM_REGION:
            memory->oam[addr & OAM_MASK] = val;
            break;
        case CART_0_REGION_1:
        case CART_0_REGION_2:
        case CART_1_REGION_1:
        case CART_1_REGION_2:
        case CART_2_REGION_1:
        case CART_2_REGION_2:
            /* Ignore writes attempts to the cartridge memory. */
            break;
        case CART_SRAM_REGION:
            memory->sram[addr & CART_SRAM_MASK] = val;
            break;
        default:
            logln(HS_MEMORY, "Invalid write at address 0x%08x", addr);
    }
}

/*
** Read the word at the given address.
*/
void
mem_write16(
    struct gba *gba,
    uint32_t addr,
    uint16_t val
) {
    addr &= ~(sizeof(uint16_t) - 1);
    mem_write8(gba, addr + 0, (uint8_t)(val >> 0));
    mem_write8(gba, addr + 1, (uint8_t)(val >> 8));
}

/*
** Read the double-word at the given address.
*/
void
mem_write32(
    struct gba *gba,
    uint32_t addr,
    uint32_t val
) {
    addr &= ~(sizeof(uint32_t) - 1);
    mem_write8(gba, addr + 0, (uint8_t)(val >>  0));
    mem_write8(gba, addr + 1, (uint8_t)(val >>  8));
    mem_write8(gba, addr + 2, (uint8_t)(val >> 16));
    mem_write8(gba, addr + 3, (uint8_t)(val >> 24));
}