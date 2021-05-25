/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <endian.h>
#include <string.h>
#include "memory.h"
#include "hades.h"
#include "core.h"

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
    struct memory const *memory,
    uint32_t addr
) {
    switch (addr) {
        case BIOS_START ... BIOS_END:
            return (memory->bios[addr & 0x3FFF]);
        case EWRAM_START ... EWRAM_END:
            return (memory->ewram[addr & 0x3FFFF]);
        case IWRAM_START ... IWRAM_END:
            return (memory->iwram[addr & 0x7FFF]);
        case IO_START ... IO_END:
            return (memory->io[addr & 0x3FF]);
        case PALRAM_START ... PALRAM_END:
            return (memory->palram[addr & 0x3FF]);
        case VRAM_START ... VRAM_END:
            return (memory->vram[addr & 0x17FFF]);
        case OAM_START ... OAM_END:
            return (memory->oam[addr & 0x3FF]);
        case CART_0_START ... CART_0_END:
        case CART_1_START ... CART_1_END:
        case CART_2_START ... CART_2_END:
            return (memory->rom[addr & 0x1FFFFFF]);
        case CART_SRAM_START ... CART_SRAM_END:
            return (memory->sram[addr & 0xFFFF]);
    default:
            panic(HS_CORE, "Invalid read at address %#08x", addr);
    }
}

/*
** Try to read the byte at the given address, return 0 in
** case of failure.
*/
uint8_t
mem_try_read8(
    struct memory const *memory,
    uint32_t addr
) {
    switch (addr) {
        case BIOS_START ... BIOS_END:
            return (memory->bios[addr & 0x3FFF]);
        case EWRAM_START ... EWRAM_END:
            return (memory->ewram[addr & 0x3FFFF]);
        case IWRAM_START ... IWRAM_END:
            return (memory->iwram[addr & 0x7FFF]);
        case IO_START ... IO_END:
            return (memory->io[addr & 0x3FF]);
        case PALRAM_START ... PALRAM_END:
            return (memory->palram[addr & 0x3FF]);
        case VRAM_START ... VRAM_END:
            return (memory->vram[addr & 0x17FFF]);
        case OAM_START ... OAM_END:
            return (memory->oam[addr & 0x3FF]);
        case CART_0_START ... CART_0_END:
        case CART_1_START ... CART_1_END:
        case CART_2_START ... CART_2_END:
            return (memory->rom[addr & 0x1FFFFFF]);
        case CART_SRAM_START ... CART_SRAM_END:
            return (memory->sram[addr & 0xFFFF]);
        default:
            return 0;
    }
}

/*
** Read the word at the given address, hiding all endianness conversions.
**
** This function returns an `uint32_t` instead of an `uint16_t` to account for
** some of the shenanigans the ARM7TDMI does when supplied an unligned address.
*/
uint32_t
mem_read16(
    struct memory const *memory,
    uint32_t addr
) {
    uint32_t rotate;
    uint32_t value;

    rotate = (addr % 2) << 3;
    addr &= 0xFFFFFFFE;

    value =
        (mem_read8(memory, addr + 0) << 0) |
        (mem_read8(memory, addr + 1) << 8)
    ;

    /* Unaligned 16-bits loads are supposed to be unpredictable, but in practise the GBA rotates them */
    return ((value >> rotate) | (value << (32 - rotate)));
}

/*
** Try to read the word at the given address, hiding all endianness conversions.
**
** This function returns an `uint32_t` instead of an `uint16_t` to account for
** some of the shenanigans the ARM7TDMI does when supplied an unligned address.
*/
uint32_t
mem_try_read16(
    struct memory const *memory,
    uint32_t addr
) {
    uint32_t rotate;
    uint32_t value;

    rotate = (addr % 2) << 3;
    addr &= 0xFFFFFFFE;

    value =
        (mem_try_read8(memory, addr + 0) << 0) |
        (mem_try_read8(memory, addr + 1) << 8)
    ;

    /* Unaligned 16-bits loads are supposed to be unpredictable, but in practise the GBA rotates them */
    return ((value >> rotate) | (value << (32 - rotate)));
}

/*
** Read the double-word at the given address, hiding all endianness conversions.
*/
uint32_t
mem_read32(
    struct memory const *memory,
    uint32_t addr
) {
    uint32_t rotate;
    uint32_t value;

    rotate = (addr % 4) << 3;
    addr &= 0xFFFFFFFE;

    value =
        (mem_read8(memory, addr + 0) << 0) |
        (mem_read8(memory, addr + 1) << 8) |
        (mem_read8(memory, addr + 2) << 16) |
        (mem_read8(memory, addr + 3) << 24)
    ;

    /* Unaligned 32-bits loads are rotated */
    return ((value >> rotate) | (value << (32 - rotate)));
}

/*
** Try to read the double-word at the given address, hiding all endianness conversions.
*/
uint32_t
mem_try_read32(
    struct memory const *memory,
    uint32_t addr
) {
    uint32_t rotate;
    uint32_t value;

    rotate = (addr % 4) << 3;
    addr &= 0xFFFFFFFE;

    value =
        (mem_try_read8(memory, addr + 0) << 0) |
        (mem_try_read8(memory, addr + 1) << 8) |
        (mem_try_read8(memory, addr + 2) << 16) |
        (mem_try_read8(memory, addr + 3) << 24)
    ;

    /* Unaligned 32-bits loads are rotated */
    return ((value >> rotate) | (value << (32 - rotate)));
}


/*
** Read the byte at the given address.
*/
void
mem_write8(
    struct memory *memory,
    uint32_t addr,
    uint8_t val
) {
    switch (addr) {
        case BIOS_START ... BIOS_END:
            memory->bios[addr & 0x3FFF] = val;
            break;
        case EWRAM_START ... EWRAM_END:
            memory->ewram[addr & 0x3FFFF] = val;
            break;
        case IWRAM_START ... IWRAM_END:
            memory->iwram[addr & 0x7FFF] = val;
            break;
        case IO_START ... IO_END:
            memory->io[addr & 0x3FF] = val;
            if (addr % 4 == 3) {
                mem_io_write(memory, addr - 3);
            }
            break;
        case PALRAM_START ... PALRAM_END:
            memory->palram[addr & 0x3FF] = val;
            break;
        case VRAM_START ... VRAM_END:
            memory->vram[addr & 0x17FFF] = val;
            break;
        case OAM_START ... OAM_END:
            memory->oam[addr & 0x3FF] = val;
            break;
        case CART_0_START ... CART_0_END:
        case CART_1_START ... CART_1_END:
        case CART_2_START ... CART_2_END:
            memory->rom[addr & 0x1FFFFFF] = val;
            break;
        case CART_SRAM_START ... CART_SRAM_END:
            memory->sram[addr & 0xFFFF] = val;
            break;
        default:
            panic(HS_CORE, "Invalid write at address %#08x", addr);
    }
}

/*
** Read the word at the given address, hiding all endianness conversions.
*/
void
mem_write16(
    struct memory *memory,
    uint32_t addr,
    uint16_t val
) {
    mem_write8(memory, addr + 0, (uint8_t)(val >> 0));
    mem_write8(memory, addr + 1, (uint8_t)(val >> 8));
}

/*
** Read the double-word at the given address, hiding all endianness conversions.
*/
void
mem_write32(
    struct memory *memory,
    uint32_t addr,
    uint32_t val
) {
    mem_write8(memory, addr + 0, (uint8_t)(val >>  0));
    mem_write8(memory, addr + 1, (uint8_t)(val >>  8));
    mem_write8(memory, addr + 2, (uint8_t)(val >> 16));
    mem_write8(memory, addr + 3, (uint8_t)(val >> 24));
}