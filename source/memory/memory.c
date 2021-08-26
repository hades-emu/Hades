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

static uint32_t access_time16[2][16] = {
    [NON_SEQUENTIAL]    = { 1, 1, 3, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1 },
    [SEQUENTIAL]        = { 1, 1, 3, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1 },
};

static uint32_t access_time32[2][16] = {
    [NON_SEQUENTIAL]    = { 1, 1, 6, 1, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 1 },
    [SEQUENTIAL]        = { 1, 1, 6, 1, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 1 },
};

static uint32_t gamepak_nonseq_waitstates[4] = { 4, 3, 2, 8 };

/*
** Initialize the memory to its initial state, before the system is up.
*/
void
mem_init(
    struct memory *memory
) {
    memset(memory, 0, sizeof(*memory));
}

void
mem_update_waitstates(
    struct gba const *gba
) {
    struct io const *io;
    uint32_t x;

    io = &gba->io;

    // 16 bit, non seq
    access_time16[NON_SEQUENTIAL][CART_0_REGION_1]  = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws0_nonseq];
    access_time16[NON_SEQUENTIAL][CART_0_REGION_2]  = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws0_nonseq];
    access_time16[NON_SEQUENTIAL][CART_1_REGION_1]  = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws1_nonseq];
    access_time16[NON_SEQUENTIAL][CART_1_REGION_2]  = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws1_nonseq];
    access_time16[NON_SEQUENTIAL][CART_2_REGION_1]  = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws2_nonseq];
    access_time16[NON_SEQUENTIAL][CART_2_REGION_2]  = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws2_nonseq];
    access_time16[NON_SEQUENTIAL][CART_SRAM_REGION] = 1 + gamepak_nonseq_waitstates[io->waitcnt.sram];

    // 16 bit, seq
    access_time16[SEQUENTIAL][CART_0_REGION_1]  = 1 + (io->waitcnt.ws0_seq ? 1 : 2);
    access_time16[SEQUENTIAL][CART_0_REGION_2]  = 1 + (io->waitcnt.ws0_seq ? 1 : 2);
    access_time16[SEQUENTIAL][CART_1_REGION_1]  = 1 + (io->waitcnt.ws1_seq ? 1 : 4);
    access_time16[SEQUENTIAL][CART_1_REGION_2]  = 1 + (io->waitcnt.ws1_seq ? 1 : 4);
    access_time16[SEQUENTIAL][CART_2_REGION_1]  = 1 + (io->waitcnt.ws2_seq ? 1 : 8);
    access_time16[SEQUENTIAL][CART_2_REGION_2]  = 1 + (io->waitcnt.ws2_seq ? 1 : 8);
    access_time16[SEQUENTIAL][CART_SRAM_REGION] = 1 + gamepak_nonseq_waitstates[io->waitcnt.sram];

    // Update for 32-bit too.
    for (x = CART_0_REGION_1; x <= CART_SRAM_REGION; ++x) {
        access_time32[NON_SEQUENTIAL][x] = access_time16[NON_SEQUENTIAL][x] + access_time16[SEQUENTIAL][x];
        access_time32[SEQUENTIAL][x] = 2 * access_time16[SEQUENTIAL][x];
    }
}

/*
** Calculate and add to the current cycle counter the amount of cycles needed for as many bus accesses
** are needed to transfer a data of the given size and access type.
**
** Region        Bus   Read      Write     Cycles   Note
** ==================================================
** BIOS ROM      32    8/16/32   -         1/1/1
** Work RAM 32K  32    8/16/32   8/16/32   1/1/1
** I/O           32    8/16/32   8/16/32   1/1/1
** OAM           32    8/16/32   16/32     1/1/1    a
** Work RAM 256K 16    8/16/32   8/16/32   3/3/6    b
** Palette RAM   16    8/16/32   16/32     1/1/2    a
** VRAM          16    8/16/32   16/32     1/1/2    a
** GamePak ROM   16    8/16/32   -         5/5/8    b/c
** GamePak Flash 16    8/16/32   16/32     5/5/8    b/c
** GamePak SRAM  8     8         8         5        b
**
** Timing Notes:
**
**  a   Plus 1 cycle if GBA accesses video memory at the same time.
**  b   Default waitstate settings, see System Control chapter.
**  c   Separate timings for sequential, and non-sequential accesses.
**
** Source: GBATek
*/
static
inline
void
mem_access(
    struct gba *gba,
    uint32_t addr,
    uint32_t size,  // In bytes
    enum access_type access_type
) {
    uint32_t cycles;
    uint32_t page;

    page = (addr >> 24) & 0xF;

    if (page >= CART_0_REGION_1 && page <= CART_2_REGION_2 && (addr & 0x1FFFF) == 0) {
        access_type = NON_SEQUENTIAL;
    }

    if (size <= sizeof(uint16_t)) {
        cycles = access_time16[access_type][page];
    } else {
        cycles = access_time32[access_type][page];
    }

    core_idle_for(gba, cycles);
}

/*
** Read the byte at the given address.
*/
uint8_t
mem_read8(
    struct gba *gba,
    uint32_t addr,
    enum access_type access_type
) {
    mem_access(gba, addr, sizeof(uint8_t), access_type);
    return (mem_read8_raw(gba, addr));
}

/*
** Read the byte at the given address without updating the cycle counter.
*/
uint8_t
mem_read8_raw(
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
            return (mem_palram_read8(gba, addr));
        case VRAM_REGION:
            return (mem_vram_read8(gba, addr));
        case OAM_REGION:
            return (mem_oam_read8(gba, addr));
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
** Read the half-word at the given address.
*/
uint16_t
mem_read16(
    struct gba *gba,
    uint32_t addr,
    enum access_type access_type
) {
    addr &= ~(sizeof(uint16_t) - 1);

    mem_access(gba, addr, sizeof(uint16_t), access_type);

    return (
        (mem_read8_raw(gba, addr + 0) << 0) |
        (mem_read8_raw(gba, addr + 1) << 8)
    );
}

/*
** Read the half-word at the given address without updating the cycle counter.
*/
uint16_t
mem_read16_raw(
    struct gba const *gba,
    uint32_t addr
) {
    addr &= ~(sizeof(uint16_t) - 1);
    return (
        (mem_read8_raw(gba, addr + 0) << 0) |
        (mem_read8_raw(gba, addr + 1) << 8)
    );
}

/*
** Read the half-word at the given address and ROR it if the
** address isn't aligned.
*/
uint32_t
mem_read16_ror(
    struct gba *gba,
    uint32_t addr,
    enum access_type access_type
) {
    uint32_t rotate;
    uint32_t value;

    rotate = (addr % 2) << 3;
    addr &= ~(sizeof(uint16_t) - 1);

    value = mem_read16(gba, addr, access_type);

    /* Unaligned 16-bits loads are supposed to be unpredictable, but in practise the GBA rotates them */
    return (ror32(value, rotate));
}

/*
** Read the word at the given address.
*/
uint32_t
mem_read32(
    struct gba *gba,
    uint32_t addr,
    enum access_type access_type
) {
    addr &= ~(sizeof(uint32_t) - 1);

    mem_access(gba, addr, sizeof(uint32_t), access_type);
    return (
        (mem_read8_raw(gba, addr + 0) <<  0) |
        (mem_read8_raw(gba, addr + 1) <<  8) |
        (mem_read8_raw(gba, addr + 2) << 16) |
        (mem_read8_raw(gba, addr + 3) << 24)
    );
}

/*
** Read the word at the given address without updating the cycle counter.
*/
uint32_t
mem_read32_raw(
    struct gba const *gba,
    uint32_t addr
) {
    addr &= ~(sizeof(uint32_t) - 1);

    return (
        (mem_read8_raw(gba, addr + 0) <<  0) |
        (mem_read8_raw(gba, addr + 1) <<  8) |
        (mem_read8_raw(gba, addr + 2) << 16) |
        (mem_read8_raw(gba, addr + 3) << 24)
    );
}

/*
** Read the word at the given address and ROR it if the
** address isn't aligned.
*/
uint32_t
mem_read32_ror(
    struct gba *gba,
    uint32_t addr,
    enum access_type access_type
) {
    uint32_t rotate;
    uint32_t value;

    rotate = (addr % 4) << 3;
    value = mem_read32(gba, addr, access_type);
    return (ror32(value, rotate));
}

/*
** Write a byte at the given address.
*/
void
mem_write8(
    struct gba *gba,
    uint32_t addr,
    uint8_t val,
    enum access_type access_type
) {
    mem_access(gba, addr, sizeof(uint8_t), access_type);
    mem_write8_raw(gba, addr, val);
}

/*
** Write a byte at the given address, *without* updating the cycle counter.
*/
void
mem_write8_raw(
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
** write a half-word at the given address.
*/
void
mem_write16(
    struct gba *gba,
    uint32_t addr,
    uint16_t val,
    enum access_type access_type
) {
    addr &= ~(sizeof(uint16_t) - 1);

    mem_access(gba, addr, sizeof(uint16_t), access_type);
    mem_write8_raw(gba, addr + 0, (uint8_t)(val >> 0));
    mem_write8_raw(gba, addr + 1, (uint8_t)(val >> 8));
}

/*
** write a half-word at the given address without updating the cycle counter.
*/
void
mem_write16_raw(
    struct gba *gba,
    uint32_t addr,
    uint16_t val
) {
    addr &= ~(sizeof(uint16_t) - 1);

    mem_write8_raw(gba, addr + 0, (uint8_t)(val >> 0));
    mem_write8_raw(gba, addr + 1, (uint8_t)(val >> 8));
}

/*
** Write a word at the given address.
*/
void
mem_write32(
    struct gba *gba,
    uint32_t addr,
    uint32_t val,
    enum access_type access_type
) {
    addr &= ~(sizeof(uint32_t) - 1);

    mem_access(gba, addr, sizeof(uint32_t), access_type);
    mem_write8_raw(gba, addr + 0, (uint8_t)(val >>  0));
    mem_write8_raw(gba, addr + 1, (uint8_t)(val >>  8));
    mem_write8_raw(gba, addr + 2, (uint8_t)(val >> 16));
    mem_write8_raw(gba, addr + 3, (uint8_t)(val >> 24));
}

/*
** Write a double-word at the given address without updating the cycle counter.
*/
void
mem_write32_raw(
    struct gba *gba,
    uint32_t addr,
    uint32_t val
) {
    addr &= ~(sizeof(uint32_t) - 1);

    mem_write8_raw(gba, addr + 0, (uint8_t)(val >>  0));
    mem_write8_raw(gba, addr + 1, (uint8_t)(val >>  8));
    mem_write8_raw(gba, addr + 2, (uint8_t)(val >> 16));
    mem_write8_raw(gba, addr + 3, (uint8_t)(val >> 24));
}