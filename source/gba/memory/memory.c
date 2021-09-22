/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "gba/gba.h"
#include "gba/core.h"
#include "gba/memory.h"

/*
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
mem_reset(
    struct memory *memory
) {
    memset(memory->ewram, 0, sizeof(memory->ewram));
    memset(memory->iwram, 0, sizeof(memory->iwram));
    memset(memory->palram, 0, sizeof(memory->palram));
    memset(memory->vram, 0, sizeof(memory->vram));
    memset(memory->oam, 0, sizeof(memory->oam));
    memset(&memory->pbuffer, 0, sizeof(memory->pbuffer));
    memset(&memory->flash, 0, sizeof(memory->flash));
    memory->gamepak_bus_in_use = false;
}

/*
** Set the waitstates for ROM/SRAM memory according to the content of REG_WAITCNT.
*/
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
    access_time16[NON_SEQUENTIAL][SRAM_REGION]      = 1 + gamepak_nonseq_waitstates[io->waitcnt.sram];

    // 16 bit, seq
    access_time16[SEQUENTIAL][CART_0_REGION_1]  = 1 + (io->waitcnt.ws0_seq ? 1 : 2);
    access_time16[SEQUENTIAL][CART_0_REGION_2]  = 1 + (io->waitcnt.ws0_seq ? 1 : 2);
    access_time16[SEQUENTIAL][CART_1_REGION_1]  = 1 + (io->waitcnt.ws1_seq ? 1 : 4);
    access_time16[SEQUENTIAL][CART_1_REGION_2]  = 1 + (io->waitcnt.ws1_seq ? 1 : 4);
    access_time16[SEQUENTIAL][CART_2_REGION_1]  = 1 + (io->waitcnt.ws2_seq ? 1 : 8);
    access_time16[SEQUENTIAL][CART_2_REGION_2]  = 1 + (io->waitcnt.ws2_seq ? 1 : 8);
    access_time16[SEQUENTIAL][SRAM_REGION]      = 1 + gamepak_nonseq_waitstates[io->waitcnt.sram];

    // Update for 32-bit too.
    for (x = CART_0_REGION_1; x <= SRAM_REGION; ++x) {
        access_time32[NON_SEQUENTIAL][x] = access_time16[NON_SEQUENTIAL][x] + access_time16[SEQUENTIAL][x];
        access_time32[SEQUENTIAL][x] = 2 * access_time16[SEQUENTIAL][x];
    }
}

/*
** Calculate and add to the current cycle counter the amount of cycles needed for as many bus accesses
** are needed to transfer a data of the given size and access type.
*/
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

    if (page >= CART_REGION_START && page <= CART_REGION_END && !(addr & 0x1FFFF)) {
        access_type = NON_SEQUENTIAL;
    }

    if (size <= sizeof(uint16_t)) {
        cycles = access_time16[access_type][page];
    } else {
        cycles = access_time32[access_type][page];
    }

    gba->memory.gamepak_bus_in_use = (page >= CART_REGION_START && page <= CART_REGION_END);
    if (gba->memory.gamepak_bus_in_use && gba->memory.pbuffer.enabled) {
        mem_prefetch_buffer_access(gba, addr, cycles);
    } else {
        core_idle_for(gba, cycles);
    }
}

void
mem_prefetch_buffer_access(
    struct gba *gba,
    uint32_t addr,
    uint32_t intended_cycles
) {
    struct prefetch_buffer *pbuffer;

    pbuffer = &gba->memory.pbuffer;

    if (pbuffer->tail == addr) {
        if (pbuffer->size == 0) { // Finish to fetch if it isnt' done yet
            gba->memory.gamepak_bus_in_use = false;
            core_idle_for(gba, pbuffer->countdown);

            pbuffer->tail += pbuffer->insn_len;
            --pbuffer->size;
        } else {
            pbuffer->tail += pbuffer->insn_len;
            --pbuffer->size;

            gba->memory.gamepak_bus_in_use = false;
            core_idle(gba);
        }
    } else {
        // Do it first or it'll screw our pbuffer settings
        core_idle_for(gba, intended_cycles);

        if (gba->core.cpsr.thumb) {
            pbuffer->insn_len = sizeof(uint16_t);
            pbuffer->capacity = 8;
            pbuffer->reload = access_time16[SEQUENTIAL][(addr >> 24) & 0xF];
        } else {
            pbuffer->insn_len = sizeof(uint32_t);
            pbuffer->capacity = 4;
            pbuffer->reload = access_time32[SEQUENTIAL][(addr >> 24) & 0xF];
        }

        pbuffer->countdown = pbuffer->reload;
        pbuffer->tail = addr + pbuffer->insn_len;
        pbuffer->head = pbuffer->tail;
        pbuffer->size = 0;
    }

}

void
mem_prefetch_buffer_step(
    struct gba *gba,
    uint32_t cycles
) {
    struct prefetch_buffer *pbuffer;

    pbuffer = &gba->memory.pbuffer;

    while (cycles >= pbuffer->countdown && pbuffer->size < pbuffer->capacity) {
        cycles -= pbuffer->countdown;
        pbuffer->head += pbuffer->insn_len;
        pbuffer->countdown = pbuffer->reload;
        ++pbuffer->size;
    }

    if (pbuffer->size < pbuffer->capacity) {
        pbuffer->countdown -= cycles;
    }
}

/*
** Read the data of type T located in memory at the given address.
**
** T must be either uint32_t, uint16_t or uint8_t.
*/
#define template_read(T, gba, addr)                                                         \
    ({                                                                                      \
        T _ret = 0;                                                                         \
        switch ((addr) >> 24) {                                                             \
            case BIOS_REGION:                                                               \
                _ret = *(T *)((uint8_t *)((gba)->memory.bios) + ((addr) & BIOS_MASK));      \
                break;                                                                      \
            case EWRAM_REGION:                                                              \
                _ret = *(T *)((uint8_t *)((gba)->memory.ewram) + ((addr) & EWRAM_MASK));    \
                break;                                                                      \
            case IWRAM_REGION:                                                              \
                _ret = *(T *)((uint8_t *)((gba)->memory.iwram) + ((addr) & IWRAM_MASK));    \
                break;                                                                      \
            case IO_REGION:                                                                 \
                _ret = _Generic(_ret,                                                       \
                    uint32_t: (                                                             \
                        (mem_io_read8((gba), (addr) + 0) <<  0) |                           \
                        (mem_io_read8((gba), (addr) + 1) <<  8) |                           \
                        (mem_io_read8((gba), (addr) + 2) << 16) |                           \
                        (mem_io_read8((gba), (addr) + 3) << 24)                             \
                    ),                                                                      \
                    uint16_t: (                                                             \
                        (mem_io_read8((gba), (addr) + 0) <<  0) |                           \
                        (mem_io_read8((gba), (addr) + 1) <<  8)                             \
                    ),                                                                      \
                    default: mem_io_read8((gba), (addr))                                    \
                );                                                                          \
                break;                                                                      \
            case PALRAM_REGION:                                                             \
                _ret = *(T *)((uint8_t *)((gba)->memory.palram) + ((addr) & PALRAM_MASK));  \
                break;                                                                      \
            case VRAM_REGION:                                                               \
                _ret = *(T *)((uint8_t *)((gba)->memory.vram) + ((addr) & (((addr) & 0x10000) ? VRAM_MASK_1 : VRAM_MASK_2))); \
                break;                                                                      \
            case OAM_REGION:                                                                \
                _ret = *(T *)((uint8_t *)((gba)->memory.oam) + ((addr) & OAM_MASK));        \
                break;                                                                      \
            case CART_REGION_START ... CART_REGION_END:                                     \
                _ret = *(T *)((uint8_t *)((gba)->memory.rom) + ((addr) & CART_MASK));       \
                break;                                                                      \
            case SRAM_REGION:                                                               \
                _ret = _Generic(_ret,                                                       \
                    uint32_t: (                                                             \
                        (mem_backup_storage_read8((gba), (addr) + 0) <<  0) |               \
                        (mem_backup_storage_read8((gba), (addr) + 1) <<  8) |               \
                        (mem_backup_storage_read8((gba), (addr) + 2) << 16) |               \
                        (mem_backup_storage_read8((gba), (addr) + 3) << 24)                 \
                    ),                                                                      \
                    uint16_t: (                                                             \
                        (mem_backup_storage_read8((gba), (addr) + 0) <<  0) |               \
                        (mem_backup_storage_read8((gba), (addr) + 1) <<  8)                 \
                    ),                                                                      \
                    default: mem_backup_storage_read8((gba), (addr))                        \
                );                                                                          \
                break;                                                                      \
            default:                                                                        \
                logln(HS_MEMORY, "Invalid read at address 0x%08x", addr);                   \
                _ret = 0;                                                                   \
                break;                                                                      \
        };                                                                                  \
        _ret;                                                                               \
    })

/*
** Wriote a data of type T to memory at the given address.
**
** T must be either uint32_t, uint16_t or uint8_t.
*/
#define template_write(T, gba, addr, val)                                                       \
    ({                                                                                          \
        switch ((addr) >> 24) {                                                                 \
            case BIOS_REGION:                                                                   \
                /* Ignore writes attempts to the bios memory. */                                \
                break;                                                                          \
            case EWRAM_REGION:                                                                  \
                *(T *)((uint8_t *)((gba)->memory.ewram) + ((addr) & EWRAM_MASK)) = (T)(val);    \
                break;                                                                          \
            case IWRAM_REGION:                                                                  \
                *(T *)((uint8_t *)((gba)->memory.iwram) + ((addr) & IWRAM_MASK)) = (T)(val);    \
                break;                                                                          \
            case IO_REGION:                                                                     \
                _Generic(val,                                                                   \
                    uint32_t: ({                                                                \
                        mem_io_write8((gba), (addr) + 0, (uint8_t)((val) >>  0));               \
                        mem_io_write8((gba), (addr) + 1, (uint8_t)((val) >>  8));               \
                        mem_io_write8((gba), (addr) + 2, (uint8_t)((val) >> 16));               \
                        mem_io_write8((gba), (addr) + 3, (uint8_t)((val) >> 24));               \
                    }),                                                                         \
                    uint16_t: ({                                                                \
                        mem_io_write8((gba), (addr) + 0, (uint8_t)((val) >>  0));               \
                        mem_io_write8((gba), (addr) + 1, (uint8_t)((val) >>  8));               \
                    }),                                                                         \
                    default: ({                                                                 \
                        mem_io_write8((gba), (addr), (val));                                    \
                    })                                                                          \
                );                                                                              \
                break;                                                                          \
            case PALRAM_REGION:                                                                 \
                *(T *)((uint8_t *)((gba)->memory.palram) + ((addr) & PALRAM_MASK)) = (T)(val);  \
                break;                                                                          \
            case VRAM_REGION:                                                                   \
                *(T *)((uint8_t *)((gba)->memory.vram) + ((addr) & (((addr) & 0x10000) ? VRAM_MASK_1 : VRAM_MASK_2))) = (T)(val); \
                break;                                                                          \
            case OAM_REGION:                                                                    \
                *(T *)((uint8_t *)((gba)->memory.oam) + ((addr) & OAM_MASK)) = (T)(val);        \
                break;                                                                          \
            case CART_REGION_START ... CART_REGION_END:                                         \
                /* Ignore writes attempts to the cartridge memory. */                           \
                break;                                                                          \
            case SRAM_REGION:                                                                   \
                _Generic(val,                                                                   \
                    uint32_t: ({                                                                \
                        mem_backup_storage_write8((gba), (addr) + 0, (uint8_t)((val) >>  0));   \
                        mem_backup_storage_write8((gba), (addr) + 1, (uint8_t)((val) >>  8));   \
                        mem_backup_storage_write8((gba), (addr) + 2, (uint8_t)((val) >> 16));   \
                        mem_backup_storage_write8((gba), (addr) + 3, (uint8_t)((val) >> 24));   \
                    }),                                                                         \
                    uint16_t: ({                                                                \
                        mem_backup_storage_write8((gba), (addr) + 0, (uint8_t)((val) >>  0));   \
                        mem_backup_storage_write8((gba), (addr) + 1, (uint8_t)((val) >>  8));   \
                    }),                                                                         \
                    default: ({                                                                 \
                        mem_backup_storage_write8((gba), (addr), (val));                        \
                    })                                                                          \
                );                                                                              \
                break;                                                                          \
            default:                                                                            \
                logln(HS_MEMORY, "Invalid write at address 0x%08x", addr);                      \
        };                                                                                      \
    })


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
    return (template_read(uint8_t, gba, addr));
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
    return (template_read(uint16_t, gba, addr));
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
    return (template_read(uint32_t, gba, addr));
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
    template_write(uint8_t, gba, addr, val);
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
    template_write(uint16_t, gba, addr, val);
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
    template_write(uint32_t, gba, addr, val);
}