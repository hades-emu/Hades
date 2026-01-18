/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <unistd.h>

#include "gba/gba.h"

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
** Set the waitstates for ROM/SRAM memory according to the content of REG_WAITCNT.
*/
void
mem_bus_update_waitstates(
    struct gba const *gba
) {
    struct io const *io;
    uint32_t x;

    io = &gba->io;

    // 16 bit, non seq
    access_time16[NON_SEQUENTIAL][CART_0_REGION_1] = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws0_nonseq];
    access_time16[NON_SEQUENTIAL][CART_0_REGION_2] = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws0_nonseq];
    access_time16[NON_SEQUENTIAL][CART_1_REGION_1] = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws1_nonseq];
    access_time16[NON_SEQUENTIAL][CART_1_REGION_2] = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws1_nonseq];
    access_time16[NON_SEQUENTIAL][CART_2_REGION_1] = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws2_nonseq];
    access_time16[NON_SEQUENTIAL][CART_2_REGION_2] = 1 + gamepak_nonseq_waitstates[io->waitcnt.ws2_nonseq];
    access_time16[NON_SEQUENTIAL][SRAM_REGION]     = 1 + gamepak_nonseq_waitstates[io->waitcnt.sram];

    // 16 bit, seq
    access_time16[SEQUENTIAL][CART_0_REGION_1] = 1 + (io->waitcnt.ws0_seq ? 1 : 2);
    access_time16[SEQUENTIAL][CART_0_REGION_2] = 1 + (io->waitcnt.ws0_seq ? 1 : 2);
    access_time16[SEQUENTIAL][CART_1_REGION_1] = 1 + (io->waitcnt.ws1_seq ? 1 : 4);
    access_time16[SEQUENTIAL][CART_1_REGION_2] = 1 + (io->waitcnt.ws1_seq ? 1 : 4);
    access_time16[SEQUENTIAL][CART_2_REGION_1] = 1 + (io->waitcnt.ws2_seq ? 1 : 8);
    access_time16[SEQUENTIAL][CART_2_REGION_2] = 1 + (io->waitcnt.ws2_seq ? 1 : 8);
    access_time16[SEQUENTIAL][SRAM_REGION]     = 1 + gamepak_nonseq_waitstates[io->waitcnt.sram];

    // Update for 32-bit too.
    for (x = CART_0_REGION_1; x <= SRAM_REGION; ++x) {
        access_time32[NON_SEQUENTIAL][x] = access_time16[NON_SEQUENTIAL][x] + access_time16[SEQUENTIAL][x];
        access_time32[SEQUENTIAL][x] = 2 * access_time16[SEQUENTIAL][x];
    }
}

void
mem_bus_wait_for(
    struct gba *gba,
    uint64_t cycles
) {
    gba->scheduler.cycles += cycles;

    // Process any pending scheduler event
    if (unlikely(gba->scheduler.cycles >= gba->scheduler.next_event)) {
        sched_process_events(gba);
    }

    // Step the prefetch buffer
    if (gba->memory.pbuffer.active) {
        mem_bus_pbuffer_step(gba, cycles);
    }
}

void
mem_bus_wait(
    struct gba *gba
) {
    mem_bus_wait_for(gba, 1);
}

/*
** Simulate what happens when the bus is accessing a memory location.
**
** This mostly calculate and add to the current cycle counter the amount of cycles needed for as many bus accesses
** are needed to transfer a data of the given size and access type.
*/
void
mem_bus_access(
    struct gba *gba,
    uint32_t addr,
    uint32_t size,  // In bytes
    enum access_flags flags
) {
    enum access_flags access_type;
    bool is_gamepak_access;
    uint32_t cycles;
    uint32_t page;

    addr = align_on(addr, size);
    page = (addr >> 24) & 0xF;
    access_type = flags & 0b1;

    is_gamepak_access = (page >= CART_REGION_START && page <= CART_REGION_END);

    // Start any pending DMA transfer
    if (gba->core.pending_dma && !gba->core.is_dma_running && !(flags & LOCK)) {
        mem_dma_do_all_pending_transfers(gba);
    }

    // Ensure memory access to page boundary are non-sequential
    if (unlikely(page >= CART_REGION_START && page <= CART_REGION_END && !(addr & 0x1FFFF))) {
        access_type = NON_SEQUENTIAL;
    }

    // Retrieve the amount of cycles needed for the bus to perform the memory access
    if (size <= sizeof(uint16_t)) {
        cycles = access_time16[access_type][page];
    } else {
        cycles = access_time32[access_type][page];
    }

    if (is_gamepak_access) {
        mem_bus_pbuffer_access(gba, addr, cycles, flags, size);
    } else {
        mem_bus_wait_for(gba, cycles);
    }
}

void
mem_bus_idle(
    struct gba *gba
) {
    // The CPU keeps running during a DMA until it tries to access the memory bus.
    // We simulate this by skipping any bus idle cycle when a DMA is about to run.
    if (gba->core.pending_dma && !gba->core.is_dma_running) {
        return;
    }

    mem_bus_wait_for(gba, 1);
}

void
mem_bus_pbuffer_access(
    struct gba *gba,
    uint32_t addr,
    uint32_t intended_cycles,
    enum access_flags flags,
    uint32_t size  // In bytes
) {
    struct prefetch_buffer *pbuffer;

    pbuffer = &gba->memory.pbuffer;

    // DMA and direct memory reads/writes do not benefit from the prefetch buffer.
    if (!(flags & PIPELINE)) {
        mem_bus_pbuffer_stop(gba);
        mem_bus_wait_for(gba, intended_cycles);
        return;
    }

    // When a memory read is done, first the prefetch unit checks if it is at the head of the buffer and "pops" it
    // Otherwise, if the prefetch unit is already prefetching the requested value, the CPU just stalls for the amount of
    // time it takes to let the prefetch unit complete that access.
    //
    // Source:
    //   - Fleroviux on the Emulator Development Discord
    //     https://discord.com/channels/465585922579103744/465586361731121162/882693177730007101

    if (pbuffer->active) {
        // Check if the requested value is at the top of the prefetch buffer
        if (pbuffer->head == addr && pbuffer->size > 0) {
            pbuffer->head += pbuffer->insn_len;
            --pbuffer->size;

            mem_bus_wait(gba);
            return;
        }

        // Check if the requested value is being prefetched right now
        if (pbuffer->tail == addr && pbuffer->remaining > 0) {
            mem_bus_wait_for(gba, pbuffer->remaining);

            pbuffer->size = 0;
            pbuffer->head = pbuffer->tail;

            // Some wizardry to correctly handle the case where the prefetch unit is disabled.
            // We want to make sure the prefetch unit will consume what's in the buffer and can finish the current transfer
            // without transferring new values after that.
            // Setting `pbuffer->remaining` to zero prevents us from re-entering this condition on the next memory access.
            if (pbuffer->disabling_now) {
                pbuffer->remaining = 0;
            }

            return;
        }
    }

    // When the prefetch unit is disabled and once its buffer is empty, the next access the CPU makes is a nonsequential one.
    // Source: https://github.com/zaydlang/AGBEEG-Aging-Cartridge/blob/master/documentation/cartridge/toggle_prefetcher.md
    if (pbuffer->disabling_now) {
        uint32_t page;

        page = (addr >> 24) & 0xF;
        if (size <= sizeof(uint16_t)) {
            intended_cycles = access_time16[NON_SEQUENTIAL][page];
        } else {
            intended_cycles = access_time32[NON_SEQUENTIAL][page];
        }
    }

    // The address couldn't be prefetched: stop the prefetch buffer
    mem_bus_pbuffer_stop(gba);

    // And wait the intended amount of cycles
    mem_bus_wait_for(gba, intended_cycles);

    // Start a new burst transfer
    if (pbuffer->enabled) {
        pbuffer->thumb = gba->core.cpsr.thumb;

        if (pbuffer->thumb) {
            pbuffer->insn_len = sizeof(uint16_t);
            pbuffer->capacity = 8;
            pbuffer->reload = access_time16[SEQUENTIAL][(addr >> 24) & 0xF];
        } else {
            pbuffer->insn_len = sizeof(uint32_t);
            pbuffer->capacity = 4;
            pbuffer->reload = access_time32[SEQUENTIAL][(addr >> 24) & 0xF];
        }

        pbuffer->remaining = pbuffer->reload;
        pbuffer->tail = addr + pbuffer->insn_len;
        pbuffer->head = pbuffer->tail;
        pbuffer->size = 0;
        pbuffer->active = true;
    }
}

void
mem_bus_pbuffer_step(
    struct gba *gba,
    uint32_t cycles
) {
    struct prefetch_buffer *pbuffer;

    pbuffer = &gba->memory.pbuffer;

    while (pbuffer->remaining <= cycles && pbuffer->size < pbuffer->capacity) {
        cycles -= pbuffer->remaining;
        pbuffer->tail += pbuffer->insn_len;
        pbuffer->remaining = pbuffer->reload;
        ++pbuffer->size;
    }

    if (pbuffer->size < pbuffer->capacity) {
        pbuffer->remaining -= cycles;
    }
}

void
mem_bus_pbuffer_stop(
    struct gba *gba
) {
    struct prefetch_buffer *pbuffer;
    bool penalty;

    pbuffer = &gba->memory.pbuffer;

    // When the prefetcher is currently in the middle of prefetching an opcode and a ROM data access is made
    // (either reads or writes, doesn't matter), the access will idle an extra cycle than it normally does if either:
    //   - The prefetcher is in THUMB mode and is 1 cycle away from finishing it's current fetch.
    //   - The prefetcher is in ARM mode and is 1 cycle away from finishing fetching either halfword that makes up the full word.
    //
    // Source:
    //   - https://github.com/zaydlang/AGBEEG-Aging-Cartridge/blob/master/documentation/cartridge/rom_access_during_prefetch.md

    if (pbuffer->active) {
        pbuffer->active = false;
        pbuffer->disabling_now = false;

        penalty = false;
        penalty |= pbuffer->thumb && pbuffer->remaining == 1;
        penalty |= !pbuffer->thumb && (pbuffer->remaining == 1 || pbuffer->remaining == pbuffer->reload / 2 + 1);

        if (penalty) {
            mem_bus_wait(gba);
        }
    }
}
