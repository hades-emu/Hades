/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "gba/gba.h"

void
apu_reset_fifo(
    struct gba *gba,
    enum fifo_idx fifo_idx
) {
    memset(&gba->apu.fifos[fifo_idx], 0, sizeof(gba->apu.fifos[0]));
}

void
apu_fifo_write8(
    struct gba *gba,
    enum fifo_idx fifo_idx,
    uint8_t val
) {
    struct apu_fifo *fifo;

    fifo = &gba->apu.fifos[fifo_idx];

    if (fifo->size < FIFO_CAPACITY) {
        fifo->data[fifo->write_idx] = (int8_t)val;
        fifo->write_idx = (fifo->write_idx + 1) % FIFO_CAPACITY;
        ++fifo->size;
    }
}

static
int8_t
apu_fifo_read8(
    struct gba *gba,
    uint32_t fifo_idx
) {
    struct apu_fifo *fifo;
    int8_t val;

    fifo = &gba->apu.fifos[fifo_idx];
    val = fifo->data[fifo->read_idx];

    if (fifo->size > 0) {
        fifo->read_idx = (fifo->read_idx + 1) % FIFO_CAPACITY;
        --fifo->size;
    }

    return (val);
}

void
apu_fifo_timer_overflow(
    struct gba *gba,
    uint32_t timer_id
) {
    struct io *io;
    size_t fifo_idx;

    io = &gba->io;

    if (!io->soundcnt_x.master_enable) {
        return;
    }

    for (fifo_idx = 0; fifo_idx < 2; ++fifo_idx) {

        // We are interested only in the FIFO synchronised with our timer
        if (bitfield_get(io->soundcnt_h.raw, 10 + fifo_idx * 4) != timer_id) {
            continue;
        }

        gba->apu.latch.fifo[fifo_idx] = apu_fifo_read8(gba, fifo_idx);

        if (gba->apu.fifos[fifo_idx].size <= 16) {
            size_t dma_idx;

            for (dma_idx = 1; dma_idx <= 2; ++dma_idx) {
                if (mem_dma_is_fifo(gba, dma_idx, fifo_idx)) {
                    mem_schedule_dma_transfers_for(gba, dma_idx, DMA_TIMING_SPECIAL); // Fifo DMA
                }
            }
        }
    }
}
