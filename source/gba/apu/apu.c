/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/apu.h"
#include "gba/scheduler.h"

static void apu_resample(struct gba *gba, union event_data data);

void
apu_init(
    struct gba *gba
) {
    memset(gba->apu.fifos, 0, sizeof(gba->apu.fifos));
    memset(&gba->apu.channel_left, 0, sizeof(gba->apu.channel_left));
    memset(&gba->apu.channel_right, 0, sizeof(gba->apu.channel_right));
    pthread_mutex_init(&gba->apu.frontend_channels_mutex, NULL);

    sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            0,
            gba->apu.resample_frequency,
            apu_resample
        )
    );
}

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
    struct fifo *fifo;

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
    struct fifo *fifo;
    int8_t val;

    fifo = &gba->apu.fifos[fifo_idx];
    val = fifo->data[fifo->read_idx];

    if (fifo->size > 0) {
        fifo->read_idx = (fifo->read_idx + 1) % FIFO_CAPACITY;
        --fifo->size;
    }

    return (val);
}

static
void
apu_rbuffer_push(
    struct apu_rbuffer *rbuffer,
    int16_t val
) {
    if (rbuffer->size < APU_RBUFFER_CAPACITY) {
        rbuffer->data[rbuffer->write_idx] = val;
        rbuffer->write_idx = (rbuffer->write_idx + 1) % APU_RBUFFER_CAPACITY;
        ++rbuffer->size;
    }
}

int16_t
apu_rbuffer_pop(
    struct apu_rbuffer *rbuffer
) {
    int16_t val;

    val = rbuffer->data[rbuffer->read_idx];
    if (rbuffer->size > 0) {
        rbuffer->read_idx = (rbuffer->read_idx + 1) % APU_RBUFFER_CAPACITY;
        --rbuffer->size;
    }

    return (val);
}

void
apu_on_timer_overflow(
    struct gba *gba,
    uint32_t timer_id
) {
    struct io *io;
    size_t fifo_idx;

    io = &gba->io;

    if (!io->soundcnt_x.master_fifo_enable) {
        return;
    }

    for (fifo_idx = 0; fifo_idx < 2; ++fifo_idx) {

        // We are interested only in the FIFO synchronised with our timer
        if (bitfield_get(io->soundcnt_h.raw, 10 + fifo_idx * 4) != timer_id) {
            continue;
        }

        gba->apu.latch[fifo_idx] = apu_fifo_read8(gba, fifo_idx);

        if (gba->apu.fifos[fifo_idx].size <= 16) {
            size_t dma_idx;

            for (dma_idx = 1; dma_idx <= 2; ++dma_idx) {
                if (mem_dma_is_fifo(gba, dma_idx, fifo_idx)) {
                    mem_schedule_dma_fifo(gba, dma_idx);
                }
            }
        }
    }
}

static
void
apu_resample(
    struct gba *gba,
    union event_data data
) {
    static float fifo_volume[2] = {0.5f, 1.f};
    int16_t sample_l;
    int16_t sample_r;

    sample_l = 0;
    sample_r = 0;

    sample_l += gba->apu.latch[FIFO_A] * (bool)gba->io.soundcnt_h.enable_fifo_a_left * fifo_volume[gba->io.soundcnt_h.volume_fifo_a];
    sample_r += gba->apu.latch[FIFO_A] * (bool)gba->io.soundcnt_h.enable_fifo_a_right * fifo_volume[gba->io.soundcnt_h.volume_fifo_a];

    sample_l += gba->apu.latch[FIFO_B] * (bool)gba->io.soundcnt_h.enable_fifo_b_left * fifo_volume[gba->io.soundcnt_h.volume_fifo_b];
    sample_r += gba->apu.latch[FIFO_B] * (bool)gba->io.soundcnt_h.enable_fifo_b_right * fifo_volume[gba->io.soundcnt_h.volume_fifo_b];

    if (sample_l < -0x200) {
        sample_l = -0x200;
    } else if (sample_l > 0x200) {
        sample_l = 0x200;
    }

    if (sample_r < -0x200) {
        sample_r = -0x200;
    } else if (sample_r > 0x200) {
        sample_r = 0x200;
    }

    pthread_mutex_lock(&gba->apu.frontend_channels_mutex);
    apu_rbuffer_push(&gba->apu.channel_left, (int16_t)((uint16_t)sample_l << 6));
    apu_rbuffer_push(&gba->apu.channel_right, (int16_t)((uint16_t)sample_r << 6));
    pthread_mutex_unlock(&gba->apu.frontend_channels_mutex);
}