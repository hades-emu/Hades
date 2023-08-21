/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include <pthread.h>

#define FIFO_CAPACITY       32

// TODO: This should be dynamically set to a least 3x the value contained in `have.samples` (see `gui/sdl/audio.c`)
#define APU_RBUFFER_CAPACITY (2048 * 3)

enum fifo_idx {
    FIFO_A = 0,
    FIFO_B = 1,
};

struct fifo {
    int8_t data[FIFO_CAPACITY];
    size_t read_idx;
    size_t write_idx;
    size_t size;
};

struct wave {
    uint32_t step;
    uint32_t length;
    event_handler_t step_handler;
    event_handler_t counter_handler;
};

struct apu_rbuffer {
    uint32_t data[APU_RBUFFER_CAPACITY];
    size_t read_idx;
    size_t write_idx;
    size_t size;
};

struct apu {
    uint64_t resample_frequency; // In cycles

    struct fifo fifos[2];
    struct wave wave;

    struct {
        int16_t fifo[2];
        int16_t wave;
    } latch;

    pthread_mutex_t frontend_channels_mutex;
    struct apu_rbuffer frontend_channels;
};

/* gba/apu/apu.c */
void apu_init(struct gba *gba);
void apu_reset_fifo(struct gba *gba, enum fifo_idx fifo_idx);
void apu_fifo_write8(struct gba *gba, enum fifo_idx fifo_idx, uint8_t val);
uint32_t apu_rbuffer_pop(struct apu_rbuffer *rbuffer);
void apu_on_timer_overflow(struct gba *gba, uint32_t timer_id);

/* gba/apu/wave.c */
void apu_wave_init(struct gba *);
void apu_wave_reset(struct gba *gba);
void apu_wave_stop(struct gba *gba);
