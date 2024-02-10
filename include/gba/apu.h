/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include <pthread.h>

#define FIFO_CAPACITY                       32

// TODO: This should be dynamically set to a least 3x the value contained in `have.samples` (see `gui/sdl/audio.c`)
#define APU_RBUFFER_CAPACITY                (2048 * 3)

enum fifo_idx {
    FIFO_A = 0,
    FIFO_B = 1,
};

struct apu_fifo {
    int8_t data[FIFO_CAPACITY];
    size_t read_idx;
    size_t write_idx;
    size_t size;
};

struct apu_counter {
    bool enabled;

    uint32_t value;
};

struct apu_sweep {
    uint32_t shifts;
    bool direction;
    uint32_t time;

    uint32_t step;
    uint32_t frequency;
    uint32_t shadow_frequency;
};

struct apu_envelope {
    uint32_t step_time;
    bool direction;
    int32_t initial_volume;

    bool enabled;

    uint32_t step;
    int32_t volume;
};

struct apu_tone_and_sweep {
    bool enabled;

    struct apu_sweep sweep;
    struct apu_counter counter;
    struct apu_envelope envelope;

    uint32_t step;
    event_handler_t step_handler;
};

struct apu_tone {
    bool enabled;

    struct apu_counter counter;
    struct apu_envelope envelope;

    uint32_t step;
    event_handler_t step_handler;
};

struct apu_wave {
    bool enabled;

    uint32_t step;
    event_handler_t step_handler;
    struct apu_counter counter;
};

struct apu_noise {
    bool enabled;

    struct apu_counter counter;
    struct apu_envelope envelope;

    uint32_t lfsr;

    event_handler_t step_handler;
};

struct apu_rbuffer {
    uint32_t data[APU_RBUFFER_CAPACITY];
    size_t read_idx;
    size_t write_idx;
    size_t size;
};

struct apu {
    struct apu_fifo fifos[2];
    struct apu_tone_and_sweep tone_and_sweep;
    struct apu_tone tone;
    struct apu_wave wave;
    struct apu_noise noise;

    uint32_t modules_step;

    struct {
        int16_t fifo[2];
        int16_t channel_1;
        int16_t channel_2;
        int16_t channel_3;
        int16_t channel_4;
    } latch;
};

/* gba/apu/apu.c */
uint32_t apu_rbuffer_pop(struct apu_rbuffer *rbuffer);
void apu_resample(struct gba *gba, struct event_args args);

/* gba/apu/fifo.c */
void apu_reset_fifo(struct gba *gba, enum fifo_idx fifo_idx);
void apu_fifo_write8(struct gba *gba, enum fifo_idx fifo_idx, uint8_t val);
void apu_fifo_timer_overflow(struct gba *gba, uint32_t timer_id);

/* gba/apu/modules.c */
void apu_modules_step(struct gba *gba, struct event_args args);
void apu_modules_sweep_reset(struct apu_sweep *sweep, uint32_t frequency, uint32_t shifts, bool direction, uint32_t time);
void apu_modules_counter_reset(struct apu_counter *counter, bool enabled, uint32_t value);
void apu_modules_envelope_reset(struct apu_envelope *envelope, uint32_t step_time, bool direction, uint32_t initial_volume);

/* gba/apu/noise.c */
void apu_noise_reset(struct gba *gba);
void apu_noise_stop(struct gba *gba);
void apu_noise_step(struct gba *gba, struct event_args args);

/* gba/apu/tone.c */
void apu_tone_and_sweep_reset(struct gba *gba);
void apu_tone_and_sweep_stop(struct gba *gba);
void apu_tone_and_sweep_step(struct gba *gba, struct event_args args);
void apu_tone_reset(struct gba *gba);
void apu_tone_stop(struct gba *gba);
void apu_tone_step(struct gba *gba, struct event_args args);

/* gba/apu/wave.c */
void apu_wave_reset(struct gba *gba);
void apu_wave_stop(struct gba *gba);
void apu_wave_step(struct gba *gba, struct event_args args);
