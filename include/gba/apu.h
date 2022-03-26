/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef GBA_APU_H
# define GBA_APU_H

# include <pthread.h>

# define FIFO_CAPACITY      32

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

# define APU_RBUFFER_CAPACITY (4096)

struct apu_rbuffer {
    int16_t data[APU_RBUFFER_CAPACITY];
    size_t read_idx;
    size_t write_idx;
    size_t size;
};

struct apu {
    struct fifo fifos[2];

    struct apu_rbuffer channel_left;
    struct apu_rbuffer channel_right;
    pthread_mutex_t frontend_channels_mutex;

    uint64_t resample_frequency; // In cycles
    int16_t latch[2];
};

/* gba/apu/apu.c */
void apu_init(struct gba *gba);
void apu_reset_fifo(struct gba *gba, enum fifo_idx fifo_idx);
void apu_fifo_write8(struct gba *gba, enum fifo_idx fifo_idx, uint8_t val);
int16_t apu_rbuffer_pop(struct apu_rbuffer *rbuffer);
void apu_on_timer_overflow(struct gba *gba, uint32_t timer_id);

#endif /* !GBA_APU_H */