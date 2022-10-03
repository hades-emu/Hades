/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/apu.h"
#include "gba/scheduler.h"

static void apu_wave_step(struct gba *, struct event_args args);

static int16_t volume_lut[4] = { 0, 4, 2, 1};

void
apu_wave_init(
    struct gba *gba
) {
    gba->apu.wave.step_handler = INVALID_EVENT_HANDLE;
    gba->apu.wave.counter_handler = INVALID_EVENT_HANDLE;
}

void
apu_wave_reset(
    struct gba *gba
) {
    size_t period;

    gba->io.sound3cnt_x.reset = false;
    apu_wave_stop(gba);

    if (gba->io.sound3cnt_x.use_length) {
        gba->apu.wave.length = 256 - gba->io.sound3cnt_h.length;
    } else {
        gba->apu.wave.length = 0;
    }

    period = CYCLES_PER_SECOND / (2097152 / (2048 - gba->io.sound3cnt_x.sample_rate));

    gba->apu.wave.step_handler = sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            gba->core.cycles, // TODO: Is there a delay before the sound is started?
            period,
            apu_wave_step
        )
    );
}

void
apu_wave_stop(
    struct gba *gba
) {
    gba->apu.latch.wave = 0;
    gba->apu.wave.step = 0;
    gba->apu.wave.length = 0;
    gba->io.soundcnt_x.sound_1_status = false;

    if (gba->apu.wave.step_handler != INVALID_EVENT_HANDLE) {
        sched_cancel_event(gba, gba->apu.wave.step_handler);
    }
    gba->apu.wave.step_handler = INVALID_EVENT_HANDLE;

    if (gba->apu.wave.counter_handler != INVALID_EVENT_HANDLE) {
        sched_cancel_event(gba, gba->apu.wave.counter_handler);
    }
    gba->apu.wave.counter_handler = INVALID_EVENT_HANDLE;
}

/*
** Shift the wave bank and store the 4 least significant bits
** into `gba->apu.latch.wave`.
*/
static
void
apu_wave_step(
    struct gba *gba,
    struct event_args args __unused
) {
    uint8_t byte;
    int16_t sample;

    if (!gba->io.sound3cnt_l.enable) {
        apu_wave_stop(gba);
        return ;
    }

    gba->io.soundcnt_x.sound_1_status = true;

    byte = gba->io.waveram[gba->io.sound3cnt_l.bank_select][gba->apu.wave.step / 2];

    if (gba->apu.wave.step & 0b1) {
        byte &= 0xF;
    } else {
        byte >>= 4;
    }

    // Recenter the sample around 0.
    sample = byte - 8;

    // Apply volume
    sample *= gba->io.sound3cnt_h.force_volume ? 3 : volume_lut[gba->io.sound3cnt_h.volume];

    gba->apu.latch.wave = sample;

    // Swap bank if we reached the end of this one and `bank_mode` is 1.
    ++gba->apu.wave.step;
    if (gba->apu.wave.step == 32) {
        gba->apu.wave.step = 0;

        if (gba->io.sound3cnt_l.bank_mode == 1) {
            gba->io.sound3cnt_l.bank_select ^= 1;
        }
    }
}