/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/apu.h"
#include "gba/scheduler.h"

static int16_t volume_lut[4] = { 0, 4, 2, 1};

#define CHANNEL_FREQUENCY_AS_CYCLES(x)      ((GBA_CYCLES_PER_SECOND / 2097152) * (2048 - (x)))

void
apu_wave_reset(
    struct gba *gba
) {
    uint64_t period;

    gba->io.sound3cnt_x.reset = false;

    apu_wave_stop(gba);

    gba->apu.wave.enabled = true;
    gba->apu.wave.step = 0;

    apu_modules_counter_reset(
        &gba->apu.wave.counter,
        gba->io.sound3cnt_x.use_length,
        gba->io.sound3cnt_x.use_length ? 256 - gba->io.sound3cnt_h.length : 0
    );

    period = CHANNEL_FREQUENCY_AS_CYCLES(gba->io.sound3cnt_x.sample_rate);

    gba->apu.wave.step_handler = sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            SCHED_EVENT_APU_WAVE_STEP,
            gba->scheduler.cycles, // TODO: Is there a delay before the sound is started?
            period
        )
    );
}

void
apu_wave_stop(
    struct gba *gba
) {
    gba->io.soundcnt_x.sound_3_status = false;
    gba->apu.latch.channel_3 = 0;
    gba->apu.wave.step = 0;
    gba->apu.wave.enabled = false;

    if (gba->apu.wave.step_handler != INVALID_EVENT_HANDLE) {
        sched_cancel_event(gba, gba->apu.wave.step_handler);
        gba->apu.wave.step_handler = INVALID_EVENT_HANDLE;
    }
}

/*
** Shift the wave bank and store the 4 least significant bits
** into `gba->apu.latch.wave`.
*/
void
apu_wave_step(
    struct gba *gba,
    struct event_args args __unused
) {
    uint8_t byte;
    int16_t sample;

    if (!gba->io.sound3cnt_l.enable || !gba->apu.wave.enabled) {
        apu_wave_stop(gba);
        return;
    }

    gba->io.soundcnt_x.sound_3_status = true;

    byte = gba->io.waveram[gba->io.sound3cnt_l.bank_select][gba->apu.wave.step / 2];

    if (gba->apu.wave.step & 0b1) {
        byte &= 0xF;
    } else {
        byte >>= 4;
    }

    // Center the sample around 0.
    sample = byte - 8; // [-8; 7]

    // Apply counter
    sample *= gba->io.sound3cnt_x.use_length ? (gba->apu.wave.counter.value > 0) : 1; // [-8; 7]

    // Apply volume
    sample *= gba->io.sound3cnt_h.force_volume ? 3 : volume_lut[gba->io.sound3cnt_h.volume]; // [-32; 28], since volume is at most 4

    // Adjust the volume to match the other PSG channels
    sample *= 4; // [-128; 112]

    gba->apu.latch.channel_3 = sample;

    // Swap bank if we reached the end of this one and `bank_mode` is 1.
    ++gba->apu.wave.step;
    if (gba->apu.wave.step == 32) {
        gba->apu.wave.step = 0;

        if (gba->io.sound3cnt_l.bank_mode == 1) {
            gba->io.sound3cnt_l.bank_select ^= 1;
        }
    }
}
