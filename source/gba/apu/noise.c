/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba/gba.h"

void
apu_noise_reset(
    struct gba *gba
) {
    uint64_t period;

    gba->io.sound4cnt_h.reset = false;

    apu_noise_stop(gba);

    // Enveloppe set to decrease mode with a volume of 0 mutes the channel
    if (!gba->io.sound4cnt_l.envelope_direction && !gba->io.sound4cnt_l.envelope_initial_volume) {
        return;
    }

    gba->apu.noise.enabled = true;
    gba->apu.noise.lfsr = gba->io.sound4cnt_h.width ? 0x40 : 0x4000;

    apu_modules_envelope_reset(
        &gba->apu.noise.envelope,
        gba->io.sound4cnt_l.envelope_step_time,
        gba->io.sound4cnt_l.envelope_direction,
        gba->io.sound4cnt_l.envelope_initial_volume
    );

    apu_modules_counter_reset(
        &gba->apu.noise.counter,
        gba->io.sound4cnt_h.use_length,
        gba->io.sound4cnt_h.use_length ? 64 - gba->io.sound4cnt_l.length : 0
    );

    period = 524288;
    if (gba->io.sound4cnt_h.frequency_ratio == 0) {
        period *= 2;
    } else {
        period /= gba->io.sound4cnt_h.frequency_ratio;
    }
    period /= 1 << (gba->io.sound4cnt_h.frequency_shift + 1);
    period = GBA_CYCLES_PER_SECOND / period;

    gba->apu.noise.step_handler = sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            SCHED_EVENT_APU_NOISE_STEP,
            gba->scheduler.cycles, // TODO: Is there a delay before the sound is started?
            period
        )
    );
}

void
apu_noise_stop(
    struct gba *gba
) {
    gba->io.soundcnt_x.sound_4_status = false;
    gba->apu.latch.channel_4 = 0;
    gba->apu.noise.lfsr = 0;
    gba->apu.noise.enabled = false;

    if (gba->apu.noise.step_handler != INVALID_EVENT_HANDLE) {
        sched_cancel_event(gba, gba->apu.noise.step_handler);
        gba->apu.noise.step_handler = INVALID_EVENT_HANDLE;
    }
}

void
apu_noise_step(
    struct gba *gba,
    struct event_args args __unused
) {
    bool carry;
    int16_t sample;

    if (!gba->apu.noise.enabled) {
        apu_noise_stop(gba);
        return;
    }

    gba->io.soundcnt_x.sound_4_status = true;

    carry = gba->apu.noise.lfsr & 0b1;

    gba->apu.noise.lfsr >>= 1;

    if (carry) {
        gba->apu.noise.lfsr ^= gba->io.sound4cnt_h.width ? 0x60 : 0x6000;
    }

    // Center the sample around 0.
    sample = 2 * carry - 1; // [-1; 1]

    // Apply counter
    sample *= gba->io.sound4cnt_h.use_length ? (gba->apu.noise.counter.value > 0) : 1; // [-1; +1]

    // Apply envelope
    sample *= gba->apu.noise.envelope.volume; // [-15; 15], since `volume` is `[0; 0xF]`

    // Adjust the volume to match the other PSG channels
    sample *= 8; // [-120; 120]

    gba->apu.latch.channel_4 = sample;
}
