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
apu_modules_counter_reset(
    struct apu_counter *counter,
    bool enabled,
    uint32_t value
) {
    counter->enabled = enabled;
    counter->value = value;
}

static inline
bool
apu_modules_counter_step(
    struct apu_counter *counter
) {
    if (counter->enabled) {
        counter->value -= (counter->value > 0);
        return (counter->value > 0);
    }
    return (true);
}

void
apu_modules_sweep_reset(
    struct apu_sweep *sweep,
    uint32_t frequency,
    uint32_t shifts,
    bool direction,
    uint32_t time
) {
    sweep->shifts = shifts;
    sweep->direction = direction;
    sweep->time = time;

    sweep->frequency = frequency;
    sweep->shadow_frequency = frequency;

    sweep->step = sweep->time;
}

static inline
bool
apu_modules_sweep_step(
    struct apu_sweep *sweep
) {
    if (sweep->time) {
        --sweep->step;

        if (!sweep->step) {
            uint32_t new_frequency;

            if (sweep->direction) {
                new_frequency = sweep->shadow_frequency - (sweep->shadow_frequency >> sweep->shifts);
            } else {
                new_frequency = sweep->shadow_frequency + (sweep->shadow_frequency >> sweep->shifts);
            }

            /* Overflow check */
            if (new_frequency >= 2048) {
                return (false);
            }

            if (sweep->shifts > 0) {
                sweep->frequency = new_frequency;
                sweep->shadow_frequency = new_frequency;
            }

            sweep->step = sweep->time;
        }
    }

    return (true);
}

void
apu_modules_envelope_reset(
    struct apu_envelope *envelope,
    uint32_t step_time,
    bool direction,
    uint32_t initial_volume
) {
    envelope->step_time = step_time;
    envelope->direction = direction;
    envelope->initial_volume = initial_volume;

    envelope->step = step_time;
    envelope->volume = initial_volume;
}

static inline
void
apu_modules_envelope_step(
    struct apu_envelope *envelope
) {
    if (envelope->step_time) {
        --envelope->step;

        if (!envelope->step) {
            envelope->step = envelope->step_time;

            envelope->volume += 2 * envelope->direction - 1; // Increment or decrement the volume based on the direction
            envelope->volume = max(min(envelope->volume, 0xF), 0); // Clamp the volume to [0; 0xF]
        }
    }
}

/*
** Called at a rate of 512Hz to update all the submodules that a PSG channel can rely on.
*/
void
apu_modules_step(
    struct gba *gba,
    struct event_args args __unused
) {
    // Tick the length counter modules at a rate of 256Hz
    if ((gba->apu.modules_step % 2) == 0) {
        gba->apu.tone_and_sweep.enabled &= apu_modules_counter_step(&gba->apu.tone_and_sweep.counter);
        gba->apu.tone.enabled &= apu_modules_counter_step(&gba->apu.tone.counter);
        gba->apu.wave.enabled &= apu_modules_counter_step(&gba->apu.wave.counter);
        gba->apu.noise.enabled &= apu_modules_counter_step(&gba->apu.noise.counter);
    }

    // Tick the sweep module at a rate of 128Hz
    if (gba->apu.modules_step == 2 || gba->apu.modules_step == 6) {
        gba->apu.tone_and_sweep.enabled &= apu_modules_sweep_step(&gba->apu.tone_and_sweep.sweep);
    }

    // Tick the envelope modules at a rate of 64Hz
    if (gba->apu.modules_step == 7) {
        apu_modules_envelope_step(&gba->apu.tone_and_sweep.envelope);
        apu_modules_envelope_step(&gba->apu.tone.envelope);
        apu_modules_envelope_step(&gba->apu.noise.envelope);
    }

    ++gba->apu.modules_step;
    gba->apu.modules_step %= 8;
}
