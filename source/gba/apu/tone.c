/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
********************************************************************/

#include "gba/gba.h"
#include "gba/apu.h"

/*
** Reference:
**   - https://gbdev.gg8.se/wiki/articles/Gameboy_sound_hardware#Square_Wave
*/
static int16_t duty_lut[4][8] = {
    [0] = {  1,  1,  1,  1,  1,  1,  1, -1}, // 12.5%
    [1] = { -1,  1,  1,  1,  1,  1,  1, -1}, // 25%
    [2] = { -1,  1,  1,  1,  1, -1, -1, -1}, // 50%
    [3] = {  1, -1, -1, -1, -1, -1, -1,  1}, // 75%
};

/*
** This is the frequency of a whole cycle. Our `step` function is called 8 times per cycle, hence why
** we have an extra division by 8 at the end.
*/
#define CHANNEL_FREQUENCY_AS_CYCLES(x)          ((GBA_CYCLES_PER_SECOND * (2048 - (x))) / (131072 * 8))

void
apu_tone_and_sweep_reset(
    struct gba *gba
) {
    gba->io.sound1cnt_x.reset = false;

    apu_tone_and_sweep_stop(gba);

    // Envelope set to decrease mode with a volume of 0 mutes the channel
    if (!gba->io.sound1cnt_h.envelope_direction && !gba->io.sound1cnt_h.envelope_initial_volume) {
        return;
    }

    gba->apu.tone_and_sweep.enabled = true;

    apu_modules_envelope_reset(
        &gba->apu.tone_and_sweep.envelope,
        gba->io.sound1cnt_h.envelope_step_time,
        gba->io.sound1cnt_h.envelope_direction,
        gba->io.sound1cnt_h.envelope_initial_volume
    );

    apu_modules_sweep_reset(
        &gba->apu.tone_and_sweep.sweep,
        gba->io.sound1cnt_x.sample_rate,
        gba->io.sound1cnt_l.sweep_shift_number,
        gba->io.sound1cnt_l.sweep_direction,
        gba->io.sound1cnt_l.sweep_step_time
    );

    apu_modules_counter_reset(
        &gba->apu.tone_and_sweep.counter,
        gba->io.sound1cnt_x.use_length,
        gba->io.sound1cnt_x.use_length ? 64 - gba->io.sound1cnt_h.length : 0
    );

    gba->apu.tone_and_sweep.step_handler = sched_add_event(
        gba,
        NEW_FIX_EVENT(
            SCHED_EVENT_APU_TONE_AND_SWEEP_STEP,
            gba->scheduler.cycles + CHANNEL_FREQUENCY_AS_CYCLES(gba->apu.tone_and_sweep.sweep.frequency) // TODO: Is there a delay before the sound is started?
        )
    );
}

void
apu_tone_and_sweep_stop(
    struct gba *gba
) {
    gba->io.soundcnt_x.sound_1_status = false;
    gba->apu.latch.channel_1 = 0;
    gba->apu.tone_and_sweep.enabled = false;

    if (gba->apu.tone_and_sweep.step_handler != INVALID_EVENT_HANDLE) {
        sched_cancel_event(gba, gba->apu.tone_and_sweep.step_handler);
        gba->apu.tone_and_sweep.step_handler = INVALID_EVENT_HANDLE;
    }
}

void
apu_tone_and_sweep_step(
    struct gba *gba,
    struct event_args args __unused
) {
    int16_t sample;

    if (!gba->apu.tone_and_sweep.enabled) {
        apu_tone_and_sweep_stop(gba);
        return;
    }

    gba->io.soundcnt_x.sound_1_status = true;

    // Fetch the value from the duty LUT.
    sample = duty_lut[gba->io.sound1cnt_h.duty][gba->apu.tone_and_sweep.step]; // [-1; +1]

    // Apply counter
    sample *= gba->io.sound1cnt_x.use_length ? (gba->apu.tone_and_sweep.counter.value > 0) : 1; // [-1; +1]

    // Apply envelope
    sample *= gba->apu.tone_and_sweep.envelope.volume; // [-15; 15], since `volume` is `[0; 0xF]`

    // Adjust the volume to match the other PSG channels
    sample *= 8; // [-120; 120]

    gba->apu.latch.channel_1 = sample;

    // Increment the step counter
    ++gba->apu.tone_and_sweep.step;
    gba->apu.tone_and_sweep.step %= 8;

    gba->apu.tone_and_sweep.step_handler = sched_add_event(
        gba,
        NEW_FIX_EVENT(
            SCHED_EVENT_APU_TONE_AND_SWEEP_STEP,
            gba->scheduler.cycles + CHANNEL_FREQUENCY_AS_CYCLES(gba->apu.tone_and_sweep.sweep.frequency) // TODO: Is there a delay before the sound is started?
        )
    );
}

void
apu_tone_reset(
    struct gba *gba
) {
    gba->io.sound2cnt_h.reset = false;

    apu_tone_stop(gba);

    // Envelope set to decrease mode with a volume of 0 mutes the channel
    if (!gba->io.sound2cnt_l.envelope_direction && !gba->io.sound2cnt_l.envelope_initial_volume) {
        return;
    }

    gba->apu.tone.enabled = true;

    apu_modules_envelope_reset(
        &gba->apu.tone.envelope,
        gba->io.sound2cnt_l.envelope_step_time,
        gba->io.sound2cnt_l.envelope_direction,
        gba->io.sound2cnt_l.envelope_initial_volume
    );

    apu_modules_counter_reset(
        &gba->apu.tone.counter,
        gba->io.sound2cnt_h.use_length,
        gba->io.sound2cnt_h.use_length ? 64 - gba->io.sound2cnt_l.length : 0
    );

    gba->apu.tone.step_handler = sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            SCHED_EVENT_APU_TONE_STEP,
            gba->scheduler.cycles,
            CHANNEL_FREQUENCY_AS_CYCLES(gba->io.sound2cnt_h.sample_rate) // TODO: Is there a delay before the sound is started?
        )
    );
}

void
apu_tone_stop(
    struct gba *gba
) {
    gba->io.soundcnt_x.sound_2_status = false;
    gba->apu.latch.channel_2 = 0;
    gba->apu.tone.enabled = false;

    if (gba->apu.tone.step_handler != INVALID_EVENT_HANDLE) {
        sched_cancel_event(gba, gba->apu.tone.step_handler);
        gba->apu.tone.step_handler = INVALID_EVENT_HANDLE;
    }
}

void
apu_tone_step(
    struct gba *gba,
    struct event_args args __unused
) {
    int16_t sample;

    if (!gba->apu.tone.enabled) {
        apu_tone_stop(gba);
        return;
    }

    gba->io.soundcnt_x.sound_2_status = true;

    // Fetch the value from the duty LUT.
    sample = duty_lut[gba->io.sound2cnt_l.duty][gba->apu.tone.step]; // [-1; +1]

    // Apply counter
    sample *= gba->io.sound2cnt_h.use_length ? (gba->apu.tone.counter.value > 0) : 1; // [-1; +1]

    // Apply envelope
    sample *= gba->apu.tone.envelope.volume; // [-15; 15], since `volume` is `[0; 0xF]`

    // Adjust the volume to match the other PSG channels
    sample *= 8; // [-120; 120]

    gba->apu.latch.channel_2 = sample;

    // Increment the step counter
    ++gba->apu.tone.step;
    gba->apu.tone.step %= 8;
}
