/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include "gba/gba.h"
#include "gba/apu.h"

/*
** Reference for the APU implementation:
**   - https://belogic.com/gba/channel1.shtml
**   - https://gbdev.gg8.se/wiki/articles/Gameboy_sound_hardware
**   - https://gbdev.io/pandocs/Audio_details.html
**   - https://nightshade256.github.io/2021/03/27/gb-sound-emulation.html
*/

static int32_t fifo_volume[2] = {2, 4};
static int32_t psg_volume[4] = {1, 2, 4, 0};

static
void
apu_rbuffer_push(
    struct apu_rbuffer *rbuffer,
    int16_t val_l,
    int16_t val_r
) {
    if (rbuffer->size < APU_RBUFFER_CAPACITY) {
        uint32_t data;

        data = (((uint32_t)(uint16_t)val_l) << 16) | ((uint32_t)(uint16_t)val_r);
        rbuffer->data[rbuffer->write_idx] = data;
        rbuffer->write_idx = (rbuffer->write_idx + 1) % APU_RBUFFER_CAPACITY;
        ++rbuffer->size;
    }
}

uint32_t
apu_rbuffer_pop(
    struct apu_rbuffer *rbuffer
) {
    uint32_t val;

    val = rbuffer->data[rbuffer->read_idx];
    if (rbuffer->size > 0) {
        rbuffer->read_idx = (rbuffer->read_idx + 1) % APU_RBUFFER_CAPACITY;
        --rbuffer->size;
    }

    return (val);
}

/*
** This function is called at the same frequency than the real hardware the emulator is running on (probably 48000Hz).
**
** The goal here is to feed `apu_rbuffer` with whatever sound the GBA would be playing at this time, which is contained in `gba->apu.latch`.
*/
void
apu_resample(
    struct gba *gba,
    struct event_args args __unused
) {
    int32_t sample_l;
    int32_t sample_r;

    sample_l = 0;
    sample_r = 0;

    sample_l += (gba->apu.latch.channel_1 * (bool)gba->io.soundcnt_l.enable_sound_1_left * gba->settings.apu.enable_psg_channels[0]); // [-0x80; 0x80]
    sample_r += (gba->apu.latch.channel_1 * (bool)gba->io.soundcnt_l.enable_sound_1_right * gba->settings.apu.enable_psg_channels[0]);

    sample_l += (gba->apu.latch.channel_2 * (bool)gba->io.soundcnt_l.enable_sound_2_left * gba->settings.apu.enable_psg_channels[1]); // [-0x100; 0x100]
    sample_r += (gba->apu.latch.channel_2 * (bool)gba->io.soundcnt_l.enable_sound_2_right * gba->settings.apu.enable_psg_channels[1]);

    sample_l += (gba->apu.latch.channel_3 * (bool)gba->io.soundcnt_l.enable_sound_3_left * gba->settings.apu.enable_psg_channels[2]); // [-0x180; 0x180]
    sample_r += (gba->apu.latch.channel_3 * (bool)gba->io.soundcnt_l.enable_sound_3_right * gba->settings.apu.enable_psg_channels[2]);

    sample_l += (gba->apu.latch.channel_4 * (bool)gba->io.soundcnt_l.enable_sound_4_left * gba->settings.apu.enable_psg_channels[3]); // [-0x200; 0x200]
    sample_r += (gba->apu.latch.channel_4 * (bool)gba->io.soundcnt_l.enable_sound_4_right * gba->settings.apu.enable_psg_channels[3]);

    sample_l *= psg_volume[gba->io.soundcnt_h.volume_channels] * gba->io.soundcnt_l.channel_left_volume; // [-0x3800; 0x3800]
    sample_r *= psg_volume[gba->io.soundcnt_h.volume_channels] * gba->io.soundcnt_l.channel_right_volume; // [-0x3800; 0x3800]

    /*
    ** Keep the range of the PSG channels within [-0x200; 0x200] even after applying the volumes.
    ** This ensures the ratio PSG/Direct Sound is normal.
    **
    ** max(sound_volume) * max(gba->io.soundcnt_l.channel_{left,right}_volume) = 4 * 7 = 28
    */
    sample_l /= 28; // [-0x200; 0x200]
    sample_r /= 28;

    sample_l += (gba->apu.latch.fifo[FIFO_A] * (bool)gba->io.soundcnt_h.enable_fifo_a_left) * fifo_volume[gba->io.soundcnt_h.volume_fifo_a] * gba->settings.apu.enable_fifo_channels[0]; // [-0x400; 0x400]
    sample_r += (gba->apu.latch.fifo[FIFO_A] * (bool)gba->io.soundcnt_h.enable_fifo_a_right)  * fifo_volume[gba->io.soundcnt_h.volume_fifo_a] * gba->settings.apu.enable_fifo_channels[0];

    sample_l += (gba->apu.latch.fifo[FIFO_B] * (bool)gba->io.soundcnt_h.enable_fifo_b_left) * fifo_volume[gba->io.soundcnt_h.volume_fifo_b] * gba->settings.apu.enable_fifo_channels[1]; // [-0x600; 0x600]
    sample_r += (gba->apu.latch.fifo[FIFO_B] * (bool)gba->io.soundcnt_h.enable_fifo_b_right) * fifo_volume[gba->io.soundcnt_h.volume_fifo_b] * gba->settings.apu.enable_fifo_channels[1];

    sample_l += gba->io.soundbias.bias; // [-0x400; 0x800] (with default bias)
    sample_r += gba->io.soundbias.bias;

    sample_l = max(min(sample_l, 0x3FF), 0) - 0x200;  // [-0x200; 0x200]
    sample_r = max(min(sample_r, 0x3FF), 0) - 0x200;

    sample_l *= 32; // Otherwise we can't hear much
    sample_r *= 32;

    pthread_mutex_lock(&gba->shared_data.audio_rbuffer_mutex);
    apu_rbuffer_push(&gba->shared_data.audio_rbuffer, (int16_t)sample_l, (int16_t)sample_r);
    pthread_mutex_unlock(&gba->shared_data.audio_rbuffer_mutex);
}
