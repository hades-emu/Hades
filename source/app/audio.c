/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include "app/app.h"
#include "gba/gba.h"

static
void
app_sdl_audio_callback(
    void *raw_app,
    SDL_AudioStream *stream,
    int additional_amount,
    int total_amount __unused
) {
    struct app *app;
    struct gba *gba;
    size_t len;
    size_t i;

    app = raw_app;
    gba = app->emulation.gba;
    len = additional_amount / sizeof(int16_t);

    if (len <= 0) {
        return;
    }

    if (len > array_length(app->audio.buffer)) {
        len = array_length(app->audio.buffer);
    }

    pthread_mutex_lock(&gba->shared_data.audio_rbuffer_mutex);
    for (i = 0; i < len / 2; ++i) {
        uint32_t val;
        int16_t left;
        int16_t right;

        val = apu_rbuffer_pop(&gba->shared_data.audio_rbuffer);
        left = (int16_t)((val >> 16) & 0xFFFF);
        right = (int16_t)(val & 0xFFFF);

        app->audio.buffer[i * 2 + 0] = (int16_t)(left * !app->settings.audio.mute * app->settings.audio.level);
        app->audio.buffer[i * 2 + 1] = (int16_t)(right * !app->settings.audio.mute * app->settings.audio.level);
    }
    pthread_mutex_unlock(&gba->shared_data.audio_rbuffer_mutex);

    SDL_PutAudioStreamData(stream, app->audio.buffer, len * sizeof(app->audio.buffer[0]));
}

void
app_sdl_audio_init(
    struct app *app
) {
    SDL_AudioSpec spec;

    spec.freq = 48000;
    spec.format = SDL_AUDIO_S16LE;
    spec.channels = 2;

    app->audio.stream = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, app_sdl_audio_callback, app);

    if (app->audio.stream) {
        // Update `spec` to contain the actual audio spec of the device we opened, which might not be the same than the
        // one we requested.
        SDL_GetAudioStreamFormat(app->audio.stream, NULL, &spec);

        app->audio.resample_frequency = spec.freq;
        SDL_ResumeAudioStreamDevice(app->audio.stream);
    } else {
         logln(HS_ERROR, "Failed to initialize the audio device: %s", SDL_GetError());
         app->audio.resample_frequency = spec.freq;
    }
}

void
app_sdl_audio_cleanup(
    struct app const *app
) {
    if (app->audio.stream) {
        SDL_DestroyAudioStream(app->audio.stream);
    }
}
