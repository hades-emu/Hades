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

/*
** Should be called roughly 23/24 times per second (48000 / 2048, see the the values in `app_sdl_audio_init()`).
**
** We transfer the data contained in the apu_rbuffer to the SDL.
*/
static
void
app_sdl_audio_callback(
    void *raw_app,
    uint8_t *raw_stream,
    int raw_stream_len
) {
    struct app *app;
    struct gba *gba;
    int16_t *stream;
    size_t len;
    size_t i;

    app = raw_app;
    gba = app->emulation.gba;
    stream = (int16_t *)raw_stream;
    len = raw_stream_len / (2 * sizeof(*stream));

    pthread_mutex_lock(&gba->shared_data.audio_rbuffer_mutex);
    for (i = 0; i < len; ++i) {
        uint32_t val;
        int16_t left;
        int16_t right;

        val = apu_rbuffer_pop(&gba->shared_data.audio_rbuffer);
        left = (int16_t)((val >> 16) & 0xFFFF);
        right = (int16_t)(val & 0xFFFF);

        stream[0] = (int16_t)(left * !app->settings.audio.mute * app->settings.audio.level);
        stream[1] = (int16_t)(right * !app->settings.audio.mute * app->settings.audio.level);
        stream += 2;
    }
    pthread_mutex_unlock(&gba->shared_data.audio_rbuffer_mutex);
}

void
app_sdl_audio_init(
    struct app *app
) {
    SDL_AudioSpec want;
    SDL_AudioSpec have;

    want.freq = 48000;
    want.samples = 2048;
    want.format = AUDIO_S16;
    want.channels = 2;
    want.callback = app_sdl_audio_callback;
    want.userdata = app;

    app->sdl.audio_device = SDL_OpenAudioDevice(NULL, 0, &want, &have, 0);

    if (app->sdl.audio_device) {
        app->audio.resample_frequency = have.freq;
        SDL_PauseAudioDevice(app->sdl.audio_device, SDL_FALSE);
    } else {
        logln(HS_ERROR, "Failed to initialize the audio device: %s", SDL_GetError());
        app->audio.resample_frequency = want.freq;
    }
}

void
app_sdl_audio_cleanup(
    struct app const *app
) {
    if (app->sdl.audio_device) {
        SDL_CloseAudioDevice(app->sdl.audio_device);
    }
}
