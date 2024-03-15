/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#pragma once

#define GBA_SCREEN_WIDTH                240
#define GBA_SCREEN_HEIGHT               160
#define GBA_SCREEN_REAL_WIDTH           308
#define GBA_SCREEN_REAL_HEIGHT          228
#define GBA_CYCLES_PER_PIXEL            4
#define GBA_CYCLES_PER_FRAME            (CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH * GBA_SCREEN_REAL_HEIGHT)
#define GBA_CYCLES_PER_SECOND           ((uint64_t)(16 * 1024 * 1024))

#include "hades.h"
#include "gba/channel.h"
#include "gba/core.h"
#include "gba/scheduler.h"
#include "gba/memory.h"
#include "gba/ppu.h"
#include "gba/apu.h"
#include "gba/io.h"
#include "gba/gpio.h"
#include "gba/debugger.h"

enum gba_states {
    GBA_STATE_STOP = 0,
    GBA_STATE_PAUSE,
    GBA_STATE_RUN,
};

enum keys {
    KEY_A,
    KEY_B,
    KEY_L,
    KEY_R,
    KEY_UP,
    KEY_DOWN,
    KEY_LEFT,
    KEY_RIGHT,
    KEY_START,
    KEY_SELECT,

    KEY_MAX,
    KEY_MIN = KEY_A,
};

struct shared_data {
    // The emulator's screen, as built by the PPU each frame.
    struct {
        uint32_t data[GBA_SCREEN_WIDTH * GBA_SCREEN_HEIGHT];
        pthread_mutex_t lock;
    } framebuffer;

    // The game's backup storage.
    // There's no lock behind this data because
    struct {
        uint8_t *data;
        size_t size;

        atomic_bool dirty; // Set to true when `data` is modified.
    } backup_storage;

    // The frame counter, used for FPS calculations.
    atomic_uint frame_counter;

    // Audio ring buffer.
    struct apu_rbuffer audio_rbuffer;
    pthread_mutex_t audio_rbuffer_mutex;
};

/*
** Settings that can be altered while the game is running.
*/
struct emulation_settings {
    // Fast forward
    bool fast_forward;

    // Speed. 0.5 = 30fps, 1 = 60fps, 2 = 120fps, etc.
    // Can't be 0 unless `fast_forward` is true.
    float speed;

    struct {
        bool enable_bg_layers[4];
        bool enable_oam;
    } ppu;

    struct {
        bool enable_psg_channels[4];
        bool enable_fifo_channels[2];
    } apu;
};

struct game_entry {
    char *code;
    enum backup_storage_types storage;
    enum gpio_device_types gpio;
    char *title;
};

struct gba {
    bool exit;

    // The current state of the GBA
    enum gba_states state;

    // The channel used to communicate with the frontend
    struct channels channels;

    // Shared data with the frontend, mainly the framebuffer and audio channels.
    struct shared_data shared_data;

    // A set of settings the frontend can update during the emulator's execution (speed, etc.)
    struct emulation_settings settings;

    // The different components of the GBA
    struct core core;
    struct scheduler scheduler;
    struct memory memory;
    struct ppu ppu;
    struct apu apu;
    struct io io;
    struct gpio gpio;

#ifdef WITH_DEBUGGER
    struct debugger debugger;
#endif
};

struct launch_config {
    // The game ROM and its size
    struct {
        uint8_t *data;
        size_t size;
    } rom;

    // The BIOS and its size
    struct {
        uint8_t *data;
        size_t size;
    } bios;

    // True if the BIOS should be skipped
    bool skip_bios;

    // Set to the frontend's audio frequency.
    // Can be 0 if the frontend has no audio.
    uint32_t audio_frequency;

    // GPIO device attached to the cartridge.
    enum gpio_device_types gpio_device_type;

    // The kind of storage type to use.
    struct {
        enum backup_storage_types type;
        uint8_t *data;
        size_t size;
    } backup_storage;

    // Initial value for all runtime-settings (speed, etc.)
    struct emulation_settings settings;
};

struct notification;

/* source/gba.c */
struct gba *gba_create(void);
void gba_run(struct gba *gba);
void gba_delete(struct gba *gba);
void gba_shared_framebuffer_lock(struct gba *gba);
void gba_shared_framebuffer_release(struct gba *gba);
void gba_shared_audio_rbuffer_lock(struct gba *gba);
void gba_shared_audio_rbuffer_release(struct gba *gba);
uint32_t gba_shared_audio_rbuffer_pop_sample(struct gba *gba);
uint32_t gba_shared_reset_frame_counter(struct gba *gba);
void gba_delete_notification(struct notification const *notif);

/* source/db.c */
struct game_entry *db_lookup_game(uint8_t const *code);
struct game_entry *db_autodetect_game_features(uint8_t const *rom, size_t rom_size);
