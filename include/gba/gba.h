/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#ifndef GBA_GBA_H
# define GBA_GBA_H

# include <stdatomic.h>
# include "gba/core.h"
# include "gba/memory.h"
# include "gba/ppu.h"
# include "gba/io.h"
# include "gba/apu.h"
# include "gba/scheduler.h"

enum gba_state {
    GBA_STATE_PAUSE = 0,
    GBA_STATE_RUN,
};

enum message_type {
    MESSAGE_EXIT,
    MESSAGE_LOAD_BIOS,
    MESSAGE_LOAD_ROM,
    MESSAGE_LOAD_BACKUP,
    MESSAGE_BACKUP_TYPE,
    MESSAGE_RESET,
    MESSAGE_RUN,
    MESSAGE_PAUSE,
    MESSAGE_KEYINPUT,
    MESSAGE_QUICKLOAD,
    MESSAGE_QUICKSAVE,
    MESSAGE_AUDIO_RESAMPLE_FREQ,
    MESSAGE_COLOR_CORRECTION,
};

enum keyinput {
    KEY_A,
    KEY_B,
    KEY_L,
    KEY_R,
    KEY_UP,
    KEY_DOWN,
    KEY_RIGHT,
    KEY_LEFT,
    KEY_START,
    KEY_SELECT,
};

struct message {
    enum message_type type;
    size_t size;
};

struct message_run {
    struct message super;
    uint32_t speed; // 0 means unbounded (no fps cap).
};

struct message_keyinput {
    struct message super;
    enum keyinput key;
    bool pressed;
};

struct message_backup_type {
    struct message super;
    enum backup_storage type;
};

struct message_data {
    struct message super;
    uint8_t *data;
    size_t size;
    void (*cleanup)(void *);
};

struct message_audio_freq {
    struct message super;
    uint64_t refill_frequency;
};

struct message_color_correction {
    struct message super;
    bool color_correction;
};

struct message_queue {
    struct message *messages;
    size_t length;
    size_t allocated_size;

    pthread_mutex_t lock;
};

struct game_entry;

struct gba {
    enum gba_state state;
    uint32_t speed;

    struct core core;
    struct memory memory;
    struct io io;
    struct ppu ppu;
    struct apu apu;
    struct scheduler scheduler;

    /* Entry in the game database, if it exists. */
    struct game_entry *game_entry;

    /* Stores if color correction is enabled. */
    bool color_correction;

    /* The message queue used by the frontend to communicate with the emulator. */
    struct message_queue message_queue;

    /* The emulator's screen as it is being rendered. */
    uint32_t framebuffer[GBA_SCREEN_WIDTH * GBA_SCREEN_HEIGHT];

    /* The emulator's screen, refreshed each frame, used by the frontend */
    uint32_t framebuffer_frontend[GBA_SCREEN_WIDTH * GBA_SCREEN_HEIGHT];
    pthread_mutex_t framebuffer_frontend_mutex;

    /* The frame counter, used for FPS calculations. */
    atomic_uint framecounter;
};

# define NEW_MESSAGE_KEYINPUT(_key, _pressed)           \
    ((struct message *)&((struct message_keyinput){     \
        .super = (struct message){                      \
            .size = sizeof(struct message_keyinput),    \
            .type = MESSAGE_KEYINPUT,                   \
        },                                              \
        .key = (_key),                                  \
        .pressed = (_pressed)                           \
    }))

# define NEW_MESSAGE_QUICKSAVE(_path)                   \
    ((struct message *)&((struct message_data){         \
        .super = (struct message){                      \
            .size = sizeof(struct message_data),        \
            .type = MESSAGE_QUICKSAVE,                  \
        },                                              \
        .data = (uint8_t *)strdup(_path),               \
        .size = strlen(_path),                          \
        .cleanup = free,                                \
    }))

# define NEW_MESSAGE_QUICKLOAD(_path)                   \
    ((struct message *)&((struct message_data){         \
        .super = (struct message){                      \
            .size = sizeof(struct message_data),        \
            .type = MESSAGE_QUICKLOAD,                  \
        },                                              \
        .data = (uint8_t *)strdup(_path),               \
        .size = strlen(_path),                          \
        .cleanup = free,                                \
    }))

# define NEW_MESSAGE_RUN(_speed)                        \
    ((struct message *)&((struct message_run){          \
        .super = (struct message){                      \
            .size = sizeof(struct message_run),         \
            .type = MESSAGE_RUN,                        \
        },                                              \
        .speed = (_speed),                              \
    }))

# define NEW_MESSAGE_PAUSE()                            \
    (&((struct message){                                \
        .type = MESSAGE_PAUSE,                          \
        .size = sizeof(struct message),                 \
    }))

# define NEW_MESSAGE_RESET()                            \
    (&((struct message){                                \
        .type = MESSAGE_RESET,                          \
        .size = sizeof(struct message),                 \
    }))

# define NEW_MESSAGE_LOAD_BIOS(_data, _cleanup)         \
    ((struct message *)&((struct message_data){         \
        .super = (struct message){                      \
            .size = sizeof(struct message_data),        \
            .type = MESSAGE_LOAD_BIOS,                  \
        },                                              \
        .data = (_data),                                \
        .size = (BIOS_SIZE),                            \
        .cleanup = (_cleanup),                          \
    }))

# define NEW_MESSAGE_LOAD_ROM(_data, _size, _cleanup)   \
    ((struct message *)&((struct message_data){         \
        .super = (struct message){                      \
            .size = sizeof(struct message_data),        \
            .type = MESSAGE_LOAD_ROM,                   \
        },                                              \
        .data = (_data),                                \
        .size = (_size),                                \
        .cleanup = (_cleanup),                          \
    }))

# define NEW_MESSAGE_BACKUP_TYPE(_type)                 \
    ((struct message *)&((struct message_backup_type){  \
        .super = (struct message){                      \
            .size = sizeof(struct message_backup_type), \
            .type = MESSAGE_BACKUP_TYPE,                \
        },                                              \
        .type = (_type),                                \
    }))

# define NEW_MESSAGE_LOAD_BACKUP(_data, _size, _cleanup)\
    ((struct message *)&((struct message_data){         \
        .super = (struct message){                      \
            .size = sizeof(struct message_data),        \
            .type = MESSAGE_LOAD_BACKUP,                \
        },                                              \
        .data = (_data),                                \
        .size = (_size),                                \
        .cleanup = (_cleanup),                          \
    }))

# define NEW_MESSAGE_AUDIO_RESAMPLE_FREQ(_freq)         \
    ((struct message *)&((struct message_audio_freq){   \
        .super = (struct message){                      \
            .size = sizeof(struct message_audio_freq),  \
            .type = MESSAGE_AUDIO_RESAMPLE_FREQ,        \
        },                                              \
        .refill_frequency = (_freq),                    \
    }))

# define NEW_MESSAGE_COLOR_CORRECTION(_color)                   \
    ((struct message *)&((struct message_color_correction){     \
        .super = (struct message){                              \
            .size = sizeof(struct message_color_correction),    \
            .type = MESSAGE_COLOR_CORRECTION,                   \
        },                                                      \
        .color_correction = (_color),                           \
    }))

/* gba/gba.c */
void gba_init(struct gba *gba);
void gba_run(struct gba *gba);
void gba_message_push(struct gba *gba, struct message *message);

#endif /* GBA_GBA_H */