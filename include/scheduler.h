/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#ifndef SCHEDULER_H
# define SCHEDULER_H

enum sched_event_type {
    SCHED_EVENT_FIXED,
    SCHED_EVENT_REPEAT,
};

union event_data {
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
    void *ptr;
};

struct scheduler_event {
    bool active;
    bool repeat;

    uint64_t at;
    uint64_t period; // When the event is fired and repeat is true, `at` is reloaded to ̛`at+count` and the event stays active.
    union event_data data; // The "argument" given to the event callback.

    void (*callback)(struct gba *gba, union event_data data);
};

struct scheduler {
    uint64_t next_event;            // The next event should occure when cycles == next_event

    struct scheduler_event *events;
    size_t events_size;
};

/* scheduler.c */
void sched_init(struct gba *gba);
void sched_cleanup(struct scheduler *scheduler);
void sched_run_forever(struct gba *gba);
void sched_run_for(struct gba *gba, uint64_t cycles);
void sched_add_event(struct gba *gba, struct scheduler_event event);
void sched_frame_limiter(struct gba *gba, union event_data data);
void sched_save_to_disk(struct gba *gba, union event_data data);
void sched_process_events(struct gba *gba);

# define NEW_FIX_EVENT(_at, _callback)  \
    (struct scheduler_event){           \
        .active = true,                 \
        .repeat = false,                \
        .at = (_at),                    \
        .period = 0,                    \
        .data = (union event_data){ 0 },\
        .callback = (_callback),        \
    }

# define NEW_FIX_EVENT_DATA(_at, _callback, _data)  \
    (struct scheduler_event){           \
        .active = true,                 \
        .repeat = false,                \
        .at = (_at),                    \
        .period = 0,                    \
        .data = (_data),                \
        .callback = (_callback),        \
    }

# define NEW_REPEAT_EVENT(_at, _period, _callback)  \
    (struct scheduler_event){                       \
        .active = true,                             \
        .repeat = true,                             \
        .at = (_at),                                \
        .period = (_period),                        \
        .data = (union event_data){ 0 },            \
        .callback = (_callback),                    \
    }

# define NEW_FIX_EVENT_DATA(_at, _callback, _data)  \
    (struct scheduler_event){                       \
        .active = true,                             \
        .repeat = false,                            \
        .at = (_at),                                \
        .period = 0,                                \
        .data = (_data),                            \
        .callback = (_callback),                    \
    }

#endif /* !SCHEDULER_H */