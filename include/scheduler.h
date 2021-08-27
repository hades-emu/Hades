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

struct scheduler_event {
    bool active;
    bool repeat;

    uint64_t at;
    uint64_t period; // When the event is fired and repeat is true, `at` is reloaded to ̛`at+count` and the event stays active.

    void (*callback)(struct gba *gba, uint64_t extra_cycles);
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
void sched_frame_limiter(struct gba *gba, uint64_t extra_cycles);

# define NEW_FIX_EVENT(_at, _callback)  \
    (struct scheduler_event){           \
        .active = true,                 \
        .repeat = false,                \
        .at = (_at),                    \
        .period = 0,                    \
        .callback = (_callback),        \
    }

# define NEW_REPEAT_EVENT(_at, _period, _callback)  \
    (struct scheduler_event){                       \
        .active = true,                             \
        .repeat = true,                             \
        .at = (_at),                                \
        .period = (_period),                        \
        .callback = (_callback),                    \
    }

#endif /* !SCHEDULER_H */