/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

#define INVALID_EVENT_HANDLE    ((size_t)(-1))

typedef size_t event_handler_t;

enum sched_event_kind {
    SCHED_EVENT_FRAME_LIMITER,
    SCHED_EVENT_PPU_HDRAW,
    SCHED_EVENT_PPU_HBLANK,
    SCHED_EVENT_TIMER_OVERFLOW,
    SCHED_EVENT_TIMER_STOP,
    SCHED_EVENT_APU_SEQUENCER,
    SCHED_EVENT_APU_RESAMPLE,
    SCHED_EVENT_APU_WAVE_STEP,
    SCHED_EVENT_DMA_ADD_PENDING,
};

enum sched_event_type {
    SCHED_EVENT_FIXED,
    SCHED_EVENT_REPEAT,
};

union event_arg {
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
};

// The "argument" given to the event callback.
struct event_args {
    union event_arg a1;
    union event_arg a2;
    union event_arg a3;
    union event_arg a4;
};

struct scheduler_event {
    enum sched_event_kind kind;

    bool active;
    bool repeat;

    uint64_t at;
    uint64_t period; // When the event is fired and repeat is true, `at` is reloaded to ̛`at+count` and the event stays active.

    // The "argument" given to the event callback.
    struct event_args args;
};

struct scheduler {
    uint64_t cycles;                // Amount of cycles spent by the system since initialization

    uint64_t next_event;            // The next event should occure when cycles == next_event

    struct scheduler_event *events;
    size_t events_size;

    uint32_t speed;                 // Speed. 0 = unlimited, 1 = 60fps, 2 = 120fps, etc.

    uint64_t time_per_frame;
    uint64_t time_last_frame;
    uint64_t accumulated_time;
};

#define NEW_FIX_EVENT(_kind, _at)           \
    (struct scheduler_event){               \
        .kind = (_kind),                    \
        .active = true,                     \
        .repeat = false,                    \
        .at = (_at),                        \
        .period = 0,                        \
        .args = (struct event_args){{ 0 }}, \
    }

#define NEW_FIX_EVENT_ARGS(_kind, _at, ...)         \
    (struct scheduler_event){                       \
        .kind = (_kind),                            \
        .active = true,                             \
        .repeat = false,                            \
        .at = (_at),                                \
        .period = 0,                                \
        .args = EVENT_ARGS(__VA_ARGS__),            \
    }

#define NEW_REPEAT_EVENT(_kind, _at, _period)       \
    (struct scheduler_event){                       \
        .kind = (_kind),                            \
        .active = true,                             \
        .repeat = true,                             \
        .at = (_at),                                \
        .period = (_period),                        \
        .args = (struct event_args){{ 0 }},         \
    }

#define NEW_REPEAT_EVENT_ARGS(_kind, _at, _period, ...)         \
    (struct scheduler_event){                                   \
        .kind = (_kind),                                        \
        .active = true,                                         \
        .repeat = true,                                         \
        .at = (_at),                                            \
        .period = (_period),                                    \
        .args = EVENT_ARGS(__VA_ARGS__),                        \
    }

#define EVENT_ARGS_1(_1)                ((struct event_args) { .a1 = (_1), .a2 = EVENT_ARG_EMPTY })
#define EVENT_ARGS_2(_1, _2)            ((struct event_args) { .a1 = (_1), .a2 = (_2) })
#define EVENT_ARGS_3(_1, _2, _3)        ((struct event_args) { .a1 = (_1), .a2 = (_2), .a3 = (_3) })
#define EVENT_ARGS_4(_1, _2, _3, _4)    ((struct event_args) { .a1 = (_1), .a2 = (_2), .a3 = (_3), .a4 = (_4) })
#define EVENT_ARGS(...)                 CONCAT(EVENT_ARGS_, NARG(__VA_ARGS__))(__VA_ARGS__)
#define EVENT_ARG(kind, _value)         ((union event_arg) { .kind = (_value) })
#define EVENT_ARG_EMPTY                 ((union event_arg) { 0 })

struct gba;

/* gba/scheduler.c */
event_handler_t sched_add_event(struct gba *gba, struct scheduler_event event);
void sched_cancel_event(struct gba *gba, event_handler_t handler);
void sched_process_events(struct gba *gba);
void sched_run_for(struct gba *gba, uint64_t cycles);
void sched_frame_limiter(struct gba *gba,struct event_args args);
void sched_reset_frame_limiter(struct gba *gba);
void sched_update_speed(struct gba *gba, uint32_t speed);
