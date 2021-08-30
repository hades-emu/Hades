/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "gba.h"
#include "compat.h"
#include "scheduler.h"
#include "memory.h"

void
sched_init(
    struct gba *gba
) {
    struct scheduler *scheduler;

    scheduler = &gba->scheduler;

    // Pre-allocate 10 events
    scheduler->events_size = 10;
    scheduler->events = calloc(scheduler->events_size, sizeof(struct scheduler_event));
    hs_assert(scheduler->events);

    // Frame limiter event
    sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            CYCLES_PER_PIXEL * SCREEN_REAL_WIDTH * SCREEN_REAL_HEIGHT,  // Timing of first trigger
            CYCLES_PER_PIXEL * SCREEN_REAL_WIDTH * SCREEN_REAL_HEIGHT,  // Period
            sched_frame_limiter
        )
    );

    // Write save data to disk
    sched_add_event(
        gba,
        NEW_REPEAT_EVENT(
            CYCLES_PER_PIXEL * SCREEN_REAL_WIDTH * SCREEN_REAL_HEIGHT * 60,  // Timing of first trigger
            CYCLES_PER_PIXEL * SCREEN_REAL_WIDTH * SCREEN_REAL_HEIGHT * 60,  // Period
            sched_save_to_disk
        )
    );
}

void
sched_cleanup(
    struct scheduler *scheduler
) {
    free(scheduler->events);
    scheduler->events = NULL;
    scheduler->events_size = 0;
}

void
sched_process_events(
    struct gba *gba
) {
    size_t i;
    struct core *core;
    struct scheduler *scheduler;
    struct scheduler_event *event;

    core = &gba->core;
    scheduler = &gba->scheduler;
    while (true) {
        event = NULL;

        // We want to fire all the events in the correct order, hence the complicated
        // loop.
        for (i = 0; i < scheduler->events_size; ++i) {

            // Keep only the event that are active and should occure now
            if (scheduler->events[i].active && scheduler->events[i].at <= core->cycles) {
                if (!event || scheduler->events[i].at < event->at) {
                    event = scheduler->events + i;
                }
            }
        }

        if (!event) {
            break;
        }

        event->callback(gba, core->cycles - event->at);
        if (event->repeat) {
            event->at += event->period;
        } else {
            event->active = false;
        }
    }
}

void
sched_add_event(
    struct gba *gba,
    struct scheduler_event event
) {
    struct scheduler *scheduler;
    size_t i;

    scheduler = &gba->scheduler;

    // Try and reuse an inactive event
    for (i = 0; i < scheduler->events_size; ++i) {
        if (!scheduler->events[i].active) {
            scheduler->events[i] = event;
            scheduler->events[i].active = true;
            goto end;
        }
    }

    i = scheduler->events_size;

    // If no event are available, reallocate `scheduler->events`.
    scheduler->events_size += 5;
    scheduler->events = realloc(scheduler->events, scheduler->events_size * sizeof(struct scheduler_event));
    hs_assert(scheduler->events);

    scheduler->events[i] = event;
    scheduler->events[i].active = true;

end:
    if (event.at < scheduler->next_event) {
        scheduler->next_event = event.at;
    }
}

void
sched_run_for(
    struct gba *gba,
    uint64_t cycles
) {
    struct core *core;
    struct scheduler *scheduler;
    uint64_t target;

    core = &gba->core;
    scheduler = &gba->scheduler;
    target = core->cycles + cycles;
    while (!g_interrupt && core->cycles < target ) {
        uint64_t elapsed;
        uint64_t old_cycles;

        old_cycles = core->cycles;
        core_next(gba);
        elapsed = core->cycles - old_cycles;

        if (!elapsed) {
            logln(HS_WARNING, "No cycles elapsed during `core_next()`.");
        }

#if ENABLE_DEBUGGER
        if (gba->options.debugger) {
            debugger_eval_breakpoints(gba);
        }
#endif

        if (core->cycles >= scheduler->next_event) {
            sched_process_events(gba);
        }

        event_handle_all(gba);
    }
}

void
sched_run_forever(
    struct gba *gba
) {
    while (!g_stop) {
        sched_run_for(gba, UINT32_MAX);
    }
}

void
sched_frame_limiter(
    struct gba *gba,
    uint64_t extra_cycles __unused
) {
    uint64_t diff;
    uint64_t sleep_time;

    // Early return if we are unbounded
    if (!gba->options.speed) {
        goto end;
    }

    diff = hs_tick_count() - gba->previous_frame_tick;

    if (diff < 17 / gba->options.speed) { // One frame is supposed to take 16.6 millisecond
        sleep_time = 17 / gba->options.speed - diff; // Millis
        usleep(sleep_time * 1000);
    }

    gba->previous_frame_tick = hs_tick_count();

end:
    ++gba->frame_counter;
}

void
sched_save_to_disk(
    struct gba *gba,
    uint64_t extra_cycles __unused
) {
    mem_backup_storage_write_to_disk(gba);
}