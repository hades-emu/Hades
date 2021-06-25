/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "gba.h"

void
sched_init(
    struct scheduler *scheduler
) {
    // Pre-allocate 10 events
    scheduler->events_size = 10;
    scheduler->events = calloc(scheduler->events_size, sizeof(struct scheduler_event));
    hs_assert(scheduler->events);
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
    struct scheduler *scheduler;
    struct scheduler_event *event;

    scheduler = &gba->scheduler;
    while (true) {
        event = NULL;

        // We want to fire all the events in the correct order, hence the complicated
        // loop.
        for (i = 0; i < scheduler->events_size; ++i) {

            // Keep only the event that are active and should occure now
            if (scheduler->events[i].active && scheduler->events[i].at <= scheduler->cycles) {
                if (!event || scheduler->events[i].at < event->at) {
                    event = scheduler->events + i;
                }
            }
        }

        if (!event) {
            break;
        }

        event->callback(gba, scheduler->cycles - event->at);
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
    scheduler->events = reallocarray(scheduler->events, scheduler->events_size, sizeof(struct scheduler_event));
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
    struct scheduler *scheduler;
    uint64_t target;

    scheduler = &gba->scheduler;
    target = scheduler->cycles + cycles;
    pthread_mutex_lock(&gba->emulator_mutex);
    while (!g_interrupt && scheduler->cycles < target ) {
        uint64_t elapsed;
        uint64_t old_cycles;

        old_cycles = scheduler->cycles;
        core_next(gba);
        elapsed = scheduler->cycles - old_cycles;

        timer_tick(gba, elapsed); // TODO: Make this a scheduler event?

        if (scheduler->cycles >= scheduler->next_event) {
            sched_process_events(gba);
        }
    }
    pthread_mutex_unlock(&gba->emulator_mutex);
}

void
sched_run_forever(
    struct gba *gba
) {
    while (!g_stop) {
        sched_run_for(gba, UINT32_MAX);
    }
}