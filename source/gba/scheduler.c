/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/scheduler.h"
#include "gba/memory.h"

void
sched_init(
    struct gba *gba
) {
    struct scheduler *scheduler;

    scheduler = &gba->scheduler;

    memset(scheduler, 0, sizeof(*scheduler));

    // Pre-allocate 64 events
    scheduler->events_size = 64;
    scheduler->events = calloc(scheduler->events_size, sizeof(struct scheduler_event));
    hs_assert(scheduler->events);
}

void
sched_cleanup(
    struct gba *gba
) {
    struct scheduler *scheduler;

    scheduler = &gba->scheduler;
    free(scheduler->events);
    scheduler->events = NULL;
    scheduler->events_size = 0;
}

void
sched_process_events(
    struct gba *gba
) {
    struct core *core;
    struct scheduler *scheduler;
    struct scheduler_event *event;
    uint64_t next_event;
    size_t i;

    core = &gba->core;
    scheduler = &gba->scheduler;
    while (true) {
        event = NULL;

        next_event = UINT64_MAX;

        // We want to fire all the events in the correct order, hence the complicated
        // loop.
        for (i = 0; i < scheduler->events_size; ++i) {

            // Keep only the event that are active and should occure now
            if (scheduler->events[i].active) {
                if (scheduler->events[i].at <= core->cycles) {
                    if (!event || scheduler->events[i].at < event->at) {
                        event = scheduler->events + i;
                    }
                } else if (scheduler->events[i].at < next_event) {
                    next_event = scheduler->events[i].at;
                }
            }
        }

        scheduler->next_event = next_event;

        if (!event) {
            break;
        }

        if (event->repeat) {
            event->at += event->period;

            if (event->at < scheduler->next_event) {
                scheduler->next_event = event->at;
            }

        } else {
            event->active = false;
        }

        event->callback(gba, event->args);
    }
}

event_handler_t
sched_add_event(
    struct gba *gba,
    struct scheduler_event event
) {
    struct scheduler *scheduler;
    size_t i;

    scheduler = &gba->scheduler;

    hs_assert(!event.repeat || event.period);

    // Try and reuse an inactive event
    for (i = 0; i < scheduler->events_size; ++i) {
        if (!scheduler->events[i].active) {
            scheduler->events[i] = event;
            scheduler->events[i].active = true;
            goto end;
        }
    }

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

    return (i);
}

void
sched_cancel_event(
    struct gba *gba,
    event_handler_t handler
) {
    struct scheduler *scheduler;

    scheduler = &gba->scheduler;

    if (scheduler->events[handler].active) {
        scheduler->events[handler].active = false;
    }

    // TODO: update `scheduler->next_event`? Is it worth it?
}

void
sched_run_for(
    struct gba *gba,
    uint64_t cycles
) {
    struct core *core;
    uint64_t target;

    core = &gba->core;
    target = core->cycles + cycles;

#ifdef WITH_DEBUGGER
    while (core->cycles < target && !gba->debugger.interrupt.flag) {
#else
    while (core->cycles < target) {
#endif
        uint64_t elapsed;
        uint64_t old_cycles;

        old_cycles = core->cycles;
        core_next(gba);
        elapsed = core->cycles - old_cycles;

        if (!elapsed) {
            if (core->state != CORE_STOP) {
                logln(HS_WARNING, "No cycles elapsed during `core_next()`.");
            }
            break;
        }
    }
}