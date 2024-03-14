/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "gba/gba.h"
#include "gba/scheduler.h"
#include "gba/memory.h"
#include "compat.h"

void (*sched_event_callbacks[])(struct gba *gba, struct event_args args) = {
    [SCHED_EVENT_FRAME_LIMITER] = sched_frame_limiter,
    [SCHED_EVENT_PPU_HDRAW] = ppu_hdraw,
    [SCHED_EVENT_PPU_HBLANK] = ppu_hblank,
    [SCHED_EVENT_TIMER_OVERFLOW] = timer_overflow,
    [SCHED_EVENT_APU_MODULES_STEP] = apu_modules_step,
    [SCHED_EVENT_APU_RESAMPLE] = apu_resample,
    [SCHED_EVENT_APU_TONE_AND_SWEEP_STEP] = apu_tone_and_sweep_step,
    [SCHED_EVENT_APU_TONE_STEP] = apu_tone_step,
    [SCHED_EVENT_APU_WAVE_STEP] = apu_wave_step,
    [SCHED_EVENT_APU_NOISE_STEP] = apu_noise_step,
    [SCHED_EVENT_DMA_ADD_PENDING] = mem_dma_add_to_pending,
    [SCHED_EVENT_IO_WRITE] = io_register_delayed_write,
    [SCHED_EVENT_CORE_UPDATE_IRQ_LINE] = core_update_irq_line,
};

void
sched_process_events(
    struct gba *gba
) {
    struct scheduler *scheduler;

    scheduler = &gba->scheduler;
    while (true) {
        struct scheduler_event *event;
        uint64_t next_event;
        uint64_t delay;
        size_t i;

        event = NULL;

        next_event = UINT64_MAX;

        // We want to fire all the events in the correct order, hence the complicated
        // loop.
        for (i = 0; i < scheduler->events_size; ++i) {

            // Keep only the event that are active and should occure now
            if (scheduler->events[i].active) {
                if (scheduler->events[i].at <= scheduler->cycles) {
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

        // We 'rollback' the cycle counter for the duration of the callback
        delay = scheduler->cycles - event->at;
        scheduler->cycles -= delay;

        if (event->repeat) {
            event->at += event->period;

            if (event->at < scheduler->next_event) {
                scheduler->next_event = event->at;
            }
        } else {
            event->active = false;
        }

        sched_event_callbacks[event->kind](gba, event->args);
        scheduler->cycles += delay;
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
    struct scheduler *scheduler;
    uint64_t target;

    scheduler = &gba->scheduler;
    target = scheduler->cycles + cycles;

#ifdef WITH_DEBUGGER
    gba->debugger.interrupted = false;

    while (scheduler->cycles < target && !gba->debugger.interrupted) {
#else
    while (scheduler->cycles < target) {
#endif
        uint64_t elapsed;
        uint64_t old_cycles;

        old_cycles = scheduler->cycles;
        core_next(gba);
        elapsed = scheduler->cycles - old_cycles;

        if (!elapsed) {
            if (gba->core.state != CORE_STOP) {
                logln(HS_WARNING, "No cycles elapsed during `core_next()`.");
            }
            break;
        }
    }
}

void
sched_reset_frame_limiter(
    struct gba *gba
) {
    gba->scheduler.accumulated_time = 0;
    gba->scheduler.time_last_frame = hs_time();
}

void
sched_frame_limiter(
    struct gba *gba,
    struct event_args args __unused
) {
    if (!gba->scheduler.fast_forward) {
        uint64_t now;

        now = hs_time();
        gba->scheduler.accumulated_time += now - gba->scheduler.time_last_frame;
        gba->scheduler.time_last_frame = now;

        if (gba->scheduler.accumulated_time < gba->scheduler.time_per_frame) {
            hs_usleep(gba->scheduler.time_per_frame - gba->scheduler.accumulated_time);
        }
        gba->scheduler.accumulated_time -= gba->scheduler.time_per_frame;
    }
}

void
sched_update_speed(
    struct gba *gba,
    bool fast_forward,
    float speed
) {
    struct scheduler *scheduler;

    scheduler = &gba->scheduler;

    scheduler->fast_forward = fast_forward;

    if (fast_forward) {
        scheduler->speed = 0.0;
        scheduler->time_per_frame = 0.0;
    } else {
        scheduler->speed = speed;
        scheduler->time_per_frame = 1000.f * 1000.f / (speed * 59.737f);
    }

    sched_reset_frame_limiter(gba);
}
