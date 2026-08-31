/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
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

/*
** Push the entry (at, idx) onto the scheduler's minheap, growing it if necessary.
** Reference:
**  - https://www.geeksforgeeks.org/dsa/introduction-to-min-heap-data-structure/
*/
static
void
sched_minheap_push(
    struct scheduler *scheduler,
    uint64_t at,
    size_t idx
) {
    size_t child_idx;

    // Reallocate the minheap inner array if needed
    if (scheduler->minheap_size == scheduler->minheap_capacity) {
        scheduler->minheap_capacity = scheduler->minheap_capacity * 2 + 64;
        scheduler->minheap = realloc(scheduler->minheap, scheduler->minheap_capacity * sizeof(struct scheduler_minheap_entry));
        hs_assert(scheduler->minheap);
    }

    child_idx = scheduler->minheap_size;
    scheduler->minheap_size += 1;

    // Shift the new entry up until the minheap property (parent <= child) is true again.
    while (child_idx > 0) {
        size_t parent_idx;

        parent_idx = (child_idx - 1) / 2;

        // Stop if the parent is smaller or equal to the new element
        if (scheduler->minheap[parent_idx].at <= at) {
            break;
        }

        // Swap the parent with the child
        scheduler->minheap[child_idx] = scheduler->minheap[parent_idx];
        child_idx = parent_idx;
    }

    scheduler->minheap[child_idx].at = at;
    scheduler->minheap[child_idx].idx = idx;
}

/*
** Remove the top element of the scheduler's minheap.
*/
static
void
sched_minheap_pop(
    struct scheduler *scheduler
) {
    struct scheduler_minheap_entry last;
    size_t parent_idx;

    scheduler->minheap_size -= 1;
    last = scheduler->minheap[scheduler->minheap_size];

    parent_idx = 0;
    while (true) {
        size_t child_idx;
        size_t left_idx;
        size_t right_idx;

        left_idx = 2 * parent_idx + 1;
        right_idx = 2 * parent_idx + 2;

        if (left_idx >= scheduler->minheap_size) {
            break;
        }

        if (right_idx < scheduler->minheap_size && scheduler->minheap[right_idx].at < scheduler->minheap[left_idx].at) {
            child_idx = right_idx;
        } else {
            child_idx = left_idx;
        }

        if (last.at <= scheduler->minheap[child_idx].at) {
            break;
        }

        scheduler->minheap[parent_idx] = scheduler->minheap[child_idx];
        parent_idx = child_idx;
    }

    scheduler->minheap[parent_idx] = last;
}

void
sched_minheap_rebuild(
    struct gba *gba
) {
    struct scheduler *scheduler;
    size_t i;

    scheduler = &gba->scheduler;
    scheduler->minheap_size = 0;

    for (i = 0; i < scheduler->events_size; ++i) {
        if (scheduler->events[i].active) {
            sched_minheap_push(scheduler, scheduler->events[i].at, i);
        }
    }
}

void
sched_process_events(
    struct gba *gba
) {
    struct scheduler *scheduler;

    scheduler = &gba->scheduler;

    while (true) {
        struct scheduler_event *event;
        uint64_t delay;
        size_t idx;

        // Discard any stale entry in the scheduler's minheap
        // Those stale entry can be caused by deleted or rescheduled events.
        while (scheduler->minheap_size > 0) {
            struct scheduler_minheap_entry top;

            top = scheduler->minheap[0];
            if (!scheduler->events[top.idx].active || scheduler->events[top.idx].at != top.at) {
                sched_minheap_pop(scheduler);
                continue;
            }

            break;
        }

        if (scheduler->minheap_size == 0) {
            scheduler->next_event = UINT64_MAX;
            break;
        }

        idx = scheduler->minheap[0].idx;
        event = &scheduler->events[idx];

        if (event->at > scheduler->cycles) {
            scheduler->next_event = event->at;
            break;
        }

        sched_minheap_pop(scheduler);

        // We 'rollback' the cycle counter for the duration of the callback
        delay = scheduler->cycles - event->at;
        scheduler->cycles -= delay;

        if (event->repeat) {
            event->at += event->period;
            sched_minheap_push(scheduler, event->at, idx);
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
    sched_minheap_push(scheduler, event.at, i);

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
                logln(HS_WARN, "No cycles elapsed during `core_next()`.");
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
    if (gba->scheduler.time_per_frame) {
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
    struct gba *gba
) {
    struct scheduler *scheduler;

    scheduler = &gba->scheduler;

    if (gba->settings.fast_forward) {
        scheduler->time_per_frame = 0;
    } else {
        scheduler->time_per_frame = 1000.f * 1000.f / (gba->settings.speed * 59.737f);
    }

    sched_reset_frame_limiter(gba);
}
