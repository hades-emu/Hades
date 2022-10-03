/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include "gba/gba.h"

static uint64_t scalers[4] = { 0, 6, 8, 10 };

void timer_overflow(struct gba *gba, struct event_args args);

void
timer_start(
    struct gba *gba,
    uint32_t timer_idx
) {
    struct timer *timer;

    timer = &gba->io.timers[timer_idx];
    timer->counter.raw = timer->reload.raw;

    logln(HS_TIMER, "Timer %u started with initial value %04x", timer_idx, timer->reload.raw);

    if (!timer->control.count_up) {
        timer->handler = sched_add_event(
            gba,
            NEW_REPEAT_EVENT_ARGS(
                gba->core.cycles + ((0x10000 - timer->counter.raw) << scalers[timer->control.prescaler]) + 2,
                ((0x10000 - timer->counter.raw) << scalers[timer->control.prescaler]),
                timer_overflow,
                EVENT_ARG(u32, timer_idx)
            )
        );
    } else {
        timer->handler = INVALID_EVENT_HANDLE;
    }
}

void
timer_overflow(
    struct gba *gba,
    struct event_args args
) {
    uint32_t timer_idx;
    struct timer *timer;

    timer_idx = args.a1.u32;
    timer = &gba->io.timers[timer_idx];

    logln(HS_TIMER, "Timer %u overflowed.");

    timer->counter.raw = timer->reload.raw;

    if (timer->control.irq) {
        gba->io.int_flag.raw |= 1 << (IRQ_TIMER0 + timer_idx);
    }

    if (timer_idx == 0 || timer_idx == 1) {
        apu_on_timer_overflow(gba, timer_idx);
    }

    if (timer_idx < 3 && gba->io.timers[timer_idx + 1].control.enable && gba->io.timers[timer_idx + 1].control.count_up) {
        uint32_t new;

        new = gba->io.timers[timer_idx + 1].counter.raw + 1;

        if (new == 0x10000) {
            timer_overflow(
                gba,
                EVENT_ARGS(
                    EVENT_ARG(u32, timer_idx + 1)
                )
            );
        } else {
            gba->io.timers[timer_idx + 1].counter.raw = new;
        }
    }
}

uint16_t
timer_update_counter(
    struct gba const *gba,
    uint32_t timer_idx
) {
    struct timer const *timer;
    uint64_t elapsed;

    timer = &gba->io.timers[timer_idx];
    elapsed = gba->core.cycles - gba->scheduler.events[timer->handler].at;
    return (elapsed >> scalers[timer->control.prescaler]);
}

uint16_t
timer_read_value(
    struct gba const *gba,
    uint32_t timer_idx
) {
    struct timer const *timer;

    timer = &gba->io.timers[timer_idx];
    if (timer->control.enable) {
        return (timer_update_counter(gba, timer_idx));
    }
    return (timer->counter.raw);
}

void
timer_stop(
    struct gba *gba,
    uint32_t timer_idx
) {
    struct timer *timer;

    timer = &gba->io.timers[timer_idx];
    timer->control.enable = false;
    timer->counter.raw = timer_update_counter(gba, timer_idx);

    if (timer->handler != INVALID_EVENT_HANDLE) {
        sched_cancel_event(gba, timer->handler);
        timer->handler = INVALID_EVENT_HANDLE;
    }
}