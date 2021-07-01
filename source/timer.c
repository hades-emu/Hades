/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "hades.h"
#include "gba.h"

static uint64_t scalers[4] = { 1, 64, 256, 1024};

void
timer_tick(
    struct gba *gba,
    uint32_t cycles
) {
    bool prev_overflow;
    uint32_t i;

    prev_overflow = false;
    for (i = 0; i < 4; ++i) {
        struct timer *timer;

        timer = gba->io.timers + i;
        if (!timer->control.enable) {
            prev_overflow = false;
            continue;
        }

        if (timer->control.count_up && i != 0) {
            timer->real_counter += prev_overflow;
            timer->counter.raw = timer->real_counter;
            prev_overflow = (timer->real_counter > (uint64_t)timer->counter.raw);
        } else {
            timer->real_counter += cycles;
            timer->counter.raw = timer->real_counter / scalers[timer->control.prescaler];
            prev_overflow = ((timer->real_counter / scalers[timer->control.prescaler]) > (uint64_t)timer->counter.raw);
        }

        if (prev_overflow) {
            timer->real_counter = timer->reload.raw;
            timer->counter.raw = timer->reload.raw;
            logln(
                HS_TIMER,
                "Timer %u overflowed. Reloading with value %04x",
                i,
                timer->reload.raw
            );

            if (timer->control.irq) {
                core_trigger_irq(gba, IRQ_TIMER0 + i);
            }
        }
    }
}