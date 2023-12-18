/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#ifdef WITH_DEBUGGER

#include <string.h>
#include "hades.h"
#include "gba/gba.h"
#include "gba/core.h"
#include "gba/event.h"

void gba_state_pause(struct gba *);
void gba_send_notification_raw(struct gba *gba, struct event_header const *notif_header);

void
debugger_init(
    struct debugger *debugger
) {
    memset(debugger, 0, sizeof(*debugger));
}

void
debugger_eval_breakpoints(
    struct gba *gba
) {
    uint32_t pc;
    struct breakpoint *bp;

    pc = gba->core.pc - (gba->core.cpsr.thumb ? 2 : 4) * 2;
    for (bp = gba->debugger.breakpoints.list; bp && bp < gba->debugger.breakpoints.list + gba->debugger.breakpoints.len; ++bp) {
        if (bp->ptr == pc) {
            struct notification_breakpoint notif;

            notif.header.kind = NOTIFICATION_BREAKPOINT;
            notif.header.size = sizeof(notif);
            notif.addr = pc;

            gba->debugger.interrupted = true;

            gba_send_notification_raw(gba, &notif.header);
            gba_state_pause(gba);
            break;
        }
    }
}

void
debugger_eval_write_watchpoints(
    struct gba *gba,
    uint32_t addr,
    size_t size,
    uint32_t new_value
) {
    struct watchpoint *wp;

    for (wp = gba->debugger.watchpoints.list; wp && wp < gba->debugger.watchpoints.list + gba->debugger.watchpoints.len; ++wp) {
        if (wp->ptr >= addr && wp->ptr < addr + size && wp->write) {
            struct notification_watchpoint notif;

            notif.header.kind = NOTIFICATION_WATCHPOINT;
            notif.header.size = sizeof(notif);

            notif.addr = wp->ptr;
            notif.access.addr = addr;
            notif.access.val = new_value;
            notif.access.size = size;
            notif.access.write = true;

            gba->debugger.interrupted = true;

            gba_send_notification_raw(gba, &notif.header);
            gba_state_pause(gba);
            break;
        }
    }
}

void
debugger_eval_read_watchpoints(
    struct gba *gba,
    uint32_t addr,
    size_t size
) {
    struct watchpoint *wp;

    for (wp = gba->debugger.watchpoints.list; wp && wp < gba->debugger.watchpoints.list + gba->debugger.watchpoints.len; ++wp) {
        if (wp->ptr >= addr && wp->ptr < addr + size && !wp->write) {
            struct notification_watchpoint notif;

            notif.header.kind = NOTIFICATION_WATCHPOINT;
            notif.header.size = sizeof(notif);

            notif.addr = wp->ptr;
            notif.access.addr = addr;
            notif.access.val = 0;
            notif.access.size = size;
            notif.access.write = false;

            gba->debugger.interrupted = true;

            gba_send_notification_raw(gba, &notif.header);
            gba_state_pause(gba);
            break;
        }
    }
}

void
debugger_execute_run_mode(
    struct gba *gba
) {
    switch (gba->debugger.run_mode) {
        case GBA_RUN_MODE_NORMAL: {
            sched_run_for(gba, GBA_CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH);
            break;
        };
        case GBA_RUN_MODE_FRAME: {
            if (gba->debugger.frame.count) {
                --gba->debugger.frame.count;
                sched_run_for(gba, GBA_CYCLES_PER_PIXEL * GBA_SCREEN_REAL_WIDTH * GBA_SCREEN_HEIGHT);
            } else {
                gba_state_pause(gba);
            }
            break;
        };
        case GBA_RUN_MODE_TRACE: {
            size_t cnt;

            cnt = 4096; // Split the process in chunks of 4096 insns.

            while (cnt && gba->debugger.trace.count) {
                sched_run_for(gba, 1);
                gba->debugger.trace.tracer_cb(gba->debugger.trace.arg);

                --gba->debugger.trace.count;
                --cnt;
            }

            if (!gba->debugger.trace.count) {
                gba_state_pause(gba);
            }
            break;

        };
        case GBA_RUN_MODE_STEP_IN: {
            size_t cnt;

            cnt = 4096; // Split the process in chunks of 4096 insns.

            while (cnt && gba->debugger.step.count) {
                sched_run_for(gba, 1);
                --gba->debugger.step.count;
                --cnt;
            }

            if (!gba->debugger.step.count) {
                gba_state_pause(gba);
            }
            break;
        };
        case GBA_RUN_MODE_STEP_OVER: {
            size_t cnt;

            cnt = 4096; // Split the process in chunks of 4096 insns.

            while (cnt && gba->debugger.step.count) {
                while (cnt && gba->core.pc != gba->debugger.step.next_pc) {
                    sched_run_for(gba, 1);
                    --cnt;
                }

                if (gba->core.pc == gba->debugger.step.next_pc) {
                    --gba->debugger.step.count;
                    gba->debugger.step.next_pc += (gba->core.cpsr.thumb ? 2 : 4);
                }
            }

            if (!gba->debugger.step.count) {
                gba_state_pause(gba);
            }
            break;
        };
    }
}

#endif
