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

void
debugger_init(
    struct debugger *debugger
) {
    if (debugger->breakpoints.cleanup) {
        debugger->breakpoints.cleanup(debugger->breakpoints.list);
    }

    if (debugger->watchpoints.cleanup) {
        debugger->watchpoints.cleanup(debugger->watchpoints.list);
    }

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
            gba->debugger.interrupt.reason = GBA_INTERRUPT_REASON_BREAKPOINT_REACHED;
            gba->debugger.interrupt.data.breakpoint = bp;
            gba->debugger.interrupt.flag = true;
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
            gba->debugger.interrupt.reason = GBA_INTERRUPT_REASON_WATCHPOINT_REACHED;
            gba->debugger.interrupt.data.watchpoint = wp;
            gba->debugger.interrupt.data.access.ptr = addr;
            gba->debugger.interrupt.data.access.write = true;
            gba->debugger.interrupt.data.access.val = new_value;
            gba->debugger.interrupt.data.access.size = size;
            gba->debugger.interrupt.flag = true;
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
            gba->debugger.interrupt.reason = GBA_INTERRUPT_REASON_WATCHPOINT_REACHED;
            gba->debugger.interrupt.data.watchpoint = wp;
            gba->debugger.interrupt.data.access.ptr = addr;
            gba->debugger.interrupt.data.access.write = false;
            gba->debugger.interrupt.data.access.val = 0;
            gba->debugger.interrupt.data.access.size = size;
            gba->debugger.interrupt.flag = true;
            break;
        }
    }
}

#endif
