/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

#ifdef WITH_DEBUGGER

#include "hades.h"

enum gba_run_modes {
    GBA_RUN_MODE_NORMAL,
    GBA_RUN_MODE_FRAME,
    GBA_RUN_MODE_TRACE,
    GBA_RUN_MODE_STEP_IN,
    GBA_RUN_MODE_STEP_OVER,
};

/*
** The different reasons why the emulation could be interrupted.
*/
enum interrupt_reasons {
    GBA_INTERRUPT_REASON_UNKNOWN = 0,
    GBA_INTERRUPT_REASON_PAUSE,
    GBA_INTERRUPT_REASON_TRACE_FINISHED,
    GBA_INTERRUPT_REASON_STEP_FINISHED,
    GBA_INTERRUPT_REASON_BREAKPOINT_REACHED,
    GBA_INTERRUPT_REASON_WATCHPOINT_REACHED,
    GBA_INTERRUPT_REASON_FRAME_FINISHED,
};

struct breakpoint {
    uint32_t ptr;
};

struct watchpoint {
    uint32_t ptr;
    bool write;
};

struct debugger {
    // The "run mode" of the gba (how it should behave when running).
    enum gba_run_modes run_mode;

    bool interrupted;

    struct {
        struct breakpoint *list;
        size_t len;
    } breakpoints;

    struct {
        struct watchpoint *list;
        size_t len;
        void (*cleanup)(void *);
    } watchpoints;

    struct {
        size_t count;
        void (*tracer_cb)(void *);
        void *arg;
    } trace;

    struct {
        uint32_t next_pc;
        size_t count;
    } step;
};

/* gba/debugger.c */
void debugger_init(struct debugger *debugger);
void debugger_eval_breakpoints(struct gba *gba);
void debugger_eval_write_watchpoints(struct gba *gba, uint32_t addr, size_t size, uint32_t);
void debugger_eval_read_watchpoints(struct gba *gba, uint32_t addr, size_t size);
void debugger_execute_run_mode(struct gba *gba);

#endif /* WITH_DEBUGGER */
