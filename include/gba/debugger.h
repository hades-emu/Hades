/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#pragma once

#include "hades.h"

struct gba;

struct sw_breakpoint {
    uint32_t ptr;
    bool thumb;
    void (*hook)(struct gba *gba, struct sw_breakpoint const *bp);
};

#ifdef WITH_DEBUGGER

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

struct hw_breakpoint {
    uint32_t ptr;
};

struct watchpoint {
    uint32_t ptr;
    bool write;
};

struct debugger {
    bool interrupted;

    struct {
        struct hw_breakpoint *list;
        size_t len;
    } hw_breakpoints;

    struct {
        struct sw_breakpoint *list;
        size_t len;
    } sw_breakpoints;

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

    struct {
        size_t count;
    } frame;
};

/* gba/debugger.c */
void debugger_eval_sw_breakpoints(struct gba *gba, uint32_t addr);
void debugger_eval_hw_breakpoints(struct gba *gba);
void debugger_eval_write_watchpoints(struct gba *gba, uint32_t addr, size_t size, uint32_t);
void debugger_eval_read_watchpoints(struct gba *gba, uint32_t addr, size_t size);
void debugger_execute_run_mode(struct gba *gba);

#else

struct debugger {
    struct {
        struct sw_breakpoint *list;
        size_t len;
    } sw_breakpoints;
};

#endif /* WITH_DEBUGGER */
