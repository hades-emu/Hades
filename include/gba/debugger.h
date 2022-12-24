/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#if !defined(GBA_DEBUGGER_H) && defined(WITH_DEBUGGER)
# define GBA_DEBUGGER_H

# include "hades.h"

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
    struct {
        atomic_bool flag;
        enum interrupt_reasons reason;

        union {
            struct breakpoint *breakpoint;
            struct {
                struct watchpoint *watchpoint;
                struct {
                    uint32_t ptr;
                    uint32_t val;
                    uint8_t size;
                    bool write;
                } access;
            };
        } data;
    } interrupt;

    struct {
        struct breakpoint *list;
        size_t len;
        void (*cleanup)(void *);
    } breakpoints;

    struct {
        struct watchpoint *list;
        size_t len;
        void (*cleanup)(void *);
    } watchpoints;

    struct {
        size_t count;
        void *data;
        void (*tracer)(void *);
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

#endif /* !GBA_DEBUGGER_H */
