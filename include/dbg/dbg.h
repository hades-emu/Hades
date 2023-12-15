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

#include <stdbool.h>
#include "hades.h"
#include "common/channel/event.h"
#include "gba/gba.h"

struct app;

/*
** An enumeration of all registers and
*/
enum register_index {
    REGISTER_R0         = 0,
    REGISTER_R1         = 1,
    REGISTER_R2         = 2,
    REGISTER_R3         = 3,
    REGISTER_R4         = 4,
    REGISTER_R5         = 5,
    REGISTER_R6         = 6,
    REGISTER_R7         = 7,
    REGISTER_R8         = 8,
    REGISTER_R9         = 9,
    REGISTER_R10        = 10,
    REGISTER_R11        = 11,
    REGISTER_R12        = 12,
    REGISTER_R13        = 13,
    REGISTER_R14        = 14,
    REGISTER_R15        = 15,
    REGISTER_CPSR,
};

/*
** The user-friendly name of all registers
*/
static char const * const registers_name[] = {
    [REGISTER_R0]     = "r0",
    [REGISTER_R1]     = "r1",
    [REGISTER_R2]     = "r2",
    [REGISTER_R3]     = "r3",
    [REGISTER_R4]     = "r4",
    [REGISTER_R5]     = "r5",
    [REGISTER_R6]     = "r6",
    [REGISTER_R7]     = "r7",
    [REGISTER_R8]     = "r8",
    [REGISTER_R9]     = "r9",
    [REGISTER_R10]    = "sl",
    [REGISTER_R11]    = "fp",
    [REGISTER_R12]    = "ip",
    [REGISTER_R13]    = "sp",
    [REGISTER_R14]    = "lr",
    [REGISTER_R15]    = "pc",
};

/*
** The common suffix of all ARM conditions.
*/
static char const * const cond_suffix[] = {
    [COND_EQ] = "EQ",
    [COND_NE] = "NE",
    [COND_CS] = "CS",
    [COND_CC] = "CC",
    [COND_MI] = "MI",
    [COND_PL] = "PL",
    [COND_VS] = "VS",
    [COND_VC] = "VC",
    [COND_HI] = "HI",
    [COND_LS] = "LS",
    [COND_GE] = "GE",
    [COND_LT] = "LT",
    [COND_GT] = "GT",
    [COND_LE] = "LE",
    [COND_AL] = "",
};

#define ARGS_MANDATORY  0
#define ARGS_OPTIONAL   1

enum args_type {
    ARGS_INTEGER,
    ARGS_STRING,
};

static char const * const args_type_names[] = {
    [ARGS_INTEGER] = "integer",
    [ARGS_STRING] = "string",
};

struct arg {
    enum args_type type;
    union {
        uint64_t i64;
        char const *s;
    } value;
};

/*
** A command of the debugger's REPL
*/
struct command {
    char const *name;
    char const *alias;
    char const *usage;
    char const *description;
    void (*func)(struct app *app, size_t argc, struct arg const *argv);
};

enum commands_list {
    CMD_HELP        = 0x0,
    CMD_EXIT,
    CMD_CONTINUE,
    CMD_STEP_IN,
    CMD_STEP_OVER,
    CMD_REGISTERS,
    CMD_DISAS,
    CMD_CONTEXT,
    CMD_CONTEXT_COMPACT,
    CMD_PRINT,
    CMD_BREAK,
    CMD_WATCH,
    CMD_TRACE,
    CMD_VERBOSE,
    CMD_RESET,
    CMD_FRAME,
    CMD_IO,
    CMD_KEY,
    CMD_SCREENSHOT,
};

struct io_bitfield {
    size_t start;
    size_t end;
    char const *label;
    char const *hint;
};

struct io_register {
    uint32_t address;
    size_t size;
    char const *name;
    union {
        uint16_t *ptr16;
        uint32_t *ptr32;
    };
    struct io_bitfield bitfield[16];
    size_t bitfield_len;
};

/*
** An array containing all the commands supported by the debugger.
*/
extern struct command g_commands[];

/*
** An array containing a description of every bits in all IO registers.
*/
extern struct io_register g_io_registers[];
extern size_t g_io_registers_len;

/* dbg/cmd/break.c */
void debugger_cmd_break(struct app *, size_t, struct arg const *);

/* dbg/cmd/context.c */
void debugger_dump_context(struct app *);
void debugger_dump_context_auto(struct app *);
void debugger_dump_context_compact(struct app *);
void debugger_dump_context_compact_header(void);
void debugger_cmd_context(struct app *, size_t, struct arg const *);
void debugger_cmd_context_compact(struct app *, size_t, struct arg const *);

/* dbg/cmd/continue.c */
void debugger_cmd_continue(struct app *, size_t, struct arg const *);

/* dbg/cmd/disas.c */
void debugger_cmd_disas(struct app *, size_t, struct arg const *);
void debugger_cmd_disas_at(struct app *app, uint32_t ptr, bool);

/* dbg/cmd/exit.c */
void debugger_cmd_exit(struct app *, size_t, struct arg const *);

/* dbg/cmd/frame.c */
void debugger_cmd_frame(struct app *, size_t, struct arg const *);

/* dbg/cmd/help.c */
void debugger_cmd_help(struct app *, size_t, struct arg const *);

/* dbg/cmd/io.c */
void debugger_cmd_io(struct app *, size_t, struct arg const *);

/* dbg/cmd/key.c */
void debugger_cmd_key(struct app *, size_t, struct arg const *);

/* dbg/cmd/print.c */
void debugger_cmd_print(struct app *, size_t, struct arg const *);
void debugger_cmd_print_u8(struct app const *, uint32_t, size_t, size_t);
void debugger_cmd_print_u16(struct app const *, uint32_t, size_t, size_t);
void debugger_cmd_print_u32(struct app const *, uint32_t, size_t, size_t);

/* dbg/cmd/registers.c */
void debugger_cmd_registers(struct app *, size_t, struct arg const *);

/* dbg/cmd/reset.c */
void debugger_cmd_reset(struct app *, size_t, struct arg const *);

/* dbg/cmd/screenshot.c */
void debugger_cmd_screenshot(struct app *, size_t, struct arg const *);

/* dbg/cmd/step.c */
void debugger_cmd_step_in(struct app *, size_t, struct arg const *);
void debugger_cmd_step_over(struct app *, size_t, struct arg const *);

/* dbg/cmd/trace.c */
void debugger_cmd_trace(struct app *, size_t, struct arg const *);

/* dbg/cmd/verbose.c */
void debugger_cmd_verbose(struct app *, size_t, struct arg const *);

/* dbg/cmd/watch.c */
void debugger_cmd_watch(struct app *, size_t, struct arg const *);

/* dbg/debugger.c */
void debugger_run(struct app *app);
void debugger_reset_terminal(void);
bool debugger_check_arg_type(enum commands_list command, struct arg const *arg, enum args_type expected);
void debugger_process_all_notifs(struct app *);
void debugger_wait_for_emulator(struct app *);
void debugger_wait_for_notif(struct app *, enum notification_kind kind);

/* dbg/io.c */
void debugger_io_init(struct gba *);
struct io_register *debugger_io_lookup_reg(uint32_t address);

#endif /* WITH_DEBUGGER */
