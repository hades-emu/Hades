/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#if !defined(GUI_DEBUGGER_H) && defined(WITH_DEBUGGER)
# define GUI_DEBUGGER_H

# include <stdbool.h>
# include "hades.h"
# include "gba/gba.h"

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
};

/*
** An array containing all the commands supported by the debugger.
*/
extern struct command g_commands[];

/* platform/gui/debugger/cmd/break.c */
void debugger_cmd_break(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/context.c */
void debugger_dump_context(struct app *, bool);
void debugger_dump_context_compact(struct app *);
void debugger_dump_context_compact_header(void);
void debugger_cmd_context(struct app *, size_t, struct arg const *);
void debugger_cmd_context_compact(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/continue.c */
void debugger_cmd_continue(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/disas.c */
void debugger_cmd_disas(struct app *, size_t, struct arg const *);
void debugger_cmd_disas_at(struct app *app, uint32_t ptr, bool);

/* platform/gui/debugger/cmd/exit.c */
void debugger_cmd_exit(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/frame.c */
void debugger_cmd_frame(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/help.c */
void debugger_cmd_help(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/print.c */
void debugger_cmd_print(struct app *, size_t, struct arg const *);
void debugger_cmd_print_u8(struct app const *, uint32_t, size_t, size_t);
void debugger_cmd_print_u16(struct app const *, uint32_t, size_t, size_t);
void debugger_cmd_print_u32(struct app const *, uint32_t, size_t, size_t);

/* platform/gui/debugger/cmd/registers.c */
void debugger_cmd_registers(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/reset.c */
void debugger_cmd_reset(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/step.c */
void debugger_cmd_step_in(struct app *, size_t, struct arg const *);
void debugger_cmd_step_over(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/trace.c */
void debugger_cmd_trace(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/verbose.c */
void debugger_cmd_verbose(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/cmd/watch.c */
void debugger_cmd_watch(struct app *, size_t, struct arg const *);

/* platform/gui/debugger/debugger.c */
void debugger_run(struct app *app);
bool debugger_check_arg_type(enum commands_list command, struct arg const *arg, enum args_type expected);
void debugger_wait_for_emulator(struct app *, bool);

#endif /* !defined(GUI_DEBUGGER_H) && defined(WITH_DEBUGGER) */