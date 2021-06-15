/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#ifndef DEBUGGER_H
# define DEBUGGER_H

# include <stdbool.h>
# include <capstone/capstone.h>
# include "hades.h"
# include "core.h"

/*
** A structure containing the internal state of the debugger.
*/
struct debugger {
    csh handle_arm;         // Capstone handle for ARM mode
    csh handle_thumb;       // Capstone handle for Thumb mode

    uint32_t *breakpoints;
    size_t breakpoints_len;
};

struct gba;

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

struct register_alias {
    char const *name;
    size_t idx;
};

/*
** A table mapping all registers name and aliases to their indexes, with special indexes
** for banked registers or PSRs.
*/
extern struct register_alias register_alias_list[];

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

/*
** A command of the debugger's REPL
*/
struct dbg_command {
    char const *name;
    char const *alias;
    char const *usage;
    char const *desc;
    int nargs;
    void (*func)(struct gba *gba, size_t argc, char const * const *argv);
};

enum dbg_commands {
    CMD_HELP        = 0x0,
    CMD_QUIT,
    CMD_CONTINUE,
    CMD_NEXT,
    CMD_STEP,
    CMD_REGISTERS,
    CMD_DISAS,
    CMD_SET,
    CMD_CONTEXT,
    CMD_CONTEXT_COMPACT,
    CMD_PRINT,
    CMD_BREAK,
    CMD_TRACE,
    CMD_VERBOSE,
    CMD_MAIN,
};

/*
** A global variable of all the commands supported by the debugger.
*/
extern struct dbg_command g_commands[];

/* debugger/cmd/break.c */
void debugger_cmd_break(struct gba *, size_t, char const * const *);
void debugger_eval_breakpoints(struct gba *gba);

/* debugger/debugger.c */
void debugger_init(struct gba *gba);
void debugger_destroy(struct gba *gba);
void debugger_repl(struct gba *gba);
uint32_t debugger_eval_expr(struct gba const *gba, char const *expr);

/* debugger/cmd/context.c */
void debugger_dump_context(struct gba *, bool);
void debugger_dump_context_compact(struct gba *);
void debugger_dump_context_compact_header(void);
void debugger_cmd_context(struct gba *, size_t, char const * const *);
void debugger_cmd_context_compact(struct gba *, size_t, char const * const *);

/* debugger/cmd/continue.c */
void debugger_cmd_continue(struct gba *, size_t, char const * const *);

/* debugger/cmd/disas.c */
void debugger_cmd_disas(struct gba *, size_t, char const * const *);
void debugger_cmd_disas_at(struct gba *gba, uint32_t ptr);

/* debugger/cmd/help.c */
void debugger_cmd_help(struct gba *, size_t, char const * const *);

/* debugger/cmd/main.c */
void debugger_cmd_main(struct gba *, size_t, char const * const *);

/* debugger/cmd/next.c */
void debugger_cmd_next(struct gba *, size_t, char const * const *);

/* debugger/cmd/print.c */
void debugger_cmd_print(struct gba *, size_t, char const * const *);
void debugger_cmd_print_u8(struct gba const *, uint32_t, size_t, size_t);
void debugger_cmd_print_u16(struct gba const *, uint32_t, size_t, size_t);
void debugger_cmd_print_u32(struct gba const *, uint32_t, size_t, size_t);

/* debugger/cmd/registers.c */
void debugger_cmd_registers(struct gba *, size_t, char const * const *);

/* debugger/cmd/set.c */
void debugger_cmd_set(struct gba *, size_t, char const * const *);

/* debugger/cmd/step.c */
void debugger_cmd_step(struct gba *, size_t, char const * const *);

/* debugger/cmd/trace.c */
void debugger_cmd_trace(struct gba *, size_t, char const * const *);

/* debugger/cmd/verbose.c */
void debugger_cmd_verbose(struct gba *, size_t, char const * const *);

#endif /* !DEBUGGER_H */
