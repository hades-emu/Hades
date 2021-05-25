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
# include "hades.h"
# include "core.h"

struct gba;

/*
** The user-friendly name of all registers
*/
static char const * const registers_name[] = {
    [0]     = "r0",
    [1]     = "r1",
    [2]     = "r2",
    [3]     = "r3",
    [4]     = "r4",
    [5]     = "r5",
    [6]     = "r6",
    [7]     = "r7",
    [8]     = "r8",
    [9]     = "r9",
    [10]    = "r10",
    [11]    = "fp",
    [12]    = "ip",
    [13]    = "sp",
    [14]    = "lr",
    [15]    = "pc",
};

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
    CMD_PRINT,
};

/*
** A global variable of all the commands supported by the debugger.
*/
extern struct dbg_command g_commands[];

/* debugger/debugger.c */
void debugger_repl(struct gba *gba);
uint32_t debugger_eval_expr(struct gba const *gba, char const *expr);

/* debugger/cmd/context.c */
void debugger_dump_context(struct gba *);
void debugger_cmd_context(struct gba *, size_t, char const * const *);

/* debugger/cmd/continue.c */
void debugger_cmd_continue(struct gba *, size_t, char const * const *);

/* debugger/cmd/disas.c */
void debugger_cmd_disas(struct gba *, size_t, char const * const *);

/* debugger/cmd/help.c */
void debugger_cmd_help(struct gba *, size_t, char const * const *);

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

#endif /* !DEBUGGER_H */
