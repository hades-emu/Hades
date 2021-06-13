/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <string.h>
#include "hades.h"
#include "debugger.h"
#include "gba.h"

struct dbg_command g_commands[] = {
    [CMD_HELP] = {
        .name = "help",
        .alias = "h",
        .usage = "help [COMMAND]",
        .desc = "Show a list of all commands, or show the usage of \"COMMAND\".",
        .nargs = 0,
        .func = debugger_cmd_help,
    },
    [CMD_QUIT] = {
        .name = "quit",
        .alias = "q",
        .usage = "exit",
        .desc = "Close Hades",
        .nargs = 1,
        .func = NULL,
    },
    [CMD_CONTINUE] = {
        .name = "continue",
        .alias = "c",
        .usage = "continue",
        .desc = "Continue the execution until a breakpoint is reached",
        .nargs = 1,
        .func = debugger_cmd_continue,
    },
    [CMD_NEXT] = {
        .name = "next",
        .alias = "n",
        .usage = "next [N=1]",
        .desc = "Execute the next N instructions, stepping over branching instructions.",
        .nargs = 0,
        .func = debugger_cmd_next,
    },
    [CMD_STEP] = {
        .name = "step",
        .alias = "s",
        .usage = "step [N=1]",
        .desc = "Execute the next N instructions, following branching instructions.",
        .nargs = 0,
        .func = debugger_cmd_step,
    },
    [CMD_REGISTERS] = {
        .name = "registers",
        .alias = "r",
        .usage = "registers",
        .desc = "List the content of all registers",
        .nargs = 1,
        .func = debugger_cmd_registers,
    },
    [CMD_DISAS] = {
        .name = "disas",
        .alias = "d",
        .usage = "disas [ADDR=r15]",
        .desc = "Disassemble the instructions around \"ADDR\".",
        .nargs = 0,
        .func = debugger_cmd_disas,
    },
    [CMD_SET] = {
        .name = "set",
        .alias = NULL,
        .usage = "set REGISTER EXPR",
        .desc = "Set the content of REGISTER to EXPR.",
        .nargs = 3,
        .func = debugger_cmd_set,
    },
    [CMD_CONTEXT] = {
        .name = "context",
        .alias = "v",
        .usage = "context",
        .desc = "Show the most important information of the current context (registers, stack, instructions, etc.).",
        .nargs = 1,
        .func = debugger_cmd_context,
    },
    [CMD_PRINT] = {
        .name = "print",
        .alias = "p",
        .usage = "print <TYPE> <QUANTITY> <EXPR>",
        .desc = "Print QUANTITY memory located at EXPR of type TYPE (string, char, word, dword, etc.).",
        .nargs = 4,
        .func = debugger_cmd_print,
    },
    [CMD_BREAK] = {
        .name = "break",
        .alias = "b",
        .usage = "break <ADDR>",
        .desc = "Add a breakpoint at address ADDR.",
        .nargs = 2,
        .func = debugger_cmd_break,
    },
    [CMD_MAIN] = {
        .name = "main",
        .alias = "m",
        .usage = "main",
        .desc = "Continue until pc isn't 0x08000000 (Temporary)",
        .nargs = 1,
        .func = debugger_cmd_main,
    },
    {
        .name = NULL,
    }
};

void
debugger_init(
    struct gba *gba
) {
    struct debugger *debugger;

    debugger = &gba->debugger;
    memset(debugger, 0, sizeof(*debugger));

    read_history(".hades-dbg.history");
    write_history(".hades-dbg.history");

    if (
        (cs_open(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN, &debugger->handle_arm) != CS_ERR_OK) ||
        (cs_open(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN, &debugger->handle_thumb) != CS_ERR_OK) ||
        (cs_option(debugger->handle_arm, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) ||
        (cs_option(debugger->handle_thumb, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
    ) {
        fprintf(stderr, "Failed to open capstone for ARM mode.\n");
        exit(1);
    }
}

void
debugger_destroy(
    struct gba *gba
) {
    struct debugger *debugger;

    debugger = &gba->debugger;
    cs_close(&debugger->handle_arm);
    cs_close(&debugger->handle_thumb);
}

/*
** Enter a "Read/Evaluate/Print" loop.
*/
void
debugger_repl(
    struct gba *gba
) {
    char *input;

    hs_logln(HS_GLOBAL, "Welcome to Hades");
    hs_logln(HS_GLOBAL, "----------------");

    debugger_dump_context(gba, false);

    while (!g_stop && (input = readline("$ ")) != NULL) {
        char *saveptr;
        char *cmd_str;
        /* Skip blank lines */
        if (!*input) {
            free(input);
            continue;
        }

        /* Add input to history */
        add_history(input);
        append_history(1, ".hades-dbg.history");

        cmd_str = strtok_r(input, ";", &saveptr);

        while (cmd_str) {
            char **tokens;
            size_t tokens_length;
            struct dbg_command const *cmd;

            /* Reset the g_interrupt global variable */
            g_interrupt = false;

            tokens = strsplit(cmd_str, &tokens_length);
            if (tokens_length == 0) {
                goto next;
            }

            cmd = g_commands;
            while (cmd->name) {
                if (!strcmp(cmd->name, tokens[0]) || (cmd-> alias && !strcmp(cmd->alias, tokens[0]))) {
                    if (cmd->nargs > 0 && cmd->nargs != tokens_length) {
                        printf("Usage: %s\n", cmd->usage);
                    } else if (cmd->func) {
                        cmd->func(gba, tokens_length, (char const * const *)tokens);
                    } else {
                        free((void *)tokens);
                        free(input);
                        printf("command \"%s\" isn't implemented yet.\n", tokens[0]);
                        return ;
                    }
                    goto next;
                }
                ++cmd;
            }
            printf("Unknown command \"%s\". Type \"help\" for a list of commands.\n", tokens[0]);

            next:
            free((void *)tokens);
            cmd_str = strtok_r(NULL, ";", &saveptr);
        }

        free(input);
    }

    g_stop = true;
}

/*
** ""Parse"" and evaluate an expression.
**
** I don't wanna loose any more time writing an expression parser, so `expr`
** must either be a constant or a register name.
*/
uint32_t
debugger_eval_expr(
    struct gba const *gba,
    char const *expr
) {
    struct core const *core;
    struct register_alias *alias;

    core = &gba->core;

    /* Try to see if it matches a register name. */
    alias = register_alias_list;
    while (alias->name) {
        if (!strcmp(alias->name, expr)) {
            switch (alias->idx) {
                case REGISTER_R0 ... REGISTER_R15:
                    return (core->registers[alias->idx]);
                    break;
                case REGISTER_CPSR:
                    return (core->cpsr.raw);
                    break;
            }
        }
        ++alias;
    }

    /* Fallback on a constant expression. */
    return (strtoul(expr, NULL, 0));
}

struct register_alias register_alias_list[] = {
    {
        .name = "r0",
        .idx = REGISTER_R0,
    },
    {
        .name = "r1",
        .idx = REGISTER_R1,
    },
    {
        .name = "r2",
        .idx = REGISTER_R2,
    },
    {
        .name = "r3",
        .idx = REGISTER_R3,
    },
    {
        .name = "r4",
        .idx = REGISTER_R4,
    },
    {
        .name = "r5",
        .idx = REGISTER_R5,
    },
    {
        .name = "r6",
        .idx = REGISTER_R6,
    },
    {
        .name = "r7",
        .idx = REGISTER_R7,
    },
    {
        .name = "r8",
        .idx = REGISTER_R8,
    },
    {
        .name = "r9",
        .idx = REGISTER_R9,
    },
    {
        .name = "r10",
        .idx = REGISTER_R10,
    },
    {
        .name = "r11",
        .idx = REGISTER_R11,
    },
    {
        .name = "fp",
        .idx = REGISTER_R11,
    },
    {
        .name = "r12",
        .idx = REGISTER_R12,
    },
    {
        .name = "r13",
        .idx = REGISTER_R13,
    },
    {
        .name = "sp",
        .idx = REGISTER_R13,
    },
    {
        .name = "r14",
        .idx = REGISTER_R14,
    },
    {
        .name = "lr",
        .idx = REGISTER_R14,
    },
    {
        .name = "r15",
        .idx = REGISTER_R15,
    },
    {
        .name = "pc",
        .idx = REGISTER_R15,
    },
    {
        .name = "cpsr",
        .idx = REGISTER_CPSR,
    },
    {
        .name = NULL,
    },
};
