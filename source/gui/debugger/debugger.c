/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "gui/app.h"
#include "gui/lang.h"
#include "gui/debugger.h"
#include "utils/time.h"
#include "gba/gba.h"
#include "hades.h"

struct command g_commands[] = {
    [CMD_HELP] = {
        .name = "help",
        .alias = "h",
        .usage = "help [COMMAND]",
        .description = "Show a list of all commands, or show the usage of \"COMMAND\".",
        .func = debugger_cmd_help,
    },
    [CMD_EXIT] = {
        .name = "exit",
        .usage = "exit",
        .description = "Exit Hades.",
        .func = debugger_cmd_exit,
    },
    [CMD_CONTINUE] = {
        .name = "continue",
        .alias = "c",
        .usage = "continue",
        .description = "Continue the execution until a breakpoint is reached.",
        .func = debugger_cmd_continue,
    },
    [CMD_STEP_IN] = {
        .name = "stepin",
        .alias = "si",
        .usage = "stepin [N=1]",
        .description = "Execute the next N instructions, following branching instructions.",
        .func = debugger_cmd_step_in,
    },
    [CMD_STEP_OVER] = {
        .name = "stepover",
        .alias = "so",
        .usage = "stepover [N=1]",
        .description = "Execute the next N instructions, stepping over branching instructions.",
        .func = debugger_cmd_step_over,
    },
    [CMD_REGISTERS] = {
        .name = "registers",
        .alias = "r",
        .usage = "registers",
        .description = "List the content of all registers.",
        .func = debugger_cmd_registers,
    },
    [CMD_DISAS] = {
        .name = "disas",
        .alias = NULL,
        .usage = "disas [MODE] [ADDR=pc]",
        .description = "Disassemble the instructions around \"ADDR\".",
        .func = debugger_cmd_disas,
    },
    [CMD_CONTEXT] = {
        .name = "context",
        .alias = "d",
        .usage = "context",
        .description = "Show the most important information of the current context (registers, stack, instructions, etc.).",
        .func = debugger_cmd_context,
    },
    [CMD_CONTEXT_COMPACT] = {
        .name = "compact",
        .alias = "dc",
        .usage = "compact",
        .description = "Show the most important information of the current context (registers, current instruction, etc.) in a compact form.",
        .func = debugger_cmd_context_compact,
    },
    [CMD_PRINT] = {
        .name = "print",
        .alias = "p",
        .usage = "print <TYPE> [QUANTITY] <EXPR>",
        .description = "Print QUANTITY (Default: 1) memory located at EXPR of type TYPE (string, char, word, dword, etc.).",
        .func = debugger_cmd_print,
    },
    [CMD_BREAK] = {
        .name = "break",
        .alias = "b",
        .usage = "break | break <ADDR> | break delete <ID>",
        .description = "Add or remove a breakpoint.",
        .func = debugger_cmd_break,
    },
    [CMD_WATCH] = {
        .name = "watch",
        .alias = "w",
        .usage = "watch | watch <read|write> <ADDR> | watch delete <ID>",
        .description = "Add or remove a watchpoint.",
        .func = debugger_cmd_watch,
    },
    [CMD_TRACE] = {
        .name = "trace",
        .alias = "t",
        .usage = "trace [N=1]",
        .description = "Execute the next N instructions, dumping the content of all registers in between them.",
        .func = debugger_cmd_trace,
    },
    [CMD_VERBOSE] = {
        .name = "verbose",
        .alias = "v",
        .usage = "verbose [NAME]",
        .description = "Inverse the verbosity of module NAME.",
        .func = debugger_cmd_verbose,
    },
    [CMD_RESET] = {
        .name = "reset",
        .alias = NULL,
        .usage = "reset",
        .description = "Reset the emulation",
        .func = debugger_cmd_reset,
    },
    {
        .name = NULL,
    }
};

void
debugger_wait_for_emulator(
    struct app *app,
    bool dump_context
) {
    while (!app->emulation.gba->debugger.interrupt.flag) {
        // This is to ensure the loop has a side-effect (otherwise it's UB)
        // and to help the CPU save some energy.
        hs_usleep(100000);
    }

    if (dump_context) {
        debugger_dump_context(app, false);
    }

    switch (app->emulation.gba->debugger.interrupt.reason) {
        case GBA_INTERRUPT_REASON_BREAKPOINT_REACHED: {
            printf(
                ">>>>> Breakpoint %s0x%08x%s hit! <<<<<\n",
                g_light_magenta,
                app->emulation.gba->debugger.interrupt.data.breakpoint->ptr,
                g_reset
            );
            break;
        };
        case GBA_INTERRUPT_REASON_WATCHPOINT_REACHED: {
            if (app->emulation.gba->debugger.interrupt.data.access.write) {
                printf(
                    ">>>>> Watchpoint %s0x%08x%s hit with a %swrite%s of %s0x%0*x%s to %s0x%08x%s! <<<<<\n",
                    g_light_magenta,
                    app->emulation.gba->debugger.interrupt.data.watchpoint->ptr,
                    g_reset,
                    g_light_green,
                    g_reset,
                    g_light_magenta,
                    app->emulation.gba->debugger.interrupt.data.access.size * 2,
                    app->emulation.gba->debugger.interrupt.data.access.val,
                    g_reset,
                    g_light_magenta,
                    app->emulation.gba->debugger.interrupt.data.access.ptr,
                    g_reset
                );
            } else {
                printf(
                    ">>>>> Watchpoint %s0x%08x%s hit with a %sread%s of size %s%i%s to %s0x%08x%s! <<<<<\n",
                    g_light_magenta,
                    app->emulation.gba->debugger.interrupt.data.watchpoint->ptr,
                    g_reset,
                    g_light_green,
                    g_reset,
                    g_light_magenta,
                    app->emulation.gba->debugger.interrupt.data.access.size,
                    g_reset,
                    g_light_magenta,
                    app->emulation.gba->debugger.interrupt.data.access.ptr,
                    g_reset
                );
            }
            break;
        };
        default: break;
    }

    gui_game_pause(app);
}

static
void
debugger_run_command(
    struct app *app,
    struct command *cmd,
    struct ast *ast
) {
    struct arg *args;
    size_t len;

    args = NULL;
    len = 0;

    // Consume arguments to produce AST nodes
    while (ast->token) {

        debugger_lang_parse(ast, ast->token);

        if (ast->error) {
            printf("Error: %s.\n", ast->error);
            // TODO FIXME free stuff
            return ;
        }

        args = realloc(args, sizeof(*args) * (len + 1));
        hs_assert(args);
        ++len;

        // A string is a unique NODE_VARIABLE that doesn't match any variable
        if (ast->root->kind == NODE_VARIABLE && !debugger_lang_variables_lookup(app, ast->root->value.identifier)) {
            args[len - 1].type = ARGS_STRING;
            args[len - 1].value.s = strdup(ast->root->value.identifier);
        } else {
            struct eval eval;

            memset(&eval, 0, sizeof(eval));

            debugger_lang_eval(&eval, app, ast);

            if (eval.error) {
                printf("Error: %s.\n", eval.error);
                // TODO FIXME free stuff
                return ;
            }

            args[len - 1].type = ARGS_INTEGER;
            args[len - 1].value.i64 = eval.res;
        }

        // TODO FIXME free stuff
    }

    cmd->func(app, len, args);
}

void
debugger_run(
    struct app *app
) {
    char *input;
    uint32_t ptr;

    read_history(".hades-dbg.history");
    write_history(".hades-dbg.history");

    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN, &app->debugger.handle_arm) != CS_ERR_OK
        || cs_open(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN, &app->debugger.handle_thumb) != CS_ERR_OK
        || cs_option(app->debugger.handle_arm, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK
        || cs_option(app->debugger.handle_thumb, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK
    ) {
        panic(HS_DEBUG, "Failed to open capstone for ARM mode.");
    }

    /* Push the different registers as variable */

    debugger_lang_mut_variables_push(app, "r0", &app->emulation.gba->core.registers[0]);
    debugger_lang_mut_variables_push(app, "r1", &app->emulation.gba->core.registers[1]);
    debugger_lang_mut_variables_push(app, "r2", &app->emulation.gba->core.registers[2]);
    debugger_lang_mut_variables_push(app, "r3", &app->emulation.gba->core.registers[3]);
    debugger_lang_mut_variables_push(app, "r4", &app->emulation.gba->core.registers[4]);
    debugger_lang_mut_variables_push(app, "r5", &app->emulation.gba->core.registers[5]);
    debugger_lang_mut_variables_push(app, "r6", &app->emulation.gba->core.registers[6]);
    debugger_lang_mut_variables_push(app, "r7", &app->emulation.gba->core.registers[7]);
    debugger_lang_mut_variables_push(app, "r8", &app->emulation.gba->core.registers[8]);
    debugger_lang_mut_variables_push(app, "r9", &app->emulation.gba->core.registers[9]);
    debugger_lang_mut_variables_push(app, "r10", &app->emulation.gba->core.registers[10]);
    debugger_lang_mut_variables_push(app, "r11", &app->emulation.gba->core.registers[11]);
    debugger_lang_mut_variables_push(app, "r12", &app->emulation.gba->core.registers[12]);
    debugger_lang_mut_variables_push(app, "r13", &app->emulation.gba->core.registers[13]);
    debugger_lang_mut_variables_push(app, "r14", &app->emulation.gba->core.registers[14]);
    debugger_lang_mut_variables_push(app, "r15", &app->emulation.gba->core.registers[15]);

    debugger_lang_mut_variables_push(app, "pc", &app->emulation.gba->core.registers[15]);
    debugger_lang_mut_variables_push(app, "lr", &app->emulation.gba->core.registers[14]);
    debugger_lang_mut_variables_push(app, "sp", &app->emulation.gba->core.registers[13]);
    debugger_lang_mut_variables_push(app, "ip", &app->emulation.gba->core.registers[12]);
    debugger_lang_mut_variables_push(app, "fp", &app->emulation.gba->core.registers[11]);
    debugger_lang_mut_variables_push(app, "sl", &app->emulation.gba->core.registers[10]);

    /* Push all the IO registers name */

    for (ptr = IO_REG_START; ptr < IO_REG_END; ptr += 2) {
        char const *name;

        name = mem_io_reg_name(ptr);
        if (name && strcmp(name, "<unknown>")) {
            debugger_lang_const_variables_push(app, name, ptr);
        }
    }

    debugger_wait_for_emulator(app, true);

    while (app->run && (input = readline("$ ")) != NULL) {
        char *saveptr;
        char *cmd_str;

        /* Skip blank lines */
        if (!*input) {
            free(input);
            continue;
        }

        /* Add input to history */
        add_history(input);
        write_history(".hades-dbg.history");

        cmd_str = strtok_r(input, ";", &saveptr);

        while (cmd_str) {
            struct lexer lexer;
            struct ast ast;
            struct eval eval;

            memset(&lexer, 0, sizeof(lexer));
            memset(&ast, 0, sizeof(ast));
            memset(&eval, 0, sizeof(eval));

            debugger_lang_lexe(&lexer, cmd_str);
            if (lexer.error) {
                printf("Error: %s.\n", lexer.error);
                goto cleanup;
            }

            // debugger_lang_dump_lexer(&lexer);

            debugger_lang_parse(&ast, lexer.tokens);
            if (ast.error) {
                printf("Error: %s.\n", ast.error);
                goto cleanup;
            }

            // debugger_lang_dump_ast(&ast);

            // A command is a unique NODE_VARIABLE that doesn't match any variable
            if (ast.root->kind == NODE_VARIABLE && !debugger_lang_variables_lookup(app, ast.root->value.identifier)) {
                struct command *cmd;
                char const *input_cmd;

                input_cmd = ast.root->value.identifier;
                for (cmd = g_commands; cmd->name; ++cmd) {
                    if (!strcmp(cmd->name, input_cmd) || (cmd->alias && !strcmp(cmd->alias, input_cmd))) {
                        if (cmd->func) {
                            debugger_run_command(app, cmd, &ast);
                        } else {
                            printf("command \"%s\" isn't implemented yet.\n", input_cmd);
                        }
                        goto cleanup;
                    }
                }

                printf("Unknown command \"%s\". Type \"help\" for a list of commands.\n", input_cmd);
            } else {
                debugger_lang_eval(&eval, app, &ast);
                if (eval.error) {
                    printf("Error: %s.\n", eval.error);
                } else {
                    printf("%s0x%08x%s\n", g_dark_gray, (uint32_t)eval.res, g_reset);
                }
            }

cleanup:
            debugger_lang_cleanup(&lexer, &ast, &eval);
            cmd_str = strtok_r(NULL, ";", &saveptr);
        }

        free(input);
    }

    app->run = false;

    cs_close(&app->debugger.handle_arm);
    cs_close(&app->debugger.handle_thumb);
}

bool
debugger_check_arg_type(
    enum commands_list command,
    struct arg const *arg,
    enum args_type expected
) {
    if (arg->type != expected) {
        printf("Expected argument of type %s, got %s.\n", args_type_names[expected], args_type_names[arg->type]);
        printf("Usage: %s\n", g_commands[command].usage);
        return (true);
    } else {
        return (false);
    }
}