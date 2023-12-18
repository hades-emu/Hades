/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "app/app.h"
#include "app/dbg.h"

void
debugger_cmd_help(
    struct app *app __unused,
    size_t argc,
    struct arg const *argv
) {
    struct command *cmd;

    if (argc == 0) {
        printf("Available commands:\n");

        cmd = g_commands;
        while (cmd->name) {
            printf("    %-10s %s\n", cmd->name, cmd->description);
            ++cmd;
        }
    } else if (argc == 1) {
        if (!debugger_check_arg_type(CMD_HELP, &argv[0], ARGS_STRING)) {
            cmd = g_commands;
            while (cmd->name) {
                if (!strcmp(cmd->name, argv[0].value.s)) {
                    printf("Usage: %s\n", cmd->usage);
                    printf("\n");
                    printf("%s\n", cmd->description);
                    return ;
                }
                ++cmd;
            }

            printf("Unknown command \"%s\". Use \"help\" (no argument) to see a list of all commands.\n", argv[0].value.s);
        }
    } else {
        printf("Usage: %s\n", g_commands[CMD_HELP].usage);
    }
}
