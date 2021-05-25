/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "debugger.h"
#include "gba.h"

void
debugger_cmd_help(
    struct gba *gba __unused,
    size_t argc,
    char const * const *argv
) {
    struct dbg_command *cmd;

    if (argc == 1) {
        printf("Available commands:\n");

        cmd = g_commands;
        while (cmd->name) {
            printf("    %-10s %s\n", cmd->name, cmd->desc);
            ++cmd;
        }
    } else if (argc == 2) {
        cmd = g_commands;
        while (cmd->name) {
            if (!strcmp(cmd->name, argv[1])) {
                printf("Usage: %s\n", cmd->usage);
                printf("\n");
                printf("%s\n", cmd->desc);
                return ;
            }
            ++cmd;
        }

        printf("Unknown command \"%s\". Use \"help\" (no argument) to see a list of all commands.\n", argv[1]);
    } else {
        printf("Usage: %s\n", g_commands[CMD_HELP].usage);
    }
}
