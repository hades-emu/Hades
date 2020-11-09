/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2020 - The Hades Authors
**
\******************************************************************************/

#include "debugger.h"
#include "hades.h"

void
debugger_cmd_next(
    struct debugger *debugger,
    size_t argc,
    char const * const *argv
) {
    struct core *core;
    size_t op_len;

    core = debugger->core;
    op_len = core->cpsr.thumb ? 2 : 4;

    if (argc == 1) {
        uint32_t next_pc;

        next_pc = core->pc + op_len;
        while (core->pc != next_pc) {
            core_step(core);
        }

        debugger_dump_context(debugger);
    } else if (argc == 2) {
        uint32_t next_pc;

        next_pc = core->pc + strtoul(argv[1], NULL, 0) * op_len;
        while (core->pc != next_pc) {
            core_step(core);
        }

        debugger_dump_context(debugger);
    } else {
        printf("Usage: %s\n", g_commands[CMD_NEXT].usage);
    }
}
