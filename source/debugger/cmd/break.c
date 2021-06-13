/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021 - The Hades Authors
**
\******************************************************************************/

#include "gba.h"
#include "hades.h"
#include "debugger.h"

void
debugger_eval_breakpoints(
    struct gba *gba
) {
    struct debugger *debugger;
    size_t i;
    uint32_t pc;

    debugger = &gba->debugger;
    pc = gba->core.pc - (gba->core.cpsr.thumb ? 2 : 4);

    i = 0;
    while (i < debugger->breakpoints_len) {
        if (debugger->breakpoints[i] == pc) {
            printf(">>>> Breakpoint hit (%zu) at " LIGHT_MAGENTA "0x%08x" RESET " <<<<\n", i, pc);
            debugger_dump_context(gba, false);
            g_interrupt = true;
        }
        ++i;
    }
}

void
debugger_cmd_break(
    struct gba *gba,
    size_t argc,
    char const * const *argv
) {
    if (argc == 2) {
        struct debugger *debugger;
        uint32_t addr;

        debugger = &gba->debugger;
        addr = strtoul(argv[1], NULL, 0);

        debugger->breakpoints = realloc(
            debugger->breakpoints,
            (debugger->breakpoints_len + 1) * sizeof(uint32_t)
        );
        hs_assert(debugger->breakpoints);

        debugger->breakpoints[debugger->breakpoints_len] = addr;

        debugger->breakpoints_len += 1;

        printf("New breakpoint at address " LIGHT_MAGENTA "0x%08x" RESET ".\n", addr);
    } else {
        printf("Usage: %s\n", g_commands[CMD_BREAK].usage);
    }
}

